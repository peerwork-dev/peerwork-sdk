//! Exact, durable local kernel command journal. A pending record is never
//! inferred accepted from an HTTP status or a missing response.

use peerwork_core::crypto::sha256_hex;
use peerwork_core::discovery::{parse_discovery_wire, ParsedDiscovery};
use peerwork_core::prepared_command::{
    verify_prepared_command_wire, CommandPins, VerifiedPreparedCommand,
};
use peerwork_core::receipt_wire::{verify_http_response_for_prepared, VerifiedCommandResponse};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const APPLICATION_ID: i64 = 0x5057_5344; // PWSD; intentionally distinct from TS PWC1.
const SCHEMA_VERSION: i64 = 3;
const MAX_BODY_BYTES: usize = 262_144;
const MAX_JWS_BYTES: usize = 250_000;
const SCHEMA_SQL: &str = "CREATE TABLE kernel_intents(
                 command_id TEXT PRIMARY KEY NOT NULL,
                 path TEXT NOT NULL,
                 signed_jws TEXT NOT NULL,
                 intent_digest TEXT NOT NULL,
                 http_body BLOB NOT NULL,
                 state TEXT NOT NULL CHECK(state='PENDING'),
                 created_at_ms INTEGER NOT NULL
             )";
const CONTEXT_SQL: &str = "CREATE TABLE pinned_discovery(
                 id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
                 origin TEXT NOT NULL,
                 discovery_wire BLOB NOT NULL
             )";
const ACCEPTED_SQL: &str = "CREATE TABLE accepted_responses(
                 command_id TEXT PRIMARY KEY NOT NULL REFERENCES kernel_intents(command_id),
                 response_wire BLOB NOT NULL CHECK(length(response_wire)>0)
             )";

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("protected state directory or file required")]
    Protection,
    #[error("unsupported platform for protected local state")]
    UnsupportedPlatform,
    #[error("intent fields are invalid")]
    InvalidIntent,
    #[error("existing intent id binds different bytes")]
    IntentConflict,
    #[error("incompatible or corrupt intent database; migration required")]
    IncompatibleStore,
    #[error("discovery origin or pinned semantics changed")]
    DiscoveryChanged,
    #[error("signed receipt does not bind the saved command and result")]
    InvalidReceipt,
    #[error("local intent store failed")]
    Storage(#[from] rusqlite::Error),
    #[error("local file operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKernelIntent {
    pub command_id: String,
    pub intent_digest: String,
    pub created_at_ms: i64,
}

/// Internal exact saved request plus a private-constructor core signature
/// proof. Only a higher layer holding local identity and pinned discovery may
/// request this value; neither the signed packet nor body is a public DTO.
pub(crate) struct VerifiedPendingCommand {
    pub(crate) proof: VerifiedPreparedCommand,
    pub(crate) jws: String,
    pub(crate) body: Vec<u8>,
}

/// Core-recognized kernel POST paths. This is local preparation, not
/// authorization to transmit the signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelPath {
    Command,
    CatalogUpload,
    PrivatePackageUpload,
    BrowserSessionCommand(String),
}

impl KernelPath {
    pub fn browser_session_command(session_id: &str) -> Result<Self, JournalError> {
        if !valid_token(session_id) {
            return Err(JournalError::InvalidIntent);
        }
        Ok(Self::BrowserSessionCommand(format!(
            "/api/workspace/v1/browser/sessions/{session_id}/commands"
        )))
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Command => "/api/workspace/v1/commands",
            Self::CatalogUpload => "/api/workspace/v1/catalog/upload",
            Self::PrivatePackageUpload => "/api/workspace/v1/private/packages/upload",
            Self::BrowserSessionCommand(path) => path,
        }
    }
}

pub struct KernelIntentJournal {
    db: Connection,
    _path: PathBuf,
}

impl KernelIntentJournal {
    /// Opens a new native store in an existing private state directory. An
    /// old TypeScript store at this path is rejected until explicit migration.
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        ensure_private_parent(path)?;
        create_or_check_private_file(path)?;
        #[cfg(windows)]
        check_private_sidecars(path)?;
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        initialize(&mut db)?;
        set_wal_with_retry(&db)?;
        #[cfg(windows)]
        check_private_sidecars(path)?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Self {
            db,
            _path: path.to_path_buf(),
        })
    }

    /// Persists the exact original signed JWS and exact HTTP request body.
    /// Repeating an id is permitted only when every saved byte is identical.
    /// This API never sends a request or marks acceptance.
    pub fn prepare(
        &mut self,
        command_id: &str,
        path: KernelPath,
        signed_jws: &str,
        http_body: &[u8],
    ) -> Result<PendingKernelIntent, JournalError> {
        self.prepare_at_time(command_id, path, signed_jws, http_body, unix_millis()?)
    }

    fn prepare_at_time(
        &mut self,
        command_id: &str,
        path: KernelPath,
        signed_jws: &str,
        http_body: &[u8],
        now: i64,
    ) -> Result<PendingKernelIntent, JournalError> {
        if !valid_token(command_id)
            || signed_jws.is_empty()
            || signed_jws.len() > MAX_JWS_BYTES
            || http_body.is_empty()
            || http_body.len() > MAX_BODY_BYTES
        {
            return Err(JournalError::InvalidIntent);
        }
        let digest = sha256_hex(signed_jws.as_bytes());
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, Vec<u8>, String, String, i64)> = tx
            .query_row(
                "SELECT path,http_body,signed_jws,intent_digest,created_at_ms FROM kernel_intents WHERE command_id=?1",
                [command_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let record = if let Some((old_path, old_body, old_jws, old_digest, created)) = existing {
            if old_path != path.as_str()
                || old_body != http_body
                || old_jws != signed_jws
                || old_digest != digest
            {
                return Err(JournalError::IntentConflict);
            }
            PendingKernelIntent {
                command_id: command_id.to_owned(),
                intent_digest: digest,
                created_at_ms: created,
            }
        } else {
            tx.execute(
                "INSERT INTO kernel_intents(command_id,path,signed_jws,intent_digest,http_body,state,created_at_ms) VALUES (?1,?2,?3,?4,?5,'PENDING',?6)",
                params![command_id, path.as_str(), signed_jws, digest, http_body, now],
            )?;
            PendingKernelIntent {
                command_id: command_id.to_owned(),
                intent_digest: digest,
                created_at_ms: now,
            }
        };
        tx.commit()?;
        Ok(record)
    }

    /// Import a quiesced TypeScript v1 SQLite store after the owning client
    /// has fetched discovery over its configured origin and pinned it here.
    /// The old store is never modified; a checked online backup remains at
    /// `backup_path`. A retry after interrupted native import is idempotent.
    pub(crate) fn import_ts_backup(
        &mut self,
        source_path: &Path,
        backup_path: &Path,
        trusted_local_key_ids: &[String],
        discovery: &ParsedDiscovery,
    ) -> Result<(usize, usize), crate::ts_migration::TsMigrationError> {
        use crate::ts_migration::TsMigrationError;
        if source_path == self._path
            || backup_path == self._path
            || std::fs::canonicalize(source_path)
                .ok()
                .zip(std::fs::canonicalize(&self._path).ok())
                .is_some_and(|(source, native)| source == native)
            || std::fs::canonicalize(backup_path)
                .ok()
                .zip(std::fs::canonicalize(&self._path).ok())
                .is_some_and(|(backup, native)| backup == native)
        {
            return Err(TsMigrationError::BackupConflict);
        }
        let rows = crate::ts_migration::backed_up_rows(
            source_path,
            backup_path,
            discovery,
            trusted_local_key_ids,
        )?;
        let source_ids: std::collections::HashSet<&str> =
            rows.iter().map(|row| row.command_id.as_str()).collect();
        for existing in self.all_prepared()? {
            if !source_ids.contains(existing.command_id.as_str()) {
                return Err(TsMigrationError::DestinationConflict);
            }
        }
        let mut pending = 0;
        let mut accepted = 0;
        for row in rows {
            let prepared =
                self.prepare_at_time(&row.command_id, row.path, &row.jws, &row.body, row.created)?;
            if prepared.created_at_ms != row.created {
                return Err(TsMigrationError::DestinationConflict);
            }
            let saved = self
                .verified_pending(
                    &row.command_id,
                    &row.local_key_id,
                    discovery.audience_utf16(),
                )?
                .ok_or(TsMigrationError::DestinationConflict)?;
            match row.response {
                Some(response) => {
                    let existing: Option<Vec<u8>> = self
                        .db
                        .query_row(
                            "SELECT response_wire FROM accepted_responses WHERE command_id=?1",
                            [&row.command_id],
                            |record| record.get(0),
                        )
                        .optional()?;
                    if existing.as_ref().is_some_and(|old| old != &response) {
                        return Err(TsMigrationError::DestinationConflict);
                    }
                    self.record_verified_response(
                        &saved,
                        &response,
                        discovery.receipt_public_key(),
                    )?;
                    accepted += 1;
                }
                None => {
                    if self
                        .accepted_response(&saved, discovery.receipt_public_key())?
                        .is_some()
                    {
                        return Err(TsMigrationError::DestinationConflict);
                    }
                    pending += 1;
                }
            }
        }
        Ok((pending, accepted))
    }

    /// The higher client re-verifies every accepted row before classifying
    /// operations; this raw prepared-row scan never declares acceptance.
    pub(crate) fn all_prepared(&self) -> Result<Vec<PendingKernelIntent>, JournalError> {
        let mut statement = self.db.prepare(
            "SELECT command_id,intent_digest,created_at_ms FROM kernel_intents ORDER BY created_at_ms,command_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(PendingKernelIntent {
                command_id: row.get(0)?,
                intent_digest: row.get(1)?,
                created_at_ms: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(JournalError::Storage)
    }

    /// Verify every saved row under its own signed public key before
    /// selecting operations for one locally configured identity. This keeps
    /// mixed-actor migrated stores usable without exposing other actors'
    /// operation IDs through an actor-specific listing.
    pub(crate) fn all_prepared_for_key(
        &self,
        local_key_id: &str,
        audience_utf16: &[u16],
    ) -> Result<Vec<PendingKernelIntent>, JournalError> {
        let mut selected = Vec::new();
        for row in self.all_prepared()? {
            let jws: String = self.db.query_row(
                "SELECT signed_jws FROM kernel_intents WHERE command_id=?1",
                [&row.command_id],
                |record| record.get(0),
            )?;
            let signer = signer_key_id(&jws).ok_or(JournalError::IncompatibleStore)?;
            self.verified_pending(&row.command_id, &signer, audience_utf16)?
                .ok_or(JournalError::IncompatibleStore)?;
            if signer == local_key_id {
                selected.push(row);
            }
        }
        Ok(selected)
    }

    /// Pin the schema-validated response returned by this runtime's configured
    /// HTTPS origin. Only the owning client calls this with its transport's
    /// actual origin; arbitrary public callers cannot authorize a pin.
    pub(crate) fn bind_discovery(
        &mut self,
        origin: &str,
        discovered: &ParsedDiscovery,
    ) -> Result<(), JournalError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT origin,discovery_wire FROM pinned_discovery WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((previous_origin, previous_wire)) = previous {
            let parsed = parse_discovery_wire(&previous_wire, 256 * 1024)
                .map_err(|_| JournalError::IncompatibleStore)?;
            if previous_origin != origin || !discovered.permits_update_from(&parsed) {
                return Err(JournalError::DiscoveryChanged);
            }
            if previous_wire != discovered.raw_wire() {
                tx.execute(
                    "UPDATE pinned_discovery SET discovery_wire=?1 WHERE id=1",
                    [discovered.raw_wire()],
                )?;
            }
        } else {
            tx.execute(
                "INSERT INTO pinned_discovery(id,origin,discovery_wire) VALUES (1,?1,?2)",
                params![origin, discovered.raw_wire()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn verified_pending(
        &self,
        command_id: &str,
        local_key_id: &str,
        audience_utf16: &[u16],
    ) -> Result<Option<VerifiedPendingCommand>, JournalError> {
        if !valid_token(command_id) {
            return Err(JournalError::InvalidIntent);
        }
        let row: Option<(String, String, String, Vec<u8>, String)> = self
            .db
            .query_row(
                "SELECT path,signed_jws,intent_digest,http_body,state FROM kernel_intents WHERE command_id=?1",
                [command_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let Some((path, jws, digest, body, state)) = row else {
            return Ok(None);
        };
        let proof = verify_prepared_command_wire(
            &jws,
            &body,
            &CommandPins {
                local_key_id,
                audience_utf16,
            },
        )
        .map_err(|_| JournalError::IncompatibleStore)?;
        if state != "PENDING"
            || proof.command_id() != command_id
            || proof.path() != path
            || proof.intent_digest() != digest
            || sha256_hex(jws.as_bytes()) != digest
        {
            return Err(JournalError::IncompatibleStore);
        }
        Ok(Some(VerifiedPendingCommand { proof, jws, body }))
    }

    pub(crate) fn accepted_response(
        &self,
        saved: &VerifiedPendingCommand,
        receipt_key: &str,
    ) -> Result<Option<VerifiedCommandResponse>, JournalError> {
        let wire: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT response_wire FROM accepted_responses WHERE command_id=?1",
                [saved.proof.command_id()],
                |row| row.get(0),
            )
            .optional()?;
        wire.map(|wire| {
            verify_http_response_for_prepared(&wire, &saved.proof, receipt_key)
                .map_err(|_| JournalError::IncompatibleStore)
        })
        .transpose()
    }

    pub(crate) fn record_verified_response(
        &mut self,
        saved: &VerifiedPendingCommand,
        response_wire: &[u8],
        receipt_key: &str,
    ) -> Result<VerifiedCommandResponse, JournalError> {
        let verified = verify_http_response_for_prepared(response_wire, &saved.proof, receipt_key)
            .map_err(|_| JournalError::InvalidReceipt)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, String, String, Vec<u8>, String)> = tx
            .query_row(
                "SELECT path,signed_jws,intent_digest,http_body,state FROM kernel_intents WHERE command_id=?1",
                [saved.proof.command_id()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        if !row.is_some_and(|(path, jws, digest, body, state)| {
            state == "PENDING"
                && path == saved.proof.path()
                && jws == saved.jws
                && digest == saved.proof.intent_digest()
                && body == saved.body
        }) {
            return Err(JournalError::IncompatibleStore);
        }
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT response_wire FROM accepted_responses WHERE command_id=?1",
                [saved.proof.command_id()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return verify_http_response_for_prepared(&existing, &saved.proof, receipt_key)
                .map_err(|_| JournalError::IncompatibleStore);
        }
        tx.execute(
            "INSERT INTO accepted_responses(command_id,response_wire) VALUES (?1,?2)",
            params![saved.proof.command_id(), response_wire],
        )?;
        tx.commit()?;
        Ok(verified)
    }

    #[cfg(test)]
    pub(crate) fn exact_request_for_test(
        &self,
        command_id: &str,
    ) -> Result<Option<(String, Vec<u8>)>, JournalError> {
        self.db
            .query_row(
                "SELECT signed_jws,http_body FROM kernel_intents WHERE command_id=?1",
                [command_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(JournalError::Storage)
    }
}

fn set_wal_with_retry(db: &Connection) -> Result<(), JournalError> {
    // Two independent processes may initialize the same new DB and race at
    // the journal-mode transition after their short schema transactions.
    // SQLite's busy timeout does not cover every WAL mode-change conflict.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match db.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(rusqlite::Error::SqliteFailure(code, _))
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(JournalError::Storage(error)),
        }
    }
}

fn initialize(db: &mut Connection) -> Result<(), JournalError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let app: i64 = tx.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let objects: Vec<(String, String, String)> = tx
        .prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    if app == 0 && version == 0 && objects.is_empty() {
        tx.execute_batch(&format!(
            "{SCHEMA_SQL}; {CONTEXT_SQL}; {ACCEPTED_SQL}; PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={SCHEMA_VERSION};"
        ))?;
    } else if app != APPLICATION_ID {
        return Err(JournalError::IncompatibleStore);
    } else if version == 1 {
        // A native v1 store holds only immutable PENDING commands. Refuse any
        // weakened schema before adding the new discovery-continuity table.
        if objects != [("table".into(), "kernel_intents".into(), SCHEMA_SQL.into())] {
            return Err(JournalError::IncompatibleStore);
        }
        let check: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if check != "ok" {
            return Err(JournalError::IncompatibleStore);
        }
        tx.execute_batch(&format!(
            "{CONTEXT_SQL}; {ACCEPTED_SQL}; PRAGMA user_version={SCHEMA_VERSION};"
        ))?;
    } else if version == 2 {
        if objects
            != [
                ("table".into(), "kernel_intents".into(), SCHEMA_SQL.into()),
                (
                    "table".into(),
                    "pinned_discovery".into(),
                    CONTEXT_SQL.into(),
                ),
            ]
        {
            return Err(JournalError::IncompatibleStore);
        }
        let check: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if check != "ok" {
            return Err(JournalError::IncompatibleStore);
        }
        tx.execute_batch(&format!(
            "{ACCEPTED_SQL}; PRAGMA user_version={SCHEMA_VERSION};"
        ))?;
    } else if version != SCHEMA_VERSION {
        return Err(JournalError::IncompatibleStore);
    }
    let objects: Vec<(String, String, String)> = tx
        .prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    if objects
        != [
            (
                "table".into(),
                "accepted_responses".into(),
                ACCEPTED_SQL.into(),
            ),
            ("table".into(), "kernel_intents".into(), SCHEMA_SQL.into()),
            (
                "table".into(),
                "pinned_discovery".into(),
                CONTEXT_SQL.into(),
            ),
        ]
    {
        return Err(JournalError::IncompatibleStore);
    }
    let columns: Vec<String> = tx
        .prepare("PRAGMA table_info(kernel_intents)")?
        .query_map([], |row| row.get(1))?
        .collect::<Result<_, _>>()?;
    if columns
        != [
            "command_id",
            "path",
            "signed_jws",
            "intent_digest",
            "http_body",
            "state",
            "created_at_ms",
        ]
    {
        return Err(JournalError::IncompatibleStore);
    }
    let context_columns: Vec<String> = tx
        .prepare("PRAGMA table_info(pinned_discovery)")?
        .query_map([], |row| row.get(1))?
        .collect::<Result<_, _>>()?;
    if context_columns != ["id", "origin", "discovery_wire"] {
        return Err(JournalError::IncompatibleStore);
    }
    let accepted_columns: Vec<String> = tx
        .prepare("PRAGMA table_info(accepted_responses)")?
        .query_map([], |row| row.get(1))?
        .collect::<Result<_, _>>()?;
    if accepted_columns != ["command_id", "response_wire"] {
        return Err(JournalError::IncompatibleStore);
    }
    let check: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
        return Err(JournalError::IncompatibleStore);
    }
    let foreign_key_error: Option<String> = tx
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    if foreign_key_error.is_some() {
        return Err(JournalError::IncompatibleStore);
    }
    tx.commit()?;
    Ok(())
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn signer_key_id(jws: &str) -> Option<String> {
    use peerwork_core::{crypto::decode_base64url, wire_json::parse_wire_json_bounded};
    if jws.len() > MAX_JWS_BYTES {
        return None;
    }
    let mut parts = jws.split('.');
    let header = parts.next()?;
    parts.next()?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let bytes = decode_base64url(header).ok()?;
    let value = parse_wire_json_bounded(&bytes, 3, 256).ok()?;
    let kid = value.get("kid")?.as_string()?;
    valid_token(&kid).then_some(kid)
}

fn unix_millis() -> Result<i64, JournalError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalError::InvalidIntent)?;
    i64::try_from(duration.as_millis()).map_err(|_| JournalError::InvalidIntent)
}

#[cfg(unix)]
fn ensure_private_parent(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(JournalError::Protection);
    }
    let parent = path.parent().ok_or(JournalError::Protection)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| JournalError::Protection)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
        || fs::canonicalize(parent).map_err(|_| JournalError::Protection)? != parent
    {
        return Err(JournalError::Protection);
    }
    Ok(())
}

#[cfg(unix)]
fn create_or_check_private_file(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => drop(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let meta = fs::symlink_metadata(path).map_err(|_| JournalError::Protection)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
    {
        return Err(JournalError::Protection);
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_private_parent(path: &Path) -> Result<(), JournalError> {
    crate::windows_fs::private_parent(path).map_err(|_| JournalError::Protection)
}

#[cfg(windows)]
fn create_or_check_private_file(path: &Path) -> Result<(), JournalError> {
    crate::windows_fs::create_or_check_file(path).map_err(|_| JournalError::Protection)
}

#[cfg(windows)]
fn check_private_sidecars(path: &Path) -> Result<(), JournalError> {
    use std::ffi::OsString;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        crate::windows_fs::private_file_if_exists(Path::new(&name))
            .map_err(|_| JournalError::Protection)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_private_parent(_: &Path) -> Result<(), JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(not(any(unix, windows)))]
fn create_or_check_private_file(_: &Path) -> Result<(), JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use peerwork_core::{
        canonical::{canonical, Path as CanonicalPath},
        crypto::{actor_id, base64url, key_id},
    };
    use serde_json::json;
    use tempfile::TempDir;

    #[cfg(windows)]
    #[test]
    fn windows_private_journal_reopens_exact_pending_row() {
        let outer = tempfile::tempdir().unwrap();
        let state_dir = outer.path().join("state");
        crate::windows_fs::create_private_directory(&state_dir).unwrap();
        let path = state_dir.join("intents.sqlite");
        let id = "W".repeat(43);
        {
            let mut journal = KernelIntentJournal::open(&path).unwrap();
            journal
                .prepare(
                    &id,
                    KernelPath::Command,
                    "signed.header.payload",
                    b"{\"jws\":\"\\ud800\"}",
                )
                .unwrap();
        }
        let reopened = KernelIntentJournal::open(&path).unwrap();
        assert_eq!(
            reopened.exact_request_for_test(&id).unwrap(),
            Some((
                "signed.header.payload".into(),
                b"{\"jws\":\"\\ud800\"}".to_vec()
            ))
        );
    }

    #[cfg(unix)]
    fn private_dir() -> TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn exact_bytes_survive_restart_and_conflict_cannot_replace_them() {
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        let id = "A".repeat(43);
        let first = {
            let mut journal = KernelIntentJournal::open(&path).unwrap();
            let first = journal
                .prepare(
                    &id,
                    KernelPath::Command,
                    "signed.header.payload",
                    b"{\"jws\":\"one\"}",
                )
                .unwrap();
            assert_eq!(journal.all_prepared().unwrap(), vec![first.clone()]);
            first
        };
        let mut reopened = KernelIntentJournal::open(&path).unwrap();
        assert_eq!(reopened.all_prepared().unwrap(), vec![first.clone()]);
        assert_eq!(
            reopened.exact_request_for_test(&id).unwrap(),
            Some((
                "signed.header.payload".into(),
                b"{\"jws\":\"one\"}".to_vec()
            ))
        );
        assert_eq!(
            reopened
                .prepare(
                    &id,
                    KernelPath::Command,
                    "signed.header.payload",
                    b"{\"jws\":\"one\"}"
                )
                .unwrap(),
            first
        );
        assert!(matches!(
            reopened.prepare(
                &id,
                KernelPath::Command,
                "signed.header.payload",
                b"{\"jws\":\"two\"}"
            ),
            Err(JournalError::IntentConflict)
        ));
        assert_eq!(reopened.all_prepared().unwrap(), vec![first]);
    }

    #[cfg(unix)]
    #[test]
    fn exact_native_v1_pending_row_migrates_atomically_to_response_schema() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        let id = "M".repeat(43);
        let body = b"{\"jws\":\"\\ud800\"}";
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(&format!(
                "{SCHEMA_SQL}; PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=1;"
            ))
            .unwrap();
            db.execute(
                "INSERT INTO kernel_intents(command_id,path,signed_jws,intent_digest,http_body,state,created_at_ms) VALUES (?1,?2,?3,?4,?5,'PENDING',123)",
                params![id, KernelPath::Command.as_str(), "signed.header.payload", sha256_hex(b"signed.header.payload"), body],
            ).unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let journal = KernelIntentJournal::open(&path).unwrap();
        assert_eq!(journal.all_prepared().unwrap().len(), 1);
        assert_eq!(
            journal.exact_request_for_test(&id).unwrap(),
            Some(("signed.header.payload".into(), body.to_vec()))
        );
        let version: i64 = journal
            .db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
        let context_rows: i64 = journal
            .db
            .query_row("SELECT count(*) FROM pinned_discovery", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(context_rows, 0);
        let accepted_rows: i64 = journal
            .db
            .query_row("SELECT count(*) FROM accepted_responses", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(accepted_rows, 0);
        drop(journal);
        let reopened = KernelIntentJournal::open(&path).unwrap();
        assert_eq!(
            reopened.exact_request_for_test(&id).unwrap().unwrap().1,
            body
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_native_v2_discovery_pin_survives_response_schema_migration() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        let discovery = b"{\"audience\":\"\\ud800\"}";
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(&format!(
                "{SCHEMA_SQL}; {CONTEXT_SQL}; PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=2;"
            ))
            .unwrap();
            db.execute(
                "INSERT INTO pinned_discovery(id,origin,discovery_wire) VALUES (1,?1,?2)",
                params!["https://workspace.example/", discovery],
            )
            .unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let journal = KernelIntentJournal::open(&path).unwrap();
        let stored: Vec<u8> = journal
            .db
            .query_row(
                "SELECT discovery_wire FROM pinned_discovery WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, discovery);
        let version: i64 = journal
            .db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
        drop(journal);
        KernelIntentJournal::open(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn orphan_accepted_response_is_refused_before_listing() {
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        drop(KernelIntentJournal::open(&path).unwrap());
        {
            // A separate SQLite writer with foreign-key enforcement disabled
            // can leave a structurally valid but orphaned acceptance record.
            let db = Connection::open(&path).unwrap();
            db.pragma_update(None, "foreign_keys", "OFF").unwrap();
            db.execute(
                "INSERT INTO accepted_responses(command_id,response_wire) VALUES (?1,?2)",
                params!["O".repeat(43), b"{}"],
            )
            .unwrap();
        }
        assert!(matches!(
            KernelIntentJournal::open(&path),
            Err(JournalError::IncompatibleStore)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn exact_saved_row_requires_core_command_proof_and_matching_pins() {
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        let signing = SigningKey::from_bytes(&[21; 32]);
        let public = signing.verifying_key().to_bytes();
        let kid = key_id(&public);
        let actor = actor_id(&public);
        let command_id = key_id(&[23; 32]);
        let audience: Vec<u16> = "https://workspace.example".encode_utf16().collect();
        let header = canonical(
            &json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid}),
            CanonicalPath::SecureArtifact,
        )
        .unwrap();
        let command = json!({
            "v":1,"audience":"https://workspace.example","command_id":command_id,
            "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
            "path":"/api/workspace/v1/commands","workspace_id":null,"instance_id":null,
            "protocol_digest":null,"action_id":"catalog.namespace.claim",
            "expected_workspace_revision":null,"expected_instance_revision":null,
            "exact_input_refs":[],"body":{"namespace":actor},"issued_at":1,"expires_at":600001
        });
        let payload = canonical(&command, CanonicalPath::COMMAND).unwrap();
        let input = format!(
            "{}.{}",
            base64url(header.as_bytes()),
            base64url(payload.as_bytes())
        );
        let jws = format!(
            "{}.{}",
            input,
            base64url(&signing.sign(input.as_bytes()).to_bytes())
        );
        let body = canonical(&json!({"jws":jws}), CanonicalPath::COMMAND).unwrap();

        let mut journal = KernelIntentJournal::open(&path).unwrap();
        journal
            .prepare(&command_id, KernelPath::Command, &jws, body.as_bytes())
            .unwrap();
        let pending = journal
            .verified_pending(&command_id, &kid, &audience)
            .unwrap()
            .unwrap();
        assert_eq!(pending.proof.command_id(), command_id);
        assert_eq!(pending.body, body.as_bytes());
        assert!(matches!(
            journal.verified_pending(&command_id, &key_id(&[24; 32]), &audience),
            Err(JournalError::IncompatibleStore)
        ));
        journal
            .db
            .execute(
                "UPDATE kernel_intents SET intent_digest=?1 WHERE command_id=?2",
                params!["0".repeat(64), command_id],
            )
            .unwrap();
        assert!(matches!(
            journal.verified_pending(&command_id, &kid, &audience),
            Err(JournalError::IncompatibleStore)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_old_store_and_unprotected_paths() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        {
            let db = Connection::open(&path).unwrap();
            db.pragma_update(None, "application_id", 1347896113)
                .unwrap();
            db.pragma_update(None, "user_version", 1).unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            KernelIntentJournal::open(&path),
            Err(JournalError::IncompatibleStore)
        ));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            KernelIntentJournal::open(&path),
            Err(JournalError::Protection)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn expected_ids_and_columns_do_not_authorize_weakened_schema() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE kernel_intents(command_id TEXT NOT NULL,path TEXT NOT NULL,signed_jws TEXT NOT NULL,intent_digest TEXT NOT NULL,http_body BLOB NOT NULL,state TEXT NOT NULL,created_at_ms INTEGER NOT NULL);
                 PRAGMA application_id=1347900228; PRAGMA user_version=1;",
            )
            .unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            KernelIntentJournal::open(&path),
            Err(JournalError::IncompatibleStore)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn wal_transition_waits_for_a_bounded_reader() {
        use std::sync::mpsc;
        let dir = private_dir();
        let path = dir.path().join("wal-race.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE sample(value INTEGER);")
            .unwrap();
        db.busy_timeout(Duration::from_millis(20)).unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            let reader = Connection::open(worker_path).unwrap();
            reader
                .execute_batch("BEGIN; SELECT value FROM sample;")
                .unwrap();
            sender.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(150));
            reader.execute_batch("COMMIT;").unwrap();
        });
        receiver.recv().unwrap();
        set_wal_with_retry(&db).unwrap();
        worker.join().unwrap();
        let mode: String = db
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[cfg(unix)]
    #[test]
    fn child_prepare_worker() {
        let Ok(path) = std::env::var("PEERWORK_TEST_JOURNAL_PATH") else {
            return;
        };
        let variant = std::env::var("PEERWORK_TEST_VARIANT").unwrap();
        let mut journal = KernelIntentJournal::open(Path::new(&path)).unwrap();
        let id = "B".repeat(43);
        let jws = format!("signed.header.{variant}");
        let body = format!("{{\"variant\":\"{variant}\"}}");
        match journal.prepare(&id, KernelPath::Command, &jws, body.as_bytes()) {
            Ok(_) => println!("PEERWORK_WORKER_PREPARED"),
            Err(JournalError::IntentConflict) => println!("PEERWORK_WORKER_CONFLICT"),
            Err(error) => panic!("unexpected worker store error: {error}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn cross_process_same_id_race_keeps_one_exact_packet() {
        use std::process::{Command, Stdio};
        let dir = private_dir();
        let path = dir.path().join("intents.sqlite");
        let executable = std::env::current_exe().unwrap();
        let spawn = |variant| {
            Command::new(&executable)
                .args([
                    "--exact",
                    "kernel_intents::tests::child_prepare_worker",
                    "--nocapture",
                ])
                .env("PEERWORK_TEST_JOURNAL_PATH", &path)
                .env("PEERWORK_TEST_VARIANT", variant)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let first = spawn("one");
        let second = spawn("two");
        let outputs = [
            first.wait_with_output().unwrap(),
            second.wait_with_output().unwrap(),
        ];
        let output = outputs
            .iter()
            .map(|result| {
                format!(
                    "stdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                )
            })
            .collect::<Vec<_>>();
        assert!(
            outputs.iter().all(|result| result.status.success()),
            "{output:?}"
        );
        assert_eq!(
            output
                .iter()
                .filter(|text| text.contains("PEERWORK_WORKER_PREPARED"))
                .count(),
            1,
            "{output:?}"
        );
        assert_eq!(
            output
                .iter()
                .filter(|text| text.contains("PEERWORK_WORKER_CONFLICT"))
                .count(),
            1,
            "{output:?}"
        );
        let journal = KernelIntentJournal::open(&path).unwrap();
        let id = "B".repeat(43);
        assert_eq!(journal.all_prepared().unwrap().len(), 1);
        let (jws, body) = journal.exact_request_for_test(&id).unwrap().unwrap();
        assert!(matches!(
            jws.as_str(),
            "signed.header.one" | "signed.header.two"
        ));
        assert_eq!(
            body,
            format!("{{\"variant\":\"{}\"}}", jws.rsplit('.').next().unwrap()).as_bytes()
        );
    }
}
