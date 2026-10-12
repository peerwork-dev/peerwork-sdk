//! Exact, durable local kernel command journal. A pending record is never
//! inferred accepted from an HTTP status or a missing response.

use peerwork_core::crypto::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const APPLICATION_ID: i64 = 0x5057_5344; // PWSD; intentionally distinct from TS PWC1.
const SCHEMA_VERSION: i64 = 1;
const MAX_BODY_BYTES: usize = 1_048_576;
const MAX_JWS_BYTES: usize = 250_000;

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

/// The only supported kernel POST paths at this checkpoint. This is local
/// preparation, not authorization to transmit the signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPath {
    Command,
    CatalogUpload,
}

impl KernelPath {
    fn as_str(self) -> &'static str {
        match self {
            Self::Command => "/api/workspace/v1/commands",
            Self::CatalogUpload => "/api/workspace/v1/catalog/upload",
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
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        initialize(&mut db)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
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
        if !valid_token(command_id)
            || signed_jws.is_empty()
            || signed_jws.len() > MAX_JWS_BYTES
            || http_body.is_empty()
            || http_body.len() > MAX_BODY_BYTES
        {
            return Err(JournalError::InvalidIntent);
        }
        let digest = sha256_hex(signed_jws.as_bytes());
        let now = unix_millis()?;
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

    /// Redacted view. No private signed request or raw packet leaves the store.
    pub fn pending(&self) -> Result<Vec<PendingKernelIntent>, JournalError> {
        let mut statement = self.db.prepare(
            "SELECT command_id,intent_digest,created_at_ms FROM kernel_intents WHERE state='PENDING' ORDER BY created_at_ms,command_id",
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

    #[cfg(test)]
    fn exact_request_for_test(
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

fn initialize(db: &mut Connection) -> Result<(), JournalError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let app: i64 = tx.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let tables: Vec<String> = tx
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if app == 0 && version == 0 && tables.is_empty() {
        tx.execute_batch(
            "CREATE TABLE kernel_intents(
                 command_id TEXT PRIMARY KEY NOT NULL,
                 path TEXT NOT NULL,
                 signed_jws TEXT NOT NULL,
                 intent_digest TEXT NOT NULL,
                 http_body BLOB NOT NULL,
                 state TEXT NOT NULL CHECK(state='PENDING'),
                 created_at_ms INTEGER NOT NULL
             );
             PRAGMA application_id=1347900228;
             PRAGMA user_version=1;",
        )?;
    } else if app != APPLICATION_ID || version != SCHEMA_VERSION || tables != ["kernel_intents"] {
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
    let check: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
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

#[cfg(not(unix))]
fn ensure_private_parent(_: &Path) -> Result<(), JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn create_or_check_private_file(_: &Path) -> Result<(), JournalError> {
    Err(JournalError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
            assert_eq!(journal.pending().unwrap(), vec![first.clone()]);
            first
        };
        let mut reopened = KernelIntentJournal::open(&path).unwrap();
        assert_eq!(reopened.pending().unwrap(), vec![first.clone()]);
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
        assert_eq!(reopened.pending().unwrap(), vec![first]);
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
            .map(|result| String::from_utf8_lossy(&result.stdout).to_string())
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
        assert_eq!(journal.pending().unwrap().len(), 1);
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
