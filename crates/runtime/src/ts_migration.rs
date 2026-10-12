//! Read-only TypeScript WorkspaceClient v1 snapshot and online backup.
//! The caller must quiesce its old client before import. We never open the
//! source with write flags or mutate it in place.

use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{decode_base64url, sha256_hex},
    discovery::ParsedDiscovery,
    prepared_command::{verify_prepared_command_wire, CommandPins},
    receipt_wire::verify_http_response_for_prepared,
    wire_json::{canonical_wire_json, canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use std::fs::{self, File};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

const TS_APPLICATION_ID: i64 = 0x5057_4331; // PWC1.
const MAX_ROWS: usize = 100_000;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const CONTEXT_SQL: &str =
    "CREATE TABLE client_context(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)";
const INTENTS_SQL: &str = "CREATE TABLE client_intents(command_id TEXT PRIMARY KEY,jws TEXT NOT NULL,intent_digest TEXT NOT NULL,command TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('PENDING','ACCEPTED')),response TEXT,created INTEGER NOT NULL,updated INTEGER NOT NULL)";

#[derive(Debug, Error)]
pub enum TsMigrationError {
    #[error("TypeScript source or backup schema, rows, or pins are incompatible")]
    Incompatible,
    #[error("TypeScript operation signer {0} is not in the trusted public-key allowlist")]
    MissingSigner(String),
    #[error("backup path and source path conflict")]
    BackupConflict,
    #[error("TypeScript migration exceeds bounded snapshot size")]
    TooLarge,
    #[error("TypeScript source or backup is not privately stored")]
    Protection,
    #[error("native destination contains unrelated or conflicting operations")]
    DestinationConflict,
    #[error("local backup or readback failed")]
    Io(#[from] std::io::Error),
    #[error("SQLite backup or readback failed")]
    Sqlite(#[from] rusqlite::Error),
    #[error("native journal import failed")]
    Journal(#[from] crate::kernel_intents::JournalError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TsStoredRow {
    command_id: String,
    jws: String,
    intent_digest: String,
    command: String,
    status: String,
    response: Option<String>,
    created: i64,
    updated: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TsSnapshot {
    context: String,
    rows: Vec<TsStoredRow>,
}

pub(crate) struct TsImportRow {
    pub command_id: String,
    pub local_key_id: String,
    pub jws: String,
    pub body: Vec<u8>,
    pub path: crate::kernel_intents::KernelPath,
    pub response: Option<Vec<u8>>,
    pub created: i64,
}

pub(crate) fn backed_up_rows(
    source_path: &Path,
    backup_path: &Path,
    discovery: &ParsedDiscovery,
    trusted_local_key_ids: &[String],
) -> Result<Vec<TsImportRow>, TsMigrationError> {
    if source_path == backup_path || !source_path.is_absolute() || !backup_path.is_absolute() {
        return Err(TsMigrationError::BackupConflict);
    }
    check_source(source_path)?;
    check_sidecars(source_path)?;
    check_backup_parent(backup_path)?;
    if fs::canonicalize(source_path).ok() == fs::canonicalize(backup_path).ok()
        && fs::canonicalize(source_path).is_ok()
    {
        return Err(TsMigrationError::BackupConflict);
    }
    let source = Connection::open_with_flags(source_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    source.busy_timeout(Duration::from_secs(5))?;
    let before = read_snapshot(&source)?;
    let backup_exists = match fs::symlink_metadata(backup_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(TsMigrationError::Io(error)),
    };
    if !backup_exists {
        create_backup_file(backup_path)?;
        let copied = (|| -> Result<(), TsMigrationError> {
            let mut backup = Connection::open(backup_path)?;
            let copy = Backup::new(&source, &mut backup)?;
            copy.run_to_completion(100, Duration::from_millis(50), None)?;
            drop(copy);
            drop(backup);
            File::open(backup_path)?.sync_all()?;
            #[cfg(unix)]
            File::open(backup_path.parent().ok_or(TsMigrationError::Protection)?)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = copied {
            // A backup we just created is not a resumable snapshot. Remove
            // that incomplete artifact so a retry can take a fresh one.
            fs::remove_file(backup_path)?;
            return Err(error);
        }
    }
    check_backup_file(backup_path)?;
    check_sidecars(backup_path)?;
    let backup = Connection::open_with_flags(backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let saved = read_snapshot(&backup)?;
    let after = read_snapshot(&source)?;
    check_sidecars(source_path)?;
    check_sidecars(backup_path)?;
    if before != saved || before != after {
        return Err(TsMigrationError::Incompatible);
    }
    let old_context = peerwork_core::discovery::parse_discovery_wire(
        saved.context.as_bytes(),
        crate::transport::MAX_DISCOVERY_BYTES,
    )
    .map_err(|_| TsMigrationError::Incompatible)?;
    if !discovery.permits_update_from(&old_context) {
        return Err(TsMigrationError::Incompatible);
    }
    saved
        .rows
        .iter()
        .map(|row| prepare_row(row, discovery, trusted_local_key_ids))
        .collect()
}

fn read_snapshot(db: &Connection) -> Result<TsSnapshot, TsMigrationError> {
    let app: i64 = db.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if app != TS_APPLICATION_ID || version != 1 {
        return Err(TsMigrationError::Incompatible);
    }
    let objects: Vec<(String, String, String)> = db
        .prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    if objects
        != [
            ("table".into(), "client_context".into(), CONTEXT_SQL.into()),
            ("table".into(), "client_intents".into(), INTENTS_SQL.into()),
        ]
    {
        return Err(TsMigrationError::Incompatible);
    }
    let check: String = db.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
        return Err(TsMigrationError::Incompatible);
    }
    let contexts: Vec<(i64, String)> = db
        .prepare("SELECT id,value FROM client_context")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let [(1, context)] = contexts.as_slice() else {
        return Err(TsMigrationError::Incompatible);
    };
    let count: i64 = db.query_row("SELECT count(*) FROM client_intents", [], |row| row.get(0))?;
    if count < 0 || count as usize > MAX_ROWS {
        return Err(TsMigrationError::TooLarge);
    }
    let mut rows = Vec::with_capacity(count as usize);
    let mut total = context.len();
    let mut statement = db.prepare("SELECT command_id,jws,intent_digest,command,status,response,created,updated FROM client_intents ORDER BY created,command_id")?;
    let iterator = statement.query_map([], |row| {
        Ok(TsStoredRow {
            command_id: row.get(0)?,
            jws: row.get(1)?,
            intent_digest: row.get(2)?,
            command: row.get(3)?,
            status: row.get(4)?,
            response: row.get(5)?,
            created: row.get(6)?,
            updated: row.get(7)?,
        })
    })?;
    for row in iterator {
        let row = row?;
        total = total.saturating_add(
            row.command_id.len()
                + row.jws.len()
                + row.intent_digest.len()
                + row.command.len()
                + row.status.len()
                + row.response.as_ref().map_or(0, String::len),
        );
        if total > MAX_TOTAL_BYTES {
            return Err(TsMigrationError::TooLarge);
        }
        rows.push(row);
    }
    Ok(TsSnapshot {
        context: context.clone(),
        rows,
    })
}

fn prepare_row(
    row: &TsStoredRow,
    discovery: &ParsedDiscovery,
    trusted_local_key_ids: &[String],
) -> Result<TsImportRow, TsMigrationError> {
    let invalid = || TsMigrationError::Incompatible;
    if row.created < 0
        || row.updated < row.created
        || row.updated > 9_007_199_254_740_991
        || row.intent_digest != sha256_hex(row.jws.as_bytes())
        || !row
            .jws
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(invalid());
    }
    let mut parts = row.jws.split('.');
    let header_part = parts.next().ok_or_else(invalid)?;
    let payload = parts.next().ok_or_else(invalid)?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(invalid());
    }
    let header_bytes = decode_base64url(header_part).map_err(|_| invalid())?;
    let header = parse_wire_json_bounded(&header_bytes, 3, 256).map_err(|_| invalid())?;
    let local_key_id = header
        .get("kid")
        .and_then(WireValue::as_string)
        .ok_or_else(invalid)?;
    if local_key_id.len() != 43
        || !local_key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid());
    }
    if !trusted_local_key_ids.iter().any(|key| key == &local_key_id) {
        return Err(TsMigrationError::MissingSigner(format!(
            "{}…{}",
            &local_key_id[..8],
            &local_key_id[35..]
        )));
    }
    let command_bytes = decode_base64url(payload).map_err(|_| invalid())?;
    let stored =
        parse_wire_json_bounded(row.command.as_bytes(), 42, 262_144).map_err(|_| invalid())?;
    let (command, chunk) = match &stored {
        WireValue::Object(fields)
            if fields.len() == 2
                && stored.get("command").is_some()
                && stored.get("upload_chunk").is_some() =>
        {
            (
                stored.get("command").ok_or_else(invalid)?,
                Some(
                    stored
                        .get("upload_chunk")
                        .and_then(WireValue::as_string)
                        .ok_or_else(invalid)?,
                ),
            )
        }
        _ => (&stored, None),
    };
    if canonical_wire_value(command, CanonicalPath::COMMAND)
        .map_err(|_| invalid())?
        .as_bytes()
        != command_bytes
        || canonical_wire_value(&stored, CanonicalPath::Kernel { max_depth: 42 })
            .map_err(|_| invalid())?
            != row.command
    {
        return Err(invalid());
    }
    let body = if let Some(chunk) = chunk.as_ref() {
        if !chunk
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid());
        }
        format!(
            "{{\"chunk\":\"{chunk}\",\"command\":{{\"jws\":\"{}\"}}}}",
            row.jws
        )
        .into_bytes()
    } else {
        format!("{{\"jws\":\"{}\"}}", row.jws).into_bytes()
    };
    let proof = verify_prepared_command_wire(
        &row.jws,
        &body,
        &CommandPins {
            local_key_id: &local_key_id,
            audience_utf16: discovery.audience_utf16(),
        },
    )
    .map_err(|_| invalid())?;
    if proof.command_id() != row.command_id {
        return Err(invalid());
    }
    let path = match proof.path() {
        "/api/workspace/v1/commands" if chunk.is_none() => {
            crate::kernel_intents::KernelPath::Command
        }
        "/api/workspace/v1/catalog/upload" if chunk.is_some() => {
            crate::kernel_intents::KernelPath::CatalogUpload
        }
        _ => return Err(invalid()),
    };
    let response = match (row.status.as_str(), row.response.as_ref()) {
        ("PENDING", None) => None,
        ("ACCEPTED", Some(response)) => {
            if canonical_wire_json(response.as_bytes(), CanonicalPath::RESPONSE)
                .map_err(|_| invalid())?
                != *response
            {
                return Err(invalid());
            }
            verify_http_response_for_prepared(
                response.as_bytes(),
                &proof,
                discovery.receipt_public_key(),
            )
            .map_err(|_| invalid())?;
            Some(response.as_bytes().to_vec())
        }
        _ => return Err(invalid()),
    };
    Ok(TsImportRow {
        command_id: row.command_id.clone(),
        local_key_id,
        jws: row.jws.clone(),
        body,
        path,
        response,
        created: row.created,
    })
}

#[cfg(unix)]
fn check_source(path: &Path) -> Result<(), TsMigrationError> {
    use std::os::unix::fs::MetadataExt;
    let parent = path.parent().ok_or(TsMigrationError::Protection)?;
    let dir = fs::symlink_metadata(parent).map_err(|_| TsMigrationError::Protection)?;
    let file = fs::symlink_metadata(path).map_err(|_| TsMigrationError::Protection)?;
    if !dir.is_dir()
        || dir.file_type().is_symlink()
        || dir.mode() & 0o077 != 0
        || dir.uid() != unsafe { libc::geteuid() }
        || fs::canonicalize(parent).map_err(|_| TsMigrationError::Protection)? != parent
        || !file.is_file()
        || file.file_type().is_symlink()
        || file.nlink() != 1
        || file.uid() != unsafe { libc::geteuid() }
    {
        return Err(TsMigrationError::Protection);
    }
    Ok(())
}

#[cfg(windows)]
fn check_source(path: &Path) -> Result<(), TsMigrationError> {
    crate::windows_fs::private_parent(path).map_err(|_| TsMigrationError::Protection)?;
    crate::windows_fs::private_file(path).map_err(|_| TsMigrationError::Protection)
}

#[cfg(not(any(unix, windows)))]
fn check_source(_: &Path) -> Result<(), TsMigrationError> {
    Err(TsMigrationError::Protection)
}

fn check_backup_parent(path: &Path) -> Result<(), TsMigrationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent = path.parent().ok_or(TsMigrationError::Protection)?;
        let dir = fs::symlink_metadata(parent).map_err(|_| TsMigrationError::Protection)?;
        if !dir.is_dir()
            || dir.file_type().is_symlink()
            || dir.mode() & 0o077 != 0
            || dir.uid() != unsafe { libc::geteuid() }
            || fs::canonicalize(parent).map_err(|_| TsMigrationError::Protection)? != parent
        {
            return Err(TsMigrationError::Protection);
        }
    }
    #[cfg(windows)]
    crate::windows_fs::private_parent(path).map_err(|_| TsMigrationError::Protection)?;
    #[cfg(not(any(unix, windows)))]
    return Err(TsMigrationError::Protection);
    Ok(())
}

fn create_backup_file(path: &Path) -> Result<(), TsMigrationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
    }
    #[cfg(windows)]
    crate::windows_fs::create_or_check_file(path).map_err(|_| TsMigrationError::Protection)?;
    Ok(())
}

fn check_backup_file(path: &Path) -> Result<(), TsMigrationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file = fs::symlink_metadata(path).map_err(|_| TsMigrationError::Protection)?;
        if !file.is_file()
            || file.file_type().is_symlink()
            || file.nlink() != 1
            || file.mode() & 0o077 != 0
            || file.uid() != unsafe { libc::geteuid() }
        {
            return Err(TsMigrationError::Protection);
        }
    }
    #[cfg(windows)]
    crate::windows_fs::private_file(path).map_err(|_| TsMigrationError::Protection)?;
    Ok(())
}

fn check_sidecars(path: &Path) -> Result<(), TsMigrationError> {
    use std::ffi::OsString;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        let sidecar = Path::new(&name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match fs::symlink_metadata(sidecar) {
                Ok(meta)
                    if meta.is_file()
                        && !meta.file_type().is_symlink()
                        && meta.nlink() == 1
                        && meta.uid() == unsafe { libc::geteuid() } => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(TsMigrationError::Protection),
            }
        }
        #[cfg(windows)]
        crate::windows_fs::private_file_if_exists(sidecar)
            .map_err(|_| TsMigrationError::Protection)?;
        #[cfg(not(any(unix, windows)))]
        return Err(TsMigrationError::Protection);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::kernel_intents::KernelIntentJournal;
    use ed25519_dalek::{Signer, SigningKey};
    use peerwork_core::{
        canonical::{canonical, Path as CanonicalPath},
        crypto::{actor_id, base64url, key_id, sign_compact},
        discovery::parse_discovery_wire,
    };
    use rusqlite::params;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn signed_command(signing: &SigningKey, id: &str) -> (String, String, String) {
        let public = signing.verifying_key().to_bytes();
        let kid = key_id(&public);
        let actor = actor_id(&public);
        let command = json!({
            "v":1,"audience":"https://workspace.example","command_id":id,
            "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
            "path":"/api/workspace/v1/commands","workspace_id":null,"instance_id":null,
            "protocol_digest":null,"action_id":"catalog.namespace.claim",
            "expected_workspace_revision":null,"expected_instance_revision":null,
            "exact_input_refs":[],"body":{"namespace":actor},"issued_at":1,"expires_at":600001
        });
        let payload = canonical(&command, CanonicalPath::COMMAND).unwrap();
        let header = canonical(
            &json!({
                "alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid
            }),
            CanonicalPath::SecureArtifact,
        )
        .unwrap();
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
        let body = format!("{{\"jws\":\"{jws}\"}}");
        (jws, payload, body)
    }

    fn signed_catalog_chunk(
        signing: &SigningKey,
        id: &str,
        chunk: &[u8],
    ) -> (String, String, String) {
        let public = signing.verifying_key().to_bytes();
        let kid = key_id(&public);
        let actor = actor_id(&public);
        let encoded_chunk = base64url(chunk);
        let command = json!({
            "v":1,"audience":"https://workspace.example","command_id":id,
            "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
            "path":"/api/workspace/v1/catalog/upload","workspace_id":null,"instance_id":null,
            "protocol_digest":null,"action_id":"catalog.upload.chunk",
            "expected_workspace_revision":null,"expected_instance_revision":null,
            "exact_input_refs":[],"body":{
                "bundle_digest":"a".repeat(64),"byte_length":chunk.len(),"chunk_digest":sha256_hex(chunk),
                "index":0,"offset":0,"upload_id":key_id(&[44;32])
            },"issued_at":1,"expires_at":600001
        });
        let payload = canonical(&command, CanonicalPath::COMMAND).unwrap();
        let header = canonical(
            &json!({
                "alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid
            }),
            CanonicalPath::SecureArtifact,
        )
        .unwrap();
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
        let stored = canonical(
            &json!({"command":command,"upload_chunk":encoded_chunk}),
            CanonicalPath::KERNEL,
        )
        .unwrap();
        let body = format!("{{\"chunk\":\"{encoded_chunk}\",\"command\":{{\"jws\":\"{jws}\"}}}}");
        (jws, stored, body)
    }

    #[test]
    fn ts_backup_readback_imports_pending_and_verified_accepted_without_source_mutation() {
        let dir = private_dir();
        let source_path = dir.path().join("old.sqlite");
        let backup_path = dir.path().join("old.backup.sqlite");
        let native_path = dir.path().join("new.sqlite");
        let signing = SigningKey::from_bytes(&[21; 32]);
        let kid = key_id(&signing.verifying_key().to_bytes());
        let actor = actor_id(&signing.verifying_key().to_bytes());
        let other_signing = SigningKey::from_bytes(&[22; 32]);
        let other_kid = key_id(&other_signing.verifying_key().to_bytes());
        let context = canonical(
            &json!({
                "semantics":"peerwork.kernel.v1", "audience":"https://workspace.example",
                "command_type":"peerwork.kernel-command.v1+jws",
                "receipt_type":"peerwork.kernel-receipt.v1+jws",
                "receipt_public_key":kid, "limits":{"command_bytes":262144},
                "protocol_features":[]
            }),
            CanonicalPath::KERNEL,
        )
        .unwrap();
        let discovery =
            parse_discovery_wire(context.as_bytes(), crate::transport::MAX_DISCOVERY_BYTES)
                .unwrap();
        let pending_id = key_id(&[31; 32]);
        let accepted_id = key_id(&[32; 32]);
        let other_id = key_id(&[33; 32]);
        let (pending_jws, pending_command, pending_body) = signed_command(&signing, &pending_id);
        let (accepted_jws, accepted_command, accepted_body) =
            signed_command(&signing, &accepted_id);
        let (other_jws, other_command, other_body) =
            signed_catalog_chunk(&other_signing, &other_id, b"synthetic chunk");
        let result = json!({"workspace_id":null,"event_sequence":null,"revision":null});
        let result_digest = sha256_hex(
            canonical(&result, CanonicalPath::KERNEL)
                .unwrap()
                .as_bytes(),
        );
        let receipt = sign_compact(
            &json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid}),
            &json!({
                "v":1,"audience":"https://workspace.example","actor_id":actor,"workspace_id":null,
                "command_id":accepted_id,"intent_digest":sha256_hex(accepted_jws.as_bytes()),
                "result_digest":result_digest,"protocol_digest":null,"event_sequence":null,
                "instance_revision":null,"accepted_at":2
            }),
            &signing,
        )
        .unwrap();
        let response = canonical(
            &json!({"command_id":accepted_id,"receipt":receipt,"result":result}),
            CanonicalPath::RESPONSE,
        )
        .unwrap();
        let noncanonical_accepted = TsStoredRow {
            command_id: accepted_id.clone(),
            jws: accepted_jws.clone(),
            intent_digest: sha256_hex(accepted_jws.as_bytes()),
            command: accepted_command.clone(),
            status: "ACCEPTED".into(),
            response: Some(format!(" {response}")),
            created: 2,
            updated: 3,
        };
        assert!(matches!(
            prepare_row(&noncanonical_accepted, &discovery, &[kid.clone()]),
            Err(TsMigrationError::Incompatible)
        ));
        {
            let db = Connection::open(&source_path).unwrap();
            db.execute_batch(&format!("{CONTEXT_SQL}; {INTENTS_SQL}; PRAGMA application_id={TS_APPLICATION_ID}; PRAGMA user_version=1;")).unwrap();
            db.execute(
                "INSERT INTO client_context(id,value) VALUES (1,?1)",
                [&context],
            )
            .unwrap();
            db.execute(
                "INSERT INTO client_intents VALUES (?1,?2,?3,?4,'PENDING',NULL,1,1)",
                params![
                    pending_id,
                    pending_jws,
                    sha256_hex(pending_jws.as_bytes()),
                    pending_command
                ],
            )
            .unwrap();
            db.execute(
                "INSERT INTO client_intents VALUES (?1,?2,?3,?4,'ACCEPTED',?5,2,3)",
                params![
                    accepted_id,
                    accepted_jws,
                    sha256_hex(accepted_jws.as_bytes()),
                    accepted_command,
                    response
                ],
            )
            .unwrap();
            db.execute(
                "INSERT INTO client_intents VALUES (?1,?2,?3,?4,'PENDING',NULL,3,3)",
                params![
                    other_id,
                    other_jws,
                    sha256_hex(other_jws.as_bytes()),
                    other_command
                ],
            )
            .unwrap();
        }
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o644)).unwrap();
        let original_source = fs::read(&source_path).unwrap();
        let mut conflicting =
            KernelIntentJournal::open(&dir.path().join("conflict.sqlite")).unwrap();
        conflicting
            .bind_discovery("https://workspace.example/", &discovery)
            .unwrap();
        conflicting
            .prepare(
                &accepted_id,
                crate::kernel_intents::KernelPath::Command,
                "foreign",
                b"{}",
            )
            .unwrap();
        assert!(matches!(
            conflicting.import_ts_backup(
                &source_path,
                &backup_path,
                &[kid.clone(), other_kid.clone()],
                &discovery
            ),
            Err(TsMigrationError::DestinationConflict)
        ));
        assert_eq!(conflicting.all_prepared().unwrap().len(), 1);
        assert!(conflicting
            .exact_request_for_test(&pending_id)
            .unwrap()
            .is_none());
        drop(conflicting);
        let mut native = KernelIntentJournal::open(&native_path).unwrap();
        native
            .bind_discovery("https://workspace.example/", &discovery)
            .unwrap();
        assert!(matches!(
            native.import_ts_backup(&source_path, &backup_path, &[kid.clone()], &discovery),
            Err(TsMigrationError::MissingSigner(missing))
                if missing.starts_with(&other_kid[..8]) && missing.ends_with(&other_kid[35..])
                    && missing.len() < other_kid.len()
        ));
        assert!(native.all_prepared().unwrap().is_empty());
        assert_eq!(
            native
                .import_ts_backup(
                    &source_path,
                    &backup_path,
                    &[kid.clone(), other_kid.clone()],
                    &discovery
                )
                .unwrap(),
            (2, 1)
        );
        assert_eq!(fs::read(&source_path).unwrap(), original_source);
        assert_eq!(
            native
                .exact_request_for_test(&pending_id)
                .unwrap()
                .unwrap()
                .1,
            pending_body.as_bytes()
        );
        assert_eq!(
            native
                .exact_request_for_test(&accepted_id)
                .unwrap()
                .unwrap()
                .1,
            accepted_body.as_bytes()
        );
        assert_eq!(
            native.exact_request_for_test(&other_id).unwrap().unwrap().1,
            other_body.as_bytes()
        );
        assert_eq!(
            native
                .all_prepared_for_key(&kid, discovery.audience_utf16())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            native
                .all_prepared_for_key(&other_kid, discovery.audience_utf16())
                .unwrap()
                .len(),
            1
        );
        let accepted = native
            .verified_pending(&accepted_id, &kid, discovery.audience_utf16())
            .unwrap()
            .unwrap();
        assert_eq!(
            native
                .accepted_response(&accepted, discovery.receipt_public_key())
                .unwrap()
                .unwrap()
                .command_id(),
            accepted_id
        );
        drop(native);
        let mut reopened = KernelIntentJournal::open(&native_path).unwrap();
        assert_eq!(
            reopened
                .import_ts_backup(
                    &source_path,
                    &backup_path,
                    &[kid.clone(), other_kid.clone()],
                    &discovery
                )
                .unwrap(),
            (2, 1)
        );
        assert_eq!(reopened.all_prepared().unwrap().len(), 3);
        {
            let db = Connection::open(&source_path).unwrap();
            db.execute(
                "UPDATE client_intents SET updated=4 WHERE command_id=?1",
                [&pending_id],
            )
            .unwrap();
        }
        assert!(matches!(
            reopened.import_ts_backup(&source_path, &backup_path, &[kid, other_kid], &discovery),
            Err(TsMigrationError::Incompatible)
        ));
    }

    #[test]
    fn matching_names_and_columns_without_baseline_constraints_are_refused_before_backup() {
        let dir = private_dir();
        let source_path = dir.path().join("weak.sqlite");
        let backup_path = dir.path().join("weak.backup.sqlite");
        let db = Connection::open(&source_path).unwrap();
        db.execute_batch("CREATE TABLE client_context(id INTEGER,value TEXT); CREATE TABLE client_intents(command_id TEXT,jws TEXT,intent_digest TEXT,command TEXT,status TEXT,response TEXT,created INTEGER,updated INTEGER); PRAGMA application_id=1347896113; PRAGMA user_version=1;").unwrap();
        drop(db);
        let signing = SigningKey::from_bytes(&[21; 32]);
        let kid = key_id(&signing.verifying_key().to_bytes());
        let context = canonical(
            &json!({
                "semantics":"peerwork.kernel.v1", "audience":"https://workspace.example",
                "command_type":"peerwork.kernel-command.v1+jws",
                "receipt_type":"peerwork.kernel-receipt.v1+jws", "receipt_public_key":kid,
                "limits":{"command_bytes":262144}, "protocol_features":[]
            }),
            CanonicalPath::KERNEL,
        )
        .unwrap();
        let discovery =
            parse_discovery_wire(context.as_bytes(), crate::transport::MAX_DISCOVERY_BYTES)
                .unwrap();
        assert!(matches!(
            backed_up_rows(&source_path, &backup_path, &discovery, &[kid]),
            Err(TsMigrationError::Incompatible)
        ));
        assert!(!backup_path.exists());
    }

    #[test]
    fn accepted_without_valid_signed_receipt_and_pending_with_response_are_refused() {
        let signing = SigningKey::from_bytes(&[21; 32]);
        let kid = key_id(&signing.verifying_key().to_bytes());
        let id = key_id(&[41; 32]);
        let (jws, command, _) = signed_command(&signing, &id);
        let context = canonical(
            &json!({
                "semantics":"peerwork.kernel.v1", "audience":"https://workspace.example",
                "command_type":"peerwork.kernel-command.v1+jws",
                "receipt_type":"peerwork.kernel-receipt.v1+jws", "receipt_public_key":kid,
                "limits":{"command_bytes":262144}, "protocol_features":[]
            }),
            CanonicalPath::KERNEL,
        )
        .unwrap();
        let discovery =
            parse_discovery_wire(context.as_bytes(), crate::transport::MAX_DISCOVERY_BYTES)
                .unwrap();
        let mut row = TsStoredRow {
            command_id: id,
            intent_digest: sha256_hex(jws.as_bytes()),
            jws,
            command,
            status: "ACCEPTED".into(),
            response: Some("{\"command_id\":\"bad\",\"receipt\":\"forged\",\"result\":{}}".into()),
            created: 1,
            updated: 2,
        };
        assert!(matches!(
            prepare_row(&row, &discovery, &[kid.clone()]),
            Err(TsMigrationError::Incompatible)
        ));
        row.status = "PENDING".into();
        assert!(matches!(
            prepare_row(&row, &discovery, &[kid]),
            Err(TsMigrationError::Incompatible)
        ));
    }
}
