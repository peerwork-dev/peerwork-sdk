//! Explicit offline engine handoff. Copy ciphertext indexes with SQLite's
//! snapshot API; keep the original identity/journal/key paths and call bindings.
//! A permanent source fence prevents two engine roots owning that same state.
use crate::{
    communication_host::{random_token, write_private},
    communication_runtime::{EngineConfig, RuntimeConfig},
    communication_store::private_json,
    kernel_identity::KernelIdentity,
    participant::{ParticipantError, Result},
    secure_state::{create_private_state_directory, validate_private_file, SecureStateStore},
};
use peerwork_core::crypto::sha256_hex;
use rusqlite::{
    backup::{Backup, StepResult},
    Connection, OpenFlags,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const OUT: &str = "engine-export.state";
const IN: &str = "engine-import.state";
fn error(code: &str) -> ParticipantError {
    let mut error = ParticipantError::local(code, "ENGINE_TRANSFER");
    if code.ends_with("FAILED")
        || matches!(
            code,
            "TRANSFER_SOURCE_BUSY_RESUME_SAME_JOB"
                | "TRANSFER_SNAPSHOT_INVALID"
                | "TRANSFER_TARGET_STATE_MISSING"
        )
    {
        error.effect_certainty = "UNKNOWN".into();
        error.recovery = "RESUME_SAME_TRANSFER_SELECTION".into();
    }
    error
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Pin {
    format: String,
    job_id: String,
    config_digest: String,
    source_directory: PathBuf,
    target_directory: PathBuf,
    role: String,
    phase: String,
}
fn read(store: &SecureStateStore) -> Result<Option<Pin>> {
    let bytes = store
        .read_exact()
        .map_err(|_| error("ENGINE_TRANSFER_STATE_INVALID"))?;
    bytes
        .map(|bytes| {
            if bytes.len() > 16384 {
                return Err(error("ENGINE_TRANSFER_STATE_INVALID"));
            }
            let pin: Pin = serde_json::from_slice(&bytes)
                .map_err(|_| error("ENGINE_TRANSFER_STATE_INVALID"))?;
            if pin.format != "peerwork.engine-transfer.v1"
                || pin.job_id.len() != 43
                || !pin
                    .job_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                || !crate::participant_migration::digest(&pin.config_digest)
                || !pin.source_directory.is_absolute()
                || !pin.target_directory.is_absolute()
            {
                return Err(error("ENGINE_TRANSFER_STATE_INVALID"));
            }
            Ok(pin)
        })
        .transpose()
}
fn write(store: &SecureStateStore, pin: &Pin) -> Result<()> {
    store
        .write_exact(&serde_json::to_vec(pin).map_err(|_| error("ENGINE_TRANSFER_STATE_INVALID"))?)
        .map_err(|_| error("ENGINE_TRANSFER_STATE_FAILED"))
}
fn marker(path: &Path) -> Result<SecureStateStore> {
    SecureStateStore::open(path).map_err(|_| error("ENGINE_TRANSFER_ALREADY_RUNNING"))
}
/// Called under the engine owner's lock before any store recovery or remote IO.
pub(crate) fn check_open(directory: &Path) -> Result<()> {
    for (file, role) in [(OUT, "SOURCE"), (IN, "TARGET")] {
        let path = directory.join(file);
        if !path.exists() {
            continue;
        }
        let pin = read(&marker(&path)?)?.ok_or_else(|| error("ENGINE_TRANSFER_STATE_INVALID"))?;
        match (role, pin.role.as_str(), pin.phase.as_str()) {
            ("SOURCE", "SOURCE", "FENCED" | "COMPLETE") if pin.source_directory == directory => {
                return Err(error("ENGINE_STATE_TRANSFERRED_USE_TARGET"))
            }
            ("TARGET", "TARGET", "COPYING") if pin.target_directory == directory => {
                return Err(error("ENGINE_TRANSFER_NOT_READY"))
            }
            ("TARGET", "TARGET", "READY") if pin.target_directory == directory => (),
            _ => return Err(error("ENGINE_TRANSFER_STATE_INVALID")),
        }
    }
    Ok(())
}
fn same(a: &Pin, b: &Pin) -> bool {
    a.job_id == b.job_id
        && a.config_digest == b.config_digest
        && a.source_directory == b.source_directory
        && a.target_directory == b.target_directory
}
fn output(config_path: &Path, pin: &Pin) -> Value {
    json!({"state":"TRANSFER_READY","job_id":pin.job_id,"runtime_config_path":config_path,"source":"PERMANENTLY_FENCED","identity_journal_and_keys":"ORIGINAL_PATHS_RETAINED","host_calls":"ORIGINAL_BINDINGS_AND_EVIDENCE_RETAINED","network_or_host_readiness":"NOT_ATTESTED"})
}
fn snapshot(source: &Path, target: &Path) -> Result<()> {
    validate_private_file(source).map_err(|_| error("TRANSFER_SOURCE_NOT_PRIVATE"))?;
    if target.exists() {
        validate_private_file(target).map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?;
    } else {
        write_private(target, b"").map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?;
    }
    let source = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| error("TRANSFER_SOURCE_DATABASE_INVALID"))?;
    let mut destination = Connection::open_with_flags(
        target,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| error("TRANSFER_TARGET_DATABASE_INVALID"))?;
    destination
        .execute_batch("PRAGMA synchronous=FULL;")
        .map_err(|_| error("TRANSFER_TARGET_DATABASE_INVALID"))?;
    let started = Instant::now();
    {
        let backup = Backup::new(&source, &mut destination)
            .map_err(|_| error("TRANSFER_SNAPSHOT_FAILED"))?;
        loop {
            match backup
                .step(32)
                .map_err(|_| error("TRANSFER_SNAPSHOT_FAILED"))?
            {
                StepResult::Done => break,
                StepResult::More => std::thread::yield_now(),
                StepResult::Busy | StepResult::Locked => {
                    if started.elapsed() > Duration::from_secs(5) {
                        return Err(error("TRANSFER_SOURCE_BUSY_RESUME_SAME_JOB"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => return Err(error("TRANSFER_SNAPSHOT_FAILED")),
            }
        }
    }
    let check: String = destination
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|_| error("TRANSFER_SNAPSHOT_INVALID"))?;
    if check != "ok" {
        return Err(error("TRANSFER_SNAPSHOT_INVALID"));
    }
    destination
        .close()
        .map_err(|_| error("TRANSFER_SNAPSHOT_FAILED"))?;
    // Windows FlushFileBuffers requires a writable handle; a read-only
    // reopen succeeds but cannot establish the promised durable snapshot.
    std::fs::OpenOptions::new()
        .write(true)
        .open(target)
        .and_then(|f| f.sync_all())
        .map_err(|_| error("TRANSFER_SNAPSHOT_FAILED"))?;
    Ok(())
}
fn pin_binding(engine: &EngineConfig) -> Result<Vec<u8>> {
    let identity =
        KernelIdentity::open(&engine.identity_path).map_err(|_| error("IDENTITY_STATE_INVALID"))?;
    if identity.actor_id() != engine.expected_actor {
        return Err(error("IDENTITY_MISMATCH"));
    }
    let origin =
        crate::transport::canonical_lifecycle_origin(&engine.origin, engine.allow_loopback_http)
            .map_err(|_| error("ORIGIN_INVALID"))?;
    let authority = engine
        .authority
        .clone()
        .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
    Ok(crate::participant_owner::logical_binding(&identity,&origin,&authority))
}
/// Stop the owning runtime/embedded program first. This same-host operation
/// changes only the chosen engine state directory; its clients, capabilities,
/// Runtime root/host pins and original journal/body-key locations stay pinned.
pub fn transfer_engine(config_path: &Path, name: &str, target: &Path) -> Result<Value> {
    transfer_with(config_path, name, target, |_| Ok(()))
}
fn transfer_with(
    config_path: &Path,
    name: &str,
    target: &Path,
    mut boundary: impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    let config: RuntimeConfig = serde_json::from_value(
        private_json(config_path, 65536).map_err(|_| error("RUNTIME_CONFIG_NOT_PRIVATE"))?,
    )
    .map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    if config.format != "peerwork.participant-runtime.v1"
        || config.engines.iter().filter(|c| c.name == name).count() != 1
        || !target.is_absolute()
    {
        return Err(error("ENGINE_TRANSFER_SELECTION_INVALID"));
    }
    let engine = config.engines.iter().find(|c| c.name == name).unwrap();
    let source = &engine.state_directory;
    if !source.is_absolute()
        || source == target
        || source.starts_with(target)
        || target.starts_with(source)
    {
        return Err(error("ENGINE_TRANSFER_SELECTION_INVALID"));
    }
    let expected = pin_binding(engine)?;
    validate_private_file(&source.join("engine-owner.state"))
        .map_err(|_| error("TRANSFER_SOURCE_NOT_INITIALIZED"))?;
    let owner = SecureStateStore::open(&source.join("engine-owner.state"))
        .map_err(|_| error("TRANSFER_SOURCE_STILL_OWNED"))?;
    let owner_wire=owner
        .read_exact()
        .map_err(|_| error("TRANSFER_SOURCE_STATE_INVALID"))?
        .ok_or_else(||error("TRANSFER_SOURCE_STATE_INVALID"))?;
    crate::participant_owner::validate_ready(&owner,&expected)?;
    if source.join(IN).exists() {
        let incoming = read(&marker(&source.join(IN))?)?
            .ok_or_else(|| error("ENGINE_TRANSFER_STATE_INVALID"))?;
        if incoming.role != "TARGET"
            || incoming.phase != "READY"
            || incoming.target_directory != *source
        {
            return Err(error("ENGINE_TRANSFER_NOT_READY"));
        }
    }
    let digest =
        sha256_hex(&serde_json::to_vec(&config).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?);
    let source_marker = marker(&source.join(OUT))?;
    let old = read(&source_marker)?;
    if old.as_ref().is_some_and(|p| {
        p.config_digest != digest
            || p.source_directory != *source
            || p.target_directory != target
            || p.role != "SOURCE"
            || !matches!(p.phase.as_str(), "FENCED" | "COMPLETE")
    }) {
        return Err(error("TRANSFER_ORIGINAL_SELECTION_REQUIRED"));
    }
    let config_output = target.join("transferred-runtime.json");
    let mut updated = config.clone();
    let next = updated.engines.iter_mut().find(|e| e.name == name).unwrap();
    next.journal_path = Some(engine.participant_config().journal_path);
    next.state_directory = target.into();
    let config_bytes = serde_json::to_vec(&updated).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    // A completed retry is an observation. The target may already contain new
    // operations, so do not acquire its engine/journal ownership or copy again.
    if let Some(pin) = &old {
        if target.join(IN).exists() {
            let target_marker = marker(&target.join(IN))?;
            if let Some(import) = read(&target_marker)? {
                if !same(pin, &import)
                    || import.role != "TARGET"
                    || !matches!(import.phase.as_str(), "COPYING" | "READY")
                {
                    return Err(error("TRANSFER_TARGET_CONFLICT"));
                }
                if import.phase == "READY" {
                    let bytes =
                        crate::secure_state::read_private_file_bounded(&config_output, 65536)
                            .map_err(|_| error("TRANSFER_TARGET_CONFIG_INVALID"))?;
                    if bytes.as_slice() != config_bytes {
                        return Err(error("TRANSFER_TARGET_CONFIG_INVALID"));
                    }
                    let mut complete = pin.clone();
                    complete.phase = "COMPLETE".into();
                    write(&source_marker, &complete)?;
                    return Ok(output(&config_output, pin));
                }
            }
        }
        if pin.phase == "COMPLETE" {
            return Err(error("TRANSFER_TARGET_STATE_MISSING"));
        }
    }
    let _runtime = SecureStateStore::open(&config.state_directory.join("runtime.state"))
        .map_err(|_| error("TRANSFER_RUNTIME_STILL_OWNED"))?;
    let journal = engine.participant_config().journal_path;
    let _journal = SecureStateStore::open(&journal.with_extension("participant-owner.state"))
        .map_err(|_| error("TRANSFER_JOURNAL_STILL_OWNED"))?;
    for database in ["participant.sqlite", "participant-inbox.sqlite"] {
        validate_private_file(&source.join(database))
            .map_err(|_| error("TRANSFER_SOURCE_NOT_INITIALIZED"))?;
    }
    let owner_pin: Value =
        serde_json::from_slice(&expected).map_err(|_| error("STATE_BINDING_MISMATCH"))?;
    for (database, table, format) in [
        (
            "participant.sqlite",
            "participant_meta",
            "peerwork.participant-store.v1",
        ),
        (
            "participant-inbox.sqlite",
            "inbox_meta",
            "peerwork.participant-inbox.v1",
        ),
    ] {
        let db = Connection::open_with_flags(
            source.join(database),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| error("TRANSFER_SOURCE_DATABASE_INVALID"))?;
        let binding: String = db
            .query_row(
                &format!("SELECT binding FROM {table} WHERE id=1"),
                [],
                |r| r.get(0),
            )
            .map_err(|_| error("TRANSFER_SOURCE_DATABASE_INVALID"))?;
        let binding: Value =
            serde_json::from_str(&binding).map_err(|_| error("STATE_BINDING_MISMATCH"))?;
        if binding
            != json!({"format":format,"actor":owner_pin["actor"],"key":owner_pin["key"],"origin":owner_pin["origin"]})
        {
            return Err(error("STATE_BINDING_MISMATCH"));
        }
    }
    if !target.exists() {
        create_private_state_directory(target).map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?;
    } else {
        create_private_state_directory(target).map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?;
        if !target.join(IN).exists() {
            // Interrupted initialization may leave only the two empty lock files.
            for entry in
                std::fs::read_dir(target).map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?
            {
                let entry = entry.map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?;
                let name = entry.file_name();
                if name != "engine-owner.state.lock" && name != "engine-import.state.lock" {
                    return Err(error("TRANSFER_TARGET_NOT_EMPTY"));
                }
                validate_private_file(&entry.path())
                    .map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?;
                if entry
                    .metadata()
                    .map_err(|_| error("TRANSFER_TARGET_NOT_PRIVATE"))?
                    .len()
                    != 0
                {
                    return Err(error("TRANSFER_TARGET_NOT_EMPTY"));
                }
            }
        }
    }

    let _target_owner = SecureStateStore::open(&target.join("engine-owner.state"))
        .map_err(|_| error("TRANSFER_TARGET_STILL_OWNED"))?;
    let target_marker = marker(&target.join(IN))?;
    let prior = read(&target_marker)?;
    let pin = match (old, prior.as_ref()) {
        (Some(pin), _) => pin,
        (None, Some(import))
            if import.config_digest == digest
                && import.source_directory == *source
                && import.target_directory == target
                && import.role == "TARGET"
                && import.phase == "COPYING" =>
        {
            let mut pin = import.clone();
            pin.role = "SOURCE".into();
            pin.phase = "FENCED".into();
            pin
        }
        (None, None) => Pin {
            format: "peerwork.engine-transfer.v1".into(),
            job_id: random_token().map_err(|_| error("ENTROPY_UNAVAILABLE"))?,
            config_digest: digest,
            source_directory: source.clone(),
            target_directory: target.into(),
            role: "SOURCE".into(),
            phase: "FENCED".into(),
        },
        _ => return Err(error("TRANSFER_TARGET_CONFLICT")),
    };
    if let Some(prior) = prior {
        if !same(&pin, &prior) || prior.role != "TARGET" || prior.phase != "COPYING" {
            return Err(error("TRANSFER_TARGET_CONFLICT"));
        }
    }
    let mut importing = pin.clone();
    importing.role = "TARGET".into();
    importing.phase = "COPYING".into();
    // Reserve/fence the empty target first. If interrupted here the source may
    // continue, but no snapshot has been made and the target cannot start.
    write(&target_marker, &importing)?;
    boundary("TARGET_RESERVED")?;
    write(&source_marker, &pin)?;
    boundary("SOURCE_FENCED")?;
    for database in ["participant.sqlite", "participant-inbox.sqlite"] {
        snapshot(&source.join(database), &target.join(database))?;
        boundary(database)?;
    }
    _target_owner
        .write_exact(&owner_wire)
        .map_err(|_| error("TRANSFER_TARGET_STATE_FAILED"))?;
    if config_output.exists() {
        let old = crate::secure_state::read_private_file_bounded(&config_output, 65536)
            .map_err(|_| error("TRANSFER_TARGET_CONFIG_INVALID"))?;
        if old.as_slice() != config_bytes {
            return Err(error("TRANSFER_TARGET_CONFIG_INVALID"));
        }
    } else {
        write_private(&config_output, &config_bytes)
            .map_err(|_| error("TRANSFER_TARGET_CONFIG_INVALID"))?;
    }
    importing.phase = "READY".into();
    write(&target_marker, &importing)?;
    boundary("TARGET_READY")?;
    let mut complete = pin.clone();
    complete.phase = "COMPLETE".into();
    write(&source_marker, &complete)?;
    Ok(output(&config_output, &pin))
}

#[cfg(test)]
#[path = "participant_transfer_tests.rs"]
mod tests;
