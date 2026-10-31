//! Explicit, stopped-installation recovery of published Node delivery state.
//! Old business events are local evidence, never native mailbox inputs. Keep
//! their original bytes and uncertainties; importing does not submit anything.
use crate::{
    communication_store::{private_json, single_owner_database as database},
    kernel_identity::KernelIdentity,
    kernel_intents::parent_operations::{open_bounded, seal_bounded},
    participant::{ParticipantError, Result},
    secure_state::{validate_private_file, SecureStateStore},
};
use peerwork_core::crypto::sha256_hex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const PAGE: usize = 32;
const SOURCE_RECORD_BYTES: usize = 1024 * 1024;
// A source string becomes a JSON string inside the encrypted evidence record.
const RECORD_BYTES: usize = SOURCE_RECORD_BYTES * 4 + 4096;
const TOTAL_BYTES: usize = 32 * 1024 * 1024;
const ROWS: usize = 4096;
const MARKER: &str = "peerwork.native-retirement.v1";
fn err(code: &str) -> ParticipantError {
    ParticipantError::local(code, "LEGACY_DELIVERY_IMPORT")
}
fn invalid() -> ParticipantError {
    err("LEGACY_DELIVERY_STATE_INVALID")
}
fn failed() -> ParticipantError {
    let mut error = err("LEGACY_DELIVERY_IMPORT_FAILED_RESUME_SAME_SELECTION");
    error.effect_certainty = "UNKNOWN".into();
    error.recovery = "RESUME_SAME_IMPORT_SELECTION".into();
    error
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyDeliverySelection {
    pub format: String,
    pub source_directory: PathBuf,
    pub archive_directory: PathBuf,
    pub identity_path: PathBuf,
    pub expected_actor: String,
    /// Exact published ReceiverStore constructor hash, not reserialized JSON.
    pub expected_binding_digest: String,
    /// RECEIVER or BRIDGE. Bridge-only opaque rows retain their original keys.
    pub kind: String,
    /// Operator attestation; absence of /proc/PID visibility is not this fact.
    pub source_stopped: bool,
}
fn directory(path: &Path) -> Result<()> {
    // Reuse native directory checks without creating a missing source.
    let m = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || std::fs::canonicalize(path).ok().as_deref() != Some(path)
    {
        return Err(invalid());
    }
    crate::secure_state::create_private_state_directory(path).map_err(|_| invalid())
}
fn check_file(path: &Path) -> Result<()> {
    validate_private_file(path).map_err(|_| err("LEGACY_DELIVERY_SOURCE_NOT_PRIVATE"))
}
struct Archive {
    _owner: SecureStateStore,
    db: Connection,
    identity: KernelIdentity,
    pin: String,
}
impl Archive {
    fn open(s: &LegacyDeliverySelection) -> Result<Self> {
        if s.format != "peerwork.legacy-delivery-import.v1"
            || !s.source_stopped
            || !matches!(s.kind.as_str(), "RECEIVER" | "BRIDGE")
            || !crate::participant_migration::digest(&s.expected_binding_digest)
            || !s.source_directory.is_absolute()
            || !s.archive_directory.is_absolute()
            || s.source_directory.starts_with(&s.archive_directory)
            || s.archive_directory.starts_with(&s.source_directory)
        {
            return Err(err("LEGACY_DELIVERY_SELECTION_INVALID"));
        }
        directory(&s.source_directory)?;
        // Old code does not honor native OS locks. Require an explicitly stopped
        // installation and a released old lock; never unlink it or guess death.
        match std::fs::symlink_metadata(s.source_directory.join("receiver.lock")) {
            Ok(_) => return Err(err("LEGACY_DELIVERY_SOURCE_STILL_LOCKED")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(err("LEGACY_DELIVERY_SOURCE_STILL_LOCKED")),
        }
        let identity = KernelIdentity::open(&s.identity_path).map_err(|_| invalid())?;
        if identity.actor_id() != s.expected_actor {
            return Err(err("IDENTITY_MISMATCH"));
        }
        let pin = sha256_hex(
            json!(["peerwork.legacy-delivery-archive.v1", s, identity.key_id()])
                .to_string()
                .as_bytes(),
        );
        // A mistyped source pin must not bind an empty destination permanently.
        // Check it before creating archive metadata; the write transaction
        // below rechecks it before retirement. Existing archives remain readable
        // even if the old bridge ledger later changes.
        if !s.archive_directory.join("legacy-delivery.sqlite").exists() {
            let source = source(s)?;
            let binding: String = source
                .query_row("SELECT value FROM control WHERE key='binding'", [], |r| {
                    r.get(0)
                })
                .map_err(|_| invalid())?;
            let saved: Option<String> = source
                .query_row("SELECT value FROM control WHERE key=?1", [MARKER], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(|_| invalid())?;
            let original = serde_json::from_str::<String>(&binding).ok();
            let resumed = saved
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .is_some_and(|v| {
                    v["pin"] == pin
                        && v["original_binding"] == s.expected_binding_digest
                        && original.as_deref() == Some(&format!("RETIRED:{pin}"))
                });
            if !resumed
                && (saved.is_some() || original.as_deref() != Some(&s.expected_binding_digest))
            {
                return Err(err("LEGACY_DELIVERY_BINDING_MISMATCH"));
            }
        }
        crate::secure_state::create_private_state_directory(&s.archive_directory)
            .map_err(|_| failed())?;
        let owner = SecureStateStore::open(&s.archive_directory.join("legacy-import.state"))
            .map_err(|_| err("LEGACY_DELIVERY_IMPORT_ALREADY_RUNNING"))?;
        let db = database(&s.archive_directory, "legacy-delivery.sqlite").map_err(|_| failed())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS legacy_meta(id INTEGER PRIMARY KEY CHECK(id=1),pin TEXT NOT NULL,phase TEXT NOT NULL,cursor TEXT NOT NULL,allocated INTEGER NOT NULL,rows INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS legacy_records(key TEXT PRIMARY KEY,digest TEXT NOT NULL,evidence BLOB NOT NULL);").map_err(|_| failed())?;
        db.execute(
            "INSERT OR IGNORE INTO legacy_meta VALUES(1,?1,'CONTROL','',0,0)",
            [&pin],
        )
        .map_err(|_| failed())?;
        let saved: String = db
            .query_row("SELECT pin FROM legacy_meta WHERE id=1", [], |r| r.get(0))
            .map_err(|_| invalid())?;
        if saved != pin {
            return Err(err("LEGACY_DELIVERY_SELECTION_CHANGED"));
        }
        Ok(Self {
            _owner: owner,
            db,
            identity,
            pin,
        })
    }
    fn aad(&self, key: &str, digest: &str) -> String {
        json!(["peerwork.legacy-delivery-record.v1", self.pin, key, digest]).to_string()
    }
    fn read(&self, key: &str) -> Result<Value> {
        let row: Option<(String, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT digest,evidence FROM legacy_records WHERE key=?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| invalid())?;
        let (digest, sealed) = row.ok_or_else(|| err("LEGACY_DELIVERY_RECORD_NOT_FOUND"))?;
        let raw = open_bounded(
            &self.identity,
            &self.aad(key, &digest),
            &sealed,
            RECORD_BYTES,
        )
        .map_err(|_| invalid())?;
        if sha256_hex(raw.as_bytes()) != digest {
            return Err(invalid());
        }
        let evidence =
            peerwork_core::strict_json::parse_strict_json(raw.as_bytes()).map_err(|_| invalid())?;
        Ok(
            json!({"key":key,"digest":digest,"evidence":evidence,"assurance":"LOCAL_LEGACY_EVIDENCE_NOT_REVERIFIED","model_response":"NOT_ATTESTED","native_delivery":"NOT_CREATED"}),
        )
    }
    fn save(&mut self, phase: &str, cursor: &str, records: Vec<(String, Value)>) -> Result<()> {
        let mut prepared = Vec::new();
        let mut allocation = 0usize;
        for (key, evidence) in records {
            let raw = evidence.to_string();
            if raw.len() > RECORD_BYTES {
                return Err(err("LEGACY_DELIVERY_RECORD_TOO_LARGE"));
            }
            let digest = sha256_hex(raw.as_bytes());
            let sealed = seal_bounded(&self.identity, &self.aad(&key, &digest), &raw, RECORD_BYTES)
                .map_err(|_| failed())?;
            allocation = allocation.checked_add(sealed.len()).ok_or_else(invalid)?;
            prepared.push((key, digest, sealed));
        }
        let tx = self.db.transaction().map_err(|_| failed())?;
        let (used, count): (usize, usize) = tx
            .query_row(
                "SELECT allocated,rows FROM legacy_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| invalid())?;
        if used.saturating_add(allocation) > TOTAL_BYTES
            || count.saturating_add(prepared.len()) > ROWS
        {
            return Err(err("LEGACY_DELIVERY_ARCHIVE_CAPACITY"));
        }
        for (key, digest, sealed) in &prepared {
            tx.execute(
                "INSERT INTO legacy_records VALUES(?1,?2,?3)",
                params![key, digest, sealed],
            )
            .map_err(|_| failed())?;
        }
        tx.execute("UPDATE legacy_meta SET phase=?1,cursor=?2,allocated=allocated+?3,rows=rows+?4 WHERE id=1",params![phase,cursor,allocation,prepared.len()]).map_err(|_|failed())?;
        tx.commit().map_err(|_| failed())
    }
    fn status(&self) -> Result<Value> {
        let (phase, rows): (String, usize) = self
            .db
            .query_row("SELECT phase,rows FROM legacy_meta WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(|_| invalid())?;
        Ok(
            json!({"state":if phase=="COMPLETE"{"LEGACY_EVIDENCE_IMPORTED"}else{"LEGACY_IMPORT_PENDING"},"phase":phase,"archived_records":rows,"page_limit":PAGE,"source":"RETIRED_FOR_OLD_CONSTRUCTOR","assurance":"LOCAL_LEGACY_EVIDENCE_NOT_REVERIFIED","native_delivery":"NOT_CREATED","model_response":"NOT_ATTESTED","recovery":"INSPECT_ORIGINAL_EVIDENCE_NO_AUTOMATIC_REPLAY"}),
        )
    }
}
fn source(s: &LegacyDeliverySelection) -> Result<Connection> {
    let path = s.source_directory.join("receiver.sqlite");
    check_file(&path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = s.source_directory.join(format!("receiver.sqlite{suffix}"));
        match std::fs::symlink_metadata(&side) {
            Ok(_) => check_file(&side)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(invalid()),
        }
    }
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| invalid())?;
    db.busy_timeout(std::time::Duration::ZERO)
        .map_err(|_| invalid())?;
    db.execute_batch("PRAGMA synchronous=FULL;")
        .map_err(|_| invalid())?;
    // Check exact published columns before changing the old binding.
    for sql in [
        "SELECT key,value FROM control LIMIT 0",
        "SELECT sequence,event,status,receipt,body_hash FROM deliveries LIMIT 0",
    ] {
        db.prepare(sql).map_err(|_| invalid())?;
    }
    Ok(db)
}
fn bridge_bytes(s: &LegacyDeliverySelection) -> Result<Option<Vec<u8>>> {
    if s.kind != "BRIDGE" {
        return Ok(None);
    }
    let raw = crate::secure_state::read_private_file_bounded(
        &s.source_directory.join("deliveries.json"),
        SOURCE_RECORD_BYTES,
    )
    .map_err(|_| invalid())?
    .to_vec();
    let value = peerwork_core::strict_json::parse_strict_json(&raw).map_err(|_| invalid())?;
    if value.as_array().is_none_or(|v| v.len() > 256) {
        return Err(invalid());
    }
    Ok(Some(raw))
}
/// One explicit maintenance page (<=32 records). Original files remain in the
/// old directory; only its constructor binding is permanently retired. A
/// crash resumes the same selection, without touching any remote/host state.
pub fn import_page(s: &LegacyDeliverySelection) -> Result<Value> {
    let mut archive = Archive::open(s)?;
    let mut source = source(s)?;
    let bridge = bridge_bytes(s)?;
    let marker=json!({"format":MARKER,"pin":archive.pin,"original_binding":s.expected_binding_digest,"bridge_sha256":bridge.as_ref().map(|b|sha256_hex(b))}).to_string();
    let retired =
        serde_json::to_string(&format!("RETIRED:{}", archive.pin)).map_err(|_| invalid())?;
    let tx = source
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| err("LEGACY_DELIVERY_SOURCE_BUSY"))?;
    let binding: String = tx
        .query_row("SELECT value FROM control WHERE key='binding'", [], |r| {
            r.get(0)
        })
        .map_err(|_| invalid())?;
    let saved: Option<String> = tx
        .query_row("SELECT value FROM control WHERE key=?1", [MARKER], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|_| invalid())?;
    match saved {
        Some(old) if old == marker && binding == retired => (),
        Some(_) => return Err(err("LEGACY_DELIVERY_RETIREMENT_MISMATCH")),
        None => {
            if serde_json::from_str::<String>(&binding).ok().as_deref()
                != Some(&s.expected_binding_digest)
            {
                return Err(err("LEGACY_DELIVERY_BINDING_MISMATCH"));
            }
            tx.execute("INSERT INTO control VALUES(?1,?2)", params![MARKER, marker])
                .map_err(|_| failed())?;
            tx.execute(
                "UPDATE control SET value=?1 WHERE key='binding'",
                [&retired],
            )
            .map_err(|_| failed())?;
        }
    }
    tx.commit().map_err(|_| failed())?;
    let (phase, cursor): (String, String) = archive
        .db
        .query_row("SELECT phase,cursor FROM legacy_meta WHERE id=1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(|_| invalid())?;
    match phase.as_str() {
        "CONTROL" => {
            let rows=source.prepare("SELECT key,value FROM control WHERE (?1='' OR key>?1) AND key<>?2 ORDER BY key LIMIT ?3").map_err(|_|invalid())?.query_map(params![cursor,MARKER,PAGE],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).map_err(|_|invalid())?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|invalid())?;
            let next = rows.last().map(|r| r.0.clone()).unwrap_or(cursor);
            let full = rows.len() == PAGE;
            let mut records: Vec<_> = rows
                .into_iter()
                .map(|(key, value)| {
                    let original = if key == "binding" {
                        serde_json::to_string(&s.expected_binding_digest).unwrap()
                    } else {
                        value
                    };
                    (
                        format!("control:{key}"),
                        json!({"kind":"CONTROL","key":key,"original_json":original}),
                    )
                })
                .collect();
            if !full {
                if let Some(raw) = &bridge {
                    records.push(("bridge:original".into(),json!({"kind":"OPAQUE_BRIDGE_LEDGER","original_json":std::str::from_utf8(raw).map_err(|_|invalid())?})));
                }
            }
            archive.save(
                if full { "CONTROL" } else { "DELIVERIES" },
                if full { &next } else { "-1" },
                records,
            )?;
        }
        "DELIVERIES" => {
            let after: i64 = cursor.parse().map_err(|_| invalid())?;
            let rows=source.prepare("SELECT sequence,event,status,receipt,body_hash FROM deliveries WHERE sequence>?1 ORDER BY sequence LIMIT ?2").map_err(|_|invalid())?.query_map(params![after,PAGE],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?))).map_err(|_|invalid())?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|invalid())?;
            let next = rows.last().map(|r| r.0.to_string()).unwrap_or(cursor);
            let full = rows.len() == PAGE;
            let records=rows.into_iter().map(|(sequence,event,status,receipt,body_hash)|(format!("delivery:{sequence}"),json!({"kind":"DELIVERY","sequence":sequence,"original_event_json":event,"original_status":status,"original_receipt":receipt,"original_body_hash":body_hash,"execution":"NEVER_REPLAYED","model_response":"NOT_ATTESTED"}))).collect();
            archive.save(
                if full {
                    "DELIVERIES"
                } else if bridge.is_some() {
                    "BRIDGE"
                } else {
                    "COMPLETE"
                },
                if full { &next } else { "0" },
                records,
            )?;
        }
        "BRIDGE" => {
            let value: Value = serde_json::from_slice(bridge.as_ref().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            let rows = value.as_array().ok_or_else(invalid)?;
            let after: usize = cursor.parse().map_err(|_| invalid())?;
            if after > rows.len() {
                return Err(invalid());
            }
            let until = after.saturating_add(PAGE).min(rows.len());
            let records=rows[after..until].iter().enumerate().map(|(i,row)|(format!("bridge:{}",after+i),json!({"kind":"OPAQUE_BRIDGE_CALL","original":row,"assurance":"UNATTRIBUTED_LOCAL_ROW","execution":"NEVER_REPLAYED"}))).collect();
            archive.save(
                if until == rows.len() {
                    "COMPLETE"
                } else {
                    "BRIDGE"
                },
                &until.to_string(),
                records,
            )?;
        }
        "COMPLETE" => (),
        _ => return Err(invalid()),
    }
    archive.status()
}
pub fn read_evidence(s: &LegacyDeliverySelection, key: &str) -> Result<Value> {
    if key.is_empty() || key.len() > 512 {
        return Err(invalid());
    }
    if !s.archive_directory.join("legacy-delivery.sqlite").is_file() {
        return Err(err("LEGACY_DELIVERY_ARCHIVE_MISSING"));
    }
    Archive::open(s)?.read(key)
}
/// One user operation owns all bounded maintenance pages. Agents do not need
/// to write polling scripts or reconstruct a new selection between pages.
pub fn import_all(s: &LegacyDeliverySelection) -> Result<Value> {
    for _ in 0..(ROWS / PAGE + 4) {
        let status = import_page(s)?;
        if status["state"] == "LEGACY_EVIDENCE_IMPORTED" {
            return Ok(status);
        }
    }
    Err(failed())
}
pub fn load_selection(path: &Path) -> Result<LegacyDeliverySelection> {
    serde_json::from_value(
        private_json(path, 65536).map_err(|_| err("LEGACY_DELIVERY_SELECTION_NOT_PRIVATE"))?,
    )
    .map_err(|_| err("LEGACY_DELIVERY_SELECTION_INVALID"))
}

#[cfg(test)]
#[path = "participant_legacy_delivery_tests.rs"]
mod tests;
