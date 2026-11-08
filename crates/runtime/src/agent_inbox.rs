//! Durable local delivery, not a journal verifier or incremental reader.
//! Only native verified source adapters may ingest. Acknowledgement records
//! consumer delivery acceptance; it never completes a protocol task.
use peerwork_core::crypto::{base64url, sha256_hex};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum InboxError {
    #[error("inbox is not ready; sync verified source first")]
    NotReady,
    #[error("inbox storage protection failed")]
    Protection,
    #[error("inbox platform is unsupported")]
    Unsupported,
    #[error("inbox context does not match")]
    ContextMismatch,
    #[error("inbox input is invalid")]
    Invalid,
    #[error("inbox source cursor conflict")]
    CursorConflict,
    #[error("inbox event identity conflict")]
    EventConflict,
    #[error("inbox capacity reached; source position unchanged")]
    Backpressure,
    #[error("inbox source history gap requires explicit recovery")]
    Gap,
    #[error("inbox consumer is not registered")]
    ConsumerMissing,
    #[error("inbox delivery lease is stale")]
    StaleLease,
    #[error("inbox operation cancelled")]
    Cancelled,
    #[error("inbox state is busy")]
    Busy,
    #[error("inbox storage operation failed")]
    Storage,
}
impl From<rusqlite::Error> for InboxError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            _ => Self::Storage,
        }
    }
}

/// All fields participate in the immutable binding. Fingerprint binds the
/// caller's already validated trust/device/history context, not merely a URL.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboxBinding {
    pub service: String,
    pub principal: String,
    pub workspace: String,
    pub source: String,
    pub context_fingerprint: String,
}
#[derive(Clone, Copy, Debug)]
pub struct InboxLimits {
    pub max_events: u64,
    pub max_payload_bytes: u64,
    pub max_batch_events: usize,
}
impl Default for InboxLimits {
    fn default() -> Self {
        Self {
            max_events: 10_000,
            max_payload_bytes: 64 * 1024 * 1024,
            max_batch_events: 256,
        }
    }
}
/// Source identity is scoped by the store binding. Payloads are stored in a
/// private local file, not encrypted by a new unrelated key-management layer.
#[derive(Clone, Serialize)]
pub(crate) struct InboxSourceEvent {
    pub(crate) event_id: String,
    pub(crate) version: String,
    pub(crate) authoritative_hash: String,
    pub(crate) payload: Vec<u8>,
}
/// Crate-only boundary: callers of the public SDK cannot label JSON verified.
/// Adapter must derive ordered events and cursors from authenticated replay.
pub(crate) struct VerifiedInboxBatch {
    pub(crate) prior_cursor: Option<String>,
    pub(crate) next_cursor: String,
    pub(crate) events: Vec<InboxSourceEvent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxDelivery {
    pub consumer_id: String,
    pub filter_version: String,
    pub event_id: String,
    pub version: String,
    pub authoritative_hash: String,
    pub payload: Vec<u8>,
    pub ack_token: String,
    pub lease_until_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxStatus {
    pub verified_cursor: Option<String>,
    pub enqueued_cursor: Option<String>,
    pub retained_events: u64,
    pub retained_payload_bytes: u64,
    pub gap: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxConsumerStatus {
    pub acknowledged_position: u64,
    pub leased_position: Option<u64>,
    pub lease_until_ms: Option<i64>,
    pub pending_events: u64,
}

pub struct AgentInbox {
    db: Connection,
    path: PathBuf,
    limits: InboxLimits,
}
fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.contains('\0')
}
fn now_ms() -> Result<i64, InboxError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or(InboxError::Invalid)
}
impl AgentInbox {
    /// Open only an existing, fully bound database; never create state/schema.
    pub fn open_existing(
        path: &Path,
        binding: &InboxBinding,
        limits: InboxLimits,
    ) -> Result<Self, InboxError> {
        crate::secure_state::check_private_directory(path.parent().ok_or(InboxError::Protection)?)
            .map_err(|_| InboxError::Protection)?;
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(InboxError::NotReady),
            Err(_) => return Err(InboxError::Protection),
            Ok(_) => {}
        }
        check_files(path)?;
        let db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "trusted_schema", "OFF")?;
        let saved: String = db.query_row("SELECT binding FROM inbox_meta WHERE id=1", [], |r| {
            r.get(0)
        })?;
        if saved != serde_json::to_string(binding).map_err(|_| InboxError::Invalid)? {
            return Err(InboxError::ContextMismatch);
        }
        Ok(Self {
            db,
            path: path.to_owned(),
            limits,
        })
    }
    /// Existing private parent required. No identity generation or network I/O.
    pub fn open(
        path: &Path,
        binding: &InboxBinding,
        limits: InboxLimits,
    ) -> Result<Self, InboxError> {
        if ![
            &binding.service,
            &binding.principal,
            &binding.workspace,
            &binding.source,
            &binding.context_fingerprint,
        ]
        .into_iter()
        .all(|s| valid(s))
            || limits.max_events == 0
            || limits.max_payload_bytes == 0
            || limits.max_batch_events == 0
            || limits.max_events > i64::MAX as u64
            || limits.max_payload_bytes > i64::MAX as u64
        {
            return Err(InboxError::Invalid);
        }
        protect(path)?;
        let mut db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        // DELETE journal avoids persistent shared-memory sidecars; SQLite gives
        // its journal the protected database mode. Check pre-existing sidecars.
        db.pragma_update(None, "journal_mode", "DELETE")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "trusted_schema", "OFF")?;
        let binding_wire = serde_json::to_string(binding).map_err(|_| InboxError::Invalid)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS inbox_meta (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, cursor TEXT, batch_digest TEXT, gap INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS inbox_events (position INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, version TEXT NOT NULL, source_hash TEXT NOT NULL, payload BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS inbox_consumers (consumer TEXT NOT NULL, filter_version TEXT NOT NULL, ack_position INTEGER NOT NULL DEFAULT 0, lease_position INTEGER, lease_token TEXT, lease_until INTEGER, PRIMARY KEY(consumer,filter_version));")?;
        let saved: Option<String> = tx
            .query_row("SELECT binding FROM inbox_meta WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match saved {
            Some(saved) if saved != binding_wire => return Err(InboxError::ContextMismatch),
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT INTO inbox_meta(id,binding) VALUES(1,?1)",
                    [&binding_wire],
                )?;
            }
        }
        tx.commit()?;
        Ok(Self {
            db,
            path: path.to_owned(),
            limits,
        })
    }
    fn check(&self) -> Result<(), InboxError> {
        check_files(&self.path)
    }

    /// Each consumer/version receives the retained source from the beginning.
    /// This foundation does not interpret filters: adapter-selected streams are
    /// bound by `source`; a version creates an independent delivery cursor.
    pub fn register_consumer(
        &mut self,
        consumer: &str,
        filter_version: &str,
    ) -> Result<(), InboxError> {
        if !valid(consumer) || !valid(filter_version) {
            return Err(InboxError::Invalid);
        }
        self.check()?;
        self.db.execute(
            "INSERT OR IGNORE INTO inbox_consumers(consumer,filter_version) VALUES(?1,?2)",
            params![consumer, filter_version],
        )?;
        Ok(())
    }
    pub(crate) fn ingest_verified(&mut self, batch: VerifiedInboxBatch) -> Result<(), InboxError> {
        if !valid(&batch.next_cursor)
            || batch.prior_cursor.as_ref().is_some_and(|s| !valid(s))
            || batch.events.len() > self.limits.max_batch_events
        {
            return Err(InboxError::Invalid);
        }
        if batch
            .events
            .iter()
            .any(|e| !valid(&e.event_id) || !valid(&e.version) || !valid(&e.authoritative_hash))
        {
            return Err(InboxError::Invalid);
        }
        let batch_bytes = batch
            .events
            .iter()
            .try_fold(0u64, |n, e| n.checked_add(e.payload.len() as u64))
            .ok_or(InboxError::Backpressure)?;
        if batch_bytes > self.limits.max_payload_bytes {
            return Err(InboxError::Backpressure);
        }
        self.check()?;
        let digest = sha256_hex(
            &serde_json::to_vec(&(&batch.prior_cursor, &batch.next_cursor, &batch.events))
                .map_err(|_| InboxError::Invalid)?,
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (cursor, last_digest, gap): (Option<String>, Option<String>, bool) = tx.query_row(
            "SELECT cursor,batch_digest,gap FROM inbox_meta WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if gap {
            return Err(InboxError::Gap);
        }
        if cursor.as_deref() == Some(&batch.next_cursor) && last_digest.as_deref() == Some(&digest)
        {
            return Ok(());
        }
        if cursor != batch.prior_cursor {
            return Err(InboxError::CursorConflict);
        }
        if batch.prior_cursor.as_ref() == Some(&batch.next_cursor) {
            return Err(InboxError::CursorConflict);
        }
        let (mut count, mut bytes): (u64, u64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM inbox_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        for event in batch.events {
            let saved: Option<(String, String, Vec<u8>)> = tx
                .query_row(
                    "SELECT version,source_hash,payload FROM inbox_events WHERE event_id=?1",
                    [&event.event_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((version, hash, payload)) = saved {
                if version != event.version
                    || hash != event.authoritative_hash
                    || payload != event.payload
                {
                    return Err(InboxError::EventConflict);
                }
                continue;
            }
            count = count.checked_add(1).ok_or(InboxError::Backpressure)?;
            bytes = bytes
                .checked_add(event.payload.len() as u64)
                .ok_or(InboxError::Backpressure)?;
            if count > self.limits.max_events || bytes > self.limits.max_payload_bytes {
                return Err(InboxError::Backpressure);
            }
            tx.execute("INSERT INTO inbox_events(event_id,version,source_hash,payload) VALUES(?1,?2,?3,?4)", params![event.event_id,event.version,event.authoritative_hash,event.payload])?;
        }
        // Cursor is both verified and enqueued progress: no partial advance.
        tx.execute(
            "UPDATE inbox_meta SET cursor=?1,batch_digest=?2 WHERE id=1",
            params![batch.next_cursor, digest],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Gap is sticky: recovery needs a future explicit source reconstruction
    /// contract. Neither delivery nor ack may conceal it as successful replay.
    pub(crate) fn report_gap(&mut self) -> Result<(), InboxError> {
        self.check()?;
        self.db
            .execute("UPDATE inbox_meta SET gap=1 WHERE id=1", [])?;
        Ok(())
    }
    pub fn receive(
        &mut self,
        consumer: &str,
        filter_version: &str,
        lease_ms: u64,
        cancel: &CancellationToken,
    ) -> Result<Option<InboxDelivery>, InboxError> {
        self.receive_at(consumer, filter_version, lease_ms, cancel, now_ms()?)
    }
    fn receive_at(
        &mut self,
        consumer: &str,
        filter_version: &str,
        lease_ms: u64,
        cancel: &CancellationToken,
        now: i64,
    ) -> Result<Option<InboxDelivery>, InboxError> {
        if cancel.is_cancelled() {
            return Err(InboxError::Cancelled);
        }
        if !valid(consumer) || !valid(filter_version) || !(1..=3_600_000).contains(&lease_ms) {
            return Err(InboxError::Invalid);
        }
        let until = now
            .checked_add(lease_ms as i64)
            .ok_or(InboxError::Invalid)?;
        self.check()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.query_row("SELECT gap FROM inbox_meta WHERE id=1", [], |r| {
            r.get::<_, bool>(0)
        })? {
            return Err(InboxError::Gap);
        }
        let row: Option<(i64,Option<i64>)> = tx.query_row("SELECT ack_position,lease_until FROM inbox_consumers WHERE consumer=?1 AND filter_version=?2", params![consumer,filter_version], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (acked, leased_until) = row.ok_or(InboxError::ConsumerMissing)?;
        if leased_until.is_some_and(|until| until > now) {
            return Ok(None);
        }
        let event: Option<(i64,String,String,String,Vec<u8>)> = tx.query_row("SELECT position,event_id,version,source_hash,payload FROM inbox_events WHERE position>?1 ORDER BY position LIMIT 1", [acked], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let Some((position, event_id, version, authoritative_hash, payload)) = event else {
            return Ok(None);
        };
        let mut random = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| InboxError::Storage)?;
        let token = base64url(&random);
        tx.execute("UPDATE inbox_consumers SET lease_position=?1,lease_token=?2,lease_until=?3 WHERE consumer=?4 AND filter_version=?5", params![position,token,until,consumer,filter_version])?;
        if cancel.is_cancelled() {
            return Err(InboxError::Cancelled);
        }
        tx.commit()?;
        Ok(Some(InboxDelivery {
            consumer_id: consumer.to_owned(),
            filter_version: filter_version.to_owned(),
            event_id,
            version,
            authoritative_hash,
            payload,
            ack_token: token,
            lease_until_ms: until,
        }))
    }
    pub fn ack(
        &mut self,
        consumer: &str,
        filter_version: &str,
        ack_token: &str,
    ) -> Result<(), InboxError> {
        self.ack_at(consumer, filter_version, ack_token, now_ms()?)
    }
    fn ack_at(
        &mut self,
        consumer: &str,
        filter_version: &str,
        token: &str,
        now: i64,
    ) -> Result<(), InboxError> {
        if !valid(consumer) || !valid(filter_version) || !valid(token) {
            return Err(InboxError::Invalid);
        }
        self.check()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.query_row("SELECT gap FROM inbox_meta WHERE id=1", [], |r| {
            r.get::<_, bool>(0)
        })? {
            return Err(InboxError::Gap);
        }
        let changed = tx.execute("UPDATE inbox_consumers SET ack_position=lease_position,lease_position=NULL,lease_token=NULL,lease_until=NULL WHERE consumer=?1 AND filter_version=?2 AND lease_token=?3 AND lease_until>?4", params![consumer,filter_version,token,now])?;
        if changed != 1 {
            return Err(InboxError::StaleLease);
        }
        tx.commit()?;
        Ok(())
    }
    pub fn status(&self) -> Result<InboxStatus, InboxError> {
        self.check()?;
        Ok(self.db.query_row("SELECT cursor,gap,(SELECT COUNT(*) FROM inbox_events),(SELECT COALESCE(SUM(length(payload)),0) FROM inbox_events) FROM inbox_meta WHERE id=1", [], |r| { let cursor: Option<String> = r.get(0)?; Ok(InboxStatus { verified_cursor: cursor.clone(), enqueued_cursor: cursor, gap: r.get(1)?, retained_events:r.get(2)?, retained_payload_bytes:r.get(3)? }) })?)
    }
    pub fn consumer_status(
        &self,
        consumer: &str,
        version: &str,
    ) -> Result<InboxConsumerStatus, InboxError> {
        self.check()?;
        self.db.query_row("SELECT ack_position,lease_position,lease_until,(SELECT COUNT(*) FROM inbox_events WHERE position>ack_position) FROM inbox_consumers WHERE consumer=?1 AND filter_version=?2", params![consumer,version], |r| Ok(InboxConsumerStatus { acknowledged_position:r.get(0)?, leased_position:r.get(1)?, lease_until_ms:r.get(2)?, pending_events:r.get(3)? })).optional()?.ok_or(InboxError::ConsumerMissing)
    }
}

#[cfg(unix)]
fn check_file(path: &Path, optional: bool) -> Result<(), InboxError> {
    use std::os::unix::fs::MetadataExt;
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(InboxError::Protection),
    };
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || meta.mode() & 0o777 != 0o600
        || meta.uid() != unsafe { libc::geteuid() }
    {
        return Err(InboxError::Protection);
    }
    Ok(())
}
#[cfg(unix)]
fn check_files(path: &Path) -> Result<(), InboxError> {
    crate::secure_state::check_private_directory(path.parent().ok_or(InboxError::Protection)?)
        .map_err(|_| InboxError::Protection)?;
    check_file(path, false)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        check_file(Path::new(&sidecar), true)?;
    }
    Ok(())
}
#[cfg(unix)]
fn protect(path: &Path) -> Result<(), InboxError> {
    use std::os::unix::fs::OpenOptionsExt;
    crate::secure_state::check_private_directory(path.parent().ok_or(InboxError::Protection)?)
        .map_err(|_| InboxError::Protection)?;
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(InboxError::Protection),
    }
    check_files(path)
}
#[cfg(not(unix))]
fn protect(_: &Path) -> Result<(), InboxError> {
    Err(InboxError::Unsupported)
}
#[cfg(not(unix))]
fn check_files(_: &Path) -> Result<(), InboxError> {
    Err(InboxError::Unsupported)
}

#[cfg(all(test, unix))]
mod tests;
