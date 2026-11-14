//! Durable compact presentation scheduling. No bodies, business effects or host IO.
use crate::participant::{ParticipantError, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, sync::Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceHead {
    pub key: String,
    pub checkpoint: u64,
    pub has_pending: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Range {
    pub key: String,
    pub after: u64,
    pub through: u64,
    pub backlog: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wake {
    pub batch: String,
    pub attempt: u64,
    pub revision: u64,
    pub ranges: Vec<Range>,
    pub self_test: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct Source {
    cursor: u64,
    backlog: bool,
}
#[derive(Serialize, Deserialize)]
struct Batch {
    wake: Wake,
    observed: bool,
    retired: bool,
}
#[derive(Serialize, Deserialize)]
struct State {
    owner: String,
    mode: String,
    revision: u64,
    probe: bool,
    probe_resumes: bool,
    sources: BTreeMap<String, Source>,
    batches: Vec<Batch>,
    active: Option<String>,
    retry_at: i64,
    #[serde(default)]
    last_self_test_at_ms: Option<i64>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            owner: String::new(),
            mode: "VERIFYING".into(),
            revision: 1,
            probe: true,
            probe_resumes: true,
            sources: BTreeMap::new(),
            batches: vec![],
            active: None,
            retry_at: 0,
            last_self_test_at_ms: None,
        }
    }
}
fn error(code: &str) -> ParticipantError {
    ParticipantError::local(code, "NOTIFICATION_DELIVERY")
}
fn db_error(_: rusqlite::Error) -> ParticipantError {
    error("NOTIFICATION_STATE_FAILED")
}
fn valid(id: &str) -> Result<()> {
    if crate::communication_store::identifier(id) {
        Ok(())
    } else {
        Err(error("NOTIFICATION_SCOPE_INVALID"))
    }
}
pub struct Store {
    db: Mutex<Connection>,
}
impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        let db = crate::communication_store::single_owner_database(
            directory,
            "notification-delivery.sqlite",
        )
        .map_err(error)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS notification_owners(owner TEXT PRIMARY KEY,state TEXT NOT NULL);").map_err(db_error)?;
        Ok(Self { db: Mutex::new(db) })
    }
    fn transaction<T>(&self, owner: &str, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        valid(owner)?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let saved: Option<String> = tx
            .query_row(
                "SELECT state FROM notification_owners WHERE owner=?1",
                [owner],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let mut state: State = match saved.as_ref() {
            Some(encoded) => {
                if encoded.len() > 131072 {
                    return Err(error("NOTIFICATION_STATE_CAPACITY"));
                }
                serde_json::from_str(encoded).map_err(|_| error("NOTIFICATION_STATE_INVALID"))?
            }
            None => {
                let mut state = State::default();
                state.owner = owner.into();
                state
            }
        };
        if state.owner != owner
            || state.sources.len() > 8
            || state.batches.len() > 64
            || !matches!(state.mode.as_str(), "PAUSED" | "VERIFYING" | "RUNNING")
        {
            return Err(error("NOTIFICATION_STATE_INVALID"));
        }
        if state
            .sources
            .keys()
            .any(|key| !crate::communication_store::identifier(key))
        {
            return Err(error("NOTIFICATION_STATE_INVALID"));
        }
        let live: Vec<_> = state
            .batches
            .iter()
            .filter(|b| !b.observed && !b.retired)
            .collect();
        if live.len() > 1 || live.first().map(|b| b.wake.batch.as_str()) != state.active.as_deref()
        {
            return Err(error("NOTIFICATION_STATE_INVALID"));
        }
        for batch in &state.batches {
            if batch.wake.ranges.len() > 8
                || batch.wake.revision > state.revision
                || !crate::communication_store::identifier(&batch.wake.batch)
            {
                return Err(error("NOTIFICATION_STATE_INVALID"));
            }
            for range in &batch.wake.ranges {
                if range.after > range.through
                    || !crate::communication_store::identifier(&range.key)
                    || (!batch.observed
                        && !batch.retired
                        && !state.sources.contains_key(&range.key))
                {
                    return Err(error("NOTIFICATION_STATE_INVALID"));
                }
            }
        }
        // Pre-verification candidate records must qualify once rather than
        // claiming automatic receiving from their historical RUNNING flag.
        if state.mode == "RUNNING" && state.last_self_test_at_ms.is_none() {
            invalidate(&mut state);
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or_else(|| error("NOTIFICATION_REVISION_EXHAUSTED"))?;
            state.mode = "VERIFYING".into();
            state.probe = true;
            state.probe_resumes = true;
        }
        let result = f(&mut state)?;
        // One active batch plus the most recent completed tokens; no live token eviction.
        while state.batches.len() > 64 {
            let Some(index) = state.batches.iter().position(|b| b.observed || b.retired) else {
                return Err(error("NOTIFICATION_STATE_CAPACITY"));
            };
            state.batches.remove(index);
        }
        let encoded =
            serde_json::to_string(&state).map_err(|_| error("NOTIFICATION_STATE_INVALID"))?;
        if encoded.len() > 131072 {
            return Err(error("NOTIFICATION_STATE_CAPACITY"));
        }
        if saved.as_deref() != Some(encoded.as_str()) {
            let (owners, bytes): (usize, usize) = tx
                .query_row(
                    "SELECT count(*),COALESCE(sum(length(state)),0) FROM notification_owners",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(db_error)?;
            if saved.is_none() && owners >= 128
                || bytes
                    .saturating_sub(saved.as_ref().map_or(0, String::len))
                    .saturating_add(encoded.len())
                    > 16 * 1024 * 1024
            {
                return Err(error("NOTIFICATION_STATE_CAPACITY"));
            }
            tx.execute("INSERT INTO notification_owners VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET state=excluded.state", params![owner, encoded]).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(result)
    }
    pub fn status(&self, owner: &str) -> Result<Value> {
        self.transaction(owner, |s| Ok(status(s)))
    }
    /// One coherent remote-fence snapshot; never combine a current revision
    /// with a caller's potentially stale wake or absence of one.
    pub(crate) fn snapshot(&self, owner: &str) -> Result<(Value, Option<Wake>)> {
        self.transaction(owner, |s| {
            let wake = s
                .active
                .as_ref()
                .and_then(|id| s.batches.iter().find(|b| &b.wake.batch == id))
                .map(|b| b.wake.clone());
            Ok((status(s), wake))
        })
    }
    pub fn control(&self, owner: &str, mode: &str) -> Result<Value> {
        self.transaction(owner, |s| {
            if !matches!(mode, "pause" | "resume" | "self_test") {
                return Err(error("NOTIFICATION_CONTROL_INVALID"));
            }
            if mode == "pause" && s.mode == "PAUSED" && !s.probe
                || mode == "resume" && s.mode == "VERIFYING" && s.probe && s.probe_resumes
                || mode == "self_test" && s.probe
            {
                return Ok(status(s));
            }
            s.revision = s
                .revision
                .checked_add(1)
                .ok_or_else(|| error("NOTIFICATION_REVISION_EXHAUSTED"))?;
            invalidate(s);
            match mode {
                "pause" => {
                    s.mode = "PAUSED".into();
                    s.probe = false;
                    s.probe_resumes = false;
                }
                "resume" => {
                    s.mode = "VERIFYING".into();
                    s.probe = true;
                    s.probe_resumes = true;
                }
                _ => {
                    s.probe = true;
                    s.probe_resumes = s.mode != "PAUSED";
                    if s.probe_resumes {
                        s.mode = "VERIFYING".into();
                    }
                }
            }
            Ok(status(s))
        })
    }
    pub fn due(&self, owner: &str, heads: &[SourceHead], now: i64) -> Result<Option<Wake>> {
        self.transaction(owner, |s| {
            if heads.len() > 8 {
                return Err(error("NOTIFICATION_SOURCE_LIMIT"));
            }
            let mut selected = BTreeMap::new();
            for h in heads {
                valid(&h.key)?;
                if selected.insert(h.key.clone(), h).is_some() {
                    return Err(error("NOTIFICATION_SOURCE_DUPLICATE"));
                }
            }
            // `heads` is the complete authorized binding snapshot, never a
            // partial healthy subset. Retire presentation metadata only.
            let removed: Vec<_> = s
                .sources
                .keys()
                .filter(|key| !selected.contains_key(*key))
                .cloned()
                .collect();
            let invalid_active = s.active.as_ref().is_some_and(|id| {
                s.batches.iter().any(|b| {
                    &b.wake.batch == id && b.wake.ranges.iter().any(|r| removed.contains(&r.key))
                })
            });
            if invalid_active {
                invalidate(s);
                s.revision = s
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("NOTIFICATION_REVISION_EXHAUSTED"))?;
            }
            for key in removed {
                s.sources.remove(&key);
            }
            for h in heads {
                if !s.sources.contains_key(&h.key) {
                    if s.sources.len() >= 8 {
                        return Err(error("NOTIFICATION_SOURCE_LIMIT"));
                    }
                    s.sources.insert(
                        h.key.clone(),
                        Source {
                            cursor: h.checkpoint,
                            backlog: h.has_pending,
                        },
                    );
                }
            }
            if s.mode == "PAUSED" && !s.probe {
                return Ok(None);
            }
            if s.active.is_none() {
                let ranges = if s.probe {
                    vec![]
                } else {
                    heads
                        .iter()
                        .filter_map(|h| {
                            let source = &s.sources[&h.key];
                            (h.checkpoint > source.cursor || source.backlog && h.has_pending).then(
                                || Range {
                                    key: h.key.clone(),
                                    after: source.cursor,
                                    through: h.checkpoint.max(source.cursor),
                                    backlog: source.backlog && h.has_pending,
                                },
                            )
                        })
                        .collect::<Vec<_>>()
                };
                if !s.probe && ranges.is_empty() {
                    return Ok(None);
                }
                for r in &ranges {
                    let source = s.sources.get_mut(&r.key).unwrap();
                    source.cursor = r.through;
                    source.backlog = false;
                }
                s.revision = s
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("NOTIFICATION_REVISION_EXHAUSTED"))?;
                let batch = crate::communication_host::random_token().map_err(error)?;
                s.batches.push(Batch {
                    wake: Wake {
                        batch: batch.clone(),
                        attempt: 0,
                        revision: s.revision,
                        ranges,
                        self_test: s.probe,
                    },
                    observed: false,
                    retired: false,
                });
                s.active = Some(batch);
                s.retry_at = now;
            }
            if s.retry_at > now.saturating_add(300_000) {
                s.retry_at = now;
            }
            if now < s.retry_at {
                return Ok(None);
            }
            let id = s.active.as_ref().unwrap();
            let b = s
                .batches
                .iter_mut()
                .find(|b| &b.wake.batch == id)
                .ok_or_else(|| error("NOTIFICATION_STATE_INVALID"))?;
            b.wake.attempt = b
                .wake
                .attempt
                .checked_add(1)
                .ok_or_else(|| error("NOTIFICATION_ATTEMPT_EXHAUSTED"))?;
            // Stable bounded jitter; retry reservation is committed before caller IO.
            let hash =
                peerwork_core::crypto::sha256_hex(format!("{}:{}", id, b.wake.attempt).as_bytes());
            let jitter = u16::from_str_radix(&hash[..4], 16).unwrap_or(0) as i64 % 1001;
            let delay = (3000i64.saturating_mul(1i64 << b.wake.attempt.saturating_sub(1).min(7))
                + jitter)
                .min(300_000);
            s.retry_at = now.saturating_add(delay);
            Ok(Some(b.wake.clone()))
        })
    }
    /// Inspect the active notification without admitting an attempt or changing
    /// its retry deadline. Callers must not expose a self-test token through
    /// ordinary inbox reads: only host delivery establishes that challenge.
    pub(crate) fn current(&self, owner: &str) -> Result<Option<Wake>> {
        self.transaction(owner, |s| {
            Ok(s.active.as_ref().and_then(|id| {
                s.batches
                    .iter()
                    .find(|b| &b.wake.batch == id)
                    .map(|b| b.wake.clone())
            }))
        })
    }
    pub fn batch(&self, owner: &str, batch: &str) -> Result<Wake> {
        self.transaction(owner, |s| {
            s.batches
                .iter()
                .find(|b| b.wake.batch == batch)
                .map(|b| b.wake.clone())
                .ok_or_else(|| error("BATCH_EXPIRED"))
        })
    }
    pub fn observed(&self, owner: &str, batch: &str) -> Result<Value> {
        self.transaction(owner, |s| {
            let b = s
                .batches
                .iter_mut()
                .find(|b| b.wake.batch == batch)
                .ok_or_else(|| error("BATCH_EXPIRED"))?;
            let current = s.active.as_deref() == Some(batch) && b.wake.revision == s.revision;
            b.observed = true;
            if current {
                s.revision = s
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("NOTIFICATION_REVISION_EXHAUSTED"))?;
                if b.wake.self_test {
                    s.last_self_test_at_ms = Some(crate::participant_store::now());
                    s.probe = false;
                    if s.probe_resumes {
                        s.mode = "RUNNING".into();
                    }
                }
                s.active = None;
                s.retry_at = 0;
            }
            let mut value = status(s);
            value["accepted_generation"] = json!(current);
            value["notification_observed"] = json!(true);
            Ok(value)
        })
    }
    pub fn admission(&self, owner: &str, batch: &str, revision: u64) -> Result<bool> {
        self.transaction(owner, |s| {
            Ok(s.revision == revision
                && s.active.as_deref() == Some(batch)
                && (s.mode != "PAUSED" || s.probe)
                && s.batches.iter().any(|b| {
                    b.wake.batch == batch
                        && !b.observed
                        && !b.retired
                        && b.wake.revision == revision
                }))
        })
    }
}
fn invalidate(s: &mut State) {
    if let Some(id) = s.active.take() {
        if let Some(b) = s.batches.iter_mut().find(|b| b.wake.batch == id) {
            for r in &b.wake.ranges {
                if let Some(source) = s.sources.get_mut(&r.key) {
                    source.cursor = source.cursor.min(r.after);
                    source.backlog |= r.backlog;
                }
            }
            b.retired = true; // Retirement is not an assertion of model observation.
        }
    }
    s.retry_at = 0;
}
fn status(s: &State) -> Value {
    let pending = s
        .active
        .as_ref()
        .and_then(|id| s.batches.iter().find(|b| &b.wake.batch == id));
    json!({"state":s.mode,"revision":s.revision,"self_test_requested":s.probe,"automatic_receiving":if s.mode=="PAUSED"{"PAUSED"}else if s.mode=="RUNNING"&&s.last_self_test_at_ms.is_some(){"VERIFIED"}else{"VERIFYING"},"last_verified_at":s.last_self_test_at_ms,"verification_time_basis":"LOCAL_OBSERVATION","pending":pending.map(|b| json!({"attempt":b.wake.attempt,"self_test":b.wake.self_test,"source_count":b.wake.ranges.len(),"retry_at":s.retry_at})),"source_count":s.sources.len(),"retained_batches":s.batches.len()})
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(crate::test_support::ProtectedTestDir);
    impl Fixture {
        fn new() -> Self {
            Self(crate::test_support::protected_test_dir())
        }
        fn open(&self) -> Store {
            Store::open(&self.0.path().join("state")).unwrap()
        }
    }
    fn head(n: u64) -> Vec<SourceHead> {
        vec![SourceHead {
            key: "scope".into(),
            checkpoint: n,
            has_pending: true,
        }]
    }
    fn ready(s: &Store, owner: &str, heads: &[SourceHead]) {
        let test = s.due(owner, heads, 0).unwrap().unwrap();
        assert!(test.self_test);
        assert_eq!(s.observed(owner, &test.batch).unwrap()["state"], "RUNNING");
    }
    #[test]
    fn restart_freezes_snapshot_and_reserves_retry_before_io() {
        let f = Fixture::new();
        let s = f.open();
        ready(&s, "owner", &head(68));
        let first = s.due("owner", &head(68), 0).unwrap().unwrap();
        assert!(first.ranges[0].backlog);
        assert_eq!(first.ranges[0].after, 68);
        drop(s);
        let s = f.open();
        assert!(s.due("owner", &head(634), 1).unwrap().is_none());
        let retry = s.due("owner", &head(634), 4000).unwrap().unwrap();
        assert_eq!(retry.batch, first.batch);
        assert_eq!(retry.ranges[0].through, 68);
        assert_eq!(retry.attempt, 2);
        s.observed("owner", &first.batch).unwrap();
        let next = s.due("owner", &head(634), 4001).unwrap().unwrap();
        assert_eq!(next.ranges[0].after, 68);
        assert_eq!(next.ranges[0].through, 634);
        assert!(!next.ranges[0].backlog);
    }
    #[test]
    fn late_observation_cannot_unpause_and_other_owner_is_independent() {
        let f = Fixture::new();
        let s = f.open();
        ready(&s, "one", &head(1));
        ready(&s, "two", &head(1));
        let old = s.due("one", &head(1), 0).unwrap().unwrap();
        s.control("one", "pause").unwrap();
        assert!(!s.admission("one", &old.batch, old.revision).unwrap());
        assert_eq!(s.observed("one", &old.batch).unwrap()["state"], "PAUSED");
        assert!(s.due("one", &head(2), 9000).unwrap().is_none());
        assert!(s.due("two", &head(2), 0).unwrap().is_some());
        s.control("one", "self_test").unwrap();
        let test = s.due("one", &head(2), 10000).unwrap().unwrap();
        assert!(test.self_test);
        assert!(s.admission("one", &test.batch, test.revision).unwrap());
        assert_eq!(s.observed("one", &test.batch).unwrap()["state"], "PAUSED");
        s.control("one", "resume").unwrap();
        let test = s.due("one", &head(2), 10001).unwrap().unwrap();
        assert!(test.self_test);
        s.observed("one", &test.batch).unwrap();
        let wake = s.due("one", &head(2), 10002).unwrap().unwrap();
        assert!(wake.ranges[0].backlog);
        assert_eq!(wake.ranges[0].through, 2);
    }
    #[test]
    fn paused_latch_survives_restart_and_status_never_exposes_test_token() {
        let f = Fixture::new();
        let s = f.open();
        let test = s.due("owner", &head(3), 0).unwrap().unwrap();
        assert!(!s.status("owner").unwrap().to_string().contains(&test.batch));
        s.control("owner", "pause").unwrap();
        drop(s);
        let s = f.open();
        assert_eq!(s.status("owner").unwrap()["state"], "PAUSED");
        assert!(s.due("owner", &head(4), 10000).unwrap().is_none());
        s.observed("owner", &test.batch).unwrap();
        assert_eq!(s.status("owner").unwrap()["state"], "PAUSED");
    }
    #[test]
    fn retained_tokens_are_bounded_without_losing_current_wake() {
        let f = Fixture::new();
        let s = f.open();
        ready(&s, "owner", &head(0));
        let old = s.due("owner", &head(0), 0).unwrap().unwrap();
        s.observed("owner", &old.batch).unwrap();
        for n in 1..80 {
            let wake = s.due("owner", &head(n), n as i64).unwrap().unwrap();
            s.observed("owner", &wake.batch).unwrap();
        }
        assert!(s.batch("owner", &old.batch).is_err());
        let live = s.due("owner", &head(80), 80).unwrap().unwrap();
        assert_eq!(s.status("owner").unwrap()["retained_batches"], 64);
        assert_eq!(s.batch("owner", &live.batch).unwrap().batch, live.batch);
        assert!(s.batch("other", &live.batch).is_err());
    }
    #[test]
    fn unchanged_reads_do_not_write_and_corrupt_owner_binding_is_rejected() {
        let f = Fixture::new();
        let s = f.open();
        let wake = s.due("owner", &head(1), 0).unwrap().unwrap();
        let before = s.db.lock().unwrap().total_changes();
        s.status("owner").unwrap();
        let (snapshot, snap_wake) = s.snapshot("owner").unwrap();
        assert_eq!(
            snapshot["revision"].as_u64(),
            Some(snap_wake.as_ref().unwrap().revision)
        );
        let current = s.current("owner").unwrap().unwrap();
        assert_eq!(current.batch, wake.batch);
        assert_eq!(current.attempt, wake.attempt);
        s.batch("owner", &wake.batch).unwrap();
        assert!(s.admission("owner", &wake.batch, wake.revision).unwrap());
        assert!(s.due("owner", &head(2), 1).unwrap().is_none());
        assert_eq!(s.db.lock().unwrap().total_changes(), before);
        s.db.lock().unwrap().execute("INSERT INTO notification_owners SELECT 'other',state FROM notification_owners WHERE owner='owner'", []).unwrap();
        assert!(s.status("other").is_err());
    }
    #[test]
    fn repeated_control_keeps_probe_and_each_batch_has_a_new_fence() {
        let f = Fixture::new();
        let s = f.open();
        let test = s.due("owner", &head(1000), 0).unwrap().unwrap();
        let revision = s.control("owner", "resume").unwrap()["revision"]
            .as_u64()
            .unwrap();
        assert_eq!(revision, test.revision);
        assert_eq!(s.current("owner").unwrap().unwrap().batch, test.batch);
        s.observed("owner", &test.batch).unwrap();
        let wake = s.due("owner", &head(1001), 1).unwrap().unwrap();
        assert!(wake.revision > test.revision);
        assert!(wake.ranges[0].backlog);
        assert_eq!((wake.ranges[0].after, wake.ranges[0].through), (1000, 1001));
        assert!(!s.admission("owner", &test.batch, test.revision).unwrap());
        let paused = s.control("owner", "pause").unwrap();
        assert_eq!(
            s.control("owner", "pause").unwrap()["revision"],
            paused["revision"]
        );
        s.control("owner", "resume").unwrap();
        let probe = s.due("owner", &head(1002), 2).unwrap().unwrap();
        assert!(probe.revision > wake.revision);
        s.control("owner", "resume").unwrap();
        assert_eq!(s.current("owner").unwrap().unwrap().batch, probe.batch);
    }
    #[test]
    fn thousand_old_pending_items_are_one_bounded_notice_and_fresh_heads_progress() {
        let f = Fixture::new();
        let s = f.open();
        ready(&s, "owner", &head(1000));
        let backlog = s.due("owner", &head(1000), 0).unwrap().unwrap();
        assert_eq!(backlog.ranges.len(), 1);
        assert!(backlog.ranges[0].backlog);
        for n in 1001..2001 {
            assert!(s.due("owner", &head(n), 1).unwrap().is_none());
        }
        assert_eq!(s.current("owner").unwrap().unwrap().ranges[0].through, 1000);
        s.observed("owner", &backlog.batch).unwrap();
        let fresh = s.due("owner", &head(2000), 2).unwrap().unwrap();
        assert_eq!(fresh.ranges.len(), 1);
        assert!(!fresh.ranges[0].backlog);
        assert_eq!(
            (fresh.ranges[0].after, fresh.ranges[0].through),
            (1000, 2000)
        );
        assert!(fresh.revision > backlog.revision);
        s.observed("owner", &fresh.batch).unwrap();
        assert!(s.due("owner", &head(2000), 300000).unwrap().is_none());
        let size: usize =
            s.db.lock()
                .unwrap()
                .query_row(
                    "SELECT length(state) FROM notification_owners WHERE owner='owner'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
        assert!(size < 4096, "No per-item notification tombstones or bodies");
    }
    #[test]
    fn authoritative_replacement_retires_old_scope_without_rewinding_other_cursors() {
        let f = Fixture::new();
        let s = f.open();
        ready(&s, "owner", &head(10));
        let initial = s.due("owner", &head(10), 0).unwrap().unwrap();
        s.observed("owner", &initial.batch).unwrap();
        for n in 0..20 {
            let heads = vec![
                SourceHead {
                    key: "scope".into(),
                    checkpoint: 10,
                    has_pending: true,
                },
                SourceHead {
                    key: format!("replacement{n}"),
                    checkpoint: 100,
                    has_pending: true,
                },
            ];
            let wake = s.due("owner", &heads, n).unwrap().unwrap();
            assert_eq!(wake.ranges.len(), 1);
            assert_eq!(wake.ranges[0].key, format!("replacement{n}"));
            if n > 0 {
                assert!(wake.revision > initial.revision);
            }
        }
        assert_eq!(s.status("owner").unwrap()["source_count"], 2);
        let stale = s.current("owner").unwrap().unwrap();
        s.control("owner", "pause").unwrap();
        let replaced = vec![SourceHead {
            key: "scope".into(),
            checkpoint: 11,
            has_pending: true,
        }];
        assert!(s.due("owner", &replaced, 100).unwrap().is_none());
        s.observed("owner", &stale.batch).unwrap();
        assert_eq!(s.status("owner").unwrap()["state"], "PAUSED");
        assert!(!s.admission("owner", &stale.batch, stale.revision).unwrap());
    }
    #[test]
    fn only_current_probe_records_local_verification_and_pause_stays_distinct() {
        let f = Fixture::new();
        let s = f.open();
        assert_eq!(
            s.status("owner").unwrap()["automatic_receiving"],
            "VERIFYING"
        );
        let old = s.due("owner", &head(1), 0).unwrap().unwrap();
        s.control("owner", "pause").unwrap();
        s.observed("owner", &old.batch).unwrap();
        assert!(s.status("owner").unwrap()["last_verified_at"].is_null());
        let request = s.control("owner", "self_test").unwrap();
        assert_eq!(request["self_test_requested"], true);
        assert!(request.get("batch").is_none());
        let paused_probe = s.due("owner", &head(1), 1).unwrap().unwrap();
        let paused = s.observed("owner", &paused_probe.batch).unwrap();
        assert_eq!(paused["automatic_receiving"], "PAUSED");
        assert!(paused["last_verified_at"].is_i64());
        s.control("owner", "resume").unwrap();
        assert_eq!(
            s.status("owner").unwrap()["automatic_receiving"],
            "VERIFYING"
        );
        let current = s.due("owner", &head(1), 2).unwrap().unwrap();
        assert_eq!(
            s.observed("owner", &current.batch).unwrap()["automatic_receiving"],
            "VERIFIED"
        );
        let verified = s.status("owner").unwrap()["last_verified_at"].clone();
        s.observed("owner", &old.batch).unwrap();
        assert_eq!(s.status("owner").unwrap()["last_verified_at"], verified);
    }
    #[test]
    fn older_candidate_running_record_requires_fresh_probe() {
        let f = Fixture::new();
        let s = f.open();
        ready(&s, "owner", &head(1));
        let wire: String =
            s.db.lock()
                .unwrap()
                .query_row(
                    "SELECT state FROM notification_owners WHERE owner='owner'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
        let mut value: Value = serde_json::from_str(&wire).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("last_self_test_at_ms");
        s.db.lock()
            .unwrap()
            .execute(
                "UPDATE notification_owners SET state=?1 WHERE owner='owner'",
                [value.to_string()],
            )
            .unwrap();
        assert_eq!(
            s.status("owner").unwrap()["automatic_receiving"],
            "VERIFYING"
        );
        assert!(s.due("owner", &head(1), 1).unwrap().unwrap().self_test);
    }
}
