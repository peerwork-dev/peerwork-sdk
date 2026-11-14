//! Bridge-local generation and attempt fencing. Never performs host IO.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};
type R<T> = Result<T, &'static str>;
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    owner: String,
    revision: u64,
    batch: Option<String>,
    paused: bool,
    attempt: u64,
    outcome: Option<Value>,
}
struct Inner {
    db: Connection,
    inflight: BTreeMap<String, (String, u64)>,
}
pub(crate) struct Fence {
    inner: Mutex<Inner>,
}
fn valid(value: &str) -> R<()> {
    if crate::communication_store::identifier(value) {
        Ok(())
    } else {
        Err("NOTIFICATION_FENCE_SCOPE_INVALID")
    }
}
fn load(db: &Connection, owner: &str) -> R<Option<Record>> {
    let saved: Option<String> = db
        .query_row(
            "SELECT state FROM notification_fences WHERE owner=?1",
            [owner],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
    saved
        .map(|wire| {
            if wire.len() > 32768 {
                return Err("NOTIFICATION_FENCE_STATE_INVALID");
            }
            let row: Record =
                serde_json::from_str(&wire).map_err(|_| "NOTIFICATION_FENCE_STATE_INVALID")?;
            if row.owner != owner
                || row.revision == 0
                || row.batch.as_deref().is_some_and(|b| valid(b).is_err())
            {
                return Err("NOTIFICATION_FENCE_STATE_INVALID");
            }
            Ok(row)
        })
        .transpose()
}
fn save(db: &Connection, row: &Record) -> R<()> {
    let wire = serde_json::to_string(row).map_err(|_| "NOTIFICATION_FENCE_STATE_INVALID")?;
    if wire.len() > 32768 {
        return Err("NOTIFICATION_FENCE_CAPACITY");
    }
    let count: u64 = db
        .query_row("SELECT count(*) FROM notification_fences", [], |r| r.get(0))
        .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
    if count >= 128 && load(db, &row.owner)?.is_none() {
        return Err("NOTIFICATION_FENCE_CAPACITY");
    }
    db.execute("INSERT INTO notification_fences VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET state=excluded.state",params![row.owner,wire]).map_err(|_|"NOTIFICATION_FENCE_STATE_FAILED")?;
    Ok(())
}
impl Fence {
    pub(crate) fn open(directory: &Path) -> R<Arc<Self>> {
        let db = crate::communication_store::single_owner_database(
            directory,
            "notification-fence.sqlite",
        )?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS notification_fences(owner TEXT PRIMARY KEY,state TEXT NOT NULL);").map_err(|_|"NOTIFICATION_FENCE_STATE_FAILED")?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                db,
                inflight: BTreeMap::new(),
            }),
        }))
    }
    pub(crate) fn control(
        &self,
        owner: &str,
        revision: u64,
        batch: Option<&str>,
        paused: bool,
    ) -> R<Value> {
        valid(owner)?;
        if let Some(batch) = batch {
            valid(batch)?;
        }
        if revision == 0 {
            return Err("NOTIFICATION_FENCE_REVISION_INVALID");
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        let tx = inner
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        let old = load(&tx, owner)?;
        if let Some(old) = &old {
            if revision < old.revision {
                return Err("NOTIFICATION_FENCE_STALE");
            }
            if revision == old.revision && (old.batch.as_deref() != batch || old.paused != paused) {
                return Err("NOTIFICATION_FENCE_CONFLICT");
            }
        }
        if old.as_ref().is_none_or(|old| old.revision != revision) {
            save(
                &tx,
                &Record {
                    owner: owner.into(),
                    revision,
                    batch: batch.map(str::to_owned),
                    paused,
                    attempt: old
                        .as_ref()
                        .filter(|old| batch.is_some() && old.batch.as_deref() == batch)
                        .map_or(0, |old| old.attempt),
                    outcome: old
                        .as_ref()
                        .filter(|old| batch.is_some() && old.batch.as_deref() == batch)
                        .and_then(|old| old.outcome.clone()),
                },
            )?;
        }
        tx.commit().map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        Ok(
            json!({"state":"FENCE_INSTALLED","revision":revision,"paused":paused,"already_inflight":inner.inflight.contains_key(owner),"host_accepted_input_retractable":false}),
        )
    }
    pub(crate) fn check(&self, owner: &str, revision: u64, batch: &str) -> R<bool> {
        valid(owner)?;
        valid(batch)?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        Ok(load(&inner.db, owner)?
            .is_some_and(|r| r.revision == revision && r.batch.as_deref() == Some(batch)))
    }
    pub(crate) fn legacy_allowed(&self, owner: &str) -> R<bool> {
        valid(owner)?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        // Installing a compact fence opts this owner into the new pipeline.
        // A RUNNING compact owner must not also admit legacy full-frame input.
        Ok(load(&inner.db, owner)?.is_none())
    }
    /// None admits one input; Some returns its durable outcome and forbids a
    /// second send. A paused control with a batch explicitly admits that probe.
    pub(crate) fn begin(
        &self,
        owner: &str,
        revision: u64,
        batch: &str,
        attempt: u64,
    ) -> R<Option<Value>> {
        valid(owner)?;
        valid(batch)?;
        if attempt == 0 {
            return Err("NOTIFICATION_FENCE_ATTEMPT_INVALID");
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        let busy = inner.inflight.contains_key(owner);
        let tx = inner
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        let mut row = load(&tx, owner)?.ok_or("NOTIFICATION_FENCE_NOT_CONFIGURED")?;
        if row.revision != revision || row.batch.as_deref() != Some(batch) {
            return Err("NOTIFICATION_FENCE_STALE");
        }
        if attempt < row.attempt {
            return Err("NOTIFICATION_FENCE_ATTEMPT_STALE");
        }
        if attempt == row.attempt {
            return Ok(Some(row.outcome.unwrap_or_else(
                || json!({"state":"RESULT_UNKNOWN","code":"NOTIFICATION_INPUT_UNRESOLVED"}),
            )));
        }
        if busy {
            return Err("NOTIFICATION_INPUT_IN_FLIGHT");
        }
        row.attempt = attempt;
        row.outcome =
            Some(json!({"state":"RESULT_UNKNOWN","code":"NOTIFICATION_INPUT_UNRESOLVED"}));
        save(&tx, &row)?;
        tx.commit().map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        inner.inflight.insert(owner.into(), (batch.into(), attempt));
        Ok(None)
    }
    pub(crate) fn finish(&self, owner: &str, batch: &str, attempt: u64, outcome: &Value) -> R<()> {
        valid(owner)?;
        valid(batch)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        // The provider calls finish only after this admitted physical IO has
        // returned. Release that process-local fact even if persistence fails;
        // the previously committed UNKNOWN still fences same-attempt replay.
        if inner
            .inflight
            .get(owner)
            .is_some_and(|(b, a)| b == batch && *a == attempt)
        {
            inner.inflight.remove(owner);
        }
        if !outcome.is_object() || outcome.to_string().len() > 16384 {
            return Err("NOTIFICATION_FENCE_OUTCOME_INVALID");
        }
        let tx = inner
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        if let Some(mut row) = load(&tx, owner)? {
            if row.batch.as_deref() == Some(batch)
                && row.attempt == attempt
                && row.outcome.as_ref() != Some(outcome)
            {
                // Only an unresolved original call may acquire a terminal fact.
                // Duplicate or delayed callbacks cannot rewrite accepted evidence.
                if row.outcome.as_ref().is_some_and(|v| {
                    matches!(v["state"].as_str(), Some("RESULT_UNKNOWN" | "HOST_QUEUED"))
                }) {
                    row.outcome = Some(outcome.clone());
                    save(&tx, &row)?;
                }
            }
        }
        tx.commit().map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(crate::test_support::ProtectedTestDir);
    impl Fixture {
        fn new() -> Self {
            Self(crate::test_support::protected_test_dir())
        }
    }
    #[test]
    fn unknown_after_restart_suppresses_same_attempt_but_new_attempt_recovers() {
        let f = Fixture::new();
        let fence = Fence::open(&f.0.path().join("state")).unwrap();
        fence.control("owner", 1, Some("batch"), false).unwrap();
        assert!(!fence.legacy_allowed("owner").unwrap());
        assert!(fence.legacy_allowed("unconfigured").unwrap());
        assert!(fence.begin("owner", 1, "batch", 1).unwrap().is_none());
        drop(fence);
        let fence = Fence::open(&f.0.path().join("state")).unwrap();
        assert_eq!(
            fence.begin("owner", 1, "batch", 1).unwrap().unwrap()["state"],
            "RESULT_UNKNOWN"
        );
        assert!(fence.begin("owner", 1, "batch", 2).unwrap().is_none());
        fence
            .finish(
                "owner",
                "batch",
                2,
                &json!({"state":"HOST_ACCEPTED","receipt":"turn"}),
            )
            .unwrap();
        assert_eq!(
            fence.begin("owner", 1, "batch", 2).unwrap().unwrap()["state"],
            "HOST_ACCEPTED"
        );
    }
    #[test]
    fn pause_is_independent_of_inflight_and_old_finish_cannot_overwrite_successor() {
        let f = Fixture::new();
        let fence = Fence::open(&f.0.path().join("state")).unwrap();
        fence.control("owner", 1, Some("old"), false).unwrap();
        fence.begin("owner", 1, "old", 1).unwrap();
        let paused = fence.control("owner", 2, None, true).unwrap();
        assert_eq!(paused["already_inflight"], true);
        assert!(!fence.check("owner", 1, "old").unwrap());
        assert!(!fence.legacy_allowed("owner").unwrap());
        assert!(fence.legacy_allowed("other").unwrap());
        assert!(fence.control("owner", 1, Some("old"), false).is_err());
        assert!(fence.control("owner", 2, Some("probe"), true).is_err());
        fence.control("owner", 3, Some("probe"), true).unwrap();
        assert!(fence.begin("owner", 3, "probe", 1).is_err());
        fence
            .finish("owner", "old", 1, &json!({"state":"HOST_ACCEPTED"}))
            .unwrap();
        assert!(fence.begin("owner", 3, "probe", 1).unwrap().is_none());
        fence
            .finish("owner", "old", 1, &json!({"state":"NOT_SENT"}))
            .unwrap();
        assert_eq!(
            fence.begin("owner", 3, "probe", 1).unwrap().unwrap()["state"],
            "RESULT_UNKNOWN"
        );
        fence
            .finish("owner", "probe", 1, &json!({"state":"HOST_ACCEPTED"}))
            .unwrap();
        fence
            .finish("owner", "probe", 1, &json!({"state":"NOT_SENT"}))
            .unwrap();
        assert_eq!(
            fence.begin("owner", 3, "probe", 1).unwrap().unwrap()["state"],
            "HOST_ACCEPTED"
        );
    }
    #[test]
    fn outcome_storage_failure_releases_completed_io_but_preserves_unknown_replay_fence() {
        let f = Fixture::new();
        let fence = Fence::open(&f.0.path().join("state")).unwrap();
        fence.control("owner", 1, Some("batch"), false).unwrap();
        assert!(fence.begin("owner", 1, "batch", 1).unwrap().is_none());
        fence.inner.lock().unwrap().db.execute_batch("CREATE TRIGGER reject_outcome BEFORE UPDATE ON notification_fences BEGIN SELECT RAISE(ABORT,'injected outcome persistence failure'); END;").unwrap();
        assert!(fence
            .finish("owner", "batch", 1, &json!({"state":"HOST_ACCEPTED"}))
            .is_err());
        assert_eq!(
            fence.begin("owner", 1, "batch", 1).unwrap().unwrap()["state"],
            "RESULT_UNKNOWN"
        );
        assert_eq!(
            fence.control("owner", 1, Some("batch"), false).unwrap()["already_inflight"],
            false
        );
        fence
            .inner
            .lock()
            .unwrap()
            .db
            .execute_batch("DROP TRIGGER reject_outcome;")
            .unwrap();
        assert!(fence.begin("owner", 1, "batch", 2).unwrap().is_none());
        fence
            .finish("owner", "batch", 2, &json!({"state":"HOST_ACCEPTED"}))
            .unwrap();
        assert_eq!(
            fence.begin("owner", 1, "batch", 2).unwrap().unwrap()["state"],
            "HOST_ACCEPTED"
        );
    }
}
