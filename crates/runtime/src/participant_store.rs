//! Bounded durable admission queue. Exact signed packets remain authoritative
//! in the native journal; this index owns scheduling, not remote effect truth.
use crate::{
    communication_store::single_owner_database as database,
    kernel_identity::KernelIdentity,
    kernel_intents::parent_operations::{open, seal},
    participant::{Capability, Invoke, Operation, ParticipantError, Result},
};
use peerwork_core::crypto::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const OUTCOME_RESERVE: usize = 262144;
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn storage() -> ParticipantError {
    state_error("STATE_FAILED")
}
fn corrupt() -> ParticipantError {
    state_error("STATE_INVALID")
}
fn state_error(code: &str) -> ParticipantError {
    ParticipantError {
        code: code.into(),
        phase: "LOCAL_STATE".into(),
        effect_certainty: "UNKNOWN".into(),
        recovery: "OBSERVE_OR_RECOVER_ORIGINAL_OPERATION".into(),
        operation_id: None,
    }
}
pub(crate) struct Store {
    db: Connection,
    binding: String,
}
impl Store {
    pub fn open(directory: &Path, identity: &KernelIdentity, origin: &str) -> Result<Self> {
        let db = database(directory, "participant.sqlite").map_err(|_| storage())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS participant_meta(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL,pending INTEGER NOT NULL,allocated INTEGER NOT NULL,rows INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS participant_operations(session TEXT NOT NULL,id TEXT NOT NULL,input_hash TEXT NOT NULL,action TEXT NOT NULL,
            workspace TEXT,instance TEXT,protocol TEXT,status TEXT NOT NULL,input BLOB NOT NULL,outcome BLOB,command_id TEXT,
            failures INTEGER NOT NULL DEFAULT 0,next_retry INTEGER NOT NULL DEFAULT 0,allocation INTEGER NOT NULL,lane INTEGER NOT NULL,
            PRIMARY KEY(session,id));
            CREATE INDEX IF NOT EXISTS participant_due ON participant_operations(status,lane,next_retry,session,id);")
            .map_err(|_|storage())?;
        let binding=json!({"format":"peerwork.participant-store.v1","actor":identity.actor_id(),"key":identity.key_id(),"origin":origin}).to_string();
        db.execute(
            "INSERT OR IGNORE INTO participant_meta VALUES(1,?1,0,0,0)",
            [&binding],
        )
        .map_err(|_| storage())?;
        let old: String = db
            .query_row("SELECT binding FROM participant_meta WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| storage())?;
        if old != binding {
            return Err(ParticipantError::local(
                "STATE_BINDING_MISMATCH",
                "LOCAL_STATE",
            ));
        }
        Ok(Self { db, binding })
    }
    fn aad(&self, session: &str, id: &str, hash: &str, kind: &str) -> String {
        json!({"format":"peerwork.participant-local.v1","binding":self.binding,"session":session,"operation_id":id,"input_hash":hash,"kind":kind}).to_string()
    }
    pub fn reset_running(&self) -> Result<()> {
        self.db.execute("UPDATE participant_operations SET status='PENDING',next_retry=0 WHERE status='RUNNING'",[]).map_err(|_|storage())?;
        Ok(())
    }
    pub fn reserve(
        &mut self,
        session: &str,
        request: &Invoke,
        identity: &KernelIdentity,
        max_pending: usize,
        max_bytes: usize,
    ) -> Result<Operation> {
        let wire = serde_json::to_string(request).map_err(|_| corrupt())?;
        let hash = sha256_hex(wire.as_bytes());
        if let Some(old) = self.hash(session, &request.operation_id)? {
            if old != hash {
                return Err(ParticipantError::local(
                    "OPERATION_INPUT_CONFLICT",
                    "PREPARATION",
                ));
            }
            return self.get(session, &request.operation_id, identity);
        }
        let sealed = seal(
            identity,
            &self.aad(session, &request.operation_id, &hash, "INPUT"),
            &wire,
        )
        .map_err(|_| corrupt())?;
        let allocated = sealed.len() + OUTCOME_RESERVE + 1024;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let (pending, bytes, rows): (usize, usize, usize) = tx
            .query_row(
                "SELECT pending,allocated,rows FROM participant_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| storage())?;
        if pending >= max_pending || bytes.saturating_add(allocated) > max_bytes || rows >= 65536 {
            return Err(ParticipantError::local(
                "NOT_ADMITTED_CAPACITY",
                "ADMISSION",
            ));
        }
        let s = &request.scope;
        let lane = if crate::participant_actions::maintenance(&request.action) {
            1
        } else {
            0
        };
        tx.execute("INSERT INTO participant_operations(session,id,input_hash,action,workspace,instance,protocol,status,input,allocation,lane) VALUES(?1,?2,?3,?4,?5,?6,?7,'ADMITTED',?8,?9,?10)",
            params![session,request.operation_id,hash,request.action,s.workspace_id,s.instance_id,s.protocol_digest,sealed,allocated,lane]).map_err(|_|storage())?;
        tx.execute("UPDATE participant_meta SET pending=pending+1,allocated=allocated+?1,rows=rows+1 WHERE id=1",[allocated]).map_err(|_|storage())?;
        tx.commit().map_err(|_| storage())?;
        // Nothing fallible after durable admission: a failed follow-up read
        // must not misreport an operation the engine can now execute.
        Ok(Operation {
            operation_id: request.operation_id.clone(),
            state: "ADMITTED".into(),
            command_id: None,
            effect_certainty: "NOT_SUBMITTED".into(),
            outcome: None,
            observation: "LOCAL_DURABLE".into(),
        })
    }
    pub fn existing(
        &self,
        session: &str,
        request: &Invoke,
        identity: &KernelIdentity,
    ) -> Result<Option<Operation>> {
        let Some(hash) = self.hash(session, &request.operation_id)? else {
            return Ok(None);
        };
        let actual = sha256_hex(
            serde_json::to_string(request)
                .map_err(|_| corrupt())?
                .as_bytes(),
        );
        if hash != actual {
            return Err(ParticipantError::local(
                "OPERATION_INPUT_CONFLICT",
                "PREPARATION",
            ));
        }
        self.get(session, &request.operation_id, identity).map(Some)
    }
    fn hash(&self, session: &str, id: &str) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT input_hash FROM participant_operations WHERE session=?1 AND id=?2",
                params![session, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| storage())
    }
    pub fn request(&self, session: &str, id: &str, identity: &KernelIdentity) -> Result<Invoke> {
        let row: Option<(String, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT input_hash,input FROM participant_operations WHERE session=?1 AND id=?2",
                params![session, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| storage())?;
        let (hash, sealed) =
            row.ok_or_else(|| ParticipantError::local("OPERATION_NOT_FOUND", "OBSERVATION"))?;
        let wire = open(identity, &self.aad(session, id, &hash, "INPUT"), &sealed)
            .map_err(|_| corrupt())?;
        let request: Invoke = serde_json::from_str(&wire).map_err(|_| corrupt())?;
        if request.operation_id != id
            || sha256_hex(
                serde_json::to_string(&request)
                    .map_err(|_| corrupt())?
                    .as_bytes(),
            ) != hash
        {
            return Err(corrupt());
        }
        Ok(request)
    }
    pub fn get(&self, session: &str, id: &str, identity: &KernelIdentity) -> Result<Operation> {
        let row:Option<(String,String,Option<Vec<u8>>,Option<String>)>=self.db.query_row("SELECT input_hash,status,outcome,command_id FROM participant_operations WHERE session=?1 AND id=?2",params![session,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|_|storage())?;
        let (hash, status, outcome, command) =
            row.ok_or_else(|| ParticipantError::local("OPERATION_NOT_FOUND", "OBSERVATION"))?;
        let out = outcome
            .map(|bytes| {
                open(identity, &self.aad(session, id, &hash, "OUTCOME"), &bytes)
                    .map_err(|_| corrupt())
                    .and_then(|v| serde_json::from_str::<Value>(&v).map_err(|_| corrupt()))
            })
            .transpose()?;
        let committed = out
            .as_ref()
            .is_some_and(|v| v["effect_certainty"] == "COMMITTED");
        let not_submitted = out
            .as_ref()
            .is_some_and(|v| v["effect_certainty"] == "NOT_SUBMITTED");
        Ok(Operation {
            operation_id: id.into(),
            state: status.clone(),
            command_id: command,
            effect_certainty: match status.as_str() {
                "ACCEPTED" => "COMMITTED",
                "REJECTED_NO_EFFECT" => "NO_EFFECT",
                _ if committed => "COMMITTED",
                _ if not_submitted => "NOT_SUBMITTED",
                "ADMITTED" => "NOT_SUBMITTED",
                _ => "UNKNOWN",
            }
            .into(),
            outcome: out,
            observation: "LOCAL_DURABLE".into(),
        })
    }
    pub fn due(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let clock = now();
        let mut stmt=self.db.prepare("SELECT session,id FROM participant_operations WHERE status IN ('ADMITTED','PENDING') AND (next_retry<=?1 OR next_retry>?2) ORDER BY lane,next_retry,session,id LIMIT ?3").map_err(|_|storage())?;
        let rows = stmt
            .query_map(params![clock, clock + 30000, limit], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(|_| storage())?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| storage())
    }
    pub fn running(&self, session: &str, id: &str) -> Result<()> {
        self.db.execute("UPDATE participant_operations SET status='RUNNING' WHERE session=?1 AND id=?2 AND status IN ('ADMITTED','PENDING')",params![session,id]).map_err(|_|storage())?;
        Ok(())
    }
    pub fn recover(&self, session: &str, id: &str) -> Result<()> {
        self.db.execute("UPDATE participant_operations SET status='PENDING',next_retry=0 WHERE session=?1 AND id=?2 AND status IN ('PENDING','BLOCKED','RUNNING')",params![session,id]).map_err(|_|storage())?;
        Ok(())
    }
    pub fn finish(
        &mut self,
        session: &str,
        id: &str,
        identity: &KernelIdentity,
        value: &Value,
    ) -> Result<Operation> {
        let current = self.get(session, id, identity)?;
        if matches!(current.state.as_str(), "ACCEPTED" | "REJECTED_NO_EFFECT") {
            return Ok(current);
        }
        let mut state = match value["state"].as_str() {
            Some("ACCEPTED" | "COMMITTED" | "COMPLETED") => "ACCEPTED",
            Some("REJECTED") => "REJECTED_NO_EFFECT",
            _ => {
                if value["retryable"] == true {
                    "PENDING"
                } else {
                    "BLOCKED"
                }
            }
        };
        let committed = current.effect_certainty == "COMMITTED";
        if committed && state == "REJECTED_NO_EFFECT" {
            state = "BLOCKED";
        }
        let terminal = matches!(state, "ACCEPTED" | "REJECTED_NO_EFFECT");
        let mut saved = value.clone();
        if committed && !terminal && value["effect_certainty"] != "COMMITTED" {
            let prior = current
                .outcome
                .as_ref()
                .and_then(|value| value.get("confirmed_outcome"))
                .or(current.outcome.as_ref());
            saved = json!({"state":value["state"],"command_id":current.command_id,"effect_certainty":"COMMITTED","confirmed_outcome":prior,"continuation_error":value});
            if value["state"] == "REJECTED" {
                saved["code"] = json!("COMMITTED_OUTCOME_CONFLICT");
            }
        }
        let mut wire = saved.to_string();
        if wire.len() > OUTCOME_RESERVE - 64 {
            saved = json!({"state":value["state"],"effect_certainty":if committed{json!("COMMITTED")}else{value["effect_certainty"].clone()},"command_id":value.get("command_id").unwrap_or(&value["result"]["command_id"]),"result":{"workspace_id":value["result"]["workspace_id"],"instance_id":value["result"]["instance_id"],"event_sequence":value["result"]["event_sequence"],"revision":value["result"]["revision"],"produced_record_ids":value["result"]["produced_record_ids"]},"detail_source":"VERIFIED_NATIVE_JOURNAL"});
            wire = saved.to_string();
            if wire.len() > OUTCOME_RESERVE - 64 {
                return Err(corrupt());
            }
        }
        let hash = self.hash(session, id)?.ok_or_else(corrupt)?;
        let sealed = seal(identity, &self.aad(session, id, &hash, "OUTCOME"), &wire)
            .map_err(|_| corrupt())?;
        let command = value["command_id"]
            .as_str()
            .or_else(|| value["result"]["command_id"].as_str());
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let (failures,allocation,input_len):(usize,usize,usize)=tx.query_row("SELECT failures,allocation,length(input) FROM participant_operations WHERE session=?1 AND id=?2",params![session,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|storage())?;
        let next_allocation = if terminal {
            input_len + sealed.len() + 1024
        } else {
            allocation
        };
        let delay = 500i64.saturating_mul(1i64 << failures.min(6)).min(30000);
        tx.execute("UPDATE participant_operations SET status=?1,outcome=?2,command_id=COALESCE(?3,command_id),failures=failures+1,next_retry=?4,allocation=?5 WHERE session=?6 AND id=?7",params![state,sealed,command,now()+delay,next_allocation,session,id]).map_err(|_|storage())?;
        if terminal {
            tx.execute("UPDATE participant_meta SET pending=pending-1,allocated=allocated-?1+?2 WHERE id=1",params![allocation,next_allocation]).map_err(|_|storage())?;
        }
        tx.commit().map_err(|_| storage())?;
        self.get(session, id, identity)
    }
    pub fn list(
        &self,
        session: &str,
        capability: &Capability,
        identity: &KernelIdentity,
        after: &str,
        limit: usize,
    ) -> Result<Value> {
        if limit == 0 || limit > 32 {
            return Err(ParticipantError::local("PAGE_INVALID", "VALIDATION"));
        }
        let mut stmt=self.db.prepare("SELECT id FROM participant_operations WHERE session=?1 AND id>?2 ORDER BY id LIMIT ?3").map_err(|_|storage())?;
        let ids = stmt
            .query_map(params![session, after, limit + 1], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| storage())?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| storage())?;
        let more = ids.len() > limit;
        let selected = &ids[..ids.len().min(limit)];
        let mut items = Vec::new();
        for id in selected {
            if capability
                .authorize(&self.request(session, id, identity)?)
                .is_ok()
            {
                items.push(self.get(session, id, identity)?);
            }
        }
        Ok(json!({"items":items,"next_after":if more{selected.last()}else{None}}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participant::Scope;
    #[test]
    fn admission_quota_is_atomic_and_replay_does_not_allocate_again() {
        let t = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&t.path().join("identity")).unwrap();
        let directory = t.path().join("state");
        let mut store = Store::open(&directory, &identity, "https://service.invalid/").unwrap();
        let a = Invoke::new(
            "a",
            "structure.workspace.create",
            Scope::default(),
            json!({"name":"one"}),
        );
        store
            .reserve("program", &a, &identity, 1, 1024 * 1024)
            .unwrap();
        store
            .reserve("program", &a, &identity, 1, 1024 * 1024)
            .unwrap();
        let b = Invoke::new(
            "b",
            "structure.workspace.create",
            Scope::default(),
            json!({"name":"two"}),
        );
        assert_eq!(
            store
                .reserve("program", &b, &identity, 1, 1024 * 1024)
                .unwrap_err()
                .code,
            "NOT_ADMITTED_CAPACITY"
        );
        assert_eq!(
            store
                .db
                .query_row("SELECT rows FROM participant_meta", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        store.running("program", "a").unwrap();
        store.reset_running().unwrap();
        assert_eq!(
            store
                .get("program", "a", &identity)
                .unwrap()
                .effect_certainty,
            "UNKNOWN"
        );
        store
            .finish(
                "program",
                "a",
                &identity,
                &json!({"state":"ACCEPTED","result":{"command_id":"signed-original"}}),
            )
            .unwrap();
        store
            .reserve("program", &b, &identity, 1, 1024 * 1024)
            .unwrap();
        assert!(store.get("other", "a", &identity).is_err());
        let forged = json!({"state":"REJECTED","result":{"command_id":"other"}});
        store.finish("program", "a", &identity, &forged).unwrap();
        assert_eq!(
            store.get("program", "a", &identity).unwrap().state,
            "ACCEPTED"
        );
    }
    #[test]
    fn sealed_input_cannot_be_rebound_to_another_operation() {
        let t = crate::test_support::protected_test_dir();
        let id = KernelIdentity::create(&t.path().join("id")).unwrap();
        let mut s = Store::open(&t.path().join("state"), &id, "https://service.invalid/").unwrap();
        for name in ["a", "b"] {
            s.reserve(
                "program",
                &Invoke::new(
                    name,
                    "structure.workspace.create",
                    Scope::default(),
                    json!({"name":"secret"}),
                ),
                &id,
                4,
                2 * 1024 * 1024,
            )
            .unwrap();
        }
        s.db.execute("UPDATE participant_operations SET input=(SELECT input FROM participant_operations WHERE id='a') WHERE id='b'",[]).unwrap();
        assert!(s.request("program", "b", &id).is_err());
    }
    #[test]
    fn committed_effect_is_preserved_while_key_delivery_is_pending() {
        let t = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&t.path().join("identity")).unwrap();
        let mut store = Store::open(
            &t.path().join("state"),
            &identity,
            "https://service.invalid/",
        )
        .unwrap();
        let request = Invoke::new(
            "authorize",
            "structure.access.authorize",
            crate::participant::Scope {
                workspace_id: Some("space".into()),
                ..Default::default()
            },
            json!({}),
        );
        store
            .reserve("program", &request, &identity, 4, 1024 * 1024)
            .unwrap();
        store.running("program", "authorize").unwrap();
        let pending = json!({"state":"PENDING","phase":"KEY_DELIVERY","effect_certainty":"COMMITTED","retryable":true,"command_id":"original"});
        assert_eq!(
            store
                .finish("program", "authorize", &identity, &pending)
                .unwrap()
                .effect_certainty,
            "COMMITTED"
        );
        for failure in [
            json!({"state":"FAILED","code":"NETWORK_FAILED","retryable":true}),
            json!({"state":"FAILED","code":"LOCAL_CONFIGURATION_INVALID","retryable":false}),
        ] {
            let observed = store
                .finish("program", "authorize", &identity, &failure)
                .unwrap();
            assert_eq!(observed.effect_certainty, "COMMITTED");
            assert_eq!(observed.command_id.as_deref(), Some("original"));
            let value = observed.outcome.unwrap();
            assert_eq!(value["confirmed_outcome"]["phase"], "KEY_DELIVERY");
            assert_eq!(value["continuation_error"]["code"], failure["code"]);
        }
        let conflict = store
            .finish(
                "program",
                "authorize",
                &identity,
                &json!({"state":"REJECTED"}),
            )
            .unwrap();
        assert_eq!(conflict.state, "BLOCKED");
        assert_eq!(conflict.effect_certainty, "COMMITTED");
        assert_eq!(
            store
                .db
                .query_row("SELECT pending FROM participant_meta", [], |row| row
                    .get::<_, usize>(0))
                .unwrap(),
            1
        );
        let large=store.finish("program","authorize",&identity,&json!({"state":"FAILED","retryable":true,"diagnostic":"x".repeat(OUTCOME_RESERVE)})).unwrap();
        assert_eq!(large.effect_certainty, "COMMITTED");
        assert_eq!(
            large.outcome.unwrap()["detail_source"],
            "VERIFIED_NATIVE_JOURNAL"
        );
        store.recover("program", "authorize").unwrap();
        store.running("program", "authorize").unwrap();
        store.reset_running().unwrap();
        assert_eq!(
            store
                .get("program", "authorize", &identity)
                .unwrap()
                .effect_certainty,
            "COMMITTED"
        );
        drop(store);
        let store = Store::open(
            &t.path().join("state"),
            &identity,
            "https://service.invalid/",
        )
        .unwrap();
        assert_eq!(
            store
                .get("program", "authorize", &identity)
                .unwrap()
                .effect_certainty,
            "COMMITTED"
        );
    }
    #[test]
    fn storage_failure_never_claims_the_original_operation_was_not_submitted() {
        let t = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&t.path().join("identity")).unwrap();
        let mut store = Store::open(
            &t.path().join("state"),
            &identity,
            "https://service.invalid/",
        )
        .unwrap();
        store.db.execute_batch("PRAGMA query_only=ON;").unwrap();
        let request = Invoke::new(
            "one",
            "structure.workspace.create",
            Scope::default(),
            json!({"name":"Synthetic"}),
        );
        let error = store
            .reserve("program", &request, &identity, 4, 1024 * 1024)
            .unwrap_err();
        assert_eq!(error.code, "STATE_FAILED");
        assert_eq!(error.effect_certainty, "UNKNOWN");
        assert_eq!(
            store
                .db
                .query_row("SELECT rows FROM participant_meta", [], |row| row
                    .get::<_, usize>(0))
                .unwrap(),
            0
        );
    }
}
