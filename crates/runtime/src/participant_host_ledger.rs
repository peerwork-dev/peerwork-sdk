//! Child of the durable inbox: selected host work and scoped call evidence.
//! Host IO never runs while one of these transactions is open.
use super::*;
#[path="participant_host_gc.rs"]
mod retirement;
#[path = "participant_host_rebind.rs"]
pub(super) mod rebind;
use crate::participant_watch::{DeliveryReference, WatchOptions};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostBinding {
    pub destination: Value,
    pub digest: String,
}
impl HostBinding {
    pub fn new(destination: Value) -> Result<Self> {
        if destination.as_object().is_none_or(|o| {
            o.keys().any(|k| {
                !["host", "conversation_id", "session_id", "endpoint", "bridge_id"].contains(&k.as_str())
            })
        }) || !["CODEX_APP_SERVER", "ANTIGRAVITY_APP", "ANTIGRAVITY_CLI"]
            .contains(&destination["host"].as_str().unwrap_or(""))
            || ["conversation_id", "session_id"].iter().any(|k| {
                destination[*k]
                    .as_str()
                    .is_none_or(|s| s.is_empty() || s.len() > 256)
            })
            || destination.get("bridge_id").is_some_and(|v|v.as_str().is_none_or(|s|s.len()!=43||!s.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'-'|b'_'))))
            || destination.to_string().len() > 4096
        {
            return Err(invalid());
        }
        let digest = sha256_hex(destination.to_string().as_bytes());
        Ok(Self {
            destination,
            digest,
        })
    }
    fn validate(&self) -> Result<()> {
        if Self::new(self.destination.clone())?.digest != self.digest {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_blocks_only_its_lane_and_queue_progress_keeps_both_facts() {
        let temp = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&temp.path().join("identity")).unwrap();
        let mut store = InboxStore::open_local(
            &temp.path().join("inbox"),
            &identity,
            "https://example.invalid/",
        )
        .unwrap();
        let host = HostBinding::new(
            json!({"host":"CODEX_APP_SERVER","conversation_id":"thread","session_id":"session"}),
        )
        .unwrap();
        let options = WatchOptions {
            workspace_id: "w".repeat(43),
            mailbox_id: "m".repeat(43),
            membership_id: "g".repeat(43),
            consumer_id: "worker".into(),
            host_destination: Some(host.digest.clone()),
        };
        let ns = "program:worker";
        let binding = store.attach_watch(&identity, ns, &options).unwrap();
        store
            .register(&MailboxPins {
                workspace_id: options.workspace_id.clone(),
                mailbox_id: options.mailbox_id.clone(),
                membership_id: options.membership_id.clone(),
                receiver_id: binding.receiver,
                epoch: 1,
                destination_digest: host.digest.clone(),
                binding_version: 1,
                after_sequence: 0,
                after_control_sequence: Some(0),
            })
            .unwrap();
        store.host_attach(ns, &options, &host).unwrap();
        let mut items = Vec::new();
        for sequence in 1..=3u64 {
            let item = DeliveryReference {
                sequence,
                delivery_id: format!("{sequence:043}"),
            };
            let envelope = json!({"sequence":sequence,"delivery_id":item.delivery_id,"kind":"BUSINESS","business":{"instance_id":"synthetic"}});
            let wire = json!({"items":[envelope]}).to_string();
            let digest = sha256_hex(wire.as_bytes());
            let encrypted = seal_bounded(
                &identity,
                &store.aad(&options.workspace_id, &options.mailbox_id, &digest),
                &wire,
                MAX_FRAME_BYTES,
            )
            .unwrap();
            store
                .db
                .execute(
                    "INSERT INTO inbox_frames VALUES(?1,?2,?3,?4,?5)",
                    params![
                        digest,
                        options.workspace_id,
                        options.mailbox_id,
                        encrypted,
                        wire.len()
                    ],
                )
                .unwrap();
            store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,?6,'PENDING')",params![options.workspace_id,options.mailbox_id,sequence,item.delivery_id,digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
            store
                .db
                .execute(
                    "INSERT INTO inbox_item_lanes VALUES(?1,?2,?3,?4)",
                    params![
                        options.workspace_id,
                        options.mailbox_id,
                        sequence,
                        if sequence == 3 {
                            "other-conversation"
                        } else {
                            "same-conversation"
                        }
                    ],
                )
                .unwrap();
            items.push(item);
        }
        store
            .db
            .execute("UPDATE inbox_mailboxes SET item_cursor=3", [])
            .unwrap();
        assert_eq!(
            store
                .host_due(ns, &options, 32)
                .unwrap()
                .iter()
                .map(|r| r.sequence)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        let frame = json!({"message_id":"synthetic"});
        let first = store
            .host_begin(&identity, ns, &options, &items[0], frame.clone())
            .unwrap()
            .unwrap();
        let before:(String,u64)=store.db.query_row("SELECT state,report_version FROM inbox_host_calls WHERE call_id=?1",[&first.call_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(before.0,"CALL_OPEN");
        let wrong=InboxStore::open_local(&temp.path().join("inbox"),&identity,"https://another.invalid/");
        assert_eq!(wrong.err().unwrap().code,"INBOX_BINDING_MISMATCH");
        let another=KernelIdentity::create(&temp.path().join("another-identity")).unwrap();
        assert_eq!(InboxStore::open_local(&temp.path().join("inbox"),&another,"https://example.invalid/").err().unwrap().code,"INBOX_BINDING_MISMATCH");
        let after:(String,u64)=store.db.query_row("SELECT state,report_version FROM inbox_host_calls WHERE call_id=?1",[&first.call_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(before,after,"another Origin must not run recovery mutations");
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &first,
                HostOutcome::Unknown {
                    code: "HOST_ACK_UNKNOWN".into(),
                },
            )
            .unwrap();
        assert_eq!(store.host_due(ns, &options, 32).unwrap()[0].sequence, 3);
        let observed=store.host_reconcile_due(&identity,ns,&options).unwrap().unwrap();
        assert_eq!(observed.call_id,first.call_id);
        assert_eq!(observed.frame,first.frame);
        assert_eq!(observed.scope,first.scope);
        assert!(store.host_reconcile_due(&identity,ns,&options).unwrap().is_none(),"the same unavailable call must back off");
        assert!(store.host_reconcile_due(&identity,"another-client",&options).is_err());
        assert_eq!(
            store
                .host_begin(&identity, ns, &options, &items[1], frame.clone())
                .unwrap_err()
                .code,
            "HOST_LANE_BLOCKED"
        );
        let third = store
            .host_begin(&identity, ns, &options, &items[2], frame)
            .unwrap()
            .unwrap();
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &third,
                HostOutcome::HostQueued {
                    receipt: "queue-receipt".into(),
                },
            )
            .unwrap();
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &third,
                HostOutcome::HostAccepted {
                    receipt: "turn-receipt".into(),
                },
            )
            .unwrap();
        let status = store
            .host_status(&identity, ns, &options, &items[2])
            .unwrap();
        assert_eq!(status["facts"].as_array().unwrap().len(), 2);
        assert_eq!(
            serde_json::to_value(HostOutcome::Unknown {
                code: "HOST_ACK_UNKNOWN".into()
            })
            .unwrap()["state"],
            "RESULT_UNKNOWN"
        );
        store
            .host_reported(
                &options.workspace_id,
                &options.mailbox_id,
                &third.call_id,
                third.report_version,
            )
            .unwrap();
        assert_eq!(
            store
                .host_status(&identity, ns, &options, &items[2])
                .unwrap()["reporting"],
            "PENDING"
        );
        let current = store.host_call(&identity, &third.call_id).unwrap();
        store
            .host_report_failed(
                &options.workspace_id,
                &options.mailbox_id,
                &third.call_id,
                current.report_version,
                "HOST_EVIDENCE_CONFLICT",
            )
            .unwrap();
        let blocked = store
            .host_status(&identity, ns, &options, &items[2])
            .unwrap();
        assert_eq!(blocked["reporting"], "BLOCKED");
        assert_eq!(blocked["host"], "HOST_ACCEPTED");
        assert_eq!(blocked["reporting_error"], "HOST_EVIDENCE_CONFLICT");
        assert_ne!(
            store
                .pending_host_report(&identity, ns, &options)
                .unwrap()
                .unwrap()
                .0,
            third.call_id
        );
        store
            .host_reported(
                &options.workspace_id,
                &options.mailbox_id,
                &third.call_id,
                current.report_version,
            )
            .unwrap();
        assert_eq!(
            store
                .host_status(&identity, ns, &options, &items[2])
                .unwrap()["reporting"],
            "SERVICE_CONFIRMED"
        );
        assert_eq!(status["model_response"], "NOT_ATTESTED");
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &first,
                HostOutcome::HostAccepted {
                    receipt: "late-original-turn".into(),
                },
            )
            .unwrap();
        assert_eq!(store.host_due(ns, &options, 32).unwrap()[0].sequence, 2);
    }
    #[test]
    fn crash_and_scoped_late_facts_never_reinject_unknown_or_accepted_calls() {
        let temp = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&temp.path().join("identity")).unwrap();
        let directory = temp.path().join("inbox");
        let mut store =
            InboxStore::open_local(&directory, &identity, "https://example.invalid/").unwrap();
        let host=HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"existing-thread","session_id":"existing-session","endpoint":"unix:///private/control.sock"})).unwrap();
        let options = WatchOptions {
            workspace_id: "w".repeat(43),
            mailbox_id: "m".repeat(43),
            membership_id: "g".repeat(43),
            consumer_id: "worker".into(),
            host_destination: Some(host.digest.clone()),
        };
        let ns = "program:worker";
        let binding = store.attach_watch(&identity, ns, &options).unwrap();
        store
            .register(&MailboxPins {
                workspace_id: options.workspace_id.clone(),
                mailbox_id: options.mailbox_id.clone(),
                membership_id: options.membership_id.clone(),
                receiver_id: binding.receiver,
                epoch: 1,
                destination_digest: host.digest.clone(),
                binding_version: 1,
                after_sequence: 0,
                after_control_sequence: Some(0),
            })
            .unwrap();
        store.host_attach(ns, &options, &host).unwrap();
        // Synthetic cache construction tests local evidence boundaries only;
        // actual service/author verification is qualified by separate HTTP tests.
        let item = DeliveryReference {
            sequence: 1,
            delivery_id: "d".repeat(43),
        };
        let envelope = json!({"sequence":1,"delivery_id":item.delivery_id,"kind":"BUSINESS","business":{"kind":"action.accepted"}});
        let wire = json!({"items":[envelope]}).to_string();
        let digest = sha256_hex(wire.as_bytes());
        let encrypted = seal_bounded(
            &identity,
            &store.aad(&options.workspace_id, &options.mailbox_id, &digest),
            &wire,
            MAX_FRAME_BYTES,
        )
        .unwrap();
        store
            .db
            .execute(
                "INSERT INTO inbox_frames VALUES(?1,?2,?3,?4,?5)",
                params![
                    digest,
                    options.workspace_id,
                    options.mailbox_id,
                    encrypted,
                    wire.len()
                ],
            )
            .unwrap();
        store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,1,?3,'BUSINESS',?4,0,?5,'PENDING')",params![options.workspace_id,options.mailbox_id,item.delivery_id,digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
        store
            .db
            .execute("UPDATE inbox_mailboxes SET item_cursor=1", [])
            .unwrap();
        assert_eq!(store.host_due(ns, &options, 32).unwrap().len(), 1);
        let frame = json!({"format":"peerwork.incoming.v2","message_id":"one-frozen-frame","text":"private_host_text_to_keep_encrypted"});
        let first = store
            .host_begin(&identity, ns, &options, &item, frame.clone())
            .unwrap()
            .unwrap();
        store
            .host_defer(ns, &options, &item, "HOST_NOT_READY")
            .unwrap();
        assert!(store.host_due(ns, &options, 32).unwrap().is_empty());
        assert!(store
            .host_begin(&identity, ns, &options, &item, frame.clone())
            .is_err());
        drop(store);
        let mut store =
            InboxStore::open_local(&directory, &identity, "https://example.invalid/").unwrap();
        assert_eq!(
            store.host_status(&identity, ns, &options, &item).unwrap()["host"],
            "RESULT_UNKNOWN"
        );
        assert!(store.host_due(ns, &options, 32).unwrap().is_empty());
        let mut wrong = first.clone();
        wrong.scope["epoch"] = json!(2);
        assert_eq!(
            store
                .host_finish(
                    &identity,
                    ns,
                    &options,
                    &wrong,
                    HostOutcome::NotSent {
                        code: "HOST_NOT_SENT".into(),
                        proof: "BOUND_HOST_RECONCILIATION".into()
                    }
                )
                .unwrap_err()
                .code,
            "HOST_EVIDENCE_SCOPE_MISMATCH"
        );
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &first,
                HostOutcome::NotSent {
                    code: "HOST_NOT_SENT".into(),
                    proof: "BOUND_HOST_RECONCILIATION".into(),
                },
            )
            .unwrap();
        store
            .db
            .execute("UPDATE inbox_host_ready SET next_retry=0", [])
            .unwrap();
        let second = store
            .host_begin(&identity, ns, &options, &item, frame)
            .unwrap()
            .unwrap();
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &second,
                HostOutcome::Unknown {
                    code: "HOST_ACK_UNKNOWN".into(),
                },
            )
            .unwrap();
        // An idempotent old NOT_SENT cannot resolve another attempt.
        store
            .host_finish(
                &identity,
                ns,
                &options,
                &first,
                HostOutcome::NotSent {
                    code: "HOST_NOT_SENT".into(),
                    proof: "BOUND_HOST_RECONCILIATION".into(),
                },
            )
            .unwrap();
        assert_eq!(
            store.host_status(&identity, ns, &options, &item).unwrap()["host"],
            "RESULT_UNKNOWN"
        );
        store.disable_watch(ns, &options).unwrap();
        let ack = HostOutcome::HostAccepted {
            receipt: "actual-host-turn".into(),
        };
        store
            .host_finish(&identity, ns, &options, &second, ack.clone())
            .unwrap();
        store
            .host_finish(&identity, ns, &options, &second, ack)
            .unwrap();
        assert!(store.host_due(ns, &options, 32).unwrap().is_empty());
        assert_eq!(
            store.host_status(&identity, ns, &options, &item).unwrap()["host"],
            "HOST_ACCEPTED"
        );
        assert_eq!(
            store
                .host_finish(
                    &identity,
                    ns,
                    &options,
                    &second,
                    HostOutcome::HostAccepted {
                        receipt: "unrelated-turn".into()
                    }
                )
                .unwrap_err()
                .code,
            "HOST_EVIDENCE_CONFLICT"
        );
        let bytes = std::fs::read(directory.join("participant-inbox.sqlite")).unwrap();
        assert!(!bytes
            .windows(b"private_host_text_to_keep_encrypted".len())
            .any(|v| v == b"private_host_text_to_keep_encrypted"));
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct HostCall {
    pub call_id: String,
    pub scope: Value,
    pub frame_digest: String,
    pub frame: Value,
    pub state: String,
    pub outcome: Option<Value>,
    pub attempt: u64,
    pub report_version: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub(crate) enum HostOutcome {
    NotSent {
        code: String,
        proof: String,
    },
    #[serde(rename = "RESULT_UNKNOWN", alias = "UNKNOWN")]
    Unknown {
        code: String,
    },
    HostQueued {
        receipt: String,
    },
    HostAccepted {
        receipt: String,
    },
}
pub(crate) enum HostOperation {
    RetirementPlan,
    RetirementCommit(Value),
    AccessScope,
    ReconcileDue,
    Presence{value:Value,observed_at:std::time::Instant},
    Attach(HostBinding),
    Due {
        limit: usize,
    },
    Begin {
        item: DeliveryReference,
        frame: Value,
    },
    Finish {
        call: HostCall,
        outcome: HostOutcome,
    },
    Defer {
        item: DeliveryReference,
        code: String,
    },
    Status {
        item: DeliveryReference,
    },
}
pub(crate) enum HostReply {
    Retirement(Option<Value>),
    AccessScope(Value),
    Saved,
    Due(Vec<DeliveryReference>),
    Call(Option<HostCall>),
    Status(Value),
}
impl HostOutcome {
    fn status(&self) -> &'static str {
        match self {
            Self::NotSent { .. } => "NOT_SENT",
            Self::Unknown { .. } => "RESULT_UNKNOWN",
            Self::HostQueued { .. } => "HOST_QUEUED",
            Self::HostAccepted { .. } => "HOST_ACCEPTED",
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::NotSent { code, proof }
                if crate::communication_store::identifier(code)
                    && matches!(
                        proof.as_str(),
                        "LOCAL_PREFLIGHT_NO_IO"
                            | "PROCESS_NOT_STARTED"
                            | "BOUND_HOST_RECONCILIATION"
                    ) =>
            {
                Ok(())
            }
            Self::Unknown { code } if crate::communication_store::identifier(code) => Ok(()),
            Self::HostQueued { receipt } | Self::HostAccepted { receipt }
                if !receipt.is_empty() && receipt.len() <= 2048 =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}
pub(super) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS inbox_item_lanes(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,lane TEXT NOT NULL,PRIMARY KEY(workspace,mailbox,sequence),FOREIGN KEY(workspace,mailbox,sequence) REFERENCES inbox_items(workspace,mailbox,sequence) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS inbox_host_lanes(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,lane TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(workspace,mailbox,sequence));
        CREATE INDEX IF NOT EXISTS inbox_host_lane_order ON inbox_host_lanes(workspace,mailbox,lane,state,sequence);
        CREATE TABLE IF NOT EXISTS inbox_host_facts(call_id TEXT NOT NULL,state TEXT NOT NULL,evidence BLOB NOT NULL,PRIMARY KEY(call_id,state));
        CREATE TABLE IF NOT EXISTS inbox_host_retired(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,host TEXT NOT NULL,through_sequence INTEGER NOT NULL,lane_after INTEGER NOT NULL,lane_pending INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox));
        CREATE TABLE IF NOT EXISTS inbox_host_meta(id INTEGER PRIMARY KEY CHECK(id=1),allocated INTEGER NOT NULL,rows INTEGER NOT NULL);
        INSERT OR IGNORE INTO inbox_host_meta VALUES(1,0,0);
        CREATE TABLE IF NOT EXISTS inbox_host_links(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,namespace TEXT NOT NULL,host TEXT NOT NULL,descriptor TEXT NOT NULL,cursor INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox));
        CREATE TABLE IF NOT EXISTS inbox_host_ready(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,delivery_id TEXT NOT NULL,host TEXT NOT NULL,next_retry INTEGER NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,code TEXT,PRIMARY KEY(workspace,mailbox,sequence));
        CREATE INDEX IF NOT EXISTS inbox_host_due ON inbox_host_ready(workspace,mailbox,next_retry,sequence);
        CREATE TABLE IF NOT EXISTS inbox_host_calls(call_id TEXT PRIMARY KEY,workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,delivery_id TEXT NOT NULL,host TEXT NOT NULL,attempt INTEGER NOT NULL,scope TEXT NOT NULL,frame_digest TEXT NOT NULL,frame BLOB NOT NULL,state TEXT NOT NULL,outcome BLOB,allocation INTEGER NOT NULL,report_version INTEGER NOT NULL DEFAULT 1,report_pending INTEGER NOT NULL DEFAULT 1,report_code TEXT);
        CREATE INDEX IF NOT EXISTS inbox_host_delivery ON inbox_host_calls(workspace,mailbox,sequence,attempt DESC);
        CREATE INDEX IF NOT EXISTS inbox_host_unresolved ON inbox_host_calls(host,state,call_id);
        CREATE INDEX IF NOT EXISTS inbox_host_open ON inbox_host_calls(state,call_id);
        CREATE INDEX IF NOT EXISTS inbox_host_scope_unknown ON inbox_host_calls(workspace,mailbox,state);
        CREATE INDEX IF NOT EXISTS inbox_host_key_wait ON inbox_host_ready(workspace,mailbox,code,sequence);

        CREATE INDEX IF NOT EXISTS inbox_host_lane_state ON inbox_host_lanes(state,sequence);
        UPDATE inbox_host_lanes SET state='RESULT_UNKNOWN' WHERE state='CALL_OPEN';").map_err(db_error)?;
    rebind::initialize(db)?;
    let columns = db
        .prepare("PRAGMA table_info(inbox_host_calls)")
        .map_err(db_error)?
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(db_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_error)?;
    for name in ["report_version", "report_pending"] {
        if !columns.iter().any(|c| c == name) {
            db.execute_batch(&format!(
                "ALTER TABLE inbox_host_calls ADD COLUMN {name} INTEGER NOT NULL DEFAULT 1"
            ))
            .map_err(db_error)?;
        }
    }
    if !columns.iter().any(|c| c == "report_code") {
        db.execute_batch("ALTER TABLE inbox_host_calls ADD COLUMN report_code TEXT")
            .map_err(db_error)?;
    }
    for name in ["reconcile_at", "reconcile_failures"] {
        if !columns.iter().any(|c|c==name) {
            db.execute_batch(&format!("ALTER TABLE inbox_host_calls ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0")).map_err(db_error)?;
        }
    }
    db.execute_batch("CREATE INDEX IF NOT EXISTS inbox_host_gc ON inbox_host_calls(workspace,mailbox,report_pending,state,sequence,call_id);").map_err(db_error)?;
    db.execute_batch("CREATE INDEX IF NOT EXISTS inbox_host_gc_binding ON inbox_host_calls(workspace,mailbox,host,report_pending,state,sequence,call_id);").map_err(db_error)?;
    db.execute_batch("CREATE INDEX IF NOT EXISTS inbox_host_reconcile ON inbox_host_calls(workspace,mailbox,host,state,reconcile_at,call_id);").map_err(db_error)?;
    db.execute_batch("CREATE INDEX IF NOT EXISTS inbox_host_report_pending ON inbox_host_calls(workspace,mailbox,report_pending,call_id); UPDATE inbox_host_calls SET state='RESULT_UNKNOWN',report_version=report_version+1,report_pending=1,report_code=NULL WHERE state='CALL_OPEN';").map_err(db_error)?;
    Ok(())
}
impl InboxStore {
    pub fn host_access_scope(&self,namespace:&str,options:&WatchOptions)->Result<Value>{
        self.host_evidence_scope(namespace,options)?;
        Ok(json!({"format":"peerwork.host-access.v1","owner":self.binding,"namespace":namespace,"workspace_id":options.workspace_id,"mailbox_id":options.mailbox_id,"membership_id":options.membership_id,"destination_digest":options.host_destination}))
    }
    /// Read the original encrypted call only. Reserve the next probe before IO
    /// so crashes and a permanently unknown prefix cannot starve other calls.
    pub fn host_reconcile_due(&mut self,identity:&KernelIdentity,namespace:&str,options:&WatchOptions)->Result<Option<HostCall>> {
        let (host,_)=self.host_link(namespace,options)?;
        let now=crate::participant_store::now();
        let mut selected:Option<(String,i64,u64)>=None;
        for status in ["RESULT_UNKNOWN","HOST_QUEUED"] {
            // Two range seeks, rather than scanning sleeping calls. The second
            // also repairs scheduling after a backwards wall-clock jump.
            for (predicate,threshold) in [("reconcile_at<=?5",now),("reconcile_at>?5",now.saturating_add(30000))] {
                let sql=format!("SELECT call_id,reconcile_at,reconcile_failures FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND host=?3 AND state=?4 AND {predicate} ORDER BY reconcile_at,call_id LIMIT 1");
                let row:Option<(String,i64,u64)>=self.db.query_row(&sql,params![options.workspace_id,options.mailbox_id,host,status,threshold],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
                if let Some(row)=row {
                    if selected.as_ref().is_none_or(|old|(row.1.min(now),&row.0)<(old.1.min(now),&old.0)) {selected=Some(row);}
                }
            }
        }
        let Some((id,_,failures))=selected else{return Ok(None);};
        let call=self.host_call(identity,&id)?;
        if call.scope["namespace"]!=namespace||call.scope["membership_id"]!=options.membership_id||call.scope["destination_digest"]!=host {return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));}
        let delay=(500i64<<failures.min(6)).min(30000);
        self.db.execute("UPDATE inbox_host_calls SET reconcile_at=?2,reconcile_failures=min(reconcile_failures+1,64) WHERE call_id=?1",params![id,now.saturating_add(delay)]).map_err(db_error)?;
        Ok(Some(call))
    }
    fn host_watch_scope(&self, namespace: &str, options: &WatchOptions) -> Result<()> {
        options.validate()?;
        let descriptor = serde_json::to_string(options).map_err(|_| invalid())?;
        let watch:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_watches WHERE workspace=?1 AND mailbox=?2 AND namespace=?3 AND descriptor=?4)",params![options.workspace_id,options.mailbox_id,namespace,descriptor],|r|r.get(0)).map_err(db_error)?;
        if !watch {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        Ok(())
    }
    fn host_link(&self, namespace: &str, options: &WatchOptions) -> Result<(String, u64)> {
        self.host_rebind_available(options)?;
        self.host_watch_scope(namespace, options)?;
        let row:Option<(String,String,u64)>=self.db.query_row("SELECT namespace,host,cursor FROM inbox_host_links WHERE workspace=?1 AND mailbox=?2",params![options.workspace_id,options.mailbox_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
        let (saved, host, cursor) = row.ok_or_else(|| failure("HOST_BINDING_NOT_CONFIGURED"))?;
        if saved != namespace || options.host_destination.as_deref() != Some(&host) {
            return Err(failure("HOST_BINDING_MISMATCH"));
        }
        Ok((host, cursor))
    }
    pub fn host_attach(
        &mut self,
        namespace: &str,
        options: &WatchOptions,
        host: &HostBinding,
    ) -> Result<()> {
        self.host_watch_scope(namespace, options)?;
        host.validate()?;
        if options.host_destination.as_deref() != Some(&host.digest) {
            return Err(failure("HOST_BINDING_MISMATCH"));
        }
        let descriptor = serde_json::to_string(host).map_err(|_| invalid())?;
        self.db
            .execute(
                "INSERT OR IGNORE INTO inbox_host_links VALUES(?1,?2,?3,?4,?5,0)",
                params![
                    options.workspace_id,
                    options.mailbox_id,
                    namespace,
                    host.digest,
                    descriptor
                ],
            )
            .map_err(db_error)?;
        let (old, _) = self.host_link(namespace, options)?;
        let saved: String = self
            .db
            .query_row(
                "SELECT descriptor FROM inbox_host_links WHERE workspace=?1 AND mailbox=?2",
                params![options.workspace_id, options.mailbox_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if old != host.digest || saved != descriptor {
            return Err(failure("HOST_BINDING_MISMATCH"));
        }
        Ok(())
    }
    pub fn host_due(
        &mut self,
        namespace: &str,
        options: &WatchOptions,
        limit: usize,
    ) -> Result<Vec<DeliveryReference>> {
        if !(1..=32).contains(&limit) {
            return Err(invalid());
        }
        let (host, after) = self.host_link(namespace, options)?;
        let version=self.pins(&options.workspace_id,&options.mailbox_id)?.ok_or_else(invalid)?.binding_version;
        // Populate one bounded keyset page, independently of old call history.
        let rows=self.db.prepare("SELECT sequence,delivery_id FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence>?3 AND consume_requested=0 ORDER BY sequence LIMIT 32").map_err(db_error)?
            .query_map(params![options.workspace_id,options.mailbox_id,after],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        let cursor = rows.last().map(|r| r.0).unwrap_or(
            self.cursor(&options.workspace_id, &options.mailbox_id)?
                .map(|c| c.item)
                .unwrap_or(after),
        );
        if !rows.is_empty() || cursor != after {
            let tx = self.db.unchecked_transaction().map_err(db_error)?;
            for (sequence, _) in &rows {
                let original:String=tx.query_row("SELECT COALESCE((SELECT lane FROM inbox_item_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3),'MAILBOX')",params![options.workspace_id,options.mailbox_id,sequence],|r|r.get(0)).map_err(db_error)?;
                let lane=rebind::lane_key(version,&host,&original);
                tx.execute("INSERT OR IGNORE INTO inbox_host_lanes VALUES(?1,?2,?3,?4,'WAITING')",params![options.workspace_id,options.mailbox_id,sequence,lane]).map_err(db_error)?;
                let lane:String=tx.query_row("SELECT lane FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence],|r|r.get(0)).map_err(db_error)?;
                promote_lane(
                    &tx,
                    &options.workspace_id,
                    &options.mailbox_id,
                    &lane,
                    &host,
                )?;
            }
            tx.execute("UPDATE inbox_host_links SET cursor=max(cursor,?3) WHERE workspace=?1 AND mailbox=?2",params![options.workspace_id,options.mailbox_id,cursor]).map_err(db_error)?;
            tx.commit().map_err(db_error)?;
        }
        let now = crate::participant_store::now();
        self.db.prepare("SELECT sequence,delivery_id FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND host=?6 AND (next_retry<=?3 OR next_retry>?4) ORDER BY next_retry,sequence LIMIT ?5").map_err(db_error)?
            .query_map(params![options.workspace_id,options.mailbox_id,now,now+30000,limit,host],|r|Ok(DeliveryReference{sequence:r.get(0)?,delivery_id:r.get(1)?})).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)
    }
    pub fn host_defer(
        &self,
        namespace: &str,
        options: &WatchOptions,
        item: &DeliveryReference,
        code: &str,
    ) -> Result<()> {
        self.host_link(namespace, options)?;
        if !crate::communication_store::identifier(code) {
            return Err(invalid());
        }
        self.db.execute("UPDATE inbox_host_ready SET next_retry=?4+min(30000,500*(1<<min(failures,6))),failures=failures+1,code=?5 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?6",params![options.workspace_id,options.mailbox_id,item.sequence,crate::participant_store::now(),code,item.delivery_id]).map_err(db_error)?;
        Ok(())
    }
    pub fn host_begin(
        &mut self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
        item: &DeliveryReference,
        frame: Value,
    ) -> Result<Option<HostCall>> {
        let (host, _) = self.host_link(namespace, options)?;
        let retired=self.host_retired(options,&host)?;
        if item.sequence<=retired.0{return Ok(None);}
        let source = self.pending(
            identity,
            &options.workspace_id,
            &options.mailbox_id,
            item.sequence.saturating_sub(1),
            1,
        )?;
        let Some(source) = source.first().filter(|v| {
            v["sequence"].as_u64() == Some(item.sequence) && v["delivery_id"] == item.delivery_id
        }) else {
            let consumed:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4 AND consume_requested=1) OR EXISTS(SELECT 1 FROM inbox_consumed WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4)",params![options.workspace_id,options.mailbox_id,item.sequence,item.delivery_id],|r|r.get(0)).map_err(db_error)?;
            if consumed{return Ok(None);}
            return Err(failure("HOST_DELIVERY_NOT_AVAILABLE"));
        };
        if source["state"] != "PENDING" {
            let tx = self.db.unchecked_transaction().map_err(db_error)?;
            tx.execute("UPDATE inbox_host_lanes SET state='RETIRED' WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,item.sequence]).map_err(db_error)?;
            tx.execute(
                "DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",
                params![options.workspace_id, options.mailbox_id, item.sequence],
            )
            .map_err(db_error)?;
            let lane:String=tx.query_row("SELECT lane FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,item.sequence],|r|r.get(0)).map_err(db_error)?;
            promote_lane(
                &tx,
                &options.workspace_id,
                &options.mailbox_id,
                &lane,
                &host,
            )?;
            tx.commit().map_err(db_error)?;
            return Ok(None);
        }
        let pins = self
            .pins(&options.workspace_id, &options.mailbox_id)?
            .ok_or_else(|| failure("WATCH_NOT_CONNECTED"))?;
        if pins.destination_digest != host || pins.membership_id != options.membership_id {
            return Err(failure("HOST_BINDING_MISMATCH"));
        }
        if !frame.is_object() || frame.to_string().len() > 65536 {
            return Err(failure("HOST_FRAME_INVALID"));
        }
        let wire = frame.to_string();
        let hash = sha256_hex(wire.as_bytes());
        let call_id = crate::communication_host::random_token().map_err(|_| state())?;
        let scope = json!({"format":"peerwork.host-call.v1","owner":self.binding,"namespace":namespace,"workspace_id":options.workspace_id,"mailbox_id":options.mailbox_id,"membership_id":options.membership_id,"sequence":item.sequence,"delivery_id":item.delivery_id,"receiver_id":pins.receiver_id,"epoch":pins.epoch,"binding_version":pins.binding_version,"destination_digest":host,"call_id":call_id,"frame_digest":hash,"source_digest":sha256_hex(source["envelope"].to_string().as_bytes())});
        let aad = scope.to_string();
        let sealed = seal_bounded(identity, &aad, &wire, 65536).map_err(|_| invalid())?;
        let allocation = sealed.len() + aad.len() + 32768;
        let tx = self.db.unchecked_transaction().map_err(db_error)?;
        let prior:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND state<>'NOT_SENT')",params![options.workspace_id,options.mailbox_id,item.sequence],|r|r.get(0)).map_err(db_error)?;
        if prior {
            return Err(failure("HOST_ORIGINAL_CALL_UNRESOLVED_OR_ACCEPTED"));
        }
        let blocked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_lanes b JOIN inbox_host_lanes a ON a.workspace=b.workspace AND a.mailbox=b.mailbox AND a.lane=b.lane WHERE a.workspace=?1 AND a.mailbox=?2 AND a.sequence=?3 AND b.sequence<a.sequence AND b.state IN ('WAITING','CALL_OPEN','RESULT_UNKNOWN'))",params![options.workspace_id,options.mailbox_id,item.sequence],|r|r.get(0)).map_err(db_error)?;
        if blocked {
            return Err(failure("HOST_LANE_BLOCKED"));
        }
        let attempts:Option<u64>=tx.query_row("SELECT attempts FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![options.workspace_id,options.mailbox_id,item.sequence,item.delivery_id],|r|r.get(0)).optional().map_err(db_error)?;
        attempts.ok_or_else(|| failure("HOST_WORK_NOT_READY"))?;
        let attempts:u64=tx.query_row("SELECT COALESCE(max(attempt),0) FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,item.sequence],|r|r.get(0)).map_err(db_error)?;
        if attempts >= 32 {
            return Err(failure("HOST_ATTEMPT_LIMIT"));
        }
        let (bytes, rows): (usize, usize) = tx
            .query_row(
                "SELECT allocated,rows FROM inbox_host_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        if bytes + allocation > 32 * 1024 * 1024 || rows >= 65536 {
            return Err(failure("HOST_STATE_CAPACITY"));
        }
        tx.execute("INSERT INTO inbox_host_calls(call_id,workspace,mailbox,sequence,delivery_id,host,attempt,scope,frame_digest,frame,state,outcome,allocation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'CALL_OPEN',NULL,?11)",params![call_id,options.workspace_id,options.mailbox_id,item.sequence,item.delivery_id,host,attempts+1,aad,hash,sealed,allocation]).map_err(db_error)?;
        tx.execute(
            "DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",
            params![options.workspace_id, options.mailbox_id, item.sequence],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE inbox_host_lanes SET state='CALL_OPEN' WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,item.sequence]).map_err(db_error)?;
        tx.execute(
            "UPDATE inbox_host_meta SET allocated=allocated+?1,rows=rows+1 WHERE id=1",
            [allocation],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(Some(HostCall {
            call_id,
            scope,
            frame_digest: hash,
            frame,
            state: "CALL_OPEN".into(),
            outcome: None,
            attempt: attempts + 1,
            report_version: 1,
        }))
    }
    fn host_call(&self, identity: &KernelIdentity, call_id: &str) -> Result<HostCall> {
        let (aad,hash,frame,status,outcome,attempt,report_version):(String,String,Vec<u8>,String,Option<Vec<u8>>,u64,u64)=self.db.query_row("SELECT scope,frame_digest,frame,state,outcome,attempt,report_version FROM inbox_host_calls WHERE call_id=?1",[call_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(db_error)?;
        let scope: Value = serde_json::from_str(&aad).map_err(|_| invalid())?;
        if scope["owner"] != self.binding
            || scope["call_id"] != call_id
            || scope["frame_digest"] != hash
        {
            return Err(invalid());
        }
        let frame = open_bounded(identity, &aad, &frame, 65536).map_err(|_| invalid())?;
        if sha256_hex(frame.as_bytes()) != hash {
            return Err(invalid());
        }
        let frame = serde_json::from_str(&frame).map_err(|_| invalid())?;
        let outcome = outcome
            .map(|b| {
                open_bounded(identity, &format!("{aad}:OUTCOME"), &b, 4096)
                    .map_err(|_| invalid())
                    .and_then(|s| serde_json::from_str::<HostOutcome>(&s).map_err(|_| invalid()))
            })
            .transpose()?;
        if let Some(out) = &outcome {
            out.validate()?;
            if out.status() != status {
                return Err(invalid());
            }
        } else if !matches!(status.as_str(), "CALL_OPEN" | "RESULT_UNKNOWN") {
            return Err(invalid());
        }
        Ok(HostCall {
            call_id: call_id.into(),
            scope,
            frame_digest: hash,
            frame,
            state: status,
            outcome: outcome.map(|v| serde_json::to_value(v).unwrap()),
            attempt,
            report_version,
        })
    }
    pub fn host_finish(
        &mut self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
        call: &HostCall,
        outcome: HostOutcome,
    ) -> Result<()> {
        let mut historical=self.host_evidence_scope(namespace, options)?;
        outcome.validate()?;
        let old = self.host_call(identity, &call.call_id)?;
        self.host_original_scope(namespace,options,&old)?;
        historical|=old.scope["binding_version"]!=self.pins(&options.workspace_id,&options.mailbox_id)?.ok_or_else(invalid)?.binding_version;
        if old.scope != call.scope
            || old.frame_digest != call.frame_digest
            || old.scope["namespace"] != namespace
            || old.scope["workspace_id"] != options.workspace_id
            || old.scope["mailbox_id"] != options.mailbox_id
            || old.scope["membership_id"] != options.membership_id
            || old.scope["destination_digest"] != options.host_destination.as_deref().unwrap_or("")
        {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        let value = serde_json::to_value(&outcome).map_err(|_| invalid())?;
        if old.outcome.as_ref() == Some(&value) {
            return Ok(());
        }
        if old.state == "RESULT_UNKNOWN"
            && matches!(outcome, HostOutcome::Unknown { .. })
            && old.outcome.is_some()
        {
            return Err(failure("HOST_EVIDENCE_CONFLICT"));
        }
        let advances_queue =
            old.state == "HOST_QUEUED" && matches!(outcome, HostOutcome::HostAccepted { .. });
        if matches!(
            old.state.as_str(),
            "NOT_SENT" | "HOST_QUEUED" | "HOST_ACCEPTED"
        ) && !advances_queue
        {
            return if old.outcome.as_ref() == Some(&value) {
                Ok(())
            } else {
                Err(failure("HOST_EVIDENCE_CONFLICT"))
            };
        }
        let aad = old.scope.to_string();
        let sealed = seal_bounded(
            identity,
            &format!("{aad}:OUTCOME"),
            &value.to_string(),
            4096,
        )
        .map_err(|_| invalid())?;
        let sequence = old.scope["sequence"].as_u64().ok_or_else(invalid)?;
        let tx = self.db.unchecked_transaction().map_err(db_error)?;
        tx.execute(
            "INSERT INTO inbox_host_facts VALUES(?1,?2,?3)",
            params![call.call_id, outcome.status(), sealed],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE inbox_host_calls SET state=?2,outcome=?3,report_version=report_version+1,report_pending=1,report_code=NULL WHERE call_id=?1",
            params![call.call_id, outcome.status(), sealed],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE inbox_host_lanes SET state=?4 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence,if historical&&matches!(outcome,HostOutcome::NotSent{..}){"HISTORICAL_NOT_SENT"}else if matches!(outcome,HostOutcome::NotSent{..}){"WAITING"}else{outcome.status()}]).map_err(db_error)?;
        if historical {tx.commit().map_err(db_error)?;return Ok(());}
        let lane:String=tx.query_row("SELECT lane FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence],|r|r.get(0)).map_err(db_error)?;
        promote_lane(
            &tx,
            &options.workspace_id,
            &options.mailbox_id,
            &lane,
            options.host_destination.as_deref().unwrap_or(""),
        )?;
        if let HostOutcome::NotSent { code, .. } = &outcome {
            tx.execute("UPDATE inbox_host_ready SET next_retry=?4+min(30000,500*(1<<min(failures,6))),failures=failures+1,code=?5 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence,crate::participant_store::now(),code]).map_err(db_error)?;
        } else {
            tx.execute(
                "DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",
                params![options.workspace_id, options.mailbox_id, sequence],
            )
            .map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(())
    }
    pub fn host_status(
        &self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
        item: &DeliveryReference,
    ) -> Result<Value> {
        self.host_evidence_scope(namespace, options)?;
        let id:Option<String>=self.db.query_row("SELECT call_id FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4 AND host=?5 ORDER BY attempt DESC LIMIT 1",params![options.workspace_id,options.mailbox_id,item.sequence,item.delivery_id,options.host_destination],|r|r.get(0)).optional().map_err(db_error)?;
        let call = id.map(|id| self.host_call(identity, &id)).transpose()?;
        let retired=call.is_none()&&item.sequence<=self.host_retired(options,options.host_destination.as_deref().unwrap_or(""))?.0;

        if call.as_ref().is_some_and(|c| {
            c.scope["namespace"] != namespace
                || c.scope["membership_id"] != options.membership_id
                || c.scope["destination_digest"]
                    != options.host_destination.as_deref().unwrap_or("")
        }) {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        let blocker:Option<String>=self.db.query_row("SELECT code FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![options.workspace_id,options.mailbox_id,item.sequence,item.delivery_id],|r|r.get::<_,Option<String>>(0)).optional().map_err(db_error)?.flatten();
        let facts = call
            .as_ref()
            .map(|c| self.host_facts(identity, c))
            .transpose()?
            .unwrap_or_default();

        let reporting = if let Some(c) = &call {
            self.db
                .query_row(
                    "SELECT report_pending,report_code FROM inbox_host_calls WHERE call_id=?1",
                    [&c.call_id],
                    |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Option<String>>(1)?)),
                )
                .map_err(db_error)?
        } else {
            (0, None)
        };
        Ok(
            json!({"format":"peerwork.communication-state.v1","observer":"RECIPIENT_RUNTIME","assurance":"RECEIVER_ATTESTED","reporting":if reporting.0==2{"BLOCKED"}else if reporting.0==1{"PENDING"}else if call.is_some(){"SERVICE_CONFIRMED"}else{"LOCAL_ONLY"},"reporting_error":reporting.1,"workspace_id":options.workspace_id,"mailbox_id":options.mailbox_id,"delivery_id":item.delivery_id,"sequence":item.sequence,"host":call.as_ref().map(|c|c.state.as_str()).unwrap_or(if retired{"LOCAL_EVIDENCE_RETIRED"}else{"NO_CONFIRMED_INVOCATION"}),"call_id":call.as_ref().map(|c|&c.call_id),"frame_digest":call.as_ref().map(|c|&c.frame_digest),"outcome":call.as_ref().and_then(|c|c.outcome.as_ref()),"facts":facts,"blocker":blocker,"model_response":"NOT_ATTESTED"}),
        )
    }
    pub fn host_scope_check(&self,namespace:&str,options:&WatchOptions)->Result<()>{self.host_link(namespace,options).map(|_|())}
    pub fn host_has_unknown(&self,workspace:&str,mailbox:&str)->Result<bool>{self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND state='RESULT_UNKNOWN')",params![workspace,mailbox],|r|r.get(0)).map_err(db_error)}

    fn host_facts(&self, identity: &KernelIdentity, c: &HostCall) -> Result<Vec<Value>> {
        let rows=self.db.prepare("SELECT state,evidence FROM inbox_host_facts WHERE call_id=?1 ORDER BY state LIMIT 4").map_err(db_error)?.query_map([&c.call_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        let mut facts = Vec::new();
        for (state, evidence) in rows {
            let wire = open_bounded(identity, &format!("{}:OUTCOME", c.scope), &evidence, 4096)
                .map_err(|_| invalid())?;
            let fact: HostOutcome = serde_json::from_str(&wire).map_err(|_| invalid())?;
            fact.validate()?;
            if fact.status() != state {
                return Err(invalid());
            }
            facts.push(serde_json::to_value(fact).map_err(|_| invalid())?);
        }
        Ok(facts)
    }
    pub fn pending_host_report(
        &self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
    ) -> Result<Option<(String, u64, Value)>> {
        self.host_link(namespace, options)?;
        let id:Option<String>=self.db.query_row("SELECT call_id FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND report_pending=1 ORDER BY call_id LIMIT 1",params![options.workspace_id,options.mailbox_id],|r|r.get(0)).optional().map_err(db_error)?;
        let Some(id) = id else {
            return Ok(None);
        };
        let call = self.host_call(identity, &id)?;
        self.host_original_scope(namespace,options,&call)?;
        let report = json!({"sequence":call.scope["sequence"],"delivery_id":call.scope["delivery_id"],"call_id":id,"attempt":call.attempt,"scope":call.scope,"frame_digest":call.frame_digest,"state":call.state,"facts":self.host_facts(identity,&call)?,"report_sequence":call.report_version});
        Ok(Some((id, call.report_version, report)))
    }
    pub fn host_report_failed(
        &self,
        workspace: &str,
        mailbox: &str,
        id: &str,
        version: u64,
        code: &str,
    ) -> Result<()> {
        if !crate::communication_store::identifier(code) {
            return Err(invalid());
        }
        self.db.execute("UPDATE inbox_host_calls SET report_pending=2,report_code=?5 WHERE workspace=?1 AND mailbox=?2 AND call_id=?3 AND report_version=?4",params![workspace,mailbox,id,version,code]).map_err(db_error)?;
        Ok(())
    }
    pub fn host_reported(
        &self,
        workspace: &str,
        mailbox: &str,
        id: &str,
        version: u64,
    ) -> Result<()> {
        self.db.execute("UPDATE inbox_host_calls SET report_pending=0,report_code=NULL WHERE workspace=?1 AND mailbox=?2 AND call_id=?3 AND report_version=?4",params![workspace,mailbox,id,version]).map_err(db_error)?;
        Ok(())
    }
}

fn promote_lane(
    tx: &rusqlite::Transaction<'_>,
    workspace: &str,
    mailbox: &str,
    lane: &str,
    host: &str,
) -> Result<()> {
    for _ in 0..32 {
        let mut head: Option<(u64, String)> = None;
        for state in ["WAITING", "CALL_OPEN", "RESULT_UNKNOWN"] {
            let row:Option<u64>=tx.query_row("SELECT sequence FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND lane=?3 AND state=?4 ORDER BY sequence LIMIT 1",params![workspace,mailbox,lane,state],|r|r.get(0)).optional().map_err(db_error)?;
            if let Some(sequence) = row {
                if head.as_ref().is_none_or(|h| sequence < h.0) {
                    head = Some((sequence, state.into()));
                }
            }
        }
        let Some((sequence, state)) = head else {
            return Ok(());
        };
        if state != "WAITING" {
            return Ok(());
        }
        let inserted=tx.execute("INSERT OR IGNORE INTO inbox_host_ready(workspace,mailbox,sequence,delivery_id,host) SELECT workspace,mailbox,sequence,delivery_id,?4 FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND consume_requested=0",params![workspace,mailbox,sequence,host]).map_err(db_error)?;
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3)",params![workspace,mailbox,sequence],|r|r.get(0)).map_err(db_error)?;
        if inserted != 0 || exists {
            return Ok(());
        }
        tx.execute("UPDATE inbox_host_lanes SET state='RETIRED' WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND state='WAITING'",params![workspace,mailbox,sequence]).map_err(db_error)?;
    }
    Ok(())
}
