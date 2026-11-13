//! Notification delivery obligations are distinct from immutable host facts.
//! Repeated notifications keep their frozen message ID; business operations are
//! never reissued by this scheduler.
use super::*;

pub(super) fn retry_delay(state: &str, attempt: u64) -> i64 {
    let base = match state {
        "HOST_ACCEPTED" => 60_000i64,
        "HOST_QUEUED" => 30_000,
        _ => 3_000,
    };
    (base << attempt.saturating_sub(1).min(7)).min(300_000)
}

impl InboxStore {
    pub(super) fn host_delivery_completed(
        &mut self, namespace: &str, options: &WatchOptions, call: &HostCall,
    ) -> Result<bool> {
        self.host_original_scope(namespace, options, call)?;
        let sequence = call.scope["sequence"].as_u64().ok_or_else(invalid)?;
        let id = call.scope["delivery_id"].as_str().ok_or_else(invalid)?;
        let consumed: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4 AND consume_requested=1) OR EXISTS(SELECT 1 FROM inbox_consumed WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4)",
            params![options.workspace_id, options.mailbox_id, sequence, id], |r|r.get(0),
        ).map_err(db_error)?;
        let durable:bool=self.db.query_row("SELECT consumed_confirmed=1 FROM inbox_host_calls WHERE call_id=?1",[&call.call_id],|r|r.get(0)).map_err(db_error)?;
        let consumed=consumed||durable;
        let retired=sequence<=self.host_retired(options,options.host_destination.as_deref().unwrap_or(""))?.0;
        let terminal:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4 AND status<>'PENDING')",params![options.workspace_id,options.mailbox_id,sequence,id],|r|r.get(0)).map_err(db_error)?;
        if !consumed && !retired && !terminal { return Ok(false); }
        let disposition=if consumed {"CONSUMED"}else if retired {"RETIRED"}else{"TERMINAL"};
        let tx = self.db.unchecked_transaction().map_err(db_error)?;
        tx.execute("UPDATE inbox_host_calls SET delivery_state=?6 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4 AND host=?5", params![options.workspace_id,options.mailbox_id,sequence,id,options.host_destination,disposition]).map_err(db_error)?;
        let lane: Option<String> = tx.query_row("SELECT lane FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence],|r|r.get(0)).optional().map_err(db_error)?;
        tx.execute("UPDATE inbox_host_lanes SET state='CONSUMED' WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence]).map_err(db_error)?;
        tx.execute("DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence]).map_err(db_error)?;
        if let Some(lane) = lane { promote_lane(&tx,&options.workspace_id,&options.mailbox_id,&lane,options.host_destination.as_deref().unwrap_or(""))?; }
        tx.commit().map_err(db_error)?;
        Ok(true)
    }

    pub fn host_retry(
        &mut self, identity: &KernelIdentity, namespace: &str,
        options: &WatchOptions, original: &HostCall,
    ) -> Result<Option<HostCall>> {
        self.host_link(namespace, options)?;
        let call = self.host_call(identity, &original.call_id)?;
        self.host_original_scope(namespace, options, &call)?;
        if call.scope != original.scope || call.frame_digest != original.frame_digest {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        if self.host_delivery_completed(namespace, options, &call)? { return Ok(None); }
        let (active, retry_at): (bool,i64) = self.db.query_row("SELECT delivery_state='ACTIVE',retry_at FROM inbox_host_calls WHERE call_id=?1",[&call.call_id],|r|Ok((r.get(0)?,r.get(1)?))).map_err(db_error)?;
        if !active || !matches!(call.state.as_str(),"RESULT_UNKNOWN"|"HOST_QUEUED") || retry_at > crate::participant_store::now() { return Ok(None); }
        let pins = self.pins(&options.workspace_id,&options.mailbox_id)?.ok_or_else(invalid)?;
        if call.scope["receiver_id"] != pins.receiver_id || call.scope["epoch"] != pins.epoch
            || call.scope["binding_version"] != pins.binding_version || call.scope["destination_digest"] != pins.destination_digest {
            return Err(failure("HOST_RETRY_ORIGINAL_BINDING_CHANGED"));
        }
        let item = DeliveryReference { sequence: call.scope["sequence"].as_u64().ok_or_else(invalid)?, delivery_id: call.scope["delivery_id"].as_str().ok_or_else(invalid)?.into() };
        // Admission is serialized with inbox consumption and result writes by
        // the existing receiver actor. Reservation is committed before host IO.
        self.db.execute("INSERT OR IGNORE INTO inbox_host_ready(workspace,mailbox,sequence,delivery_id,host) VALUES(?1,?2,?3,?4,?5)",params![options.workspace_id,options.mailbox_id,item.sequence,item.delivery_id,options.host_destination]).map_err(db_error)?;
        self.host_begin_attempt(identity,namespace,options,&item,call.frame.clone(),Some(&call))
    }

    pub fn host_diagnostic(&self, identity: &KernelIdentity, namespace: &str,
        options: &WatchOptions, supplied: &HostCall, snapshot: &Value) -> Result<()> {
        self.host_evidence_scope(namespace,options)?;
        let call=self.host_call(identity,&supplied.call_id)?;
        self.host_original_scope(namespace,options,&call)?;
        if supplied.scope!=call.scope || supplied.frame_digest!=call.frame_digest { return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH")); }
        let mut safe=serde_json::Map::new();
        for key in ["phase","original_error_code","failure_phase","last_error_code"] {
            if let Some(value)=snapshot[key].as_str().filter(|s|crate::communication_store::identifier(s)) { safe.insert(key.into(),json!(value)); }
        }
        for key in ["elapsed_ms","budget_ms","last_success_at","last_failure_at","observed_at","rpc_error_code"] {
            if let Some(value)=snapshot[key].as_i64() { safe.insert(key.into(),json!(value)); }
        }
        self.db.execute("UPDATE inbox_host_calls SET diagnostic=COALESCE(diagnostic,?2) WHERE call_id=?1",params![call.call_id,Value::Object(safe).to_string()]).map_err(db_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        root: crate::test_support::ProtectedTestDir, identity: KernelIdentity, store: InboxStore,
        options: WatchOptions, items: Vec<DeliveryReference>,
    }
    const NS: &str = "program:recovery";
    impl Fixture {
        fn new() -> Self {
            let root=crate::test_support::protected_test_dir();
            let identity=KernelIdentity::create(&root.path().join("identity")).unwrap();
            let mut store=InboxStore::open_local(&root.path().join("inbox"),&identity,"https://example.invalid/").unwrap();
            let host=HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"original-thread","session_id":"original-session"})).unwrap();
            let options=WatchOptions{workspace_id:"W".repeat(43),mailbox_id:"M".repeat(43),membership_id:"G".repeat(43),consumer_id:"recovery".into(),host_destination:Some(host.digest.clone())};
            let binding=store.attach_watch(&identity,NS,&options).unwrap();
            store.register(&MailboxPins{workspace_id:options.workspace_id.clone(),mailbox_id:options.mailbox_id.clone(),membership_id:options.membership_id.clone(),receiver_id:binding.receiver,epoch:1,destination_digest:host.digest.clone(),binding_version:1,after_sequence:0,after_control_sequence:Some(0)}).unwrap();
            store.host_attach(NS,&options,&host).unwrap();
            let mut items=Vec::new();
            for sequence in 1..=2 {
                let item=DeliveryReference{sequence,delivery_id:format!("{sequence:043}")};
                let envelope=json!({"sequence":sequence,"delivery_id":item.delivery_id,"kind":"BUSINESS","business":{"instance_id":"same-instance"}});
                let wire=json!({"items":[envelope]}).to_string();let digest=sha256_hex(wire.as_bytes());
                let sealed=seal_bounded(&identity,&store.aad(&options.workspace_id,&options.mailbox_id,&digest),&wire,MAX_FRAME_BYTES).unwrap();
                store.db.execute("INSERT INTO inbox_frames VALUES(?1,?2,?3,?4,?5)",params![digest,options.workspace_id,options.mailbox_id,sealed,wire.len()]).unwrap();
                store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,?6,'PENDING')",params![options.workspace_id,options.mailbox_id,sequence,item.delivery_id,digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
                store.db.execute("UPDATE inbox_meta SET allocated=allocated+?1,rows=rows+1 WHERE id=1",[wire.len()]).unwrap();
                store.db.execute("INSERT INTO inbox_item_lanes VALUES(?1,?2,?3,'same-lane')",params![options.workspace_id,options.mailbox_id,sequence]).unwrap();items.push(item);
            }
            store.db.execute("UPDATE inbox_mailboxes SET item_cursor=2",[]).unwrap();
            store.host_due(NS,&options,32).unwrap();
            Self{root,identity,store,options,items}
        }
        fn begin(&mut self) -> HostCall {
            self.store.host_begin(&self.identity,NS,&self.options,&self.items[0],json!({"message_id":"stable-notification-id","rendered_text":"synthetic private message"})).unwrap().unwrap()
        }
        fn finish(&mut self,call:&HostCall,outcome:HostOutcome) {
            self.store.host_finish(&self.identity,NS,&self.options,call,outcome).unwrap();
        }
        fn retry_now(&self) { self.store.db.execute("UPDATE inbox_host_calls SET retry_at=0,reconcile_at=0",[]).unwrap(); }
    }
    #[test]
    fn lost_acceptance_retries_frozen_notification_after_restart_without_falsifying_original() {
        let mut f=Fixture::new();let first=f.begin();
        f.finish(&first,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});
        assert!(f.store.host_retry(&f.identity,NS,&f.options,&first).unwrap().is_none(),"respect the initial recovery grace");
        f.retry_now();
        for index in ["inbox_host_current_unknown","inbox_host_original_active","inbox_host_delivery_recovery"] {f.store.db.execute_batch(&format!("DROP INDEX {index}")).unwrap();}
        for column in ["retry_at","retry_of","diagnostic","delivery_state"] {f.store.db.execute_batch(&format!("ALTER TABLE inbox_host_calls DROP COLUMN {column}")).unwrap();}
        let mut reopened=InboxStore::open_local(&f.root.path().join("inbox"),&f.identity,"https://example.invalid/").unwrap();
        let original=reopened.host_reconcile_due(&f.identity,NS,&f.options).unwrap().unwrap();
        let retry=reopened.host_retry(&f.identity,NS,&f.options,&original).unwrap().unwrap();
        assert_ne!(retry.call_id,first.call_id);assert_eq!(retry.attempt,2);
        assert_eq!(retry.frame,first.frame);assert_eq!(retry.frame_digest,first.frame_digest);assert_eq!(retry.retry_of,Some(first.scope.clone()));
        assert_eq!(reopened.host_call(&f.identity,&first.call_id).unwrap().state,"RESULT_UNKNOWN");
        assert!(reopened.host_retry(&f.identity,NS,&f.options,&original).unwrap().is_none(),"one original admits only one successor");
        reopened.host_finish(&f.identity,NS,&f.options,&first,HostOutcome::HostAccepted{receipt:"late-original-ack".into()}).unwrap();
        let lane:String=reopened.db.query_row("SELECT state FROM inbox_host_lanes WHERE sequence=1",[],|r|r.get(0)).unwrap();
        assert_eq!(lane,"CALL_OPEN","a late original receipt cannot overwrite the active successor");
        reopened.host_finish(&f.identity,NS,&f.options,&retry,HostOutcome::HostAccepted{receipt:"retry-accepted".into()}).unwrap();
        assert_eq!(reopened.host_due(NS,&f.options,32).unwrap()[0].sequence,2);
    }
    #[test]
    fn exact_consumption_ends_unknown_obligation_and_unblocks_lane_without_fabricating_acceptance() {
        let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});
        f.store.db.execute("INSERT INTO inbox_consumed VALUES(?1,?2,1,?3)",params![f.options.workspace_id,f.options.mailbox_id,f.items[0].delivery_id]).unwrap();
        f.store.db.execute("DELETE FROM inbox_items WHERE sequence=1",[]).unwrap();f.retry_now();
        assert!(f.store.host_reconcile_due(&f.identity,NS,&f.options).unwrap().is_none());
        let status=f.store.host_status(&f.identity,NS,&f.options,&f.items[0]).unwrap();
        assert_eq!(status["host"],"RESULT_UNKNOWN");assert_eq!(status["delivery"]["state"],"CONSUMED");
        assert_eq!(f.store.host_summary(&f.identity,NS,&f.options).unwrap()["acceptance_unresolved"],false);
        assert_eq!(f.store.host_due(NS,&f.options,32).unwrap()[0].sequence,2);
        assert!(f.store.host_retry(&f.identity,NS,&f.options,&first).unwrap().is_none());
    }
    #[test]
    fn retry_rejects_changed_binding_and_preserves_original_diagnostics() {
        let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::Unknown{code:"HOST_OPERATION_TIMEOUT".into()});f.retry_now();
        f.store.host_diagnostic(&f.identity,NS,&f.options,&first,&json!({"phase":"DELIVER","failure_phase":"INPUT_REPLY","original_error_code":"HOST_OPERATION_TIMEOUT","elapsed_ms":10000,"body":"must never persist"})).unwrap();
        f.store.host_diagnostic(&f.identity,NS,&f.options,&first,&json!({"phase":"HEALTH","failure_phase":"SESSION_READ"})).unwrap();
        let status=f.store.host_status(&f.identity,NS,&f.options,&f.items[0]).unwrap();
        assert_eq!(status["delivery"]["diagnostic"]["failure_phase"],"INPUT_REPLY");assert!(status["delivery"]["diagnostic"].get("body").is_none());
        f.store.db.execute("UPDATE inbox_mailboxes SET binding_version=2",[]).unwrap();
        assert_eq!(f.store.host_retry(&f.identity,NS,&f.options,&first).unwrap_err().code,"HOST_EVIDENCE_SCOPE_MISMATCH");
        assert_eq!(f.store.host_call(&f.identity,&first.call_id).unwrap().state,"RESULT_UNKNOWN");
    }
    #[test]
    fn accepted_input_is_not_consumption_and_does_not_reinject_the_full_message() {
        let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::HostAccepted{receipt:"host-only".into()});
        f.retry_now();
        assert!(f.store.host_retry(&f.identity,NS,&f.options,&first).unwrap().is_none());
        assert_eq!(f.store.host_status(&f.identity,NS,&f.options,&f.items[0]).unwrap()["delivery"]["state"],"ACTIVE");
        assert_eq!(retry_delay("RESULT_UNKNOWN",1000),300000);
    }
    #[test]
    fn confirmed_retirement_closes_old_unknown_after_bounded_consumption_receipts_are_trimmed() {
        let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});
        f.store.db.execute("INSERT INTO inbox_consumed VALUES(?1,?2,1,?3)",params![f.options.workspace_id,f.options.mailbox_id,f.items[0].delivery_id]).unwrap();
        f.store.db.execute("DELETE FROM inbox_items WHERE sequence=1",[]).unwrap();
        let plan=f.store.host_retirement_plan(&f.identity,NS,&f.options).unwrap().unwrap();
        f.store.host_retirement_commit(&f.identity,NS,&f.options,&plan).unwrap();
        f.store.db.execute("DELETE FROM inbox_consumed",[]).unwrap();f.retry_now();
        assert!(f.store.host_reconcile_due(&f.identity,NS,&f.options).unwrap().is_none());
        let status=f.store.host_status(&f.identity,NS,&f.options,&f.items[0]).unwrap();
        assert_eq!(status["host"],"RESULT_UNKNOWN");assert_eq!(status["delivery"]["state"],"RETIRED");
        assert_eq!(f.store.host_summary(&f.identity,NS,&f.options).unwrap()["acceptance_unresolved"],false);
    }

    include!("participant_host_retention_tests.rs");

}
