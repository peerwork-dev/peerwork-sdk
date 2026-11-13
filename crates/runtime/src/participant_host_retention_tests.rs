// Included in recovery tests to exercise the real inbox and notification actor.
impl Fixture {
    fn add(&mut self, sequence:u64)->DeliveryReference {
        let item=DeliveryReference{sequence,delivery_id:format!("{sequence:043}")};
        let envelope=json!({"sequence":sequence,"delivery_id":item.delivery_id,"kind":"BUSINESS","business":{"instance_id":format!("instance-{sequence}")}});
        let wire=json!({"items":[envelope]}).to_string();let digest=sha256_hex(wire.as_bytes());
        let encrypted=seal_bounded(&self.identity,&self.store.aad(&self.options.workspace_id,&self.options.mailbox_id,&digest),&wire,MAX_FRAME_BYTES).unwrap();
        self.store.db.execute("INSERT INTO inbox_frames VALUES(?1,?2,?3,?4,?5)",params![digest,self.options.workspace_id,self.options.mailbox_id,encrypted,wire.len()]).unwrap();
        self.store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,?6,'PENDING')",params![self.options.workspace_id,self.options.mailbox_id,sequence,item.delivery_id,digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
        self.store.db.execute("UPDATE inbox_meta SET allocated=allocated+?1,rows=rows+1 WHERE id=1",[wire.len()]).unwrap();
        self.store.db.execute("UPDATE inbox_mailboxes SET item_cursor=?1",[sequence]).unwrap();item
    }
    fn acknowledge(&mut self, items:&[DeliveryReference]) {
        for page in items.chunks(32) {
            let refs=page.iter().map(|r|(r.sequence,r.delivery_id.clone())).collect::<Vec<_>>();
            self.store.consume(&self.options.workspace_id,&self.options.mailbox_id,&refs).unwrap();
            self.store.acknowledged(&self.options.workspace_id,&self.options.mailbox_id,&refs,true).unwrap();
        }
    }
    fn reported(&self, call:&HostCall) {
        let current=self.store.host_call(&self.identity,&call.call_id).unwrap();
        self.store.host_reported(&self.options.workspace_id,&self.options.mailbox_id,&call.call_id,current.report_version).unwrap();
    }
}
#[test]
fn completed_notification_retires_across_a_permanent_early_hole_after_receipt_cache_rollover() {
    let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::HostAccepted{receipt:"first-unconsumed".into()});f.reported(&first);
    let second=f.store.host_begin(&f.identity,NS,&f.options,&f.items[1],json!({"message_id":"second","rendered_text":"private-second"})).unwrap().unwrap();
    f.finish(&second,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});f.reported(&second);
    f.acknowledge(&[f.items[1].clone()]);
    let mut later=Vec::new();for sequence in 3..=1050 {later.push(f.add(sequence));}f.acknowledge(&later);
    let remembered:bool=f.store.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_consumed WHERE sequence=2)",[],|r|r.get(0)).unwrap();assert!(!remembered,"the finite retry cache really rolled over");
    assert_eq!(f.store.host_consumed_frontier(&f.options).unwrap(),0);
    let plan=f.store.host_retirement_plan(&f.identity,NS,&f.options).unwrap().unwrap();assert_eq!(plan["through_sequence"],0);assert_eq!(plan["calls"].as_array().unwrap().len(),1);
    assert_eq!(plan["calls"][0]["call_id"],second.call_id);
    f.store.host_retirement_commit(&f.identity,NS,&f.options,&plan).unwrap();
    // A crash after either side's durable commit is idempotent.
    drop(f.store);f.store=InboxStore::open_local(&f.root.path().join("inbox"),&f.identity,"https://example.invalid/").unwrap();
    f.store.host_retirement_commit(&f.identity,NS,&f.options,&plan).unwrap();
    assert_eq!(f.store.host_call(&f.identity,&first.call_id).unwrap().state,"HOST_ACCEPTED");
    assert_eq!(f.store.host_status(&f.identity,NS,&f.options,&f.items[1]).unwrap()["host"],"LOCAL_EVIDENCE_RETIRED");
    assert!(f.store.host_begin(&f.identity,NS,&f.options,&f.items[1],second.frame.clone()).unwrap().is_none());
    f.store.host_finish(&f.identity,NS,&f.options,&second,HostOutcome::HostAccepted{receipt:"late-input".into()}).unwrap();
    assert_eq!(f.store.host_status(&f.identity,NS,&f.options,&f.items[1]).unwrap()["host"],"LOCAL_EVIDENCE_RETIRED");
}
#[test]
fn pending_report_keeps_facts_but_not_consumed_private_payload() {
    let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});
    let before:u64=f.store.db.query_row("SELECT allocated FROM inbox_host_meta",[],|r|r.get(0)).unwrap();
    f.acknowledge(&[f.items[0].clone()]);
    let payloads:u64=f.store.db.query_row("SELECT count(*) FROM inbox_host_payloads",[],|r|r.get(0)).unwrap();assert_eq!(payloads,0);
    let report=f.store.pending_host_report(&f.identity,NS,&f.options).unwrap().unwrap();assert_eq!(report.0,first.call_id);assert_eq!(report.2["state"],"RESULT_UNKNOWN");
    assert!(f.store.host_retirement_plan(&f.identity,NS,&f.options).unwrap().unwrap()["calls"].as_array().unwrap().is_empty());
    let after:u64=f.store.db.query_row("SELECT allocated FROM inbox_host_meta",[],|r|r.get(0)).unwrap();assert!(after<before);
    f.reported(&first);let plan=f.store.host_retirement_plan(&f.identity,NS,&f.options).unwrap().unwrap();f.store.host_retirement_commit(&f.identity,NS,&f.options,&plan).unwrap();
}
#[test]
fn retries_share_one_authenticated_payload_and_release_it_after_exact_consumption() {
    let mut f=Fixture::new();let first=f.begin();f.finish(&first,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});f.reported(&first);f.retry_now();
    let second=f.store.host_retry(&f.identity,NS,&f.options,&first).unwrap().unwrap();f.finish(&second,HostOutcome::Unknown{code:"HOST_ACK_UNKNOWN".into()});f.reported(&second);
    let payloads:u64=f.store.db.query_row("SELECT count(*) FROM inbox_host_payloads",[],|r|r.get(0)).unwrap();assert_eq!(payloads,1);
    assert_eq!(f.store.host_call(&f.identity,&first.call_id).unwrap().frame,f.store.host_call(&f.identity,&second.call_id).unwrap().frame);
    f.acknowledge(&[f.items[0].clone()]);let plan=f.store.host_retirement_plan(&f.identity,NS,&f.options).unwrap().unwrap();assert_eq!(plan["calls"].as_array().unwrap().len(),2);
    f.store.host_retirement_commit(&f.identity,NS,&f.options,&plan).unwrap();let (rows,bytes):(u64,u64)=f.store.db.query_row("SELECT rows,allocated FROM inbox_host_meta",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();assert_eq!((rows,bytes),(0,0));
}
