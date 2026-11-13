// Included in recovery tests to exercise the real inbox and notification actor.
impl Fixture {
    fn add(&mut self, sequence: u64) -> DeliveryReference {
        let item = DeliveryReference {
            sequence,
            delivery_id: format!("{sequence:043}"),
        };
        let envelope = json!({"sequence":sequence,"delivery_id":item.delivery_id,"kind":"BUSINESS","business":{"instance_id":format!("instance-{sequence}")}});
        let wire = json!({"items":[envelope]}).to_string();
        let digest = sha256_hex(wire.as_bytes());
        let encrypted = seal_bounded(
            &self.identity,
            &self.store.aad(
                &self.options.workspace_id,
                &self.options.mailbox_id,
                &digest,
            ),
            &wire,
            MAX_FRAME_BYTES,
        )
        .unwrap();
        self.store
            .db
            .execute(
                "INSERT INTO inbox_frames VALUES(?1,?2,?3,?4,?5)",
                params![
                    digest,
                    self.options.workspace_id,
                    self.options.mailbox_id,
                    encrypted,
                    wire.len()
                ],
            )
            .unwrap();
        self.store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,?6,'PENDING')",params![self.options.workspace_id,self.options.mailbox_id,sequence,item.delivery_id,digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
        self.store
            .db
            .execute(
                "UPDATE inbox_meta SET allocated=allocated+?1,rows=rows+1 WHERE id=1",
                [wire.len()],
            )
            .unwrap();
        self.store
            .db
            .execute("UPDATE inbox_mailboxes SET item_cursor=?1", [sequence])
            .unwrap();
        item
    }
    fn acknowledge(&mut self, items: &[DeliveryReference]) {
        for page in items.chunks(32) {
            let refs = page
                .iter()
                .map(|r| (r.sequence, r.delivery_id.clone()))
                .collect::<Vec<_>>();
            self.store
                .consume(&self.options.workspace_id, &self.options.mailbox_id, &refs)
                .unwrap();
            self.store
                .acknowledged(
                    &self.options.workspace_id,
                    &self.options.mailbox_id,
                    &refs,
                    true,
                )
                .unwrap();
        }
    }
    fn reported(&self, call: &HostCall) {
        let current = self.store.host_call(&self.identity, &call.call_id).unwrap();
        self.store
            .host_reported(
                &self.options.workspace_id,
                &self.options.mailbox_id,
                &call.call_id,
                current.report_version,
            )
            .unwrap();
    }
}
#[test]
fn completed_notification_retires_across_a_permanent_early_hole_after_receipt_cache_rollover() {
    let mut f = Fixture::new();
    let first = f.begin();
    f.finish(
        &first,
        HostOutcome::HostAccepted {
            receipt: "first-unconsumed".into(),
        },
    );
    f.reported(&first);
    let second = f
        .store
        .host_begin(
            &f.identity,
            NS,
            &f.options,
            &f.items[1],
            json!({"message_id":"second","rendered_text":"private-second"}),
        )
        .unwrap()
        .unwrap();
    f.finish(
        &second,
        HostOutcome::Unknown {
            code: "HOST_ACK_UNKNOWN".into(),
        },
    );
    f.reported(&second);
    f.acknowledge(&[f.items[1].clone()]);
    let mut later = Vec::new();
    for sequence in 3..=1050 {
        later.push(f.add(sequence));
    }
    f.acknowledge(&later);
    let remembered: bool = f
        .store
        .db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM inbox_consumed WHERE sequence=2)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!remembered, "the finite retry cache really rolled over");
    assert_eq!(f.store.host_consumed_frontier(&f.options).unwrap(), 0);
    let plan = f
        .store
        .host_retirement_plan(&f.identity, NS, &f.options)
        .unwrap()
        .unwrap();
    assert_eq!(plan["through_sequence"], 0);
    assert_eq!(plan["calls"].as_array().unwrap().len(), 1);
    assert_eq!(plan["calls"][0]["call_id"], second.call_id);
    f.store
        .host_retirement_commit(&f.identity, NS, &f.options, &plan)
        .unwrap();
    // A crash after either side's durable commit is idempotent.
    drop(f.store);
    f.store = InboxStore::open_local(
        &f.root.path().join("inbox"),
        &f.identity,
        "https://example.invalid/",
    )
    .unwrap();
    f.store
        .host_retirement_commit(&f.identity, NS, &f.options, &plan)
        .unwrap();
    assert_eq!(
        f.store
            .host_call(&f.identity, &first.call_id)
            .unwrap()
            .state,
        "HOST_ACCEPTED"
    );
    assert_eq!(
        f.store
            .host_status(&f.identity, NS, &f.options, &f.items[1])
            .unwrap()["host"],
        "LOCAL_EVIDENCE_RETIRED"
    );
    assert!(f
        .store
        .host_begin(
            &f.identity,
            NS,
            &f.options,
            &f.items[1],
            second.frame.clone()
        )
        .unwrap()
        .is_none());
    f.store
        .host_finish(
            &f.identity,
            NS,
            &f.options,
            &second,
            HostOutcome::HostAccepted {
                receipt: "late-input".into(),
            },
        )
        .unwrap();
    assert_eq!(
        f.store
            .host_status(&f.identity, NS, &f.options, &f.items[1])
            .unwrap()["host"],
        "LOCAL_EVIDENCE_RETIRED"
    );
}
#[test]
fn pending_report_keeps_facts_but_not_consumed_private_payload() {
    let mut f = Fixture::new();
    let first = f.begin();
    f.finish(
        &first,
        HostOutcome::Unknown {
            code: "HOST_ACK_UNKNOWN".into(),
        },
    );
    let before: u64 = f
        .store
        .db
        .query_row("SELECT allocated FROM inbox_host_meta", [], |r| r.get(0))
        .unwrap();
    f.acknowledge(&[f.items[0].clone()]);
    let payloads: u64 = f
        .store
        .db
        .query_row("SELECT count(*) FROM inbox_host_payloads", [], |r| r.get(0))
        .unwrap();
    assert_eq!(payloads, 0);
    let report = f
        .store
        .pending_host_report(&f.identity, NS, &f.options)
        .unwrap()
        .unwrap();
    assert_eq!(report.0, first.call_id);
    assert_eq!(report.2["state"], "RESULT_UNKNOWN");
    assert!(f
        .store
        .host_retirement_plan(&f.identity, NS, &f.options)
        .unwrap()
        .unwrap()["calls"]
        .as_array()
        .unwrap()
        .is_empty());
    let after: u64 = f
        .store
        .db
        .query_row("SELECT allocated FROM inbox_host_meta", [], |r| r.get(0))
        .unwrap();
    assert!(after < before);
    assert!(
        after < 4000,
        "completed pending reports reserve only compact evidence"
    );
    f.reported(&first);
    let plan = f
        .store
        .host_retirement_plan(&f.identity, NS, &f.options)
        .unwrap()
        .unwrap();
    f.store
        .host_retirement_commit(&f.identity, NS, &f.options, &plan)
        .unwrap();
}
#[test]
fn retries_share_one_authenticated_payload_and_release_it_after_exact_consumption() {
    let mut f = Fixture::new();
    let first = f.begin();
    f.finish(
        &first,
        HostOutcome::Unknown {
            code: "HOST_ACK_UNKNOWN".into(),
        },
    );
    f.reported(&first);
    f.retry_now();
    let second = f
        .store
        .host_retry(&f.identity, NS, &f.options, &first)
        .unwrap()
        .unwrap();
    f.finish(
        &second,
        HostOutcome::Unknown {
            code: "HOST_ACK_UNKNOWN".into(),
        },
    );
    f.reported(&second);
    let payloads: u64 = f
        .store
        .db
        .query_row("SELECT count(*) FROM inbox_host_payloads", [], |r| r.get(0))
        .unwrap();
    assert_eq!(payloads, 1);
    assert_eq!(
        f.store
            .host_call(&f.identity, &first.call_id)
            .unwrap()
            .frame,
        f.store
            .host_call(&f.identity, &second.call_id)
            .unwrap()
            .frame
    );
    f.acknowledge(&[f.items[0].clone()]);
    let plan = f
        .store
        .host_retirement_plan(&f.identity, NS, &f.options)
        .unwrap()
        .unwrap();
    assert_eq!(plan["calls"].as_array().unwrap().len(), 2);
    f.store
        .host_retirement_commit(&f.identity, NS, &f.options, &plan)
        .unwrap();
    let (rows, bytes): (u64, u64) = f
        .store
        .db
        .query_row("SELECT rows,allocated FROM inbox_host_meta", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((rows, bytes), (0, 0));
}
#[test]
fn repeated_unknown_inputs_keep_one_current_call_and_never_reset_the_attempt_counter() {
    let mut f = Fixture::new();
    let first = f.begin();
    let mut current = first.clone();
    for attempt in 1..=80u64 {
        assert_eq!(current.attempt, attempt);
        f.finish(
            &current,
            HostOutcome::Unknown {
                code: "HOST_ACK_UNKNOWN".into(),
            },
        );
        f.reported(&current);
        f.retry_now();
        let report = f
            .store
            .pending_host_report(&f.identity, NS, &f.options)
            .unwrap();
        assert!(report.is_none());
        let next = f
            .store
            .host_retry(&f.identity, NS, &f.options, &current)
            .unwrap()
            .unwrap();
        let plan = f
            .store
            .host_retirement_plan(&f.identity, NS, &f.options)
            .unwrap()
            .unwrap();
        assert!(plan["calls"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["retirement"] == "SUPERSEDED"));
        f.store
            .host_retirement_commit(&f.identity, NS, &f.options, &plan)
            .unwrap();
        f.store
            .host_retirement_commit(&f.identity, NS, &f.options, &plan)
            .unwrap();
        current = next;
        let (rows, bytes): (u64, u64) = f
            .store
            .db
            .query_row("SELECT rows,allocated FROM inbox_host_meta", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(rows, 1);
        assert!(bytes < 30000);
        assert!(
            !f.store.host_sequence_closed(NS, &f.options, 1).unwrap(),
            "compacting attempts cannot close live delivery"
        );
    }
    f.store
        .host_finish(
            &f.identity,
            NS,
            &f.options,
            &first,
            HostOutcome::HostAccepted {
                receipt: "obsolete-late".into(),
            },
        )
        .unwrap();
    assert_eq!(
        f.store
            .host_call(&f.identity, &current.call_id)
            .unwrap()
            .state,
        "CALL_OPEN"
    );
    let report = f
        .store
        .pending_host_report(&f.identity, NS, &f.options)
        .unwrap()
        .unwrap();
    assert!(
        report.2["scope"].get("attempt").is_none(),
        "public service scope retains the existing schema"
    );
    assert_eq!(report.2["attempt"], 81);
}
#[test]
fn a_full_legacy_ledger_compacts_before_admission_without_replacing_original_calls() {
    let mut f = Fixture::new();
    let first = f.begin();
    f.finish(
        &first,
        HostOutcome::HostAccepted {
            receipt: "old-host".into(),
        },
    );
    let mut allocated = 0usize;
    let mut count = 0u64;
    let tx = f.store.db.unchecked_transaction().unwrap();
    tx.execute("DELETE FROM inbox_host_facts", []).unwrap();
    tx.execute("DELETE FROM inbox_host_calls", []).unwrap();
    tx.execute("DELETE FROM inbox_host_payloads", []).unwrap();
    loop {
        let id = if count == 0 {
            first.call_id.clone()
        } else {
            format!("{count:043}")
        };
        let mut scope = first.scope.clone();
        scope.as_object_mut().unwrap().remove("attempt");
        scope["call_id"] = json!(id);
        let aad = scope.to_string();
        let frame = seal_bounded(&f.identity, &aad, &first.frame.to_string(), 65536).unwrap();
        let allocation = frame.len() + aad.len() + 32768;
        if allocated + allocation > 32 * 1024 * 1024 {
            break;
        }
        let outcome = seal_bounded(
            &f.identity,
            &format!("{aad}:OUTCOME"),
            &json!({"state":"HOST_ACCEPTED","receipt":"old-host"}).to_string(),
            4096,
        )
        .unwrap();
        tx.execute("INSERT INTO inbox_host_calls(call_id,workspace,mailbox,sequence,delivery_id,host,attempt,scope,frame_digest,frame,state,outcome,allocation,report_version,report_pending,delivery_state,storage_version) VALUES(?1,?2,?3,1,?4,?5,?6,?7,?8,?9,'HOST_ACCEPTED',?10,?11,2,0,'SUPERSEDED',0)",params![id,f.options.workspace_id,f.options.mailbox_id,f.items[0].delivery_id,f.options.host_destination,count+1,aad,first.frame_digest,frame,outcome,allocation]).unwrap();
        allocated += allocation;
        count += 1;
    }
    tx.execute(
        "UPDATE inbox_host_meta SET allocated=?1,rows=?2",
        params![allocated, count],
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(32 * 1024 * 1024 - allocated < 40000);
    let next = f
        .store
        .host_begin(
            &f.identity,
            NS,
            &f.options,
            &f.items[1],
            json!({"message_id":"after-upgrade","rendered_text":"new message"}),
        )
        .unwrap()
        .unwrap();
    assert_eq!(next.attempt, 1);
    let after: u64 = f
        .store
        .db
        .query_row("SELECT allocated FROM inbox_host_meta", [], |r| r.get(0))
        .unwrap();
    assert!(after + 500000 < allocated as u64);
    assert_eq!(
        f.store
            .host_call(&f.identity, &first.call_id)
            .unwrap()
            .state,
        "HOST_ACCEPTED"
    );
    let remaining: u64 = f
        .store
        .db
        .query_row(
            "SELECT count(*) FROM inbox_host_calls WHERE storage_version=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining,
        count - 32,
        "upgrade yields after one bounded authenticated page"
    );
}
#[test]
fn legacy_payload_compaction_refuses_invalid_ciphertext_without_deleting_evidence() {
    let mut f = Fixture::new();
    let first = f.begin();
    f.finish(
        &first,
        HostOutcome::Unknown {
            code: "HOST_ACK_UNKNOWN".into(),
        },
    );
    let mut sealed = seal_bounded(
        &f.identity,
        &first.scope.to_string(),
        &first.frame.to_string(),
        65536,
    )
    .unwrap();
    sealed[15] ^= 1;
    f.store.db.execute("UPDATE inbox_host_calls SET frame=?2,payload_key=NULL,storage_version=0 WHERE call_id=?1",params![first.call_id,sealed]).unwrap();
    assert_eq!(
        f.store
            .host_compact_page(&f.identity, NS, &f.options)
            .unwrap_err()
            .code,
        "INBOX_STATE_INVALID"
    );
    let unchanged: Vec<u8> = f
        .store
        .db
        .query_row(
            "SELECT frame FROM inbox_host_calls WHERE call_id=?1",
            [&first.call_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unchanged, sealed);
}
