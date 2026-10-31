//! Service-confirmed application consumption and exact confirmed host facts
//! authorize bounded local retirement. Unknown/queued calls are never collected.
use super::*;
impl InboxStore {
    pub(super) fn host_retired(
        &self,
        options: &WatchOptions,
        host: &str,
    ) -> Result<(u64, u64, bool)> {
        let row:Option<(String,u64,u64,bool)>=self.db.query_row("SELECT host,through_sequence,lane_after,lane_pending FROM inbox_host_retired_v2 WHERE workspace=?1 AND mailbox=?2 AND host=?3",params![options.workspace_id,options.mailbox_id,host],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(db_error)?;
        if let Some((saved, through, after, pending)) = row {
            if saved != host {
                return Err(failure("HOST_RETIREMENT_SCOPE_MISMATCH"));
            }
            Ok((through, after, pending))
        } else {
            Ok((0, 0, false))
        }
    }
    fn host_consumed_frontier(&self, options: &WatchOptions) -> Result<u64> {
        let cursor = self
            .pins(&options.workspace_id, &options.mailbox_id)?
            .ok_or_else(invalid)?
            .after_sequence;
        let first:Option<u64>=self.db.query_row("SELECT sequence FROM inbox_items WHERE workspace=?1 AND mailbox=?2 ORDER BY sequence LIMIT 1",params![options.workspace_id,options.mailbox_id],|r|r.get(0)).optional().map_err(db_error)?;
        Ok(first.map_or(cursor, |n| cursor.min(n.saturating_sub(1))))
    }
    pub fn host_retirement_plan(
        &self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
    ) -> Result<Option<Value>> {
        self.host_evidence_scope(namespace,options)?;
        let host=options.host_destination.as_deref().ok_or_else(invalid)?.to_owned();
        let through = self.host_consumed_frontier(options)?;
        let previous = self.host_retired(options, &host)?;
        if through < previous.0 {
            return Err(failure("HOST_RETIREMENT_FRONTIER_REGRESSED"));
        }
        let mut calls = Vec::new();
        for state in ["HOST_ACCEPTED", "NOT_SENT"] {
            let ids=self.db.prepare("SELECT call_id FROM inbox_host_calls INDEXED BY inbox_host_gc_binding WHERE workspace=?1 AND mailbox=?2 AND report_pending=0 AND state=?3 AND sequence<=?4 AND host=?5 ORDER BY sequence,call_id LIMIT 32").map_err(db_error)?.query_map(params![options.workspace_id,options.mailbox_id,state,through,host],|r|r.get::<_,String>(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
            for id in ids {
                let call = self.host_call(identity, &id)?;
                if call.scope["namespace"] != namespace
                    || call.scope["membership_id"] != options.membership_id
                    || call.scope["destination_digest"] != host
                    || call.state != state
                {
                    return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
                }
                calls.push(json!({"call_id":id,"sequence":call.scope["sequence"],"frame_digest":call.frame_digest,"state":call.state,"outcome_digest":sha256_hex(call.outcome.as_ref().ok_or_else(invalid)?.to_string().as_bytes()),"report_version":call.report_version}));
            }
        }
        calls.sort_by(|a, b| {
            (&a["sequence"].as_u64(), a["call_id"].as_str())
                .cmp(&(&b["sequence"].as_u64(), b["call_id"].as_str()))
        });
        calls.truncate(32);
        if through == 0 || (through == previous.0 && calls.is_empty() && !previous.2) {
            return Ok(None);
        }
        Ok(Some(
            json!({"binding":self.host_access_scope(namespace,options)?,"through_sequence":through,"calls":calls}),
        ))
    }
    pub fn host_retirement_commit(
        &mut self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
        plan: &Value,
    ) -> Result<()> {
        self.host_evidence_scope(namespace,options)?;
        let host=options.host_destination.as_deref().ok_or_else(invalid)?.to_owned();
        if plan["binding"] != self.host_access_scope(namespace, options)? {
            return Err(failure("HOST_RETIREMENT_SCOPE_MISMATCH"));
        }
        let through = plan["through_sequence"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 9_007_199_254_740_991)
            .ok_or_else(invalid)?;
        if through > self.host_consumed_frontier(options)? {
            return Err(failure("HOST_RETIREMENT_NOT_CONSUMED"));
        }
        let previous = self.host_retired(options, &host)?;
        let calls = plan["calls"]
            .as_array()
            .filter(|v| v.len() <= 32)
            .ok_or_else(invalid)?;
        let mut selected = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for entry in calls {
            let id = entry["call_id"].as_str().ok_or_else(invalid)?;
            let sequence = entry["sequence"]
                .as_u64()
                .filter(|n| *n > 0 && *n <= through)
                .ok_or_else(invalid)?;
            if !ids.insert(id) {
                return Err(invalid());
            }
            let row:Option<(u64,u64,bool)>=self.db.query_row("SELECT allocation,report_version,report_pending=0 FROM inbox_host_calls WHERE call_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
            let Some((allocation, version, reported)) = row else {
                if sequence > previous.0 {
                    return Err(failure("HOST_RETIREMENT_NOT_FOUND"));
                }
                continue;
            };
            let call = self.host_call(identity, id)?;
            if !reported
                || entry["report_version"] != version
                || call.report_version != version
                || call.scope["sequence"] != sequence
                || call.scope["namespace"] != namespace
                || call.scope["workspace_id"] != options.workspace_id
                || call.scope["mailbox_id"] != options.mailbox_id
                || call.scope["membership_id"] != options.membership_id
                || call.scope["destination_digest"] != host
                || call.frame_digest != entry["frame_digest"]
                || call.state != entry["state"]
                || !matches!(call.state.as_str(), "HOST_ACCEPTED" | "NOT_SENT")
                || sha256_hex(
                    call.outcome
                        .as_ref()
                        .ok_or_else(invalid)?
                        .to_string()
                        .as_bytes(),
                ) != entry["outcome_digest"]
            {
                return Err(failure("HOST_RETIREMENT_CONFLICT"));
            }
            selected.push((id.to_owned(), allocation, sequence));
        }
        let tx = self.db.unchecked_transaction().map_err(db_error)?;
        tx.execute("INSERT INTO inbox_host_retired_v2 VALUES(?1,?2,?3,?4,0,1) ON CONFLICT(workspace,mailbox,host) DO UPDATE SET through_sequence=max(through_sequence,excluded.through_sequence),lane_pending=1",params![options.workspace_id,options.mailbox_id,host,through]).map_err(db_error)?;
        for (id, allocation, _) in &selected {
            tx.execute("DELETE FROM inbox_host_facts WHERE call_id=?1", [id])
                .map_err(db_error)?;
            tx.execute("DELETE FROM inbox_host_calls WHERE call_id=?1", [id])
                .map_err(db_error)?;
            tx.execute(
                "UPDATE inbox_host_meta SET allocated=allocated-?1,rows=rows-1 WHERE id=1",
                [allocation],
            )
            .map_err(db_error)?;
        }
        let sequences = selected
            .iter()
            .map(|v| v.2)
            .collect::<std::collections::BTreeSet<_>>();
        for sequence in sequences {
            let live:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND sequence=?3)",params![options.workspace_id,options.mailbox_id,sequence],|r|r.get(0)).map_err(db_error)?;
            if !live {
                tx.execute("DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence]).map_err(db_error)?;
                tx.execute("DELETE FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence]).map_err(db_error)?;
            }
        }
        // A persisted keyset cursor bounds projection cleanup even if retained
        // unknown/queued lanes occupy a long prefix. Never remove their guards.
        let rows=tx.prepare("SELECT sequence FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence>?3 AND sequence<=?4 ORDER BY sequence LIMIT 32").map_err(db_error)?.query_map(params![options.workspace_id,options.mailbox_id,previous.1,through.max(previous.0)],|r|r.get::<_,u64>(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        for sequence in &rows {
            let live:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND sequence=?3)",params![options.workspace_id,options.mailbox_id,sequence],|r|r.get(0)).map_err(db_error)?;
            if !live {
                tx.execute("DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence]).map_err(db_error)?;
                tx.execute("DELETE FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![options.workspace_id,options.mailbox_id,sequence]).map_err(db_error)?;
            }
        }
        tx.execute("UPDATE inbox_host_retired_v2 SET lane_after=?3,lane_pending=?4 WHERE workspace=?1 AND mailbox=?2 AND host=?5",params![options.workspace_id,options.mailbox_id,rows.last().copied().filter(|_|rows.len()==32).unwrap_or(0),if rows.len()==32{1}else{0},host]).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumed_confirmed_calls_retire_in_bounded_pages_but_uncertainty_and_late_facts_survive() {
        let directory = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&directory.path().join("identity")).unwrap();
        let path = directory.path().join("inbox");
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        let host=HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"gc-thread","session_id":"gc-session"})).unwrap();
        let options = WatchOptions {
            workspace_id: "W".repeat(43),
            mailbox_id: "M".repeat(43),
            membership_id: "G".repeat(43),
            consumer_id: "gc-program".into(),
            host_destination: Some(host.digest.clone()),
        };
        let namespace = "program:gc";
        let binding = store.attach_watch(&identity, namespace, &options).unwrap();
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
        store.host_attach(namespace, &options, &host).unwrap();
        let mut references = Vec::new();
        let mut originals = Vec::new();
        for sequence in 1..=75 {
            let id = format!("{sequence:043}");
            let envelope = json!({"sequence":sequence,"delivery_id":id,"kind":"BUSINESS","business":{"instance_id":format!("instance-{sequence}")}});
            let wire = json!({"items":[envelope]}).to_string();
            let digest = sha256_hex(wire.as_bytes());
            let sealed = seal_bounded(
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
                        sealed,
                        wire.len()
                    ],
                )
                .unwrap();
            store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,?6,'PENDING')",params![options.workspace_id,options.mailbox_id,sequence,id,digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
            store
                .db
                .execute(
                    "INSERT INTO inbox_item_lanes VALUES(?1,?2,?3,?4)",
                    params![
                        options.workspace_id,
                        options.mailbox_id,
                        sequence,
                        format!("lane-{sequence}")
                    ],
                )
                .unwrap();
            store
                .db
                .execute("UPDATE inbox_mailboxes SET item_cursor=?1", [sequence])
                .unwrap();
            store
                .db
                .execute(
                    "UPDATE inbox_meta SET allocated=allocated+?1,rows=rows+1",
                    [wire.len()],
                )
                .unwrap();
            let item = DeliveryReference {
                sequence,
                delivery_id: id,
            };
            assert!(store
                .host_due(namespace, &options, 32)
                .unwrap()
                .iter()
                .any(|v| v.sequence == sequence));
            if sequence == 75 {
                store
                    .consume(
                        &options.workspace_id,
                        &options.mailbox_id,
                        &[(sequence, item.delivery_id.clone())],
                    )
                    .unwrap();
                assert!(store.host_begin(&identity,namespace,&options,&item,json!({})).unwrap().is_none(),"consumption between selection and begin cancels input without failing the dispatcher");
                assert!(!store
                    .host_due(namespace, &options, 32)
                    .unwrap()
                    .iter()
                    .any(|v| v.sequence == sequence));
                references.push(item);
                continue;
            }
            let call=store.host_begin(&identity,namespace,&options,&item,json!({"message_id":format!("message-{sequence}"),"rendered_text":"private_gc_fixture"})).unwrap().unwrap();
            let outcome = match sequence {
                71 => HostOutcome::Unknown {
                    code: "HOST_ACK_UNKNOWN".into(),
                },
                72 => HostOutcome::HostQueued {
                    receipt: "queue".into(),
                },
                74 => HostOutcome::NotSent {
                    code: "HOST_NOT_READY".into(),
                    proof: "LOCAL_PREFLIGHT_NO_IO".into(),
                },
                _ => HostOutcome::HostAccepted {
                    receipt: format!("turn-{sequence}"),
                },
            };
            store
                .host_finish(&identity, namespace, &options, &call, outcome)
                .unwrap();
            let current = store.host_call(&identity, &call.call_id).unwrap();
            if sequence == 73 {
                store
                    .host_report_failed(
                        &options.workspace_id,
                        &options.mailbox_id,
                        &call.call_id,
                        current.report_version,
                        "HOST_EVIDENCE_CONFLICT",
                    )
                    .unwrap();
            } else {
                store
                    .host_reported(
                        &options.workspace_id,
                        &options.mailbox_id,
                        &call.call_id,
                        current.report_version,
                    )
                    .unwrap();
            }
            originals.push(call);
            references.push(item);
        }
        assert!(store
            .host_retirement_plan(&identity, namespace, &options)
            .unwrap()
            .is_none());
        for items in references.chunks(32) {
            let items = items
                .iter()
                .map(|v| (v.sequence, v.delivery_id.clone()))
                .collect::<Vec<_>>();
            let before = store.host_consumed_frontier(&options).unwrap();
            store
                .consume(&options.workspace_id, &options.mailbox_id, &items)
                .unwrap();
            assert_eq!(
                store.host_consumed_frontier(&options).unwrap(),
                before,
                "local consumption request alone cannot authorize retirement"
            );
            store
                .acknowledged(&options.workspace_id, &options.mailbox_id, &items, false)
                .unwrap();
            store
                .acknowledged(&options.workspace_id, &options.mailbox_id, &items, true)
                .unwrap();
        }
        let first = store
            .host_retirement_plan(&identity, namespace, &options)
            .unwrap()
            .unwrap();
        assert_eq!(first["calls"].as_array().unwrap().len(), 32);
        let mut wrong = first.clone();
        wrong["binding"]["namespace"] = json!("other");
        assert_eq!(
            store
                .host_retirement_commit(&identity, namespace, &options, &wrong)
                .unwrap_err()
                .code,
            "HOST_RETIREMENT_SCOPE_MISMATCH"
        );
        let first_id = first["calls"][0]["call_id"].as_str().unwrap();
        store
            .db
            .execute(
                "UPDATE inbox_host_calls SET report_pending=1 WHERE call_id=?1",
                [first_id],
            )
            .unwrap();
        assert_eq!(
            store
                .host_retirement_commit(&identity, namespace, &options, &first)
                .unwrap_err()
                .code,
            "HOST_RETIREMENT_CONFLICT"
        );
        assert_eq!(store.host_retired(&options, &host.digest).unwrap().0, 0);
        store
            .host_reported(&options.workspace_id, &options.mailbox_id, first_id, 2)
            .unwrap();
        store
            .host_retirement_commit(&identity, namespace, &options, &first)
            .unwrap();
        drop(store);
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        store
            .host_retirement_commit(&identity, namespace, &options, &first)
            .unwrap();
        for _ in 0..8 {
            let Some(plan) = store
                .host_retirement_plan(&identity, namespace, &options)
                .unwrap()
            else {
                break;
            };
            assert!(plan["calls"].as_array().unwrap().len() <= 32);
            store
                .host_retirement_commit(&identity, namespace, &options, &plan)
                .unwrap();
        }
        assert!(store
            .host_retirement_plan(&identity, namespace, &options)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .db
                .query_row("SELECT rows FROM inbox_host_meta", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            store
                .host_status(&identity, namespace, &options, &references[0])
                .unwrap()["host"],
            "LOCAL_EVIDENCE_RETIRED"
        );
        assert!(store
            .host_begin(&identity, namespace, &options, &references[0], json!({}))
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .db
                .query_row("SELECT count(*) FROM inbox_item_lanes", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .host_status(&identity, namespace, &options, &references[70])
                .unwrap()["host"],
            "RESULT_UNKNOWN"
        );
        assert_eq!(
            store
                .host_status(&identity, namespace, &options, &references[71])
                .unwrap()["host"],
            "HOST_QUEUED"
        );
        assert_eq!(
            store
                .host_status(&identity, namespace, &options, &references[72])
                .unwrap()["reporting"],
            "BLOCKED"
        );
        // A late acceptance after a retirement frontier remains verifiable and
        // uploads before this call can become eligible for physical collection.
        store
            .host_finish(
                &identity,
                namespace,
                &options,
                &originals[71],
                HostOutcome::HostAccepted {
                    receipt: "late-turn".into(),
                },
            )
            .unwrap();
        assert!(store
            .host_retirement_plan(&identity, namespace, &options)
            .unwrap()
            .is_none());
        let late = store.host_call(&identity, &originals[71].call_id).unwrap();
        store
            .host_reported(
                &options.workspace_id,
                &options.mailbox_id,
                &late.call_id,
                late.report_version,
            )
            .unwrap();
        let plan = store
            .host_retirement_plan(&identity, namespace, &options)
            .unwrap()
            .unwrap();
        assert_eq!(plan["calls"].as_array().unwrap().len(), 1);
        store
            .host_retirement_commit(&identity, namespace, &options, &plan)
            .unwrap();
        assert_eq!(
            store
                .db
                .query_row("SELECT rows FROM inbox_host_meta", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            2
        );
    }
}
