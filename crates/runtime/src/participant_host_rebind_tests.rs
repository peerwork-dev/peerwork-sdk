use super::*;
use crate::{kernel_identity::KernelIdentity, secure_state::create_private_state_directory};

fn setup(
    count: u64,
    distinct_second: bool,
) -> (
    crate::test_support::ProtectedTestDir,
    KernelIdentity,
    InboxStore,
    HostRebind,
    HostCall,
) {
    let root = crate::test_support::protected_test_dir();
    let identity = KernelIdentity::create(&root.path().join("identity")).unwrap();
    let dir = root.path().join("inbox");
    create_private_state_directory(&dir).unwrap();
    let mut store = InboxStore::open_local(&dir, &identity, "https://example.invalid/").unwrap();
    let old_host = HostBinding::new(
        json!({"host":"CODEX_APP_SERVER","session_id":"original","conversation_id":"original"}),
    )
    .unwrap();
    let host=HostBinding::new(json!({"host":"CODEX_APP_SERVER","session_id":"selected-new","conversation_id":"selected-new"})).unwrap();
    let old = WatchOptions {
        workspace_id: "w".repeat(43),
        mailbox_id: "m".repeat(43),
        membership_id: "g".repeat(43),
        consumer_id: "worker".into(),
        host_destination: Some(old_host.digest.clone()),
    };
    let namespace = "program:worker";
    let binding = store.attach_watch(&identity, namespace, &old).unwrap();
    let expected = MailboxPins {
        workspace_id: old.workspace_id.clone(),
        mailbox_id: old.mailbox_id.clone(),
        membership_id: old.membership_id.clone(),
        receiver_id: binding.receiver,
        epoch: 1,
        destination_digest: old_host.digest.clone(),
        binding_version: 1,
        after_sequence: 0,
        after_control_sequence: Some(0),
    };
    store.register(&expected).unwrap();
    store.host_attach(namespace, &old, &old_host).unwrap();
    for sequence in 1..=count {
        let envelope = json!({"sequence":sequence,"delivery_id":format!("{sequence:043}"),"kind":"BUSINESS","business":{"instance_id":"synthetic"}});
        let wire = json!({"items":[envelope]}).to_string();
        let digest = sha256_hex(wire.as_bytes());
        let encrypted = seal_bounded(
            &identity,
            &store.aad(&old.workspace_id, &old.mailbox_id, &digest),
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
                    old.workspace_id,
                    old.mailbox_id,
                    encrypted,
                    wire.len()
                ],
            )
            .unwrap();
        store.db.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,?6,'PENDING')",params![old.workspace_id,old.mailbox_id,sequence,format!("{sequence:043}"),digest,sha256_hex(envelope.to_string().as_bytes())]).unwrap();
        store
            .db
            .execute(
                "INSERT INTO inbox_item_lanes VALUES(?1,?2,?3,?4)",
                params![
                    old.workspace_id,
                    old.mailbox_id,
                    sequence,
                    if distinct_second && sequence == 2 {
                        "other-conversation"
                    } else {
                        "same-conversation"
                    }
                ],
            )
            .unwrap();
    }
    store
        .db
        .execute("UPDATE inbox_mailboxes SET item_cursor=?1", [count])
        .unwrap();
    for _ in 0..=(count / 32) {
        store.host_due(namespace, &old, 32).unwrap();
    }
    let item = DeliveryReference {
        sequence: 1,
        delivery_id: format!("{:043}", 1),
    };
    let call = store
        .host_begin(
            &identity,
            namespace,
            &old,
            &item,
            json!({"message_id":"old-original-input","text":"PRIVATE-ORIGINAL-HOST-FRAME"}),
        )
        .unwrap()
        .unwrap();
    store
        .host_finish(
            &identity,
            namespace,
            &old,
            &call,
            HostOutcome::Unknown {
                code: "HOST_ACK_UNKNOWN".into(),
            },
        )
        .unwrap();
    let expected = store
        .pins(&old.workspace_id, &old.mailbox_id)
        .unwrap()
        .unwrap();
    let mut confirmed = expected.clone();
    confirmed.epoch += 1;
    confirmed.binding_version += 1;
    confirmed.destination_digest = host.digest.clone();
    let mut new = old.clone();
    new.host_destination = Some(host.digest.clone());
    let selection = HostRebind {
        operation_id: "o".repeat(43),
        namespace: namespace.into(),
        old,
        new,
        expected,
        confirmed,
        host,
    };
    (root, identity, store, selection, call)
}
fn ready(store: &mut InboxStore, s: &HostRebind, call: &HostCall) {
    store.disable_watch(&s.namespace, &s.old).unwrap();
    let call = store.host_call_for_test(call);
    store
        .host_reported(
            &s.old.workspace_id,
            &s.old.mailbox_id,
            &call.call_id,
            call.report_version,
        )
        .unwrap();
}
impl InboxStore {
    fn host_call_for_test(&self, call: &HostCall) -> HostCall {
        let mut call = call.clone();
        call.report_version = self
            .db
            .query_row(
                "SELECT report_version FROM inbox_host_calls WHERE call_id=?1",
                [&call.call_id],
                |r| r.get(0),
            )
            .unwrap();
        call
    }
}
#[test]
fn rebind_preserves_original_unknown_keys_cursors_and_unblocks_only_the_new_lane() {
    let (_root, identity, mut store, s, call) = setup(70, false);
    assert_eq!(
        store.host_rebind_commit(&s).unwrap_err().code,
        "HOST_REBIND_STOP_DISPATCHER_FIRST"
    );
    store.disable_watch(&s.namespace, &s.old).unwrap();
    assert_eq!(
        store.host_rebind_commit(&s).unwrap_err().code,
        "HOST_REBIND_FLUSH_ORIGINAL_REPORTS_FIRST"
    );
    ready(&mut store, &s, &call);
    let key: Vec<u8> = store
        .db
        .query_row("SELECT sealed FROM inbox_receiver_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        store.host_rebind_commit(&s).unwrap()["state"],
        "LOCAL_REBIND_COMMITTED"
    );
    assert_eq!(
        store
            .pins(&s.old.workspace_id, &s.old.mailbox_id)
            .unwrap()
            .as_ref()
            .map(pins),
        Some(pins(&s.confirmed))
    );
    let after: Vec<u8> = store
        .db
        .query_row("SELECT sealed FROM inbox_receiver_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(after, key);
    assert!(store.attach_watch(&identity, &s.namespace, &s.old).is_err());
    let attached = store.attach_watch(&identity, &s.namespace, &s.new).unwrap();
    assert_eq!(attached.receiver, s.expected.receiver_id);
    assert!(attached.claim_wire.is_none());
    let original = store
        .host_original_call(&identity, &s.namespace, &s.new, &call.call_id)
        .unwrap();
    assert_eq!(original.state, "RESULT_UNKNOWN");
    assert_eq!(original.frame, call.frame);
    assert_eq!(original.scope["binding_version"], 1);
    let due = store.host_due(&s.namespace, &s.new, 32).unwrap();
    assert_eq!(due.first().unwrap().sequence, 2);
    assert_eq!(
        store
            .host_begin(
                &identity,
                &s.namespace,
                &s.new,
                &DeliveryReference {
                    sequence: 1,
                    delivery_id: format!("{:043}", 1)
                },
                json!({"message_id":"forbidden-retry"})
            )
            .unwrap_err()
            .code,
        "HOST_ORIGINAL_CALL_UNRESOLVED_OR_ACCEPTED"
    );
    let next = store
        .host_begin(
            &identity,
            &s.namespace,
            &s.new,
            &due[0],
            json!({"message_id":"new-input"}),
        )
        .unwrap()
        .unwrap();
    assert_eq!(next.scope["binding_version"], 2);
    store
        .host_finish(
            &identity,
            &s.namespace,
            &s.new,
            &next,
            HostOutcome::HostAccepted {
                receipt: "new-turn".into(),
            },
        )
        .unwrap();
    let n = store.host_call_for_test(&next);
    store
        .host_reported(
            &s.new.workspace_id,
            &s.new.mailbox_id,
            &n.call_id,
            n.report_version,
        )
        .unwrap();
    store
        .host_finish(
            &identity,
            &s.namespace,
            &s.old,
            &original,
            HostOutcome::HostAccepted {
                receipt: "late-original-turn".into(),
            },
        )
        .unwrap();
    let (_, _, report) = store
        .pending_host_report(&identity, &s.namespace, &s.new)
        .unwrap()
        .unwrap();
    assert_eq!(report["scope"], original.scope);
    assert_eq!(report["state"], "HOST_ACCEPTED");
    assert_eq!(
        store.host_call(&identity, &call.call_id).unwrap().scope,
        call.scope
    );
}
#[test]
fn interrupted_bounded_copy_reopens_fenced_and_same_operation_never_overwrites_later_writes() {
    for stage in ["FENCED", "PAGE", "COMMITTED"] {
        let (root, identity, mut store, s, call) = setup(70, false);
        ready(&mut store, &s, &call);
        let result = store.host_rebind_with_boundary(&s, |seen| {
            if seen == stage {
                Err(failure("INJECTED_INTERRUPTION"))
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err().code, "INJECTED_INTERRUPTION");
        drop(store);
        let mut store = InboxStore::open_local(
            &root.path().join("inbox"),
            &identity,
            "https://example.invalid/",
        )
        .unwrap();
        if stage != "COMMITTED" {
            assert_eq!(
                store
                    .attach_watch(&identity, &s.namespace, &s.old)
                    .err()
                    .unwrap()
                    .code,
                "HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"
            );
            assert_eq!(
                store
                    .attach_watch(&identity, &s.namespace, &s.new)
                    .err()
                    .unwrap()
                    .code,
                "HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"
            );
        }
        assert_eq!(
            store.host_rebind_commit(&s).unwrap()["state"],
            "LOCAL_REBIND_COMMITTED"
        );
        store
            .db
            .execute("UPDATE inbox_mailboxes SET item_cursor=99", [])
            .unwrap();
        assert_eq!(store.host_rebind_commit(&s).unwrap()["replayed"], true);
        assert_eq!(
            store
                .pins(&s.new.workspace_id, &s.new.mailbox_id)
                .unwrap()
                .unwrap()
                .after_sequence,
            99
        );
        let mut wrong = s.clone();
        wrong.operation_id = "x".repeat(43);
        assert_eq!(
            store.host_rebind_commit(&wrong).unwrap_err().code,
            "HOST_REBIND_ORIGINAL_SELECTION_REQUIRED"
        );
        let old = store
            .host_original_call(&identity, &s.namespace, &s.new, &call.call_id)
            .unwrap();
        assert_eq!(old.state, "RESULT_UNKNOWN");
        assert_eq!(old.frame, call.frame);
    }
}
#[test]
fn historical_negative_resolution_never_reinjects_the_old_input() {
    let (_root, identity, mut store, s, call) = setup(3, false);
    ready(&mut store, &s, &call);
    store.host_rebind_commit(&s).unwrap();
    let original = store
        .host_original_call(&identity, &s.namespace, &s.new, &call.call_id)
        .unwrap();
    store
        .host_finish(
            &identity,
            &s.namespace,
            &s.old,
            &original,
            HostOutcome::NotSent {
                code: "ORIGINAL_HOST_CONFIRMED_NOT_SENT".into(),
                proof: "BOUND_HOST_RECONCILIATION".into(),
            },
        )
        .unwrap();
    let due = store.host_due(&s.namespace, &s.new, 32).unwrap();
    assert_eq!(due.first().unwrap().sequence, 2);
    assert!(due.iter().all(|i| i.sequence != 1));
    let old = store
        .host_original_call(&identity, &s.namespace, &s.new, &call.call_id)
        .unwrap();
    assert_eq!(old.state, "NOT_SENT");
    let (_, _, report) = store
        .pending_host_report(&identity, &s.namespace, &s.new)
        .unwrap()
        .unwrap();
    assert_eq!(report["facts"].as_array().unwrap().len(), 2);
    assert_eq!(report["state"], "NOT_SENT");
    let mut foreign = s.new.clone();
    foreign.membership_id = "z".repeat(43);
    assert!(store
        .host_original_call(&identity, "other-namespace", &s.new, &call.call_id)
        .is_err());
    assert!(store
        .host_original_call(&identity, &s.namespace, &foreign, &call.call_id)
        .is_err());
}
#[test]
fn old_retirement_metadata_is_upgraded_once_and_scoped_to_each_physical_host() {
    let (root, identity, store, s, _call) = setup(2, false);
    store
        .db
        .execute(
            "INSERT INTO inbox_host_retired VALUES(?1,?2,?3,7,0,0)",
            params![
                s.old.workspace_id,
                s.old.mailbox_id,
                s.expected.destination_digest
            ],
        )
        .unwrap();
    store
        .db
        .execute_batch("DROP TABLE inbox_host_retired_v2")
        .unwrap();
    drop(store);
    let store = InboxStore::open_local(
        &root.path().join("inbox"),
        &identity,
        "https://example.invalid/",
    )
    .unwrap();
    assert_eq!(
        store
            .host_retired(&s.old, &s.expected.destination_digest)
            .unwrap()
            .0,
        7
    );
    assert_eq!(store.host_retired(&s.new, &s.host.digest).unwrap().0, 0);
    store
        .db
        .execute(
            "INSERT INTO inbox_host_retired_v2 VALUES(?1,?2,?3,9,0,0)",
            params![s.new.workspace_id, s.new.mailbox_id, s.host.digest],
        )
        .unwrap();
    drop(store);
    let store = InboxStore::open_local(
        &root.path().join("inbox"),
        &identity,
        "https://example.invalid/",
    )
    .unwrap();
    assert_eq!(
        store
            .host_retired(&s.old, &s.expected.destination_digest)
            .unwrap()
            .0,
        7
    );
    assert_eq!(store.host_retired(&s.new, &s.host.digest).unwrap().0, 9);
}

#[test]
fn rebind_drops_old_host_readiness_backoff_without_inventing_delivery_success() {
    let (_root, identity, mut store, s, call) = setup(3, true);
    let item = DeliveryReference {
        sequence: 2,
        delivery_id: format!("{:043}", 2),
    };
    store
        .host_defer(&s.namespace, &s.old, &item, "HOST_WAITING_APPROVAL")
        .unwrap();
    let previous: i64 = store
        .db
        .query_row(
            "SELECT next_retry FROM inbox_host_ready WHERE sequence=2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(previous > crate::participant_store::now());
    ready(&mut store, &s, &call);
    store.host_rebind_commit(&s).unwrap();
    assert!(store
        .host_due(&s.namespace, &s.new, 32)
        .unwrap()
        .iter()
        .any(|r| r.sequence == 2));
    let old = store
        .host_original_call(&identity, &s.namespace, &s.new, &call.call_id)
        .unwrap();
    assert_eq!(old.state, "RESULT_UNKNOWN");
    let second = store
        .host_status(&identity, &s.namespace, &s.new, &item)
        .unwrap();
    assert_eq!(second["host"], "NO_CONFIRMED_INVOCATION");
}
