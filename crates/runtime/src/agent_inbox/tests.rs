use super::*;
fn binding() -> InboxBinding {
    InboxBinding {
        service: "service-a".into(),
        principal: "actor-a".into(),
        workspace: "space-a".into(),
        source: "journal-events-v1".into(),
        context_fingerprint: "trust-device-history-v1".into(),
    }
}
fn event(id: &str) -> InboxSourceEvent {
    InboxSourceEvent {
        event_id: id.into(),
        version: "1".into(),
        authoritative_hash: format!("commit-{id}"),
        payload: id.as_bytes().to_vec(),
    }
}
fn batch(prior: Option<&str>, next: &str, ids: &[&str]) -> VerifiedInboxBatch {
    VerifiedInboxBatch {
        prior_cursor: prior.map(str::to_owned),
        next_cursor: next.into(),
        events: ids.iter().map(|s| event(s)).collect(),
    }
}
#[test]
fn restart_competing_connections_fanout_and_stale_ack() {
    let dir = crate::test_support::protected_test_dir();
    let path = dir.path().join("inbox.sqlite");
    let mut a = AgentInbox::open(&path, &binding(), InboxLimits::default()).unwrap();
    let mut b = AgentInbox::open(&path, &binding(), InboxLimits::default()).unwrap();
    a.ingest_verified(batch(None, "c1", &["a", "b"])).unwrap();
    a.register_consumer("worker", "v1").unwrap();
    b.register_consumer("observer", "v1").unwrap();
    let cancel = CancellationToken::new();
    {
        let tx =
            b.db.transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
        assert!(matches!(
            a.receive_at("worker", "v1", 100, &cancel, 999),
            Err(InboxError::Busy)
        ));
        drop(tx);
    }
    let first = a
        .receive_at("worker", "v1", 100, &cancel, 1000)
        .unwrap()
        .unwrap();
    assert!(b
        .receive_at("worker", "v1", 100, &cancel, 1001)
        .unwrap()
        .is_none());
    let other = b
        .receive_at("observer", "v1", 100, &cancel, 1001)
        .unwrap()
        .unwrap();
    assert_eq!(first.event_id, other.event_id);
    drop(a);
    let mut a = AgentInbox::open(&path, &binding(), InboxLimits::default()).unwrap();
    assert!(matches!(
        a.ack_at("worker", "v1", &first.ack_token, 1100),
        Err(InboxError::StaleLease)
    ));
    let retry = a
        .receive_at("worker", "v1", 100, &cancel, 1100)
        .unwrap()
        .unwrap();
    assert_eq!(retry.event_id, first.event_id);
    assert_ne!(retry.ack_token, first.ack_token);
    assert!(matches!(
        b.ack_at("worker", "v1", &first.ack_token, 1101),
        Err(InboxError::StaleLease)
    ));
    b.ack_at("worker", "v1", &retry.ack_token, 1101).unwrap();
    assert_eq!(a.consumer_status("worker", "v1").unwrap().pending_events, 1);
    assert_eq!(
        a.consumer_status("observer", "v1").unwrap().pending_events,
        2
    );
    assert_eq!(
        a.receive_at("worker", "v1", 100, &cancel, 1102)
            .unwrap()
            .unwrap()
            .event_id,
        "b"
    );
}
#[test]
fn atomic_backpressure_duplicates_conflicts_and_cursor_cas() {
    let dir = crate::test_support::protected_test_dir();
    let path = dir.path().join("inbox.sqlite");
    let mut store = AgentInbox::open(
        &path,
        &binding(),
        InboxLimits {
            max_events: 2,
            ..InboxLimits::default()
        },
    )
    .unwrap();
    store.ingest_verified(batch(None, "c1", &["a"])).unwrap();
    store.ingest_verified(batch(None, "c1", &["a"])).unwrap();
    assert_eq!(store.status().unwrap().retained_events, 1);
    assert!(matches!(
        store.ingest_verified(batch(Some("c1"), "c2", &["b", "c"])),
        Err(InboxError::Backpressure)
    ));
    let status = store.status().unwrap();
    assert_eq!(status.verified_cursor.as_deref(), Some("c1"));
    assert_eq!(status.retained_events, 1);
    let mut conflict = batch(Some("c1"), "c2", &["b", "a"]);
    conflict.events[1].payload = b"changed".to_vec();
    assert!(matches!(
        store.ingest_verified(conflict),
        Err(InboxError::EventConflict)
    ));
    assert_eq!(store.status().unwrap().retained_events, 1);
    assert!(matches!(
        store.ingest_verified(batch(None, "stale", &[])),
        Err(InboxError::CursorConflict)
    ));
    store
        .ingest_verified(batch(Some("c1"), "c2", &["a", "b"]))
        .unwrap();
    assert_eq!(store.status().unwrap().retained_events, 2);
}
#[test]
fn wrong_context_cancel_empty_and_gap_do_not_advance() {
    let dir = crate::test_support::protected_test_dir();
    let path = dir.path().join("inbox.sqlite");
    let mut store = AgentInbox::open(&path, &binding(), InboxLimits::default()).unwrap();
    let mut wrong = binding();
    wrong.context_fingerprint = "different-device".into();
    assert!(matches!(
        AgentInbox::open(&path, &wrong, InboxLimits::default()),
        Err(InboxError::ContextMismatch)
    ));
    store.register_consumer("c", "v1").unwrap();
    let cancel = CancellationToken::new();
    assert!(store
        .receive_at("c", "v1", 10, &cancel, 0)
        .unwrap()
        .is_none());
    cancel.cancel();
    assert!(matches!(
        store.receive_at("c", "v1", 10, &cancel, 0),
        Err(InboxError::Cancelled)
    ));
    assert_eq!(
        store
            .consumer_status("c", "v1")
            .unwrap()
            .acknowledged_position,
        0
    );
    store.ingest_verified(batch(None, "c1", &["a"])).unwrap();
    let lease = store
        .receive_at("c", "v1", 100, &CancellationToken::new(), 100)
        .unwrap()
        .unwrap();
    store.report_gap().unwrap();
    assert!(matches!(
        store.ack_at("c", "v1", &lease.ack_token, 101),
        Err(InboxError::Gap)
    ));
    assert!(matches!(
        store.ingest_verified(batch(Some("c1"), "c2", &[])),
        Err(InboxError::Gap)
    ));
    assert_eq!(
        store.status().unwrap().enqueued_cursor.as_deref(),
        Some("c1")
    );
}
#[test]
fn refuses_permissive_symlink_hardlink_and_sidecar() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = crate::test_support::protected_test_dir();
    let path = dir.path().join("inbox.sqlite");
    let store = AgentInbox::open(&path, &binding(), InboxLimits::default()).unwrap();
    drop(store);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        AgentInbox::open(&path, &binding(), InboxLimits::default()),
        Err(InboxError::Protection)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(matches!(
        AgentInbox::open(&link, &binding(), InboxLimits::default()),
        Err(InboxError::Protection)
    ));
    fs::remove_file(&link).unwrap();
    fs::hard_link(&path, &link).unwrap();
    assert!(matches!(
        AgentInbox::open(&path, &binding(), InboxLimits::default()),
        Err(InboxError::Protection)
    ));
    fs::remove_file(&link).unwrap();
    symlink(&path, dir.path().join("inbox.sqlite-journal")).unwrap();
    assert!(matches!(
        AgentInbox::open(&path, &binding(), InboxLimits::default()),
        Err(InboxError::Protection)
    ));
}
