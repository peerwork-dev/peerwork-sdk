use super::*;
use peerwork_core::replayed_secure_journal::{replay_secure_journal_exact, JournalReplayInput};

#[test]
fn real_signed_replay_receipt_retains_all_exact_effects() {
    // Real core signatures/PRIVATE replay, not a fake verifier. This qualifies
    // receipt projection only; transport-origin integration needs service tests.
    let f: Value = serde_json::from_str(include_str!(
        "../../../../conformance/signed-many-action-vectors.json"
    ))
    .unwrap();
    let policies = f["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::to_vec(v).unwrap())
        .collect::<Vec<_>>();
    let commits = f["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::to_vec(v).unwrap())
        .collect::<Vec<_>>();
    let pr = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let cr = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let cp = serde_json::to_vec(&f["checkpoint"]).unwrap();
    let keys = serde_json::to_vec(&f["keyring"]).unwrap();
    let replay = replay_secure_journal_exact(JournalReplayInput {
        policy_wires: &pr,
        commit_wires: &cr,
        checkpoint_wire: &cp,
        workspace_id: f["workspace_id"].as_str().unwrap(),
        owner_actor_id: f["owner"]["actor_id"].as_str().unwrap(),
        owner_signing_key: f["owner"]["key"].as_str().unwrap(),
        final_sequence: 2,
        final_head: f["checkpoint"]["head"].as_str(),
        final_policy_hash: f["checkpoint"]["policy_hash"].as_str().unwrap(),
        keyring_wire: Some(&keys),
    })
    .unwrap();
    let receipt = replay
        .action_receipt(f["receipt"]["command_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let event = receipt_event(receipt).unwrap();
    let decoded: Value = serde_json::from_slice(&event.payload).unwrap();
    assert_eq!(decoded, f["receipt"]);
    assert_eq!(decoded["effects"].as_array().unwrap().len(), 2);
    assert!(!replay.contains_checkpoint(2, Some("wrong-head"), replay.policy_hash()));
    let dir = crate::test_support::protected_test_dir();
    let opened = AgentInbox::open(
        &dir.path().join("events.sqlite"),
        &InboxBinding {
            service: "fixture-service".into(),
            principal: "fixture-principal".into(),
            workspace: replay.workspace_id().into(),
            source: SOURCE.into(),
            context_fingerprint: "fixture-transport-not-qualified".into(),
        },
        InboxLimits::default(),
    );
    if cfg!(not(unix)) {
        assert!(matches!(opened, Err(InboxError::Unsupported)));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        return;
    }
    let mut inbox = opened.unwrap();
    inbox
        .ingest_verified(VerifiedInboxBatch {
            prior_cursor: None,
            next_cursor: "2".into(),
            events: vec![event],
        })
        .unwrap();
    inbox.register_consumer("c", "v1").unwrap();
    let delivery = inbox
        .receive("c", "v1", 1000, &CancellationToken::new())
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&delivery.payload).unwrap(),
        f["receipt"]
    );
}
fn config(path: &std::path::Path) -> SecureReadProfileConfig {
    SecureReadProfileConfig {
        transport: Default::default(),
        origin: "https://invalid.example".into(),
        state_dir: path.to_owned(),
        identity_path: path.join("missing.identity"),
        workspace_id: "space".into(),
        owner_actor_id: None,
        owner_key_id: None,
        authority: None,
        required_features: vec![],
        allow_loopback_http: false,
        max_replay_artifact_bytes: 64 * 1024 * 1024,
        max_replay_commits: 102400,
    }
}
#[test]
fn invalid_or_cancelled_wait_has_no_profile_or_inbox_effect() {
    let dir = crate::test_support::protected_test_dir();
    let cfg = config(dir.path());
    let token = CancellationToken::new();
    assert_eq!(
        receive(cfg.clone(), "fp", "c", "v1", 1, 60001, &token)
            .unwrap_err()
            .code(),
        "INVALID_INPUT"
    );
    assert_eq!(
        ack(cfg.clone(), "fp", "c", "v1", "").unwrap_err().code(),
        "INVALID_INPUT"
    );
    token.cancel();
    assert_eq!(
        receive(cfg, "fp", "c", "v1", 1, 1, &token)
            .unwrap_err()
            .code(),
        "CANCELLED"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn local_delivery_ack_status_need_no_discovery_and_missing_store_is_noncreating() {
    let dir = crate::test_support::protected_test_dir();
    let mut cfg = config(dir.path());
    let network = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    network.set_nonblocking(true).unwrap();
    cfg.origin = format!("http://{}", network.local_addr().unwrap());
    cfg.allow_loopback_http = true;
    cfg.transport.request_timeout_ms = 100;
    cfg.owner_actor_id = Some("owner".into());
    cfg.owner_key_id = Some("owner-key".into());
    crate::kernel_identity::KernelIdentity::create(&cfg.identity_path).unwrap();
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(
        status(cfg.clone(), "fp").unwrap_err().code(),
        "INBOX_NOT_READY"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
    // Test-only source construction: production creation remains gated by
    // authenticated replay. Any network attempt remains visible in the local
    // listener backlog; it cannot receive a discovery response.
    let (binding, _, _) = local_binding(&cfg, "fp").unwrap();
    let opened = AgentInbox::open(
        &cfg.state_dir.join("agent-events.sqlite"),
        &binding,
        InboxLimits::default(),
    );
    if cfg!(not(unix)) {
        assert!(matches!(opened, Err(InboxError::Unsupported)));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
        assert!(!cfg.state_dir.join("agent-events.sqlite").exists());
        assert!(!cfg.state_dir.join("kernel.sqlite").exists());
        return;
    }
    let mut inbox = opened.unwrap();
    let wire = parse_wire_json_bounded(
        br#"{"commit_hash":"hash","command_id":"cmd","actor_id":"actor","effects":[]}"#,
        32,
        4096,
    )
    .unwrap();
    inbox
        .ingest_verified(VerifiedInboxBatch {
            prior_cursor: None,
            next_cursor: "1".into(),
            events: vec![receipt_event(&wire).unwrap()],
        })
        .unwrap();
    drop(inbox);
    let delivered = receive(
        cfg.clone(),
        "fp",
        "c",
        "v1",
        30000,
        5000,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(delivered["wait_status"], "delivered");
    let token = delivered["delivery"]["ack_token"].as_str().unwrap();
    assert_eq!(delivered["delivery"]["receipt"]["command_id"], "cmd");
    ack(cfg.clone(), "fp", "c", "v1", token).unwrap();
    assert_eq!(
        status(cfg.clone(), "fp").unwrap()["status"]["retained_events"],
        1
    );
    assert_eq!(
        status(cfg, "different-fp").unwrap_err().code(),
        "CONTEXT_MISMATCH"
    );
    assert_eq!(
        network.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "local delivery/status/ack attempted network access"
    );
    assert!(!dir.path().join("kernel.sqlite").exists());
}

#[test]
fn unchanged_checkpoint_probe_requires_exact_existing_identity_and_empty_page() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../conformance/signed-many-action-vectors.json"
    ))
    .unwrap();
    let mut cfg = config(std::path::Path::new("/unused"));
    cfg.workspace_id = fixture["workspace_id"].as_str().unwrap().into();
    cfg.owner_actor_id = Some(fixture["checkpoint"]["owner_id"].as_str().unwrap().into());
    cfg.owner_key_id = Some(fixture["checkpoint"]["owner_key"].as_str().unwrap().into());
    let cursor = Cursor {
        sequence: fixture["checkpoint"]["sequence"].as_u64().unwrap(),
        head: fixture["checkpoint"]["head"].as_str().map(str::to_owned),
        policy_hash: fixture["checkpoint"]["policy_hash"]
            .as_str()
            .unwrap()
            .into(),
    };
    let page = json!({"workspace_id":cfg.workspace_id,"state":"ACTIVE","visibility":"PRIVATE","checkpoint":fixture["checkpoint"],"policies":fixture["policies"],"commits":[],"next":null});
    let check = |v: &Value| {
        unchanged_probe_reply(&serde_json::to_vec(v).unwrap(), &cfg, &cursor, 1024 * 1024)
    };
    assert!(check(&page));
    for (field, value) in [
        ("head", json!("wrong")),
        ("sequence", json!(cursor.sequence + 1)),
        ("policy_hash", json!("different")),
        ("owner_id", json!("other-owner")),
        ("owner_key", json!("other-key")),
        ("workspace_id", json!("other-space")),
        ("v", json!(2)),
    ] {
        let mut changed = page.clone();
        changed["checkpoint"][field] = value;
        assert!(!check(&changed), "{field}");
    }
    for (field, value) in [
        ("workspace_id", json!("other-space")),
        ("state", json!("SEEDING")),
        ("visibility", json!("PUBLIC")),
        ("commits", json!([fixture["commits"][0]])),
        ("next", json!(cursor.sequence)),
        ("policies", json!([])),
    ] {
        let mut changed = page.clone();
        changed[field] = value;
        assert!(!check(&changed), "{field}");
    }
    let mut changed = page.clone();
    for policy in changed["policies"].as_array_mut().unwrap() {
        policy["signature"] = json!("tampered");
    }
    assert!(!check(&changed));
    assert!(!unchanged_probe_reply(b"not JSON", &cfg, &cursor, 1024));
    assert!(!unchanged_probe_reply(
        &serde_json::to_vec(&page).unwrap(),
        &cfg,
        &cursor,
        8
    ));
    assert_eq!(
        cursor.sequence,
        fixture["checkpoint"]["sequence"].as_u64().unwrap()
    );
}

#[test]
fn missing_inbox_probe_does_not_create_state_or_bootstrap_discovery() {
    let dir = crate::test_support::protected_test_dir();
    let mut cfg = config(dir.path());
    cfg.owner_actor_id = Some("owner".into());
    cfg.owner_key_id = Some("owner-key".into());
    crate::kernel_identity::KernelIdentity::create(&cfg.identity_path).unwrap();
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    assert!(try_unchanged_probe(&cfg, "fp", &CancellationToken::new())
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
    assert!(!cfg.state_dir.join("kernel.sqlite").exists());
}

#[test]
fn backlog_over_one_batch_resumes_without_skipping_receipts() {
    // Projection-only synthetic inputs: trust is separately covered by the real
    // signed receipt vector and core's authenticated checkpoint_at vectors.
    let dir = crate::test_support::protected_test_dir();
    let binding = InboxBinding {
        service: "s".into(),
        principal: "p".into(),
        workspace: "w".into(),
        source: SOURCE.into(),
        context_fingerprint: "fp".into(),
    };
    let mut after = 0;
    let mut prior = None;
    let mut batches = Vec::new();
    let mut collected = Vec::new();
    for expected_count in [256, 44] {
        let receipts = (1u64..=603).map(|seq| {
            let event = if seq % 2 == 0 && seq <= 600 {
                Some(InboxSourceEvent {
                    event_id: format!("event-{seq}"),
                    version: "1".into(),
                    authoritative_hash: format!("hash-{seq}"),
                    payload: seq.to_string().into_bytes(),
                })
            } else {
                None
            };
            Ok((seq, event))
        });
        let (events, through) = receipt_batch(receipts, after, 603, 256).unwrap();
        assert_eq!(events.len(), expected_count);
        assert_eq!(through, if after == 0 { 512 } else { 603 });
        collected.extend(events.iter().map(|event| event.event_id.clone()));
        let cursor = through.to_string();
        batches.push(VerifiedInboxBatch {
            prior_cursor: prior,
            next_cursor: cursor.clone(),
            events,
        });
        prior = Some(cursor);
        after = through;
    }
    assert_eq!(
        collected,
        (1u64..=300)
            .map(|i| format!("event-{}", i * 2))
            .collect::<Vec<_>>()
    );
    // The projection above runs on every platform. Persistence must fail closed
    // without creating state where private SQLite protection is unsupported.
    let opened = AgentInbox::open(
        &dir.path().join("inbox.sqlite"),
        &binding,
        InboxLimits::default(),
    );
    if cfg!(not(unix)) {
        assert!(matches!(opened, Err(InboxError::Unsupported)));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        return;
    }
    let mut inbox = opened.unwrap();
    for batch in batches {
        inbox.ingest_verified(batch).unwrap();
    }
    assert_eq!(inbox.status().unwrap().retained_events, 300);
    assert_eq!(
        inbox.status().unwrap().verified_cursor.as_deref(),
        Some("603")
    );
}
