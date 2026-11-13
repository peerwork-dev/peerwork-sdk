// Synthetic bridge retirement exercises the original protocol and encrypted store.
fn completed_call(binding: &Value) -> Value {
    json!({"call_id":binding["call_id"],"sequence":binding["sequence"],"frame_digest":binding["frame_digest"],"state":"RESULT_UNKNOWN","outcome_digest":"0".repeat(64),"report_version":2,"retirement":"SERVICE_CONFIRMED_CONSUMED"})
}
#[test]
fn sparse_completed_calls_are_fenced_after_restart_without_retiring_the_old_hole() {
    let root = crate::test_support::protected_test_dir();
    let path = root.path().join("bridge");
    create_private_state_directory(&path).unwrap();
    let destination =
        json!({"host":"CODEX_APP_SERVER","conversation_id":"thread","session_id":"session"});
    let mut store = store::Store::open(&path, "sparse", true).unwrap();
    let (first, one) = frame(&destination, 1);
    let (second, two) = frame(&destination, 2);
    for (binding, message) in [(&first, &one), (&second, &two)] {
        store
            .reserve(
                binding,
                message["message_id"].as_str().unwrap(),
                binding["frame_digest"].as_str().unwrap(),
                Some(message),
            )
            .unwrap();
        store
            .finish(
                binding,
                &json!({"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"}),
            )
            .unwrap();
    }
    let scope = access_scope(&second);
    let selected = completed_call(&second);
    assert_eq!(store.retire(&scope, 0, &[selected.clone()]).unwrap(), 1);
    drop(store);
    let mut store = store::Store::open(&path, "sparse", false).unwrap();
    assert_eq!(store.retire(&scope, 0, &[selected]).unwrap(), 0);
    assert!(!store.retired(&first).unwrap());
    assert!(store.retired(&second).unwrap());
    assert_eq!(
        store
            .get(
                &first,
                one["message_id"].as_str().unwrap(),
                first["frame_digest"].as_str().unwrap()
            )
            .unwrap()
            .unwrap()["state"],
        "RESULT_UNKNOWN"
    );
    assert_eq!(
        store
            .reserve(
                &second,
                two["message_id"].as_str().unwrap(),
                second["frame_digest"].as_str().unwrap(),
                Some(&two)
            )
            .unwrap_err(),
        "HOST_EVIDENCE_RETIRED"
    );
    store
        .finish(&second, &json!({"state":"HOST_ACCEPTED","receipt":"late"}))
        .unwrap();
    assert!(store
        .get(
            &second,
            two["message_id"].as_str().unwrap(),
            second["frame_digest"].as_str().unwrap()
        )
        .unwrap()
        .is_none());
    let sql = rusqlite::Connection::open(path.join("bridge.sqlite")).unwrap();
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM bridge_calls WHERE frame IS NOT NULL",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        0,
        "only Runtime retains rendered private input"
    );
}
#[test]
fn retirement_refuses_a_live_physical_input_and_authenticates_sparse_fences() {
    let root = crate::test_support::protected_test_dir();
    let path = root.path().join("bridge");
    create_private_state_directory(&path).unwrap();
    let destination =
        json!({"host":"CODEX_APP_SERVER","conversation_id":"thread","session_id":"session"});
    let mut store = store::Store::open(&path, "active", true).unwrap();
    let (binding, message) = frame(&destination, 2);
    let scope = access_scope(&binding);
    let selected = completed_call(&binding);
    store
        .reserve(
            &binding,
            message["message_id"].as_str().unwrap(),
            binding["frame_digest"].as_str().unwrap(),
            Some(&message),
        )
        .unwrap();
    assert_eq!(
        store.retire(&scope, 0, &[selected.clone()]).unwrap_err(),
        "HOST_RETIREMENT_ACTIVE_INPUT"
    );
    store
        .finish(
            &binding,
            &json!({"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"}),
        )
        .unwrap();
    store.retire(&scope, 0, &[selected]).unwrap();
    let sql = rusqlite::Connection::open(path.join("bridge.sqlite")).unwrap();
    sql.execute("UPDATE bridge_closed_ranges SET hi=hi+1", [])
        .unwrap();
    assert_eq!(store.retired(&binding).unwrap_err(), "BRIDGE_STATE_INVALID");
}
#[test]
fn generation_fences_compact_retry_history_without_fabricating_negative_receipts() {
    let root = crate::test_support::protected_test_dir();
    let path = root.path().join("bridge");
    create_private_state_directory(&path).unwrap();
    let destination =
        json!({"host":"CODEX_APP_SERVER","conversation_id":"thread","session_id":"session"});
    let mut store = store::Store::open(&path, "generations", true).unwrap();
    let (mut binding, message) = frame(&destination, 1);
    binding["attempt"] = json!(1);
    let digest = binding["frame_digest"].as_str().unwrap().to_owned();
    let id = message["message_id"].as_str().unwrap();
    store
        .reserve(&binding, id, &digest, Some(&message))
        .unwrap();
    let first = binding.clone();
    for attempt in 2..=80u64 {
        store
            .finish(
                &binding,
                &json!({"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"}),
            )
            .unwrap();
        let mut next = binding.clone();
        next["attempt"] = json!(attempt);
        next["call_id"] = json!(format!("{attempt:043}"));
        store
            .reserve_retry(&next, id, &digest, Some(&message), Some(&binding))
            .unwrap();
        let mut entry = completed_call(&binding);
        entry["retirement"] = json!("SUPERSEDED");
        entry["attempt"] = binding["attempt"].clone();
        let scope = access_scope(&binding);
        assert_eq!(store.retire(&scope, 0, &[entry.clone()]).unwrap(), 1);
        assert_eq!(store.retire(&scope, 0, &[entry]).unwrap(), 0);
        assert_eq!(
            store.get(&binding, id, &digest).unwrap_err(),
            "HOST_EVIDENCE_RETIRED"
        );
        assert!(!store.retired(&next).unwrap());
        binding = next;
    }
    store
        .finish(
            &binding,
            &json!({"state":"NOT_SENT","code":"HOST_NOT_READY","proof":"LOCAL_PREFLIGHT_NO_IO"}),
        )
        .unwrap();
    // A terminal current call must not let an old absent call re-enter.
    assert_eq!(
        store
            .reserve(&first, id, &digest, Some(&message))
            .unwrap_err(),
        "HOST_EVIDENCE_RETIRED"
    );
    store
        .finish(&first, &json!({"state":"HOST_ACCEPTED","receipt":"late"}))
        .unwrap();
    drop(store);
    let store = store::Store::open(&path, "generations", false).unwrap();
    assert_eq!(
        store.get(&first, id, &digest).unwrap_err(),
        "HOST_EVIDENCE_RETIRED"
    );
    let sql = rusqlite::Connection::open(path.join("bridge.sqlite")).unwrap();
    assert_eq!(
        sql.query_row("SELECT rows FROM bridge_meta", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback bridge and a synthetic Codex host"]
async fn sparse_retirement_and_retry_generations_cross_the_authenticated_bridge_wire() {
    let fixture = CodexFixture::start();
    fixture.emit_events.store(false, Ordering::SeqCst);
    let root = crate::test_support::protected_test_dir();
    let config = BridgeConfig {
        format: "peerwork.host-bridge.v1".into(),
        state_directory: root.path().join("bridge"),
        host: fixture.config(),
        bindings: vec![grant()],
    };
    let (ready, stop, task) = start(config).await;
    wait_ready(&ready).await;
    let (mut first, one) = frame(&ready.adapter["destination"], 1);
    first["attempt"] = json!(1);
    assert_eq!(
        call(&ready, "deliver", &first, json!({"message":one})).await["state"],
        "HOST_ACCEPTED"
    );
    let (mut second, two) = frame(&ready.adapter["destination"], 2);
    second["attempt"] = json!(1);
    assert_eq!(
        call(&ready, "deliver", &second, json!({"message":two})).await["state"],
        "HOST_ACCEPTED"
    );
    let mut entry = completed_call(&second);
    entry["state"] = json!("HOST_ACCEPTED");
    entry["attempt"] = json!(1);
    let scope = access_scope(&second);
    let retired = call(
        &ready,
        "retire",
        &scope,
        json!({"through_sequence":0,"calls":[entry]}),
    )
    .await;
    assert_eq!(retired["removed"], 1, "{retired}");
    assert_eq!(
        call(
            &ready,
            "receipt",
            &second,
            json!({"message_id":two["message_id"],"body_hash":second["frame_digest"]})
        )
        .await["error"],
        "HOST_EVIDENCE_RETIRED"
    );
    assert_eq!(
        call(
            &ready,
            "receipt",
            &first,
            json!({"message_id":one["message_id"],"body_hash":first["frame_digest"]})
        )
        .await["state"],
        "HOST_ACCEPTED"
    );
    stop.cancel();
    task.await.unwrap().unwrap();
    drop(fixture);
}
