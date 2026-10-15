#[test]
fn actual_service_completed_install_preserves_historical_end_and_current_floor() {
    let _guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
    let Ok(reference) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
        return;
    };
    let node = std::env::var("PEERWORK_NODE_BIN").unwrap();
    let root = PathBuf::from(std::env::var("PEERWORK_COMPLETED_FLOOR_ROOT").unwrap());
    assert!(!root.exists());
    std::fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let later = std::env::var("PEERWORK_COMPLETED_FLOOR_MODE").unwrap_or_else(|_| "later".into())
        == "later";
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let requests = root.join("requests.jsonl");
    std::fs::write(&requests, b"").unwrap();
    let child = Command::new(&node)
        .arg("--require")
        .arg(sdk.join("tests/historical-direct-request-observer.cjs"))
        .arg(sdk.join("tests/reference-kernel-server.mjs"))
        .env("PEERWORK_REFERENCE_ROOT", &reference)
        .env("PEERWORK_TEST_STATE", &root)
        .env("PEERWORK_TEST_REQUEST_OBSERVER", &requests)
        .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(root.join("service.stderr")).unwrap())
        .spawn()
        .unwrap();
    struct StopFloor {
        child: Child,
        root: PathBuf,
    }
    impl Drop for StopFloor {
        fn drop(&mut self) {
            let pid = self.child.id();
            let _ = self.child.kill();
            let result = self.child.wait();
            let data = serde_json::json!({"pid":pid,"wait_ok":result.is_ok(),"exit_code":result.ok().and_then(|s|s.code())});
            let _ = std::fs::write(self.root.join("service-exit.json"), data.to_string());
        }
    }
    let mut service = StopFloor {
        child,
        root: root.clone(),
    };
    let mut line = String::new();
    BufReader::new(service.child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let origin = ready["origin"].as_str().unwrap();
    let frozen = std::env::var("PEERWORK_TEST_SDK_ROOT").unwrap();
    let helper = if later {
        sdk.join("tests/completed-install-read-floor/producer.mjs")
    } else {
        PathBuf::from(&frozen).join("tests/legacy-owner-install-intent.mjs")
    };
    let output = Command::new(&node)
        .arg(helper)
        .arg(origin)
        .arg(root.join("source"))
        .arg(&reference)
        .arg("direct-staged-package-completed-end")
        .env("PEERWORK_TEST_SDK_ROOT", &frozen)
        .output()
        .unwrap();
    std::fs::write(root.join("producer.stdout"), &output.stdout).unwrap();
    std::fs::write(root.join("producer.stderr"), &output.stderr).unwrap();
    assert!(output.status.success(), "public producer failed");
    let f: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let workspace = f["workspace_id"].as_str().unwrap();
    let instance = f["instance_id"].as_str().unwrap();
    let input = HistoricalOwnerAttachInput {
        workspace_id: workspace.into(),
        protected_ts_state_path: f["state_path"].as_str().unwrap().into(),
        protected_owner_pkcs8_path: f["pem_path"].as_str().unwrap().into(),
        protected_ts_intent_db_path: f["intent_db_path"].as_str().unwrap().into(),
        expected_owner_actor_id: f["owner_actor_id"].as_str().unwrap().into(),
        expected_owner_key_id: f["owner_key_id"].as_str().unwrap().into(),
        recover_pending_action: false,
        retain_pending_action_command_id: None,
        selected_pending_package_stage_command_id: None,
        selected_orphan_package_stage_command_id: None,
        expected_ts_state_digest: None,
        kernel_pending_command_ids: vec![],
        expected_kernel_intent_db_digest: None,
    };
    let options = std::fs::read_to_string(f["options_path"].as_str().unwrap()).unwrap();
    let material = std::fs::read_to_string(f["material_path"].as_str().unwrap()).unwrap();
    let source = std::fs::read(&input.protected_ts_state_path).unwrap();
    let config = SecureOwnerCreateConfig {
        origin: origin.into(),
        state_dir: root.join("native"),
        allow_loopback_http: true,
        max_replay_artifact_bytes: 64 * 1024 * 1024,
    };
    let attach = SecureHistoricalOwnerAttach::new(config.clone());
    let cancel = CancellationToken::new();
    let db = rusqlite::Connection::open_with_flags(
        root.join("control.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let count = || -> i64 {
        db.query_row(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=?1",
            [workspace],
            |r| r.get(0),
        )
        .unwrap()
    };
    let floor = if later { 6 } else { 5 };
    assert_eq!(count(), floor);
    let posts = std::fs::read(&requests).unwrap();
    let inventory = attach
        .inspect_completed_direct_install(&input, instance, &options, &material, &cancel)
        .unwrap();
    assert_eq!(inventory.end_sequence, 5);
    assert_eq!(inventory.status, "COMPLETED_IN_SIGNED_REPLAY");
    assert!(matches!(
        attach.inspect_completed_direct_install(
            &input,
            &base64url(&[91; 32]),
            &options,
            &material,
            &cancel
        ),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.inspect_completed_direct_install(&input, instance, &options, "{}", &cancel),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.attach_completed_direct_install(
            input.clone(),
            instance,
            &inventory.ts_state_digest,
            &options,
            "{}",
            &cancel
        ),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.attach_completed_direct_install(
            input.clone(),
            instance,
            &"0".repeat(64),
            &options,
            &material,
            &cancel
        ),
        Err(HistoricalOwnerAttachError::SourceChanged)
    ));
    assert!(attach.attachments().unwrap().is_empty());
    assert!(!attach
        .workspace_dir(workspace)
        .join("lifecycle.state")
        .exists());
    assert_eq!(count(), floor);
    assert_eq!(
        std::fs::read(&input.protected_ts_state_path).unwrap(),
        source
    );
    assert_eq!(std::fs::read(&requests).unwrap(), posts);
    TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
    assert!(matches!(
        attach.attach_completed_direct_install(
            input.clone(),
            instance,
            &inventory.ts_state_digest,
            &options,
            &material,
            &cancel
        ),
        Err(HistoricalOwnerAttachError::Cancelled)
    ));
    let rows = attach.attachments().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "PREPARED");
    std::fs::rename(root.join("source"), root.join("source-gone")).unwrap();
    let fresh = SecureHistoricalOwnerAttach::new(config.clone());
    let done = fresh
        .resume_attachment(&rows[0].attach_id, &cancel)
        .unwrap();
    assert_eq!(done.status, "ATTACHED");
    assert_eq!(done.sequence, Some(floor as u64));
    assert_eq!(
        done.pending_direct_install_status.as_deref(),
        Some("ACCEPTED")
    );
    let history = fresh.attachments().unwrap();
    assert_eq!(history, vec![done.clone()]);
    let saved = fresh
        .load_quarantined_direct_install_plan(
            &done.attach_id,
            &read_history(
                &SecureStateStore::open(&fresh.history_path()).unwrap(),
                origin,
            )
            .unwrap()
            .rows[&done.attach_id],
        )
        .unwrap();
    if later {
        let end = saved.manifest.completed_checkpoint.as_ref().unwrap();
        assert_eq!(end.sequence, 5);
        assert_eq!(end.head, f["completed_head"].as_str().unwrap());
        assert_eq!(saved.manifest.source_sequence, 6);
    } else {
        assert!(saved.manifest.completed_checkpoint.is_none());
    }
    let read: serde_json::Value =
        serde_json::from_str(&fresh.read_workspace_json(workspace, &cancel).unwrap()).unwrap();
    assert_eq!(read["sequence"], floor);
    assert_eq!(read["structure_status"], "ACTIVE");
    assert!(read["objects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["kind"] == "instances"
            && r["id"] == instance
            && r["value"]["protocol_digest"] == f["protocol_digest"]));
    if later {
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == &f["later_record"]));
        assert_eq!(read["head"], f["latest_head"]);
    }
    assert_eq!(
        fresh.resume_attachment(&done.attach_id, &cancel).unwrap(),
        done
    );
    assert_eq!(count(), floor);
    assert_eq!(std::fs::read(&requests).unwrap(), posts);
    eprintln!("COMPLETED_READ_FLOOR PASS later={later} original_end=5 source_floor={floor} current_read={floor} mutation_posts=0 source_gone=true");
}
