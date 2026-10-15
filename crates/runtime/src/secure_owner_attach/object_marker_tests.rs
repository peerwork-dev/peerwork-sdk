#[test]
fn actual_service_imports_marker_only_object_stage() {
    let _guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
    let Ok(reference) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
        return;
    };
    let node = std::env::var("PEERWORK_NODE_BIN").unwrap();
    let mode = std::env::var("PEERWORK_MARKER_MODE").unwrap();
    let root = PathBuf::from(std::env::var("PEERWORK_MARKER_ROOT").unwrap());
    assert!(!root.exists());
    std::fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let requests = root.join("requests.jsonl");
    std::fs::write(&requests, b"").unwrap();
    let mut child = Command::new(&node)
        .arg("--require")
        .arg(sdk.join("tests/historical-direct-request-observer.cjs"))
        .arg(sdk.join("tests/reference-kernel-server.mjs"))
        .env("PEERWORK_TEST_REQUEST_OBSERVER", &requests)
        .env("PEERWORK_REFERENCE_ROOT", &reference)
        .env("PEERWORK_TEST_STATE", &root)
        .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(root.join("service.stderr")).unwrap())
        .spawn()
        .unwrap();
    struct Stop(Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let mut service = Stop(child);
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let origin = ready["origin"].as_str().unwrap();
    let out = Command::new(&node)
        .arg(sdk.join("tests/legacy-owner-marker-object-stage.mjs"))
        .arg(origin)
        .arg(root.join("source"))
        .arg(&reference)
        .arg(&mode)
        .output()
        .unwrap();
    std::fs::write(root.join("producer.stdout"), &out.stdout).unwrap();
    std::fs::write(root.join("producer.stderr"), &out.stderr).unwrap();
    assert!(
        out.status.success(),
        "producer failed at {}",
        root.display()
    );
    let f: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let input = HistoricalOwnerAttachInput {
        workspace_id: f["workspace_id"].as_str().unwrap().into(),
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
    let workspace = input.workspace_id.clone();
    let hash = f["marker_hash"].as_str().unwrap();
    let source = std::fs::read(&input.protected_ts_state_path).unwrap();
    let options = std::fs::read_to_string(f["options_path"].as_str().unwrap()).unwrap();
    let material = std::fs::read_to_string(f["material_path"].as_str().unwrap()).unwrap();
    let db = rusqlite::Connection::open_with_flags(
        root.join("control.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let count = || {
        db.query_row(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=?1",
            [&workspace],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    let initial = if mode == "cleanup-applied" { 2 } else { 1 };
    assert_eq!(count(), initial);
    let config = SecureOwnerCreateConfig {
        origin: origin.into(),
        state_dir: root.join("native"),
        allow_loopback_http: true,
        max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
    };
    let attach = SecureHistoricalOwnerAttach::new(config.clone());
    let cancel = CancellationToken::new();
    let candidates = attach.object_stage_intent_candidates(&input).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].marker_hash, hash);
    assert_eq!(candidates[0].instance_id, f["instance_id"]);
    assert!(matches!(
        attach.attach(input.clone(), &cancel),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.inspect_object_stage_intent(&input, hash, &options, "", &cancel),
        Err(HistoricalOwnerAttachError::ObjectMaterialRequired)
    ));
    assert!(matches!(
        attach.inspect_object_stage_intent(&input, &"0".repeat(64), &options, &material, &cancel),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.inspect_object_stage_intent(&input, hash, &options, "{}", &cancel),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(attach.attachments().unwrap().is_empty());
    assert_eq!(count(), initial);
    let inventory = attach
        .inspect_object_stage_intent(&input, hash, &options, &material, &cancel)
        .unwrap();
    assert_eq!(inventory.accepted_parts, (initial - 1) as usize);
    assert_eq!(inventory.part_count, 4);
    TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
    assert!(matches!(
        attach.attach_object_stage_intent(
            input.clone(),
            hash,
            &inventory.ts_state_digest,
            &options,
            &material,
            &cancel
        ),
        Err(HistoricalOwnerAttachError::Cancelled)
    ));
    let prepared = attach.attachments().unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].status, "PREPARED");
    assert_eq!(count(), initial);
    assert_eq!(
        std::fs::read(&input.protected_ts_state_path).unwrap(),
        source
    );
    std::fs::rename(root.join("source"), root.join("source-gone")).unwrap();
    let id = &prepared[0].attach_id;
    let fresh = SecureHistoricalOwnerAttach::new(config.clone());
    let resumed = fresh.resume_attachment(id, &cancel).unwrap();
    assert_eq!(resumed.status, "ATTACHED_RESTRICTED");
    assert_eq!(
        resumed.object_stage_intent_marker_hash.as_deref(),
        Some(hash)
    );
    assert_eq!(resumed.pending_object_stage_command_id, None);
    assert_eq!(
        resumed.pending_object_stage_status.as_deref(),
        Some(if initial == 1 {
            "PENDING_UNRESOLVED"
        } else {
            "STAGE_ACCEPTED_INSTALL_PENDING"
        })
    );
    let store = SecureStateStore::open(&fresh.history_path()).unwrap();
    let row = read_history(&store, origin).unwrap().rows[id].clone();
    drop(store);
    let saved = row.pending_object_stage.as_ref().unwrap();
    let directory = fresh.object_stage_plan_directory(&saved.plan_id);
    let original = SecureStateStore::open(&directory.join("source-state.state")).unwrap();
    assert_eq!(
        original.read_exact_secret().unwrap().unwrap().as_slice(),
        source.as_slice()
    );
    drop(original);
    for index in (initial - 1) as usize..4 {
        object_stage::TEST_STOP_AFTER_OBJECT_REMAINDER_ROW.store(true, Ordering::SeqCst);
        assert!(matches!(
            fresh.recover_object_stage_intent(id, hash, &cancel),
            Err(HistoricalOwnerAttachError::Cancelled)
        ));
        assert_eq!(count(), index as i64 + 1);
        let store = SecureStateStore::open(&directory.join("native-remainder.state")).unwrap();
        let bytes = store.read_exact_secret().unwrap().unwrap();
        drop(store);
        let packets: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let packet = packets["packets"].as_array().unwrap().last().unwrap();
        assert_eq!(packet["part_index"], index);
        if let Some(orphan) = f["orphan_command_id"].as_str() {
            assert_ne!(packet["command_id"], orphan);
        }
        let reopened = SecureHistoricalOwnerAttach::new(config.clone());
        assert_eq!(
            reopened.resume_attachment(id, &cancel).unwrap().status,
            "ATTACHED_RESTRICTED"
        );
        assert_eq!(count(), index as i64 + 1);
        assert_eq!(
            reopened
                .recover_object_stage_intent(id, hash, &cancel)
                .unwrap()
                .status,
            "ATTACHED_RESTRICTED"
        );
        assert_eq!(count(), index as i64 + 2);
        let store = SecureStateStore::open(&directory.join("native-remainder.state")).unwrap();
        assert_eq!(
            store.read_exact_secret().unwrap().unwrap().as_slice(),
            bytes.as_slice()
        );
    }
    let mut complete = None;
    for _ in 0..8 {
        let result = SecureHistoricalOwnerAttach::new(config.clone())
            .recover_object_stage_intent(id, hash, &cancel)
            .unwrap();
        if result.status == "ATTACHED" {
            complete = Some(result);
            break;
        }
    }
    let complete = complete.expect("marker recovery did not complete");
    assert_eq!(count(), 7);
    let begin = complete
        .pending_object_stage_native_begin_command_id
        .as_ref()
        .unwrap();
    let rows:Vec<(String,String)>=db.prepare("SELECT command_id,action_id FROM secure_commits WHERE workspace_id=?1 ORDER BY sequence").unwrap().query_map([&workspace],|r|Ok((r.get(0)?,r.get(1)?))).unwrap().collect::<Result<_,_>>().unwrap();
    assert_eq!(
        rows.iter()
            .filter(|r| r.1 == "secure.protocol-object.stage")
            .count(),
        4
    );
    assert_eq!(&rows[5].0, begin);
    assert_eq!(rows[6].1, "secure.structure.end");
    assert_eq!(
        rows.iter()
            .map(|r| &r.0)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        7
    );
    if let Some(orphan) = f["orphan_command_id"].as_str() {
        assert_eq!(
            rows.iter().filter(|r| r.0 == orphan).count(),
            usize::from(mode == "cleanup-applied")
        );
    }
    let profile = fresh
        .attached_profile_config(&workspace, "PRIVATE")
        .unwrap();
    let read = SecureReadProfile::new(profile)
        .read_latest_json_with_cancel(&cancel)
        .unwrap();
    let read: serde_json::Value = serde_json::from_str(&read).unwrap();
    std::fs::write(
        root.join("signed-read.json"),
        serde_json::to_vec(&read).unwrap(),
    )
    .unwrap();
    assert_eq!(read["sequence"], 7);
    assert_eq!(read["structure_status"], "ACTIVE");
    let objects = read["objects"].as_array().unwrap();
    assert!(objects
        .iter()
        .any(|o| o["kind"] == "protocols" && o["id"] == f["protocol_digest"]));
    assert!(objects
        .iter()
        .any(|o| o["kind"] == "instances" && o["id"] == f["instance_id"]));
    assert_eq!(
        fresh
            .recover_object_stage_intent(id, hash, &cancel)
            .unwrap(),
        complete
    );
    assert_eq!(count(), 7);
    let state = std::fs::read(root.join("source-gone/agent.state")).unwrap();
    assert_eq!(state, source);
    let pid = service.0.id();
    service.0.kill().unwrap();
    service.0.wait().unwrap();
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    std::fs::write(root.join("summary.json"),serde_json::to_vec(&serde_json::json!({"mode":mode,"accepted_before":initial,"final_sequence":7,"stage_effects":4,"new_native_begin":begin,"source_unchanged":true,"sourcegone":true,"fresh_handles":true,"save_before_post_reopen":true,"idempotent":true,"service_pid":pid,"service_reaped":true})).unwrap()).unwrap();
    println!("MARKER_INTENT_PASS mode={mode} parts=4 final=7 native_tail_saved=true sourcegone=true service_reaped=true");
}

#[test]
fn reconcile_marker_object_http_evidence_offline() {
    let Ok(paths) = std::env::var("PEERWORK_MARKER_OFFLINE_ROOTS") else {
        return;
    };
    for path in paths.split(':') {
        let root = PathBuf::from(path);
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("producer.stdout")).unwrap()).unwrap();
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("source-gone/agent.state")).unwrap())
                .unwrap();
        let marker = state["protocol_object_stage_intents"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        let text = marker["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["value"]["text"].as_str().unwrap())
            .collect::<String>();
        let logical: serde_json::Value = serde_json::from_str(&text).unwrap();
        let read: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("signed-read.json")).unwrap()).unwrap();
        let protocol = read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["kind"] == "protocols" && o["id"] == fixture["protocol_digest"])
            .unwrap();
        assert_eq!(
            protocol["value"],
            logical,
            "full logical readback differs: {}",
            root.display()
        );
        let plans = root.join("native/owner-object-stage-plans");
        let directories = std::fs::read_dir(plans)
            .unwrap()
            .map(|p| p.unwrap().path())
            .filter(|p| p.is_dir())
            .collect::<Vec<_>>();
        assert_eq!(directories.len(), 1);
        let plan = &directories[0];
        let mut packets = Vec::new();
        for name in ["native-remainder.state", "native-begin.state"] {
            let store = SecureStateStore::open(&plan.join(name)).unwrap();
            let bytes = store.read_exact_secret().unwrap().unwrap();
            drop(store);
            let row: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let entries = if name == "native-begin.state" {
                vec![&row]
            } else {
                row["packets"].as_array().unwrap().iter().collect()
            };
            for entry in entries {
                let body =
                    peerwork_core::crypto::decode_base64url(entry["request_b64"].as_str().unwrap())
                        .unwrap();
                packets.push((
                    entry["command_id"].as_str().unwrap().to_owned(),
                    sha256_hex(&body),
                ));
            }
        }
        let origin = read["origin"].as_str();
        let rows = std::fs::read_to_string(root.join("requests.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .collect::<Vec<_>>();
        // The reference proxy and internal listener both observe each request.
        // Check each command at each observed host, without mixing boundaries.
        for (id, hash) in &packets {
            let selected = rows
                .iter()
                .filter(|r| r["command_id"] == id.as_str())
                .collect::<Vec<_>>();
            assert!(!selected.is_empty());
            let mut hosts = std::collections::HashSet::new();
            for row in selected {
                assert!(hosts.insert(row["host"].as_str().unwrap()));
                assert_eq!(row["body_sha256"], hash.as_str());
                assert_eq!(row["method"], "POST");
            }
        }
        let record = serde_json::json!({"full_logical_readback_equal":true,"compiler_equality_from_genuine_producer":fixture["compiler_equality"],"native_exact_request_hashes":packets,"all_observed_hosts_one_post_per_command":true,"read_origin_present":origin.is_some(),"offline_only":true});
        std::fs::write(
            root.join("offline-http-reconciliation.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        println!(
            "MARKER_OFFLINE_PASS mode={} full_value=true native_exact_requests={}",
            fixture["mode"],
            packets.len()
        );
    }
}
