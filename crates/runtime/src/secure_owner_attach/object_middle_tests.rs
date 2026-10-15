// Included in the existing Owner attachment tests module to share its fault lock.
#[test]
fn actual_service_imports_middle_partial_protocol_object_stage() {
    let _fault_guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
    let Ok(reference) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
        return;
    };
    let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
    let mode = std::env::var("PEERWORK_PARTIAL_OBJECT_STAGE_MODE")
        .unwrap_or_else(|_| "middle-part1-before-post".into());
    assert!(["middle-part1-before-post", "middle-part1-applied-loss"].contains(&mode.as_str()));
    let root = if let Ok(path) = std::env::var("PEERWORK_PARTIAL_OBJECT_NATIVE_ROOT") {
        let path = PathBuf::from(path);
        assert!(!path.exists());
        std::fs::create_dir_all(&path).unwrap();
        path
    } else {
        tempfile::tempdir().unwrap().keep()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stderr_path = root.join("service.stderr");
    let stderr = std::fs::File::create(&stderr_path).unwrap();
    let requests = root.join("requests.jsonl");
    std::fs::write(&requests, b"").unwrap();
    let child = Command::new(&node)
        .arg("--require")
        .arg(sdk.join("tests/historical-direct-request-observer.cjs"))
        .arg(sdk.join("tests/reference-kernel-server.mjs"))
        .env("PEERWORK_TEST_REQUEST_OBSERVER", &requests)
        .env("PEERWORK_REFERENCE_ROOT", &reference)
        .env("PEERWORK_TEST_STATE", &root)
        .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .unwrap();
    struct PartialServer(Child);
    impl Drop for PartialServer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = PartialServer(child);
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let origin = ready["origin"].as_str().unwrap();
    let oracle = rusqlite::Connection::open_with_flags(
        root.join("control.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let produce = |name: &str| -> serde_json::Value {
        let output = Command::new(&node)
            .arg(sdk.join("tests/legacy-owner-partial-object-stage.mjs"))
            .arg(origin)
            .arg(root.join(name))
            .arg(&reference)
            .arg(&mode)
            .output()
            .unwrap();
        std::fs::write(root.join(format!("{name}.stdout")), &output.stdout).unwrap();
        std::fs::write(root.join(format!("{name}.stderr")), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "genuine partial source failed; protected root={}",
            root.display()
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let fixture = produce("source");
    let make_input = |fixture: &serde_json::Value| HistoricalOwnerAttachInput {
        workspace_id: fixture["workspace_id"].as_str().unwrap().into(),
        protected_ts_state_path: fixture["state_path"].as_str().unwrap().into(),
        protected_owner_pkcs8_path: fixture["pem_path"].as_str().unwrap().into(),
        protected_ts_intent_db_path: fixture["intent_db_path"].as_str().unwrap().into(),
        expected_owner_actor_id: fixture["owner_actor_id"].as_str().unwrap().into(),
        expected_owner_key_id: fixture["owner_key_id"].as_str().unwrap().into(),
        recover_pending_action: false,
        retain_pending_action_command_id: None,
        selected_pending_package_stage_command_id: None,
        selected_orphan_package_stage_command_id: None,
        expected_ts_state_digest: None,
        kernel_pending_command_ids: vec![],
        expected_kernel_intent_db_digest: None,
    };
    let input = make_input(&fixture);
    let workspace = &input.workspace_id;
    let count_for = |workspace: &str| -> i64 {
        oracle
            .query_row(
                "SELECT count(*) FROM secure_commits WHERE workspace_id=?1",
                [workspace],
                |row| row.get(0),
            )
            .unwrap()
    };
    let count = || count_for(workspace);
    let applied = mode.ends_with("applied-loss");
    let before = count();
    assert_eq!(before, if applied { 3 } else { 2 });
    let command = fixture["pending_command_id"].as_str().unwrap();
    let options = std::fs::read_to_string(fixture["options_path"].as_str().unwrap()).unwrap();
    let material = std::fs::read_to_string(fixture["material_path"].as_str().unwrap()).unwrap();
    let source_bytes = std::fs::read(&input.protected_ts_state_path).unwrap();
    let source: serde_json::Value = serde_json::from_slice(&source_bytes).unwrap();
    let selected_key = format!("{}.{}", workspace, fixture["instance_id"].as_str().unwrap());
    assert!(source
        .get("protocol_install_intents")
        .is_none_or(|value| value.as_object().unwrap().is_empty()));
    let packet = source["pending"][command]["body"].clone();
    let packet =
        parse_wire_json_bounded(&serde_json::to_vec(&packet).unwrap(), 64, 220_000).unwrap();
    let expected_request = canonical_wire_value(&packet, CanonicalPath::SecureArtifact)
        .unwrap()
        .into_bytes();
    let config = SecureOwnerCreateConfig {
        origin: origin.into(),
        state_dir: root.join("native"),
        allow_loopback_http: true,
        max_replay_artifact_bytes: 64 * 1024 * 1024,
    };
    let attach = SecureHistoricalOwnerAttach::new(config.clone());
    let cancel = CancellationToken::new();
    assert!(matches!(
        attach.attach(input.clone(), &cancel),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.inspect_pending_object_stage(&input, command, &options, "", &cancel),
        Err(HistoricalOwnerAttachError::ObjectMaterialRequired)
    ));
    let inventory = attach
        .inspect_pending_object_stage(&input, command, &options, &material, &cancel)
        .unwrap();
    assert_eq!(
        inventory.status,
        if applied {
            "APPLIED_IN_SIGNED_REPLAY"
        } else {
            "PENDING_UNRESOLVED"
        }
    );
    assert_eq!(inventory.part_index, 1);
    assert_eq!(inventory.part_count, 4);
    assert_eq!(fixture["part_count"], 4);
    assert_eq!(
        inventory.original_commit_hash,
        fixture["pending_commit_hash"].as_str().unwrap()
    );
    assert!(matches!(
        attach.attach_pending_object_stage(
            input.clone(),
            command,
            &inventory.ts_state_digest,
            &options,
            "",
            &cancel
        ),
        Err(HistoricalOwnerAttachError::ObjectMaterialRequired)
    ));
    for case in [
        "part-text",
        "selected-packet",
        "wrong-material",
        "invalid-grant",
    ] {
        let mut copy = source.clone();
        let mut options_copy: serde_json::Value = serde_json::from_str(&options).unwrap();
        let mut material_copy = material.clone();
        match case {
            "raw-hash" => {
                copy["protocol_object_stage_intents"][&selected_key]["request_hash"] =
                    serde_json::json!("0".repeat(64))
            }
            "descriptor" => {
                copy["protocol_object_stage_intents"][&selected_key]["proof"]["parts"][0]
                    ["sha256"] = serde_json::json!("0".repeat(64))
            }
            "part-text" => {
                copy["protocol_object_stage_intents"][&selected_key]["parts"][0]["value"]["text"] =
                    serde_json::json!("changed")
            }
            "missing-part" => {
                copy["protocol_object_stage_intents"][&selected_key]["parts"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            "extra-part" => {
                let extra =
                    copy["protocol_object_stage_intents"][&selected_key]["parts"][0].clone();
                copy["protocol_object_stage_intents"][&selected_key]["parts"]
                    .as_array_mut()
                    .unwrap()
                    .push(extra);
            }
            "source-checkpoint" => {
                copy["protocol_object_stage_intents"][&selected_key]["proof"]["source"]["head"] =
                    serde_json::json!("0".repeat(64))
            }
            "selected-packet" => {
                copy["pending"][command]["body"]["commit"]["payload"]["previous"] =
                    serde_json::json!("0".repeat(64))
            }
            "wrong-material" => material_copy = "{}".into(),
            "wrong-manifest" => {
                options_copy["manifest"]["name"] = serde_json::json!("changed.material")
            }
            "invalid-grant" => {
                options_copy["grants"][0]["actor_id"] = serde_json::json!(base64url(&[199; 32]))
            }
            _ => {
                let marker = copy["protocol_object_stage_intents"][&selected_key].clone();
                copy["protocol_object_stage_intents"]
                    [format!("{}.{}", workspace, base64url(&[198; 32]))] = marker;
            }
        }
        let options_copy = options_copy.to_string();
        if ["wrong-manifest", "invalid-grant"].contains(&case) {
            let value =
                parse_wire_json_bounded(options_copy.as_bytes(), 64, 2 * 1024 * 1024).unwrap();
            copy["protocol_object_stage_intents"][&selected_key]["request_hash"] =
                serde_json::json!(sha256_hex(
                    canonical_wire_value(&value, CanonicalPath::SecureArtifact)
                        .unwrap()
                        .as_bytes()
                ));
        }
        let copied_bytes = serde_json::to_vec(&copy).unwrap();
        let path = root.join(format!("negative-{case}.state"));
        std::fs::write(&path, &copied_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut negative = input.clone();
        negative.protected_ts_state_path = path.clone();
        assert!(
            matches!(
                attach.inspect_pending_object_stage(
                    &negative,
                    command,
                    &options_copy,
                    &material_copy,
                    &cancel
                ),
                Err(HistoricalOwnerAttachError::SourceUnresolved)
            ),
            "inspect {case}"
        );
        assert!(
            matches!(
                attach.attach_pending_object_stage(
                    negative,
                    command,
                    &sha256_hex(&copied_bytes),
                    &options_copy,
                    &material_copy,
                    &cancel
                ),
                Err(HistoricalOwnerAttachError::SourceUnresolved)
            ),
            "attach {case}"
        );
        assert!(attach.attachments().unwrap().is_empty());
        assert!(!attach
            .workspace_dir(workspace)
            .join("lifecycle.state")
            .exists());
        assert_eq!(count(), before);
        assert_eq!(std::fs::read(path).unwrap(), copied_bytes);
        assert_eq!(
            std::fs::read(&input.protected_ts_state_path).unwrap(),
            source_bytes
        );
    }
    assert!(matches!(
        attach.inspect_pending_object_stage(
            &input,
            &base64url(&[197; 32]),
            &options,
            &material,
            &cancel
        ),
        Err(HistoricalOwnerAttachError::SourceUnresolved)
    ));
    assert!(matches!(
        attach.attach_pending_object_stage(
            input.clone(),
            command,
            &"0".repeat(64),
            &options,
            &material,
            &cancel
        ),
        Err(HistoricalOwnerAttachError::SourceChanged)
    ));
    TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
    assert!(matches!(
        attach.attach_pending_object_stage(
            input.clone(),
            command,
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
    assert_eq!(count(), before);
    let history = SecureStateStore::open(&attach.history_path()).unwrap();
    let row = read_history(&history, origin).unwrap().rows[&prepared[0].attach_id].clone();
    drop(history);
    let saved = row.pending_object_stage.as_ref().unwrap();
    let protected = SecureStateStore::open(
        &config
            .state_dir
            .join("owner-object-stage-plans")
            .join(&saved.plan_id)
            .join("source-state.state"),
    )
    .unwrap();
    assert_eq!(
        protected.read_exact_secret().unwrap().unwrap().as_slice(),
        source_bytes.as_slice()
    );
    drop(protected);
    std::fs::rename(root.join("source"), root.join("source-gone")).unwrap();
    let fresh = SecureHistoricalOwnerAttach::new(config.clone());
    let attach_id = &prepared[0].attach_id;
    let resumed = fresh.resume_attachment(attach_id, &cancel).unwrap();
    assert_eq!(resumed.status, "ATTACHED_RESTRICTED");
    assert!(matches!(
        fresh.attached_profile_config(workspace, "PRIVATE"),
        Err(HistoricalOwnerAttachError::PendingObjectStageUnresolved)
    ));
    assert_eq!(
        resumed.pending_object_stage_command_id.as_deref(),
        Some(command)
    );
    assert_eq!(
        resumed.pending_object_stage_status.as_deref(),
        Some(if applied {
            "STAGE_ACCEPTED_INSTALL_PENDING"
        } else {
            "PENDING_UNRESOLVED"
        })
    );
    assert_eq!(
        fresh.resume_attachment(attach_id, &cancel).unwrap(),
        resumed
    );
    assert_eq!(count(), before);
    assert!(matches!(
        fresh.recover_pending_object_stage(attach_id, &base64url(&[196; 32]), &cancel),
        Err(HistoricalOwnerAttachError::Conflict)
    ));
    // Reconcile the original selected middle part, with no future part or BEGIN yet.
    if !applied {
        let selected = fresh
            .recover_pending_object_stage(attach_id, command, &cancel)
            .unwrap();
        assert_eq!(selected.status, "ATTACHED_RESTRICTED");
        assert!(selected
            .pending_object_stage_native_begin_command_id
            .is_none());
    }
    assert_eq!(count(), 3);
    let remaining_path = fresh
        .object_stage_plan_directory(&saved.plan_id)
        .join("native-remainder.state");
    let mut tail_packets: Vec<(String, Vec<u8>)> = Vec::new();
    let mut previous_hash = fixture["pending_commit_hash"].as_str().unwrap().to_owned();
    for index in 2..4usize {
        object_stage::TEST_STOP_AFTER_OBJECT_REMAINDER_ROW.store(true, Ordering::SeqCst);
        assert!(matches!(
            fresh.recover_pending_object_stage(attach_id, command, &cancel),
            Err(HistoricalOwnerAttachError::Cancelled)
        ));
        assert_eq!(count(), (index + 1) as i64);
        let store = SecureStateStore::open(&remaining_path).unwrap();
        let remaining_bytes = store.read_exact_secret().unwrap().unwrap();
        let remaining: serde_json::Value = serde_json::from_slice(&remaining_bytes).unwrap();
        drop(store);
        let packets = remaining["packets"].as_array().unwrap();
        assert_eq!(packets.len(), index - 1);
        let packet = packets.last().unwrap();
        let remaining_id = packet["command_id"].as_str().unwrap().to_owned();
        assert_ne!(remaining_id, command);
        assert!(tail_packets.iter().all(|p| p.0 != remaining_id));
        assert_eq!(packet["part_index"], index);
        let remaining_wire =
            peerwork_core::crypto::decode_base64url(packet["request_b64"].as_str().unwrap())
                .unwrap();
        let request = parse_wire_json_bounded(&remaining_wire, 64, 220_000).unwrap();
        let payload = request.get("commit").unwrap().get("payload").unwrap();
        assert_eq!(
            payload.get("previous").unwrap().as_string().unwrap(),
            previous_hash
        );
        assert_eq!(exact_u64(payload.get("sequence")), Some((index + 2) as u64));
        assert_eq!(
            payload.get("command_id").unwrap().as_string().unwrap(),
            remaining_id
        );
        previous_hash = packet["commit_hash"].as_str().unwrap().to_owned();
        let reopened = SecureHistoricalOwnerAttach::new(config.clone());
        let resumed_remaining = reopened.resume_attachment(attach_id, &cancel).unwrap();
        assert_eq!(resumed_remaining.status, "ATTACHED_RESTRICTED");
        assert!(resumed_remaining
            .pending_object_stage_native_begin_command_id
            .is_none());
        assert_eq!(count(), (index + 1) as i64);
        let staged = reopened
            .recover_pending_object_stage(attach_id, command, &cancel)
            .unwrap();
        assert_eq!(staged.status, "ATTACHED_RESTRICTED");
        assert!(staged
            .pending_object_stage_native_begin_command_id
            .is_none());
        assert_eq!(count(), (index + 2) as i64);
        let store = SecureStateStore::open(&remaining_path).unwrap();
        assert_eq!(
            store.read_exact_secret().unwrap().unwrap().as_slice(),
            remaining_bytes.as_slice()
        );
        drop(store);
        let intents = SecureIntentJournal::open(
            &fresh
                .workspace_dir(workspace)
                .join("private-object-stage-intents.state"),
            origin,
            &input.expected_owner_actor_id,
        )
        .unwrap();
        assert_eq!(
            intents.exact_request(&remaining_id).unwrap(),
            remaining_wire
        );
        drop(intents);
        tail_packets.push((remaining_id, remaining_wire));
    }
    let installer = SecurePrivatePackageInstall::new(fresh.profile_config(&input));
    let mut complete = None;
    for _ in 0..8 {
        let result = fresh
            .recover_pending_object_stage(attach_id, command, &cancel)
            .unwrap();
        if let Some(new_begin) = result
            .pending_object_stage_native_begin_command_id
            .as_deref()
        {
            assert_ne!(new_begin, command);
            assert!(installer.continue_install_json(new_begin).is_err());
        }
        if result.status == "ATTACHED" {
            complete = Some(result);
            break;
        }
        assert_eq!(result.status, "ATTACHED_RESTRICTED");
    }
    let complete = complete.expect("middle source did not finish its distinct native install");
    assert_eq!(
        complete.pending_object_stage_status.as_deref(),
        Some("ACCEPTED")
    );
    assert_eq!(count(), 7);
    let original_count: i64 = oracle
        .query_row(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=?1 AND command_id=?2",
            [workspace.as_str(), command],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(original_count, 1);
    let native_begin = complete
        .pending_object_stage_native_begin_command_id
        .as_deref()
        .unwrap();
    let steps: Vec<(String, String)> = oracle.prepare("SELECT command_id,action_id FROM secure_commits WHERE workspace_id=?1 ORDER BY sequence").unwrap()
        .query_map([workspace], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        steps.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
        [
            "secure.bootstrap",
            "secure.protocol-object.stage",
            "secure.protocol-object.stage",
            "secure.protocol-object.stage",
            "secure.protocol-object.stage",
            "secure.structure.begin",
            "secure.structure.end"
        ]
    );
    assert_eq!(steps[3].0, tail_packets[0].0);
    assert_eq!(steps[4].0, tail_packets[1].0);
    assert_eq!(steps[5].0, native_begin);
    assert!(tail_packets.iter().all(|p| p.0 != native_begin));
    assert_ne!(native_begin, command);
    if !applied {
        let intents = SecureIntentJournal::open(
            &fresh
                .workspace_dir(workspace)
                .join("private-object-stage-intents.state"),
            origin,
            &input.expected_owner_actor_id,
        )
        .unwrap();
        assert_eq!(intents.exact_request(command).unwrap(), expected_request);
    }
    let read: serde_json::Value =
        serde_json::from_str(&fresh.read_workspace_json(workspace, &cancel).unwrap()).unwrap();
    assert_eq!(read["structure_status"], "ACTIVE");
    assert_eq!(read["sequence"], 7);
    assert!(read["objects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["kind"] == "instances"
            && row["id"] == fixture["instance_id"]
            && row["value"]["protocol_digest"] == fixture["protocol_digest"]
            && row["value"]["origin_entrypoint"] == fixture["entrypoint"]));
    assert_eq!(
        fresh
            .recover_pending_object_stage(attach_id, command, &cancel)
            .unwrap(),
        complete
    );
    assert_eq!(
        fresh.resume_attachment(attach_id, &cancel).unwrap(),
        complete
    );
    assert_eq!(count(), 7);
    let protocol = read["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "protocols" && r["id"] == fixture["protocol_digest"])
        .unwrap();
    assert_eq!(
        protocol["value"]["manifest"],
        protocol["value"]["resolved_manifest"]
    );
    assert!(
        protocol["value"]["composition"]["dependencies"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    let origin_host = reqwest::Url::parse(origin)
        .unwrap()
        .socket_addrs(|| None)
        .unwrap()[0]
        .to_string();
    let request_rows: Vec<serde_json::Value> = std::fs::read_to_string(&requests)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|r: &serde_json::Value| r["host"] == origin_host)
        .collect();
    assert_eq!(request_rows.len(), 6);
    for id in std::iter::once(command)
        .chain(tail_packets.iter().map(|p| p.0.as_str()))
        .chain(std::iter::once(native_begin))
    {
        assert_eq!(
            request_rows
                .iter()
                .filter(|r| r["command_id"] == id)
                .count(),
            1
        );
    }
    let original_post = request_rows
        .iter()
        .find(|r| r["command_id"] == command)
        .unwrap();
    if applied {
        assert_eq!(
            original_post["body_sha256"],
            fixture["pending_transport_body_sha256"]
        );
    } else {
        assert_eq!(original_post["body_sha256"], sha256_hex(&expected_request));
    }
    for (id, wire) in &tail_packets {
        let post = request_rows
            .iter()
            .find(|r| r["command_id"] == id.as_str())
            .unwrap();
        assert_eq!(post["body_sha256"], sha256_hex(wire));
    }
    eprintln!("MIDDLE_OBJECT_STAGE PASS mode={mode} initial={before} final=7 parts=4 remaining=2 exact_post_count=6");
}
