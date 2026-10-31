//! Real HTTP and PostgreSQL; the host is a synthetic selected-session adapter.
use super::*;
use crate::{
    communication_host::write_private,
    communication_runtime::{ClientConfig, EngineConfig},
    participant::http_tests::{configuration, install_synthetic_key, mutate, selected, Service},
    participant::{Capability, Invoke, ParticipantClient, Scope},
    participant_dispatch::{HostConfig, HostSubscription},
    participant_inbox::HostOutcome,
    secure_state::create_private_state_directory,
};
use std::{path::PathBuf, time::Duration};

async fn setup(
    root: &Path,
    service: &Service,
) -> (RuntimeConfig, PathBuf, HostRebindRequest, Vec<WatchOptions>) {
    let cfg = configuration(root, &service.origin);
    let old=HostBinding::new(json!({"host":"ANTIGRAVITY_APP","conversation_id":format!("old-{}",root.display()),"session_id":format!("old-{}",root.display())})).unwrap();
    let client = ParticipantClient::open(cfg.clone()).await.unwrap();
    let worker = client.restrict("worker", Capability::owner()).unwrap();
    let mut watches = Vec::new();
    for index in 0..2 {
        let ws = mutate(
            &client,
            &format!("create-{index}"),
            "structure.workspace.create",
            &Scope::default(),
            json!({"name":"Synthetic rebind"}),
        )
        .await["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let scope = Scope {
            workspace_id: Some(ws.clone()),
            ..Default::default()
        };
        let meta = selected(&client, "structure.workspace.get", &scope, json!({})).await;
        let mailbox=mutate(&client,&format!("grant-{index}"),"structure.communication.grant.set",&scope,json!({"actor_id":cfg.expected_actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
        let key = install_synthetic_key(&cfg, &ws, &[38; 32], None);
        mutate(
            &client,
            &format!("key-{index}"),
            "structure.content-key.set",
            &scope,
            json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
        )
        .await;
        let options = WatchOptions {
            workspace_id: ws.clone(),
            mailbox_id: mailbox["mailbox_id"].as_str().unwrap().into(),
            membership_id: mailbox["membership_id"].as_str().unwrap().into(),
            consumer_id: "worker".into(),
            host_destination: Some(old.digest.clone()),
        };
        let mut watch = worker.watch(options.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let s = watch.next().await.unwrap();
                assert_ne!(s.state, "BLOCKED", "{s:?}");
                if s.receiver_link_verified {
                    break;
                }
            }
        })
        .await
        .unwrap();
        worker
            .host_operation(
                &options,
                crate::participant_inbox::HostOperation::Attach(old.clone()),
            )
            .await
            .unwrap();
        let mut send = Invoke::new(
            format!("send-{index}"),
            "structure.message.send",
            scope,
            json!({"conversation_id":"c".repeat(43),"reply_to":null,"reply_address":null,"recipients":[{"mailbox_id":mailbox["mailbox_id"],"membership_id":mailbox["membership_id"]}],"content":{"mode":"WORKSPACE_E2EE"}}),
        );
        send.plaintext_message = Some("Synthetic rebind private body".into());
        let sent = client.invoke(send, Duration::from_secs(10)).await.unwrap();
        assert!(sent.is_terminal(), "{sent:?}");
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let s = watch.next().await.unwrap();
                assert_ne!(s.state, "BLOCKED", "{s:?}");
                if !s.items.is_empty() {
                    break;
                }
            }
        })
        .await
        .unwrap();
        // Graceful stop: the explicit job must find disabled subscriptions.
        watch.stop().await.unwrap();
        watches.push(options);
    }
    client.close().await.unwrap();
    let identity = KernelIdentity::open(&cfg.identity_path).unwrap();
    let mut inbox = InboxStore::open_local(
        &cfg.state_directory,
        &identity,
        &crate::transport::canonical_lifecycle_origin(&cfg.origin, true).unwrap(),
    )
    .unwrap();
    let mut originals = Vec::new();
    for options in &watches {
        let due = inbox.host_due("program:worker", options, 32).unwrap();
        let item = due.first().expect("message available for original host");
        let call=inbox.host_begin(&identity,"program:worker",options,item,json!({"message_id":item.delivery_id,"rendered_text":"Synthetic original host input"})).unwrap().unwrap();
        inbox
            .host_finish(
                &identity,
                "program:worker",
                options,
                &call,
                HostOutcome::Unknown {
                    code: "HOST_ACK_UNKNOWN".into(),
                },
            )
            .unwrap();
        originals.push(
            json!({"call_id":call.call_id,"frame_digest":call.frame_digest,"scope":call.scope}),
        );
    }
    drop(inbox);
    write_private(
        &root.join("originals.json"),
        &serde_json::to_vec(&originals).unwrap(),
    )
    .unwrap();
    let runtime = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: root.join("runtime"),
        engines: vec![EngineConfig {
            name: "one".into(),
            origin: cfg.origin,
            expected_actor: cfg.expected_actor,
            authority: cfg.authority,
            identity_path: cfg.identity_path,
            state_directory: cfg.state_directory,
            journal_path: Some(cfg.journal_path),
            allow_loopback_http: true,
            transport: cfg.transport,
            max_inflight: cfg.max_inflight,
            max_pending: cfg.max_pending,
            max_stored_bytes: cfg.max_stored_bytes,
            migration_sources: vec![],
        }],
        clients: vec![ClientConfig {
            name: "worker".into(),
            engine: "one".into(),
            capability: Capability::owner(),
        }],
        hosts: vec![HostConfig {
            name: "selected".into(),
            adapter: json!({"kind":"agy-app","agentapi_path":std::env::current_exe().unwrap(),"conversation_id":format!("old-{}",root.display()),"inbox_directory":root}),
            subscriptions: watches
                .iter()
                .map(|watch| HostSubscription {
                    client: "worker".into(),
                    watch: watch.clone(),
                })
                .collect(),
        }],
    };
    create_private_state_directory(&runtime.state_directory).unwrap();
    let path = root.join("runtime.json");
    write_private(&path, &serde_json::to_vec(&runtime).unwrap()).unwrap();
    let request = HostRebindRequest {
        format: "peerwork.host-rebind.v1".into(),
        operation_id: "move-session".into(),
        engine: "one".into(),
        host: "selected".into(),
        adapter: json!({"kind":"agy-app","agentapi_path":std::env::current_exe().unwrap(),"conversation_id":format!("new-{}",root.display()),"inbox_directory":root}),
    };
    (runtime, path, request, watches)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and service fixture"]
async fn public_job_resumes_each_commit_boundary_and_preserves_original_unknown_calls() {
    let service = Service::start();
    for fault in [
        "FENCED",
        "CLAIM_FROZEN",
        "CLAIM_CONFIRMED_BEFORE_SAVE",
        "LOCAL_COMMITTED_BEFORE_SAVE",
        "HOST_PIN_COMMITTED",
        "CONFIG_COMMITTED",
        "OWNER_COMPLETED",
    ] {
        let root = crate::test_support::protected_test_dir();
        let (cfg, path, request, watches) = setup(root.path(), &service).await;
        let before_identity = std::fs::read(&cfg.engines[0].identity_path).unwrap();
        let p = path.clone();
        let r = request.clone();
        let stage = fault.to_owned();
        let e = tokio::task::spawn_blocking(move || {
            rebind_with(&p, r, |at| {
                if at == stage {
                    Err(error("SYNTHETIC_INTERRUPTION"))
                } else {
                    Ok(())
                }
            })
        })
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(e.code, "SYNTHETIC_INTERRUPTION", "{fault}");
        if fault != "OWNER_COMPLETED" {
            let e = ParticipantClient::open(cfg.engines[0].participant_config())
                .await
                .err()
                .unwrap();
            assert_eq!(
                e.code, "OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION",
                "{fault}"
            );
        }
        let ready = rebind_host(&path, request.clone()).await.unwrap();
        assert_eq!(ready["state"], "HOST_REBIND_READY", "{fault}");
        assert_eq!(ready["scopes"], 2);
        assert_eq!(
            std::fs::read(&cfg.engines[0].identity_path).unwrap(),
            before_identity
        );
        let identity = KernelIdentity::open(&cfg.engines[0].identity_path).unwrap();
        let origin =
            crate::transport::canonical_lifecycle_origin(&cfg.engines[0].origin, true).unwrap();
        let inbox =
            InboxStore::open_local(&cfg.engines[0].state_directory, &identity, &origin).unwrap();
        let originals: Vec<Value> =
            serde_json::from_slice(&std::fs::read(root.path().join("originals.json")).unwrap())
                .unwrap();
        for (index, old) in watches.iter().enumerate() {
            let pins = inbox
                .pins(&old.workspace_id, &old.mailbox_id)
                .unwrap()
                .unwrap();
            assert_eq!(pins.binding_version, 2);
            assert_eq!(pins.epoch, 2, "no duplicate replacement after {fault}");
            let call = inbox
                .host_original_call(
                    &identity,
                    "program:worker",
                    old,
                    originals[index]["call_id"].as_str().unwrap(),
                )
                .unwrap();
            assert_eq!(call.state, "RESULT_UNKNOWN");
            assert_eq!(call.scope, originals[index]["scope"]);
            assert_eq!(call.frame_digest, originals[index]["frame_digest"]);
            assert!(pins.after_sequence >= 1);
        }
        drop(inbox);
        if fault == "FENCED" {
            let runtime: RuntimeConfig =
                serde_json::from_value(private_json(&path, 65536).unwrap()).unwrap();
            let cancel = KernelCancellationToken::new();
            let stop = cancel.clone();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let running = tokio::spawn(crate::communication_runtime::serve(runtime, stop, tx));
            let endpoint = rx.await.unwrap().unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let status = crate::communication_runtime::call(
                        &endpoint.admin_endpoint,
                        json!({"method":"status"}),
                    )
                    .await
                    .unwrap();
                    assert_ne!(status["value"]["hosts"][0]["state"], "BLOCKED", "{status}");
                    if status["value"]["hosts"][0]["state"] == "HOST_ATTACHED" {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            cancel.cancel();
            running.await.unwrap().unwrap();
        }
        let active = ParticipantClient::open(cfg.engines[0].participant_config())
            .await
            .unwrap();
        active
            .invoke(
                Invoke::new(
                    "later-local-write",
                    "structure.workspace.create",
                    Scope::default(),
                    json!({"name":"Later operation"}),
                ),
                Duration::ZERO,
            )
            .await
            .unwrap();
        let edited =
            serde_json::from_value::<RuntimeConfig>(private_json(&path, 65536).unwrap()).unwrap();
        let mut edited = serde_json::to_value(edited).unwrap();
        edited["hosts"][0]["name"] = json!("selected");
        edited["clients"][0]["name"] = json!("later-worker");
        crate::communication_bridge::replace_descriptor(&path, &edited).unwrap();
        assert_eq!(
            rebind_host(&path, request).await.unwrap()["state"],
            "HOST_REBIND_READY"
        );
        assert_eq!(
            private_json(&path, 65536).unwrap()["clients"][0]["name"],
            "later-worker"
        );
        assert_eq!(
            active
                .operation("later-local-write")
                .await
                .unwrap()
                .operation_id,
            "later-local-write"
        );
        active.close().await.unwrap();
    }
    assert_eq!(service.counts().await["journal_reads"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL, service fixture and rebuilt native CLI"]
async fn installed_cli_reconciles_lost_committed_claim_response_without_new_generation() {
    let cli =
        PathBuf::from(std::env::var("PEERWORK_PARTICIPANT_CLI").expect("explicit current CLI"));
    let root = crate::test_support::protected_test_dir();
    let service = Service::start();
    let (cfg, path, request, watches) = setup(root.path(), &service).await;
    let input = root.path().join("request.json");
    write_private(&input, &serde_json::to_vec(&request).unwrap()).unwrap();
    service
        .config(json!({"drop_action":"structure.mailbox.claim"}))
        .await;
    let run = |cli: PathBuf, path: PathBuf, input: PathBuf| async move {
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(cli)
                .args(["runtime", "rebind-host"])
                .arg(path)
                .arg(input)
                .output()
                .unwrap()
        })
        .await
        .unwrap()
    };
    let first = run(cli.clone(), path.clone(), input.clone()).await;
    assert!(!first.status.success());
    let refusal: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(refusal["error"]["effect_certainty"], "UNKNOWN", "{refusal}");
    assert_eq!(
        refusal["error"]["recovery"],
        "RESUME_SAME_HOST_REBIND_OPERATION"
    );
    let before = service.counts().await;
    let abort = HostRebindRecoveryRequest {
        format: "peerwork.host-rebind-recovery.v1".into(),
        decision_id: "unknown-abort".into(),
        action: HostRebindRecoveryAction::Abort,
    };
    assert_eq!(
        recover_host_rebind(&path, request.clone(), abort)
            .await
            .unwrap_err()
            .code,
        "HOST_REBIND_UNKNOWN_CLAIM_RESUME_ORIGINAL"
    );
    let retry = HostRebindRecoveryRequest {
        format: "peerwork.host-rebind-recovery.v1".into(),
        decision_id: "unknown-retry".into(),
        action: HostRebindRecoveryAction::RetryRejected,
    };
    assert_eq!(
        recover_host_rebind(&path, request.clone(), retry)
            .await
            .unwrap_err()
            .code,
        "HOST_REBIND_NO_VERIFIED_REJECTED_CLAIM_RESUME_ORIGINAL"
    );
    assert_eq!(
        service.counts().await["commands"],
        before["commands"],
        "uncertainty recovery selection performs no submission"
    );
    service.config(json!({"offline":false})).await;
    let second = run(cli, path.clone(), input).await;
    assert!(
        second.status.success(),
        "{} {}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&second.stdout).unwrap()["state"],
        "HOST_REBIND_READY"
    );
    let identity = KernelIdentity::open(&cfg.engines[0].identity_path).unwrap();
    let inbox = InboxStore::open_local(
        &cfg.engines[0].state_directory,
        &identity,
        &crate::transport::canonical_lifecycle_origin(&cfg.engines[0].origin, true).unwrap(),
    )
    .unwrap();
    for w in watches {
        let pins = inbox.pins(&w.workspace_id, &w.mailbox_id).unwrap().unwrap();
        assert_eq!(pins.epoch, 2);
        assert_eq!(pins.binding_version, 2);
    }
    let counts = service.counts().await;
    assert_eq!(counts["dropped"], 1);
    assert_eq!(counts["journal_reads"], 0);
    let replacements = counts["claim_commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["replace"] == true)
        .map(|v| v["command_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        replacements.len(),
        2,
        "one fixed replacement per selected mailbox"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and service fixture"]
async fn live_runtime_and_changed_config_are_refused_without_overwrite() {
    let root = crate::test_support::protected_test_dir();
    let service = Service::start();
    let (cfg, path, request, _) = setup(root.path(), &service).await;
    let owner = SecureStateStore::open(&cfg.state_directory.join("runtime.state")).unwrap();
    let e = rebind_host(&path, request.clone()).await.unwrap_err();
    assert_eq!(e.code, "HOST_REBIND_STOP_RUNTIME_FIRST");
    drop(owner);
    let p = path.clone();
    let r = request.clone();
    tokio::task::spawn_blocking(move || {
        rebind_with(&p, r, |at| {
            if at == "PREPARED" {
                Err(error("SYNTHETIC_INTERRUPTION"))
            } else {
                Ok(())
            }
        })
    })
    .await
    .unwrap()
    .unwrap_err();
    let mut edited = private_json(&path, 65536).unwrap();
    edited["clients"][0]["name"] = json!("edited");
    crate::communication_bridge::replace_descriptor(&path, &edited).unwrap();
    assert_eq!(
        rebind_host(&path, request.clone()).await.unwrap_err().code,
        "HOST_REBIND_CONFIG_CHANGED_RESTORE_ORIGINAL_SELECTION"
    );
    assert_eq!(
        private_json(&path, 65536).unwrap()["clients"][0]["name"],
        "edited"
    );
    let mut other = request;
    other.adapter["conversation_id"] = json!("different");
    assert_eq!(
        rebind_host(&path, other).await.unwrap_err().code,
        "HOST_REBIND_ORIGINAL_SELECTION_REQUIRED"
    );
}

fn decision(id: &str, action: HostRebindRecoveryAction) -> HostRebindRecoveryRequest {
    HostRebindRecoveryRequest {
        format: "peerwork.host-rebind-recovery.v1".into(),
        decision_id: id.into(),
        action,
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and service fixture"]
async fn frozen_unsubmitted_claim_can_abort_and_restore_original_enabled_watch() {
    let root = crate::test_support::protected_test_dir();
    let service = Service::start();
    let (cfg, path, request, watches) = setup(root.path(), &service).await;
    let identity = KernelIdentity::open(&cfg.engines[0].identity_path).unwrap();
    let origin =
        crate::transport::canonical_lifecycle_origin(&cfg.engines[0].origin, true).unwrap();
    let mut inbox =
        InboxStore::open_local(&cfg.engines[0].state_directory, &identity, &origin).unwrap();
    inbox
        .attach_watch(&identity, "program:worker", &watches[0])
        .unwrap();
    drop(inbox);
    let p = path.clone();
    let r = request.clone();
    let err = tokio::task::spawn_blocking(move || {
        rebind_with(&p, r, |at| {
            if at == "CLAIM_FROZEN" {
                Err(error("SYNTHETIC_INTERRUPTION"))
            } else {
                Ok(())
            }
        })
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(err.code, "SYNTHETIC_INTERRUPTION");
    assert_eq!(
        recover_host_rebind(
            &path,
            request,
            decision("abort-before-submission", HostRebindRecoveryAction::Abort)
        )
        .await
        .unwrap()["state"],
        "HOST_REBIND_ABORTED"
    );
    let inbox =
        InboxStore::open_local(&cfg.engines[0].state_directory, &identity, &origin).unwrap();
    assert!(inbox
        .rebind_watch_enabled("program:worker", &watches[0])
        .unwrap());
    assert!(!inbox
        .rebind_watch_enabled("program:worker", &watches[1])
        .unwrap());
    let counts = service.counts().await;
    assert!(counts["claim_commands"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["replace"] != true));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and service fixture"]
async fn signed_refusal_retry_is_explicit_idempotent_and_keeps_partial_commits() {
    let service = Service::start();
    for rejected_index in 0..2 {
        let root = crate::test_support::protected_test_dir();
        let (cfg, path, request, watches) = setup(root.path(), &service).await;
        service
            .config(json!({"reject_next_rebind_mailbox":watches[rejected_index].mailbox_id}))
            .await;
        let rejected = rebind_host(&path, request.clone()).await.unwrap_err();
        assert_eq!(
            rejected.effect_certainty, "REJECTED_NO_EFFECT",
            "{rejected:?}"
        );
        assert_eq!(
            rejected.recovery,
            "EXPLICIT_HOST_REBIND_RECOVERY_DECISION_REQUIRED"
        );
        if rejected_index == 1 {
            assert_eq!(
                recover_host_rebind(
                    &path,
                    request.clone(),
                    decision("abort-partial", HostRebindRecoveryAction::Abort)
                )
                .await
                .unwrap_err()
                .code,
                "HOST_REBIND_COMMITTED_FORWARD_RECOVERY_REQUIRED"
            );
        }
        let p = path.clone();
        let r = request.clone();
        let d = decision(
            "retry-same-selection",
            HostRebindRecoveryAction::RetryRejected,
        );
        let prepared = d.clone();
        let err = tokio::task::spawn_blocking(move || {
            rebind_action(&p, r, Some(prepared), |at| {
                if at == "RETRY_REJECTED_FROZEN" {
                    Err(error("SYNTHETIC_INTERRUPTION"))
                } else {
                    Ok(())
                }
            })
        })
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code, "SYNTHETIC_INTERRUPTION");
        let output = recover_host_rebind(&path, request.clone(), d.clone())
            .await
            .unwrap();
        assert_eq!(output["state"], "HOST_REBIND_READY");
        let before = service.counts().await;
        assert_eq!(
            recover_host_rebind(&path, request.clone(), d)
                .await
                .unwrap()["state"],
            "HOST_REBIND_READY"
        );
        assert_eq!(service.counts().await["commands"], before["commands"]);
        assert_eq!(
            recover_host_rebind(
                &path,
                request,
                decision("retry-same-selection", HostRebindRecoveryAction::Abort)
            )
            .await
            .unwrap_err()
            .code,
            "HOST_REBIND_ORIGINAL_RECOVERY_DECISION_REQUIRED"
        );
        let identity = KernelIdentity::open(&cfg.engines[0].identity_path).unwrap();
        let inbox = InboxStore::open_local(
            &cfg.engines[0].state_directory,
            &identity,
            &crate::transport::canonical_lifecycle_origin(&cfg.engines[0].origin, true).unwrap(),
        )
        .unwrap();
        for (index, w) in watches.iter().enumerate() {
            let pins = inbox.pins(&w.workspace_id, &w.mailbox_id).unwrap().unwrap();
            assert_eq!(pins.epoch, if index == rejected_index { 3 } else { 2 });
            assert_eq!(pins.binding_version, 2);
        }
    }
    assert_eq!(service.counts().await["journal_reads"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and service fixture"]
async fn abort_restores_only_proven_original_state_and_resumes_each_abort_boundary() {
    let service = Service::start();
    for fault in [
        "ABORT_FROZEN",
        "ABORT_WATCH_RESTORED",
        "ABORT_OWNER_COMPLETED",
    ] {
        let root = crate::test_support::protected_test_dir();
        let (cfg, path, request, watches) = setup(root.path(), &service).await;
        service
            .config(json!({"reject_next_rebind_mailbox":watches[0].mailbox_id}))
            .await;
        rebind_host(&path, request.clone()).await.unwrap_err();
        let original = std::fs::read(&path).unwrap();
        let identity_bytes = std::fs::read(&cfg.engines[0].identity_path).unwrap();
        let d = decision("abort-known-no-effect", HostRebindRecoveryAction::Abort);
        let p = path.clone();
        let r = request.clone();
        let initial = d.clone();
        let stage = fault.to_owned();
        let err = tokio::task::spawn_blocking(move || {
            rebind_action(&p, r, Some(initial), |at| {
                if at == stage {
                    Err(error("SYNTHETIC_INTERRUPTION"))
                } else {
                    Ok(())
                }
            })
        })
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.code, "SYNTHETIC_INTERRUPTION");
        let active = if fault == "ABORT_OWNER_COMPLETED" {
            Some(
                ParticipantClient::open(cfg.engines[0].participant_config())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        assert_eq!(
            recover_host_rebind(&path, request.clone(), d.clone())
                .await
                .unwrap()["state"],
            "HOST_REBIND_ABORTED"
        );
        assert_eq!(
            rebind_host(&path, request.clone()).await.unwrap()["state"],
            "HOST_REBIND_ABORTED"
        );
        assert_eq!(
            recover_host_rebind(
                &path,
                request,
                decision("new-retry", HostRebindRecoveryAction::RetryRejected)
            )
            .await
            .unwrap_err()
            .code,
            "HOST_REBIND_ABORTED_NEW_JOB_REQUIRED"
        );
        if let Some(active) = active {
            active.close().await.unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read(&cfg.engines[0].identity_path).unwrap(),
            identity_bytes
        );
        let identity = KernelIdentity::open(&cfg.engines[0].identity_path).unwrap();
        let inbox = InboxStore::open_local(
            &cfg.engines[0].state_directory,
            &identity,
            &crate::transport::canonical_lifecycle_origin(&cfg.engines[0].origin, true).unwrap(),
        )
        .unwrap();
        for w in &watches {
            let pins = inbox.pins(&w.workspace_id, &w.mailbox_id).unwrap().unwrap();
            assert_eq!(pins.binding_version, 1);
            assert_eq!(pins.destination_digest, w.host_destination.clone().unwrap());
            assert!(pins.after_sequence >= 1);
            assert!(!inbox.rebind_watch_enabled("program:worker", w).unwrap());
        }
    }
    assert_eq!(service.counts().await["journal_reads"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL, service fixture and rebuilt native CLI"]
async fn installed_cli_abort_checks_signed_receipt_and_rejects_tampering() {
    let cli =
        PathBuf::from(std::env::var("PEERWORK_PARTICIPANT_CLI").expect("explicit current CLI"));
    let service = Service::start();
    let root = crate::test_support::protected_test_dir();
    let (cfg, path, request, watches) = setup(root.path(), &service).await;
    service
        .config(json!({"reject_next_rebind_mailbox":watches[0].mailbox_id}))
        .await;
    rebind_host(&path, request.clone()).await.unwrap_err();
    let input = root.path().join("request.json");
    let recovery = root.path().join("recovery.json");
    write_private(&input, &serde_json::to_vec(&request).unwrap()).unwrap();
    write_private(
        &recovery,
        &serde_json::to_vec(&decision("cli-abort", HostRebindRecoveryAction::Abort)).unwrap(),
    )
    .unwrap();
    let p = path.clone();
    let r = input.clone();
    let d = recovery.clone();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(cli)
            .args(["runtime", "recover-host-rebind"])
            .arg(p)
            .arg(r)
            .arg(d)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["state"],
        "HOST_REBIND_ABORTED"
    );
    let active = ParticipantClient::open(cfg.engines[0].participant_config())
        .await
        .unwrap();
    active.close().await.unwrap();
    // Separate original job: a tampered local receipt never proves no effect.
    let other = crate::test_support::protected_test_dir();
    let (cfg, path, request, watches) = setup(other.path(), &service).await;
    service
        .config(json!({"reject_next_rebind_mailbox":watches[0].mailbox_id}))
        .await;
    rebind_host(&path, request.clone()).await.unwrap_err();
    let counts = service.counts().await;
    let id = counts["claim_commands"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|c| c["replace"] == true)
        .unwrap()["command_id"]
        .as_str()
        .unwrap();
    let db = rusqlite::Connection::open(cfg.engines[0].participant_config().journal_path).unwrap();
    db.execute(
        "UPDATE accepted_responses SET response_wire=x'00' WHERE command_id=?1",
        [id],
    )
    .unwrap();
    drop(db);
    for action in [
        HostRebindRecoveryAction::Abort,
        HostRebindRecoveryAction::RetryRejected,
    ] {
        assert_eq!(
            recover_host_rebind(&path, request.clone(), decision("tampered", action))
                .await
                .unwrap_err()
                .code,
            "HOST_REBIND_ORIGINAL_JOURNAL_INVALID"
        );
    }
    assert_eq!(
        ParticipantClient::open(cfg.engines[0].participant_config())
            .await
            .err()
            .unwrap()
            .code,
        "OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION"
    );
}
