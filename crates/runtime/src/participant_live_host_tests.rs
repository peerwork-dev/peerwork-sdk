//! Explicit existing-session qualification. Never run against a discovered or
//! guessed host: the operator supplies one protected host configuration. The
//! service, identities, body keys and workspace are synthetic and isolated.
use crate::{
    agent_tools::{AgentProfile, AgentRequest, AgentTools, Contact, MailScope},
    communication_bridge::{self, BridgeConfig, BridgeGrant},
    communication_runtime::{self, ClientConfig, EngineConfig, RuntimeClient, RuntimeConfig},
    kernel_identity::KernelIdentity,
    participant::http_tests::{
        configuration, install_synthetic_key, mutate, selected, structure, Service,
    },
    participant::{Capability, Invoke, ParticipantClient, ParticipantConfig, Scope, WatchOptions},
    participant_dispatch::{HostConfig, HostSubscription},
    participant_inbox::HostBinding,
    secure_state::create_private_state_directory,
    KernelCancellationToken,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

/// A measured SDK/service baseline, separate from live model/host behavior.
/// Every accepted sample remains in the report; this is not an IM release gate
/// when compiled in an unoptimized test profile or on an unqualified machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit synthetic PostgreSQL, compiled service and a protected measurement report path"]
async fn two_program_warm_mail_latency_and_request_counts() {
    let report = PathBuf::from(
        std::env::var("PEERWORK_PROGRAM_LATENCY_REPORT").expect("explicit protected result path"),
    );
    assert!(report.is_absolute() && !report.exists());
    let root = crate::test_support::protected_test_dir();
    for name in ["master", "worker"] {
        create_private_state_directory(&root.path().join(name)).unwrap();
    }
    let service = Service::start();
    let master_config = configuration(&root.path().join("master"), &service.origin);
    let worker_config = configuration(&root.path().join("worker"), &service.origin);
    let master = ParticipantClient::open(master_config.clone())
        .await
        .unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let ws = mutate(
        &master,
        "latency-create",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Native two-program latency baseline"}),
    )
    .await["workspace_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&master, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "latency-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&master.invoke(join, Duration::from_secs(5)).await.unwrap());
    let box_=mutate(&master,"latency-worker-mail","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    mutate(&master,"latency-master-send","structure.communication.grant.set",&scope,json!({"actor_id":master_config.expected_actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":false})).await;
    let key = install_synthetic_key(&master_config, &ws, &[94u8; 32], None);
    install_synthetic_key(&worker_config, &ws, &[94u8; 32], None);
    mutate(
        &master,
        "latency-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let options = watch(&mail_scope(&ws, &box_), "program-latency", None);
    let mut receiver = worker.watch(options.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = receiver.next().await.unwrap();
            assert_ne!(snapshot.state, "BLOCKED", "{snapshot:?}");
            if snapshot.receiver_link_verified {
                return;
            }
        }
    })
    .await
    .unwrap();
    let before = service.counts().await;
    let mut samples = Vec::new();
    // One separately reported first send followed by32 warm eligible samples.
    for index in 0..33u64 {
        let text = format!("Synthetic program latency sample {index}");
        let mut request = Invoke::new(
            format!("latency-{index}"),
            "structure.message.send",
            scope.clone(),
            json!({
            "conversation_id":"V".repeat(43),"reply_to":null,"reply_address":null,
            "recipients":[{"mailbox_id":box_["mailbox_id"],"membership_id":box_["membership_id"]}],"content":{"mode":"WORKSPACE_E2EE"}}),
        );
        request.plaintext_message = Some(text.clone());
        let started = Instant::now();
        let accepted = structure(
            &master
                .invoke(request, Duration::from_secs(5))
                .await
                .unwrap(),
        );
        let accepted_ms = started.elapsed().as_secs_f64() * 1000.;
        let item = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let snapshot = receiver.next().await.unwrap();
                assert_ne!(snapshot.state, "BLOCKED", "{snapshot:?}");
                if let Some(item) = snapshot.items.iter().find(|item| {
                    item["envelope"]["message"]["message_id"] == accepted["message_id"]
                }) {
                    assert_eq!(item["opened_message"]["text"], text);
                    return item.clone();
                }
            }
        })
        .await
        .expect("accepted sample was not received");
        samples.push(json!({"index":index,"accepted_ms":accepted_ms,"receiver_observed_ms":started.elapsed().as_secs_f64()*1000.}));
        worker
            .consume(
                &options,
                vec![crate::participant::DeliveryReference {
                    sequence: item["sequence"].as_u64().unwrap(),
                    delivery_id: item["delivery_id"].as_str().unwrap().into(),
                }],
            )
            .await
            .unwrap();
    }
    let after = service.counts().await;
    fn distribution(samples: &[Value], name: &str) -> Value {
        let mut values = samples
            .iter()
            .map(|v| v[name].as_f64().unwrap())
            .collect::<Vec<_>>();
        values.sort_by(f64::total_cmp);
        let quantile = |q: f64| {
            values[((values.len() as f64 * q).ceil() as usize)
                .saturating_sub(1)
                .min(values.len() - 1)]
        };
        json!({"p50_ms":quantile(0.5),"p95_ms":quantile(0.95),"p99_ms":quantile(0.99),"max_ms":values[values.len()-1]})
    }
    let result = json!({"format":"peerwork.program-latency-observation.v1","state":"MEASURED","participants":2,
        "samples":samples,"warm_samples":32,"first_send":samples[0],"warm_accepted":distribution(&samples[1..],"accepted_ms"),
        "warm_receiver_observed":distribution(&samples[1..],"receiver_observed_ms"),"build_profile":if cfg!(debug_assertions){"unoptimized-test"}else{"optimized"},
        "service":"local synthetic PostgreSQL/HTTP","transport":"signed SSE; E2EE bodies","host_or_model":"NOT_EXERCISED",
        "timing_basis":"single observer monotonic clock; receiver measurements include observer scheduling",
        "send_http_count":after["actions"]["structure.message.send"].as_u64().unwrap_or(0)-before["actions"]["structure.message.send"].as_u64().unwrap_or(0),
        "discovery_http_count":after["discovery"].as_u64().unwrap_or(0)-before["discovery"].as_u64().unwrap_or(0),
        "context_http_count":after["context"].as_u64().unwrap_or(0)-before["context"].as_u64().unwrap_or(0),
        "journal_reads":after["journal_reads"],"release_gate_qualified":false});
    write_report(&report, &result);
    println!("PROGRAM_LATENCY_RESULT {result}");
    master.close().await.unwrap();
    worker.close().await.unwrap();
    assert_eq!(result["send_http_count"], 33);
    assert_eq!(result["journal_reads"], 0);
}

fn engine(name: &str, c: &ParticipantConfig) -> EngineConfig {
    EngineConfig {
        name: name.into(),
        origin: c.origin.clone(),
        expected_actor: c.expected_actor.clone(),
        authority: c.authority.clone(),
        identity_path: c.identity_path.clone(),
        state_directory: c.state_directory.clone(),
        journal_path: Some(c.journal_path.clone()),
        allow_loopback_http: true,
        transport: c.transport.clone(),
        max_inflight: 4,
        max_pending: 32,
        max_stored_bytes: 32 * 1024 * 1024,
        migration_sources: Vec::new(),
    }
}
fn mail_scope(ws: &str, b: &Value) -> MailScope {
    MailScope {
        workspace_id: ws.into(),
        mailbox_id: b["mailbox_id"].as_str().unwrap().into(),
        membership_id: b["membership_id"].as_str().unwrap().into(),
    }
}
fn watch(scope: &MailScope, consumer: &str, destination: Option<String>) -> WatchOptions {
    WatchOptions {
        workspace_id: scope.workspace_id.clone(),
        mailbox_id: scope.mailbox_id.clone(),
        membership_id: scope.membership_id.clone(),
        consumer_id: consumer.into(),
        host_destination: destination,
    }
}
async fn receiver_ready(client: &RuntimeClient, options: &WatchOptions) {
    client
        .call(json!({"method":"watch","options":options}))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = client
                .call(json!({"method":"watch_next","options":options,"wait_ms":5000}))
                .await
                .unwrap();
            assert_ne!(snapshot["state"], "BLOCKED", "{snapshot}");
            if snapshot["receiver_link_verified"] == true {
                return;
            }
        }
    })
    .await
    .expect("receiver path was not verified");
}
fn write_report(path: &std::path::Path, value: &Value) {
    // The explicit report parent is private; no identities, credentials,
    // arbitrary peer bodies or host transcripts are included in this report.
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly registered live host, isolated PostgreSQL and a real Agent reply through native CLI/MCP"]
async fn program_master_existing_session_and_native_agent_reply() {
    let host_path = PathBuf::from(
        std::env::var("PEERWORK_LIVE_HOST_CONFIG")
            .expect("explicit protected host configuration required"),
    );
    let host = crate::communication_store::private_json(&host_path, 65536).unwrap();
    let root = PathBuf::from(
        std::env::var("PEERWORK_LIVE_HOST_STATE_DIR")
            .expect("explicit empty protected fixture root required"),
    );
    assert!(
        root.is_absolute() && !root.exists(),
        "preserve/reconcile the original run; never restart into its state root"
    );
    create_private_state_directory(&root).unwrap();
    let report = PathBuf::from(
        std::env::var("PEERWORK_LIVE_HOST_REPORT").expect("explicit result path required"),
    );
    create_private_state_directory(report.parent().unwrap()).unwrap();
    assert!(
        !report.exists(),
        "a qualification result is immutable; inspect the original run"
    );
    let nonce =
        std::env::var("PEERWORK_LIVE_HOST_NONCE").expect("explicit unique test nonce required");
    assert!(
        !nonce.is_empty()
            && nonce.len() <= 64
            && nonce
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    );
    let service = Service::start();
    for name in ["master", "worker"] {
        create_private_state_directory(&root.join(name)).unwrap();
    }
    let master_config = configuration(&root.join("master"), &service.origin);
    let worker_config = configuration(&root.join("worker"), &service.origin);
    let master = ParticipantClient::open(master_config.clone())
        .await
        .unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let ws = mutate(
        &master,
        "live-create",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Explicit native live-host qualification"}),
    )
    .await["workspace_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&master, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "live-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&master.invoke(join, Duration::from_secs(5)).await.unwrap());
    let master_box=mutate(&master,"live-master-mail","structure.communication.grant.set",&scope,json!({"actor_id":master_config.expected_actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&master,"live-worker-mail","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&master_config, &ws, &[93u8; 32], None);
    install_synthetic_key(&worker_config, &ws, &[93u8; 32], None);
    mutate(
        &master,
        "live-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    master.close().await.unwrap();
    worker.close().await.unwrap();

    let worker_identity = KernelIdentity::open(&worker_config.identity_path).unwrap();
    let bridge_config = BridgeConfig {
        format: "peerwork.host-bridge.v1".into(),
        state_directory: root.join("bridge"),
        host,
        bindings: vec![BridgeGrant {
            expected_origin: worker_config.origin.clone(),
            expected_actor: worker_config.expected_actor.clone(),
            expected_key_id: worker_identity.key_id().into(),
            namespace: "program:worker".into(),
            workspace_id: ws.clone(),
            mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
            membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        }],
    };
    crate::communication_host::write_private(
        &root.join("bridge.json"),
        &serde_json::to_vec(&bridge_config).unwrap(),
    )
    .unwrap();
    let bridge_stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let bridge = tokio::spawn(communication_bridge::serve(
        bridge_config,
        bridge_stop.clone(),
        tx,
    ));
    let bridge_ready = rx.await.unwrap().unwrap();
    let destination = HostBinding::new(bridge_ready.adapter["destination"].clone()).unwrap();
    let master_scope = mail_scope(&ws, &master_box);
    let worker_scope = mail_scope(&ws, &worker_box);
    let master_watch = watch(&master_scope, "master", None);
    let worker_watch = watch(&worker_scope, "worker", Some(destination.digest));
    let mut cap = Capability::owner();
    cap.allow_root = false;
    cap.workspace_ids = Some([ws.clone()].into());
    cap.operations = [
        "structure.message.send",
        "structure.message.receipts.read",
        "structure.mailbox.get",
        "structure.mailbox.claim",
        "structure.mailbox.pulse",
        "structure.mailbox.ack",
        "structure.mailbox.report",
        "structure.mailbox.inbox.read",
    ]
    .map(str::to_owned)
    .into();
    let cfg = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: root.join("runtime"),
        engines: vec![
            engine("master", &master_config),
            engine("worker", &worker_config),
        ],
        clients: vec![
            ClientConfig {
                name: "master".into(),
                engine: "master".into(),
                capability: cap.clone(),
            },
            ClientConfig {
                name: "worker".into(),
                engine: "worker".into(),
                capability: cap,
            },
        ],
        hosts: vec![HostConfig {
            name: "explicit-existing-worker".into(),
            adapter: bridge_ready.adapter,
            subscriptions: vec![HostSubscription {
                client: "worker".into(),
                watch: worker_watch.clone(),
            }],
        }],
    };
    crate::communication_host::write_private(
        &root.join("runtime.json"),
        &serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    let runtime_stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let runtime = tokio::spawn(communication_runtime::serve(cfg, runtime_stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let master_client = RuntimeClient::connect(
        ready.client_endpoints["master"].clone(),
        &service.origin,
        &master_config.expected_actor,
    )
    .await
    .unwrap();
    let worker_client = RuntimeClient::connect(
        ready.client_endpoints["worker"].clone(),
        &service.origin,
        &worker_config.expected_actor,
    )
    .await
    .unwrap();
    receiver_ready(&master_client, &master_watch).await;
    receiver_ready(&worker_client, &worker_watch).await;
    let profile = |actor: &str, name: &str, s: MailScope, contacts| AgentProfile {
        format: "peerwork.agent-profile.v1".into(),
        endpoint_path: ready.client_endpoints[name].clone(),
        expected_origin: service.origin.clone(),
        expected_actor: actor.into(),
        scopes: BTreeMap::from([("live".into(), s)]),
        contacts,
        protocols: BTreeMap::new(),
    };
    let master_profile = profile(
        &master_config.expected_actor,
        "master",
        master_scope,
        BTreeMap::from([(
            "worker".into(),
            Contact {
                scope: "live".into(),
                recipient: peerwork_core::communication::MailboxAddress {
                    mailbox_id: worker_scope.mailbox_id.clone(),
                    membership_id: worker_scope.membership_id.clone(),
                },
            },
        )]),
    );
    let worker_profile = profile(
        &worker_config.expected_actor,
        "worker",
        worker_scope,
        BTreeMap::new(),
    );
    let worker_profile_path = root.join("worker-agent.json");
    crate::communication_host::write_private(
        &worker_profile_path,
        &serde_json::to_vec(&worker_profile).unwrap(),
    )
    .unwrap();
    let master = AgentTools::open(master_profile).await.unwrap();
    let before = service.counts().await;
    let mut result = json!({"state":"READY","format":"peerwork.live-host-qualification.v1","nonce":nonce,
        "worker_profile":worker_profile_path,"expected_reply":format!("PONG {nonce}"),"fresh_agent_first_use":false,
        "service":"LOCAL_SYNTHETIC_POSTGRES_HTTP","host":"EXPLICIT_EXISTING_SESSION","body_mode":"WORKSPACE_E2EE",
        "timing_basis":"one observer monotonic clock; delivery observations are upper bounds, not isolated internal phase spans"});
    write_report(&report, &result);
    println!("LIVE_HOST_READY {}", result);
    let started = Instant::now();
    let sent=master.call(AgentRequest::parse("send",json!({"contact":"worker","operation_id":format!("ping-{nonce}"),"text":format!("PING {nonce}. Native Peerwork live-host qualification. Please reply with exactly PONG {nonce} using the native Peerwork reply tool for this verified inbox item."),"wait_ms":5000})).unwrap()).await.unwrap();
    result["accepted_observed_ms"] = json!(started.elapsed().as_millis());
    result["send_state"] = sent["state"].clone();
    result["original_operation_id"] = json!(format!("ping-{nonce}"));
    write_report(&report, &result);
    assert_eq!(sent["state"], "ACCEPTED", "{sent}");
    let message_id = sent["result"]["structure"]["message_id"].clone();
    let item = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let page = worker_client
                .call(json!({"method":"watch_next","options":worker_watch,"wait_ms":5000}))
                .await
                .unwrap();
            assert_ne!(page["state"], "BLOCKED", "{page}");
            if let Some(items) = page["items"].as_array() {
                if let Some(item) = items.first() {
                    return json!({"sequence":item["sequence"],"delivery_id":item["delivery_id"]});
                }
            }
        }
    })
    .await
    .expect("receiver did not durably store the accepted mail");
    result["receiver_store_observed_ms"] = json!(started.elapsed().as_millis());
    result["inbox_item"] = item.clone();
    write_report(&report, &result);
    println!(
        "LIVE_HOST_DELIVERY {}",
        json!({"nonce":nonce,"worker_profile":worker_profile_path,"item":item,"accepted_observed_ms":result["accepted_observed_ms"],"receiver_store_observed_ms":result["receiver_store_observed_ms"]})
    );
    let observed = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let arrival = master
                .call(
                    AgentRequest::parse("wait", json!({"scope":"live","wait_ms":30000,"limit":8}))
                        .unwrap(),
                )
                .await
                .unwrap();
            if let Some(items) = arrival["items"].as_array() {
                for item in items {
                    if item["message"]["reply_to"] == message_id
                        && item["message"]["text"] == format!("PONG {nonce}")
                    {
                        return item.clone();
                    }
                }
            }
        }
    })
    .await;
    result["reply_observed_ms"] = json!(started.elapsed().as_millis());
    let local = worker_client
        .call(json!({"method":"delivery_status","options":worker_watch,"item":item}))
        .await
        .unwrap();
    result["host_fact"] = local["host"].clone();
    result["model_reply_observed"] = json!(observed.is_ok());
    let after = service.counts().await;
    result["message_send_http_count"] = json!(
        after["actions"]["structure.message.send"]
            .as_u64()
            .unwrap_or(0)
            - before["actions"]["structure.message.send"]
                .as_u64()
                .unwrap_or(0)
    );
    result["journal_reads"] = after["journal_reads"].clone();
    result["state"] = json!(if observed.is_ok() && local["host"] == "HOST_ACCEPTED" {
        "COMPLETED"
    } else {
        "NOT_QUALIFIED"
    });
    runtime_stop.cancel();
    runtime.await.unwrap().unwrap();
    bridge_stop.cancel();
    bridge.await.unwrap().unwrap();
    result["owned_runtime_and_bridge_stopped"] = json!(true);
    result["state_retained"] = json!(true);
    write_report(&report, &result);
    println!("LIVE_HOST_RESULT {}", result);
    assert_eq!(
        result["state"], "COMPLETED",
        "inspect retained qualification result; do not resend original input"
    );
}
