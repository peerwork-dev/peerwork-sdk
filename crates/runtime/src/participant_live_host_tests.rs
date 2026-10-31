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

/// Concurrent ring traffic tests contention between independent identities in
/// one workspace. Every accepted message must be verified and opened; no model
/// or host latency is inferred from this local service/SDK measurement.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires explicit synthetic PostgreSQL, compiled service and protected matrix report path"]
async fn one_to_eight_program_concurrent_mail_latency() {
    let report = PathBuf::from(
        std::env::var("PEERWORK_PROGRAM_MATRIX_REPORT").expect("explicit protected result path"),
    );
    assert!(report.is_absolute() && !report.exists());
    let root = crate::test_support::protected_test_dir();
    let service = Service::start();
    let mut cases = Vec::new();
    let sizes = std::env::var("PEERWORK_PROGRAM_MATRIX_CASES")
        .map(|s| {
            s.split(',')
                .map(|s| s.parse::<usize>().unwrap())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|_| vec![1, 2, 4, 8]);
    assert!(!sizes.is_empty() && sizes.iter().all(|s| [1, 2, 4, 8].contains(s)));
    let rounds = std::env::var("PEERWORK_PROGRAM_MATRIX_ROUNDS")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(33);
    assert!((2..=33).contains(&rounds));
    let payload_bytes = std::env::var("PEERWORK_PROGRAM_MATRIX_PAYLOAD_BYTES")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(payload_bytes == 0 || (128..=8192).contains(&payload_bytes));
    let link_rtt_ms = std::env::var("PEERWORK_FIXTURE_LINK_RTT_MS")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(0);
    let phase_diagnostic = std::env::var("PEERWORK_PROGRAM_MATRIX_PHASES").as_deref() == Ok("1");
    for size in sizes {
        let mut configs = Vec::new();
        let mut clients = Vec::new();
        for member in 0..size {
            let dir = root.path().join(format!("case-{size}-member-{member}"));
            create_private_state_directory(&dir).unwrap();
            let config = configuration(&dir, &service.origin);
            clients.push(ParticipantClient::open(config.clone()).await.unwrap());
            configs.push(config);
        }
        let ws = mutate(
            &clients[0],
            "matrix-create",
            "structure.workspace.create",
            &Scope::default(),
            json!({"name":"Synthetic concurrent mail qualification"}),
        )
        .await["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let scope = Scope {
            workspace_id: Some(ws.clone()),
            ..Default::default()
        };
        let mut boxes = Vec::new();
        for member in 0..size {
            let meta = selected(&clients[0], "structure.workspace.get", &scope, json!({})).await;
            let membership = if member == 0 {
                meta["membership"]["membership_id"].clone()
            } else {
                let mut request = Invoke::new(
                    format!("matrix-join-{member}"),
                    "structure.member.set",
                    scope.clone(),
                    json!({"actor_id":configs[member].expected_actor,"state":"ACTIVE","expected_membership_id":null}),
                );
                request.expected_workspace_revision = meta["workspace_revision"].as_u64();
                structure(
                    &clients[0]
                        .invoke(request, Duration::from_secs(5))
                        .await
                        .unwrap(),
                )["membership_id"]
                    .clone()
            };
            boxes.push(mutate(
                &clients[0], &format!("matrix-grant-{member}"), "structure.communication.grant.set", &scope,
                json!({"actor_id":configs[member].expected_actor,"membership_id":membership,"expected_revision":null,"send":true,"receive":true}),
            ).await["mailbox"].clone());
        }
        let mut key = String::new();
        for config in &configs {
            key = install_synthetic_key(config, &ws, &[93u8; 32], None);
        }
        mutate(
            &clients[0],
            "matrix-key",
            "structure.content-key.set",
            &scope,
            json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
        )
        .await;
        let mut receivers = Vec::new();
        let mut options = Vec::new();
        for (member, client) in clients.iter().enumerate() {
            let opt = watch(&mail_scope(&ws, &boxes[member]), "matrix", None);
            let mut receiver = client.watch(opt.clone()).await.unwrap();
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let snapshot = receiver.next().await.unwrap();
                    assert_ne!(snapshot.state, "BLOCKED", "{snapshot:?}");
                    if snapshot.receiver_link_verified {
                        break;
                    }
                }
            })
            .await
            .expect("every receiver must independently verify its link");
            options.push(opt);
            receivers.push(receiver);
        }
        let before = service.counts().await;
        let mut before_metrics = Vec::new();
        for client in &clients {
            before_metrics.push(client.metrics().await.unwrap()["http"].clone());
        }
        let mut samples = Vec::new();
        // First round is reported separately. All32 warm rounds remain eligible.
        for round in 0..rounds {
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(size));
            let round_start = Instant::now();
            let mut jobs = tokio::task::JoinSet::new();
            for (member, mut receiver) in receivers.drain(..).enumerate() {
                let client = clients[member].clone();
                let option = options[member].clone();
                let scope = scope.clone();
                let target = boxes[(member + 1) % size].clone();
                let barrier = barrier.clone();
                jobs.spawn(async move {
                    let outgoing = matrix_text(size, round, member, payload_bytes);
                    let incoming = matrix_text(size, round, (member + size - 1) % size, payload_bytes);
                    let mut request = Invoke::new(format!("matrix-{round}-{member}"), "structure.message.send", scope,
                        json!({"conversation_id":"V".repeat(43),"reply_to":null,"reply_address":null,
                            "recipients":[{"mailbox_id":target["mailbox_id"],"membership_id":target["membership_id"]}],
                            "content":{"mode":"WORKSPACE_E2EE"}}));
                    request.plaintext_message = Some(outgoing);
                    // One send per identity per round. Snapshot outside the
                    // timed interval; task-local phases exclude watch/ACK work.
                    let phase_before = if phase_diagnostic {Some(client.metrics().await.unwrap()["http"].clone())}else{None};
                    barrier.wait().await;
                    let call_started = round_start.elapsed().as_secs_f64() * 1000.;
                    let send = async {
                        let accepted = structure(&client.invoke(request, Duration::from_secs(10)).await.unwrap());
                        assert!(accepted["message_id"].is_string(), "{accepted}");
                        let accepted_at=round_start.elapsed().as_secs_f64() * 1000.;
                        let phases=if let Some(before)=phase_before {
                            let after=client.metrics().await.unwrap()["http"].clone();
                            json!({"send_execution":phase_interval(&before["send_execution_phases"],&after["send_execution_phases"],None),
                                "operation_store":phase_interval(&before["local_phases"],&after["local_phases"],Some(&["admission_reserve","running_store","completion_store"]))})
                        }else{Value::Null};
                        (accepted, accepted_at, phases)
                    };
                    let receive = tokio::time::timeout(Duration::from_secs(15), async {
                        loop {
                            let snapshot = receiver.next().await.unwrap();
                            assert_ne!(snapshot.state, "BLOCKED", "{snapshot:?}");
                            if let Some(item) = snapshot.items.iter().find(|item| item["opened_message"]["text"] == incoming) {
                                assert_eq!(item["opened_message"]["assurance"], "AUTHOR_SIGNATURE_AND_AEAD");
                                return (item.clone(), round_start.elapsed().as_secs_f64() * 1000.);
                            }
                        }
                    });
                    // Observe receive independently: never wait for this member's
                    // own outgoing acceptance before observing its incoming mail.
                    let ((accepted, accepted_at, phases), received) = tokio::join!(send, receive);
                    let (item, received_at) = received.expect("accepted ring message missing");
                    client.consume(&option, vec![crate::participant::DeliveryReference {
                        sequence: item["sequence"].as_u64().unwrap(),
                        delivery_id: item["delivery_id"].as_str().unwrap().into(),
                    }]).await.unwrap();
                    (member, receiver, json!({"call_started":call_started,"accepted_at":accepted_at,
                        "received_at":received_at,"outgoing_id":accepted["message_id"],
                        "incoming_id":item["envelope"]["message"]["message_id"],"phases":phases}))
                });
            }
            let mut outcomes = Vec::new();
            while let Some(result) = jobs.join_next().await {
                outcomes.push(result.unwrap());
            }
            outcomes.sort_by_key(|(member, _, _)| *member);
            for member in 0..size {
                let sender = &outcomes[member].2;
                let recipient = &outcomes[(member + 1) % size].2;
                assert_eq!(sender["outgoing_id"], recipient["incoming_id"]);
                let mut sample=json!({"round":round,"sender":member,
                    "accepted_ms":sender["accepted_at"].as_f64().unwrap()-sender["call_started"].as_f64().unwrap(),
                    "receiver_observed_ms":recipient["received_at"].as_f64().unwrap()-sender["call_started"].as_f64().unwrap()});
                if phase_diagnostic {sample["phases"]=sender["phases"].clone();}
                samples.push(sample);
            }
            receivers = outcomes
                .into_iter()
                .map(|(_, receiver, _)| receiver)
                .collect();
        }
        let after = service.counts().await;
        let mut after_metrics = Vec::new();
        for client in &clients {
            after_metrics.push(client.metrics().await.unwrap()["http"].clone());
        }
        let warm = samples
            .iter()
            .filter(|s| s["round"] != 0)
            .cloned()
            .collect::<Vec<_>>();
        let accepted = measured_distribution(&warm, "accepted_ms");
        let observed = measured_distribution(&warm, "receiver_observed_ms");
        let send_count = after["actions"]["structure.message.send"].as_u64().unwrap()
            - before["actions"]["structure.message.send"]
                .as_u64()
                .unwrap_or(0);
        let pulse_count = after["actions"]["structure.mailbox.pulse"].as_u64().unwrap_or(0)
            - before["actions"]["structure.mailbox.pulse"].as_u64().unwrap_or(0);
        cases.push(json!({"participants":size,"warm_samples":warm.len(),"samples":samples,
            "warm_accepted":accepted,"warm_receiver_observed":observed,"send_http_count":send_count,
            "pulse_http_count":pulse_count,
            "client_metrics_before":before_metrics,"client_metrics_after":after_metrics,
            "discovery_http_count":after["discovery"].as_u64().unwrap_or(0)-before["discovery"].as_u64().unwrap_or(0),
            "context_http_count":after["context"].as_u64().unwrap_or(0)-before["context"].as_u64().unwrap_or(0),
            "journal_reads":after["journal_reads"],
            "phase_diagnostic":phase_diagnostic,
            "warm_acceptance_target_met":!phase_diagnostic && !cfg!(debug_assertions) && accepted["p95_ms"].as_f64().unwrap()<=300.}));
        // Retain measured cases even if a later qualification case fails.
        write_report(
            &report,
            &json!({"format":"peerwork.program-matrix.v1","state":"MEASURING","cases":cases,
                "payload_bytes":if payload_bytes==0{json!([41,42])}else{json!([payload_bytes])},"simulated_link_rtt_ms":link_rtt_ms,"phase_diagnostic":phase_diagnostic}),
        );
        assert_eq!(send_count, (rounds * size) as u64);
        if rounds == 33 {
            assert!(pulse_count < send_count, "consumption must not force a heartbeat per message");
        }
        assert_eq!(after["journal_reads"], 0);
        drop(receivers);
        for client in clients {
            client.close().await.unwrap();
        }
    }
    write_report(
        &report,
        &json!({"format":"peerwork.program-matrix.v1","state":"MEASURED","cases":cases,
        "build_profile":if cfg!(debug_assertions){"unoptimized-test"}else{"optimized"},
        "service":"local synthetic PostgreSQL/HTTP","traffic":"one concurrent ring send per identity per round; E2EE bodies; signed SSE",
        "payload_bytes":if payload_bytes==0{json!([41,42])}else{json!([payload_bytes])},"simulated_link_rtt_ms":link_rtt_ms,
        "phase_diagnostic":phase_diagnostic,
        "timing_basis":"single monotonic clock; receive observation runs independently of outgoing acceptance and includes observer scheduling; not an isolated service-acceptance-to-store span; simulated link delays exclude TCP/TLS setup, bandwidth limits, jitter and packet loss",
        "host_or_model":"NOT_EXERCISED","release_gate_qualified":false}),
    );
}

fn phase_interval(before:&Value,after:&Value,selected:Option<&[&str]>)->Value{
    let mut interval=serde_json::Map::new();
    for (name,value) in after.as_object().unwrap(){
        if selected.is_some_and(|names|!names.contains(&name.as_str())){continue;}
        let count=value["count"].as_u64().and_then(|n|n.checked_sub(before[name]["count"].as_u64()?));
        let elapsed=value["elapsed_us"].as_u64().and_then(|n|n.checked_sub(before[name]["elapsed_us"].as_u64()?));
        interval.insert(name.clone(),json!({"count":count,"elapsed_us":elapsed,"monotonic":count.is_some()&&elapsed.is_some()}));
    }
    Value::Object(interval)
}

fn matrix_text(size: usize, round: usize, member: usize, bytes: usize) -> String {
    let mut text = format!("Concurrent mail case {size}, round {round}, member {member}");
    if bytes != 0 {
        assert!(text.len() <= bytes);
        text.extend(std::iter::repeat('x').take(bytes - text.len()));
        assert_eq!(text.len(), bytes);
    }
    text
}

fn measured_distribution(samples: &[Value], name: &str) -> Value {
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
    qualify_native_reply(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit fresh AGY process with workspace MCP and isolated PostgreSQL; no host push is implied"]
async fn fresh_agy_native_mcp_reply() {
    qualify_native_reply(true).await;
}

async fn qualify_native_reply(mcp_only: bool) {
    let host = if mcp_only {
        Value::Null
    } else {
        let host_path = PathBuf::from(
            std::env::var("PEERWORK_LIVE_HOST_CONFIG")
                .expect("explicit protected host configuration required"),
        );
        crate::communication_store::private_json(&host_path, 65536).unwrap()
    };
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

    // MCP discovery may happen while a managed host initializes. Supply its
    // protected profile before starting that host; execution still waits for
    // the scoped runtime endpoint and never opens another signing engine.
    let worker_scope_early = mail_scope(&ws, &worker_box);
    let early_worker_profile = AgentProfile {
        format: "peerwork.agent-profile.v1".into(),
        endpoint_path: root.join("runtime/client-worker.json"),
        expected_origin: service.origin.clone(),
        expected_actor: worker_config.expected_actor.clone(),
        scopes: BTreeMap::from([("live".into(), worker_scope_early)]),
        contacts: BTreeMap::new(), protocols: BTreeMap::new(),
    };
    let worker_profile_path = root.join("worker-agent.json");
    crate::communication_host::write_private(&worker_profile_path,
        &serde_json::to_vec(&early_worker_profile).unwrap()).unwrap();
    let (mut bridge_lifecycle, adapter, destination) = if mcp_only {
        (None, None, None)
    } else {
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
        (
            Some((bridge_stop, bridge)),
            Some(bridge_ready.adapter),
            Some(destination.digest),
        )
    };
    let master_scope = mail_scope(&ws, &master_box);
    let worker_scope = mail_scope(&ws, &worker_box);
    let master_watch = watch(&master_scope, "master", None);
    let worker_watch = watch(&worker_scope, "worker", destination);
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
    let original_bridge_adapter = adapter.clone();
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
        hosts: adapter
            .into_iter()
            .map(|adapter| HostConfig {
                name: "explicit-existing-worker".into(),
                adapter,
                subscriptions: vec![HostSubscription {
                    client: "worker".into(),
                    watch: worker_watch.clone(),
                }],
            })
            .collect(),
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
    assert_eq!(worker_profile.endpoint_path, early_worker_profile.endpoint_path);
    assert_eq!(serde_json::to_value(&worker_profile).unwrap(),serde_json::to_value(&early_worker_profile).unwrap());
    let master = AgentTools::open(master_profile).await.unwrap();
    let before = service.counts().await;
    let mut result = json!({"state":"READY","format":"peerwork.live-host-qualification.v1","nonce":nonce,
        "worker_profile":worker_profile_path,"expected_reply":format!("PONG {nonce}"),"fresh_agent_first_use":false,"first_use_requires_external_harness_evidence":mcp_only,
        "service":"LOCAL_SYNTHETIC_POSTGRES_HTTP","host":if mcp_only {"MCP_WAIT_ONLY_NO_HOST_PUSH"} else {"EXPLICIT_EXISTING_SESSION"},"body_mode":"WORKSPACE_E2EE",
        "timing_basis":"one observer monotonic clock; delivery observations are upper bounds, not isolated internal phase spans"});
    write_report(&report, &result);
    println!("LIVE_HOST_READY {}", result);
    let require_consumption = std::env::var("PEERWORK_LIVE_HOST_REQUIRE_CONSUMED").as_deref() == Ok("1");
    result["consumption_required"] = json!(require_consumption);
    let rounds = std::env::var("PEERWORK_LIVE_HOST_ROUNDS").ok()
        .map(|v| v.parse::<usize>().expect("explicit round count"))
        .unwrap_or(if mcp_only { 2 } else { 1 });
    assert!((1..=8).contains(&rounds));
    let restart_bridge = std::env::var("PEERWORK_LIVE_HOST_RESTART_BRIDGE").as_deref() == Ok("1");
    if restart_bridge {
        assert!(!mcp_only && rounds >= 2 && require_consumption);
        let saved: BridgeConfig = serde_json::from_slice(&std::fs::read(root.join("bridge.json")).unwrap()).unwrap();
        assert_eq!(saved.host["kind"], "agy-stdio", "restart only our explicitly managed CLI");
    }
    result["bridge_restarts"] = json!(0);
    let mut samples = Vec::new();
    for round in 1..=rounds {
        let started = Instant::now();
        let sent=master.call(AgentRequest::parse("send",json!({"contact":"worker","operation_id":format!("ping-{nonce}-{round}"),"text":format!("PING {nonce}. Native Peerwork live-host qualification. Please reply with exactly PONG {nonce} using the native Peerwork reply tool for this verified inbox item."),"wait_ms":5000})).unwrap()).await.unwrap();
        result["accepted_observed_ms"] = json!(started.elapsed().as_millis());
        result["send_state"] = sent["state"].clone();
        result["original_operation_id"] = json!(format!("ping-{nonce}-{round}"));
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
                if let Some(item) = items.iter().find(|item|item["envelope"]["message"]["message_id"]==message_id) {
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
        if !mcp_only {
            // Observe host acceptance before waiting for model output. Poll
            // only the original local delivery; never resubmit its input. A
            // same-observer upper bound is not an internal host-only span.
            let early_ack = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let status = worker_client
                        .call(json!({"method":"delivery_status","options":worker_watch,"item":item}))
                        .await
                        .unwrap();
                    if status["host"] == "HOST_ACCEPTED" {
                        return started.elapsed().as_millis();
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
            result["host_ack_observed_ms"] = json!(early_ack.as_ref().ok().copied());
            result["host_ack_observation_state"] = json!(if early_ack.is_ok() {
                "HOST_ACCEPTED"
            } else {
                "OBSERVATION_BUDGET_EXCEEDED"
            });
            write_report(&report, &result);
            println!(
                "LIVE_HOST_ACK {}",
                json!({"nonce":nonce,"host_ack_observed_ms":result["host_ack_observed_ms"],"state":result["host_ack_observation_state"]})
            );
        }
        let observed = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                if mcp_only && root.join("agent-failed").exists() {
                    return Value::Null;
                }
                let arrival = master
                    .call(
                        AgentRequest::parse(
                            "wait",
                            json!({"scope":"live","wait_ms":30000,"limit":8}),
                        )
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
        let local = if mcp_only {
            json!({"host":"NOT_CONFIGURED"})
        } else {
            worker_client
                .call(json!({"method":"delivery_status","options":worker_watch,"item":item}))
                .await
                .unwrap()
        };
        result["host_fact"] = local["host"].clone();
        let model_reply_observed = observed.as_ref().is_ok_and(|v| v.is_object());
        result["model_reply_observed"] = json!(model_reply_observed);
        let mut qualified = model_reply_observed && (mcp_only || local["host"] == "HOST_ACCEPTED");
        let consumed = if require_consumption && qualified {
            let done = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let page = worker_client.call(json!({"method":"inbox","options":worker_watch,"after":0,"limit":32})).await.unwrap();
                    let pending = page["items"].as_array().expect("explicit local inbox page");
                    if !pending.iter().any(|entry|entry["delivery_id"]==item["delivery_id"]) { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.is_ok();
            qualified &= done;
            Some(done)
        } else { None };
        samples.push(json!({"round":round,"accepted_observed_ms":result["accepted_observed_ms"],"receiver_store_observed_ms":result["receiver_store_observed_ms"],"host_ack_observed_ms":result["host_ack_observed_ms"],"reply_observed_ms":result["reply_observed_ms"],"worker_consumed":consumed,"qualified":qualified}));
        if let Ok(arrival) = observed {
            if arrival.is_object() {
                master
                    .call(
                        AgentRequest::parse(
                            "consume",
                            json!({"scope":"live","items":[arrival["item"]]}),
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        }
        if !qualified {
            break;
        }
        if restart_bridge && round == 1 {
            let (stop, bridge) = bridge_lifecycle.take().unwrap();
            stop.cancel();
            bridge.await.unwrap().unwrap();
            let saved: BridgeConfig = serde_json::from_slice(&std::fs::read(root.join("bridge.json")).unwrap()).unwrap();
            let stop = KernelCancellationToken::new();
            let (tx, rx) = oneshot::channel();
            let bridge = tokio::spawn(communication_bridge::serve(saved, stop.clone(), tx));
            let restarted = rx.await.unwrap().unwrap();
            assert_eq!(Some(restarted.adapter), original_bridge_adapter,
                "same conversation restart must preserve bridge identity, credentials and destination");
            bridge_lifecycle = Some((stop, bridge));
            result["bridge_restarts"] = json!(1);
            write_report(&report, &result);
        }
    }
    result["samples"] = json!(samples);
    if mcp_only {
        let completed = tokio::time::timeout(Duration::from_secs(45), async {
            while !root.join("agent-finished").exists() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        result["agent_turn_completed"] = json!(completed.is_ok());
    }
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
    result["state"] = json!(if samples.len() == rounds
        && samples.iter().all(|s| s["qualified"] == true)
        && (!mcp_only || result["agent_turn_completed"] == true)
    {
        "COMPLETED"
    } else {
        "NOT_QUALIFIED"
    });
    runtime_stop.cancel();
    runtime.await.unwrap().unwrap();
    if let Some((bridge_stop, bridge)) = bridge_lifecycle {
        bridge_stop.cancel();
        bridge.await.unwrap().unwrap();
    }
    result["owned_runtime_and_bridge_stopped"] = json!(true);
    result["state_retained"] = json!(true);
    write_report(&report, &result);
    println!("LIVE_HOST_RESULT {}", result);
    assert_eq!(
        result["state"], "COMPLETED",
        "inspect retained qualification result; do not resend original input"
    );
}

#[test]
#[ignore = "requires explicit protected config selecting an owned synthetic existing AGY conversation"]
fn agy_stdio_selected_cli_two_input_receipts() {
    let config_path = std::env::var("PEERWORK_AGY_STDIO_CONFIG").unwrap();
    let report_path = std::env::var("PEERWORK_AGY_STDIO_REPORT").unwrap();
    assert!(std::path::Path::new(&report_path).is_absolute() && !std::path::Path::new(&report_path).exists());
    let config = crate::communication_store::private_json(std::path::Path::new(&config_path),65536).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut host = crate::communication_host::Host::open(config,rt.handle().clone()).unwrap();
    let mut samples = Vec::new();
    for index in 0..2 {
        let deadline = Instant::now()+Duration::from_secs(90);
        while host.health(&json!({})).unwrap()["ready"] != true { assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(20)); }
        let before = Instant::now();
        let receipt = host.deliver(&json!({}),&json!({"rendered_text":format!("Peerwork isolated native stdio interoperability check. Reply exactly PW-AGY-NATIVE-{index}. Do not use tools or read files. Preserve all task permissions.")})).unwrap();
        assert_eq!(receipt["state"],"HOST_ACCEPTED");
        samples.push(json!({"index":index,"host_accepted_ms":before.elapsed().as_secs_f64()*1000.,"state":receipt["state"]}));
        assert_eq!(host.health(&json!({})).unwrap()["execution_state"],"BUSY");
    }
    let destination=host.destination.clone();drop(host);
    std::fs::write(report_path,serde_json::to_vec_pretty(&json!({"state":"PASS","destination":destination,"samples":samples,"process_reused":true,"owned_process_stopped":true,"model_reply":"NOT_ATTESTED","peerwork_service":"NOT_EXERCISED","scope":"Two native provider receipts, not IM percentiles"})).unwrap()).unwrap();
}
