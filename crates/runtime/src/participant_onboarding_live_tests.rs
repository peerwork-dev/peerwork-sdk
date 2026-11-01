//! Explicit maintainer fixture for actual-host onboarding. Only synthetic
//! identities/body keys and the selected isolated HTTP/PostgreSQL are used.
//! The controller runs the normal installed CLI; no Agent profile is fabricated.
use crate::{
    communication_host::write_private,
    communication_runtime::{self as ipc, EngineConfig, RuntimeClient},
    participant::http_tests::{
        configuration, install_synthetic_key, mutate, selected, structure, Service,
    },
    participant::{Invoke, ParticipantClient, Scope, WatchOptions},
    participant_connect::Connect,
    secure_state::create_private_state_directory,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn report(path: &Path, value: &Value) {
    crate::onboarding_files::replace(path, &serde_json::to_vec(value).unwrap()).unwrap();
}
async fn gate(root: &Path, name: &str) {
    tokio::time::timeout(Duration::from_secs(180), async {
        while !root.join(name).is_file() {
            assert!(
                name == "finish" || !root.join("finish").exists(),
                "owned controller aborted this qualification"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("owned controller did not reach the selected barrier");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit actual Codex/AGY controller, synthetic PostgreSQL and rebuilt native CLI"]
async fn native_connect_actual_agent_fixture() {
    let root = PathBuf::from(
        std::env::var("PEERWORK_CONNECT_LIVE_ROOT").expect("explicit empty protected root"),
    );
    assert!(
        root.is_absolute() && !root.exists(),
        "reconcile the original operation rather than replace its state"
    );
    create_private_state_directory(&root).unwrap();
    let output = root.join("result.json");
    let service = Service::start();
    for name in ["master", "worker"] {
        create_private_state_directory(&root.join(name)).unwrap();
    }
    let project = std::env::var("PEERWORK_CONNECT_LIVE_PROJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join("project"));
    if project.exists() {
        crate::onboarding_files::check_directory(&project, true).unwrap();
    } else {
        create_private_state_directory(&project).unwrap();
    }
    let master_config = configuration(&root.join("master"), &service.origin);
    let mut worker_config = configuration(&root.join("worker"), &service.origin);
    worker_config.journal_path = root.join("worker/original-journal.sqlite");
    worker_config.authority = Some(peerwork_core::crypto::sha256_hex(
        worker_config.expected_actor.as_bytes(),
    ));
    let master = ParticipantClient::open(master_config.clone())
        .await
        .unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let created = mutate(
        &master,
        "actual-create",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Actual Agent self-configuration qualification"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&master, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "actual-member",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker.actor_id(),"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&master.invoke(join, Duration::from_secs(5)).await.unwrap());
    let master_box=mutate(&master,"actual-master-grant","structure.communication.grant.set",&scope,json!({"actor_id":master.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&master,"actual-worker-grant","structure.communication.grant.set",&scope,json!({"actor_id":worker.actor_id(),"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&master_config, &ws, &[61; 32], None);
    install_synthetic_key(&worker_config, &ws, &[61; 32], None);
    mutate(
        &master,
        "actual-head",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let bundle: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/protocol-role-bundle-v1.json"
    ))
    .unwrap();
    let package = mutate(
        &master,
        "actual-register",
        "structure.protocol.register",
        &scope,
        json!({"bundle":bundle["bundle"]}),
    )
    .await;
    let mut roles = Vec::new();
    for index in 0..2 {
        let adopted=mutate(&master,&format!("actual-adopt-{index}"),"structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":{"actions":["claim"],"protocol_roles":["WORKER"]}})).await;
        let instance = adopted["instance_id"].as_str().unwrap();
        let resolved = selected(
            &master,
            "structure.instance.resolve",
            &scope,
            json!({"instance_id":instance}),
        )
        .await;
        let role_scope = Scope {
            workspace_id: Some(ws.clone()),
            instance_id: Some(instance.into()),
            protocol_digest: Some(
                resolved["instance"]["protocol_digest"]
                    .as_str()
                    .unwrap()
                    .into(),
            ),
        };
        mutate(&master,&format!("actual-role-{index}"),"structure.grant.set",&role_scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_grant_revision":null,"actions":["claim"],"protocol_roles":["WORKER"],"capabilities":[],"expires_at":null})).await;
        roles
            .push(json!({"alias":format!("claim-{index}"),"instance_id":instance,"role":"WORKER"}));
    }
    let original = worker
        .invoke(
            crate::participant::http_tests::native_message(
                "original-before-connect",
                &scope,
                &master_box,
                &worker_box,
                &"P".repeat(43),
                "preexisting original operation",
            ),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(original.state, "ACCEPTED");
    worker.close().await.unwrap();
    let engine = EngineConfig {
        name: "original".into(),
        origin: worker_config.origin.clone(),
        expected_actor: worker_config.expected_actor.clone(),
        authority: worker_config.authority.clone(),
        identity_path: worker_config.identity_path.clone(),
        state_directory: worker_config.state_directory.clone(),
        journal_path: Some(worker_config.journal_path.clone()),
        allow_loopback_http: true,
        transport: worker_config.transport.clone(),
        max_inflight: 4,
        max_pending: 32,
        max_stored_bytes: 8 * 1024 * 1024,
        migration_sources: Vec::new(),
    };
    let engine_path = root.join("worker-engine.json");
    write_private(&engine_path, &serde_json::to_vec(&engine).unwrap()).unwrap();
    let identity_hash =
        peerwork_core::crypto::sha256_hex(&std::fs::read(&worker_config.identity_path).unwrap());
    let master_options = WatchOptions {
        workspace_id: ws.clone(),
        mailbox_id: master_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: master_box["membership_id"].as_str().unwrap().into(),
        consumer_id: "actual-controller".into(),
        host_destination: None,
    };
    let mut inbox = master.watch(master_options.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if inbox.next().await.unwrap().receiver_link_verified {
                break;
            }
        }
    })
    .await
    .unwrap();
    let before = service.counts().await;
    let mut result = json!({"format":"peerwork.actual-connect-qualification.v1","state":"AWAITING_CONNECT","origin":service.origin,"workspace_id":ws,"worker_actor":worker_config.expected_actor,"master_actor":master_config.expected_actor,"engine_config":engine_path,"project":project,"local":root.join("local"),"identity_retained":true,"owner_exchanges":0,"roles":roles,"samples":[]});
    report(&output, &result);
    gate(&root, "start-sends").await;
    let connect = Connect::inspect(&root.join("local")).unwrap();
    let profile = connect.profile().unwrap().unwrap();
    assert_eq!(profile.expected_actor, worker_config.expected_actor);
    assert!(profile.protocols.contains_key("claim-0"));
    let original_sender = profile.endpoint_path.clone();
    let original_receiver = profile.receive_endpoint_path.clone();
    let receiving = RuntimeClient::connect(
        profile.receive_endpoint_path.clone().unwrap(),
        &service.origin,
        &worker_config.expected_actor,
    )
    .await
    .unwrap();
    let bindings = receiving.call(json!({"method":"bindings"})).await.unwrap();
    let worker_options: WatchOptions =
        serde_json::from_value(bindings.as_array().unwrap()[0].clone()).unwrap();
    drop(connect);
    for round in 1..=2 {
        if round == 2 {
            result["state"] = json!("FIRST_REPLY_VERIFIED");
            report(&output, &result);
            gate(&root, "second-send").await;
            let updated = Connect::inspect(&root.join("local"))
                .unwrap()
                .profile()
                .unwrap()
                .unwrap();
            assert!(
                updated.protocols.contains_key("claim-0")
                    && updated.protocols.contains_key("claim-1")
            );
            assert_eq!(updated.endpoint_path, original_sender);
            assert_eq!(updated.receive_endpoint_path, original_receiver);
            result["role_reuse_preserved_sender_and_receiver"] = json!(true);
        }
        let nonce = format!("PW-CONNECT-{}-{round}", &ws[..8]);
        let text=format!("PING {nonce}. Please reply with exactly PONG {nonce} to this verified inbox item and consume it after the reply is accepted.");
        let started = Instant::now();
        let sent = structure(
            &master
                .invoke(
                    crate::participant::http_tests::native_message(
                        &format!("actual-ping-{round}"),
                        &scope,
                        &worker_box,
                        &master_box,
                        &"V".repeat(43),
                        &text,
                    ),
                    Duration::from_secs(5),
                )
                .await
                .unwrap(),
        );
        let accepted_ms = started.elapsed().as_millis();
        let message = sent["message_id"].as_str().unwrap();
        let target = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let page = receiving
                    .call(json!({"method":"inbox","options":worker_options,"after":0,"limit":32}))
                    .await
                    .unwrap();
                if let Some(item) = page["items"].as_array().and_then(|xs| {
                    xs.iter()
                        .find(|v| v["envelope"]["message"]["message_id"] == message)
                }) {
                    break json!({"sequence":item["sequence"],"delivery_id":item["delivery_id"]});
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("selected receiver did not store the accepted input");
        let stored_ms = started.elapsed().as_millis();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let status = receiving
                    .call(
                        json!({"method":"delivery_status","options":worker_options,"item":target}),
                    )
                    .await
                    .unwrap();
                if status["host"] == "HOST_ACCEPTED" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("selected actual host did not accept the stored input");
        let host_ms = started.elapsed().as_millis();
        result["state"] = json!("AWAITING_MODEL_REPLY");
        result["round"] = json!(round);
        result["expected_reply"] = json!(format!("PONG {nonce}"));
        report(&output, &result);
        let reply = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                let page = inbox.next().await.unwrap();
                if let Some(item) = page
                    .items
                    .iter()
                    .find(|v| v["opened_message"]["text"] == format!("PONG {nonce}"))
                {
                    let envelope = &item["envelope"]["message"];
                    assert_eq!(
                        envelope["sender_actor"], worker_config.expected_actor,
                        "{envelope}"
                    );
                    assert_eq!(
                        item["opened_message"]["reply_to"], message,
                        "reply must reference the original input"
                    );
                    break item.clone();
                }
            }
        })
        .await
        .expect("actual Agent did not produce a verified correlated reply");
        let reply_ms = started.elapsed().as_millis();
        let status = receiving
            .call(json!({"method":"delivery_status","options":worker_options,"item":target}))
            .await
            .unwrap();
        assert_eq!(
            status["host"], "HOST_ACCEPTED",
            "model reply does not substitute for host receipt: {status}"
        );
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let receipts = selected(
                    &master,
                    "structure.message.receipts.read",
                    &scope,
                    json!({"message_id":message}),
                )
                .await;
                if !receipts["deliveries"][0]["application_consumed_at"].is_null() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("actual Agent replied but did not consume the original verified item");
        result["samples"].as_array_mut().unwrap().push(json!({"round":round,"accepted_observed_ms":accepted_ms,"stored_observed_ms":stored_ms,"host_accepted_observed_ms":host_ms,"actual_reply_observed_ms":reply_ms,"host":status["host"],"reply_correlated":true}));
        master
            .consume(
                &master_options,
                vec![crate::participant::DeliveryReference {
                    sequence: reply["sequence"].as_u64().unwrap(),
                    delivery_id: reply["delivery_id"].as_str().unwrap().into(),
                }],
            )
            .await
            .unwrap();
    }
    let after = service.counts().await;
    assert_eq!(after["journal_reads"], 0);
    assert_eq!(
        after["actions"]["structure.communication.grant.set"],
        before["actions"]["structure.communication.grant.set"],
        "authorized connect asked Owner to change grants"
    );
    assert_eq!(
        after["actions"]["structure.grant.set"], before["actions"]["structure.grant.set"],
        "role reuse requested new Owner authorization"
    );
    assert_eq!(
        peerwork_core::crypto::sha256_hex(&std::fs::read(&worker_config.identity_path).unwrap()),
        identity_hash
    );
    result["state"] = json!("PASS");
    result["journal_reads"] = json!(0);
    result["owner_exchanges"] = json!(0);
    report(&output, &result);
    gate(&root, "finish").await;
    let restored = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match ParticipantClient::open(worker_config.clone()).await {
                Ok(client) => break client,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("controller did not release the original worker engine");
    assert_eq!(
        restored
            .operation("original-before-connect")
            .await
            .unwrap()
            .command_id,
        original.command_id
    );
    restored.close().await.unwrap();
    master.close().await.unwrap();
}
