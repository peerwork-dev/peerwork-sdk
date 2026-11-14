//! Real local authenticated IPC over synthetic cached inbox evidence. This does
//! not qualify remote service signature ingestion or an authenticated model host.
use crate::{
    agent_tools::{AgentProfile, AgentRequest, AgentTools},
    communication_notifications::Hub,
    communication_runtime::{self, RuntimeConfig, RuntimeReady},
    kernel_identity::KernelIdentity,
    notification_delivery::SourceHead,
    participant::WatchOptions,
    KernelCancellationToken,
};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

async fn start(
    config: RuntimeConfig,
) -> (
    RuntimeReady,
    KernelCancellationToken,
    tokio::task::JoinHandle<crate::participant::Result<()>>,
) {
    let stop = KernelCancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(communication_runtime::serve(config, stop.clone(), tx));
    let ready = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    (ready, stop, task)
}
fn profile(ready: &RuntimeReady, actor: &str, options: &WatchOptions, name: &str) -> AgentProfile {
    serde_json::from_value(json!({"format":"peerwork.agent-profile.v1","endpoint_path":ready.client_endpoints[name],"expected_origin":"http://127.0.0.1:1/","expected_actor":actor,"scopes":{"main":{"workspace_id":options.workspace_id,"mailbox_id":options.mailbox_id,"membership_id":options.membership_id}}})).unwrap()
}
async fn invoke(tools: &AgentTools, name: &str, args: Value) -> Value {
    tools
        .call(AgentRequest::parse(name, args).unwrap())
        .await
        .unwrap()
}
fn config(root: &Path, actor: &str) -> RuntimeConfig {
    serde_json::from_value(json!({"format":"peerwork.participant-runtime.v1","state_directory":root.join("runtime"),"hosts":[],"engines":[{"name":"identity","origin":"http://127.0.0.1:1/","expected_actor":actor,"identity_path":root.join("identity"),"state_directory":root.join("engine"),"allow_loopback_http":true,"max_inflight":1,"max_pending":32,"max_stored_bytes":1048576}],"clients":[{"name":"creator","engine":"identity","capability":crate::participant::Capability::owner()},{"name":"other","engine":"identity","capability":crate::participant::Capability::owner()}]})).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback IPC permission; synthetic local runtime only"]
async fn real_runtime_compact_read_preserves_backlog_scope_chunks_and_pause_across_restart() {
    let root = crate::test_support::protected_test_dir();
    let identity = KernelIdentity::create(&root.path().join("identity")).unwrap();
    let options = WatchOptions {
        workspace_id: "W".repeat(43),
        mailbox_id: "M".repeat(43),
        membership_id: "G".repeat(43),
        consumer_id: "creator".into(),
        host_destination: None,
    };
    let config = config(root.path(), identity.actor_id());
    let origin = "http://127.0.0.1:1/";
    crate::participant_inbox::seed_notification_events(
        &config.engines[0].state_directory,
        &identity,
        origin,
        &options,
        &[
            (12, json!({"kind":"old","text":"old twelve"})),
            (68, json!({"kind":"old","text":"old sixty-eight"})),
        ],
    );
    let key = peerwork_core::crypto::sha256_hex(
        json!([
            origin,
            identity.actor_id(),
            "program:creator",
            "CLAUDE_CHANNEL"
        ])
        .to_string()
        .as_bytes(),
    );
    let source = peerwork_core::crypto::sha256_hex(
        json!([origin, identity.actor_id(), "program:creator", options])
            .to_string()
            .as_bytes(),
    );
    let heads = |checkpoint| {
        vec![SourceHead {
            key: source.clone(),
            checkpoint,
            has_pending: true,
        }]
    };
    let (ready, stop, task) = start(config.clone()).await;
    let hub = Hub::open(&config.state_directory).unwrap();
    let tools = AgentTools::open(profile(&ready, identity.actor_id(), &options, "creator"))
        .await
        .unwrap();
    let probe = hub
        .store
        .due(&key, &heads(68), crate::participant_store::now())
        .unwrap()
        .unwrap();
    assert!(probe.self_test);
    let tested = invoke(&tools, "inbox", json!({"batch":probe.batch})).await;
    assert_eq!(tested["state"], "SELF_TEST_OBSERVED");
    let backlog = hub
        .store
        .due(&key, &heads(68), crate::participant_store::now())
        .unwrap()
        .unwrap();
    let page = invoke(&tools, "inbox", json!({"batch":backlog.batch})).await;
    assert_eq!(page["state"], "BACKLOG_AVAILABLE");
    assert!(page["items"].as_array().unwrap().is_empty());
    drop(tools);
    stop.cancel();
    task.await.unwrap().unwrap();
    drop(hub);
    let event = json!({"kind":"new","text":"雪🌍".repeat(2000)});
    crate::participant_inbox::seed_notification_events(
        &config.engines[0].state_directory,
        &identity,
        origin,
        &options,
        &[(634, event.clone())],
    );
    let (ready, stop, task) = start(config.clone()).await;
    let hub = Hub::open(&config.state_directory).unwrap();
    let tools = AgentTools::open(profile(&ready, identity.actor_id(), &options, "creator"))
        .await
        .unwrap();
    let wake = hub
        .store
        .due(&key, &heads(634), crate::participant_store::now())
        .unwrap()
        .unwrap();
    assert!(!wake.self_test);
    assert!(tools
        .call(
            AgentRequest::parse(
                "inbox",
                json!({"batch":wake.batch,"scope":"unselected-scope"})
            )
            .unwrap()
        )
        .await
        .is_err());
    let other = AgentTools::open(profile(&ready, identity.actor_id(), &options, "other"))
        .await
        .unwrap();
    assert!(other
        .call(AgentRequest::parse("inbox", json!({"batch":wake.batch})).unwrap())
        .await
        .is_err());
    drop(other);
    let mut cursor = None;
    let mut assembled = String::new();
    for _ in 0..100 {
        let mut args = json!({"batch":wake.batch,"max_bytes":2048,"limit":1});
        if let Some(cursor) = cursor.take() {
            args["cursor"] = cursor;
        }
        let page = invoke(&tools, "inbox", args).await;
        assert!(page.to_string().len() <= 2048);
        for item in page["items"].as_array().unwrap() {
            assert_eq!(item["item"]["sequence"], 634);
            assert_eq!(page["scope"], "main");
            assembled.push_str(item["message"]["text"].as_str().unwrap());
        }
        if page["more"] != true {
            break;
        }
        cursor = Some(page["continuation"].clone());
    }
    assert_eq!(serde_json::from_str::<Value>(&assembled).unwrap(), event);
    let active = invoke(
        &tools,
        "inbox",
        json!({"view":"active","scope":"main","limit":2}),
    )
    .await;
    assert_eq!(active["items"][0]["item"]["sequence"], 12);
    assert_eq!(active["items"][1]["item"]["sequence"], 68);
    invoke(&tools, "delivery", json!({"mode":"pause"})).await;
    drop(tools);
    stop.cancel();
    task.await.unwrap().unwrap();
    drop(hub);
    let (ready, stop, task) = start(config.clone()).await;
    let tools = AgentTools::open(profile(&ready, identity.actor_id(), &options, "creator"))
        .await
        .unwrap();
    let status = invoke(&tools, "delivery", json!({"mode":"status"})).await;
    assert_eq!(status["destinations"][0]["state"], "PAUSED");
    let _ = invoke(&tools, "inbox", json!({"batch":wake.batch,"limit":1})).await;
    assert_eq!(
        invoke(&tools, "delivery", json!({"mode":"status"})).await["destinations"][0]["state"],
        "PAUSED"
    );
    let active = invoke(&tools, "inbox", json!({"view":"active","limit":3})).await;
    assert_eq!(active["items"].as_array().unwrap().len(), 3);
    assert_eq!(
        invoke(&tools, "context", json!({})).await["actor_id"],
        identity.actor_id()
    );
    drop(tools);
    stop.cancel();
    task.await.unwrap().unwrap();
}

/// A deliberately selected real host reads compact references through the same
/// native tools. Cached synthetic events isolate host/MCP behavior from service
/// availability; this does not qualify remote signature ingestion or an IM SLA.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicit owned real host, native CLI and private controller directory"]
async fn selected_real_host_reads_compact_batches_without_application_consumption() {
    let directory =
        std::path::PathBuf::from(std::env::var("PEERWORK_COMPACT_LIVE_DIRECTORY").unwrap());
    assert!(directory.is_absolute() && !directory.exists());
    crate::secure_state::create_private_state_directory(&directory).unwrap();
    let identity = KernelIdentity::create(&directory.join("identity")).unwrap();
    let options = WatchOptions {
        workspace_id: "W".repeat(43),
        mailbox_id: "M".repeat(43),
        membership_id: "G".repeat(43),
        consumer_id: "creator".into(),
        host_destination: None,
    };
    let config = config(&directory, identity.actor_id());
    let event = json!({"kind":"peerwork.synthetic.host-check","token":"PW-COMPACT-REAL-HOST","text":"Synthetic retained work; no business action is requested."});
    crate::participant_inbox::seed_notification_events(
        &config.engines[0].state_directory,
        &identity,
        "http://127.0.0.1:1/",
        &options,
        &[(1, event)],
    );
    let (ready, stop, task) = start(config.clone()).await;
    let profile = profile(&ready, identity.actor_id(), &options, "creator");
    crate::communication_host::write_private(
        &directory.join("profile.json"),
        &serde_json::to_vec(&profile).unwrap(),
    )
    .unwrap();
    let tools = AgentTools::open(profile).await.unwrap();
    let hub = Hub::open(&config.state_directory).unwrap();
    let key = peerwork_core::crypto::sha256_hex(
        json!([
            "http://127.0.0.1:1/",
            identity.actor_id(),
            "program:creator",
            "CLAUDE_CHANNEL"
        ])
        .to_string()
        .as_bytes(),
    );
    let source = peerwork_core::crypto::sha256_hex(
        json!([
            "http://127.0.0.1:1/",
            identity.actor_id(),
            "program:creator",
            options
        ])
        .to_string()
        .as_bytes(),
    );
    let heads = |checkpoint| {
        vec![SourceHead {
            key: source.clone(),
            checkpoint,
            has_pending: checkpoint > 0,
        }]
    };
    crate::communication_host::write_private(
        &directory.join("ready.json"),
        b"{\"state\":\"LOCAL_FIXTURE_READY\"}",
    )
    .unwrap();
    let host_path = directory.join("host.json");
    tokio::time::timeout(Duration::from_secs(60), async {
        while !host_path.is_file() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("explicit real host configuration missing");
    let host_config = crate::communication_store::private_json(&host_path, 65536).unwrap();
    assert!(matches!(
        host_config["kind"].as_str(),
        Some("codex" | "agy-stdio")
    ));
    let executor = tokio::runtime::Handle::current();
    let host = tokio::task::spawn_blocking(move || {
        crate::communication_host::Host::open(host_config, executor)
    })
    .await
    .unwrap()
    .unwrap();
    let host = std::sync::Arc::new(std::sync::Mutex::new(host));
    let mut observations = Vec::new();
    let result: Result<(),String> = async {
        // A controlled initial frontier precedes the synthetic cached event.
        // Only the host can carry the opaque probe to the model tool call.
        for (label,checkpoint) in [("initial-probe",0),("fresh-content",1),("resume-probe",1)] {
            if label=="resume-probe" {
                let paused=invoke(&tools,"delivery",json!({"mode":"pause"})).await;
                assert_eq!(paused["state"],"PAUSED");
                assert!(hub.store.due(&key,&heads(1),crate::participant_store::now()).unwrap().is_none());
                invoke(&tools,"delivery",json!({"mode":"resume"})).await;
            }
            let wake=hub.store.due(&key,&heads(checkpoint),crate::participant_store::now()).map_err(|e|e.code)?.ok_or("expected notification missing")?;
            let idle_host=host.clone();
            tokio::task::spawn_blocking(move || {
                let deadline=std::time::Instant::now()+Duration::from_secs(90);
                loop {
                    let health=idle_host.lock().unwrap().health(&json!({}))?;
                    if health["ready"]==true && health["execution_state"]=="IDLE" {return Ok::<(), &'static str>(());}
                    if std::time::Instant::now()>=deadline{return Err("REAL_HOST_IDLE_TIMEOUT");}
                    std::thread::sleep(Duration::from_millis(50));
                }
            }).await.map_err(|_|"HOST_HEALTH_TASK_FAILED")?.map_err(str::to_owned)?;
            let batch=wake.batch.clone();let selected=host.clone();let admitted=hub.clone();let selected_key=key.clone();
            let before=std::time::Instant::now();
            let outcome=tokio::task::spawn_blocking(move || {
                let _admission=admitted.admit(&selected_key,&wake.batch,wake.revision).map_err(|_|"NOTIFICATION_ADMISSION_FAILED")?;
                selected.lock().map_err(|_|"HOST_LOCK_FAILED")?.deliver_notice(&json!({}),&wake)
            }).await.map_err(|_|"HOST_TASK_FAILED")?.map_err(str::to_owned)?;
            observations.push(json!({"phase":label,"host_outcome":outcome["state"],"host_receipt_ms":before.elapsed().as_secs_f64()*1000.}));
            tokio::time::timeout(Duration::from_secs(120),async {
                loop {
                    if hub.store.current(&key).unwrap().is_none(){break;}
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.map_err(|_|format!("REAL_MODEL_BATCH_READ_TIMEOUT_{label}"))?;
            assert!(hub.store.batch(&key,&batch).is_ok());
            assert_eq!(hub.store.status(&key).unwrap()["state"],"RUNNING");
            observations.last_mut().unwrap()["bound_read_ms"]=json!(before.elapsed().as_secs_f64()*1000.);
            if label!="initial-probe" {assert!(hub.store.due(&key,&heads(1),crate::participant_store::now()+600_000).unwrap().is_none(),"read notification must not repeat for unconsumed work");}
        }
        let retained=invoke(&tools,"inbox",json!({"view":"active","limit":1})).await;
        assert_eq!(retained["items"][0]["state"],"PENDING");
        assert_eq!(retained["items"][0]["item"]["sequence"],1);
        Ok(())
    }.await;
    tokio::task::spawn_blocking(move || drop(host))
        .await
        .unwrap();
    drop(tools);
    stop.cancel();
    task.await.unwrap().unwrap();
    let record = json!({"state":if result.is_ok(){"PASS"}else{"FAILED"},"error":result.as_ref().err(),"samples":observations,"application_consumption":"UNCHANGED","existing_peer_processes":"UNTOUCHED","service_ingestion":"SYNTHETIC_CACHE_ONLY","model_tool_read":"OPAQUE_BATCH_FROM_HOST","owned_runtime_and_adapter_stopped":true});
    crate::communication_host::write_private(
        &directory.join("result.json"),
        &serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    assert!(result.is_ok(), "{record}");
}
