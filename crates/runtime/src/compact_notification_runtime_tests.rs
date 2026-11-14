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
