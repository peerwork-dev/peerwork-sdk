//! No server/model fixture: exercise the actual engine, original encrypted
//! operation store and MCP stream. Existing pending work must remain owned by
//! its original client, even when no installation or mailbox has been created.
use crate::{
    agent_tools::{AgentRequest, AgentSelection, AgentTools},
    kernel_identity::KernelIdentity,
    participant::{Capability, Invoke, ParticipantClient, ParticipantConfig, Scope},
    participant_store::Store,
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn config(directory: &std::path::Path) -> ParticipantConfig {
    let path = directory.join("identity");
    let identity = KernelIdentity::create(&path).unwrap();
    let mut config = ParticipantConfig::new("http://127.0.0.1:1/", identity.actor_id(), path, directory.join("engine"));
    config.allow_loopback_http = true;
    config.transport.request_timeout_ms = 100;
    config
}

#[tokio::test]
async fn attached_tools_keep_original_namespace_permissions_and_client_lifecycle() {
    let root = crate::test_support::protected_test_dir();
    let owner = ParticipantClient::open(config(root.path())).await.unwrap();
    let mut rights = Capability::owner();
    rights.operations = ["structure.workspace.get".into()].into();
    rights.workspace_ids = Some(["W".repeat(43)].into());
    rights.allow_root = false;
    let original = owner.restrict("old-worker", rights).unwrap();
    let tools = AgentTools::from_client(original.clone(), AgentSelection::for_client(&original)).unwrap();
    let context = tools.call(AgentRequest::Context).await.unwrap();
    assert_eq!(context["actor_id"], original.actor_id());
    assert_eq!(context["local_engine"], "ATTACHED_ORIGINAL_CLIENT");
    assert_eq!(context["state_migration_required"], false);
    assert_eq!(context["capability"], serde_json::to_value(original.capability()).unwrap());
    assert_eq!(context["bindings"], json!([]));
    assert!(!context.to_string().contains(root.path().to_str().unwrap()));
    assert!(!root.path().join("connect.state").exists());
    let error = tools.call(AgentRequest::Recover { recovery_view:None, protocol_view: None, management: None, workspace: None, operation_id: "missing".into(), protocol: None }).await.unwrap_err();
    assert_eq!(error.code, "OPERATION_NOT_FOUND");
    drop(tools);
    assert_eq!(original.local_namespace(), "program:old-worker");
    assert!(original.operations("", 32).await.unwrap()["items"].as_array().unwrap().is_empty());
    assert_eq!(original.invoke(Invoke::new("forbidden", "structure.workspace.create", Scope::default(), json!({"name":"bad"})), Duration::ZERO).await.unwrap_err().code, "LOCAL_SCOPE_DENIED");
    let mut wrong = AgentSelection::for_client(&original);
    wrong.expected_actor = "A".repeat(43);
    assert!(matches!(AgentTools::from_client(original.clone(), wrong), Err(e) if e.code == "CLIENT_IDENTITY_OR_ORIGIN_MISMATCH"));
    let mut wrong = AgentSelection::for_client(&original);
    wrong.expected_origin = "https://different.invalid".into();
    assert!(matches!(AgentTools::from_client(original.clone(), wrong), Err(e) if e.code == "CLIENT_IDENTITY_OR_ORIGIN_MISMATCH"));
    original.revoke_local();
    assert!(matches!(AgentTools::from_client(original.clone(), AgentSelection::for_client(&original)), Err(e) if e.code == "LOCAL_CLIENT_REVOKED"));
    owner.close().await.unwrap();
}

#[tokio::test]
async fn attached_business_action_uses_original_operation_namespace_and_capability() {
    let root = crate::test_support::protected_test_dir();
    let config=config(root.path());let identity=KernelIdentity::open(&config.identity_path).unwrap();
    let mut original=Invoke::new("same-intent","structure.action",Scope{workspace_id:Some("W".repeat(43)),instance_id:Some("I".repeat(43)),protocol_digest:Some("d".repeat(64))},json!({"action_id":"task.report","structure":{"kind":"PROGRESS"}}));original.expected_instance_revision=Some(1);
    let mut store=Store::open(&config.state_directory,&identity,&config.origin).unwrap();store.reserve("program:original-worker",&original,&identity,64,32*1024*1024).unwrap();
    store.finish("program:original-worker","same-intent",&identity,&json!({"state":"PENDING","retryable":false,"effect_certainty":"UNKNOWN"})).unwrap();drop(store);
    let owner = ParticipantClient::open(config).await.unwrap();
    let worker = owner.restrict("original-worker", Capability::owner()).unwrap();
    let mut selection = AgentSelection::for_client(&worker);
    selection.protocols.insert("tasks".into(), Scope {
        workspace_id: Some("W".repeat(43)), instance_id: Some("I".repeat(43)), protocol_digest: Some("d".repeat(64)),
    });
    let tools = AgentTools::from_client(worker.clone(), selection.clone()).unwrap();
    let action = || AgentRequest::Act { execution_context_id: None,record_id: None,
        protocol: "tasks".into(), operation_id: "same-intent".into(), action: "task.report".into(),
        structure: json!({"kind":"PROGRESS"}), plaintext_contents: None, expected_revision: 1, exact_input_refs: vec![], wait_ms: 0,
    };
    // Existing admission reuses its exact original namespace offline. Fresh
    // execution selection is covered by the real HTTP protocol acceptance.
    let submitted = tools.call(action()).await.unwrap();
    assert_eq!(submitted["operation_id"], "same-intent");
    let original = worker.operation("same-intent").await.unwrap();
    assert_eq!(original.operation_id, "same-intent");
    assert!(matches!(owner.operation("same-intent").await, Err(e) if e.code == "OPERATION_NOT_FOUND"));
    drop(tools);
    let tools = AgentTools::from_client(worker.clone(), selection.clone()).unwrap();
    tools.call(action()).await.unwrap();
    assert_eq!(worker.operations("", 32).await.unwrap()["items"].as_array().unwrap().len(), 1);
    let mut denied = Capability::owner();
    denied.operations = ["structure.workspace.get".into()].into();
    let reader = worker.restrict("reader", denied).unwrap();
    let mut selected = selection;
    selected.expected_actor = reader.actor_id().into();
    let reader_tools = AgentTools::from_client(reader.clone(), selected).unwrap();
    assert_eq!(reader_tools.call(action()).await.unwrap_err().code, "LOCAL_SCOPE_DENIED");
    assert!(reader.operations("", 32).await.unwrap()["items"].as_array().unwrap().is_empty());
    worker.revoke_local();
    assert_eq!(tools.call(action()).await.unwrap_err().code, "LOCAL_CLIENT_REVOKED");
    owner.close().await.unwrap();
}

#[tokio::test]
async fn attached_mcp_observes_original_pending_id_without_installation_or_mailbox() {
    let root = crate::test_support::protected_test_dir();
    let config = config(root.path());
    let identity = KernelIdentity::open(&config.identity_path).unwrap();
    let mut store = Store::open(&config.state_directory, &identity, &config.origin).unwrap();
    // Seed an authentic encrypted saved result before the original engine
    // starts. BLOCKED/UNKNOWN is intentionally not eligible for auto-retry.
    let request = Invoke::new("original-pending", "structure.workspace.create", Scope::default(), json!({"name":"original"}));
    store.reserve("program:legacy", &request, &identity, 64, 32*1024*1024).unwrap();
    store.finish("program:legacy", "original-pending", &identity, &json!({"state":"PENDING","retryable":false,"effect_certainty":"UNKNOWN","command_id":"original-command"})).unwrap();
    drop(store);
    let owner = ParticipantClient::open(config).await.unwrap();
    let worker = owner.restrict("legacy", Capability::owner()).unwrap();
    let selection = AgentSelection::for_client(&worker);
    let (server, client) = tokio::io::duplex(65536);
    let (sr, sw) = tokio::io::split(server);
    let (cr, mut cw) = tokio::io::split(client);
    let mut cr = BufReader::new(cr);
    let task = tokio::spawn(crate::agent_mcp::serve_client(worker.clone(), selection, BufReader::new(sr), sw));
    for (id, method, arguments) in [(1, "tools/list", json!({})), (2, "tools/call", json!({"name":"peerwork_status","arguments":{"operation_id":"original-pending"}}))] {
        let value = json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":arguments["name"],"arguments":arguments["arguments"]}});
        // tools/list accepts only its usual metadata; do not rely on ignored
        // call fields in the actual round-trip.
        let mut value = value;
        if method == "tools/list" { value["params"].as_object_mut().unwrap().remove("name"); value["params"].as_object_mut().unwrap().remove("arguments"); }
        cw.write_all(format!("{value}\n").as_bytes()).await.unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), cr.read_line(&mut line)).await.unwrap().unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], id);
        if id == 1 {
            let tools = response["result"]["tools"].as_array().unwrap();
            assert!(tools.iter().any(|t| t["name"] == "peerwork_send"));
            assert!(tools.iter().all(|t| t["name"] != "peerwork_connect" && t["name"] != "peerwork_connect_approve"));
        } else {
            assert_eq!(response["result"]["isError"], false, "{response}");
            let result = &response["result"]["structuredContent"];
            assert_eq!(result["operation_id"], "original-pending");
            assert_eq!(result["command_id"], "original-command");
            assert_eq!(result["effect_certainty"], "UNKNOWN");
        }
    }
    drop(cw); drop(cr);
    task.await.unwrap().unwrap();
    assert_eq!(worker.operation("original-pending").await.unwrap().command_id.as_deref(), Some("original-command"));
    assert!(matches!(owner.operation("original-pending").await, Err(e) if e.code == "OPERATION_NOT_FOUND"));
    assert_eq!(worker.operations("", 32).await.unwrap()["items"].as_array().unwrap().len(), 1);
    assert!(!root.path().join("connect.state").exists());
    assert_eq!(worker.watch_bindings().await.unwrap().len(), 0);
    owner.close().await.unwrap();
}
