//! Ordinary Connect/MCP coverage, rather than an unrestricted attached client.
use super::*;
use crate::{agent_tools::{AgentTools,AgentRequest},communication_runtime as ipc,participant_connect::{Connect,ConnectRequest,Registration}};
use tokio::io::{AsyncBufRead,AsyncBufReadExt,AsyncWrite,AsyncWriteExt};

pub(super) async fn mcp<R:AsyncBufRead+Unpin,W:AsyncWrite+Unpin>(reader:&mut R,writer:&mut W,id:u64,tool:&str,arguments:Value)->Value {
    let request=json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":format!("peerwork_{tool}"),"arguments":arguments,
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}});
    writer.write_all(format!("{request}\n").as_bytes()).await.unwrap();writer.flush().await.unwrap();
    let mut line=String::new();tokio::time::timeout(Duration::from_secs(30),reader.read_line(&mut line)).await.unwrap().unwrap();
    let response:Value=serde_json::from_str(&line).unwrap();assert_eq!(response["id"],id,"{response}");
    assert!(response["error"].is_null(),"{response}");response["result"]["structuredContent"].clone()
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires local TEST PostgreSQL and real product HTTP"]
async fn connect_management_mcp_uses_immutable_views_and_retains_original_receiver_and_pending() {
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    let config=configuration(root.path(),&service.origin);let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"management-space","structure.workspace.create",&Scope::default(),json!({"name":"Ordinary MCP management"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let metadata=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    mutate(&owner,"management-communication","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":metadata["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await;
    let key=install_synthetic_key(&config,&ws,&[75;32],None);
    mutate(&owner,"management-head","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    owner.close().await.unwrap();
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],
        engines:vec![ipc::EngineConfig{name:"original".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),authority:config.authority.clone(),identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:8,max_pending:64,max_stored_bytes:32*1024*1024,migration_sources:vec![]}],
        clients:vec![ipc::ClientConfig{name:"owner".into(),engine:"original".into(),capability:Capability::owner()}]};
    let cancel=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
    let daemon=tokio::spawn(ipc::serve(runtime,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let registry=root.path().join("registry");let mut connect=Connect::open(&registry).unwrap();
    connect.register("owner",Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:ready.client_endpoints["owner"].clone()}).await.unwrap();
    let request:ConnectRequest=serde_json::from_value(json!({"participant":"owner","workspace_id":ws,"alias":"project","send":true,"receive":true,"receive_mode":"INBOX"})).unwrap();
    let initial=connect.run_agent(request).await.unwrap();assert_eq!(initial["state"],"LOCAL_CONFIGURED","{initial}");
    let old_profile=connect.profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();drop(connect);
    let receiver=ipc::RuntimeClient::connect(old_profile.receive_endpoint_path.clone().unwrap(),&service.origin,&config.expected_actor).await.unwrap();
    let original_binding=receiver.call(json!({"method":"binding"})).await.unwrap();
    let original_watches=receiver.call(json!({"method":"bindings"})).await.unwrap();
    let original_sender=ipc::RuntimeClient::connect(old_profile.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();
    let original_sender_binding=original_sender.call(json!({"method":"binding"})).await.unwrap();
    let (server,client)=tokio::io::duplex(1024*1024);let(sr,sw)=tokio::io::split(server);let(cr,mut cw)=tokio::io::split(client);let mut cr=tokio::io::BufReader::new(cr);
    let frontend=tokio::spawn(crate::agent_mcp::serve_local_selected(registry.clone(),Some("owner".into()),Some(ws.clone()),tokio::io::BufReader::new(sr),sw));
    service.config(json!({"delay_action":"structure.message.send"})).await;
    let pending=mcp(&mut cr,&mut cw,1,"send",json!({"workspace":"project","to":config.expected_actor,"operation_id":"original-mail-pending","text":"Keep the original pending operation","wait_ms":0})).await;
    assert!(pending["error"].is_null(),"{pending}");
    let pending_before=original_sender.call(json!({"method":"operation","operation_id":"original-mail-pending"})).await.unwrap();
    let fixture:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
    let registration=json!({"mode":"invoke","operation":"protocol.register","workspace":"project","operation_id":"management-register","body":{"bundle":fixture["bundle"]},"wait_ms":5000});
    let denied=mcp(&mut cr,&mut cw,2,"manage",registration.clone()).await;
    assert_eq!(denied["error"]["code"],"LOCAL_SCOPE_DENIED","{denied}");
    assert_eq!(denied["error"]["details"]["management_enable"]["arguments"]["request"]["management"],json!(["protocol.register"]));
    // A view request cannot manufacture an operation absent from its selected
    // local parent, even though this actor remains the remote Workspace Owner.
    let original=ipc::RuntimeClient::connect(ready.client_endpoints["owner"].clone(),&service.origin,&config.expected_actor).await.unwrap();
    let mut limited_cap=Capability::owner();limited_cap.operations.remove("structure.protocol.register");
    let limited=original.call(json!({"method":"derive","name":"limited-management-source","capability":limited_cap})).await.unwrap();
    let mut limited_connect=Connect::open(&root.path().join("limited-registry")).unwrap();
    limited_connect.register("limited",Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:PathBuf::from(limited["endpoint_path"].as_str().unwrap())}).await.unwrap();
    let unavailable=limited_connect.run_agent(serde_json::from_value(json!({"participant":"limited","workspace_id":ws,"management":["protocol.register"]})).unwrap()).await.unwrap_err();
    assert_eq!(unavailable.code,"LOCAL_SCOPE_DENIED");
    assert_eq!(unavailable.details.as_ref().unwrap()["missing_operations"],json!(["structure.protocol.register"]));
    assert_eq!(unavailable.details.as_ref().unwrap()["remote_permission_checked"],false);
    drop(limited_connect);drop(original);
    let counts=service.counts().await;
    let enabled=mcp(&mut cr,&mut cw,3,"connect",json!({"request":{"workspace_id":ws,"management":["protocol.register","protocol.adopt","access.approve"]}})).await;
    assert_eq!(enabled["state"],"LOCAL_CONFIGURED","{enabled}");
    assert!(enabled["details"]["authorization_request"].is_null(),"view enable must not request remote rights: {enabled}");
    let profile=Connect::inspect(&registry).unwrap().profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();
    assert_eq!(profile.endpoint_path,old_profile.endpoint_path);assert_eq!(profile.receive_endpoint_path,old_profile.receive_endpoint_path);
    assert_eq!(profile.directory_endpoints,old_profile.directory_endpoints);assert_eq!(profile.protocol_endpoints,old_profile.protocol_endpoints);
    assert_eq!(profile.management_views.len(),1);let view=profile.management_views.keys().next().unwrap().clone();
    assert_eq!(receiver.call(json!({"method":"binding"})).await.unwrap(),original_binding);
    assert_eq!(receiver.call(json!({"method":"bindings"})).await.unwrap(),original_watches);
    assert_eq!(original_sender.call(json!({"method":"binding"})).await.unwrap(),original_sender_binding);
    let still_pending=original_sender.call(json!({"method":"operation","operation_id":"original-mail-pending"})).await.unwrap();
    if !pending_before["command_id"].is_null(){assert_eq!(still_pending["command_id"],pending_before["command_id"]);}
    assert_eq!(still_pending["operation_id"],pending_before["operation_id"]);
    assert_eq!(service.counts().await["actions"]["structure.communication.grant.set"],counts["actions"]["structure.communication.grant.set"]);
    let old_tools=AgentTools::open(old_profile).await.unwrap();
    assert_eq!(old_tools.call(AgentRequest::parse("manage",registration.clone()).unwrap()).await.unwrap_err().code,"LOCAL_SCOPE_DENIED","old directory credentials were widened");
    let registered=mcp(&mut cr,&mut cw,4,"manage",registration.clone()).await;assert_eq!(registered["state"],"ACCEPTED","{registered}");
    assert_eq!(registered["recovery_arguments"]["management"],view);assert!(registered["recovery_arguments"]["workspace"].is_null());
    let adopted=mcp(&mut cr,&mut cw,5,"manage",json!({"mode":"invoke","operation":"protocol.adopt","workspace":"project","operation_id":"management-adopt","body":{"package_digest":registered["result"]["structure"]["package_digest"],"bootstrap_grant":{"actions":[],"protocol_roles":[],"capabilities":[]}},"wait_ms":5000})).await;
    assert_eq!(adopted["state"],"ACCEPTED","{adopted}");
    let browser_root=crate::test_support::protected_test_dir();let browser=ParticipantClient::open(configuration(browser_root.path(),&service.origin)).await.unwrap();
    let browser_request=browser.request(Invoke::new("management-browser-request","participant.access.request",scope,json!({"label":"Managed browser","kind":"BROWSER"}))).await.unwrap();
    let approved=mcp(&mut cr,&mut cw,6,"manage",json!({"mode":"invoke","operation":"access.approve","workspace":"project","operation_id":"management-browser-approve","body":{"request_jws":browser_request["request_jws"],"deliver_content_keys":true},"wait_ms":5000})).await;
    assert_eq!(approved["state"],"ACCEPTED","{approved}");assert!(approved["result"]["browser_approval_reference"].as_str().is_some_and(|s|s.starts_with("peerwork-browser-approval:v2:")),"{approved}");
    let added=mcp(&mut cr,&mut cw,7,"connect",json!({"request":{"workspace_id":ws,"management":["protocol.register"]}})).await;assert_eq!(added["state"],"LOCAL_CONFIGURED","{added}");
    let repeated=mcp(&mut cr,&mut cw,8,"manage",registration).await;
    assert_eq!(repeated["command_id"],registered["command_id"]);assert_eq!(repeated["recovery_arguments"]["management"],view);
    assert_eq!(service.counts().await["actions"]["structure.protocol.register"],1);
    let profile=Connect::inspect(&registry).unwrap().profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();assert_eq!(profile.management_views.len(),2);assert!(profile.management_views.contains_key(&view));
    for (id,view_meta) in &profile.management_views {
        if id!=&view {
            assert!(view_meta.client_generation>profile.management_views[&view].client_generation);
            let other=ipc::RuntimeClient::connect(view_meta.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();
            assert_eq!(other.call(json!({"method":"operation","operation_id":"management-register"})).await.unwrap_err().code,"OPERATION_NOT_FOUND");
        }
    }
    let status=mcp(&mut cr,&mut cw,9,"status",registered["recovery_arguments"].clone()).await;assert_eq!(status["command_id"],registered["command_id"]);
    let recovered=mcp(&mut cr,&mut cw,10,"recover",registered["recovery_arguments"].clone()).await;assert_eq!(recovered["command_id"],registered["command_id"]);
    let ambiguous=mcp(&mut cr,&mut cw,11,"status",json!({"operation_id":"management-register","workspace":"project","management":view})).await;assert_eq!(ambiguous["error"]["code"],"OPERATION_SCOPE_AMBIGUOUS");
    service.config(json!({"release":true})).await;
    let original=mcp(&mut cr,&mut cw,12,"status",json!({"operation_id":"original-mail-pending"})).await;assert_eq!(original["operation_id"],"original-mail-pending");
    assert_eq!(original_sender.call(json!({"method":"binding"})).await.unwrap(),original_sender_binding);
    // Owner administration targets public verified instance IDs directly. It
    // does not attach a WORKER role or a new business protocol credential.
    let enabled=mcp(&mut cr,&mut cw,13,"connect",json!({"request":{"workspace_id":ws,"management":["instances.read","grant.get","grant.set"]}})).await;assert_eq!(enabled["state"],"LOCAL_CONFIGURED","{enabled}");
    let instances=mcp(&mut cr,&mut cw,14,"manage",json!({"mode":"read","operation":"instances.read","workspace":"project","body":{"limit":8}})).await;
    let target=instances["instances"].as_array().unwrap().iter().find(|instance|instance["instance_id"]==adopted["result"]["structure"]["instance_id"]).unwrap();
    let rights=mcp(&mut cr,&mut cw,15,"manage",json!({"mode":"read","operation":"grant.get","workspace":"project","instance_id":target["instance_id"],"protocol_digest":target["protocol_digest"],"body":{"actor_id":config.expected_actor}})).await;
    assert!(rights["error"].is_null(),"{rights}");
    // Grant assignments require at least one declared action; empty write
    // authority uses grant.revoke, rather than an invalid empty grant.set.
    let changed=mcp(&mut cr,&mut cw,16,"manage",json!({"mode":"invoke","operation":"grant.set","workspace":"project","instance_id":target["instance_id"],"protocol_digest":target["protocol_digest"],"operation_id":"management-owner-grant","body":{"actor_id":config.expected_actor,"membership_id":metadata["membership"]["membership_id"],"expected_grant_revision":rights["grant"]["grant_revision"],"actions":[fixture["bundle"]["manifest"]["actions"][0]["id"]],"protocol_roles":[],"capabilities":[],"expires_at":null},"wait_ms":5000})).await;
    assert_eq!(changed["state"],"ACCEPTED","{changed}");assert!(changed["recovery_arguments"]["management"].is_string());
    let missing_pair=mcp(&mut cr,&mut cw,17,"manage",json!({"mode":"read","operation":"grant.get","workspace":"project","instance_id":target["instance_id"],"body":{"actor_id":config.expected_actor}})).await;assert_eq!(missing_pair["error"]["code"],"MANAGEMENT_INSTANCE_TARGET_PAIR_REQUIRED");
    let conflicting=mcp(&mut cr,&mut cw,18,"manage",json!({"mode":"read","operation":"grant.get","protocol":"unattached","instance_id":target["instance_id"],"protocol_digest":target["protocol_digest"],"body":{"actor_id":config.expected_actor}})).await;assert_eq!(conflicting["error"]["code"],"MANAGEMENT_SCOPE_SELECTION_INVALID");
    let status=mcp(&mut cr,&mut cw,19,"status",changed["recovery_arguments"].clone()).await;assert_eq!(status["command_id"],changed["command_id"]);
    let profile=Connect::inspect(&registry).unwrap().profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();assert!(profile.protocols.is_empty());assert!(profile.protocol_endpoints.is_empty());
    browser.close().await.unwrap();drop(old_tools);drop(receiver);drop(original_sender);cw.shutdown().await.unwrap();drop(cw);drop(cr);frontend.await.unwrap().unwrap();cancel.cancel();daemon.await.unwrap().unwrap();
}
