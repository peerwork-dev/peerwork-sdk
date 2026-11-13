use super::*;
use crate::participant::{ParticipantClient,Invoke,Scope};
use crate::participant::http_tests::{Service,configuration,mutate,selected};
use crate::agent_tools::AgentRequest;
use crate::communication_runtime as ipc;
use tokio::io::{AsyncBufReadExt,AsyncWriteExt};

fn without_observation_times(mut value:Value)->Value {
    match &mut value {
        Value::Object(fields)=>{
            fields.remove("observed_at");fields.remove("evaluated_at");
            for field in fields.values_mut(){*field=without_observation_times(field.take());}
        },
        Value::Array(items)=>for item in items {*item=without_observation_times(item.take());},
        _=>(),
    }
    value
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL, product build and real HTTP"]
async fn raw_profile_owner_adoption_unifies_mcp_local_and_original_operation_recovery() {
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    let config=configuration(root.path(),&service.origin);
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"source-space","structure.workspace.create",&Scope::default(),json!({"name":"Source lifecycle"})).await["workspace_id"].as_str().unwrap().to_owned();
    let other_ws=mutate(&owner,"source-second-space","structure.workspace.create",&Scope::default(),json!({"name":"Second source Space"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let metadata=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    owner.close().await.unwrap();
    let mut legacy=Capability::owner();legacy.mailbox_ids=Some(["M".repeat(43)].into());
    // SUMMARY member discovery is intentionally available to mailbox-limited
    // clients. Model a genuine retained operation ceiling, not a restriction
    // that the shared discovery view no longer needs to cross.
    legacy.operations.remove("structure.members.read");
    let mut runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],
        engines:vec![ipc::EngineConfig{name:"original".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),authority:config.authority.clone(),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:8,max_pending:64,max_stored_bytes:32*1024*1024,migration_sources:vec![]}],
        clients:vec![ipc::ClientConfig{name:"legacy".into(),engine:"original".into(),capability:legacy.clone()}]};
    let other_root=crate::test_support::protected_test_dir();let other_config=configuration(other_root.path(),&service.origin);
    let mut other_engine=runtime.engines[0].clone();other_engine.name="separate".into();other_engine.expected_actor=other_config.expected_actor;
    other_engine.identity_path=other_config.identity_path;other_engine.state_directory=other_config.state_directory;other_engine.journal_path=Some(other_config.journal_path);
    runtime.engines.push(other_engine);runtime.clients.push(ipc::ClientConfig{name:"separate".into(),engine:"separate".into(),capability:Capability::owner()});
    let config_path=root.path().join("original-runtime.json");write_private(&config_path,&serde_json::to_vec(&runtime).unwrap()).unwrap();
    let cancel=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let task=tokio::spawn(ipc::serve(runtime.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let old=RuntimeClient::connect(ready.client_endpoints["legacy"].clone(),&service.origin,&config.expected_actor).await.unwrap();
    let original_binding=old.call(json!({"method":"binding"})).await.unwrap();
    let profile:AgentProfile=serde_json::from_value(json!({"format":"peerwork.agent-profile.v1","endpoint_path":ready.client_endpoints["legacy"],"expected_origin":service.origin,"expected_actor":config.expected_actor,"workspaces":{"project":ws,"other":other_ws},"scopes":{}})).unwrap();
    let original_profile=serde_json::to_vec(&profile).unwrap();
    let source=crate::agent_lifecycle::Lifecycle::profile(profile.clone());
    let error=source.call(AgentRequest::parse("reachability",json!({"workspace":ws})).unwrap()).await.unwrap_err();
    assert_eq!(error.code,"LOCAL_SCOPE_DENIED");assert_eq!(error.details.unwrap()["continuation"]["code"],"ORIGINAL_ISSUER_SELECTION_REQUIRED");
    let directory=Connect::profile_directory(&profile).unwrap();assert!(!directory.exists());
    // Freeze an accepted operation in the old client namespace before adoption.
    let mut name=Invoke::new("original-name","structure.member.name.set",scope.clone(),json!({"membership_id":metadata["membership"]["membership_id"],"name":"Original author"}));
    name.expected_workspace_revision=metadata["workspace_revision"].as_u64();
    let accepted=old.call(json!({"method":"invoke","request":name,"wait_ms":5000})).await.unwrap();assert_eq!(accepted["state"],"ACCEPTED","{accepted}");
    let mut connect=Connect::open(&directory).unwrap();
    let preserved=connect.adopt_profile(&profile,None,false).await.unwrap();
    assert_eq!(connect.profile_for_scope(Some(&preserved),Some(&ws)).unwrap().unwrap().endpoint_path,profile.endpoint_path);
    let handle=connect.adopt_from_owner(&profile,config_path.clone()).await.unwrap();
    assert_eq!(connect.adopt_from_owner(&profile,config_path).await.unwrap(),handle);
    let current=connect.profile_for_scope(Some(&handle),Some(&ws)).unwrap().unwrap();
    assert_eq!(current.expected_origin,old.origin());
    assert!(current.recovery_views.values().any(|view|view.workspace_id==ws));
    assert!(current.recovery_views.values().any(|view|view.workspace_id==other_ws));
    assert!(connect.profile_for_scope(Some(&handle),None).unwrap().is_some());
    let issuer=RuntimeClient::connect(current.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();
    let capability=issuer.call(json!({"method":"capabilities"})).await.unwrap()["capability"].clone();
    assert_eq!(capability["workspace_ids"].as_array().unwrap().len(),2);
    assert!(RuntimeClient::connect(ready.client_endpoints["separate"].clone(),&service.origin,&config.expected_actor).await.is_err());
    assert!(!current.recovery_views.is_empty());assert_eq!(current.receive_endpoint_path,profile.receive_endpoint_path);
    assert_eq!(connect.selected_handle(None).unwrap(),Some(handle.clone()));
    drop(connect);
    assert_eq!(old.call(json!({"method":"binding"})).await.unwrap(),original_binding);
    assert_eq!(old.call(json!({"method":"capabilities"})).await.unwrap()["capability"],serde_json::to_value(legacy).unwrap());
    assert_eq!(serde_json::to_vec(&profile).unwrap(),original_profile);
    assert_eq!(source.call(AgentRequest::parse("reachability",json!({})).unwrap()).await.unwrap_err().code,"SELECT_ONE_CONFIGURED_WORKSPACE");
    let raw=source.call(AgentRequest::parse("reachability",json!({"workspace":ws})).unwrap()).await.unwrap();
    let local=crate::agent_lifecycle::Lifecycle::local(directory.clone(),None,Some(ws.clone())).call(AgentRequest::parse("reachability",json!({"workspace":ws})).unwrap()).await.unwrap();
    assert!(raw["observed_at"].as_u64().is_some());assert!(local["observed_at"].as_u64().is_some());
    assert_eq!(without_observation_times(raw),without_observation_times(local));
    // Both MCP protocol frontends reuse the original unchanged profile source.
    for protocol in ["2025-11-25","2026-07-28"] {
        let(server,client)=tokio::io::duplex(1024*1024);let(sr,sw)=tokio::io::split(server);let(cr,mut cw)=tokio::io::split(client);let mut cr=tokio::io::BufReader::new(cr);
        let frontend=tokio::spawn(crate::agent_mcp::serve(profile.clone(),tokio::io::BufReader::new(sr),sw));
        if protocol=="2025-11-25" {
            cw.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":protocol,"capabilities":{},"clientInfo":{"name":"source-fixture","version":"1"}}})).as_bytes()).await.unwrap();
            let mut line=String::new();cr.read_line(&mut line).await.unwrap();
            cw.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
        }
        let mut params=json!({"name":"peerwork_reachability","arguments":{"workspace":ws}});
        if protocol=="2026-07-28" {params["_meta"]=json!({"io.modelcontextprotocol/protocolVersion":protocol});}
        cw.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":params})).as_bytes()).await.unwrap();
        let mut line=String::new();cr.read_line(&mut line).await.unwrap();let reply:Value=serde_json::from_str(&line).unwrap();assert!(reply["error"].is_null(),"{reply}");assert_ne!(reply["result"]["isError"],true,"{reply}");
        drop(cw);drop(cr);frontend.await.unwrap().unwrap();
    }
    // Cached clients must authenticate changed descriptor bytes before use.
    // Same actor/Origin is insufficient when the namespace was substituted.
    let original_descriptor=std::fs::read(&profile.endpoint_path).unwrap();
    let adopted_descriptor=std::fs::read(&current.endpoint_path).unwrap();
    write_private(&profile.endpoint_path,&adopted_descriptor).unwrap();
    assert_eq!(source.call(AgentRequest::Context).await.unwrap_err().code,"ORIGINAL_RUNTIME_BINDING_CHANGED");
    write_private(&profile.endpoint_path,&original_descriptor).unwrap();
    assert!(source.call(AgentRequest::Context).await.is_ok());
    write_private(&current.endpoint_path,&original_descriptor).unwrap();
    assert_eq!(source.call(AgentRequest::Context).await.unwrap_err().code,"ORIGINAL_RUNTIME_BINDING_CHANGED");
    write_private(&current.endpoint_path,&adopted_descriptor).unwrap();
    assert!(source.call(AgentRequest::Context).await.is_ok());
    service.config(json!({"offline":true})).await;
    let recovered=source.call(AgentRequest::parse("status",json!({"workspace":ws,"operation_id":"original-name"})).unwrap()).await.unwrap();
    assert_eq!(recovered["command_id"],accepted["command_id"]);assert_eq!(recovered["state"],"ACCEPTED");
    cancel.cancel();task.await.unwrap().unwrap();
    let cancel=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let task=tokio::spawn(ipc::serve(runtime,cancel.clone(),tx));rx.await.unwrap().unwrap();
    let again=source.call(AgentRequest::parse("status",json!({"workspace":ws,"operation_id":"original-name"})).unwrap()).await.unwrap();assert_eq!(again["command_id"],accepted["command_id"]);
    cancel.cancel();task.await.unwrap().unwrap();
}
