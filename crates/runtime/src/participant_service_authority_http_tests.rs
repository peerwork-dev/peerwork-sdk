//! Ordinary authorization through a sealed old native installation, real HTTP
//! and native IPC. Explicit foreign signer delegates are tested separately.
use super::*;
use crate::{agent_tools::{AgentRequest,AgentTools},communication_runtime as ipc,
    participant_connect::{Connect,ConnectRequest,Registration},kernel_identity::KernelIdentity};

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires designated TEST PostgreSQL and real product HTTP"]
async fn ordinary_native_authority_normalizes_before_context_and_survives_restart() {
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    let config=configuration(root.path(),&service.origin);
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"create","structure.workspace.create",&Scope::default(),json!({"name":"Service authority"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let bundle:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
    let package=mutate(&owner,"register","structure.protocol.register",&scope,json!({"bundle":bundle["bundle"]})).await;
    let adopted=mutate(&owner,"adopt","structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":{"actions":["claim"],"protocol_roles":["WORKER"]}})).await;
    owner.close().await.unwrap();
    // The original unknown operation is encrypted in the original namespace.
    let identity=KernelIdentity::open(&config.identity_path).unwrap();
    let origin=crate::transport::canonical_lifecycle_origin(&config.origin,true).unwrap();
    let mut store=crate::participant_store::Store::open(&config.state_directory,&identity,&origin).unwrap();
    let pending=Invoke::new("original-unknown","structure.member.name.set",scope.clone(),json!({"membership_id":"M".repeat(43),"name":"Original"}));
    store.reserve("program:bootstrap",&pending,&identity,64,32*1024*1024).unwrap();
    store.finish("program:bootstrap","original-unknown",&identity,&json!({"state":"PENDING","retryable":false,"effect_certainty":"UNKNOWN","command_id":"C".repeat(43)})).unwrap();drop(store);
    let registry=root.path().join("registry");let mut connect=Connect::open(&registry).unwrap();
    let runtime_directory=registry.join("runtime-peer");crate::secure_state::create_private_state_directory(&runtime_directory).unwrap();
    let mut old_cap=Capability::owner();
    for action in ["structure.members.read","structure.instance.resolve","structure.protocol.resolve","structure.protocol.resource.get","structure.action"]{old_cap.operations.remove(action);}
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:runtime_directory.clone(),hosts:vec![],
        engines:vec![ipc::EngineConfig{name:"selected".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),authority:config.authority.clone(),
            identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),allow_loopback_http:true,
            transport:config.transport.clone(),max_inflight:4,max_pending:64,max_stored_bytes:32*1024*1024,migration_sources:vec![]}],
        clients:vec![ipc::ClientConfig{name:"bootstrap".into(),engine:"selected".into(),capability:old_cap.clone()}]};
    let original_config=serde_json::to_vec(&runtime).unwrap();
    crate::communication_host::write_private(&runtime_directory.join("config.json"),&original_config).unwrap();
    let launch=crate::secure_state::SecureStateStore::open(&runtime_directory.join("bootstrap.state")).unwrap();
    launch.write_exact(&serde_json::to_vec(&json!({"config_digest":peerwork_core::crypto::sha256_hex(&original_config),"pid":null,"process_token":null,"launcher":null})).unwrap()).unwrap();drop(launch);
    let stop=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime.clone(),stop.clone(),tx));let ready=rx.await.unwrap().unwrap();
    connect.register("peer",Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:ready.client_endpoints["bootstrap"].clone()}).await.unwrap();drop(connect);
    let store=crate::secure_state::SecureStateStore::open(&registry.join("connect.state")).unwrap();let mut state:Value=serde_json::from_slice(&store.read_exact().unwrap().unwrap()).unwrap();
    state["local_runtime_admins"]=json!({"peer":ready.admin_endpoint});store.write_exact(&serde_json::to_vec(&state).unwrap()).unwrap();drop(store);
    let mut connect=Connect::open(&registry).unwrap();
    let request:ConnectRequest=serde_json::from_value(json!({"participant":"peer","workspace_id":ws,"alias":"project","send":false,"receive":false,
        "protocols":[{"alias":"tasks","instance_id":adopted["instance_id"],"role":"WORKER","actions":["claim"]}]})).unwrap();
    assert_eq!(connect.run(request).await.unwrap()["state"],"LOCAL_CONFIGURED");
    let mut profile=connect.profile_for_scope(Some("peer"),Some(&ws)).unwrap().unwrap();
    assert_eq!(profile.protocol_endpoints["tasks"],profile.endpoint_path);
    let current=ipc::RuntimeClient::connect(profile.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();
    assert!(Capability::from_observation(&current.call(json!({"method":"capabilities"})).await.unwrap()).unwrap().operations.contains("*"));
    drop(current);drop(connect);
    // Reproduce a previously declared SERVICE_CURRENT projection that still
    // contains the old bootstrap operation snapshot. Context must repair it.
    profile.endpoint_path=ready.client_endpoints["bootstrap"].clone();profile.directory_endpoints.clear();profile.protocol_endpoints.clear();
    let store=crate::secure_state::SecureStateStore::open(&registry.join("connect.state")).unwrap();let mut state:Value=serde_json::from_slice(&store.read_exact().unwrap().unwrap()).unwrap();let active=state["active"].as_str().unwrap().to_owned();
    state["setups"][&active]["profile"]=json!(profile);state["setups"][&active]["sender_capability"]=json!(old_cap);
    state["setups"][&active]["result"].as_object_mut().unwrap().remove("client_authority_revision");
    assert_eq!(state["setups"][&active]["result"]["client_authority_model"],"SERVICE_CURRENT");
    store.write_exact(&serde_json::to_vec(&state).unwrap()).unwrap();drop(store);
    let before=service.counts().await;
    let lifecycle=crate::agent_lifecycle::Lifecycle::local(registry.clone(),Some("peer".into()),Some(ws.clone()));
    let context=lifecycle.call(AgentRequest::Context).await.unwrap();assert_eq!(context["actor_id"],config.expected_actor);
    assert_eq!(service.counts().await["commands"],before["commands"],"normalization must not submit remote permissions or work");
    let fixed=Connect::inspect(&registry).unwrap().profile_for_scope(Some("peer"),Some(&ws)).unwrap().unwrap();
    assert_ne!(fixed.endpoint_path,profile.endpoint_path);assert!(fixed.recovery_views.values().any(|view|view.endpoint_path==profile.endpoint_path));
    let tools=AgentTools::open(fixed.clone()).await.unwrap();
    let role=tools.call(AgentRequest::parse("protocol",json!({"protocol":"tasks","role":"WORKER"})).unwrap()).await.unwrap();assert_eq!(role["runtime"]["role"],"WORKER");
    assert!(tools.call(AgentRequest::parse("reachability",json!({"workspace":"project"})).unwrap()).await.unwrap()["members"].is_array());
    let pending=lifecycle.call(AgentRequest::parse("status",json!({"workspace":"project","operation_id":"original-unknown"})).unwrap()).await.unwrap();assert_eq!(pending["command_id"],"C".repeat(43));
    let original=ipc::RuntimeClient::connect(profile.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();assert_eq!(original.call(json!({"method":"capabilities"})).await.unwrap()["capability"],json!(old_cap));
    let selected=ipc::RuntimeClient::connect(fixed.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();let binding=crate::communication_runtime::canonical_binding(&selected.call(json!({"method":"binding"})).await.unwrap());
    drop(tools);drop(original);drop(selected);drop(lifecycle);stop.cancel();daemon.await.unwrap().unwrap();
    let stop=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime,stop.clone(),tx));rx.await.unwrap().unwrap();
    let restored=ipc::RuntimeClient::connect_bound(fixed.endpoint_path.clone(),&service.origin,&config.expected_actor,binding).await.unwrap();
    assert!(Capability::from_observation(&restored.call(json!({"method":"capabilities"})).await.unwrap()).unwrap().operations.contains("*"));
    let tools=AgentTools::open(fixed).await.unwrap();assert_eq!(tools.call(AgentRequest::parse("protocol",json!({"protocol":"tasks","role":"WORKER"})).unwrap()).await.unwrap()["runtime"]["role"],"WORKER");
    assert_eq!(std::fs::read(runtime_directory.join("config.json")).unwrap(),original_config);
    assert!(service.counts().await["actions"]["structure.member.name.set"].is_null(),"the original unknown intent must not be replayed");
    drop(tools);drop(restored);stop.cancel();daemon.await.unwrap().unwrap();
}
