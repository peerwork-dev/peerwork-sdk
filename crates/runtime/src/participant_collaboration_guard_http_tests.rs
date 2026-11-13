//! Collaboration-first defaults through actual HTTP and the shared native API.
use super::*;
use crate::agent_tools::{AgentRequest, AgentSelection, AgentTools};

async fn tool(tools:&AgentTools,name:&str,args:Value)->Value {
    tools.call(AgentRequest::parse(name,args).unwrap()).await.unwrap()
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL and real product HTTP"]
async fn exact_instance_tools_preserve_attached_namespaces_and_work_offline_after_acceptance() {
    let service=Service::start();let home=crate::test_support::protected_test_dir();
    let mut config=configuration(home.path(),&service.origin);config.transport.request_timeout_ms=5000;
    let owner=ParticipantClient::open(config).await.unwrap();
    let ws=mutate(&owner,"space","structure.workspace.create",&Scope::default(),json!({"name":"Exact selectors"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let bundle:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
    let package=mutate(&owner,"register","structure.protocol.register",&scope,json!({"bundle":bundle["bundle"]})).await;
    let adopted=mutate(&owner,"adopt","structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":{"actions":["claim"],"protocol_roles":["WORKER"]}})).await;
    let instance=adopted["instance_id"].as_str().unwrap().to_owned();
    let mut selection=AgentSelection::for_client(&owner);selection.workspaces.insert("project".into(),ws.clone());
    let tools=AgentTools::from_client(owner.clone(),selection.clone()).unwrap();
    let selector=format!("project/{instance}");
    let inspected=tool(&tools,"protocol",json!({"protocol":selector,"role":"WORKER"})).await;
    assert_eq!(inspected["runtime"]["role"],"WORKER");
    let args=json!({"protocol":selector,"operation_id":"claim-exact","action":"claim","structure":{"ttl_ms":100},"expected_revision":1,"wait_ms":5000});
    let accepted=tool(&tools,"act",args.clone()).await;assert_eq!(accepted["state"],"ACCEPTED","{accepted}");
    let target=Scope{workspace_id:Some(ws),instance_id:Some(instance.clone()),protocol_digest:adopted["protocol_digest"].as_str().map(str::to_owned)};
    selection.protocols.insert("claim".into(),target.clone());selection.protocols.insert("claim_alt".into(),target);
    let aliases=AgentTools::from_client(owner.clone(),selection).unwrap();
    service.config(json!({"offline":true})).await;
    let before=service.counts().await;
    let status=tool(&tools,"status",accepted["recovery_arguments"].clone()).await;assert_eq!(status["command_id"],accepted["command_id"]);
    let recovered=tool(&tools,"recover",accepted["recovery_arguments"].clone()).await;assert_eq!(recovered["command_id"],accepted["command_id"]);
    let repeated=tool(&tools,"act",args.clone()).await;assert_eq!(repeated["command_id"],accepted["command_id"]);
    let repeated=tool(&aliases,"act",args).await;assert_eq!(repeated["command_id"],accepted["command_id"],"aliases of one client cannot become ambiguous recovery sources");
    let after=service.counts().await;assert_eq!(before["commands"],after["commands"],"original operations do not resolve fresh metadata");
    assert_eq!(after["journal_reads"],0);
    owner.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL and real product HTTP"]
async fn ordinary_tools_discover_and_message_a_peer_admitted_after_configuration() {
    let service=Service::start();let home=crate::test_support::protected_test_dir();let peer_home=crate::test_support::protected_test_dir();
    let mut config=configuration(home.path(),&service.origin);config.transport.request_timeout_ms=5000;
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"space","structure.workspace.create",&Scope::default(),json!({"name":"New Peer"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let key=install_synthetic_key(&config,&ws,&[84;32],None);
    mutate(&owner,"key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let mut selection=AgentSelection::for_client(&owner);selection.workspaces.insert("project".into(),ws.clone());
    let tools=AgentTools::from_client(owner.clone(),selection).unwrap();
    assert_eq!(tool(&tools,"reachability",json!({})).await["members"].as_array().unwrap().len(),1);
    let peer_config=configuration(peer_home.path(),&service.origin);let peer=ParticipantClient::open(peer_config).await.unwrap();
    let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    let mut join=Invoke::new("admit-new-peer","structure.member.set",scope.clone(),json!({"actor_id":peer.actor_id(),"state":"ACTIVE","expected_membership_id":null}));join.expected_workspace_revision=meta["workspace_revision"].as_u64();
    assert_eq!(owner.invoke(join,Duration::from_secs(5)).await.unwrap().state,"ACCEPTED");
    let before=service.counts().await;
    assert_eq!(tool(&tools,"reachability",json!({})).await["members"].as_array().unwrap().len(),2);
    let sent=tool(&tools,"send",json!({"to":peer.actor_id(),"operation_id":"new-peer-message","text":"Welcome","wait_ms":5000})).await;
    assert_eq!(sent["state"],"ACCEPTED","{sent}");
    let after=service.counts().await;
    assert_eq!(before["actions"]["structure.communication.grant.set"],after["actions"]["structure.communication.grant.set"],"newcomers need no extra communication approval");
    assert_eq!(after["journal_reads"],0);
    peer.close().await.unwrap();owner.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL and real product HTTP"]
async fn business_role_approval_uses_current_protocol_maintainer_authority() {
    use crate::{communication_runtime as ipc,participant_connect::{Connect,Registration,AuthorizationRequest}};
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    let owner_home=root.path().join("owner");let maintainer_home=root.path().join("maintainer");let target_home=root.path().join("target");
    for path in [&owner_home,&maintainer_home,&target_home]{crate::secure_state::create_private_state_directory(path).unwrap();}
    let owner=ParticipantClient::open(configuration(&owner_home,&service.origin)).await.unwrap();
    let maintainer=configuration(&maintainer_home,&service.origin);let target=configuration(&target_home,&service.origin);
    let ws=mutate(&owner,"space","structure.workspace.create",&Scope::default(),json!({"name":"Delegated approval"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let bundle:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
    let package=mutate(&owner,"register","structure.protocol.register",&scope,json!({"bundle":bundle["bundle"]})).await;
    let adopted=mutate(&owner,"adopt","structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":{"actions":["claim"],"protocol_roles":["WORKER"]}})).await;
    let mut memberships=Vec::new();
    for (index,config) in [&maintainer,&target].into_iter().enumerate(){
        let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
        let mut join=Invoke::new(format!("admit-{index}"),"structure.member.set",scope.clone(),json!({"actor_id":config.expected_actor,"state":"ACTIVE","expected_membership_id":null}));join.expected_workspace_revision=meta["workspace_revision"].as_u64();
        memberships.push(structure(&owner.invoke(join,Duration::from_secs(5)).await.unwrap())["membership_id"].clone());
    }
    let instance_scope=Scope{workspace_id:Some(ws.clone()),instance_id:adopted["instance_id"].as_str().map(str::to_owned),protocol_digest:adopted["protocol_digest"].as_str().map(str::to_owned)};
    mutate(&owner,"delegate-maintenance","structure.grant.set",&instance_scope,json!({"actor_id":maintainer.expected_actor,"membership_id":memberships[0],"expected_grant_revision":null,"actions":["claim"],"protocol_roles":["WORKER"],"capabilities":["workspace.protocol.maintain"],"expires_at":null})).await;
    let engine=|name:&str,c:&ParticipantConfig|ipc::EngineConfig{name:name.into(),origin:c.origin.clone(),expected_actor:c.expected_actor.clone(),authority:None,identity_path:c.identity_path.clone(),state_directory:c.state_directory.clone(),journal_path:Some(c.journal_path.clone()),allow_loopback_http:true,transport:c.transport.clone(),max_inflight:4,max_pending:16,max_stored_bytes:8*1024*1024,migration_sources:vec![]};
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],engines:vec![engine("maintainer",&maintainer),engine("target",&target)],clients:vec![ipc::ClientConfig{name:"maintainer".into(),engine:"maintainer".into(),capability:Capability::owner()},ipc::ClientConfig{name:"target".into(),engine:"target".into(),capability:Capability::owner()}]};
    let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let mut connect=Connect::open(&root.path().join("registry")).unwrap();
    for (name,config) in [("maintainer",&maintainer),("target",&target)]{connect.register(name,Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:ready.client_endpoints[name].clone()}).await.unwrap();}
    let input=json!({"format":"peerwork.connect-authorization-request.v1","setup_id":"role-request","origin":service.origin,"workspace_id":ws,"actor_id":target.expected_actor,"membership_id":memberships[1],"owner_id":owner.actor_id(),"body_keys_required":false,"missing":[{"kind":"BUSINESS_ROLE","instance_id":instance_scope.instance_id,"protocol_digest":instance_scope.protocol_digest,"role":"WORKER","actions":["claim"]}]});
    let denied=connect.approve("target","not-a-maintainer",AuthorizationRequest::from_input(input.clone()).unwrap()).await.unwrap();
    assert_eq!(denied["state"],"REJECTED_NO_EFFECT","{denied}");assert_eq!(denied["original_operation"]["code"],"PROTOCOL_MAINTAINER_REQUIRED");
    let approved=connect.approve("maintainer","maintainer-approval",AuthorizationRequest::from_input(input.clone()).unwrap()).await.unwrap();
    assert_eq!(approved["state"],"APPROVED","{approved}");
    let grant=selected(&owner,"structure.grant.get",&instance_scope,json!({"actor_id":target.expected_actor,"view":"SUMMARY"})).await;
    assert_eq!(grant["grant"]["protocol_roles"],json!(["WORKER"]));
    let mut communication=input;communication["missing"]=json!([{"kind":"COMMUNICATION_SEND"}]);
    let error=connect.approve("maintainer","not-space-owner",AuthorizationRequest::from_input(communication).unwrap()).await.unwrap_err();assert_eq!(error.code,"APPROVER_IDENTITY_OR_ORIGIN_MISMATCH");
    cancel.cancel();daemon.await.unwrap().unwrap();owner.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL and real product HTTP"]
async fn exact_instance_cannot_promote_a_broader_metadata_route_into_action_authority() {
    use crate::{communication_runtime as ipc,agent_tools::AgentProfile};
    let service=Service::start();let root=crate::test_support::protected_test_dir();let config=configuration(root.path(),&service.origin);
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"space","structure.workspace.create",&Scope::default(),json!({"name":"Explicit action ceiling"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let bundle:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
    let package=mutate(&owner,"register","structure.protocol.register",&scope,json!({"bundle":bundle["bundle"]})).await;
    let adopted=mutate(&owner,"adopt","structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":{"actions":["claim"],"protocol_roles":["WORKER"]}})).await;
    owner.close().await.unwrap();
    let mut cap=Capability::owner();cap.allow_root=false;cap.workspace_ids=Some([ws.clone()].into());cap.business_actions=Some(["different-action".into()].into());
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],engines:vec![ipc::EngineConfig{name:"original".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),authority:None,identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:4,max_pending:16,max_stored_bytes:8*1024*1024,migration_sources:vec![]}],clients:vec![ipc::ClientConfig{name:"sender".into(),engine:"original".into(),capability:cap},ipc::ClientConfig{name:"directory".into(),engine:"original".into(),capability:Capability::owner()}]};
    let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let other="O".repeat(43);let missing=root.path().join("unavailable-other-space.json");
    let profile:AgentProfile=serde_json::from_value(json!({"format":"peerwork.agent-profile.v1","expected_origin":service.origin,"expected_actor":config.expected_actor,"endpoint_path":ready.client_endpoints["sender"],"workspaces":{"project":ws,"other":other},"directory_endpoints":{(ws.clone()):ready.client_endpoints["directory"],(other):missing},"scopes":{}})).unwrap();
    let tools=AgentTools::open(profile).await.unwrap();
    assert!(tool(&tools,"reachability",json!({"workspace":"project"})).await["members"].is_array());
    let absent=tools.call(AgentRequest::parse("status",json!({"workspace":"project","operation_id":"not-submitted"})).unwrap()).await.unwrap_err();
    assert_eq!(absent.code,"OPERATION_NOT_FOUND","an unrelated unavailable directory must not block this Space");
    let before=service.counts().await;
    let args=json!({"protocol":format!("project/{}",adopted["instance_id"].as_str().unwrap()),"operation_id":"cannot-borrow-directory","action":"claim","structure":{"ttl_ms":100},"expected_revision":1,"wait_ms":5000});
    let error=tools.call(AgentRequest::parse("act",args).unwrap()).await.unwrap_err();
    assert_eq!(error.code,"LOCAL_SCOPE_DENIED");assert_eq!(error.details.as_ref().unwrap()["restricted_by"],json!(["business_actions"]));assert!(!crate::agent_tools::refresh_protocol_error(&error));
    assert_eq!(service.counts().await["actions"]["structure.action"],before["actions"]["structure.action"]);
    cancel.cancel();daemon.await.unwrap().unwrap();
}
