//! A browser role delta reuses current maintainer authority in its exact execution.
use super::*;
use crate::{communication_runtime as ipc,participant_connect::{Connect,Registration,AuthorizationRequest}};

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated local TEST PostgreSQL and real HTTP"]
async fn action_only_approval_preserves_upgraded_context_existing_roles_and_original_id() {
    let fixtures=std::process::Command::new(std::env::var("PEERWORK_TEST_NODE").unwrap())
        .arg(PathBuf::from(std::env::var_os("PEERWORK_SDK_REFERENCE_ROOT").unwrap()).join("tests/protocol-upgrade-fixtures.mjs"))
        .output().unwrap();
    assert!(fixtures.status.success(),"{}",String::from_utf8_lossy(&fixtures.stderr));
    let fixture:Value=serde_json::from_slice(&fixtures.stdout).unwrap();
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    for name in ["owner","maintainer","target"]{crate::secure_state::create_private_state_directory(&root.path().join(name)).unwrap();}
    let owner_config=configuration(&root.path().join("owner"),&service.origin);
    let owner=ParticipantClient::open(owner_config).await.unwrap();
    let maintainer=configuration(&root.path().join("maintainer"),&service.origin);
    let target=configuration(&root.path().join("target"),&service.origin);
    let workspace=mutate(&owner,"context-space","structure.workspace.create",&Scope::default(),json!({"name":"Exact role delta"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(workspace.clone()),..Default::default()};
    let package=mutate(&owner,"context-package","structure.protocol.register",&scope,json!({"bundle":fixture["v1"]})).await;
    let mut bootstrap=fixture["writer1"].clone();bootstrap.as_object_mut().unwrap().remove("expires_at");
    let adopted=mutate(&owner,"context-adopt","structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":bootstrap})).await;
    let instance=adopted["instance_id"].as_str().unwrap().to_owned();
    let mut memberships=Vec::new();
    for (index,config) in [&maintainer,&target].into_iter().enumerate(){
        let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
        let mut request=Invoke::new(format!("context-member-{index}"),"structure.member.set",scope.clone(),json!({"actor_id":config.expected_actor,"state":"ACTIVE","expected_membership_id":null}));
        request.expected_workspace_revision=meta["workspace_revision"].as_u64();
        memberships.push(structure(&owner.invoke(request,Duration::from_secs(5)).await.unwrap())["membership_id"].clone());
    }
    let mut maintenance=fixture["writer2"].clone();maintenance["actor_id"]=json!(maintainer.expected_actor);maintenance["capabilities"]=json!(["workspace.protocol.maintain"]);
    let mut existing_role=fixture["writer2"].clone();existing_role["actor_id"]=json!(target.expected_actor);existing_role["actions"]=json!(["ticket.revise"]);
    let initial=Scope{workspace_id:scope.workspace_id.clone(),instance_id:Some(instance.clone()),protocol_digest:adopted["protocol_digest"].as_str().map(str::to_owned)};
    let mut owner_writer=fixture["writer2"].clone();owner_writer["actor_id"]=json!(owner.actor_id());
    let upgrade=owner.invoke(Invoke::new("context-upgrade","participant.protocol.upgrade",scope.clone(),json!({"instance_id":instance,"bundle":fixture["v2"],"grants":[owner_writer,maintenance,existing_role]})),Duration::from_secs(10)).await.unwrap();
    assert_eq!(upgrade.state,"ACCEPTED","{upgrade:?}");let upgraded=structure(&upgrade);
    let context=upgraded["execution_context_id"].as_str().unwrap().to_owned();assert_ne!(context,instance);
    let selected_scope=Scope{workspace_id:scope.workspace_id.clone(),instance_id:Some(instance.clone()),protocol_digest:upgraded["protocol_digest"].as_str().map(str::to_owned)};
    let engine=|name:&str,config:&ParticipantConfig|ipc::EngineConfig{name:name.into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),authority:None,identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:4,max_pending:16,max_stored_bytes:8*1024*1024,migration_sources:vec![]};
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],engines:vec![engine("maintainer",&maintainer),engine("target",&target)],clients:vec![ipc::ClientConfig{name:"maintainer".into(),engine:"maintainer".into(),capability:Capability::owner()},ipc::ClientConfig{name:"target".into(),engine:"target".into(),capability:Capability::owner()}]};
    let stop=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime,stop.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let mut connect=Connect::open(&root.path().join("registry")).unwrap();
    for (name,config) in [("maintainer",&maintainer),("target",&target)]{connect.register(name,Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:ready.client_endpoints[name].clone()}).await.unwrap();}
    let mut input=json!({"format":"peerwork.connect-authorization-request.v1","setup_id":"browser-role-delta","origin":crate::transport::canonical_lifecycle_origin(&service.origin,true).unwrap(),"workspace_id":workspace,"actor_id":target.expected_actor,"membership_id":memberships[1],"owner_id":owner.actor_id(),"body_keys_required":false,"missing":[{"kind":"BUSINESS_ROLE","instance_id":instance,"protocol_digest":selected_scope.protocol_digest,"execution_context_id":context,"actions":["ticket.create"]}]});
    let denied=connect.approve("target","cannot-self-grant",AuthorizationRequest::from_input(input.clone()).unwrap()).await.unwrap();
    assert_eq!(denied["state"],"REJECTED_NO_EFFECT","{denied}");assert_eq!(denied["original_operation"]["code"],"PROTOCOL_MAINTAINER_REQUIRED");
    let approved=connect.approve("maintainer","exact-context-approval",AuthorizationRequest::from_input(input.clone()).unwrap()).await.unwrap();
    assert_eq!(approved["state"],"APPROVED","{approved}");
    let grant=selected(&owner,"structure.grant.get",&selected_scope,json!({"actor_id":target.expected_actor,"execution_context_id":context,"view":"SUMMARY"})).await;
    assert_eq!(grant["grant"]["execution_context_id"],context);assert_eq!(grant["grant"]["actions"],json!(["ticket.create","ticket.revise"]));
    assert_eq!(grant["grant"]["protocol_roles"],fixture["writer2"]["protocol_roles"]);
    let old=selected(&owner,"structure.grant.get",&initial,json!({"actor_id":target.expected_actor,"execution_context_id":instance,"view":"SUMMARY"})).await;
    assert!(old["grant"].is_null(),"new role delta must not write the old execution: {old}");
    let before=service.counts().await;
    let repeated=connect.approve("maintainer","exact-context-approval",AuthorizationRequest::from_input(input.clone()).unwrap()).await.unwrap();
    assert_eq!(repeated["results"],approved["results"]);assert_eq!(service.counts().await["actions"]["structure.grant.set"],before["actions"]["structure.grant.set"]);
    input["missing"][0]["execution_context_id"]=json!(instance);
    let error=connect.approve("maintainer","exact-context-approval",AuthorizationRequest::from_input(input).unwrap()).await.unwrap_err();assert_eq!(error.code,"APPROVAL_ID_CONFLICT_RESUME_ORIGINAL");
    drop(connect);stop.cancel();daemon.await.unwrap().unwrap();owner.close().await.unwrap();
}
