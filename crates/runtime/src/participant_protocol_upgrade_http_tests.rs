//! Shared product fixture + ordinary local-registry MCP + original native API.
use super::*;
use super::management::mcp;
use crate::{communication_runtime as ipc,participant_connect::{Connect,Registration,ConnectRequest}};
use tokio::io::AsyncWriteExt;
fn fixtures()->Value {
    let output=std::process::Command::new(std::env::var("PEERWORK_TEST_NODE").expect("explicit fixture Node"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/protocol-upgrade-fixtures.mjs")).output().unwrap();
    assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));serde_json::from_slice(&output.stdout).unwrap()
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL, product build and real HTTP"]
async fn normal_alias_upgrade_routes_old_work_new_roots_and_preserves_original_intents(){
    let fixture=fixtures();let service=Service::start();let root=crate::test_support::protected_test_dir();let mut config=configuration(root.path(),&service.origin);config.transport.request_timeout_ms=20_000;
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"upgrade-space","structure.workspace.create",&Scope::default(),json!({"name":"Native instance upgrades"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let registered=mutate(&owner,"register-v1","structure.protocol.register",&scope,json!({"bundle":fixture["v1"]})).await;
    let mut bootstrap=fixture["writer1"].clone();bootstrap.as_object_mut().unwrap().remove("expires_at");
    let adopted=mutate(&owner,"adopt-v1","structure.adopt",&scope,json!({"package_digest":registered["package_digest"],"bootstrap_grant":bootstrap})).await;
    let instance=adopted["instance_id"].as_str().unwrap().to_owned();
    let key=install_synthetic_key(&config,&ws,&[83;32],None);mutate(&owner,"upgrade-key-head","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let peer_root=crate::test_support::protected_test_dir();let peer_config=configuration(peer_root.path(),&service.origin);let peer=ParticipantClient::open(peer_config.clone()).await.unwrap();
    let current=selected(&owner,"structure.workspace.get",&scope,json!({})).await;let mut join=Invoke::new("upgrade-second-member","structure.member.set",scope.clone(),json!({"actor_id":peer_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}));join.expected_workspace_revision=current["workspace_revision"].as_u64();let joined=owner.invoke(join,Duration::from_secs(5)).await.unwrap();assert_eq!(joined.state,"ACCEPTED");peer.close().await.unwrap();
    owner.close().await.unwrap();
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],engines:vec![ipc::EngineConfig{name:"original".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),authority:config.authority.clone(),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:8,max_pending:64,max_stored_bytes:32*1024*1024,migration_sources:vec![]}],clients:vec![ipc::ClientConfig{name:"owner".into(),engine:"original".into(),capability:Capability::owner()}]};
    let stop=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime,stop.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let registry=root.path().join("registry");let mut connect=Connect::open(&registry).unwrap();
    connect.register("owner",Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:ready.client_endpoints["owner"].clone()}).await.unwrap();
    let request:ConnectRequest=serde_json::from_value(json!({"participant":"owner","workspace_id":ws,"alias":"project","protocols":[{"alias":"tickets","instance_id":instance,"role":"WORKER"},{"alias":"tickets_alt","instance_id":instance,"role":"WORKER"}]})).unwrap();
    let result=connect.run_agent(request).await.unwrap();assert_eq!(result["state"],"LOCAL_CONFIGURED","{result}");
    let workspace_baseline=service.counts().await["workspaces"].clone();
    let initial=connect.profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();assert!(initial.protocol_views.values().any(|v|v.selected.read_only));
    let original_endpoint=initial.protocol_endpoints["tickets"].clone();let original_client=ipc::RuntimeClient::connect(original_endpoint.clone(),&service.origin,&config.expected_actor).await.unwrap();let original_binding=original_client.call(json!({"method":"binding"})).await.unwrap();drop(connect);
    let(server,client)=tokio::io::duplex(1024*1024);let(sr,sw)=tokio::io::split(server);let(cr,mut cw)=tokio::io::split(client);let mut cr=tokio::io::BufReader::new(cr);
    let frontend=tokio::spawn(crate::agent_mcp::serve_local_selected(registry.clone(),Some("owner".into()),Some(ws.clone()),tokio::io::BufReader::new(sr),sw));
    let old_args=json!({"protocol":"tickets","operation_id":"old-root","action":"ticket.create","structure":{"title":"old work"},"plaintext_contents":[{"record_index":0,"text":"original old body"}],"expected_revision":1,"wait_ms":5000});
    let first=mcp(&mut cr,&mut cw,1,"act",old_args.clone()).await;assert_eq!(first["state"],"ACCEPTED","{first}");
    let old_record=first["result"]["produced_record_ids"][0].as_str().unwrap().to_owned();let old_ref=json!({"record_id":old_record,"revision":1});
    let enabled=mcp(&mut cr,&mut cw,2,"connect",json!({"request":{"workspace_id":ws,"management":["protocol.upgrade"]}})).await;assert_eq!(enabled["state"],"LOCAL_CONFIGURED","{enabled}");
    let role=mcp(&mut cr,&mut cw,3,"manage",json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"role-docs-v1","body":{"bundle":fixture["role1"]},"wait_ms":5000})).await;
    assert_eq!(role["state"],"ACCEPTED","{role}");assert_eq!(role["result"]["structure"]["upgrade_kind"],"ROLE_BUNDLE_UPDATED");assert_eq!(role["result"]["structure"]["revision"],2);
    let reader=ipc::RuntimeClient::connect(initial.protocol_views.values().find(|view|view.selected.read_only).unwrap().endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();
    let mut race_old=Invoke::new("same-intent-cross-view-race","structure.action",initial.protocols["tickets"].clone(),json!({"action_id":"ticket.create","structure":{"title":"one original intent"}}));race_old.expected_instance_revision=Some(2);
    let race_old_selected=reader.call(json!({"method":"resolve_execution","request":race_old})).await.unwrap();
    // Freeze and send a v1 CREATE before changing the default, but hold its
    // HTTP arrival. It must later reject unchanged, rather than become v2.
    service.config(json!({"delay_action":"structure.action"})).await;
    let frozen_args=json!({"protocol":"tickets","operation_id":"frozen-before-upgrade","action":"ticket.create","structure":{"title":"must not retarget"},"expected_revision":2,"wait_ms":0});
    let frozen=mcp(&mut cr,&mut cw,4,"act",frozen_args.clone()).await;assert!(frozen["error"].is_null(),"{frozen}");
    tokio::time::timeout(Duration::from_secs(5),async{loop{if service.counts().await["delayed"].as_u64().unwrap_or(0)>0{break;}tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();
    let mut grant=fixture["writer2"].clone();grant["actor_id"]=json!(config.expected_actor);let mut peer_grant=fixture["writer2"].clone();peer_grant["actor_id"]=json!(peer_config.expected_actor);
    // Membership generation and grant CAS are software-derived from verified
    // metadata, while the meaningful role/action/capability selection is ours.
    let before_upgrade=service.counts().await;
    let upgrade_args=json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"upgrade-v2","body":{"bundle":fixture["v2"],"grants":[grant,peer_grant]},"wait_ms":5000});
    let upgraded=mcp(&mut cr,&mut cw,5,"manage",upgrade_args.clone()).await;assert_eq!(upgraded["state"],"ACCEPTED","{upgraded}");assert_eq!(upgraded["result"]["structure"]["upgrade_kind"],"DEFAULT_ACTIVATED");
    let context2=upgraded["result"]["structure"]["execution_context_id"].as_str().unwrap().to_owned();let protocol2=upgraded["result"]["structure"]["protocol_digest"].as_str().unwrap().to_owned();let default_revision=upgraded["result"]["structure"]["default_revision"].as_u64().unwrap();
    assert_ne!(context2,instance);assert_eq!(upgraded["result"]["structure"]["state"]["last_title"],"");
    assert_eq!(service.counts().await["members_batches"].as_u64().unwrap(),before_upgrade["members_batches"].as_u64().unwrap()+1);assert_eq!(service.counts().await["grant_batches"],before_upgrade["grant_batches"]);
    service.config(json!({"release":true})).await;
    let mut call=6;
    tokio::time::timeout(Duration::from_secs(10),async{loop{let status=mcp(&mut cr,&mut cw,call,"status",frozen["recovery_arguments"].clone()).await;call+=1;if status["state"]=="REJECTED_NO_EFFECT"{break;}assert_ne!(status["state"],"ACCEPTED","frozen work was retargeted: {status}");tokio::time::sleep(Duration::from_millis(20)).await;}}).await.unwrap();
    let counts=service.counts().await;let again=mcp(&mut cr,&mut cw,call,"act",frozen_args).await;call+=1;assert_eq!(again["state"],"REJECTED_NO_EFFECT");assert_eq!(service.counts().await["actions"]["structure.action"],counts["actions"]["structure.action"]);
    let schema=mcp(&mut cr,&mut cw,call,"protocol",json!({"protocol":"tickets","record_id":old_record,"role":"WORKER"})).await;call+=1;
    assert!(schema["runtime"]["tools"].as_array().unwrap().iter().any(|tool|tool["action"]=="ticket.update"));assert!(!schema["runtime"]["tools"].as_array().unwrap().iter().any(|tool|tool["action"]=="ticket.revise"));
    let current=mcp(&mut cr,&mut cw,call,"read",json!({"protocol":"tickets"})).await;call+=1;assert_eq!(current["execution_context_id"],context2);assert_eq!(current["revision"],1);
    let created=mcp(&mut cr,&mut cw,call,"act",json!({"protocol":"tickets","operation_id":"new-root","action":"ticket.create","structure":{"headline":"new work"},"plaintext_contents":[{"record_index":0,"text":"new generation body"}],"expected_revision":1,"wait_ms":5000})).await;call+=1;assert_eq!(created["state"],"ACCEPTED","{created}");
    assert!(created["recovery_arguments"]["protocol_view"].is_string());
    // Two independent native frontends finished preparation on opposite sides
    // of the default upgrade. They race the same semantic ID into immutable
    // namespaces. Only one may admit/sign/send, even when both would reject
    // under their frozen version rules (old CAS versus new input schema).
    let latest=Connect::inspect(&registry).unwrap().profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();
    let new_view=&latest.protocol_views[created["recovery_arguments"]["protocol_view"].as_str().unwrap()];
    let race_new_client=ipc::RuntimeClient::connect(new_view.endpoint_path.clone(),&service.origin,&config.expected_actor).await.unwrap();
    let mut race_new=race_old.clone();race_new.scope=new_view.selected.scope.clone();
    let race_new_selected=reader.call(json!({"method":"resolve_execution","request":race_new})).await.unwrap();
    let before_race=service.counts().await;let barrier=std::sync::Arc::new(tokio::sync::Barrier::new(2));let old_barrier=barrier.clone();
    let(old_result,new_result)=tokio::join!(async{old_barrier.wait().await;original_client.call(json!({"method":"invoke","request":race_old,"resolved_request":race_old_selected,"protocol_route":true,"wait_ms":5000})).await},async{barrier.wait().await;race_new_client.call(json!({"method":"invoke","request":race_new,"resolved_request":race_new_selected,"protocol_route":true,"wait_ms":5000})).await});
    assert_eq!(usize::from(old_result.is_ok())+usize::from(new_result.is_ok()),1,"old={old_result:?}, new={new_result:?}");
    let loser=old_result.as_ref().err().or(new_result.as_ref().err()).unwrap();assert_eq!(loser.code,"PROTOCOL_OPERATION_ROUTE_EXISTS");
    assert_eq!(service.counts().await["actions"]["structure.action"].as_u64().unwrap(),before_race["actions"]["structure.action"].as_u64().unwrap()+1);
    let winner=if old_result.is_ok(){&original_client}else{&race_new_client};let winner_request=if old_result.is_ok(){race_old.clone()}else{race_new.clone()};
    let same=winner.call(json!({"method":"invoke","request":winner_request,"protocol_route":true,"wait_ms":5000})).await.unwrap();assert_eq!(same["command_id"],old_result.as_ref().or(new_result.as_ref()).unwrap()["command_id"]);
    let mut changed=race_new.clone();changed.body["structure"]["title"]=json!("another intent");let conflict=race_new_client.call(json!({"method":"invoke","request":changed,"resolved_request":null,"protocol_route":true,"wait_ms":0})).await.unwrap_err();assert_eq!(conflict.code,"OPERATION_INPUT_CONFLICT");
    drop(race_new_client);
    let continued=mcp(&mut cr,&mut cw,call,"act",json!({"protocol":"tickets","record_id":old_record,"operation_id":"old-continuation","action":"ticket.update","structure":{"previous":old_ref,"title":"old continued"},"plaintext_contents":[{"record_index":0,"text":"continued old body"}],"exact_input_refs":[old_ref],"expected_revision":2,"wait_ms":5000})).await;call+=1;assert_eq!(continued["state"],"ACCEPTED","{continued}");
    let rows=mcp(&mut cr,&mut cw,call,"read",json!({"protocol":"tickets","view":"records","limit":32})).await;call+=1;
    let records=rows["records"].as_array().unwrap();assert!(records.iter().any(|row|row["execution_context_id"]==instance));assert!(records.iter().any(|row|row["execution_context_id"]==context2));
    let bodies=rows["opened_contents"].as_array().unwrap();assert!(bodies.iter().any(|body|body["text"]=="continued old body"));assert!(bodies.iter().any(|body|body["text"]=="new generation body"));
    assert_eq!(original_client.call(json!({"method":"binding"})).await.unwrap(),original_binding);
    let original=mcp(&mut cr,&mut cw,call,"status",json!({"protocol":"tickets","operation_id":"old-root"})).await;call+=1;assert_eq!(original["command_id"],first["command_id"]);
    let counts=service.counts().await;let repeated=mcp(&mut cr,&mut cw,call,"act",old_args.clone()).await;call+=1;assert_eq!(repeated["command_id"],first["command_id"]);assert_eq!(service.counts().await["actions"]["structure.action"],counts["actions"]["structure.action"]);
    let mut other_alias=old_args.clone();other_alias["protocol"]=json!("tickets_alt");let same_other_alias=mcp(&mut cr,&mut cw,call,"act",other_alias.clone()).await;call+=1;assert_eq!(same_other_alias["command_id"],first["command_id"]);
    other_alias["structure"]["title"]=json!("different intent through another alias");let other_conflict=mcp(&mut cr,&mut cw,call,"act",other_alias).await;call+=1;assert_eq!(other_conflict["error"]["code"],"OPERATION_INPUT_CONFLICT","{other_conflict}");assert_eq!(service.counts().await["actions"]["structure.action"],counts["actions"]["structure.action"]);
    let changed=mcp(&mut cr,&mut cw,call,"act",json!({"protocol":"tickets","operation_id":"old-root","action":"ticket.create","structure":{"title":"changed old work"},"plaintext_contents":[{"record_index":0,"text":"original old body"}],"expected_revision":1,"wait_ms":5000})).await;call+=1;
    assert_eq!(changed["error"]["code"],"OPERATION_INPUT_CONFLICT","{changed}");assert_eq!(service.counts().await["actions"]["structure.action"],counts["actions"]["structure.action"]);
    let before_repeat=service.counts().await;let repeat_upgrade=mcp(&mut cr,&mut cw,call,"manage",upgrade_args).await;call+=1;assert_eq!(repeat_upgrade["command_id"],upgraded["command_id"]);assert_eq!(service.counts().await["members_batches"],before_repeat["members_batches"]);assert_eq!(service.counts().await["grant_batches"],before_repeat["grant_batches"]);
    let docs=mcp(&mut cr,&mut cw,call,"manage",json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"edit-old-v1-docs","body":{"record_id":old_record,"bundle":fixture["oldRole"]},"wait_ms":5000})).await;call+=1;
    assert_eq!(docs["state"],"ACCEPTED","{docs}");assert_eq!(docs["result"]["structure"]["upgrade_kind"],"ROLE_BUNDLE_UPDATED");assert_eq!(docs["result"]["structure"]["execution_context_id"],instance);assert_eq!(docs["result"]["structure"]["default_revision"],default_revision);
    // Full Rust/native API: a previously verified v2 default fence is still
    // valid after an unrelated nondefault v1 instruction edit.
    let native=ipc::RuntimeClient::connect(ready.client_endpoints["owner"].clone(),&service.origin,&config.expected_actor).await.unwrap();
    // A v2-only local management credential cannot use an explicit old
    // context to cross its digest ceiling during native preparation.
    let mut bounded=Capability::owner();bounded.allow_root=false;bounded.workspace_ids=Some([ws.clone()].into());bounded.instance_ids=Some([instance.clone()].into());bounded.protocol_digests=Some([protocol2.clone()].into());bounded.operations.retain(|operation|matches!(operation.as_str(),"structure.grant.set"|"participant.publication.publish"));
    let derived=native.call(json!({"method":"derive","name":"v2-only-grant-ceiling","capability":bounded})).await.unwrap();let grant_client=ipc::RuntimeClient::connect(PathBuf::from(derived["endpoint_path"].as_str().unwrap()),&service.origin,&config.expected_actor).await.unwrap();
    let before_grant=service.counts().await;let attempt=Invoke::new("old-context-cannot-bypass-v2-cap","structure.grant.set",Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance.clone()),protocol_digest:Some(protocol2.clone())},json!({"execution_context_id":instance,"actor_id":config.expected_actor,"membership_id":"M".repeat(43),"expected_grant_revision":1,"actions":[],"protocol_roles":[],"capabilities":[],"expires_at":null}));
    let denied=grant_client.call(json!({"method":"invoke","request":attempt,"wait_ms":5000})).await.unwrap_err();assert_eq!(denied.code,"LOCAL_SCOPE_DENIED");assert_eq!(service.counts().await["actions"]["structure.grant.set"],before_grant["actions"]["structure.grant.set"]);
    let publication=Invoke::new("old-record-cannot-bypass-v2-cap","participant.publication.publish",Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance.clone()),protocol_digest:Some(protocol2.clone())},json!({"record_id":old_record,"revision":1,"title":"Explicit publication consent","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"RECORD"}}));
    let denied=grant_client.call(json!({"method":"invoke","request":publication,"wait_ms":5000})).await.unwrap_err();assert_eq!(denied.code,"LOCAL_SCOPE_DENIED");assert_eq!(service.counts().await["actions"]["structure.publication.entry.set"],before_grant["actions"]["structure.publication.entry.set"]);drop(grant_client);
    let meta=native.call(json!({"method":"request","request":Invoke::new("publication-workspace-head","structure.workspace.get",scope.clone(),json!({}))})).await.unwrap();
    let mut open_view=Invoke::new("open-synthetic-public-view","structure.publication.set",scope.clone(),json!({"state":"PUBLIC","expected_publication_revision":0,"title":"Synthetic old work","description":"Explicit synthetic test disclosure","disclosure":"PUBLISH_SELECTED_CONTENT"}));open_view.expected_workspace_revision=meta["result"]["structure"]["workspace_revision"].as_u64();
    assert_eq!(native.call(json!({"method":"invoke","request":open_view,"wait_ms":5000})).await.unwrap()["state"],"ACCEPTED");
    let publication=Invoke::new("publish-old-record-from-logical-v2","participant.publication.publish",Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance.clone()),protocol_digest:Some(protocol2.clone())},json!({"record_id":old_record,"revision":1,"title":"Explicit old-record publication","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"RECORD"}}));
    let published=native.call(json!({"method":"invoke","request":publication,"wait_ms":5000})).await.unwrap();
    let publication_author=published["outcome"]["result"]["structure"]["author_intent"].as_str().and_then(|jws|jws.split('.').nth(1)).and_then(|payload|peerwork_core::crypto::decode_base64url(payload).ok()).and_then(|payload|serde_json::from_slice::<Value>(&payload).ok()).unwrap_or(Value::Null);
    let publication_evidence=json!({"state":published["state"],"command_id":published["command_id"],"proto":published["outcome"]["result"]["structure"]["protocol_digest"],"ctx":publication_author["body"]["execution_context_id"]});eprintln!("synthetic old-record publication acceptance: {publication_evidence}");assert_eq!(published["state"],"ACCEPTED","{publication_evidence}");assert_eq!(published["outcome"]["result"]["structure"]["protocol_digest"],initial.protocols["tickets"].protocol_digest.as_deref().unwrap(),"{publication_evidence}");
    let mut cached=Invoke::new("cached-v2-default","structure.action",Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance.clone()),protocol_digest:Some(protocol2)},json!({"execution_context_id":context2,"expected_binding_revision":default_revision,"action_id":"ticket.create","structure":{"headline":"cached v2 fence remains valid"}}));cached.expected_instance_revision=Some(2);
    let cached_result=native.call(json!({"method":"invoke","request":cached,"wait_ms":5000})).await.unwrap();assert_eq!(cached_result["state"],"ACCEPTED","{cached_result}");
    let reactivated=mcp(&mut cr,&mut cw,call,"manage",json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"reactivate-v1","body":{"target_package_digest":docs["result"]["structure"]["package_digest"]},"wait_ms":5000})).await;call+=1;
    assert_eq!(reactivated["state"],"ACCEPTED","{reactivated}");assert_eq!(reactivated["result"]["structure"]["upgrade_kind"],"DEFAULT_REACTIVATED");assert_eq!(reactivated["result"]["structure"]["execution_context_id"],instance);assert_eq!(reactivated["result"]["structure"]["state"]["last_title"],"old continued");
    let before=service.counts().await;
    let unchanged=mcp(&mut cr,&mut cw,call,"manage",json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"already-current-v1","body":{"target_package_digest":docs["result"]["structure"]["package_digest"]},"wait_ms":5000})).await;call+=1;
    assert_eq!(unchanged["state"],"ACCEPTED","{unchanged}");assert_eq!(unchanged["result"]["structure"]["upgrade_kind"],"UNCHANGED");assert_eq!(unchanged["result"]["structure"]["default_revision"],reactivated["result"]["structure"]["default_revision"]);assert_eq!(service.counts().await["events"],before["events"]);
    let mut owner_grant=fixture["writer1"].clone();owner_grant["actor_id"]=json!(config.expected_actor);let mut peer_grant=fixture["writer1"].clone();peer_grant["actor_id"]=json!(peer_config.expected_actor);let before_batch=service.counts().await;
    let refreshed=mcp(&mut cr,&mut cw,call,"manage",json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"refresh-existing-v1-authority","body":{"target_package_digest":docs["result"]["structure"]["package_digest"],"grants":[owner_grant,peer_grant]},"wait_ms":5000})).await;call+=1;
    assert_eq!(refreshed["state"],"ACCEPTED","{refreshed}");assert_eq!(service.counts().await["members_batches"].as_u64().unwrap(),before_batch["members_batches"].as_u64().unwrap()+1);assert_eq!(service.counts().await["grant_batches"].as_u64().unwrap(),before_batch["grant_batches"].as_u64().unwrap()+1);
    let before_missing=service.counts().await;let mut absent=fixture["writer1"].clone();absent["actor_id"]=json!("Z".repeat(43));
    let missing=mcp(&mut cr,&mut cw,call,"manage",json!({"mode":"invoke","operation":"protocol.upgrade","protocol":"tickets","operation_id":"missing-target-is-not-a-complete-plan","body":{"target_package_digest":docs["result"]["structure"]["package_digest"],"grants":[absent]},"wait_ms":5000})).await;call+=1;
    assert_ne!(missing["state"],"ACCEPTED","{missing}");assert_eq!(service.counts().await["actions"]["structure.protocol.upgrade"],before_missing["actions"]["structure.protocol.upgrade"]);
    assert_eq!(native.call(json!({"method":"invoke","request":cached,"wait_ms":5000})).await.unwrap()["command_id"],cached_result["command_id"]);
    let observed=mcp(&mut cr,&mut cw,call,"recover",created["recovery_arguments"].clone()).await;assert_eq!(observed["command_id"],created["command_id"]);
    let latest=Connect::inspect(&registry).unwrap().profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();assert_eq!(latest.protocols.keys().map(String::as_str).collect::<Vec<_>>(),vec!["tickets","tickets_alt"]);assert!(latest.protocol_views.values().filter(|view|!view.selected.read_only).count()>=2);assert_eq!(latest.protocol_endpoints["tickets"],original_endpoint);
    assert_eq!(service.counts().await["workspaces"],workspace_baseline,"upgrading existing work must not create another workspace");assert_eq!(service.counts().await["journal_reads"],0);
    drop(reader);drop(native);drop(original_client);cw.shutdown().await.unwrap();drop(cw);drop(cr);frontend.await.unwrap().unwrap();stop.cancel();daemon.await.unwrap().unwrap();
}
