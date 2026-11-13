//! Same task semantics across fresh selectors, with frozen old operations retained.
use super::*;
use crate::participant::{Capability,ParticipantClient};
use crate::participant::http_tests::{Service,configuration,mutate,selected,install_synthetic_key,native_message};
use crate::kernel_identity::KernelIdentity;
use std::time::Duration;

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires synthetic PostgreSQL and real product HTTP"]
async fn fresh_actor_name_and_pinned_contact_share_message_and_member_workflows(){
    let service=Service::start();let root=crate::test_support::protected_test_dir();let cfg=configuration(root.path(),&service.origin);
    let owner=ParticipantClient::open(cfg.clone()).await.unwrap();
    let ws=mutate(&owner,"create","structure.workspace.create",&Scope::default(),json!({"name":"One message workflow"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    let mailbox=mutate(&owner,"grant","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let address=MailboxAddress{mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),membership_id:mailbox["membership_id"].as_str().unwrap().into()};
    let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    let mut rename=Invoke::new("name","structure.member.name.set",scope.clone(),json!({"membership_id":address.membership_id,"name":"same-peer"}));rename.expected_workspace_revision=meta["workspace_revision"].as_u64();
    assert_eq!(owner.invoke(rename,Duration::from_secs(5)).await.unwrap().state,"ACCEPTED");
    let key=install_synthetic_key(&cfg,&ws,&[29;32],None);
    mutate(&owner,"key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let mut selection=AgentSelection::for_client(&owner);selection.workspaces.insert("project".into(),ws.clone());
    selection.scopes.insert("project".into(),MailScope{workspace_id:ws.clone(),mailbox_id:address.mailbox_id.clone(),membership_id:address.membership_id.clone()});
    selection.contacts.insert("saved-peer".into(),Contact{scope:"project".into(),recipient:address.clone()});
    let tools=AgentTools::from_client(owner.clone(),selection.clone()).unwrap();
    for (id,target) in [("actor",json!({"to":owner.actor_id()})),("name-send",json!({"to":"same-peer"})),("contact",json!({"contact":"saved-peer"}))] {
        let mut args=target;args["operation_id"]=json!(id);args["text"]=json!("Same semantic destination");args["wait_ms"]=json!(5000);
        assert_eq!(tools.call(AgentRequest::parse("send",args).unwrap()).await.unwrap()["state"],"ACCEPTED");
    }
    for args in [json!({"workspace":"project"}),json!({"scope":"project"}),json!({"contact":"saved-peer"}),json!({"actor":"same-peer"})] {
        let page=tools.call(AgentRequest::parse("reachability",args).unwrap()).await.unwrap();
        assert_eq!(page["status_subject"],"RECEIVING_AND_DECLARED_AVAILABILITY");assert_eq!(page["members"][0]["actor_id"],owner.actor_id());assert_eq!(page["complete"],true);
    }
    let diagnostic=tools.call(AgentRequest::parse("reachability",json!({"scope":"project","diagnostic":true})).unwrap()).await.unwrap();
    assert_eq!(diagnostic["status_subject"],"EXACT_MAILBOX_DIAGNOSTIC");assert_eq!(diagnostic["model_response"],"NOT_ATTESTED");
    let mut stale=selection.clone();stale.contacts.get_mut("saved-peer").unwrap().recipient.mailbox_id="X".repeat(43);
    let pinned=AgentTools::from_client(owner.clone(),stale).unwrap();
    let rejected=pinned.call(AgentRequest::parse("send",json!({"contact":"saved-peer","operation_id":"stale-address","text":"Must not retarget","wait_ms":5000})).unwrap()).await.unwrap();assert_eq!(rejected["effect_certainty"],"NO_EFFECT","{rejected}");
    let mut exact_cap=Capability::owner();exact_cap.operations.remove("structure.members.read");exact_cap.mailbox_ids=Some([address.mailbox_id.clone()].into());
    let exact_only=AgentTools::from_client(owner.restrict("exact-address-only",exact_cap).unwrap(),selection.clone()).unwrap();let before=service.counts().await;
    assert_eq!(exact_only.call(AgentRequest::parse("send",json!({"contact":"saved-peer","operation_id":"exact-without-directory","text":"Explicit narrow address","wait_ms":5000})).unwrap()).await.unwrap()["state"],"ACCEPTED");
    assert_eq!(service.counts().await["actions"]["structure.members.read"],before["actions"]["structure.members.read"]);
    let mut capability=Capability::owner();capability.mailbox_ids=Some(Default::default());
    let narrow=AgentTools::from_client(owner.restrict("explicit-mailbox-denial",capability).unwrap(),selection).unwrap();
    assert_eq!(narrow.call(AgentRequest::parse("send",json!({"contact":"saved-peer","operation_id":"restricted","text":"Denied"})).unwrap()).await.unwrap_err().code,"LOCAL_SCOPE_DENIED");
    // A historical conversation is frozen before the upgraded tool is attached.
    let legacy=native_message("historical-message",&scope,&mailbox,&mailbox,&"L".repeat(43),"Keep the old conversation");
    assert_eq!(owner.invoke(legacy,Duration::from_secs(5)).await.unwrap().state,"ACCEPTED");
    let historical=owner.operation("historical-message").await.unwrap();
    drop(service);
    for id in ["actor","contact","historical-message"] {
        let request=AgentRequest::parse("send",json!({"contact":"saved-peer","operation_id":id,"text":"Changed input must not execute"})).unwrap();
        let refusal=tokio::time::timeout(Duration::from_secs(2),tools.call(request.clone())).await.unwrap().unwrap_err();assert_eq!(refusal.code,"EXISTING_OPERATION_USE_STATUS_OR_RECOVER");
        let preflight=tools.original_request(&request).await.unwrap().unwrap();assert_eq!(preflight["error"]["details"]["recovery_arguments"]["operation_id"],id);
    }
    assert_eq!(tools.call(AgentRequest::parse("recover",json!({"operation_id":"historical-message"})).unwrap()).await.unwrap()["state"],"ACCEPTED");
    assert_eq!(owner.operation("historical-message").await.unwrap().command_id,historical.command_id);
    drop(exact_only);drop(narrow);drop(pinned);drop(tools);owner.close().await.unwrap();
    let identity=KernelIdentity::open(&cfg.identity_path).unwrap();let store=crate::participant_store::Store::open(&cfg.state_directory,&identity,&crate::transport::canonical_lifecycle_origin(&cfg.origin,true).unwrap()).unwrap();
    let actor=store.request("program","actor",&identity).unwrap();
    for id in ["name-send","contact"] {let request=store.request("program",id,&identity).unwrap();assert_eq!(request.body,actor.body);assert_eq!(request.scope,actor.scope);}
    let rejected=store.request("program","stale-address",&identity).unwrap();assert_eq!(rejected.body["recipients"][0]["mailbox_id"],"X".repeat(43));
    let saved=store.request("program","historical-message",&identity).unwrap();assert_eq!(saved.body["conversation_id"],"L".repeat(43));assert_eq!(saved.body["recipients"][0],json!(address));
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires synthetic PostgreSQL and real product HTTP"]
async fn uncertain_original_send_is_found_before_current_directory_resolution(){
    let service=Service::start();let root=crate::test_support::protected_test_dir();let cfg=configuration(root.path(),&service.origin);let owner=ParticipantClient::open(cfg.clone()).await.unwrap();
    let ws=mutate(&owner,"create","structure.workspace.create",&Scope::default(),json!({"name":"Original uncertain send"})).await["workspace_id"].as_str().unwrap().to_owned();let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    let mailbox=mutate(&owner,"grant","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key=install_synthetic_key(&cfg,&ws,&[31;32],None);mutate(&owner,"key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let mut selection=AgentSelection::for_client(&owner);selection.workspaces.insert("project".into(),ws.clone());let tools=AgentTools::from_client(owner.clone(),selection).unwrap();
    service.config(json!({"delay_action":"structure.message.send"})).await;
    let original=native_message("unknown-original",&scope,&mailbox,&mailbox,&"U".repeat(43),"Frozen unknown message");owner.invoke(original,Duration::ZERO).await.unwrap();
    let before=service.counts().await;
    let request=AgentRequest::parse("send",json!({"to":"unresolvable-name","operation_id":"unknown-original","text":"Replacement forbidden"})).unwrap();
    let failure=tokio::time::timeout(Duration::from_secs(2),tools.call(request.clone())).await.unwrap().unwrap_err();assert_eq!(failure.code,"EXISTING_OPERATION_USE_STATUS_OR_RECOVER");
    assert!(tools.original_request(&request).await.unwrap().is_some());
    let after=service.counts().await;assert_eq!(before["actions"]["structure.members.read"],after["actions"]["structure.members.read"]);
    service.config(json!({"release":true})).await;drop(tools);owner.close().await.unwrap();
}
