use super::*;

struct Fixture {
    _root:crate::test_support::ProtectedTestDir,
    identity:KernelIdentity,
    config:ParticipantConfig,
    owner:Arc<SecureStateStore>,
    selected:WatchOptions,
    other:WatchOptions,
    request:HostRebindRequest,
}
fn fixture()->(Fixture,Controller) {
    let root=crate::test_support::protected_test_dir();
    let identity_path=root.path().join("identity");
    let identity=KernelIdentity::create(&identity_path).unwrap();
    let engine:crate::communication_runtime::EngineConfig=serde_json::from_value(json!({
        "name":"one","origin":"https://example.invalid/","expected_actor":identity.actor_id(),
        "identity_path":identity_path,"state_directory":root.path().join("engine")
    })).unwrap();
    let config=engine.participant_config();
    crate::secure_state::create_private_state_directory(&config.state_directory).unwrap();
    let owner=Arc::new(SecureStateStore::open(&config.state_directory.join("engine-owner.state")).unwrap());
    let logical=participant_owner::logical_binding(&identity,&config.origin,&sha256_hex(identity.actor_id().as_bytes()));
    owner.write_exact(&logical).unwrap();
    let mut controller=Controller::open(&config,&identity,&config.origin,owner.clone()).unwrap();
    let selected=WatchOptions{workspace_id:"w".repeat(43),mailbox_id:"m".repeat(43),membership_id:"g".repeat(43),consumer_id:"original".into(),host_destination:None};
    let mut other=selected.clone();other.workspace_id="z".repeat(43);other.mailbox_id="n".repeat(43);
    let subscription=HostSubscription{client:"worker".into(),client_generation:None,watch:selected.clone()};
    let request=HostRebindRequest{format:"peerwork.host-rebind.v1".into(),operation_id:"resident".into(),engine:"one".into(),host:"selected".into(),adapter:json!({"kind":"codex-app-server","url":"ws://127.0.0.1:1","thread_id":"selected"}),initial_subscriptions:Some(vec![subscription.clone()])};
    let original=RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),engines:vec![engine],clients:vec![],hosts:vec![]};
    let destination=HostBinding::new(json!({"host":"CODEX_APP_SERVER","session_id":"selected","conversation_id":"selected"})).unwrap();
    let mut target=original.clone();target.hosts.push(HostConfig{name:request.host.clone(),adapter:request.adapter.clone(),subscriptions:vec![subscription.clone()]});
    let id=token(json!(["peerwork.resident-host-rebind.v1",logical,config.state_directory,request.operation_id]));
    let pin=MaintenancePin{operation_id:id.clone(),selection_digest:sha256_hex(serde_json::to_string(&request).unwrap().as_bytes()),expected_revision:0};
    let scope=Subscription{namespace:"program:worker".into(),old:selected.clone(),expected:Pins{workspace_id:selected.workspace_id.clone(),mailbox_id:selected.mailbox_id.clone(),membership_id:selected.membership_id.clone(),receiver_id:"r".repeat(43),epoch:1,destination_digest:"d".repeat(64),binding_version:1,after_sequence:7,after_control_sequence:Some(3)},claim_id:"c".repeat(43),claim_wire:None,confirmed:None,committed:false,was_enabled:true,rejected:vec![],refresh_epoch_on_retry:false,source_client:Some(subscription)};
    let job=Job{format:"peerwork.host-rebind-job.v1".into(),request:request.clone(),pin,original,target,destination,host_key:"h".repeat(64),host_state_before:None,scopes:vec![scope],ready:false,decisions:vec![],aborting:None,aborted:false};
    let store=SecureStateStore::open(&config.state_directory.join(format!("resident-rebind-{id}.state"))).unwrap();
    let aad=Controller::aad(&logical,&id);save(&store,&identity,&aad,&job).unwrap();drop(store);
    controller.index=Index{active:Some(id.clone()),jobs:vec![id]};controller.save_index().unwrap();drop(controller);
    // Simulate a crash after sealed job + index but before legacy owner begin.
    let controller=Controller::open(&config,&identity,&config.origin,owner.clone()).unwrap();
    (Fixture{_root:root,identity,config,owner,selected,other,request},controller)
}
#[test]
fn resident_startup_fences_only_saved_scopes_and_legacy_reader_fails_closed() {
    let (f,controller)=fixture();
    assert!(controller.paused(&f.selected));assert!(!controller.paused(&f.other));
    assert_eq!(participant_owner::validate_ready(&f.owner,&controller.logical).unwrap_err().code,"OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION");
    assert!(!controller.active.as_ref().unwrap().authorized,"restart cannot bypass dispatcher drain");
    drop(controller);
    let restored=Controller::open(&f.config,&f.identity,&f.config.origin,f.owner.clone()).unwrap();
    assert_eq!(restored.status().unwrap().unwrap().request.operation_id,"resident");
    assert!(restored.paused(&f.selected));assert!(!restored.paused(&f.other));
}
#[test]
fn resident_startup_recognizes_completion_before_final_job_save() {
    for abort in [false,true] {
        let(f,mut controller)=fixture();
        let active=controller.active.as_mut().unwrap();
        if abort {active.job.aborting=Some("stop".into());}
        else {active.job.scopes[0].confirmed=Some(active.job.scopes[0].expected.clone());active.job.scopes[0].committed=true;}
        save(&active.store,&f.identity,&active.aad,&active.job).unwrap();
        participant_owner::complete(&f.owner,&controller.logical,&active.job.pin).unwrap();drop(controller);
        let restored=Controller::open(&f.config,&f.identity,&f.config.origin,f.owner.clone()).unwrap();
        assert!(restored.status().unwrap().is_none());
        let completed=restored.lookup(&f.request,&f.identity).unwrap().unwrap();
        assert_eq!(completed.finished,!abort);assert_eq!(completed.aborted,abort);
        participant_owner::validate_ready(&f.owner,&restored.logical).unwrap();
    }
}
#[test]
fn resident_does_not_adopt_an_unrelated_global_pending_operation() {
    let(f,controller)=fixture();let binding=controller.logical.clone();let own=controller.active.as_ref().unwrap().job.pin.clone();drop(controller);
    participant_owner::complete(&f.owner,&binding,&own).unwrap();
    let other=MaintenancePin{operation_id:"u".repeat(43),selection_digest:"e".repeat(64),expected_revision:1};
    participant_owner::begin(&f.owner,&binding,&other).unwrap();
    assert_eq!(Controller::open(&f.config,&f.identity,&f.config.origin,f.owner.clone()).err().unwrap().code,"HOST_REBIND_OWNER_SELECTION_CHANGED");
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn explicit_abort_with_live_sources_still_waits_for_original_dispatcher_drain() {
    let(f,mut controller)=fixture();
    // A live source is selection evidence. It cannot substitute for the
    // original dispatcher's acknowledgement that input/result writes drained.
    let source_config=ParticipantConfig::new(&f.config.origin,f.identity.actor_id(),&f.config.identity_path,f._root.path().join("source-engine"));
    let source=ParticipantClient::open(source_config).await.unwrap();
    let selected=source.restrict("worker",crate::participant::Capability::owner()).unwrap();
    let active=controller.active.as_mut().unwrap();
    active.sources=vec![Source{subscription:active.job.scopes[0].source_client.clone().unwrap(),client:selected}];
    let journal=crate::kernel_intents::KernelIntentJournal::open(&f.config.journal_path).unwrap();drop(journal);
    let decision=HostRebindRecoveryRequest{format:"peerwork.host-rebind-recovery.v1".into(),decision_id:"before-drain".into(),action:HostRebindRecoveryAction::Abort};
    let snapshot=controller.recover(&f.request,&decision,&f.identity).unwrap();
    assert!(snapshot.aborting);assert!(!snapshot.rollback_ready);
    assert!(!controller.active.as_ref().unwrap().authorized);
    let mut inbox=InboxStore::open_local(&f.config.state_directory,&f.identity,&f.config.origin).unwrap();
    assert!(controller.next(&mut inbox,&f.identity).unwrap().is_none(),"no mailbox close/read may run before the original dispatcher barrier");
    drop(inbox);drop(controller);source.close().await.unwrap();
    let restored=Controller::open(&f.config,&f.identity,&f.config.origin,f.owner.clone()).unwrap();
    assert!(restored.status().unwrap().unwrap().aborting);
    assert!(!restored.active.as_ref().unwrap().authorized,"restart must observe the same barrier again");
}
