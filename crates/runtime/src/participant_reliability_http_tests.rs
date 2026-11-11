//! Fault injection uses the real product HTTP/SSE service and synthetic keys.
use super::*;
struct Member {
    scope: Scope,
    mailbox: Value,
    options: WatchOptions,
    watch: ProgramWatch,
}
struct Cohort {
    service: Service,
    _temp: crate::test_support::ProtectedTestDir,
    config: ParticipantConfig,
    client: ParticipantClient,
    members: Vec<Member>,
}
impl Cohort {
    async fn start(count: usize) -> Self {
        Self::with_destination(count,None).await
    }
    async fn with_destination(count: usize, destination: Option<String>) -> Self {
        let service=Service::start();
        let temp=crate::test_support::protected_test_dir();
        let mut config=configuration(temp.path(),&service.origin);
        config.transport.request_timeout_ms=30000;
        let client=ParticipantClient::open(config.clone()).await.unwrap();
        let mut members=Vec::new();
        for index in 0..count {
            let ws=mutate(&client,&format!("create-{index}"),"structure.workspace.create",&Scope::default(),json!({"name":format!("Reliability {index}")})).await["workspace_id"].as_str().unwrap().to_owned();
            let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
            let meta=selected(&client,"structure.workspace.get",&scope,json!({})).await;
            let mailbox=mutate(&client,&format!("grant-{index}"),"structure.communication.grant.set",&scope,json!({"actor_id":client.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
            let key=install_synthetic_key(&config,&ws,&[42;32],None);
            mutate(&client,&format!("key-{index}"),"structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
            let options=WatchOptions{workspace_id:ws,mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:format!("receiver-{index}"),host_destination:destination.clone()};
            let mut watch=client.watch(options.clone()).await.unwrap();
            watch_until(&mut watch,|s|s.receiver_link_verified).await;
            members.push(Member{scope,mailbox,options,watch});
        }
        Self{service,_temp:temp,config,client,members}
    }
    async fn send(&self,index:usize,id:&str)->Value {
        let member=&self.members[index];
        structure(&self.client.invoke(native_message(id,&member.scope,&member.mailbox,&member.mailbox,&"v".repeat(43),id),Duration::from_secs(5)).await.unwrap())
    }
}
async fn fault(watch:&mut ProgramWatch)->WatchSnapshot {
    tokio::time::timeout(Duration::from_secs(10),async {
        loop {let s=watch.next().await.unwrap();if s.verification_failure.is_some(){return s;}}
    }).await.unwrap()
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn managed_mcp_and_cli_repair_generated_directory_clients_without_replacing_original_authority(){
    use crate::{communication_runtime as ipc,participant_connect::{Connect,ConnectRequest,Registration},agent_tools::{AgentTools,AgentRequest}};
    use tokio::io::AsyncWriteExt;
    let service=Service::start();let root=crate::test_support::protected_test_dir();let config=configuration(root.path(),&service.origin);
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let ws=mutate(&owner,"directory-space","structure.workspace.create",&Scope::default(),json!({"name":"Directory recovery"})).await["workspace_id"].as_str().unwrap().to_owned();
    owner.close().await.unwrap();
    let runtime=ipc::RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),hosts:vec![],engines:vec![ipc::EngineConfig{name:"original".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),authority:config.authority.clone(),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:8,max_pending:64,max_stored_bytes:32*1024*1024,migration_sources:vec![]}],clients:vec![ipc::ClientConfig{name:"owner".into(),engine:"original".into(),capability:Capability::owner()}]};
    let stop=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let daemon=tokio::spawn(ipc::serve(runtime,stop.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let registry=root.path().join("registry");let mut connect=Connect::open(&registry).unwrap();
    connect.register("owner",Registration{origin:service.origin.clone(),actor_id:config.expected_actor.clone(),endpoint_path:ready.client_endpoints["owner"].clone()}).await.unwrap();
    let request:ConnectRequest=serde_json::from_value(json!({"participant":"owner","workspace_id":ws,"send":false,"receive":false})).unwrap();
    assert_eq!(connect.run(request).await.unwrap()["state"],"LOCAL_CONFIGURED");
    let mut profile=connect.profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();
    let original=ipc::RuntimeClient::connect(ready.client_endpoints["owner"].clone(),&service.origin,&config.expected_actor).await.unwrap();
    let mut narrow=Capability::owner();narrow.allow_root=false;narrow.workspace_ids=Some([ws.clone()].into());narrow.operations.remove("structure.members.read");narrow.instance_ids=Some(["I".repeat(43)].into());narrow.protocol_digests=Some(["a".repeat(64)].into());narrow.mailbox_ids=Some(["M".repeat(43)].into());
    let derived=original.call(json!({"method":"derive","name":"historical-directory-client","capability":narrow})).await.unwrap();let legacy=PathBuf::from(derived["endpoint_path"].as_str().unwrap());
    profile.endpoint_path=legacy.clone();profile.directory_endpoints.clear();
    let restricted=AgentTools::open(profile.clone()).await.unwrap();let baseline=service.counts().await;
    let error=restricted.call(AgentRequest::parse("reachability",json!({"workspace":ws})).unwrap()).await.unwrap_err();
    assert_eq!(error.code,"LOCAL_SCOPE_DENIED");assert_eq!(error.details.as_ref().unwrap()["restricted_by"],json!(["operations","instance_ids","protocol_digests","mailbox_ids"]));
    assert_eq!(service.counts().await["commands"],baseline["commands"],"the original denial must not submit a request");
    drop(restricted);drop(connect);
    let store=crate::secure_state::SecureStateStore::open(&registry.join("connect.state")).unwrap();let mut state:Value=serde_json::from_slice(&store.read_exact().unwrap().unwrap()).unwrap();let active=state["active"].as_str().unwrap().to_owned();
    state["setups"][&active]["profile"]=json!(profile);state["setups"][&active]["sender_capability"]=json!(narrow);state["setups"][&active]["result"].as_object_mut().unwrap().remove("client_authority_model");
    let profile_path=PathBuf::from(state["setups"][&active]["result"]["profile_path"].as_str().unwrap());crate::onboarding_files::replace(&profile_path,&serde_json::to_vec(&profile).unwrap()).unwrap();
    let historical=serde_json::to_vec(&state).unwrap();store.write_exact(&historical).unwrap();drop(store);
    let(server,client)=tokio::io::duplex(1024*1024);let(sr,sw)=tokio::io::split(server);let(cr,mut cw)=tokio::io::split(client);let mut cr=tokio::io::BufReader::new(cr);
    let frontend=tokio::spawn(crate::agent_mcp::serve_local_selected(registry.clone(),Some("owner".into()),Some(ws.clone()),tokio::io::BufReader::new(sr),sw));
    let found=super::management::mcp(&mut cr,&mut cw,1,"reachability",json!({"workspace":ws})).await;assert!(found["members"].is_array(),"{found}");assert_eq!(found["members"].as_array().unwrap().len(),1,"{found}");
    cw.shutdown().await.unwrap();drop(cw);drop(cr);frontend.await.unwrap().unwrap();
    let fixed=Connect::inspect(&registry).unwrap().profile_for_scope(Some("owner"),Some(&ws)).unwrap().unwrap();
    assert_eq!(fixed.expected_actor,config.expected_actor);assert_ne!(fixed.endpoint_path,legacy);assert!(fixed.recovery_views.values().any(|v|v.endpoint_path==legacy));
    let old=ipc::RuntimeClient::connect(legacy,&service.origin,&config.expected_actor).await.unwrap();assert_eq!(old.call(json!({"method":"capabilities"})).await.unwrap()["capability"],json!(narrow));
    let store=crate::secure_state::SecureStateStore::open(&registry.join("connect.state")).unwrap();store.write_exact(&historical).unwrap();drop(store);
    let args=vec!["--local".into(),registry.to_string_lossy().into_owned(),"--participant".into(),"owner".into(),"--workspace".into(),ws.clone(),"reachability".into()];
    let found=tokio::task::spawn_blocking(move||crate::agent_frontend::cli(&args)).await.unwrap();assert_eq!(found["members"].as_array().unwrap().len(),1,"{found}");
    assert_eq!(service.counts().await["workspaces"],baseline["workspaces"]);assert_eq!(service.counts().await["actions"]["structure.member.set"],baseline["actions"]["structure.member.set"]);
    drop(old);drop(original);stop.cancel();daemon.await.unwrap().unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn receiver_capacity_recovers_claim_pulse_ack_and_stream_without_replacing_identity_or_cursor() {
    for (action,code) in [
        ("structure.mailbox.get","RESOURCE_EXHAUSTED"),
        ("structure.mailbox.claim","RESOURCE_EXHAUSTED"),
        ("structure.mailbox.pulse","RESOURCE_EXHAUSTED"),
        ("structure.mailbox.ack","RESOURCE_EXHAUSTED"),
        ("structure.communication.stream.get","RESOURCE_EXHAUSTED"),
        ("structure.communication.stream.get","CAPACITY_RESERVATION_EXHAUSTED"),
    ] {
        eprintln!("capacity recovery case: {action} / {code}");
        let service=Service::start();
        let temp=crate::test_support::protected_test_dir();
        let config=configuration(temp.path(),&service.origin);
        let client=ParticipantClient::open(config.clone()).await.unwrap();
        let actor=client.actor_id().to_owned();
        let ws=mutate(&client,"create-capacity","structure.workspace.create",&Scope::default(),json!({"name":"Capacity recovery"})).await["workspace_id"].as_str().unwrap().to_owned();
        let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
        let meta=selected(&client,"structure.workspace.get",&scope,json!({})).await;
        let mailbox=mutate(&client,"grant-capacity","structure.communication.grant.set",&scope,json!({"actor_id":actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
        let key=install_synthetic_key(&config,&ws,&[42;32],None);
        mutate(&client,"key-capacity","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
        let options=WatchOptions{workspace_id:ws,mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:"capacity-receiver".into(),host_destination:None};
        let initial=matches!(action,"structure.mailbox.get"|"structure.mailbox.claim");
        if initial { service.config(json!({"resource_refusal":{"action":action,"code":code}})).await; }
        let mut watch=client.watch(options.clone()).await.unwrap();
        let before=if initial {watch.page(0,32).await.unwrap()} else {watch_until(&mut watch,|s|s.receiver_link_verified).await};
        if !initial {
            service.config(json!({"resource_refusal":{"action":action,"code":code},"close_connections":action=="structure.communication.stream.get"})).await;
        }
        let sent=structure(&client.invoke(native_message("during-capacity",&scope,&mailbox,&mailbox,&"v".repeat(43),"recover-original-delivery"),Duration::from_secs(5)).await.unwrap());
        let ack=action=="structure.mailbox.ack";
        let recovering=watch_until(&mut watch,|s|if ack{s.acknowledgment_code.as_deref()==Some(code)}else{s.code.as_deref()==Some(code)}).await;
        eprintln!("capacity refusal observed: {action}; code={:?}; checkpoint={}",recovering.code,recovering.checkpoint);
        assert!(service.counts().await["resource_refusals"].as_u64().unwrap_or(0)>0,"the configured resource refusal must actually occur");
        if ack {assert_eq!(recovering.acknowledgment_code.as_deref(),Some(code));assert!(recovering.receiver_link_verified);}
        else if action!="structure.mailbox.get" { assert_eq!(recovering.code.as_deref(),Some(code)); }
        assert_eq!(recovering.state,if ack{"RECEIVER_LINK_VERIFIED"}else{"RECONNECTING"},"{action} must not require a runtime restart");
        assert!(recovering.verification_failure.is_none());
        assert!(recovering.checkpoint>=before.checkpoint);
        let held=service.counts().await["resource_refusals"].as_u64().unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(service.counts().await["resource_refusals"].as_u64().unwrap(),held,"{action} must back off rather than spin");
        service.config(json!({"resource_refusal":null})).await;
        let recovered=watch_until(&mut watch,|s|s.receiver_link_verified&&s.code.is_none()&&s.acknowledgment_code.is_none()&&s.presence["key_current"]==true&&s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==sent["message_id"])).await;
        eprintln!("capacity recovery verified: {action}; checkpoint={}",recovered.checkpoint);
        assert_eq!(recovered.items.iter().filter(|v|v["envelope"]["message"]["message_id"]==sent["message_id"]).count(),1);
        assert_eq!(client.actor_id(),actor);
        assert!(recovered.checkpoint>=recovering.checkpoint);
        let current=selected(&client,"structure.mailbox.get",&scope,json!({"mailbox_id":options.mailbox_id})).await;
        assert_eq!(current["mailbox"]["epoch"],1,"capacity recovery must preserve the original receiver generation");
        let claims=service.counts().await["claim_commands"].as_array().unwrap().clone();
        assert!(claims.iter().all(|v|v["command_id"]==claims[0]["command_id"]&&v["receiver_id"]==claims[0]["receiver_id"]&&v["replace"]==false),"unknown claim attempts must retain their frozen command and receiver IDs");
        client.close().await.unwrap();
    }
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn unchanged_host_probes_coalesce_wire_traffic_without_stopping_the_receiver() {
    use crate::participant_inbox::{HostBinding,HostOperation};
    let binding=HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"synthetic-control-cost","session_id":"synthetic-probe-session","endpoint":"unix:///synthetic/unused.sock"})).unwrap();
    let c=Cohort::with_destination(1,Some(binding.digest.clone())).await;
    c.client.host_operation(&c.members[0].options,HostOperation::Attach(binding)).await.unwrap();
    let before=c.service.counts().await;
    let probes=12;
    for _ in 0..probes {
        c.client.host_operation(&c.members[0].options,HostOperation::Presence{value:json!({"mode":"LIVE","ready":true,"execution_state":"IDLE"}),observed_at:std::time::Instant::now()}).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after=c.service.counts().await;
    let pulses=after["actions"]["structure.mailbox.pulse"].as_u64().unwrap_or(0)-before["actions"]["structure.mailbox.pulse"].as_u64().unwrap_or(0);
    assert!(pulses<probes,"unchanged host probes must not force one heartbeat each");
    assert!(c.members[0].watch.page(0,32).await.unwrap().receiver_link_verified);
    let report=json!({"format":"peerwork.control-cost-probe.v1","state":"PASS","host_observations":probes,"network_pulses":pulses,
        "command_request_bytes":after["command_request_bytes"].as_u64().unwrap()-before["command_request_bytes"].as_u64().unwrap(),
        "command_response_bytes":after["command_response_bytes"].as_u64().unwrap()-before["command_response_bytes"].as_u64().unwrap(),
        "sse_bytes":after["sse_bytes"].as_u64().unwrap()-before["sse_bytes"].as_u64().unwrap(),
        "scope":"Synthetic host observations to real SDK/HTTP; no Agent session invoked; application payload bytes exclude HTTP/TLS"});
    if let Ok(path)=std::env::var("PEERWORK_CONTROL_COST_REPORT") {
        let path=std::path::PathBuf::from(path);assert!(path.is_absolute()&&!path.exists());
        std::fs::write(path,serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("{report}");c.client.close().await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn poison_is_durable_and_slow_ack_cannot_starve_lease_or_clear_quarantine() {
    let mut c=Cohort::start(2).await;
    c.service.config(json!({"delay_action":"structure.mailbox.ack"})).await;
    c.send(0,"before-slow-ack").await;
    let before=watch_until(&mut c.members[0].watch,|s|!s.items.is_empty()).await;
    tokio::time::timeout(Duration::from_secs(5),async {while c.service.counts().await["delayed"]!=1{tokio::time::sleep(Duration::from_millis(30)).await;}}).await.unwrap();
    // This deliberately crosses the actual 15-second lease, while the ACK is
    // still in flight with its real 30-second request budget.
    tokio::time::sleep(Duration::from_secs(16)).await;
    let meta=selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]})).await;
    assert!(meta["mailbox"]["lease_until"].as_u64().unwrap()>meta["mailbox"]["server_time"].as_u64().unwrap(),"slow ACK must not expire the receiver lease");
    assert_eq!(meta["mailbox"]["epoch"],1);
    c.service.config(json!({"corrupt_frame":{"mailbox_id":c.members[0].mailbox["mailbox_id"],"mode":"ITEM_PROOF"}})).await;
    let poisoned=c.send(0,"poisoned-source-proof").await;
    let isolated=fault(&mut c.members[0].watch).await;
    assert_eq!(isolated.checkpoint,before.checkpoint);
    assert_eq!(isolated.control_checkpoint,before.control_checkpoint);
    assert_eq!(isolated.verification_failure.as_ref().unwrap()["code"],"STREAM_ITEM_EVIDENCE_INVALID");
    assert_eq!(isolated.verification_failure.as_ref().unwrap()["scope_authenticated"],true);
    assert!(!isolated.receiver_link_verified);
    c.service.config(json!({"release":true})).await;
    let healthy=c.send(1,"healthy-after-poison").await;
    watch_until(&mut c.members[1].watch,|s|s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==healthy["message_id"])).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let still=c.members[0].watch.page(0,32).await.unwrap();
    assert_eq!(still.state,"BLOCKED","late ACK result must not clear receive quarantine");
    assert_eq!(still.checkpoint,before.checkpoint);
    let meta=selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]})).await;
    assert_eq!(meta["mailbox"]["state"],"DELAYED","an active lease is not receive readiness");
    assert!(meta["mailbox"]["lease_until"].as_u64().unwrap()>meta["mailbox"]["server_time"].as_u64().unwrap());
    c.client.close().await.unwrap();
    let restored=ParticipantClient::open(c.config.clone()).await.unwrap();
    let mut watch=restored.watch(c.members[0].options.clone()).await.unwrap();
    let quarantined=watch.page(0,32).await.unwrap();
    assert_eq!(quarantined.state,"BLOCKED","process restart must retain poison isolation");
    assert_eq!(quarantined.checkpoint,before.checkpoint);
    // Explicit stop/start permits one fresh fully verified probe at the same
    // durable cursor, without changing the receiver, identity or original send.
    watch.stop().await.unwrap();drop(watch);
    let mut watch=restored.watch(c.members[0].options.clone()).await.unwrap();
    let recovered=watch_until(&mut watch,|s|s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==poisoned["message_id"])).await;
    assert!(recovered.verification_failure.is_none());
    assert!(recovered.receiver_link_verified);
    restored.close().await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn slow_workspace_key_refresh_does_not_stall_other_workspace() {
    let mut c=Cohort::start(4).await;
    c.service.config(json!({"key_delay_workspace":c.members[0].options.workspace_id,"key_delay_ms":12000})).await;
    tokio::time::timeout(Duration::from_secs(25),async {
        loop {
            let s=c.members[0].watch.next().await.unwrap();
            if s.presence["body_key"]["code"]=="KEY_SYNC_TIMEOUT"{break;}
        }
    }).await.unwrap();
    for index in 1..c.members.len() {
        let sent=c.send(index,&format!("healthy-while-key-sync-times-out-{index}")).await;
        let healthy=watch_until(&mut c.members[index].watch,|s|s.receiver_link_verified&&s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==sent["message_id"])).await;
        assert_eq!(healthy.presence["key_current"],true);
        assert!(healthy.verification_failure.is_none());
    }
    c.service.config(json!({"key_delay_workspace":null,"key_delay_ms":0})).await;
    watch_until(&mut c.members[0].watch,|s|s.presence["body_key"]["state"]=="READY"&&s.presence["key_current"]==true).await;
    c.client.close().await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn expired_frame_context_is_reverified_without_skipping_delivery() {
    let mut c=Cohort::start(1).await;
    let before=c.members[0].watch.page(0,32).await.unwrap();
    c.service.config(json!({"corrupt_frame":{"mailbox_id":c.members[0].mailbox["mailbox_id"],"mode":"TIME"}})).await;
    let sent=c.send(0,"recover-time-context").await;
    let recovered=watch_until(&mut c.members[0].watch,|s|s.receiver_link_verified&&s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==sent["message_id"])).await;
    assert_eq!(recovered.items.len(),before.items.len()+1);
    assert!(recovered.verification_failure.is_none());
    assert_eq!(c.service.counts().await["corrupted_frames"],1);
    c.client.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn untrusted_signature_format_and_routing_isolate_connection_without_ack_or_cursor_progress() {
    for (mode,code) in [("SIGNATURE","STREAM_SERVICE_PROOF_INVALID"),("MALFORMED","STREAM_FRAME_FORMAT_INVALID"),("UNKNOWN_SCOPE","STREAM_SCOPE_MISMATCH")] {
        let mut c=Cohort::start(2).await;
        let before=c.members[0].watch.page(0,32).await.unwrap();
        c.service.config(json!({"corrupt_frame":{"mailbox_id":c.members[0].mailbox["mailbox_id"],"mode":mode}})).await;
        c.send(0,"untrusted-frame").await;
        let isolated=fault(&mut c.members[0].watch).await;
        let peer=fault(&mut c.members[1].watch).await;
        assert_eq!(isolated.verification_failure.as_ref().unwrap()["code"],code);
        assert_eq!(isolated.verification_failure.as_ref().unwrap()["scope_authenticated"],false);
        assert_eq!(isolated.checkpoint,before.checkpoint);
        assert_eq!(isolated.control_checkpoint,before.control_checkpoint);
        assert!(isolated.items.is_empty());
        assert!(!isolated.receiver_ack_pending);
        assert!(!isolated.receiver_link_verified);
        assert!(!peer.receiver_link_verified,"untrusted routing cannot select an authenticated offending scope");
        let streams=c.service.counts().await["native_streams"].as_u64().unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(c.service.counts().await["native_streams"],streams,"poison must not cause a reconnect loop");
        c.client.close().await.unwrap();
    }
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn invalid_control_does_not_advance_either_cursor_or_block_other_mailbox() {
    let mut c=Cohort::start(2).await;
    let before=c.members[0].watch.page(0,32).await.unwrap();
    c.service.config(json!({"corrupt_frame":{"mailbox_id":c.members[0].mailbox["mailbox_id"],"mode":"CONTROL_PROOF"}})).await;
    c.send(0,"untrusted-control").await;
    let isolated=fault(&mut c.members[0].watch).await;
    assert_eq!(isolated.verification_failure.as_ref().unwrap()["code"],"STREAM_CONTROL_EVIDENCE_INVALID");
    assert_eq!(isolated.checkpoint,before.checkpoint);
    assert_eq!(isolated.control_checkpoint,before.control_checkpoint);
    assert!(isolated.items.is_empty());
    let healthy=c.send(1,"healthy-after-control-error").await;
    watch_until(&mut c.members[1].watch,|s|s.receiver_link_verified&&s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==healthy["message_id"])).await;
    c.client.close().await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn delayed_old_pulse_is_followed_by_current_not_ready_report_and_stop_start_keeps_fence() {
    let mut c=Cohort::start(1).await;
    c.service.config(json!({"delay_action":"structure.mailbox.pulse","delay_mailbox":c.members[0].mailbox["mailbox_id"]})).await;
    tokio::time::timeout(Duration::from_secs(10),async {while c.service.counts().await["delayed"]!=1{tokio::time::sleep(Duration::from_millis(30)).await;}}).await.unwrap();
    c.service.config(json!({"corrupt_frame":{"mailbox_id":c.members[0].mailbox["mailbox_id"],"mode":"ITEM_PROOF"}})).await;
    c.send(0,"poison-during-old-pulse").await;
    fault(&mut c.members[0].watch).await;
    c.service.config(json!({"release":true})).await;
    tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let meta=selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]})).await;
            if meta["mailbox"]["state"]=="DELAYED" {break;}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }).await.unwrap();
    assert_eq!(c.members[0].watch.page(0,32).await.unwrap().state,"BLOCKED");
    c.members[0].watch.stop().await.unwrap();
    let mut watch=c.client.watch(c.members[0].options.clone()).await.unwrap();
    watch_until(&mut watch,|s|s.receiver_link_verified&&!s.items.is_empty()).await;
    let meta=selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]})).await;
    assert_eq!(meta["mailbox"]["epoch"],1);
    c.client.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn timed_out_read_is_unavailable_observation_and_does_not_become_missing_state_or_saved_intent() {
    let service=Service::start();let temp=crate::test_support::protected_test_dir();
    let cfg=configuration(temp.path(),&service.origin);
    let client=ParticipantClient::open(cfg).await.unwrap();
    let ws=mutate(&client,"read-timeout-space","structure.workspace.create",&Scope::default(),json!({"name":"Read timeout"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws),..Default::default()};
    service.config(json!({"timeout_action":"structure.workspace.get"})).await;
    let failure=match client.request(Invoke::new("failed-read","structure.workspace.get",scope.clone(),json!({}))).await {
        Err(error)=>error,Ok(value)=>panic!("delayed read unexpectedly succeeded with state {}",value["state"]),
    };
    assert_eq!(failure.code,"TIMEOUT");
    assert_eq!(failure.phase,"READ");
    assert_eq!(failure.effect_certainty,"NO_EFFECT");
    assert_eq!(failure.recovery,"REPEAT_SELECTED_READ");
    assert!(failure.operation_id.is_none());
    let details=failure.details.unwrap();
    assert_eq!(details["observation"],"UNAVAILABLE");
    assert_eq!(details["intent_persisted"],false);
    assert!(details["elapsed_ms"].as_u64().unwrap()>0);
    service.config(json!({"release":true})).await;
    let success=selected(&client,"structure.workspace.get",&scope,json!({})).await;
    assert_eq!(success["workspace_id"],scope.workspace_id.unwrap());
    client.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn one_two_four_eight_distinct_participants_receive_exact_targets_and_offline_peer_recovers() {
    for count in [1,2,4,8] {
        let mut c=Cohort::start(1).await;
        let owner=c.members.remove(0);
        let scope=owner.scope.clone();let owner_box=owner.mailbox.clone();
        let mut peers=vec![(c.config.clone(),c.client.clone(),owner.options,owner.watch,owner.mailbox)];
        for index in 1..count {
            let dir=c._temp.path().join(format!("peer-{index}"));
            crate::secure_state::create_private_state_directory(&dir).unwrap();
            let mut cfg=configuration(&dir,&c.service.origin);cfg.transport.request_timeout_ms=30000;
            let peer=ParticipantClient::open(cfg.clone()).await.unwrap();
            let meta=selected(&c.client,"structure.workspace.get",&scope,json!({})).await;
            let mut join=Invoke::new(format!("join-{index}"),"structure.member.set",scope.clone(),json!({"actor_id":peer.actor_id(),"state":"ACTIVE","expected_membership_id":null}));
            join.expected_workspace_revision=meta["workspace_revision"].as_u64();
            let joined=structure(&c.client.invoke(join,Duration::from_secs(5)).await.unwrap());
            let mailbox=mutate(&c.client,&format!("grant-peer-{index}"),"structure.communication.grant.set",&scope,json!({"actor_id":peer.actor_id(),"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
            install_synthetic_key(&cfg,scope.workspace_id.as_ref().unwrap(),&[42;32],None);
            let options=WatchOptions{workspace_id:scope.workspace_id.clone().unwrap(),mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:"receiver".into(),host_destination:None};
            let mut watch=peer.watch(options.clone()).await.unwrap();watch_until(&mut watch,|s|s.receiver_link_verified).await;
            peers.push((cfg,peer,options,watch,mailbox));
        }
        let actors=peers.iter().map(|(_,p,_,_,_)|p.actor_id().to_owned()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actors.len(),count,"cohort identities must actually be distinct");
        if count>2 {peers[count-1].1.close().await.unwrap();}
        let mut send=native_message("cohort-message",&scope,&owner_box,&owner_box,&"v".repeat(43),"Exact cohort delivery");
        send.body["recipients"]=json!(peers.iter().enumerate().filter(|(index,_)|*index!=1).map(|(_,(_,_,_,_,m))|json!({"mailbox_id":m["mailbox_id"],"membership_id":m["membership_id"]})).collect::<Vec<_>>());
        let accepted=structure(&c.client.invoke(send,Duration::from_secs(5)).await.unwrap());
        if count>2 {
            let (cfg,_,options,_,mailbox)=&peers[count-1];
            let cfg=cfg.clone();let options=options.clone();let mailbox=mailbox.clone();
            let restored=ParticipantClient::open(cfg.clone()).await.unwrap();
            let watch=restored.watch(options.clone()).await.unwrap();
            peers[count-1]=(cfg,restored,options,watch,mailbox);
        }
        for (index,(_,peer,_,watch,mailbox)) in peers.iter_mut().enumerate() {
            if index==1 {
                let meta=selected(peer,"structure.mailbox.get",&scope,json!({"mailbox_id":mailbox["mailbox_id"]})).await;
                assert_eq!(meta["mailbox"]["capacity"]["pending_items"],0,"online but unselected peer must have no delivery obligation");
                assert!(watch.page(0,32).await.unwrap().items.is_empty());continue;
            }
            let delivered=watch_until(watch,|s|s.receiver_link_verified&&s.items.iter().any(|item|item["envelope"]["message"]["message_id"]==accepted["message_id"])).await;
            assert_eq!(delivered.items.len(),1);
            assert_eq!(delivered.items[0]["opened_message"]["text"],"Exact cohort delivery");
            assert_eq!(delivered.mailbox_id,mailbox["mailbox_id"].as_str().unwrap());
            assert_eq!(delivered.model_response,"NOT_ATTESTED");
            let _=peer;
        }
        for (_,peer,_,_,_) in peers {peer.close().await.unwrap();}
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn repeated_truncated_streams_back_off_and_recover_original_delivery() {
    let mut c=Cohort::start(1).await;
    let before=c.service.counts().await["native_streams"].as_u64().unwrap();
    c.service.config(json!({"early_eof_count":3,"close_connections":true})).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sent=c.send(0,"mail-during-repeated-eof").await;
    let recovered=watch_until(&mut c.members[0].watch,|s|s.receiver_link_verified&&s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==sent["message_id"])).await;
    assert!(recovered.verification_failure.is_none(),"an incomplete transport frame is not a cryptographic rejection");
    assert_eq!(recovered.items.len(),1);
    assert!(c.service.counts().await["native_streams"].as_u64().unwrap()-before<=5,"early EOF must not create a 50ms reconnect loop");
    c.client.close().await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn timed_out_old_ready_pulse_cannot_override_new_not_ready_pulse() {
    let mut c=Cohort::start(1).await;
    c.service.config(json!({"delay_action":"structure.mailbox.pulse","delay_mailbox":c.members[0].mailbox["mailbox_id"]})).await;
    tokio::time::timeout(Duration::from_secs(10),async {while c.service.counts().await["delayed"]!=1{tokio::time::sleep(Duration::from_millis(30)).await;}}).await.unwrap();
    c.service.config(json!({"corrupt_frame":{"mailbox_id":c.members[0].mailbox["mailbox_id"],"mode":"ITEM_PROOF"}})).await;
    c.send(0,"poison-before-old-pulse-timeout").await;fault(&mut c.members[0].watch).await;
    let observe=||selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]}));
    // Synchronize with the newer NOT_READY commit, not a fixed sleep at the
    // 5s timeout/retry boundary. The old request remains explicitly held.
    let current=tokio::time::timeout(Duration::from_secs(15),async {
        loop {let value=observe().await;if value["mailbox"]["state"]=="DELAYED"{break value;}tokio::time::sleep(Duration::from_millis(50)).await;}
    }).await.expect("newer not-ready pulse did not commit while the old request was held");
    assert!(current["mailbox"]["lease_until"].as_u64().unwrap()>current["mailbox"]["server_time"].as_u64().unwrap());
    c.service.config(json!({"release":true})).await;
    tokio::time::timeout(Duration::from_secs(5),async {
        while c.service.counts().await["delayed_completed"].as_u64().unwrap_or(0)<1 {tokio::time::sleep(Duration::from_millis(30)).await;}
    }).await.expect("released older pulse did not reach the service");
    assert_eq!(observe().await["mailbox"]["state"],"DELAYED","an older server-side pulse must not override newer readiness");
    assert_eq!(c.members[0].watch.page(0,32).await.unwrap().state,"BLOCKED");
    c.client.close().await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn stop_attach_while_original_pulse_is_in_flight_preserves_current_receiver_lifecycle() {
    let mut c=Cohort::start(1).await;
    c.service.config(json!({"delay_action":"structure.mailbox.pulse","delay_mailbox":c.members[0].mailbox["mailbox_id"]})).await;
    tokio::time::timeout(Duration::from_secs(10),async {while c.service.counts().await["delayed"]!=1{tokio::time::sleep(Duration::from_millis(30)).await;}}).await.unwrap();
    c.members[0].watch.stop().await.unwrap();
    let mut current=c.client.watch(c.members[0].options.clone()).await.unwrap();
    watch_until(&mut current,|s|s.receiver_link_verified).await;
    c.service.config(json!({"release":true})).await;
    let sent=c.send(0,"after-in-flight-pulse-stop-attach").await;
    let received=watch_until(&mut current,|s|s.receiver_link_verified&&s.items.iter().any(|v|v["envelope"]["message"]["message_id"]==sent["message_id"])).await;
    assert!(received.verification_failure.is_none());
    let meta=selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]})).await;
    assert_eq!(meta["mailbox"]["epoch"],1);
    assert_eq!(c.service.counts().await["claim_commands"].as_array().unwrap().len(),1);
    c.client.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn direct_codex_lost_acceptance_redelivers_same_notification_without_connect_or_rebind() {
    use crate::{communication_host::tests::CodexFixture,participant_dispatch::{self,HostConfig,HostSubscription},participant_inbox::HostBinding};
    use std::sync::atomic::Ordering;
    let fixture=CodexFixture::start();let adapter=fixture.config();
    let destination=HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"existing-thread","session_id":adapter["expected_session_id"],"endpoint":adapter["endpoint"]})).unwrap();
    let c=Cohort::with_destination(1,Some(destination.digest)).await;
    let options=c.members[0].options.clone();let cancel=KernelCancellationToken::new();
    let configs=[HostConfig{name:"same-codex".into(),adapter,subscriptions:vec![HostSubscription{client:"original".into(),client_generation:None,watch:options.clone()}]}];
    let clients=BTreeMap::from([("original".into(),c.client.clone())]);
    let initial=c.client.inbox(&options,0,32).await.unwrap();
    let initial=initial.items.iter().map(|item|DeliveryReference{sequence:item["sequence"].as_u64().unwrap(),delivery_id:item["delivery_id"].as_str().unwrap().into()}).collect::<Vec<_>>();
    if !initial.is_empty(){c.client.consume(&options,initial).await.unwrap();}
    let sent=c.send(0,"one-business-message").await;
    let item=tokio::time::timeout(Duration::from_secs(15),async{loop{
        let page=c.client.inbox(&options,0,32).await.unwrap();
        if let Some(item)=page.items.iter().find(|v|v["envelope"]["message"]["message_id"]==sent["message_id"]){break DeliveryReference{sequence:item["sequence"].as_u64().unwrap(),delivery_id:item["delivery_id"].as_str().unwrap().into()};}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }}).await.unwrap();
    fixture.lose_next_ack.store(true,Ordering::SeqCst);
    let hosts=participant_dispatch::start(&configs,&clients,c._temp.path(),cancel.clone()).unwrap();
    tokio::time::timeout(Duration::from_secs(15),async{loop{
        if c.client.delivery_status(&options,item.clone()).await.unwrap()["host"]=="RESULT_UNKNOWN" {break;}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }}).await.unwrap();
    assert_eq!(fixture.calls().iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).count(),1);
    // The fixture was actually processing the first input. Finish that turn;
    // recovery must not require Connect, a new session or manual replay.
    *fixture.status_override.lock().unwrap()=Some("idle".into());
    let accepted=tokio::time::timeout(Duration::from_secs(20),async{loop{
        let status=c.client.delivery_status(&options,item.clone()).await.unwrap();
        if status["host"]=="HOST_ACCEPTED" {break status;}
        tokio::time::sleep(Duration::from_millis(25)).await;
    }}).await.unwrap();
    assert_eq!(accepted["delivery"]["attempt"],2,"the missing original reply must recover automatically");
    let inputs=fixture.calls().into_iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).collect::<Vec<_>>();
    assert_eq!(inputs.len(),2);assert_eq!(inputs[0]["params"]["clientUserMessageId"],inputs[1]["params"]["clientUserMessageId"]);assert_eq!(inputs[0]["params"]["input"],inputs[1]["params"]["input"]);
    c.client.consume(&options,vec![item]).await.unwrap();
    assert_eq!(c.service.counts().await["actions"]["structure.message.send"],1);
    cancel.cancel();for host in hosts{host.task.await.unwrap();}c.client.close().await.unwrap();
}
