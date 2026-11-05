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
    tokio::time::sleep(Duration::from_secs(6)).await;
    let observe=||selected(&c.client,"structure.mailbox.get",&c.members[0].scope,json!({"mailbox_id":c.members[0].mailbox["mailbox_id"]}));
    let current=observe().await;
    assert_eq!(current["mailbox"]["state"],"DELAYED");
    assert!(current["mailbox"]["lease_until"].as_u64().unwrap()>current["mailbox"]["server_time"].as_u64().unwrap());
    c.service.config(json!({"release":true})).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
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
