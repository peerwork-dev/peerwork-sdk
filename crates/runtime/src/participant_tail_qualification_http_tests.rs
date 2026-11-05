//! Opt-in maintainer qualification: eight actual native identities, encrypted
//! mail and a separate resident production Worker. No Agent model is involved.
use super::*;

async fn consume_snapshot(watch: &mut ProgramWatch, snapshot: &WatchSnapshot) {
    let refs = snapshot.items.iter().map(|v| DeliveryReference {
        sequence:v["sequence"].as_u64().unwrap(),
        delivery_id:v["delivery_id"].as_str().unwrap().into(),
    }).collect::<Vec<_>>();
    if !refs.is_empty() {
        watch.consume(refs).await.unwrap();
        watch_until(watch,|s|!s.application_ack_pending).await;
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires designated local TEST, synthetic PostgreSQL and resident product Worker"]
async fn eight_native_participants_and_resident_broadcast_worker_qualify_tail_repair() {
    let service=Service::start();
    let seconds=std::env::var("PEERWORK_TAIL_QUAL_SECONDS").ok().map(|v|v.parse::<u64>().unwrap()).unwrap_or(315);
    assert!((15..=360).contains(&seconds));
    let mut homes=Vec::new();let mut configs=Vec::new();let mut clients=Vec::new();
    for _ in 0..8 {
        let home=crate::test_support::protected_test_dir();
        let mut cfg=configuration(home.path(),&service.origin);cfg.transport.request_timeout_ms=5000;
        let client=ParticipantClient::open(cfg.clone()).await.unwrap();
        homes.push(home);configs.push(cfg);clients.push(client);
    }
    let owner=clients[0].clone();
    let ws=mutate(&owner,"qualification-create","structure.workspace.create",&Scope::default(),json!({"name":"Native tail qualification"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    for (i,peer) in clients.iter().enumerate().skip(1) {
        let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
        let mut join=Invoke::new(format!("qualification-join-{i}"),"structure.member.set",scope.clone(),json!({"actor_id":peer.actor_id(),"state":"ACTIVE","expected_membership_id":null}));
        join.expected_workspace_revision=meta["workspace_revision"].as_u64();
        assert_eq!(owner.invoke(join,Duration::from_secs(10)).await.unwrap().state,"ACCEPTED");
    }
    let key=install_synthetic_key(&configs[0],&ws,&[63;32],None);
    for config in configs.iter().skip(1){install_synthetic_key(config,&ws,&[63;32],None);}
    mutate(&owner,"qualification-key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let mut boxes=Vec::new();let mut watches=Vec::new();
    for (i,client) in clients.iter().enumerate(){
        let page=selected(client,"structure.mailboxes.read",&scope,json!({})).await;let box_=page["mailboxes"][0].clone();
        let mut watch=client.watch(WatchOptions{workspace_id:ws.clone(),mailbox_id:box_["mailbox_id"].as_str().unwrap().into(),membership_id:box_["membership_id"].as_str().unwrap().into(),consumer_id:format!("tail-native-{i}"),host_destination:None}).await.unwrap();
        watch_until(&mut watch,|s|s.receiver_link_verified).await;boxes.push(box_);watches.push(watch);
    }
    service.config(json!({"resident_worker":true})).await;
    let bundle:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
    let registered=mutate(&owner,"qualification-register","structure.protocol.register",&scope,json!({"bundle":bundle["bundle"]})).await;
    let adopted=mutate(&owner,"qualification-adopt","structure.adopt",&scope,json!({"package_digest":registered["package_digest"],"bootstrap_grant":{"actions":[],"protocol_roles":[],"capabilities":[]}})).await;
    let sequence=adopted["notifications"].as_array().unwrap().iter().find(|v|v["audience"]=="ALL_MEMBERS").unwrap()["event_sequence"].as_u64().unwrap();
    let broadcast_start=Instant::now();let mut broadcast_observed_ms=Vec::new();
    for watch in &mut watches {
        let snapshot=watch_until(watch,|s|s.items.iter().any(|i|i["envelope"]["event_source_sequence"]==sequence)).await;
        assert!(snapshot.verification_failure.is_none());broadcast_observed_ms.push(broadcast_start.elapsed().as_secs_f64()*1000.0);
        consume_snapshot(watch,&snapshot).await;
    }
    let progress=selected(&owner,"structure.communication.event.get",&scope,json!({"event_sequence":sequence})).await;
    assert_eq!(progress["outcome"],"ALL_DELIVERED");assert_eq!(progress["counts"]["targets"],8);

    // A quiet independent workspace exercises the same real client and service
    // alongside busy-space delivery. No user/role or artificial pool change.
    let quiet_ws=mutate(&owner,"qualification-quiet","structure.workspace.create",&Scope::default(),json!({"name":"Quiet native scope"})).await["workspace_id"].as_str().unwrap().to_owned();
    let quiet=Scope{workspace_id:Some(quiet_ws),..Default::default()};
    let mut stream_ids=Vec::new();for watch in &watches{stream_ids.push(watch.page(0,32).await.unwrap().stream_id);}
    let start=Instant::now();let before=service.counts().await;let mut submit_ms=Vec::new();let mut quiet_read_ms=Vec::new();let mut verified=0;
    for n in 0..32 {
        let sending=Instant::now();let id=format!("qualification-message-{n}");let text=format!("Synthetic verified message {n}: {}","x".repeat(900));
        let mut intent=native_message(&id,&scope,&boxes[0],&boxes[0],&"v".repeat(43),&text);
        intent.body["recipients"]=json!(boxes.iter().map(|b|json!({"mailbox_id":b["mailbox_id"],"membership_id":b["membership_id"]})).collect::<Vec<_>>());
        let sent=structure(&owner.invoke(intent,Duration::from_secs(10)).await.unwrap());submit_ms.push(sending.elapsed().as_secs_f64()*1000.0);
        let quiet_start=Instant::now();selected(&owner,"structure.workspace.get",&quiet,json!({})).await;quiet_read_ms.push(quiet_start.elapsed().as_secs_f64()*1000.0);
        for watch in &mut watches {
            let snapshot=watch_until(watch,|s|s.items.iter().any(|i|i["envelope"]["message"]["message_id"]==sent["message_id"])).await;
            let item=snapshot.items.iter().find(|i|i["envelope"]["message"]["message_id"]==sent["message_id"]).unwrap();assert_eq!(item["opened_message"]["text"],text);verified+=1;consume_snapshot(watch,&snapshot).await;
        }
    }
    let mut lease_margin_min=u64::MAX;
    while start.elapsed()<Duration::from_secs(seconds) {
        tokio::time::sleep(Duration::from_secs(4)).await;
        for (client,box_) in clients.iter().zip(boxes.iter()) {
            let current=selected(client,"structure.mailbox.get",&scope,json!({"mailbox_id":box_["mailbox_id"]})).await;
            lease_margin_min=lease_margin_min.min(current["mailbox"]["lease_until"].as_u64().unwrap().saturating_sub(current["mailbox"]["server_time"].as_u64().unwrap()));
        }
    }
    let mut renewed=0;for (i,watch) in watches.iter().enumerate(){let s=watch.page(0,32).await.unwrap();assert!(s.receiver_link_verified&&s.verification_failure.is_none());if s.stream_id!=stream_ids[i]{renewed+=1;}}
    if seconds>=315{assert_eq!(renewed,8,"each actual native receiver crosses its signed stream deadline");}
    assert_eq!(verified,256);assert!(lease_margin_min>0);let after=service.counts().await;assert_eq!(after["resident_worker_running"],true);assert_eq!(after["journal_reads"],0);
    let report=json!({"format":"peerwork.native-tail-qualification.v1","state":"PASS","scope":"8 real native identities, synthetic E2EE keys, real HTTP and separate resident Worker; no TLS/proxy/Agent model","seconds":start.elapsed().as_secs_f64(),"requested_seconds":seconds,"diagnostic_lease_poll_seconds":4,"independent_fanout_commands":32,"verified_message_deliveries":verified,"broadcast_targets":8,"broadcast_outcome":progress["outcome"],"broadcast_observation_upper_bounds_ms":broadcast_observed_ms,"submit_ms":submit_ms,"quiet_workspace_read_ms":quiet_read_ms,"renewed_receivers":renewed,"lease_margin_min_ms":lease_margin_min,"ack_batches":after["ack_batches"],"pulse_requests":after["actions"]["structure.mailbox.pulse"].as_u64().unwrap()-before["actions"]["structure.mailbox.pulse"].as_u64().unwrap(),"request_bytes":after["command_request_bytes"].as_u64().unwrap()-before["command_request_bytes"].as_u64().unwrap(),"response_bytes":after["command_response_bytes"].as_u64().unwrap()-before["command_response_bytes"].as_u64().unwrap(),"sse_bytes":after["sse_bytes"].as_u64().unwrap()-before["sse_bytes"].as_u64().unwrap()});
    if let Ok(path)=std::env::var("PEERWORK_TAIL_QUAL_REPORT"){let path=PathBuf::from(path);assert!(path.is_absolute()&&!path.exists());std::fs::write(path,serde_json::to_vec_pretty(&report).unwrap()).unwrap();}
    println!("{report}");drop(watches);for client in &clients{client.close().await.unwrap();}drop(homes);
}
