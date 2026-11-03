//! First PUSH binding through the original native receiver, including derived clients.
use super::*;
use crate::{
    communication_host::{tests::CodexFixture,write_private},
    communication_runtime::{self as ipc,ClientConfig,EngineConfig,RuntimeClient},
    participant::{Capability,Invoke,ParticipantClient,Scope},
    participant::http_tests::{configuration,install_synthetic_key,mutate,selected,Service,native_message},
    participant_dispatch::HostSubscription,
    secure_state::create_private_state_directory,
};
use std::{path::PathBuf,time::Duration};
struct Initial {
    service:Service,
    _root:crate::test_support::ProtectedTestDir,
    path:PathBuf,
    runtime:RuntimeConfig,
    request:HostRebindRequest,
    old:WatchOptions,
    namespace:String,
    original:MailboxPins,
    client_name:String,
    delivered:Value,
    connect_directory:Option<PathBuf>,
    inbox_request:Option<Value>,
}
async fn setup(derived:bool,adapter:Value)->Initial {
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    let cfg=configuration(root.path(),&service.origin);
    let client=ParticipantClient::open(cfg.clone()).await.unwrap();
    let ws=mutate(&client,"initial-space","structure.workspace.create",&Scope::default(),json!({"name":"First host"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
    let meta=selected(&client,"structure.workspace.get",&scope,json!({})).await;
    let mailbox=mutate(&client,"initial-grant","structure.communication.grant.set",&scope,json!({"actor_id":client.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key=install_synthetic_key(&cfg,&ws,&[49;32],None);
    mutate(&client,"initial-key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let delivered=mutate_message(&client,&scope,&mailbox,"already-consumed").await;
    mutate_message(&client,&scope,&mailbox,"pending-before-first-host").await;
    client.close().await.unwrap();
    let runtime=RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.path().join("runtime"),
        engines:vec![EngineConfig{name:"one".into(),origin:cfg.origin.clone(),expected_actor:cfg.expected_actor.clone(),authority:None,identity_path:cfg.identity_path.clone(),state_directory:cfg.state_directory.clone(),journal_path:Some(cfg.journal_path.clone()),allow_loopback_http:true,transport:cfg.transport.clone(),max_inflight:4,max_pending:16,max_stored_bytes:8*1024*1024,migration_sources:vec![]}],
        clients:vec![ClientConfig{name:"worker".into(),engine:"one".into(),capability:Capability::owner()}],hosts:vec![]};
    let cancel=KernelCancellationToken::new();let (tx,rx)=tokio::sync::oneshot::channel();let running=tokio::spawn(ipc::serve(runtime.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let root_client=RuntimeClient::connect(ready.client_endpoints["worker"].clone(),&cfg.origin,&cfg.expected_actor).await.unwrap();
    let mut old=WatchOptions{workspace_id:ws.clone(),mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:"original-inbox".into(),host_destination:None};
    let mut connect_directory=None;let mut inbox_request=None;
    let (receiver,client_name,generation,namespace)=if derived {
        use crate::participant_connect::{Connect,ConnectRequest,Registration};
        let directory=root.path().join("connect");let mut connect=Connect::open(&directory).unwrap();
        connect.register("worker",Registration{origin:cfg.origin.clone(),actor_id:cfg.expected_actor.clone(),endpoint_path:ready.client_endpoints["worker"].clone()}).await.unwrap();
        let request=json!({"setup_id":"inbox","participant":"worker","workspace_id":ws,"alias":"project","send":true,"receive":true,"receive_mode":"INBOX"});
        let configured=connect.run_agent(serde_json::from_value::<ConnectRequest>(request.clone()).unwrap()).await.unwrap();
        assert_eq!(configured["state"],"LOCAL_CONFIGURED","{configured}");
        let profile=connect.profile().unwrap().unwrap();
        let receiver=RuntimeClient::connect(profile.receive_endpoint_path.unwrap(),&cfg.origin,&cfg.expected_actor).await.unwrap();
        let observed=receiver.call(json!({"method":"bindings"})).await.unwrap();
        old=serde_json::from_value(observed[0].clone()).unwrap();
        let binding=receiver.call(json!({"method":"binding"})).await.unwrap();
        connect_directory=Some(directory);inbox_request=Some(request);
        (receiver,binding["client_name"].as_str().unwrap().to_owned(),binding["client_generation"].as_u64(),binding["namespace"].as_str().unwrap().to_owned())
    }else{(root_client,"worker".into(),None,"program:worker".into())};
    receiver.call(json!({"method":"watch","options":old})).await.unwrap();
    let page=tokio::time::timeout(Duration::from_secs(15),async{loop{
        let p=receiver.call(json!({"method":"inbox","options":old,"after":0,"limit":32})).await.unwrap();
        assert_ne!(p["state"],"BLOCKED","{p}");
        if p["receiver_link_verified"]==true&&p["items"].as_array().is_some_and(|v|v.len()==2){break p;}
        tokio::time::sleep(Duration::from_millis(30)).await;
    }}).await.unwrap();
    let first=&page["items"][0];
    receiver.call(json!({"method":"consume","options":old,"items":[{"sequence":first["sequence"],"delivery_id":first["delivery_id"]}]})).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10),async{loop{
        let p=receiver.call(json!({"method":"inbox","options":old,"after":0,"limit":32})).await.unwrap();
        if p["items"].as_array().is_some_and(|v|v.len()==1)&&p["receiver_ack_pending"]==false&&p["application_ack_pending"]==false{break;}
        tokio::time::sleep(Duration::from_millis(30)).await;
    }}).await.unwrap();
    cancel.cancel();running.await.unwrap().unwrap();
    let identity=KernelIdentity::open(&cfg.identity_path).unwrap();
    let store=InboxStore::open_local(&cfg.state_directory,&identity,&crate::transport::canonical_lifecycle_origin(&cfg.origin,true).unwrap()).unwrap();
    let original=store.pins(&old.workspace_id,&old.mailbox_id).unwrap().unwrap();drop(store);
    let path=root.path().join("runtime.json");write_private(&path,&serde_json::to_vec(&runtime).unwrap()).unwrap();
    let request=HostRebindRequest{format:"peerwork.host-rebind.v1".into(),operation_id:"first-host".into(),engine:"one".into(),host:"selected-first".into(),adapter,
        initial_subscriptions:Some(vec![HostSubscription{client:client_name.clone(),client_generation:generation,watch:old.clone()}])};
    Initial{service,_root:root,path,runtime,request,old,namespace,original,client_name,delivered,connect_directory,inbox_request}
}
async fn mutate_message(client:&ParticipantClient,scope:&Scope,mailbox:&Value,id:&str)->Value {
    let request=native_message(id,scope,mailbox,mailbox,&"v".repeat(43),id);
    crate::participant::http_tests::structure(&client.invoke(request,Duration::from_secs(5)).await.unwrap())
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn first_push_preserves_static_and_derived_inbox_and_delivers_only_unconsumed_mail() {
    for derived in [false,true] {
        let host=CodexFixture::start();let source=setup(derived,host.config()).await;
        let selected=crate::communication_runtime::rebind_client(&source.runtime,&source.client_name).unwrap();
        assert_eq!(selected.namespace,source.namespace);
        let moved=rebind_host(&source.path,source.request.clone()).await.unwrap();
        assert_eq!(moved["state"],"HOST_REBIND_READY");
        assert_eq!(rebind_host(&source.path,source.request.clone()).await.unwrap()["state"],"HOST_REBIND_READY");
        let engine=&source.runtime.engines[0];let identity=KernelIdentity::open(&engine.identity_path).unwrap();
        let store=InboxStore::open_local(&engine.state_directory,&identity,&crate::transport::canonical_lifecycle_origin(&engine.origin,true).unwrap()).unwrap();
        let current=store.pins(&source.old.workspace_id,&source.old.mailbox_id).unwrap().unwrap();
        assert_eq!(current.receiver_id,source.original.receiver_id);assert_eq!(current.after_sequence,source.original.after_sequence);assert_eq!(current.after_control_sequence,source.original.after_control_sequence);
        assert_eq!(current.epoch,source.original.epoch+1);assert_eq!(current.binding_version,source.original.binding_version+1);
        let mut new=source.old.clone();new.host_destination=Some(moved["destination_digest"].as_str().unwrap().into());
        assert!(store.selected_watch(&source.namespace,&new).is_ok());drop(store);
        let target:RuntimeConfig=serde_json::from_value(private_json(&source.path,65536).unwrap()).unwrap();
        assert_eq!(target.clients.len(),1,"derived clients must not become new static roots");
        let cancel=KernelCancellationToken::new();let (tx,rx)=tokio::sync::oneshot::channel();let running=tokio::spawn(ipc::serve(target,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(15),async{loop{
            if host.calls().iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).count()==1{break;}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }}).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let calls=host.calls().into_iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).collect::<Vec<_>>();
        assert_eq!(calls.len(),1,"consumed mail must not be injected after first PUSH binding");
        assert!(calls[0].to_string().contains("pending-before-first-host"));
        assert!(!calls[0].to_string().contains(source.delivered["message_id"].as_str().unwrap()));
        let status=ipc::call(&ready.admin_endpoint,json!({"method":"status"})).await.unwrap();assert_eq!(status["ok"],true);
        if let Some(directory)=&source.connect_directory {
            use crate::participant_connect::{Connect,ConnectRequest,HostSelection};
            let mut connect=Connect::open(directory).unwrap();
            let before=connect.profile().unwrap().unwrap().receive_endpoint_path;
            connect.register_host("selected-first",HostSelection{participant:"worker".into(),admin_endpoint:ready.admin_endpoint.clone(),adapter:host.config()}).await.unwrap();
            let request:ConnectRequest=serde_json::from_value(json!({"setup_id":"push","participant":"worker","workspace_id":source.old.workspace_id,"alias":"project","send":true,"receive":true,"host":"selected-first"})).unwrap();
            let mut program=request.clone();program.setup_id="program-push".into();
            let configured=connect.run(program).await.unwrap();
            assert_eq!(configured["state"],"LOCAL_CONFIGURED","{configured}; selected_watch={new:?}; hosts={}",status["value"]["hosts"]);
            assert_eq!(configured["receive_mode"],"PUSH");
            assert_eq!(configured["self_test"]["state"],"READY","PUSH setup must verify the real receiver and host path");
            assert_eq!(connect.profile().unwrap().unwrap().receive_endpoint_path,before);
            let configured=connect.run_agent(request.clone()).await.unwrap();
            assert_eq!(configured["state"],"LOCAL_CONFIGURED","{configured}");
            assert_eq!(connect.profile().unwrap().unwrap().receive_endpoint_path,before,"PUSH must reuse the original receive endpoint");
            assert_eq!(connect.run_agent(request.clone()).await.unwrap()["state"],"LOCAL_CONFIGURED");
            let denied=connect.run_agent(serde_json::from_value(source.inbox_request.clone().unwrap()).unwrap()).await.unwrap();
            assert_eq!(denied["blocker"]["code"],"EXISTING_PUSH_RECEIVER_REQUIRES_EXPLICIT_REBIND","cached INBOX setup must not conceal the new host");
            host.approval.store(true,std::sync::atomic::Ordering::SeqCst);
            let receiver=RuntimeClient::connect(before.clone().unwrap(),&engine.origin,&engine.expected_actor).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10),async{loop {
                let page=receiver.call(json!({"method":"inbox","options":new,"after":0,"limit":1})).await.unwrap();
                if page["presence"]["host"]["ready"]==false {break;}
                tokio::time::sleep(Duration::from_millis(30)).await;
            }}).await.unwrap();
            let pending=connect.run_agent(request).await.unwrap();
            assert_eq!(pending["state"],"PENDING","host approval must retain pending setup recovery");
            assert_eq!(pending["blocker"]["stage"],"RECEIVING_SELF_TEST");

        }

        cancel.cancel();running.await.unwrap().unwrap();
        assert_eq!(source.service.counts().await["claim_commands"].as_array().unwrap().len(),2,"one initial claim and one exact replacement claim");
        if let Some(directory)=&source.connect_directory {
            // Same physical group/route, a new explicit Codex session pin.
            host.approval.store(false,std::sync::atomic::Ordering::SeqCst);
            let mut replacement=host.config();replacement["expected_session_id"]=json!("replacement-session");
            *host.actual_session.lock().unwrap()="replacement-session".into();
            let request=HostRebindRequest{format:"peerwork.host-rebind.v1".into(),operation_id:"replace-first-host".into(),engine:"one".into(),host:"selected-first".into(),adapter:replacement.clone(),initial_subscriptions:None};
            assert_eq!(rebind_host(&source.path,request).await.unwrap()["state"],"HOST_REBIND_READY");
            let target:RuntimeConfig=serde_json::from_value(private_json(&source.path,65536).unwrap()).unwrap();
            let cancel=KernelCancellationToken::new();let (tx,rx)=tokio::sync::oneshot::channel();let running=tokio::spawn(ipc::serve(target,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
            let mut connect=crate::participant_connect::Connect::open(directory).unwrap();
            let original_endpoint=connect.profile().unwrap().unwrap().receive_endpoint_path;
            for setup_id in ["program-push","push"] {
                for _ in 0..2 {
                    let original=serde_json::from_value(json!({"setup_id":setup_id,"participant":"worker","workspace_id":source.old.workspace_id,"alias":"project","send":true,"receive":true,"host":"selected-first"})).unwrap();
                    let observed=if setup_id=="push"{connect.run_agent(original).await.unwrap()}else{connect.run(original).await.unwrap()};
                    assert_eq!(observed["state"],"PENDING");
                    assert_eq!(observed["blocker"]["code"],"HOST_SELECTION_CHANGED_REBIND_REQUIRED","cached and pending old setups must not claim a replacement host is their original destination");
                    assert!(observed["self_test"].is_null());
                }
            }
            connect.register_host("selected-replacement",crate::participant_connect::HostSelection{participant:"worker".into(),admin_endpoint:ready.admin_endpoint.clone(),adapter:replacement}).await.unwrap();
            let selected=serde_json::from_value(json!({"setup_id":"selected-new-session","participant":"worker","workspace_id":source.old.workspace_id,"alias":"project","send":true,"receive":true,"host":"selected-replacement"})).unwrap();
            let current=connect.run_agent(selected).await.unwrap();
            assert_eq!(current["state"],"LOCAL_CONFIGURED","explicitly selected replacement must reuse its already committed binding: {current}");
            assert_eq!(current["self_test"]["state"],"READY");
            assert_eq!(connect.profile().unwrap().unwrap().receive_endpoint_path,original_endpoint);
            assert_eq!(host.calls().iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).count(),1,"session selection must not duplicate original model input");
            cancel.cancel();running.await.unwrap().unwrap();
            assert_eq!(source.service.counts().await["claim_commands"].as_array().unwrap().len(),3,"checking or selecting a completed binding must not submit another claim");
        }
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn first_push_refuses_changed_derived_generation_before_remote_claim() {
    let host=CodexFixture::start();let mut source=setup(true,host.config()).await;
    let count=source.service.counts().await["claim_commands"].as_array().unwrap().len();
    let selected=source.request.initial_subscriptions.as_mut().unwrap();selected[0].client_generation=selected[0].client_generation.map(|n|n+1);
    assert_eq!(rebind_host(&source.path,source.request).await.unwrap_err().code,"HOST_REBIND_SELECTED_HOST_ENGINE_OR_GENERATION_MISMATCH");
    assert_eq!(source.service.counts().await["claim_commands"].as_array().unwrap().len(),count);
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn first_push_resumes_original_job_at_prepare_claim_local_and_config_boundaries() {
    for boundary in ["PREPARED","CLAIM_CONFIRMED_BEFORE_SAVE","LOCAL_COMMITTED_BEFORE_SAVE","CONFIG_COMMITTED"] {
        let host=CodexFixture::start();let source=setup(true,host.config()).await;
        let path=source.path.clone();let request=source.request.clone();
        let failed=tokio::task::spawn_blocking(move||rebind_with(&path,request,|point|if point==boundary{Err(error("SYNTHETIC_FIRST_HOST_INTERRUPTION"))}else{Ok(())})).await.unwrap().unwrap_err();
        assert_eq!(failed.code,"SYNTHETIC_FIRST_HOST_INTERRUPTION");
        assert_eq!(rebind_host(&source.path,source.request.clone()).await.unwrap()["state"],"HOST_REBIND_READY");
        assert_eq!(rebind_host(&source.path,source.request.clone()).await.unwrap()["state"],"HOST_REBIND_READY");
        let engine=&source.runtime.engines[0];let identity=KernelIdentity::open(&engine.identity_path).unwrap();
        let store=InboxStore::open_local(&engine.state_directory,&identity,&crate::transport::canonical_lifecycle_origin(&engine.origin,true).unwrap()).unwrap();
        let pins=store.pins(&source.old.workspace_id,&source.old.mailbox_id).unwrap().unwrap();
        assert_eq!(pins.receiver_id,source.original.receiver_id);assert_eq!(pins.after_sequence,source.original.after_sequence);assert_eq!(pins.after_control_sequence,source.original.after_control_sequence);
        assert_eq!(pins.epoch,source.original.epoch+1);assert_eq!(pins.binding_version,source.original.binding_version+1);
        assert_eq!(source.service.counts().await["claim_commands"].as_array().unwrap().len(),2,"duplicate claim after {boundary}");
    }
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn first_push_keeps_quarantined_receive_path_blocked_without_host_input() {
    let host=CodexFixture::start();let source=setup(false,host.config()).await;
    let engine=&source.runtime.engines[0];let identity=KernelIdentity::open(&engine.identity_path).unwrap();
    let store=InboxStore::open_local(&engine.state_directory,&identity,&crate::transport::canonical_lifecycle_origin(&engine.origin,true).unwrap()).unwrap();
    let fault=json!({"code":"STREAM_CONTROL_EVIDENCE_INVALID","scope_authenticated":true});
    store.quarantine_receive(&source.old.workspace_id,&source.old.mailbox_id,&fault).unwrap();drop(store);
    let moved=rebind_host(&source.path,source.request.clone()).await.unwrap();
    let target:RuntimeConfig=serde_json::from_value(private_json(&source.path,65536).unwrap()).unwrap();
    let cancel=KernelCancellationToken::new();let (tx,rx)=tokio::sync::oneshot::channel();let running=tokio::spawn(ipc::serve(target,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let client=RuntimeClient::connect(ready.client_endpoints["worker"].clone(),&engine.origin,&engine.expected_actor).await.unwrap();
    let mut options=source.old.clone();options.host_destination=moved["destination_digest"].as_str().map(str::to_owned);
    let page=tokio::time::timeout(Duration::from_secs(10),async{loop{
        match client.call(json!({"method":"inbox","options":options,"after":0,"limit":32})).await {
            Ok(value)=>break value,Err(e) if e.code=="WATCH_NOT_FOUND"=>tokio::time::sleep(Duration::from_millis(30)).await,Err(e)=>panic!("{}",e.code),
        }
    }}).await.unwrap();
    assert_eq!(page["state"],"BLOCKED");assert_eq!(page["verification_failure"],fault);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!host.calls().iter().any(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))));
    cancel.cancel();running.await.unwrap().unwrap();
}
