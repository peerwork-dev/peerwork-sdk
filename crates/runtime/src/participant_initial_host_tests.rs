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

/// Explicit maintainer qualification against an isolated official App Server.
/// A deterministic local model fixture is sufficient to prove host acceptance;
/// this does not claim a real model response or latency SLA.
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires isolated official Codex host plus synthetic PostgreSQL HTTP service"]
async fn official_unloaded_codex_receives_original_pending_mail_once() {
    let path=std::env::var("PEERWORK_CODEX_CONTROL_CONFIG").expect("isolated adapter required");
    let adapter:Value=serde_json::from_slice(&crate::secure_state::read_private_file_bounded(Path::new(&path),8192).unwrap()).unwrap();
    let source=setup(false,adapter.clone()).await;
    let started=std::time::Instant::now();
    let moved=rebind_host(&source.path,source.request.clone()).await.unwrap();
    assert_eq!(moved["state"],"HOST_REBIND_READY");
    let target:RuntimeConfig=serde_json::from_value(private_json(&source.path,65536).unwrap()).unwrap();
    let engine=target.engines[0].clone();
    let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
    let running=tokio::spawn(ipc::serve(target,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let client=RuntimeClient::connect(ready.client_endpoints["worker"].clone(),&engine.origin,&engine.expected_actor).await.unwrap();
    let mut watch=source.old.clone();watch.host_destination=Some(moved["destination_digest"].as_str().unwrap().into());
    let accepted=tokio::time::timeout(Duration::from_secs(25),async{loop{
        let page=match client.call(json!({"method":"inbox","options":watch,"after":0,"limit":32})).await {
            Ok(page)=>page,
            Err(error) if error.code=="WATCH_NOT_FOUND"=>{tokio::time::sleep(Duration::from_millis(50)).await;continue;},
            Err(error)=>panic!("original receiver failed: {error:?}"),
        };
        if let Some(item)=page["items"].as_array().and_then(|items|items.first()) {
            let selected=json!({"sequence":item["sequence"],"delivery_id":item["delivery_id"]});
            let status=client.call(json!({"method":"delivery_status","options":watch,"item":selected})).await.unwrap();
            if status["host"]=="HOST_ACCEPTED"{break status;}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await;
    cancel.cancel();running.await.unwrap().unwrap();
    let accepted=accepted.expect("original pending mail must reach the official selected host");
    let identity=KernelIdentity::open(&engine.identity_path).unwrap();
    let store=InboxStore::open_local(&engine.state_directory,&identity,&crate::transport::canonical_lifecycle_origin(&engine.origin,true).unwrap()).unwrap();
    let pins=store.pins(&watch.workspace_id,&watch.mailbox_id).unwrap().unwrap();
    assert_eq!(pins.receiver_id,source.original.receiver_id);
    let report=json!({"state":"PASS","scope":"real official host; synthetic service, identity and model output","host_receipt":accepted,"elapsed_ms":started.elapsed().as_millis(),"same_receiver":true,"thread_id":adapter["thread_id"],"session_id":adapter["expected_session_id"]});
    write_private(Path::new(&std::env::var("PEERWORK_OFFICIAL_HOST_REPORT").unwrap()),&serde_json::to_vec_pretty(&report).unwrap()).unwrap();
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

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn resident_first_host_keeps_original_process_and_other_workspace_available() {
    for derived in [false,true] {
        let host=CodexFixture::start();let source=setup(derived,host.config()).await;
        // The live entry needs the authenticated admin and receive binding,
        // not a recoverable original configuration filename or launch receipt.
        std::fs::remove_file(&source.path).unwrap();
        let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
        let running=tokio::spawn(ipc::serve(source.runtime.clone(),cancel.clone(),tx));
        let ready=rx.await.unwrap().unwrap();
        let root_endpoint=ready.client_endpoints["worker"].clone();
        let endpoint=ready.client_endpoints[&source.client_name].clone();
        let endpoint_before=std::fs::read(&endpoint).unwrap();
        async fn rpc(path:&Path,value:Value)->Value {
            let out=ipc::call(path,value).await.unwrap();assert_eq!(out["ok"],true,"{out}");out["value"].clone()
        }
        let created=rpc(&root_endpoint,json!({"method":"invoke","wait_ms":5000,
            "request":Invoke::new("other-space","structure.workspace.create",Scope::default(),json!({"name":"Unaffected scope"}))})).await;
        let workspace=created["outcome"]["result"]["structure"]["workspace_id"].as_str().unwrap().to_owned();
        let other_scope=Scope{workspace_id:Some(workspace.clone()),..Default::default()};
        let meta=rpc(&root_endpoint,json!({"method":"request","request":Invoke::new("other-meta","structure.workspace.get",other_scope.clone(),json!({}))})).await;
        let granted=rpc(&root_endpoint,json!({"method":"invoke","wait_ms":5000,"request":Invoke::new("other-grant","structure.communication.grant.set",other_scope.clone(),
            json!({"actor_id":source.runtime.engines[0].expected_actor,"membership_id":meta["result"]["structure"]["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true}))})).await;
        let mailbox=&granted["outcome"]["result"]["structure"]["mailbox"];
        let other=WatchOptions{workspace_id:workspace,mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),
            membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:"other".into(),host_destination:None};
        rpc(&root_endpoint,json!({"method":"watch","options":other})).await;
        rpc(&endpoint,json!({"method":"watch","options":source.old})).await;
        source.service.config(json!({"delay_action":"structure.mailbox.claim","delay_mailbox":source.old.mailbox_id})).await;
        let mut status=rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":source.request})).await;
        tokio::time::timeout(Duration::from_secs(15),async{loop{
            if source.service.counts().await["delayed"].as_u64().unwrap_or(0)>0 {break;}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }}).await.unwrap();
        // The selected replacement HTTP request is deliberately still pending.
        // The same watch driver must establish another workspace's real stream.
        tokio::time::timeout(Duration::from_secs(10),async{loop{
            let page=rpc(&root_endpoint,json!({"method":"inbox","options":other,"after":0,"limit":1})).await;
            if page["receiver_link_verified"]==true{break;}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }}).await.unwrap();
        source.service.config(json!({"release":true})).await;
        let mut reads=0;
        tokio::time::timeout(Duration::from_secs(45),async{
            while status["state"]!="HOST_REBIND_READY" {
                assert!(!running.is_finished(),"resident rebind stopped the runtime");
                let observed=tokio::time::timeout(Duration::from_secs(5),rpc(&root_endpoint,json!({"method":"request", "request":Invoke::new("other-live-read","structure.workspace.get",other_scope.clone(),json!({}))}))).await.unwrap();
                assert_eq!(observed["result"]["structure"]["workspace_id"].as_str(),other_scope.workspace_id.as_deref(),"{observed}");reads+=1;
                tokio::time::sleep(Duration::from_millis(50)).await;
                status=rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":source.request})).await;
            }
        }).await.unwrap();
        assert!(reads>0);assert_eq!(status["runtime_restarted"],false);
        assert_eq!(std::fs::read(&endpoint).unwrap(),endpoint_before);
        let repeated=rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":source.request})).await;
        assert_eq!(repeated["state"],"HOST_REBIND_READY");
        tokio::time::timeout(Duration::from_secs(15),async{loop{
            if host.calls().iter().any(|c|matches!(c["method"].as_str(),Some("turn/start"|"turn/steer"))){break;}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }}).await.unwrap();
        cancel.cancel();running.await.unwrap().unwrap();
        // Restart the unchanged original in-memory configuration. The runtime
        // host store must recover the newly published source without a new claim.
        let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
        let running=tokio::spawn(ipc::serve(source.runtime.clone(),cancel.clone(),tx));
        let ready=rx.await.unwrap().unwrap();
        assert_eq!(rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":source.request})).await["state"],"HOST_REBIND_READY");
        cancel.cancel();running.await.unwrap().unwrap();
        assert_eq!(source.service.counts().await["claim_commands"].as_array().unwrap().len(),3);
        assert_eq!(host.calls().iter().filter(|c|matches!(c["method"].as_str(),Some("turn/start"|"turn/steer"))).count(),1);
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn resident_signed_rejection_keeps_original_scope_and_accepts_explicit_decisions() {
    async fn rpc(path:&Path,value:Value)->Value {
        let out=ipc::call(path,value).await.unwrap();assert_eq!(out["ok"],true,"{out}");out["value"].clone()
    }
    async fn wait(path:&Path,request:&HostRebindRequest,terminal:&str)->Value {
        let mut last=Value::Null;
        let result=tokio::time::timeout(Duration::from_secs(45),async{loop{
            last=rpc(path,json!({"method":"host_rebind","rebind":request})).await;
            if last["state"]==terminal || terminal=="REJECTED"&&last["blocker"]["effect_certainty"]=="REJECTED_NO_EFFECT"{return last.clone();}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await;
        result.unwrap_or_else(|_|panic!("resident recovery timed out: {last}"))
    }
    for abort in [false,true] {
        let host=CodexFixture::start();let source=setup(false,host.config()).await;
        source.service.config(json!({"reject_next_rebind_mailbox":source.old.mailbox_id})).await;
        let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
        let running=tokio::spawn(ipc::serve(source.runtime.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
        wait(&ready.admin_endpoint,&source.request,"REJECTED").await;
        let original_claims=source.service.counts().await["claim_commands"].as_array().unwrap().iter().map(|v|v["command_id"].as_str().unwrap().to_owned()).collect::<std::collections::BTreeSet<_>>();
        // Administrative business calls remain schedulable even while the
        // receiver is fenced and waiting for an explicit recovery decision.
        rpc(&ready.client_endpoints["worker"],json!({"method":"request","request":Invoke::new("during-maintenance","structure.workspace.get",Scope{workspace_id:Some(source.old.workspace_id.clone()),..Default::default()},json!({}))})).await;
        // Process interruption is a test fault. A restarted new reader must
        // recover the saved scope; an old reader sees the global pending pin.
        cancel.cancel();running.await.unwrap().unwrap();
        let engine=&source.runtime.engines[0];
        let owner=SecureStateStore::open(&engine.state_directory.join("engine-owner.state")).unwrap();
        let identity=KernelIdentity::open(&engine.identity_path).unwrap();
        let origin=crate::transport::canonical_lifecycle_origin(&engine.origin,true).unwrap();
        let binding=participant_owner::logical_binding(&identity,&origin,&sha256_hex(identity.actor_id().as_bytes()));
        assert_eq!(participant_owner::validate_ready(&owner,&binding).unwrap_err().code,"OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION");drop(owner);
        let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
        let running=tokio::spawn(ipc::serve(source.runtime.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
        wait(&ready.admin_endpoint,&source.request,"REJECTED").await;
        assert_eq!(source.service.counts().await["claim_commands"].as_array().unwrap().iter().map(|v|v["command_id"].as_str().unwrap().to_owned()).collect::<std::collections::BTreeSet<_>>(),original_claims,"restart must replay the same signed refusal, not create another claim");
        let decision=HostRebindRecoveryRequest{format:"peerwork.host-rebind-recovery.v1".into(),decision_id:"selected-decision".into(),action:if abort{HostRebindRecoveryAction::Abort}else{HostRebindRecoveryAction::RetryRejected}};
        rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":source.request,"recovery":decision})).await;
        let terminal=if abort{"HOST_REBIND_ABORTED"}else{"HOST_REBIND_READY"};
        wait(&ready.admin_endpoint,&source.request,terminal).await;
        assert_eq!(rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":source.request,"recovery":decision})).await["state"],terminal);
        if abort {
            tokio::time::timeout(Duration::from_secs(15),async{loop{
                let page=rpc(&ready.client_endpoints["worker"],json!({"method":"inbox","options":source.old,"after":0,"limit":32})).await;
                if page["receiver_link_verified"]==true{break;}
                tokio::time::sleep(Duration::from_millis(30)).await;
            }}).await.unwrap();
            assert!(!host.calls().iter().any(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))));
        }
        cancel.cancel();running.await.unwrap().unwrap();
        let store=InboxStore::open_local(&engine.state_directory,&identity,&origin).unwrap();
        let pins=store.pins(&source.old.workspace_id,&source.old.mailbox_id).unwrap().unwrap();
        assert_eq!(pins.receiver_id,source.original.receiver_id);
        assert_eq!(pins.binding_version,source.original.binding_version+u64::from(!abort));
        let counts=source.service.counts().await;
        let replacements=counts["claim_commands"].as_array().unwrap().iter().filter(|v|v["replace"]==true).map(|v|v["command_id"].as_str().unwrap()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(replacements.len(),if abort{1}else{2});
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn resident_unknown_claim_refuses_abort_and_new_id_then_reconciles_original() {
    let host=CodexFixture::start();let source=setup(false,host.config()).await;
    let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
    let running=tokio::spawn(ipc::serve(source.runtime.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    source.service.config(json!({"drop_action":"structure.mailbox.claim"})).await;
    let call=|request:Value|ipc::call(&ready.admin_endpoint,request);
    let started=call(json!({"method":"host_rebind","rebind":source.request})).await.unwrap();assert_eq!(started["ok"],true,"{started}");
    tokio::time::timeout(Duration::from_secs(45),async{loop{
        let status=call(json!({"method":"host_rebind","rebind":source.request})).await.unwrap();
        if status["value"]["blocker"]["effect_certainty"]=="UNKNOWN"{break;}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.unwrap();
    for (action,code) in [(HostRebindRecoveryAction::Abort,"HOST_REBIND_UNKNOWN_CLAIM_RESUME_ORIGINAL"),(HostRebindRecoveryAction::RetryRejected,"HOST_REBIND_NO_VERIFIED_REJECTED_CLAIM_RESUME_ORIGINAL")] {
        let decision=HostRebindRecoveryRequest{format:"peerwork.host-rebind-recovery.v1".into(),decision_id:if action==HostRebindRecoveryAction::Abort{"abort"}else{"retry"}.into(),action};
        tokio::time::timeout(Duration::from_secs(30),async{loop{
            let value=call(json!({"method":"host_rebind","rebind":source.request,"recovery":decision})).await.unwrap();
            assert_eq!(value["ok"],false,"{value}");
            if value["error"]["code"]=="HOST_REBIND_WORK_PENDING_RESUME_DECISION"{tokio::time::sleep(Duration::from_millis(50)).await;continue;}
            assert_eq!(value["error"]["code"],code,"{value}");break;
        }}).await.unwrap();
    }
    source.service.config(json!({"offline":false})).await;
    tokio::time::timeout(Duration::from_secs(45),async{loop{
        let value=call(json!({"method":"host_rebind","rebind":source.request})).await.unwrap();
        if value["value"]["state"]=="HOST_REBIND_READY"{break;}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.unwrap();
    assert!(!running.is_finished());cancel.cancel();running.await.unwrap().unwrap();
    let counts=source.service.counts().await;
    let ids=counts["claim_commands"].as_array().unwrap().iter().filter(|v|v["replace"]==true).map(|v|v["command_id"].as_str().unwrap()).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(),1,"lost response must retain the original replacement command");
    assert_eq!(counts["dropped"],1);
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires synthetic PostgreSQL and real HTTP service"]
async fn resident_existing_push_reuses_physical_owner_and_restarts_from_unchanged_base() {
    async fn rpc(path:&Path,value:Value)->Value {
        let out=ipc::call(path,value).await.unwrap();assert_eq!(out["ok"],true,"{out}");out["value"].clone()
    }
    let host=CodexFixture::start();let source=setup(false,host.config()).await;
    // Establish the existing PUSH base before starting the resident test.
    rebind_host(&source.path,source.request.clone()).await.unwrap();
    let base:RuntimeConfig=serde_json::from_value(private_json(&source.path,65536).unwrap()).unwrap();
    let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
    let running=tokio::spawn(ipc::serve(base.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    let endpoint=ready.client_endpoints["worker"].clone();let before=std::fs::read(&endpoint).unwrap();
    tokio::time::timeout(Duration::from_secs(15),async{loop{
        if host.calls().iter().any(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))){break;}
        tokio::time::sleep(Duration::from_millis(30)).await;
    }}).await.unwrap();
    *host.actual_session.lock().unwrap()="explicit-replacement".into();
    let mut adapter=host.config();adapter["expected_session_id"]=json!("explicit-replacement");
    let request=HostRebindRequest{format:"peerwork.host-rebind.v1".into(),operation_id:"resident-push-replacement".into(),engine:"one".into(),host:"selected-first".into(),adapter,initial_subscriptions:None};
    let mut last=Value::Null;
    let result=tokio::time::timeout(Duration::from_secs(45),async{loop{
        last=rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":request})).await;
        assert!(!running.is_finished());
        if last["state"]=="HOST_REBIND_READY"{break;}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await;
    assert!(result.is_ok(),"{last}");assert_eq!(std::fs::read(&endpoint).unwrap(),before);
    let status=rpc(&ready.admin_endpoint,json!({"method":"status"})).await;
    assert!(status["hosts"].as_array().unwrap().iter().any(|h|h["source_name"]=="selected-first"));
    cancel.cancel();running.await.unwrap().unwrap();
    // The original base still names the old session. The durable Hosts store
    // suppresses exactly that base entry and reconstructs the new dispatcher.
    let cancel=KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();
    let running=tokio::spawn(ipc::serve(base,cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
    assert_eq!(rpc(&ready.admin_endpoint,json!({"method":"host_rebind","rebind":request})).await["state"],"HOST_REBIND_READY");
    cancel.cancel();running.await.unwrap().unwrap();
    let engine=&source.runtime.engines[0];let identity=KernelIdentity::open(&engine.identity_path).unwrap();
    let origin=crate::transport::canonical_lifecycle_origin(&engine.origin,true).unwrap();
    let store=InboxStore::open_local(&engine.state_directory,&identity,&origin).unwrap();
    let pins=store.pins(&source.old.workspace_id,&source.old.mailbox_id).unwrap().unwrap();
    assert_eq!(pins.receiver_id,source.original.receiver_id);assert_eq!(pins.binding_version,source.original.binding_version+2);
    assert_eq!(host.calls().iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).count(),1,"original accepted input cannot be replayed into the new session");
}
