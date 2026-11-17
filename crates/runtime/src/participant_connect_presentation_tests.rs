//! Original-client presentation succession over signed product HTTP and native
//! IPC. All identities, Spaces, keys and host installations are synthetic.
use super::*;
use crate::{
    agent_lifecycle::Lifecycle,
    agent_tools::AgentRequest,
    communication_runtime::{self as ipc, RuntimeConfig, RuntimeReady},
    participant::{ParticipantClient, ParticipantConfig},
    participant::http_tests::{Service, configuration, mutate, selected, install_synthetic_key, native_message},
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt,AsyncWriteExt};

async fn start(config:RuntimeConfig)->(RuntimeReady,crate::KernelCancellationToken,tokio::task::JoinHandle<Result<()>>) {
    let stop=crate::KernelCancellationToken::new();
    let(tx,rx)=tokio::sync::oneshot::channel();
    let task=tokio::spawn(ipc::serve(config,stop.clone(),tx));
    let ready=tokio::time::timeout(Duration::from_secs(15),rx).await.unwrap().unwrap().unwrap();
    (ready,stop,task)
}
fn runtime(root:&Path,config:&ParticipantConfig)->RuntimeConfig {
    RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:root.join("runtime"),hosts:vec![],
        engines:vec![ipc::EngineConfig{name:"original".into(),origin:config.origin.clone(),expected_actor:config.expected_actor.clone(),
            identity_path:config.identity_path.clone(),state_directory:config.state_directory.clone(),journal_path:Some(config.journal_path.clone()),
            authority:config.authority.clone(),allow_loopback_http:true,transport:config.transport.clone(),max_inflight:8,max_pending:64,
            max_stored_bytes:32*1024*1024,migration_sources:vec![]}],
        clients:vec![ipc::ClientConfig{name:"original".into(),engine:"original".into(),capability:Capability::service()}]}
}
async fn ready(client:&RuntimeClient,options:&WatchOptions) {
    client.call(json!({"method":"watch","options":options})).await.unwrap();
    tokio::time::timeout(Duration::from_secs(25),async {loop {
        let value=client.call(json!({"method":"watch_next","options":options,"wait_ms":1000})).await.unwrap();
        assert_ne!(value["state"],"BLOCKED","{value}");
        if value["receiver_link_verified"]==true {break;}
    }}).await.expect("original signed receiver did not become ready");
}
async fn due(lifecycle:&Lifecycle,scope:&str,activation:&Value)->Value {
    tokio::time::timeout(Duration::from_secs(30),async {loop {
        let value=lifecycle.presentation_poll(scope,activation).await.unwrap();
        if value["state"]=="NOTIFICATION_DUE" {return value;}
        tokio::time::sleep(Duration::from_millis(25)).await;
    }}).await.expect("original notification did not become due")
}
async fn tool(lifecycle:&Lifecycle,name:&str,args:Value)->Value {
    lifecycle.call(AgentRequest::parse(name,args).unwrap()).await.unwrap()
}
fn new_frontend(directory:&Path,handle:&str,kind:&str)->Lifecycle {
    let lifecycle=Lifecycle::local(directory.into(),Some(handle.into()),None);
    lifecycle.presentation_transport(kind).unwrap();lifecycle
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
#[ignore="requires isolated TEST PostgreSQL, product HTTP and a persistent candidate executable"]
async fn original_two_space_presentations_replace_without_reclaim_or_pending_operation_loss() {
    let service=Service::start();let root=crate::test_support::protected_test_dir();
    let config=configuration(root.path(),&service.origin);
    let identity=std::fs::read(&config.identity_path).unwrap();
    let owner=ParticipantClient::open(config.clone()).await.unwrap();
    let mut spaces=Vec::new();let mut mailboxes=Vec::new();let mut options=Vec::new();
    for (index,alias) in ["one","two"].iter().enumerate() {
        let ws=mutate(&owner,&format!("presentation-space-{index}"),"structure.workspace.create",&Scope::default(),json!({"name":format!("Presentation {alias}")})).await["workspace_id"].as_str().unwrap().to_owned();
        let scope=Scope{workspace_id:Some(ws.clone()),..Default::default()};
        let metadata=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
        let mailbox=mutate(&owner,&format!("presentation-mailbox-{index}"),"structure.communication.grant.set",&scope,
            json!({"actor_id":owner.actor_id(),"membership_id":metadata["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
        let key=install_synthetic_key(&config,&ws,&[81+index as u8;32],None);
        mutate(&owner,&format!("presentation-key-{index}"),"structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
        options.push(WatchOptions{workspace_id:ws.clone(),mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),
            membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:"original-presentation".into(),host_destination:None});
        spaces.push(ws);mailboxes.push(mailbox);
    }
    owner.close().await.unwrap();
    service.config(json!({"resident_worker":true})).await;
    let runtime=runtime(root.path(),&config);
    let(runtime_ready,stop,task)=start(runtime.clone()).await;
    let original=RuntimeClient::connect(runtime_ready.client_endpoints["original"].clone(),&service.origin,&config.expected_actor).await.unwrap();
    for watch in &options {ready(&original,watch).await;}
    let binding=original.call(json!({"method":"binding"})).await.unwrap();
    let profile:AgentProfile=serde_json::from_value(json!({"format":"peerwork.agent-profile.v1","endpoint_path":runtime_ready.client_endpoints["original"],
        "expected_origin":service.origin,"expected_actor":config.expected_actor,"workspaces":{"one":spaces[0],"two":spaces[1]},
        "scopes":{"one":{"workspace_id":spaces[0],"mailbox_id":options[0].mailbox_id,"membership_id":options[0].membership_id},
                  "two":{"workspace_id":spaces[1],"mailbox_id":options[1].mailbox_id,"membership_id":options[1].membership_id}}})).unwrap();
    let directory=root.path().join("registry");let mut connect=Connect::open(&directory).unwrap();
    let handle=connect.adopt_profile(&profile,None,false).await.unwrap();
    connect.runtime_admin(&handle,Some(&RuntimeSelection{admin_endpoint:runtime_ready.admin_endpoint.clone(),config_path:None})).await.unwrap();
    let project=root.path().join("project");create_private_state_directory(&project).unwrap();
    let executable=std::env::var_os("PEERWORK_UPDATE_TEST_BINARY").map(PathBuf::from).unwrap_or_else(||std::env::current_exe().unwrap());
    for host in ["claude","agy"] {for workspace in &spaces {
        connect.install(&handle,workspace,Installation{host:host.into(),project:project.clone(),executable:executable.clone()}).unwrap();
    }}
    drop(connect);

    let ordinary=Lifecycle::local(directory.clone(),Some(handle.clone()),None);
    assert_eq!(ordinary.presentation_selection("one").await.unwrap_err().code,"PRESENTATION_HOST_OPT_IN_REQUIRED");
    assert_eq!(tool(&ordinary,"context",json!({})).await["actor_id"],config.expected_actor);
    let before=original.call(json!({"method":"presentation_status","options":options[0]})).await.unwrap();
    assert_eq!(before["state"],"UNMANAGED");assert_eq!(before["group"]["members"].as_array().unwrap().len(),2);

    let old=new_frontend(&directory,&handle,"MCP_STDIO_CHANNEL");
    let activation_a=old.presentation_selection("one").await.unwrap().unwrap();
    assert_eq!(old.presentation_selection("two").await.unwrap().unwrap(),activation_a,"aliases in one coalesced source must not replace each other");
    let initial=due(&old,"one",&activation_a).await;
    assert_eq!(initial["self_test"],true);
    assert_eq!(tool(&old,"inbox",json!({"batch":initial["batch"]})).await["state"],"SELF_TEST_OBSERVED");
    let message=original.call(json!({"method":"invoke","wait_ms":5000,"request":native_message("presentation-original-message",
        &Scope{workspace_id:Some(spaces[0].clone()),..Default::default()},&mailboxes[0],&mailboxes[0],&"p".repeat(43),"Original encrypted presentation body")})).await.unwrap();
    assert_eq!(message["state"],"ACCEPTED","{message}");
    let pending_notice=due(&old,"one",&activation_a).await;
    assert_eq!(pending_notice["self_test"],false);
    let batch=pending_notice["batch"].as_str().unwrap();let revision=pending_notice["revision"].as_u64().unwrap();
    assert!(old.presentation_allowed("one",&activation_a,batch,revision).await.unwrap());

    let successor=new_frontend(&directory,&handle,"MCP_BACKGROUND_TOOL");
    let activation_b=successor.presentation_selection("two").await.unwrap().unwrap();
    assert_eq!(successor.presentation_selection("one").await.unwrap().unwrap(),activation_b);
    assert_eq!(activation_b["generation"].as_u64().unwrap(),activation_a["generation"].as_u64().unwrap()+1);
    assert_eq!(old.presentation_poll("one",&activation_a).await.unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
    assert_eq!(old.presentation_allowed("one",&activation_a,batch,revision).await.unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
    assert!(successor.presentation_allowed("two",&activation_b,batch,revision).await.unwrap(),"coalesced notification admission retains the original destination batch");
    assert_eq!(old.presentation_selection("one").await.unwrap().unwrap(),activation_a,"old observer must resume its frozen decision, never reclaim");
    assert_eq!(original.call(json!({"method":"presentation_status","options":options[0]})).await.unwrap()["current_generation"],activation_b["generation"]);
    let page=tool(&old,"inbox",json!({"batch":batch})).await;
    assert!(page.to_string().contains("Original encrypted presentation body"),"{page}");
    let item=page["items"][0]["item"].clone();assert!(item["delivery_id"].is_string(),"{page}");
    tool(&old,"consume",json!({"scope":"one","items":[item]})).await;
    assert!(tool(&successor,"inbox",json!({"scope":"one","view":"active"})).await["items"].as_array().unwrap().is_empty(),"same binding shares original consumption");
    assert_eq!(tool(&ordinary,"status",json!({"operation_id":"presentation-original-message"})).await["command_id"],message["command_id"]);

    tool(&ordinary,"delivery",json!({"mode":"pause"})).await;
    tool(&ordinary,"delivery",json!({"mode":"self_test"})).await;
    let paused_probe=due(&successor,"two",&activation_b).await;assert_eq!(paused_probe["self_test"],true);
    let current=new_frontend(&directory,&handle,"MCP_STDIO_CHANNEL");
    let activation_c=current.presentation_selection("one").await.unwrap().unwrap();
    assert_eq!(current.presentation_selection("two").await.unwrap().unwrap(),activation_c);
    let status=tool(&current,"delivery",json!({"mode":"status"})).await;
    assert_eq!(status["destinations"][0]["state"],"PAUSED","{status}");
    let paused_batch=paused_probe["batch"].as_str().unwrap();let paused_revision=paused_probe["revision"].as_u64().unwrap();
    assert!(current.presentation_allowed("one",&activation_c,paused_batch,paused_revision).await.unwrap());
    assert_eq!(tool(&ordinary,"inbox",json!({"batch":paused_batch})).await["state"],"SELF_TEST_OBSERVED");
    assert_eq!(tool(&current,"delivery",json!({"mode":"status"})).await["destinations"][0]["state"],"PAUSED");

    // Freeze a genuinely uncompleted signed operation, then keep HTTP offline.
    // Replacement/restart must not create another namespace or command ID.
    service.config(json!({"offline":true})).await;
    let pending=original.call(json!({"method":"invoke","wait_ms":50,"request":Invoke::new("presentation-original-pending",
        "structure.workspace.create",Scope::default(),json!({"name":"Pending original presentation work"}))})).await.unwrap();
    assert_eq!(pending["operation_id"],"presentation-original-pending");assert!(pending["command_id"].is_string());assert_ne!(pending["state"],"ACCEPTED");
    let snapshot=original.call(json!({"method":"operation","operation_id":"presentation-original-pending"})).await.unwrap();
    let old_identity=std::fs::read(&config.identity_path).unwrap();assert_eq!(old_identity,identity);
    stop.cancel();task.await.unwrap().unwrap();
    let(_,stop,task)=start(runtime).await;
    assert_eq!(original.call(json!({"method":"binding"})).await.unwrap(),binding);
    assert_eq!(current.presentation_selection("one").await.unwrap().unwrap(),activation_c);
    let resumed=original.call(json!({"method":"presentation_resume","options":options[1],"activation":activation_c})).await.unwrap();
    assert_eq!(resumed["state"],"ACTIVE");assert_eq!(resumed["activation"],activation_c);
    assert_eq!(old.presentation_poll("two",&activation_a).await.unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
    assert_eq!(successor.presentation_poll("one",&activation_b).await.unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
    let after=tool(&old,"status",json!({"operation_id":"presentation-original-pending"})).await;
    assert_eq!(after["command_id"],snapshot["command_id"]);assert_eq!(after["operation_id"],snapshot["operation_id"]);
    assert_eq!(tool(&ordinary,"status",json!({"operation_id":"presentation-original-message"})).await["command_id"],message["command_id"]);
    assert_eq!(tool(&current,"delivery",json!({"mode":"status"})).await["destinations"][0]["state"],"PAUSED");
    assert_eq!(std::fs::read(&config.identity_path).unwrap(),identity);

    // Exercise the actual Channel transport and final output gate over duplex
    // MCP. This qualifies native projection, not an authenticated Claude model.
    service.config(json!({"offline":false})).await;
    for watch in &options {ready(&original,watch).await;}
    tool(&ordinary,"delivery",json!({"mode":"self_test"})).await;
    let(server,host)=tokio::io::duplex(1024*1024);
    let(sr,sw)=tokio::io::split(server);let(hr,mut hw)=tokio::io::split(host);
    let mut hr=tokio::io::BufReader::new(hr);
    let channel=tokio::spawn(crate::agent_mcp::serve_claude_local(directory.clone(),Some(handle.clone()),None,tokio::io::BufReader::new(sr),sw));
    hw.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"presentation-test-host","version":"1"}}})).as_bytes()).await.unwrap();
    let mut line=String::new();tokio::time::timeout(Duration::from_secs(10),hr.read_line(&mut line)).await.unwrap().unwrap();
    let initialized:Value=serde_json::from_str(&line).unwrap();assert_eq!(initialized["id"],1);
    hw.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
    line.clear();tokio::time::timeout(Duration::from_secs(30),hr.read_line(&mut line)).await.unwrap().unwrap();
    let notice:Value=serde_json::from_str(&line).unwrap();
    assert_eq!(notice["method"],"notifications/claude/channel","{notice}");
    assert!(notice.get("_presentation").is_none());assert!(!line.contains("registration_id"));assert!(!line.contains("operation_id"));
    assert_eq!(current.presentation_poll("one",&activation_c).await.unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
    hw.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"peerwork_inbox","arguments":{"batch":notice["params"]["meta"]["batch"]}}})).as_bytes()).await.unwrap();
    let observed=tokio::time::timeout(Duration::from_secs(10),async {loop {
        line.clear();assert!(hr.read_line(&mut line).await.unwrap()>0);
        let response:Value=serde_json::from_str(&line).unwrap();if response["id"]==2{return response;}
        assert_eq!(response["method"],"notifications/claude/channel","{response}");
    }}).await.unwrap();
    assert_eq!(observed["result"]["isError"],false,"{observed}");
    assert_eq!(observed["result"]["structuredContent"]["state"],"SELF_TEST_OBSERVED","{observed}");
    drop(hw);drop(hr);tokio::time::timeout(Duration::from_secs(10),channel).await.unwrap().unwrap().unwrap();
    assert_eq!(tool(&ordinary,"delivery",json!({"mode":"status"})).await["destinations"][0]["state"],"PAUSED");
    stop.cancel();task.await.unwrap().unwrap();
}
