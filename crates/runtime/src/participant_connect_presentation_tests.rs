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

struct InstalledChannel {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
}

impl InstalledChannel {
    async fn start(project: &Path, entry: &Value) -> Self {
        use std::process::Stdio;
        let mut child = tokio::process::Command::new(entry["command"].as_str().unwrap())
            .args(entry["args"].as_array().unwrap().iter().map(|arg| arg.as_str().unwrap()))
            .current_dir(project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut channel = Self { child, input, output };
        channel.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"installed-channel-fixture","version":"1"}}})).await;
        let initialized = channel.next().await;
        assert_eq!(initialized["id"], 1);
        assert!(initialized["result"]["capabilities"]["experimental"]["claude/channel"].is_object());
        channel.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await;
        channel
    }

    async fn send(&mut self, request: Value) {
        self.input.write_all(format!("{request}\n").as_bytes()).await.unwrap();
    }

    async fn next(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(20), self.output.next_line())
            .await.unwrap().unwrap().expect("installed MCP closed before responding");
        serde_json::from_str(&line).unwrap()
    }

    async fn read_probe(&mut self) {
        let notice = self.next().await;
        self.observe_probe(notice).await;
    }

    async fn observe_probe(&mut self, notice: Value) {
        assert_eq!(notice["method"], "notifications/claude/channel", "{notice}");
        self.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"peerwork_inbox",
            "arguments":{"batch":notice["params"]["meta"]["batch"]}}})).await;
        let response = self.next().await;
        assert_eq!(response["id"], 2, "{response}");
        assert_eq!(response["result"]["structuredContent"]["state"], "SELF_TEST_OBSERVED", "{response}");
    }

    async fn context(&mut self) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"peerwork_context","arguments":{}}})).await;
        let response = self.next().await;
        assert_eq!(response["id"], 3, "{response}");
        response["result"]["structuredContent"].clone()
    }

    async fn close(self) {
        let Self { mut child, input, output: _ } = self;
        drop(input);
        let exit = tokio::time::timeout(Duration::from_secs(10), child.wait()).await.unwrap().unwrap();
        assert!(exit.success(), "{exit}");
    }
}

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

    let old=std::sync::Arc::new(new_frontend(&directory,&handle,"MCP_STDIO_CHANNEL"));
    let select=|scope:&'static str| {
        let frontend=old.clone();
        tokio::spawn(async move { frontend.presentation_selection(scope).await })
    };
    let (first,second)=tokio::join!(select("one"),select("two"));
    let activation_a=first.unwrap().unwrap().unwrap();
    assert_eq!(second.unwrap().unwrap().unwrap(),activation_a,"concurrent aliases in one coalesced source must share one decision");
    assert_eq!(activation_a["generation"],before["current_generation"].as_u64().unwrap()+1);
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
    assert_eq!(status["destinations"][0]["control_state"],"PAUSED","{status}");
    let paused_batch=paused_probe["batch"].as_str().unwrap();let paused_revision=paused_probe["revision"].as_u64().unwrap();
    assert!(current.presentation_allowed("one",&activation_c,paused_batch,paused_revision).await.unwrap());
    assert_eq!(tool(&ordinary,"inbox",json!({"batch":paused_batch})).await["state"],"SELF_TEST_OBSERVED");
    assert_eq!(tool(&current,"delivery",json!({"mode":"status"})).await["destinations"][0]["control_state"],"PAUSED");

    // Lose the acceptance reply after the real signed operation commits. The
    // fixture then goes offline, keeping the original outcome UNKNOWN locally.
    // Replacement/restart must not create another namespace or command ID.
    service.config(json!({"drop_action":"structure.workspace.create"})).await;
    let pending=original.call(json!({"method":"invoke","wait_ms":200,"request":Invoke::new("presentation-original-pending",
        "structure.workspace.create",Scope::default(),json!({"name":"Pending original presentation work"}))})).await.unwrap();
    assert_eq!(pending["operation_id"],"presentation-original-pending");
    assert!(!matches!(pending["state"].as_str(),Some("ACCEPTED"|"REJECTED_NO_EFFECT")),"{pending}");
    tokio::time::timeout(Duration::from_secs(10),async {
        while service.counts().await["dropped"]!=1 {tokio::time::sleep(Duration::from_millis(20)).await;}
    }).await.expect("fixture did not drop the original signed acceptance reply");
    let snapshot=tokio::time::timeout(Duration::from_secs(10),async {loop {
        let operation=original.call(json!({"method":"operation","operation_id":"presentation-original-pending"})).await.unwrap();
        assert!(!matches!(operation["state"].as_str(),Some("ACCEPTED"|"REJECTED_NO_EFFECT")),"{operation}");
        if operation["command_id"].is_string() {break operation;}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }}).await.expect("original signed command ID was not frozen after lost acceptance");
    assert_eq!(snapshot["effect_certainty"],"UNKNOWN","{snapshot}");
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
    assert_eq!(tool(&current,"delivery",json!({"mode":"status"})).await["destinations"][0]["control_state"],"PAUSED");
    assert_eq!(std::fs::read(&config.identity_path).unwrap(),identity);

    // Exercise the actual Channel transport and final output gate over duplex
    // MCP. This qualifies native projection, not an authenticated Claude model.
    service.config(json!({"offline":false})).await;
    for watch in &options {ready(&original,watch).await;}
    tool(&ordinary,"delivery",json!({"mode":"self_test"})).await;
    drop(current);
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
    assert_eq!(original.call(json!({"method":"presentation_resume","options":options[0],"activation":activation_c})).await.unwrap()["state"],"SUPERSEDED");
    hw.write_all(format!("{}\n",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"peerwork_inbox","arguments":{"batch":notice["params"]["meta"]["batch"]}}})).as_bytes()).await.unwrap();
    let observed=tokio::time::timeout(Duration::from_secs(10),async {loop {
        line.clear();assert!(hr.read_line(&mut line).await.unwrap()>0);
        let response:Value=serde_json::from_str(&line).unwrap();if response["id"]==2{return response;}
        assert_eq!(response["method"],"notifications/claude/channel","{response}");
    }}).await.unwrap();
    assert_eq!(observed["result"]["isError"],false,"{observed}");
    assert_eq!(observed["result"]["structuredContent"]["state"],"SELF_TEST_OBSERVED","{observed}");
    drop(hw);drop(hr);tokio::time::timeout(Duration::from_secs(10),channel).await.unwrap().unwrap().unwrap();
    assert_eq!(tool(&ordinary,"delivery",json!({"mode":"status"})).await["destinations"][0]["control_state"],"PAUSED");

    let installed: Value = serde_json::from_slice(&std::fs::read(project.join(".mcp.json")).unwrap()).unwrap();
    let entry = |space: &str| installed["mcpServers"].as_object().unwrap().values()
        .find(|entry| entry["args"].as_array().unwrap().iter().any(|arg| arg == space)).unwrap();
    let host_cli = |entry: &str| {
        let mut command = tokio::process::Command::new(&executable);
        command.arg(entry).arg("--local").arg(&directory).current_dir(&project);
        command
    };
    let connect_status = host_cli("connect").arg("--context").output().await.unwrap();
    assert!(connect_status.status.success(), "{}", String::from_utf8_lossy(&connect_status.stdout));
    let cli_context = host_cli("agent").args(["--participant", &handle, "context"]).output().await.unwrap();
    let context: Value = serde_json::from_slice(&cli_context.stdout).unwrap();
    assert_eq!(context["actor_id"], config.expected_actor);

    let generation = || async {
        original.call(json!({"method":"presentation_status","options":options[0]})).await.unwrap()["current_generation"].as_u64().unwrap()
    };
    let mut foreground = InstalledChannel::start(&project, entry(&spaces[0])).await;
    tool(&ordinary,"delivery",json!({"mode":"self_test"})).await;
    foreground.read_probe().await;
    let selected = generation().await;
    let mut standby = InstalledChannel::start(&project, entry(&spaces[1])).await;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let standby_context = standby.context().await;
            assert_eq!(standby_context["actor_id"], config.expected_actor);
            if standby_context["host_channel"]["scopes"].as_object().is_some_and(|scopes|
                scopes.values().any(|scope| scope["code"] == "CLAUDE_CHANNEL_STANDBY")) {break;}
            assert_eq!(generation().await, selected, "handshake-only spare displaced the installed Channel");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.expect("overlapping installed Channels did not identify the standby");
    // A spare that only initializes must not replace a working connection.
    // A real batch exposes the ownership difference without changing the
    // service consumer or treating the MCP handshake as a wake receipt.
    tool(&ordinary,"delivery",json!({"mode":"self_test"})).await;
    let notice = tokio::select! {
        result = foreground.next() => result,
        _ = standby.next() => panic!("an initialized standby intercepted the active Channel batch"),
        _ = tokio::time::sleep(Duration::from_secs(12)) => panic!("neither Channel presented the pending batch"),
    };
    foreground.observe_probe(notice).await;
    assert_eq!(generation().await, selected, "handshake-only spare displaced the installed Channel");
    foreground.close().await;
    tool(&ordinary,"delivery",json!({"mode":"self_test"})).await;
    standby.read_probe().await;
    assert_eq!(generation().await, selected + 1);
    assert_eq!(tool(&ordinary,"delivery",json!({"mode":"status"})).await["destinations"][0]["control_state"],"PAUSED");
    standby.close().await;

    // The installed MCP fixture above exercises the existing startup path.
    // Exercise the session-qualified successor through the same authenticated
    // runtime entry before teaching the frontend to send the host marker.
    let observed=original.call(json!({"method":"presentation_status","options":options[0]})).await.unwrap();
    let opts=serde_json::to_value(&options[0]).unwrap();
    let source=crate::agent_delivery_status::binding(&context,&opts);
    let activate=|operation:&str,generation:u64,marker:Value,select:bool| {
        let mut target=json!({"kind":"MCP_STDIO_CHANNEL","registration_id":"installed-claude-session","host_destination":null});
        if !marker.is_null() {target["host_session"]=marker;}
        json!({"method":"presentation_activate","activation":{
            "client_name":source["client_name"],"source_binding":source,"source_group":observed["group"],
            "options":opts,"target":target,"operation_id":operation,"expected_generation":generation,"select_session":select}})
    };
    let submit=|value| crate::communication_runtime::call(&runtime_ready.admin_endpoint,value);
    let current=generation().await;
    let selected_session=json!("a".repeat(64));
    let wrong_session=json!("b".repeat(64));
    let invalid=submit(activate("invalid-marker",current,json!("not-a-digest"),true)).await.unwrap();
    assert_eq!(invalid["error"]["code"],"PRESENTATION_TARGET_INVALID");
    let initial=submit(activate("initial-handshake",current,selected_session.clone(),false)).await.unwrap();
    assert_eq!(initial["error"]["code"],"CLAUDE_CHANNEL_SESSION_SELECTION_REQUIRED");
    let initial=submit(activate("choose-this-session",current,selected_session.clone(),true)).await.unwrap();
    assert_eq!(initial["value"]["state"],"ACTIVE","{initial}");
    let pinned=generation().await;
    for marker in [wrong_session,Value::Null] {
        let result=submit(activate("standby-handshake",pinned,marker,false)).await.unwrap();
        assert_eq!(result["error"]["code"],"CLAUDE_CHANNEL_SESSION_MISMATCH");
        assert_eq!(generation().await,pinned);
    }
    let same=activate("original-session-returned",pinned,selected_session,false);
    let activated=submit(same.clone()).await.unwrap();
    assert_eq!(activated["value"]["current_generation"],pinned+1);
    assert_eq!(submit(same).await.unwrap(),activated);
    let old=original.call(json!({"method":"presentation_resume","options":options[1],"activation":initial["value"]["activation"]})).await.unwrap();
    assert_eq!(old["state"],"SUPERSEDED");
    assert_eq!(tool(&ordinary,"delivery",json!({"mode":"status"})).await["destinations"][0]["control_state"],"PAUSED");
    assert_eq!(original.call(json!({"method":"binding"})).await.unwrap(),binding);
    assert_eq!(tool(&ordinary,"status",json!({"operation_id":"presentation-original-message"})).await["command_id"],message["command_id"]);
    stop.cancel();task.await.unwrap().unwrap();
}
