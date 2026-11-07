//! Public-API qualification avoids compiling the runtime's entire legacy unit
//! test harness. All service data, identities and keys here are synthetic.
use peerwork_runtime::{participant::{Capability,DeliveryReference,Invoke,Operation,ParticipantClient,ParticipantConfig,Scope,WatchOptions},agent_tools::{AgentRequest,AgentSelection,AgentTools,MailScope},kernel_identity::KernelIdentity};
use peerwork_core::crypto::sha256_hex;
use serde_json::{json,Value};
use std::{path::{Path,PathBuf},process::{Child,Command,Stdio},io::{BufRead,BufReader,Write},time::Duration};

struct InstalledProcess {child:Child,frames:std::sync::mpsc::Receiver<Value>}
impl InstalledProcess {
    fn start(binary:&Path,words:&[&str])->Self {
        let mut child=Command::new(binary).args(words).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let stdout=child.stdout.take().unwrap();let(tx,frames)=std::sync::mpsc::channel();
        std::thread::spawn(move||{for line in BufReader::new(stdout).lines(){let Ok(line)=line else{break};let value=serde_json::from_str(&line).expect("installed process emitted invalid JSON");if tx.send(value).is_err(){break;}}});Self{child,frames}
    }
    fn write(&mut self,value:Value){let input=self.child.stdin.as_mut().unwrap();writeln!(input,"{value}").unwrap();input.flush().unwrap();}
    fn rpc(&mut self,id:u64,method:&str,params:Value)->Value {
        self.write(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        loop{let value=self.frames.recv_timeout(Duration::from_secs(20)).expect("installed MCP response timeout");if value.get("id").is_none(){continue;}assert_eq!(value["id"],id);assert!(value.get("error").is_none(),"{value}");return value["result"].clone();}
    }
    fn tool(&mut self,id:u64,name:&str,arguments:Value)->Value {
        let result=self.rpc(id,"tools/call",json!({"name":name,"arguments":arguments}));assert_ne!(result["isError"],true,"{result}");assert!(result["structuredContent"].is_object(),"{result}");result["structuredContent"].clone()
    }
    fn finish(&mut self){drop(self.child.stdin.take());let end=std::time::Instant::now()+Duration::from_secs(10);loop{if let Some(status)=self.child.try_wait().unwrap(){assert!(status.success());return;}assert!(std::time::Instant::now()<end,"owned installed process did not stop");std::thread::sleep(Duration::from_millis(20));}}
}
impl Drop for InstalledProcess {fn drop(&mut self){if self.child.try_wait().ok().flatten().is_none(){let _=self.child.kill();let _=self.child.wait();}}}
fn private_json(path:&Path,value:Value){
    let mut options=std::fs::OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let mut file=options.open(path).unwrap();file.write_all(value.to_string().as_bytes()).unwrap();
}

struct Service {child:Child,origin:String}
impl Service {
    fn start()->Self {
        let node=std::env::var("PEERWORK_TEST_NODE").expect("explicit TEST Node");
        let script=PathBuf::from(std::env::var("PEERWORK_SDK_REFERENCE_ROOT").expect("explicit matching SDK fixture root")).join("tests/participant-service.mjs");
        let mut child=Command::new(node).arg(script).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let stdout=child.stdout.take().unwrap();let(tx,rx)=std::sync::mpsc::channel();
        let reader=std::thread::spawn(move||{let mut text=String::new();let _=BufReader::new(stdout).read_line(&mut text);let _=tx.send(text);});
        let text=match rx.recv_timeout(Duration::from_secs(30)){Ok(v)=>v,Err(e)=>{let _=child.kill();let _=child.wait();panic!("fixture start: {e}")}};reader.join().unwrap();
        let data:Value=serde_json::from_str(&text).expect("fixture endpoint");Self{child,origin:data["origin"].as_str().unwrap().into()}
    }
    async fn config(&self,value:Value){reqwest::Client::new().post(format!("{}/__test/config",self.origin)).body(value.to_string()).send().await.unwrap().error_for_status().unwrap();}
    async fn counts(&self)->Value {reqwest::get(format!("{}/__test/counts",self.origin)).await.unwrap().text().await.map(|v|serde_json::from_str(&v).unwrap()).unwrap()}
}
impl Drop for Service {
    fn drop(&mut self){
        #[cfg(unix)] unsafe{libc::kill(self.child.id() as i32,libc::SIGTERM);}
        for _ in 0..250{if self.child.try_wait().ok().flatten().is_some(){return;}std::thread::sleep(Duration::from_millis(20));}
        let _=self.child.kill();let _=self.child.wait();
    }
}
fn private_dir()->tempfile::TempDir {
    let path=tempfile::tempdir().unwrap();
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(path.path(),std::fs::Permissions::from_mode(0o700)).unwrap();}
    path
}
fn configuration(directory:&Path,origin:&str)->ParticipantConfig {
    let path=directory.join("identity");let identity=KernelIdentity::create(&path).unwrap();let mut config=ParticipantConfig::new(origin,identity.actor_id(),path,directory.join("engine"));config.allow_loopback_http=true;config.transport.request_timeout_ms=2000;config
}
fn install_synthetic_key(config:&ParticipantConfig,origin:&str,workspace:&str,secret:&[u8;32],expected:Option<&str>)->String {
    let identity=KernelIdentity::open(&config.identity_path).unwrap();let key=peerwork_core::structure_content::structure_content_key_id(secret);
    let mut transport=peerwork_runtime::transport::TransportConfig::new(origin);transport.allow_loopback_http=true;
    let path=config.identity_path.with_extension(format!("{}.content-keys.sqlite",sha256_hex(origin.as_bytes())));
    let source=config.identity_path.with_extension("synthetic-content-key");std::fs::write(&source,secret).unwrap();
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&source,std::fs::Permissions::from_mode(0o600)).unwrap();}
    let mut keys=peerwork_runtime::kernel_intents::StructureContentKeys::open(&path,transport).unwrap();keys.import_current_from_file(identity.key_id(),workspace,&source,&key,expected).unwrap();std::fs::remove_file(source).unwrap();key
}
fn structure(op:&Operation)->Value {assert_eq!(op.state,"ACCEPTED","{}",serde_json::to_string(op).unwrap());op.outcome.as_ref().unwrap()["result"]["structure"].clone()}
async fn mutate(client:&ParticipantClient,id:&str,action:&str,scope:&Scope,body:Value)->Value {
    let mut op=client.invoke(Invoke::new(id,action,scope.clone(),body),Duration::from_secs(5)).await.unwrap();
    let end=std::time::Instant::now()+Duration::from_secs(10);
    while !op.is_terminal(){assert!(std::time::Instant::now()<end,"operation did not settle");tokio::time::sleep(Duration::from_millis(20)).await;op=client.operation(id).await.unwrap();}
    structure(&op)
}
async fn selected(client:&ParticipantClient,action:&str,scope:&Scope,body:Value)->Value {
    let value=client.request(Invoke::new("selected",action,scope.clone(),body)).await.unwrap();assert_eq!(value["state"],"ACCEPTED","{action}: {value}");value["result"]["structure"].clone()
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires explicit local TEST PostgreSQL and compiled product fixture"]
async fn shared_conversation_native_watch_mcp_reply_and_original_journal_recovery(){
    let service=Service::start();
    let owner_root=private_dir();let worker_root=private_dir();
    let owner_config=configuration(owner_root.path(),&service.origin);let worker_config=configuration(worker_root.path(),&service.origin);
    let owner=ParticipantClient::open(owner_config.clone()).await.unwrap();let worker=ParticipantClient::open(worker_config.clone()).await.unwrap();
    let created=mutate(&owner,"shared-space","structure.workspace.create",&Scope::default(),json!({"name":"Shared conversation"})).await;
    let workspace=created["workspace_id"].as_str().unwrap().to_owned();let scope=Scope{workspace_id:Some(workspace.clone()),..Default::default()};
    let meta=selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    let mut join=Invoke::new("shared-join","structure.member.set",scope.clone(),json!({"actor_id":worker.actor_id(),"state":"ACTIVE","expected_membership_id":null}));join.expected_workspace_revision=meta["workspace_revision"].as_u64();
    let joined=structure(&owner.invoke(join,Duration::from_secs(5)).await.unwrap());
    let key=install_synthetic_key(&owner_config,owner.origin(),&workspace,&[37;32],None);install_synthetic_key(&worker_config,worker.origin(),&workspace,&[37;32],None);
    mutate(&owner,"shared-key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let mailbox=selected(&worker,"structure.mailboxes.read",&scope,json!({"limit":8})).await["mailboxes"][0].clone();
    assert_eq!(mailbox["membership_id"],joined["membership_id"]);
    service.config(json!({"resident_worker":true,"capture_disclosure":true})).await;
    let options=WatchOptions{workspace_id:workspace.clone(),mailbox_id:mailbox["mailbox_id"].as_str().unwrap().into(),membership_id:mailbox["membership_id"].as_str().unwrap().into(),consumer_id:"room-native".into(),host_destination:None};
    let watch=worker.watch(options.clone()).await.unwrap();
    let room=peerwork_core::communication::space_conversation_id(&workspace).unwrap();
    let mut send=Invoke::new("shared-original-post","structure.conversation.post",scope.clone(),json!({"conversation_id":room,"audience":"SPACE_MEMBERS","thread_root":null,"reply_to":null,"context":null,"mentions":[worker.actor_id()],"content":{"mode":"WORKSPACE_E2EE"}}));send.plaintext_message=Some("Shared ping 📨".into());
    let sent=structure(&owner.invoke(send.clone(),Duration::from_secs(5)).await.unwrap());
    assert_eq!(sent["conversation"]["audience_count"],2);assert_eq!(sent["sender_membership"],meta["membership"]["membership_id"]);
    assert_eq!(structure(&owner.invoke(send,Duration::from_secs(5)).await.unwrap()),sent);
    let initial=owner.request(Invoke::new("initial-history","structure.conversation.messages.read",scope.clone(),json!({"conversation_id":room,"limit":8}))).await;assert!(initial.is_ok(),"history: {:?} fixture: {}",initial.err(),service.counts().await);
    let entry=tokio::time::timeout(Duration::from_secs(12),async{loop{
        let page=watch.page(0,32).await.unwrap();
        if let Some(item)=page.items.iter().find(|v|v["envelope"]["message"]["message_id"]==sent["message_id"]).cloned(){break item;}
        assert!(!matches!(page.state.as_str(),"BLOCKED"|"STREAM_VERIFICATION_FAILED"),"{} fixture: {}",serde_json::to_string(&page).unwrap(),service.counts().await);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }}).await.expect("shared group message not delivered");
    assert_eq!(entry["opened_message"]["text"],"Shared ping 📨");assert_eq!(entry["opened_message"]["message_kind"],"SPACE_CONVERSATION");assert_eq!(entry["opened_message"]["mentions"][0],worker.actor_id());
    let reference=DeliveryReference{sequence:entry["sequence"].as_u64().unwrap(),delivery_id:entry["delivery_id"].as_str().unwrap().into()};
    let mut selection=AgentSelection::for_client(&worker);selection.workspaces.insert("team".into(),workspace.clone());selection.scopes.insert("team".into(),MailScope{workspace_id:workspace.clone(),mailbox_id:options.mailbox_id.clone(),membership_id:options.membership_id.clone()});
    assert!(selection.contacts.is_empty());let tools=AgentTools::from_client(worker.clone(),selection).unwrap();
    let replied=tools.call(AgentRequest::Reply{scope:"team".into(),item:reference.clone(),operation_id:"shared-mcp-reply".into(),text:"Shared pong".into(),wait_ms:5000}).await.unwrap();assert_eq!(replied["state"],"ACCEPTED");
    let posted=tools.call(AgentRequest::parse("post",json!({"workspace":"team","operation_id":"shared-mcp-post","text":"Group update","wait_ms":5000})).unwrap()).await.unwrap();assert_eq!(posted["state"],"ACCEPTED");
    let history=tools.call(AgentRequest::parse("chat",json!({"workspace":"team","limit":8})).unwrap()).await.unwrap();
    assert_eq!(history["messages"].as_array().unwrap().len(),3);assert_eq!(history["messages"][0]["body"]["text"],"Shared ping 📨");assert_eq!(history["messages"][1]["body"]["text"],"Shared pong");assert_eq!(history["messages"][0]["conversation"]["thread_root"],history["messages"][1]["conversation"]["thread_root"]);
    assert!(!history.to_string().contains("author_intent"));assert!(!history.to_string().contains("ciphertext"));assert_eq!(history["authority"],"EXTERNAL_PEER_DATA");
    let address=selected(&worker,"structure.mailbox.get",&scope,json!({"mailbox_id":options.mailbox_id})).await["mailbox"].clone();
    let host_scope=json!({"format":"peerwork.host-call.v1","owner":"synthetic-public-client","namespace":"program:synthetic","workspace_id":workspace,"mailbox_id":options.mailbox_id,"membership_id":options.membership_id,"sequence":reference.sequence,"delivery_id":reference.delivery_id,"receiver_id":address["receiver_id"],"epoch":address["epoch"],"binding_version":address["binding_version"],"destination_digest":address["destination_digest"],"call_id":"H".repeat(43),"frame_digest":"e".repeat(64),"source_digest":"f".repeat(64)});
    let host_report=json!({"sequence":reference.sequence,"delivery_id":reference.delivery_id,"call_id":"H".repeat(43),"attempt":1,"scope":host_scope,"frame_digest":"e".repeat(64),"state":"HOST_QUEUED","facts":[{"state":"HOST_QUEUED","receipt":"synthetic-program-queue"}],"report_sequence":1});
    selected(&worker,"structure.mailbox.report",&scope,json!({"mailbox_id":options.mailbox_id,"receiver_id":address["receiver_id"],"epoch":address["epoch"],"report":host_report})).await;
    let host_receipts=tools.call(AgentRequest::parse("receipts",json!({"scope":"team","message_id":sent["message_id"],"conversation":true})).unwrap()).await.unwrap();
    let target=host_receipts["deliveries"].as_array().unwrap().iter().find(|v|v["actor_id"]==worker.actor_id()).unwrap();assert_eq!(target["host_report"]["state"],"HOST_QUEUED");assert_eq!(target["host_report"]["model_response"],"NOT_ATTESTED");assert!(target["application_consumed_at"].is_null());
    watch.consume(vec![reference]).await.unwrap();
    let receipts=tokio::time::timeout(Duration::from_secs(8),async{loop{
        let current=tools.call(AgentRequest::parse("receipts",json!({"scope":"team","message_id":sent["message_id"],"conversation":true})).unwrap()).await.unwrap();
        if current["counts"]["application_consumed"]==1{break current;}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }}).await.expect("native consumption not recorded");assert_eq!(receipts["counts"]["targets"],2);assert_eq!(receipts["model_response"],"NOT_ATTESTED");
    mutate(&worker,"shared-pin","structure.conversation.pin.set",&scope,json!({"conversation_id":room,"expected_revision":0,"reference":{"kind":"MESSAGE","message_id":sent["message_id"]}})).await;
    let pinned=owner.request(Invoke::new("pinned-room","structure.conversation.get",scope.clone(),json!({}))).await.unwrap();
    assert_eq!(pinned["result"]["structure"]["conversation"]["pin_author"],worker.actor_id());assert_eq!(pinned["result"]["opened_messages"][0]["text"],"Shared ping 📨");
    let before=service.counts().await;owner.close().await.unwrap();
    let restored=ParticipantClient::open(owner_config).await.unwrap();let recovered=restored.recover("shared-original-post").await.unwrap();assert_eq!(structure(&recovered),sent);assert_eq!(before["commands"],service.counts().await["commands"]);
    mutate(&restored,"shared-withdraw","structure.message.withdraw",&scope,json!({"message_id":sent["message_id"]})).await;
    let current=selected(&worker,"structure.conversation.messages.read",&scope,json!({"conversation_id":room,"limit":8})).await;assert_eq!(current["messages"][0]["state"],"WITHDRAWN");assert!(current["messages"][0].get("author_intent").is_none());
    let pinned=worker.request(Invoke::new("withdrawn-pin","structure.conversation.get",scope.clone(),json!({}))).await.unwrap();assert_eq!(pinned["result"]["structure"]["conversation"]["pin_message"]["state"],"WITHDRAWN");assert!(pinned["result"]["opened_messages"].as_array().unwrap().is_empty());
    worker.unwatch(&options).await.unwrap();drop(tools);worker.close().await.unwrap();
    if let Ok(installed)=std::env::var("PEERWORK_TEST_CLI") {
        // Exercise the actual installed stdin-MCP and scoped encrypted IPC,
        // reopening this same synthetic identity and original journal.
        let cli=worker_root.path().join("peerwork");std::fs::copy(installed,&cli).unwrap();
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&cli,std::fs::Permissions::from_mode(0o700)).unwrap();}
        let mut capability=Capability::owner();capability.allow_root=false;capability.workspace_ids=Some([workspace.clone()].into());
        let config=worker_root.path().join("runtime.json");private_json(&config,json!({"format":"peerwork.participant-runtime.v1","state_directory":worker_root.path().join("runtime"),"engines":[{"name":"worker","origin":restored.origin(),"expected_actor":worker.actor_id(),"identity_path":worker_config.identity_path,"state_directory":worker_config.state_directory,"allow_loopback_http":true,"max_inflight":2,"max_pending":8}],"clients":[{"name":"agent","engine":"worker","capability":capability}],"hosts":[]}));
        let mut runtime=InstalledProcess::start(&cli,&["runtime","run",config.to_str().unwrap()]);let ready=runtime.frames.recv_timeout(Duration::from_secs(20)).unwrap();assert_eq!(ready["state"],"LOCAL_READY","{ready}");
        let profile=worker_root.path().join("agent.json");private_json(&profile,json!({"format":"peerwork.agent-profile.v1","endpoint_path":ready["client_endpoints"]["agent"],"expected_origin":restored.origin(),"expected_actor":worker.actor_id(),"workspaces":{"team":workspace},"scopes":{}}));
        let start_mcp=||{
            let mut mcp=InstalledProcess::start(&cli,&["agent","--profile",profile.to_str().unwrap(),"mcp"]);
            mcp.rpc(1,"initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"installed-room-qualification","version":"1"}}));mcp.write(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));mcp
        };
        let mut mcp=start_mcp();let catalog=mcp.rpc(2,"tools/list",json!({}));for name in ["peerwork_chat","peerwork_post"]{assert!(catalog["tools"].as_array().unwrap().iter().any(|tool|tool["name"]==name));}
        let history=mcp.tool(3,"peerwork_chat",json!({"workspace":"team","limit":8}));assert_eq!(history["messages"].as_array().unwrap().len(),3);assert_eq!(history["messages"][0]["state"],"WITHDRAWN");assert_eq!(history["messages"][1]["body"]["text"],"Shared pong");assert!(!history.to_string().contains("author_intent"));
        let post=json!({"workspace":"team","operation_id":"installed-room-post","text":"Installed MCP shared update","wait_ms":5000});let accepted=mcp.tool(4,"peerwork_post",post.clone());assert_eq!(accepted["state"],"ACCEPTED");mcp.finish();
        let before=service.counts().await;mcp=start_mcp();let again=mcp.tool(2,"peerwork_post",post);assert_eq!(again["state"],"ACCEPTED");assert_eq!(service.counts().await["commands"],before["commands"],"restarting MCP must retain the original accepted intent");
        let history=restored.request(Invoke::new("installed-group-history","structure.conversation.messages.read",scope.clone(),json!({"conversation_id":room,"limit":8}))).await.unwrap();assert_eq!(history["result"]["structure"]["messages"].as_array().unwrap().len(),4);assert_eq!(history["result"]["opened_messages"].as_array().unwrap().last().unwrap()["text"],"Installed MCP shared update");mcp.finish();
        let stop=Command::new(&cli).args(["runtime","admin",ready["admin_endpoint"].as_str().unwrap(),"stop"]).output().unwrap();assert!(stop.status.success(),"{}",String::from_utf8_lossy(&stop.stdout));runtime.finish();
        eprintln!("INSTALLED_STDIO_MCP_GROUP_AND_SAME_INTENT_RESTART_PASS");
        if let Ok(adapter_path)=std::env::var("PEERWORK_CODEX_CONTROL_CONFIG") {
            // A separate synthetic member has never bound a receiver. Attach
            // the installed runtime to an explicitly selected, isolated official
            // host; do not replace any existing user's conversation or receiver.
            let adapter:Value=serde_json::from_slice(&std::fs::read(adapter_path).unwrap()).unwrap();
            let host_root=private_dir();let host_config=configuration(host_root.path(),restored.origin());
            let host_client=ParticipantClient::open(host_config.clone()).await.unwrap();
            let current=selected(&restored,"structure.workspace.get",&scope,json!({})).await;
            let mut join=Invoke::new("official-host-member","structure.member.set",scope.clone(),json!({"actor_id":host_client.actor_id(),"state":"ACTIVE","expected_membership_id":null}));join.expected_workspace_revision=current["workspace_revision"].as_u64();
            restored.invoke(join,Duration::from_secs(5)).await.unwrap();
            // A new local key store has no previous selection. The remote
            // workspace key is not an expected prior local selection.
            install_synthetic_key(&host_config,restored.origin(),&workspace,&[37;32],None);
            let mailbox=selected(&host_client,"structure.mailboxes.read",&scope,json!({"limit":8})).await["mailboxes"][0].clone();host_client.close().await.unwrap();
            let mut capability=Capability::owner();capability.allow_root=false;capability.workspace_ids=Some([workspace.clone()].into());
            let config=host_root.path().join("runtime.json");private_json(&config,json!({"format":"peerwork.participant-runtime.v1","state_directory":host_root.path().join("runtime"),"engines":[{"name":"host","origin":restored.origin(),"expected_actor":host_client.actor_id(),"identity_path":host_config.identity_path,"state_directory":host_config.state_directory,"allow_loopback_http":true,"max_inflight":2,"max_pending":8}],"clients":[{"name":"agent","engine":"host","capability":capability}],"hosts":[{"name":"official-room","adapter":adapter,"subscriptions":[{"client":"agent","watch":{"workspace_id":workspace,"mailbox_id":mailbox["mailbox_id"],"membership_id":mailbox["membership_id"],"consumer_id":"official-room","host_destination":null}}]}]}));
            let mut runtime=InstalledProcess::start(&cli,&["runtime","run",config.to_str().unwrap()]);let ready=runtime.frames.recv_timeout(Duration::from_secs(20)).unwrap();assert_eq!(ready["state"],"LOCAL_READY","{ready}");
            let mut post=Invoke::new("official-host-room-post","structure.conversation.post",scope.clone(),json!({"conversation_id":room,"audience":"SPACE_MEMBERS","thread_root":null,"reply_to":null,"context":null,"mentions":[host_client.actor_id()],"content":{"mode":"WORKSPACE_E2EE"}}));post.plaintext_message=Some("PW-SHARED-INSTALLED-HOST-20261107".into());
            let sent=structure(&restored.invoke(post,Duration::from_secs(5)).await.unwrap());
            let accepted=tokio::time::timeout(Duration::from_secs(30),async{loop{
                let facts=selected(&restored,"structure.conversation.deliveries.read",&scope,json!({"message_id":sent["message_id"],"limit":8})).await;
                if let Some(target)=facts["deliveries"].as_array().unwrap().iter().find(|v|v["actor_id"]==host_client.actor_id()&&v["host_report"]["state"]=="HOST_ACCEPTED"){break target.clone();}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }}).await;
            let stop=Command::new(&cli).args(["runtime","admin",ready["admin_endpoint"].as_str().unwrap(),"stop"]).output().unwrap();assert!(stop.status.success());runtime.finish();
            let accepted=accepted.expect("installed shared-room message did not reach the selected official host");assert_eq!(accepted["host_report"]["model_response"],"NOT_ATTESTED");
            eprintln!("INSTALLED_SHARED_ROOM_OFFICIAL_CODEX_HOST_ACCEPTED_PASS");
        }
    }
    restored.close().await.unwrap();
}

#[test]
fn shared_conversation_tools_are_workspace_first_and_keep_explicit_parent_boundaries(){
    let names=peerwork_runtime::agent_tools::catalog().into_iter().map(|v|v["name"].as_str().unwrap().to_owned()).collect::<Vec<_>>();assert!(names.contains(&"peerwork_chat".into()));assert!(names.contains(&"peerwork_post".into()));
    let post=AgentRequest::parse("post",json!({"operation_id":"one","text":"group"})).unwrap();assert!(matches!(post,AgentRequest::Post{workspace:None,..}));
    assert!(AgentRequest::parse("post",json!({"operation_id":"one","text":"group","identity_path":"/wrong"})).is_err());
    let mut capability=Capability::owner();capability.allow_root=false;capability.workspace_ids=Some(["W".repeat(43)].into());
    let request=Invoke::new("group","structure.conversation.post",Scope{workspace_id:Some("W".repeat(43)),..Default::default()},json!({}));assert!(capability.authorize(&request).is_ok());
    capability.mailbox_ids=Some(["M".repeat(43)].into());assert_eq!(capability.authorize(&request).unwrap_err().code,"LOCAL_SCOPE_DENIED");
}
