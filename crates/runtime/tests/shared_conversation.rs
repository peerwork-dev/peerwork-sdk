//! Public-API qualification avoids compiling the runtime's entire legacy unit
//! test harness. All service data, identities and keys here are synthetic.
use peerwork_runtime::{participant::{Capability,DeliveryReference,Invoke,Operation,ParticipantClient,ParticipantConfig,Scope,WatchOptions},agent_tools::{AgentRequest,AgentSelection,AgentTools,MailScope},kernel_identity::KernelIdentity};
use peerwork_core::crypto::sha256_hex;
use serde_json::{json,Value};
use std::{path::{Path,PathBuf},process::{Child,Command,Stdio},io::{BufRead,BufReader},time::Duration};

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
    let initial=selected(&owner,"structure.conversation.messages.read",&scope,json!({"conversation_id":room,"limit":8})).await;assert_eq!(initial["messages"].as_array().unwrap().len(),1);
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
    watch.consume(vec![reference]).await.unwrap();
    let receipts=tokio::time::timeout(Duration::from_secs(8),async{loop{
        let current=tools.call(AgentRequest::parse("receipts",json!({"scope":"team","message_id":sent["message_id"],"conversation":true})).unwrap()).await.unwrap();
        if current["counts"]["application_consumed"]==1{break current;}
        tokio::time::sleep(Duration::from_millis(20)).await;
    }}).await.expect("native consumption not recorded");assert_eq!(receipts["counts"]["targets"],2);assert_eq!(receipts["model_response"],"NOT_ATTESTED");
    mutate(&worker,"shared-pin","structure.conversation.pin.set",&scope,json!({"conversation_id":room,"expected_revision":0,"reference":{"kind":"MESSAGE","message_id":sent["message_id"]}})).await;
    let head=selected(&owner,"structure.conversation.get",&scope,json!({})).await;assert_eq!(head["conversation"]["pin_author"],worker.actor_id());
    let before=service.counts().await;owner.close().await.unwrap();
    let restored=ParticipantClient::open(owner_config).await.unwrap();let recovered=restored.recover("shared-original-post").await.unwrap();assert_eq!(structure(&recovered),sent);assert_eq!(before["commands"],service.counts().await["commands"]);
    mutate(&restored,"shared-withdraw","structure.message.withdraw",&scope,json!({"message_id":sent["message_id"]})).await;
    let current=selected(&worker,"structure.conversation.messages.read",&scope,json!({"conversation_id":room,"limit":8})).await;assert_eq!(current["messages"][0]["state"],"WITHDRAWN");assert!(current["messages"][0].get("author_intent").is_none());
    worker.unwatch(&options).await.unwrap();drop(tools);worker.close().await.unwrap();restored.close().await.unwrap();
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
