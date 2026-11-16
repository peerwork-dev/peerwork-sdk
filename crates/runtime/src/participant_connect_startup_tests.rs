//! Real CLI children, synthetic identity/state, no remote workspace or model.
use super::*;
use crate::{communication_runtime::{ClientConfig, EngineConfig, RuntimeConfig}, kernel_identity::KernelIdentity};
use std::{process::{Child, Command, Stdio}, io::{BufRead, BufReader, Write}, time::Duration};

struct Mcp(Child);
impl Mcp {
    fn new(binary: &Path, registry: &Path) -> Self {
        use std::os::unix::fs::OpenOptionsExt;
        let log=std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(registry.join("mcp-startup-test.log")).unwrap();
        let mut child = Command::new(binary).args(["agent", "--local"]).arg(registry)
            .args(["--participant", "peer", "mcp"]).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(log).spawn().unwrap();
        writeln!(child.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"startup-test","version":"1"}}})).unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 1);
        writeln!(child.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc":"2.0","method":"notifications/initialized"})).unwrap();
        Self(child)
    }
}
impl Drop for Mcp { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
struct OriginalChild(Child);
impl Drop for OriginalChild { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

struct Fixture {
    root: crate::test_support::ProtectedTestDir,
    binary: PathBuf,
    first: OriginalChild,
    directory: PathBuf,
    config: RuntimeConfig,
    registration: Registration,
    binding: Value,
}
impl Fixture {
    async fn new() -> Self {
        Self::at("http://127.0.0.1:1").await
    }
    async fn at(origin: &str) -> Self {
        Self::initial(origin,None).await
    }
    async fn initial(origin:&str,previous:Option<&Path>)->Self {
        let candidate = PathBuf::from(std::env::var_os("PEERWORK_UPDATE_TEST_BINARY").expect("set exact candidate CLI"));
        let root = crate::test_support::protected_test_dir();
        // Installation requires a persistent executable. Reuse the caller's
        // frozen candidate; keep only synthetic identity/state in the temp root.
        let binary=std::fs::canonicalize(&candidate).unwrap();
        let identity_path = root.path().join("identity");
        let identity = KernelIdentity::create(&identity_path).unwrap();
        let directory = root.path().join("registry");
        let mut connect = Connect::open(&directory).unwrap();
        let runtime = directory.join("runtime-peer"); create_private_state_directory(&runtime).unwrap();
        let config = RuntimeConfig { format:"peerwork.participant-runtime.v1".into(), state_directory:runtime.clone(), hosts:vec![],
            engines:vec![EngineConfig { name:"original".into(), origin:origin.into(), expected_actor:identity.actor_id().into(),
                identity_path, state_directory:root.path().join("engine"), journal_path:None, authority:None, migration_sources:vec![],
                allow_loopback_http:true, transport:Default::default(), max_inflight:1, max_pending:2, max_stored_bytes:1024*1024 }],
            clients:vec![ClientConfig { name:"bootstrap".into(), engine:"original".into(), capability:Capability::owner() }] };
        let bytes = serde_json::to_vec(&config).unwrap(); write_private(&runtime.join("config.json"), &bytes).unwrap();
        let first = OriginalChild(Command::new(previous.unwrap_or(&binary)).args(["runtime", "run"]).arg(runtime.join("config.json"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let store = SecureStateStore::open(&runtime.join("bootstrap.state")).unwrap();
        let mut launch=json!({"config_digest":sha256_hex(&bytes),"pid":first.0.id(),
            "process_token":crate::communication_store::process_token(first.0.id())});
        if previous.is_none(){launch["launcher"]=serde_json::to_value(crate::runtime_startup::Launcher::capture(binary.clone()).unwrap()).unwrap();}
        store.write_exact(&serde_json::to_vec(&launch).unwrap()).unwrap(); drop(store);
        let registration = Registration { origin:config.engines[0].origin.clone(), actor_id:identity.actor_id().into(), endpoint_path:runtime.join("client-bootstrap.json") };
        for _ in 0..200 {
            if RuntimeClient::connect(registration.endpoint_path.clone(), &registration.origin, &registration.actor_id).await.is_ok() { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        connect.register_pinned("peer", registration.clone(), None, Some(runtime.join("admin.json"))).await.unwrap();
        let binding = connect.registry.verified_bindings["peer"].clone();
        let setup: Setup = serde_json::from_value(json!({"desired":{"setup_id":"original","participant":"peer","workspace_id":"W".repeat(43)},
            "registration":registration,"digest":"a".repeat(64),"profile":null,"result":{"state":"LOCAL_CONFIGURED"}})).unwrap();
        connect.registry.setups.insert("original".into(), setup); connect.save().unwrap();
        let project = root.path().join("project"); create_private_state_directory(&project).unwrap();
        let installed = connect.install("peer", &"W".repeat(43), Installation { host:"codex".into(), project, executable:binary.clone() }).unwrap();
        assert_eq!(installed["automatic_startup"]["state"],if previous.is_some(){"VERIFYING_RUNTIME_SUPPORT"}else{"AUTOMATIC"}); drop(connect);
        if previous.is_some(){assert!(crate::runtime_startup::read(&runtime).unwrap().is_none());}
        else{assert!(crate::runtime_startup::read(&runtime).unwrap().unwrap().launcher.is_some());}
        Self { root, binary, first, directory, config, registration, binding }
    }
    fn launch(&self) -> Value { serde_json::from_slice(&SecureStateStore::read_snapshot(&self.config.state_directory.join("bootstrap.state"),65536).unwrap()).unwrap() }
    fn crash(&mut self) {
        let pid = self.launch()["pid"].as_u64().unwrap() as u32;
        assert!(crate::communication_store::process_token(pid).is_some());
        unsafe { assert_eq!(libc::kill(pid as i32, libc::SIGKILL), 0); }
        if pid == self.first.0.id() { let _ = self.first.0.wait(); }
    }
    async fn restored(&self, previous: u64) -> Value {
        tokio::time::timeout(Duration::from_secs(30), async { loop {
            let launch = self.launch();
            if launch["pid"].as_u64().is_some_and(|pid|pid!=previous && pid!=0) {
                if let Ok(client) = RuntimeClient::connect_bound(self.registration.endpoint_path.clone(),&self.registration.origin,&self.registration.actor_id,self.binding.clone()).await {
                    let binding = client.call(json!({"method":"binding"})).await.unwrap();
                    assert_eq!(crate::communication_runtime::canonical_binding(&binding), self.binding);
                    return launch;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await.unwrap_or_else(|error|panic!("original runtime did not recover: {error}; MCP={}; runtime={}",
            std::fs::read_to_string(self.directory.join("mcp-startup-test.log")).unwrap_or_default(),
            std::fs::read_to_string(self.config.state_directory.join("runtime.log")).unwrap_or_default()))
    }
    fn stop(&self) {
        let output = Command::new(&self.binary).args(["runtime", "admin"]).arg(self.config.state_directory.join("admin.json")).arg("stop").output().unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap(); assert_eq!(value["ok"], true, "{value}");
        for _ in 0..100 {
            if SecureStateStore::open(&self.config.state_directory.join("runtime.state")).is_ok(){return;}
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("original runtime did not release its writer after stop");
    }
}
impl Drop for Fixture { fn drop(&mut self) {
    let _ = Command::new(&self.binary).args(["runtime","admin"]).arg(self.config.state_directory.join("admin.json")).arg("stop").output();
    let _ = self.first.0.kill(); let _ = self.first.0.wait();
    let _ = &self.root;
} }

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate CLI and synthetic process/loopback IPC"]
async fn mcp_startup_and_runtime_crash_restore_without_any_tool_call() {
    let mut fixture = Fixture::new().await;
    let client = RuntimeClient::connect_bound(fixture.registration.endpoint_path.clone(),&fixture.registration.origin,&fixture.registration.actor_id,fixture.binding.clone()).await.unwrap();
    let pending = client.call(json!({"method":"invoke","wait_ms":100,"request":crate::participant::Invoke::new(
        "original-pending","structure.workspace.create",Scope::default(),json!({"name":"Offline pending intent"}))})).await.unwrap();
    assert_eq!(pending["operation_id"],"original-pending");
    let first = fixture.launch()["pid"].as_u64().unwrap(); fixture.crash();
    let mcp = Mcp::new(&fixture.binary, &fixture.directory);
    let restored = fixture.restored(first).await;
    let retained = client.call(json!({"method":"operation","operation_id":"original-pending"})).await.unwrap();
    assert_eq!(retained["operation_id"],pending["operation_id"]);
    assert_eq!(retained["command_id"],pending["command_id"]);
    fixture.crash(); fixture.restored(restored["pid"].as_u64().unwrap()).await;
    fixture.stop();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!crate::runtime_startup::read(&fixture.config.state_directory).unwrap().unwrap().automatic);
    assert!(RuntimeClient::connect(fixture.registration.endpoint_path.clone(),&fixture.registration.origin,&fixture.registration.actor_id).await.is_err());
    drop(mcp);
    let _restarted = Mcp::new(&fixture.binary, &fixture.directory);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(RuntimeClient::connect(fixture.registration.endpoint_path.clone(),&fixture.registration.origin,&fixture.registration.actor_id).await.is_err());
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate CLI and synthetic process/loopback IPC"]
async fn concurrent_frontends_wait_for_maintenance_then_restore_one_original_writer() {
    let mut fixture = Fixture::new().await;
    let first = fixture.launch()["pid"].as_u64().unwrap();
    let maintenance = crate::runtime_startup::recovery_fence(&fixture.config.state_directory).unwrap();
    fixture.crash();
    let _a = Mcp::new(&fixture.binary,&fixture.directory);
    let _b = Mcp::new(&fixture.binary,&fixture.directory);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(fixture.launch()["pid"], first, "background must not race a maintenance owner");
    drop(maintenance);
    let restored = fixture.restored(first).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(fixture.launch(), restored, "frontends must share one original runtime");
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate CLI and synthetic process/loopback IPC"]
async fn surviving_frontend_restores_the_committed_launcher_instead_of_itself() {
    let mut fixture=Fixture::new().await;
    let target=fixture.root.path().join("committed-peerwork");std::fs::copy(&fixture.binary,&target).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&target,std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut policy=crate::runtime_startup::read(&fixture.config.state_directory).unwrap().unwrap();
    policy.launcher=Some(crate::runtime_startup::Launcher::capture(target.clone()).unwrap());
    let store=SecureStateStore::open(&fixture.config.state_directory.join("startup.state")).unwrap();
    store.write_exact(&serde_json::to_vec(&policy).unwrap()).unwrap();drop(store);
    let previous=fixture.launch()["pid"].as_u64().unwrap();fixture.crash();
    let _mcp=Mcp::new(&fixture.binary,&fixture.directory);
    let restored=fixture.restored(previous).await;
    assert_eq!(std::fs::read_link(format!("/proc/{}/exe",restored["pid"])).unwrap(),target);
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate CLI and synthetic process/loopback IPC"]
async fn explicit_resume_and_adopt_preserve_the_committed_launcher() {
    let mut fixture=Fixture::new().await;
    let target=fixture.root.path().join("committed-peerwork");std::fs::copy(&fixture.binary,&target).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&target,std::fs::Permissions::from_mode(0o700)).unwrap();
    let previous=fixture.launch()["pid"].as_u64().unwrap(); fixture.stop();
    let output=Command::new(&target).args(["connect","--local"]).arg(&fixture.directory)
        .args(["--participant","peer","--update","apply"]).output().unwrap();
    let updated:Value=serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(updated["runtime"],"STOPPED_PRESERVED","{updated}");
    let stopped=crate::runtime_startup::read(&fixture.config.state_directory).unwrap().unwrap();
    assert!(!stopped.automatic); assert_eq!(stopped.launcher.unwrap().executable,target);
    // The receiving fixture has no business profile. Resume must restore the
    // original runtime before profile selection, regardless of that later error.
    let _=Command::new(&fixture.binary).args(["agent","--local"]).arg(&fixture.directory)
        .args(["--participant","peer","delivery","resume"]).output().unwrap();
    let restored=fixture.restored(previous).await;
    assert_eq!(std::fs::read_link(format!("/proc/{}/exe",restored["pid"])).unwrap(),target);
    fixture.crash();
    let mut connect=Connect::open(&fixture.directory).unwrap();
    connect.adopt("peer").await.unwrap();drop(connect);
    let adopted=fixture.restored(restored["pid"].as_u64().unwrap()).await;
    assert_eq!(std::fs::read_link(format!("/proc/{}/exe",adopted["pid"])).unwrap(),target);
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate CLI and synthetic process/loopback IPC"]
async fn every_recovery_entry_resumes_the_recorded_update_before_starting() {
    for (trigger,was_running) in [("automatic",false),("resume",false),("adopt",false),("automatic",true)] {
        eprintln!("interrupted update case: {trigger}, was_running={was_running}");
        let mut fixture=Fixture::new().await;
        let target=fixture.root.path().join("updated-peerwork");std::fs::copy(&fixture.binary,&target).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target,std::fs::Permissions::from_mode(0o700)).unwrap();
        let previous=fixture.launch()["pid"].as_u64().unwrap();
        if trigger=="resume" {fixture.stop();}else{fixture.crash();}
        let original=bootstrap::owned_runtime(&Connect::inspect(&fixture.directory).unwrap(),"peer").unwrap();
        let update=json!({"format":"peerwork.owned-update.v1","participant":"peer","registration":original.registration,
            "executable":target,"executable_digest":crate::runtime_startup::Launcher::capture(target.clone()).unwrap().sha256,
            "required_features":["host-observation-upload-deadline-v1","current-host-delivery-health-v1","automatic-runtime-startup-v1"],
            "original":original,"was_running":was_running,"phase":"RUNTIME_READY"});
        let path=fixture.directory.join("update-peer.state");let store=SecureStateStore::open(&path).unwrap();
        store.write_exact(&serde_json::to_vec(&update).unwrap()).unwrap();drop(store);
        let _mcp=match trigger {
            "automatic"=>Some(Mcp::new(&fixture.binary,&fixture.directory)),
            "resume"=>{let _=Command::new(&fixture.binary).args(["agent","--local"]).arg(&fixture.directory)
                .args(["--participant","peer","delivery","resume"]).output().unwrap();None},
            "adopt"=>{let mut connect=Connect::open(&fixture.directory).unwrap();connect.adopt("peer").await.unwrap();None},
            _=>unreachable!(),
        };
        let restored=fixture.restored(previous).await;
        assert_eq!(std::fs::read_link(format!("/proc/{}/exe",restored["pid"])).unwrap(),target,"{trigger}");
        // A child becoming live precedes the updater's target/installation
        // commit. Observe the operation itself rather than conflating them.
        tokio::time::timeout(Duration::from_secs(30),async {loop {
            let completed:Value=serde_json::from_slice(&SecureStateStore::read_snapshot(&path,2*1024*1024).unwrap()).unwrap();
            if completed["phase"]=="COMPLETE"{break;}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }}).await.expect("original update did not commit after runtime readiness");
        assert_eq!(crate::runtime_startup::read(&fixture.config.state_directory).unwrap().unwrap().launcher.unwrap().executable,target);
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate/previous CLI artifacts and synthetic process/loopback IPC"]
async fn unsupported_legacy_stop_is_not_converted_to_automatic_start_on_update() {
    let previous=PathBuf::from(std::env::var_os("PEERWORK_UPDATE_PREVIOUS_BINARY").expect("set previous CLI"));
    let fixture=Fixture::initial("http://127.0.0.1:1",Some(&previous)).await;
    let pid=fixture.launch()["pid"].as_u64().unwrap();
    let result=Command::new(&previous).args(["runtime","admin"]).arg(fixture.config.state_directory.join("admin.json"))
        .arg("stop").output().unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout).unwrap()["ok"],true);
    tokio::time::timeout(Duration::from_secs(10),async {loop {
        if SecureStateStore::open(&fixture.config.state_directory.join("runtime.state")).is_ok(){break;}
        tokio::time::sleep(Duration::from_millis(25)).await;
    }}).await.unwrap();
    assert!(crate::runtime_startup::read(&fixture.config.state_directory).unwrap().is_none());
    let result=Command::new(&fixture.binary).args(["connect","--local"]).arg(&fixture.directory)
        .args(["--participant","peer","--update","apply"]).output().unwrap();
    let result:Value=serde_json::from_slice(&result.stdout).unwrap();assert_eq!(result["runtime"],"STOPPED_PRESERVED","{result}");
    let _mcp=Mcp::new(&fixture.binary,&fixture.directory);tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!crate::runtime_startup::read(&fixture.config.state_directory).unwrap().unwrap().automatic);
    assert_eq!(fixture.launch()["pid"],pid);
    assert!(RuntimeClient::connect(fixture.registration.endpoint_path.clone(),&fixture.registration.origin,&fixture.registration.actor_id).await.is_err());
}

#[tokio::test(flavor="multi_thread",worker_threads=3)]
#[ignore="requires exact candidate CLI and selected local TEST PostgreSQL/product fixture"]
async fn restarted_installation_automatically_notifies_a_fresh_encrypted_message() {
    use crate::{participant::{ParticipantClient, Invoke, Scope}, agent_tools::{AgentProfile, AgentTools, AgentRequest},
        participant::http_tests::{Service, configuration, mutate, selected, install_synthetic_key, structure}, communication_host::tests::CodexFixture};
    let service = Service::start();
    let root = crate::test_support::protected_test_dir();
    let owner_config = configuration(root.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let mut fixture = Fixture::at(&service.origin).await;
    let workspace = mutate(&owner,"startup-space","structure.workspace.create",&Scope::default(),json!({"name":"Startup qualification"})).await["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope { workspace_id:Some(workspace.clone()), ..Default::default() };
    let meta = selected(&owner,"structure.workspace.get",&scope,json!({})).await;
    let mut join = Invoke::new("startup-join","structure.member.set",scope.clone(),json!({"actor_id":fixture.registration.actor_id,"state":"ACTIVE","expected_membership_id":null}));
    join.expected_workspace_revision = meta["workspace_revision"].as_u64(); structure(&owner.invoke(join,Duration::from_secs(5)).await.unwrap());
    let key = install_synthetic_key(&owner_config,&workspace,&[73;32],None);
    install_synthetic_key(&fixture.config.engines[0].participant_config(),&workspace,&[73;32],None);
    mutate(&owner,"startup-key","structure.content-key.set",&scope,json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null})).await;
    let client = RuntimeClient::connect_bound(fixture.registration.endpoint_path.clone(),&fixture.registration.origin,&fixture.registration.actor_id,fixture.binding.clone()).await.unwrap();
    let mailbox = client.call(json!({"method":"request","request":Invoke::new("startup-mailbox","structure.mailboxes.read",scope.clone(),json!({"limit":8}))})).await.unwrap()["result"]["structure"]["mailboxes"][0].clone();
    assert!(mailbox["mailbox_id"].is_string());
    let host = CodexFixture::start();
    let watch = json!({"workspace_id":workspace,"mailbox_id":mailbox["mailbox_id"],"membership_id":mailbox["membership_id"],"consumer_id":"startup-notify","host_destination":null});
    // Configure the synthetic original host while stopped, before MCP exists.
    let original = bootstrap::owned_runtime(&Connect::inspect(&fixture.directory).unwrap(),"peer").unwrap();
    original.stop().await.unwrap();
    fixture.config.hosts = vec![serde_json::from_value(json!({"name":"original-host","adapter":host.config(),"subscriptions":[{"client":"bootstrap","watch":watch}]})).unwrap()];
    let bytes = serde_json::to_vec(&fixture.config).unwrap();
    crate::onboarding_files::replace(&fixture.config.state_directory.join("config.json"),&bytes).unwrap();
    let launch = SecureStateStore::open(&fixture.config.state_directory.join("bootstrap.state")).unwrap();
    launch.write_exact(&serde_json::to_vec(&json!({"config_digest":sha256_hex(&bytes),"pid":0,"process_token":null})).unwrap()).unwrap(); drop(launch);
    service.config(json!({"resident_worker":true})).await;
    let _mcp = Mcp::new(&fixture.binary,&fixture.directory);
    fixture.restored(0).await;
    let profile: AgentProfile = serde_json::from_value(json!({"format":"peerwork.agent-profile.v1","endpoint_path":fixture.registration.endpoint_path,
        "expected_origin":fixture.registration.origin,"expected_actor":fixture.registration.actor_id,
        "workspaces":{"team":workspace},"scopes":{"team":{"workspace_id":workspace,"mailbox_id":mailbox["mailbox_id"],"membership_id":mailbox["membership_id"]}}})).unwrap();
    let tools = AgentTools::open(profile).await.unwrap();
    fn batches(host: &CodexFixture) -> Vec<String> {
        host.calls().iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).filter_map(|v| {
            let text=v["params"]["input"][0]["text"].as_str()?;let start=text.find("{\"batch\"")?;
            let end=text[start..].find('}')?+start;
            serde_json::from_str::<Value>(&text[start..=end]).ok()?["batch"].as_str().map(str::to_owned)
        }).collect()
    }
    // No tool call or model action preceded the first automatic host input.
    let first = tokio::time::timeout(Duration::from_secs(25),async {loop{
        if let Some(batch)=batches(&host).first(){break batch.clone();}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.expect("MCP startup did not produce automatic host notification");
    tools.call(AgentRequest::parse("inbox",json!({"batch":first})).unwrap()).await.unwrap();
    let before = fixture.launch()["pid"].as_u64().unwrap(); fixture.crash(); fixture.restored(before).await;
    let before = batches(&host).len();
    let room = peerwork_core::communication::space_conversation_id(&workspace).unwrap();
    let mut post=Invoke::new("startup-fresh-message","structure.conversation.post",scope.clone(),json!({"conversation_id":room,"audience":"SPACE_MEMBERS","thread_root":null,"reply_to":null,"context":null,"mentions":[fixture.registration.actor_id],"content":{"mode":"WORKSPACE_E2EE"}}));
    post.plaintext_message=Some("AUTOMATIC-RESTART-RECEIVED".into()); structure(&owner.invoke(post,Duration::from_secs(5)).await.unwrap());
    tokio::time::timeout(Duration::from_secs(30),async {let mut seen=before;loop{
        for batch in batches(&host).into_iter().skip(seen) {
            seen+=1;
            let page=tools.call(AgentRequest::parse("inbox",json!({"batch":batch})).unwrap()).await.unwrap();
            if page["items"].as_array().into_iter().flatten().any(|v|v["message"]["text"]=="AUTOMATIC-RESTART-RECEIVED") {return;}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.expect("fresh encrypted message was not automatically notified after runtime-only crash");
    owner.close().await.unwrap();
}
