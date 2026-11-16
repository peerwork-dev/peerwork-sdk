//! Real CLI children, synthetic identity/state, no remote workspace or model.
use super::*;
use crate::{communication_runtime::{ClientConfig, EngineConfig, RuntimeConfig}, kernel_identity::KernelIdentity};
use std::{process::{Child, Command, Stdio}, io::{BufRead, BufReader, Write}, time::Duration};

struct Mcp(Child);
impl Mcp {
    fn new(binary: &Path, registry: &Path) -> Self {
        let mut child = Command::new(binary).args(["agent", "--local"]).arg(registry)
            .args(["--participant", "peer", "mcp"]).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::null()).spawn().unwrap();
        writeln!(child.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"startup-test","version":"1"}}})).unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 1);
        Self(child)
    }
}
impl Drop for Mcp { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

struct Fixture {
    root: crate::test_support::ProtectedTestDir,
    binary: PathBuf,
    first: Child,
    directory: PathBuf,
    config: RuntimeConfig,
    registration: Registration,
    binding: Value,
}
impl Fixture {
    async fn new() -> Self {
        let binary = PathBuf::from(std::env::var_os("PEERWORK_UPDATE_TEST_BINARY").expect("set exact candidate CLI"));
        let root = crate::test_support::protected_test_dir();
        let identity_path = root.path().join("identity");
        let identity = KernelIdentity::create(&identity_path).unwrap();
        let directory = root.path().join("registry");
        let mut connect = Connect::open(&directory).unwrap();
        let runtime = directory.join("runtime-peer"); create_private_state_directory(&runtime).unwrap();
        let config = RuntimeConfig { format:"peerwork.participant-runtime.v1".into(), state_directory:runtime.clone(), hosts:vec![],
            engines:vec![EngineConfig { name:"original".into(), origin:"http://127.0.0.1:1".into(), expected_actor:identity.actor_id().into(),
                identity_path, state_directory:root.path().join("engine"), journal_path:None, authority:None, migration_sources:vec![],
                allow_loopback_http:true, transport:Default::default(), max_inflight:1, max_pending:2, max_stored_bytes:1024*1024 }],
            clients:vec![ClientConfig { name:"bootstrap".into(), engine:"original".into(), capability:Capability::owner() }] };
        let bytes = serde_json::to_vec(&config).unwrap(); write_private(&runtime.join("config.json"), &bytes).unwrap();
        let first = Command::new(&binary).args(["runtime", "run"]).arg(runtime.join("config.json"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let store = SecureStateStore::open(&runtime.join("bootstrap.state")).unwrap();
        store.write_exact(&serde_json::to_vec(&json!({"config_digest":sha256_hex(&bytes),"pid":first.id(),
            "process_token":crate::communication_store::process_token(first.id())})).unwrap()).unwrap(); drop(store);
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
        assert_eq!(installed["automatic_startup"]["state"], "AUTOMATIC"); drop(connect);
        for _ in 0..200 {
            if crate::runtime_startup::read(&runtime).unwrap().is_some_and(|p|p.qualified) { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(crate::runtime_startup::read(&runtime).unwrap().unwrap().qualified);
        Self { root, binary, first, directory, config, registration, binding }
    }
    fn launch(&self) -> Value { serde_json::from_slice(&SecureStateStore::read_snapshot(&self.config.state_directory.join("bootstrap.state"),65536).unwrap()).unwrap() }
    fn crash(&mut self) {
        let pid = self.launch()["pid"].as_u64().unwrap() as u32;
        assert!(crate::communication_store::process_token(pid).is_some());
        unsafe { assert_eq!(libc::kill(pid as i32, libc::SIGKILL), 0); }
        if pid == self.first.id() { let _ = self.first.wait(); }
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
        }}).await.expect("normal MCP startup did not restore original runtime")
    }
    fn stop(&self) {
        let output = Command::new(&self.binary).args(["runtime", "admin"]).arg(self.config.state_directory.join("admin.json")).arg("stop").output().unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap(); assert_eq!(value["ok"], true, "{value}");
    }
}
impl Drop for Fixture { fn drop(&mut self) {
    let _ = Command::new(&self.binary).args(["runtime","admin"]).arg(self.config.state_directory.join("admin.json")).arg("stop").output();
    let _ = self.first.wait();
    let _ = &self.root;
} }

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires exact candidate CLI and synthetic process/loopback IPC"]
async fn mcp_startup_and_runtime_crash_restore_without_any_tool_call() {
    let mut fixture = Fixture::new().await;
    let first = fixture.launch()["pid"].as_u64().unwrap(); fixture.crash();
    let mcp = Mcp::new(&fixture.binary, &fixture.directory);
    let restored = fixture.restored(first).await;
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
