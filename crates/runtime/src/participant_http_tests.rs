//! Real service acceptance. Run only with an explicit synthetic PostgreSQL URL,
//! product root and Node fixture executable; these are test dependencies only.
use super::*;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
};

pub(crate) struct Service {
    child: Child,
    pub(crate) origin: String,
    bootstrap: Value,
}
impl Service {
    pub(crate) fn start() -> Self {
        Self::fixture("participant-service.mjs")
    }
    fn fixture(name: &str) -> Self {
        let node = std::env::var("PEERWORK_TEST_NODE").expect("explicit Node fixture executable");
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests")
            .join(name);
        let mut child = Command::new(node)
            .arg(fixture)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => line,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fixture startup: {error}");
            }
        };
        reader.join().unwrap();
        let bootstrap = serde_json::from_str::<Value>(&line).expect("fixture endpoint");
        let origin = bootstrap["origin"].as_str().unwrap().to_owned();
        Self {
            child,
            origin,
            bootstrap,
        }
    }
    async fn config(&self, value: Value) {
        reqwest::Client::new()
            .post(format!("{}/__test/config", self.origin))
            .body(value.to_string())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    pub(crate) async fn counts(&self) -> Value {
        let text = reqwest::get(format!("{}/__test/counts", self.origin))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        serde_json::from_str(&text).unwrap()
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        for _ in 0..250 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
pub(crate) fn configuration(directory: &std::path::Path, origin: &str) -> ParticipantConfig {
    let path = directory.join("identity");
    let identity = KernelIdentity::create(&path).unwrap();
    let mut config =
        ParticipantConfig::new(origin, identity.actor_id(), path, directory.join("engine"));
    config.allow_loopback_http = true;
    config.transport.request_timeout_ms = 1000;
    config
}
async fn wait_terminal(client: &ParticipantClient, id: &str) -> Operation {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let op = client.operation(id).await.unwrap();
            if op.is_terminal() {
                return op;
            }
            assert_ne!(
                op.state,
                "BLOCKED",
                "{}",
                serde_json::to_string(&op).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("operation did not become terminal")
}
pub(crate) fn structure(op: &Operation) -> Value {
    assert_eq!(
        op.state,
        "ACCEPTED",
        "{}",
        serde_json::to_string(op).unwrap()
    );
    op.outcome.as_ref().unwrap()["result"]["structure"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real archived-space HTTP fixture"]
async fn program_archive_migration_uses_bound_source_and_resumes_lost_admission() {
    let service = Service::fixture("participant-migration-service.mjs");
    let temp = crate::test_support::protected_test_dir();
    let data = &service.bootstrap;
    let mut config = ParticipantConfig::new(
        &service.origin,
        data["actor_id"].as_str().unwrap(),
        data["identity_path"].as_str().unwrap(),
        temp.path().join("engine"),
    );
    config.authority = Some(data["authority"].as_str().unwrap().into());
    config.allow_loopback_http = true;
    config.transport.request_timeout_ms = 1000;
    let source = MigrationSource::Checkpoint {
        workspace_id: data["workspace_id"].as_str().unwrap().into(),
        path: PathBuf::from(data["checkpoint_path"].as_str().unwrap()),
        sha256: data["checkpoint_sha256"].as_str().unwrap().into(),
    };
    config.migration_sources.push(source.clone());
    let bad_hash = MigrationSource::Checkpoint {
        workspace_id: source.workspace_id().into(),
        path: PathBuf::from(data["checkpoint_path"].as_str().unwrap()),
        sha256: "0".repeat(64),
    };
    config.migration_sources.push(bad_hash.clone());
    let scope = Scope {
        workspace_id: Some(source.workspace_id().into()),
        ..Default::default()
    };
    let client = ParticipantClient::open(config.clone()).await.unwrap();
    let sources = client
        .request(Invoke::new(
            "sources",
            "participant.archive.sources",
            scope.clone(),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(
        sources["sources"][0]["source_id"],
        source.source_id().unwrap()
    );
    assert!(sources["sources"][0].get("path").is_none());
    let missing = Invoke::new(
        "bad-source",
        "participant.archive.migrate",
        scope.clone(),
        json!({"source_id":"0".repeat(64)}),
    );
    assert_eq!(
        client
            .invoke(missing, Duration::ZERO)
            .await
            .unwrap_err()
            .code,
        "MIGRATION_SOURCE_NOT_CONFIGURED"
    );
    assert_eq!(
        client.operation("bad-source").await.unwrap_err().code,
        "OPERATION_NOT_FOUND"
    );
    let wrong = client
        .invoke(
            Invoke::new(
                "wrong-checkpoint-hash",
                "participant.archive.migrate",
                scope.clone(),
                json!({"source_id":bad_hash.source_id().unwrap()}),
            ),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(wrong.state, "BLOCKED");
    assert_eq!(
        wrong.outcome.as_ref().unwrap()["server_code"],
        "MIGRATION_ARTIFACT_CHANGED"
    );
    assert_eq!(service.counts().await["jobs"], 0);
    let migration = Invoke::new(
        "migrate",
        "participant.archive.migrate",
        scope.clone(),
        json!({"source_id":source.source_id().unwrap()}),
    );
    service.config(json!({"drop_admission":true})).await;
    let unresolved = client
        .invoke(migration.clone(), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(!unresolved.is_terminal());
    assert_eq!(service.counts().await["dropped"], 1);
    // An admitted migration cannot occupy the ordinary event/read executor.
    let local = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(Invoke::new(
            "source-while-migrating",
            "participant.archive.sources",
            scope.clone(),
            json!({}),
        )),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(local["state"], "LOCAL_CONFIGURATION");
    client.close().await.unwrap();
    service
        .config(json!({"offline":false,"paused":false}))
        .await;
    let mut recovered_config = config.clone();
    recovered_config.migration_sources.clear();
    let client = ParticipantClient::open(recovered_config).await.unwrap();
    let done = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let op = client.operation("migrate").await.unwrap();
            if op.is_terminal() {
                break op;
            }
            assert_ne!(
                op.state,
                "BLOCKED",
                "{}",
                serde_json::to_string(&op).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(done.state, "ACCEPTED");
    assert_eq!(structure(&done)["migration"]["state"], "COMPLETE");
    if let Some(original) = unresolved.command_id {
        assert_eq!(done.command_id.as_deref(), Some(original.as_str()));
    }
    assert_eq!(service.counts().await["jobs"], 1);
    service.config(json!({"remove_checkpoint":true})).await;
    assert_eq!(
        client
            .invoke(migration, Duration::from_secs(1))
            .await
            .unwrap()
            .command_id,
        done.command_id
    );
    let records = client
        .request(Invoke::new(
            "after-conversion",
            "structure.records.read",
            Scope {
                workspace_id: scope.workspace_id.clone(),
                instance_id: Some(data["instance_id"].as_str().unwrap().into()),
                protocol_digest: Some(data["protocol_digest"].as_str().unwrap().into()),
            },
            json!({"limit":32}),
        ))
        .await
        .unwrap();
    assert_eq!(
        records["result"]["structure"]["records"]
            .as_array()
            .unwrap()
            .len(),
        17
    );
    client.close().await.unwrap();
    let mut changed = config;
    changed.authority = Some("f".repeat(64));
    assert_eq!(
        ParticipantClient::open(changed).await.err().unwrap().code,
        "STATE_BINDING_MISMATCH"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn program_root_http_async_scope_and_exact_operation_restart() {
    let service = Service::start();
    let temp = crate::test_support::protected_test_dir();
    let config = configuration(temp.path(), &service.origin);
    let client = ParticipantClient::open(config.clone()).await.unwrap();
    let created = client
        .invoke(
            Invoke::new(
                "create",
                "structure.workspace.create",
                Scope::default(),
                json!({"name":"Program-owned synthetic workspace"}),
            ),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let created = if created.is_terminal() {
        created
    } else {
        wait_terminal(&client, "create").await
    };
    let workspace = structure(&created)["workspace_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scope = Scope {
        workspace_id: Some(workspace.clone()),
        ..Default::default()
    };
    let get = Invoke::new("get", "structure.workspace.get", scope.clone(), json!({}));
    assert_eq!(
        client.request(get.clone()).await.unwrap()["result"]["structure"]["workspace_id"],
        workspace
    );
    // A warm selected read uses the shared pool and anchor: exactly one HTTP
    // request, independent of retained history or number of logical clients.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let before = service.counts().await;
    client.request(get).await.unwrap();
    let after = service.counts().await;
    assert_eq!(
        after["commands"].as_u64().unwrap() - before["commands"].as_u64().unwrap(),
        1
    );
    assert_eq!(after["discovery"], before["discovery"]);
    assert_eq!(after["context"], before["context"]);
    let worker = client
        .restrict(
            "reader",
            Capability {
                operations: ["structure.workspace.get".into()].into(),
                allow_root: false,
                workspace_ids: Some([workspace.clone()].into()),
                instance_ids: None,
                protocol_digests: None,
                business_actions: None,
                mailbox_ids: None,
            },
        )
        .unwrap();
    assert_eq!(
        worker
            .request(Invoke::new(
                "wrong",
                "structure.workspace.get",
                Scope {
                    workspace_id: Some("wrong-workspace".into()),
                    ..Default::default()
                },
                json!({})
            ))
            .await
            .unwrap_err()
            .code,
        "LOCAL_SCOPE_DENIED"
    );
    assert_eq!(worker.close().await.unwrap_err().code, "ADMIN_REQUIRED");
    // Slow remote work occupies a real slot, while independent work continues.
    service
        .config(json!({"delay_name":"Slow independent create"}))
        .await;
    let slow = client
        .invoke(
            Invoke::new(
                "slow",
                "structure.workspace.create",
                Scope::default(),
                json!({"name":"Slow independent create"}),
            ),
            Duration::ZERO,
        )
        .await
        .unwrap();
    assert!(!slow.is_terminal());
    let ready = client
        .invoke(
            Invoke::new(
                "ready",
                "structure.workspace.create",
                Scope::default(),
                json!({"name":"Ready independent create"}),
            ),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(ready.state, "ACCEPTED");
    service.config(json!({"release":true})).await;
    wait_terminal(&client, "slow").await;
    // Lost acceptance response: close and reopen the same owner, recover only
    // the original operation, and prove exactly one new remote workspace.
    let initial = service.counts().await;
    service
        .config(json!({"drop_action":"structure.workspace.create"}))
        .await;
    let lost = client
        .invoke(
            Invoke::new(
                "lost",
                "structure.workspace.create",
                Scope::default(),
                json!({"name":"Committed response lost"}),
            ),
            Duration::from_millis(200),
        )
        .await
        .unwrap();
    assert!(!lost.is_terminal());
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.counts().await["dropped"] != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    client.close().await.unwrap();
    service.config(json!({"offline":false})).await;
    let client = ParticipantClient::open(config).await.unwrap();
    let recovered = wait_terminal(&client, "lost").await;
    assert_eq!(
        client.recover("lost").await.unwrap().command_id,
        recovered.command_id
    );
    let final_counts = service.counts().await;
    assert_eq!(
        final_counts["workspaces"].as_u64().unwrap(),
        initial["workspaces"].as_u64().unwrap() + 1
    );
    assert_eq!(
        final_counts["unique_commands"].as_u64().unwrap(),
        initial["unique_commands"].as_u64().unwrap() + 1
    );
    assert_eq!(final_counts["journal_reads"], 0);
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn resident_runtime_keeps_durable_work_after_caller_disconnect_and_multiplexes_frames() {
    use crate::communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpStream,
    };
    let service = Service::start();
    let temp = crate::test_support::protected_test_dir();
    let engine = configuration(temp.path(), &service.origin);
    let options = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        hosts: Vec::new(),
        state_directory: temp.path().join("runtime"),
        engines: vec![EngineConfig {
            authority: None,
            migration_sources: Vec::new(),
            name: "program".into(),
            origin: engine.origin,
            expected_actor: engine.expected_actor,
            identity_path: engine.identity_path,
            state_directory: engine.state_directory,
            journal_path: None,
            allow_loopback_http: true,
            transport: engine.transport,
            max_inflight: 4,
            max_pending: 8,
            max_stored_bytes: 4 * 1024 * 1024,
        }],
        clients: vec![ClientConfig {
            name: "master".into(),
            engine: "program".into(),
            capability: Capability::owner(),
        }],
    };
    let stop = KernelCancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(ipc::serve(options, stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let path = &ready.client_endpoints["master"];
    let endpoint = crate::communication_store::private_json(path, 4096).unwrap();
    let mut stream = tokio::io::BufReader::new(
        TcpStream::connect(endpoint["address"].as_str().unwrap())
            .await
            .unwrap(),
    );
    let auth = ipc::client_handshake(&mut stream, endpoint["token"].as_str().unwrap())
        .await
        .unwrap();
    service
        .config(json!({"delay_name":"Disconnected caller"}))
        .await;
    let request = Invoke::new(
        "disconnect",
        "structure.workspace.create",
        Scope::default(),
        json!({"name":"Disconnected caller"}),
    );
    let (encoded, _) = ipc::encode_request(
        &auth,
        "lost-caller",
        json!({"method":"invoke","request":request,"wait_ms":3000}),
    )
    .unwrap();
    stream
        .get_mut()
        .write_all((encoded.to_string() + "\n").as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.counts().await["commands"].as_u64().unwrap() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(stream);
    service.config(json!({"release":true})).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let saved = ipc::call(
                path,
                json!({"method":"operation","operation_id":"disconnect"}),
            )
            .await
            .unwrap();
            if saved["value"]["state"] == "ACCEPTED" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Keep a partial second frame buffered while the first call completes;
    // then finish it on the same connection. No prefix may be lost.
    service
        .config(json!({"delay_name":"Multiplexed first call"}))
        .await;
    let mut stream = tokio::io::BufReader::new(
        TcpStream::connect(endpoint["address"].as_str().unwrap())
            .await
            .unwrap(),
    );
    let auth = ipc::client_handshake(&mut stream, endpoint["token"].as_str().unwrap())
        .await
        .unwrap();
    let (read, mut write) = stream.into_inner().into_split();
    let mut read = BufReader::new(read);
    let request = Invoke::new(
        "multiplex",
        "structure.workspace.create",
        Scope::default(),
        json!({"name":"Multiplexed first call"}),
    );
    let (first, first_wire) = ipc::encode_request(
        &auth,
        "first",
        json!({"method":"invoke","request":request,"wait_ms":3000}),
    )
    .unwrap();
    let (second, second_wire) =
        ipc::encode_request(&auth, "second", json!({"method":"capabilities"})).unwrap();
    let first = first.to_string() + "\n";
    let second = second.to_string() + "\n";
    write.write_all(first.as_bytes()).await.unwrap();
    write.write_all(&second.as_bytes()[..20]).await.unwrap();
    service.config(json!({"release":true})).await;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), read.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ipc::decode_response(&auth, "first", &first_wire, line.as_bytes()).unwrap()["request_id"],
        "first"
    );
    write.write_all(&second.as_bytes()[20..]).await.unwrap();
    line.clear();
    tokio::time::timeout(Duration::from_secs(5), read.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let second = ipc::decode_response(&auth, "second", &second_wire, line.as_bytes()).unwrap();
    assert_eq!(second["request_id"], "second");
    assert_eq!(second["ok"], true);
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(service.counts().await["workspaces"], 3);
}

struct RuntimeProcess {
    child: Child,
    ready: crate::communication_runtime::RuntimeReady,
    _stdout: BufReader<std::process::ChildStdout>,
}
impl RuntimeProcess {
    fn start(config_path: &std::path::Path) -> Self {
        let binary =
            std::env::var("PEERWORK_PARTICIPANT_CLI").expect("explicit freshly built native CLI");
        let mut child = Command::new(binary)
            .args(["runtime", "run"])
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let mut stdout = BufReader::new(stdout);
            let _ = stdout.read_line(&mut line);
            let _ = tx.send((line, stdout));
        });
        let (line, stdout) = match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("runtime startup: {error}");
            }
        };
        reader.join().unwrap();
        let ready = serde_json::from_str(&line).expect("native runtime ready frame");
        Self {
            child,
            ready,
            _stdout: stdout,
        }
    }
    fn kill(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.child.wait().unwrap().success());
    }
}
impl Drop for RuntimeProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires freshly built CLI, synthetic PostgreSQL and real product HTTP fixture"]
async fn killed_native_runtime_reconciles_committed_packet_without_duplicate_effect() {
    use crate::communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig};
    let service = Service::start();
    let temp = crate::test_support::protected_test_dir();
    let engine = configuration(temp.path(), &service.origin);
    let options = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        hosts: Vec::new(),
        state_directory: temp.path().join("runtime"),
        engines: vec![EngineConfig {
            authority: None,
            migration_sources: Vec::new(),
            name: "program".into(),
            origin: engine.origin,
            expected_actor: engine.expected_actor,
            identity_path: engine.identity_path,
            state_directory: engine.state_directory,
            journal_path: None,
            allow_loopback_http: true,
            transport: engine.transport,
            max_inflight: 2,
            max_pending: 4,
            max_stored_bytes: 2 * 1024 * 1024,
        }],
        clients: vec![ClientConfig {
            name: "master".into(),
            engine: "program".into(),
            capability: Capability::owner(),
        }],
    };
    let config_path = temp.path().join("runtime.json");
    crate::communication_host::write_private(&config_path, &serde_json::to_vec(&options).unwrap())
        .unwrap();
    let mut process = RuntimeProcess::start(&config_path);
    let path = &process.ready.client_endpoints["master"];
    service
        .config(json!({"drop_action":"structure.workspace.create"}))
        .await;
    let request = Invoke::new(
        "kill-window",
        "structure.workspace.create",
        Scope::default(),
        json!({"name":"Durable across SIGKILL"}),
    );
    let initial = ipc::call(
        path,
        json!({"method":"invoke","request":request,"wait_ms":0}),
    )
    .await
    .unwrap();
    assert_eq!(initial["value"]["operation_id"], "kill-window");
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.counts().await["dropped"] != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    process.kill();
    service.config(json!({"offline":false})).await;
    let mut process = RuntimeProcess::start(&config_path);
    let path = &process.ready.client_endpoints["master"];
    let done = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let op = ipc::call(
                path,
                json!({"method":"operation","operation_id":"kill-window"}),
            )
            .await
            .unwrap();
            if op["value"]["state"] == "ACCEPTED" {
                break op;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(done["value"]["effect_certainty"], "COMMITTED");
    let counts = service.counts().await;
    assert_eq!(counts["workspaces"], 2);
    assert_eq!(counts["unique_commands"], 1);
    assert_eq!(counts["journal_reads"], 0);
    assert_eq!(
        ipc::call(&process.ready.admin_endpoint, json!({"method":"stop"}))
            .await
            .unwrap()["ok"],
        true
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = process.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

fn test_receiver(label: &str) -> String {
    peerwork_core::communication::receiver_id(&peerwork_core::crypto::sha256(label.as_bytes()))
}
async fn test_claim_proof(client: &ParticipantClient, scope: &Scope, body: &mut Value) {
    let label = ["R", "F"]
        .into_iter()
        .find(|label| body["receiver_id"] == test_receiver(label))
        .expect("synthetic receiver key");
    let bytes = reqwest::get(format!(
        "{}/api/workspace/v1/discovery",
        client.origin().trim_end_matches('/')
    ))
    .await
    .unwrap()
    .bytes()
    .await
    .unwrap();
    let discovery = peerwork_core::discovery::parse_discovery_wire(&bytes, 65536).unwrap();
    let audience = String::from_utf16(discovery.audience_utf16()).unwrap();
    if body.get("claim_command_id").is_none() {
        use rand_core::RngCore;
        let mut bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        body["claim_command_id"] = json!(peerwork_core::crypto::base64url(&bytes));
    }
    body["continuity_proof"] = json!(peerwork_core::communication::receiver_claim_proof(
        &peerwork_core::crypto::sha256(label.as_bytes()),
        &audience,
        client.actor_id(),
        scope.workspace_id.as_deref().unwrap(),
        body
    )
    .unwrap());
}

pub(crate) async fn mutate(
    client: &ParticipantClient,
    id: &str,
    action: &str,
    scope: &Scope,
    mut body: Value,
) -> Value {
    if action == "structure.mailbox.claim" {
        test_claim_proof(client, scope, &mut body).await;
    }
    let op = client
        .invoke(
            Invoke::new(id, action, scope.clone(), body),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    structure(&if op.is_terminal() {
        op
    } else {
        wait_terminal(client, id).await
    })
}
pub(crate) async fn selected(
    client: &ParticipantClient,
    action: &str,
    scope: &Scope,
    body: Value,
) -> Value {
    let value = client
        .request(Invoke::new("selection", action, scope.clone(), body))
        .await
        .unwrap();
    assert_eq!(value["state"], "ACCEPTED", "{action}: {value}");
    value["result"]["structure"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn program_management_key_handoff_publication_and_offline_result() {
    let service = Service::start();
    let a = crate::test_support::protected_test_dir();
    let b = crate::test_support::protected_test_dir();
    let config = configuration(a.path(), &service.origin);
    let mut owner = ParticipantClient::open(config.clone()).await.unwrap();
    let worker = ParticipantClient::open(configuration(b.path(), &service.origin))
        .await
        .unwrap();
    service.config(json!({"offline":true})).await;
    let initialized = owner
        .request(Invoke::new(
            "local-only",
            "participant.keys.initialize",
            Scope {
                workspace_id: Some("L".repeat(43)),
                ..Default::default()
            },
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(initialized["effect_certainty"], "LOCAL_ONLY");
    service.config(json!({"offline":false})).await;
    let created = mutate(
        &owner,
        "managed-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Managed program space"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    mutate(
        &owner,
        "rotate",
        "participant.keys.rotate",
        &scope,
        json!({}),
    )
    .await;
    let metadata = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let key = metadata["content_key_head"]["key_id"].clone();
    let requested = worker
        .request(Invoke::new(
            "access",
            "participant.access.request",
            scope.clone(),
            json!({"label":"Synthetic program Worker"}),
        ))
        .await
        .unwrap();
    assert_eq!(requested["state"], "AWAITING_OWNER_APPROVAL");
    let approve = Invoke::new(
        "approve",
        "participant.access.approve",
        scope.clone(),
        json!({"request_jws":requested["request_jws"],"follow_current_key":true}),
    );
    service
        .config(json!({"drop_action":"structure.access.authorize"}))
        .await;
    let uncertain = owner
        .invoke(approve.clone(), Duration::from_secs(1))
        .await
        .unwrap();
    assert!(!uncertain.is_terminal());
    assert_eq!(service.counts().await["dropped"], 1);
    owner.close().await.unwrap();
    service.config(json!({"offline":false})).await;
    owner = ParticipantClient::open(config.clone()).await.unwrap();
    let approved = wait_terminal(&owner, "approve").await;
    if let Some(command) = uncertain.command_id {
        assert_eq!(approved.command_id.as_deref(), Some(command.as_str()));
    }
    assert_eq!(
        approved.state,
        "ACCEPTED",
        "{}",
        serde_json::to_string(&approved).unwrap()
    );
    assert_eq!(
        owner
            .invoke(approve, Duration::from_secs(1))
            .await
            .unwrap()
            .command_id,
        approved.command_id
    );
    let imported = worker
        .request(Invoke::new(
            "import",
            "participant.keys.accept",
            scope.clone(),
            json!({"owner_id":owner.actor_id(),"key_ids":[key],"current_key_id":key}),
        ))
        .await
        .unwrap();
    assert_eq!(imported["state"], "IMPORTED");
    mutate(
        &owner,
        "coordinate",
        "participant.keys.coordinate",
        &scope,
        json!({}),
    )
    .await;
    let manifest = json!({"name":"managed-notes","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{},
        "record_schemas":{"note":{"type":"object","fields":{"text":"string"},"required":["text"],"max_bytes":128}},
        "actions":[{"id":"post","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":(0..3).map(|_|json!({"op":"append","schema":"note","value":{"from":"literal","value":{"text":"readable structure"}},"relations":[]})).collect::<Vec<_>>()}]}]});
    let adopted = mutate(
        &owner,
        "notes",
        "structure.adopt",
        &scope,
        json!({"manifest":manifest,"bootstrap_grant":{"actions":["post"]}}),
    )
    .await;
    let instance = Scope {
        workspace_id: Some(ws.clone()),
        instance_id: Some(adopted["instance_id"].as_str().unwrap().into()),
        protocol_digest: Some(adopted["protocol_digest"].as_str().unwrap().into()),
    };
    let mut post = Invoke::new(
        "post-notes",
        "structure.action",
        instance.clone(),
        json!({"action_id":"post","structure":{}}),
    );
    let text = "Encrypted content. ".repeat(3000);
    post.plaintext_contents = Some(json!([{"record_index":0,"text":text}]));
    post.expected_instance_revision = Some(1);
    let posted = owner.invoke(post, Duration::from_secs(10)).await.unwrap();
    assert_eq!(
        posted.state,
        "ACCEPTED",
        "{}",
        serde_json::to_string(&posted).unwrap()
    );
    let record = posted.outcome.as_ref().unwrap()["result"]["produced_record_ids"][0].clone();
    // No synthetic shared-key import: the actual approval and native import
    // above must let the other identity authenticate and open this ciphertext.
    let read = worker
        .request(Invoke::new(
            "read-note",
            "structure.record.get",
            instance.clone(),
            json!({"record_id":record,"revision":1}),
        ))
        .await
        .unwrap();
    assert_eq!(read["result"]["opened_contents"][0]["text"], text);
    let publication = Invoke::new(
        "publish",
        "participant.publication.publish",
        instance.clone(),
        json!({"record_id":record,"revision":1,"title":"Synthetic selected note","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"RECORD"}}),
    );
    let blocked = owner
        .invoke(publication, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(blocked.state, "BLOCKED");
    assert_eq!(
        blocked.outcome.as_ref().unwrap()["details"]["server_code"],
        "PUBLIC_VIEW_NOT_ACTIVE"
    );
    let original_publication = blocked.outcome.as_ref().unwrap()["details"]["command_id"].clone();
    let current = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mut open_view = Invoke::new(
        "open-public-view",
        "structure.publication.set",
        scope.clone(),
        json!({"profile":"backend-structure-v1","state":"PUBLIC","expected_publication_revision":0,"title":"Synthetic program feed","description":"Explicitly selected synthetic content","disclosure":"PUBLISH_SELECTED_CONTENT"}),
    );
    open_view.expected_workspace_revision = current["workspace_revision"].as_u64();
    assert_eq!(
        owner
            .invoke(open_view, Duration::from_secs(5))
            .await
            .unwrap()
            .state,
        "ACCEPTED"
    );
    owner.recover("publish").await.unwrap();
    let published = wait_terminal(&owner, "publish").await;
    assert_eq!(
        published.command_id.as_deref(),
        original_publication.as_str()
    );
    assert_eq!(structure(&published)["publication_state"], "PUBLIC");
    service.config(json!({"offline":true})).await;
    owner.close().await.unwrap();
    // Fault injection: retain only the queue summary, as for an oversized
    // outcome. The native request/receipt below remain genuine real-HTTP
    // evidence. This tests the summary recovery branch without relaxing the
    // native 180KiB packet or 64KiB body limits to manufacture a large packet.
    let identity = KernelIdentity::open(&config.identity_path).unwrap();
    let db = rusqlite::Connection::open(config.state_directory.join("participant.sqlite")).unwrap();
    let binding: String = db
        .query_row("SELECT binding FROM participant_meta WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let hash:String=db.query_row("SELECT input_hash FROM participant_operations WHERE session='program' AND id='post-notes'",[],|r|r.get(0)).unwrap();
    let aad=json!({"format":"peerwork.participant-local.v1","binding":binding,"session":"program","operation_id":"post-notes","input_hash":hash,"kind":"OUTCOME"}).to_string();
    let mut summary = posted.outcome.clone().unwrap();
    summary["result"]["structure"] = Value::Null;
    summary["detail_source"] = json!("VERIFIED_NATIVE_JOURNAL");
    let sealed =
        crate::kernel_intents::parent_operations::seal(&identity, &aad, &summary.to_string())
            .unwrap();
    db.execute(
        "UPDATE participant_operations SET outcome=?1 WHERE session='program' AND id='post-notes'",
        [sealed],
    )
    .unwrap();
    drop(db);
    let owner = ParticipantClient::open(config).await.unwrap();
    let before = service.counts().await;
    let mut selection = ResultSelection {
        pointer: "/result/structure/author_intent".into(),
        offset: 0,
        limit: 8192,
        expected_sha256: None,
    };
    let mut bytes = Vec::new();
    loop {
        let chunk = owner
            .operation_result("post-notes", selection.clone())
            .await
            .unwrap();
        assert_eq!(chunk["source"], "VERIFIED_NATIVE_COMMAND_RESULT");
        assert_eq!(chunk["effect_certainty"], "COMMITTED");
        bytes.extend(
            peerwork_core::crypto::decode_base64url(chunk["data"].as_str().unwrap()).unwrap(),
        );
        selection.expected_sha256 = Some(chunk["sha256"].as_str().unwrap().into());
        let Some(next) = chunk["next_offset"].as_u64() else {
            break;
        };
        selection.offset = next as usize;
    }
    assert!(bytes.len() > 64 * 1024);
    let jws = serde_json::from_slice::<String>(&bytes).unwrap();
    let payload = peerwork_core::crypto::decode_base64url(jws.split('.').nth(1).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&payload).unwrap()["command_id"],
        posted.command_id.unwrap()
    );
    let after = service.counts().await;
    assert_eq!(
        before["commands"], after["commands"],
        "result access must not submit or reconcile"
    );
    assert_eq!(after["journal_reads"], 0);
    let cache = owner.metrics().await.unwrap()["result_cache"].clone();
    assert_eq!(
        cache["preparations"], 1,
        "continuation chunks must reuse the verified snapshot"
    );
    assert!(cache["hits"].as_u64().unwrap() >= 4);
    let mut limited = Capability::owner();
    limited.operations = ["structure.workspace.get".into()].into();
    assert_eq!(
        owner
            .restrict("other-program", limited)
            .unwrap()
            .operation_result(
                "post-notes",
                ResultSelection {
                    pointer: "".into(),
                    offset: 0,
                    limit: 1024,
                    expected_sha256: None
                }
            )
            .await
            .unwrap_err()
            .code,
        "OPERATION_NOT_FOUND"
    );
    worker.close().await.unwrap();
    owner.close().await.unwrap();
}
pub(crate) fn install_synthetic_key(
    config: &ParticipantConfig,
    workspace: &str,
    secret: &[u8; 32],
    expected: Option<&str>,
) -> String {
    // Explicit synthetic fixture import; real applications use signed key delivery.
    let identity = KernelIdentity::open(&config.identity_path).unwrap();
    let key = peerwork_core::structure_content::structure_content_key_id(secret);
    let mut transport = crate::transport::TransportConfig::new(&config.origin);
    transport.allow_loopback_http = true;
    let origin = crate::transport::HttpTransport::new(transport)
        .unwrap()
        .trusted_origin()
        .to_owned();
    let mut transport = crate::transport::TransportConfig::new(&origin);
    transport.allow_loopback_http = true;
    let path = config.identity_path.with_extension(format!(
        "{}.content-keys.sqlite",
        sha256_hex(origin.as_bytes())
    ));
    let mut keys = crate::kernel_intents::StructureContentKeys::open(&path, transport).unwrap();
    keys.retain_current(identity.key_id(), workspace, secret, &key, expected)
        .unwrap();
    key
}
fn native_message(
    id: &str,
    scope: &Scope,
    recipient: &Value,
    reply_address: &Value,
    conversation: &str,
    text: &str,
) -> Invoke {
    let mut invoke = Invoke::new(
        id,
        "structure.message.send",
        scope.clone(),
        json!({"conversation_id":conversation,
        "recipients":[{"mailbox_id":recipient["mailbox_id"],"membership_id":recipient["membership_id"]}],
        "reply_address":{"mailbox_id":reply_address["mailbox_id"],"membership_id":reply_address["membership_id"]},
        "content":{"mode":"WORKSPACE_E2EE"}}),
    );
    invoke.plaintext_message = Some(text.into());
    invoke
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn native_program_mail_crypto_reply_sse_and_original_packet_recovery() {
    let service = Service::start();
    let owner_dir = crate::test_support::protected_test_dir();
    let worker_dir = crate::test_support::protected_test_dir();
    let owner_config = configuration(owner_dir.path(), &service.origin);
    let worker_config = configuration(worker_dir.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let created = mutate(
        &owner,
        "mail-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Native program mail"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&owner.invoke(join, Duration::from_secs(5)).await.unwrap());
    let owner_box=mutate(&owner,"grant-owner","structure.communication.grant.set",&scope,json!({"actor_id":owner_config.expected_actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&owner,"grant-worker","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&owner_config, &ws, &[19; 32], None);
    mutate(
        &owner,
        "select-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    // Offline mailbox accepts mail before a receiver exists. This is not a task report.
    let send = native_message(
        "message-one",
        &scope,
        &worker_box,
        &owner_box,
        &"V".repeat(43),
        "Hello native worker 📨",
    );
    let sent = structure(
        &owner
            .invoke(send.clone(), Duration::from_secs(10))
            .await
            .unwrap(),
    );
    let message_id = sent["message_id"].as_str().unwrap();
    assert_eq!(sent["status"], "APPLIED");
    let claim=mutate(&worker,"worker-claim","structure.mailbox.claim",&scope,json!({"mailbox_id":worker_box["mailbox_id"],"receiver_id":test_receiver("R"),"expected_epoch":null,"destination_digest":"d".repeat(64)})).await;
    let fence = json!({"mailbox_id":worker_box["mailbox_id"],"receiver_id":test_receiver("R"),"epoch":claim["mailbox"]["epoch"]});
    let mut pulse = fence.clone();
    pulse["ready"] = json!(true);
    pulse["execution_state"] = json!("IDLE");
    selected(&worker, "structure.mailbox.pulse", &scope, pulse).await;
    let missing = worker
        .request(Invoke::new(
            "missing-key",
            "structure.message.get",
            scope.clone(),
            json!({"message_id":message_id}),
        ))
        .await
        .unwrap();
    assert_eq!(
        missing["result"]["opened_messages"][0]["state"],
        "KEY_UNAVAILABLE"
    );
    install_synthetic_key(&worker_config, &ws, &[19; 32], None);
    let read = worker
        .request(Invoke::new(
            "inbox",
            "structure.mailbox.inbox.read",
            scope.clone(),
            fence.clone(),
        ))
        .await
        .unwrap();
    let inbox = &read["result"]["structure"];
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        read["result"]["opened_messages"][0]["text"],
        "Hello native worker 📨"
    );
    assert_eq!(
        read["result"]["opened_messages"][0]["assurance"],
        "AUTHOR_SIGNATURE_AND_AEAD"
    );
    let mut reply = native_message(
        "worker-reply",
        &scope,
        &owner_box,
        &worker_box,
        &"V".repeat(43),
        "PONG native owner",
    );
    reply.body["reply_to"] = json!(message_id);
    let replied = structure(&worker.invoke(reply, Duration::from_secs(5)).await.unwrap());
    let owner_read = owner
        .request(Invoke::new(
            "reply-read",
            "structure.message.get",
            scope.clone(),
            json!({"message_id":replied["message_id"]}),
        ))
        .await
        .unwrap();
    assert_eq!(
        owner_read["result"]["opened_messages"][0]["text"],
        "PONG native owner"
    );
    // Warm send is one remote command and reuses original ciphertext on dedup.
    let before = service.counts().await;
    let warm = native_message(
        "message-two",
        &scope,
        &worker_box,
        &owner_box,
        &"V".repeat(43),
        "Warm send",
    );
    let warm_result = structure(&owner.invoke(warm, Duration::from_secs(5)).await.unwrap());
    let after = service.counts().await;
    assert_eq!(
        after["commands"].as_u64().unwrap() - before["commands"].as_u64().unwrap(),
        1
    );
    assert_eq!(before["context"], after["context"]);
    assert_eq!(before["discovery"], after["discovery"]);
    assert_eq!(
        structure(&owner.invoke(send, Duration::from_secs(5)).await.unwrap()),
        sent
    );
    // Verify a real full-data SSE frame independently of the read receipt.
    let after_control = inbox["control_checkpoint"].as_u64().unwrap();
    let stream=selected(&worker,"structure.communication.stream.get",&Scope::default(),json!({"scopes":[{"workspace_id":ws,"mailbox_id":worker_box["mailbox_id"],"receiver_id":test_receiver("R"),"epoch":claim["mailbox"]["epoch"],"after_sequence":0,"after_control_sequence":after_control}]})).await;
    let discovery = reqwest::get(format!("{}/api/workspace/v1/discovery", service.origin))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let discovery = peerwork_core::discovery::parse_discovery_wire(&discovery, 65536).unwrap();
    let mut response = reqwest::Client::new()
        .get(format!(
            "{}{}",
            service.origin,
            stream["stream"]["path"].as_str().unwrap()
        ))
        .bearer_auth(stream["stream"]["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let data = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buffer = Vec::new();
        loop {
            let chunk = response.chunk().await.unwrap().expect("stream closed");
            buffer.extend_from_slice(&chunk);
            assert!(buffer.len() < 2 * 1024 * 1024);
            let text = std::str::from_utf8(&buffer).unwrap();
            for event in text.split("\n\n") {
                if let Some(data) = event.strip_prefix("event: delivery\ndata: ") {
                    return data.to_owned();
                }
            }
        }
    })
    .await
    .unwrap();
    let pins = peerwork_core::communication::MailboxPins {
        workspace_id: ws.clone(),
        mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        receiver_id: test_receiver("R"),
        epoch: claim["mailbox"]["epoch"].as_u64().unwrap(),
        destination_digest: "d".repeat(64),
        binding_version: 1,
        after_sequence: 0,
        after_control_sequence: Some(after_control),
    };
    let page = peerwork_core::communication::verify_mailbox_frame(
        data.as_bytes(),
        &peerwork_core::communication::FramePins {
            audience: discovery.audience_utf16(),
            actor_id: &worker_config.expected_actor,
            stream_id: stream["stream"]["stream_id"].as_str().unwrap(),
            mailbox: &pins,
            service_key: discovery.receipt_public_key(),
            server_time_floor: claim["mailbox"]["server_time"].as_u64().unwrap(),
            expires_at: stream["stream"]["expires_at"].as_u64().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(page.items().len(), 2);
    assert_eq!(page.items()[0].message().unwrap().message_id(), message_id);
    drop(response);
    let worker_identity = KernelIdentity::open(&worker_config.identity_path).unwrap();
    let mut local = crate::participant_inbox::InboxStore::open(
        &worker_config.state_directory.join("manual-inbox"),
        &worker_identity,
        &service.origin,
        discovery.audience_utf16(),
        discovery.receipt_public_key(),
    )
    .unwrap();
    local.register(&pins).unwrap();
    assert_eq!(
        local.ingest(&worker_identity, &page, 1).unwrap_err().code,
        "INBOX_CAPACITY"
    );
    assert_eq!(
        local.cursor(&ws, &pins.mailbox_id).unwrap().unwrap().item,
        0
    );
    let cursor = local
        .ingest(&worker_identity, &page, 64 * 1024 * 1024)
        .unwrap();
    assert_eq!(cursor.item, 2);
    assert_eq!(cursor.control, Some(page.control_checkpoint()));
    // Genuine verified ciphertext creates a durable receive-only key reference.
    let needed = local.key_batch(&worker_identity, &ws).unwrap();
    assert_eq!(needed, vec![key.clone()]);
    assert!(local.key_missing(&ws).unwrap());
    local
        .keys_checked(&ws, &needed, &Default::default())
        .unwrap();
    assert!(!local.key_missing(&ws).unwrap());
    local
        .ingest(&worker_identity, &page, 64 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        local
            .pending(&worker_identity, &ws, &pins.mailbox_id, 0, 32)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        local
            .acknowledgements(&ws, &pins.mailbox_id, false)
            .unwrap()
            .len(),
        2
    );
    assert!(local
        .acknowledgements(&ws, &pins.mailbox_id, true)
        .unwrap()
        .is_empty());
    let local_first = (page.items()[0].sequence(), page.items()[0].delivery_id());
    local
        .consume(&ws, &pins.mailbox_id, &[local_first.clone()])
        .unwrap();
    assert!(
        local
            .acknowledgements(&ws, &pins.mailbox_id, true)
            .unwrap()
            .is_empty(),
        "app consumption cannot overtake durable custody ACK upload"
    );
    drop(local);
    let mut local = crate::participant_inbox::InboxStore::open(
        &worker_config.state_directory.join("manual-inbox"),
        &worker_identity,
        &service.origin,
        discovery.audience_utf16(),
        discovery.receipt_public_key(),
    )
    .unwrap();
    assert_eq!(
        local.cursor(&ws, &pins.mailbox_id).unwrap().unwrap(),
        cursor
    );
    assert_eq!(
        local
            .pending(&worker_identity, &ws, &pins.mailbox_id, 0, 32)
            .unwrap()
            .len(),
        1
    );
    // A business commit carries only source references, with an independent
    // original command/receipt proof. Controls remain visible after its cursor.
    let manifest = json!({"name":"mail-business","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{},
        "record_schemas":{"note":{"type":"object","fields":{"text":"string"},"required":["text"],"max_bytes":128}},
        "actions":[{"id":"post","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"append","schema":"note","value":{"from":"literal","value":{"text":"business structure"}},"relations":[]}]}]}]});
    let adopted = mutate(
        &owner,
        "mail-business",
        "structure.adopt",
        &scope,
        json!({"manifest":manifest,"bootstrap_grant":{"actions":["post"]}}),
    )
    .await;
    let business_scope = Scope {
        workspace_id: Some(ws.clone()),
        instance_id: Some(adopted["instance_id"].as_str().unwrap().into()),
        protocol_digest: Some(adopted["protocol_digest"].as_str().unwrap().into()),
    };
    let subscription = json!({"subscription_id":"S".repeat(43),"mailbox_id":worker_box["mailbox_id"],"instance_id":adopted["instance_id"],"protocol_digest":adopted["protocol_digest"],"expected_revision":null,"state":"ACTIVE","actions":["post"]});
    mutate(
        &owner,
        "business-sub",
        "structure.communication.subscription.set",
        &scope,
        subscription.clone(),
    )
    .await;
    let mut action = Invoke::new(
        "business-post",
        "structure.action",
        business_scope.clone(),
        json!({"action_id":"post","structure":{}}),
    );
    action.expected_instance_revision = Some(1);
    let action = structure(&owner.invoke(action, Duration::from_secs(5)).await.unwrap());
    let mut selection = fence.clone();
    selection["after_sequence"] = json!(2);
    selection["after_control_sequence"] = json!(after_control);
    let business_page = selected(
        &worker,
        "structure.mailbox.inbox.read",
        &scope,
        selection.clone(),
    )
    .await;
    assert_eq!(business_page["items"][0]["kind"], "BUSINESS");
    assert_eq!(
        business_page["items"][0]["business"]["kind"],
        "action.accepted"
    );
    let mut withdraw = Invoke::new(
        "business-withdraw",
        "structure.record.withdraw",
        business_scope.clone(),
        json!({"record_id":action["produced_record_ids"][0],"revision":1}),
    );
    withdraw.expected_instance_revision = action["revision"].as_u64();
    owner
        .invoke(withdraw, Duration::from_secs(5))
        .await
        .unwrap();
    let mut stop = subscription;
    stop["expected_revision"] = json!(1);
    stop["state"] = json!("STOPPED");
    mutate(
        &owner,
        "business-stop",
        "structure.communication.subscription.set",
        &scope,
        stop,
    )
    .await;
    selection["after_sequence"] = business_page["checkpoint"].clone();
    let controls = selected(&worker, "structure.mailbox.inbox.read", &scope, selection).await;
    assert_eq!(controls["controls"].as_array().unwrap().len(), 2);
    assert_eq!(controls["controls"][0]["kind"], "record.withdrawn");
    assert_eq!(
        controls["controls"][1]["kind"],
        "communication.subscription.changed"
    );
    let first = inbox["items"][0].clone();
    let mut ack = fence.clone();
    ack["stage"] = json!("RECEIVER_STORED");
    ack["items"] = json!([{"sequence":first["sequence"],"delivery_id":first["delivery_id"]}]);
    selected(&worker, "structure.mailbox.ack", &scope, ack.clone()).await;
    local
        .acknowledged(&ws, &pins.mailbox_id, &[local_first.clone()], false)
        .unwrap();
    assert_eq!(
        local.acknowledgements(&ws, &pins.mailbox_id, true).unwrap(),
        vec![local_first.clone()]
    );
    ack["stage"] = json!("APPLICATION_CONSUMED");
    selected(&worker, "structure.mailbox.ack", &scope, ack).await;
    local
        .acknowledged(&ws, &pins.mailbox_id, &[local_first], true)
        .unwrap();
    let receipt = selected(
        &owner,
        "structure.message.receipts.read",
        &scope,
        json!({"message_id":message_id}),
    )
    .await;
    assert!(receipt["deliveries"][0]["receiver_stored_at"].is_number());
    assert!(receipt["deliveries"][0]["application_consumed_at"].is_number());
    assert_eq!(receipt["model_response"], "NOT_ATTESTED");
    // All-or-nothing acceptance lost on the wire must recover the exact intent.
    service
        .config(json!({"drop_action":"structure.message.send"}))
        .await;
    let lost = owner
        .invoke(
            native_message(
                "lost-mail",
                &scope,
                &worker_box,
                &owner_box,
                &"V".repeat(43),
                "Original ciphertext survives",
            ),
            Duration::from_millis(200),
        )
        .await
        .unwrap();
    assert!(!lost.is_terminal());
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.counts().await["dropped"] != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    owner.close().await.unwrap();
    service.config(json!({"offline":false})).await;
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let recovered = wait_terminal(&owner, "lost-mail").await;
    let recovered = structure(&recovered);
    assert_eq!(recovered["status"], "APPLIED");
    let fetched = selected(
        &owner,
        "structure.message.get",
        &scope,
        json!({"message_id":recovered["message_id"]}),
    )
    .await;
    assert_eq!(fetched["message"]["message_id"], recovered["message_id"]);
    // Remote rotation invalidates only the rejected candidate's local selection.
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let new_key = install_synthetic_key(&owner_config, &ws, &[20; 32], Some(&key));
    mutate(&owner,"rotate-key","structure.content-key.set",&scope,json!({"key_id":new_key,"expected_epoch":meta["content_key_head"]["epoch"],"expected_head_revision":meta["content_key_head"]["revision"]})).await;
    let stale = worker
        .invoke(
            native_message(
                "old-head",
                &scope,
                &owner_box,
                &worker_box,
                &"V".repeat(43),
                "old key",
            ),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(stale.state, "REJECTED_NO_EFFECT", "{stale:?}");
    assert_eq!(
        stale.outcome.as_ref().unwrap()["result"]["structure"]["error"]["code"],
        "CONTENT_KEY_STALE"
    );
    install_synthetic_key(&worker_config, &ws, &[20; 32], None);
    let fresh = structure(
        &worker
            .invoke(
                native_message(
                    "new-head",
                    &scope,
                    &owner_box,
                    &worker_box,
                    &"V".repeat(43),
                    "new key",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    assert_eq!(fresh["status"], "APPLIED");
    let historical = worker
        .request(Invoke::new(
            "old-message",
            "structure.message.get",
            scope.clone(),
            json!({"message_id":message_id}),
        ))
        .await
        .unwrap();
    assert_eq!(
        historical["result"]["opened_messages"][0]["text"],
        "Hello native worker 📨"
    );
    assert!(warm_result["message_id"].is_string());
    owner.close().await.unwrap();
    worker.close().await.unwrap();
}

async fn watch_until(
    watch: &mut ProgramWatch,
    condition: impl Fn(&WatchSnapshot) -> bool,
) -> WatchSnapshot {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let snapshot = watch.next().await.unwrap();
            assert_ne!(snapshot.state, "BLOCKED", "{snapshot:?}");
            if condition(&snapshot) {
                return snapshot;
            }
        }
    })
    .await
    .expect("watch did not reach expected condition")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn automatic_native_program_watch_spools_offline_consumes_and_reconnects() {
    let service = Service::start();
    let owner_dir = crate::test_support::protected_test_dir();
    let worker_dir = crate::test_support::protected_test_dir();
    let owner_config = configuration(owner_dir.path(), &service.origin);
    let worker_config = configuration(worker_dir.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let created = mutate(
        &owner,
        "watch-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Automatic native watch"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "watch-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker.actor_id(),"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&owner.invoke(join, Duration::from_secs(5)).await.unwrap());
    let owner_box=mutate(&owner,"watch-grant-owner","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&owner,"watch-grant-worker","structure.communication.grant.set",&scope,json!({"actor_id":worker.actor_id(),"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&owner_config, &ws, &[29; 32], None);
    install_synthetic_key(&worker_config, &ws, &[29; 32], None);
    mutate(
        &owner,
        "watch-select-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let options = |mailbox: &Value, consumer: &str| WatchOptions {
        host_destination: None,
        workspace_id: ws.clone(),
        mailbox_id: mailbox["mailbox_id"].as_str().unwrap().into(),
        membership_id: mailbox["membership_id"].as_str().unwrap().into(),
        consumer_id: consumer.into(),
    };
    let worker_options = options(&worker_box, "worker-program");
    let owner_options = options(&owner_box, "master-program");
    // Spool offline mail. The ordinary program calls watch once; it does not
    // construct claims, pulse leases, read remote pages or upload storage ACKs.
    let sent = structure(
        &owner
            .invoke(
                native_message(
                    "watch-offline-mail",
                    &scope,
                    &worker_box,
                    &owner_box,
                    &"V".repeat(43),
                    "Work while Master computes",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    let mut worker_watch = worker.watch(worker_options.clone()).await.unwrap();
    let received = watch_until(&mut worker_watch, |s| {
        s.receiver_link_verified && !s.items.is_empty()
    })
    .await;
    assert_eq!(
        received.items[0]["envelope"]["message"]["message_id"],
        sent["message_id"]
    );
    assert_eq!(
        received.items[0]["opened_message"]["text"],
        "Work while Master computes"
    );
    let mut owner_watch = owner.watch(owner_options.clone()).await.unwrap();
    watch_until(&mut owner_watch, |s| s.receiver_link_verified).await;
    let mut reply = native_message(
        "watch-pong",
        &scope,
        &owner_box,
        &worker_box,
        &"V".repeat(43),
        "PONG from ordinary Worker program",
    );
    reply.body["reply_to"] = sent["message_id"].clone();
    worker.invoke(reply, Duration::from_secs(5)).await.unwrap();
    let pong = watch_until(&mut owner_watch, |s| {
        s.items
            .iter()
            .any(|v| v["opened_message"]["text"] == "PONG from ordinary Worker program")
    })
    .await;
    assert_eq!(pong.model_response, "NOT_ATTESTED");
    let reference = DeliveryReference {
        sequence: received.items[0]["sequence"].as_u64().unwrap(),
        delivery_id: received.items[0]["delivery_id"].as_str().unwrap().into(),
    };
    worker_watch.consume(vec![reference.clone()]).await.unwrap();
    // Wait on local notifications from the asynchronous ACK worker, then check
    // one independently signed service observation of the consumption fact.
    watch_until(&mut worker_watch, |s| {
        s.items.is_empty() && !s.receiver_ack_pending && !s.application_ack_pending
    })
    .await;
    let receipt = selected(
        &owner,
        "structure.message.receipts.read",
        &scope,
        json!({"message_id":sent["message_id"]}),
    )
    .await;
    assert!(receipt["deliveries"][0]["receiver_stored_at"].is_number());
    assert!(receipt["deliveries"][0]["application_consumed_at"].is_number());
    // Graceful EOF, rather than an error response, must revoke current readiness
    // and reconnect with durable cursors. Server closes this one stream normally.
    drop(owner_watch);
    drop(worker_watch);
    worker.close().await.unwrap();
    service.config(json!({"stream_duration_once_ms":300})).await;
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let mut restarted = worker.watch(worker_options.clone()).await.unwrap();
    watch_until(&mut restarted, |s| s.receiver_link_verified).await;
    watch_until(&mut restarted, |s| {
        s.disconnects >= 1 && s.receiver_link_verified
    })
    .await;
    let snapshot = restarted.page(0, 32).await.unwrap();
    assert!(
        snapshot.items.is_empty(),
        "consumed mail is not replayed after reconnect"
    );
    let sent2 = structure(
        &owner
            .invoke(
                native_message(
                    "watch-after-restart",
                    &scope,
                    &worker_box,
                    &owner_box,
                    &"V".repeat(43),
                    "After graceful reconnect",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    let received2 = watch_until(&mut restarted, |s| {
        s.items
            .iter()
            .any(|v| v["envelope"]["message"]["message_id"] == sent2["message_id"])
    })
    .await;
    assert_eq!(
        received2.items[0]["opened_message"]["text"],
        "After graceful reconnect"
    );
    // Three mailbox scopes of one participant are handled by the same driver.
    let b = mutate(
        &worker,
        "mailbox-b",
        "structure.mailbox.create",
        &scope,
        json!({"name":"research"}),
    )
    .await["mailbox"]
        .clone();
    let c = mutate(
        &worker,
        "mailbox-c",
        "structure.mailbox.create",
        &scope,
        json!({"name":"discussion"}),
    )
    .await["mailbox"]
        .clone();
    service
        .config(json!({"drop_action":"structure.mailbox.claim"}))
        .await;
    let mut wb = worker.watch(options(&b, "research-program")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.counts().await["dropped"] != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    service.config(json!({"offline":false})).await;
    watch_until(&mut wb, |s| s.receiver_link_verified).await;
    let claimed = selected(
        &worker,
        "structure.mailbox.get",
        &scope,
        json!({"mailbox_id":b["mailbox_id"]}),
    )
    .await;
    assert_eq!(
        claimed["mailbox"]["epoch"], 1,
        "lost claim result resumes the original command instead of claiming a new epoch"
    );
    let mut wc = worker
        .watch(options(&c, "discussion-program"))
        .await
        .unwrap();
    let connected_c = watch_until(&mut wc, |s| s.receiver_link_verified).await;
    // Scope changes replace the old stream; all current frames share the new grant.
    let target = connected_c.stream_id.clone();
    watch_until(&mut restarted, |s| {
        s.receiver_link_verified && s.stream_id == target
    })
    .await;
    // Each scope independently verifies its first signed frame. Another
    // mailbox becoming ready does not imply this mailbox's frame was stored.
    let b_snapshot = watch_until(&mut wb, |s| {
        s.receiver_link_verified && s.stream_id == target
    })
    .await;
    assert!(target.is_some());
    assert_eq!(b_snapshot.stream_id, target);
    let mut changed = worker_options.clone();
    changed.consumer_id = "other-program".into();
    assert_eq!(
        worker.watch(changed).await.err().unwrap().code,
        "WATCH_BINDING_MISMATCH"
    );
    // Revocation/readiness evidence never says a model handled a message.
    assert_eq!(
        restarted.page(0, 32).await.unwrap().model_response,
        "NOT_ATTESTED"
    );
    wb.stop().await.unwrap();
    let paused = worker
        .inbox(&options(&b, "research-program"), 0, 32)
        .await
        .unwrap();
    assert_eq!(paused.state, "LOCAL_STOPPED");
    assert!(!paused.receiver_link_verified);
    let mut wb = worker.watch(options(&b, "research-program")).await.unwrap();
    watch_until(&mut wb, |s| s.receiver_link_verified).await;
    // A server clock jump invalidates the short heartbeat issuance window.
    // It must refresh trusted time and recover without another claim/identity.
    let previous = wb.page(0, 32).await.unwrap().disconnects;
    service.config(json!({"clock_offset_ms":20000})).await;
    watch_until(&mut wb, |s| {
        s.receiver_link_verified && s.disconnects > previous
    })
    .await;
    // Replacing one mailbox fence must isolate that scope, while the other
    // healthy scopes reconnect and continue receiving on the shared stream.
    let current = selected(
        &worker,
        "structure.mailbox.get",
        &scope,
        json!({"mailbox_id":b["mailbox_id"]}),
    )
    .await;
    let mut replacement = json!({"mailbox_id":b["mailbox_id"],"receiver_id":test_receiver("F"),"expected_epoch":current["mailbox"]["epoch"],"destination_digest":current["mailbox"]["destination_digest"],"replace":true});
    test_claim_proof(&worker, &scope, &mut replacement).await;
    let rejected = worker
        .invoke(
            Invoke::new(
                "replace-b-refused",
                "structure.mailbox.claim",
                scope.clone(),
                replacement,
            ),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(rejected.state, "REJECTED_NO_EFFECT");
    assert_eq!(
        rejected.outcome.unwrap()["result"]["structure"]["error"]["code"],
        "MAILBOX_STATE_RECOVERY_REQUIRED"
    );
    // Simulate a separately authorized administrative fence in the isolated
    // fixture, to retain the scope-isolation test without an unsafe public API.
    service
        .config(json!({"fence_mailbox":b["mailbox_id"]}))
        .await;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = wb.next().await.unwrap();
            if status.state == "BLOCKED" {
                assert_eq!(status.code.as_deref(), Some("MAILBOX_EPOCH_MISMATCH"));
                break;
            }
        }
    })
    .await
    .unwrap();
    let delivered = structure(
        &owner
            .invoke(
                native_message(
                    "healthy-c-after-fence",
                    &scope,
                    &c,
                    &owner_box,
                    &"V".repeat(43),
                    "Healthy mailbox survives another scope's fence failure",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    watch_until(&mut wc, |s| {
        s.receiver_link_verified
            && s.items
                .iter()
                .any(|v| v["envelope"]["message"]["message_id"] == delivered["message_id"])
    })
    .await;
    drop(restarted);
    drop(wb);
    drop(wc);
    worker.close().await.unwrap();
    // A corrupt persisted descriptor must report recovery failure rather than
    // silently starting a driver with no durable receiving obligations.
    let db = rusqlite::Connection::open(
        worker_config
            .state_directory
            .join("participant-inbox.sqlite"),
    )
    .unwrap();
    db.execute(
        "UPDATE inbox_watches SET descriptor='{}' WHERE enabled=1",
        [],
    )
    .unwrap();
    drop(db);
    let damaged = ParticipantClient::open(worker_config).await.unwrap();
    assert_eq!(
        damaged.watch(worker_options).await.err().unwrap().code,
        "INBOX_STATE_INVALID"
    );
    damaged
        .request(Invoke::new(
            "still-readable",
            "structure.workspace.get",
            scope,
            json!({}),
        ))
        .await
        .unwrap();
    damaged.close().await.unwrap();
    owner.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit synthetic PostgreSQL and real product HTTP fixture"]
async fn resident_runtime_program_watch_is_scoped_and_receives_while_other_calls_progress() {
    use crate::communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig};
    let service = Service::start();
    let directory = crate::test_support::protected_test_dir();
    let config = configuration(directory.path(), &service.origin);
    let runtime = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        hosts: Vec::new(),
        state_directory: directory.path().join("runtime"),
        engines: vec![EngineConfig {
            authority: None,
            migration_sources: Vec::new(),
            name: "program".into(),
            origin: config.origin.clone(),
            expected_actor: config.expected_actor.clone(),
            identity_path: config.identity_path.clone(),
            state_directory: config.state_directory.clone(),
            journal_path: Some(config.journal_path.clone()),
            allow_loopback_http: true,
            transport: config.transport.clone(),
            max_inflight: 4,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
        }],
        clients: vec![ClientConfig {
            name: "application".into(),
            engine: "program".into(),
            capability: Capability::owner(),
        }],
    };
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime, stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let endpoint = ready.client_endpoints["application"].clone();
    async fn rpc(endpoint: &std::path::Path, value: Value) -> Value {
        let result = crate::communication_runtime::call(endpoint, value)
            .await
            .unwrap();
        assert_eq!(result["ok"], true, "{result}");
        result["value"].clone()
    }
    async fn request(endpoint: &std::path::Path, request: Invoke) -> Value {
        rpc(endpoint, json!({"method":"request","request":request})).await["result"]["structure"]
            .clone()
    }
    async fn mutation(endpoint: &std::path::Path, request: Invoke) -> Value {
        let result = rpc(
            endpoint,
            json!({"method":"invoke","request":request,"wait_ms":5000}),
        )
        .await;
        assert_eq!(result["state"], "ACCEPTED", "{result}");
        result["outcome"]["result"]["structure"].clone()
    }
    let created = mutation(
        &endpoint,
        Invoke::new(
            "ipc-watch-space",
            "structure.workspace.create",
            Scope::default(),
            json!({"name":"Thin program watch"}),
        ),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let metadata = request(
        &endpoint,
        Invoke::new("meta", "structure.workspace.get", scope.clone(), json!({})),
    )
    .await;
    let mailbox=mutation(&endpoint,Invoke::new("ipc-watch-grant","structure.communication.grant.set",scope.clone(),json!({"actor_id":config.expected_actor,"membership_id":metadata["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true}))).await["mailbox"].clone();
    let key = install_synthetic_key(&config, &ws, &[37; 32], None);
    mutation(
        &endpoint,
        Invoke::new(
            "ipc-watch-key",
            "structure.content-key.set",
            scope.clone(),
            json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
        ),
    )
    .await;
    let options = WatchOptions {
        host_destination: None,
        workspace_id: ws,
        mailbox_id: mailbox["mailbox_id"].as_str().unwrap().into(),
        membership_id: mailbox["membership_id"].as_str().unwrap().into(),
        consumer_id: "application".into(),
    };
    rpc(&endpoint, json!({"method":"watch","options":options})).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = rpc(
                &endpoint,
                json!({"method":"watch_next","options":options,"wait_ms":3000}),
            )
            .await;
            assert_ne!(snapshot["state"], "BLOCKED", "{snapshot}");
            if snapshot["receiver_link_verified"] == true {
                break;
            }
        }
    })
    .await
    .unwrap();
    let waiting_endpoint = endpoint.clone();
    let waiting_options = options.clone();
    let pending = tokio::spawn(async move {
        rpc(
            &waiting_endpoint,
            json!({"method":"watch_next","options":waiting_options,"wait_ms":5000}),
        )
        .await
    });
    let sent = mutation(
        &endpoint,
        native_message(
            "ipc-watch-send",
            &scope,
            &mailbox,
            &mailbox,
            &"I".repeat(43),
            "Thin client receives without Node SDK",
        ),
    )
    .await;
    let mut received = pending.await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !received["items"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|v| v["envelope"]["message"]["message_id"] == sent["message_id"])
        }) {
            received = rpc(
                &endpoint,
                json!({"method":"watch_next","options":options,"wait_ms":3000}),
            )
            .await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        received["items"][0]["opened_message"]["text"],
        "Thin client receives without Node SDK"
    );
    let reference = json!({"sequence":received["items"][0]["sequence"],"delivery_id":received["items"][0]["delivery_id"]});
    let consumed = rpc(
        &endpoint,
        json!({"method":"consume","options":options,"items":[reference]}),
    )
    .await;
    assert_eq!(consumed["state"], "LOCAL_CONSUMPTION_RECORDED");
    assert_eq!(consumed["model_response"], "NOT_ATTESTED");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = rpc(
                &endpoint,
                json!({"method":"watch_next","options":options,"wait_ms":3000}),
            )
            .await;
            if state["items"]
                .as_array()
                .is_some_and(|items| items.is_empty())
                && state["receiver_ack_pending"] == false
                && state["application_ack_pending"] == false
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let expired = rpc(
        &endpoint,
        json!({"method":"watch_next","options":options,"wait_ms":30}),
    )
    .await;
    assert_eq!(expired["state"], "WAIT_EXPIRED");
    assert_eq!(expired["watch_continues"], true);
    let paused = rpc(&endpoint, json!({"method":"unwatch","options":options})).await;
    assert_eq!(paused["state"], "LOCAL_STOPPED");
    stop.cancel();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires synthetic PostgreSQL, real product HTTP and synthetic host protocol"]
async fn runtime_host_dispatch_persists_unknown_and_blocks_only_same_conversation_across_restart() {
    use crate::{
        communication_host::tests::CodexFixture,
        communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig},
        participant_dispatch::{HostConfig, HostSubscription},
        participant_inbox::HostBinding,
    };
    let service = Service::start();
    let fixture = CodexFixture::start();
    let owner_dir = crate::test_support::protected_test_dir();
    let worker_dir = crate::test_support::protected_test_dir();
    let owner_config = configuration(owner_dir.path(), &service.origin);
    let worker_config = configuration(worker_dir.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let created = mutate(
        &owner,
        "dispatch-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Synthetic existing-host dispatch"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "dispatch-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&owner.invoke(join, Duration::from_secs(5)).await.unwrap());
    let owner_box=mutate(&owner,"dispatch-grant-owner","structure.communication.grant.set",&scope,json!({"actor_id":owner_config.expected_actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&owner,"dispatch-grant-worker","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&owner_config, &ws, &[47; 32], None);
    install_synthetic_key(&worker_config, &ws, &[47; 32], None);
    mutate(
        &owner,
        "dispatch-select-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let conversations = ["A".repeat(43), "A".repeat(43), "B".repeat(43)];
    let mut sent = Vec::new();
    for (index, conversation) in conversations.iter().enumerate() {
        sent.push(structure(
            &owner
                .invoke(
                    native_message(
                        &format!("dispatch-message-{index}"),
                        &scope,
                        &worker_box,
                        &owner_box,
                        conversation,
                        &format!("synthetic-message-{index}"),
                    ),
                    Duration::from_secs(5),
                )
                .await
                .unwrap(),
        ));
    }
    let adapter = fixture.config();
    let binding=HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"existing-thread","session_id":adapter["expected_session_id"],"endpoint":adapter["endpoint"]})).unwrap();
    let options = WatchOptions {
        workspace_id: ws,
        mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        consumer_id: "native-dispatcher".into(),
        host_destination: Some(binding.digest),
    };
    let host = HostConfig {
        name: "existing-codex".into(),
        adapter,
        subscriptions: vec![HostSubscription {
            client: "worker".into(),
            watch: options.clone(),
        }],
    };
    let runtime = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: worker_dir.path().join("runtime"),
        engines: vec![EngineConfig {
            name: "worker".into(),
            origin: worker_config.origin.clone(),
            expected_actor: worker_config.expected_actor.clone(),
            authority: None,
            identity_path: worker_config.identity_path.clone(),
            state_directory: worker_config.state_directory.clone(),
            journal_path: Some(worker_config.journal_path.clone()),
            allow_loopback_http: true,
            transport: worker_config.transport.clone(),
            max_inflight: 4,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
            migration_sources: Vec::new(),
        }],
        clients: vec![ClientConfig {
            name: "worker".into(),
            engine: "worker".into(),
            capability: Capability::owner(),
        }],
        hosts: vec![host.clone(), host],
    };
    fixture
        .lose_next_ack
        .store(true, std::sync::atomic::Ordering::SeqCst);
    service
        .config(json!({"drop_action":"structure.mailbox.report","report_quota_blocked":true}))
        .await;
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime.clone(), stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let endpoint = &ready.client_endpoints["worker"];
    let mut diagnostic = json!({});
    let (first,third)=tokio::time::timeout(Duration::from_secs(20),async{loop{
        let page=ipc::call(endpoint,json!({"method":"inbox","options":options,"after":0,"limit":32})).await.unwrap();
        diagnostic=json!({"page_state":page["value"]["state"],"error":page["error"],"items":page["value"]["items"].as_array().map(|items|items.iter().map(|v|json!({"sequence":v["sequence"],"state":v["state"],"kind":v["kind"],"opened":v["opened_message"]["state"]})).collect::<Vec<_>>())});
        if let Some(items)=page["value"]["items"].as_array().filter(|v|v.len()==3){
            let reference=|v:&Value|DeliveryReference{sequence:v["sequence"].as_u64().unwrap(),delivery_id:v["delivery_id"].as_str().unwrap().into()};
            let first=reference(&items[0]);let third=reference(&items[2]);
            let status=ipc::call(endpoint,json!({"method":"delivery_status","options":options,"item":third})).await.unwrap();
            if status["value"]["host"]=="HOST_ACCEPTED"{break(first,third);}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.unwrap_or_else(|_|{
        // Synthetic metadata only; no real profile or message is logged.
        panic!("host dispatch did not finish: {diagnostic}; host protocol methods {:?}",fixture.calls().iter().map(|v|v["method"].clone()).collect::<Vec<_>>());
    });
    let state = ipc::call(
        endpoint,
        json!({"method":"delivery_status","options":options,"item":first}),
    )
    .await
    .unwrap();
    assert_eq!(state["value"]["host"], "RESULT_UNKNOWN");
    assert_eq!(state["value"]["model_response"], "NOT_ATTESTED");
    let admin = ipc::call(&ready.admin_endpoint, json!({"method":"status"}))
        .await
        .unwrap();
    assert_eq!(admin["value"]["hosts"].as_array().unwrap().len(), 1);
    let calls = fixture.calls();
    let submitted: Vec<_> = calls
        .iter()
        .filter(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer")))
        .collect();
    assert_eq!(
        submitted.len(),
        2,
        "one uncertain original plus one unrelated conversation"
    );
    assert!(
        submitted
            .iter()
            .all(|v| !v.to_string().contains("synthetic-message-1")),
        "same conversation must not overtake an unknown call"
    );
    // Exercise a genuine accounting refusal first. Reporting must resume after
    // capacity returns, without quarantining valid facts or repeating input.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let page = ipc::call(
                endpoint,
                json!({"method":"inbox","options":options,"after":0,"limit":1}),
            )
            .await
            .unwrap();
            if page["value"]["reporting_code"] == "RESOURCE_EXHAUSTED" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("genuine report quota refusal not observed");
    service.config(json!({"report_quota_blocked":false})).await;
    // Lose one accepted report reply, then restore HTTP. This must retry
    // the facts only, never inject another input into the host session.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if service.counts().await["dropped"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("synthetic report response was not lost");
    service.config(json!({"offline":false})).await;
    // The sender queries one native receipt read, not receiver-local files.
    let mut report_diagnostic = json!({});
    tokio::time::timeout(Duration::from_secs(15),async{loop{
        let remote=selected(&owner,"structure.message.receipts.read",&scope,json!({"message_id":sent[2]["message_id"]})).await;
        let local=ipc::call(endpoint,json!({"method":"inbox","options":options,"after":0,"limit":1})).await.unwrap();
        report_diagnostic=json!({"third_state":remote["deliveries"][0]["host_report"]["state"],"third_version":remote["deliveries"][0]["host_report"]["report_sequence"],"reporting_code":local["value"]["reporting_code"],"receiver_state":local["value"]["state"]});
        if remote["deliveries"][0]["host_report"]["state"]=="HOST_ACCEPTED"{
            assert!(remote["deliveries"][0]["application_consumed_at"].is_null());
            assert_eq!(remote["deliveries"][0]["host_report"]["model_response"],"NOT_ATTESTED");
            let first_report=selected(&owner,"structure.message.receipts.read",&scope,json!({"message_id":sent[0]["message_id"]})).await;
            if first_report["deliveries"][0]["host_report"]["state"]=="RESULT_UNKNOWN"{break;}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await.unwrap_or_else(|_|panic!("recipient host facts not reported to sender: {report_diagnostic}"));
    let remote = selected(
        &owner,
        "structure.message.receipts.read",
        &scope,
        json!({"message_id":sent[0]["message_id"]}),
    )
    .await;
    assert_eq!(
        remote["deliveries"][0]["host_report"]["state"],
        "RESULT_UNKNOWN"
    );
    let reported = ipc::call(
        endpoint,
        json!({"method":"delivery_status","options":options,"item":third}),
    )
    .await
    .unwrap();
    assert_eq!(reported["value"]["reporting"], "SERVICE_CONFIRMED");
    assert_eq!(service.counts().await["journal_reads"], 0);
    stop.cancel();
    server.await.unwrap().unwrap();
    // Move the complete encrypted inbox/host ledger, not just its cursor.
    // Original journal/key paths and physical host binding are retained.
    let transfer_config = worker_dir.path().join("transfer-runtime.json");
    crate::communication_host::write_private(
        &transfer_config,
        &serde_json::to_vec(&runtime).unwrap(),
    )
    .unwrap();
    let target = worker_dir.path().join("taken-over-engine");
    let executable =
        std::env::var("PEERWORK_PARTICIPANT_CLI").expect("rebuilt native CLI required");
    let copied = Command::new(&executable)
        .args([
            "runtime",
            "transfer-engine",
            transfer_config.to_str().unwrap(),
            "worker",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let copied: Value = serde_json::from_slice(&copied.stdout).unwrap();
    assert_eq!(copied["state"], "TRANSFER_READY", "{copied}");
    assert_eq!(
        ParticipantClient::open(worker_config.clone())
            .await
            .err()
            .unwrap()
            .code,
        "ENGINE_STATE_TRANSFERRED_USE_TARGET"
    );
    let moved: ipc::RuntimeConfig = serde_json::from_value(
        crate::communication_store::private_json(
            std::path::Path::new(copied["runtime_config_path"].as_str().unwrap()),
            65536,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        moved.engines[0].journal_path,
        Some(worker_config.journal_path.clone())
    );
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(moved, stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let endpoint = &ready.client_endpoints["worker"];
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = ipc::call(
                endpoint,
                json!({"method":"delivery_status","options":options,"item":third}),
            )
            .await
            .unwrap();
            if status["ok"] == true {
                assert_eq!(status["value"]["host"], "HOST_ACCEPTED");
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let retry = Command::new(&executable)
        .args([
            "runtime",
            "transfer-engine",
            transfer_config.to_str().unwrap(),
            "worker",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&retry.stdout).unwrap()["job_id"],
        copied["job_id"]
    );
    let original = ipc::call(
        endpoint,
        json!({"method":"delivery_status","options":options,"item":first}),
    )
    .await
    .unwrap();
    assert_eq!(original["value"]["host"], "RESULT_UNKNOWN");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer")))
            .count(),
        2,
        "restart cannot replay unknown or accepted calls"
    );
    let fresh = structure(
        &owner
            .invoke(
                native_message(
                    "post-transfer-message",
                    &scope,
                    &worker_box,
                    &owner_box,
                    &"C".repeat(43),
                    "Fresh E2EE mail after state handoff",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    let fresh_item = json!({"sequence":fresh["deliveries"][0]["sequence"],"delivery_id":fresh["deliveries"][0]["delivery_id"]});
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = ipc::call(
                endpoint,
                json!({"method":"delivery_status","options":options,"item":fresh_item}),
            )
            .await
            .unwrap();
            if status["value"]["host"] == "HOST_ACCEPTED" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    let opened=ipc::call(endpoint,json!({"method":"inbox","options":options,"after":fresh["deliveries"][0]["sequence"].as_u64().unwrap()-1,"limit":1})).await.unwrap();
    assert_eq!(
        opened["value"]["items"][0]["opened_message"]["text"],
        "Fresh E2EE mail after state handoff"
    );
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer")))
            .count(),
        3,
        "fresh unrelated mail progresses while the original unknown remains pinned"
    );
    assert_eq!(service.counts().await["journal_reads"], 0);
    stop.cancel();
    server.await.unwrap().unwrap();
    owner.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires synthetic PostgreSQL, real HTTP and synthetic existing host"]
async fn native_presence_selftests_empty_receiver_imports_authorized_keys_and_tracks_approval() {
    use crate::{
        communication_host::tests::CodexFixture,
        communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig},
        participant_dispatch::{HostConfig, HostSubscription},
    };
    let service = Service::start();
    let fixture = CodexFixture::start();
    let a = crate::test_support::protected_test_dir();
    let b = crate::test_support::protected_test_dir();
    let owner_config = configuration(a.path(), &service.origin);
    let worker_config = configuration(b.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    // A receive-only prerequisite may observe no head, but cannot publish one.
    let empty = mutate(
        &owner,
        "no-body-head",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"No implicit crypto mutations"}),
    )
    .await;
    let empty_scope = Scope {
        workspace_id: Some(empty["workspace_id"].as_str().unwrap().into()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &empty_scope, json!({})).await;
    let empty_box=mutate(&owner,"no-head-box","structure.communication.grant.set",&empty_scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let empty_options = WatchOptions {
        workspace_id: empty_scope.workspace_id.clone().unwrap(),
        mailbox_id: empty_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: empty_box["membership_id"].as_str().unwrap().into(),
        consumer_id: "no-head-program".into(),
        host_destination: None,
    };
    let mut empty_watch = owner.watch(empty_options.clone()).await.unwrap();
    let empty_snapshot = watch_until(&mut empty_watch, |s| {
        s.receiver_link_verified && s.presence["body_key"]["state"] == "NOT_REQUIRED"
    })
    .await;
    assert!(empty_snapshot.items.is_empty());
    assert_eq!(service.counts().await["key_epochs"], 0);
    owner.unwatch(&empty_options).await.unwrap();
    let created = mutate(
        &owner,
        "presence-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Current host and imported body key"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    mutate(
        &owner,
        "presence-key",
        "participant.keys.rotate",
        &scope,
        json!({}),
    )
    .await;
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let current_key = meta["content_key_head"]["key_id"].clone();
    let requested = worker
        .request(Invoke::new(
            "presence-request",
            "participant.access.request",
            scope.clone(),
            json!({"label":"Synthetic native recipient"}),
        ))
        .await
        .unwrap();
    mutate(&owner,"presence-approve","participant.access.approve",&scope,json!({"request_jws":requested["request_jws"],"follow_current_key":false,"deliver_content_keys":false})).await;
    let member = selected(&worker, "structure.workspace.get", &scope, json!({})).await;
    let owner_box=mutate(&owner,"presence-owner-mail","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&owner,"presence-worker-mail","structure.communication.grant.set",&scope,json!({"actor_id":worker.actor_id(),"membership_id":member["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    worker.close().await.unwrap();
    let options = WatchOptions {
        workspace_id: ws,
        mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        consumer_id: "presence-worker".into(),
        host_destination: None,
    };
    let runtime = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: b.path().join("runtime"),
        engines: vec![EngineConfig {
            name: "worker".into(),
            origin: worker_config.origin.clone(),
            expected_actor: worker_config.expected_actor.clone(),
            authority: None,
            identity_path: worker_config.identity_path.clone(),
            state_directory: worker_config.state_directory.clone(),
            journal_path: Some(worker_config.journal_path.clone()),
            allow_loopback_http: true,
            transport: worker_config.transport.clone(),
            max_inflight: 4,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
            migration_sources: Vec::new(),
        }],
        clients: vec![ClientConfig {
            name: "worker".into(),
            engine: "worker".into(),
            capability: Capability::owner(),
        }],
        hosts: vec![HostConfig {
            name: "existing-codex".into(),
            adapter: fixture.config(),
            subscriptions: vec![HostSubscription {
                client: "worker".into(),
                watch: options.clone(),
            }],
        }],
    };
    let before = service.counts().await;
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime, stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    async fn presence(
        owner: &ParticipantClient,
        scope: &Scope,
        actor: &str,
        condition: impl Fn(&Value) -> bool,
    ) -> Value {
        let mut diagnostic = json!({});
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let boxes = selected(
                    owner,
                    "structure.mailboxes.read",
                    scope,
                    json!({"actor_id":actor}),
                )
                .await;
                let view = &boxes["mailboxes"][0];
                diagnostic = view["presence"].clone();
                if condition(view) {
                    return view.clone();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("presence condition not reached: {diagnostic}"))
    }
    let missing = presence(&owner, &scope, &worker_config.expected_actor, |v| {
        v["presence"]["body_key"]["state"] == "MISSING" && v["presence"]["host"]["ready"] == true
    })
    .await;
    assert_eq!(missing["presence"]["reachability"], "UNCONFIRMED");
    assert_eq!(
        service.counts().await["events"],
        before["events"],
        "missing keys cannot trigger publication or grants"
    );
    // The Owner explicitly authorizes a fresh recipient-bound key delivery.
    // The resident Worker asks for approval without reopening its state or
    // manually accepting keys; its existing listener imports the result.
    let renewed=ipc::call(&ready.client_endpoints["worker"],json!({"method":"request","request":Invoke::new("key-delivery-request","participant.access.request",scope.clone(),json!({"label":"Authorized key continuation"}))})).await.unwrap();
    assert_eq!(renewed["ok"], true, "{renewed}");
    mutate(&owner,"presence-deliver","participant.access.approve",&scope,json!({"request_jws":renewed["value"]["request_jws"],"mode":"KEYS_ONLY","follow_current_key":true})).await;
    let delivered_events = service.counts().await["events"].clone();
    let qualified = presence(&owner, &scope, &worker_config.expected_actor, |v| {
        v["presence"]["reachability"] == "PATH_QUALIFIED"
    })
    .await;
    assert_eq!(qualified["presence"]["body_key"]["key_id"], current_key);
    assert_eq!(qualified["presence"]["host"]["mode"], "LIVE");
    assert_eq!(
        service.counts().await["events"],
        delivered_events,
        "startup self-test must not write probe messages or publish keys"
    );
    assert_eq!(
        service.counts().await["key_epochs"],
        1,
        "receiving cannot rotate the Owner-selected epoch"
    );
    assert!(!fixture
        .calls()
        .iter()
        .any(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer"))));
    fixture
        .approval
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let waiting = presence(&owner, &scope, &worker_config.expected_actor, |v| {
        v["presence"]["host"]["execution_state"] == "WAITING_APPROVAL"
    })
    .await;
    assert_eq!(waiting["presence"]["reachability"], "UNCONFIRMED");
    fixture
        .approval
        .store(false, std::sync::atomic::Ordering::SeqCst);
    presence(&owner, &scope, &worker_config.expected_actor, |v| {
        v["presence"]["reachability"] == "PATH_QUALIFIED"
    })
    .await;
    let sent = structure(
        &owner
            .invoke(
                native_message(
                    "presence-message",
                    &scope,
                    &worker_box,
                    &owner_box,
                    &"V".repeat(43),
                    "Automatically opened from an Owner-authorized delivery",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    let mut selected_options = options;
    selected_options.host_destination = qualified["destination_digest"].as_str().map(str::to_owned);
    let endpoint = &ready.client_endpoints["worker"];
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = ipc::call(
                endpoint,
                json!({"method":"inbox","options":selected_options,"after":0,"limit":32}),
            )
            .await
            .unwrap();
            if let Some(item) = page["value"]["items"].as_array().and_then(|v| v.first()) {
                assert_eq!(
                    item["opened_message"]["text"],
                    "Automatically opened from an Owner-authorized delivery"
                );
                let remote = selected(
                    &owner,
                    "structure.message.receipts.read",
                    &scope,
                    json!({"message_id":sent["message_id"]}),
                )
                .await;
                if remote["deliveries"][0]["host_report"]["state"] == "HOST_ACCEPTED" {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("authorized key import did not open and deliver native mail");
    assert_eq!(service.counts().await["journal_reads"], 0);
    stop.cancel();
    server.await.unwrap().unwrap();
    owner.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires synthetic PostgreSQL, real product HTTP and synthetic bridge protocol"]
async fn runtime_bridge_reconciles_only_original_bound_receipts_across_recipient_restart() {
    use crate::{
        communication_host::tests::BridgeFixture,
        communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig},
        participant_dispatch::{HostConfig, HostSubscription},
        participant_inbox::HostBinding,
    };
    use std::sync::atomic::Ordering;
    let service = Service::start();
    let bridge = BridgeFixture::start();
    let a = crate::test_support::protected_test_dir();
    let b = crate::test_support::protected_test_dir();
    let owner_config = configuration(a.path(), &service.origin);
    let worker_config = configuration(b.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let created = mutate(
        &owner,
        "bridge-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Original receipt recovery"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "bridge-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&owner.invoke(join, Duration::from_secs(5)).await.unwrap());
    let owner_box=mutate(&owner,"bridge-owner","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&owner,"bridge-worker","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&owner_config, &ws, &[51; 32], None);
    install_synthetic_key(&worker_config, &ws, &[51; 32], None);
    mutate(
        &owner,
        "bridge-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let mut sent = Vec::new();
    let mut items = Vec::new();
    for i in 0..2 {
        let result = structure(
            &owner
                .invoke(
                    native_message(
                        &format!("bridge-mail-{i}"),
                        &scope,
                        &worker_box,
                        &owner_box,
                        &"V".repeat(43),
                        &format!("original-mail-{i}"),
                    ),
                    Duration::from_secs(5),
                )
                .await
                .unwrap(),
        );
        let read = selected(
            &owner,
            "structure.message.receipts.read",
            &scope,
            json!({"message_id":result["message_id"]}),
        )
        .await;
        items.push(DeliveryReference {
            sequence: read["deliveries"][0]["sequence"].as_u64().unwrap(),
            delivery_id: read["deliveries"][0]["delivery_id"]
                .as_str()
                .unwrap()
                .into(),
        });
        sent.push(result);
    }
    let adapter = bridge.config();
    let destination = HostBinding::new(adapter["destination"].clone()).unwrap();
    let options = WatchOptions {
        workspace_id: ws,
        mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        consumer_id: "bridge-worker".into(),
        host_destination: Some(destination.digest),
    };
    let runtime = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: b.path().join("runtime"),
        engines: vec![EngineConfig {
            name: "worker".into(),
            origin: worker_config.origin.clone(),
            expected_actor: worker_config.expected_actor.clone(),
            authority: None,
            identity_path: worker_config.identity_path.clone(),
            state_directory: worker_config.state_directory.clone(),
            journal_path: Some(worker_config.journal_path.clone()),
            allow_loopback_http: true,
            transport: worker_config.transport.clone(),
            max_inflight: 4,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
            migration_sources: Vec::new(),
        }],
        clients: vec![ClientConfig {
            name: "worker".into(),
            engine: "worker".into(),
            capability: Capability::owner(),
        }],
        hosts: vec![HostConfig {
            name: "bridge-existing-session".into(),
            adapter,
            subscriptions: vec![HostSubscription {
                client: "worker".into(),
                watch: options.clone(),
            }],
        }],
    };
    async fn wait_host(
        endpoint: &std::path::Path,
        options: &WatchOptions,
        item: &DeliveryReference,
        state: &str,
    ) -> Value {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let value = ipc::call(
                    endpoint,
                    json!({"method":"delivery_status","options":options,"item":item}),
                )
                .await
                .unwrap();
                if value["value"]["host"] == state {
                    return value["value"].clone();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("host did not reach {state}"))
    }
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime.clone(), stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let original = wait_host(
        &ready.client_endpoints["worker"],
        &options,
        &items[0],
        "RESULT_UNKNOWN",
    )
    .await;
    // A malicious/mismatched receipt cannot release the original lane.
    bridge.receipt_state.store(4, Ordering::SeqCst);
    let seen = bridge
        .calls()
        .iter()
        .filter(|v| v["method"] == "receipt")
        .count();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if bridge
                .calls()
                .iter()
                .filter(|v| v["method"] == "receipt")
                .count()
                > seen
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let still = wait_host(
        &ready.client_endpoints["worker"],
        &options,
        &items[0],
        "RESULT_UNKNOWN",
    )
    .await;
    assert_eq!(still["call_id"], original["call_id"]);
    assert_eq!(
        bridge
            .calls()
            .iter()
            .filter(|v| v["method"] == "deliver")
            .count(),
        1
    );
    stop.cancel();
    server.await.unwrap().unwrap();
    bridge.receipt_state.store(0, Ordering::SeqCst);
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime, stop.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    let endpoint = &ready.client_endpoints["worker"];
    let restarted = wait_host(endpoint, &options, &items[0], "RESULT_UNKNOWN").await;
    assert_eq!(restarted["call_id"], original["call_id"]);
    bridge.receipt_state.store(1, Ordering::SeqCst);
    let queued = wait_host(endpoint, &options, &items[0], "HOST_QUEUED").await;
    assert_eq!(queued["call_id"], original["call_id"]);
    wait_host(endpoint, &options, &items[1], "HOST_ACCEPTED").await;
    bridge.receipt_state.store(2, Ordering::SeqCst);
    let accepted = wait_host(endpoint, &options, &items[0], "HOST_ACCEPTED").await;
    assert_eq!(accepted["call_id"], original["call_id"]);
    assert_eq!(accepted["frame_digest"], original["frame_digest"]);
    assert_eq!(accepted["model_response"], "NOT_ATTESTED");
    let states = accepted["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["state"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(
        states.contains(&"RESULT_UNKNOWN")
            && states.contains(&"HOST_QUEUED")
            && states.contains(&"HOST_ACCEPTED")
    );
    let calls = bridge.calls();
    assert_eq!(calls.iter().filter(|v| v["method"] == "deliver").count(), 2);
    let first = calls.iter().find(|v| v["method"] == "deliver").unwrap();
    assert!(calls
        .iter()
        .filter(
            |v| v["method"] == "receipt" && v["body"]["binding"]["call_id"] == original["call_id"]
        )
        .all(|v| v["body"]["binding"] == first["body"]["binding"]));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let read = selected(
                &owner,
                "structure.message.receipts.read",
                &scope,
                json!({"message_id":sent[0]["message_id"]}),
            )
            .await;
            if read["deliveries"][0]["host_report"]["state"] == "HOST_ACCEPTED" {
                assert!(read["deliveries"][0]["application_consumed_at"].is_null());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(service.counts().await["journal_reads"], 0);
    stop.cancel();
    server.await.unwrap().unwrap();
    owner.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires synthetic PostgreSQL, real product/native-bridge HTTP and synthetic host"]
async fn native_bridge_receives_genuine_verified_e2ee_mail_from_shared_runtime() {
    use crate::{
        communication_bridge::{self, BridgeConfig, BridgeGrant},
        communication_host::tests::CodexFixture,
        communication_runtime::{self as ipc, ClientConfig, EngineConfig, RuntimeConfig},
        participant_dispatch::{HostConfig, HostSubscription},
        participant_inbox::HostBinding,
    };
    let service = Service::start();
    let fixture = CodexFixture::start();
    let a = crate::test_support::protected_test_dir();
    let b = crate::test_support::protected_test_dir();
    let h = crate::test_support::protected_test_dir();
    let owner_config = configuration(a.path(), &service.origin);
    let worker_config = configuration(b.path(), &service.origin);
    let owner = ParticipantClient::open(owner_config.clone()).await.unwrap();
    let created = mutate(
        &owner,
        "native-bridge-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Native host-user bridge"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "native-bridge-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&owner.invoke(join, Duration::from_secs(5)).await.unwrap());
    let owner_box=mutate(&owner,"native-bridge-owner","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&owner,"native-bridge-worker","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&owner_config, &ws, &[57; 32], None);
    install_synthetic_key(&worker_config, &ws, &[57; 32], None);
    mutate(
        &owner,
        "native-bridge-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let sent = structure(
        &owner
            .invoke(
                native_message(
                    "native-bridge-mail",
                    &scope,
                    &worker_box,
                    &owner_box,
                    &"V".repeat(43),
                    "genuine encrypted native bridge payload",
                ),
                Duration::from_secs(5),
            )
            .await
            .unwrap(),
    );
    let worker_identity = KernelIdentity::open(&worker_config.identity_path).unwrap();
    let delivery = selected(
        &owner,
        "structure.message.receipts.read",
        &scope,
        json!({"message_id":sent["message_id"]}),
    )
    .await;
    let item = DeliveryReference {
        sequence: delivery["deliveries"][0]["sequence"].as_u64().unwrap(),
        delivery_id: delivery["deliveries"][0]["delivery_id"]
            .as_str()
            .unwrap()
            .into(),
    };
    fixture
        .approval
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let bridge_config = BridgeConfig {
        format: "peerwork.host-bridge.v1".into(),
        state_directory: h.path().join("host-bridge"),
        host: fixture.config(),
        bindings: vec![BridgeGrant {
            expected_origin: worker_config.origin.clone(),
            expected_actor: worker_config.expected_actor.clone(),
            expected_key_id: worker_identity.key_id().into(),
            namespace: "program:worker".into(),
            workspace_id: ws.clone(),
            mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
            membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        }],
    };
    let bridge_stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let bridge = tokio::spawn(communication_bridge::serve(
        bridge_config.clone(),
        bridge_stop.clone(),
        tx,
    ));
    let ready = rx.await.unwrap().unwrap();
    let destination = HostBinding::new(ready.adapter["destination"].clone()).unwrap();
    let options = WatchOptions {
        workspace_id: ws,
        mailbox_id: worker_box["mailbox_id"].as_str().unwrap().into(),
        membership_id: worker_box["membership_id"].as_str().unwrap().into(),
        consumer_id: "native-bridge-worker".into(),
        host_destination: Some(destination.digest),
    };
    let runtime = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: b.path().join("runtime"),
        engines: vec![EngineConfig {
            name: "worker".into(),
            origin: worker_config.origin.clone(),
            expected_actor: worker_config.expected_actor.clone(),
            authority: None,
            identity_path: worker_config.identity_path.clone(),
            state_directory: worker_config.state_directory.clone(),
            journal_path: Some(worker_config.journal_path.clone()),
            allow_loopback_http: true,
            transport: worker_config.transport.clone(),
            max_inflight: 4,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
            migration_sources: Vec::new(),
        }],
        clients: vec![ClientConfig {
            name: "worker".into(),
            engine: "worker".into(),
            capability: Capability::owner(),
        }],
        hosts: vec![HostConfig {
            name: "native-host-bridge".into(),
            adapter: ready.adapter,
            subscriptions: vec![HostSubscription {
                client: "worker".into(),
                watch: options.clone(),
            }],
        }],
    };
    let retired_adapter = runtime.hosts[0].adapter.clone();
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime.clone(), stop.clone(), tx));
    let runtime_ready = rx.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let page = ipc::call(
                &runtime_ready.client_endpoints["worker"],
                json!({"method":"inbox","options":options,"after":0,"limit":1}),
            )
            .await
            .unwrap();
            if page["value"]["presence"]["host"]["execution_state"] == "WAITING_APPROVAL" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let waiting = ipc::call(
        &runtime_ready.client_endpoints["worker"],
        json!({"method":"delivery_status","options":options,"item":item}),
    )
    .await
    .unwrap();
    assert!(
        waiting["value"]["call_id"].is_null(),
        "waiting approval must not begin an input attempt"
    );
    assert!(!fixture
        .calls()
        .iter()
        .any(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer"))));
    fixture
        .approval
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut diagnostic = json!({});
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let observed = selected(
                &owner,
                "structure.message.receipts.read",
                &scope,
                json!({"message_id":sent["message_id"]}),
            )
            .await;
            diagnostic = observed["deliveries"][0]["host_report"].clone();
            if diagnostic["state"] == "HOST_ACCEPTED" {
                assert!(observed["deliveries"][0]["application_consumed_at"].is_null());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("native bridge did not accept synthetic E2EE delivery: {diagnostic}")
    });
    let inputs = fixture
        .calls()
        .into_iter()
        .filter(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer")))
        .collect::<Vec<_>>();
    assert_eq!(inputs.len(), 1);
    assert!(inputs[0]["params"]["input"][0]["text"]
        .as_str()
        .unwrap()
        .contains("genuine encrypted native bridge payload"));
    assert_eq!(service.counts().await["journal_reads"], 0);
    // Explicit application consumption, not host ACK, enables reclamation.
    let consumed = ipc::call(
        &runtime_ready.client_endpoints["worker"],
        json!({"method":"consume","options":options,"items":[item]}),
    )
    .await
    .unwrap();
    assert!(consumed.get("error").is_none());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = ipc::call(
                &runtime_ready.client_endpoints["worker"],
                json!({"method":"delivery_status","options":options,"item":item}),
            )
            .await
            .unwrap();
            if status["value"]["host"] == "LOCAL_EVIDENCE_RETIRED" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let history = selected(
        &owner,
        "structure.message.receipts.read",
        &scope,
        json!({"message_id":sent["message_id"]}),
    )
    .await;
    assert_eq!(
        history["deliveries"][0]["host_report"]["state"],
        "HOST_ACCEPTED"
    );
    assert!(history["deliveries"][0]["application_consumed_at"].is_number());
    let rendered = inputs[0]["params"]["input"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let incoming: Value = serde_json::from_str(rendered.split_once('\n').unwrap().1).unwrap();
    let original_frame = json!({"format":"peerwork.host-frame.v1","message_id":peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(rendered.as_bytes())),"rendered_text":rendered,"incoming":incoming});
    assert_eq!(
        sha256_hex(original_frame.to_string().as_bytes()),
        diagnostic["frame_digest"]
    );
    let original_scope = diagnostic["scope"].clone();
    stop.cancel();
    server.await.unwrap().unwrap();
    bridge_stop.cancel();
    bridge.await.unwrap().unwrap();
    // A full bridge/runtime restart must retain the no-reinjection frontier.
    let bridge_stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let bridge = tokio::spawn(communication_bridge::serve(
        bridge_config,
        bridge_stop.clone(),
        tx,
    ));
    let again = rx.await.unwrap().unwrap();
    assert_eq!(again.adapter, retired_adapter);
    let stop = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(ipc::serve(runtime, stop.clone(), tx));
    let again = rx.await.unwrap().unwrap();
    let status = ipc::call(
        &again.client_endpoints["worker"],
        json!({"method":"delivery_status","options":options,"item":item}),
    )
    .await
    .unwrap();
    assert_eq!(status["value"]["host"], "LOCAL_EVIDENCE_RETIRED");
    let handle = tokio::runtime::Handle::current();
    let refusal = tokio::task::spawn_blocking(move || {
        let mut peer = crate::communication_host::Host::open(retired_adapter, handle).unwrap();
        let sent = peer.deliver(&original_scope, &original_frame);
        let observed = peer.reconcile(
            &original_scope,
            original_frame["message_id"].as_str().unwrap(),
            original_scope["frame_digest"].as_str().unwrap(),
        );
        (sent, observed)
    })
    .await
    .unwrap();
    assert_eq!(refusal.0.unwrap_err(), "HOST_EVIDENCE_RETIRED");
    assert_eq!(
        refusal.1.unwrap_err(),
        "HOST_EVIDENCE_RETIRED",
        "retired absence must never become a NOT_SENT proof"
    );
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|v| matches!(v["method"].as_str(), Some("turn/start" | "turn/steer")))
            .count(),
        1
    );
    stop.cancel();
    server.await.unwrap().unwrap();
    bridge_stop.cancel();
    bridge.await.unwrap().unwrap();
    owner.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires real PostgreSQL/HTTP synthetic service"]
async fn refused_busy_claim_preserves_original_selection_and_refuses_foreign_continuity() {
    async fn refused(watch: &mut ProgramWatch) -> WatchSnapshot {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let s = watch.next().await.unwrap();
                if matches!(
                    s.code.as_deref(),
                    Some("MAILBOX_RECEIVER_BUSY" | "MAILBOX_STATE_RECOVERY_REQUIRED")
                ) {
                    return s;
                }
                assert_ne!(s.state, "BLOCKED", "unexpected refusal: {s:?}");
            }
        })
        .await
        .expect("watch did not report original-custody refusal")
    }

    let service = Service::start();
    let directory = crate::test_support::protected_test_dir();
    let config = configuration(directory.path(), &service.origin);
    let owner = ParticipantClient::open(config.clone()).await.unwrap();
    let created = mutate(
        &owner,
        "busy-space",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Confirmed BUSY recovery"}),
    )
    .await;
    let ws = created["workspace_id"].as_str().unwrap().to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
    let mailbox=mutate(&owner,"busy-grant","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let options = WatchOptions {
        workspace_id: ws.clone(),
        mailbox_id: mailbox["mailbox_id"].as_str().unwrap().into(),
        membership_id: mailbox["membership_id"].as_str().unwrap().into(),
        consumer_id: "busy-program".into(),
        host_destination: None,
    };
    let destination = sha256_hex(
        json!([
            "peerwork.program-consumer.v1",
            owner.actor_id(),
            format!("{}/", service.origin),
            owner.namespace,
            options.consumer_id
        ])
        .to_string()
        .as_bytes(),
    );
    service
        .config(json!({"delay_action":"structure.mailbox.claim"}))
        .await;
    let mut watch = owner.watch(options.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        while service.counts().await["delayed"] != 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // A competing receiver wins after our inspect, before our frozen claim.
    let competitor=mutate(&owner,"busy-competitor","structure.mailbox.claim",&scope,json!({"mailbox_id":options.mailbox_id,"receiver_id":test_receiver("F"),"expected_epoch":null,"destination_digest":destination,"replace":false})).await["mailbox"].clone();
    selected(&owner,"structure.mailbox.pulse",&scope,json!({"mailbox_id":options.mailbox_id,"receiver_id":test_receiver("F"),"epoch":competitor["epoch"],"ready":false,"execution_state":"OFFLINE"})).await;
    service.config(json!({"release":true})).await;
    let busy = refused(&mut watch).await;
    assert!(!busy.receiver_link_verified);
    assert_eq!(
        service.counts().await["claim_commands"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "no new claim while another receiver's lease is live"
    );
    owner.close().await.unwrap();
    drop(watch);
    drop(owner);
    // Expiration does not transfer the competing receiver's uncertainty ledger.
    service.config(json!({"clock_offset_ms":20000})).await;
    let owner = ParticipantClient::open(config).await.unwrap();
    let mut watch = owner.watch(options.clone()).await.unwrap();
    let blocked = refused(&mut watch).await;
    assert_eq!(blocked.state, "BLOCKED");
    assert_eq!(
        blocked.code.as_deref(),
        Some("MAILBOX_STATE_RECOVERY_REQUIRED")
    );
    assert!(!blocked.receiver_link_verified);
    let current = selected(
        &owner,
        "structure.mailbox.get",
        &scope,
        json!({"mailbox_id":options.mailbox_id}),
    )
    .await;
    assert_eq!(current["mailbox"]["epoch"], 1);
    assert_eq!(current["mailbox"]["receiver_id"], test_receiver("F"));
    assert_eq!(
        service.counts().await["claim_commands"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "no fresh claim after expiry when continuity state belongs to another receiver"
    );
    owner.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires synthetic PostgreSQL, real product HTTP and rebuilt native CLI"]
async fn native_agent_cli_mcp_send_reply_and_cancel_preserve_one_engine_intent() {
    use crate::{
        agent_tools::{AgentProfile, AgentRequest, AgentTools, Contact, MailScope},
        communication_runtime::{self, ClientConfig, EngineConfig, RuntimeClient, RuntimeConfig},
    };
    use std::collections::BTreeMap;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let service = Service::start();
    let master_dir = crate::test_support::protected_test_dir();
    let worker_dir = crate::test_support::protected_test_dir();
    let runtime_dir = crate::test_support::protected_test_dir();
    let master_config = configuration(master_dir.path(), &service.origin);
    let worker_config = configuration(worker_dir.path(), &service.origin);
    let master = ParticipantClient::open(master_config.clone())
        .await
        .unwrap();
    let worker = ParticipantClient::open(worker_config.clone())
        .await
        .unwrap();
    let ws = mutate(
        &master,
        "tools-workspace",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Native Agent tools"}),
    )
    .await["workspace_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scope = Scope {
        workspace_id: Some(ws.clone()),
        ..Default::default()
    };
    let meta = selected(&master, "structure.workspace.get", &scope, json!({})).await;
    let mut join = Invoke::new(
        "tools-join",
        "structure.member.set",
        scope.clone(),
        json!({"actor_id":worker_config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
    );
    join.expected_workspace_revision = meta["workspace_revision"].as_u64();
    let joined = structure(&master.invoke(join, Duration::from_secs(5)).await.unwrap());
    let master_box=mutate(&master,"tools-master-grant","structure.communication.grant.set",&scope,json!({"actor_id":master_config.expected_actor,"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let worker_box=mutate(&master,"tools-worker-grant","structure.communication.grant.set",&scope,json!({"actor_id":worker_config.expected_actor,"membership_id":joined["membership_id"],"expected_revision":null,"send":true,"receive":true})).await["mailbox"].clone();
    let key = install_synthetic_key(&master_config, &ws, &[83; 32], None);
    install_synthetic_key(&worker_config, &ws, &[83; 32], None);
    mutate(
        &master,
        "tools-key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/protocol-role-bundle-v1.json"
    ))
    .unwrap();
    let package = mutate(
        &master,
        "tools-protocol-register",
        "structure.protocol.register",
        &scope,
        json!({"bundle":fixture["bundle"]}),
    )
    .await;
    let adopted=mutate(&master,"tools-protocol-adopt","structure.adopt",&scope,json!({"package_digest":package["package_digest"],"bootstrap_grant":{"actions":["claim"],"protocol_roles":["WORKER"]}})).await;
    let protocol_scope = Scope {
        workspace_id: Some(ws.clone()),
        instance_id: Some(adopted["instance_id"].as_str().unwrap().into()),
        protocol_digest: Some(adopted["protocol_digest"].as_str().unwrap().into()),
    };
    master.close().await.unwrap();
    worker.close().await.unwrap();
    fn engine(name: &str, c: &ParticipantConfig) -> EngineConfig {
        EngineConfig {
            name: name.into(),
            origin: c.origin.clone(),
            expected_actor: c.expected_actor.clone(),
            authority: c.authority.clone(),
            identity_path: c.identity_path.clone(),
            state_directory: c.state_directory.clone(),
            journal_path: Some(c.journal_path.clone()),
            allow_loopback_http: true,
            transport: c.transport.clone(),
            max_inflight: 4,
            max_pending: 32,
            max_stored_bytes: 32 * 1024 * 1024,
            migration_sources: Vec::new(),
        }
    }
    let mut cap = Capability::owner();
    cap.allow_root = false;
    cap.workspace_ids = Some([ws.clone()].into());
    cap.operations = [
        "structure.instance.get",
        "structure.record.get",
        "structure.records.read",
        "structure.action",
        "structure.protocol.resolve",
        "structure.protocol.resource.get",
        "structure.message.send",
        "structure.message.receipts.read",
        "structure.mailbox.get",
        "structure.mailbox.claim",
        "structure.mailbox.pulse",
        "structure.mailbox.ack",
        "structure.mailbox.inbox.read",
    ]
    .map(str::to_owned)
    .into();
    let cfg = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: runtime_dir.path().join("runtime"),
        engines: vec![
            engine("master", &master_config),
            engine("worker", &worker_config),
        ],
        clients: vec![
            ClientConfig {
                name: "master".into(),
                engine: "master".into(),
                capability: cap.clone(),
            },
            ClientConfig {
                name: "worker".into(),
                engine: "worker".into(),
                capability: cap,
            },
        ],
        hosts: Vec::new(),
    };
    let cancel = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let daemon = tokio::spawn(communication_runtime::serve(cfg, cancel.clone(), tx));
    let ready = rx.await.unwrap().unwrap();
    fn mail_scope(ws: &str, b: &Value) -> MailScope {
        MailScope {
            workspace_id: ws.into(),
            mailbox_id: b["mailbox_id"].as_str().unwrap().into(),
            membership_id: b["membership_id"].as_str().unwrap().into(),
        }
    }
    let master_scope = mail_scope(&ws, &master_box);
    let worker_scope = mail_scope(&ws, &worker_box);
    let master_profile = AgentProfile {
        format: "peerwork.agent-profile.v1".into(),
        endpoint_path: ready.client_endpoints["master"].clone(),
        expected_origin: service.origin.clone(),
        expected_actor: master_config.expected_actor.clone(),
        scopes: BTreeMap::from([("project".into(), master_scope.clone())]),
        contacts: BTreeMap::from([(
            "worker".into(),
            Contact {
                scope: "project".into(),
                recipient: peerwork_core::communication::MailboxAddress {
                    mailbox_id: worker_scope.mailbox_id.clone(),
                    membership_id: worker_scope.membership_id.clone(),
                },
            },
        )]),
        protocols: BTreeMap::from([("claim".into(), protocol_scope)]),
    };
    let worker_profile = AgentProfile {
        format: "peerwork.agent-profile.v1".into(),
        endpoint_path: ready.client_endpoints["worker"].clone(),
        expected_origin: service.origin.clone(),
        expected_actor: worker_config.expected_actor.clone(),
        scopes: BTreeMap::from([("project".into(), worker_scope.clone())]),
        contacts: BTreeMap::new(),
        protocols: BTreeMap::new(),
    };
    for (name, profile, s) in [
        ("master", &master_profile, &master_scope),
        ("worker", &worker_profile, &worker_scope),
    ] {
        let client = RuntimeClient::connect(
            ready.client_endpoints[name].clone(),
            &service.origin,
            &profile.expected_actor,
        )
        .await
        .unwrap();
        let options = WatchOptions {
            workspace_id: ws.clone(),
            mailbox_id: s.mailbox_id.clone(),
            membership_id: s.membership_id.clone(),
            consumer_id: name.into(),
            host_destination: None,
        };
        client
            .call(json!({"method":"watch","options":options}))
            .await
            .unwrap();
    }
    let master = AgentTools::open(master_profile.clone()).await.unwrap();
    let worker = AgentTools::open(worker_profile).await.unwrap();
    let role = master
        .call(AgentRequest::parse("protocol", json!({"protocol":"claim","role":"WORKER"})).unwrap())
        .await
        .unwrap();
    assert_eq!(role["runtime"]["role"], "WORKER");
    assert_eq!(
        role["resources"]["roles/worker.md"]["content"],
        fixture["bundle"]["resources"]["roles/worker.md"]["text"]
    );
    assert!(!role.to_string().contains("author_intent"));
    let action=master.call(AgentRequest::parse("act",json!({"protocol":"claim","operation_id":"tools-claim","action":"claim","structure":{"ttl_ms":100},"expected_revision":1,"wait_ms":5000})).unwrap()).await.unwrap();
    assert_eq!(action["state"], "ACCEPTED", "{action}");
    let current = master
        .call(AgentRequest::parse("read", json!({"protocol":"claim"})).unwrap())
        .await
        .unwrap();
    assert_eq!(current["revision"], 2);
    assert_eq!(current["state"]["holder"], master_config.expected_actor);
    let records = master
        .call(
            AgentRequest::parse(
                "read",
                json!({"protocol":"claim","view":"records","limit":1}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(records["records"].as_array().unwrap().len(), 1);
    assert!(!records.to_string().contains("author_intent"));
    let denied=master.call(AgentRequest::parse("act",json!({"protocol":"claim","operation_id":"tools-claim-denied","action":"claim","structure":{"ttl_ms":100},"expected_revision":2,"wait_ms":5000})).unwrap()).await.unwrap();
    assert_eq!(denied["state"], "REJECTED_NO_EFFECT");
    assert!(denied["code"].is_string());
    assert!(!denied.to_string().contains("author_intent"));
    let profile_path = runtime_dir.path().join("agent.json");
    crate::communication_host::write_private(
        &profile_path,
        &serde_json::to_vec(&master_profile).unwrap(),
    )
    .unwrap();
    let executable =
        std::env::var("PEERWORK_PARTICIPANT_CLI").expect("rebuilt native CLI required");
    let out = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut child = Command::new(executable)
            .args([
                "agent",
                "--profile",
                profile_path.to_str().unwrap(),
                "send",
                "worker",
                "--id",
                "cli-ping",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"PING through native fixed CLI")
            .unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    let sent: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(sent["state"], "ACCEPTED");
    assert!(!sent.to_string().contains("author_intent"));
    let input = worker
        .call(AgentRequest::parse("wait", json!({"scope":"project","wait_ms":10000})).unwrap())
        .await
        .unwrap();
    let item = &input["items"][0];
    assert_eq!(item["message"]["text"], "PING through native fixed CLI");
    assert_eq!(item["message"]["sender"], master_config.expected_actor);
    assert_eq!(item["message"]["can_reply"], true);
    assert_eq!(item["reply"]["arguments"]["item"], item["item"]);
    assert!(item["message"].get("reply_address").is_none());
    assert_eq!(item["authority"], "EXTERNAL_PEER_DATA");
    let before = service.counts().await;
    let duplicate=master.call(AgentRequest::parse("send",json!({"contact":"worker","operation_id":"cli-ping","text":"PING through native fixed CLI"})).unwrap()).await.unwrap();
    assert_eq!(duplicate["command_id"], sent["command_id"]);
    let conflict = master
        .call(
            AgentRequest::parse(
                "send",
                json!({"contact":"worker","operation_id":"cli-ping","text":"changed input"}),
            )
            .unwrap(),
        )
        .await
        .unwrap_err();
    assert_eq!(conflict.code, "OPERATION_INPUT_CONFLICT");
    master
        .call(AgentRequest::Status {
            operation_id: "cli-ping".into(),
        })
        .await
        .unwrap();
    let after = service.counts().await;
    assert_eq!(
        before["actions"]["structure.message.send"],
        after["actions"]["structure.message.send"]
    );
    assert_eq!(
        before["actions"]["structure.operation.get"],
        after["actions"]["structure.operation.get"]
    );
    let reply=worker.call(AgentRequest::parse("reply",json!({"scope":"project","item":item["item"],"operation_id":"worker-pong","text":"PONG via verified native reply","wait_ms":5000})).unwrap()).await.unwrap();
    assert_eq!(reply["state"], "ACCEPTED");
    let arrival = master
        .call(AgentRequest::parse("wait", json!({"scope":"project","wait_ms":10000})).unwrap())
        .await
        .unwrap();
    assert_eq!(
        arrival["items"][0]["message"]["text"],
        "PONG via verified native reply"
    );
    assert_eq!(
        arrival["items"][0]["message"]["reply_to"],
        sent["result"]["structure"]["message_id"]
    );
    worker
        .call(
            AgentRequest::parse("consume", json!({"scope":"project","items":[item["item"]]}))
                .unwrap(),
        )
        .await
        .unwrap();
    master
        .call(
            AgentRequest::parse(
                "consume",
                json!({"scope":"project","items":[arrival["items"][0]["item"]]}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let empty = master
        .call(AgentRequest::parse("wait", json!({"scope":"project","wait_ms":80})).unwrap())
        .await
        .unwrap();
    assert_eq!(empty["state"], "WAIT_EXPIRED");

    // Real MCP tool cancellation after the remote request arrived cannot cancel
    // durable engine work or generate a replacement operation/host input.
    let (server, client) = tokio::io::duplex(65536);
    let (sr, sw) = tokio::io::split(server);
    let (cr, mut cw) = tokio::io::split(client);
    let mut cr = tokio::io::BufReader::new(cr);
    let mcp = tokio::spawn(crate::agent_mcp::serve(
        master_profile,
        tokio::io::BufReader::new(sr),
        sw,
    ));
    service
        .config(json!({"delay_action":"structure.message.send"}))
        .await;
    let request = json!({"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"peerwork_send","arguments":{"contact":"worker","operation_id":"mcp-original-cancelled-wait","text":"Committed after observation cancellation","wait_ms":5000}}});
    cw.write_all(format!("{request}\n").as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if service.counts().await["delayed"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    cw.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":100}}\n").await.unwrap();
    cw.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"ping\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}\n").await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), cr.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 101);
    service.config(json!({"release":true})).await;
    let recovered = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let v = master
                .call(AgentRequest::Status {
                    operation_id: "mcp-original-cancelled-wait".into(),
                })
                .await
                .unwrap();
            if v["state"] == "ACCEPTED" {
                break v;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(recovered["effect_certainty"], "COMMITTED");
    let counts = service.counts().await;
    assert_eq!(counts["actions"]["structure.message.send"], 3);
    assert_eq!(counts["journal_reads"], 0);
    line.clear();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), cr.read_line(&mut line))
            .await
            .is_err(),
        "cancelled MCP request must have no later response"
    );
    drop(cw);
    drop(cr);
    mcp.await.unwrap().unwrap();
    cancel.cancel();
    daemon.await.unwrap().unwrap();
}
