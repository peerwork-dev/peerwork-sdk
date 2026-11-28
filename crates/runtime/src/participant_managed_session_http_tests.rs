use super::*;
use crate::{
    agent_lifecycle::Lifecycle,
    agent_tools::AgentRequest,
    communication_runtime as ipc,
    participant::http_tests::{
        configuration, install_synthetic_key, mutate, selected, structure, wait_terminal,
        RuntimeProcess, Service,
    },
    participant::{ParticipantClient, ParticipantConfig},
};
use std::time::Duration;

fn engine(handle: &str, config: &ParticipantConfig) -> ipc::EngineConfig {
    ipc::EngineConfig {
        name: handle.into(),
        origin: config.origin.clone(),
        expected_actor: config.expected_actor.clone(),
        identity_path: config.identity_path.clone(),
        state_directory: config.state_directory.clone(),
        journal_path: Some(config.journal_path.clone()),
        authority: None,
        allow_loopback_http: true,
        transport: config.transport.clone(),
        max_inflight: 8,
        max_pending: 16,
        max_stored_bytes: 8 * 1024 * 1024,
        migration_sources: vec![],
    }
}

async fn session(frontend: &Lifecycle, mode: &str, id: &str, peer: Option<&str>) -> Result<Value> {
    let mut request = json!({"mode":mode,"operation_id":id});
    if let Some(peer) = peer {
        request["peer"] = json!(peer);
    }
    frontend
        .call(AgentRequest::parse("session", json!({"request":request}))?)
        .await
}

async fn wait_state(
    frontend: &Lifecycle,
    mode: &str,
    id: &str,
    peer: Option<&str>,
    wanted: &str,
) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(65);
    let mut action = None;
    loop {
        let selection = match action.take() {
            Some(arguments) => {
                frontend
                    .call(AgentRequest::parse("session", arguments).unwrap())
                    .await
            }
            None => session(frontend, mode, id, peer).await,
        };
        let observation = match selection {
            Ok(value) if value["state"] == wanted => return value,
            Ok(value) => {
                if let Some(next) = value.get("next_action") {
                    assert_eq!(next["tool"], "peerwork_session");
                    assert_eq!(next["arguments"]["request"]["operation_id"], id);
                    action = Some(next["arguments"].clone());
                }
                value
            }
            Err(error)
                if error.operation_id.as_deref() == Some(id)
                    && error.phase == "LOCAL_IPC"
                    && matches!(error.code.as_str(), "IPC_DISCONNECTED" | "IPC_TIMEOUT") =>
            {
                let next = &error.details.as_ref().unwrap()["next_action"];
                assert_eq!(next["arguments"]["request"]["operation_id"], id);
                action = Some(next["arguments"].clone());
                json!({"error":error})
            }
            Err(error) => panic!("selected session operation {id}: {error:?}"),
        };
        assert!(
            tokio::time::Instant::now() < deadline,
            "last state for {id}: {observation}"
        );
        let delay = observation["retry_after_ms"].as_u64().unwrap_or(250);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

async fn signed_round(
    frontend: &Lifecycle,
    receiver: &RuntimeClient,
    watch: &Value,
    peer: &str,
    nonce: &str,
) {
    let sent = frontend
        .call(
            AgentRequest::parse(
                "send",
                json!({"to":peer,
        "operation_id":format!("ping-{nonce}"),"text":format!("PING {nonce}"),"wait_ms":5000}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sent["state"], "ACCEPTED", "{sent}");
    let id = &sent["result"]["structure"]["message_id"];
    assert!(id.is_string(), "{sent}");
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let page = receiver
                .call(json!({"method":"inbox","options":watch,"after":0,"limit":16}))
                .await
                .unwrap();
            if page["items"].as_array().unwrap().iter().any(|item| {
                let message = &item["opened_message"];
                message["reply_to"] == *id
                    && message["sender"] == peer
                    && message["text"] == format!("PONG {nonce}")
                    && message["assurance"] == "AUTHOR_SIGNATURE_AND_AEAD"
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("target harness did not send a correlated signed reply for {nonce}")
    });
    eprintln!("verified signed reply for {nonce}");
}

struct CodexCleanup(PathBuf);
impl Drop for CodexCleanup {
    fn drop(&mut self) {
        for id in ["implement"] {
            let socket = self
                .0
                .join(format!("s-{}", &sha256_hex(id.as_bytes())[..20]))
                .join("codex.sock");
            if let Ok(stream) =
                std::os::unix::net::UnixStream::connect(&socket).and_then(|stream| {
                    stream.set_nonblocking(true)?;
                    tokio::net::UnixStream::from_std(stream)
                })
            {
                if let Some(pid) = stream.peer_cred().ok().and_then(|value| value.pid()) {
                    // The test creates this private socket in its disposable fixture.
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated PostgreSQL and real Codex and OpenCode V2 test hosts"]
async fn independent_managed_codex_and_opencode_sessions() {
    independent_managed_sessions("opencode").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated PostgreSQL and real Codex and AGY ACP test hosts"]
async fn independent_managed_codex_and_agy_sessions() {
    independent_managed_sessions("agy").await;
}

async fn independent_managed_sessions(reviewer_harness: &str) {
    use std::path::PathBuf;
    let root = crate::test_support::protected_test_dir();
    let service = Service::start();
    let handles = ["coordinator", "builder", "reviewer"];
    let configs = handles.map(|handle| {
        let directory = root.path().join(handle);
        crate::onboarding_files::directory(&directory, true).unwrap();
        let mut config = configuration(&directory, &service.origin);
        config.transport.request_timeout_ms = 15_000;
        config
    });
    let author = ParticipantClient::open(configs[0].clone()).await.unwrap();
    eprintln!("creating synthetic Space");
    let workspace = mutate(
        &author,
        "create",
        "structure.workspace.create",
        &Scope::default(),
        json!({"name":"Synthetic owned sessions"}),
    )
    .await["workspace_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let scope = Scope {
        workspace_id: Some(workspace.clone()),
        ..Default::default()
    };
    for config in &configs {
        eprintln!("enrolling a synthetic Peer");
        let current = selected(&author, "structure.workspace.get", &scope, json!({})).await;
        let membership = if config.expected_actor == author.actor_id() {
            current["membership"]["membership_id"].clone()
        } else {
            let mut join = Invoke::new(
                format!("join-{}", config.expected_actor),
                "structure.member.set",
                scope.clone(),
                json!({"actor_id":config.expected_actor,"state":"ACTIVE","expected_membership_id":null}),
            );
            join.expected_workspace_revision = current["workspace_revision"].as_u64();
            let id = join.operation_id.clone();
            let accepted = author.invoke(join, Duration::from_secs(5)).await.unwrap();
            let outcome = if accepted.is_terminal() {
                accepted
            } else {
                wait_terminal(&author, &id).await
            };
            structure(&outcome)["membership_id"].clone()
        };
        mutate(&author,&format!("mail-{}", config.expected_actor),"structure.communication.grant.set",&scope,
            json!({"actor_id":config.expected_actor,"membership_id":membership,"expected_revision":null,
                "send":true,"receive":true})).await;
    }
    let seed = [81_u8; 32];
    let key = install_synthetic_key(&configs[0], &workspace, &seed, None);
    mutate(
        &author,
        "key",
        "structure.content-key.set",
        &scope,
        json!({"key_id":key,"expected_epoch":0,"expected_head_revision":null}),
    )
    .await;
    author.close().await.unwrap();
    // The synthetic key is shared through TEST setup rather than exercising a
    // separate membership/key onboarding workflow in this lifecycle test.
    for config in &configs[1..] {
        install_synthetic_key(config, &workspace, &seed, None);
    }

    let runtime = ipc::RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: root.path().join("runtime"),
        engines: handles
            .iter()
            .zip(&configs)
            .map(|(handle, c)| engine(handle, c))
            .collect(),
        clients: handles
            .iter()
            .map(|handle| ipc::ClientConfig {
                name: (*handle).into(),
                engine: (*handle).into(),
                capability: Capability::owner(),
            })
            .collect(),
        hosts: Vec::new(),
    };
    let config_path = root.path().join("runtime.json");
    crate::communication_host::write_private(&config_path, &serde_json::to_vec(&runtime).unwrap())
        .unwrap();
    let mut process = RuntimeProcess::start(&config_path);
    let ready = &process.ready;

    let location = root.path().join("connect");
    let _cleanup = CodexCleanup(location.clone());
    let codex = root.path().join("project-codex");
    crate::onboarding_files::directory(&codex, true).unwrap();
    let (reviewer_project, reviewer_slot, review_nonces, review_stop) = if reviewer_harness == "agy" {
        (
            PathBuf::from(std::env::var_os("PEERWORK_TEST_AGY_PROJECT").unwrap()),
            json!({"harness":"agy","executable":std::env::var("PEERWORK_TEST_AGY_EXECUTABLE").unwrap(),
                "conversation_id":std::env::var("PEERWORK_TEST_AGY_CONVERSATION").unwrap()}),
            ["AGY-1", "AGY-2"],
            "AGY_RECEIVING_ROUTE_RETIRED",
        )
    } else {
        (
            PathBuf::from(std::env::var_os("PEERWORK_TEST_OPENCODE_PROJECT").unwrap()),
            json!({"harness":"opencode","service_file":std::env::var("PEERWORK_TEST_OPENCODE_SERVICE").unwrap()}),
            ["OPEN-1", "OPEN-2"],
            "OPENCODE_RECEIVING_ROUTE_RETIRED",
        )
    };
    let cli = PathBuf::from(std::env::var_os("PEERWORK_PARTICIPANT_CLI").unwrap());
    {
        let mut registry = Connect::open(&location).unwrap();
        for (handle, config) in handles.iter().zip(&configs) {
            registry
                .register(
                    handle,
                    Registration {
                        origin: service.origin.clone(),
                        actor_id: config.expected_actor.clone(),
                        endpoint_path: ready.client_endpoints[*handle].clone(),
                    },
                )
                .await
                .unwrap();
            registry
                .registry
                .local_runtime_admins
                .insert((*handle).into(), ready.admin_endpoint.clone());
            registry.save().unwrap();
            let request: ConnectRequest = serde_json::from_value(
                json!({"setup_id":format!("start-{handle}"),"participant":handle,
                "workspace_id":workspace,"send":true,"receive":true,"require_body_keys":true,"receive_mode":"INBOX"}),
            )
            .unwrap();
            let mut configured = registry.run_agent(request.clone()).await.unwrap();
            if configured["state"] != "LOCAL_CONFIGURED" {
                assert_eq!(
                    configured["blocker"]["stage"], "RECEIVING_SELF_TEST",
                    "{configured}"
                );
                let profile = registry
                    .profile_for_scope(Some(handle), Some(&workspace))
                    .unwrap()
                    .unwrap();
                let receiver = RuntimeClient::connect(
                    profile.receive_endpoint_path.unwrap(),
                    &service.origin,
                    &config.expected_actor,
                )
                .await
                .unwrap();
                let bindings = receiver.call(json!({"method":"bindings"})).await.unwrap();
                let watch = &bindings[0];
                assert_eq!(watch["workspace_id"], workspace);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(75);
                loop {
                    let inbox = receiver
                        .call(json!({"method":"inbox","options":watch,"after":0,"limit":1}))
                        .await
                        .unwrap();
                    if inbox["receiver_link_verified"] == true {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        let counts = service.counts().await;
                        panic!(
                            "{handle}: {} / {}; fixture actions: {}; streams: {}",
                            inbox["state"],
                            inbox["code"],
                            counts["actions"],
                            counts["native_streams"]
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                configured = registry.run_agent(request).await.unwrap();
            }
            assert_eq!(
                configured["state"], "LOCAL_CONFIGURED",
                "{handle}: {configured}"
            );
            eprintln!("verified native inbox for {handle}");
        }
        for (handle, harness, project) in [
            ("builder", "codex", codex.clone()),
            ("reviewer", reviewer_harness, reviewer_project),
        ] {
            let installed = registry
                .install(
                    handle,
                    &workspace,
                    install::Installation {
                        host: harness.into(),
                        project,
                        executable: cli.clone(),
                    },
                )
                .unwrap();
            if harness == "codex" {
                use std::io::Write;
                let name = installed["server_name"].as_str().unwrap();
                let home = PathBuf::from(std::env::var_os("PEERWORK_TEST_CODEX_HOME").unwrap());
                assert_eq!(
                    std::env::var_os("CODEX_HOME").as_deref(),
                    Some(home.as_os_str())
                );
                // The TEST operator authorizes exactly its synthetic reply.
                // Managed launch must preserve this host tool approval policy.
                let mut config = std::fs::OpenOptions::new()
                    .append(true)
                    .open(home.join("config.toml"))
                    .unwrap();
                writeln!(
                    config,
                    "\n[mcp_servers.{name}.tools.peerwork_reply]\napproval_mode = \"approve\""
                )
                .unwrap();
            }
        }
        registry.private_directory.replace_private(POLICY,None,&serde_json::to_vec(&json!({
            "format":"peerwork.session-launch.v1","controller":"coordinator","workspace_id":workspace,
            "peers":{"builder":{"harness":"codex"},
                     "reviewer":reviewer_slot}
        })).unwrap()).unwrap();
    }
    let frontend = || {
        Lifecycle::local(
            location.clone(),
            Some("coordinator".into()),
            Some(workspace.clone()),
        )
    };
    let a = frontend();
    let sibling = Lifecycle::local(
        location.clone(),
        Some("reviewer".into()),
        Some(workspace.clone()),
    );
    let catalog = a.catalog().unwrap();
    let launch = catalog
        .iter()
        .find(|tool| tool["name"] == "peerwork_session")
        .unwrap();
    assert_eq!(
        launch["inputSchema"]["properties"]["request"]["oneOf"][0]["properties"]["peer"]["enum"],
        json!(["builder", "reviewer"])
    );
    assert!(!sibling
        .catalog()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "peerwork_session"));
    assert_eq!(
        session(&sibling, "start", "unapproved", Some("builder"))
            .await
            .unwrap_err()
            .code,
        "SESSION_CONTROLLER_NOT_AUTHORIZED"
    );
    let original = a.call(AgentRequest::Context).await.unwrap();
    let c = wait_state(&a, "start", "review", Some("reviewer"), "READY").await;
    let b = wait_state(&a, "start", "implement", Some("builder"), "READY").await;
    assert_eq!(
        session(&a, "start", "implement", Some("reviewer"))
            .await
            .unwrap_err()
            .code,
        "SESSION_OPERATION_ID_CONFLICT"
    );
    let duplicate = session(&a, "start", "double", Some("builder"))
        .await
        .unwrap_err();
    assert_eq!(duplicate.code, "SESSION_PEER_ALREADY_MANAGED");
    let details = duplicate.details.unwrap();
    assert_eq!(details["original_launch_id"], "implement");
    assert_eq!(
        details["next_action"],
        json!({
            "tool":"peerwork_session","arguments":{"request":{"mode":"status","operation_id":"implement"}}
        })
    );
    assert_eq!(b["automatic_receiving"], "VERIFIED");
    assert_eq!(b["model_response"], "NOT_ATTESTED");
    let rebound = frontend();
    for (id, expected) in [("implement", &b), ("review", &c)] {
        assert_eq!(
            session(&rebound, "status", id, None).await.unwrap()["session"],
            expected["session"]
        );
    }
    let current = a.call(AgentRequest::Context).await.unwrap();
    assert_eq!(current["actor_id"], original["actor_id"]);
    assert_eq!(current["bindings"], original["bindings"]);
    {
        let registry = Connect::inspect(&location).unwrap();
        let original_profile = registry
            .profile_for_scope(Some("coordinator"), Some(&workspace))
            .unwrap()
            .unwrap();
        let receiver = RuntimeClient::connect(
            original_profile.receive_endpoint_path.unwrap(),
            &service.origin,
            &configs[0].expected_actor,
        )
        .await
        .unwrap();
        let watches = receiver.call(json!({"method":"bindings"})).await.unwrap();
        let watch = &watches[0];
        assert_eq!(watch["workspace_id"], workspace);
        tokio::join!(
            signed_round(
                &rebound,
                &receiver,
                watch,
                &configs[1].expected_actor,
                "HANDOFF-1"
            ),
            signed_round(
                &rebound,
                &receiver,
                watch,
                &configs[2].expected_actor,
                review_nonces[0]
            ),
        );
        let stopped = wait_state(&rebound, "stop", "implement", None, "STOPPED").await;
        assert_eq!(stopped["stop_effect"], "DEDICATED_CODEX_HOST_EXITED");
        assert_eq!(
            session(&rebound, "start", "implement", Some("builder"))
                .await
                .unwrap()["state"],
            "STOPPED"
        );
        assert_eq!(
            session(&rebound, "status", "review", None).await.unwrap()["state"],
            "READY"
        );
        signed_round(
            &rebound,
            &receiver,
            watch,
            &configs[2].expected_actor,
            review_nonces[1],
        )
        .await;
    }
    let stopped = wait_state(&rebound, "stop", "review", None, "STOPPED").await;
    assert_eq!(stopped["stop_effect"], review_stop);
    process.stop_gracefully().await;
}
