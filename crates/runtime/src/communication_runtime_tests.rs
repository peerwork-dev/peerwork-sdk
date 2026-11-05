use super::*;
use crate::kernel_identity::KernelIdentity;

fn config(directory: &Path) -> RuntimeConfig {
    let identity_path = directory.join("identity");
    let identity = KernelIdentity::create(&identity_path).unwrap();
    let mut reader = Capability::owner();
    reader.operations = ["structure.workspace.get".into()].into();
    reader.allow_root = false;
    reader.workspace_ids = Some(["allowed".into()].into());
    RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        hosts: Vec::new(),
        state_directory: directory.join("runtime"),
        engines: vec![EngineConfig {
            authority: None,
            migration_sources: Vec::new(),
            name: "one-identity".into(),
            origin: "http://127.0.0.1:1".into(),
            expected_actor: identity.actor_id().into(),
            identity_path,
            state_directory: directory.join("engine"),
            journal_path: None,
            allow_loopback_http: true,
            transport: Default::default(),
            max_inflight: 1,
            max_pending: 2,
            max_stored_bytes: 1024 * 1024,
        }],
        clients: vec![
            ClientConfig {
                name: "creator".into(),
                engine: "one-identity".into(),
                capability: Capability::owner(),
            },
            ClientConfig {
                name: "reader".into(),
                engine: "one-identity".into(),
                capability: reader,
            },
        ],
    }
}
async fn start(
    config: RuntimeConfig,
) -> (
    RuntimeReady,
    KernelCancellationToken,
    tokio::task::JoinHandle<Result<()>>,
) {
    let cancel = KernelCancellationToken::new();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(serve(config, cancel.clone(), tx));
    let ready = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    (ready, cancel, task)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback IPC permission"]
async fn derived_clients_reuse_authority_namespace_and_survive_restart_without_engine_reload() {
    let temp = crate::test_support::protected_test_dir();
    let options = config(temp.path());
    let (ready, cancel, task) = start(options.clone()).await;
    let parent = &ready.client_endpoints["reader"];
    let cap = options.clients[1].capability.clone();
    let request = json!({"method":"derive","name":"role-a","capability":cap});
    let first = call(parent, request.clone()).await.unwrap();
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(first["value"]["engine_restarted"], false);
    let path = PathBuf::from(first["value"]["endpoint_path"].as_str().unwrap());
    let original = std::fs::read(&path).unwrap();
    let again = call(parent, request.clone()).await.unwrap();
    assert_eq!(again["value"], first["value"]);
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let escalation = call(
        parent,
        json!({"method":"derive","name":"bad","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    assert_eq!(escalation["error"]["code"], "CAPABILITY_ESCALATION");
    assert_eq!(
        call(&path, json!({"method":"stop"})).await.unwrap()["error"]["code"],
        "CLIENT_REQUEST_INVALID"
    );
    assert_eq!(
        call(&path, json!({"method":"capabilities"})).await.unwrap()["value"]["capability"],
        serde_json::to_value(&cap).unwrap()
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        call(parent, request.clone()).await.unwrap()["value"],
        first["value"]
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original,
        "repair must not rotate live credentials"
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (ready, cancel, task) = start(options.clone()).await;
    let restored = call(&ready.client_endpoints["reader"], request)
        .await
        .unwrap();
    assert_eq!(
        restored["value"]["endpoint_path"],
        first["value"]["endpoint_path"]
    );
    assert_eq!(
        call(&path, json!({"method":"capabilities"})).await.unwrap()["value"]["capability"],
        serde_json::to_value(cap).unwrap()
    );
    let old_token = temp.path().join("copied-restricted-endpoint.json");
    write_private(&old_token, &std::fs::read(&path).unwrap()).unwrap();
    let nested = call(
        &path,
        json!({"method":"derive","name":"nested","capability":options.clients[1].capability}),
    )
    .await
    .unwrap();
    let nested_path = PathBuf::from(nested["value"]["endpoint_path"].as_str().unwrap());
    let revoked=call(&ready.client_endpoints["reader"],json!({"method":"revoke_derived","name":"role-a","expected_binding":restored["value"]["binding_version"]})).await.unwrap();
    assert_eq!(revoked["value"]["count"], 2, "{revoked}");
    assert!(!path.exists());
    assert!(!nested_path.exists());
    assert!(matches!(
        call(&old_token, json!({"method":"capabilities"}))
            .await
            .unwrap_err()
            .code
            .as_str(),
        "IPC_UNAUTHORIZED" | "IPC_DISCONNECTED"
    ));
    assert_eq!(call(&ready.client_endpoints["reader"],json!({"method":"revoke_derived","name":"role-a","expected_binding":restored["value"]["binding_version"]})).await.unwrap()["value"]["count"],0);
    cancel.cancel();
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn framing_is_bounded_and_preserves_multiple_messages() {
    let (input, mut output) = tokio::io::duplex(64);
    let mut input = BufReader::new(input);
    let task = tokio::spawn(async move {
        output
            .write_all(b"{\"one\":1}\n{\"two\":2}\n")
            .await
            .unwrap();
    });
    assert_eq!(
        read_frame(&mut input, 64).await.unwrap().unwrap(),
        b"{\"one\":1}\n"
    );
    assert_eq!(
        read_frame(&mut input, 64).await.unwrap().unwrap(),
        b"{\"two\":2}\n"
    );
    task.await.unwrap();
    assert!(read_frame(&mut input, 64).await.unwrap().is_none());
    let (input, mut output) = tokio::io::duplex(64);
    let mut input = BufReader::new(input);
    output.write_all(b"123456789").await.unwrap();
    assert_eq!(
        read_frame(&mut input, 8).await.unwrap_err().code,
        "IPC_FRAME_TOO_LARGE"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback IPC permission"]
async fn authenticated_local_client_keeps_small_frames_immediate() {
    let temp = crate::test_support::protected_test_dir();
    let options = config(temp.path());
    let (ready, cancel, task) = start(options.clone()).await;
    let endpoint = load_endpoint(&ready.client_endpoints["reader"]).unwrap();
    let mut stream = BufReader::new(TcpStream::connect(endpoint.address).await.unwrap());
    let auth = client_handshake(&mut stream, &endpoint.token)
        .await
        .unwrap();
    // Socket policy is deterministic across supported OSes; wall-clock timing
    // would turn scheduler contention into a flaky transport regression.
    assert!(stream.get_ref().nodelay().unwrap());
    let id = random_token().unwrap();
    let (wire, request) = encode_request(&auth, &id, json!({"method":"capabilities"})).unwrap();
    write_frame(stream.get_mut(), &wire).await.unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame(&mut stream, MAX_WIRE_RESPONSE),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let verified = decode_response(&auth, &id, &request, &response).unwrap();
    assert_eq!(verified["ok"], true);
    assert_eq!(
        verified["value"]["actor_id"],
        options.engines[0].expected_actor
    );
    assert_eq!(verified["value"]["admin"], false);
    drop(stream);
    cancel.cancel();
    task.await.unwrap().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback IPC permission"]
async fn scoped_clients_share_engine_but_not_administration_or_operations() {
    let temp = crate::test_support::protected_test_dir();
    let options = config(temp.path());
    let (ready, cancel, task) = start(options.clone()).await;
    let creator = &ready.client_endpoints["creator"];
    let reader = &ready.client_endpoints["reader"];
    let first: Endpoint = serde_json::from_value(private_json(reader, 4096).unwrap()).unwrap();
    let mut unauthenticated = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        unauthenticated.push(TcpStream::connect(first.address).await.unwrap());
    }
    let reachable = tokio::time::timeout(
        Duration::from_secs(5),
        call(reader, json!({"method":"capabilities"})),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        reachable["ok"], true,
        "empty local connections must expire promptly"
    );
    drop(unauthenticated);
    assert_eq!(ready.state, "LOCAL_READY");
    let cap = call(reader, json!({"method":"capabilities"}))
        .await
        .unwrap();
    assert_eq!(cap["value"]["admin"], false);
    assert_eq!(
        call(reader, json!({"method":"stop"})).await.unwrap()["error"]["code"],
        "CLIENT_REQUEST_INVALID"
    );
    assert_eq!(
        call(reader, json!({"method":"capabilities","profile":"creator"}))
            .await
            .unwrap()["error"]["code"],
        "CLIENT_REQUEST_INVALID"
    );
    let request = Invoke::new(
        "first",
        "structure.workspace.create",
        Default::default(),
        json!({"name":"Synthetic admission"}),
    );
    assert_eq!(
        call(
            reader,
            json!({"method":"invoke","request":request,"wait_ms":0})
        )
        .await
        .unwrap()["error"]["code"],
        "LOCAL_SCOPE_DENIED"
    );
    let admitted = call(
        creator,
        json!({"method":"invoke","request":request,"wait_ms":0}),
    )
    .await
    .unwrap();
    assert_eq!(admitted["ok"], true);
    assert_eq!(admitted["value"]["operation_id"], "first");
    let result=call(creator,json!({"method":"operation_result","operation_id":"missing-original","selection":{"limit":1024}})).await.unwrap();
    assert_eq!(result["error"]["code"], "OPERATION_NOT_FOUND");
    assert_eq!(result["error"]["effect_certainty"], "UNKNOWN");
    assert_eq!(
        call(
            reader,
            json!({"method":"operation_result","operation_id":"first","selection":{"limit":1024}})
        )
        .await
        .unwrap()["error"]["code"],
        "OPERATION_NOT_FOUND"
    );
    assert_eq!(
        call(reader, json!({"method":"operation","operation_id":"first"}))
            .await
            .unwrap()["error"]["code"],
        "OPERATION_NOT_FOUND"
    );
    let admin = call(&ready.admin_endpoint, json!({"method":"status"}))
        .await
        .unwrap();
    assert_eq!(admin["value"]["engines"].as_array().unwrap().len(), 1);
    assert_eq!(admin["value"]["network_or_host_readiness"], "NOT_ATTESTED");
    let old: Endpoint = serde_json::from_value(private_json(creator, 4096).unwrap()).unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
    assert!(!creator.exists());
    assert!(!ready.admin_endpoint.exists());
    let (ready, _cancel, task) = start(options).await;
    let current: Endpoint =
        serde_json::from_value(private_json(&ready.client_endpoints["creator"], 4096).unwrap())
            .unwrap();
    assert!(!equal(&old.token, &current.token));
    let mut stream = BufReader::new(TcpStream::connect(current.address).await.unwrap());
    assert!(
        client_handshake(&mut stream, &old.token).await.is_err(),
        "a retired credential cannot authenticate the new runtime"
    );
    let recovered = call(
        &ready.client_endpoints["creator"],
        json!({"method":"operation","operation_id":"first"}),
    )
    .await
    .unwrap();
    assert_eq!(recovered["value"]["operation_id"], "first");
    assert_eq!(
        call(&ready.admin_endpoint, json!({"method":"stop"}))
            .await
            .unwrap()["value"]["state"],
        "STOPPING"
    );
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn request_enum_is_the_single_catalog_and_rejects_extra_authority() {
    let options = json!({"workspace_id":"w".repeat(43),"mailbox_id":"m".repeat(43),"membership_id":"g".repeat(43),"consumer_id":"worker"});
    let valid = json!({"method":"delivery_status","options":options,"item":{"sequence":1,"delivery_id":"d".repeat(43)}});
    assert!(ClientRequest::parse(valid.clone()).is_ok());
    let mut extra = valid;
    extra["profile"] = json!("another-identity");
    assert!(ClientRequest::parse(extra).is_err());
    assert!(
        ClientRequest::parse(json!({"method":"capabilities","identity_path":"/other"})).is_err()
    );
    assert!(ClientRequest::parse(json!({"method":"host_finish","call_id":"untrusted"})).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local loopback IPC sockets"]
async fn fake_runtime_cannot_read_private_requests_or_forge_peer_challenge() {
    let directory = crate::test_support::protected_test_dir();
    let file = directory.path().join("client.json");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let credential = "K".repeat(43);
    endpoint(&file, listener.local_addr().unwrap(), &credential, "CLIENT").unwrap();
    let captured = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let hello = read_frame(&mut stream, 4096).await.unwrap().unwrap();
        let text = std::str::from_utf8(&hello).unwrap();
        assert!(!text.contains(&credential));
        assert!(!text.contains("private_rpc_request_body"));
        let parsed: Value = serde_json::from_slice(&hello).unwrap();
        assert_eq!(parsed["format"], HELLO_FORMAT);
        write_frame(
            stream.get_mut(),
            &json!({"format":CHALLENGE_FORMAT,"payload":"forged ACK"}),
        )
        .await
        .unwrap();
        let next = tokio::time::timeout(
            Duration::from_secs(2),
            read_frame(&mut stream, MAX_WIRE_REQUEST),
        )
        .await;
        assert!(
            matches!(next, Ok(Ok(None)) | Ok(Err(_))),
            "private request must not follow an unauthenticated peer"
        );
    });
    let value = call(
        &file,
        json!({"method":"invoke","request":{"secret":"private_rpc_request_body"}}),
    )
    .await
    .unwrap_err();
    assert_eq!(value.code, "IPC_PEER_UNVERIFIED");
    assert_eq!(value.effect_certainty, "UNKNOWN");
    captured.await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local loopback IPC sockets"]
async fn encrypted_rpc_replay_is_rejected_after_completion_and_on_another_connection() {
    let directory = crate::test_support::protected_test_dir();
    let (ready, cancel, task) = start(config(directory.path())).await;
    let selected: Endpoint =
        serde_json::from_value(private_json(&ready.client_endpoints["reader"], 4096).unwrap())
            .unwrap();
    let mut first = BufReader::new(TcpStream::connect(selected.address).await.unwrap());
    let auth = client_handshake(&mut first, &selected.token).await.unwrap();
    let (frame, wire) =
        encode_request(&auth, "request-one", json!({"method":"capabilities"})).unwrap();
    write_frame(first.get_mut(), &frame).await.unwrap();
    let reply = read_frame(&mut first, MAX_WIRE_RESPONSE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_response(&auth, "request-one", &wire, &reply).unwrap()["ok"],
        true
    );
    let mut other = BufReader::new(TcpStream::connect(selected.address).await.unwrap());
    client_handshake(&mut other, &selected.token).await.unwrap();
    write_frame(other.get_mut(), &frame).await.unwrap();
    assert!(
        matches!(
            read_frame(&mut other, MAX_WIRE_RESPONSE).await,
            Ok(None) | Err(_)
        ),
        "a previous connection's packet cannot authenticate"
    );
    write_frame(first.get_mut(), &frame).await.unwrap();
    assert!(
        matches!(
            read_frame(&mut first, MAX_WIRE_RESPONSE).await,
            Ok(None) | Err(_)
        ),
        "completed request IDs cannot execute twice on a live connection"
    );
    assert_eq!(
        call(
            &ready.client_endpoints["reader"],
            json!({"method":"capabilities"})
        )
        .await
        .unwrap()["ok"],
        true
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local loopback IPC sockets"]
async fn knowing_key_identifier_without_its_key_cannot_hold_runtime_slots() {
    let directory = crate::test_support::protected_test_dir();
    let (ready, cancel, task) = start(config(directory.path())).await;
    let selected: Endpoint =
        serde_json::from_value(private_json(&ready.client_endpoints["reader"], 4096).unwrap())
            .unwrap();
    let mut waiting = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut stream = BufReader::new(TcpStream::connect(selected.address).await.unwrap());
        write_frame(stream.get_mut(),&json!({"format":HELLO_FORMAT,"key_id":channel::key_id(&selected.token),"client_nonce":"N".repeat(43)})).await.unwrap();
        // An attacker can read a challenge envelope but cannot answer it.
        assert!(read_frame(&mut stream, 16384).await.unwrap().is_some());
        waiting.push(stream);
    }
    let reply = tokio::time::timeout(
        Duration::from_secs(6),
        call(
            &ready.client_endpoints["reader"],
            json!({"method":"capabilities"}),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply["ok"], true);
    drop(waiting);
    cancel.cancel();
    task.await.unwrap().unwrap();
}
#[test]
fn encrypted_rpc_keeps_large_payload_limits_separate_from_bridge_limits() {
    let auth = Authenticated {
        credential: "K".repeat(43),
        method: "PARTICIPANT_RPC:test".into(),
    };
    let request = json!({"method":"capabilities","padding":"x".repeat(300*1024)});
    let (encoded, wire) = encode_request(&auth, "large", request.clone()).unwrap();
    let (decoded, _) = decode_request(&auth, encoded.to_string().as_bytes()).unwrap();
    assert_eq!(decoded.request, request);
    assert!(
        ClientRequest::parse(decoded.request).is_err(),
        "transport size must not weaken the request catalog"
    );
    let out = response("large", Ok(json!({"payload":"🦀".repeat(100000)})));
    let payload = channel::response_bounded(
        &auth.credential,
        &auth.method,
        wire.as_bytes(),
        &out,
        MAX_RESPONSE,
    )
    .unwrap();
    let reply =
        json!({"format":SEALED_RESPONSE,"request_id":"large","payload":payload}).to_string();
    assert_eq!(
        decode_response(&auth, "large", &wire, reply.as_bytes()).unwrap(),
        out
    );
    assert!(encode_request(
        &auth,
        "oversize",
        json!({"padding":"x".repeat(MAX_REQUEST)})
    )
    .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local loopback IPC sockets"]
async fn pinned_client_rechecks_replacement_and_keeps_original_operation() {
    let directory = crate::test_support::protected_test_dir();
    let options = config(directory.path());
    let actor = options.engines[0].expected_actor.clone();
    let origin = options.engines[0].origin.clone();
    let (ready, cancel, task) = start(options.clone()).await;
    let client = RuntimeClient::connect(ready.client_endpoints["creator"].clone(), &origin, &actor)
        .await
        .unwrap();
    assert_eq!(
        client.call(json!({"method":"bindings"})).await.unwrap(),
        json!([])
    );
    assert_eq!(
        client
            .call(json!({"method":"capabilities","profile":"reader"}))
            .await
            .unwrap_err()
            .code,
        "CLIENT_REQUEST_INVALID"
    );
    let error = RuntimeClient::connect(ready.admin_endpoint.clone(), &origin, &actor)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "CLIENT_ADMIN_ENDPOINT_FORBIDDEN");
    let mut request = Invoke::new(
        "pinned-original",
        "structure.workspace.create",
        crate::participant::Scope::default(),
        json!({"name":"Synthetic pin test"}),
    );
    let out = client
        .call(json!({"method":"invoke","request":request,"wait_ms":0}))
        .await
        .unwrap();
    assert_eq!(out["operation_id"], "pinned-original");
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (ready, cancel, task) = start(options).await;
    assert_eq!(
        client
            .call(json!({"method":"operation","operation_id":"pinned-original"}))
            .await
            .unwrap()["operation_id"],
        "pinned-original"
    );

    let other_directory = crate::test_support::protected_test_dir();
    let (other, other_cancel, other_task) = start(config(other_directory.path())).await;
    let path = &ready.client_endpoints["creator"];
    let correct = std::fs::read(path).unwrap();
    std::fs::write(
        path,
        &std::fs::read(&other.client_endpoints["creator"]).unwrap(),
    )
    .unwrap();
    request.operation_id = "must-not-cross-identity".into();
    let error = client
        .call(json!({"method":"invoke","request":request,"wait_ms":0}))
        .await
        .unwrap_err();
    assert_eq!(error.code, "CLIENT_IDENTITY_OR_ORIGIN_MISMATCH");
    let absent = call(
        &other.client_endpoints["creator"],
        json!({"method":"operation","operation_id":"must-not-cross-identity"}),
    )
    .await
    .unwrap();
    assert_eq!(absent["error"]["code"], "OPERATION_NOT_FOUND");
    std::fs::write(path, &correct).unwrap();
    assert_eq!(
        client.call(json!({"method":"capabilities"})).await.unwrap()["actor_id"],
        actor
    );
    other_cancel.cancel();
    other_task.await.unwrap().unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local loopback IPC sockets"]
async fn watch_binding_discovery_cannot_cross_namespace_or_capability() {
    let directory = crate::test_support::protected_test_dir();
    let options = config(directory.path());
    let (ready, cancel, task) = start(options).await;
    let creator = &ready.client_endpoints["creator"];
    let reader = &ready.client_endpoints["reader"];
    let options = json!({"workspace_id":"w".repeat(43),"mailbox_id":"m".repeat(43),"membership_id":"g".repeat(43),"consumer_id":"selected-worker"});
    let watch = call(creator, json!({"method":"watch","options":options}))
        .await
        .unwrap();
    assert_eq!(watch["ok"], true);
    let bindings = call(creator, json!({"method":"bindings"})).await.unwrap();
    assert_eq!(bindings["value"], json!([options]));
    assert_eq!(
        call(reader, json!({"method":"bindings"})).await.unwrap()["value"],
        json!([])
    );
    assert_eq!(
        call(
            reader,
            json!({"method":"inbox","options":options,"limit":1})
        )
        .await
        .unwrap()["error"]["code"],
        "LOCAL_SCOPE_DENIED"
    );
    assert_eq!(
        call(creator, json!({"method":"bindings","namespace":"reader"}))
            .await
            .unwrap()["error"]["code"],
        "CLIENT_REQUEST_INVALID"
    );
    assert_eq!(
        call(creator, json!({"method":"unwatch","options":options}))
            .await
            .unwrap()["ok"],
        true
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        call(creator, json!({"method":"unwatch","options":options}))
            .await
            .unwrap()["ok"],
        true,
        "the same persisted stopped binding must not depend on an in-memory slot"
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback IPC permission"]
async fn derived_capability_changes_compare_previous_authority_and_never_leave_narrowed_clones() {
    let temp = crate::test_support::protected_test_dir();
    let options = config(temp.path());
    let (ready, cancel, task) = start(options.clone()).await;
    let parent = &ready.client_endpoints["creator"];
    let initial = options.clients[1].capability.clone();
    let first = call(
        parent,
        json!({"method":"derive","name":"scoped","capability":initial}),
    )
    .await
    .unwrap();
    assert_eq!(first["ok"], true);
    let endpoint = PathBuf::from(first["value"]["endpoint_path"].as_str().unwrap());
    let credential = std::fs::read(&endpoint).unwrap();
    let mut added = initial.clone();
    added.operations.insert("structure.mailbox.get".into());
    let conflict = call(
        parent,
        json!({"method":"derive","name":"scoped","capability":added}),
    )
    .await
    .unwrap();
    assert_eq!(conflict["error"]["code"], "CLIENT_BINDING_CONFLICT");
    let changed = call(
        parent,
        json!({"method":"derive","name":"scoped","capability":added,"expected_capability":initial}),
    )
    .await
    .unwrap();
    assert_eq!(changed["ok"], true, "{changed}");
    assert_eq!(
        std::fs::read(&endpoint).unwrap(),
        credential,
        "additive permission change rotated the client identity"
    );
    assert_eq!(
        call(&endpoint, json!({"method":"capabilities"}))
            .await
            .unwrap()["value"]["capability"],
        serde_json::to_value(&added).unwrap()
    );
    let removed = call(
        parent,
        json!({"method":"derive","name":"scoped","capability":initial,"expected_capability":added}),
    )
    .await
    .unwrap();
    assert_eq!(
        removed["error"]["code"],
        "CLIENT_NARROWING_REQUIRES_REVOCATION"
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (ready, cancel, task) = start(options).await;
    let restored = call(
        &ready.client_endpoints["creator"],
        json!({"method":"derive","name":"scoped","capability":added}),
    )
    .await
    .unwrap();
    assert_eq!(
        restored["value"]["endpoint_path"],
        first["value"]["endpoint_path"]
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires protected temporary state and loopback IPC"]
async fn interrupted_revocation_survives_restart_and_stale_generation_cannot_reactivate_or_revoke_rejoin(
) {
    use crate::participant_dispatch::{HostConfig, HostSubscription};
    use std::os::unix::fs::PermissionsExt;
    let temp = crate::test_support::protected_test_dir();
    let options = config(temp.path());
    let directory = options.state_directory.clone();
    let (ready, cancel, task) = start(options.clone()).await;
    let parent = &ready.client_endpoints["creator"];
    let first = call(
        parent,
        json!({"method":"derive","name":"retire","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    let healthy = call(
        parent,
        json!({"method":"derive","name":"healthy","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    let selected = |derived: &Value, mailbox: &str| HostSubscription {
        client: derived["value"]["client_name"].as_str().unwrap().into(),
        client_generation: derived["value"]["client_generation"].as_u64(),
        watch: WatchOptions {
            workspace_id: "W".repeat(43),
            mailbox_id: mailbox.repeat(43),
            membership_id: "M".repeat(43),
            consumer_id: "worker".into(),
            host_destination: None,
        },
    };
    let host = HostConfig {
        name: "owned-host".into(),
        adapter: json!({"kind":"codex","endpoint":"ws://127.0.0.1:1","thread_id":"owned-synthetic-thread"}),
        subscriptions: vec![selected(&first, "A"), selected(&healthy, "B")],
    };
    assert_eq!(
        call(
            &ready.admin_endpoint,
            json!({"method":"host_ensure","config":host})
        )
        .await
        .unwrap()["ok"],
        true
    );
    let endpoint = PathBuf::from(first["value"]["endpoint_path"].as_str().unwrap());
    let copied = temp.path().join("retired-copy.json");
    write_private(&copied, &std::fs::read(&endpoint).unwrap()).unwrap();
    let submitted=call(&endpoint,json!({"method":"invoke","request":Invoke::new("retain-original","structure.workspace.create",Default::default(),json!({"name":"unreachable synthetic service"})),"wait_ms":0})).await.unwrap();
    assert_eq!(submitted["ok"], true, "{submitted}");
    // A genuine file-protection failure prevents publication, leaving the old
    // valid host registry in place. Revocation must still invalidate credentials
    // and be recoverable after the process exits before cleanup completes.
    let saved = directory.join("runtime-hosts.state");
    std::fs::set_permissions(&saved, std::fs::Permissions::from_mode(0o644)).unwrap();
    let revoked=call(parent,json!({"method":"revoke_derived","name":"retire","expected_binding":first["value"]["binding_version"]})).await.unwrap();
    assert_eq!(
        revoked["value"]["state"], "LOCAL_CLIENTS_REVOKED_CLEANUP_PENDING",
        "{revoked}"
    );
    assert!(
        endpoint.exists(),
        "failed cleanup retains the original endpoint until its owned deletion can be confirmed"
    );
    assert!(call(&copied, json!({"method":"capabilities"}))
        .await
        .is_err());
    assert_eq!(
        call(
            parent,
            json!({"method":"derive","name":"retire","capability":Capability::owner()})
        )
        .await
        .unwrap()["error"]["code"],
        "CLIENT_REVOCATION_PENDING"
    );
    assert_eq!(
        call(
            &PathBuf::from(healthy["value"]["endpoint_path"].as_str().unwrap()),
            json!({"method":"capabilities"})
        )
        .await
        .unwrap()["ok"],
        true
    );
    std::fs::set_permissions(&saved, std::fs::Permissions::from_mode(0o600)).unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (regained, cancel, task) = start(options).await;
    let host_state: Value =
        serde_json::from_slice(&SecureStateStore::read_snapshot(&saved, 65536).unwrap()).unwrap();
    assert_eq!(
        host_state[0]["subscriptions"].as_array().unwrap().len(),
        1,
        "restart resurrected a revoked subscription: {host_state}"
    );
    assert_eq!(
        host_state[0]["subscriptions"][0]["client"],
        healthy["value"]["client_name"]
    );
    let next = call(
        &regained.client_endpoints["creator"],
        json!({"method":"derive","name":"retire","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    assert_eq!(
        next["value"]["endpoint_path"],
        first["value"]["endpoint_path"]
    );
    assert!(
        next["value"]["client_generation"].as_u64().unwrap()
            > first["value"]["client_generation"].as_u64().unwrap()
    );
    let original = call(
        &endpoint,
        json!({"method":"operation","operation_id":"retain-original"}),
    )
    .await
    .unwrap();
    assert_eq!(
        original["value"]["operation_id"], "retain-original",
        "{original}"
    );
    let stale = call(
        &regained.admin_endpoint,
        json!({"method":"host_ensure","config":host}),
    )
    .await
    .unwrap();
    assert_eq!(
        stale["error"]["code"], "HOST_CLIENT_BINDING_CHANGED",
        "{stale}"
    );
    let stale_revoke=call(&regained.client_endpoints["creator"],json!({"method":"revoke_derived","name":"retire","expected_binding":first["value"]["binding_version"]})).await.unwrap();
    assert_eq!(stale_revoke["error"]["code"], "CLIENT_BINDING_CHANGED");
    let mut explicit = host;
    explicit.subscriptions = vec![selected(&next, "A")];
    assert_eq!(
        call(
            &regained.admin_endpoint,
            json!({"method":"host_ensure","config":explicit})
        )
        .await
        .unwrap()["ok"],
        true
    );
    std::fs::set_permissions(&saved, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pending=call(&regained.client_endpoints["creator"],json!({"method":"revoke_derived","name":"retire","expected_binding":next["value"]["binding_version"]})).await.unwrap();
    assert_eq!(
        pending["value"]["state"],
        "LOCAL_CLIENTS_REVOKED_CLEANUP_PENDING"
    );
    std::fs::set_permissions(&saved, std::fs::Permissions::from_mode(0o600)).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = call(&regained.admin_endpoint, json!({"method":"status"}))
                .await
                .unwrap();
            if status["value"]["pending_client_revocations"]
                .as_array()
                .is_some_and(|xs| xs.is_empty())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("runtime did not resume the original revocation after storage was repaired");
    let reissued = call(
        &regained.client_endpoints["creator"],
        json!({"method":"derive","name":"retire","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    assert_eq!(reissued["ok"], true, "{reissued}");
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback IPC permission"]
async fn host_scope_conflicts_are_rejected_before_persistence_and_terminal_dispatchers_are_not_ready(
) {
    use crate::participant_dispatch::{HostConfig, HostSubscription};
    let temp = crate::test_support::protected_test_dir();
    let mut options = config(temp.path());
    options.clients.push(ClientConfig {
        name: "other".into(),
        engine: "one-identity".into(),
        capability: Capability::owner(),
    });
    let runtime_directory = options.state_directory.clone();
    let (ready, cancel, task) = start(options).await;
    let watch = WatchOptions {
        workspace_id: "W".repeat(43),
        mailbox_id: "B".repeat(43),
        membership_id: "M".repeat(43),
        consumer_id: "first".into(),
        host_destination: None,
    };
    let mut host = HostConfig {
        name: "selected".into(),
        adapter: json!({"kind":"codex","endpoint":"ws://127.0.0.1:1","thread_id":"owned-synthetic-thread"}),
        subscriptions: vec![
            HostSubscription {
                client_generation: None,
                client: "creator".into(),
                watch: watch.clone(),
            },
            HostSubscription {
                client_generation: None,
                client: "other".into(),
                watch,
            },
        ],
    };
    let rejected = call(
        &ready.admin_endpoint,
        json!({"method":"host_ensure","config":host}),
    )
    .await
    .unwrap();
    assert_eq!(
        rejected["error"]["code"], "HOST_SUBSCRIPTION_CONFLICT",
        "{rejected}"
    );
    assert!(
        !runtime_directory.join("runtime-hosts.state").exists(),
        "invalid host configuration was persisted before validation"
    );
    host.subscriptions.pop();
    let key = host.key().unwrap();
    let owner =
        SecureStateStore::open(&runtime_directory.join(format!("host-{key}.state"))).unwrap();
    let registered = call(
        &ready.admin_endpoint,
        json!({"method":"host_ensure","config":host}),
    )
    .await
    .unwrap();
    assert_eq!(registered["ok"], true, "{registered}");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = call(&ready.admin_endpoint, json!({"method":"status"}))
                .await
                .unwrap();
            if status["value"]["hosts"][0]["code"] == "HOST_STATE_ALREADY_OWNED" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let failed = call(
        &ready.admin_endpoint,
        json!({"method":"host_ensure","config":host}),
    )
    .await
    .unwrap();
    assert_eq!(
        failed["error"]["code"], "HOST_DISPATCHER_RECOVERY_REQUIRED",
        "{failed}"
    );
    assert_eq!(
        call(
            &ready.client_endpoints["creator"],
            json!({"method":"capabilities"})
        )
        .await
        .unwrap()["ok"],
        true
    );
    drop(owner);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires protected synthetic state and loopback IPC"]
async fn nested_pending_revocations_keep_original_root_and_remove_only_their_original_endpoints() {
    use crate::participant_dispatch::{HostConfig, HostSubscription};
    use std::os::unix::fs::PermissionsExt;
    let root = crate::test_support::protected_test_dir();
    let original = config(root.path());
    let directory = original.state_directory.clone();
    let (ready, cancel, task) = start(original.clone()).await;
    let parent = call(
        &ready.client_endpoints["creator"],
        json!({"method":"derive","name":"parent","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    let parent_path = PathBuf::from(parent["value"]["endpoint_path"].as_str().unwrap());
    let child = call(
        &parent_path,
        json!({"method":"derive","name":"child","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    let child_path = PathBuf::from(child["value"]["endpoint_path"].as_str().unwrap());
    let host = HostConfig {
        name: "owned".into(),
        adapter: json!({"kind":"codex","endpoint":"ws://127.0.0.1:1","thread_id":"synthetic"}),
        subscriptions: vec![HostSubscription {
            client: child["value"]["client_name"].as_str().unwrap().into(),
            client_generation: child["value"]["client_generation"].as_u64(),
            watch: WatchOptions {
                workspace_id: "W".repeat(43),
                mailbox_id: "M".repeat(43),
                membership_id: "G".repeat(43),
                consumer_id: "child".into(),
                host_destination: None,
            },
        }],
    };
    assert_eq!(
        call(
            &ready.admin_endpoint,
            json!({"method":"host_ensure","config":host})
        )
        .await
        .unwrap()["ok"],
        true
    );
    let saved = directory.join("runtime-hosts.state");
    std::fs::set_permissions(&saved, std::fs::Permissions::from_mode(0o644)).unwrap();
    for (endpoint, name, binding) in [
        (&parent_path, "child", &child["value"]["binding_version"]),
        (
            &ready.client_endpoints["creator"],
            "parent",
            &parent["value"]["binding_version"],
        ),
    ] {
        let revoked = call(
            endpoint,
            json!({"method":"revoke_derived","name":name,"expected_binding":binding}),
        )
        .await
        .unwrap();
        assert_eq!(
            revoked["value"]["state"], "LOCAL_CLIENTS_REVOKED_CLEANUP_PENDING",
            "{revoked}"
        );
    }
    assert!(
        parent_path.exists() && child_path.exists(),
        "failed cleanup lost endpoint ownership evidence"
    );
    std::fs::set_permissions(&saved, std::fs::Permissions::from_mode(0o600)).unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
    let other = crate::test_support::protected_test_dir();
    let mut wrong = config(other.path());
    wrong.state_directory = directory.clone();
    let (wrong_ready, wrong_stop, wrong_task) = start(wrong).await;
    let status = call(&wrong_ready.admin_endpoint, json!({"method":"status"}))
        .await
        .unwrap();
    assert_eq!(
        status["value"]["pending_client_revocations"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "same config names must not substitute another identity"
    );
    assert!(parent_path.exists() && child_path.exists());
    wrong_stop.cancel();
    wrong_task.await.unwrap().unwrap();
    let (ready, cancel, task) = start(original).await;
    assert!(
        !parent_path.exists() && !child_path.exists(),
        "restart retained old derived endpoints after completing revocation"
    );
    let status = call(&ready.admin_endpoint, json!({"method":"status"}))
        .await
        .unwrap();
    assert_eq!(status["value"]["pending_client_revocations"], json!([]));
    let next = call(
        &ready.client_endpoints["creator"],
        json!({"method":"derive","name":"parent","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    assert_eq!(next["ok"], true, "{next}");
    let child_again = call(
        &parent_path,
        json!({"method":"derive","name":"child","capability":Capability::owner()}),
    )
    .await
    .unwrap();
    assert_eq!(child_again["ok"], true, "{child_again}");
    assert!(
        child_again["value"]["client_generation"].as_u64().unwrap()
            > child["value"]["client_generation"].as_u64().unwrap()
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn revoked_client_clone_cannot_readmit_a_watch_or_new_business_intent() {
    let root = crate::test_support::protected_test_dir();
    let options = config(root.path()).engines.remove(0).participant_config();
    let owner = ParticipantClient::open(options).await.unwrap();
    let scoped = owner.restrict("participant", Capability::owner()).unwrap();
    let stale = scoped.clone();
    let watch = WatchOptions {
        workspace_id: "W".repeat(43),
        mailbox_id: "M".repeat(43),
        membership_id: "G".repeat(43),
        consumer_id: "participant".into(),
        host_destination: None,
    };
    scoped.revoke_local();
    assert_eq!(
        stale.watch(watch).await.err().unwrap().code,
        "LOCAL_CLIENT_REVOKED"
    );
    let rejected = stale
        .invoke(
            Invoke::new(
                "after-revoke",
                "structure.workspace.create",
                Default::default(),
                json!({"name":"must not be admitted"}),
            ),
            Duration::ZERO,
        )
        .await
        .unwrap_err();
    assert_eq!(rejected.code, "LOCAL_CLIENT_REVOKED");
    assert_eq!(rejected.effect_certainty, "NOT_SUBMITTED");
    assert_eq!(
        stale.operation("after-revoke").await.unwrap_err().code,
        "OPERATION_NOT_FOUND"
    );
    assert!(owner.watch_bindings().await.unwrap().is_empty());
    owner.close().await.unwrap();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires loopback IPC permission"]
async fn existing_endpoint_attachment_needs_no_discovery_rights_and_keeps_original_pending(){
    use crate::{participant_connect::{Connect,Registration},agent_tools::{AgentRequest,AgentTools},participant_store::Store};
    let temp=crate::test_support::protected_test_dir();let mut cfg=config(temp.path());cfg.engines[0].origin.push('/');cfg.clients[1].capability.operations.insert("structure.member.name.set".into());cfg.clients[1].capability.workspace_ids=Some(["W".repeat(43)].into());
    let identity=KernelIdentity::open(&cfg.engines[0].identity_path).unwrap();
    let mut store=Store::open(&cfg.engines[0].state_directory,&identity,&cfg.engines[0].origin).unwrap();
    let request=Invoke::new("original-pending","structure.member.name.set",crate::participant::Scope{workspace_id:Some("W".repeat(43)),..Default::default()},json!({"membership_id":"M".repeat(43),"name":"old"}));
    store.reserve("program:reader",&request,&identity,64,32*1024*1024).unwrap();
    store.finish("program:reader","original-pending",&identity,&json!({"state":"PENDING","retryable":false,"effect_certainty":"UNKNOWN","command_id":"old-command"})).unwrap();drop(store);
    let (ready,cancel,task)=start(cfg.clone()).await;
    let mut connect=Connect::open(&temp.path().join("local")).unwrap();
    connect.register("worker",Registration{origin:cfg.engines[0].origin.clone(),actor_id:identity.actor_id().into(),endpoint_path:ready.client_endpoints["reader"].clone()}).await.unwrap();
    let ws="W".repeat(43);
    assert_eq!(connect.attach("worker",&ws,"project",Default::default()).await.unwrap()["state"],"LOCAL_ATTACHED");
    let profile=connect.profile_for_scope(Some("worker"),Some(&ws)).unwrap().unwrap();
    assert_eq!(profile.endpoint_path,ready.client_endpoints["reader"]);
    assert!(profile.contacts.is_empty()&&profile.scopes.is_empty());
    let tools=AgentTools::open(profile).await.unwrap();
    let pending=tools.call(AgentRequest::Status{ recovery_view:None, protocol_view: None, management: None,workspace:None,protocol:None,operation_id:"original-pending".into()}).await.unwrap();
    assert_eq!(pending["command_id"],"old-command");assert_eq!(pending["effect_certainty"],"UNKNOWN");
    let context=tools.call(AgentRequest::Context).await.unwrap();
    assert_eq!(context["capability"],serde_json::to_value(&cfg.clients[1].capability).unwrap());
    assert_eq!(context["workspaces"]["project"],ws);
    drop(tools);drop(connect);cancel.cancel();task.await.unwrap().unwrap();
}
