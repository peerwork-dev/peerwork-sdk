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
    let mut stream=BufReader::new(TcpStream::connect(current.address).await.unwrap());
    assert!(client_handshake(&mut stream,&old.token).await.is_err(),"a retired credential cannot authenticate the new runtime");
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
fn request_enum_is_the_single_catalog_and_rejects_extra_authority(){
    let options=json!({"workspace_id":"w".repeat(43),"mailbox_id":"m".repeat(43),"membership_id":"g".repeat(43),"consumer_id":"worker"});
    let valid=json!({"method":"delivery_status","options":options,"item":{"sequence":1,"delivery_id":"d".repeat(43)}});
    assert!(ClientRequest::parse(valid.clone()).is_ok());
    let mut extra=valid;extra["profile"]=json!("another-identity");assert!(ClientRequest::parse(extra).is_err());
    assert!(ClientRequest::parse(json!({"method":"capabilities","identity_path":"/other"})).is_err());
    assert!(ClientRequest::parse(json!({"method":"host_finish","call_id":"untrusted"})).is_err());
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires local loopback IPC sockets"]
async fn fake_runtime_cannot_read_private_requests_or_forge_peer_challenge(){
    let directory=crate::test_support::protected_test_dir();let file=directory.path().join("client.json");
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let credential="K".repeat(43);
    endpoint(&file,listener.local_addr().unwrap(),&credential,"CLIENT").unwrap();
    let captured=tokio::spawn(async move{
        let(stream,_)=listener.accept().await.unwrap();let mut stream=BufReader::new(stream);
        let hello=read_frame(&mut stream,4096).await.unwrap().unwrap();let text=std::str::from_utf8(&hello).unwrap();
        assert!(!text.contains(&credential));assert!(!text.contains("private_rpc_request_body"));
        let parsed:Value=serde_json::from_slice(&hello).unwrap();assert_eq!(parsed["format"],HELLO_FORMAT);
        write_frame(stream.get_mut(),&json!({"format":CHALLENGE_FORMAT,"payload":"forged ACK"})).await.unwrap();
        let next=tokio::time::timeout(Duration::from_secs(2),read_frame(&mut stream,MAX_WIRE_REQUEST)).await;
        assert!(matches!(next,Ok(Ok(None))|Ok(Err(_))),"private request must not follow an unauthenticated peer");
    });
    let value=call(&file,json!({"method":"invoke","request":{"secret":"private_rpc_request_body"}})).await.unwrap_err();
    assert_eq!(value.code,"IPC_PEER_UNVERIFIED");assert_eq!(value.effect_certainty,"UNKNOWN");captured.await.unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires local loopback IPC sockets"]
async fn encrypted_rpc_replay_is_rejected_after_completion_and_on_another_connection(){
    let directory=crate::test_support::protected_test_dir();let(ready,cancel,task)=start(config(directory.path())).await;
    let selected:Endpoint=serde_json::from_value(private_json(&ready.client_endpoints["reader"],4096).unwrap()).unwrap();
    let mut first=BufReader::new(TcpStream::connect(selected.address).await.unwrap());let auth=client_handshake(&mut first,&selected.token).await.unwrap();
    let(frame,wire)=encode_request(&auth,"request-one",json!({"method":"capabilities"})).unwrap();
    write_frame(first.get_mut(),&frame).await.unwrap();let reply=read_frame(&mut first,MAX_WIRE_RESPONSE).await.unwrap().unwrap();
    assert_eq!(decode_response(&auth,"request-one",&wire,&reply).unwrap()["ok"],true);
    let mut other=BufReader::new(TcpStream::connect(selected.address).await.unwrap());client_handshake(&mut other,&selected.token).await.unwrap();
    write_frame(other.get_mut(),&frame).await.unwrap();
    assert!(matches!(read_frame(&mut other,MAX_WIRE_RESPONSE).await,Ok(None)|Err(_)),"a previous connection's packet cannot authenticate");
    write_frame(first.get_mut(),&frame).await.unwrap();
    assert!(matches!(read_frame(&mut first,MAX_WIRE_RESPONSE).await,Ok(None)|Err(_)),"completed request IDs cannot execute twice on a live connection");
    assert_eq!(call(&ready.client_endpoints["reader"],json!({"method":"capabilities"})).await.unwrap()["ok"],true);
    cancel.cancel();task.await.unwrap().unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
#[ignore="requires local loopback IPC sockets"]
async fn knowing_key_identifier_without_its_key_cannot_hold_runtime_slots(){
    let directory=crate::test_support::protected_test_dir();let(ready,cancel,task)=start(config(directory.path())).await;
    let selected:Endpoint=serde_json::from_value(private_json(&ready.client_endpoints["reader"],4096).unwrap()).unwrap();
    let mut waiting=Vec::new();
    for _ in 0..MAX_CONNECTIONS{
        let mut stream=BufReader::new(TcpStream::connect(selected.address).await.unwrap());
        write_frame(stream.get_mut(),&json!({"format":HELLO_FORMAT,"key_id":channel::key_id(&selected.token),"client_nonce":"N".repeat(43)})).await.unwrap();
        // An attacker can read a challenge envelope but cannot answer it.
        assert!(read_frame(&mut stream,16384).await.unwrap().is_some());waiting.push(stream);
    }
    let reply=tokio::time::timeout(Duration::from_secs(6),call(&ready.client_endpoints["reader"],json!({"method":"capabilities"}))).await.unwrap().unwrap();
    assert_eq!(reply["ok"],true);drop(waiting);cancel.cancel();task.await.unwrap().unwrap();
}
#[test]
fn encrypted_rpc_keeps_large_payload_limits_separate_from_bridge_limits(){
    let auth=Authenticated{credential:"K".repeat(43),method:"PARTICIPANT_RPC:test".into()};
    let request=json!({"method":"capabilities","padding":"x".repeat(300*1024)});
    let(encoded,wire)=encode_request(&auth,"large",request.clone()).unwrap();
    let(decoded,_)=decode_request(&auth,encoded.to_string().as_bytes()).unwrap();assert_eq!(decoded.request,request);
    assert!(ClientRequest::parse(decoded.request).is_err(),"transport size must not weaken the request catalog");
    let out=response("large",Ok(json!({"payload":"🦀".repeat(100000)})));
    let payload=channel::response_bounded(&auth.credential,&auth.method,wire.as_bytes(),&out,MAX_RESPONSE).unwrap();
    let reply=json!({"format":SEALED_RESPONSE,"request_id":"large","payload":payload}).to_string();
    assert_eq!(decode_response(&auth,"large",&wire,reply.as_bytes()).unwrap(),out);
    assert!(encode_request(&auth,"oversize",json!({"padding":"x".repeat(MAX_REQUEST)})).is_err());
}
