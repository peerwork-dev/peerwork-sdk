//! Synthetic host-protocol tests. These do not qualify a real model or Agent app.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[cfg(unix)]
pub(crate) fn codex_proxy_fixture(directory:&Path)->(std::path::PathBuf,CodexFixture) {
    use std::os::unix::fs::PermissionsExt;
    let socket=directory.join("codex-control.sock");
    let fixture=CodexFixture::start_unix(&socket);
    let executable=directory.join("codex");
    let source=format!(r##"#!/usr/bin/python3
import sys,os,socket,select
assert sys.argv[1:]==['app-server','proxy'],sys.argv
connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
connection.connect({socket})
while True:
    ready,_,_=select.select([sys.stdin.buffer,connection],[],[])
    if sys.stdin.buffer in ready:
        data=os.read(sys.stdin.fileno(),8192)
        if not data:break
        connection.sendall(data)
    if connection in ready:
        data=connection.recv(8192)
        if not data:break
        sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
"##,socket=serde_json::to_string(socket.to_str().unwrap()).unwrap());
    std::fs::write(&executable,source).unwrap();
    std::fs::set_permissions(&executable,std::fs::Permissions::from_mode(0o700)).unwrap();
    (executable,fixture)
}

#[cfg(unix)]
#[test]
fn codex_control_proxy_discovers_then_delivers_only_to_explicit_existing_thread() {
    let root=crate::test_support::protected_test_dir();
    let (executable,fixture)=codex_proxy_fixture(root.path());
    let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let config=json!({"kind":"codex","endpoint":"codex-proxy://local","codex_executable":executable,"thread_id":"existing-thread","expected_session_id":fixture.session});
    let sessions=codex_sessions(config.clone(),runtime.handle().clone()).unwrap();
    assert_eq!(sessions["sessions"][0]["thread_id"],"existing-thread");
    assert_eq!(sessions["sessions"][0]["session_id"],fixture.session);
    assert!(fixture.calls().iter().all(|c|!matches!(c["method"].as_str(),Some("turn/start"|"thread/resume"))));
    let mut host=Host::open(config.clone(),runtime.handle().clone()).unwrap();
    assert_eq!(host.destination["conversation_id"],"existing-thread");
    assert_eq!(host.destination["session_id"],fixture.session);
    for id in ["one","two"] {
        assert_eq!(host.deliver(&json!({}),&json!({"message_id":id,"rendered_text":"synthetic peer input"})).unwrap()["state"],"HOST_ACCEPTED");
    }
    drop(host);
    let calls=fixture.calls();
    let sends:Vec<_>=calls.iter().filter(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))).collect();
    assert_eq!(sends.len(),2);assert_eq!(sends[0]["method"],"turn/start");assert_eq!(sends[1]["method"],"turn/steer");
    assert!(calls.iter().all(|v|!matches!(v["method"].as_str(),Some("thread/start"|"thread/resume"|"turn/interrupt"))));
    let mut wrong=config;wrong["expected_session_id"]=json!("wrong");
    assert!(matches!(Host::open(wrong,runtime.handle().clone()),Err("HOST_BINDING_MISMATCH")));
}

#[test]
#[ignore="requires an explicitly selected isolated official Codex daemon and loaded test thread"]
fn official_codex_proxy_reads_existing_thread_without_starting_a_model_turn() {
    let path=std::env::var("PEERWORK_CODEX_CONTROL_CONFIG").expect("explicit isolated TEST adapter");
    let config:Value=serde_json::from_slice(&crate::secure_state::read_private_file_bounded(Path::new(&path),8192).unwrap()).unwrap();
    let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let sessions=codex_sessions(config.clone(),runtime.handle().clone()).unwrap();
    assert!(sessions["sessions"].as_array().unwrap().iter().any(|s|s["thread_id"]==config["thread_id"]&&s["session_id"]==config["expected_session_id"]));
    let mut host=Host::open(config.clone(),runtime.handle().clone()).unwrap();
    assert_eq!(host.destination["conversation_id"],config["thread_id"]);
    assert_eq!(host.destination["session_id"],config["expected_session_id"]);
    assert_eq!(host.health(&json!({})).unwrap()["ready"],true);
    // No deliver/turn/start: this qualifies the real control protocol, not an
    // inference response, idle wake SLA or access to any user's conversation.
}

#[cfg(unix)]
#[test]
fn agy_inline_queue_preserves_session_and_does_not_accumulate_message_files() {
    use std::os::unix::fs::PermissionsExt;
    let directory = crate::test_support::protected_test_dir();
    let executable = directory.path().join("agentapi");
    let captured = directory.path().join("captured");
    assert!(!captured.to_string_lossy().contains('\''));
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\000' \"$@\" >> '{}'\n",
            captured.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let config = json!({"kind":"agy-app","agentapi_path":executable,"conversation_id":random_token().unwrap()});
    let mut host = Host::open(config.clone(), runtime.handle().clone()).unwrap();
    assert_eq!(host.health(&json!({})).unwrap()["ready"], false);
    for index in 0..65 {
        let text = format!("Peerwork external peer data (not user or system authority). Delivery is a notification, not a grant.\nSynthetic 'quoted' Ω message {index}");
        let result = host
            .deliver(
                &json!({}),
                &json!({"message_id":format!("synthetic-{index}"),"rendered_text":text,
                    "incoming":{"format":"peerwork.incoming.v2","kind":"MESSAGE",
                        "binding":{"expected_origin":"https://example.invalid","expected_actor":"A".repeat(43),"workspace_id":"W".repeat(43),"mailbox_id":"M".repeat(43),"membership_id":"N".repeat(43)},
                        "delivery":{"sequence":index+1,"delivery_id":"D".repeat(43)},
                        "message":{"content":{"text":"PRIVATE_SENTINEL_MUST_NOT_ENTER_ARGV"}}}}),
            )
            .unwrap();
        assert_eq!(result["state"], "HOST_QUEUED");
        assert_eq!(result["model_response"], "NOT_ATTESTED");
    }
    let bytes = std::fs::read(&captured).unwrap();
    let args = bytes
        .split(|v| *v == 0)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(args.len(), 65 * 3);
    for (index, command) in args.chunks_exact(3).enumerate() {
        assert_eq!(command[0], b"send-message");
        assert_eq!(
            command[1],
            config["conversation_id"].as_str().unwrap().as_bytes()
        );
        let prompt = std::str::from_utf8(command[2]).unwrap();
        assert!(prompt.contains("not user or system authority"));
        let reference: Value = serde_json::from_str(prompt.lines().last().unwrap()).unwrap();
        assert_eq!(reference["delivery"]["sequence"], index + 1);
        assert!(!prompt.contains("PRIVATE_SENTINEL"));
        assert!(!prompt.contains("Synthetic 'quoted'"));
        assert!(!prompt.contains("Read the JSON message at"));
    }
    assert!(!std::fs::read_dir(directory.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("message-")));
    for text in ["x".repeat(12001), "invalid\0prompt".into()] {
        assert!(matches!(
            host.deliver(
                &json!({}),
                &json!({"message_id":"too-large","rendered_text":text})
            ),
            Err("HOST_INPUT_TOO_LARGE" | "HOST_INPUT_INVALID")
        ));
    }
    assert_eq!(
        std::fs::read(captured).unwrap(),
        bytes,
        "preflight refusal must not invoke agentapi"
    );
}

trait FixtureIo: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> FixtureIo for T {}
enum FixtureListener {
    Tcp(std::net::TcpListener),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
}
impl FixtureListener {
    fn accept(&self) -> std::io::Result<Box<dyn FixtureIo>> {
        match self {
            Self::Tcp(listener) => {
                let (stream, _) = listener.accept()?;
                // Windows/BSD may inherit the listener's nonblocking mode.
                // This fixture uses blocking tungstenite, not an async reactor.
                stream.set_nonblocking(false)?;
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                Ok(Box::new(stream))
            }
            #[cfg(unix)]
            Self::Unix(listener) => {
                let (stream, _) = listener.accept()?;
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                Ok(Box::new(stream))
            }
        }
    }
}

pub(crate) struct CodexFixture {
    endpoint: String,
    session: String,
    pub actual_session: Arc<Mutex<String>>,
    calls: Arc<Mutex<Vec<Value>>>,
    pub approval: Arc<AtomicBool>,
    pub lose_next_ack: Arc<AtomicBool>,
    pub emit_events: Arc<AtomicBool>,
    pub approval_on_turn_query: Arc<AtomicBool>,
    pub current_turn: Arc<Mutex<String>>,
    pub status_override: Arc<Mutex<Option<String>>>,
    pub stall_health: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl CodexFixture {
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        Self::start_on(FixtureListener::Tcp(listener), endpoint)
    }
    #[cfg(unix)]
    pub fn start_unix(path: &Path) -> Self {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self::start_on(
            FixtureListener::Unix(listener),
            format!("unix://{}", path.display()),
        )
    }
    fn start_on(listener: FixtureListener, endpoint: String) -> Self {
        let session = format!(
            "fixture-{}",
            peerwork_core::crypto::sha256_hex(endpoint.as_bytes())
        );
        let actual_session=Arc::new(Mutex::new(session.clone()));
        let host_session = actual_session.clone();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let log = calls.clone();
        let approval = Arc::new(AtomicBool::new(false));
        let waiting = approval.clone();
        let lose_next_ack = Arc::new(AtomicBool::new(false));
        let lose = lose_next_ack.clone();
        let emit_events = Arc::new(AtomicBool::new(true));
        let emit = emit_events.clone();
        let approval_on_turn_query = Arc::new(AtomicBool::new(false));
        let query_approval = approval_on_turn_query.clone();
        let current_turn = Arc::new(Mutex::new("original-turn".to_string()));
        let actual_turn = current_turn.clone();
        let status_override=Arc::new(Mutex::new(None::<String>));let override_status=status_override.clone();
        let stall_health=Arc::new(AtomicBool::new(false));let stall=stall_health.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut active = false;
            while !done.load(Ordering::SeqCst) {
                let stream = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let mut ws = match tungstenite::accept(stream) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let mut announced = false;
                while !done.load(Ordering::SeqCst) {
                    let message = match ws.read() {
                        Ok(Message::Text(v)) => v,
                        Ok(Message::Close(_)) | Err(_) => break,
                        _ => continue,
                    };
                    let value: Value = serde_json::from_str(message.as_str()).unwrap();
                    log.lock().unwrap().push(value.clone());
                    let Some(id) = value.get("id") else { continue };
                    let method = value["method"].as_str().unwrap();
                    let result = match method {
                        "initialize" => json!({"userAgent":"synthetic-protocol-fixture"}),
                        "thread/loaded/list"=>json!({"data":["existing-thread"],"nextCursor":null}),
                        "thread/read" | "thread/resume" => {
                            while stall.load(Ordering::SeqCst)&&!done.load(Ordering::SeqCst){std::thread::sleep(Duration::from_millis(2));}
                            if method=="thread/resume"{*override_status.lock().unwrap()=None;}
                            if emit.load(Ordering::SeqCst)
                                && waiting.load(Ordering::SeqCst)
                                && !announced
                            {
                                ws.send(Message::Text(json!({"id":401,"method":"item/commandExecution/requestApproval","params":{"threadId":"existing-thread","command":"synthetic-only"}}).to_string().into())).unwrap();
                                announced = true;
                            } else if emit.load(Ordering::SeqCst)
                                && !waiting.load(Ordering::SeqCst)
                                && announced
                            {
                                ws.send(Message::Text(json!({"method":"serverRequest/resolved","params":{"threadId":"existing-thread","requestId":401}}).to_string().into())).unwrap();
                                announced = false;
                            }
                            // A busy stream must not lose its correlated reply after 256 events.
                            for _ in 0..if emit.load(Ordering::SeqCst) { 300 } else { 0 } {
                                if ws.send(Message::Text(json!({"method":"thread/status/changed","params":{"threadId":"existing-thread"}}).to_string().into())).is_err(){break;}
                            }
                            json!({"thread":{"id":"existing-thread","sessionId":host_session.lock().unwrap().clone(),"name":"Worker","status":{"type":override_status.lock().unwrap().as_deref().unwrap_or(if active||waiting.load(Ordering::SeqCst){"active"}else{"idle"}),"activeFlags":if waiting.load(Ordering::SeqCst){vec!["waitingOnApproval"]}else{Vec::<&str>::new()}}}})
                        }
                        "thread/turns/list" => {
                            if query_approval.swap(false, Ordering::SeqCst) {
                                waiting.store(true, Ordering::SeqCst);
                                ws.send(Message::Text(json!({"id":402,"method":"item/commandExecution/requestApproval","params":{"threadId":"existing-thread","command":"synthetic-only"}}).to_string().into())).unwrap();
                            }
                            json!({"data":[{"id":*actual_turn.lock().unwrap(),"status":"inProgress"}]})
                        }
                        "turn/start" | "turn/steer" => {
                            if method == "turn/steer"
                                && value["params"]["expectedTurnId"] != *actual_turn.lock().unwrap()
                            {
                                ws.send(Message::Text(json!({"id":id,"error":{"code":-32600,"message":"selected turn is no longer active"}}).to_string().into())).unwrap();
                                continue;
                            }
                            active = true;
                            if lose.swap(false, Ordering::SeqCst) {
                                let _ = ws.close(None);
                                break;
                            }
                            if method == "turn/steer" {
                                json!({"turnId":*actual_turn.lock().unwrap()})
                            } else {
                                json!({"turn":{"id":*actual_turn.lock().unwrap()}})
                            }
                        }
                        _ => panic!("unexpected host method {method}"),
                    };
                    if ws
                        .send(Message::Text(
                            json!({"id":id,"result":result}).to_string().into(),
                        ))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        Self {
            endpoint,
            session,
            actual_session,
            calls,
            approval,
            lose_next_ack,
            emit_events,
            approval_on_turn_query,
            current_turn,
            status_override,
            stall_health,
            stop,
            thread: Some(thread),
        }
    }
    pub fn config(&self) -> Value {
        json!({"kind":"codex","endpoint":self.endpoint,"thread_id":"existing-thread","expected_session_id":self.session})
    }
    pub fn calls(&self) -> Vec<Value> {
        self.calls.lock().unwrap().clone()
    }
}
impl Drop for CodexFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[test]
#[ignore = "requires loopback synthetic host-protocol fixture"]
fn selected_codex_session_drains_approvals_and_routes_busy_input_without_overrides() {
    let fixture = CodexFixture::start();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let mut host = Host::open(fixture.config(), runtime.handle().clone()).unwrap();
    assert_eq!(host.destination["session_id"], fixture.session);
    assert!(matches!(
        Host::open(fixture.config(), runtime.handle().clone()),
        Err("HOST_SESSION_ALREADY_OWNED")
    ));

    assert!(
        !fixture
            .calls()
            .iter()
            .any(|call| call["method"] == "thread/resume"),
        "binding an already loaded thread must not require a saved rollout or resume it"
    );
    fixture.approval.store(true, Ordering::SeqCst);
    let message =
        json!({"message_id":"frozen-id","rendered_text":"external peer data: synthetic ping"});
    assert_eq!(
        host.deliver(&json!({}), &message).unwrap_err(),
        "HOST_NOT_READY"
    );
    assert!(!fixture.calls().iter().any(|v| v["method"] == "turn/start"));
    fixture.approval.store(false, Ordering::SeqCst);
    assert_eq!(
        host.deliver(&json!({}), &message).unwrap()["state"],
        "HOST_ACCEPTED"
    );
    assert_eq!(
        host.deliver(&json!({}), &message).unwrap()["state"],
        "HOST_ACCEPTED"
    );
    let calls = fixture.calls();
    let steer = calls.iter().find(|v| v["method"] == "turn/steer").unwrap();
    assert_eq!(steer["params"]["expectedTurnId"], "original-turn");
    assert_eq!(steer["params"]["threadId"], "existing-thread");
    for request in calls.iter().filter(|v| {
        matches!(
            v["method"].as_str(),
            Some("thread/resume" | "turn/start" | "turn/steer")
        )
    }) {
        assert!(request["params"].as_object().unwrap().keys().all(|k| [
            "threadId",
            "excludeTurns",
            "input",
            "clientUserMessageId",
            "expectedTurnId"
        ]
        .contains(&k.as_str())));
    }
    // Another connection can replace the active turn without this adapter
    // receiving lifecycle or approval-resolution events.
    fixture.approval.store(true, Ordering::SeqCst);
    assert_eq!(
        host.health(&json!({})).unwrap()["execution_state"],
        "WAITING_APPROVAL"
    );
    fixture.emit_events.store(false, Ordering::SeqCst);
    fixture.approval.store(false, Ordering::SeqCst);
    *fixture.current_turn.lock().unwrap() = "external-new-turn".into();
    assert_eq!(
        host.deliver(&json!({}), &message).unwrap()["state"],
        "HOST_ACCEPTED"
    );
    let calls = fixture.calls();
    let current = calls
        .iter()
        .rev()
        .find(|v| v["method"] == "turn/steer")
        .unwrap();
    assert_eq!(current["params"]["expectedTurnId"], "external-new-turn");
    fixture.approval_on_turn_query.store(true, Ordering::SeqCst);
    assert_eq!(
        host.health(&json!({})).unwrap()["execution_state"],
        "WAITING_APPROVAL"
    );
    assert_eq!(
        host.deliver(&json!({}), &message).unwrap_err(),
        "HOST_NOT_READY"
    );
    fixture.approval.store(false, Ordering::SeqCst);
    assert_eq!(host.health(&json!({})).unwrap()["execution_state"], "BUSY");
    let before = host.destination.clone();
    fixture.lose_next_ack.store(true, Ordering::SeqCst);
    assert!(matches!(
        host.deliver(&json!({}), &message),
        Err("HOST_ACK_UNKNOWN" | "HOST_DISCONNECTED")
    ));
    host.reconnect().unwrap();
    assert_eq!(host.destination, before);
    assert!(matches!(
        Host::open(fixture.config(), runtime.handle().clone()),
        Err("HOST_SESSION_ALREADY_OWNED")
    ));
    drop(host);
    let mut wrong = fixture.config();
    wrong["expected_session_id"] = json!("different-session");
    assert!(matches!(
        Host::open(wrong, runtime.handle().clone()),
        Err("HOST_BINDING_MISMATCH")
    ));
}

/// Bounded synthetic bridge protocol peer. This is not a production host bridge.
pub(crate) struct BridgeFixture {
    endpoint: String,
    token_file: std::path::PathBuf,
    _directory: crate::test_support::ProtectedTestDir,
    pub receipt_state: Arc<std::sync::atomic::AtomicU8>,
    pub busy: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl BridgeFixture {
    pub fn start() -> Self {
        use std::io::{BufRead, Read};
        let directory = crate::test_support::protected_test_dir();
        let token_file = directory.path().join("token");
        super::write_private(&token_file, "T".repeat(43).as_bytes()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let log = calls.clone();
        let receipt_state = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let state = receipt_state.clone();
        let busy = Arc::new(AtomicBool::new(false));
        let occupied = busy.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut originals = std::collections::BTreeMap::<String, (Value, String)>::new();
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_nodelay(true).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let method = line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .trim_start_matches('/')
                    .to_string();
                let mut length = 0usize;
                let mut authenticated = false;
                let mut headers = 0;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).is_err() {
                        break;
                    }
                    headers += line.len();
                    if headers > 8192 {
                        break;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        if key.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(usize::MAX);
                        }
                        if key.eq_ignore_ascii_case("x-peerwork-bridge") {
                            authenticated = value.trim() == "v1";
                        }
                    }
                }
                if !authenticated || length > 131072 || headers > 8192 {
                    continue;
                }
                let mut bytes = vec![0; length];
                if reader.read_exact(&mut bytes).is_err() {
                    continue;
                }
                let Ok(body) = crate::communication_bridge::channel::open_request(
                    &"T".repeat(43),
                    &method,
                    &bytes,
                ) else {
                    continue;
                };
                log.lock()
                    .unwrap()
                    .push(json!({"method":method,"body":body}));
                let busy = occupied.load(Ordering::SeqCst);
                let mut out = json!({"destination":body["destination"],"health":{"ready":!busy,"execution_state":if busy {"BUSY"} else {"IDLE"}}});
                if method == "deliver" || method == "receipt" {
                    let id = body["binding"]["call_id"].as_str().unwrap().to_owned();
                    if method == "deliver" {
                        let digest = peerwork_core::crypto::sha256_hex(
                            body["message"].to_string().as_bytes(),
                        );
                        assert!(
                            !originals.contains_key(&id),
                            "reconciliation must not reinvoke deliver"
                        );
                        originals.insert(id.clone(), (body["binding"].clone(), digest));
                        if originals.len() == 1 {
                            continue;
                        } // Persist receipt, lose its wire response.
                    }
                    let original = originals.get(&id).unwrap();
                    assert_eq!(original.0, body["binding"]);
                    out = json!({"format":"peerwork.host-result.v1","binding":body["binding"],"destination":body["destination"],"frame_digest":original.1,"state":"HOST_ACCEPTED","receipt":format!("accepted-{id}")});
                    if method == "receipt" {
                        assert_eq!(body["body_hash"], original.1);
                        match state.load(Ordering::SeqCst) {
                            0 => {
                                out["state"] = json!("RESULT_UNKNOWN");
                                out.as_object_mut().unwrap().remove("receipt");
                            }
                            1 => {
                                out["state"] = json!("HOST_QUEUED");
                                out["receipt"] = json!(format!("queued-{id}"));
                            }
                            3 => {
                                out["state"] = json!("NOT_SENT");
                                out["proof"] = json!("BOUND_HOST_RECONCILIATION");
                                out.as_object_mut().unwrap().remove("receipt");
                            }
                            4 => out["binding"]["call_id"] = json!("wrong-call"),
                            5 => out["frame_digest"] = json!("wrong-frame"),
                            6 => out["destination"]["session_id"] = json!("wrong-session"),
                            _ => {}
                        }
                    }
                }
                let wire = crate::communication_bridge::channel::response(
                    &"T".repeat(43),
                    &method,
                    &bytes,
                    &out,
                )
                .unwrap();
                let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",wire.len(),wire);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            endpoint,
            token_file,
            _directory: directory,
            receipt_state,
            busy,
            calls,
            stop,
            thread: Some(thread),
        }
    }
    pub fn config(&self) -> Value {
        json!({"kind":"bridge","endpoint":self.endpoint,"token_file":self.token_file,"destination":{"host":"CODEX_APP_SERVER","conversation_id":"bridge-thread","session_id":"bridge-session","bridge_id":"B".repeat(43)}})
    }
    pub fn calls(&self) -> Vec<Value> {
        self.calls.lock().unwrap().clone()
    }
}
impl Drop for BridgeFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[test]
#[ignore = "requires loopback synthetic bridge protocol fixture"]
fn bridge_receipt_reads_keep_original_call_and_reject_retargeted_evidence() {
    let fixture = BridgeFixture::start();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut host = Host::open(fixture.config(), runtime.handle().clone()).unwrap();
    let binding = json!({"call_id":"original-call"});
    let frame = json!({"message_id":"frozen-message","rendered_text":"synthetic original"});
    let digest = peerwork_core::crypto::sha256_hex(frame.to_string().as_bytes());
    assert_eq!(
        host.deliver(&binding, &frame).unwrap_err(),
        "HOST_ACK_UNKNOWN"
    );
    assert_eq!(
        host.reconcile(&binding, "frozen-message", &digest)
            .unwrap()
            .unwrap()["state"],
        "RESULT_UNKNOWN"
    );
    for bad in [4, 5, 6] {
        fixture.receipt_state.store(bad, Ordering::SeqCst);
        assert_eq!(
            host.reconcile(&binding, "frozen-message", &digest)
                .unwrap_err(),
            "HOST_ACK_UNKNOWN"
        );
    }
    fixture.receipt_state.store(2, Ordering::SeqCst);
    assert_eq!(
        host.reconcile(&binding, "frozen-message", &digest)
            .unwrap()
            .unwrap()["state"],
        "HOST_ACCEPTED"
    );
    assert_eq!(
        fixture
            .calls()
            .iter()
            .filter(|v| v["method"] == "deliver")
            .count(),
        1
    );
}

#[test]
#[ignore = "requires loopback synthetic host"]
fn codex_unloaded_original_recovers_and_distinguishes_system_error() {
    let fixture=CodexFixture::start();fixture.emit_events.store(false,Ordering::SeqCst);
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let mut host=Host::open(fixture.config(),runtime.handle().clone()).unwrap();
    let original=host.destination.clone();
    *fixture.status_override.lock().unwrap()=Some("notLoaded".into());
    assert_eq!(host.health(&json!({})).unwrap()["ready"],true);
    let calls=fixture.calls();let resume=calls.iter().find(|v|v["method"]=="thread/resume").unwrap();
    assert_eq!(resume["params"],json!({"threadId":"existing-thread","excludeTurns":true}));
    assert_eq!(host.destination,original);
    *fixture.status_override.lock().unwrap()=Some("systemError".into());
    let health=host.health(&json!({})).unwrap();assert_eq!(health["ready"],false);assert_eq!(health["reason"],"HOST_SESSION_ERROR");
    assert!(!fixture.calls().iter().any(|v|matches!(v["method"].as_str(),Some("turn/start"|"turn/steer"))));
    *fixture.status_override.lock().unwrap()=None;
    assert_eq!(host.health(&json!({})).unwrap()["ready"],true);
    drop(host);drop(fixture);
}
#[test]
#[ignore = "requires loopback synthetic host"]
fn host_operation_deadline_expires_while_diagnostics_remain_readable() {
    let fixture=CodexFixture::start();fixture.emit_events.store(false,Ordering::SeqCst);
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let budget=operation::Budget::new(Duration::from_millis(300));
    let mut host=Host::open_progress(fixture.config(),runtime.handle().clone(),budget.clone()).unwrap();
    fixture.stall_health.store(true,Ordering::SeqCst);
    let started=Instant::now();let worker=std::thread::spawn(move||{let result=host.health(&json!({}));drop(host);result});
    while budget.snapshot()["inflight"]!=true&&started.elapsed()<Duration::from_secs(2){std::thread::yield_now();}
    assert_eq!(budget.snapshot()["inflight"],true);
    let result=worker.join().unwrap();assert!(result.is_err());assert!(started.elapsed()<Duration::from_secs(2));
    assert!(budget.snapshot()["original_error_code"].as_str().is_some());
    fixture.stall_health.store(false,Ordering::SeqCst);drop(fixture);
}

#[test]
#[ignore="requires loopback slow byte transport"]
fn slow_partial_websocket_handshake_cannot_reset_the_operation_budget(){
    use std::io::{Read,Write};
    let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let endpoint=format!("ws://{}",listener.local_addr().unwrap());
    let server=std::thread::spawn(move||{
        let(mut stream,_)=listener.accept().unwrap();stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut request=[0;8192];let _=stream.read(&mut request);
        for byte in b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" {
            if stream.write_all(&[*byte]).is_err(){break;}
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let budget=operation::Budget::new(Duration::from_millis(250));let started=Instant::now();
    let result=Host::open_progress(json!({"kind":"codex","endpoint":endpoint,"thread_id":"existing-thread"}),runtime.handle().clone(),budget.clone());
    assert!(result.is_err());assert!(started.elapsed()<Duration::from_secs(2));
    assert_eq!(budget.snapshot()["failure_phase"],"HANDSHAKE");
    server.join().unwrap();
}
