//! Explicitly owned AGY stream-json process. One launch per physical binding;
//! no process/model is started by delivery or automatic reconnect.
use super::{random_token, text, R};
use crate::secure_state::SecureStateStore;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, process::{Child, ChildStdin, Command}, runtime::Handle, sync::mpsc::{self, Receiver}, task::JoinHandle};
const MAX_EVENT: u64 = 2 * 1024 * 1024;
#[derive(Debug)]
enum Event {
    Init(String),
    Input(String, u64),
    Result(String),
    Ignore,
}
fn event(value: &Value) -> R<Event> {
    Ok(match value["event"].as_str() {
        Some("init") => Event::Init(text(value, "conversation_id")?.into()),
        Some("step_update")
            if value["step_update"]["step_type"] == "user_input"
                && value["step_update"]["state"] == "DONE" =>
        {
            let step = &value["step_update"];
            Event::Input(
                text(step, "conversation_id")?.into(),
                step["step_index"].as_u64().filter(|v| *v <= 9_007_199_254_740_991)
                    .ok_or("HOST_RESPONSE_INVALID")?,
            )
        }
        Some("result") => Event::Result(text(&value["result"], "conversation_id")?.into()),
        Some("error") => return Err("HOST_RESPONSE_INVALID"),
        _ => Event::Ignore,
    })
}
pub(super) struct AgyStdio {
    child: Child,
    input: Option<ChildStdin>,
    events: Option<Receiver<R<Event>>>,
    reader: Option<JoinHandle<()>>,
    fence: SecureStateStore,
    conversation: String,
    session: String,
    executor: Handle,
    busy: bool,
    last_input: Option<u64>,
    attempted: bool,
    failed: bool,
}
impl AgyStdio {
    pub fn open(config: &Value, executor: Handle) -> R<Self> {
        if config["managed"] != true {
            return Err("AGY_STDIO_EXPLICIT_OWNERSHIP_REQUIRED");
        }
        let executable = text(config, "executable")?;
        let working = text(config, "working_directory")?;
        let conversation = text(config, "conversation_id")?;
        let session = text(config, "session_id")?;
        if !Path::new(executable).is_absolute()
            || !std::fs::metadata(executable).is_ok_and(|m| m.is_file())
            || !Path::new(working).is_absolute()
            || !std::fs::metadata(working).is_ok_and(|m| m.is_dir())
            || conversation.len() > 256
            || !conversation.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            || session.len() < 16 || session.len() > 128
            || !session.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err("HOST_CONFIG_INVALID");
        }
        let fence_path = text(config, "launch_fence")?;
        if !Path::new(fence_path).is_absolute() { return Err("HOST_CONFIG_INVALID"); }
        let fence = SecureStateStore::open(Path::new(fence_path))
            .map_err(|_| "AGY_STDIO_SESSION_ALREADY_OWNED")?;
        if let Some(bytes) = fence.read_exact().map_err(|_| "HOST_STATE_INVALID")? {
            let old: Value = serde_json::from_slice(&bytes).map_err(|_| "HOST_STATE_INVALID")?;
            if old["format"] != "peerwork.agy-stdio-launch.v1" || old["state"] != "STOPPED_WITHOUT_INPUT" || old["session_id"] != session {
                return Err("AGY_STDIO_RESTART_REQUIRES_REBIND");
            }
        }
        fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v1","state":"STARTING","session_id":session}).to_string().as_bytes())
            .map_err(|_| "HOST_STATE_FAILED")?;
        let entered = executor.enter();
        let mut child = Command::new(executable)
            .args(["--conversation", conversation, "--add-dir", working, "--input-format", "stream-json", "--output-format", "stream-json"])
            .current_dir(working).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::null()).kill_on_drop(true).spawn().map_err(|_| "HOST_NOT_SENT")?;
        let input = child.stdin.take().ok_or("HOST_STATE_INVALID")?;
        let output = child.stdout.take().ok_or("HOST_STATE_INVALID")?;
        drop(entered);
        let (tx, rx) = mpsc::channel(8);
        let reader = executor.spawn(async move {
            let mut reader = BufReader::new(output);
            loop {
                let mut bytes = Vec::new();
                let read: R<()> = async {
                    loop {
                        let chunk = reader.fill_buf().await.map_err(|_| "HOST_DISCONNECTED")?;
                        if chunk.is_empty() { return Err("HOST_DISCONNECTED"); }
                        let end = chunk.iter().position(|b| *b == b'\n');
                        let used = end.map_or(chunk.len(), |at| at + 1);
                        if bytes.len() + used > MAX_EVENT as usize { return Err("HOST_RESPONSE_INVALID"); }
                        bytes.extend_from_slice(&chunk[..used]);
                        reader.consume(used);
                        if end.is_some() { return Ok(()); }
                    }
                }.await;
                let value = read.and_then(|_| serde_json::from_slice::<Value>(&bytes)
                    .map_err(|_| "HOST_RESPONSE_INVALID").and_then(|v| event(&v)));
                if matches!(value, Ok(Event::Ignore)) { continue; }
                let terminal = value.is_err();
                if tx.send(value).await.is_err() || terminal { break; }
            }
        });
        let mut host = Self { child, input: Some(input), events: Some(rx), reader: Some(reader),
            fence, conversation: conversation.into(), session: session.into(), executor, busy: false, last_input: None, attempted: false, failed: false };
        match host.next(Instant::now() + Duration::from_secs(30))? {
            Event::Init(id) if id == host.conversation => Ok(host),
            _ => Err("HOST_BINDING_MISMATCH"),
        }
    }
    fn next(&mut self, deadline: Instant) -> R<Event> {
        let timeout = deadline.checked_duration_since(Instant::now()).ok_or("HOST_ACK_UNKNOWN")?;
        let events = self.events.as_mut().ok_or("HOST_DISCONNECTED")?;
        self.executor.block_on(async { tokio::time::timeout(timeout, events.recv()).await
            .map_err(|_| "HOST_ACK_UNKNOWN")?.ok_or("HOST_DISCONNECTED")? })
    }
    fn drain(&mut self) -> R<()> {
        if self.failed { return Err("HOST_ACK_UNKNOWN"); }
        loop {
            let next = self.events.as_mut().ok_or("HOST_DISCONNECTED")?.try_recv();
            match next {
                Ok(Ok(Event::Result(id))) if id == self.conversation && self.busy => self.busy = false,
                Err(mpsc::error::TryRecvError::Empty) => return Ok(()),
                other => {
                    self.failed = true;
                    return Err(match other { Ok(Err(code)) => code, _ => "HOST_RESPONSE_INVALID" });
                }
            }
        }
    }
    pub fn health(&mut self) -> R<Value> {
        self.drain()?;
        if self.child.try_wait().map_err(|_| "HOST_DISCONNECTED")?.is_some() {
            self.failed = true;
            return Err("HOST_DISCONNECTED");
        }
        Ok(json!({"ready":!self.busy,"can_attempt":!self.busy,"execution_state":if self.busy {"BUSY"} else {"IDLE"}}))
    }
    pub fn deliver(&mut self, message: &Value) -> R<Value> {
        if self.health()?["ready"] != true { return Err("HOST_NOT_READY"); }
        let rendered = text(message, "rendered_text")?;
        if rendered.len() > 48000 { return Err("HOST_INPUT_TOO_LARGE"); }
        // This fenced attempt survives a lost pipe reply or bridge crash. A
        // new physical process needs an explicit new binding; never replay.
        self.fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v1","state":"INPUT_ATTEMPTED","session_id":self.session}).to_string().as_bytes())
            .map_err(|_| "HOST_STATE_FAILED")?;
        self.attempted = true;
        let mut bytes = serde_json::to_vec(&json!({"event":"user","message":{"content":rendered}}))
            .map_err(|_| "HOST_INPUT_INVALID")?;
        bytes.push(b'\n');
        let input = self.input.as_mut().ok_or("HOST_DISCONNECTED")?;
        if self.executor.block_on(input.write_all(&bytes)).is_err() {
            self.failed = true; return Err("HOST_ACK_UNKNOWN");
        }
        let result = self.next(Instant::now() + Duration::from_secs(10));
        match result {
            Ok(Event::Input(id, index)) if id == self.conversation && self.last_input.is_none_or(|last| index > last) => {
                self.last_input = Some(index); self.busy = true;
                Ok(json!({"state":"HOST_ACCEPTED","receipt":format!("agy-stdio:{index}:{}",random_token()?),"execution_state":"BUSY","model_response":"NOT_ATTESTED"}))
            }
            _ => { self.failed = true; Err("HOST_ACK_UNKNOWN") }
        }
    }
}
impl Drop for AgyStdio {
    fn drop(&mut self) {
        self.input.take();
        self.events.take();
        if let Some(reader) = self.reader.take() {
            reader.abort();
            let _ = self.executor.block_on(reader);
        }
        let terminal = self.executor.block_on(async {
            if self.child.try_wait().ok().flatten().is_none() { let _ = self.child.start_kill(); }
            self.child.wait().await.is_ok()
        });
        if terminal && !self.attempted {
            // Safe retry only when this exact owned process is terminal and
            // no input was ever attempted. A crash retains STARTING instead.
            let _ = self.fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v1","state":"STOPPED_WITHOUT_INPUT","session_id":self.session}).to_string().as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stub(root: &Path, bad_ack: bool) -> Value {
        let executable;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            executable = root.join("fake-agy.sh");
            let ack = if bad_ack { "agent_response" } else { "user_input" };
            let body = format!("#!/bin/sh\nprintf '%s\\n' start >> starts.txt\nprintf '%s\\n' '{{\"event\":\"init\",\"conversation_id\":\"owned-conversation\"}}'\nIFS= read -r line || exit 0\nprintf '%s\\n' '{{\"event\":\"step_update\",\"step_update\":{{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"{ack}\",\"step_index\":0}}}}'\n");
            let tail = if bad_ack { "exit 0\n" } else { "printf '%s\\n' '{\"event\":\"result\",\"result\":{\"conversation_id\":\"owned-conversation\"}}'\nIFS= read -r line || exit 0\nprintf '%s\\n' '{\"event\":\"step_update\",\"step_update\":{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"user_input\",\"step_index\":2}}'\nIFS= read -r line\n" };
            std::fs::write(&executable, body + tail).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)] {
            executable = root.join("fake-agy.cmd");
            let ack = if bad_ack { "agent_response" } else { "user_input" };
            let body = format!("@echo off\r\necho start>>starts.txt\r\necho {{\"event\":\"init\",\"conversation_id\":\"owned-conversation\"}}\r\nset /p line=\r\necho {{\"event\":\"step_update\",\"step_update\":{{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"{ack}\",\"step_index\":0}}}}\r\n");
            let tail = if bad_ack { "exit /b 0\r\n" } else { "echo {\"event\":\"result\",\"result\":{\"conversation_id\":\"owned-conversation\"}}\r\nset /p line=\r\necho {\"event\":\"step_update\",\"step_update\":{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"user_input\",\"step_index\":2}}\r\nset /p line=\r\n" };
            std::fs::write(&executable, body + tail).unwrap();
        }
        json!({"kind":"agy-stdio","managed":true,"executable":executable,"working_directory":root,
            "conversation_id":"owned-conversation","session_id":"explicit-physical-session-1","launch_fence":root.join("launch.state")})
    }
    #[test]
    fn one_process_handles_two_inputs_and_refuses_unreviewed_restart() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let mut host = AgyStdio::open(&config, rt.handle().clone()).unwrap();
        assert_eq!(host.health().unwrap()["execution_state"], "IDLE");
        assert_eq!(host.deliver(&json!({"rendered_text":"first external data"})).unwrap()["state"],"HOST_ACCEPTED");
        let deadline = Instant::now() + Duration::from_secs(2);
        while host.health().unwrap()["ready"] != true { assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(5)); }
        assert_eq!(host.deliver(&json!({"rendered_text":"second external data"})).unwrap()["state"],"HOST_ACCEPTED");
        drop(host);
        assert_eq!(std::fs::read_to_string(root.path().join("starts.txt")).unwrap().lines().count(),1);
        assert!(matches!(AgyStdio::open(&config,rt.handle().clone()),Err("AGY_STDIO_RESTART_REQUIRES_REBIND")));
    }
    #[test]
    fn wrong_event_never_attests_acceptance_or_replays_unknown_input() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), true);
        let mut host = AgyStdio::open(&config,rt.handle().clone()).unwrap();
        assert_eq!(host.deliver(&json!({"rendered_text":"possibly received"})).unwrap_err(),"HOST_ACK_UNKNOWN");
        drop(host);
        assert!(matches!(AgyStdio::open(&config,rt.handle().clone()),Err("AGY_STDIO_RESTART_REQUIRES_REBIND")));
        assert_eq!(std::fs::read_to_string(root.path().join("starts.txt")).unwrap().lines().count(),1);
    }
    #[test]
    fn metadata_only_terminal_process_can_retry_but_requires_explicit_ownership() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let mut unowned = config.clone();unowned["managed"] = json!(false);
        assert!(matches!(AgyStdio::open(&unowned,rt.handle().clone()),Err("AGY_STDIO_EXPLICIT_OWNERSHIP_REQUIRED")));
        assert!(!root.path().join("starts.txt").exists());
        drop(AgyStdio::open(&config,rt.handle().clone()).unwrap());
        drop(AgyStdio::open(&config,rt.handle().clone()).unwrap());
        assert_eq!(std::fs::read_to_string(root.path().join("starts.txt")).unwrap().lines().count(),2);
    }
    #[test]
    #[ignore = "requires explicit protected config selecting an owned synthetic existing AGY conversation"]
    fn real_selected_cli_two_input_receipts() {
        let config_path = std::env::var("PEERWORK_AGY_STDIO_CONFIG").unwrap();
        let report_path = std::env::var("PEERWORK_AGY_STDIO_REPORT").unwrap();
        assert!(Path::new(&report_path).is_absolute() && !Path::new(&report_path).exists());
        let config = crate::communication_store::private_json(Path::new(&config_path),65536).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut host = super::super::Host::open(config,rt.handle().clone()).unwrap();
        let mut samples = Vec::new();
        for index in 0..2 {
            let deadline = Instant::now()+Duration::from_secs(90);
            while host.health(&json!({})).unwrap()["ready"] != true { assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(20)); }
            let before = Instant::now();
            let receipt = host.deliver(&json!({}),&json!({"rendered_text":format!("Peerwork isolated native stdio interoperability check. Reply exactly PW-AGY-NATIVE-{index}. Do not use tools or read files. Preserve all task permissions.")})).unwrap();
            assert_eq!(receipt["state"],"HOST_ACCEPTED");
            samples.push(json!({"index":index,"host_accepted_ms":before.elapsed().as_secs_f64()*1000.,"state":receipt["state"]}));
            assert_eq!(host.health(&json!({})).unwrap()["execution_state"],"BUSY");
        }
        let destination=host.destination.clone();drop(host);
        std::fs::write(report_path,serde_json::to_vec_pretty(&json!({"state":"PASS","destination":destination,"samples":samples,"process_reused":true,"owned_process_stopped":true,"model_reply":"NOT_ATTESTED","peerwork_service":"NOT_EXERCISED","scope":"Two native provider receipts, not IM percentiles"})).unwrap()).unwrap();
    }
    #[test]
    fn only_native_user_input_done_is_an_ack() {
        assert!(matches!(event(&json!({"event":"step_update","step_update":{"step_type":"user_input","state":"DONE","conversation_id":"owned","step_index":4}})).unwrap(),Event::Input(id,4) if id=="owned"));
        for kind in ["tool","agent_response"] {
            assert!(matches!(event(&json!({"event":"step_update","step_update":{"step_type":kind,"state":"DONE"}})).unwrap(),Event::Ignore));
        }
        assert!(event(&json!({"event":"step_update","step_update":{"step_type":"user_input","state":"DONE","conversation_id":"owned","step_index":-1}})).is_err());
    }
}
