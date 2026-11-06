//! Explicitly owned AGY stream-json process. One launch per bridge lifecycle;
//! no process/model is started by delivery or automatic reconnect.
use super::{random_token, text, R};
use crate::secure_state::SecureStateStore;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    runtime::Handle,
    sync::mpsc::{self, Receiver},
    task::JoinHandle,
};
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
                step["step_index"]
                    .as_u64()
                    .filter(|v| *v <= 9_007_199_254_740_991)
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
    pid: u32,
    process_token: Option<String>,
    executor: Handle,
    busy: bool,
    last_input: Option<u64>,
    attempted: bool,
    io_budget: Duration,
    shutdown_budget: Duration,
    failed: bool,
    aggregate: Option<super::operation::Budget>,
}
fn session_tool_settings(config: &Value) -> R<Option<String>> {
    let Some(server) = config.get("mcp_server") else {
        return Ok(None);
    };
    let server = server.as_str().ok_or("HOST_CONFIG_INVALID")?;
    let suffix = server
        .strip_prefix("peerwork-")
        .ok_or("HOST_CONFIG_INVALID")?;
    if suffix.len() != 16 || !suffix.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err("HOST_CONFIG_INVALID");
    }
    let allow: Vec<_> = crate::agent_tools::catalog()
        .iter()
        .map(|tool| {
            format!(
                "mcp({server}/{})",
                tool["name"].as_str().expect("native tool catalog name")
            )
        })
        .collect();
    // A local operator selected this owned native integration. Grant only its
    // exact tool names for this session; never grant shell/filesystem or change
    // global settings, sandbox policy, other MCP servers or remote permissions.
    Ok(Some(json!({"permissions":{"allow":allow}}).to_string()))
}
impl AgyStdio {
    pub fn open(config: &Value, executor: Handle) -> R<Self> {
        Self::open_inner(config,executor,None)
    }
    pub fn open_budget(config:&Value,executor:Handle,budget:super::operation::Budget)->R<Self>{Self::open_inner(config,executor,Some(budget))}
    fn open_inner(config: &Value, executor: Handle,aggregate:Option<super::operation::Budget>) -> R<Self> {
        if config["managed"] != true {
            return Err("AGY_STDIO_EXPLICIT_OWNERSHIP_REQUIRED");
        }
        let executable = text(config, "executable")?;
        let working = text(config, "working_directory")?;
        let conversation = text(config, "conversation_id")?;
        if !Path::new(executable).is_absolute()
            || !std::fs::metadata(executable).is_ok_and(|m| m.is_file())
            || !Path::new(working).is_absolute()
            || !std::fs::metadata(working).is_ok_and(|m| m.is_dir())
            || conversation.len() > 256
            || !conversation
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err("HOST_CONFIG_INVALID");
        }
        let settings = session_tool_settings(config)?;
        let fence_path = text(config, "launch_fence")?;
        if !Path::new(fence_path).is_absolute() {
            return Err("HOST_CONFIG_INVALID");
        }
        let fence = SecureStateStore::open(Path::new(fence_path))
            .map_err(|_| "AGY_STDIO_SESSION_ALREADY_OWNED")?;
        if let Some(bytes) = fence.read_exact().map_err(|_| "HOST_STATE_INVALID")? {
            let old: Value = serde_json::from_slice(&bytes).map_err(|_| "HOST_STATE_INVALID")?;
            if old["format"] != "peerwork.agy-stdio-launch.v2"
                || old["conversation_id"] != conversation
            {
                return Err("HOST_BINDING_MISMATCH");
            }
            match old["state"].as_str() {
                Some("STOPPED") => (),
                Some("OPENED" | "INPUT_ATTEMPTED") => {
                    let pid = old["pid"]
                        .as_u64()
                        .and_then(|v| u32::try_from(v).ok())
                        .filter(|pid| *pid > 0)
                        .ok_or("HOST_STATE_INVALID")?;
                    if crate::communication_store::process_alive(pid, old["process_token"].as_str())
                    {
                        return Err("AGY_STDIO_PREVIOUS_PROCESS_RUNNING");
                    }
                }
                // A crash between spawn and its durable PID record cannot be
                // force-reclaimed. It is distinct from an ordinary restart.
                Some("STARTING") => return Err("AGY_STDIO_LAUNCH_RECOVERY_REQUIRED"),
                _ => return Err("HOST_STATE_INVALID"),
            }
        }
        if aggregate.as_ref().is_some_and(|b|b.remaining().is_err()){return Err("HOST_PREFLIGHT_DEADLINE");}
        fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"STARTING","conversation_id":conversation}).to_string().as_bytes())
            .map_err(|_| "HOST_STATE_FAILED")?;
        let entered = executor.enter();
        let mut command = Command::new(executable);
        command.args([
            "--conversation",
            conversation,
            "--add-dir",
            working,
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
        ]);
        if let Some(settings) = settings {
            command.args(["--settings", &settings]);
        }
        if aggregate.as_ref().is_some_and(|b|b.remaining().is_err()){
            fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"STOPPED","conversation_id":conversation,"input_attempted":false}).to_string().as_bytes()).map_err(|_|"HOST_STATE_FAILED")?;
            return Err("HOST_PREFLIGHT_DEADLINE");
        }
        let spawned = command
            .current_dir(working)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(_) => {
                // No executable started and no input existed. Repairing a
                // local launch error must not require inventing another intent.
                let _ = fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"STOPPED","conversation_id":conversation,"input_attempted":false}).to_string().as_bytes());
                return Err("HOST_NOT_SENT");
            }
        };
        drop(entered);
        let pid = child.id().ok_or("HOST_STATE_INVALID")?;
        let process_token = crate::communication_store::process_token(pid);
        if fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"OPENED","conversation_id":conversation,"pid":pid,"process_token":process_token,"input_attempted":false}).to_string().as_bytes()).is_err() {
            let _ = executor.block_on(child.kill());
            let _ = executor.block_on(child.wait());
            return Err("HOST_STATE_FAILED");
        }
        let input = child.stdin.take().ok_or("HOST_STATE_INVALID")?;
        let output = child.stdout.take().ok_or("HOST_STATE_INVALID")?;
        let (tx, rx) = mpsc::channel(8);
        let reader = executor.spawn(async move {
            let mut reader = BufReader::new(output);
            loop {
                let mut bytes = Vec::new();
                let read: R<()> = async {
                    loop {
                        let chunk = reader.fill_buf().await.map_err(|_| "HOST_DISCONNECTED")?;
                        if chunk.is_empty() {
                            return Err("HOST_DISCONNECTED");
                        }
                        let end = chunk.iter().position(|b| *b == b'\n');
                        let used = end.map_or(chunk.len(), |at| at + 1);
                        if bytes.len() + used > MAX_EVENT as usize {
                            return Err("HOST_RESPONSE_INVALID");
                        }
                        bytes.extend_from_slice(&chunk[..used]);
                        reader.consume(used);
                        if end.is_some() {
                            return Ok(());
                        }
                    }
                }
                .await;
                let value = read.and_then(|_| {
                    serde_json::from_slice::<Value>(&bytes)
                        .map_err(|_| "HOST_RESPONSE_INVALID")
                        .and_then(|v| event(&v))
                });
                if matches!(value, Ok(Event::Ignore)) {
                    continue;
                }
                let terminal = value.is_err();
                if tx.send(value).await.is_err() || terminal {
                    break;
                }
            }
        });
        let mut host = Self {
            child,
            input: Some(input),
            events: Some(rx),
            reader: Some(reader),
            fence,
            conversation: conversation.into(),
            pid,
            process_token,
            executor,
            busy: false,
            last_input: None,
            attempted: false,
            io_budget: Duration::from_secs(10),
            shutdown_budget: Duration::from_secs(10),
            failed: false,
            aggregate,
        };
        match host.next(Instant::now() + Duration::from_secs(30))? {
            Event::Init(id) if id == host.conversation => Ok(host),
            _ => Err("HOST_BINDING_MISMATCH"),
        }
    }
    fn next(&mut self, deadline: Instant) -> R<Event> {
        let deadline=self.aggregate.as_ref().map(|b|deadline.min(b.deadline())).unwrap_or(deadline);
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or("HOST_ACK_UNKNOWN")?;
        let events = self.events.as_mut().ok_or("HOST_DISCONNECTED")?;
        self.executor.block_on(async {
            tokio::time::timeout(timeout, events.recv())
                .await
                .map_err(|_| "HOST_ACK_UNKNOWN")?
                .ok_or("HOST_DISCONNECTED")?
        })
    }
    fn drain(&mut self) -> R<()> {
        if self.failed {
            return Err("HOST_ACK_UNKNOWN");
        }
        for _ in 0..256 {
            if self.aggregate.as_ref().is_some_and(|b|b.remaining().is_err()){return Err("HOST_OPERATION_TIMEOUT");}
            let next = self.events.as_mut().ok_or("HOST_DISCONNECTED")?.try_recv();
            match next {
                Ok(Ok(Event::Result(id))) if id == self.conversation && self.busy => {
                    self.busy = false
                }
                Err(mpsc::error::TryRecvError::Empty) => return Ok(()),
                other => {
                    self.failed = true;
                    return Err(match other {
                        Ok(Err(code)) => code,
                        _ => "HOST_RESPONSE_INVALID",
                    });
                }
            }
        }
        Ok(())
    }
    pub fn health(&mut self) -> R<Value> {
        self.drain()?;
        if self
            .child
            .try_wait()
            .map_err(|_| "HOST_DISCONNECTED")?
            .is_some()
        {
            self.failed = true;
            return Err("HOST_DISCONNECTED");
        }
        Ok(
            json!({"ready":!self.busy,"can_attempt":!self.busy,"execution_state":if self.busy {"BUSY"} else {"IDLE"}}),
        )
    }
    pub fn deliver(&mut self, message: &Value) -> R<Value> {
        if self.health().map_err(|code| {
            if let Some(budget)=&self.aggregate {budget.failure(code,None);}
            "HOST_PREFLIGHT_FAILED"
        })?["ready"] != true {
            return Err("HOST_NOT_READY");
        }
        let rendered = text(message, "rendered_text")?;
        if rendered.len() > 48000 {
            return Err("HOST_INPUT_TOO_LARGE");
        }
        // The bridge journal, not the process marker, owns original call
        // certainty. Restarting this conversation never replays those calls.
        self.fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"INPUT_ATTEMPTED","conversation_id":self.conversation,"pid":self.pid,"process_token":self.process_token,"input_attempted":true}).to_string().as_bytes())
            .map_err(|_| "HOST_STATE_FAILED")?;
        if self.aggregate.as_ref().is_some_and(|b|b.remaining().is_err()){return Err("HOST_PREFLIGHT_DEADLINE");}
        self.attempted = true;
        let mut bytes = serde_json::to_vec(&json!({"event":"user","message":{"content":rendered}}))
            .map_err(|_| "HOST_INPUT_INVALID")?;
        bytes.push(b'\n');
        let deadline = self.aggregate.as_ref().map(|b|b.deadline().min(Instant::now()+self.io_budget)).unwrap_or_else(||Instant::now()+self.io_budget);
        let input = self.input.as_mut().ok_or("HOST_DISCONNECTED")?;
        let written = self.executor.block_on(async {
            tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), input.write_all(&bytes)).await
        });
        if !matches!(written, Ok(Ok(()))) {
            self.failed = true;
            return Err("HOST_ACK_UNKNOWN");
        }
        let result = self.next(deadline);
        match result {
            Ok(Event::Input(id, index))
                if id == self.conversation && self.last_input.is_none_or(|last| index > last) =>
            {
                self.last_input = Some(index);
                self.busy = true;
                Ok(
                    json!({"state":"HOST_ACCEPTED","receipt":format!("agy-stdio:{index}:{}",random_token()?),"execution_state":"BUSY","model_response":"NOT_ATTESTED"}),
                )
            }
            _ => {
                self.failed = true;
                Err("HOST_ACK_UNKNOWN")
            }
        }
    }
}
impl Drop for AgyStdio {
    fn drop(&mut self) {
        self.input.take();
        // EOF is the vendor's normal stream shutdown. Keep draining stdout so
        // the active turn can finish and persist its host/tool state. A signed
        // reply and inbox consumption can precede the native terminal result.
        if let Some(budget)=&self.aggregate{budget.phase("TERMINATING");}
        let (terminal, graceful) = self.executor.block_on(async {
            if let Ok(result) = tokio::time::timeout(self.shutdown_budget, self.child.wait()).await
            {
                return match result {
                    Ok(status) => (true, status.success()),
                    Err(_) => {
                        let _=self.child.start_kill();
                        loop {if self.child.wait().await.is_ok()||!crate::communication_store::process_alive(self.pid,self.process_token.as_deref()){break;}
                            if let Some(budget)=&self.aggregate{budget.phase("STALLED_TERMINATION");}tokio::time::sleep(Duration::from_millis(100)).await;}
                        (true,false)
                    },
                };
            }
            let _ = self.child.start_kill();
            loop {if self.child.wait().await.is_ok()||!crate::communication_store::process_alive(self.pid,self.process_token.as_deref()){break;}
                if let Some(budget)=&self.aggregate{budget.phase("STALLED_TERMINATION");}tokio::time::sleep(Duration::from_millis(100)).await;}
            (true, false)
        });
        self.events.take();
        if let Some(reader) = self.reader.take() {
            reader.abort();
            let _ = self.executor.block_on(reader);
        }
        if terminal {
            // This records process termination only. Accepted and unknown
            // inputs remain unchanged in the encrypted bridge journal.
            let _ = self.fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"STOPPED","conversation_id":self.conversation,"pid":self.pid,"process_token":self.process_token,"input_attempted":self.attempted,"graceful":graceful}).to_string().as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stub(root: &Path, bad_ack: bool) -> Value {
        let executable;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            executable = root.join("fake-agy.sh");
            let ack = if bad_ack {
                "agent_response"
            } else {
                "user_input"
            };
            let body = format!("#!/bin/sh\nprintf '%s\\n' start >> starts.txt\nprintf '%s\\n' '{{\"event\":\"init\",\"conversation_id\":\"owned-conversation\"}}'\nIFS= read -r line || exit 0\nprintf '%s\\n' '{{\"event\":\"step_update\",\"step_update\":{{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"{ack}\",\"step_index\":0}}}}'\n");
            let tail = if bad_ack {
                "exit 0\n"
            } else {
                "printf '%s\\n' '{\"event\":\"result\",\"result\":{\"conversation_id\":\"owned-conversation\"}}'\nIFS= read -r line || exit 0\nprintf '%s\\n' '{\"event\":\"step_update\",\"step_update\":{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"user_input\",\"step_index\":2}}'\nIFS= read -r line\n"
            };
            std::fs::write(&executable, body + tail).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        {
            executable = root.join("fake-agy.cmd");
            let ack = if bad_ack {
                "agent_response"
            } else {
                "user_input"
            };
            let body = format!("@echo off\r\necho start>>starts.txt\r\necho {{\"event\":\"init\",\"conversation_id\":\"owned-conversation\"}}\r\nset /p line=\r\necho {{\"event\":\"step_update\",\"step_update\":{{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"{ack}\",\"step_index\":0}}}}\r\n");
            let tail = if bad_ack {
                "exit /b 0\r\n"
            } else {
                "echo {\"event\":\"result\",\"result\":{\"conversation_id\":\"owned-conversation\"}}\r\nset /p line=\r\necho {\"event\":\"step_update\",\"step_update\":{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"user_input\",\"step_index\":2}}\r\nset /p line=\r\n"
            };
            std::fs::write(&executable, body + tail).unwrap();
        }
        json!({"kind":"agy-stdio","managed":true,"executable":executable,"working_directory":root,
            "conversation_id":"owned-conversation","launch_fence":root.join("launch.state")})
    }
    #[test]
    fn explicit_native_install_grants_only_its_exact_mcp_tools_for_one_session() {
        assert!(session_tool_settings(&json!({})).unwrap().is_none());
        let server = "peerwork-0123456789abcdef";
        let value: Value = serde_json::from_str(
            &session_tool_settings(&json!({"mcp_server":server}))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let allowed = value["permissions"]["allow"].as_array().unwrap();
        assert_eq!(allowed.len(), crate::agent_tools::catalog().len());
        assert!(allowed
            .iter()
            .any(|v| v == &format!("mcp({server}/peerwork_reply)")));
        assert!(allowed.iter().all(|v| v
            .as_str()
            .unwrap()
            .starts_with(&format!("mcp({server}/peerwork_"))
            && !v.as_str().unwrap().contains('*')));
        assert_eq!(value.as_object().unwrap().len(), 1);
        assert_eq!(value["permissions"].as_object().unwrap().len(), 1);
        for invalid in [
            "*",
            "other-server",
            "peerwork-*",
            "peerwork-0123456789abcde/",
        ] {
            assert!(session_tool_settings(&json!({"mcp_server":invalid})).is_err());
        }
    }
    #[test]
    fn invalid_session_tool_selection_has_no_launch_or_recovery_side_effects() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let mut config = stub(root.path(), false);
        config["mcp_server"] = json!("*");
        assert!(matches!(
            AgyStdio::open(&config, rt.handle().clone()),
            Err("HOST_CONFIG_INVALID")
        ));
        assert!(!root.path().join("launch.state").exists());
        assert!(!root.path().join("starts.txt").exists());
        config.as_object_mut().unwrap().remove("mcp_server");
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
    }
    #[test]
    fn one_process_handles_two_inputs_and_terminal_restart_does_not_replay() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let mut host = AgyStdio::open(&config, rt.handle().clone()).unwrap();
        assert_eq!(host.health().unwrap()["execution_state"], "IDLE");
        assert_eq!(
            host.deliver(&json!({"rendered_text":"first external data"}))
                .unwrap()["state"],
            "HOST_ACCEPTED"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while host.health().unwrap()["ready"] != true {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            host.deliver(&json!({"rendered_text":"second external data"}))
                .unwrap()["state"],
            "HOST_ACCEPTED"
        );
        drop(host);
        assert_eq!(
            std::fs::read_to_string(root.path().join("starts.txt"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
        assert_eq!(
            std::fs::read_to_string(root.path().join("starts.txt"))
                .unwrap()
                .lines()
                .count(),
            2
        );
        let fence = SecureStateStore::open(&root.path().join("launch.state")).unwrap();
        let saved: Value = serde_json::from_slice(&fence.read_exact().unwrap().unwrap()).unwrap();
        assert_eq!(saved["state"], "STOPPED");
        assert_eq!(saved["input_attempted"], false);
    }
    #[test]
    fn disappeared_child_before_input_is_proven_not_sent() {
        let rt=tokio::runtime::Runtime::new().unwrap();
        let root=crate::test_support::protected_test_dir();
        let config=stub(root.path(),false);
        let mut host=AgyStdio::open(&config,rt.handle().clone()).unwrap();
        assert_eq!(host.health().unwrap()["ready"],true);
        rt.block_on(async{host.child.kill().await.unwrap();});
        let result=host.deliver(&json!({"rendered_text":"must not be written"}));
        assert_eq!(result.unwrap_err(),"HOST_PREFLIGHT_FAILED");
        assert!(!host.attempted);
        let outcome=crate::participant_dispatch::host_outcome("agy-stdio",Err("HOST_PREFLIGHT_FAILED"));
        assert_eq!(serde_json::to_value(outcome).unwrap()["state"],"NOT_SENT");
        drop(host);
        let replacement=AgyStdio::open(&config,rt.handle().clone()).unwrap();
        assert!(!replacement.attempted);
    }
    #[test]
    fn running_previous_process_is_not_replaced() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let pid = std::process::id();
        let fence = SecureStateStore::open(&root.path().join("launch.state")).unwrap();
        fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"INPUT_ATTEMPTED","conversation_id":"owned-conversation","pid":pid,"process_token":crate::communication_store::process_token(pid)}).to_string().as_bytes()).unwrap();
        drop(fence);
        assert!(matches!(
            AgyStdio::open(&config, rt.handle().clone()),
            Err("AGY_STDIO_PREVIOUS_PROCESS_RUNNING")
        ));
        assert!(!root.path().join("starts.txt").exists());
    }
    #[test]
    fn terminated_previous_process_can_resume_same_conversation_without_input() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let host = AgyStdio::open(&config, rt.handle().clone()).unwrap();
        let pid = host.pid;
        let token = host.process_token.clone();
        drop(host);
        assert!(!crate::communication_store::process_alive(
            pid,
            token.as_deref()
        ));
        // Simulate a crash after process exit but before the STOPPED marker.
        let fence = SecureStateStore::open(&root.path().join("launch.state")).unwrap();
        fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":"INPUT_ATTEMPTED","conversation_id":"owned-conversation","pid":pid,"process_token":token}).to_string().as_bytes()).unwrap();
        drop(fence);
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
        let fence = SecureStateStore::open(&root.path().join("launch.state")).unwrap();
        let saved: Value = serde_json::from_slice(&fence.read_exact().unwrap().unwrap()).unwrap();
        assert_eq!(saved["state"], "STOPPED");
        assert_eq!(saved["input_attempted"], false);
    }
    #[test]
    fn uncertain_launch_and_different_conversation_are_not_force_reclaimed() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        for (state, conversation, pid, expected) in [
            (
                "STARTING",
                "owned-conversation",
                1,
                "AGY_STDIO_LAUNCH_RECOVERY_REQUIRED",
            ),
            (
                "STOPPED",
                "different-conversation",
                1,
                "HOST_BINDING_MISMATCH",
            ),
            ("OPENED", "owned-conversation", 0, "HOST_STATE_INVALID"),
        ] {
            let fence = SecureStateStore::open(&root.path().join("launch.state")).unwrap();
            fence.write_exact(json!({"format":"peerwork.agy-stdio-launch.v2","state":state,"conversation_id":conversation,"pid":pid}).to_string().as_bytes()).unwrap();
            drop(fence);
            assert!(
                matches!(AgyStdio::open(&config,rt.handle().clone()),Err(code) if code == expected)
            );
        }
        assert!(!root.path().join("starts.txt").exists());
    }
    #[test]
    fn wrong_event_never_attests_acceptance_or_replays_unknown_input() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), true);
        let mut host = AgyStdio::open(&config, rt.handle().clone()).unwrap();
        assert_eq!(
            host.deliver(&json!({"rendered_text":"possibly received"}))
                .unwrap_err(),
            "HOST_ACK_UNKNOWN"
        );
        drop(host);
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
        assert_eq!(
            std::fs::read_to_string(root.path().join("starts.txt"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }
    #[test]
    fn metadata_only_terminal_process_can_retry_but_requires_explicit_ownership() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let mut unowned = config.clone();
        unowned["managed"] = json!(false);
        assert!(matches!(
            AgyStdio::open(&unowned, rt.handle().clone()),
            Err("AGY_STDIO_EXPLICIT_OWNERSHIP_REQUIRED")
        ));
        assert!(!root.path().join("starts.txt").exists());
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
        assert_eq!(
            std::fs::read_to_string(root.path().join("starts.txt"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }
    #[cfg(unix)]
    #[test]
    fn proven_failed_spawn_can_retry_after_local_repair() {
        use std::os::unix::fs::PermissionsExt;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let executable = Path::new(config["executable"].as_str().unwrap());
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            AgyStdio::open(&config, rt.handle().clone()),
            Err("HOST_NOT_SENT")
        ));
        assert!(!root.path().join("starts.txt").exists());
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
    }
    #[cfg(unix)]
    #[test]
    fn graceful_eof_persists_host_state_before_release() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        std::fs::write(config["executable"].as_str().unwrap(),concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' '{\"event\":\"init\",\"conversation_id\":\"owned-conversation\"}'\n",
            "IFS= read -r line || exit 1\n",
            "printf '%s\\n' '{\"event\":\"step_update\",\"step_update\":{\"conversation_id\":\"owned-conversation\",\"state\":\"DONE\",\"step_type\":\"user_input\",\"step_index\":0}}'\n",
            "while IFS= read -r line; do :; done\n",
            "sleep 0.05\nprintf saved > flushed.txt\n")).unwrap();
        let mut host = AgyStdio::open(&config, rt.handle().clone()).unwrap();
        host.shutdown_budget = Duration::from_secs(2);
        assert_eq!(
            host.deliver(&json!({"rendered_text":"test input"}))
                .unwrap()["state"],
            "HOST_ACCEPTED"
        );
        drop(host);
        assert_eq!(
            std::fs::read_to_string(root.path().join("flushed.txt")).unwrap(),
            "saved"
        );
        let fence = SecureStateStore::open(&root.path().join("launch.state")).unwrap();
        let saved: Value = serde_json::from_slice(&fence.read_exact().unwrap().unwrap()).unwrap();
        assert_eq!(saved["state"], "STOPPED");
        assert_eq!(saved["graceful"], true);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn blocked_pipe_write_is_bounded_and_cannot_replay() {
        use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = crate::test_support::protected_test_dir();
        let config = stub(root.path(), false);
        let fifo = std::ffi::CString::new(
            root.path()
                .join("stall.fifo")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let executable = Path::new(config["executable"].as_str().unwrap());
        std::fs::write(executable,"#!/bin/sh\nprintf '%s\\n' '{\"event\":\"init\",\"conversation_id\":\"owned-conversation\"}'\nread stalled < stall.fifo\n").unwrap();
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut host = AgyStdio::open(&config, rt.handle().clone()).unwrap();
        assert!(
            unsafe {
                libc::fcntl(
                    host.input.as_ref().unwrap().as_raw_fd(),
                    libc::F_SETPIPE_SZ,
                    4096,
                )
            } >= 4096
        );
        host.io_budget = Duration::from_millis(250);
        host.shutdown_budget = Duration::from_millis(250);
        let pid = host.child.id().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let outcome = host.deliver(&json!({"rendered_text":"X".repeat(48000)}));
            drop(host);
            tx.send(outcome).unwrap();
        });
        let observed = rx.recv_timeout(Duration::from_secs(3));
        if observed.is_err() {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
        worker.join().unwrap();
        assert!(matches!(observed, Ok(Err("HOST_ACK_UNKNOWN"))));
        drop(AgyStdio::open(&config, rt.handle().clone()).unwrap());
    }
    #[test]
    fn only_native_user_input_done_is_an_ack() {
        assert!(
            matches!(event(&json!({"event":"step_update","step_update":{"step_type":"user_input","state":"DONE","conversation_id":"owned","step_index":4}})).unwrap(),Event::Input(id,4) if id=="owned")
        );
        for kind in ["tool", "agent_response"] {
            assert!(matches!(
                event(
                    &json!({"event":"step_update","step_update":{"step_type":kind,"state":"DONE"}})
                )
                .unwrap(),
                Event::Ignore
            ));
        }
        assert!(event(&json!({"event":"step_update","step_update":{"step_type":"user_input","state":"DONE","conversation_id":"owned","step_index":-1}})).is_err());
    }
}
