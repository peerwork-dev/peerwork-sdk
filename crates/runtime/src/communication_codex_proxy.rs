//! Byte transport to an existing Codex daemon. WebSocket framing is performed
//! by the shared host adapter, including over these stdio proxy pipes. The only child command is the
//! official control-socket proxy; it never creates a server, thread or model.
use serde_json::Value;
use super::operation::Budget;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin},
    sync::mpsc,
};
type R<T> = Result<T, &'static str>;

pub(super) fn executable(explicit: Option<&str>) -> R<PathBuf> {
    let path = if let Some(path) = explicit {
        PathBuf::from(path)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").ok_or("CODEX_EXECUTABLE_REQUIRED")?)
            .filter(|p| p.is_absolute())
            .map(|p| p.join(if cfg!(windows) { "codex.exe" } else { "codex" }))
            .find(|p| p.is_file())
            .ok_or("CODEX_EXECUTABLE_REQUIRED")?
    };
    if !path.is_absolute() {
        return Err("CODEX_EXECUTABLE_INVALID");
    }
    let path = std::fs::canonicalize(path).map_err(|_| "CODEX_EXECUTABLE_INVALID")?;
    let meta = std::fs::metadata(&path).map_err(|_| "CODEX_EXECUTABLE_INVALID")?;
    if !meta.is_file() {
        return Err("CODEX_EXECUTABLE_INVALID");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o111 == 0
            || meta.mode() & 0o022 != 0
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
        {
            return Err("CODEX_EXECUTABLE_UNTRUSTED");
        }
        crate::onboarding_files::check_directory(
            path.parent().ok_or("CODEX_EXECUTABLE_INVALID")?,
            false,
        )
        .map_err(|_| "CODEX_EXECUTABLE_UNTRUSTED")?;
    }
    Ok(path)
}

/// Pin the host installation once, independently of the signer's later environment.
pub(super) fn pin_installation(config: &mut Value) -> R<()> {
    let home = std::env::var_os("CODEX_HOME").map(PathBuf::from).or_else(||
        std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".codex")))
        .filter(|p| p.is_absolute()).ok_or("CODEX_HOME_REQUIRED")?;
    config["codex_home"] = serde_json::json!(home);
    #[cfg(unix)]
    { config["codex_uid"] = serde_json::json!(unsafe { libc::geteuid() }); }
    Ok(())
}

/// The pinned installation's normal daemon can outlive an explicit socket
/// selected for an earlier owner. Never search other users' installations.
pub(super) fn default_route(config: &Value) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if config["endpoint"] != "codex-proxy://local"
            || config["codex_uid"].as_u64() != Some(unsafe { libc::geteuid() } as u64)
        {
            return None;
        }
        let previous = Path::new(config["control_socket"].as_str()?);
        let home = Path::new(config["codex_home"].as_str()?);
        if !home.is_absolute() { return None; }
        let directory = home.join("app-server-control");
        let directory_owner = std::fs::metadata(&directory).ok()?.uid();
        if directory_owner as u64 != config["codex_uid"].as_u64()? { return None; }
        let path = directory.join("app-server-control.sock");
        let meta = std::fs::metadata(&path).ok()?;
        if !meta.file_type().is_socket() || meta.uid() as u64 != config["codex_uid"].as_u64()? {
            return None;
        }
        if previous == path || std::fs::canonicalize(previous).ok().as_ref()
            == Some(&std::fs::canonicalize(&path).ok()?)
        {
            return None;
        }
        return Some(format!("unix://{}", path.to_str()?));
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        None
    }
}

fn configure_installation(command: &mut tokio::process::Command, config: &Value) -> R<()> {
    if let Some(home) = config.get("codex_home") {
        let home = home.as_str().filter(|p| Path::new(p).is_absolute())
            .ok_or("CODEX_HOME_INVALID")?;
        command.env("CODEX_HOME", home);
    }
    #[cfg(unix)]
    if let Some(uid) = config.get("codex_uid") {
        if uid.as_u64() != Some(unsafe { libc::geteuid() } as u64) {
            return Err("CODEX_HOST_USER_MISMATCH");
        }
    }
    Ok(())
}

fn queue_thread(config: &Value) -> R<&str> {
    let thread = super::text(config, "thread_id")?;
    let id = thread.as_bytes();
    if id.len() != 36 || id.iter().enumerate().any(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { *byte != b'-' } else { !byte.is_ascii_hexdigit() }
    }) || config["expected_session_id"] != thread {
        return Err("HOST_SESSION_BINDING_UNAVAILABLE");
    }
    Ok(thread)
}

pub(super) fn pinned_queue_recovery(config: &Value) -> bool {
    config["kind"] == "codex" && config["endpoint"] == "codex-proxy://local"
        && config["codex_executable"].is_string() && config["codex_home"].is_string()
        && config["codex_uid"].is_u64() && config["auth_token_env"].is_null()
        && queue_thread(config).is_ok()
}

pub(super) fn validate_queue_target(config: &Value) -> R<()> {
    queue_thread(config)?;
    if config["codex_executable"].as_str().is_none()
        || config["codex_home"].as_str().is_none()
        || config["codex_uid"].as_u64().is_none()
        || !config["auth_token_env"].is_null() {
        return Err("HOST_CONFIG_INVALID");
    }
    let home = Path::new(super::text(config, "codex_home")?);
    crate::onboarding_files::check_directory(home, true).map_err(|_| "CODEX_HOME_INVALID")?;
    let mut command = tokio::process::Command::new(executable(config["codex_executable"].as_str())?);
    configure_installation(&mut command, config)
}

pub(super) fn recoverable_queue_route(config: &Value, code: &str) -> bool {
    if config["local_queue_only"] == true || !pinned_queue_recovery(config) {
        return false;
    }
    matches!(code, "HOST_SESSION_NOT_LOADED" | "HOST_SESSION_OWNERSHIP_CONFLICT")
        || code == "HOST_WEBSOCKET_HANDSHAKE_FAILED"
            && config["control_socket"].as_str().is_some_and(|socket| {
                let socket = Path::new(socket);
                socket.is_absolute() && std::fs::symlink_metadata(socket)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            })
}

pub(super) fn queue_notification(config: &Value, executor: &tokio::runtime::Handle,
    budget: &Budget, message: &Value) -> R<Value> {
    validate_queue_target(config)?;
    let batch = message["batch"].as_str().filter(|batch| batch.len() == 43
        && batch.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        .filter(|_| message["format"] == "peerwork.notification-frame.v1").ok_or("HOST_INPUT_INVALID")?;
    let mut command = tokio::process::Command::new(executable(config["codex_executable"].as_str())?);
    configure_installation(&mut command, config)?;
    command.args(["queue", "--thread", super::text(config, "thread_id")?, "--message",
        &crate::communication_notifications::text(batch)])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
    let remaining = budget.remaining().map_err(|_| "HOST_PREFLIGHT_DEADLINE")?;
    let status = executor.block_on(async {
        tokio::time::timeout(remaining, command.status()).await
            .map_err(|_| "HOST_ACK_UNKNOWN")?.map_err(|_| "HOST_ACK_UNKNOWN")
    })?;
    if !status.success() { return Err("HOST_ACK_UNKNOWN"); }
    Ok(serde_json::json!({"state":"HOST_QUEUED","receipt":batch,"model_response":"NOT_ATTESTED"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn proxy_uses_pinned_installation_and_rejects_another_os_user_before_spawn() {
        let mut command=tokio::process::Command::new("unused");
        command.env("CODEX_HOME","/stale-signer-home");
        configure_installation(&mut command,&json!({"codex_home":"/selected-host-home"})).unwrap();
        let env=command.as_std().get_envs().find(|(key,_)|*key=="CODEX_HOME").unwrap().1.unwrap();
        assert_eq!(env,"/selected-host-home");
        assert_eq!(configure_installation(&mut command,&json!({"codex_home":"relative"})),Err("CODEX_HOME_INVALID"));
        #[cfg(unix)]
        assert_eq!(configure_installation(&mut command,&json!({"codex_uid":u64::MAX})),Err("CODEX_HOST_USER_MISMATCH"));
        assert!(configure_installation(&mut command,&json!({})).is_ok(),"existing explicit routes remain usable");
    }
}

pub(super) struct Proxy {
    child: Child,
    input: ChildStdin,
    output: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    buffered: std::io::Cursor<Vec<u8>>,
    deadline: Instant,
    reader: tokio::task::JoinHandle<()>,
    executor: tokio::runtime::Handle,
    budget: Budget,
}
impl Proxy {
    pub fn open(config: &Value, executor: tokio::runtime::Handle,budget:Budget) -> R<Self> {
        let path = executable(config["codex_executable"].as_str())?;
        let mut command = tokio::process::Command::new(path);
        command.args(["app-server", "proxy"]);
        configure_installation(&mut command, config)?;
        if let Some(socket) = config["control_socket"].as_str() {
            if !Path::new(socket).is_absolute() {
                return Err("HOST_ENDPOINT_INVALID");
            }
            command.arg("--sock").arg(socket);
        }
        let entered = executor.enter();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "HOST_PROXY_START_FAILED")?;
        let input = child.stdin.take().ok_or("HOST_PROXY_START_FAILED")?;
        let mut stdout = child.stdout.take().ok_or("HOST_PROXY_START_FAILED")?;
        let (tx, output) = mpsc::channel(8);
        let reader = executor.spawn(async move {
            use tokio::io::AsyncReadExt;
            loop {
                let mut bytes = vec![0; 8192];
                let result = match stdout.read(&mut bytes).await {
                    Ok(0) => Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "HOST_DISCONNECTED",
                    )),
                    Ok(n) => {
                        bytes.truncate(n);
                        Ok(bytes)
                    }
                    Err(error) => Err(error),
                };
                let terminal = result.is_err();
                if tx.send(result).await.is_err() || terminal {
                    break;
                }
            }
        });
        drop(entered);
        Ok(Self {
            child,
            input,
            output,
            buffered: std::io::Cursor::new(Vec::new()),
            deadline: Instant::now() + Duration::from_secs(10),
            reader,
            executor,
            budget,
        })
    }
    pub fn deadline(&mut self, deadline: Instant) {
        self.deadline = deadline.min(self.budget.deadline());
    }
}
impl std::io::Read for Proxy {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.buffered.position() as usize == self.buffered.get_ref().len() {
            let remaining = self
                .deadline.min(self.budget.deadline())
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "HOST_ACK_UNKNOWN")
                })?;
            let chunk = self.executor.block_on(async {
                tokio::time::timeout(remaining, self.output.recv())
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "HOST_ACK_UNKNOWN")
                    })?
                    .ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "HOST_DISCONNECTED")
                    })?
            })?;
            self.buffered = std::io::Cursor::new(chunk);
        }
        std::io::Read::read(&mut self.buffered, bytes)
    }
}
impl std::io::Write for Proxy {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.executor.block_on(async {
            tokio::time::timeout(self.budget.remaining()?, self.input.write_all(bytes))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "HOST_ACK_UNKNOWN")
                })??;
            Ok(bytes.len())
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.reader.abort();
        let pid=self.child.id();let token=pid.and_then(crate::communication_store::process_token);
        let _ = self.child.start_kill();
        // Reap only the proxy we own, never the daemon it forwards to.
        self.budget.phase("TERMINATING");
        let terminal=self.executor.block_on(async{tokio::time::timeout(Duration::from_secs(2),self.child.wait()).await});
        if !matches!(terminal,Ok(Ok(_))) {
            self.budget.phase("STALLED_TERMINATION");
            // A grace expiry is not termination proof. Keep the enclosing
            // physical-owner fence until the owned proxy is actually reaped.
            self.executor.block_on(async{loop{if self.child.wait().await.is_ok()||pid.is_none_or(|pid|!crate::communication_store::process_alive(pid,token.as_deref())){break;}tokio::time::sleep(Duration::from_secs(1)).await;}});
        }
    }
}
