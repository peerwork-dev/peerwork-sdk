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
