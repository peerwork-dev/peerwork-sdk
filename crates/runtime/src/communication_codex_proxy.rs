//! JSONL transport to an existing Codex daemon. The only child command is the
//! official control-socket proxy; it never creates a server, thread or model.
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin},
    sync::mpsc,
};
type R<T> = Result<T, &'static str>;
const LIMIT: usize = 2 * 1024 * 1024;

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
    output: mpsc::Receiver<R<Value>>,
    reader: tokio::task::JoinHandle<()>,
    executor: tokio::runtime::Handle,
}
impl Proxy {
    pub fn open(config: &Value, executor: tokio::runtime::Handle) -> R<Self> {
        let path = executable(config["codex_executable"].as_str())?;
        let mut command = tokio::process::Command::new(path);
        command.args(["app-server", "proxy"]);
        if let Some(socket) = config["control_socket"].as_str() {
            if !Path::new(socket).is_absolute() {
                return Err("HOST_ENDPOINT_INVALID");
            }
            command.arg("--sock").arg(socket);
        }
        let _entered = executor.enter();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "HOST_PROXY_START_FAILED")?;
        let input = child.stdin.take().ok_or("HOST_PROXY_START_FAILED")?;
        let stdout = child.stdout.take().ok_or("HOST_PROXY_START_FAILED")?;
        let (tx, output) = mpsc::channel(8);
        let reader = executor.spawn(async move {
            let mut source = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let result = async {
                    loop {
                        let chunk = source.fill_buf().await.map_err(|_| "HOST_DISCONNECTED")?;
                        if chunk.is_empty() {
                            return Err("HOST_DISCONNECTED");
                        }
                        let end = chunk.iter().position(|b| *b == b'\n');
                        let used = end.map_or(chunk.len(), |n| n + 1);
                        if bytes.len() + used > LIMIT {
                            return Err("HOST_RESPONSE_INVALID");
                        }
                        bytes.extend_from_slice(&chunk[..used]);
                        source.consume(used);
                        if end.is_some() {
                            break;
                        }
                    }
                    serde_json::from_slice(&bytes).map_err(|_| "HOST_RESPONSE_INVALID")
                }
                .await;
                let terminal = result.is_err();
                if tx.send(result).await.is_err() || terminal {
                    break;
                }
            }
        });
        drop(_entered);
        Ok(Self {
            child,
            input,
            output,
            reader,
            executor,
        })
    }
    pub fn write(&mut self, value: Value) -> R<()> {
        let mut bytes = serde_json::to_vec(&value).map_err(|_| "HOST_INPUT_INVALID")?;
        if bytes.len() > LIMIT {
            return Err("HOST_INPUT_TOO_LARGE");
        }
        bytes.push(b'\n');
        self.executor.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), self.input.write_all(&bytes))
                .await
                .map_err(|_| "HOST_ACK_UNKNOWN")?
                .map_err(|_| "HOST_ACK_UNKNOWN")
        })
    }
    pub fn read(&mut self, deadline: Instant) -> R<Value> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("HOST_ACK_UNKNOWN")?;
        self.executor.block_on(async {
            tokio::time::timeout(remaining, self.output.recv())
                .await
                .map_err(|_| "HOST_ACK_UNKNOWN")?
                .ok_or("HOST_DISCONNECTED")?
        })
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.reader.abort();
        let _ = self.child.start_kill();
        // Reap only the proxy we own, never the daemon it forwards to.
        let _ = self.executor.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await
        });
    }
}
