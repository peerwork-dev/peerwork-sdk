//! An intentional interactive Claude Channel launch. The launch marker selects
//! presentation only. The original native runtime still owns actor authority.
use crate::participant::{ParticipantError, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{io::IsTerminal, process::Command};

pub(crate) const LAUNCH_ENV: &str = "PEERWORK_CLAUDE_CHANNEL_LAUNCH";
pub(crate) const SESSION_ENV: &str = "CLAUDE_CODE_SESSION_ID";
pub(crate) const SESSION_ENDED: &str = "CLAUDE_CHANNEL_SESSION_ENDED";

#[cfg(target_os = "linux")]
const END: u8 = 1;

#[cfg(target_os = "linux")]
pub(crate) struct SessionGuard {
    pub(crate) ended: crate::KernelCancellationToken,
    listener: tokio::task::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Launch {
    pub(crate) server: String,
    pub(crate) session: String,
    pub(crate) order: LaunchOrder,
    pub(crate) select_session: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LaunchOrder {
    pub(crate) boot: String,
    pub(crate) started_ns: u64,
    pub(crate) nonce: String,
}

fn failure(code: &str) -> ParticipantError {
    ParticipantError::local(code, "CLAUDE_CHANNEL")
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn session_id(value: &str) -> Option<String> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 5 || !parts.iter().zip([8, 4, 4, 4, 12]).all(|(part, length)| hex(part, length)) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn valid_server(value: &str) -> bool {
    value.strip_prefix("peerwork-").is_some_and(|suffix| hex(suffix, 16))
}

fn entropy() -> Result<[u8; 16]> {
    let mut bytes = [0; 16];
    OsRng.try_fill_bytes(&mut bytes)
        .map_err(|_| failure("ENTROPY_UNAVAILABLE"))?;
    Ok(bytes)
}

#[cfg(target_os="linux")]
fn current_boot() -> Result<String> {
    let raw=std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_|failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE"))?;
    let id=session_id(raw.trim()).ok_or_else(||failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE"))?;
    Ok(peerwork_core::crypto::sha256_hex(id.as_bytes()))
}

#[cfg(not(target_os="linux"))]
fn current_boot() -> Result<String> {Err(failure("CLAUDE_CHANNEL_LAUNCH_UNSUPPORTED"))}

#[cfg(target_os="linux")]
fn boot_time_ns() -> Result<u64> {
    let mut time=libc::timespec { tv_sec:0,tv_nsec:0 };
    // CLOCK_BOOTTIME advances within this boot without wall-clock steps.
    if unsafe {libc::clock_gettime(libc::CLOCK_BOOTTIME,&mut time)} != 0 {
        return Err(failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE"));
    }
    u64::try_from(time.tv_sec).ok().and_then(|sec|sec.checked_mul(1_000_000_000))
        .and_then(|ns|ns.checked_add(time.tv_nsec as u64))
        .ok_or_else(||failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE"))
}

#[cfg(not(target_os="linux"))]
fn boot_time_ns() -> Result<u64> {Err(failure("CLAUDE_CHANNEL_LAUNCH_UNSUPPORTED"))}

impl LaunchOrder {
    pub(crate) fn verify_shape(&self) -> bool {
        hex(&self.boot,64) && self.started_ns>0 && hex(&self.nonce,64)
    }
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {boot:current_boot()?,started_ns:boot_time_ns()?,nonce:peerwork_core::crypto::sha256_hex(&entropy()?)})
    }
    pub(crate) fn supersedes(&self, previous:&Self) -> bool {
        self.boot!=previous.boot || self.started_ns>previous.started_ns ||
            (self.started_ns==previous.started_ns && self.nonce==previous.nonce)
    }
}

fn new_session() -> Result<String> {
    let mut bytes = entropy()?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let body = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Ok(format!("{}-{}-{}-{}-{}", &body[..8], &body[8..12],
               &body[12..16], &body[16..20], &body[20..]))
}

impl Launch {
    fn validate(&self, observed: &str) -> Result<()> {
        if !valid_server(&self.server) || !self.order.verify_shape()
            || session_id(observed).as_deref() != Some(&self.session)
            || session_id(&self.session).as_deref() != Some(&self.session)
            || self.order.boot!=current_boot()? || self.order.started_ns>boot_time_ns()?
        {
            return Err(failure("CLAUDE_CHANNEL_LAUNCH_MISMATCH"));
        }
        Ok(())
    }

    fn inherited() -> Result<Self> {
        let wire = std::env::var(LAUNCH_ENV).map_err(|_| failure("CLAUDE_CHANNEL_LAUNCH_REQUIRED"))?;
        if wire.len() > 512 {
            return Err(failure("CLAUDE_CHANNEL_LAUNCH_MISMATCH"));
        }
        serde_json::from_str(&wire).map_err(|_| failure("CLAUDE_CHANNEL_LAUNCH_MISMATCH"))
    }

    pub(crate) fn observe() -> Result<Self> {
        let launch = Self::inherited()?;
        let marker = std::env::var(SESSION_ENV).map_err(|_| failure("CLAUDE_CHANNEL_LAUNCH_MISMATCH"))?;
        launch.validate(&marker)?;
        Ok(launch)
    }

    pub(crate) fn session_digest(&self) -> String {
        peerwork_core::crypto::sha256_hex(format!("peerwork.claude-session.v1\0{}", self.session).as_bytes())
    }

    #[cfg(target_os="linux")]
    fn socket_address(&self) -> Result<std::os::unix::net::SocketAddr> {
        use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
        let key=peerwork_core::crypto::sha256_hex(format!("{}:{}",self.server,self.order.nonce).as_bytes());
        SocketAddr::from_abstract_name(format!("peerwork-claude-{key}").as_bytes())
            .map_err(|_|failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE"))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn acquire(&self) -> Result<SessionGuard> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = std::os::unix::net::UnixListener::bind_addr(&self.socket_address()?).map_err(|cause| {
            if cause.kind()==std::io::ErrorKind::AddrInUse {failure("CLAUDE_CHANNEL_LAUNCH_ALREADY_CONNECTED")}
            else {failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE")}
        })?;
        let unavailable = |_| failure("CLAUDE_CHANNEL_STATE_UNAVAILABLE");
        listener.set_nonblocking(true).map_err(unavailable)?;
        let listener = tokio::net::UnixListener::from_std(listener).map_err(unavailable)?;
        let ended = crate::KernelCancellationToken::new();
        let signal = ended.clone();
        let uid = unsafe { libc::geteuid() };
        let listener = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if !stream.peer_cred().is_ok_and(|peer| peer.uid() == uid) {
                    continue;
                }
                let _ = tokio::time::timeout(std::time::Duration::from_millis(200), async {
                    if stream.read_u8().await? == END {
                        // Stop admission before allowing the hook to return.
                        signal.cancel();
                        stream.write_u8(END).await?;
                    }
                    Ok::<(), std::io::Error>(())
                }).await;
            }
            // Losing the listener also means losing the lifecycle signal.
            signal.cancel();
        });
        Ok(SessionGuard { ended, listener })
    }
}

fn end_hook_settings(executable: &std::path::Path) -> Result<String> {
    let executable = executable.to_str().ok_or_else(|| failure("CLAUDE_CHANNEL_EXECUTABLE_UNAVAILABLE"))?;
    let command = format!("'{}' agent claude-session-end", executable.replace('\'', "'\"'\"'"));
    Ok(serde_json::json!({"hooks":{"SessionEnd":[{"hooks":[
        {"type":"command","command":command,"timeout":1}
    ]}]}}).to_string())
}

/// Invoked by the host's lifecycle hook using the ended session ID. Claude's
/// MCP subprocess environment retains its original session across a switch.
#[cfg(target_os = "linux")]
pub(crate) fn end_session() -> Result<()> {
    use std::{io::{Read, Write}, os::unix::net::UnixStream, time::Duration};

    #[derive(Deserialize)]
    struct Event {
        session_id: String,
        hook_event_name: String,
    }
    let invalid = |_| failure("CLAUDE_CHANNEL_SESSION_EVENT_INVALID");
    let mut input = Vec::new();
    std::io::stdin().lock().take(8193).read_to_end(&mut input)
        .map_err(invalid)?;
    if input.len() > 8192 {
        return Err(failure("CLAUDE_CHANNEL_SESSION_EVENT_INVALID"));
    }
    let event: Event = serde_json::from_slice(&input)
        .map_err(|_| failure("CLAUDE_CHANNEL_SESSION_EVENT_INVALID"))?;
    if event.hook_event_name != "SessionEnd" {
        return Err(failure("CLAUDE_CHANNEL_SESSION_EVENT_INVALID"));
    }
    let launch = Launch::inherited()?;
    launch.validate(&event.session_id)?;
    let mut stream = match UnixStream::connect_addr(&launch.socket_address()?) {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(()),
        Err(_) => return Err(failure("CLAUDE_CHANNEL_LIFECYCLE_UNAVAILABLE")),
    };
    let budget = Some(Duration::from_millis(500));
    let unavailable = |_| failure("CLAUDE_CHANNEL_LIFECYCLE_UNAVAILABLE");
    stream.set_read_timeout(budget).map_err(unavailable)?;
    stream.set_write_timeout(budget).map_err(unavailable)?;
    stream.write_all(&[END]).map_err(unavailable)?;
    let mut acknowledgement = [0];
    stream.read_exact(&mut acknowledgement).map_err(unavailable)?;
    if acknowledgement != [END] {
        return Err(failure("CLAUDE_CHANNEL_LIFECYCLE_UNAVAILABLE"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn end_session() -> Result<()> {
    Err(failure("CLAUDE_CHANNEL_LAUNCH_UNSUPPORTED"))
}

/// Keep the foreground terminal and its signal handling with Claude. The
/// SDK does not keep a second launcher process or start a noninteractive host.
pub(crate) fn start(args: &[String]) -> Result<()> {
    let [server, mode, rest @ ..] = args else {
        return Err(failure("CLAUDE_CHANNEL_LAUNCH_ARGUMENT_INVALID"));
    };
    if !valid_server(server) {
        return Err(failure("CLAUDE_CHANNEL_LAUNCH_ARGUMENT_INVALID"));
    }
    let (session, select_session, session_flag) = match (mode.as_str(), rest) {
        ("--new-session", []) => (new_session()?, true, "--session-id"),
        ("--resume", [session]) => (session_id(session).ok_or_else(||failure("CLAUDE_CHANNEL_LAUNCH_ARGUMENT_INVALID"))?, false, "--resume"),
        ("--resume", [session, option]) if option == "--select-session" =>
            (session_id(session).ok_or_else(||failure("CLAUDE_CHANNEL_LAUNCH_ARGUMENT_INVALID"))?, true, "--resume"),
        _ => return Err(failure("CLAUDE_CHANNEL_LAUNCH_ARGUMENT_INVALID")),
    };
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(failure("CLAUDE_CHANNEL_INTERACTIVE_TERMINAL_REQUIRED"));
    }
    let launch = Launch {
        server: server.clone(), session, order: LaunchOrder::new()?, select_session,
    };
    let wire = serde_json::to_string(&launch).map_err(|_|failure("CLAUDE_CHANNEL_LAUNCH_ARGUMENT_INVALID"))?;
    let executable = std::env::current_exe().map_err(|_| failure("CLAUDE_CHANNEL_EXECUTABLE_UNAVAILABLE"))?;
    let settings = end_hook_settings(&executable)?;
    let mut command = Command::new("claude");
    command.args([session_flag, &launch.session, "--dangerously-load-development-channels", &format!("server:{server}")])
        .args(["--settings", &settings])
        .env_remove(SESSION_ENV).env(LAUNCH_ENV, wire);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let _ = command.exec();
        Err(failure("CLAUDE_CHANNEL_EXECUTABLE_UNAVAILABLE"))
    }
    #[cfg(not(unix))]
    {
        if command.status().is_ok_and(|status|status.success()) { return Ok(()); }
        Err(failure("CLAUDE_CHANNEL_EXECUTABLE_UNAVAILABLE"))
    }
}
