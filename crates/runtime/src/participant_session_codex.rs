//! Own one private Codex App Server and its recorded thread.
use serde_json::Value;
use std::path::Path;

type Result<T> = std::result::Result<T, &'static str>;

#[cfg(target_os = "linux")]
pub(crate) use linux::{launch, launch_for_handoff, mcp_overrides, running, stop};

#[cfg(not(target_os = "linux"))]
pub(crate) async fn launch_for_handoff(
    _: &Path,
    _: &Path,
    _: &str,
    _: &Value,
    _: Option<&Value>,
) -> Result<Value> {
    Err("CODEX_HANDOFF_PLATFORM_UNSUPPORTED")
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn launch(
    _: &Path,
    _: &Path,
    _: &str,
    _: &Value,
    _: Option<&Value>,
) -> Result<Value> {
    Err("CODEX_SESSION_PLATFORM_UNSUPPORTED")
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn running(_: &Path) -> Result<bool> {
    Err("CODEX_SESSION_PLATFORM_UNSUPPORTED")
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn stop(_: &Path, _: Option<&Value>) -> Result<bool> {
    Err("CODEX_SESSION_PLATFORM_UNSUPPORTED")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{communication_host, onboarding_files, process_identity};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Map};
    use std::{
        fs::{self, File, OpenOptions},
        io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStrExt,
                fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
                net::UnixStream,
                process::CommandExt,
            },
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        time::Duration,
    };

    const INVALID: &str = "CODEX_SESSION_STATE_INVALID";
    const UNAVAILABLE: &str = "CODEX_SESSION_HOST_UNAVAILABLE";
    const UNOWNED: &str = "CODEX_SESSION_HOST_NOT_OWNED";
    const UNCERTAIN: &str = "CODEX_SESSION_CREATE_UNCERTAIN";
    const LAUNCH_FAILED: &str = "CODEX_SESSION_LAUNCH_FAILED";
    const RETRY_WAIT: Duration = Duration::from_millis(50);

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owner {
        pid: u32,
        birth: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
    enum ThreadCreation {
        Requested { owner: Owner },
        Allocated { adapter: Value },
    }

    enum Server {
        Absent,
        Starting,
        Listening(Owner),
    }

    struct OwnedEndpoint {
        root: PathBuf,
        socket: PathBuf,
    }

    impl OwnedEndpoint {
        fn at(directory: &Path, create: bool) -> Result<Option<Self>> {
            if create {
                onboarding_files::directory(directory, true).map_err(|_| INVALID)?;
            } else {
                match fs::symlink_metadata(directory) {
                    Ok(_) => {
                        onboarding_files::check_directory(directory, true).map_err(|_| INVALID)?
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(_) => return Err(INVALID),
                }
            }
            let socket = directory.join("codex.sock");
            let path = socket.to_str().ok_or(INVALID)?;
            if socket.as_os_str().as_bytes().len() >= 108 || path.contains(['?', '#']) {
                return Err("CODEX_SESSION_SOCKET_PATH_INVALID");
            }
            Ok(Some(Self {
                root: directory.into(),
                socket,
            }))
        }

        fn config(&self) -> Value {
            json!({
                "kind": "codex",
                "endpoint": format!("unix://{}", self.socket.display()),
                "expected_socket_uid": uid(),
            })
        }

        fn matches(&self, selected: &Value) -> bool {
            let expected = self.config();
            selected["kind"] == expected["kind"]
                && selected["endpoint"] == expected["endpoint"]
                && selected["expected_socket_uid"] == expected["expected_socket_uid"]
                && ["thread_id", "expected_session_id"].iter().all(|field| {
                    selected[*field]
                        .as_str()
                        .is_some_and(|id| !id.is_empty() && id.len() <= 256)
                })
        }

        fn owner(&self, create: bool) -> Result<Option<File>> {
            lock_file(&self.root.join("server-owner.lock"), create)
        }

        fn reserve(&self) -> Result<Option<File>> {
            let lock = lock_file(&self.root.join("launch.lock"), true)?.ok_or(INVALID)?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                Ok(Some(lock))
            } else if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(INVALID)
            }
        }

        fn socket_metadata(&self) -> Result<bool> {
            match fs::symlink_metadata(&self.socket) {
                Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid() => Ok(true),
                Ok(meta) if meta.file_type().is_symlink() && meta.uid() == uid() => {
                    // App Server may expose a public-name alias inside our
                    // launch directory to its private, hashed socket path.
                    let target = fs::read_link(&self.socket).map_err(|_| UNOWNED)?;
                    if !target.is_absolute() {
                        return Err(UNOWNED);
                    }
                    onboarding_files::check_directory(target.parent().ok_or(UNOWNED)?, true)
                        .map_err(|_| UNOWNED)?;
                    match fs::symlink_metadata(target) {
                        Ok(target) if target.file_type().is_socket() && target.uid() == uid() => {
                            Ok(true)
                        }
                        // The alias itself still exists and must be removed
                        // under the spawn reservation before a relaunch.
                        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
                        _ => Err(UNOWNED),
                    }
                }
                Ok(_) => Err(UNOWNED),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(_) => Err(UNAVAILABLE),
            }
        }

        fn observe(&self, owner: Option<&File>, legacy: bool) -> Result<Server> {
            let claimed = owner.map(lock_owner).transpose()?.flatten();
            let absent = || {
                if claimed.is_some() {
                    Server::Starting
                } else {
                    Server::Absent
                }
            };
            if !self.socket_metadata()? {
                return Ok(absent());
            }
            let socket = match UnixStream::connect(&self.socket) {
                Ok(socket) => socket,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    return Ok(absent());
                }
                Err(_) => return Err(UNAVAILABLE),
            };
            let (pid, peer_uid) = peer_credentials(&socket)?;
            // Existing handoffs can predate the server owner lock. Only the
            // handoff path may observe those sockets. Managed stops and
            // fresh target creation require an exact process lock owner.
            if peer_uid != uid() || claimed != Some(pid) && !(legacy && claimed.is_none()) {
                return Err(UNOWNED);
            }
            let birth = process_identity::token(pid).ok_or(UNOWNED)?;
            if claimed.is_some() && lock_owner(owner.ok_or(UNOWNED)?)? != Some(pid) {
                return Err(UNOWNED);
            }
            Ok(Server::Listening(Owner { pid, birth }))
        }
    }

    fn uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn lock_file(path: &Path, create: bool) -> Result<Option<File>> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(INVALID),
        };
        let meta = file.metadata().map_err(|_| INVALID)?;
        if !meta.is_file() || meta.uid() != uid() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
            return Err(INVALID);
        }
        Ok(Some(file))
    }

    fn write_lock() -> libc::flock {
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_whence = libc::SEEK_SET as _;
        lock.l_type = libc::F_WRLCK as _;
        lock
    }

    fn lock_owner(file: &File) -> Result<Option<u32>> {
        let mut lock = write_lock();
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } == -1 {
            return Err(INVALID);
        }
        if lock.l_type == libc::F_UNLCK as libc::c_short {
            Ok(None)
        } else if lock.l_type == libc::F_WRLCK as libc::c_short && lock.l_pid > 0 {
            Ok(Some(lock.l_pid as u32))
        } else {
            Err(INVALID)
        }
    }

    fn peer_credentials(socket: &UnixStream) -> Result<(u32, u32)> {
        let mut creds: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut creds as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if result == -1 || len as usize != std::mem::size_of::<libc::ucred>() || creds.pid <= 0 {
            return Err(UNOWNED);
        }
        Ok((creds.pid as u32, creds.uid))
    }

    struct Reap(Option<Child>);

    impl Drop for Reap {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }
    }

    fn valid_mcp(name: &str, entry: &Value) -> bool {
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            && entry["command"]
                .as_str()
                .is_some_and(|v| Path::new(v).is_absolute())
            && entry["args"]
                .as_array()
                .is_some_and(|args| args.iter().all(Value::is_string))
    }

    pub(crate) fn mcp_overrides(config: &Value, name: &str, entry: &Value) -> Result<Value> {
        if !config.is_object() || !valid_mcp(name, entry) {
            return Err(INVALID);
        }
        let existing = match config.get("mcp_servers") {
            Some(value) => Some(value.as_object().ok_or(INVALID)?),
            None => None,
        };
        let mut servers = Map::new();
        for (server, old) in existing.into_iter().flatten() {
            if server == name {
                // A collision must not inherit a different command, remote
                // URL, environment or working directory for the same name.
                if old["command"] != entry["command"]
                    || old["args"] != entry["args"]
                    || ["url", "env", "env_vars", "cwd"]
                        .iter()
                        .any(|field| old.get(*field).is_some_and(|v| !v.is_null()))
                {
                    return Err("CODEX_SESSION_MCP_NAME_CONFLICT");
                }
            } else {
                servers.insert(server.clone(), json!({"enabled": false}));
            }
        }
        servers.insert(
            name.into(),
            json!({
                "command": entry["command"],
                "args": entry["args"],
                "enabled": true,
            }),
        );
        Ok(json!({"mcp_servers": servers}))
    }

    fn spawn(
        endpoint: &OwnedEndpoint,
        owner: &File,
        installation: &Value,
        project: &Path,
        mcp_name: &str,
        mcp_entry: &Value,
    ) -> Result<Child> {
        let binary = installation["codex_executable"]
            .as_str()
            .ok_or("CODEX_EXECUTABLE_REQUIRED")?;
        let home = installation["codex_home"]
            .as_str()
            .ok_or("CODEX_HOME_REQUIRED")?;
        let owner_fd = owner.as_raw_fd();
        let writer = write_lock();
        let mut process = Command::new(binary);
        // The child inherits the launch reservation until exec. The
        // process-scoped owner lock belongs to Codex, including across exec,
        // but is automatically released when Codex itself exits.
        unsafe {
            process.pre_exec(move || {
                if libc::setsid() == -1
                    || libc::fcntl(owner_fd, libc::F_SETLK, &writer) == -1
                    || libc::fcntl(owner_fd, libc::F_SETFD, 0) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        process
            .env("CODEX_HOME", home)
            .current_dir(project)
            .arg("-c")
            .arg(format!(
                "mcp_servers.{mcp_name}.command={}",
                mcp_entry["command"]
            ))
            .arg("-c")
            .arg(format!("mcp_servers.{mcp_name}.args={}", mcp_entry["args"]))
            .args(["app-server", "--listen"])
            .arg(format!("unix://{}", endpoint.socket.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| LAUNCH_FAILED)
    }

    async fn start(
        directory: &Path,
        project: &Path,
        mcp_name: &str,
        mcp_entry: &Value,
        selected: Option<&Value>,
        managed: bool,
    ) -> Result<Value> {
        if !project.is_absolute() || !valid_mcp(mcp_name, mcp_entry) {
            return Err(INVALID);
        }
        let endpoint = OwnedEndpoint::at(directory, true)?.ok_or(INVALID)?;
        let mut child = Reap(None);
        let runtime = tokio::runtime::Handle::current();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let _reservation = loop {
            if let Some(lock) = endpoint.reserve()? {
                break lock;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(UNAVAILABLE);
            }
            tokio::time::sleep(RETRY_WAIT).await;
        };

        let creation_file = endpoint.root.join("thread-creation.json");
        let before = if managed {
            onboarding_files::read_optional(&creation_file, 8192).map_err(|_| INVALID)?
        } else {
            None
        };
        let record: Option<ThreadCreation> = before
            .as_deref()
            .map(|bytes| serde_json::from_slice(bytes).map_err(|_| INVALID))
            .transpose()?;
        let mut selected = selected;
        if let Some(ThreadCreation::Allocated { adapter }) = &record {
            if selected.is_some_and(|value| value != adapter) {
                return Err(INVALID);
            }
            selected = Some(adapter);
        }
        if selected.is_some_and(|value| !endpoint.matches(value)) {
            return Err(INVALID);
        }
        let pending = match &record {
            Some(ThreadCreation::Requested { owner }) if selected.is_none() => Some(owner),
            _ => None,
        };
        let owner = endpoint.owner(true)?.ok_or(INVALID)?;
        let server = loop {
            match endpoint.observe(Some(&owner), !managed)? {
                Server::Listening(server) => {
                    if pending.is_some_and(|expected| expected != &server) {
                        return Err(UNCERTAIN);
                    }
                    break server;
                }
                Server::Starting => (),
                Server::Absent if pending.is_some() => return Err(UNCERTAIN),
                Server::Absent if child.0.is_none() => {
                    if endpoint.socket_metadata()? {
                        fs::remove_file(&endpoint.socket).map_err(|_| UNAVAILABLE)?;
                    }
                    let installation = communication_host::codex_installation()?;
                    if managed {
                        // The same home is needed to resume the rollout after
                        // a process exit. Compare before spawning a fresh host.
                        let pin_path = endpoint.root.join("codex-home.json");
                        let pinned =
                            serde_json::to_vec(&installation["codex_home"]).map_err(|_| INVALID)?;
                        match onboarding_files::read_optional(&pin_path, 8192)
                            .map_err(|_| INVALID)?
                        {
                            Some(existing) if existing != pinned => {
                                return Err("CODEX_SESSION_INSTALLATION_CHANGED")
                            }
                            Some(_) => (),
                            None => {
                                onboarding_files::replace_if_unchanged(&pin_path, None, &pinned)
                                    .map_err(|_| INVALID)?
                            }
                        }
                    }
                    child.0 = Some(spawn(
                        &endpoint,
                        &owner,
                        &installation,
                        project,
                        mcp_name,
                        mcp_entry,
                    )?);
                }
                Server::Absent => (),
            }
            if let Some(process) = &mut child.0 {
                if process.try_wait().map_err(|_| LAUNCH_FAILED)?.is_some() {
                    return Err(LAUNCH_FAILED);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(UNAVAILABLE);
            }
            tokio::time::sleep(RETRY_WAIT).await;
        };

        let first_create = managed && selected.is_none() && pending.is_none();
        let config = selected.cloned().unwrap_or_else(|| endpoint.config());
        let project = project.to_owned();
        let mcp = managed.then(|| (mcp_name.to_owned(), mcp_entry.clone()));
        // The blocking RPC owns the reservation, including if its async
        // caller drops the join handle while allocation is still in flight.
        tokio::task::spawn_blocking(move || {
            let _reservation = _reservation;
            let mut before = before;
            let mcp = mcp.as_ref().map(|(name, entry)| (name.as_str(), entry));
            let adapter = if managed {
                let mut mark = || {
                    let bytes = serde_json::to_vec(&ThreadCreation::Requested {
                        owner: server.clone(),
                    })
                    .map_err(|_| INVALID)?;
                    onboarding_files::replace_if_unchanged(&creation_file, None, &bytes)
                        .map_err(|_| INVALID)?;
                    before = Some(bytes);
                    Ok(())
                };
                communication_host::codex_prepare_owned_session(
                    config,
                    &project,
                    runtime,
                    first_create,
                    mcp,
                    first_create.then_some(&mut mark as &mut dyn FnMut() -> Result<()>),
                )?
            } else {
                communication_host::codex_prepare_handoff(config, &project, runtime)?
            };
            if !endpoint.matches(&adapter) {
                return Err(INVALID);
            }
            if managed && !matches!(record, Some(ThreadCreation::Allocated { .. })) {
                let bytes = serde_json::to_vec(&ThreadCreation::Allocated {
                    adapter: adapter.clone(),
                })
                .map_err(|_| INVALID)?;
                onboarding_files::replace_if_unchanged(&creation_file, before.as_deref(), &bytes)
                    .map_err(|_| INVALID)?;
            }
            Ok(adapter)
        })
        .await
        .map_err(|_| LAUNCH_FAILED)?
    }

    pub(crate) async fn launch(
        directory: &Path,
        project: &Path,
        mcp_name: &str,
        mcp_entry: &Value,
        selected: Option<&Value>,
    ) -> Result<Value> {
        start(directory, project, mcp_name, mcp_entry, selected, true).await
    }

    pub(crate) async fn launch_for_handoff(
        directory: &Path,
        project: &Path,
        mcp_name: &str,
        mcp_entry: &Value,
        selected: Option<&Value>,
    ) -> Result<Value> {
        start(directory, project, mcp_name, mcp_entry, selected, false).await
    }

    pub(crate) fn running(directory: &Path) -> Result<bool> {
        let Some(endpoint) = OwnedEndpoint::at(directory, false)? else {
            return Ok(false);
        };
        let owner = endpoint.owner(false)?;
        Ok(matches!(
            endpoint.observe(owner.as_ref(), false)?,
            Server::Listening(_)
        ))
    }

    fn pidfd(pid: u32) -> Result<OwnedFd> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd == -1 {
            return Err("CODEX_SESSION_PROCESS_HANDLE_UNAVAILABLE");
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as _) })
    }

    /// Return true only after the private server is absent. A successfully
    /// requested graceful shutdown is observed on the next call.
    pub(crate) async fn stop(directory: &Path, selected: Option<&Value>) -> Result<bool> {
        let Some(endpoint) = OwnedEndpoint::at(directory, false)? else {
            return Ok(true);
        };
        let _reservation = endpoint.reserve()?.ok_or(UNAVAILABLE)?;
        let owner = endpoint.owner(false)?;
        let original = match endpoint.observe(owner.as_ref(), false)? {
            Server::Absent => return Ok(true),
            Server::Starting => return Err(UNAVAILABLE),
            Server::Listening(owner) => owner,
        };
        let bytes =
            onboarding_files::read_optional(&endpoint.root.join("thread-creation.json"), 8192)
                .map_err(|_| INVALID)?;
        let recorded = bytes
            .as_deref()
            .map(|bytes| serde_json::from_slice::<ThreadCreation>(bytes).map_err(|_| INVALID))
            .transpose()?;
        let recorded = match &recorded {
            Some(ThreadCreation::Allocated { adapter }) => Some(adapter),
            _ => None,
        };
        if recorded.zip(selected).is_some_and(|(one, two)| one != two) {
            return Err(INVALID);
        }
        let target = selected
            .or(recorded)
            .filter(|target| endpoint.matches(target))
            .ok_or(UNCERTAIN)?
            .clone();
        let process = pidfd(original.pid)?;
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let _reservation = _reservation;
            match endpoint.observe(owner.as_ref(), false)? {
                Server::Listening(current) if current == original => (),
                Server::Absent => return Ok(true),
                _ => return Err(UNOWNED),
            }
            if !communication_host::codex_owned_thread_idle(target, runtime)? {
                return Ok(false);
            }
            match endpoint.observe(owner.as_ref(), false)? {
                Server::Listening(current) if current == original => (),
                Server::Absent => return Ok(true),
                _ => return Err(UNOWNED),
            }
            let signaled = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    process.as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if signaled == 0 {
                Ok(false)
            } else if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                Ok(true)
            } else {
                Err("CODEX_SESSION_STOP_FAILED")
            }
        })
        .await
        .map_err(|_| UNAVAILABLE)?
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixListener;

        #[test]
        fn managed_mcp_uses_only_the_selected_peer() {
            let entry = json!({"command":"/opt/peerwork","args":["--participant","peer-b"]});
            let config = json!({"mcp_servers":{
                "peerwork-a":{"command":"/opt/peerwork","args":["--participant","peer-a"]},
                "peerwork-b":entry,
                "an_inherited_server":{"url":"https://example.invalid/mcp"},
            }});
            let view = mcp_overrides(&config, "peerwork-b", &entry).unwrap();
            assert_eq!(view["mcp_servers"]["peerwork-a"], json!({"enabled":false}));
            assert_eq!(
                view["mcp_servers"]["an_inherited_server"],
                json!({"enabled":false})
            );
            assert_eq!(view["mcp_servers"]["peerwork-b"]["enabled"], true);
            assert_eq!(view["mcp_servers"]["peerwork-b"]["args"], entry["args"]);
            assert_eq!(
                mcp_overrides(&config, "peerwork-a", &entry),
                Err("CODEX_SESSION_MCP_NAME_CONFLICT")
            );
        }

        #[tokio::test]
        async fn managed_stop_rejects_another_same_user_socket() {
            let root = crate::test_support::protected_test_dir();
            let state = root.path().join("server");
            let endpoint = OwnedEndpoint::at(&state, true).unwrap().unwrap();
            let foreign = UnixListener::bind(&endpoint.socket).unwrap();
            assert_eq!(running(&state), Err(UNOWNED));
            assert_eq!(stop(&state, None).await, Err(UNOWNED));
            assert_eq!(
                foreign.local_addr().unwrap().as_pathname(),
                Some(endpoint.socket.as_path())
            );
        }

        #[tokio::test]
        async fn unresolved_creation_with_lost_server_does_not_spawn_again() {
            let root = crate::test_support::protected_test_dir();
            let state = root.path().join("server");
            let endpoint = OwnedEndpoint::at(&state, true).unwrap().unwrap();
            let attempt = ThreadCreation::Requested {
                owner: Owner {
                    pid: std::process::id(),
                    birth: "earlier".into(),
                },
            };
            onboarding_files::replace_if_unchanged(
                &endpoint.root.join("thread-creation.json"),
                None,
                &serde_json::to_vec(&attempt).unwrap(),
            )
            .unwrap();
            let entry = json!({"command":"/bin/false","args":[]});
            assert_eq!(
                launch(&state, root.path(), "test-peerwork", &entry, None).await,
                Err(UNCERTAIN)
            );
            assert!(!endpoint.socket.exists());
            assert!(stop(&state, None).await.unwrap());
        }

        #[tokio::test]
        #[ignore = "requires isolated Linux Codex and a deterministic local model"]
        async fn managed_codex_exact_thread_survives_relaunch_and_stops() {
            let root = crate::test_support::protected_test_dir();
            let state = root.path().join("server");
            let entry = json!({"command":"/bin/false","args":[]});
            let endpoint = OwnedEndpoint::at(&state, true).unwrap().unwrap();
            struct Cleanup(OwnedEndpoint);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    if let Ok(Some(owner)) = self.0.owner(false) {
                        if let Ok(Server::Listening(original)) = self.0.observe(Some(&owner), false)
                        {
                            if let Ok(process) = pidfd(original.pid) {
                                if let Ok(Server::Listening(current)) =
                                    self.0.observe(Some(&owner), false)
                                {
                                    if current == original {
                                        unsafe {
                                            libc::syscall(
                                                libc::SYS_pidfd_send_signal,
                                                process.as_raw_fd(),
                                                libc::SIGTERM,
                                                std::ptr::null::<libc::siginfo_t>(),
                                                0,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let _cleanup = Cleanup(endpoint);
            async fn wait_for_stop(path: &Path) {
                tokio::time::timeout(Duration::from_secs(25), async {
                    loop {
                        match stop(path, None).await {
                            Ok(true) => break,
                            Ok(false)
                            | Err("CODEX_SESSION_BUSY" | UNAVAILABLE | "HOST_UNAVAILABLE") => (),
                            Err(code) => panic!("could not stop test session: {code}"),
                        }
                        tokio::time::sleep(RETRY_WAIT).await;
                    }
                })
                .await
                .unwrap();
            }
            let created = launch(&state, root.path(), "test-peerwork", &entry, None)
                .await
                .unwrap();
            assert!(running(&state).unwrap());
            assert_eq!(
                launch(&state, root.path(), "test-peerwork", &entry, None)
                    .await
                    .unwrap(),
                created
            );
            wait_for_stop(&state).await;
            assert!(!running(&state).unwrap());
            // The caller lost the returned result. Resume the exact adapter
            // from the durable creation record even after the App Server died.
            assert_eq!(
                launch(&state, root.path(), "test-peerwork", &entry, None)
                    .await
                    .unwrap(),
                created
            );
            wait_for_stop(&state).await;
            assert!(!running(&state).unwrap());
        }
    }
}
