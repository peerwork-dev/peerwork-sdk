//! Explicit local Codex launch, followed by the existing sealed attachment.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handoff {
    participant: String,
    workspace: String,
    request: ConnectRequest,
    adapter: Option<Value>,
    prior_attachment: Option<String>,
    ready: bool,
}

impl Connect {
    pub(crate) fn handoff_scope(
        &self,
        intent: &HandoffIntent,
        participant_pin: Option<&str>,
        workspace_pin: Option<&str>,
    ) -> Result<(String, String)> {
        let (request, _) = self.resolve_input_selected(
            ConnectInput::Intent(ConnectIntent {
                participant: intent.participant.clone(),
                workspace_id: intent.workspace_id.clone(),
                ..Default::default()
            }),
            participant_pin,
            workspace_pin,
        )?;
        Ok((request.participant, request.workspace_id))
    }

    pub(crate) async fn codex_handoff(
        &mut self,
        participant: &str,
        workspace: &str,
        id: &str,
    ) -> Result<Value> {
        if !cfg!(target_os = "linux") {
            return Err(local("CODEX_HANDOFF_PLATFORM_UNSUPPORTED"));
        }
        if !identifier(id) {
            return Err(local("CONNECT_ARGUMENT_INVALID"));
        }
        self.require_writer()?;
        let key = format!("{participant}:{workspace}");
        let admin = self.runtime_admin(participant, None).await?;
        let status = crate::communication_runtime::call(&admin, json!({"method":"status"})).await?;
        if !status["value"]["optional_features"]
            .as_array()
            .is_some_and(|features| {
                features
                    .iter()
                    .any(|feature| feature == "resident-scope-rebind-v1")
            })
        {
            return Err(local("CODEX_HANDOFF_RESIDENT_RUNTIME_REQUIRED"));
        }
        let installation = install::codex_handoff_installation(self, participant, workspace)?;
        let previous = self.codex_attachment_operation(&key);
        let mut job = match self.registry.codex_handoffs.get(id) {
            Some(job) if job.participant == participant && job.workspace == workspace => {
                job.clone()
            }
            Some(_) => return Err(local("CODEX_HANDOFF_ID_CONFLICT")),
            None => {
                if self.registry.codex_handoffs.len() >= 64 {
                    return Err(local("CODEX_HANDOFF_LIMIT"));
                }
                if self.registry.codex_handoffs.values().any(|job| {
                    job.participant == participant
                        && job.workspace == workspace
                        && !job.ready
                        && (job.prior_attachment == previous
                            || job.adapter.as_ref().is_some_and(|adapter| {
                                self.codex_attachment_targets(&key, adapter)
                            }))
                }) || self.codex_attachment_pending(participant, workspace)
                {
                    return Err(local("RESUME_ORIGINAL_CODEX_HANDOFF"));
                }
                let setup = self
                    .registry
                    .active_by_scope
                    .get(&key)
                    .and_then(|id| self.registry.setups.get(id))
                    .filter(|setup| {
                        setup.channel_receive
                            && setup
                                .profile
                                .as_ref()
                                .is_some_and(|profile| profile.receive_endpoint_path.is_some())
                    })
                    .ok_or_else(|| local("ORIGINAL_RECEIVER_SETUP_RECOVERY_REQUIRED"))?;
                let job = Handoff {
                    participant: participant.into(),
                    workspace: workspace.into(),
                    request: setup.desired.clone(),
                    adapter: None,
                    prior_attachment: previous.clone(),
                    ready: false,
                };
                self.registry.codex_handoffs.insert(id.into(), job.clone());
                self.save()?;
                job
            }
        };
        if job.ready
            && job
                .adapter
                .as_ref()
                .is_none_or(|adapter| !self.matches_codex_attachment(&key, adapter))
        {
            return Err(local("CODEX_HANDOFF_SUPERSEDED"));
        }
        if previous != job.prior_attachment
            && job
                .adapter
                .as_ref()
                .is_none_or(|adapter| !self.codex_attachment_targets(&key, adapter))
        {
            return Err(local("CODEX_HANDOFF_SUPERSEDED"));
        }
        let digest = sha256_hex(id.as_bytes());
        let directory = self.directory.join(format!("handoff-{}", &digest[..16]));
        let adapter = launch(&directory, installation, job.adapter.as_ref()).await?;
        if job.adapter.is_none() {
            job.adapter = Some(adapter.clone());
            self.registry.codex_handoffs.insert(id.into(), job.clone());
            self.save()?;
        }
        let thread = adapter["thread_id"]
            .as_str()
            .ok_or_else(|| local("CODEX_HANDOFF_STATE_INVALID"))?;
        let mut result = self
            .attach_selected_host(
                job.request.clone(),
                adapter.clone(),
                thread,
                Some(RuntimeSelection {
                    admin_endpoint: admin,
                    config_path: None,
                }),
            )
            .await?;
        let can_exit = result["binding_mode"] == "RESIDENT"
            && result["self_test"]["state"] == "READY"
            && result["self_test"]["receiver_link_verified"] == true
            && result["self_test"]["automatic_receiving"] == "VERIFIED"
            && result["self_test"]["last_verified_at"].is_number();
        if can_exit && !job.ready {
            job.ready = true;
            self.registry.codex_handoffs.insert(id.into(), job);
            self.save()?;
        }
        result["handoff"] = json!({
            "id":id,
            "state": if can_exit { "READY" } else { "PENDING" }, "target":crate::communication_host::target_summary(&adapter),
            "can_exit":can_exit,
            "next_action":if can_exit {"EXIT_ORIGINAL_SESSION"} else {"REPEAT_SAME_CODEX_HANDOFF"},
        });
        Ok(result)
    }
}

#[cfg(target_os = "linux")]
async fn launch(
    directory: &Path,
    installation: (PathBuf, String, Value),
    selected: Option<&Value>,
) -> Result<Value> {
    use std::os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, OpenOptionsExt},
            process::CommandExt,
        },
    };
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let (project, name, entry) = installation;
    let socket = directory.join("codex.sock");
    if socket.as_os_str().as_bytes().len() >= 108 {
        return Err(local("CODEX_HANDOFF_SOCKET_PATH_TOO_LONG"));
    }
    crate::onboarding_files::directory(directory, true)?;
    let socket_present = || match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(local("CODEX_HANDOFF_ENDPOINT_UNAVAILABLE")),
    };
    if socket_present()? {
        if let Some(selected) = selected {
            return Ok(selected.clone());
        }
    }
    let config = crate::communication_host::codex_installation().map_err(local)?;
    let mut child = None;
    for _ in 0..200 {
        if child.is_none() && !socket_present()? {
            // The child retains this lock across exec. A replacement client can
            // wait for the same socket even if A died before Codex finished startup.
            let lease = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(directory.join("launch.lock"))
                .map_err(|_| local("CODEX_HANDOFF_STATE_INVALID"))?;
            let fd = lease.as_raw_fd();
            let locked = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
            if !locked && std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock {
                return Err(local("CODEX_HANDOFF_STATE_INVALID"));
            }
            if locked && !socket_present()? {
                match std::fs::symlink_metadata(&socket) {
                    Ok(metadata) if metadata.file_type().is_socket() => {
                        std::fs::remove_file(&socket)
                            .map_err(|_| local("CODEX_HANDOFF_ENDPOINT_UNAVAILABLE"))?;
                    }
                    Ok(_) => return Err(local("CODEX_HANDOFF_STATE_INVALID")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(_) => return Err(local("CODEX_HANDOFF_ENDPOINT_UNAVAILABLE")),
                }

                // Codex is owned by the local installation rather than A's terminal group.
                let binary = config["codex_executable"]
                    .as_str()
                    .ok_or_else(|| local("CODEX_EXECUTABLE_REQUIRED"))?;
                let home = config["codex_home"]
                    .as_str()
                    .ok_or_else(|| local("CODEX_HOME_REQUIRED"))?;
                let command = format!("mcp_servers.{name}.command={}", entry["command"]);
                let args = format!("mcp_servers.{name}.args={}", entry["args"]);
                let mut command_line = Command::new(binary);
                // This process owns its own login session and survives A's process group.
                unsafe {
                    command_line.pre_exec(move || {
                        if libc::setsid() == -1 || libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                child = Some(
                    command_line
                        .env("CODEX_HOME", home)
                        .current_dir(&project)
                        .args(["-c", &command, "-c", &args, "app-server", "--listen"])
                        .arg(format!("unix://{}", socket.display()))
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .map_err(|_| local("CODEX_HANDOFF_LAUNCH_FAILED"))?,
                );
            }
        }
        if socket_present()? {
            let endpoint = selected.cloned().unwrap_or_else(|| {
                json!({
                    "kind":"codex","endpoint":format!("unix://{}", socket.display()),
                    "expected_socket_uid":config["codex_uid"],
                })
            });
            let executor = tokio::runtime::Handle::current();
            let project = project.clone();
            let result = tokio::task::spawn_blocking(move || {
                crate::communication_host::codex_prepare_handoff(endpoint, &project, executor)
            })
            .await
            .map_err(|_| local("CODEX_HANDOFF_LAUNCH_FAILED"))?;
            if result != Err("HOST_UNAVAILABLE") {
                if let Some(mut child) = child {
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                }
                return result.map_err(local);
            }
        }
        if let Some(process) = &mut child {
            if process
                .try_wait()
                .map_err(|_| local("CODEX_HANDOFF_LAUNCH_FAILED"))?
                .is_some()
            {
                return Err(local("CODEX_HANDOFF_LAUNCH_FAILED"));
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if let Some(mut child) = child {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    Err(local("CODEX_HANDOFF_ENDPOINT_UNAVAILABLE"))
}

#[cfg(not(target_os = "linux"))]
async fn launch(_: &Path, _: (PathBuf, String, Value), _: Option<&Value>) -> Result<Value> {
    Err(local("CODEX_HANDOFF_PLATFORM_UNSUPPORTED"))
}

pub(super) fn cli(args: &[String]) -> Value {
    let outcome = (|| -> Result<Value> {
        let [local_flag, directory, participant_flag, participant, workspace_flag, workspace, id] =
            args
        else {
            return Err(local("CONNECT_ARGUMENT_INVALID"));
        };
        if local_flag != "--local"
            || participant_flag != "--participant"
            || workspace_flag != "--workspace"
        {
            return Err(local("CONNECT_ARGUMENT_INVALID"));
        }
        let directory =
            std::path::absolute(directory).map_err(|_| local("LOCAL_SELECTION_INVALID"))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| local("EXECUTOR_FAILED"))?;
        runtime.block_on(async {
            let mut connect = Connect::open(&directory)?;
            let intent = HandoffIntent {
                codex_handoff_id: id.clone(),
                participant: Some(participant.clone()),
                workspace_id: Some(workspace.clone()),
            };
            let (participant, workspace) = connect.handoff_scope(&intent, None, None)?;
            connect.codex_handoff(&participant, &workspace, id).await
        })
    })();
    outcome.unwrap_or_else(|error| json!({"ok":false,"state":"FAILED","error":error}))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn connect_handoff_requires_an_explicit_id_and_excludes_other_actions() {
        assert!(matches!(
            serde_json::from_value::<ConnectInput>(json!({"codex_handoff_id":"replace-a"}))
                .unwrap(),
            ConnectInput::Handoff(_)
        ));
        assert!(serde_json::from_value::<ConnectInput>(
            json!({"codex_handoff_id":"replace-a","new":true})
        )
        .is_err());
    }

    #[tokio::test]
    #[ignore = "requires an isolated Linux Codex installation and synthetic model"]
    async fn codex_handoff_launch_and_same_thread_restart() {
        struct Server(libc::pid_t);
        impl Drop for Server {
            fn drop(&mut self) {
                // The PID comes from the test's private socket peer.
                unsafe {
                    libc::kill(self.0, libc::SIGTERM);
                }
            }
        }

        let root = crate::test_support::protected_test_dir();
        let server_state = root.path().join("server");
        let installation = (
            root.path().to_owned(),
            "test-peerwork".into(),
            json!({"command":"/bin/false","args":[]}),
        );
        let adapter = launch(&server_state, installation.clone(), None)
            .await
            .unwrap();
        let socket = server_state.join("codex.sock");
        let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let first = Server(stream.peer_cred().unwrap().pid().unwrap());
        drop(stream);
        let repeated = launch(&server_state, installation.clone(), None)
            .await
            .unwrap();
        assert_eq!(repeated, adapter);
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while tokio::net::UnixStream::connect(&socket).await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            launch(&server_state, installation, Some(&adapter))
                .await
                .unwrap(),
            adapter
        );
        let second = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let _second = Server(second.peer_cred().unwrap().pid().unwrap());
    }
}
