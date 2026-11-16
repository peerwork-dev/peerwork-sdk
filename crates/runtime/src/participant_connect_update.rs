//! Update the selected installation using its existing local-owner lifecycle.
//! The executing CLI is the target artifact; no command or PID is supplied by a tool.
use super::*;
use std::io::Read;

const REQUIRED: &[&str] = &["host-observation-upload-deadline-v1","current-host-delivery-health-v1","automatic-runtime-startup-v1"];

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Phase {
    Prepared,
    Stopping,
    Starting,
    RuntimeReady,
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    format: String,
    participant: String,
    registration: Registration,
    executable: PathBuf,
    executable_digest: String,
    required_features: Vec<String>,
    original: bootstrap::OwnedRuntime,
    was_running: bool,
    phase: Phase,
}
fn compatible(status: &Value, required: &[String]) -> bool {
    required.iter().all(|wanted| {
        status["optional_features"]
            .as_array()
            .is_some_and(|features| features.iter().any(|feature| feature == wanted))
    })
}
fn executable_digest(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).map_err(|_| local("UPDATE_EXECUTABLE_UNAVAILABLE"))?;
    let mut bytes = Vec::new();
    file.take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| local("UPDATE_EXECUTABLE_UNAVAILABLE"))?;
    if bytes.is_empty() || bytes.len() > 256 * 1024 * 1024 {
        return Err(local("UPDATE_EXECUTABLE_INVALID"));
    }
    Ok(sha256_hex(&bytes))
}
pub(super) fn startup_update(connect: &Connect, participant: &str) -> Result<Option<PathBuf>> {
    let path = connect.directory.join(format!("update-{participant}.state"));
    if !path.exists() { return Ok(None); }
    let update: Update = serde_json::from_slice(&SecureStateStore::read_snapshot(&path, 2 * 1024 * 1024)
        .map_err(|_| local("UPDATE_STATE_UNAVAILABLE"))?).map_err(|_| local("UPDATE_STATE_INVALID"))?;
    if update.phase == Phase::Complete { return Ok(None); }
    if update.format != "peerwork.owned-update.v1" || update.participant != participant
        || connect.registry.participants.get(participant) != Some(&update.registration)
        || !update.executable.is_absolute() || executable_digest(&update.executable)? != update.executable_digest {
        return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
    }
    // A live updater owns this existing operation fence. Do not start another
    // observer process while that operation is still progressing.
    if SecureStateStore::open(&path).is_err() { return Err(local("UPDATE_ALREADY_OWNED_OR_UNSAFE")); }
    Ok(Some(update.executable))
}
fn save(store: &SecureStateStore, update: &Update) -> Result<()> {
    store
        .write_exact(&serde_json::to_vec(update).map_err(|_| local("UPDATE_STATE_INVALID"))?)
        .map_err(|_| local("UPDATE_STATE_WRITE_FAILED"))
}
async fn observation(owned: &bootstrap::OwnedRuntime) -> Result<Value> {
    let response = crate::communication_runtime::call(
        &owned.config.state_directory.join("admin.json"),
        json!({"method":"status"}),
    )
    .await?;
    if response["ok"] != true {
        return Err(local("UPDATE_RUNTIME_STATUS_UNAVAILABLE"));
    }
    let status = &response["value"];
    for engine in &owned.config.engines {
        let digest = engine.binding_digest()?;
        if !status["engines"].as_array().is_some_and(|engines| {
            engines
                .iter()
                .any(|e| e["actor_id"] == engine.expected_actor && e["engine_digest"] == digest)
        }) {
            return Err(local("HOST_RUNTIME_BINDING_MISMATCH"));
        }
    }
    let client = RuntimeClient::connect(
        owned.registration.endpoint_path.clone(),
        &owned.registration.origin,
        &owned.registration.actor_id,
    )
    .await?;
    client.call(json!({"method":"binding"})).await?;
    Ok(status.clone())
}
fn continuation(
    connect: &Connect,
    participant: &str,
    external_runtime: bool,
    hosts: &[crate::participant_dispatch::HostConfig],
) -> Value {
    let installations = install::update_inventory(connect, participant);
    let external_hosts: Vec<_> = hosts
        .iter()
        .filter(|h| h.adapter["kind"] == "bridge")
        .map(|h| {
            json!({"name":h.name,"adapter":h.adapter["kind"],
        "loaded_version":"UNKNOWN","destination":"PRESERVE_ORIGINAL"})
        })
        .collect();
    if external_runtime || !installations.is_empty() || !external_hosts.is_empty() {
        json!({"action":"COMPLETE_ORIGINAL_STACK_UPDATE","runtime":if external_runtime{"USE_ORIGINAL_RUNTIME_SUPERVISOR"}else{"OWNED_WORK_COMPLETE"},
            "integrations":installations,"hosts":external_hosts,
            "instructions":"Refresh the listed original MCP integrations using their host-supported reload. Verify each listed independent bridge through its original owning installation; use its original launcher and state only when replacement is needed. An external runtime stays with its original supervisor. Then call peerwork_context and peerwork_delivery status in that same host; preserve its session.",
            "guide":"docs/host-bridge-recovery.md#upgrade-the-original-receiving-stack",
            "host_reload_performed":false,"model_wake":"NOT_ATTESTED"})
    } else {
        Value::Null
    }
}
impl Connect {
    /// Inspect or resume an update of the already selected client. `apply`
    /// uses this CLI's artifact and never selects new identity/host authority.
    pub async fn update(&mut self, participant: Option<&str>, apply: bool) -> Result<Value> {
        let handle = self
            .selected_handle(participant)?
            .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let executable = std::env::current_exe().map_err(|_| local("EXECUTABLE_UNAVAILABLE"))?;
        let required: Vec<String> = REQUIRED.iter().map(|s| s.to_string()).collect();
        let path = self.directory.join(format!("update-{handle}.state"));
        let owned = match bootstrap::owned_runtime(self, &handle) {
            Ok(owned) => Some(owned),
            Err(e) if e.code == "LOCAL_RUNTIME_TAKEOVER_REQUIRED" => None,
            Err(e) => return Err(e),
        };
        if !apply {
            let (runtime, hosts) = match owned.as_ref() {
                Some(o) if o.running()? => {
                    let status = observation(o).await?;
                    (
                        json!({"ownership":"OWNED","state":"RUNNING","loaded_version":status["sdk_version"],
                        "compatible":compatible(&status,&required),"required_features":required}),
                        o.config.hosts.clone(),
                    )
                }
                Some(o) => (
                    json!({"ownership":"OWNED","state":"STOPPED","loaded_version":"NOT_RUNNING"}),
                    o.config.hosts.clone(),
                ),
                None => (
                    json!({"ownership":"EXTERNAL","state":"UNKNOWN","loaded_version":"UNKNOWN"}),
                    Vec::new(),
                ),
            };
            let pending = if path.exists() {
                let wire = SecureStateStore::read_snapshot(&path, 2 * 1024 * 1024)
                    .map_err(|_| local("UPDATE_STATE_UNAVAILABLE"))?;
                let state: Update =
                    serde_json::from_slice(&wire).map_err(|_| local("UPDATE_STATE_INVALID"))?;
                json!({"phase":state.phase,"target_executable":state.executable})
            } else {
                Value::Null
            };
            return Ok(
                json!({"state":"UPDATE_INVENTORY","participant":handle,"frontend_version":env!("CARGO_PKG_VERSION"),
                "runtime":runtime,"integrations":install::update_inventory(self,&handle),"operation":pending,
                "continuation":continuation(self,&handle,owned.is_none(),&hosts)}),
            );
        }
        self.require_writer()?;
        let Some(owned) = owned else {
            // Installation ownership does not imply external process ownership.
            let outputs = install::update_owned(self, &handle, &executable)?;
            return Ok(
                json!({"state":"EXTERNAL_ACTION_REQUIRED","participant":handle,"installations":outputs,
                "continuation":continuation(self,&handle,true,&[]),"runtime_restarted":false}),
            );
        };
        let digest = executable_digest(&executable)?;
        let _maintenance = crate::runtime_startup::recovery_fence(&owned.config.state_directory)?;
        let store =
            SecureStateStore::open(&path).map_err(|_| local("UPDATE_ALREADY_OWNED_OR_UNSAFE"))?;
        let previous: Option<Update> = store
            .read_exact()
            .map_err(|_| local("UPDATE_STATE_UNAVAILABLE"))?
            .map(|wire| serde_json::from_slice(&wire).map_err(|_| local("UPDATE_STATE_INVALID")))
            .transpose()?;
        let mut update = match previous {
            Some(saved) if saved.phase != Phase::Complete => {
                if saved.format != "peerwork.owned-update.v1"
                    || saved.participant != handle
                    || saved.registration != owned.registration
                    || saved.executable_digest != digest
                    || saved.executable != executable
                    || saved.required_features != required
                {
                    return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
                }
                if serde_json::to_value(&saved.original.config).ok()
                    != serde_json::to_value(&owned.config).ok()
                {
                    return Err(local("ORIGINAL_RUNTIME_CONFIG_CHANGED"));
                }
                saved
            }
            _ => {
                let running = owned.running()?;
                // Authenticate the selected live endpoint before recording an
                // operation that can stop it. An unreachable child is not dead.
                if running {
                    observation(&owned).await?;
                }
                let next = Update {
                    format: "peerwork.owned-update.v1".into(),
                    participant: handle.clone(),
                    registration: owned.registration.clone(),
                    executable: executable.clone(),
                    executable_digest: digest,
                    required_features: required.clone(),
                    original: owned.clone(),
                    was_running: running,
                    phase: Phase::Prepared,
                };
                save(&store, &next)?;
                next
            }
        };
        if update.phase == Phase::Prepared {
            update.phase =
                if !update.was_running || compatible(&observation(&owned).await?, &required) {
                    Phase::RuntimeReady
                } else {
                    Phase::Stopping
                };
            save(&store, &update)?;
        }
        if update.phase == Phase::Stopping {
            if executable_digest(&update.executable)? != update.executable_digest {
                return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
            }
            update.original.stop().await?;
            update.phase = Phase::Starting;
            save(&store, &update)?;
        }
        if update.phase == Phase::Starting {
            // Persisted STARTING resumes the same launch after a failed spawn,
            // interrupted start, or lost response. Existing launch fences prevent
            // duplicate writers; never synthesize empty state or another config.
            if executable_digest(&update.executable)? != update.executable_digest {
                return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
            }
            update.original.restart(&update.original.config).await?;
            let status = observation(&update.original).await?;
            if !compatible(&status, &required) {
                return Err(local("UPDATE_TARGET_MISSING_REQUIRED_FEATURE"));
            }
            update.phase = Phase::RuntimeReady;
            save(&store, &update)?;
        }
        let outputs = install::update_owned(self, &handle, &executable)?;
        if update.was_running {
            let current = observation(&update.original).await?;
            if !compatible(&current, &required) {
                return Err(local("UPDATE_TARGET_MISSING_REQUIRED_FEATURE"));
            }
        } else if bootstrap::owned_runtime(self, &handle)?.running()? {
            return Err(local("UPDATE_RUNTIME_STATE_CHANGED"));
        }
        update.phase = Phase::Complete;
        save(&store, &update)?;
        Ok(
            json!({"state":"OWNED_UPDATE_COMPLETE","participant":handle,"runtime":if update.was_running{"RUNNING_COMPATIBLE"}else{"STOPPED_PRESERVED"},
            "required_features":required,"installations":outputs,"original_operations":"PRESERVED",
            "delivery_pause":"PRESERVED","approvals":"UNCHANGED","model_wake":"NOT_ATTESTED",
            "continuation":continuation(self,&handle,false,&update.original.config.hosts)}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_cli_rejects_mixed_context_or_setup_before_opening_state() {
        for extra in ["--context", "--receive"] {
            let result = cli(&["--update".into(), "apply".into(), extra.into()]);
            assert_eq!(result["state"], "FAILED");
            assert_eq!(
                result["error"]["code"],
                "UPDATE_USES_SELECTED_CLIENT_AND_STATUS_OR_APPLY"
            );
        }
    }
    #[test]
    fn compatible_mixed_versions_use_capabilities_not_version_equality() {
        let required = vec!["host-observation-upload-deadline-v1".into()];
        assert!(compatible(
            &json!({"sdk_version":"9.1.0","optional_features":required}),
            &required
        ));
        assert!(!compatible(
            &json!({"sdk_version":env!("CARGO_PKG_VERSION"),"optional_features":[]}),
            &required
        ));
        assert!(!compatible(&json!({"sdk_version":"unknown"}), &required));
    }
    #[tokio::test]
    async fn external_runtime_is_not_claimed_and_approval_state_is_untouched() {
        let root = crate::test_support::protected_test_dir();
        let mut c = Connect::open(root.path()).unwrap();
        c.registry.participants.insert(
            "peer".into(),
            Registration {
                origin: "https://example.invalid/".into(),
                actor_id: "A".repeat(43),
                endpoint_path: root.path().join("external.json"),
            },
        );
        c.save().unwrap();
        let before = std::fs::read(root.path().join("connect.state")).unwrap();
        let result = c.update(Some("peer"), true).await.unwrap();
        assert_eq!(result["state"], "EXTERNAL_ACTION_REQUIRED");
        assert_eq!(result["runtime_restarted"], false);
        assert_eq!(
            before,
            std::fs::read(root.path().join("connect.state")).unwrap()
        );
        assert!(!root.path().join("update-peer.state").exists());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod process_tests {
    use super::*;
    use crate::communication_runtime::{ClientConfig, EngineConfig, RuntimeConfig};
    use crate::kernel_identity::KernelIdentity;
    use std::process::{Child, Command, Stdio};

    struct Fixture {
        root: crate::test_support::ProtectedTestDir,
        binary: PathBuf,
        previous: PathBuf,
        child: Child,
        config: RuntimeConfig,
        registration: Registration,
    }
    impl Fixture {
        async fn new() -> Self {
            let binary = PathBuf::from(
                std::env::var_os("PEERWORK_UPDATE_TEST_BINARY").expect("set exact candidate CLI"),
            );
            let previous = PathBuf::from(
                std::env::var_os("PEERWORK_UPDATE_PREVIOUS_BINARY")
                    .expect("set previous compatible CLI"),
            );
            assert!(binary.is_absolute() && previous.is_absolute());
            let root = crate::test_support::protected_test_dir();
            let identity_path = root.path().join("identity");
            let identity = KernelIdentity::create(&identity_path).unwrap();
            let directory = root.path().join("registry");
            let mut connect = Connect::open(&directory).unwrap();
            let runtime = directory.join("runtime-peer");
            create_private_state_directory(&runtime).unwrap();
            let config = RuntimeConfig {
                format: "peerwork.participant-runtime.v1".into(),
                state_directory: runtime.clone(),
                hosts: vec![],
                engines: vec![EngineConfig {
                    name: "original".into(),
                    origin: "http://127.0.0.1:1".into(),
                    expected_actor: identity.actor_id().into(),
                    identity_path,
                    state_directory: root.path().join("engine"),
                    journal_path: None,
                    authority: None,
                    migration_sources: vec![],
                    allow_loopback_http: true,
                    transport: Default::default(),
                    max_inflight: 1,
                    max_pending: 2,
                    max_stored_bytes: 1024 * 1024,
                }],
                clients: vec![ClientConfig {
                    name: "bootstrap".into(),
                    engine: "original".into(),
                    capability: Capability::owner(),
                }],
            };
            let registration = Registration {
                origin: config.engines[0].origin.clone(),
                actor_id: identity.actor_id().into(),
                endpoint_path: runtime.join("client-bootstrap.json"),
            };
            let bytes = serde_json::to_vec(&config).unwrap();
            write_private(&runtime.join("config.json"), &bytes).unwrap();
            let child = Command::new(&previous)
                .args(["runtime", "run"])
                .arg(runtime.join("config.json"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let launch = SecureStateStore::open(&runtime.join("bootstrap.state")).unwrap();
            launch.write_exact(&serde_json::to_vec(&json!({"config_digest":sha256_hex(&bytes),"pid":child.id(),"process_token":crate::communication_store::process_token(child.id())})).unwrap()).unwrap();
            drop(launch);
            connect
                .registry
                .participants
                .insert("peer".into(), registration.clone());
            connect
                .registry
                .local_runtime_admins
                .insert("peer".into(), runtime.join("admin.json"));
            connect.save().unwrap();
            drop(connect);
            let fixture = Self {
                root,
                binary,
                previous,
                child,
                config,
                registration,
            };
            for _ in 0..100 {
                if crate::communication_runtime::call(
                    &runtime.join("admin.json"),
                    json!({"method":"status"}),
                )
                .await
                .is_ok()
                {
                    return fixture;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            panic!("synthetic original runtime did not start");
        }
        fn cli(&self, mode: &str) -> Value {
            let result = Command::new(&self.binary)
                .arg("connect")
                .arg("--local")
                .arg(self.root.path().join("registry"))
                .args(["--participant", "peer", "--update", mode])
                .output()
                .unwrap();
            serde_json::from_slice(&result.stdout).unwrap_or_else(|_| {
                panic!(
                    "invalid CLI output: {}",
                    String::from_utf8_lossy(&result.stderr)
                )
            })
        }
        fn state(&self) -> Update {
            serde_json::from_slice(
                &SecureStateStore::read_snapshot(
                    &self.root.path().join("registry/update-peer.state"),
                    2 * 1024 * 1024,
                )
                .unwrap(),
            )
            .unwrap()
        }
        fn record(&self, phase: Phase) -> Update {
            let directory = self.root.path().join("registry");
            let connect = Connect::open(&directory).unwrap();
            let original = bootstrap::owned_runtime(&connect, "peer").unwrap();
            let update = Update {
                format: "peerwork.owned-update.v1".into(),
                participant: "peer".into(),
                registration: self.registration.clone(),
                executable: self.binary.clone(),
                executable_digest: executable_digest(&self.binary).unwrap(),
                required_features: REQUIRED.iter().map(|s| s.to_string()).collect(),
                original,
                was_running: true,
                phase,
            };
            let store = SecureStateStore::open(&directory.join("update-peer.state")).unwrap();
            save(&store, &update).unwrap();
            update
        }
        async fn stop(&self) {
            let directory = self.root.path().join("registry");
            let connect = Connect::open(&directory).unwrap();
            bootstrap::owned_runtime(&connect, "peer")
                .unwrap()
                .stop()
                .await
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only test-owned original/updated children are addressed, through
            // the authenticated synthetic admin; no discovered process is killed.
            let _ = Command::new(&self.binary)
                .args(["runtime", "admin"])
                .arg(self.config.state_directory.join("admin.json"))
                .arg("stop")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.try_wait();
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires exact candidate/previous CLI artifacts and synthetic loopback IPC"]
    async fn owned_update_real_process_upgrade_compatible_repeat_and_stopped_preservation() {
        let fixture = Fixture::new().await;
        let config = std::fs::read(fixture.config.state_directory.join("config.json")).unwrap();
        let identity = std::fs::read(&fixture.config.engines[0].identity_path).unwrap();
        let registry = std::fs::read(fixture.root.path().join("registry/connect.state")).unwrap();
        let result = fixture.cli("apply");
        assert_eq!(result["state"], "OWNED_UPDATE_COMPLETE", "{result}");
        let launch = SecureStateStore::read_snapshot(
            &fixture.config.state_directory.join("bootstrap.state"),
            65536,
        )
        .unwrap();
        let result = fixture.cli("apply");
        assert_eq!(result["state"], "OWNED_UPDATE_COMPLETE", "{result}");
        assert_eq!(
            launch,
            SecureStateStore::read_snapshot(
                &fixture.config.state_directory.join("bootstrap.state"),
                65536
            )
            .unwrap(),
            "compatible loaded runtime must not restart"
        );
        let mixed = Command::new(&fixture.previous)
            .args(["runtime", "admin"])
            .arg(fixture.config.state_directory.join("admin.json"))
            .arg("status")
            .output()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&mixed.stdout).unwrap()["ok"],
            true,
            "previous frontend can observe new runtime"
        );
        fixture.stop().await;
        let result = fixture.cli("apply");
        assert_eq!(result["runtime"], "STOPPED_PRESERVED", "{result}");
        assert_eq!(fixture.cli("status")["runtime"]["state"], "STOPPED");
        assert_eq!(
            config,
            std::fs::read(fixture.config.state_directory.join("config.json")).unwrap()
        );
        assert_eq!(
            identity,
            std::fs::read(&fixture.config.engines[0].identity_path).unwrap()
        );
        assert_eq!(
            registry,
            std::fs::read(fixture.root.path().join("registry/connect.state")).unwrap()
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires exact candidate/previous CLI artifacts and synthetic loopback IPC"]
    async fn owned_update_real_process_resumes_interrupted_stop_and_failed_start() {
        let fixture = Fixture::new().await;
        let update = fixture.record(Phase::Stopping);
        update.original.stop().await.unwrap(); // interruption after stop, before STARTING checkpoint
        let held =
            SecureStateStore::open(&fixture.config.state_directory.join("runtime.state")).unwrap();
        let result = fixture.cli("apply");
        assert_eq!(result["state"], "FAILED", "{result}");
        assert!(matches!(fixture.state().phase, Phase::Starting));
        drop(held);
        let result = fixture.cli("apply");
        assert_eq!(result["state"], "OWNED_UPDATE_COMPLETE", "{result}");
        assert_eq!(fixture.cli("status")["runtime"]["compatible"], true);
        fixture.stop().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires exact candidate/previous CLI artifacts and synthetic loopback IPC"]
    async fn owned_update_real_process_external_owner_keeps_running_and_updates_only_owned_entry() {
        let mut fixture = Fixture::new().await;
        let directory = fixture.root.path().join("registry");
        let project = fixture.root.path().join("project");
        crate::onboarding_files::directory(&project, false).unwrap();
        let mut connect = Connect::open(&directory).unwrap();
        let original = bootstrap::owned_runtime(&connect, "peer").unwrap();
        connect
            .install(
                "peer",
                &"W".repeat(43),
                Installation {
                    host: "agy".into(),
                    project: project.clone(),
                    executable: fixture.previous.clone(),
                },
            )
            .unwrap();
        connect.registry.local_runtime_admins.remove("peer");
        connect.save().unwrap();
        drop(connect);
        let result = fixture.cli("apply");
        assert_eq!(result["state"], "EXTERNAL_ACTION_REQUIRED", "{result}");
        assert_eq!(result["runtime_restarted"], false);
        assert!(
            fixture.child.try_wait().unwrap().is_none(),
            "external process must remain alive"
        );
        let configured: Value = serde_json::from_slice(
            &std::fs::read(project.join(".agents/mcp_config.json")).unwrap(),
        )
        .unwrap();
        let entries = configured["mcpServers"].as_object().unwrap();
        assert_eq!(
            entries.values().next().unwrap()["command"],
            json!(fixture.binary)
        );
        assert_eq!(
            result["continuation"]["integrations"][0]["loaded_version"],
            "UNKNOWN"
        );
        assert!(!directory.join("update-peer.state").exists());
        original.stop().await.unwrap();
    }
}
