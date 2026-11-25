//! Update the selected installation using its existing local-owner lifecycle.
//! The executing CLI is the target artifact; no command or PID is supplied by a tool.
use super::*;
use std::io::Read;

const REQUIRED: &[&str] = &["host-observation-upload-deadline-v1","current-host-delivery-health-v1","automatic-runtime-startup-v1","harness-connection-context-v1","receiving-lifecycle-recovery-v1"];

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
    if !update.required_features.iter().any(|f| f == "automatic-runtime-startup-v1") {
        return Err(local("UPDATE_RUNTIME_UPGRADE_REQUIRED"));
    }
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
fn verify_engines(config: &crate::communication_runtime::RuntimeConfig, status: &Value) -> Result<()> {
    let engines = status["engines"].as_array()
        .filter(|engines| engines.len() == config.engines.len())
        .ok_or_else(|| local("HOST_RUNTIME_BINDING_MISMATCH"))?;
    for engine in &config.engines {
        let digest = engine.binding_digest()?;
        if !engines.iter().any(|observed| observed["name"] == engine.name
            && observed["actor_id"] == engine.expected_actor
            && observed["engine_digest"] == digest) {
            return Err(local("HOST_RUNTIME_BINDING_MISMATCH"));
        }
    }
    Ok(())
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
    verify_engines(&owned.config, status)?;
    let client = RuntimeClient::connect(
        owned.registration.endpoint_path.clone(),
        &owned.registration.origin,
        &owned.registration.actor_id,
    )
    .await?;
    client.call(json!({"method":"binding"})).await?;
    Ok(status.clone())
}
fn host_inventory(owned: &bootstrap::OwnedRuntime, status: Option<&Value>) -> Result<Vec<crate::participant_dispatch::HostConfig>> {
    if let Some(hosts) = status.and_then(|status| status.get("host_configurations")) {
        // This field comes only from the authenticated original administrator.
        // Do not replace invalid current inventory with an older disk snapshot.
        return serde_json::from_value(hosts.clone()).map_err(|_| local("UPDATE_HOST_INVENTORY_INVALID"));
    }
    crate::communication_runtime::host_configuration_snapshot(&owned.config.state_directory, &owned.config.hosts)
}
async fn external_runtime_status(connect: &Connect, handle: &str, required: &[String]) -> Value {
    let observed = match connect.original_client(handle).await {
        Ok(client) => client.call(json!({"method":"capabilities"})).await,
        Err(error) => Err(error),
    };
    match observed {
        Ok(value) if value["sdk_version"].is_string() => {
            let compatible = value["features"].as_array().is_some_and(|features|
                required.iter().all(|wanted| features.iter().any(|feature| feature == wanted)));
            json!({"ownership":"EXTERNAL","state":"RUNNING","loaded_version":value["sdk_version"],
                "compatible":compatible,"observation":"AUTHENTICATED_CLIENT_IPC"})
        }
        Ok(_) => json!({"ownership":"EXTERNAL","state":"UNKNOWN","loaded_version":"UNKNOWN"}),
        Err(error) => json!({"ownership":"EXTERNAL","state":"UNKNOWN","loaded_version":"UNKNOWN","code":error.code}),
    }
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
        json!({"action":"COMPLETE_ORIGINAL_STACK_UPDATE","runtime":if external_runtime{"USE_ORIGINAL_RUNTIME_LIFECYCLE"}else{"OWNED_WORK_COMPLETE"},
            "integrations":installations,"hosts":external_hosts,
            "instructions":"Refresh the listed original MCP integrations using their host-supported reload. Verify each listed independent bridge through its original owning installation; use its original launcher and state only when replacement is needed. Use the original supervisor when it owns a shared runtime. For a directly launched runtime, its operator can explicitly select the original config, admin endpoint and rollback binary with update apply. Then call peerwork_context and peerwork_delivery status in that same host; preserve its session.",
            "guide":"docs/host-bridge-recovery.md#upgrade-the-original-receiving-stack",
            "host_reload_performed":false,"model_wake":"NOT_ATTESTED"})
    } else {
        Value::Null
    }
}
use crate::runtime_startup::{Launcher, Policy};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SharedPhase { Stopping, Starting, RollingBack, RolledBack, Complete, Reconciled }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedUpdate {
    original: bootstrap::OwnedRuntime,
    target: Launcher,
    rollback: Launcher,
    previous_version: String,
    receivers: Value,
    hosts: Vec<crate::participant_dispatch::HostConfig>,
    policy: Option<Policy>,
    phase: SharedPhase,
}

fn save_shared(store: &SecureStateStore, update: &SharedUpdate) -> Result<()> {
    store.write_exact(&serde_json::to_vec(update).map_err(|_| local("UPDATE_STATE_INVALID"))?)
        .map_err(|_| local("UPDATE_STATE_WRITE_FAILED"))
}

fn read_shared_config(selection: &bootstrap::RuntimeSelection) -> Result<crate::communication_runtime::RuntimeConfig> {
    let path = selection.config_path.as_deref().ok_or_else(|| local("ORIGINAL_RUNTIME_CONFIG_SELECTION_REQUIRED"))?;
    let config: crate::communication_runtime::RuntimeConfig = serde_json::from_value(
        crate::communication_store::private_json(path, 65536).map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
    ).map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
    if !config.state_directory.is_absolute() || selection.admin_endpoint != config.state_directory.join("admin.json") {
        return Err(local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"));
    }
    Ok(config)
}

fn verify_shared_state(update: &SharedUpdate, status: &Value) -> Result<()> {
    if status["receivers"] != update.receivers
        || serde_json::to_value(host_inventory(&update.original, Some(status))?).ok()
            != serde_json::to_value(&update.hosts).ok()
    {
        return Err(local("UPDATE_ORIGINAL_RECEIVING_BINDINGS_CHANGED"));
    }
    Ok(())
}
async fn rollback_version(artifact: &Launcher) -> Result<String> {
    let mut command = tokio::process::Command::new(&artifact.executable);
    command.arg("version").kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
        .await.map_err(|_| local("UPDATE_ROLLBACK_VERSION_UNAVAILABLE"))?
        .map_err(|_| local("UPDATE_ROLLBACK_VERSION_UNAVAILABLE"))?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(local("UPDATE_ROLLBACK_VERSION_UNAVAILABLE"));
    }
    let version: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| local("UPDATE_ROLLBACK_VERSION_UNAVAILABLE"))?;
    version["version"].as_str().map(str::to_owned).ok_or_else(|| local("UPDATE_ROLLBACK_VERSION_UNAVAILABLE"))
}

fn release_version(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let version = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(version)
}

async fn reconcile_rollback(store: &SecureStateStore, mut update: SharedUpdate,
    current_artifact: &Launcher) -> Result<Value> {
    let status = observation(&update.original).await?;
    verify_shared_state(&update, &status)?;
    current_artifact.verify()?;
    let version = rollback_version(current_artifact).await?;
    if status["state"] != "LOCAL_READY" || status["sdk_version"] != version {
        return Err(local("UPDATE_ROLLBACK_RUNTIME_VERSION_MISMATCH"));
    }
    let version_number = |version| release_version(version).ok_or_else(|| local("UPDATE_RUNTIME_VERSION_UNCONFIRMED"));
    let current = version_number(&version)?;
    if current < version_number(&update.previous_version)? || current > version_number(env!("CARGO_PKG_VERSION"))? {
        return Err(local("UPDATE_ROLLBACK_RECONCILIATION_REQUIRES_COMPATIBLE_UPGRADE"));
    }
    let directory = &update.original.config.state_directory;
    if update.policy.is_none() && crate::runtime_startup::read(directory)?.is_some() {
        return Err(local("RUNTIME_STARTUP_POLICY_CHANGED"));
    }
    // Keep the existing startup intent. If it had a launcher, pin the
    // verified current-version artifact before closing the obsolete rollback.
    crate::runtime_startup::commit_maintenance_launcher(directory, &update.policy, current_artifact)?;
    update.phase = SharedPhase::Reconciled;
    save_shared(store, &update)?;
    Ok(json!({"state":"SHARED_RUNTIME_UPDATE_RECONCILED","runtime_version":version,
        "abandoned_rollback_version":update.previous_version,"runtime_restarted":false,
        "original_operations":"PRESERVED","next_action":"REPEAT_UPDATE_APPLY_WITH_CURRENT_RUNTIME_ARTIFACT",
        "model_wake":"NOT_ATTESTED"}))
}

impl Connect {
    /// Explicit local-owner takeover for a directly launched shared runtime.
    /// Its original state directory serializes updates across all registries.
    pub(super) async fn update_shared(&mut self, participant: Option<&str>,
        selection: &bootstrap::RuntimeSelection, rollback_path: &Path) -> Result<Value> {
        let target = Launcher::capture(install::persistent_executable(
            &std::env::current_exe().map_err(|_| local("EXECUTABLE_UNAVAILABLE"))?)?)?;
        let rollback = Launcher::capture(install::persistent_executable(rollback_path)?)?;
        self.update_shared_using(participant, selection, target, rollback).await
    }

    async fn update_shared_using(&mut self, participant: Option<&str>,
        selection: &bootstrap::RuntimeSelection, target: Launcher, rollback: Launcher) -> Result<Value> {
        self.require_writer()?;
        let handle = self.selected_handle(participant)?.ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let registration = self.registry.participants.get(&handle).cloned().ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let config = read_shared_config(selection)?;
        let directory = &config.state_directory;
        let _fence = crate::runtime_startup::recovery_fence(directory)?;
        let store = SecureStateStore::open(&directory.join("shared-update.state"))
            .map_err(|_| local("UPDATE_ALREADY_OWNED_OR_UNSAFE"))?;
        let persisted = store.read_exact().map_err(|_| local("UPDATE_STATE_UNAVAILABLE"))?
            .map(|wire| serde_json::from_slice::<SharedUpdate>(&wire).map_err(|_| local("UPDATE_STATE_INVALID")))
            .transpose()?;
        let mut update = if let Some(saved) = persisted.filter(|saved| match saved.phase {
            SharedPhase::Reconciled => false,
            SharedPhase::Complete | SharedPhase::RolledBack => saved.target == target,
            _ => true,
        }) {
            if saved.original.registration != registration || saved.original.path() != *selection.config_path.as_ref().unwrap()
                || serde_json::to_value(&saved.original.config).ok() != serde_json::to_value(&config).ok() {
                return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
            }
            if saved.target != target || saved.rollback != rollback {
                if saved.phase == SharedPhase::RollingBack {
                    // Reconcile only from live evidence on the sealed original
                    // binding. Neither artifact from the old transaction runs.
                    self.original_client(&handle).await?;
                    return reconcile_rollback(&store, saved, &rollback).await;
                }
                return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
            }
            saved
        } else {
            let original = self.runtime_for_source(&handle, selection).await?;
            let status = observation(&original).await?;
            let version = rollback_version(&rollback).await?;
            if status["sdk_version"] != version || rollback == target {
                return Err(local("UPDATE_ROLLBACK_RUNTIME_VERSION_MISMATCH"));
            }
            let hosts = host_inventory(&original, Some(&status))?;
            let policy = crate::runtime_startup::read(directory)?;
            if policy.as_ref().is_some_and(|policy| !policy.automatic) {
                return Err(local("RUNTIME_AUTOMATIC_START_DISABLED"));
            }
            original.preflight_shared_launcher()?;
            let update = SharedUpdate {original, target, rollback, previous_version: version,
                receivers: status["receivers"].clone(), hosts, policy, phase: SharedPhase::Stopping};
            save_shared(&store, &update)?;
            update
        };
        if update.phase == SharedPhase::Stopping {
            // If the stop reply was lost, stop still requires writer release.
            update.target.verify()?;
            update.rollback.verify()?;
            if crate::runtime_startup::read(directory)? != update.policy {
                return Err(local("RUNTIME_STARTUP_POLICY_CHANGED"));
            }
            update.original.stop_for_shared_update().await?;
            update.phase = SharedPhase::Starting;
            save_shared(&store, &update)?;
        }
        if update.phase == SharedPhase::Starting {
            match update.original.launch_shared(&update.target, &update.policy).await {
                Ok(()) => {}
                Err(error) if matches!(error.code.as_str(),
                    "RUNTIME_START_FAILED" | "RUNTIME_START_FAILED_CHECK_ORIGINAL_STATE_OWNER") => {
                    update.phase = SharedPhase::RollingBack;
                    save_shared(&store, &update)?;
                }
                Err(error) => return Err(error),
            }
        }
        if update.phase == SharedPhase::RollingBack {
            update.original.launch_shared(&update.rollback, &update.policy).await?;
            let status = observation(&update.original).await?;
            verify_shared_state(&update, &status)?;
            if status["sdk_version"] != update.previous_version {
                return Err(local("UPDATE_ROLLBACK_RUNTIME_VERSION_MISMATCH"));
            }
            update.phase = SharedPhase::RolledBack;
            save_shared(&store, &update)?;
        }
        if update.phase == SharedPhase::RolledBack {
            update.original.verify_shared_launcher(&update.rollback)?;
            return Ok(json!({"state":"SHARED_RUNTIME_UPDATE_ROLLED_BACK","runtime_version":observation(&update.original).await?["sdk_version"],
                "model_wake":"NOT_ATTESTED"}));
        }
        let status = observation(&update.original).await?;
        update.original.verify_shared_launcher(&update.target)?;
        verify_shared_state(&update, &status)?;
        if status["sdk_version"] != env!("CARGO_PKG_VERSION") {
            return Err(local("UPDATE_TARGET_RUNTIME_VERSION_MISMATCH"));
        }
        let hosts = host_inventory(&update.original, Some(&status))?;
        let installations = install::update_owned(self, &handle, &update.target.executable)?;
        crate::runtime_startup::commit_maintenance_launcher(directory, &update.policy, &update.target)?;
        update.phase = SharedPhase::Complete;
        save_shared(&store, &update)?;
        Ok(json!({"state":"SHARED_RUNTIME_UPDATE_COMPLETE","runtime_version":status["sdk_version"],
            "installations":installations,"original_operations":"PRESERVED","startup_policy":"PRESERVED",
            "model_wake":"NOT_ATTESTED","continuation":continuation(self,&handle,false,&hosts)}))
    }

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
                        host_inventory(o, Some(&status))?,
                    )
                }
                Some(o) => (
                    json!({"ownership":"OWNED","state":"STOPPED","loaded_version":"NOT_RUNNING"}),
                    host_inventory(o, None)?,
                ),
                None => (external_runtime_status(self, &handle, &required).await, Vec::new()),
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
                "continuation":continuation(self,&handle,true,&[]),
                "runtime":external_runtime_status(self,&handle,&required).await,"runtime_restarted":false}),
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
        if update.phase==Phase::RuntimeReady && update.was_running && !bootstrap::owned_runtime(self,&handle)?.running()? {
            // RuntimeReady is a durable operation phase, not proof that the
            // observed process survived an interruption before target commit.
            update.phase=Phase::Starting;save(&store,&update)?;
        }
        if update.phase == Phase::Starting {
            // Persisted STARTING resumes the same launch after a failed spawn,
            // interrupted start, or lost response. Existing launch fences prevent
            // duplicate writers; never synthesize empty state or another config.
            if executable_digest(&update.executable)? != update.executable_digest {
                return Err(local("UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"));
            }
            let launcher=crate::runtime_startup::Launcher { executable:update.executable.clone(), sha256:update.executable_digest.clone() };
            update.original.restart_pinned(&update.original.config,&launcher).await?;
            let status = observation(&update.original).await?;
            if !compatible(&status, &required) {
                return Err(local("UPDATE_TARGET_MISSING_REQUIRED_FEATURE"));
            }
            update.phase = Phase::RuntimeReady;
            save(&store, &update)?;
        }
        let outputs = install::update_owned(self, &handle, &executable)?;
        let hosts = if update.was_running {
            let current = observation(&update.original).await?;
            if !compatible(&current, &required) {
                return Err(local("UPDATE_TARGET_MISSING_REQUIRED_FEATURE"));
            }
            host_inventory(&update.original, Some(&current))?
        } else {
            if bootstrap::owned_runtime(self, &handle)?.running()? {
                return Err(local("UPDATE_RUNTIME_STATE_CHANGED"));
            }
            host_inventory(&update.original, None)?
        };
        if update.was_running {crate::runtime_startup::enroll(&update.original.config.state_directory)?;}
        crate::runtime_startup::select_launcher(&update.original.config.state_directory,crate::runtime_startup::Launcher {
            executable:update.executable.clone(),sha256:update.executable_digest.clone()
        })?;
        update.phase = Phase::Complete;
        save(&store, &update)?;
        Ok(
            json!({"state":"OWNED_UPDATE_COMPLETE","participant":handle,"runtime":if update.was_running{"RUNNING_COMPATIBLE"}else{"STOPPED_PRESERVED"},
            "required_features":required,"installations":outputs,"original_operations":"PRESERVED",
            "delivery_pause":"PRESERVED","approvals":"UNCHANGED","model_wake":"NOT_ATTESTED",
            "continuation":continuation(self,&handle,false,&hosts)}),
        )
    }
}

#[cfg(test)]
#[path = "participant_connect_update_inventory_tests.rs"]
mod inventory_tests;

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
    fn update_status_does_not_create_a_missing_registry() {
        let root = crate::test_support::protected_test_dir();
        let missing = root.path().join("missing");
        let result = cli(&[
            "--local".into(),
            missing.to_str().unwrap().into(),
            "--update".into(),
            "status".into(),
        ]);
        assert_eq!(result["state"], "FAILED");
        assert_eq!(result["error"]["effect_certainty"], "NOT_SUBMITTED");
        assert!(!missing.exists());
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
            Self::with_host_inventory(false).await
        }
        async fn with_host_inventory(include_hosts: bool) -> Self {
            Self::start(include_hosts, false).await
        }
        async fn start(include_hosts: bool, compact_history: bool) -> Self {
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
            let base = include_hosts.then(|| inventory_tests::bridge(root.path(), "old"));
            if let Some(base) = &base {
                inventory_tests::overlay(&runtime, &[inventory_tests::bridge(root.path(), "replacement"), inventory_tests::bridge(root.path(), "added")], &[base.clone()]);
            }
            let config = RuntimeConfig {
                format: "peerwork.participant-runtime.v1".into(),
                state_directory: runtime.clone(),
                hosts: base.into_iter().collect(),
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
            if compact_history {
                let origin = crate::transport::canonical_lifecycle_origin(&registration.origin, true).unwrap();
                let mut history = crate::participant_store::Store::open(
                    &config.engines[0].state_directory, &identity, &origin).unwrap();
                let request = crate::participant::Invoke::new("retained-result", "structure.workspace.create",
                    crate::participant::Scope::default(), json!({"name":"Original operation"}));
                history.reserve("program:bootstrap", &request, &identity, 2, 1024 * 1024).unwrap();
                history.finish("program:bootstrap", "retained-result", &identity,
                    &json!({"state":"ACCEPTED","result":{"description":"retained result ".repeat(4096)}})).unwrap();
                history.compact_history(&identity).unwrap();
            }
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
        fn cli_shared(&self, rollback: &Path) -> Value {
            let result = Command::new(&self.binary)
                .args(["connect", "--local"]).arg(self.root.path().join("registry"))
                .args(["--participant", "peer", "--update", "apply", "--runtime-config"])
                .arg(self.config.state_directory.join("config.json"))
                .arg("--admin").arg(self.config.state_directory.join("admin.json"))
                .arg("--rollback-executable").arg(rollback)
                .output().unwrap();
            serde_json::from_slice(&result.stdout).unwrap_or_else(|_| {
                panic!("invalid shared update CLI output: {}", String::from_utf8_lossy(&result.stderr))
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
        async fn shared_connect(&self) -> Connect {
            let binding = RuntimeClient::connect(self.registration.endpoint_path.clone(),
                &self.registration.origin, &self.registration.actor_id).await.unwrap()
                .call(json!({"method":"binding"})).await.unwrap();
            let mut connect = Connect::open(&self.root.path().join("registry")).unwrap();
            connect.registry.participants.get_mut("peer").unwrap().origin =
                binding["origin"].as_str().unwrap().to_owned();
            connect.registry.verified_bindings.insert("peer".into(),
                crate::communication_runtime::canonical_binding(&binding));
            connect.save().unwrap();
            connect
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
    #[ignore = "requires the native CLI and a previous resident binary"]
    async fn update_status_reads_the_running_version_while_apply_respects_the_registry_lock() {
        let fixture = Fixture::new().await;
        let registry = fixture.root.path().join("registry");
        let writer = Connect::open(&registry).unwrap();
        let original = bootstrap::owned_runtime(&writer, "peer").unwrap();
        let before = observation(&original).await.unwrap();
        let registry_before = std::fs::read(registry.join("connect.state")).unwrap();

        let status = fixture.cli("status");
        assert_eq!(status["state"], "UPDATE_INVENTORY", "{status}");
        assert_eq!(status["runtime"]["state"], "RUNNING");
        assert_eq!(status["runtime"]["loaded_version"], before["sdk_version"]);
        assert_eq!(status["frontend_version"], env!("CARGO_PKG_VERSION"));
        assert_ne!(status["runtime"]["loaded_version"], status["frontend_version"]);
        assert!(status["operation"].is_null());

        let apply = fixture.cli("apply");
        assert_eq!(apply["state"], "FAILED");
        assert_eq!(apply["error"]["code"], "CONNECT_STATE_ALREADY_OWNED_OR_UNSAFE");
        assert_eq!(apply["error"]["details"]["local_state"]["cause"], "BUSY");
        assert_eq!(apply["error"]["effect_certainty"], "NOT_SUBMITTED");
        assert!(!registry.join("update-peer.state").exists());
        assert_eq!(std::fs::read(registry.join("connect.state")).unwrap(), registry_before);
        assert_eq!(observation(&original).await.unwrap()["sdk_version"], before["sdk_version"]);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires the native CLI and a previous resident binary"]
    async fn shared_update_rolls_back_definitive_launch_failure_and_repeats_safely() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new().await;
        let broken = fixture.root.path().join("broken-runtime");
        write_private(&broken, b"#!/bin/sh\nexit 42\n").unwrap();
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = Launcher::capture(broken).unwrap();
        let rollback = Launcher::capture(fixture.previous.clone()).unwrap();
        let directory = &fixture.config.state_directory;
        let selection = bootstrap::RuntimeSelection {
            admin_endpoint: directory.join("admin.json"), config_path: Some(directory.join("config.json")),
        };
        let original_config = std::fs::read(selection.config_path.as_ref().unwrap()).unwrap();
        let mut connect = fixture.shared_connect().await;
        for _ in 0..2 {
            let result = connect.update_shared_using(Some("peer"), &selection, target.clone(), rollback.clone()).await.unwrap();
            assert_eq!(result["state"], "SHARED_RUNTIME_UPDATE_ROLLED_BACK");
            assert_eq!(result["runtime_version"], rollback_version(&rollback).await.unwrap());
            assert_eq!(std::fs::read(selection.config_path.as_ref().unwrap()).unwrap(), original_config);
            assert!(crate::runtime_startup::read(directory).unwrap().is_none());
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires candidate, 0.3.62 live runtime, and the 0.3.60 rollback binary"]
    async fn shared_update_reconciles_stale_rollback_without_downgrading_compacted_history() {
        let mut fixture = Fixture::start(false, true).await;
        let obsolete = PathBuf::from(std::env::var_os("PEERWORK_UPDATE_OBSOLETE_BINARY").unwrap());
        let directory = &fixture.config.state_directory;
        let selection = bootstrap::RuntimeSelection {
            admin_endpoint: directory.join("admin.json"), config_path: Some(directory.join("config.json")),
        };
        let mut connect = fixture.shared_connect().await;
        let original = connect.runtime_for_source("peer", &selection).await.unwrap();
        drop(connect);
        let status = observation(&original).await.unwrap();
        assert_eq!(status["sdk_version"], "0.3.62");
        let rollback = Launcher::capture(obsolete.clone()).unwrap();
        crate::runtime_startup::enroll(directory).unwrap();
        crate::runtime_startup::select_launcher(directory, rollback.clone()).unwrap();
        let saved = SharedUpdate { original, target: Launcher::capture(fixture.previous.clone()).unwrap(),
            rollback, previous_version: "0.3.60".into(), receivers: status["receivers"].clone(),
            hosts: Vec::new(), policy: crate::runtime_startup::read(directory).unwrap(), phase: SharedPhase::RollingBack };
        let update_path = directory.join("shared-update.state");
        {
            let file = SecureStateStore::open(&update_path).unwrap();
            save_shared(&file, &saved).unwrap();
        }
        let saved_bytes = SecureStateStore::read_snapshot(&update_path, 2 * 1024 * 1024).unwrap();
        let launch_before = SecureStateStore::read_snapshot(&directory.join("bootstrap.state"), 65536).unwrap();
        let history = || {
            let db = rusqlite::Connection::open_with_flags(
                fixture.config.engines[0].state_directory.join("participant.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            db.query_row("SELECT outcome, allocation_version FROM participant_operations WHERE id='retained-result'", [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))).unwrap()
        };
        let retained = history();
        assert_eq!(retained.1, 2);
        assert!(retained.0.len() < 4096);
        let read_result = || async {
            let client = RuntimeClient::connect(fixture.registration.endpoint_path.clone(),
                &fixture.registration.origin, &fixture.registration.actor_id).await.unwrap();
            client.call(json!({"method":"operation", "operation_id":"retained-result"})).await.unwrap()
        };
        let retained_result = read_result().await;
        assert_eq!(retained_result["outcome"]["result"]["description"], "retained result ".repeat(4096));

        let rejected = fixture.cli_shared(&obsolete);
        assert_eq!(rejected["error"]["code"], "UPDATE_ROLLBACK_RUNTIME_VERSION_MISMATCH", "{rejected}");
        assert_eq!(SecureStateStore::read_snapshot(&update_path, 2 * 1024 * 1024).unwrap(), saved_bytes);

        let reconciled = fixture.cli_shared(&fixture.previous);
        assert_eq!(reconciled["state"], "SHARED_RUNTIME_UPDATE_RECONCILED", "{reconciled}");
        assert_eq!(reconciled["runtime_version"], "0.3.62");
        assert_eq!(reconciled["runtime_restarted"], false);
        assert!(fixture.child.try_wait().unwrap().is_none());
        assert_eq!(SecureStateStore::read_snapshot(&directory.join("bootstrap.state"), 65536).unwrap(), launch_before);
        assert_eq!(history(), retained);
        let reconciled_record: SharedUpdate = serde_json::from_slice(
            &SecureStateStore::read_snapshot(&update_path, 2 * 1024 * 1024).unwrap()).unwrap();
        assert!(reconciled_record.phase == SharedPhase::Reconciled);
        assert_eq!(reconciled_record.rollback, saved.rollback);
        let mut expected = saved.policy.unwrap();
        expected.launcher = Some(Launcher::capture(fixture.previous.clone()).unwrap());
        assert_eq!(crate::runtime_startup::read(directory).unwrap(), Some(expected));

        let upgraded = fixture.cli_shared(&fixture.previous);
        assert_eq!(upgraded["state"], "SHARED_RUNTIME_UPDATE_COMPLETE", "{upgraded}");
        assert_eq!(upgraded["runtime_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(history(), retained);
        assert_eq!(read_result().await, retained_result);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires the native CLI and a previous resident binary"]
    async fn shared_update_stale_launch_pin_keeps_original_runtime_running() {
        let mut fixture = Fixture::new().await;
        let directory = &fixture.config.state_directory;
        let selection = bootstrap::RuntimeSelection {
            admin_endpoint: directory.join("admin.json"), config_path: Some(directory.join("config.json")),
        };
        let pin = SecureStateStore::open(&directory.join("bootstrap.state")).unwrap();
        let mut launch: Value = serde_json::from_slice(&pin.read_exact().unwrap().unwrap()).unwrap();
        launch["config_digest"] = json!("0".repeat(64));
        pin.write_exact(&serde_json::to_vec(&launch).unwrap()).unwrap();
        drop(pin);

        let mut connect = fixture.shared_connect().await;
        let target = Launcher::capture(fixture.binary.clone()).unwrap();
        let rollback = Launcher::capture(fixture.previous.clone()).unwrap();
        for _ in 0..2 {
            let error = connect.update_shared_using(Some("peer"), &selection, target.clone(), rollback.clone()).await.unwrap_err();
            assert_eq!(error.code, "ORIGINAL_RUNTIME_CONFIG_CHANGED");
            assert_eq!(error.details.unwrap()["field"], "bootstrap.state.config_digest");
            assert!(fixture.child.try_wait().unwrap().is_none());
            let status = crate::communication_runtime::call(&selection.admin_endpoint, json!({"method":"status"})).await.unwrap();
            assert_eq!(status["ok"], true);
            assert_eq!(status["value"]["sdk_version"], rollback_version(&rollback).await.unwrap());
            let update_state = SecureStateStore::open(&directory.join("shared-update.state")).unwrap();
            assert!(update_state.read_exact().unwrap().is_none());
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires exact candidate/previous CLI artifacts and synthetic loopback IPC"]
    async fn owned_update_real_process_inventory_survives_interrupted_update_and_stop() {
        let fixture = Fixture::with_host_inventory(true).await;
        let path = fixture.config.state_directory.join("runtime-hosts.state");
        let hosts_before = SecureStateStore::read_snapshot(&path, 512 * 1024).unwrap();
        let config_before = std::fs::read(fixture.config.state_directory.join("config.json")).unwrap();
        let inspection = fixture.cli("status");
        assert_eq!(inventory_tests::names(&inspection), ["replacement", "added"]);
        let update = fixture.record(Phase::Stopping);
        update.original.stop().await.unwrap();
        let result = fixture.cli("apply");
        assert_eq!(result["state"], "OWNED_UPDATE_COMPLETE", "{result}");
        assert_eq!(inventory_tests::names(&result), ["replacement", "added"]);
        let status = observation(&update.original).await.unwrap();
        assert_eq!(status["host_configurations"].as_array().unwrap().len(), 2);
        assert_eq!(status["hosts"][0]["state"], "BLOCKED_SOURCES");
        fixture.stop().await;
        assert_eq!(inventory_tests::names(&fixture.cli("status")), ["replacement", "added"]);
        let stopped = fixture.cli("apply");
        assert_eq!(stopped["runtime"], "STOPPED_PRESERVED");
        assert_eq!(inventory_tests::names(&stopped), ["replacement", "added"]);
        assert_eq!(SecureStateStore::read_snapshot(&path, 512 * 1024).unwrap(), hosts_before);
        assert_eq!(std::fs::read(fixture.config.state_directory.join("config.json")).unwrap(), config_before);
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
