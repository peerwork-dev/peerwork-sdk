//! One recovery task per original runtime; no model call or remote health poll.
use super::*;
use crate::secure_state::SecureStateStore;
use std::{path::PathBuf, time::Duration};

#[derive(Default)]
pub(super) struct State(std::sync::Mutex<(Value, bool)>);
impl State {
    fn set(&self, state: &str, code: &str) {
        let value = json!({"state":state,"code":code,"model_wake":"NOT_ATTESTED"});
        let mut current = self.0.lock().expect("startup observation lock");
        if current.0 != value {
            eprintln!("Peerwork startup: {state} / {code}");
            *current = (value, !matches!(state, "NOT_MANAGED" | "NOT_CONFIGURED"));
        }
    }
    pub(super) fn snapshot(&self, always: bool) -> Option<Value> {
        let mut current = self.0.lock().expect("startup observation lock");
        if current.0.is_null() || !always && !current.1 { return None; }
        current.1 = false;
        Some(current.0.clone())
    }
}

impl Lifecycle {
    fn startup_update(&self) -> Result<Option<(PathBuf, String, PathBuf)>> {
        if let Some(directory) = &self.local {
            return crate::participant_connect::Connect::inspect(directory)?.startup_update(self.handle.as_deref());
        }
        if let Some(profile) = &self.profile {
            if let Some((_directory, connect, handle)) = self.source_selection(profile)? {
                return connect.startup_update(Some(&handle));
            }
        }
        Ok(None)
    }
    fn startup_runtime(&self) -> Result<Option<crate::participant_connect::bootstrap::OwnedRuntime>> {
        if let Some(directory) = &self.local {
            return crate::participant_connect::Connect::inspect(directory)?.startup_runtime(self.handle.as_deref());
        }
        if let Some(profile) = &self.profile {
            if let Some((_directory, connect, handle)) = self.source_selection(profile)? {
                return connect.startup_runtime(Some(&handle));
            }
        }
        Ok(None)
    }
    /// Embedded clients retain their application's lifecycle ownership.
    pub(crate) async fn recover_startup(self: Arc<Self>) {
        let mut leader: Option<(PathBuf, SecureStateStore)> = None;
        let mut attempt = 0u32;
        loop {
            let mut delay = Duration::from_secs(3);
            let outcome: Result<()> = async {
                let Some(runtime) = self.startup_runtime()? else {
                    leader = None;
                    self.startup.set("NOT_MANAGED", "EXTERNAL_OR_MANUAL_LIFECYCLE");
                    return Ok(());
                };
                let directory = &runtime.config.state_directory;
                if leader.as_ref().is_some_and(|(old, _)| old != directory) { leader = None; }
                let policy = crate::runtime_startup::read(directory)?;
                if policy.as_ref().is_some_and(|p| !p.automatic) {
                    self.startup.set("DISABLED", "USER_DISABLED_AUTOMATIC_START");
                    return Ok(());
                }
                if let Some((registry, handle, executable)) = self.startup_update()? {
                    self.startup.set("RECOVERING", "RESUMING_ORIGINAL_UPDATE");
                    let output = tokio::process::Command::new(executable)
                        .arg("connect").arg("--local").arg(registry)
                        .arg("--participant").arg(handle).args(["--update", "apply"])
                        .stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                        .output().await.map_err(|_| ParticipantError::local("UPDATE_EXECUTABLE_UNAVAILABLE", "STARTUP"))?;
                    let result: Value = serde_json::from_slice(&output.stdout)
                        .map_err(|_| ParticipantError::local("UPDATE_STATE_INVALID", "STARTUP"))?;
                    if result["state"] != "OWNED_UPDATE_COMPLETE" {
                        return Err(ParticipantError::local("ORIGINAL_UPDATE_NOT_COMPLETE", "STARTUP"));
                    }
                    return Ok(());
                }
                let Some(policy) = policy else {
                    self.startup.set("BLOCKED", "RUNTIME_STARTUP_POLICY_REQUIRED");
                    delay = Duration::from_secs(30);
                    return Ok(());
                };
                if !policy.qualified {
                    self.startup.set("BLOCKED", "RUNTIME_STARTUP_SUPPORT_UNCONFIRMED_UPDATE_ORIGINAL_RUNTIME");
                    return Ok(());
                }
                if runtime.running()? {
                    attempt = 0;
                    self.startup.set("RUNTIME_RUNNING", "CHECK_CURRENT_DELIVERY_FOR_HOST_READINESS");
                    return Ok(());
                }
                if leader.is_none() {
                    match SecureStateStore::open(&directory.join("startup-recovery.state")) {
                        Ok(fence) => leader = Some((directory.clone(), fence)),
                        Err(crate::secure_state::SecureStateError::Busy) => {
                            self.startup.set("RECOVERING", "ORIGINAL_RECOVERY_ALREADY_OWNED");
                            return Ok(());
                        }
                        Err(_) => return Err(ParticipantError::local("RUNTIME_RECOVERY_FENCE_UNAVAILABLE", "STARTUP")),
                    }
                }
                if attempt == 0 { self.startup.set("RECOVERING", "RESTORING_ORIGINAL_RUNTIME"); }
                runtime.restart(&runtime.config).await?;
                self.startup.set("RUNTIME_RUNNING", "CHECK_CURRENT_DELIVERY_FOR_HOST_READINESS");
                Ok(())
            }.await;
            leader = None;
            if let Err(error) = outcome {
                attempt = attempt.saturating_add(1);
                let blocked = matches!(error.code.as_str(),
                    "ORIGINAL_RUNTIME_CONFIG_CHANGED" | "LOCAL_BINDING_CONFLICT" |
                    "ORIGINAL_RUNTIME_BINDING_CHANGED" | "RUNTIME_STARTUP_POLICY_INVALID" |
                    "RUNTIME_CONFIG_INVALID" | "RUNTIME_CONFIG_NOT_PRIVATE" |
                    "UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION" | "UPDATE_STATE_INVALID" |
                    "ORIGINAL_PROFILE_SOURCE_CHANGED" | "CLIENT_IDENTITY_OR_ORIGIN_MISMATCH");
                self.startup.set(if blocked { "BLOCKED" } else { "RECOVERING" }, &error.code);
                delay = if blocked { Duration::from_secs(60) } else {
                    crate::host_recovery_policy::delay(&error.code, attempt, "original-runtime-startup")
                };
            }
            tokio::time::sleep(delay).await;
        }
    }
    pub(super) async fn resume_startup(&self) -> Result<()> {
        if let Some(runtime) = self.startup_runtime()? {
            crate::runtime_startup::enroll(&runtime.config.state_directory)?;
            crate::runtime_startup::enable(&runtime.config.state_directory)?;
            if !runtime.running()? { runtime.restart(&runtime.config).await?; }
        }
        Ok(())
    }
}
