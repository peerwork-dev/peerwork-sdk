//! Durable user intent for an already owned runtime, independent of liveness.
use crate::{participant::{ParticipantError, Result}, secure_state::SecureStateStore};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, io::Read};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Launcher { pub executable: PathBuf, pub sha256: String }
impl Launcher {
    pub(crate) fn capture(executable: PathBuf) -> Result<Self> {
        if !executable.is_absolute() { return Err(error("RUNTIME_STARTUP_ARTIFACT_INVALID")); }
        let mut file = std::fs::File::open(&executable).map_err(|_| error("RUNTIME_STARTUP_ARTIFACT_UNAVAILABLE"))?;
        let mut hash = Sha256::new(); let mut buffer = [0u8; 65536];
        loop { let n = file.read(&mut buffer).map_err(|_| error("RUNTIME_STARTUP_ARTIFACT_UNAVAILABLE"))?;
            if n == 0 { break; } hash.update(&buffer[..n]); }
        Ok(Self { executable, sha256:format!("{:x}",hash.finalize()) })
    }
    pub(crate) fn verify(&self) -> Result<()> {
        if Self::capture(self.executable.clone())? != *self { return Err(error("RUNTIME_STARTUP_ARTIFACT_CHANGED")); }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    format: String,
    pub automatic: bool,
    pub revision: u64,
    #[serde(default)]
    pub launcher: Option<Launcher>,
}
fn error(code: &str) -> ParticipantError { ParticipantError::local(code, "STARTUP") }

/// Hold the existing launch record across the sealed rebind's configuration
/// commit. Never enroll an external runtime or discard its pinned executable.
pub(crate) struct RebindLaunch {
    store: SecureStateStore,
    launch: serde_json::Value,
    target: String,
}
impl RebindLaunch {
    pub(crate) fn prepare(
        original: &crate::communication_runtime::RuntimeConfig,
        target: &crate::communication_runtime::RuntimeConfig,
    ) -> Result<Option<Self>> {
        if original.state_directory != target.state_directory {
            return Err(error("ORIGINAL_RUNTIME_CONFIG_CHANGED"));
        }
        let path = original.state_directory.join("bootstrap.state");
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(error("RUNTIME_LAUNCH_RECOVERY_REQUIRED")),
            Ok(_) => (),
        }
        let store = SecureStateStore::open(&path)
            .map_err(|_| error("RUNTIME_LAUNCH_ALREADY_OWNED_OR_UNSAFE"))?;
        let bytes = store.read_exact().map_err(|_| error("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?
            .ok_or_else(|| error("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
        let launch: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| error("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
        let digest = |config: &crate::communication_runtime::RuntimeConfig| {
            serde_json::to_vec(config).map(|wire| peerwork_core::crypto::sha256_hex(&wire))
                .map_err(|_| error("RUNTIME_CONFIG_INVALID"))
        };
        let target = digest(target)?;
        if launch["config_digest"] != digest(original)? && launch["config_digest"] != target {
            let mut problem = error("RUNTIME_LAUNCH_CONFIG_CONFLICT");
            problem.details = Some(serde_json::json!({"field":"bootstrap.state.config_digest",
                "next_action":"RESUME_ORIGINAL_REBIND_OR_INSPECT_ORIGINAL_INSTALLATION"}));
            return Err(problem);
        }
        Ok(Some(Self { store, launch, target }))
    }
    pub(crate) fn commit(mut self) -> Result<()> {
        if self.launch["config_digest"] == self.target { return Ok(()); }
        self.launch["config_digest"] = serde_json::json!(self.target);
        self.store.write_exact(&serde_json::to_vec(&self.launch)
            .map_err(|_| error("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?)
            .map_err(|_| error("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))
    }
}
fn decode(bytes: &[u8]) -> Result<Policy> {
    let policy: Policy = serde_json::from_slice(bytes).map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?;
    if policy.format != "peerwork.runtime-startup.v1" || policy.revision == 0 {
        return Err(error("RUNTIME_STARTUP_POLICY_INVALID"));
    }
    Ok(policy)
}
pub(crate) fn read(directory: &Path) -> Result<Option<Policy>> {
    let path = directory.join("startup.state");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(error("RUNTIME_STARTUP_POLICY_UNAVAILABLE")),
        Ok(_) => decode(&SecureStateStore::read_snapshot(&path, 65536)
            .map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?).map(Some),
    }
}
/// Enrollment is explicit installation work. Reinstallation never clears stop.
pub(crate) fn enroll(directory: &Path) -> Result<Policy> {
    let mut policy = change(directory, None)?;
    if policy.launcher.is_some() { return Ok(policy); }
    // New owned launch records pin the actual executable, before installation
    // returns. This closes the first-install crash window without a timer.
    let path = directory.join("bootstrap.state");
    if path.exists() {
        let launch: serde_json::Value = serde_json::from_slice(&SecureStateStore::read_snapshot(&path,65536)
            .map_err(|_|error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?).map_err(|_|error("RUNTIME_STARTUP_POLICY_INVALID"))?;
        if let Some(value) = launch.get("launcher").filter(|v|!v.is_null()) {
            let launcher: Launcher = serde_json::from_value(value.clone()).map_err(|_|error("RUNTIME_STARTUP_ARTIFACT_INVALID"))?;
            launcher.verify()?;
            let store = SecureStateStore::open(&directory.join("startup.state")).map_err(|_|error("RUNTIME_STARTUP_POLICY_BUSY"))?;
            policy = decode(&store.read_exact().map_err(|_|error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?.ok_or_else(||error("RUNTIME_STARTUP_POLICY_INVALID"))?)?;
            if policy.launcher.is_some() { return Ok(policy); }
            policy.launcher=Some(launcher);
            store.write_exact(&serde_json::to_vec(&policy).unwrap()).map_err(|_|error("RUNTIME_STARTUP_POLICY_WRITE_FAILED"))?;
        }
    }
    Ok(policy)
}
fn change(directory: &Path, enabled: Option<bool>) -> Result<Policy> {
    let store = SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let old = store.read_exact().map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .map(|bytes| decode(&bytes)).transpose()?;
    let automatic = enabled.unwrap_or_else(|| old.as_ref().is_none_or(|p| p.automatic));
    if let Some(old) = &old { if old.automatic == automatic { return Ok(old.clone()); } }
    let launcher = old.as_ref().and_then(|p|p.launcher.clone());
    let policy = Policy { format: "peerwork.runtime-startup.v1".into(), automatic, launcher,
        revision: old.map_or(Some(1), |p| p.revision.checked_add(1)).ok_or_else(|| error("RUNTIME_STARTUP_POLICY_INVALID"))? };
    store.write_exact(&serde_json::to_vec(&policy).map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?)
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_WRITE_FAILED"))?;
    Ok(policy)
}
/// No policy means an external/legacy lifecycle; do not enroll it on stop.
pub(crate) fn disable(directory: &Path) -> Result<()> {
    let owned = if directory.join("bootstrap.state").is_file() {
        let config: crate::communication_runtime::RuntimeConfig = serde_json::from_value(
            crate::communication_store::private_json(&directory.join("config.json"), 65536)
                .map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?)
            .map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?;
        let launch: serde_json::Value = serde_json::from_slice(&SecureStateStore::read_snapshot(
            &directory.join("bootstrap.state"), 65536).map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?)
            .map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?;
        config.state_directory == directory && launch["config_digest"] == peerwork_core::crypto::sha256_hex(
            &serde_json::to_vec(&config).map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?)
    } else { false };
    if owned || read(directory)?.is_some() { change(directory, Some(false))?; }
    Ok(())
}
/// Explicit recovery of the selected original installation, never inspection.
pub(crate) fn enable(directory: &Path) -> Result<()> {
    if read(directory)?.is_some() { change(directory, Some(true))?; }
    Ok(())
}
/// An explicit stopped-stack update commits the next artifact without enabling
/// startup or claiming that a runtime/host is live.
pub(crate) fn select_launcher(directory: &Path, launcher: Launcher) -> Result<()> {
    launcher.verify()?;
    let store=SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_|error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let mut policy=store.read_exact().map_err(|_|error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .map(|bytes|decode(&bytes)).transpose()?.unwrap_or_else(||Policy {
            format:"peerwork.runtime-startup.v1".into(),automatic:false,revision:1,launcher:None,
        });
    policy.launcher=Some(launcher);
    store.write_exact(&serde_json::to_vec(&policy).unwrap()).map_err(|_|error("RUNTIME_STARTUP_POLICY_WRITE_FAILED"))
}
/// Hold only across the synchronous spawn/record transition. User stop can
/// proceed during endpoint readiness/network waits, and wins before next spawn.
pub(crate) fn launch_guard(directory: &Path) -> Result<Option<SecureStateStore>> {
    if read(directory)?.is_none() { return Ok(None); }
    let store = SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let policy = store.read_exact().map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .ok_or_else(|| error("RUNTIME_STARTUP_POLICY_INVALID"))?;
    if !decode(&policy)?.automatic { return Err(error("RUNTIME_AUTOMATIC_START_DISABLED")); }
    Ok(Some(store))
}
/// Serialize an explicitly authorized maintenance start with user intent.
pub(crate) fn maintenance_launch_guard(directory: &Path, expected: &Option<Policy>) -> Result<SecureStateStore> {
    let store = SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let current = store.read_exact().map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .as_deref().map(decode).transpose()?;
    if &current != expected {
        return Err(error("RUNTIME_STARTUP_POLICY_CHANGED"));
    }
    Ok(store)
}
pub(crate) fn commit_maintenance_launcher(directory: &Path, expected: &Option<Policy>, launcher: &Launcher) -> Result<()> {
    let Some(original) = expected else { return Ok(()); };
    let store = SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let active = store.read_exact().map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .as_deref().map(decode).transpose()?;
    let mut next = original.clone();
    next.launcher = Some(launcher.clone());
    if active.as_ref() == Some(&next) {
        return Ok(());
    }
    if active != *expected {
        return Err(error("RUNTIME_STARTUP_POLICY_CHANGED"));
    }
    store.write_exact(&serde_json::to_vec(&next).map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?)
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_WRITE_FAILED"))
}
pub(crate) fn recovery_fence(directory: &Path) -> Result<SecureStateStore> {
    SecureStateStore::open(&directory.join("startup-recovery.state"))
        .map_err(|_| error("RUNTIME_RECOVERY_ALREADY_OWNED"))
}

#[cfg(test)] mod tests {
    use super::*;
    use crate::communication_runtime::RuntimeConfig;
    use serde_json::json;
    fn rebind_configs(directory: &Path) -> (RuntimeConfig, RuntimeConfig) {
        let original=RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:directory.into(),
            engines:vec![],clients:vec![],hosts:vec![]};
        let mut target=original.clone();
        target.hosts.push(crate::participant_dispatch::HostConfig{name:"selected".into(),
            adapter:json!({"kind":"opencode","session_id":"ses_original"}),subscriptions:vec![]});
        (original,target)
    }
    #[test]
    fn sealed_rebind_updates_launch_digest_and_preserves_artifact_and_stop_intent() {
        let root=crate::test_support::protected_test_dir();let (original,target)=rebind_configs(root.path());
        let launch=json!({"config_digest":peerwork_core::crypto::sha256_hex(&serde_json::to_vec(&original).unwrap()),
            "pid":123,"process_token":"original-token","launcher":{"executable":"/original/peerwork","sha256":"a".repeat(64)}});
        let store=SecureStateStore::open(&root.path().join("bootstrap.state")).unwrap();
        store.write_exact(&serde_json::to_vec(&launch).unwrap()).unwrap();drop(store);
        change(root.path(),Some(false)).unwrap();let policy=read(root.path()).unwrap();
        // Dropping before commit models interruption before configuration commit.
        drop(RebindLaunch::prepare(&original,&target).unwrap());
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&SecureStateStore::read_snapshot(&root.path().join("bootstrap.state"),65536).unwrap()).unwrap(),launch);
        RebindLaunch::prepare(&original,&target).unwrap().unwrap().commit().unwrap();
        let observed:serde_json::Value=serde_json::from_slice(&SecureStateStore::read_snapshot(&root.path().join("bootstrap.state"),65536).unwrap()).unwrap();
        assert_eq!(observed["config_digest"],peerwork_core::crypto::sha256_hex(&serde_json::to_vec(&target).unwrap()));
        for field in ["pid","process_token","launcher"]{assert_eq!(observed[field],launch[field]);}
        let bytes=SecureStateStore::read_snapshot(&root.path().join("bootstrap.state"),65536).unwrap();
        RebindLaunch::prepare(&original,&target).unwrap().unwrap().commit().unwrap();
        assert_eq!(SecureStateStore::read_snapshot(&root.path().join("bootstrap.state"),65536).unwrap(),bytes);
        assert_eq!(read(root.path()).unwrap(),policy);
    }
    #[test]
    fn sealed_rebind_rejects_unrelated_launch_and_does_not_enroll_external_runtime() {
        let root=crate::test_support::protected_test_dir();let (original,target)=rebind_configs(root.path());
        assert!(RebindLaunch::prepare(&original,&target).unwrap().is_none());
        assert!(!root.path().join("bootstrap.state").exists());assert!(read(root.path()).unwrap().is_none());
        let marker=root.path().join("bootstrap.state");let store=SecureStateStore::open(&marker).unwrap();
        let bytes=serde_json::to_vec(&json!({"config_digest":"unrelated"})).unwrap();store.write_exact(&bytes).unwrap();drop(store);
        let error=RebindLaunch::prepare(&original,&target).err().unwrap();
        assert_eq!(error.code,"RUNTIME_LAUNCH_CONFIG_CONFLICT");assert_eq!(error.details.unwrap()["field"],"bootstrap.state.config_digest");
        assert_eq!(SecureStateStore::read_snapshot(&marker,65536).unwrap(),bytes);
    }
    #[test] fn enrollment_is_idempotent_and_preserves_explicit_stop() {
        let root = crate::test_support::protected_test_dir();
        assert!(read(root.path()).unwrap().is_none());
        disable(root.path()).unwrap();
        assert!(read(root.path()).unwrap().is_none());
        assert_eq!(enroll(root.path()).unwrap().revision, 1);
        disable(root.path()).unwrap();
        let stopped = enroll(root.path()).unwrap();
        assert!(!stopped.automatic); assert_eq!(stopped.revision, 2);
        assert_eq!(launch_guard(root.path()).err().unwrap().code, "RUNTIME_AUTOMATIC_START_DISABLED");
        enable(root.path()).unwrap();
        assert_eq!(read(root.path()).unwrap().unwrap().revision, 3);
    }
    #[test] fn stop_and_spawn_share_a_short_exclusive_intent_fence() {
        let root = crate::test_support::protected_test_dir(); enroll(root.path()).unwrap();
        let guard = launch_guard(root.path()).unwrap();
        assert_eq!(disable(root.path()).unwrap_err().code, "RUNTIME_STARTUP_POLICY_BUSY");
        drop(guard); disable(root.path()).unwrap();
        assert!(!read(root.path()).unwrap().unwrap().automatic);
    }
    #[test] fn target_commit_preserves_the_latest_user_intent() {
        let root = crate::test_support::protected_test_dir();
        let pending = enroll(root.path()).unwrap(); assert!(pending.launcher.is_none());
        let artifact=root.path().join("artifact"); std::fs::write(&artifact,b"synthetic target").unwrap();
        disable(root.path()).unwrap(); select_launcher(root.path(),Launcher::capture(artifact).unwrap()).unwrap();
        let stopped = read(root.path()).unwrap().unwrap();
        assert!(stopped.launcher.is_some()); assert!(!stopped.automatic);
        assert_eq!(stopped.revision, 2);
        assert!(!enroll(root.path()).unwrap().automatic);
    }
}
