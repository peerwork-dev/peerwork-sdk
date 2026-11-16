//! Durable user intent for an already owned runtime, independent of liveness.
use crate::{participant::{ParticipantError, Result}, secure_state::SecureStateStore};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    format: String,
    pub automatic: bool,
    pub revision: u64,
    #[serde(default)]
    pub qualified: bool,
}
fn error(code: &str) -> ParticipantError { ParticipantError::local(code, "STARTUP") }
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
        Ok(_) => decode(&SecureStateStore::read_snapshot(&path, 4096)
            .map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?).map(Some),
    }
}
/// Enrollment is explicit installation work. Reinstallation never clears stop.
pub(crate) fn enroll(directory: &Path) -> Result<Policy> {
    change(directory, None)
}
fn change(directory: &Path, enabled: Option<bool>) -> Result<Policy> {
    let store = SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let old = store.read_exact().map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .map(|bytes| decode(&bytes)).transpose()?;
    let automatic = enabled.unwrap_or_else(|| old.as_ref().is_none_or(|p| p.automatic));
    if let Some(old) = &old { if old.automatic == automatic { return Ok(old.clone()); } }
    let qualified = old.as_ref().is_some_and(|p| p.qualified);
    let policy = Policy { format: "peerwork.runtime-startup.v1".into(), automatic, qualified,
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
pub(crate) fn recovery_fence(directory: &Path) -> Result<SecureStateStore> {
    SecureStateStore::open(&directory.join("startup-recovery.state"))
        .map_err(|_| error("RUNTIME_RECOVERY_ALREADY_OWNED"))
}
/// Only a runtime implementing durable stop calls this acknowledgement. A new
/// frontend must not silently arm an old runtime's unsupported stop semantics.
pub(crate) fn qualify(directory: &Path) -> Result<()> {
    let Some(policy) = read(directory)? else { return Ok(()); };
    if policy.qualified { return Ok(()); }
    let store = SecureStateStore::open(&directory.join("startup.state"))
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_BUSY"))?;
    let mut policy = decode(&store.read_exact().map_err(|_| error("RUNTIME_STARTUP_POLICY_UNAVAILABLE"))?
        .ok_or_else(|| error("RUNTIME_STARTUP_POLICY_INVALID"))?)?;
    policy.qualified = true;
    store.write_exact(&serde_json::to_vec(&policy).map_err(|_| error("RUNTIME_STARTUP_POLICY_INVALID"))?)
        .map_err(|_| error("RUNTIME_STARTUP_POLICY_WRITE_FAILED"))
}

#[cfg(test)] mod tests {
    use super::*;
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
}
