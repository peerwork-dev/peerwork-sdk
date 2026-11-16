//! Startup recovery reuses the original installation and launch fences.
use super::*;

impl Connect {
    pub(crate) fn startup_update(&self, handle: Option<&str>) -> Result<Option<(PathBuf, String, PathBuf)>> {
        let Some(handle) = self.selected_handle(handle)? else { return Ok(None); };
        Ok(update::startup_update(self, &handle)?.map(|executable| (self.directory.clone(), handle, executable)))
    }
    pub(crate) fn startup_runtime(&self, handle: Option<&str>) -> Result<Option<bootstrap::OwnedRuntime>> {
        let Some(handle) = self.selected_handle(handle)? else { return Ok(None); };
        // An installed receiving setup is the authority to auto-restore. An
        // arbitrary endpoint/profile is not an installation ownership record.
        if !self.registry.installations.values().any(|i| i.committed && i.participant == handle)
            || !self.registry.setups.values().any(|s| s.desired.participant == handle && s.desired.receive) {
            return Ok(None);
        }
        match bootstrap::owned_runtime(self, &handle) {
            Ok(runtime) => Ok(Some(runtime)),
            Err(e) if e.code == "LOCAL_RUNTIME_TAKEOVER_REQUIRED" => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub(super) fn enroll_startup(&self, handle: &str) -> Result<Value> {
        let Some(runtime) = self.startup_runtime(Some(handle))? else {
            return Ok(json!({"state":"EXTERNAL_OR_MANUAL_LIFECYCLE"}));
        };
        let directory = &runtime.config.state_directory;
        // A dead legacy runtime has no durable stop intent. Do not guess it.
        if crate::runtime_startup::read(directory)?.is_none() && !runtime.running()? {
            return Ok(json!({"state":"POLICY_REQUIRED","code":"RUNTIME_STARTUP_POLICY_REQUIRED",
                "next_action":"RESTORE_ORIGINAL_INSTALLATION_ONCE"}));
        }
        let policy = crate::runtime_startup::enroll(directory)?;
        Ok(json!({"state":if !policy.automatic {"DISABLED"} else if policy.qualified {"AUTOMATIC"} else {"VERIFYING_RUNTIME_SUPPORT"},"revision":policy.revision}))
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "participant_connect_startup_tests.rs"]
mod tests;
