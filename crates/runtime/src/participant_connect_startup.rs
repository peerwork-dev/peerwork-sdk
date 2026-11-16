//! Startup recovery reuses the original installation and launch fences.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger { Automatic, Resume, Adopt }
fn observation(state:&str,code:&str)->Value {json!({"state":state,"code":code,"model_wake":"NOT_ATTESTED"})}
fn original(connect:&Connect,handle:&str,trigger:Trigger)->Result<Option<bootstrap::OwnedRuntime>> {
    if trigger==Trigger::Automatic {return connect.startup_runtime(Some(handle));}
    match bootstrap::owned_runtime(connect,handle) {
        Ok(runtime)=>Ok(Some(runtime)),
        Err(error) if error.code=="LOCAL_RUNTIME_TAKEOVER_REQUIRED"=>Ok(None),
        Err(error)=>Err(error),
    }
}
/// The single ordinary recovery interpreter. Callers must release the registry
/// writer before entering; the updater reacquires its original operation locks.
/// Maintenance executors use the lower-level launch primitives, never recurse.
pub(crate) async fn recover(directory:&Path,handle:Option<&str>,trigger:Trigger)->Result<Value> {
    let mut connect=Connect::inspect(directory)?;
    let Some(handle)=connect.selected_handle(handle)? else {return Ok(observation("NOT_CONFIGURED","LOCAL_SELECTION_REQUIRED"));};
    let Some(runtime)=original(&connect,&handle,trigger)? else {return Ok(observation("NOT_MANAGED","EXTERNAL_OR_MANUAL_LIFECYCLE"));};
    if trigger==Trigger::Resume {
        crate::runtime_startup::enroll(&runtime.config.state_directory)?;
        crate::runtime_startup::enable(&runtime.config.state_directory)?;
    } else if crate::runtime_startup::read(&runtime.config.state_directory)?.is_some_and(|p|!p.automatic) {
        return Ok(observation("DISABLED","USER_DISABLED_AUTOMATIC_START"));
    }
    if let Some((registry,participant,executable))=connect.startup_update(Some(&handle))? {
        let mut command=tokio::process::Command::new(executable);
        command.arg("connect").arg("--local").arg(registry).arg("--participant").arg(participant)
            .args(["--update","apply"]).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true);
        let output=tokio::time::timeout(std::time::Duration::from_secs(90),command.output()).await
            .map_err(|_|local("ORIGINAL_UPDATE_RECOVERY_TIMEOUT"))?.map_err(|_|local("UPDATE_EXECUTABLE_UNAVAILABLE"))?;
        let result:Value=serde_json::from_slice(&output.stdout).map_err(|_|local("UPDATE_STATE_INVALID"))?;
        if result["state"]!="OWNED_UPDATE_COMPLETE" {
            return Err(serde_json::from_value(result["error"].clone()).unwrap_or_else(|_|local("ORIGINAL_UPDATE_NOT_COMPLETE")));
        }
        connect=Connect::inspect(directory)?;
    }
    let runtime=original(&connect,&handle,trigger)?.ok_or_else(||local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
    let policy=crate::runtime_startup::read(&runtime.config.state_directory)?;
    if policy.as_ref().is_some_and(|p|!p.automatic) {return Ok(observation("DISABLED","USER_DISABLED_AUTOMATIC_START"));}
    if trigger==Trigger::Automatic && policy.as_ref().and_then(|p|p.launcher.as_ref()).is_none() {
        return Err(local("RUNTIME_STARTUP_SUPPORT_UNCONFIRMED_UPDATE_ORIGINAL_RUNTIME"));
    }
    if runtime.running()? {return Ok(observation("RUNTIME_RUNNING","CHECK_CURRENT_DELIVERY_FOR_HOST_READINESS"));}
    let _maintenance=crate::runtime_startup::recovery_fence(&runtime.config.state_directory)?;
    // A concurrent maintenance operation may have committed while acquiring the
    // fence. Reinterpret the latest operation, target and intent before launch.
    let current=Connect::inspect(directory)?;
    if current.startup_update(Some(&handle))?.is_some() {return Err(local("ORIGINAL_UPDATE_RECOVERY_REQUIRED"));}
    let runtime=original(&current,&handle,trigger)?.ok_or_else(||local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
    let policy=crate::runtime_startup::read(&runtime.config.state_directory)?;
    if policy.as_ref().is_some_and(|p|!p.automatic) {return Ok(observation("DISABLED","USER_DISABLED_AUTOMATIC_START"));}
    match policy.as_ref().and_then(|p|p.launcher.as_ref()) {
        Some(launcher)=>runtime.restart_pinned(&runtime.config,launcher).await?,
        None if trigger==Trigger::Automatic=>return Err(local("RUNTIME_STARTUP_SUPPORT_UNCONFIRMED_UPDATE_ORIGINAL_RUNTIME")),
        None=>runtime.upgrade_current(&runtime.config).await?,
    }
    if current.startup_runtime(Some(&handle))?.is_some() || policy.is_some() {
        crate::runtime_startup::enroll(&runtime.config.state_directory)?;
    }
    Ok(observation("RUNTIME_RUNNING","CHECK_CURRENT_DELIVERY_FOR_HOST_READINESS"))
}

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
        Ok(json!({"state":if !policy.automatic {"DISABLED"} else if policy.launcher.is_some() {"AUTOMATIC"} else {"VERIFYING_RUNTIME_SUPPORT"},"revision":policy.revision}))
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "participant_connect_startup_tests.rs"]
mod tests;
