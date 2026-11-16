//! One recovery task per original runtime; no model call or remote health poll.
use super::*;
use std::{path::PathBuf, time::Duration};

#[derive(Default)]
pub(super) struct State(std::sync::Mutex<(Value, bool)>);
impl State {
    pub(super) fn peek(&self) -> Option<Value> {
        let current=self.0.lock().expect("startup observation lock");
        (!current.0.is_null()).then(||current.0.clone())
    }
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
    fn startup_selection(&self) -> Result<Option<(PathBuf,Option<String>)>> {
        if let Some(directory)=&self.local {return Ok(Some((directory.clone(),self.handle.clone())));}
        if let Some(profile)=&self.profile {
            if let Some((directory,_connect,handle))=self.source_selection(profile)? {return Ok(Some((directory,Some(handle))));}
        }
        Ok(None)
    }
    /// MCP owns only this observer task. The shared interpreter owns recovery.
    pub(crate) async fn recover_startup(self: Arc<Self>) {
        if self.local.is_none() && self.profile.is_none() {
            self.startup.set("NOT_MANAGED","EXTERNAL_OR_MANUAL_LIFECYCLE");return;
        }
        let mut attempt=0u32;
        loop {
            let outcome:Result<Value>=async {
                let Some((directory,handle))=self.startup_selection()? else {
                    return Ok(json!({"state":"NOT_MANAGED","code":"EXTERNAL_OR_MANUAL_LIFECYCLE"}));
                };
                crate::participant_connect::startup::recover(&directory,handle.as_deref(),crate::participant_connect::startup::Trigger::Automatic).await
            }.await;
            let mut delay=Duration::from_secs(3);
            match outcome {
                Ok(value)=>{
                    attempt=0;
                    self.startup.set(value["state"].as_str().unwrap_or("UNKNOWN"),value["code"].as_str().unwrap_or("OBSERVATION_UNAVAILABLE"));
                },
                Err(error)=>{
                    attempt=attempt.saturating_add(1);
                    let blocked=matches!(error.code.as_str(),"ORIGINAL_RUNTIME_CONFIG_CHANGED"|"LOCAL_BINDING_CONFLICT"|
                        "ORIGINAL_RUNTIME_BINDING_CHANGED"|"RUNTIME_STARTUP_POLICY_INVALID"|"RUNTIME_CONFIG_INVALID"|"RUNTIME_CONFIG_NOT_PRIVATE"|
                        "UPDATE_RESUME_ORIGINAL_ARTIFACT_AND_SELECTION"|"UPDATE_STATE_INVALID"|"UPDATE_RUNTIME_UPGRADE_REQUIRED"|
                        "RUNTIME_STARTUP_ARTIFACT_CHANGED"|"RUNTIME_STARTUP_ARTIFACT_INVALID"|"ORIGINAL_PROFILE_SOURCE_CHANGED"|
                        "CLIENT_IDENTITY_OR_ORIGIN_MISMATCH"|"RUNTIME_STARTUP_SUPPORT_UNCONFIRMED_UPDATE_ORIGINAL_RUNTIME");
                    self.startup.set(if blocked{"BLOCKED"}else{"RECOVERING"},&error.code);
                    delay=if blocked{Duration::from_secs(60)}else{crate::host_recovery_policy::delay(&error.code,attempt,"original-runtime-startup")};
                },
            }
            tokio::time::sleep(delay).await;
        }
    }
    pub(super) async fn resume_startup(&self) -> Result<()> {
        if let Some((directory,handle))=self.startup_selection()? {
            let value=crate::participant_connect::startup::recover(&directory,handle.as_deref(),crate::participant_connect::startup::Trigger::Resume).await?;
            self.startup.set(value["state"].as_str().unwrap_or("UNKNOWN"),value["code"].as_str().unwrap_or("OBSERVATION_UNAVAILABLE"));
        }
        Ok(())
    }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn persistent_failure_has_one_notice_without_repeated_probes_or_context_growth() {
        let state = State::default();
        state.set("BLOCKED", "RUNTIME_STARTUP_POLICY_REQUIRED");
        assert!(state.snapshot(false).is_some());
        for _ in 0..100 {
            state.set("BLOCKED", "RUNTIME_STARTUP_POLICY_REQUIRED");
            assert!(state.snapshot(false).is_none());
        }
        assert_eq!(state.snapshot(true).unwrap()["state"], "BLOCKED");
        state.set("RUNTIME_RUNNING", "CHECK_CURRENT_DELIVERY_FOR_HOST_READINESS");
        assert_eq!(state.snapshot(false).unwrap()["model_wake"], "NOT_ATTESTED");
        assert!(state.snapshot(false).is_none());
    }
}
