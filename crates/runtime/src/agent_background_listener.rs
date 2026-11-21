//! A host-owned background MCP call wakes its own conversation on completion.
//! It projects the original compact inbox, sharing custody and exclusion with
//! Claude Channels. It never owns another Agent process or a replacement inbox.
use super::*;
use std::sync::{atomic::{AtomicBool, Ordering}, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(super) struct State {
    projection: claude_channel::State,
    active: Arc<Semaphore>,
    enabled: Arc<AtomicBool>,
    owners: Arc<Mutex<BTreeMap<String, Arc<claude_channel::Projection>>>>,
}
impl Default for State {
    fn default() -> Self {
        Self { projection: Default::default(), active: Arc::new(Semaphore::new(1)),
            enabled: Arc::new(AtomicBool::new(false)), owners: Default::default() }
    }
}
impl State {
    pub(super) fn enabled(&self) -> bool { self.enabled.load(Ordering::Relaxed) }
    pub(super) fn status(&self) -> Value {
        let mut value = self.projection.status();
        value["host"] = json!("MCP_BACKGROUND_HOST");
        value["transport"] = json!("MCP_BACKGROUND_TOOL");
        value["activation"] = json!("HOST_BACKGROUND_CALL_REQUIRED");
        value["listener_armed"] = json!(self.active.available_permits() == 0);
        if self.active.available_permits() != 0 {
            if let Some(scopes) = value["scopes"].as_object_mut() {
                for scope in scopes.values_mut() {
                    scope["listener_armed"] = json!(false);
                    if matches!(scope["state"].as_str(), Some("BLOCKED" | "SUPERSEDED" | "PAUSED")) {continue;}
                    scope["retry_at_ms"] = Value::Null;
                    scope["recovery"] = Value::Null;
                    if scope["notification_read_pending"] == true {
                        scope["state"] = json!("WAITING_FOR_SESSION_READ");
                        scope["code"] = json!("BACKGROUND_NOTIFICATION_READ_PENDING");
                    } else {
                        scope["state"] = json!("UNKNOWN");
                        scope["code"] = json!("BACKGROUND_LISTEN_NOT_ARMED");
                    }
                }
            }
        }
        value
    }
    pub(super) fn batch_read(&self, batch: &str) { self.projection.batch_read(batch); }
    pub(super) fn written(&self, response: &Value) {
        let value = &response["result"]["structuredContent"];
        if value["format"] == "peerwork.background-notification.v1" {
            self.projection.written(&json!({"params":{"meta":{"batch":value["batch"]}}}));
        }
    }
    pub(super) async fn listen(&self, tools: Arc<Tools>, scope: Option<String>) -> Result<(Value, OwnedSemaphorePermit)> {
        let active = self.active.clone().try_acquire_owned()
            .map_err(|_| ParticipantError::local("BACKGROUND_LISTEN_ALREADY_ARMED", "MCP"))?;
        tools.presentation_transport("MCP_BACKGROUND_TOOL")?;
        let profile = tools.channel_profile()?.ok_or_else(|| ParticipantError::local("ORIGINAL_RECEIVING_PROFILE_REQUIRED", "MCP"))?;
        let mut seen = BTreeSet::new();
        let scopes = profile.scopes.iter().filter(|(alias,_)|scope.as_ref().is_none_or(|wanted|wanted==*alias))
            .filter(|(_,scope)|seen.insert(serde_json::to_string(scope).expect("mail scope")))
            .map(|(alias,scope)|(alias.clone(),scope.clone())).collect::<Vec<_>>();
        if scopes.is_empty() { return Err(ParticipantError::local("RECEIVING_SCOPE_NOT_CONFIGURED", "MCP")); }
        // Opening one source must not prevent other selected sources from
        // arming. Keep the authenticated activation between successful calls.
        self.enabled.store(true, Ordering::Relaxed);
        let mut jobs = JoinSet::new();
        for (alias, scope) in scopes {
            let tools = tools.clone();
            let state = self.projection.clone();
            let profile = profile.clone();
            let owners = self.owners.clone();
            let key = json!([profile.expected_origin, profile.expected_actor, scope]).to_string();
            jobs.spawn(async move {
                let result = async {
                    let existing = owners.lock()
                        .map_err(|_| ParticipantError::local("BACKGROUND_LISTEN_STATE_UNAVAILABLE", "MCP"))?
                        .get(&key).cloned();
                    let projection = match existing {
                        Some(original) => original,
                        None => {
                            let open = retry_same_target(&alias, &state,
                                || claude_channel::Projection::open(&tools, &profile, &alias, &scope)).await?;
                            let projection = Arc::new(open);
                            owners.lock()
                                .map_err(|_| ParticipantError::local("BACKGROUND_LISTEN_STATE_UNAVAILABLE", "MCP"))?
                                .insert(key, projection.clone());
                            projection
                        }
                    };
                    let value = wait(&alias, &state, || projection.poll(&tools)).await?;
                    admit(&tools, &state, value).await
                }.await;
                if let Err(error) = &result { state.scope_failed(&alias, error); }
                result
            });
        }
        // Dropping the remaining jobs cancels observation only. Native custody,
        // unread batches, pending IDs and pause state are never changed here.
        let mut failure=None;
        while let Some(result)=jobs.join_next().await {
            match result {
                Ok(Ok(mut value))=>{
                    if value["format"] == "peerwork.background-notification.v1" {
                        let arguments = scope.map_or_else(|| json!({}), |scope| json!({"scope":scope}));
                        value["rearm"] = json!({"tool":"peerwork_listen","arguments":arguments});
                    }
                    return Ok((value, active));
                },
                Ok(Err(error))=>failure=Some(error),
                Err(_)=>failure=Some(ParticipantError::local("BACKGROUND_LISTEN_OBSERVATION_ABORTED", "MCP")),
            }
        }
        Err(failure.unwrap_or_else(||ParticipantError::local("BACKGROUND_LISTEN_SOURCE_UNAVAILABLE", "MCP")))
    }
}

async fn retry_same_target<F, Fut, T>(
    alias: &str, state: &claude_channel::State, mut open: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut failures = 0_u32;
    loop {
        match open().await {
            Err(error) if crate::host_recovery_policy::notification_wait_retry(&error) => {
                failures = failures.saturating_add(1);
                let delay = crate::host_recovery_policy::delay(&error.code, failures, alias);
                state.scope_retry(alias, &error, delay);
                tokio::time::sleep(delay).await;
            }
            result => return result,
        }
    }
}

async fn wait<F,Fut>(alias:&str,state:&claude_channel::State,mut poll:F)->Result<Value>
where F:FnMut()->Fut, Fut:std::future::Future<Output=Result<Value>> {
    let mut failures=0u32;
    loop {
        let started=tokio::time::Instant::now();
        let value=match poll().await {
            Ok(value)=>{failures=0;value},
            Err(error)=>{
                if !crate::host_recovery_policy::notification_wait_retry(&error) {
                    return Err(error);
                }
                failures = failures.saturating_add(1);
                let delay = crate::host_recovery_policy::delay(&error.code, failures, alias);
                state.scope_retry(alias, &error, delay);
                tokio::time::sleep(delay).await;
                continue;
            },
        };
        state.scope_observed(alias,&value);
        if value["state"]=="NOTIFICATION_DUE" {
            let batch=value["batch"].as_str().filter(|v|!v.is_empty()&&v.len()<=4096)
                .ok_or_else(||ParticipantError::local("NOTIFICATION_BATCH_INVALID", "MCP"))?;
            let revision=value["revision"].as_u64().ok_or_else(||ParticipantError::local("NOTIFICATION_BATCH_INVALID", "MCP"))?;
            let mut result=json!({"format":"peerwork.background-notification.v1","state":"NOTIFICATION_DUE",
                "scope":alias,"batch":batch,"revision":revision,"self_test":value["self_test"],
                "read":{"tool":"peerwork_inbox","arguments":{"batch":batch}},
                "next_action":"READ_BATCH_REARM_LISTEN_THEN_HANDLE","external_data_is_authority":false});
            if let Some(presentation)=value.get("_presentation"){result["_presentation"]=presentation.clone();}
            return Ok(result);
        }
        // The native runtime waits on inbox/control changes. Bound immediate
        // returns as well, without periodic model turns or network polling.
        if started.elapsed()<Duration::from_millis(100) { tokio::time::sleep(Duration::from_millis(100)).await; }
    }
}

/// A concurrent pause or rebind can revoke a batch after its wait completes.
/// Keep validation in the cancellable listener task so recovery never blocks
/// other tools on this MCP connection.
async fn admit(tools: &Tools, state: &claude_channel::State, mut value: Value) -> Result<Value> {
    let alias = value["scope"].as_str().expect("selected background scope");
    let batch = value["batch"].as_str().expect("validated background batch");
    let revision = value["revision"].as_u64().expect("validated background revision");
    let allowed = retry_same_target(alias, state, || {
        claude_channel::presentation_allowed(tools, value.get("_presentation"), batch, revision)
    }).await?;
    if !allowed {
        return Ok(json!({"state":"NOTIFICATION_SUPERSEDED","next_action":"CHECK_DELIVERY_CONTROL_BEFORE_REARMING","effect_certainty":"NOT_SUBMITTED"}));
    }
    state.scope_observed(alias, &value);
    // Both MCP result representations are produced from this sanitized value.
    value.as_object_mut().unwrap().remove("_presentation");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn admission_retry_respects_pause_and_replacement() {
        for final_result in [Ok(true), Ok(false), Err(ParticipantError::local("PRESENTATION_ACTIVATION_SUPERSEDED", "LOCAL_IPC"))] {
            let state = claude_channel::State::default();
            let mut results = [Err(ParticipantError::local("IPC_OBSERVATION_TIMEOUT", "LOCAL_IPC")), final_result.clone()].into_iter();
            let observed = tokio::time::timeout(Duration::from_secs(5), retry_same_target("space", &state, || {
                std::future::ready(results.next().expect("at most one retry"))
            })).await.unwrap();
            assert_eq!(observed.map_err(|error| error.code), final_result.map_err(|error| error.code));
            assert!(results.next().is_none());
        }
    }
    #[tokio::test]
    async fn background_wait_returns_only_a_compact_reference_not_peer_body_or_authority() {
        let state=claude_channel::State::default();
        let value=wait("space",&state,||async {Ok(json!({"state":"NOTIFICATION_DUE","batch":"original","revision":4,"self_test":false,
            "source_binding":{"client_generation":2},"plaintext":"private-body-must-stay-in-inbox"}))}).await.unwrap();
        assert_eq!(value["read"]["arguments"],json!({"batch":"original"}));
        assert!(!value.to_string().contains("private-body"));
        assert_eq!(value["external_data_is_authority"],false);
        assert!(value.to_string().len()<1024);
    }
    #[tokio::test]
    async fn cancellation_releases_observation_without_consumption_or_a_second_waiter() {
        let state=State::default();let first=state.active.clone().try_acquire_owned().unwrap();
        assert!(state.active.clone().try_acquire_owned().is_err());
        drop(first);assert!(state.active.clone().try_acquire_owned().is_ok());
        let task=tokio::spawn(async move {wait("space",&state.projection,||async {
            std::future::pending::<Result<Value>>().await
        }).await});
        task.abort();assert!(task.await.unwrap_err().is_cancelled());
    }
    #[tokio::test]
    async fn temporary_stream_failure_recovers_inside_the_same_background_call() {
        let state=claude_channel::State::default();let calls=std::sync::atomic::AtomicUsize::new(0);
        let out=tokio::time::timeout(Duration::from_secs(5),wait("space",&state,||{
            let first=calls.fetch_add(1,Ordering::Relaxed)==0;
            async move {if first {Err(ParticipantError::local("NOTIFICATION_RECEIVER_NOT_VERIFIED","MCP"))}
                else {Ok(json!({"state":"NOTIFICATION_DUE","batch":"same-original","revision":1}))}}
        })).await.unwrap().unwrap();
        assert_eq!(out["batch"],"same-original");assert_eq!(calls.load(Ordering::Relaxed),2);
        let error=wait("space",&state,||async {Err(ParticipantError::local("LOCAL_SCOPE_DENIED","MCP"))}).await.unwrap_err();
        assert_eq!(error.code,"LOCAL_SCOPE_DENIED");
    }
    #[tokio::test]
    async fn authenticated_time_retry_clears_failure_on_next_real_batch() {
        let state = claude_channel::State::default();
        let mut count = 0;
        let out = tokio::time::timeout(Duration::from_secs(5), wait("space", &state, || {
            count += 1;
            let first = count == 1;
            let status = state.status();
            async move {
                if first {
                    let mut error = ParticipantError::local("NOTIFICATION_RECEIVER_NOT_VERIFIED", "LOCAL_IPC");
                    error.details = Some(json!({"state":"BLOCKED","code":"STREAM_VERIFICATION_FAILED",
                        "verification_failure":{"phase":"FRAME_VERIFICATION","code":"STREAM_TIME_WINDOW_INVALID",
                            "scope_authenticated":true}}));
                    Err(error)
                } else {
                    let recovering = &status["scopes"]["space"];
                    assert_eq!(recovering["state"], "RECOVERING");
                    assert_eq!(recovering["failure"]["verification_code"], "STREAM_TIME_WINDOW_INVALID");
                    assert!(recovering["retry_at_ms"].is_number());
                    Ok(json!({"state":"NOTIFICATION_DUE","batch":"next-business-message","revision":2,"self_test":false}))
                }
            }
        })).await.unwrap().unwrap();
        assert_eq!(out["batch"], "next-business-message");
        assert_eq!(state.status()["scopes"]["space"]["state"], "NOTIFICATION_DUE");
        assert!(state.status()["scopes"]["space"]["failure"].is_null());
    }
    #[tokio::test]
    async fn opened_listener_waits_for_the_existing_owner_to_release_its_guard() {
        let state = claude_channel::State::default();
        let mut attempts = 0;
        let result = tokio::time::timeout(Duration::from_secs(5), retry_same_target("space", &state, || {
            attempts += 1;
            let first = attempts == 1;
            async move {
                if first {
                    let mut error = ParticipantError::local("CLAUDE_CHANNEL_ALREADY_ACTIVE_OR_STATE_UNAVAILABLE", "MCP");
                    error.details = Some(json!({"local_state":{"cause":"BUSY"}}));
                    Err(error)
                } else {
                    Ok("original")
                }
            }
        })).await.unwrap().unwrap();
        assert_eq!(result, "original");
        assert_eq!(attempts, 2);
        assert_eq!(state.status()["scopes"]["space"]["state"], "RECOVERING");
    }
    #[tokio::test]
    async fn pending_rebind_keeps_original_background_activation_until_abort_recovers() {
        let state=claude_channel::State::default();let calls=std::sync::atomic::AtomicUsize::new(0);
        let activation=json!({"source":"original-group","operation_id":"original-launch","generation":7});
        let out=tokio::time::timeout(Duration::from_secs(5),wait("space",&state,||{
            let first=calls.fetch_add(1,Ordering::Relaxed)==0;
            let activation=activation.clone();
            async move {if first {Err(ParticipantError::local("PRESENTATION_REBIND_PENDING","MCP"))}
                else {Ok(json!({"state":"NOTIFICATION_DUE","batch":"original-batch","revision":4,
                    "_presentation":{"scope":"space","activation":activation}}))}}
        })).await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed),2);
        assert_eq!(out["batch"],"original-batch");
        assert_eq!(out["_presentation"]["activation"],activation);
        let error=wait("space",&state,||async {Err(ParticipantError::local("PRESENTATION_ACTIVATION_SUPERSEDED","MCP"))}).await.unwrap_err();
        assert_eq!(error.code,"PRESENTATION_ACTIVATION_SUPERSEDED");
    }
    #[test]
    fn current_connection_read_requires_its_own_published_result_and_rearm() {
        let state=State::default();
        state.projection.scope_observed("space",&json!({"state":"NOTIFICATION_DUE","batch":"a","source_binding":{"client_generation":1}}));
        state.batch_read("a");assert_eq!(state.status()["scopes"]["space"]["session_receiving"],"UNCONFIRMED");
        state.written(&json!({"result":{"structuredContent":{"format":"peerwork.background-notification.v1","batch":"a"}}}));
        state.batch_read("different-batch");
        let status = state.status();
        assert_eq!(status["scopes"]["space"]["state"], "WAITING_FOR_SESSION_READ");
        assert_eq!(status["scopes"]["space"]["session_receiving"], "UNCONFIRMED");
        assert!(status["scopes"]["space"].get("latest_unread_batch").is_none());
        state.batch_read("a");assert_eq!(state.status()["scopes"]["space"]["session_receiving"],"VERIFIED");
        assert_eq!(state.status()["listener_armed"],false);
        assert_eq!(state.status()["scopes"]["space"]["code"],"BACKGROUND_LISTEN_NOT_ARMED");
        let _waiting=state.active.clone().try_acquire_owned().unwrap();
        assert_eq!(state.status()["listener_armed"],true);
        assert_eq!(state.status()["transport"],"MCP_BACKGROUND_TOOL");
        assert_eq!(state.status()["automatic_model_wake"],"NOT_ATTESTED");
    }
}
