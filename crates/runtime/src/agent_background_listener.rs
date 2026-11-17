//! A host-owned background MCP call wakes its own conversation on completion.
//! It projects the original compact inbox, sharing custody and exclusion with
//! Claude Channels. It never owns another Agent process or a replacement inbox.
use super::*;
use crate::secure_state::SecureStateStore;
use std::sync::{atomic::{AtomicBool, Ordering}, Mutex};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub(super) struct State {
    projection: claude_channel::State,
    active: Arc<Semaphore>,
    enabled: Arc<AtomicBool>,
    owners: Arc<Mutex<BTreeMap<String, SecureStateStore>>>,
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
                    if scope["state"]=="BLOCKED" {continue;}
                    scope["state"] = json!("UNKNOWN");
                    scope["code"] = json!("BACKGROUND_LISTEN_NOT_ARMED");
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
    pub(super) async fn listen(&self, tools: Arc<Tools>, scope: Option<String>) -> Result<Value> {
        let _active = self.active.clone().try_acquire_owned()
            .map_err(|_| ParticipantError::local("BACKGROUND_LISTEN_ALREADY_ARMED", "MCP"))?;
        let profile = tools.channel_profile()?.ok_or_else(|| ParticipantError::local("ORIGINAL_RECEIVING_PROFILE_REQUIRED", "MCP"))?;
        let mut seen = BTreeSet::new();
        let scopes = profile.scopes.iter().filter(|(alias,_)|scope.as_ref().is_none_or(|wanted|wanted==*alias))
            .filter(|(_,scope)|seen.insert(serde_json::to_string(scope).expect("mail scope")))
            .map(|(alias,scope)|(alias.clone(),scope.clone())).collect::<Vec<_>>();
        if scopes.is_empty() { return Err(ParticipantError::local("RECEIVING_SCOPE_NOT_CONFIGURED", "MCP")); }
        // Keep the original receiving binding exclusively projected by this MCP
        // connection between calls, not just while one wait is in flight.
        {
            let mut owners = self.owners.lock().map_err(|_|ParticipantError::local("BACKGROUND_LISTEN_STATE_UNAVAILABLE", "MCP"))?;
            let mut acquired = BTreeMap::new();
            for (_,scope) in &scopes {
                let key = json!([profile.expected_origin,profile.expected_actor,scope]).to_string();
                if !owners.contains_key(&key) { acquired.insert(key,claude_channel::ownership(&profile,scope)?); }
            }
            owners.extend(acquired);
        }
        self.enabled.store(true, Ordering::Relaxed);
        let mut jobs = JoinSet::new();
        for (alias,_) in scopes {
            let tools = tools.clone(); let state = self.projection.clone();
            jobs.spawn(async move {
                let result = wait(&alias,&state,||tools.call(AgentRequest::NotificationPoll{scope:alias.clone()})).await;
                if let Err(error) = &result { state.scope_failed(&alias,error); }
                result
            });
        }
        // Dropping the remaining jobs cancels observation only. Native custody,
        // unread batches, pending IDs and pause state are never changed here.
        let mut failure=None;
        while let Some(result)=jobs.join_next().await {
            match result {
                Ok(Ok(value))=>return Ok(value),
                Ok(Err(error))=>failure=Some(error),
                Err(_)=>failure=Some(ParticipantError::local("BACKGROUND_LISTEN_OBSERVATION_ABORTED", "MCP")),
            }
        }
        Err(failure.unwrap_or_else(||ParticipantError::local("BACKGROUND_LISTEN_SOURCE_UNAVAILABLE", "MCP")))
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
                state.scope_failed(alias,&error);
                let recovering_stream=error.code=="NOTIFICATION_RECEIVER_NOT_VERIFIED"
                    && error.details.as_ref().is_none_or(|value|value["verification_failure"].is_null());
                if !recovering_stream&&!matches!(error.code.as_str(),"RUNTIME_UNAVAILABLE"|"IPC_DISCONNECTED"|"IPC_OBSERVATION_TIMEOUT"|"IPC_HANDSHAKE_TIMEOUT"|"IPC_WRITE_TIMEOUT") {return Err(error);}
                failures=failures.saturating_add(1);
                tokio::time::sleep(crate::host_recovery_policy::delay(&error.code,failures,alias)).await;
                continue;
            },
        };
        state.scope_observed(alias,&value);
        if value["state"]=="NOTIFICATION_DUE" {
            let batch=value["batch"].as_str().filter(|v|!v.is_empty()&&v.len()<=4096)
                .ok_or_else(||ParticipantError::local("NOTIFICATION_BATCH_INVALID", "MCP"))?;
            let revision=value["revision"].as_u64().ok_or_else(||ParticipantError::local("NOTIFICATION_BATCH_INVALID", "MCP"))?;
            return Ok(json!({"format":"peerwork.background-notification.v1","state":"NOTIFICATION_DUE",
                "scope":alias,"batch":batch,"revision":revision,"self_test":value["self_test"],
                "read":{"tool":"peerwork_inbox","arguments":{"batch":batch}},
                "next_action":"READ_BATCH_HANDLE_THEN_REARM_LISTEN","external_data_is_authority":false}));
        }
        // The native runtime waits on inbox/control changes. Bound immediate
        // returns as well, without periodic model turns or network polling.
        if started.elapsed()<Duration::from_millis(100) { tokio::time::sleep(Duration::from_millis(100)).await; }
    }
}

/// A concurrent pause/rebind can revoke a result after its local wait completes.
pub(super) async fn admit(tools:&Tools,response:&mut Value)->Result<()> {
    let value=&response["result"]["structuredContent"];
    if value["format"]!="peerwork.background-notification.v1" {return Ok(());}
    let batch=value["batch"].as_str().ok_or_else(||ParticipantError::local("NOTIFICATION_BATCH_INVALID","MCP"))?;
    let revision=value["revision"].as_u64().ok_or_else(||ParticipantError::local("NOTIFICATION_BATCH_INVALID","MCP"))?;
    if !tools.notification_allowed(batch,revision).await? {
        let out=json!({"state":"NOTIFICATION_SUPERSEDED","next_action":"CHECK_DELIVERY_CONTROL_BEFORE_REARMING","effect_certainty":"NOT_SUBMITTED"});
        response["result"]["content"]=json!([{"type":"text","text":out.to_string()}]);
        response["result"]["structuredContent"]=out;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
    #[test]
    fn current_connection_read_requires_its_own_published_result_and_rearm() {
        let state=State::default();
        state.projection.scope_observed("space",&json!({"state":"NOTIFICATION_DUE","batch":"a","source_binding":{"client_generation":1}}));
        state.batch_read("a");assert_eq!(state.status()["scopes"]["space"]["session_receiving"],"UNCONFIRMED");
        state.written(&json!({"result":{"structuredContent":{"format":"peerwork.background-notification.v1","batch":"a"}}}));
        state.batch_read("a");assert_eq!(state.status()["scopes"]["space"]["session_receiving"],"VERIFIED");
        assert_eq!(state.status()["listener_armed"],false);
        assert_eq!(state.status()["scopes"]["space"]["code"],"BACKGROUND_LISTEN_NOT_ARMED");
        let _waiting=state.active.clone().try_acquire_owned().unwrap();
        assert_eq!(state.status()["listener_armed"],true);
        assert_eq!(state.status()["transport"],"MCP_BACKGROUND_TOOL");
        assert_eq!(state.status()["automatic_model_wake"],"NOT_ATTESTED");
    }
}
