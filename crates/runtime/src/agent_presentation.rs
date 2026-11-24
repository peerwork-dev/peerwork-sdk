//! An opted-in host launch owns one frozen activation decision. Observation
//! retries resume that decision; they never discover/adopt another launch token.
use super::*;
use crate::{communication_runtime::RuntimeClient, participant::WatchOptions, secure_state::{SecureStateError, SecureStateStore}};
use std::{collections::BTreeMap, path::{Path, PathBuf}};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Selection { client:Arc<RuntimeClient>, options:WatchOptions, source:String, presence:bool }
enum ChannelOwner {
    Waiting(Selection),
    Held { _guard: SecureStateStore },
}
struct Decision {
    admin: PathBuf,
    request: Value,
    activation: Option<Value>,
    terminal: Option<String>,
    channel_owner: Option<ChannelOwner>,
}
type SharedDecision=Arc<Mutex<Decision>>;
#[derive(Default)]
pub(super) struct State {
    scopes:BTreeMap<String,Selection>,
    groups:BTreeMap<String,SharedDecision>,
    legacy:BTreeMap<String,Option<Selection>>,
}
fn error(code:&str)->ParticipantError {ParticipantError::local(code,"PRESENTATION")}
fn unwrap(value:Value)->Result<Value> {
    if value["ok"]==true {Ok(value["value"].clone())}
    else {Err(serde_json::from_value(value["error"].clone()).unwrap_or_else(|_|error("PRESENTATION_RESPONSE_INVALID")))}
}
fn operation_id()->Result<String> {
    use rand_core::{OsRng,RngCore};
    let mut bytes=[0u8;24];OsRng.try_fill_bytes(&mut bytes).map_err(|_|error("ENTROPY_UNAVAILABLE"))?;
    Ok(format!("presentation_{}",peerwork_core::crypto::base64url(&bytes)))
}
fn channel_owner(admin: &Path, source: &str) -> Result<SecureStateStore> {
    if source.len() != 64 || !source.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error("PRESENTATION_RESPONSE_INVALID"));
    }
    let path = admin.with_file_name(format!("claude-channel-source-{source}.state"));
    SecureStateStore::open(&path).map_err(|cause| match cause {
        SecureStateError::Busy => error("CLAUDE_CHANNEL_STANDBY"),
        _ => cause.diagnose(error("CLAUDE_CHANNEL_ALREADY_ACTIVE_OR_STATE_UNAVAILABLE"), "OPEN"),
    })
}

fn superseded(code: &str) -> bool {
    matches!(code, "PRESENTATION_GENERATION_CONFLICT" | "PRESENTATION_SOURCE_CHANGED" | "PRESENTATION_ACTIVATION_SUPERSEDED")
}

async fn complete(decision:&SharedDecision)->Result<Value> {
    let mut decision=decision.lock().await;
    if let Some(code)=&decision.terminal {return Err(error(code));}
    if let Some(activation)=&decision.activation {return Ok(activation.clone());}
    if let Some(ChannelOwner::Waiting(selection)) = &decision.channel_owner {
        let guard = channel_owner(&decision.admin, &selection.source)?;
        let observed = selection.client.call(json!({"method":"presentation_status","options":selection.options})).await?;
        if observed["group"] != decision.request["activation"]["source_group"] {
            decision.terminal = Some("PRESENTATION_SOURCE_CHANGED".into());
            return Err(error("PRESENTATION_SOURCE_CHANGED"));
        }
        let generation = observed["current_generation"].as_u64().ok_or_else(|| error("PRESENTATION_RESPONSE_INVALID"))?;
        decision.request["activation"]["expected_generation"] = generation.into();
        decision.channel_owner = Some(ChannelOwner::Held { _guard: guard });
    }
    // Freeze before mutation. A lost reply repeats the exact native decision.
    let result=match unwrap(crate::communication_runtime::call(&decision.admin,decision.request.clone()).await?) {
        Ok(result)=>result,
        Err(failure)=>{
            if superseded(&failure.code) {
                decision.terminal=Some(failure.code.clone());
                decision.channel_owner = None;
            }
            return Err(failure);
        },
    };
    if result["state"]!="ACTIVE" {
        decision.terminal=Some("PRESENTATION_ACTIVATION_SUPERSEDED".into());
        decision.channel_owner = None;
        return Err(error("PRESENTATION_ACTIVATION_SUPERSEDED"));
    }
    let activation=result["activation"].clone();
    if !activation.is_object() {return Err(error("PRESENTATION_RESPONSE_INVALID"));}
    decision.activation=Some(activation.clone());Ok(activation)
}
impl Lifecycle {
    pub(crate) fn verify_claude_entry(&self,server:&str)->Result<()> {
        let directory=self.local.as_ref().ok_or_else(||error("CLAUDE_CHANNEL_LAUNCH_MISMATCH"))?;
        let workspace=self.workspace.as_deref().ok_or_else(||error("CLAUDE_CHANNEL_LAUNCH_MISMATCH"))?;
        let connect=self.inspect(directory)?;
        if connect.presentation_issuer(self.handle.as_deref(),workspace,"MCP_STDIO_CHANNEL",Some((server,&[workspace])))?.is_none(){
            return Err(error("CLAUDE_CHANNEL_LAUNCH_MISMATCH"));
        }
        Ok(())
    }
    pub(crate) fn presentation_transport(&self,kind:&str)->Result<()> {
        if !matches!(kind,"MCP_STDIO_CHANNEL"|"MCP_BACKGROUND_TOOL") {return Err(error("PRESENTATION_TARGET_INVALID"));}
        if let Some(old)=self.presentation_transport.get() {
            return if old==kind {Ok(())}else{Err(error("PRESENTATION_TRANSPORT_CONFLICT"))};
        }
        if self.presentation_transport.set(kind.into()).is_err() && self.presentation_transport.get().is_none_or(|old|old!=kind) {
            return Err(error("PRESENTATION_TRANSPORT_CONFLICT"));
        }
        Ok(())
    }
    pub(crate) async fn presentation_selection(&self,scope:&str)->Result<Option<Value>> {
        let kind=self.presentation_transport.get().ok_or_else(||error("PRESENTATION_HOST_OPT_IN_REQUIRED"))?.clone();
        let cached={
            let state=self.presentation.lock().await;
            if state.legacy.contains_key(scope) {return Ok(None);}
            state.scopes.get(scope).map(|selection|state.groups.get(&selection.source).cloned()
                .ok_or_else(||error("PRESENTATION_ACTIVATION_REQUIRED"))).transpose()?
        };
        if let Some(decision)=cached {return complete(&decision).await.map(Some);}
        let Some(profile)=self.channel_profile()? else{return Ok(None);};
        let wanted=profile.scopes.get(scope).ok_or_else(||error("RECEIVING_SCOPE_NOT_CONFIGURED"))?;
        let context=self.call(AgentRequest::Context).await?;
        let options=context["bindings"].as_array().into_iter().flatten().find(|binding|
            binding["workspace_id"]==wanted.workspace_id && binding["mailbox_id"]==wanted.mailbox_id && binding["membership_id"]==wanted.membership_id)
            .cloned().ok_or_else(||error("PRESENTATION_SOURCE_CHANGED"))?;
        let options:WatchOptions=serde_json::from_value(options).map_err(|_|error("PRESENTATION_SOURCE_CHANGED"))?;
        if options.host_destination.is_some(){return Err(error("CLAUDE_CHANNEL_SOURCE_ALREADY_BOUND_TO_ANOTHER_HOST"));}
        let mut binding=context["receiving_binding"].clone();
        binding["format"]=json!("peerwork.local-engine-binding.v1");
        binding["actor_id"]=context["actor_id"].clone();binding["origin"]=context["origin"].clone();
        let endpoint=profile.receive_endpoint_path.clone().unwrap_or_else(||profile.endpoint_path.clone());
        let client=Arc::new(RuntimeClient::connect_bound(endpoint,&profile.expected_origin,&profile.expected_actor,binding).await?);
        let caps=client.call(json!({"method":"capabilities"})).await?;
        if let Some(launch) = &self.claude_launch {
            let required = if launch.native { "claude-native-auto-attach-v1" } else { "claude-session-activation-v1" };
            if !caps["features"].as_array().is_some_and(|features| features.iter().any(|feature| feature == required)) {
                return Err(error("CLAUDE_CHANNEL_RUNTIME_UPGRADE_REQUIRED"));
            }
        }
        if !caps["features"].as_array().is_some_and(|features|features.iter().any(|feature|feature=="presentation-activation-v1")) {
            self.presentation.lock().await.legacy.insert(scope.into(),None);return Ok(None);
        }
        let observed=client.call(json!({"method":"presentation_status","options":options})).await?;
        let source=observed["source"].as_str().ok_or_else(||error("PRESENTATION_RESPONSE_INVALID"))?.to_owned();
        let presence = caps["features"].as_array().is_some_and(|features|
            features.iter().any(|feature| feature == crate::delivery_health::PRESENTATION_PRESENCE_FEATURE));
        let selection=Selection{client,options,source:source.clone(),presence};
        let known=self.presentation.lock().await.groups.get(&source).cloned();
        let candidate=if let Some(known)=known {known} else {
            let members=observed["group"]["bindings"].as_array().into_iter().flatten()
                .filter_map(|watch|watch["workspace_id"].as_str()).collect::<Vec<_>>();
            let launch=self.claude_launch.as_ref().map(|launch|(launch.server.as_str(),members.as_slice()));
            let registered=if let Some(directory)=&self.local {
                let connect=self.inspect(directory)?;
                connect.presentation_issuer(self.handle.as_deref(),&wanted.workspace_id,&kind,launch)?
            }else if let Some((_,connect,handle))=self.source_selection(&profile)? {
                connect.presentation_issuer(Some(&handle),&wanted.workspace_id,&kind,launch)?
            }else{None};
            let Some((admin,registration_id))=registered else {
                if launch.is_some() {return Err(error("CLAUDE_CHANNEL_LAUNCH_MISMATCH"));}
                if observed["state"]=="UNMANAGED" {
                    self.presentation.lock().await.legacy.insert(scope.into(), presence.then_some(selection));
                    return Ok(None);
                }
                return Err(error("PRESENTATION_ORIGINAL_INSTALLATION_REQUIRED"));
            };
            let source_binding=crate::agent_delivery_status::binding(&context,&serde_json::to_value(&selection.options).unwrap());
            let mut request=json!({"method":"presentation_activate","activation":{
                "client_name":source_binding["client_name"],"source_binding":source_binding,
                "options":selection.options,"source_group":observed["group"],
                "target":{"kind":kind,"registration_id":registration_id,"host_destination":null},
                "operation_id":operation_id()?,"expected_generation":observed["current_generation"]}});
            if let Some(launch)=&self.claude_launch {
                request["activation"]["target"]["host_session"]=json!(launch.session_digest());
                request["activation"]["target"]["host_launch"]=json!(launch.order);
                if launch.select_session {
                    request["activation"]["select_session"]=json!(true);
                } else if launch.native {
                    request["activation"]["select_first_session"]=json!(true);
                }
            }
            let channel_owner = (kind == "MCP_STDIO_CHANNEL" && self.claude_launch.is_none())
                .then(|| ChannelOwner::Waiting(selection.clone()));
            Arc::new(Mutex::new(Decision{admin,request,activation:None,terminal:None,channel_owner}))
        };
        // Freeze exactly one decision for all aliases of the source. The
        // directory lock is released before any IPC, including a retry after a
        // lost commit response. An existing alias keeps its original source.
        let decision={
            let mut state=self.presentation.lock().await;
            if let Some(original)=state.scopes.get(scope) {
                state.groups.get(&original.source).cloned().ok_or_else(||error("PRESENTATION_ACTIVATION_REQUIRED"))?
            }else{
                let decision=state.groups.entry(source).or_insert(candidate).clone();
                state.scopes.insert(scope.into(),selection);
                decision
            }
        };
        complete(&decision).await.map(Some)
    }
    async fn presentation_observe(&self, scope: &str, mut request: Value, verified: Option<bool>) -> Result<Value> {
        let (selected, decision) = {
            let state = self.presentation.lock().await;
            let selected = state.scopes.get(scope).cloned().ok_or_else(|| error("PRESENTATION_ACTIVATION_REQUIRED"))?;
            let decision = state.groups.get(&selected.source).cloned().ok_or_else(|| error("PRESENTATION_ACTIVATION_REQUIRED"))?;
            (selected, decision)
        };
        request["options"] = serde_json::to_value(selected.options).map_err(|_| error("PRESENTATION_RESPONSE_INVALID"))?;
        if let Some(verified) = verified.filter(|_| selected.presence) {
            request["session_receiving_verified"] = json!(verified);
            request["wait_ms"] = json!(crate::delivery_health::PRESENTATION_WAIT_MS);
        }
        let result = selected.client.call(request).await;
        if result.as_ref().is_err_and(|failure| superseded(&failure.code)) {
            // A deliberately superseded connection still has tools, but no
            // longer holds the Channel slot or competes for presentation.
            decision.lock().await.channel_owner = None;
        }
        result
    }
    pub(crate) async fn presentation_poll(&self,scope:&str,activation:&Value,verified:bool)->Result<Value> {
        self.presentation_observe(scope,json!({"method":"notification_poll","activation":activation,"wait_ms":20000}),Some(verified)).await
    }
    pub(crate) async fn unmanaged_presentation_poll(&self, scope: &str, verified: bool) -> Result<Value> {
        let selected = self.presentation.lock().await.legacy.get(scope).cloned().flatten();
        let Some(selected) = selected else {
            return self.call(AgentRequest::NotificationPoll { scope: scope.into() }).await;
        };
        selected.client.call(json!({"method":"notification_poll", "options":selected.options,
            "wait_ms":crate::delivery_health::PRESENTATION_WAIT_MS,
            "session_receiving_verified":verified})).await
    }
    pub(crate) async fn presentation_allowed(&self,scope:&str,activation:&Value,batch:&str,revision:u64)->Result<bool> {
        let value=self.presentation_observe(scope,json!({"method":"notification_validate","activation":activation,"batch":batch,"revision":revision}),None).await?;
        Ok(value["allowed"]==true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_waiting_decision_does_not_hold_another_presentation_group() {
        let saved=|generation| Arc::new(Mutex::new(Decision{
            admin:PathBuf::new(),request:Value::Null,activation:Some(json!({"generation":generation})),terminal:None,
            channel_owner:None,
        }));
        let waiting=saved(1);
        let available=saved(2);
        let held=waiting.lock().await;
        let first=complete(&waiting);
        tokio::pin!(first);
        assert!(tokio::time::timeout(Duration::from_millis(25),first.as_mut()).await.is_err());
        let result=tokio::time::timeout(Duration::from_secs(1),complete(&available)).await.unwrap().unwrap();
        assert_eq!(result["generation"],2);
        drop(held);
        assert_eq!(first.await.unwrap()["generation"],1);
    }
}
