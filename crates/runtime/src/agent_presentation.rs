//! An opted-in host launch owns one frozen activation decision. Observation
//! retries resume that decision; they never discover/adopt another launch token.
use super::*;
use crate::{communication_runtime::RuntimeClient, participant::WatchOptions};
use std::{collections::{BTreeMap, BTreeSet}, path::PathBuf};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Selection { client:Arc<RuntimeClient>, options:WatchOptions, source:String }
struct Decision { admin:PathBuf, request:Value, activation:Option<Value>, terminal:Option<String> }
type SharedDecision=Arc<Mutex<Decision>>;
#[derive(Default)]
pub(super) struct State {
    scopes:BTreeMap<String,Selection>,
    groups:BTreeMap<String,SharedDecision>,
    legacy:BTreeSet<String>,
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
async fn complete(decision:&SharedDecision)->Result<Value> {
    let mut decision=decision.lock().await;
    if let Some(code)=&decision.terminal {return Err(error(code));}
    if let Some(activation)=&decision.activation {return Ok(activation.clone());}
    // Freeze before IO. A lost reply repeats the exact native decision rather
    // than refreshing expected_generation and competing with its successor.
    let result=match unwrap(crate::communication_runtime::call(&decision.admin,decision.request.clone()).await?) {
        Ok(result)=>result,
        Err(failure)=>{
            if matches!(failure.code.as_str(),"PRESENTATION_GENERATION_CONFLICT"|"PRESENTATION_SOURCE_CHANGED"|"PRESENTATION_ACTIVATION_SUPERSEDED") {
                decision.terminal=Some(failure.code.clone());
            }
            return Err(failure);
        },
    };
    if result["state"]!="ACTIVE" {decision.terminal=Some("PRESENTATION_ACTIVATION_SUPERSEDED".into());return Err(error("PRESENTATION_ACTIVATION_SUPERSEDED"));}
    let activation=result["activation"].clone();
    if !activation.is_object() {return Err(error("PRESENTATION_RESPONSE_INVALID"));}
    decision.activation=Some(activation.clone());Ok(activation)
}
impl Lifecycle {
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
            if state.legacy.contains(scope) {return Ok(None);}
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
        if !caps["features"].as_array().is_some_and(|features|features.iter().any(|feature|feature=="presentation-activation-v1")) {
            self.presentation.lock().await.legacy.insert(scope.into());return Ok(None);
        }
        let observed=client.call(json!({"method":"presentation_status","options":options})).await?;
        let source=observed["source"].as_str().ok_or_else(||error("PRESENTATION_RESPONSE_INVALID"))?.to_owned();
        let selection=Selection{client,options,source:source.clone()};
        let known=self.presentation.lock().await.groups.get(&source).cloned();
        let candidate=if let Some(known)=known {known} else {
            let registered=if let Some(directory)=&self.local {
                let connect=self.inspect(directory)?;
                connect.presentation_issuer(self.handle.as_deref(),&wanted.workspace_id,&kind)?
            }else if let Some((_,connect,handle))=self.source_selection(&profile)? {
                connect.presentation_issuer(Some(&handle),&wanted.workspace_id,&kind)?
            }else{None};
            let Some((admin,registration_id))=registered else {
                if observed["state"]=="UNMANAGED" {self.presentation.lock().await.legacy.insert(scope.into());return Ok(None);}
                return Err(error("PRESENTATION_ORIGINAL_INSTALLATION_REQUIRED"));
            };
            let source_binding=crate::agent_delivery_status::binding(&context,&serde_json::to_value(&selection.options).unwrap());
            let request=json!({"method":"presentation_activate","activation":{
                "client_name":source_binding["client_name"],"source_binding":source_binding,
                "options":selection.options,"source_group":observed["group"],
                "target":{"kind":kind,"registration_id":registration_id,"host_destination":null},
                "operation_id":operation_id()?,"expected_generation":observed["current_generation"]}});
            Arc::new(Mutex::new(Decision{admin,request,activation:None,terminal:None}))
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
    pub(crate) async fn presentation_poll(&self,scope:&str,activation:&Value)->Result<Value> {
        let selected=self.presentation.lock().await.scopes.get(scope).cloned().ok_or_else(||error("PRESENTATION_ACTIVATION_REQUIRED"))?;
        selected.client.call(json!({"method":"notification_poll","options":selected.options,"activation":activation,"wait_ms":20000})).await
    }
    pub(crate) async fn presentation_allowed(&self,scope:&str,activation:&Value,batch:&str,revision:u64)->Result<bool> {
        let selected=self.presentation.lock().await.scopes.get(scope).cloned().ok_or_else(||error("PRESENTATION_ACTIVATION_REQUIRED"))?;
        let value=selected.client.call(json!({"method":"notification_validate","options":selected.options,"activation":activation,"batch":batch,"revision":revision})).await?;
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
