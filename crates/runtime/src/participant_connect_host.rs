//! Explicit host-user selections. MCP refers to opaque handles only; it cannot
//! supply socket paths, executables, credentials or replacement conversations.
use super::*;
use crate::participant_dispatch::{HostConfig, HostSubscription};
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostSelection {
    pub participant: String,
    pub admin_endpoint: PathBuf,
    pub adapter: Value,
}
/// Local owning-host integration input, deliberately absent from MCP/CLI
/// arguments and serde. Obtain these fields from the authenticated host
/// callback, never from model arguments or inherited process environment.
pub enum HostInvocation {
    CodexDynamicTool { thread_id: String, turn_id: String, call_id: String, instance: String },
    AntigravityApp { conversation_id: String, instance: String },
}
impl HostInvocation {
    fn verify(&self, adapter:&Value)->Result<Value> {
        let (kind,destination,instance)=match self {
            Self::CodexDynamicTool{thread_id,turn_id,call_id,instance}=>{
                if adapter["kind"]!="codex" || adapter["thread_id"]!=*thread_id || turn_id.is_empty() || call_id.is_empty() {
                    return Err(local("CURRENT_HOST_CONTEXT_MISMATCH"));
                }
                ("CODEX_OWNING_CLIENT_CALLBACK",thread_id,instance)
            },
            Self::AntigravityApp{conversation_id,instance}=>{
                if adapter["kind"]!="agy-app" || adapter["conversation_id"]!=*conversation_id {
                    return Err(local("CURRENT_HOST_CONTEXT_MISMATCH"));
                }
                ("AGY_APP_OWNING_INTEGRATION",conversation_id,instance)
            },
        };
        if destination.is_empty() || destination.len()>256 || !identifier(instance) {
            return Err(local("CURRENT_HOST_CONTEXT_INVALID"));
        }
        Ok(json!({"source":kind,"destination_digest":sha256_hex(destination.as_bytes()),"host_instance":instance,
            "current_session":"LOCAL_CALLER_CONTEXT_VERIFIED","tools_loaded":"NOT_ATTESTED","model_response":"NOT_ATTESTED"}))
    }
}
pub(super) struct CompletedHostBinding {
    pub name:String,
    pub watch:WatchOptions,
    pub client_name:String,
    pub generation:Option<u64>,
    pub endpoint:PathBuf,
    pub binding:Value,
}
/// Configured sources alone do not attest their current physical destination.
fn source_bound_to_host(host:&Value,key:&str,expected:&HostSubscription,adapter:&Value)->bool {
    if host["selection_id"]!=key{return false;}
    let Ok(binding)=crate::participant_inbox::HostBinding::new(host["destination"].clone()) else{return false;};
    if adapter["kind"]=="codex"&&adapter["expected_session_id"].as_str().is_some_and(|pin|binding.destination["session_id"]!=pin){return false;}

    if expected.watch.host_destination.as_deref()!=Some(binding.digest.as_str()){return false;}
    host["source_bindings"].as_array().is_some_and(|sources|sources.iter().any(|s| {
        let Ok(mut source)=serde_json::from_value::<HostSubscription>(s.clone()) else{return false;};
        if source.watch.host_destination.is_none(){source.watch.host_destination=Some(binding.digest.clone());}
        source.client==expected.client&&source.client_generation==expected.client_generation&&source.watch==expected.watch
    }))
}
impl Connect {
    /// Entry for a client that ALREADY owns the actual host event channel.
    /// This API does not manufacture that channel for an arbitrary UI/CLI.
    /// Host-user authority is required to open this writer and select endpoints.
    pub async fn connect_current(&mut self, request:ConnectRequest, selected:HostSelection, caller:HostInvocation)->Result<Value> {
        self.require_writer()?;
        let automatic=request.setup_id.is_empty();
        let mut request=self.normalize_agent_request(request)?;
        if !request.receive || selected.participant!=request.participant || request.host.is_some() || request.receive_mode==Some(ReceiveMode::Inbox) {
            return Err(local("CURRENT_HOST_SELECTION_CONFLICT"));
        }
        let observation=caller.verify(&selected.adapter)?;
        if automatic {request.setup_id=format!("current-{}",&sha256_hex(json!([request.setup_id,observation]).to_string().as_bytes())[..32]);}
        let name=self.registry.hosts.iter().find(|(_,old)|*old==&selected).map(|(name,_)|name.clone()).unwrap_or_else(||
            format!("host-{}",&sha256_hex(json!([selected.adapter,observation]).to_string().as_bytes())[..24]));
        if let Some(setup)=self.registry.setups.get(&request.setup_id) {
            if setup.desired!=request || setup.effective_host.as_ref().is_some_and(|old|old!=&name) {
                return Err(local("HOST_SELECTION_CHANGED_REBIND_REQUIRED"));
            }
            if setup.channel_receive && setup.effective_host.is_none() {
                return Err(local("EXISTING_PROGRAM_RECEIVER_REQUIRES_EXPLICIT_REBIND"));
            }
        }
        self.register_host(&name,selected).await?;
        // Record the selected host BEFORE remote permissions/keys. Approval
        // resumes this original selection, but never inherits caller evidence.
        if self.registry.setups.contains_key(&request.setup_id) {
            self.registry.setups.get_mut(&request.setup_id).unwrap().effective_host=Some(name);
        } else {
            let registration=self.registry.participants[&request.participant].clone();
            self.begin_setup(&request,registration,true,Some(name))?;
        }
        self.save()?;
        let mut result=self.run_agent(request).await?;
        // Ephemeral caller evidence must never be cached for another session.
        result["caller_context"]=observation;
        Ok(result)
    }
    /// Recognize an explicitly completed selected host binding through the original
    /// endpoint and an authenticated host-admin observation. No new receiver
    /// is derived and configuration completion never implies host readiness.
    pub(super) async fn completed_host_binding(&self,request:&ConnectRequest,previous:&Setup,mailbox:&Value)->Result<Option<CompletedHostBinding>> {
        let Some(name)=request.host.as_ref().or_else(||self.registry.setups.get(&request.setup_id).and_then(|s|s.effective_host.as_ref())) else{return Ok(None);};
        let Some(host)=self.registry.hosts.get(name).filter(|h|h.participant==request.participant) else{return Ok(None);};
        let Some(profile)=&previous.profile else{return Ok(None);};
        let Some(endpoint)=&profile.receive_endpoint_path else{return Ok(None);};
        let receiver=RuntimeClient::connect(endpoint.clone(),&profile.expected_origin,&profile.expected_actor).await?;
        let binding=receiver.call(json!({"method":"binding"})).await?;
        crate::communication_runtime::validate_binding(&binding,&profile.expected_origin,&profile.expected_actor)?;
        let Some(client_name)=binding["client_name"].as_str().filter(|s|identifier(s)) else{return Ok(None);};
        let bindings=receiver.call(json!({"method":"bindings"})).await?;
        let Some(watch)=bindings.as_array().and_then(|items|items.iter().find(|w|w["workspace_id"]==request.workspace_id&&w["mailbox_id"]==mailbox["mailbox_id"]&&w["membership_id"]==mailbox["membership_id"]&&w["host_destination"].is_string())) else{return Ok(None);};
        let watch:WatchOptions=serde_json::from_value(watch.clone()).map_err(|_|local("FIRST_HOST_BINDING_INVALID"))?;
        let config=HostConfig{name:name.clone(),adapter:host.adapter.clone(),subscriptions:vec![HostSubscription{client:client_name.into(),client_generation:binding["client_generation"].as_u64(),watch:watch.clone()}]};
        let key=config.key()?;
        let status=crate::communication_runtime::call(&host.admin_endpoint,json!({"method":"status"})).await?;
        if status["ok"]!=true || !status["value"]["engines"].as_array().is_some_and(|engines|engines.iter().any(|e|e["actor_id"]==profile.expected_actor&&e["origin"]==profile.expected_origin&&e["state_binding"]==binding["state_binding"]&&e["engine_digest"]==binding["engine_digest"])) {return Err(local("FIRST_HOST_ORIGINAL_ENGINE_MISMATCH"));}
        if !status["value"]["hosts"].as_array().is_some_and(|hosts|hosts.iter().any(|h|source_bound_to_host(h,&key,&config.subscriptions[0],&host.adapter))) {return Ok(None);}
        Ok(Some(CompletedHostBinding{name:name.clone(),watch,client_name:client_name.into(),generation:binding["client_generation"].as_u64(),endpoint:endpoint.clone(),binding:crate::communication_runtime::canonical_binding(&binding)}))
    }
    pub async fn register_host(&mut self, name: &str, selected: HostSelection) -> Result<Value> {
        self.require_writer()?;
        if !identifier(name) || !selected.admin_endpoint.is_absolute() {
            return Err(local("HOST_SELECTION_INVALID"));
        }
        let participant = self
            .registry
            .participants
            .get(&selected.participant)
            .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let placeholder = WatchOptions {
            workspace_id: "A".repeat(43),
            mailbox_id: "B".repeat(43),
            membership_id: "C".repeat(43),
            consumer_id: "selected".into(),
            host_destination: None,
        };
        HostConfig {
            name: name.into(),
            adapter: selected.adapter.clone(),
            subscriptions: vec![HostSubscription {
                client_generation: None,
                client: "selected".into(),
                watch: placeholder,
            }],
        }
        .key()?;
        if selected.adapter["kind"] == "agy-stdio" && selected.adapter["managed"] != true {
            return Err(local("EXISTING_AGY_SESSION_INTERFACE_REQUIRED"));
        }
        let status = crate::communication_runtime::call(
            &selected.admin_endpoint,
            json!({"method":"status"}),
        )
        .await?;
        if status["ok"] != true
            || !status["value"]["engines"]
                .as_array()
                .is_some_and(|engines| {
                    engines.iter().any(|e| {
                        e["actor_id"] == participant.actor_id && e["origin"] == participant.origin
                    })
                })
        {
            return Err(local("HOST_RUNTIME_IDENTITY_OR_ORIGIN_MISMATCH"));
        }
        if let Some(expected)=self.registry.verified_bindings.get(&selected.participant) {
            if !status["value"]["engines"].as_array().is_some_and(|xs|xs.iter().any(|e|
                e["state_binding"]==expected["state_binding"] && e["engine_digest"]==expected["engine_digest"])) {
                return Err(local("HOST_RUNTIME_BINDING_MISMATCH"));
            }
        }
        if let Some(old) = self.registry.hosts.get(name) {
            if old != &selected {
                return Err(local("HOST_SELECTION_CHANGED_REBIND_REQUIRED"));
            }
        } else {
            if self.registry.hosts.len() >= 8 {
                return Err(local("HOST_SELECTION_LIMIT"));
            }
            self.registry.hosts.insert(name.into(), selected);
            self.save()?;
        }
        Ok(json!({"state":"LOCAL_HOST_REGISTERED","host":name,"model_response":"NOT_ATTESTED"}))
    }
    pub(super) async fn ensure_host(
        &self,
        name: &str,
        request: &ConnectRequest,
        registration: &Registration,
        client_name: &str,
        client_generation: Option<u64>,
        watch: WatchOptions,
    ) -> Result<Value> {
        let selected = self
            .registry
            .hosts
            .get(name)
            .ok_or_else(|| local("HOST_BINDING_REQUIRED"))?;
        if selected.participant != request.participant {
            return Err(local("HOST_IDENTITY_PIN_MISMATCH"));
        }
        let config = HostConfig {
            name: name.into(),
            adapter: selected.adapter.clone(),
            subscriptions: vec![HostSubscription {
                client_generation,
                client: client_name.into(),
                watch,
            }],
        };
        let value = crate::communication_runtime::call(
            &selected.admin_endpoint,
            json!({"method":"host_ensure","config":config,
            "expected_actor":registration.actor_id,"expected_origin":registration.origin}),
        )
        .await?;
        if value["ok"] != true {
            return Err(serde_json::from_value(value["error"].clone())
                .unwrap_or_else(|_| local("HOST_ATTACH_FAILED")));
        }
        Ok(value["value"].clone())
    }
}

pub(super) fn adapter(values: &BTreeMap<String, String>) -> Result<Option<Value>> {
    let has = |name: &str| values.contains_key(name);
    let text = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| local("HOST_SELECTION_ARGUMENT_MISSING"))
    };
    let absolute =
        |name: &str| std::path::absolute(text(name)?).map_err(|_| local("HOST_SELECTION_INVALID"));
    let codex = [
        "--codex-endpoint",
        "--codex-thread",
        "--codex-session",
        "--codex-auth-env",
    ]
    .iter()
    .any(|s| has(s));
    let managed = has("--agy-managed");
    let app = has("--agy-api");
    if usize::from(codex) + usize::from(managed) + usize::from(app) > 1 {
        return Err(local("SELECT_ONE_HOST_ADAPTER"));
    }
    if codex {
        if ["--agy-executable", "--agy-conversation", "--agy-inbox"]
            .iter()
            .any(|s| has(s))
        {
            return Err(local("SELECT_ONE_HOST_ADAPTER"));
        }
        let mut selected = json!({"kind":"codex","endpoint":text("--codex-endpoint")?,"thread_id":text("--codex-thread")?});
        if let Some(session) = values.get("--codex-session") {
            selected["expected_session_id"] = json!(session);
        }
        if let Some(env) = values.get("--codex-auth-env") {
            if env.is_empty()
                || env.len() > 128
                || !env.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return Err(local("HOST_SELECTION_INVALID"));
            }
            selected["auth_token_env"] = json!(env);
        }
        return Ok(Some(selected));
    }
    if managed {
        if has("--agy-inbox") {
            return Err(local("SELECT_ONE_HOST_ADAPTER"));
        }
        return Ok(Some(
            json!({"kind":"agy-stdio","managed":true,"executable":absolute("--agy-executable")?,
            "working_directory":absolute("--project")?,"conversation_id":text("--agy-conversation")?}),
        ));
    }
    if app {
        if has("--agy-executable") {
            return Err(local("SELECT_ONE_HOST_ADAPTER"));
        }
        return Ok(Some(
            json!({"kind":"agy-app","agentapi_path":absolute("--agy-api")?,"inbox_directory":absolute("--agy-inbox")?,"conversation_id":text("--agy-conversation")?}),
        ));
    }
    if ["--agy-executable", "--agy-conversation", "--agy-inbox"]
        .iter()
        .any(|s| has(s))
    {
        return Err(local("EXISTING_AGY_SESSION_INTERFACE_REQUIRED"));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn explicit_inbox_rejects_current_host_binding_before_local_changes() {
        let state=crate::test_support::protected_test_dir();
        let mut connect=Connect::open(&state.path().join("registry")).unwrap();
        connect.registry.participants.insert("worker".into(),Registration{origin:"https://example.invalid/".into(),actor_id:"A".repeat(43),endpoint_path:state.path().join("not-opened.json")});
        connect.save().unwrap();
        let before=std::fs::read(connect.directory.join("connect.state")).unwrap();
        let request=serde_json::from_value(json!({"participant":"worker","workspace_id":"W".repeat(43),"receive":true,"receive_mode":"INBOX"})).unwrap();
        let selected=HostSelection{participant:"worker".into(),admin_endpoint:state.path().join("not-opened-admin.json"),adapter:json!({"kind":"codex","thread_id":"selected-thread"})};
        let caller=HostInvocation::CodexDynamicTool{thread_id:"selected-thread".into(),turn_id:"turn".into(),call_id:"call".into(),instance:"host".into()};
        let error=connect.connect_current(request,selected,caller).await.unwrap_err();
        assert_eq!(error.code,"CURRENT_HOST_SELECTION_CONFLICT");
        assert_eq!(std::fs::read(connect.directory.join("connect.state")).unwrap(),before);
        assert!(connect.registry.hosts.is_empty());assert!(connect.registry.setups.is_empty());
    }
    fn flags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    #[test]
    fn session_selection_is_explicit_and_managed_agy_never_implies_bypass() {
        assert!(adapter(&BTreeMap::new()).unwrap().is_none());
        assert_eq!(
            adapter(&flags(&[("--agy-conversation", "existing")]))
                .unwrap_err()
                .code,
            "EXISTING_AGY_SESSION_INTERFACE_REQUIRED"
        );
        let codex = adapter(&flags(&[
            ("--codex-endpoint", "ws://127.0.0.1:1"),
            ("--codex-thread", "selected-thread"),
            ("--codex-session", "selected-session"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(codex["thread_id"], "selected-thread");
        assert_eq!(codex["expected_session_id"], "selected-session");
        let managed = adapter(&flags(&[
            ("--agy-managed", "true"),
            ("--agy-executable", "agy"),
            ("--project", "."),
            ("--agy-conversation", "owned-session"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(managed["managed"], true);
        assert!(managed.get("args").is_none());
        assert!(!managed.to_string().contains("skip-permissions"));
        assert!(adapter(&flags(&[("--codex-thread", "thread")])).is_err());
        assert_eq!(
            adapter(&flags(&[
                ("--codex-thread", "thread"),
                ("--agy-managed", "true")
            ]))
            .unwrap_err()
            .code,
            "SELECT_ONE_HOST_ADAPTER"
        );
    }
}

#[cfg(test)]
mod host_source_tests {
    use super::*;
    #[test]
    fn omitted_config_destination_cannot_adopt_a_different_current_host() {
        let a=crate::participant_inbox::HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"a","session_id":"session-a"})).unwrap();
        let b=crate::participant_inbox::HostBinding::new(json!({"host":"CODEX_APP_SERVER","conversation_id":"b","session_id":"session-b"})).unwrap();
        let mut expected=HostSubscription{client:"worker".into(),client_generation:Some(1),watch:WatchOptions{workspace_id:"W".repeat(43),mailbox_id:"M".repeat(43),membership_id:"G".repeat(43),consumer_id:"original".into(),host_destination:Some(a.digest.clone())}};
        let mut source=expected.clone();source.watch.host_destination=None;
        let status=json!({"selection_id":"host-a","destination":a.destination,"source_bindings":[source]});
        assert!(source_bound_to_host(&status,"host-a",&expected,&json!({})));
        expected.watch.host_destination=Some(b.digest);
        assert!(!source_bound_to_host(&status,"host-a",&expected,&json!({})));
        let mut missing=status;missing["destination"]=Value::Null;
        assert!(!source_bound_to_host(&missing,"host-a",&expected,&json!({})));
    }
    #[test]
    fn same_route_must_honor_the_selected_codex_session_pin() {
        let mut adapter=json!({"kind":"codex","endpoint":"ws://127.0.0.1:1","thread_id":"same-thread","expected_session_id":"session-a"});
        let binding=crate::participant_inbox::HostBinding::new(json!({"host":"CODEX_APP_SERVER","endpoint":"ws://127.0.0.1:1","conversation_id":"same-thread","session_id":"session-b"})).unwrap();
        let source=HostSubscription{client:"worker".into(),client_generation:None,watch:WatchOptions{workspace_id:"W".repeat(43),mailbox_id:"M".repeat(43),membership_id:"G".repeat(43),consumer_id:"original".into(),host_destination:Some(binding.digest)}};
        let original=HostConfig{name:"selected".into(),adapter:adapter.clone(),subscriptions:vec![source.clone()]};
        let key=original.key().unwrap();adapter["expected_session_id"]=json!("session-b");
        assert_eq!(HostConfig{name:"selected".into(),adapter:adapter.clone(),subscriptions:vec![source.clone()]}.key().unwrap(),key,"persistent group keys must remain unchanged");
        let host=json!({"selection_id":key,"destination":binding.destination,"source_bindings":[source.clone()]});
        assert!(!source_bound_to_host(&host,&key,&source,&original.adapter));
        assert!(source_bound_to_host(&host,&key,&source,&adapter));
    }

}
