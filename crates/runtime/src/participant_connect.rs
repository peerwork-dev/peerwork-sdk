//! Shared, resumable local onboarding. Remote rights remain service-enforced;
//! the registry contains explicit local selections, never discovered secrets.
use crate::{
    agent_tools::{AgentProfile, Contact, MailScope, SendScope, ManagementView},
    communication_host::write_private,
    communication_runtime::RuntimeClient,
    communication_store::identifier,
    participant::{Capability, Invoke, ParticipantError, Result, Scope, WatchOptions},
    secure_state::{create_private_state_directory, SecureStateStore},
};
use peerwork_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[path = "participant_connect_approval.rs"]
mod approval;
#[path = "participant_connect_install.rs"]
mod install;
pub use approval::AuthorizationRequest;
pub use approval::deserialize_input as deserialize_authorization_input;
pub use install::Installation;
#[path = "participant_connect_host.rs"]
mod host;
pub use host::{HostInvocation, HostSelection};
#[path = "participant_connect_bootstrap.rs"]
mod bootstrap;
pub use bootstrap::RuntimeSelection;
#[path = "participant_connect_codex.rs"]
mod codex;
#[path = "participant_connect_discovery.rs"]
mod discovery;
pub use discovery::Discovery;

fn local(code: &str) -> ParticipantError {
    ParticipantError::local(code, "CONNECT")
}
fn token(s: &str) -> bool {
    crate::workspace_urls::token(s)
}
fn stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_millis() as u64)
        .unwrap_or(0)
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub origin: String,
    pub actor_id: String,
    pub endpoint_path: PathBuf,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSelection {
    pub alias: String,
    pub instance_id: String,
    pub role: String,
    #[serde(default)]
    pub actions: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContactSelection {
    pub alias: String,
    pub actor_id: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectRequest {
    #[serde(default)]
    pub setup_id: String,
    #[serde(default)]
    pub participant: String,
    pub workspace_id: String,
    #[serde(default = "default_alias")]
    pub alias: String,
    #[serde(default = "default_send")]
    pub send: bool,
    #[serde(default)]
    pub receive: bool,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub receive_mode: Option<ReceiveMode>,
    #[serde(default)]
    pub require_body_keys: bool,
    #[serde(default,skip_serializing_if="is_false")]
    pub request_membership: bool,
    #[serde(default)]
    pub protocols: Vec<ProtocolSelection>,
    /// Explicit local management views, never a request for remote grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub management: Vec<String>,
    #[serde(default)]
    pub contacts: Vec<ContactSelection>,
    #[serde(default)]
    pub host: Option<String>,
}
#[derive(Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum ReceiveMode { Push, Inbox }
fn missing_runtime_features(caps: &Value) -> Vec<&'static str> {
    crate::communication_runtime::CONNECT_FEATURES
        .into_iter()
        .filter(|wanted| {
            !caps["features"]
                .as_array()
                .is_some_and(|xs| xs.iter().any(|v| v == wanted))
        })
        .collect()
}
fn default_alias() -> String {
    "workspace".into()
}
fn default_send() -> bool { false }
fn is_false(value:&bool)->bool{!*value}
impl ConnectRequest {
    fn needs_host(&self,agent:bool)->bool {(agent||self.receive_mode==Some(ReceiveMode::Push)) && self.receive_mode!=Some(ReceiveMode::Inbox)}
    pub fn validate(&self) -> Result<()> {
        if !identifier(&self.setup_id)
            || !identifier(&self.participant)
            || !identifier(&self.alias)
            || !token(&self.workspace_id)
            || self.protocols.len() > 8
            || self.management.len() > 32
            || self.contacts.len() > 64
            || (self.receive_mode.is_some() && !self.receive)
            || (self.receive_mode==Some(ReceiveMode::Inbox) && self.host.is_some())
            || self
                .host
                .as_ref()
                .is_some_and(|h| !identifier(h) || !self.receive)
        {
            return Err(local("CONNECT_ARGUMENT_INVALID"));
        }
        crate::agent_tools::management::workspace_actions(&self.management)?;
        let mut aliases = std::collections::BTreeSet::new();
        for p in &self.protocols {
            if !identifier(&p.alias)
                || !aliases.insert(&p.alias)
                || !token(&p.instance_id)
                || p.role.is_empty()
                || p.role.len() > 128
                || p.actions.len() > 64
                || p.actions.iter().any(|s| s.is_empty() || s.len() > 128)
            {
                return Err(local("CONNECT_PROTOCOL_SELECTION_INVALID"));
            }
        }
        let mut aliases = std::collections::BTreeSet::new();
        if self
            .contacts
            .iter()
            .any(|c| !identifier(&c.alias) || !token(&c.actor_id) || !aliases.insert(&c.alias))
        {
            return Err(local("CONNECT_CONTACT_SELECTION_INVALID"));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    desired: ConnectRequest,
    registration: Registration,
    digest: String,
    profile: Option<AgentProfile>,
    result: Value,
    #[serde(default)]
    key_request: Option<Value>,
    #[serde(default)]
    key_request_history: Vec<Value>,
    #[serde(default)]
    effective_host: Option<String>,
    #[serde(default)]
    channel_send: bool,
    #[serde(default)]
    channel_receive: bool,
    #[serde(default)]
    sender_capability: Option<Capability>,
    #[serde(default)]
    agent_host_required: bool,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    #[serde(default)]
    codex_attachments: BTreeMap<String, codex::Attachment>,
    participants: BTreeMap<String, Registration>,
    setups: BTreeMap<String, Setup>,
    active: Option<String>,
    #[serde(default)]
    active_by_scope: BTreeMap<String, String>,
    #[serde(default)]
    approvals: BTreeMap<String, approval::Approval>,
    #[serde(default)]
    installations: BTreeMap<String, install::Installed>,
    #[serde(default)]
    hosts: BTreeMap<String, HostSelection>,
    #[serde(default)]
    local_runtime_admins: BTreeMap<String, PathBuf>,
    #[serde(default)]
    trusted_projects: Vec<PathBuf>,
    #[serde(default,skip_serializing_if="BTreeMap::is_empty")]
    trusted_project_identities:BTreeMap<PathBuf,Value>,
    #[serde(default)]
    sources: BTreeMap<String, discovery::Source>,
    #[serde(default)]
    verified_bindings: BTreeMap<String, Value>,
    #[serde(default)]
    project_target: Option<discovery::ProjectTarget>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    project_identity: Option<Value>,
}
pub struct Connect {
    directory: PathBuf,
    private_directory:crate::onboarding_project::Directory,
    store: Option<crate::onboarding_store::Store>,
    registry: Registry,
    #[cfg(test)]
    interrupt_after_admission: bool,
}
fn receiving_self_test(receiver:&Value,push:bool)->Value {
    let linked=receiver["receiver_link_verified"]==true
        && receiver["state"]=="RECEIVER_LINK_VERIFIED"
        && receiver["verification_failure"].is_null();
    let presence=&receiver["presence"];
    let keys=presence["key_current"]==true&&matches!(presence["body_key"]["state"].as_str(),Some("READY"|"NOT_REQUIRED"));
    let host=presence["host_current"]==true&&presence["host"]["ready"]==true&&presence["host"]["mode"]=="LIVE";
    let code=if !linked{receiver["code"].as_str().unwrap_or("RECEIVER_NOT_VERIFIED")}else if push&&!keys{"BODY_KEYS_NOT_READY"}else if push&&!host{"HOST_LIVE_DELIVERY_NOT_READY"}else{"READY"};
    json!({"state":if linked&&(!push||(host&&keys)){"READY"}else{"PENDING"},"code":code,"receiver_link_verified":linked,
        "host_required":push,"host_ready":host,"body_keys_ready":keys,"presence":presence,
        "basis":"CURRENT_LOCAL_RUNTIME_OBSERVATION","model_response":"NOT_ATTESTED"})
}
fn receiving_observation(observed:&Value)->Value {
    json!({"state":observed["state"],"code":observed["code"],"verification_failure":observed["verification_failure"],"presence":observed["presence"],"receiver_link_verified":observed["receiver_link_verified"],"checkpoint":observed["checkpoint"],"model_response":"NOT_ATTESTED"})
}
impl Connect {
    pub fn selection_required(setup_id: &str) -> Value {
        json!({"state":"PENDING","setup_id":setup_id,"blocker":{"stage":"LOCAL_SELECTION","code":"LOCAL_SELECTION_REQUIRED","next_actor":"LOCAL_RUNTIME_OWNER","next_action":"RUN_NATIVE_CONNECT_WITH_AUTHORIZED_PROJECT_CONTEXT"}})
    }
    /// One local OS-owner confirmation for an existing private registry. No signer or remote operation is opened.
    pub fn confirm_original(directory:&Path)->Result<Value>{discovery::confirm_original_store(directory)?;Ok(Self::inspect(directory)?.context())}
    pub fn open(directory: &Path) -> Result<Self> {
        let (store,private_directory) = discovery::open_original_store(directory)?;
        let registry: Registry = match store
            .read_exact()
            .map_err(|_| local("CONNECT_RECOVERY_REQUIRED"))?
        {
            None => {
                if std::fs::symlink_metadata(directory.join("initialized.json")).is_ok() {
                    return Err(local("CONNECT_ORIGINAL_BINDING_RECOVERY_REQUIRED"));
                }
                Registry::default()
            }
            Some(wire) => serde_json::from_value(
                peerwork_core::strict_json::parse_strict_json(&wire)
                    .map_err(|_| local("CONNECT_RECOVERY_REQUIRED"))?,
            )
            .map_err(|_| local("CONNECT_RECOVERY_REQUIRED"))?,
        };
        if registry.participants.len() > 8
            || registry.setups.len() > 64 || registry.codex_attachments.len() > 64
            || registry.approvals.len() > 64
            || registry.sources.len() > 8 || registry.trusted_projects.len() > 8 || registry.trusted_project_identities.len()>8 || registry.verified_bindings.len() > 8
        {
            return Err(local("CONNECT_RECOVERY_REQUIRED"));
        }
        Ok(Self {
            directory: directory.into(),
            private_directory,
            store: Some(store),
            registry,
            #[cfg(test)]
            interrupt_after_admission: false,
        })
    }
    /// Atomic, bounded read of the selected local registry. Normal tools must
    /// remain available while a setup job awaits its remote/local prerequisites.
    pub fn inspect(directory: &Path) -> Result<Self> {
        let (registry,private_directory)=discovery::inspect_original_store(directory)?;
        Ok(Self{directory:directory.into(),private_directory,store:None,registry,#[cfg(test)] interrupt_after_admission:false})
    }
    fn require_writer(&self) -> Result<()> {
        if self.store.is_some() {
            Ok(())
        } else {
            Err(local("CONNECT_READ_ONLY_VIEW"))
        }
    }
    fn save(&self) -> Result<()> {
        self.store
            .as_ref()
            .ok_or_else(|| local("CONNECT_READ_ONLY_VIEW"))?
            .write_exact(
                &serde_json::to_vec(&self.registry).map_err(|_| local("CONNECT_STATE_INVALID"))?,
            )
            .map_err(|_| local("CONNECT_STATE_WRITE_FAILED"))?;
        let expected=json!({"format":"peerwork.connect-initialized.v1"});
        match self.private_directory.read("initialized.json",1024,true)? {
            Some(bytes) if peerwork_core::strict_json::parse_strict_json(&bytes).ok().as_ref()!=Some(&expected)=>return Err(local("CONNECT_BINDING_MARKER_INVALID")),
            Some(_)=>(),None=>self.private_directory.replace_private("initialized.json",None,expected.to_string().as_bytes())?,
        }
        Ok(())
    }
    /// CLI/local-owner bootstrap only. MCP cannot select new paths or identities.
    pub async fn register(&mut self, name: &str, selected: Registration) -> Result<Value> {
        self.register_pinned(name, selected, None, None).await
    }
    pub(super) async fn register_pinned(&mut self, name: &str, mut selected: Registration, expected:Option<Value>, owned_admin:Option<PathBuf>) -> Result<Value> {
        self.require_writer()?;
        if !identifier(name) || !token(&selected.actor_id) || !selected.endpoint_path.is_absolute()
        {
            return Err(local("LOCAL_SELECTION_INVALID"));
        }
        let origin = crate::transport::canonical_lifecycle_origin(&selected.origin, true)
            .map_err(|_| local("LOCAL_SELECTION_INVALID"))?;
        selected.origin = origin.clone();
        let expected=expected.or_else(||self.registry.verified_bindings.get(name).cloned());
        let client=match expected {
            Some(binding)=>RuntimeClient::connect_bound(selected.endpoint_path.clone(), &origin, &selected.actor_id,binding).await?,
            None=>RuntimeClient::connect(selected.endpoint_path.clone(), &origin, &selected.actor_id).await?,
        };
        let observed=client.call(json!({"method":"binding"})).await.map_err(|_|local("LOCAL_RUNTIME_UPGRADE_REQUIRED"))?;
        crate::communication_runtime::validate_binding(&observed,&origin,&selected.actor_id)?;
        let observed=crate::communication_runtime::canonical_binding(&observed);
        let changed=self.registry.verified_bindings.get(name)!=Some(&observed) || !self.registry.participants.contains_key(name)
            || owned_admin.as_ref().is_some_and(|admin|self.registry.local_runtime_admins.get(name)!=Some(admin));
        if let Some(old) = self.registry.participants.get(name) {
            if old != &selected {
                return Err(local("LOCAL_BINDING_CONFLICT"));
            }
        } else {
            if self.registry.participants.len() >= 8 {
                return Err(local("LOCAL_PARTICIPANT_LIMIT"));
            }
            self.registry.participants.insert(name.into(), selected);
        }
        // Registration and its verification fact are one recoverable commit.
        self.registry.verified_bindings.insert(name.into(),observed);
        if let Some(admin)=owned_admin {self.registry.local_runtime_admins.insert(name.into(),admin);}
        if changed { self.save()?; }
        Ok(self.context())
    }
    pub fn context(&self) -> Value {
        json!({"state":if self.registry.participants.is_empty(){"NOT_CONFIGURED"}else{"LOCAL_SELECTION_REGISTERED"},
            "discovery":self.discovery_summary(),
            "participants":self.registry.participants.iter().map(|(handle,r)|json!({"handle":handle,"actor_id":r.actor_id,"origin":r.origin})).collect::<Vec<_>>(),
            "active_setup_id":self.registry.active,"setups":self.registry.setups.iter().map(|(id,s)|json!({"setup_id":id,"participant":s.desired.participant,"workspace_id":s.desired.workspace_id,"protocol_roles":s.desired.protocols,"state":s.result["state"],"blocker":s.result["blocker"]})).collect::<Vec<_>>(),
            "next_tool":"peerwork_connect","remote_or_host_readiness":"NOT_ATTESTED"})
    }
    pub fn context_for(&self, participant: Option<&str>, workspace: Option<&str>) -> Value {
        let mut value = self.context();
        if let Some(items) = value["participants"].as_array_mut() {
            items.retain(|p| participant.is_none_or(|h| p["handle"] == h));
        }
        if let Some(items) = value["setups"].as_array_mut() {
            items.retain(|s| {
                participant.is_none_or(|h| s["participant"] == h)
                    && workspace.is_none_or(|ws| s["workspace_id"] == ws)
            });
        }
        if !value["setups"]
            .as_array()
            .is_some_and(|xs| xs.iter().any(|s| s["setup_id"] == value["active_setup_id"]))
        {
            value["active_setup_id"] = Value::Null;
        }
        value
    }
    pub fn profile(&self) -> Result<Option<AgentProfile>> {
        self.profile_for(None)
    }
    pub fn selected_handle(&self, explicit: Option<&str>) -> Result<Option<String>> {
        if let Some(handle) = explicit {
            if !self.registry.participants.contains_key(handle) {
                return Err(local("LOCAL_SELECTION_REQUIRED"));
            }
            return Ok(Some(handle.into()));
        }
        match self.registry.participants.len() {
            0 => Ok(None),
            1 => Ok(self.registry.participants.keys().next().cloned()),
            _ => Err(local("MULTIPLE_IDENTITIES_SELECT_FRONTEND_PARTICIPANT")),
        }
    }
    pub fn profile_for(&self, participant: Option<&str>) -> Result<Option<AgentProfile>> {
        self.profile_for_scope(participant, None)
    }
    pub fn profile_for_scope(
        &self,
        participant: Option<&str>,
        workspace: Option<&str>,
    ) -> Result<Option<AgentProfile>> {
        let Some(handle) = self.selected_handle(participant)? else {
            return Ok(None);
        };
        let ids: Vec<_> = self
            .registry
            .active_by_scope
            .values()
            .filter(|id| {
                self.registry.setups.get(*id).is_some_and(|s| {
                    s.desired.participant == handle
                        && workspace.is_none_or(|ws| s.desired.workspace_id == ws)
                })
            })
            .collect();
        let id = match ids.as_slice() {
            [] => return Ok(None),
            [id] => *id,
            _ => return Err(local("MULTIPLE_WORKSPACES_SELECT_FRONTEND_WORKSPACE")),
        };
        let setup = self
            .registry
            .setups
            .get(id)
            .ok_or_else(|| local("BROKEN_BINDING"))?;
        if setup.desired.participant != handle {
            return Err(local("BROKEN_BINDING"));
        }
        let Some(profile) = &setup.profile else {
            return Ok(None);
        };
        self.ensure_profile(id, profile)?;
        Ok(Some(profile.clone()))
    }
    fn ensure_profile(&self, id: &str, profile: &AgentProfile) -> Result<PathBuf> {
        profile.validate()?;
        let partial = self.registry.setups.get(id).is_some_and(|s|
            s.agent_host_required && s.desired.receive && !s.channel_receive);
        let suffix = if partial { "-tools" } else { "" };
        let path = self.directory.join(format!("profile-{id}{suffix}.json"));
        let name=format!("profile-{id}{suffix}.json");
        match self.private_directory.read(&name,512*1024,true)? {
            Some(bytes)=>{
                let old:AgentProfile=serde_json::from_value(peerwork_core::strict_json::parse_strict_json(&bytes).map_err(|_|local("DERIVED_PROFILE_INVALID"))?).map_err(|_|local("DERIVED_PROFILE_INVALID"))?;
                old.validate()?;
                if serde_json::to_value(&old).ok()!=serde_json::to_value(profile).ok(){return Err(local("DERIVED_PROFILE_CONFLICT"))}
            },
            None=>self.private_directory.replace_private(&name,None,&serde_json::to_vec(profile).map_err(|_|local("DERIVED_PROFILE_INVALID"))?)?,
        }
        Ok(path)
    }
    fn record(
        &mut self,
        request: &ConnectRequest,
        result: Value,
        profile: Option<AgentProfile>,
    ) -> Result<Value> {
        let old = self
            .registry
            .setups
            .get_mut(&request.setup_id)
            .ok_or_else(|| local("CONNECT_STATE_INVALID"))?;
        if old.result != result || (old.profile.is_none() && profile.is_some()) {
            old.result = result.clone();
            if profile.is_some() {
                old.profile = profile;
            }
            self.save()?;
        }
        Ok(result)
    }
    fn pending(
        &mut self,
        r: &ConnectRequest,
        stage: &str,
        code: &str,
        actor: &str,
        action: &str,
        details: Value,
    ) -> Result<Value> {
        self.record(r, json!({"state":"PENDING","setup_id":r.setup_id,
            "blocker":{"stage":stage,"code":code,"affected_scope":{"workspace_id":r.workspace_id},"next_actor":actor,"next_action":action},
            "details":details,"existing_configuration_preserved":true}), None)
    }
    fn begin_setup(&mut self, request:&ConnectRequest, registration:Registration, agent:bool, effective_host:Option<String>)->Result<()> {
        if self.registry.setups.len()>=64 {return Err(local("SETUP_LIMIT"));}
        let digest=sha256_hex(serde_json::to_vec(request).map_err(|_|local("CONNECT_ARGUMENT_INVALID"))?.as_slice());
        self.registry.setups.insert(request.setup_id.clone(),Setup {desired:request.clone(),registration,digest,
            profile:None,key_request:None,key_request_history:vec![],effective_host,channel_send:false,channel_receive:false,
            sender_capability:None,agent_host_required:agent,result:json!({"state":"PENDING","setup_id":request.setup_id})});
        self.save()
    }
    /// Local-owner attachment to a verified existing endpoint. No discovery reads,
    /// grant requests, engine replacement or operation namespace derivation.
    pub async fn attach(&mut self, participant:&str, workspace:&str, alias:&str, protocols:BTreeMap<String,Scope>)->Result<Value>{
        self.require_writer()?;
        let selected=self.registry.participants.get(participant).cloned().ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        self.original_client(participant).await?;
        let profile=AgentProfile{ management_views: Default::default(),format:"peerwork.agent-profile.v1".into(),endpoint_path:selected.endpoint_path.clone(),
            expected_origin:selected.origin.clone(),expected_actor:selected.actor_id.clone(),workspaces:[(alias.into(),workspace.into())].into(),
            protocols,protocol_endpoints:Default::default(),directory_endpoints:Default::default(),scopes:Default::default(),
            contacts:Default::default(),send_scopes:Default::default(),receive_endpoint_path:None};
        profile.validate()?;
        if profile.protocols.values().any(|p|p.workspace_id.as_deref()!=Some(workspace)){return Err(local("ATTACH_SCOPE_INVALID"));}
        let setup_id=format!("attach-{}",&sha256_hex(serde_json::to_vec(&profile).map_err(|_|local("AGENT_PROFILE_INVALID"))?.as_slice())[..32]);
        let request=ConnectRequest{ management: Vec::new(),setup_id:setup_id.clone(),participant:participant.into(),workspace_id:workspace.into(),alias:alias.into(),
            send:false,receive:false,receive_mode:None,require_body_keys:false,request_membership:false,protocols:vec![],contacts:vec![],host:None};
        request.validate()?;
        let key=format!("{participant}:{workspace}");
        if self.registry.active_by_scope.get(&key).is_some_and(|old|old!=&setup_id){return Err(local("EXISTING_SETUP_PRESERVED_USE_ITS_PROFILE"));}
        if !self.registry.setups.contains_key(&setup_id){self.begin_setup(&request,selected,false,None)?;}
        let result=json!({"state":"LOCAL_ATTACHED","setup_id":setup_id,"remote_permissions":"CHECKED_PER_TOOL_CALL", "identity_and_operation_namespace":"ORIGINAL", "receiver":"NOT_REQUESTED", "host_tools":"CONFIGURATION_ONLY_REFRESH_HOST_THEN_CALL_CONTEXT"});
        self.record(&request,result.clone(),Some(profile.clone()))?;
        self.ensure_profile(&setup_id,&profile)?;
        self.registry.active_by_scope.insert(key,setup_id.clone());self.registry.active=Some(setup_id);self.save()?;
        Ok(result)
    }
    pub async fn run(&mut self, request: ConnectRequest) -> Result<Value> {
        self.run_mode(request, false).await
    }
    /// Agent entry must never activate a program receiver while its requested
    /// host is unknown. Named existing destinations remain named, not evidence
    /// that the invoking model session is that destination.
    pub async fn run_agent(&mut self, request: ConnectRequest) -> Result<Value> {
        self.run_mode(request, true).await
    }
    async fn run_mode(&mut self, request: ConnectRequest, agent: bool) -> Result<Value> {
        self.require_writer()?;
        let request = if agent {self.normalize_agent_request(request)?} else {self.normalize_request(request)?};
        let agent=request.needs_host(agent);
        let selected = match self.registry.participants.get(&request.participant) {
            Some(v) => v.clone(),
            None => return Ok(Self::selection_required(&request.setup_id)),
        };
        let digest = sha256_hex(
            serde_json::to_vec(&request)
                .map_err(|_| local("CONNECT_ARGUMENT_INVALID"))?
                .as_slice(),
        );
        if let Some(old) = self.registry.setups.get(&request.setup_id) {
            if old.digest != digest || old.registration != selected {
                return Err(local("SETUP_ID_CONFLICT_RESUME_ORIGINAL"));
            }
            if old.result["blocker"]["code"] == "HOST_CONTEXT_REQUIRED"
                && old.effective_host.is_none() && request.host.is_none() {
                if let Some(profile) = &old.profile {
                    self.original_client(&request.participant).await?;
                    self.ensure_profile(&request.setup_id, profile)?;
                    let mut result = old.result.clone();
                    result["observation"] = json!("CACHED_SETUP_RESULT_HOST_CONTEXT_STILL_REQUIRED");
                    return Ok(result);
                }
            }
            if agent && request.receive && !old.agent_host_required && old.channel_receive && old.effective_host.is_none() {
                return Err(local("EXISTING_PROGRAM_RECEIVER_REQUIRES_EXPLICIT_REBIND"));
            }
            if old.result["state"] == "LOCAL_CONFIGURED" {
                if old.effective_host.is_none()&&old.channel_receive {
                    if let Some(profile)=&old.profile {
                        if let Some(endpoint)=&profile.receive_endpoint_path {
                            if let Ok(receiver)=RuntimeClient::connect(endpoint.clone(),&profile.expected_origin,&profile.expected_actor).await {
                                let bindings=receiver.call(json!({"method":"bindings"})).await?;
                                if bindings.as_array().is_some_and(|items|items.iter().any(|w|w["workspace_id"]==request.workspace_id&&w["host_destination"].is_string()&&profile.scopes.values().any(|s|w["mailbox_id"]==s.mailbox_id&&w["membership_id"]==s.membership_id))) {
                                    return self.pending(&request,"HOST_BINDING","EXISTING_PUSH_RECEIVER_REQUIRES_EXPLICIT_REBIND","HOST_USER","EXPLICIT_NATIVE_REBIND",json!({"existing_receiver_preserved":true}));
                                }
                            }
                        }
                    }
                }
                if let Some(profile) = &old.profile {
                    self.original_client(&request.participant).await?;
                    self.ensure_profile(&request.setup_id, profile)?;
                    let sender_ready = RuntimeClient::connect(
                        profile.endpoint_path.clone(),
                        &profile.expected_origin,
                        &profile.expected_actor,
                    )
                    .await
                    .is_ok();
                    let receiver_ready = match &profile.receive_endpoint_path {
                        Some(path) => RuntimeClient::connect(
                            path.clone(),
                            &profile.expected_origin,
                            &profile.expected_actor,
                        )
                        .await
                        .is_ok(),
                        None => true,
                    };
                    if sender_ready && receiver_ready {
                        let mut result = old.result.clone();
                        if request.receive&&old.channel_receive {
                            if let Some(endpoint)=&profile.receive_endpoint_path {
                                let receiver=RuntimeClient::connect(endpoint.clone(),&profile.expected_origin,&profile.expected_actor).await?;
                                let bindings=receiver.call(json!({"method":"bindings"})).await?;
                                let matched=bindings.as_array().and_then(|items|items.iter().find(|w|w["workspace_id"]==request.workspace_id&&profile.scopes.values().any(|s|w["mailbox_id"]==s.mailbox_id&&w["membership_id"]==s.membership_id)));
                                if old.effective_host.is_some() {
                                    let selected=if let Some(watch)=matched{self.completed_host_binding(&request,old,watch).await?.is_some()}else{false};
                                    if !selected {
                                        return Ok(json!({"state":"PENDING","setup_id":request.setup_id,"tools_available":true,
                                            "blocker":{"stage":"HOST_BINDING","code":"HOST_SELECTION_CHANGED_REBIND_REQUIRED","next_actor":"HOST_USER","next_action":"REVIEW_SELECTED_HOST_BINDING"},
                                            "existing_configuration_preserved":true,"existing_receiver_preserved":true}));
                                    }
                                }
                                let observed=if let Some(options)=matched{receiver.call(json!({"method":"inbox","options":options,"after":0,"limit":1})).await?}else{json!({"state":"NOT_STARTED","receiver_link_verified":false})};
                                let observed=receiving_observation(&observed);
                                let self_test=receiving_self_test(&observed,old.effective_host.is_some());
                                if self_test["state"]!="READY" {
                                    return self.record(&request,json!({"state":"PENDING","setup_id":request.setup_id,"tools_available":true,
                                        "blocker":{"stage":"RECEIVING_SELF_TEST","code":self_test["code"],"next_actor":"RUNTIME","next_action":"INSPECT_RECEIVING_BLOCKER_OR_RESUME_SAME_SETUP"},
                                        "receiver":observed,"self_test":self_test,"owner_exchange_required":false}),Some(profile.clone()));
                                }
                                result["receiver"]=observed;result["self_test"]=self_test;
                            }
                        }
                        result["observation"] =
                            json!("CACHED_SETUP_RESULT_USE_REACHABILITY_FOR_CURRENT_STATE");
                        return Ok(result);
                    }
                }
            }
        } else {
            self.begin_setup(&request, selected.clone(), agent, None)?;
        }
        if agent && !self.registry.setups[&request.setup_id].agent_host_required {
            self.registry.setups.get_mut(&request.setup_id).unwrap().agent_host_required = true;
            self.save()?;
        }
        let client = match self.original_client(&request.participant).await
        {
            Ok(c) => c,
            Err(e) => {
                return self.pending(
                    &request,
                    "LOCAL_RUNTIME",
                    &e.code,
                    "LOCAL_RUNTIME_OWNER",
                    "RESTORE_SELECTED_RUNTIME",
                    json!({"recovery":e.recovery}),
                )
            }
        };
        self.verify_registered(&request.participant, &client).await?;
        let caps = client.call(json!({"method":"capabilities"})).await?;
        let missing_features = missing_runtime_features(&caps);
        if !missing_features.is_empty() {
            return self.pending(
                &request,
                "LOCAL_RUNTIME",
                "LOCAL_RUNTIME_UPGRADE_REQUIRED",
                "LOCAL_RUNTIME_OWNER",
                "UPGRADE_SELECTED_RUNTIME_PRESERVING_ORIGINAL_STATE",
                json!({"missing_features":missing_features,"remote_changes_submitted":false}),
            );
        }
        let parent: Capability = serde_json::from_value(caps["capability"].clone()).map_err(|_| local("LOCAL_CEILING_INVALID"))?;
        let management_actions=crate::agent_tools::management::workspace_actions(&request.management)?;
        let missing_management:Vec<_>=management_actions.difference(&parent.operations).cloned().collect();
        if !missing_management.is_empty() {
            let mut error=local("LOCAL_SCOPE_DENIED");error.phase="AUTHORIZATION".into();error.recovery="REVIEW_EXPLICIT_LOCAL_CAPABILITY".into();
            error.details=Some(json!({"missing_operations":missing_management,"next_actor":"LOCAL_RUNTIME_OWNER","remote_permission_checked":false,"remote_grants_changed":false}));return Err(error);
        }
        let communication_requested=request.send||request.receive||!request.contacts.is_empty();
        let mut required=vec!["structure.workspace.get"];
        if communication_requested||request.require_body_keys{required.push("participant.time.read");}
        if communication_requested{required.push("structure.communication.grant.get");}
        if request.receive{required.push("structure.mailboxes.read");}
        if !request.protocols.is_empty(){required.extend(["structure.instance.resolve","structure.protocol.resolve","structure.grant.get"]);}
        if request.send{required.push("structure.message.send");}
        let missing=required.into_iter().filter(|action|!parent.operations.contains(*action)).collect::<Vec<_>>();
        let probe=Invoke::new("connect-local-preflight","structure.workspace.get",Scope{workspace_id:Some(request.workspace_id.clone()),..Default::default()},json!({}));
        let denied=parent.authorize(&probe).err();
        if !missing.is_empty()||denied.is_some(){
            let mut error=denied.unwrap_or_else(||local("LOCAL_SCOPE_DENIED"));error.phase="AUTHORIZATION".into();error.recovery="REVIEW_EXPLICIT_LOCAL_CAPABILITY".into();
            let mut details=error.details.take().unwrap_or(json!({}));details["missing_operations"]=json!(missing);details["next_actor"]=json!("LOCAL_RUNTIME_OWNER");details["remote_permission_checked"]=json!(false);error.details=Some(details);return Err(error);
        }
        let scope = Scope {
            workspace_id: Some(request.workspace_id.clone()),
            ..Scope::default()
        };
        let now = if communication_requested||request.require_body_keys {trusted_time(&client, &scope).await?} else {0};
        let workspace = match read(&client, "structure.workspace.get", scope.clone(), json!({})).await {
            Ok(value)=>value,
            Err(error) if request.request_membership && (matches!(error.code.as_str(),"FORBIDDEN"|"UNVERIFIED_AUTHORIZATION_RESPONSE") || error.details.as_ref().is_some_and(|d|d["http_status"]==403))=>{
                return self.request_admission(&client,&request,&selected,&scope).await;
            },
            Err(error)=>return Err(error),
        };
        if !token(
            workspace["membership"]["membership_id"]
                .as_str()
                .unwrap_or(""),
        ) {
            if request.request_membership {return self.request_admission(&client,&request,&selected,&scope).await;}
            return self.pending(
                &request,
                "MEMBERSHIP",
                "MEMBERSHIP_REQUIRED",
                "WORKSPACE_OWNER",
                "USE_EXISTING_ADMISSION",
                json!({"observation":workspace}),
            );
        }
        let membership = workspace["membership"]["membership_id"].as_str().unwrap();
        let owner = workspace["owner_id"]
            .as_str()
            .ok_or_else(|| local("WORKSPACE_OBSERVATION_INVALID"))?;
        let grants = if communication_requested {read(
            &client,
            "structure.communication.grant.get",
            scope.clone(),
            json!({}),
        )
        .await?}else{json!({"grant":null})};
        let grant = &grants["grant"];
        let valid = grant["membership_id"] == membership && approval::effective(grant, now);
        let mut missing = Vec::new();
        if request.send && (!valid || grant["can_send"] != true) {
            missing.push(json!({"kind":"COMMUNICATION_SEND"}));
        }
        if request.receive && (!valid || grant["can_receive"] != true) {
            missing.push(json!({"kind":"COMMUNICATION_RECEIVE"}));
        }
        let mut protocols = BTreeMap::new();
        let mut role_actions: BTreeMap<String, std::collections::BTreeSet<String>> =
            BTreeMap::new();
        for p in &request.protocols {
            let resolved = read(
                &client,
                "structure.instance.resolve",
                scope.clone(),
                json!({"instance_id":p.instance_id}),
            )
            .await?;
            let digest = resolved["instance"]["protocol_digest"]
                .as_str()
                .ok_or_else(|| local("PROTOCOL_RESOLUTION_FAILED"))?
                .to_owned();
            let selected_scope = Scope {
                workspace_id: Some(request.workspace_id.clone()),
                instance_id: Some(p.instance_id.clone()),
                protocol_digest: Some(digest),
            };
            let binding = read(
                &client,
                "structure.protocol.resolve",
                selected_scope.clone(),
                json!({"view":"inspect","include_resources":false}),
            )
            .await?;
            if binding["bundle_header"].is_null() {
                return self.pending(
                    &request,
                    "PROTOCOL_BINDING",
                    "PROTOCOL_BUNDLE_NOT_BOUND",
                    "WORKSPACE_OWNER",
                    "BIND_PROTOCOL_BUNDLE",
                    json!({"instance_id":p.instance_id,"observation":binding}),
                );
            }
            {
                let definition = &binding["bundle_header"]["roles"][&p.role];
                if !definition.is_object() {
                    return Err(local("PROTOCOL_ROLE_NOT_FOUND"));
                }
                let declared: std::collections::BTreeSet<String> = definition["tools"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|t| t["action"].as_str().map(str::to_owned))
                    .collect();
                let wanted: std::collections::BTreeSet<String> = if p.actions.is_empty() {
                    declared.clone()
                } else {
                    p.actions.iter().cloned().collect()
                };
                if wanted.len() > 64 || !wanted.is_subset(&declared) {
                    return Err(local("ACTION_NOT_DECLARED_FOR_ROLE"));
                }
                let rights = read(
                    &client,
                    "structure.grant.get",
                    selected_scope.clone(),
                    json!({"actor_id":selected.actor_id}),
                )
                .await?;
                let g = &rights["grant"];
                let granted: std::collections::BTreeSet<String> = g["actions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                if g["effective"] != true
                    || !g["protocol_roles"]
                        .as_array()
                        .is_some_and(|rs| rs.iter().any(|v| v == &p.role))
                    || !wanted.is_subset(&granted)
                {
                    missing.push(json!({"kind":"BUSINESS_ROLE","instance_id":p.instance_id,"protocol_digest":selected_scope.protocol_digest,"role":p.role,"actions":wanted}));
                }
                let actions = wanted.intersection(&granted).cloned().collect();
                role_actions.insert(p.alias.clone(), actions);
            }
            protocols.insert(p.alias.clone(), selected_scope);
        }
        let keys = if request.require_body_keys {
            match read(
                &client,
                "participant.keys.prepare",
                scope.clone(),
                json!({}),
            )
            .await
            {
                Ok(value) if value["state"] == "READY" => value,
                Ok(value) if value["state"] == "OWNER_KEY_HEAD_REQUIRED" => {
                    return self.pending(
                        &request,
                        "CONTENT_KEYS",
                        "OWNER_KEY_HEAD_REQUIRED",
                        owner,
                        "EXPLICITLY_INITIALIZE_WORKSPACE_CONTENT_KEY_HEAD",
                        json!({"keys":value}),
                    )
                }
                Err(error) if error.code == "CONTENT_KEY_MISSING" => json!({"state":"MISSING"}),
                Err(error) => {
                    return self.pending(
                        &request,
                        "CONTENT_KEYS",
                        &error.code,
                        "RUNTIME",
                        "RECOVER_SELECTED_KEY_STATE",
                        json!({"recovery":error.recovery}),
                    )
                }
                Ok(value) => {
                    return self.pending(
                        &request,
                        "CONTENT_KEYS",
                        "KEYS_SYNCHRONIZING",
                        "RUNTIME",
                        "RESUME_SAME_SETUP",
                        json!({"keys":value}),
                    )
                }
            }
        } else {
            json!({"state":"NOT_REQUESTED"})
        };
        let needs_keys = keys["state"] == "MISSING";
        if !missing.is_empty() || needs_keys {
            let key_request = if needs_keys {
                Some(self.key_request(&client, &request, &scope).await?)
            } else {
                None
            };
            let authorization_request=AuthorizationRequest::from_input(json!({"format":"peerwork.connect-authorization-request.v1","setup_id":request.setup_id,
                    "origin":selected.origin,"workspace_id":request.workspace_id,"actor_id":selected.actor_id,"membership_id":membership,
                    "owner_id":owner,"missing":missing,"body_keys_required":needs_keys,"key_request":key_request}))?;
            let code=authorization_request.to_code()?;
            return self.pending(&request,"REMOTE_AUTHORIZATION",if missing.is_empty(){"KEY_AUTHORIZATION_REQUIRED"}else{"OWNER_APPROVAL_REQUIRED"},owner,"APPROVE_REQUESTED_PERMISSION_DELTA",
                json!({"authorization_request":authorization_request,"authorization_code":code,
                    "approval":{"tool":"peerwork_connect_approve","arguments":{"approval_id":format!("approve-{}",&sha256_hex(code.as_bytes())[..24]),"request":code},"add_required":["participant"]},
                    "delivery":"PUBLIC_REQUEST_CODE_OR_OBJECT","request_is_not_authorization":true,"contains_private_keys_or_local_paths":false}));
        }
        let mailboxes = if request.receive {read(
            &client,
            "structure.mailboxes.read",
            scope.clone(),
            json!({"limit":8}),
        )
        .await?}else{json!({"mailboxes":[]})};
        let mailbox = mailboxes["mailboxes"]
            .as_array()
            .and_then(|xs| xs.iter().find(|m| m["name"] == "default"));
        if request.receive && mailbox.is_none() {
            return self.pending(
                &request,
                "MAILBOX",
                "DEFAULT_MAILBOX_REQUIRED",
                "WORKSPACE_OWNER",
                "VERIFY_RECEIVE_GRANT",
                json!({"observation":mailboxes}),
            );
        }
        let mut previous_setup = self
            .registry
            .active_by_scope
            .get(&format!("{}:{}", request.participant, request.workspace_id))
            .and_then(|id| self.registry.setups.get(id))
            .filter(|s| s.registration == selected && s.profile.is_some())
            .or_else(|| {
                self.registry
                    .setups
                    .get(&request.setup_id)
                    .filter(|s| s.profile.is_some())
            })
            .cloned();
        let completed_first=if request.receive && (agent||request.host.is_some()) && previous_setup.as_ref().is_some_and(|s|s.channel_receive) {
            if let Some(mailbox)=mailbox {self.completed_host_binding(&request,previous_setup.as_ref().unwrap(),mailbox).await?}else{None}
        }else{None};
        if let Some(completed)=&completed_first {previous_setup.as_mut().unwrap().effective_host=Some(completed.name.clone());}
        let previous = previous_setup.as_ref().and_then(|s| s.profile.clone());
        let mut management_views=previous.as_ref().map(|p|p.management_views.clone()).unwrap_or_default();
        let management_capability=if management_actions.is_empty(){None}else{
            let mut cap=parent.clone();cap.allow_root=false;cap.workspace_ids=Some([request.workspace_id.clone()].into());cap.operations=management_actions;
            Some(cap)
        };
        let management_id=management_capability.as_ref().map(|cap|format!("management-{}",&sha256_hex(json!([request.participant,request.workspace_id,cap]).to_string().as_bytes())[..40]));
        if management_id.as_ref().is_some_and(|id|!management_views.contains_key(id))&&management_views.len()>=crate::agent_tools::MAX_MANAGEMENT_VIEWS {
            return Err(local("MANAGEMENT_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));
        }
        if request.receive_mode==Some(ReceiveMode::Inbox) && previous_setup.as_ref().is_some_and(|s|s.channel_receive&&s.effective_host.is_some()) {
            return self.pending(&request,"HOST_BINDING","EXISTING_PUSH_RECEIVER_REQUIRES_EXPLICIT_REBIND","HOST_USER","EXPLICIT_NATIVE_REBIND",json!({"existing_receiver_preserved":true}));
        }
        if (agent || self.registry.setups[&request.setup_id].agent_host_required)
            && request.receive && previous_setup.as_ref().is_some_and(|s|s.channel_receive && s.effective_host.is_none()) {
            return self.pending(&request,"HOST_BINDING",if previous_setup.as_ref().is_some_and(|s|s.desired.receive_mode==Some(ReceiveMode::Inbox)){"EXISTING_INBOX_RECEIVER_REQUIRES_EXPLICIT_REBIND"}else{"EXISTING_PROGRAM_RECEIVER_REQUIRES_EXPLICIT_REBIND"},"HOST_USER","EXPLICIT_NATIVE_REBIND",json!({"existing_receiver_preserved":true}));
        }
        let channel_send = request.send
            || previous_setup
                .as_ref()
                .is_some_and(|s| s.channel_send || s.desired.send);
        let wanted_receive = request.receive
            || previous_setup
                .as_ref()
                .is_some_and(|s| s.channel_receive);
        let old_host = previous_setup
            .as_ref()
            .and_then(|s| s.effective_host.clone().or_else(|| s.desired.host.clone()));
        if request
            .host
            .as_ref()
            .is_some_and(|wanted| old_host.as_ref() != Some(wanted))
            && previous_setup
                .as_ref()
                .is_some_and(|s| s.channel_receive)
        {
            return self.pending(
                &request,
                "HOST_BINDING",
                "HOST_SELECTION_CHANGED_REBIND_REQUIRED",
                "HOST_USER",
                "EXPLICIT_NATIVE_REBIND",
                json!({}),
            );
        }
        let effective_host = if request.receive_mode==Some(ReceiveMode::Inbox){None}else{request.host.clone().or_else(||self.registry.setups[&request.setup_id].effective_host.clone())
            .or_else(||if request.receive && (agent || self.registry.setups[&request.setup_id].agent_host_required) {None} else {old_host.clone()})};
        let host_pending = (agent || self.registry.setups[&request.setup_id].agent_host_required)
            && request.receive && effective_host.is_none();
        let channel_receive = wanted_receive && !host_pending;
        if request.receive && (agent || self.registry.setups[&request.setup_id].agent_host_required)
            && previous_setup.as_ref().is_some_and(|s|s.channel_receive)
            && effective_host!=old_host {
            return self.pending(&request,"HOST_BINDING",if effective_host.is_none(){"HOST_CONTEXT_REQUIRED"}else{"HOST_SELECTION_CHANGED_REBIND_REQUIRED"},
                "HOST_USER",if effective_host.is_none(){"ENABLE_SUPPORTED_CURRENT_SESSION_INTEGRATION_OR_SELECT_NAMED_DESTINATION"}else{"EXPLICIT_NATIVE_REBIND"},
                json!({"existing_named_receiver_preserved":true,"current_session":"NOT_ATTESTED","tools_available":previous.is_some()}));
        }
        if effective_host
            .as_ref()
            .is_some_and(|name| !self.registry.hosts.contains_key(name))
        {
            return self.pending(
                &request,
                "HOST_BINDING",
                "HOST_BINDING_REQUIRED",
                "HOST_USER",
                "SELECT_SUPPORTED_HOST_OR_REGISTER_EXISTING_HANDLE",
                json!({"host":effective_host}),
            );
        }
        if let Some(old) = &previous {
            for (name, s) in &old.protocols {
                if protocols.get(name).is_some_and(|wanted| wanted != s) {
                    return Err(local("PROTOCOL_ALIAS_CONFLICT"));
                }
                protocols.entry(name.clone()).or_insert_with(|| s.clone());
            }
        }
        let mut protocol_endpoints = previous
            .as_ref()
            .map(|p| p.protocol_endpoints.clone())
            .unwrap_or_default();
        for p in &request.protocols {
            let selected_scope = &protocols[&p.alias];
            let mut cap = parent.clone();
            cap.allow_root = false;
            cap.workspace_ids = Some([request.workspace_id.clone()].into());
            cap.instance_ids = Some([p.instance_id.clone()].into());
            cap.protocol_digests = Some([selected_scope.protocol_digest.clone().unwrap()].into());
            cap.mailbox_ids = Some(Default::default());
            cap.operations.retain(|s| {
                [
                    "structure.action",
                    "structure.instance.get",
                    "structure.protocol.resolve",
                    "structure.protocol.resource.get",
                    "structure.record.get",
                    "structure.records.read",
                ]
                .contains(&s.as_str())
            });
            {
                cap.business_actions = Some(
                    role_actions[&p.alias]
                        .iter()
                        .filter(|s| {
                            parent
                                .business_actions
                                .as_ref()
                                .is_none_or(|a| a.contains(*s))
                        })
                        .cloned()
                        .collect(),
                );
            }
            let alias = format!(
                "role-{}",
                &sha256_hex(
                    json!([
                        request.participant,
                        request.workspace_id,
                        p.alias,
                        p.instance_id,
                        p.role,
                        p.actions
                    ])
                    .to_string()
                    .as_bytes()
                )[..40]
            );
            let derived = client
                .call(json!({"method":"derive","name":alias,"capability":cap}))
                .await?;
            protocol_endpoints.insert(
                p.alias.clone(),
                PathBuf::from(
                    derived["endpoint_path"]
                        .as_str()
                        .ok_or_else(|| local("DERIVED_ENDPOINT_INVALID"))?,
                ),
            );
        }
        let mut directory_endpoints=previous.as_ref().map(|p|p.directory_endpoints.clone()).unwrap_or_default();
        if let (Some(id),Some(capability))=(management_id,management_capability) {
            let derived=client.call(json!({"method":"derive","name":id,"capability":capability})).await?;
            let endpoint_path=PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?);
            let manager=RuntimeClient::connect(endpoint_path.clone(),&selected.origin,&selected.actor_id).await?;
            let observed=manager.call(json!({"method":"binding"})).await?;
            let original=client.call(json!({"method":"binding"})).await?;
            crate::communication_runtime::validate_binding(&observed,&selected.origin,&selected.actor_id)?;
            if ["engine_digest","state_binding"].iter().any(|field|observed[*field]!=original[*field])
                || observed["client_generation"]!=derived["client_generation"] {return Err(local("MANAGEMENT_VIEW_BINDING_CHANGED"));}
            let view=ManagementView{workspace_id:request.workspace_id.clone(),operations:capability.operations,
                endpoint_path,binding:crate::communication_runtime::canonical_binding(&observed),
                client_generation:derived["client_generation"].as_u64().filter(|n|*n>0).ok_or_else(||local("DERIVED_CLIENT_GENERATION_REQUIRED"))?};
            if let Some(previous)=management_views.get(&id) {
                if serde_json::to_value(previous).ok()!=serde_json::to_value(&view).ok(){return Err(local("MANAGEMENT_VIEW_BINDING_CHANGED"));}
            }else{management_views.insert(id,view);}
        }
        let mut metadata=parent.clone();metadata.allow_root=false;metadata.workspace_ids=Some([request.workspace_id.clone()].into());
        metadata.operations.retain(|a|["structure.members.read","structure.member.name.set","structure.member.availability.set","structure.workspace.get","structure.instance.resolve","participant.time.read"].contains(&a.as_str()));
        if metadata.operations.contains("structure.members.read") {
            let alias=format!("directory-{}",&sha256_hex(json!([request.participant,request.workspace_id]).to_string().as_bytes())[..40]);
            let value=client.call(json!({"method":"derive","name":alias,"capability":metadata})).await?;
            directory_endpoints.insert(request.workspace_id.clone(),PathBuf::from(value["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?));
        }
        let mut capability=parent.clone();capability.allow_root=false;capability.workspace_ids=Some([request.workspace_id.clone()].into());
        let endpoint=if !communication_requested&&previous.is_some(){
            capability=previous_setup.as_ref().and_then(|s|s.sender_capability.clone()).unwrap_or_else(||parent.clone());
            previous.as_ref().unwrap().endpoint_path.clone()
        }else{
            let allowed: &[&str]=if communication_requested {&["structure.message.send","structure.message.receipts.read","structure.mailbox.get","structure.members.read"]}
                else {&["structure.members.read","structure.member.name.set","structure.member.availability.set","structure.workspace.get","structure.instance.resolve","participant.time.read"]};
            capability.operations.retain(|a|allowed.contains(&a.as_str()));
            if !channel_send{capability.operations.remove("structure.message.send");}
            if capability.operations.is_empty()&&parent.operations.contains("participant.time.read"){capability.operations.insert("participant.time.read".into());}
            capability.validate()?;
            let alias=format!("{}-{}",if communication_requested{"mail"}else{"tools"},&sha256_hex(json!([request.participant,request.workspace_id]).to_string().as_bytes())[..40]);
            let child=client.call(json!({"method":"derive","name":alias,"capability":capability,
                "expected_capability":previous_setup.as_ref().and_then(|s|s.sender_capability.clone())})).await?;
            PathBuf::from(child["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?)
        };
        let mut receive_endpoint = previous
            .as_ref()
            .and_then(|p| p.receive_endpoint_path.clone());
        let mut receiver_name = String::new();
        let mut receiver_generation = 0;
        let receiver_tools = if let Some(completed)=&completed_first {
            receive_endpoint=Some(completed.endpoint.clone());receiver_name=completed.client_name.clone();receiver_generation=completed.generation.unwrap_or(0);
            Some(RuntimeClient::connect_bound(completed.endpoint.clone(),&selected.origin,&selected.actor_id,completed.binding.clone()).await?)
        }else if request.receive && channel_receive {
            let mailbox_id = mailbox
                .and_then(|m| m["mailbox_id"].as_str())
                .filter(|s| token(s))
                .ok_or_else(|| local("DEFAULT_MAILBOX_REQUIRED"))?;
            let mut receive_cap = parent.clone();
            receive_cap.allow_root = false;
            receive_cap.workspace_ids = Some([request.workspace_id.clone()].into());
            receive_cap.mailbox_ids = Some([mailbox_id.into()].into());
            receive_cap.operations.retain(|s| {
                [
                    "structure.mailbox.get",
                    "structure.mailbox.claim",
                    "structure.mailbox.inbox.read",
                    "structure.mailbox.pulse",
                    "structure.mailbox.ack",
                    "structure.mailbox.report",
                    "structure.communication.stream.get",
                ]
                .contains(&s.as_str())
            });
            let alias = format!(
                "receive-{}",
                &sha256_hex(
                    json!([
                        request.participant,
                        request.workspace_id,
                        mailbox_id,
                        membership
                    ])
                    .to_string()
                    .as_bytes()
                )[..40]
            );
            let derived = client
                .call(json!({"method":"derive","name":alias,"capability":receive_cap}))
                .await?;
            receiver_generation = derived["client_generation"]
                .as_u64()
                .ok_or_else(|| local("DERIVED_CLIENT_GENERATION_REQUIRED"))?;
            receiver_name = derived["client_name"]
                .as_str()
                .ok_or_else(|| local("DERIVED_ENDPOINT_INVALID"))?
                .into();
            let path = PathBuf::from(
                derived["endpoint_path"]
                    .as_str()
                    .ok_or_else(|| local("DERIVED_ENDPOINT_INVALID"))?,
            );
            let tools =
                RuntimeClient::connect(path.clone(), &selected.origin, &selected.actor_id).await?;
            receive_endpoint = Some(path);
            Some(tools)
        } else {
            None
        };
        let mut scopes = previous
            .as_ref()
            .map(|p| p.scopes.clone())
            .unwrap_or_default();
        let mut send_scopes = previous
            .as_ref()
            .map(|p| p.send_scopes.clone())
            .unwrap_or_default();
        let mut receiver = json!({"state":if wanted_receive&&!request.receive{"EXISTING_RECEIVER_PRESERVED"}else{"NOT_REQUESTED"}});
        if let Some(mailbox) = mailbox.filter(|_| channel_receive) {
            let address = MailScope {
                workspace_id: request.workspace_id.clone(),
                mailbox_id: mailbox["mailbox_id"]
                    .as_str()
                    .filter(|v| token(v))
                    .ok_or_else(|| local("MAILBOX_OBSERVATION_INVALID"))?
                    .into(),
                membership_id: membership.into(),
            };
            if channel_receive && effective_host.is_none() {
                let options = WatchOptions {
                    workspace_id: request.workspace_id.clone(),
                    mailbox_id: address.mailbox_id.clone(),
                    membership_id: membership.into(),
                    consumer_id: format!("connect-{}", request.participant),
                    host_destination: None,
                };
                let observed = receiver_tools
                    .as_ref()
                    .unwrap()
                    .call(json!({"method":"watch","options":options}))
                    .await?;
                receiver=receiving_observation(&observed);
                let until=tokio::time::Instant::now()+std::time::Duration::from_secs(2);
                while receiver["receiver_link_verified"]!=true&&receiver["state"]!="BLOCKED"&&tokio::time::Instant::now()<until {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let observed=receiver_tools.as_ref().unwrap().call(json!({"method":"inbox","options":options,"after":0,"limit":1})).await?;
                    receiver=receiving_observation(&observed);
                }
            }
            scopes.insert(request.alias.clone(), address);
            send_scopes.remove(&request.alias);
        } else if !scopes.contains_key(&request.alias) {
            send_scopes.insert(
                request.alias.clone(),
                SendScope {
                    workspace_id: request.workspace_id.clone(),
                    membership_id: membership.into(),
                },
            );
        }
        let mut contacts = previous
            .as_ref()
            .map(|p| p.contacts.clone())
            .unwrap_or_default();
        for contact in &request.contacts {
            let addresses = read(
                &client,
                "structure.mailboxes.read",
                scope.clone(),
                json!({"actor_id":contact.actor_id,"limit":8}),
            )
            .await?;
            let address = addresses["mailboxes"]
                .as_array()
                .and_then(|xs| xs.iter().find(|m| m["name"] == "default"))
                .ok_or_else(|| local("CONTACT_MAILBOX_NOT_AUTHORIZED_OR_AVAILABLE"))?;
            let recipient = peerwork_core::communication::MailboxAddress {
                mailbox_id: address["mailbox_id"]
                    .as_str()
                    .filter(|v| token(v))
                    .ok_or_else(|| local("MAILBOX_OBSERVATION_INVALID"))?
                    .into(),
                membership_id: address["membership_id"]
                    .as_str()
                    .filter(|v| token(v))
                    .ok_or_else(|| local("MAILBOX_OBSERVATION_INVALID"))?
                    .into(),
            };
            if contacts
                .get(&contact.alias)
                .is_some_and(|old| old.recipient != recipient || old.scope != request.alias)
            {
                return Err(local("CONTACT_BINDING_CHANGED_REVIEW_REQUIRED"));
            }
            contacts.insert(
                contact.alias.clone(),
                Contact {
                    scope: request.alias.clone(),
                    recipient,
                },
            );
        }
        let mut workspaces=previous.as_ref().map(|p|p.workspaces.clone()).unwrap_or_default();workspaces.insert(request.alias.clone(),request.workspace_id.clone());
        let profile = AgentProfile {
            workspaces, directory_endpoints, management_views, format: "peerwork.agent-profile.v1".into(),
            endpoint_path: endpoint,
            expected_origin: selected.origin.clone(),
            expected_actor: selected.actor_id.clone(),
            scopes,
            contacts,
            protocols,
            protocol_endpoints,
            send_scopes,
            receive_endpoint_path: receive_endpoint,
        };
        profile.validate()?;
        // Persist the trusted derivation before materializing the expendable file.
        {
            let s = self.registry.setups.get_mut(&request.setup_id).unwrap();
            if s.profile.is_none() || (s.agent_host_required && s.desired.receive && !s.channel_receive && channel_receive) {
                s.profile = Some(profile.clone());
                s.channel_send = channel_send;
                s.channel_receive = channel_receive;
                s.sender_capability = Some(capability.clone());
                self.save()?;
            }
        }
        let path = self.ensure_profile(&request.setup_id, &profile)?;
        // Publish the already-authorized tool view before opening a managed
        // host: its MCP initialization reads this snapshot without the writer lock.
        if self
            .registry
            .active_by_scope
            .get(&format!("{}:{}", request.participant, request.workspace_id))
            != Some(&request.setup_id)
        {
            self.registry.active_by_scope.insert(
                format!("{}:{}", request.participant, request.workspace_id),
                request.setup_id.clone(),
            );
            self.registry.active = Some(request.setup_id.clone());
            self.save()?;
        }
        let mut host_observation = if !request.receive&&effective_host.is_some(){json!({"state":"EXISTING_BINDING_PRESERVED","current_readiness":"NOT_ATTESTED"})}else{json!({"state":"NOT_BOUND"})};
        if let Some(name) = effective_host.as_ref().filter(|_|request.receive) {
            self.registry
                .setups
                .get_mut(&request.setup_id)
                .unwrap()
                .effective_host = Some(name.clone());
            self.save()?;
            let address = profile
                .scopes
                .get(&request.alias)
                .ok_or_else(|| local("DEFAULT_MAILBOX_REQUIRED"))?;
            let options = completed_first.as_ref().map(|c|c.watch.clone()).unwrap_or_else(||WatchOptions {
                workspace_id: request.workspace_id.clone(),
                mailbox_id: address.mailbox_id.clone(),
                membership_id: address.membership_id.clone(),
                consumer_id: format!("connect-{}", request.participant),
                host_destination: None,
            });
            let generation=if let Some(completed)=&completed_first{completed.generation}else{Some(receiver_generation)};
            let client_name = receiver_name.as_str();
            let tools = receiver_tools
                .as_ref()
                .ok_or_else(|| local("DEFAULT_MAILBOX_REQUIRED"))?;
            // A saved pending setup may outlive an explicit physical rebind.
            // Check its current watch before ensure can touch host sources.
            let bindings=tools.call(json!({"method":"bindings"})).await?;
            if let Some(actual)=bindings.as_array().and_then(|xs|xs.iter().find(|w|w["workspace_id"]==request.workspace_id&&w["mailbox_id"]==address.mailbox_id&&w["host_destination"].is_string())) {
                if self.completed_host_binding(&request,&self.registry.setups[&request.setup_id],actual).await?.is_none() {
                    return Ok(json!({"state":"PENDING","setup_id":request.setup_id,"tools_available":true,
                        "blocker":{"stage":"HOST_BINDING","code":"HOST_SELECTION_CHANGED_REBIND_REQUIRED","next_actor":"HOST_USER","next_action":"REVIEW_SELECTED_HOST_BINDING"},"existing_configuration_preserved":true}));
                }
            }
            host_observation = self
                .ensure_host(
                    name,
                    &request,
                    &selected,
                    client_name,
                    generation,
                    options.clone(),
                )
                .await?;
            let until = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                let bindings = tools.call(json!({"method":"bindings"})).await?;
                if let Some(options) = bindings.as_array().and_then(|xs| {
                    xs.iter().find(|o| {
                        o["workspace_id"] == request.workspace_id
                            && o["mailbox_id"] == address.mailbox_id
                    })
                }) {
                    let observed = tools
                        .call(json!({"method":"inbox","options":options,"after":0,"limit":1}))
                        .await?;
                    receiver=receiving_observation(&observed);
                    if receiving_self_test(&receiver,true)["state"]=="READY" {
                        if self.completed_host_binding(&request,&self.registry.setups[&request.setup_id],options).await?.is_none() {
                            return Ok(json!({"state":"PENDING","setup_id":request.setup_id,"tools_available":true,
                                "blocker":{"stage":"HOST_BINDING","code":"HOST_SELECTION_CHANGED_REBIND_REQUIRED","next_actor":"HOST_USER","next_action":"REVIEW_SELECTED_HOST_BINDING"},"existing_configuration_preserved":true}));
                        }
                        break;
                    }
                    if receiver["state"]=="BLOCKED"||tokio::time::Instant::now()>=until {
                        return self.record(&request,json!({"state":"PENDING","setup_id":request.setup_id,"tools_available":true,"profile_path":path,
                            "blocker":{"stage":"RECEIVING_SELF_TEST","code":receiving_self_test(&receiver,true)["code"],"next_actor":"RUNTIME","next_action":"INSPECT_RECEIVING_BLOCKER_OR_RESUME_SAME_SETUP"},
                            "receiver":receiver,"self_test":receiving_self_test(&receiver,true),"host":host_observation,"owner_exchange_required":false}),Some(profile));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                if tokio::time::Instant::now() >= until {
                    host_observation = self
                        .ensure_host(
                            name,
                            &request,
                            &selected,
                            client_name,
                            generation,
                            options.clone(),
                        )
                        .await?;
                    let blocked = host_observation["observation"]["state"] == "BLOCKED";
                    let code = if blocked {
                        host_observation["observation"]["code"]
                            .as_str()
                            .unwrap_or("HOST_NOT_BOUND")
                    } else {
                        "HOST_STARTING"
                    };
                    let code = code.to_owned();
                    return self.pending(
                        &request,
                        "HOST_BINDING",
                        &code,
                        if blocked { "HOST_USER" } else { "RUNTIME" },
                        if blocked {
                            "REPAIR_SELECTED_HOST_WITHOUT_REPLACING_IDENTITY"
                        } else {
                            "RESUME_SAME_SETUP"
                        },
                        json!({"host":host_observation}),
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        let self_test=if request.receive&&channel_receive{receiving_self_test(&receiver,effective_host.is_some())}else{json!({"state":"NOT_REQUESTED","model_response":"NOT_ATTESTED"})};
        if request.receive&&channel_receive&&self_test["state"]!="READY" {
            return self.record(&request,json!({"state":"PENDING","setup_id":request.setup_id,"tools_available":true,"profile_path":path,
                "blocker":{"stage":"RECEIVING_SELF_TEST","code":self_test["code"],"next_actor":"RUNTIME","next_action":"INSPECT_RECEIVING_BLOCKER_OR_RESUME_SAME_SETUP"},
                "receiver":receiver,"self_test":self_test,"host":host_observation,"owner_exchange_required":false}),Some(profile));
        }
        if self.registry.active.as_deref() != Some(&request.setup_id) {
            self.registry.active = Some(request.setup_id.clone());
            self.registry.active_by_scope.insert(
                format!("{}:{}", request.participant, request.workspace_id),
                request.setup_id.clone(),
            );
            self.save()?;
        }
        if host_pending {
            return self.record(&request,json!({"state":"PENDING","setup_id":request.setup_id,
                "actor_id":profile.expected_actor,"origin":profile.expected_origin,"workspace_id":request.workspace_id,
                "blocker":{"stage":"HOST_BINDING","code":"HOST_CONTEXT_REQUIRED","next_actor":"HOST_USER","next_action":"ENABLE_SUPPORTED_CURRENT_SESSION_INTEGRATION_OR_SELECT_NAMED_DESTINATION"},
                "tools_available":true,"profile_path":path,"receiver":{"state":"NOT_STARTED","receiver_link_verified":false},
                "host":{"state":"NOT_BOUND","current_session":"NOT_ATTESTED","supported_fallback":"TOOLS_ONLY"},
                "keys":keys,"owner_exchange_required":false,"observed_at_ms":stamp()}),Some(profile));
        }
        self.record(&request,json!({"state":"LOCAL_CONFIGURED","setup_id":request.setup_id,"profile_path":path,
            "observed_at_ms":stamp(),
            "actor_id":profile.expected_actor,"origin":profile.expected_origin,"workspace_id":request.workspace_id,
            "membership_id":membership,"keys":keys,"receiver":receiver,"host":host_observation,"self_test":self_test,"mcp_current_session":"NOT_ATTESTED",
            "receive_mode":if request.receive{if effective_host.is_some(){"PUSH"}else{"INBOX"}}else{"NOT_REQUESTED"},"automatic_model_wake":if effective_host.is_some(){"HOST_DEPENDENT_NOT_ATTESTED"}else{"NOT_CONFIGURED"},"next_action":if request.receive_mode==Some(ReceiveMode::Inbox){"USE_MCP_INBOX_OR_WAIT"}else if !request.receive{"USE_LOADED_TOOLS"}else{"VERIFY_SELECTED_RECEIVING_PATH_AND_TOOLS"},"owner_exchange_required":false}),Some(profile))
    }
    async fn key_request(
        &mut self,
        client: &RuntimeClient,
        r: &ConnectRequest,
        scope: &Scope,
    ) -> Result<Value> {
        if let Some(value) = &self.registry.setups[&r.setup_id].key_request {
            let now = trusted_time(client, scope).await?;
            if value["expires_at"].as_u64().is_some_and(|t| t > now) {
                return Ok(value.clone());
            }
            if self.registry.setups[&r.setup_id].key_request_history.len() >= 8 {
                return Err(local(
                    "KEY_REQUEST_REVISION_LIMIT_PRESERVE_APPROVAL_HISTORY",
                ));
            }
        }
        let value = read(
            client,
            "participant.access.request",
            scope.clone(),
            json!({"label":format!("Peerwork connect {}",r.setup_id)}),
        )
        .await?;
        if value["state"] != "AWAITING_OWNER_APPROVAL" {
            return Err(local("KEY_REQUEST_FAILED"));
        }
        let setup = self.registry.setups.get_mut(&r.setup_id).unwrap();
        if let Some(previous) = setup.key_request.replace(value.clone()) {
            setup.key_request_history.push(previous);
        }
        // Prior public requests remain evidence. An approval job has its own
        // frozen digest/operation IDs; refreshing a request never changes it.
        self.save()?;
        Ok(value)
    }
    async fn request_admission(&mut self,client:&RuntimeClient,r:&ConnectRequest,selected:&Registration,scope:&Scope)->Result<Value>{
        let mut missing=vec![json!({"kind":"MEMBERSHIP"})];
        if r.send{missing.push(json!({"kind":"COMMUNICATION_SEND"}));}
        if r.receive{missing.push(json!({"kind":"COMMUNICATION_RECEIVE"}));}
        for p in &r.protocols {missing.push(json!({"kind":"BUSINESS_ROLE","instance_id":p.instance_id,"protocol_digest":"","role":p.role,"actions":p.actions}));}
        let key_request=if r.require_body_keys{Some(self.key_request(client,r,scope).await?)}else{None};
        let authorization_request=AuthorizationRequest::from_input(json!({"format":"peerwork.connect-authorization-request.v2",
            "setup_id":r.setup_id,"origin":selected.origin,"workspace_id":r.workspace_id,"actor_id":selected.actor_id,
            "membership_id":"","owner_id":"","missing":missing,"body_keys_required":r.require_body_keys,"key_request":key_request}))?;
        let code=authorization_request.to_code()?;
        self.pending(r,"ADMISSION","ADMISSION_APPROVAL_REQUIRED","WORKSPACE_OWNER","APPROVE_COMBINED_PARTICIPATION_REQUEST",
            json!({"authorization_request":authorization_request,"authorization_code":code,
                "approval":{"tool":"peerwork_connect_approve","arguments":{"approval_id":format!("approve-{}",&sha256_hex(code.as_bytes())[..24]),"request":code},"add_required":["participant"]},
                "delivery":"PUBLIC_REQUEST_CODE_OR_OBJECT","request_is_not_authorization":true,"contains_private_keys_or_local_paths":false}))
    }
}
async fn trusted_time(client: &RuntimeClient, scope: &Scope) -> Result<u64> {
    let time = read(client, "participant.time.read", scope.clone(), json!({})).await?;
    if time["source"] != "SIGNED_AUTHORIZATION_CONTEXT" {
        return Err(local("TRUSTED_TIME_UNAVAILABLE"));
    }
    time["server_time_ms"]
        .as_u64()
        .ok_or_else(|| local("TRUSTED_TIME_UNAVAILABLE"))
}
async fn read(client: &RuntimeClient, action: &str, scope: Scope, body: Value) -> Result<Value> {
    let value=client.call(json!({"method":"request","request":Invoke::new("connect-bounded-read",action,scope,body)})).await?;
    if matches!(value["state"].as_str(), Some("ACCEPTED" | "COMPLETED")) {
        Ok(value["result"]["structure"].clone())
    } else if action.starts_with("participant.") {
        Ok(value)
    } else {
        let detail = if value["result"]["structure"]["error"].is_object() {
            &value["result"]["structure"]["error"]
        } else if value["error"].is_object() {
            &value["error"]
        } else {
            &value
        };
        let mut error = local(detail["code"].as_str().unwrap_or("CONNECT_READ_FAILED"));
        error.phase = detail["phase"].as_str().unwrap_or("REMOTE_READ").into();
        Err(error)
    }
}

pub fn schema() -> Value {
    let mut schema = json!({"type":"object","additionalProperties":false,"required":["request"],"properties":{"request":{
        "type":"object","additionalProperties":false,"required":["workspace_id"],
        "properties":{"setup_id":{"type":"string"},"participant":{"type":"string"},"workspace_id":{"type":"string"},"alias":{"type":"string","default":"workspace"},"send":{"type":"boolean"},"receive":{"type":"boolean"},"require_body_keys":{"type":"boolean"},"protocols":{"type":"array","maxItems":8,"items":{"type":"object","additionalProperties":false,"required":["alias","instance_id","role"],"properties":{"alias":{"type":"string"},"instance_id":{"type":"string"},"role":{"type":"string"},"actions":{"type":"array","maxItems":64,"items":{"type":"string"}}}}}}}}});
    schema["properties"]["request"]["properties"]["contacts"] = json!({"type":"array","maxItems":64,"items":{"type":"object","additionalProperties":false,"required":["alias","actor_id"],"properties":{"alias":{"type":"string"},"actor_id":{"type":"string"}}}});
    schema["properties"]["request"]["properties"]["management"]=json!({"type":"array","maxItems":32,"uniqueItems":true,"items":{"type":"string","enum":crate::agent_tools::management::workspace_names()},"description":"Explicitly enable only these existing workspace management operations as a separate immutable local client view. Does not widen existing credentials, grant remote rights or restart the runtime. Identity-scoped workspace.create/protocol.offline are not included."});
    schema["properties"]["request"]["properties"]["send"]["default"] = json!(false);
    schema["properties"]["request"]["properties"]["request_membership"] = json!({"type":"boolean","default":false,"description":"Explicitly request admission if workspace access is not verified. Returns one public request covering membership and the requested rights; Owner approval is still required."});
    schema["properties"]["request"]["properties"]["receive_mode"] = json!({"type":"string","enum":["PUSH","INBOX"],"description":"PUSH (Agent default) requires an actual supported host destination. INBOX explicitly receives for MCP inbox/wait without requiring host push; it never claims automatic model wake or replaces an existing host binding. Requires receive=true."});
    schema["properties"]["request"]["properties"]["host"] = json!({"type":"string","description":"Existing host-user-approved named destination. Omission does not identify the current session; unknown Agent receive stays pending. No commands, sockets or session paths are accepted."});
    schema
}

pub fn cli(args: &[String]) -> Value {
    crate::onboarding_files::take_diagnostic();
    fn parse(args: &[String]) -> Result<BTreeMap<String, String>> {
        let mut values = BTreeMap::new();
        let mut i = 0;
        while i < args.len() {
            let flag = &args[i];
            let boolean = [
                "--send",
                "--join",
                "--receive",
                "--body-keys",
                "--allow-loopback-http",
                "--context",
                "--uninstall",
                "--agy-managed",
                "--codex",
                "--trust-project",
                "--confirm-original",
                "--program",
                "--attach",
            ]
            .contains(&flag.as_str());
            if ![
                "--local",
                "--participant",
                "--workspace",
                "--id",
                "--alias",
                "--identity",
                "--engine-state",
                "--origin",
                "--client",
                "--actor",
                "--send",
                "--join",
                "--receive",
                "--body-keys",
                "--allow-loopback-http",
                "--context",
                "--approve-request",
                "--approve-code",
                "--receive-mode",
                "--role",
                "--attach",
                "--protocol",
                "--contact",
                "--install",
                "--project",
                "--uninstall",
                "--engine-config",
                "--runtime-config",
                "--management",
                "--journal",
                "--authority",
                "--request-timeout-ms",
                "--ca-root",
                "--host",
                "--admin",
                "--codex",
                "--codex-chat",
                "--codex-host",
                "--binding-recovery",
                "--decision-id",
                "--codex-endpoint",
                "--codex-thread",
                "--codex-session",
                "--codex-auth-env",
                "--agy-managed",
                "--agy-executable",
                "--agy-conversation",
                "--agy-api",
                "--agy-inbox",
                "--trust-project",
                "--confirm-original",
                "--program",
            ]
            .contains(&flag.as_str())
                || values.contains_key(flag)
            {
                return Err(local("CONNECT_ARGUMENT_INVALID_SEE_HELP"));
            }
            let value = if boolean {
                "true".into()
            } else {
                i += 1;
                args.get(i)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| local("CONNECT_ARGUMENT_INVALID_SEE_HELP"))?
                    .clone()
            };
            values.insert(flag.clone(), value);
            i += 1;
        }
        Ok(values)
    }
    if args.is_empty() || args == ["--help"] {
        return json!({"state":"HELP","usage":[
            "peerwork connect --local PRIVATE_REGISTRY --participant HANDLE --client ORIGINAL_ENDPOINT --origin ORIGIN --actor ACTOR --workspace WORKSPACE --attach --protocol tasks:INSTANCE:DIGEST --install codex",
            "peerwork connect --workspace WORKSPACE --role tasks:INSTANCE:CONTRIBUTOR --install codex",
            "peerwork connect --workspace WORKSPACE --trust-project --send --receive",
            "peerwork connect --workspace WORKSPACE --send --receive --receive-mode inbox --install codex",
            "peerwork connect --workspace WORKSPACE --program --trust-project --send --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --identity IDENTITY --engine-state ORIGINAL_STATE --origin ORIGIN --workspace WORKSPACE --id SETUP_ID --send --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --client EXISTING_ENDPOINT --origin ORIGIN --actor ACTOR --workspace WORKSPACE --id SETUP_ID --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --workspace WORKSPACE --id SETUP_ID --send --receive",
            "peerwork connect --workspace WORKSPACE --codex --install codex",
            "peerwork connect --workspace WORKSPACE --codex --codex-chat SELECTED_TITLE --install codex",
            "peerwork connect --workspace WORKSPACE --codex --codex-host REGISTERED_HOST --install codex",
            "peerwork connect ORIGINAL_ATTACHMENT_ARGUMENTS --binding-recovery RETRY_REJECTED_OR_ABORT --decision-id STABLE_DECISION_ID",
            "peerwork connect --local ORIGINAL_REGISTRY --participant HANDLE --workspace WORKSPACE --codex --codex-chat TITLE --runtime-config ORIGINAL_DIRECT_RUNTIME.json --admin ORIGINAL_ADMIN.json --install codex",
            "peerwork connect --local ORIGINAL_REGISTRY --participant HANDLE --workspace WORKSPACE --management protocol.register,protocol.adopt,access.approve",
            "peerwork connect --local DIRECTORY --context",
            "peerwork connect --local ORIGINAL_DIRECTORY --context --confirm-original",
            "peerwork connect --local DIRECTORY --participant OWNER_HANDLE --id APPROVAL_ID --approve-request -",
            "peerwork connect --local DIRECTORY --participant OWNER_HANDLE --id APPROVAL_ID --approve-code PW-AUTH-1.CODE",
            "peerwork connect --local DIRECTORY --participant HANDLE --engine-config EXISTING_ENGINE.json --workspace WORKSPACE --id SETUP_ID --send --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --workspace WORKSPACE --id SETUP_ID --send --receive --host SELECTED_HOST --codex-endpoint APP_SERVER_URL --codex-thread THREAD --install codex --project PROJECT",
            "peerwork connect --local DIRECTORY --participant HANDLE --workspace WORKSPACE --id SETUP_ID --send --receive --agy-managed --agy-executable AGY --agy-conversation OWNED_CONVERSATION --project PROJECT --install agy",
            "peerwork agent --local DIRECTORY mcp"],"engine_options":["--journal ORIGINAL_JOURNAL","--authority ORIGINAL_AUTHORITY","--request-timeout-ms MILLISECONDS","--ca-root PEM_FILE"],"host_authority":"Bootstrap records its own runtime admin endpoint. An external --client requires explicit --admin when registering a host. Existing handles can be reused without adapter flags.","authority":"Initial local-owner selection preserves the existing identity/state. Missing remote rights return a consolidated approval request. Subsequent MCP connect accepts registered handles only."});
    }
    let result = || -> Result<Value> {
        let mut values = parse(args)?;
        let selected_adapter=host::adapter(&values)?;
        let binding_recovery=match (values.get("--binding-recovery"),values.get("--decision-id")) {
            (None,None)=>None,
            (Some(action),Some(decision_id)) if values.contains_key("--codex")&&identifier(decision_id)=>{
                let action=match action.as_str(){
                    "RETRY_REJECTED"=>crate::participant_rebind::HostRebindRecoveryAction::RetryRejected,
                    "ABORT"=>crate::participant_rebind::HostRebindRecoveryAction::Abort,
                    _=>return Err(local("BINDING_RECOVERY_REQUIRES_RETRY_REJECTED_OR_ABORT")),
                };
                Some(crate::participant_rebind::HostRebindRecoveryRequest{format:"peerwork.host-rebind-recovery.v1".into(),decision_id:decision_id.clone(),action})
            },
            _=>return Err(local("BINDING_RECOVERY_REQUIRES_CODEX_AND_STABLE_DECISION_ID")),
        };
        if values.contains_key("--runtime-config")&&!values.contains_key("--codex"){return Err(local("RUNTIME_CONFIG_REQUIRES_CODEX_ATTACHMENT"));}
        if values.contains_key("--runtime-config")&&values.contains_key("--engine-config"){return Err(local("SELECT_ORIGINAL_RUNTIME_OR_ENGINE_NOT_BOTH"));}
        if (values.contains_key("--codex-chat")||values.contains_key("--codex-host"))&&!values.contains_key("--codex"){return Err(local("CODEX_CHAT_REQUIRES_CODEX"));}
        if values.contains_key("--codex") {
            if values.contains_key("--codex-chat")&&values.contains_key("--codex-host"){return Err(local("SELECT_ONE_CODEX_DESTINATION"));}
            if selected_adapter.is_some()||values.contains_key("--host")||values.contains_key("--attach")||values.contains_key("--program")||values.get("--receive-mode").is_some_and(|m|m!="push") {return Err(local("SELECT_ONE_HOST_ADAPTER"));}
            values.insert("--receive".into(),"true".into());
        }
        if let Some(mode)=values.get("--receive-mode"){
            if !matches!(mode.as_str(),"push"|"inbox")||!values.contains_key("--receive"){return Err(local("RECEIVE_MODE_REQUIRES_RECEIVE_AND_PUSH_OR_INBOX"));}
            if mode=="inbox"&&(selected_adapter.is_some()||values.contains_key("--host")){return Err(local("INBOX_DOES_NOT_SELECT_HOST"));}
        }
        if selected_adapter.is_some()&&!values.contains_key("--receive"){return Err(local("HOST_SELECTION_REQUIRES_RECEIVE"));}
        if values.contains_key("--confirm-original") && (values.keys().any(|key|!matches!(key.as_str(),"--local"|"--context"|"--confirm-original")) || !values.contains_key("--local") || !values.contains_key("--context")) {return Err(local("CONFIRM_ORIGINAL_REQUIRES_LOCAL_CONTEXT_ONLY"))}
        let project = std::path::absolute(values.get("--project").cloned().unwrap_or_else(||".".into()))
            .map_err(|_|local("PROJECT_CONTEXT_INVALID"))?.components().collect::<PathBuf>();
        let mut installed_directory=None;
        if !["--local","--engine-config","--identity","--client"].iter().any(|key|values.contains_key(*key)) {
            if let Some((directory,participant))=discovery::project_target(&project)? {
                installed_directory=Some(directory);
                if !participant.is_empty() && !values.contains_key("--participant") {values.insert("--participant".into(),participant);}
            } else {
                let choices=discovery::project_bindings(&project,values.get("--workspace").map(String::as_str))?;
                let selected:Vec<_>=choices.iter().filter(|choice|values.get("--participant").is_none_or(|wanted|
                    wanted==&choice.participant || choice.summary["handle"]==*wanted)).collect();
                if selected.len()>1 {return Ok(json!({"state":"PENDING","discovery":{"state":"IDENTITY_SELECTION_REQUIRED","candidates":selected.iter().map(|c|c.summary.clone()).collect::<Vec<_>>()},
                    "blocker":{"stage":"LOCAL_IDENTITY","code":"IDENTITY_SELECTION_REQUIRED","next_actor":"LOCAL_RUNTIME_OWNER","next_action":"CHOOSE_ONE_PUBLIC_IDENTITY_HANDLE"}}));}
                if let Some(choice)=selected.first() {
                    discovery::remember_project(&project,choice)?;
                    installed_directory=Some(choice.directory.clone());
                    values.insert("--participant".into(),choice.participant.clone());
                } else if values.contains_key("--participant") && !choices.is_empty() {return Err(local("LOCAL_SELECTION_REQUIRED"));}
            }
        }
        let directory = match values.get("--local") {
            Some(path)=>std::path::absolute(path).map_err(|_|local("CONNECT_DIRECTORY_INVALID"))?,
            None=>match installed_directory {Some(path)=>path,None=>discovery::directory(&project)?},
        };
        if values.contains_key("--confirm-original") {
            if !values.contains_key("--local") || !values.contains_key("--context") {return Err(local("CONFIRM_ORIGINAL_REQUIRES_LOCAL_CONTEXT_ONLY"))}
            discovery::confirm_original_store(&directory)?;
        }
        if values.contains_key("--context") && directory.exists() {
            return Ok(Connect::inspect(&directory)?.context());
        }
        let mut connect = Connect::open(&directory)?;
        if values.contains_key("--context") {
            return Ok(connect.context());
        }
        bootstrap::runtime_inputs(&connect,&mut values)?;
        let required = |key: &str| {
            values.get(key).cloned().ok_or_else(|| local("CONNECT_ARGUMENT_INVALID_SEE_HELP"))
        };
        let explicit_engine = bootstrap::engine(&values)?;
        if values.contains_key("--attach")&&explicit_engine.is_some(){return Err(local("ATTACH_REQUIRES_EXISTING_ENDPOINT"));}
        let discovery = if explicit_engine.is_none() && !values.contains_key("--client") {
            Some(connect.discover(&project, values.contains_key("--trust-project"))?)
        } else { None };
        let handle = match values.get("--participant").cloned() {
            Some(value)=>value,
            None=>match &explicit_engine {
                Some(engine)=>format!("identity-{}",&engine.binding_digest()?[..24]),
                None=>match connect.original_handle(None) {
                    Ok(Some(handle))=>handle,
                    Ok(None)|Err(_)=>return Ok(json!({"state":"PENDING","discovery":discovery,
                        "blocker":{"stage":"LOCAL_IDENTITY","code":discovery.as_ref().map(|v|v.state.as_str()).unwrap_or("LOCAL_SELECTION_REQUIRED"),
                            "next_actor":"LOCAL_RUNTIME_OWNER","next_action":discovery.as_ref().map(|v|v.next_action.as_str()).unwrap_or("SELECT_ORIGINAL_IDENTITY")}})),
                },
            },
        };
        let installation = if let Some(host) = values.get("--install") {
            Some(Installation {
                host: host.clone(),
                project: project.clone(),
                executable: std::env::current_exe().map_err(|_| local("EXECUTABLE_UNAVAILABLE"))?,
            })
        } else {
            None
        };
        if values.contains_key("--uninstall") {
            return connect.uninstall(
                &handle,
                &required("--workspace")?,
                installation.ok_or_else(|| local("SELECT_INSTALLATION_TO_REMOVE"))?,
            );
        }
        if values.contains_key("--approve-request") && values.contains_key("--approve-code") {return Err(local("SELECT_ONE_AUTHORIZATION_INPUT"));}
        if values.contains_key("--approve-request") || values.contains_key("--approve-code") {
            use std::io::Read;
            let mut wire = if let Some(code)=values.get("--approve-code"){code.as_bytes().to_vec()}else{Vec::new()};
            if let Some(path)=values.get("--approve-request") {
            let reader:Box<dyn Read>=if path=="-"{Box::new(std::io::stdin())}else{Box::new(std::fs::File::open(path)
                .map_err(|_| local("APPROVAL_REQUEST_UNREADABLE"))?
            )};
            reader.take(43706)
                .read_to_end(&mut wire)
                .map_err(|_| local("APPROVAL_REQUEST_UNREADABLE"))?;
            }
            if wire.len() > 43705 {
                return Err(local("APPROVAL_REQUEST_TOO_LARGE"));
            }
            let text=std::str::from_utf8(&wire).map_err(|_|local("AUTHORIZATION_REQUEST_INVALID"))?.trim();
            let input=if text.starts_with("PW-AUTH-1."){json!(text)}else{peerwork_core::strict_json::parse_strict_json(text.as_bytes()).map_err(|_|local("AUTHORIZATION_REQUEST_INVALID"))?};
            let request=AuthorizationRequest::from_input(input)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|_| local("EXECUTOR_FAILED"))?;
            return runtime.block_on(connect.approve(&handle, &required("--id")?, request));
        }
        let mut request = ConnectRequest {
            setup_id: values.get("--id").cloned().unwrap_or_default(),
            participant: handle.clone(),
            workspace_id: required("--workspace")?,
            alias: values.get("--alias").cloned().unwrap_or_else(default_alias),
            send: values.contains_key("--send"),
            receive: values.contains_key("--receive"),
            receive_mode: values.get("--receive-mode").map(|v|match v.as_str(){"push"=>Ok(ReceiveMode::Push),"inbox"=>Ok(ReceiveMode::Inbox),_=>Err(local("RECEIVE_MODE_USE_PUSH_OR_INBOX"))}).transpose()?,
            require_body_keys: values.contains_key("--body-keys"),
            request_membership: values.contains_key("--join"),
            protocols: Vec::new(),
            management: values.get("--management").map(|v|v.split(',').map(str::to_owned).collect()).unwrap_or_default(),
            contacts: Vec::new(),
            host: values.get("--host").cloned(),
        };
        if let Some(role) = values.get("--role") {
            let parts: Vec<_> = role.split(':').collect();
            if parts.len() != 3 {
                return Err(local("ROLE_SELECTION_USE_ALIAS_INSTANCE_ROLE"));
            }
            request.protocols.push(ProtocolSelection {
                alias: parts[0].into(),
                instance_id: parts[1].into(),
                role: parts[2].into(),
                actions: Vec::new(),
            });
        }
        if let Some(contact) = values.get("--contact") {
            let (alias, actor) = contact
                .split_once(':')
                .ok_or_else(|| local("CONTACT_SELECTION_USE_ALIAS_ACTOR"))?;
            request.contacts.push(ContactSelection {
                alias: alias.into(),
                actor_id: actor.into(),
            });
        }
        request = if values.contains_key("--program") {connect.normalize_request(request)?} else {connect.normalize_agent_request(request)?};
        if selected_adapter.is_some() && !request.receive {
            return Err(local("HOST_SELECTION_REQUIRES_RECEIVE"));
        }
        if selected_adapter.is_none() && values.contains_key("--admin") && !values.contains_key("--codex") {
            return Err(local("HOST_SELECTION_REQUIRED"));
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| local("EXECUTOR_FAILED"))?;
        runtime.block_on(async {
            if let Some(engine) = explicit_engine {
                connect.bootstrap(&handle, engine).await?;
            } else if let Some(endpoint) = values.get("--client") {
                connect
                    .register(
                        &handle,
                        Registration {
                            origin: required("--origin")?,
                            actor_id: required("--actor")?,
                            endpoint_path: std::path::absolute(endpoint)
                                .map_err(|_| local("LOCAL_SELECTION_INVALID"))?,
                        },
                    )
                    .await?;
            }
            if values.contains_key("--codex") {
                let config_path=values.get("--runtime-config").map(std::path::absolute).transpose().map_err(|_|local("LOCAL_SELECTION_INVALID"))?;
                let admin=values.get("--admin").map(std::path::absolute).transpose().map_err(|_|local("HOST_SELECTION_INVALID"))?
                    .or_else(||config_path.as_ref().and_then(|p|crate::communication_store::private_json(p,65536).ok())
                        .and_then(|v|v["state_directory"].as_str().map(|d|PathBuf::from(d).join("admin.json"))));
                let selection=match admin {Some(admin_endpoint)=>Some(RuntimeSelection{admin_endpoint,config_path}),None=>None};
                // Resume the existing durable attachment before opening a
                // potentially stopped endpoint through ordinary discovery.
                let mut result=if let Some(decision)=binding_recovery {connect.recover_codex_attachment(request,values.get("--codex-chat").or_else(||values.get("--codex-host")).map(String::as_str),decision).await?}
                    else if let Some(host)=values.get("--codex-host") {connect.attach_codex_host_with_runtime(request,host,selection).await?}
                    else {connect.attach_codex_with_runtime(request,values.get("--codex-chat").map(String::as_str),selection).await?};
                if let Some(spec)=installation {result["integration"]=connect.install(&handle,&required("--workspace")?,spec)?;}
                return Ok(result);
            }
            connect.adopt(&handle).await?;
            if !values.contains_key("--local") {discovery::pin_project_binding(&project,&connect,&handle)?;}
            if let Some(mut adapter) = selected_adapter {
                if adapter["kind"] == "agy-stdio" {
                    if let Some(spec) = installation.as_ref().filter(|spec| spec.host == "agy") {
                        adapter["mcp_server"] = json!(install::server_name(
                            &connect.directory,
                            &handle,
                            &request.workspace_id,
                            spec
                        ));
                    }
                }
                let name = request.host.clone().unwrap_or_else(|| {
                    format!("host-{}", &sha256_hex(adapter.to_string().as_bytes())[..16])
                });
                let admin = values
                    .get("--admin")
                    .map(std::path::absolute)
                    .transpose()
                    .map_err(|_| local("HOST_SELECTION_INVALID"))?
                    .or_else(|| connect.registry.local_runtime_admins.get(&handle).cloned())
                    .ok_or_else(|| local("EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED"))?;
                connect
                    .register_host(
                        &name,
                        HostSelection {
                            participant: handle.clone(),
                            admin_endpoint: admin,
                            adapter,
                        },
                    )
                    .await?;
                request.host = Some(name);
                request.validate()?;
            }
            if values.contains_key("--attach") {
                if request.send||request.receive||request.require_body_keys||request.request_membership||!request.protocols.is_empty()||!request.contacts.is_empty()||request.host.is_some(){return Err(local("ATTACH_ONLY_REUSES_EXISTING_AUTHORITY"));}
                let mut protocols=BTreeMap::new();
                if let Some(protocol)=values.get("--protocol"){
                    for binding in protocol.split(',') {
                        let parts:Vec<_>=binding.split(':').collect();if parts.len()!=3{return Err(local("PROTOCOL_SELECTION_USE_ALIAS_INSTANCE_DIGEST"));}
                        if protocols.insert(parts[0].into(),Scope{workspace_id:Some(request.workspace_id.clone()),instance_id:Some(parts[1].into()),protocol_digest:Some(parts[2].into())}).is_some(){return Err(local("PROTOCOL_ALIAS_CONFLICT"));}
                    }
                }
                let mut result=connect.attach(&handle,&request.workspace_id,&request.alias,protocols).await?;
                if let Some(spec)=installation{result["integration"]=connect.install(&handle,&request.workspace_id,spec)?;}
                return Ok(result);
            }
            if values.contains_key("--protocol"){return Err(local("PROTOCOL_SELECTION_REQUIRES_ATTACH"));}
            let installed = installation
                .map(|spec| connect.install(&handle, &request.workspace_id, spec))
                .transpose()?;
            let result = if values.contains_key("--program") { connect.run(request).await } else { connect.run_agent(request).await };
            let mut out = match result {
                Ok(v) => v,
                Err(error) => json!({"state":"FAILED","error":error}),
            };
            if let Some(installed) = installed {
                out["integration"] = installed;
            }
            Ok(out)
        })
    };
    let mut output = result().unwrap_or_else(|error| {
        if matches!(error.code.as_str(),"RUNTIME_STARTING_REOBSERVE_SAME_BINDING"|"PROCESS_IDENTITY_UNCONFIRMED"|"RUNTIME_LAUNCH_RECOVERY_REQUIRED"){
            let selection=parse(args).unwrap_or_default();
            json!({"state":"PENDING","phase":"LOCAL_RUNTIME_STARTUP","setup_id":selection.get("--id"),"participant":selection.get("--participant"),"workspace_id":selection.get("--workspace"),"error":error,"next_action":if error.code=="RUNTIME_STARTING_REOBSERVE_SAME_BINDING"{"REOBSERVE_SAME_BINDING"}else{"VERIFY_ORIGINAL_LAUNCH_EVIDENCE"}})
        } else {json!({"state":"FAILED","error":error})}
    });
    if output["state"] == "FAILED" {
        if let Some(diagnostic) = crate::onboarding_files::take_diagnostic() {
            if output["error"]["code"]=="ORIGINAL_LOCAL_REGISTRY_CONFIRMATION_REQUIRED" {
                if let Some(path)=diagnostic["original_registry"].as_str(){
                    output["next_actor"]=json!("LOCAL_RUNTIME_OWNER");
                    output["local_command"]=json!(["peerwork","connect","--local",path,"--context","--confirm-original"]);
                }
            }
            output["error"]["local_diagnostic"] = diagnostic;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_inbox_host_conflict_does_not_bootstrap_or_create_local_state() {
        let state=crate::test_support::protected_test_dir();let directory=state.path().join("not-created");
        let args=vec!["--local".into(),directory.to_str().unwrap().into(),"--workspace".into(),"W".repeat(43),
            "--receive".into(),"--receive-mode".into(),"inbox".into(),"--host".into(),"selected-host".into()];
        let result=cli(&args);assert_eq!(result["error"]["code"],"INBOX_DOES_NOT_SELECT_HOST","{result}");
        assert!(!directory.exists());
    }
    #[test]
    fn explicit_inbox_needs_no_host_and_old_request_serialization_is_stable() {
        let wire=json!({"setup_id":"same","participant":"worker","workspace_id":"W".repeat(43),"alias":"workspace",
            "send":false,"receive":true,"require_body_keys":false,"protocols":[],"contacts":[],"host":null});
        let mut request:ConnectRequest=serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(),wire);
        assert!(request.needs_host(true));
        request.receive_mode=Some(ReceiveMode::Inbox);
        request.validate().unwrap();assert!(!request.needs_host(true));
        request.host=Some("selected-host".into());assert!(request.validate().is_err());
        request.host=None;request.receive=false;assert!(request.validate().is_err());
    }
    #[test]
    fn lost_original_registry_is_not_reinterpreted_as_first_install() {
        let temp = crate::test_support::protected_test_dir();
        let directory = temp.path().join("local");
        let connect = Connect::open(&directory).unwrap();
        connect.save().unwrap();
        drop(connect);
        std::fs::remove_file(directory.join("connect.state")).unwrap();
        let error = match Connect::open(&directory) {
            Err(e) => e,
            Ok(_) => panic!("lost original binding was silently replaced"),
        };
        assert_eq!(error.code, "CONNECT_ORIGINAL_BINDING_RECOVERY_REQUIRED");
        assert!(!directory.join("connect.state").exists());
    }
    #[tokio::test]
    async fn readers_remain_available_during_setup_without_gaining_writer_authority() {
        let temp = crate::test_support::protected_test_dir();
        let directory = temp.path().join("local");
        let writer = Connect::open(&directory).unwrap();
        writer.save().unwrap();
        let mut reader = Connect::inspect(&directory).unwrap();
        assert_eq!(reader.context()["state"], "NOT_CONFIGURED");
        let error = reader
            .run(ConnectRequest { management: Vec::new(),
                setup_id: "original".into(),
                participant: "worker".into(),
                workspace_id: "W".repeat(43),
                alias: "space".into(),
                send: false,
                receive: true,
                receive_mode: None,
                require_body_keys: false,
                request_membership: false,
                protocols: Vec::new(),
                contacts: Vec::new(),
                host: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "CONNECT_READ_ONLY_VIEW");
        assert!(reader.save().is_err());
    }
    #[test]
    fn receiving_self_test_requires_current_verified_path_and_push_prerequisites() {
        let ready=json!({"state":"RECEIVER_LINK_VERIFIED","receiver_link_verified":true,
            "presence":{"host_current":true,"host":{"ready":true,"mode":"LIVE"},
                "key_current":true,"body_key":{"state":"READY"}}});
        assert_eq!(receiving_self_test(&ready,true)["state"],"READY");
        assert_eq!(receiving_self_test(&ready,false)["state"],"READY");
        for state in ["BLOCKED","RECONNECTING","LOCAL_STOPPED","CLAIMED"] {
            let mut fault=ready.clone();fault["state"]=json!(state);
            assert_eq!(receiving_self_test(&fault,false)["state"],"PENDING");
            assert_eq!(receiving_self_test(&fault,true)["state"],"PENDING");
        }
        let mut fault=ready.clone();fault["verification_failure"]=json!({"code":"STREAM_DIGEST_INVALID"});
        assert_eq!(receiving_self_test(&fault,true)["state"],"PENDING");
        for field in ["key_current","host_current"] {
            let mut stale=ready.clone();stale["presence"][field]=json!(false);
            assert_eq!(receiving_self_test(&stale,true)["state"],"PENDING");
            assert_eq!(receiving_self_test(&stale,false)["state"],"READY");
        }
        assert_eq!(receiving_self_test(&ready,true)["model_response"],"NOT_ATTESTED");
    }

}
