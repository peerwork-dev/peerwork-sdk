//! Shared, resumable local onboarding. Remote rights remain service-enforced;
//! the registry contains explicit local selections, never discovered secrets.
use crate::{
    agent_tools::{AgentProfile, Contact, MailScope, SendScope},
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
pub use install::Installation;
#[path = "participant_connect_host.rs"]
mod host;
pub use host::{HostInvocation, HostSelection};
#[path = "participant_connect_bootstrap.rs"]
mod bootstrap;
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
    #[serde(default)]
    pub require_body_keys: bool,
    #[serde(default)]
    pub protocols: Vec<ProtocolSelection>,
    #[serde(default)]
    pub contacts: Vec<ContactSelection>,
    #[serde(default)]
    pub host: Option<String>,
}
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
fn default_send() -> bool { true }
impl ConnectRequest {
    pub fn validate(&self) -> Result<()> {
        if !identifier(&self.setup_id)
            || !identifier(&self.participant)
            || !identifier(&self.alias)
            || !token(&self.workspace_id)
            || self.protocols.len() > 8
            || self.contacts.len() > 64
            || (!self.send && !self.receive && self.protocols.is_empty())
            || self
                .host
                .as_ref()
                .is_some_and(|h| !identifier(h) || !self.receive)
        {
            return Err(local("CONNECT_ARGUMENT_INVALID"));
        }
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
            || registry.setups.len() > 64
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
        })
    }
    /// Atomic, bounded read of the selected local registry. Normal tools must
    /// remain available while a setup job awaits its remote/local prerequisites.
    pub fn inspect(directory: &Path) -> Result<Self> {
        let (registry,private_directory)=discovery::inspect_original_store(directory)?;
        Ok(Self{directory:directory.into(),private_directory,store:None,registry})
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
        let scope = Scope {
            workspace_id: Some(request.workspace_id.clone()),
            ..Scope::default()
        };
        let now = trusted_time(&client, &scope).await?;
        let workspace = read(&client, "structure.workspace.get", scope.clone(), json!({})).await?;
        if !token(
            workspace["membership"]["membership_id"]
                .as_str()
                .unwrap_or(""),
        ) {
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
        let grants = read(
            &client,
            "structure.communication.grant.get",
            scope.clone(),
            json!({}),
        )
        .await?;
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
            return self.pending(&request,"REMOTE_AUTHORIZATION",if missing.is_empty(){"KEY_AUTHORIZATION_REQUIRED"}else{"OWNER_APPROVAL_REQUIRED"},owner,"APPROVE_REQUESTED_PERMISSION_DELTA",
                json!({"authorization_request":{"format":"peerwork.connect-authorization-request.v1","setup_id":request.setup_id,
                    "origin":selected.origin,"workspace_id":request.workspace_id,"actor_id":selected.actor_id,"membership_id":membership,
                    "owner_id":owner,"missing":missing,"body_keys_required":needs_keys,"key_request":key_request},
                    "delivery":"EXISTING_ADMISSION_OR_VERIFIED_HANDOFF","contains_private_keys_or_local_paths":false}));
        }
        let mailboxes = read(
            &client,
            "structure.mailboxes.read",
            scope.clone(),
            json!({"limit":8}),
        )
        .await?;
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
        let parent: Capability = serde_json::from_value(caps["capability"].clone())
            .map_err(|_| local("LOCAL_CEILING_INVALID"))?;
        let previous_setup = self
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
        let previous = previous_setup.as_ref().and_then(|s| s.profile.clone());
        if (agent || self.registry.setups[&request.setup_id].agent_host_required)
            && request.receive && previous_setup.as_ref().is_some_and(|s|s.channel_receive && s.effective_host.is_none()) {
            return self.pending(&request,"HOST_BINDING","EXISTING_PROGRAM_RECEIVER_REQUIRES_EXPLICIT_REBIND","HOST_USER","EXPLICIT_NATIVE_REBIND",json!({"existing_receiver_preserved":true}));
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
        let effective_host = request.host.clone().or_else(||self.registry.setups[&request.setup_id].effective_host.clone())
            .or_else(||if request.receive && (agent || self.registry.setups[&request.setup_id].agent_host_required) {None} else {old_host.clone()});
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
        let mut capability = parent.clone();
        capability.allow_root = false;
        capability.workspace_ids = Some([request.workspace_id.clone()].into());
        // Sending never acquires receiver/claim/report authority. The receiver
        // gets a separate own-mailbox-bound client under the same engine.
        let allowed = [
            "structure.message.send",
            "structure.message.receipts.read",
            "structure.mailbox.get",
        ];
        capability
            .operations
            .retain(|s| allowed.contains(&s.as_str()));
        if !channel_send {
            capability.operations.remove("structure.message.send");
        }
        capability.validate()?;
        let alias = format!(
            "mail-{}",
            &sha256_hex(
                json!([request.participant, request.workspace_id])
                    .to_string()
                    .as_bytes()
            )[..40]
        );
        let child = client.call(json!({"method":"derive","name":alias,"capability":capability,
            "expected_capability":previous_setup.as_ref().and_then(|s|s.sender_capability.clone())})).await?;
        let endpoint = child["endpoint_path"]
            .as_str()
            .ok_or_else(|| local("DERIVED_ENDPOINT_INVALID"))?;
        let mut receive_endpoint = previous
            .as_ref()
            .and_then(|p| p.receive_endpoint_path.clone());
        let mut receiver_name = String::new();
        let mut receiver_generation = 0;
        let receiver_tools = if channel_receive {
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
        let mut receiver = json!({"state":"NOT_REQUESTED"});
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
                receiver = json!({"state":observed["state"],"code":observed["code"],"presence":observed["presence"],
                    "receiver_link_verified":observed["receiver_link_verified"],"checkpoint":observed["checkpoint"],
                    "model_response":"NOT_ATTESTED"});
            }
            scopes.insert(request.alias.clone(), address);
            send_scopes.remove(&request.alias);
        } else {
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
        let profile = AgentProfile {
            format: "peerwork.agent-profile.v1".into(),
            endpoint_path: PathBuf::from(endpoint),
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
        let mut host_observation = json!({"state":"NOT_BOUND"});
        if let Some(name) = &effective_host {
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
            let options = WatchOptions {
                workspace_id: request.workspace_id.clone(),
                mailbox_id: address.mailbox_id.clone(),
                membership_id: address.membership_id.clone(),
                consumer_id: format!("connect-{}", request.participant),
                host_destination: None,
            };
            let client_name = receiver_name.as_str();
            let tools = receiver_tools
                .as_ref()
                .ok_or_else(|| local("DEFAULT_MAILBOX_REQUIRED"))?;
            host_observation = self
                .ensure_host(
                    name,
                    &request,
                    &selected,
                    client_name,
                    receiver_generation,
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
                    receiver = json!({"state":observed["state"],"code":observed["code"],"presence":observed["presence"],"receiver_link_verified":observed["receiver_link_verified"],"checkpoint":observed["checkpoint"],"model_response":"NOT_ATTESTED"});
                    break;
                }
                if tokio::time::Instant::now() >= until {
                    host_observation = self
                        .ensure_host(
                            name,
                            &request,
                            &selected,
                            client_name,
                            receiver_generation,
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
            "membership_id":membership,"keys":keys,"receiver":receiver,"host":host_observation,"mcp_current_session":"NOT_ATTESTED",
            "next_action":"BIND_SELECTED_HOST_AND_VERIFY_TOOLS","owner_exchange_required":false}),Some(profile))
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
    schema["properties"]["request"]["properties"]["send"]["default"] = json!(true);
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
                "--receive",
                "--body-keys",
                "--allow-loopback-http",
                "--context",
                "--uninstall",
                "--agy-managed",
                "--trust-project",
                "--confirm-original",
                "--program",
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
                "--receive",
                "--body-keys",
                "--allow-loopback-http",
                "--context",
                "--approve-request",
                "--role",
                "--contact",
                "--install",
                "--project",
                "--uninstall",
                "--engine-config",
                "--journal",
                "--authority",
                "--request-timeout-ms",
                "--ca-root",
                "--host",
                "--admin",
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
            "peerwork connect --workspace WORKSPACE --trust-project --send --receive",
            "peerwork connect --workspace WORKSPACE --program --trust-project --send --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --identity IDENTITY --engine-state ORIGINAL_STATE --origin ORIGIN --workspace WORKSPACE --id SETUP_ID --send --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --client EXISTING_ENDPOINT --origin ORIGIN --actor ACTOR --workspace WORKSPACE --id SETUP_ID --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --workspace WORKSPACE --id SETUP_ID --send --receive",
            "peerwork connect --local DIRECTORY --context",
            "peerwork connect --local DIRECTORY --participant OWNER_HANDLE --id APPROVAL_ID --approve-request PUBLIC_REQUEST.json",
            "peerwork connect --local DIRECTORY --participant HANDLE --engine-config EXISTING_ENGINE.json --workspace WORKSPACE --id SETUP_ID --send --receive",
            "peerwork connect --local DIRECTORY --participant HANDLE --workspace WORKSPACE --id SETUP_ID --send --receive --host SELECTED_HOST --codex-endpoint APP_SERVER_URL --codex-thread THREAD --install codex --project PROJECT",
            "peerwork connect --local DIRECTORY --participant HANDLE --workspace WORKSPACE --id SETUP_ID --send --receive --agy-managed --agy-executable AGY --agy-conversation OWNED_CONVERSATION --project PROJECT --install agy",
            "peerwork agent --local DIRECTORY mcp"],"engine_options":["--journal ORIGINAL_JOURNAL","--authority ORIGINAL_AUTHORITY","--request-timeout-ms MILLISECONDS","--ca-root PEM_FILE"],"host_authority":"Bootstrap records its own runtime admin endpoint. An external --client requires explicit --admin when registering a host. Existing handles can be reused without adapter flags.","authority":"Initial local-owner selection preserves the existing identity/state. Missing remote rights return a consolidated approval request. Subsequent MCP connect accepts registered handles only."});
    }
    let result = || -> Result<Value> {
        let mut values = parse(args)?;
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
        let required = |key: &str| {
            values.get(key).cloned().ok_or_else(|| local("CONNECT_ARGUMENT_INVALID_SEE_HELP"))
        };
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
        let explicit_engine = bootstrap::engine(&values)?;
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
        if let Some(path) = values.get("--approve-request") {
            use std::io::Read;
            let mut wire = Vec::new();
            std::fs::File::open(path)
                .map_err(|_| local("APPROVAL_REQUEST_UNREADABLE"))?
                .take(32769)
                .read_to_end(&mut wire)
                .map_err(|_| local("APPROVAL_REQUEST_UNREADABLE"))?;
            if wire.len() > 32768 {
                return Err(local("APPROVAL_REQUEST_TOO_LARGE"));
            }
            let request: AuthorizationRequest = serde_json::from_value(
                peerwork_core::strict_json::parse_strict_json(&wire)
                    .map_err(|_| local("AUTHORIZATION_REQUEST_INVALID"))?,
            )
            .map_err(|_| local("AUTHORIZATION_REQUEST_INVALID"))?;
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
            send: values.contains_key("--send") || !["--receive","--role"].iter().any(|s|values.contains_key(*s)),
            receive: values.contains_key("--receive"),
            require_body_keys: values.contains_key("--body-keys"),
            protocols: Vec::new(),
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
        let selected_adapter = host::adapter(&values)?;
        if selected_adapter.is_some() && !request.receive {
            return Err(local("HOST_SELECTION_REQUIRES_RECEIVE"));
        }
        if selected_adapter.is_none() && values.contains_key("--admin") {
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
            output["error"]["local_diagnostic"] = diagnostic;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .run(ConnectRequest {
                setup_id: "original".into(),
                participant: "worker".into(),
                workspace_id: "W".repeat(43),
                alias: "space".into(),
                send: false,
                receive: true,
                require_body_keys: false,
                protocols: Vec::new(),
                contacts: Vec::new(),
                host: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "CONNECT_READ_ONLY_VIEW");
        assert!(reader.save().is_err());
    }
}
