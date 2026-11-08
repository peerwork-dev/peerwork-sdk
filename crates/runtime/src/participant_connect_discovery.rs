//! Bounded original-installation discovery. No recursive scan or engine open.
use super::*;
use crate::onboarding_project::Directory as ProjectDirectory;
use crate::communication_runtime::{EngineConfig, RuntimeConfig};

const LIMIT: usize = 8;
fn bounded_registry(bytes:&[u8])->Result<Registry>{
    let registry:Registry=serde_json::from_value(peerwork_core::strict_json::parse_strict_json(bytes).map_err(|_|local("CONNECT_RECOVERY_REQUIRED"))?).map_err(|_|local("CONNECT_RECOVERY_REQUIRED"))?;
    if registry.participants.len()>8 || registry.setups.len()>64 || registry.approvals.len()>64 || registry.sources.len()>8
        || registry.trusted_projects.len()>8 || registry.trusted_project_identities.len()>8 || registry.verified_bindings.len()>8 {return Err(local("CONNECT_RECOVERY_REQUIRED"))}
    Ok(registry)
}
fn anchored_registry(directory:&ProjectDirectory)->Result<Registry>{
    let bytes=directory.read("connect.state",64*1024*1024+128,true)?.ok_or_else(||local("CONNECT_ORIGINAL_BINDING_RECOVERY_REQUIRED"))?;
    bounded_registry(SecureStateStore::snapshot_payload(&bytes,64*1024*1024).map_err(|_|local("CONNECT_RECOVERY_REQUIRED"))?)
}
fn association_required()->ParticipantError{let mut e=local("ORIGINAL_LOCAL_REGISTRY_CONFIRMATION_REQUIRED");e.recovery="LOCAL_OWNER_CONFIRM_EXISTING_REGISTRY_WITH_CONNECT_LOCAL_CONTEXT_CONFIRM_ORIGINAL".into();e}
fn require_original_association(directory:&ProjectDirectory)->Result<()> {
    let missing=||{crate::onboarding_files::original_confirmation(directory.path());association_required()};
    let selected=crate::onboarding_state::project(directory.path(),"original-registries",false)?
        .ok_or_else(missing)?;
    let path=selected.join("association.state");
    let bytes=SecureStateStore::read_snapshot(&path,65536).map_err(|_|missing())?;
    let expected=json!({"format":"peerwork.original-registry-association.v1","directory":directory.identity()?});
    if peerwork_core::strict_json::parse_strict_json(&bytes).ok().as_ref()!=Some(&expected) {return Err(local("ORIGINAL_REGISTRY_DIRECTORY_CHANGED"))}
    Ok(())
}
/// Explicit local confirmation selects an existing private store. It changes
/// only a protected association, never keys, source state or remote authority.
pub(super) fn confirm_original_store(path:&Path)->Result<()> {
    if crate::onboarding_files::check_directory(path,true).is_ok(){return Ok(())}
    let directory=ProjectDirectory::private(path)?;
    let store=crate::onboarding_store::Store::anchored(directory.clone(),"connect.state",false)?;
    let registry=bounded_registry(&store.read_exact()?.ok_or_else(||local("CONNECT_RECOVERY_REQUIRED"))?)?;
    if registry.participants.is_empty() && registry.sources.is_empty() && registry.setups.is_empty(){return Err(local("CONFIRM_ORIGINAL_REQUIRES_EXISTING_IDENTITY"))}
    let selected=crate::onboarding_state::project(path,"original-registries",true)?.unwrap();
    let association=SecureStateStore::open(&selected.join("association.state")).map_err(|_|local("ORIGINAL_ASSOCIATION_ALREADY_OWNED"))?;
    let expected=json!({"format":"peerwork.original-registry-association.v1","directory":directory.identity()?});
    if let Some(old)=association.read_exact().map_err(|_|local("ORIGINAL_ASSOCIATION_RECOVERY_REQUIRED"))? {
        if peerwork_core::strict_json::parse_strict_json(&old).ok().as_ref()!=Some(&expected){return Err(local("ORIGINAL_REGISTRY_DIRECTORY_CHANGED"))}
    }else{directory.verify()?;association.write_exact(&serde_json::to_vec(&expected).unwrap()).map_err(|_|local("ORIGINAL_ASSOCIATION_WRITE_FAILED"))?;}
    crate::onboarding_files::take_diagnostic();Ok(())
}
pub(super) fn open_original_store(path:&Path)->Result<(crate::onboarding_store::Store,ProjectDirectory)> {
    if !path.try_exists().map_err(|_|crate::onboarding_files::path_error(path,"PRIVATE_STATE","OPEN","PERMISSION_DENIED"))? {
        crate::onboarding_files::directory(path,true)?;
    }
    if crate::onboarding_files::check_directory(path,true).is_ok(){
        let directory=ProjectDirectory::private(path)?;
        return Ok((crate::onboarding_store::Store::protected(&path.join("connect.state")).map_err(|_|local("CONNECT_STATE_ALREADY_OWNED_OR_UNSAFE"))?,directory));
    }
    let directory=ProjectDirectory::private(path)?;
    require_original_association(&directory)?;
    let store=crate::onboarding_store::Store::anchored(directory.clone(),"connect.state",false)?;
    crate::onboarding_files::take_diagnostic();Ok((store,directory))
}
pub(super) fn inspect_original_store(path:&Path)->Result<(Registry,ProjectDirectory)> {
    let ordinary=crate::onboarding_files::check_directory(path,true).is_ok();
    let directory=ProjectDirectory::private(path)?;
    if !ordinary {require_original_association(&directory)?;}
    let registry=match directory.read("connect.state",64*1024*1024+128,true)? {
        Some(bytes)=>bounded_registry(SecureStateStore::snapshot_payload(&bytes,64*1024*1024).map_err(|_|local("CONNECT_RECOVERY_REQUIRED"))?)?,
        None=>{if directory.kind("initialized.json")?.is_some(){return Err(local("CONNECT_ORIGINAL_BINDING_RECOVERY_REQUIRED"))} Registry::default()},
    };
    if !ordinary {crate::onboarding_files::take_diagnostic();}
    Ok((registry,directory))
}
pub(super) struct ProjectBinding {
    pub directory: PathBuf,
    pub participant: String,
    pub summary: Value,
    registration: Registration,
    binding: Option<Value>,
    host: String,
    name: String,
    entry: Value,
    config_path: PathBuf,
    config_digest: String,
    project_identity: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectTarget {
    directory: PathBuf,
    participant: String,
    registration: Registration,
    binding: Option<Value>,
}
fn checked_project_index(path: &Path, project: &ProjectDirectory) -> Result<Connect> {
    let index = Connect::inspect(path)?;
    if index.registry.project_identity.as_ref().is_some_and(|wanted| project.identity().as_ref().ok() != Some(wanted)) {
        return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"));
    }
    Ok(index)
}
fn resolve_target(path: PathBuf, index: Connect) -> Result<Option<(PathBuf,String)>> {
    let Some(target) = index.registry.project_target else {
        if index.registry.participants.is_empty() && index.registry.sources.is_empty()
            && index.registry.setups.is_empty() && index.registry.approvals.is_empty() {return Ok(None)}
        return Ok(Some((path,String::new())));
    };
    if target.directory == path {return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))}
    let original=Connect::inspect(&target.directory)?;
    if original.registry.project_target.is_some()
        || original.registry.participants.get(&target.participant)!=Some(&target.registration)
        || target.binding.as_ref().is_some_and(|wanted|original.registry.verified_bindings.get(&target.participant)!=Some(wanted)) {
        return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
    }
    Ok(Some((target.directory,target.participant)))
}
pub(super) fn project_target(project:&Path)->Result<Option<(PathBuf,String)>> {
    let context=ProjectDirectory::open(project)?;
    if let Some(path)=crate::onboarding_state::project(project,"projects",false)? {
        if let Some(target)=resolve_target(path.clone(),checked_project_index(&path,&context)?)? {return Ok(Some(target))}
    }
    // Old project-local registries retain their exact source. A private path
    // that fails protection is a recovery blocker, never a new-identity fallback.
    let legacy=project.join(".peerwork/connect");
    match legacy.try_exists() {
        Ok(false)=>Ok(None),
        Err(_)=>Err(crate::onboarding_files::path_error(&legacy,"LEGACY_PRIVATE_REGISTRY","DISCOVER","PERMISSION_DENIED")),
        Ok(true)=>{
            let index=checked_project_index(&legacy,&context)?;
            context.verify()?;resolve_target(legacy,index)
        },
    }
}
pub(super) fn remember_project(project:&Path,choice:&ProjectBinding)->Result<()> {
    let context=ProjectDirectory::open(project)?;
    if context.identity()?!=choice.project_identity {return Err(local("PROJECT_SOURCE_CHANGED_REDISCOVER_ORIGINAL"))}
    let original=Connect::open(&choice.directory)?;
    if original.registry.participants.get(&choice.participant)!=Some(&choice.registration)
        || original.registry.verified_bindings.get(&choice.participant)!=choice.binding.as_ref()
        || !install::matches_installation(&original,project,&choice.host,&choice.name,&choice.entry)
        || read_project_config(&context,&choice.host)?.is_none_or(|bytes|sha256_hex(&bytes)!=choice.config_digest) {
        return Err(local("PROJECT_SOURCE_CHANGED_REDISCOVER_ORIGINAL"));
    }
    let directory=directory(project)?;
    if directory==choice.directory {return Ok(())}
    let mut index=Connect::open(&directory)?;
    if !index.registry.participants.is_empty() || !index.registry.sources.is_empty()
        || !index.registry.setups.is_empty() || index.registry.project_target.is_some() {return Err(local("PROJECT_BINDING_CHANGED_RESUME_ORIGINAL"))}
    index.registry.project_target=Some(ProjectTarget{directory:choice.directory.clone(),participant:choice.participant.clone(),registration:choice.registration.clone(),binding:choice.binding.clone()});
    context.verify()?;index.save()
}
pub(super) fn pin_project_binding(project:&Path,original:&Connect,participant:&str)->Result<()> {
    let Some(directory)=crate::onboarding_state::project(project,"projects",false)? else{return Ok(())};
    if directory==original.directory {return Ok(())}
    let mut index=Connect::open(&directory)?;
    if index.registry.project_identity.as_ref()!=Some(&ProjectDirectory::open(project)?.identity()?) {return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"))}
    let Some(target)=index.registry.project_target.as_mut() else{return Ok(())};
    if target.directory!=original.directory || target.participant!=participant {return Ok(())}
    if original.registry.participants.get(participant)!=Some(&target.registration) {return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))}
    let binding=original.registry.verified_bindings.get(participant).ok_or_else(||local("ORIGINAL_BINDING_VERIFICATION_REQUIRED"))?;
    match &target.binding {Some(old) if old!=binding=>Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED")),Some(_)=>Ok(()),None=>{target.binding=Some(binding.clone());index.save()}}
}
fn read_project_config(project:&ProjectDirectory,host:&str)->Result<Option<Vec<u8>>> {
    let name=if host=="codex"{".codex"}else{".agents"};
    let Some(directory)=project.child(name,false,false)? else{return Ok(None)};
    directory.read(if host=="codex"{"config.toml"}else{"mcp_config.json"},256*1024,false)
}
/// Project entries are bounded hints, never commands to execute or signer authority.
pub(super) fn project_bindings(project:&Path,workspace:Option<&str>)->Result<Vec<ProjectBinding>> {
    let context=ProjectDirectory::open(project)?;
    let project_identity=context.identity()?;
    let mut found=BTreeMap::new();
    for host in ["codex","agy"] {
        let path=project.join(if host=="codex"{".codex/config.toml"}else{".agents/mcp_config.json"});
        let Some(bytes)=read_project_config(&context,host)? else{continue};
        let entries:Vec<(String,Value)>=if host=="codex" {
            let doc=std::str::from_utf8(&bytes).ok().and_then(|s|s.parse::<toml_edit::DocumentMut>().ok()).ok_or_else(||local("DISCOVERY_INCOMPLETE"))?;
            doc.get("mcp_servers").and_then(|v|v.as_table_like()).map(|table|table.iter().filter_map(|(name,v)|{
                let command=v.get("command")?.as_str()?;
                let args=v.get("args")?.as_array()?.iter().map(|v|v.as_str().map(str::to_owned)).collect::<Option<Vec<_>>>()?;
                let mut entry=json!({"command":command,"args":args});
                if v.as_table_like().is_none_or(|table|table.iter().any(|(key,_)|!matches!(key,"command"|"args"))) {entry["unrecognized_installation_fields"]=json!(true)}
                Some((name.to_owned(),entry))
            }).collect()).unwrap_or_default()
        }else {
            let doc=peerwork_core::strict_json::parse_strict_json(&bytes).map_err(|_|local("DISCOVERY_INCOMPLETE"))?;
            doc["mcpServers"].as_object().map(|t|t.iter().map(|(n,v)|(n.clone(),v.clone())).collect()).unwrap_or_default()
        };
        if entries.len()>32 {return Err(local("DISCOVERY_INCOMPLETE"))}
        for (name,entry) in entries {
            if !name.starts_with("peerwork-"){continue}
            let Some(args)=entry["args"].as_array() else{continue};
            if args.len()!=8 || args[0]!="agent" || args[1]!="--local" || args[3]!="--participant" || args[5]!="--workspace" || args[7]!="mcp"{continue}
            let (Some(directory),Some(participant),Some(ws))=(args[2].as_str(),args[4].as_str(),args[6].as_str())else{continue};
            if workspace.is_some_and(|wanted|wanted!=ws){continue}
            let directory=PathBuf::from(directory);let original=Connect::inspect(&directory)?;
            if !install::matches_installation(&original,project,host,&name,&entry){return Err(local("PROJECT_INSTALLATION_PROVENANCE_REQUIRED"))}
            let registration=original.registry.participants.get(participant).ok_or_else(||local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
            let choice=format!("installed-{}",&sha256_hex(json!([directory,participant]).to_string().as_bytes())[..24]);
            found.insert(choice.clone(),ProjectBinding{directory,participant:participant.into(),registration:registration.clone(),binding:original.registry.verified_bindings.get(participant).cloned(),host:host.into(),name:name.clone(),entry:entry.clone(),config_path:path.clone(),config_digest:sha256_hex(&bytes),project_identity:project_identity.clone(),summary:json!({"handle":choice,"actor_id":registration.actor_id,"origin":registration.origin,"source":"VERIFIED_PROJECT_INSTALLATION","workspace_id":ws})});
            if found.len()>LIMIT{return Err(local("DISCOVERY_INCOMPLETE"))}
        }
    }
    context.verify()?;Ok(found.into_values().collect())
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    path:PathBuf,digest:String,engine:EngineConfig,runtime:Option<PathBuf>,client:Option<String>,namespace:Option<String>,
}
#[derive(Clone,Debug,Serialize)]
pub struct Discovery {
    pub state:String,
    pub candidates:Vec<Value>,
    pub next_action:String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic:Option<Value>,
}
pub fn directory(project:&Path)->Result<PathBuf> {
    let context=ProjectDirectory::open(project)?;let identity=context.identity()?;
    let path=crate::onboarding_state::project(project,"projects",true)?.unwrap();
    let mut index=Connect::open(&path)?;
    match &index.registry.project_identity {
        Some(old) if old!=&identity=>return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL")),
        Some(_)=>(),None=>{index.registry.project_identity=Some(identity);context.verify()?;index.save()?;},
    }
    Ok(path)
}
fn binding(engine: &EngineConfig) -> Result<String> {
    let options = engine.participant_config();
    Ok(sha256_hex(json!({"actor":options.expected_actor,"origin":options.origin,
        "state":options.state_directory,"journal":options.journal_path,"authority":options.authority}).to_string().as_bytes()))
}
fn validate_engine(engine: &EngineConfig) -> Result<()> {
    let options = engine.participant_config();
    if !token(&engine.expected_actor)
        || !options.identity_path.is_absolute()
        || !options.state_directory.is_absolute()
        || !options.journal_path.is_absolute()
        || [
            &options.identity_path,
            &options.state_directory,
            &options.journal_path,
        ]
        .iter()
        .any(|p| {
            p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        })
        || options
            .authority
            .as_ref()
            .is_some_and(|v| !crate::participant_migration::digest(v))
    {
        return Err(local("ORIGINAL_ENGINE_CONFIG_INVALID"));
    }
    crate::transport::canonical_lifecycle_origin(&engine.origin, engine.allow_loopback_http)
        .map_err(|_| local("ORIGINAL_ENGINE_CONFIG_INVALID"))?;
    options
        .transport
        .validate()
        .map_err(|_| local("ORIGINAL_TRANSPORT_INVALID"))?;
    // Discovery validates declarations only. Live activation proves the binding;
    // standalone activation checks the original namespace before opening a key.
    Ok(())
}
impl Connect {
    /// Shared scoped Agent entry. Model arguments choose opaque handles only;
    /// local trust sources and host authority cannot be supplied here.
    pub async fn connect_selected(
        &mut self,
        mut request: ConnectRequest,
        participant_pin: Option<&str>,
        workspace_pin: Option<&str>,
    ) -> Result<Value> {
        self.require_writer()?;
        if workspace_pin.is_some_and(|ws| ws != request.workspace_id) {
            return Err(local("FRONTEND_WORKSPACE_PIN_MISMATCH"));
        }
        if let Some(pin) = participant_pin {
            if !request.participant.is_empty() && request.participant != pin {
                return Err(local("FRONTEND_IDENTITY_PIN_MISMATCH"));
            }
            request.participant = pin.into();
        }
        let selected = match self.original_handle(
            (!request.participant.is_empty()).then_some(request.participant.as_str()),
        ) {
            Ok(selected) => selected,
            Err(error) if error.code == "IDENTITY_SELECTION_REQUIRED" => {
                return Ok(
                    json!({"state":"PENDING","discovery":self.discovery_summary(),"blocker":{"code":"IDENTITY_SELECTION_REQUIRED","next_actor":"LOCAL_RUNTIME_OWNER","next_action":"CHOOSE_ONE_PUBLIC_IDENTITY_HANDLE"}}),
                )
            }
            Err(error)
                if error.code == "LOCAL_SELECTION_REQUIRED"
                    && self.discovery_summary().candidates.is_empty() =>
            {
                let mut result = Self::selection_required(&request.setup_id);
                result["discovery"] = serde_json::to_value(self.discovery_summary()).unwrap();
                return Ok(result);
            }
            Err(error) => return Err(error),
        };
        let Some(handle) = selected else {
            return Ok(
                json!({"state":"PENDING","discovery":self.discovery_summary(),"blocker":{"code":"LOCAL_PROJECT_TRUST_REQUIRED","next_actor":"LOCAL_RUNTIME_OWNER","next_action":"RUN_NATIVE_CONNECT_ONCE_WITH_AUTHORIZED_PROJECT_CONTEXT"}}),
            );
        };
        request.participant = handle.clone();
        self.adopt(&handle).await?;
        let mut result = self.run_agent(request).await?;
        if let Some(value) = result.as_object_mut() {
            value.remove("profile_path");
        }
        result["local_profile"] = json!("PROTECTED_LOCAL_PROJECTION");
        Ok(result)
    }
    /// Explicit local CLI consent; MCP cannot supply trust roots or file paths.
    pub fn discover(&mut self, project: &Path, authorize_project: bool) -> Result<Discovery> {
        self.require_writer()?;
        // An explicitly selected original registry already supplies authority.
        // Role reuse must not depend on an unrelated shell cwd or read it.
        if !self.registry.participants.is_empty() || !self.registry.sources.is_empty() {
            return Ok(self.discovery_summary());
        }
        let project_context = ProjectDirectory::open(project)?;
        let identity=project_context.identity()?;
        match self.registry.trusted_project_identities.get(project) {
            Some(old) if old!=&identity=>return Err(local("PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL")),
            None if !authorize_project && self.registry.trusted_projects.iter().any(|p|p==project)=>return Err(local("LOCAL_PROJECT_RECONFIRMATION_REQUIRED")),
            _=>(),
        }
        if authorize_project {
            if !self.registry.trusted_projects.iter().any(|p|p==project){
                if self.registry.trusted_projects.len()>=LIMIT{return Err(local("DISCOVERY_SOURCE_LIMIT"))}
                self.registry.trusted_projects.push(project.into());
            }
            self.registry.trusted_project_identities.insert(project.into(),identity);
            project_context.verify()?;self.save()?;
        }
        if !self.registry.trusted_projects.iter().any(|p| p == project) {
            return Ok(Discovery {
                state: "LOCAL_PROJECT_TRUST_REQUIRED".into(),
                candidates: vec![],
                next_action: "AUTHORIZE_LOCAL_PROJECT_DISCOVERY_ONCE".into(),
                diagnostic: None,
            });
        }
        let root = project.join(".peerwork");
        let Some(source_root)=project_context.child(".peerwork",false,true)? else {return Ok(self.discovery_summary())};
        let mut found = BTreeMap::new();
        // A versioned fixed provider set, not filename guessing or a home scan.
        for (name, is_runtime) in [("engine.json", false), ("runtime.json", true)] {
            let path = root.join(name);
            let Some(bytes) = source_root.read(name, 65536, true)?
            else {
                continue;
            };
            let value = peerwork_core::strict_json::parse_strict_json(&bytes)
                .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
            let mut sources = Vec::new();
            if is_runtime {
                let runtime: RuntimeConfig = serde_json::from_value(value)
                    .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
                if runtime.format != "peerwork.participant-runtime.v1"
                    || runtime.engines.len() > LIMIT
                    || runtime.clients.len() > 32
                    || !runtime.state_directory.is_absolute()
                {
                    return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
                }
                for engine in &runtime.engines {
                    for client in runtime.clients.iter().filter(|c| c.engine == engine.name) {
                        if !identifier(&client.name) {
                            return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
                        }
                        client.capability.validate()?;
                        sources.push(Source {
                            path: path.clone(),
                            digest: sha256_hex(&bytes),
                            engine: engine.clone(),
                            runtime: Some(runtime.state_directory.clone()),
                            client: Some(client.name.clone()),
                            namespace: Some(format!("program:{}", client.name)),
                        });
                    }
                }
                if sources.is_empty() {
                    return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
                }
            } else {
                let engine: EngineConfig = serde_json::from_value(value)
                    .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
                sources.push(Source {
                    path: path.clone(),
                    digest: sha256_hex(&bytes),
                    engine,
                    runtime: None,
                    client: None,
                    namespace: None,
                });
            }
            for source in sources {
                validate_engine(&source.engine)?;
                let key = format!(
                    "identity-{}",
                    &sha256_hex(
                        json!([
                            source.engine.binding_digest()?,
                            source.runtime,
                            source.namespace
                        ])
                        .to_string()
                        .as_bytes()
                    )[..24]
                );
                found.entry(key).or_insert(source);
                if found.len() > LIMIT {
                    return Err(local("DISCOVERY_INCOMPLETE"));
                }
            }
        }
        project_context.verify()?;
        if !found.is_empty() {
            self.registry.sources = found;
            self.save()?;
        }
        Ok(self.discovery_summary())
    }
    pub(crate) fn discovery_summary(&self) -> Discovery {
        let mut candidates = BTreeMap::new();
        for (handle, source) in &self.registry.sources {
            candidates.insert(handle.clone(),json!({"handle":handle,"actor_id":source.engine.expected_actor,
                "origin":source.engine.origin,"source":if source.runtime.is_some(){"NATIVE_RUNTIME_V1"}else{"NATIVE_ENGINE_V1"},
                "binding":"SOURCE_PINNED","runtime":"NOT_OBSERVED"}));
        }
        for (handle, r) in &self.registry.participants {
            candidates.insert(
                handle.clone(),
                json!({"handle":handle,"actor_id":r.actor_id,"origin":r.origin,
                "source":"REGISTERED_ORIGINAL_BINDING","runtime":"NOT_OBSERVED"}),
            );
        }
        Discovery {
            diagnostic: candidates.is_empty().then(|| json!({
                "meaning":"NO_SUPPORTED_LOCAL_CLIENT_DISCOVERED",
                "identity_existence":"NOT_DETERMINED",
                "tools_require_state_migration":false,
                "existing_client_options":["SELECT_EXISTING_NATIVE_CLIENT_ENDPOINT","ATTACH_TO_OPEN_RUST_PARTICIPANT","CUSTOM_CLIENT_REQUIRES_EXPLICIT_ADAPTER"]
            })),
            state: match candidates.len() {
                0 => "NO_SUPPORTED_LOCAL_CLIENT_FOUND",
                1 => "IDENTITY_AVAILABLE",
                _ => "IDENTITY_SELECTION_REQUIRED",
            }
            .into(),
            next_action: match candidates.len() {
                0 => "ATTACH_EXISTING_CLIENT_OR_SELECT_NATIVE_INSTALLATION",
                1 => "RESUME_CONNECT",
                _ => "CHOOSE_ONE_PUBLIC_IDENTITY_HANDLE",
            }
            .into(),
            candidates: candidates.into_values().collect(),
        }
    }
    pub(crate) fn original_handle(&self, selected: Option<&str>) -> Result<Option<String>> {
        let summary = self.discovery_summary();
        if let Some(handle) = selected {
            if summary.candidates.iter().any(|v| v["handle"] == handle) {
                return Ok(Some(handle.into()));
            }
            return Err(local("LOCAL_SELECTION_REQUIRED"));
        }
        match summary.candidates.as_slice() {
            [] => Ok(None),
            [only] => Ok(only["handle"].as_str().map(str::to_owned)),
            _ => Err(local("IDENTITY_SELECTION_REQUIRED")),
        }
    }
    pub(super) async fn verify_registered(
        &self,
        handle: &str,
        client: &RuntimeClient,
    ) -> Result<()> {
        if let Some(expected) = self.registry.verified_bindings.get(handle) {
            let observed = client.call(json!({"method":"binding"})).await?;
            for field in [
                "actor_id",
                "origin",
                "engine_digest",
                "state_binding",
                "namespace",
                "client_generation",
            ] {
                if observed[field] != expected[field] {
                    return Err(local("ORIGINAL_RUNTIME_BINDING_CHANGED"));
                }
            }
        } else {
            return Err(local("ORIGINAL_BINDING_VERIFICATION_REQUIRED"));
        }
        Ok(())
    }
    pub(super) async fn original_client(&self, handle: &str) -> Result<RuntimeClient> {
        let selected = self
            .registry
            .participants
            .get(handle)
            .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let binding = self
            .registry
            .verified_bindings
            .get(handle)
            .cloned()
            .ok_or_else(|| local("ORIGINAL_BINDING_VERIFICATION_REQUIRED"))?;
        RuntimeClient::connect_bound(
            selected.endpoint_path.clone(),
            &selected.origin,
            &selected.actor_id,
            binding,
        )
        .await
    }
    /// Activation is separate from read-only discovery. Original ownership
    /// fences remain the only path to opening a signer; state is never copied.
    pub(crate) async fn adopt(&mut self, handle: &str) -> Result<()> {
        if let Some(r) = self.registry.participants.get(handle).cloned() {
            if self.registry.verified_bindings.contains_key(handle) {
                match self.original_client(handle).await {Ok(_)=>return Ok(()),Err(error) if matches!(error.code.as_str(),"ORIGINAL_RUNTIME_BINDING_CHANGED"|"ORIGINAL_RUNTIME_BINDING_INVALID"|"CLIENT_IDENTITY_OR_ORIGIN_MISMATCH"|"CLIENT_BINDING_INVALID")=>return Err(error),Err(_)=>()}
            }
            let original = self.directory.join(format!("runtime-{handle}"));
            let owned_proof = r.endpoint_path == original.join("client-bootstrap.json")
                && original.join("config.json").is_file()
                && original.join("bootstrap.state").is_file();
            if (!self.registry.verified_bindings.contains_key(handle)
                || self.registry.local_runtime_admins.get(handle)
                    != Some(&original.join("admin.json")))
                && owned_proof
            {
                let bytes =
                    crate::onboarding_project::read_private_source(&original.join("config.json"), 65536)?
                        .ok_or_else(|| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
                let config: RuntimeConfig = serde_json::from_value(
                    peerwork_core::strict_json::parse_strict_json(&bytes)
                        .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?,
                )
                .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
                if config.engines.len() != 1 {
                    return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
                }
                self.bootstrap(handle, config.engines[0].clone()).await?;
            }
            if !self.registry.verified_bindings.contains_key(handle) {
                return Err(local("ORIGINAL_BINDING_VERIFICATION_REQUIRED"));
            }
            let client = match RuntimeClient::connect(r.endpoint_path, &r.origin, &r.actor_id).await
            {
                Ok(client) => client,
                Err(error) => {
                    // Only our original launch record can authorize restarting
                    // this resident runtime. External IPC failure never does.
                    let directory = self.directory.join(format!("runtime-{handle}"));
                    if self.registry.local_runtime_admins.get(handle)
                        != Some(&directory.join("admin.json"))
                    {
                        return Err(error);
                    }
                    let wire = crate::onboarding_project::read_private_source(
                        &directory.join("config.json"),
                        65536,
                    )?
                    .ok_or_else(|| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
                    let config: RuntimeConfig = serde_json::from_value(
                        peerwork_core::strict_json::parse_strict_json(&wire)
                            .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?,
                    )
                    .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
                    if config.engines.len() != 1 {
                        return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
                    }
                    self.bootstrap(handle, config.engines[0].clone()).await?;
                    let r = &self.registry.participants[handle];
                    RuntimeClient::connect(r.endpoint_path.clone(), &r.origin, &r.actor_id).await?
                }
            };
            return self.verify_registered(handle, &client).await;
        }
        let source = self
            .registry
            .sources
            .get(handle)
            .cloned()
            .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let bytes = crate::onboarding_project::read_private_source(&source.path, 65536)?
            .ok_or_else(|| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
        if sha256_hex(&bytes) != source.digest {
            return Err(local("ORIGINAL_SOURCE_CHANGED_RECOVERY_REQUIRED"));
        }
        validate_engine(&source.engine)?;
        if let Some(directory) = &source.runtime {
            let endpoint =
                directory.join(format!("client-{}.json", source.client.as_deref().unwrap()));
            let client = RuntimeClient::connect(
                endpoint.clone(),
                &source.engine.origin,
                &source.engine.expected_actor,
            )
            .await
            .map_err(|_| local("ORIGINAL_RUNTIME_REQUIRED_NO_REPLACEMENT_STARTED"))?;
            let observed = client
                .call(json!({"method":"binding"}))
                .await
                .map_err(|_| local("LOCAL_RUNTIME_UPGRADE_REQUIRED"))?;
            if observed["engine_digest"] != source.engine.binding_digest()?
                || observed["state_binding"] != binding(&source.engine)?
                || observed["namespace"] != source.namespace.as_deref().unwrap()
                || !observed["client_generation"].is_null()
            {
                return Err(local("ORIGINAL_RUNTIME_BINDING_CHANGED"));
            }
            // Recheck before publishing; an altered source cannot gain the
            // original runtime's authority even when its actor is unchanged.
            if crate::onboarding_project::read_private_source(&source.path, 65536)?.as_deref()
                != Some(bytes.as_slice())
            {
                return Err(local("ORIGINAL_SOURCE_CHANGED_RECOVERY_REQUIRED"));
            }
            self.register_pinned(
                handle,
                Registration {
                    origin: source.engine.origin.clone(),
                    actor_id: source.engine.expected_actor.clone(),
                    endpoint_path: endpoint,
                },
                Some(observed),
                None,
            )
            .await?;
            // Business owner capability is not runtime administration. External
            // host setup requires a separately selected local admin delegation.
            return Ok(());
        }
        bootstrap::automatic_namespace(&self.directory,&source.engine)?;
        // A standalone config may name an already active non-managed signer.
        // Take its original fences before creating any runtime/launch output.
        // Holding either fence means activation must stay pending.
        let managed = self.directory.join(format!("runtime-{handle}"));
        if !managed.join("bootstrap.state").exists() {
            let options = source.engine.participant_config();
            for path in [
                options.state_directory.join("engine-owner.state"),
                options
                    .journal_path
                    .with_extension("participant-owner.state"),
            ] {
                // The ownership lock exists before its first state payload.
                // Checking only the .state file misses an engine opening now.
                match std::fs::symlink_metadata(path.parent().unwrap()) {
                    Ok(_) => {
                        let guard = SecureStateStore::open(&path).map_err(|_| {
                            local("ORIGINAL_STATE_ALREADY_OWNED_USE_EXISTING_RUNTIME")
                        })?;
                        drop(guard);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(_) => return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED")),
                }
            }
            if options.journal_path.exists()
                || options.state_directory.join("participant.sqlite").exists()
                || options.state_directory.join("engine-owner.state").exists()
            {
                return Err(local(
                    "ORIGINAL_CLIENT_NAMESPACE_REQUIRED_USE_RUNTIME_INSTALLATION",
                ));
            }
        }
        self.bootstrap(handle, source.engine).await?;
        let selected = &self.registry.participants[handle];
        let client = RuntimeClient::connect(
            selected.endpoint_path.clone(),
            &selected.origin,
            &selected.actor_id,
        )
        .await?;
        let observed = client.call(json!({"method":"binding"})).await?;
        self.verify_registered(handle, &client).await?;
        if self.registry.verified_bindings.get(handle)
            != Some(&crate::communication_runtime::canonical_binding(&observed))
        {
            return Err(local("ORIGINAL_RUNTIME_BINDING_CHANGED"));
        }
        Ok(())
    }
    pub(super) fn normalize_request(&self, mut r: ConnectRequest) -> Result<ConnectRequest> {
        if r.participant.is_empty() {
            r.participant = self
                .original_handle(None)?
                .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        }
        if r.setup_id.is_empty() {
            r.setup_id = format!(
                "connect-{}",
                &sha256_hex(
                    serde_json::to_vec(&r)
                        .map_err(|_| local("CONNECT_ARGUMENT_INVALID"))?
                        .as_slice()
                )[..32]
            );
        }
        r.validate()?;
        Ok(r)
    }
    pub(super) fn normalize_agent_request(&self, r: ConnectRequest) -> Result<ConnectRequest> {
        let automatic = r.setup_id.is_empty();
        let mut r = self.normalize_request(r)?;
        if automatic {
            r.setup_id = format!("agent-{}", r.setup_id.trim_start_matches("connect-"));
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(project: &Path) -> EngineConfig {
        let identity_path = project.join("identity");
        let id = crate::kernel_identity::KernelIdentity::create(&identity_path).unwrap();
        EngineConfig {
            name: "original".into(),
            origin: "http://127.0.0.1:1".into(),
            expected_actor: id.actor_id().into(),
            identity_path,
            state_directory: project.join("original-state"),
            journal_path: Some(project.join("original-journal.sqlite")),
            authority: Some(sha256_hex(b"original-authority")),
            allow_loopback_http: true,
            transport: Default::default(),
            max_inflight: 1,
            max_pending: 2,
            max_stored_bytes: 1024 * 1024,
            migration_sources: vec![],
        }
    }
    fn write(path: &Path, value: &impl Serialize) {
        if let Some(parent)=path.parent(){if !parent.exists(){let base=ProjectDirectory::open(parent.parent().unwrap()).unwrap();base.child(parent.file_name().unwrap().to_str().unwrap(),true,true).unwrap();}}
        write_private(path, &serde_json::to_vec(value).unwrap()).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn shared_project_installs_and_reuses_original_without_private_repo_state(){
        use std::os::unix::fs::{PermissionsExt,MetadataExt};
        let t=crate::test_support::protected_test_dir();let shared=t.path().join("shared");std::fs::create_dir(&shared).unwrap();std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o775)).unwrap();
        let project=shared.join("repo");std::fs::create_dir(&project).unwrap();
        let index=directory(&project).unwrap();assert!(!index.starts_with(&project));assert!(!project.join(".peerwork").exists());
        let original=t.path().join("original");let mut c=Connect::open(&original).unwrap();
        c.registry.participants.insert("worker".into(),Registration{origin:"https://api.peerwork.dev".into(),actor_id:"A".repeat(43),endpoint_path:t.path().join("client.json")});c.save().unwrap();
        let spec=Installation{host:"codex".into(),project:project.clone(),executable:std::env::current_exe().unwrap()};
        c.install("worker",&"W".repeat(43),spec).unwrap();drop(c);
        assert!(project.join(".agents/.peerwork-installation").is_file());
        assert!(!project.join(".agents/.peerwork-installation/ownership.state").exists());
        let choices=project_bindings(&project,None).unwrap();assert_eq!(choices.len(),1);remember_project(&project,&choices[0]).unwrap();
        assert_eq!(project_target(&project).unwrap(),Some((original.clone(),"worker".into())));
        assert_eq!(Connect::inspect(&original).unwrap().registry.participants["worker"].actor_id,"A".repeat(43));
        assert_eq!(std::fs::metadata(shared).unwrap().mode()&0o777,0o775);
    }
    #[cfg(unix)]
    #[test]
    fn explicit_empty_registry_pins_failed_project_discovery_across_reentry(){
        let t=crate::test_support::protected_test_dir();let project=t.path().join("project");std::fs::create_dir(&project).unwrap();
        let local=t.path().join("local");let mut c=Connect::open(&local).unwrap();
        c.discover(&project,true).unwrap();drop(c);
        std::fs::rename(&project,t.path().join("original-project")).unwrap();std::fs::create_dir(&project).unwrap();
        let mut c=Connect::open(&local).unwrap();assert!(matches!(c.discover(&project,false),Err(e)if e.code=="PROJECT_DIRECTORY_CHANGED_RESELECT_ORIGINAL"));
        assert!(c.registry.sources.is_empty()&&c.registry.participants.is_empty());
    }
    #[cfg(unix)]
    #[test]
    fn legacy_registry_confirmation_pins_original_directory_without_moving_state(){
        use std::os::unix::fs::{PermissionsExt,DirBuilderExt};
        let t=crate::test_support::protected_test_dir();let shared=t.path().join("shared");create_private_state_directory(&shared).unwrap();let local=shared.join("local");
        let mut c=Connect::open(&local).unwrap();c.registry.participants.insert("worker".into(),Registration{origin:"https://api.peerwork.dev".into(),actor_id:"A".repeat(43),endpoint_path:local.join("endpoint.json")});c.save().unwrap();drop(c);
        let before=std::fs::read(local.join("connect.state")).unwrap();std::fs::write(local.join("original-journal"),b"unresolved original command: keep-id").unwrap();
        std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o775)).unwrap();
        let error=Connect::inspect(&local).err().unwrap();assert_eq!(error.code,"ORIGINAL_LOCAL_REGISTRY_CONFIRMATION_REQUIRED");assert!(!serde_json::to_string(&error).unwrap().contains(local.to_str().unwrap()));
        let local_result=super::super::cli(&["--local".to_owned(),local.to_str().unwrap().to_owned(),"--context".to_owned()]);
        assert_eq!(local_result["local_command"][3],local.to_str().unwrap());assert_eq!(local_result["local_command"][5],"--confirm-original");
        confirm_original_store(&local).unwrap();assert_eq!(std::fs::read(local.join("connect.state")).unwrap(),before);
        let mut c=Connect::open(&local).unwrap();assert_eq!(c.registry.participants["worker"].actor_id,"A".repeat(43));c.save().unwrap();drop(c);
        assert_eq!(std::fs::read(local.join("original-journal")).unwrap(),b"unresolved original command: keep-id");
        assert_eq!(std::fs::read(local.join("connect.state")).unwrap(),before);
        std::fs::rename(&local,shared.join("moved-original")).unwrap();std::fs::DirBuilder::new().mode(0o700).create(&local).unwrap();
        // Even a valid same-user clone cannot silently replace the confirmed inode.
        std::fs::write(local.join("connect.state"),before).unwrap();std::fs::set_permissions(local.join("connect.state"),std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(Connect::inspect(&local),Err(e)if e.code=="ORIGINAL_REGISTRY_DIRECTORY_CHANGED"));
    }
    #[test]
    fn missing_installation_is_not_a_missing_identity_or_migration_requirement() {
        let temp = crate::test_support::protected_test_dir();
        let mut connect = Connect::open(&temp.path().join("local")).unwrap();
        let discovery = connect.discover(temp.path(), true).unwrap();
        assert_eq!(discovery.state, "NO_SUPPORTED_LOCAL_CLIENT_FOUND");
        assert_eq!(discovery.next_action, "ATTACH_EXISTING_CLIENT_OR_SELECT_NATIVE_INSTALLATION");
        let diagnostic = discovery.diagnostic.unwrap();
        assert_eq!(diagnostic["identity_existence"], "NOT_DETERMINED");
        assert_eq!(diagnostic["tools_require_state_migration"], false);
        assert!(!temp.path().join("identity").exists());
        assert!(!temp.path().join("engine").exists());
    }
    #[test]
    fn discovery_requires_consent_and_never_opens_engine_or_exposes_paths() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let dir = directory(project).unwrap();
        let config = engine(project);
        write(&project.join(".peerwork/engine.json"), &config);
        let mut connect = Connect::open(&dir).unwrap();
        assert_eq!(
            connect.discover(project, false).unwrap().state,
            "LOCAL_PROJECT_TRUST_REQUIRED"
        );
        assert!(!config.state_directory.exists());
        assert!(!config.journal_path.as_ref().unwrap().exists());
        let found = connect.discover(project, true).unwrap();
        assert_eq!(found.candidates.len(), 1);
        let public = serde_json::to_string(&found).unwrap();
        assert!(!public.contains(&project.to_string_lossy().to_string()));
        assert!(!public.contains("seed"));
        assert!(!config.state_directory.exists());
        assert!(!config.journal_path.as_ref().unwrap().exists());
        drop(connect);
        let mut resumed = Connect::open(&dir).unwrap();
        assert_eq!(
            resumed.discover(project, false).unwrap().candidates,
            found.candidates
        );
    }
    #[test]
    fn same_actor_different_journal_requires_one_selection() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let dir = directory(project).unwrap();
        let a = engine(project);
        let mut b = a.clone();
        b.name = "other-journal".into();
        b.journal_path = Some(project.join("different.sqlite"));
        let runtime = RuntimeConfig {
            format: "peerwork.participant-runtime.v1".into(),
            state_directory: project.join("runtime"),
            engines: vec![a, b],
            clients: vec![
                crate::communication_runtime::ClientConfig {
                    name: "a".into(),
                    engine: "original".into(),
                    capability: Capability::owner(),
                },
                crate::communication_runtime::ClientConfig {
                    name: "b".into(),
                    engine: "other-journal".into(),
                    capability: Capability::owner(),
                },
            ],
            hosts: vec![],
        };
        write(&project.join(".peerwork/runtime.json"), &runtime);
        let mut c = Connect::open(&dir).unwrap();
        assert_eq!(
            c.discover(project, true).unwrap().state,
            "IDENTITY_SELECTION_REQUIRED"
        );
        assert_eq!(
            c.original_handle(None).unwrap_err().code,
            "IDENTITY_SELECTION_REQUIRED"
        );
        let name = c.discovery_summary().candidates[0]["handle"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(c.original_handle(Some(&name)).unwrap(), Some(name));
    }
    #[test]
    fn existing_binding_prevents_substitution_from_different_project_identity() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let dir = directory(project).unwrap();
        let config = engine(project);
        write(&project.join(".peerwork/engine.json"), &config);
        let mut c = Connect::open(&dir).unwrap();
        c.registry.participants.insert(
            "original".into(),
            Registration {
                origin: config.origin,
                actor_id: "A".repeat(43),
                endpoint_path: project.join("missing.json"),
            },
        );
        let found = c.discover(project, true).unwrap();
        assert_eq!(found.candidates.len(), 1);
        assert_eq!(found.candidates[0]["handle"], "original");
        assert!(c.registry.sources.is_empty());
        assert_eq!(c.discover(&project.join("unrelated-missing-project"),false).unwrap().candidates,found.candidates);
    }
    #[tokio::test]
    async fn changed_source_and_live_owner_do_not_launch_another_runtime() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let dir = directory(project).unwrap();
        let config = engine(project);
        let path = project.join(".peerwork/engine.json");
        write(&path, &config);
        let mut c = Connect::open(&dir).unwrap();
        c.discover(project, true).unwrap();
        let handle = c.original_handle(None).unwrap().unwrap();
        let mut other = config.clone();
        other.authority = None;
        crate::onboarding_files::replace(&path, &serde_json::to_vec(&other).unwrap()).unwrap();
        assert_eq!(
            c.adopt(&handle).await.unwrap_err().code,
            "ORIGINAL_SOURCE_CHANGED_RECOVERY_REQUIRED"
        );
        crate::onboarding_files::replace(&path, &serde_json::to_vec(&config).unwrap()).unwrap();
        create_private_state_directory(&config.state_directory).unwrap();
        let _owner =
            SecureStateStore::open(&config.state_directory.join("engine-owner.state")).unwrap();
        assert_eq!(
            c.adopt(&handle).await.unwrap_err().code,
            "ORIGINAL_STATE_ALREADY_OWNED_USE_EXISTING_RUNTIME"
        );
        assert!(!dir.join(format!("runtime-{handle}")).exists());
        assert!(!config.journal_path.as_ref().unwrap().exists());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_and_unreadable_provider_are_not_no_identity() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let dir = directory(project).unwrap();
        let config = engine(project);
        write(&project.join("original.json"), &config);
        crate::onboarding_files::directory(&project.join(".peerwork"),true).unwrap();
        std::os::unix::fs::symlink(
            project.join("original.json"),
            project.join(".peerwork/engine.json"),
        )
        .unwrap();
        let mut c = Connect::open(&dir).unwrap();
        assert_eq!(
            c.discover(project, true).unwrap_err().code,
            "ONBOARDING_PATH_UNSAFE"
        );
        assert!(c.registry.sources.is_empty());
    }
    #[test]
    fn default_request_is_stable_and_cannot_infer_a_second_identity() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let dir = directory(project).unwrap();
        let config = engine(project);
        write(&project.join(".peerwork/engine.json"), &config);
        let mut c = Connect::open(&dir).unwrap();
        c.discover(project, true).unwrap();
        let request: ConnectRequest =
            serde_json::from_value(json!({"workspace_id":"W".repeat(43)})).unwrap();
        let first = c.normalize_request(request.clone()).unwrap();
        let second = c.normalize_request(request).unwrap();
        assert!(first == second);
        assert!(first.send);
        assert!(first.receive);
        let public=crate::participant_connect::schema();
        assert_eq!(public["properties"]["request"]["properties"]["send"]["default"],first.send);
        assert_eq!(public["properties"]["request"]["properties"]["receive"]["default"],first.receive);
        assert!(!first.setup_id.is_empty());
        assert!(!first.participant.is_empty());
    }
    #[test]
    fn existing_default_binding_wins_and_project_reference_cannot_fall_through() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path();
        let directory = directory(project).unwrap();
        let mut c = Connect::open(&directory).unwrap();
        c.registry.participants.insert(
            "a".into(),
            Registration {
                origin: "https://example.invalid".into(),
                actor_id: "A".repeat(43),
                endpoint_path: project.join("missing.json"),
            },
        );
        c.save().unwrap();
        drop(c);
        assert_eq!(
            project_target(project).unwrap(),
            Some((directory.clone(), String::new()))
        );
        std::fs::remove_file(directory.join("connect.state")).unwrap();
        assert!(
            matches!(project_target(project),Err(e) if e.code=="CONNECT_ORIGINAL_BINDING_RECOVERY_REQUIRED")
        );
    }
    #[cfg(unix)]
    #[tokio::test(flavor="multi_thread",worker_threads=2)]
    #[ignore="requires loopback IPC permission"]
    async fn confirmed_legacy_reuses_live_bound_runtime_without_admin_repair_or_launch(){
        use crate::communication_runtime::{self as ipc,ClientConfig};
        use std::os::unix::fs::PermissionsExt;
        let t=crate::test_support::protected_test_dir();let shared=t.path().join("shared");create_private_state_directory(&shared).unwrap();
        let local=shared.join("original");let mut c=Connect::open(&local).unwrap();let e=engine(t.path());
        let config=RuntimeConfig{format:"peerwork.participant-runtime.v1".into(),state_directory:local.join("runtime-worker"),engines:vec![e.clone()],clients:vec![ClientConfig{name:"bootstrap".into(),engine:e.name.clone(),capability:Capability::owner()}],hosts:vec![]};
        let cancel=crate::KernelCancellationToken::new();let(tx,rx)=tokio::sync::oneshot::channel();let running=tokio::spawn(ipc::serve(config.clone(),cancel.clone(),tx));let ready=rx.await.unwrap().unwrap();
        let registration=Registration{origin:crate::transport::canonical_lifecycle_origin(&e.origin,true).unwrap(),actor_id:e.expected_actor.clone(),endpoint_path:ready.client_endpoints["bootstrap"].clone()};
        let client=RuntimeClient::connect(registration.endpoint_path.clone(),&registration.origin,&registration.actor_id).await.unwrap();let binding=client.call(json!({"method":"binding"})).await.unwrap();
        write(&config.state_directory.join("config.json"),&config);
        let launch=SecureStateStore::open(&config.state_directory.join("bootstrap.state")).unwrap();launch.write_exact(&serde_json::to_vec(&json!({"config_digest":sha256_hex(&serde_json::to_vec(&config).unwrap()),"pid":std::process::id(),"process_token":crate::communication_store::process_token(std::process::id())})).unwrap()).unwrap();drop(launch);
        c.registry.participants.insert("worker".into(),registration);c.registry.verified_bindings.insert("worker".into(),crate::communication_runtime::canonical_binding(&binding));c.save().unwrap();drop(c);
        std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o775)).unwrap();confirm_original_store(&local).unwrap();
        let mut c=Connect::open(&local).unwrap();c.adopt("worker").await.unwrap();assert!(c.registry.local_runtime_admins.is_empty());assert_eq!(c.registry.verified_bindings["worker"]["namespace"],"program:bootstrap");
        assert_eq!(c.original_client("worker").await.unwrap().call(json!({"method":"binding"})).await.unwrap()["namespace"],"program:bootstrap");
        drop(c);cancel.cancel();running.await.unwrap().unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires loopback IPC permission"]
    async fn v032_registry_recovers_original_owned_launch_and_namespace_without_new_signer() {
        use crate::communication_runtime::{self as ipc, ClientConfig};
        let root = crate::test_support::protected_test_dir();
        let directory = root.path().join("original-local");
        let mut c = Connect::open(&directory).unwrap();
        let mut e = engine(root.path());
        e.name = "selected".into();
        e.origin = crate::transport::canonical_lifecycle_origin(&e.origin, true).unwrap();
        let runtime = directory.join("runtime-worker");
        create_private_state_directory(&runtime).unwrap();
        let config = RuntimeConfig {
            format: "peerwork.participant-runtime.v1".into(),
            state_directory: runtime.clone(),
            engines: vec![e.clone()],
            clients: vec![ClientConfig {
                name: "bootstrap".into(),
                engine: "selected".into(),
                capability: Capability::owner(),
            }],
            hosts: vec![],
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        write_private(&runtime.join("config.json"), &bytes).unwrap();
        let launch = SecureStateStore::open(&runtime.join("bootstrap.state")).unwrap();
        launch.write_exact(&serde_json::to_vec(&json!({"config_digest":sha256_hex(&bytes),"pid":std::process::id(),"process_token":crate::communication_store::process_token(std::process::id())})).unwrap()).unwrap();
        drop(launch);
        let cancel = crate::KernelCancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let running = tokio::spawn(ipc::serve(config, cancel.clone(), tx));
        let ready = rx.await.unwrap().unwrap();
        // Exact old public schema, including the old registration/admin crash
        // window. No verified_bindings, sources, trust roots or project target.
        let selected = Registration {
            origin: e.origin.clone(),
            actor_id: e.expected_actor.clone(),
            endpoint_path: ready.client_endpoints["bootstrap"].clone(),
        };
        let old = json!({"participants":{"worker":selected},"setups":{},"active":null,"active_by_scope":{},"approvals":{},"installations":{},"hosts":{},"local_runtime_admins":{}});
        c.store
            .as_ref()
            .unwrap()
            .write_exact(&serde_json::to_vec(&old).unwrap())
            .unwrap();
        drop(c);
        let mut c = Connect::open(&directory).unwrap();
        assert!(c.registry.verified_bindings.is_empty());
        c.adopt("worker").await.unwrap();
        assert_eq!(
            c.registry.verified_bindings["worker"]["namespace"],
            "program:bootstrap"
        );
        assert_eq!(
            c.registry.local_runtime_admins["worker"],
            ready.admin_endpoint
        );
        let raw = SecureStateStore::read_snapshot(&directory.join("connect.state"), 65536).unwrap();
        let saved: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            saved["verified_bindings"]["worker"]["namespace"],
            "program:bootstrap"
        );
        assert!(saved["local_runtime_admins"]["worker"].is_string());
        drop(c);
        cancel.cancel();
        running.await.unwrap().unwrap();
    }
    #[test]
    fn existing_installation_is_found_without_copying_an_engine_config() {
        let temp = crate::test_support::protected_test_dir();
        let project = temp.path().join("project");
        crate::onboarding_files::directory(&project, false).unwrap();
        let original = temp.path().join("arbitrary-original-local");
        let mut c = Connect::open(&original).unwrap();
        c.registry.participants.insert(
            "worker".into(),
            Registration {
                origin: "https://api.peerwork.dev".into(),
                actor_id: "A".repeat(43),
                endpoint_path: temp.path().join("endpoint.json"),
            },
        );
        c.save().unwrap();
        let ws = "W".repeat(43);
        c.install(
            "worker",
            &ws,
            Installation {
                host: "codex".into(),
                project: project.clone(),
                executable: std::env::current_exe().unwrap(),
            },
        )
        .unwrap();
        drop(c);
        let bindings = project_bindings(&project, Some(&ws)).unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].directory, original);
        assert!(!project.join(".peerwork/engine.json").exists());
        assert!(!project.join(".peerwork/runtime.json").exists());
        assert!(!bindings[0]
            .summary
            .to_string()
            .contains(&original.to_string_lossy().to_string()));
        let source = &bindings[0];
        let config = std::fs::read(&source.config_path).unwrap();
        let changed = format!(
            "{}\n[mcp_servers.{}.env]\nTEST = \"changed\"\n",
            String::from_utf8(config.clone()).unwrap(),
            source.name
        );
        crate::onboarding_files::replace(&source.config_path, changed.as_bytes()).unwrap();
        assert!(
            matches!(project_bindings(&project,Some(&ws)),Err(e) if e.code=="PROJECT_INSTALLATION_PROVENANCE_REQUIRED")
        );
        crate::onboarding_files::replace(&source.config_path, &config).unwrap();
        let mut c = Connect::open(&original).unwrap();
        c.registry.participants.get_mut("worker").unwrap().actor_id = "B".repeat(43);
        c.save().unwrap();
        drop(c);
        assert!(
            matches!(remember_project(&project,source),Err(e) if e.code=="PROJECT_SOURCE_CHANGED_REDISCOVER_ORIGINAL")
        );
        assert!(!project.join(".peerwork").exists());
        let mut c = Connect::open(&original).unwrap();
        c.registry.participants.get_mut("worker").unwrap().actor_id = "A".repeat(43);
        c.save().unwrap();
        drop(c);
        // Project text alone is not permission: remove the original ownership
        // record and make the exact same config resolve to a recovery blocker.
        let mut c = Connect::open(&original).unwrap();
        c.registry.installations.clear();
        c.save().unwrap();
        drop(c);
        assert!(
            matches!(remember_project(&project,source),Err(e) if e.code=="PROJECT_SOURCE_CHANGED_REDISCOVER_ORIGINAL")
        );
        assert!(!project.join(".peerwork").exists());
        assert!(
            matches!(project_bindings(&project,Some(&ws)),Err(e) if e.code=="PROJECT_INSTALLATION_PROVENANCE_REQUIRED")
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires loopback IPC permission"]
    async fn pinned_client_rejects_same_actor_different_namespace_after_descriptor_replacement() {
        use crate::communication_runtime::{self as ipc, ClientConfig};
        let temp = crate::test_support::protected_test_dir();
        let e = engine(temp.path());
        let config = RuntimeConfig {
            format: "peerwork.participant-runtime.v1".into(),
            state_directory: temp.path().join("runtime"),
            engines: vec![e.clone()],
            clients: ["a", "b"]
                .into_iter()
                .map(|n| ClientConfig {
                    name: n.into(),
                    engine: e.name.clone(),
                    capability: Capability::owner(),
                })
                .collect(),
            hosts: vec![],
        };
        let cancel = crate::KernelCancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let running = tokio::spawn(ipc::serve(config, cancel.clone(), tx));
        let ready = rx.await.unwrap().unwrap();
        let source = &ready.client_endpoints["a"];
        let a = RuntimeClient::connect(source.clone(), &e.origin, &e.expected_actor)
            .await
            .unwrap();
        let binding = a.call(json!({"method":"binding"})).await.unwrap();
        assert_eq!(binding["namespace"], "program:a");
        let pinned =
            RuntimeClient::connect_bound(source.clone(), &e.origin, &e.expected_actor, binding)
                .await
                .unwrap();
        let original = std::fs::read(source).unwrap();
        crate::onboarding_files::replace(
            source,
            &std::fs::read(&ready.client_endpoints["b"]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            pinned
                .call(json!({"method":"operations","after":"","limit":1}))
                .await
                .unwrap_err()
                .code,
            "ORIGINAL_RUNTIME_BINDING_CHANGED"
        );
        crate::onboarding_files::replace(source, &original).unwrap();
        assert!(pinned
            .call(json!({"method":"operations","after":"","limit":1}))
            .await
            .is_ok());
        cancel.cancel();
        running.await.unwrap().unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires rebuilt native CLI, synthetic PostgreSQL and HTTP fixture"]
    async fn cold_cli_finds_old_installation_defers_host_and_program_mode_remains_explicit() {
        use crate::communication_runtime::{self as ipc, ClientConfig};
        use crate::participant::http_tests::{configuration, mutate, selected, Service};
        use crate::participant::ParticipantClient;
        let service = Service::start();
        let root = crate::test_support::protected_test_dir();
        let participant = root.path().join("participant");
        create_private_state_directory(&participant).unwrap();
        let options = configuration(&participant, &service.origin);
        let owner = ParticipantClient::open(options.clone()).await.unwrap();
        let created = mutate(
            &owner,
            "cold-create",
            "structure.workspace.create",
            &Scope::default(),
            json!({"name":"Cold connect"}),
        )
        .await;
        let ws = created["workspace_id"].as_str().unwrap().to_owned();
        let scope = Scope {
            workspace_id: Some(ws.clone()),
            ..Default::default()
        };
        let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
        mutate(&owner,"cold-grant","structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await;
        let mut extra_spaces = Vec::new();
        for (id, grant) in [("host-recovery", true), ("host-approval", false)] {
            let space = mutate(
                &owner,
                &format!("{id}-create"),
                "structure.workspace.create",
                &Scope::default(),
                json!({"name":id}),
            )
            .await;
            let ws = space["workspace_id"].as_str().unwrap().to_owned();
            if grant {
                let scope = Scope {
                    workspace_id: Some(ws.clone()),
                    ..Default::default()
                };
                let meta = selected(&owner, "structure.workspace.get", &scope, json!({})).await;
                mutate(&owner,&format!("{id}-grant"),"structure.communication.grant.set",&scope,json!({"actor_id":owner.actor_id(),"membership_id":meta["membership"]["membership_id"],"expected_revision":null,"send":true,"receive":true})).await;
            }
            extra_spaces.push(ws);
        }
        owner.close().await.unwrap();
        let engine = EngineConfig {
            name: "original".into(),
            origin: options.origin.clone(),
            expected_actor: options.expected_actor.clone(),
            authority: options.authority.clone(),
            identity_path: options.identity_path.clone(),
            state_directory: options.state_directory.clone(),
            journal_path: Some(options.journal_path.clone()),
            allow_loopback_http: true,
            transport: options.transport.clone(),
            max_inflight: 2,
            max_pending: 16,
            max_stored_bytes: 8 * 1024 * 1024,
            migration_sources: vec![],
        };
        let runtime = RuntimeConfig {
            format: "peerwork.participant-runtime.v1".into(),
            state_directory: root.path().join("resident"),
            engines: vec![engine.clone()],
            clients: vec![ClientConfig {
                name: "original-client".into(),
                engine: engine.name.clone(),
                capability: Capability::owner(),
            }],
            hosts: vec![],
        };
        let cancel = crate::KernelCancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let running = tokio::spawn(ipc::serve(runtime, cancel.clone(), tx));
        let ready = rx.await.unwrap().unwrap();
        let original = root.path().join("unusual-existing-local-directory");
        let project = root.path().join("project");
        crate::onboarding_files::directory(&project, false).unwrap();
        let mut old = Connect::open(&original).unwrap();
        old.register(
            "worker",
            Registration {
                origin: options.origin.clone(),
                actor_id: options.expected_actor.clone(),
                endpoint_path: ready.client_endpoints["original-client"].clone(),
            },
        )
        .await
        .unwrap();
        let cli =
            PathBuf::from(std::env::var("PEERWORK_PARTICIPANT_CLI").expect("rebuilt native CLI"));
        old.install(
            "worker",
            &ws,
            Installation {
                host: "codex".into(),
                project: project.clone(),
                executable: cli.clone(),
            },
        )
        .unwrap();
        drop(old);
        let run = |extra: Vec<String>| {
            let cli = cli.clone();
            let ws = ws.clone();
            let project = project.clone();
            tokio::task::spawn_blocking(move || {
                let output = std::process::Command::new(cli)
                    .args([
                        "connect",
                        "--workspace",
                        &ws,
                        "--project",
                        project.to_str().unwrap(),
                        "--send",
                        "--receive",
                    ])
                    .args(extra)
                    .output()
                    .unwrap();
                serde_json::from_slice::<Value>(&output.stdout).unwrap()
            })
        };
        let pending = run(vec![]).await.unwrap();
        assert_eq!(
            pending["blocker"]["code"], "HOST_CONTEXT_REQUIRED",
            "{pending}"
        );
        assert_eq!(pending["tools_available"], true);
        assert_eq!(pending["owner_exchange_required"], false);
        assert!(!project.join(".peerwork/engine.json").exists());
        assert!(!project.join(".peerwork/runtime.json").exists());
        let parent = RuntimeClient::connect(
            ready.client_endpoints["original-client"].clone(),
            &engine.origin,
            &engine.expected_actor,
        )
        .await
        .unwrap();
        assert!(parent
            .call(json!({"method":"bindings"}))
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            parent.call(json!({"method":"binding"})).await.unwrap()["namespace"],
            "program:original-client"
        );
        let again = run(vec![]).await.unwrap();
        assert_eq!(again["setup_id"], pending["setup_id"]);
        assert_eq!(
            again["observation"],
            "CACHED_SETUP_RESULT_HOST_CONTEXT_STILL_REQUIRED"
        );
        let configured = run(vec!["--program".into()]).await.unwrap();
        assert_eq!(configured["state"], "LOCAL_CONFIGURED", "{configured}");
        assert_ne!(configured["setup_id"], pending["setup_id"]);
        // A selected original registry is enough for sender/role reuse; neither
        // an unrelated shell cwd nor inherited program custody is a host request.
        let sender_cli=cli.clone();let sender_local=original.clone();let sender_ws=ws.clone();
        let sender=tokio::task::spawn_blocking(move||{
            let output=std::process::Command::new(sender_cli).args(["connect","--local",sender_local.to_str().unwrap(),"--participant","worker","--workspace",&sender_ws,"--id","explicit-sender-reuse","--send"]).output().unwrap();
            serde_json::from_slice::<Value>(&output.stdout).unwrap()
        }).await.unwrap();
        assert_eq!(sender["state"],"LOCAL_CONFIGURED","{sender}");
        let blocked = run(vec!["--id".into(), "another-agent".into()])
            .await
            .unwrap();
        assert_eq!(
            blocked["blocker"]["code"], "EXISTING_PROGRAM_RECEIVER_REQUIRES_EXPLICIT_REBIND",
            "{blocked}"
        );
        let host = crate::communication_host::tests::CodexFixture::start();
        let selection = HostSelection {
            participant: "worker".into(),
            admin_endpoint: ready.admin_endpoint.clone(),
            adapter: host.config(),
        };
        let mut connect = Connect::open(&original).unwrap();
        let request:ConnectRequest=serde_json::from_value(json!({"setup_id":"host-recovery","participant":"worker","workspace_id":extra_spaces[0],"send":true,"receive":true})).unwrap();
        assert_eq!(
            connect.run_agent(request.clone()).await.unwrap()["blocker"]["code"],
            "HOST_CONTEXT_REQUIRED"
        );
        connect
            .register_host("named-host", selection.clone())
            .await
            .unwrap();
        connect
            .registry
            .setups
            .get_mut(&request.setup_id)
            .unwrap()
            .effective_host = Some("named-host".into());
        let digest = connect.registry.setups[&request.setup_id].digest.clone();
        connect
            .pending(
                &request,
                "CONTENT_KEYS",
                "KEYS_SYNCHRONIZING",
                "RUNTIME",
                "RESUME_SAME_SETUP",
                json!({}),
            )
            .unwrap();
        let restored = connect.run_agent(request.clone()).await.unwrap();
        assert_eq!(restored["state"], "LOCAL_CONFIGURED", "{restored}");
        assert!(connect.registry.setups[&request.setup_id].channel_receive);
        assert_eq!(connect.registry.setups[&request.setup_id].digest, digest);
        assert!(!restored["profile_path"]
            .as_str()
            .unwrap()
            .ends_with("-tools.json"));
        connect
            .profile_for_scope(Some("worker"), Some(&extra_spaces[0]))
            .unwrap()
            .unwrap()
            .validate()
            .unwrap();
        let mut other = request.clone();
        other.setup_id = "different-current-caller".into();
        let blocked = connect.run_agent(other.clone()).await.unwrap();
        assert_eq!(blocked["blocker"]["code"], "HOST_CONTEXT_REQUIRED");
        assert!(connect.registry.setups[&other.setup_id]
            .effective_host
            .is_none());
        let wrong = HostInvocation::CodexDynamicTool {
            thread_id: "different-child".into(),
            turn_id: "turn".into(),
            call_id: "call".into(),
            instance: "owned-instance".into(),
        };
        assert_eq!(
            connect
                .connect_current(other, selection.clone(), wrong)
                .await
                .unwrap_err()
                .code,
            "CURRENT_HOST_CONTEXT_MISMATCH"
        );
        let approval:ConnectRequest=serde_json::from_value(json!({"setup_id":"host-approval","participant":"worker","workspace_id":extra_spaces[1],"send":true,"receive":true})).unwrap();
        let caller = HostInvocation::CodexDynamicTool {
            thread_id: "existing-thread".into(),
            turn_id: "turn".into(),
            call_id: "call".into(),
            instance: "owned-instance".into(),
        };
        let pending = connect
            .connect_current(approval.clone(), selection, caller)
            .await
            .unwrap();
        assert_eq!(
            pending["blocker"]["code"], "OWNER_APPROVAL_REQUIRED",
            "{pending}"
        );
        assert_eq!(
            connect.registry.setups[&approval.setup_id]
                .effective_host
                .as_deref(),
            Some("named-host")
        );
        let authorized =
            serde_json::from_value(pending["details"]["authorization_request"].clone()).unwrap();
        assert_eq!(
            connect
                .approve("worker", "approve-original-host-setup", authorized)
                .await
                .unwrap()["state"],
            "APPROVED"
        );
        let finished = connect.run_agent(approval.clone()).await.unwrap();
        assert_eq!(finished["state"], "LOCAL_CONFIGURED", "{finished}");
        assert!(
            finished.get("caller_context").is_none(),
            "old caller assertion leaked into a later invocation"
        );
        assert_eq!(
            connect.registry.setups[&approval.setup_id]
                .effective_host
                .as_deref(),
            Some("named-host")
        );
        assert_eq!(service.counts().await["journal_reads"], 0);
        drop(connect);
        cancel.cancel();
        running.await.unwrap().unwrap();
    }
}
