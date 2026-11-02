//! Bounded original-installation discovery. No recursive scan or engine open.
use super::*;
use crate::communication_runtime::{EngineConfig, RuntimeConfig};

const LIMIT: usize = 8;
pub(super) struct ProjectBinding {
    pub directory: PathBuf,
    pub participant: String,
    pub summary: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectTarget {
    directory: PathBuf,
    participant: String,
    registration: Registration,
    binding: Option<Value>,
}
pub(super) fn project_target(project: &Path) -> Result<Option<(PathBuf, String)>> {
    let path = project.join(".peerwork/connect");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED")),
        Ok(_) => (),
    }
    let index = Connect::inspect(&path)?;
    let Some(target) = index.registry.project_target else {
        return Ok(Some((path, String::new())));
    };
    if target.directory == path {
        return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
    }
    let original = Connect::inspect(&target.directory)?;
    if original.registry.project_target.is_some()
        || original.registry.participants.get(&target.participant) != Some(&target.registration)
        || target.binding.as_ref().is_some_and(|wanted| {
            original.registry.verified_bindings.get(&target.participant) != Some(wanted)
        })
    {
        return Err(local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"));
    }
    Ok(Some((target.directory, target.participant)))
}
pub(super) fn remember_project(project: &Path, choice: &ProjectBinding) -> Result<()> {
    let original = Connect::inspect(&choice.directory)?;
    let directory = directory(project)?;
    if directory == choice.directory {
        return Ok(());
    }
    let mut index = Connect::open(&directory)?;
    if !index.registry.participants.is_empty()
        || !index.registry.sources.is_empty()
        || !index.registry.setups.is_empty()
        || index.registry.project_target.is_some()
    {
        return Err(local("PROJECT_BINDING_CHANGED_RESUME_ORIGINAL"));
    }
    index.registry.project_target = Some(ProjectTarget {
        directory: choice.directory.clone(),
        participant: choice.participant.clone(),
        registration: original
            .registry
            .participants
            .get(&choice.participant)
            .cloned()
            .ok_or_else(|| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?,
        binding: original
            .registry
            .verified_bindings
            .get(&choice.participant)
            .cloned(),
    });
    index.save()
}
/// Follow only an exact installation entry confirmed by the original protected
/// registry. A repository MCP entry alone cannot authorize a private runtime.
pub(super) fn project_bindings(
    project: &Path,
    workspace: Option<&str>,
) -> Result<Vec<ProjectBinding>> {
    crate::onboarding_files::check_directory(project, false)?;
    let mut found = BTreeMap::new();
    for (host, relative) in [
        ("codex", ".codex/config.toml"),
        ("agy", ".agents/mcp_config.json"),
    ] {
        let path = project.join(relative);
        match std::fs::symlink_metadata(path.parent().unwrap()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(local("DISCOVERY_INCOMPLETE")),
            Ok(_) => (),
        }
        let Some(bytes) = crate::onboarding_files::read_public_optional(&path, 256 * 1024)
            .map_err(|_| local("DISCOVERY_INCOMPLETE"))?
        else {
            continue;
        };
        let entries: Vec<(String, Value)> = if host == "codex" {
            let doc = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                .ok_or_else(|| local("DISCOVERY_INCOMPLETE"))?;
            doc.get("mcp_servers")
                .and_then(|v| v.as_table_like())
                .map(|table| {
                    table
                        .iter()
                        .filter_map(|(name, v)| {
                            let command = v.get("command")?.as_str()?;
                            let args = v
                                .get("args")?
                                .as_array()?
                                .iter()
                                .map(|v| v.as_str().map(str::to_owned))
                                .collect::<Option<Vec<_>>>()?;
                            let mut entry = json!({"command":command,"args":args});
                            if v.as_table_like().is_none_or(|table| {
                                table
                                    .iter()
                                    .any(|(key, _)| !matches!(key, "command" | "args"))
                            }) {
                                entry["unrecognized_installation_fields"] = json!(true);
                            }
                            Some((name.to_owned(), entry))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            let doc = peerwork_core::strict_json::parse_strict_json(&bytes)
                .map_err(|_| local("DISCOVERY_INCOMPLETE"))?;
            doc["mcpServers"]
                .as_object()
                .map(|table| table.iter().map(|(n, v)| (n.clone(), v.clone())).collect())
                .unwrap_or_default()
        };
        if entries.len() > 32 {
            return Err(local("DISCOVERY_INCOMPLETE"));
        }
        for (name, entry) in entries {
            if !name.starts_with("peerwork-") {
                continue;
            }
            let Some(args) = entry["args"].as_array() else {
                continue;
            };
            if args.len() != 8
                || args[0] != "agent"
                || args[1] != "--local"
                || args[3] != "--participant"
                || args[5] != "--workspace"
                || args[7] != "mcp"
            {
                continue;
            }
            let (Some(directory), Some(participant), Some(ws)) =
                (args[2].as_str(), args[4].as_str(), args[6].as_str())
            else {
                continue;
            };
            if workspace.is_some_and(|wanted| wanted != ws) {
                continue;
            }
            let directory = PathBuf::from(directory);
            let original = Connect::inspect(&directory)
                .map_err(|_| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
            if !install::matches_installation(&original, project, host, &name, &entry) {
                return Err(local("PROJECT_INSTALLATION_PROVENANCE_REQUIRED"));
            }
            let registration = original
                .registry
                .participants
                .get(participant)
                .ok_or_else(|| local("ORIGINAL_INSTALLATION_RECOVERY_REQUIRED"))?;
            let choice = format!(
                "installed-{}",
                &sha256_hex(json!([directory, participant]).to_string().as_bytes())[..24]
            );
            found.insert(choice.clone(),ProjectBinding{directory,participant:participant.into(),
                summary:json!({"handle":choice,"actor_id":registration.actor_id,"origin":registration.origin,"source":"VERIFIED_PROJECT_INSTALLATION","workspace_id":ws})});
            if found.len() > LIMIT {
                return Err(local("DISCOVERY_INCOMPLETE"));
            }
        }
    }
    Ok(found.into_values().collect())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    path: PathBuf,
    digest: String,
    engine: EngineConfig,
    runtime: Option<PathBuf>,
    client: Option<String>,
    namespace: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Discovery {
    pub state: String,
    pub candidates: Vec<Value>,
    pub next_action: String,
}
pub fn directory(project: &Path) -> Result<PathBuf> {
    crate::onboarding_files::check_directory(project, false)?;
    let root = project.join(".peerwork");
    crate::onboarding_files::directory(&root, true)?;
    Ok(root.join("connect"))
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
    if crate::kernel_identity::KernelIdentity::open(&options.identity_path)
        .map_err(|_| local("IDENTITY_RECOVERY_REQUIRED"))?
        .actor_id()
        != engine.expected_actor
    {
        return Err(local("LOCAL_IDENTITY_MISMATCH"));
    }
    Ok(())
}
impl Connect {
    /// Explicit local CLI consent; MCP cannot supply trust roots or file paths.
    pub fn discover(&mut self, project: &Path, authorize_project: bool) -> Result<Discovery> {
        self.require_writer()?;
        crate::onboarding_files::check_directory(project, false)?;
        if authorize_project && !self.registry.trusted_projects.iter().any(|p| p == project) {
            if self.registry.trusted_projects.len() >= LIMIT {
                return Err(local("DISCOVERY_SOURCE_LIMIT"));
            }
            self.registry.trusted_projects.push(project.into());
            self.save()?;
        }
        // A previous binding wins. A damaged binding is repaired by adopt(),
        // never replaced by whichever different identity happens to be found.
        if !self.registry.participants.is_empty() || !self.registry.sources.is_empty() {
            return Ok(self.discovery_summary());
        }
        if !self.registry.trusted_projects.iter().any(|p| p == project) {
            return Ok(Discovery {
                state: "LOCAL_PROJECT_TRUST_REQUIRED".into(),
                candidates: vec![],
                next_action: "AUTHORIZE_LOCAL_PROJECT_DISCOVERY_ONCE".into(),
            });
        }
        let root = project.join(".peerwork");
        crate::onboarding_files::check_directory(&root, true)?;
        let mut found = BTreeMap::new();
        // A versioned fixed provider set, not filename guessing or a home scan.
        for (name, is_runtime) in [("engine.json", false), ("runtime.json", true)] {
            let path = root.join(name);
            let Some(bytes) = crate::onboarding_files::read_optional(&path, 65536)
                .map_err(|_| local("DISCOVERY_INCOMPLETE"))?
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
            state: match candidates.len() {
                0 => "NO_LOCAL_IDENTITY_FOUND",
                1 => "IDENTITY_AVAILABLE",
                _ => "IDENTITY_SELECTION_REQUIRED",
            }
            .into(),
            next_action: match candidates.len() {
                0 => "IMPORT_EXISTING_INSTALLATION_OR_EXPLICITLY_CREATE_IDENTITY",
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
                    crate::onboarding_files::read_optional(&original.join("config.json"), 65536)?
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
                    let wire = crate::onboarding_files::read_optional(
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
        let bytes = crate::onboarding_files::read_optional(&source.path, 65536)?
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
            if crate::onboarding_files::read_optional(&source.path, 65536)?.as_deref()
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
        if self.registry.verified_bindings.get(handle) != Some(&observed) {
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
        write_private(path, &serde_json::to_vec(value).unwrap()).unwrap();
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
        std::os::unix::fs::symlink(
            project.join("original.json"),
            project.join(".peerwork/engine.json"),
        )
        .unwrap();
        let mut c = Connect::open(&dir).unwrap();
        assert_eq!(
            c.discover(project, true).unwrap_err().code,
            "DISCOVERY_INCOMPLETE"
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
        assert!(!first.receive);
        assert!(!first.setup_id.is_empty());
        assert!(!first.participant.is_empty());
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
        // Project text alone is not permission: remove the original ownership
        // record and make the exact same config resolve to a recovery blocker.
        let mut c = Connect::open(&original).unwrap();
        c.registry.installations.clear();
        c.save().unwrap();
        drop(c);
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
        let blocked = run(vec!["--id".into(), "another-agent".into()])
            .await
            .unwrap();
        assert_eq!(
            blocked["blocker"]["code"], "EXISTING_PROGRAM_RECEIVER_REQUIRES_EXPLICIT_REBIND",
            "{blocked}"
        );
        assert_eq!(service.counts().await["journal_reads"], 0);
        cancel.cancel();
        running.await.unwrap().unwrap();
    }
}
