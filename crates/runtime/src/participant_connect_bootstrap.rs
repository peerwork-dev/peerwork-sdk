//! Explicit local engine selection and one owned resident-runtime launch.
//! Host/Agent tools cannot choose identity files or administrative endpoints.
use super::*;
use crate::communication_runtime::{ClientConfig, EngineConfig, RuntimeConfig};

/// Explicit local-owner selection. Never accepted from ordinary MCP arguments.
/// Selecting a config authorizes restoring this directly managed runtime; a
/// supervisor-managed runtime must use its established lifecycle integration.
#[derive(Clone)]
pub struct RuntimeSelection {
    pub admin_endpoint: PathBuf,
    pub config_path: Option<PathBuf>,
}
pub(super) fn runtime_inputs(connect:&Connect,values:&mut BTreeMap<String,String>)->Result<()> {
    let Some(path)=values.get("--runtime-config") else{return Ok(());};
    if ["--identity","--engine-state","--journal","--authority","--engine-config"].iter().any(|key|values.contains_key(*key)){
        return Err(local("SELECT_ORIGINAL_RUNTIME_OR_ENGINE_NOT_BOTH"));
    }
    if values.contains_key("--client") || values.get("--participant").is_some_and(|h|connect.registry.participants.contains_key(h))
        || !values.contains_key("--participant")&&!connect.registry.participants.is_empty(){return Ok(());}
    let path=std::path::absolute(path).map_err(|_|local("LOCAL_SELECTION_INVALID"))?;
    let config:RuntimeConfig=serde_json::from_value(crate::communication_store::private_json(&path,65536)
        .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?;
    if config.format!="peerwork.participant-runtime.v1"||config.engines.len()!=1||config.clients.len()!=1||!config.state_directory.is_absolute(){return Err(local("ORIGINAL_RUNTIME_CLIENT_SELECTION_REQUIRED"));}
    let engine=&config.engines[0];let client=&config.clients[0];
    if client.engine!=engine.name||!identifier(&client.name){return Err(local("RUNTIME_CONFIG_INVALID"));}
    for(key,value)in [("--client",config.state_directory.join(format!("client-{}.json",client.name)).to_string_lossy().into_owned()),("--origin",engine.origin.clone()),("--actor",engine.expected_actor.clone())]{
        if values.get(key).is_some_and(|old|old!=&value){return Err(local("LOCAL_SELECTION_CONFLICT"));}
        values.insert(key.into(),value);
    }
    values.entry("--participant".into()).or_insert(format!("identity-{}",&engine.binding_digest()?[..24]));
    Ok(())
}

pub(super) fn engine(values: &BTreeMap<String, String>) -> Result<Option<EngineConfig>> {
    let required = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| local("CONNECT_ARGUMENT_INVALID_SEE_HELP"))
    };
    let absolute =
        |value: &str| std::path::absolute(value).map_err(|_| local("LOCAL_SELECTION_INVALID"));
    if let Some(path) = values.get("--engine-config") {
        if [
            "--identity",
            "--engine-state",
            "--journal",
            "--authority",
            "--request-timeout-ms",
            "--ca-root",
            "--origin",
            "--actor",
            "--allow-loopback-http",
            "--client",
        ]
        .iter()
        .any(|k| values.contains_key(*k))
        {
            return Err(local("LOCAL_SELECTION_CONFLICT"));
        }
        return Ok(Some(EngineConfig::load(&absolute(path)?)?));
    }
    let Some(identity) = values.get("--identity") else {
        if [
            "--engine-state",
            "--journal",
            "--authority",
            "--request-timeout-ms",
            "--ca-root",
        ]
        .iter()
        .any(|k| values.contains_key(*k))
        {
            return Err(local("LOCAL_SELECTION_REQUIRED"));
        }
        return Ok(None);
    };
    if values.contains_key("--client") {
        return Err(local("LOCAL_SELECTION_CONFLICT"));
    }
    let state_directory = absolute(&required("--engine-state")?)?;
    if !values.contains_key("--journal") {
        match std::fs::read_dir(&state_directory) {
            Ok(mut entries) => {
                if entries
                    .next()
                    .transpose()
                    .map_err(|_| local("ORIGINAL_ENGINE_CONFIG_REQUIRED"))?
                    .is_some()
                {
                    return Err(local("ORIGINAL_ENGINE_CONFIG_REQUIRED"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(local("ORIGINAL_ENGINE_CONFIG_REQUIRED")),
        }
    }
    let identity_path = absolute(identity)?;
    crate::onboarding_files::check_directory(identity_path.parent().ok_or_else(||local("LOCAL_SELECTION_INVALID"))?,true)?;
    let actor = crate::kernel_identity::KernelIdentity::open(&identity_path)
        .map_err(|_| local("IDENTITY_RECOVERY_REQUIRED"))?
        .actor_id()
        .to_owned();
    if values
        .get("--actor")
        .is_some_and(|expected| expected != &actor)
    {
        return Err(local("LOCAL_IDENTITY_MISMATCH"));
    }
    let mut transport = crate::transport::TransportOptions::default();
    if let Some(value) = values.get("--request-timeout-ms") {
        transport.request_timeout_ms = value
            .parse()
            .map_err(|_| local("TRANSPORT_SELECTION_INVALID"))?;
    }
    if let Some(value) = values.get("--ca-root") {
        transport.additional_root_pem_files.push(absolute(value)?);
    }
    transport
        .validate()
        .map_err(|_| local("TRANSPORT_SELECTION_INVALID"))?;
    Ok(Some(EngineConfig {
        name: "selected".into(),
        origin: required("--origin")?,
        expected_actor: actor,
        identity_path,
        state_directory,
        journal_path: values.get("--journal").map(|p| absolute(p)).transpose()?,
        authority: values.get("--authority").cloned(),
        allow_loopback_http: values.contains_key("--allow-loopback-http"),
        transport,
        max_inflight: 4,
        max_pending: 64,
        max_stored_bytes: 32 * 1024 * 1024,
        migration_sources: Vec::new(),
    }))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    config_digest: String,
    pid: Option<u32>,
    process_token: Option<String>,
}
fn alive(pid: u32, expected: Option<&str>) -> Result<bool> {
    if pid == 0 {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|v| v.rsplit_once(") ").map(|(_, tail)| tail.starts_with('Z')))
        == Some(true)
    {
        return Ok(false);
    }
    if let (Some(expected), Some(actual)) =
        (expected, crate::communication_store::process_token(pid))
    {
        return Ok(expected == actual);
    }
    if !crate::communication_store::process_alive(pid, None) {
        return Ok(false);
    }
    Err(local("PROCESS_IDENTITY_UNCONFIRMED"))
}
fn strict_existing_parent(path:&Path,private:bool)->Result<()> {
    let mut existing=path;
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_)=>return crate::onboarding_files::check_directory(existing,private && existing==path),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>existing=existing.parent().ok_or_else(||local("LOCAL_SELECTION_INVALID"))?,
            Err(_)=>return Err(crate::onboarding_files::path_error(existing,"PRIVATE_ENGINE_NAMESPACE","STAT","PERMISSION_DENIED")),
        }
    }
}
pub(super) fn automatic_namespace(directory:&Path,engine:&EngineConfig)->Result<()> {
    let checked=(||->Result<()>{
        crate::onboarding_files::check_directory(directory,true)?;
        strict_existing_parent(engine.identity_path.parent().ok_or_else(||local("LOCAL_SELECTION_INVALID"))?,true)?;
        strict_existing_parent(&engine.state_directory,true)?;
        if let Some(journal)=&engine.journal_path{strict_existing_parent(journal.parent().ok_or_else(||local("LOCAL_SELECTION_INVALID"))?,true)?;}
        Ok(())
    })();
    checked.map_err(|_|{let mut e=local("ORIGINAL_RUNTIME_OWNER_START_REQUIRED");e.recovery="START_OR_UPGRADE_ORIGINAL_RUNTIME_WITH_ITS_LOCAL_OWNER".into();e})
}
fn planned(
    directory: &Path,
    handle: &str,
    mut engine: EngineConfig,
) -> Result<(RuntimeConfig, Registration)> {
    automatic_namespace(directory,&engine)?;
    if !identifier(handle)
        || !engine.identity_path.is_absolute()
        || !engine.state_directory.is_absolute()
        || engine
            .journal_path
            .as_ref()
            .is_some_and(|p| !p.is_absolute())
    {
        return Err(local("LOCAL_SELECTION_INVALID"));
    }
    if engine
        .authority
        .as_ref()
        .is_some_and(|a| !crate::participant_migration::digest(a))
    {
        return Err(local("AUTHORITY_INVALID"));
    }
    engine
        .transport
        .validate()
        .map_err(|_| local("TRANSPORT_SELECTION_INVALID"))?;
    let actor = crate::kernel_identity::KernelIdentity::open(&engine.identity_path)
        .map_err(|_| local("IDENTITY_RECOVERY_REQUIRED"))?
        .actor_id()
        .to_owned();
    if actor != engine.expected_actor {
        return Err(local("LOCAL_IDENTITY_MISMATCH"));
    }
    let origin =
        crate::transport::canonical_lifecycle_origin(&engine.origin, engine.allow_loopback_http)
            .map_err(|_| local("LOCAL_SELECTION_INVALID"))?;
    engine.origin = origin.clone();
    engine.name = "selected".into();
    let runtime_dir = directory.join(format!("runtime-{handle}"));
    let config = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: runtime_dir.clone(),
        engines: vec![engine],
        clients: vec![ClientConfig {
            name: "bootstrap".into(),
            engine: "selected".into(),
            capability: Capability::owner(),
        }],
        hosts: Vec::new(),
    };
    let selected = Registration {
        origin,
        actor_id: actor,
        endpoint_path: runtime_dir.join("client-bootstrap.json"),
    };
    Ok((config, selected))
}
impl Connect {
    pub(super) async fn bootstrap(&mut self, handle: &str, engine: EngineConfig) -> Result<()> {
        let (config, planned) = planned(&self.directory, handle, engine.clone())?;
        let admin = config.state_directory.join("admin.json");
        if let Some(old) = self.registry.participants.get(handle) {
            if old != &planned {
                return Err(local("LOCAL_BINDING_CONFLICT"));
            }
            if self.registry.local_runtime_admins.get(handle) != Some(&admin) {
                // Recover only from an intact protected launch/config binding;
                // a client endpoint by itself never grants admin provenance.
                let saved = crate::communication_store::private_json(
                    &config.state_directory.join("config.json"),
                    65536,
                )
                .map_err(|_| local("EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED"))?;
                let launch = SecureStateStore::read_snapshot(
                    &config.state_directory.join("bootstrap.state"),
                    65536,
                )
                .map_err(|_| local("EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED"))?;
                let launch: Launch = serde_json::from_slice(&launch)
                    .map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
                let bytes =
                    serde_json::to_vec(&config).map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
                if saved
                    != serde_json::to_value(&config).map_err(|_| local("RUNTIME_CONFIG_INVALID"))?
                    || launch.config_digest != sha256_hex(&bytes)
                {
                    return Err(local("LOCAL_BINDING_CONFLICT"));
                }
            }
        } else if self.registry.participants.len() >= 8 {
            return Err(local("LOCAL_PARTICIPANT_LIMIT"));
        }
        // All handle/provenance conflicts are rejected before launch creates
        // config, logs, a signing-state owner or any child process.
        let (selected, admin) = launch(&self.directory, handle, engine).await?;
        // The owned launch proof authorizes this admin endpoint. Publish it
        // atomically with registration/binding, not in a later crash window.
        self.register_pinned(handle, selected, None, Some(admin)).await?;
        Ok(())
    }
}
async fn launch(
    directory: &Path,
    handle: &str,
    engine: EngineConfig,
) -> Result<(Registration, PathBuf)> {
    let (config, selected) = planned(directory, handle, engine)?;
    launch_config(config, selected).await
}
async fn launch_config(config: RuntimeConfig, selected: Registration) -> Result<(Registration, PathBuf)> {
    let path = config.state_directory.join("config.json");
    launch_at(config, selected, path).await
}
fn verify_existing_launch_config(path: &Path, expected: &RuntimeConfig) -> Result<()> {
    // An original owner may omit supported default fields. Compare the same
    // strict, typed configuration the runtime loads, without rewriting its file.
    let original: RuntimeConfig = serde_json::from_value(
        crate::communication_store::private_json(path, 65536)
            .map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
    ).map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
    if serde_json::to_value(&original).map_err(|_| local("RUNTIME_CONFIG_INVALID"))?
        != serde_json::to_value(expected).map_err(|_| local("RUNTIME_CONFIG_INVALID"))? {
        return Err(local("LOCAL_BINDING_CONFLICT"));
    }
    Ok(())
}
async fn launch_at(config: RuntimeConfig, selected: Registration, config_path: PathBuf) -> Result<(Registration, PathBuf)> {
    let runtime_dir = config.state_directory.clone();
    create_private_state_directory(&runtime_dir)
        .map_err(|_| local("RUNTIME_DIRECTORY_NOT_PRIVATE"))?;
    let wire = serde_json::to_vec(&config).map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
    match std::fs::symlink_metadata(&config_path) {
        Ok(_) => verify_existing_launch_config(&config_path, &config)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_private(&config_path, &wire).map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?
        }
        Err(_) => return Err(local("RUNTIME_CONFIG_NOT_PRIVATE")),
    }
    if std::fs::symlink_metadata(&selected.endpoint_path).is_ok() {
        match RuntimeClient::connect(
            selected.endpoint_path.clone(),
            &selected.origin,
            &selected.actor_id,
        )
        .await
        {
            Ok(_) => return Ok((selected, runtime_dir.join("admin.json"))),
            Err(e) if e.code == "RUNTIME_UNAVAILABLE" => (),
            Err(e) => return Err(e),
        }
    }
    let owner = SecureStateStore::open(&runtime_dir.join("bootstrap.state"))
        .map_err(|_| local("RUNTIME_LAUNCH_ALREADY_OWNED_OR_UNSAFE"))?;
    let config_digest = sha256_hex(&wire);
    let previous: Option<Launch> = owner
        .read_exact()
        .map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))
        })
        .transpose()?;
    if let Some(previous) = previous {
        if previous.config_digest != config_digest {
            return Err(local("LOCAL_BINDING_CONFLICT"));
        }
        let pid = previous
            .pid
            .ok_or_else(|| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
        if alive(pid, previous.process_token.as_deref())? {
            // Observation timeout is not process failure. Reobserve this exact
            // child rather than spawning another process or choosing new state.
            for _ in 0..50 {
                if RuntimeClient::connect(
                    selected.endpoint_path.clone(),
                    &selected.origin,
                    &selected.actor_id,
                )
                .await
                .is_ok()
                {
                    return Ok((selected, runtime_dir.join("admin.json")));
                }
                if !alive(pid, previous.process_token.as_deref())? {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if alive(pid, previous.process_token.as_deref())? {
                return Err(local("RUNTIME_STARTING_REOBSERVE_SAME_BINDING"));
            }
        }
    }
    // A second launcher cannot own the original engine state. Never change the
    // state path to evade that fence. The parent observes the exact child.
    let log = runtime_dir.join("runtime.log");
    if std::fs::symlink_metadata(&log).is_err() {
        write_private(&log, b"").map_err(|_| local("RUNTIME_LOG_NOT_PRIVATE"))?;
    }
    crate::secure_state::validate_private_file(&log)
        .map_err(|_| local("RUNTIME_LOG_NOT_PRIVATE"))?;
    let output = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .map_err(|_| local("RUNTIME_LOG_NOT_PRIVATE"))?;
    let mut command = std::process::Command::new(
        std::env::current_exe().map_err(|_| local("EXECUTABLE_UNAVAILABLE"))?,
    );
    command
        .args(["runtime", "run"])
        .arg(&config_path)
        .stdin(std::process::Stdio::null())
        .stderr(
            output
                .try_clone()
                .map_err(|_| local("RUNTIME_LOG_NOT_PRIVATE"))?,
        )
        .stdout(output);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000200 | 0x00000008);
    }
    owner
        .write_exact(
            &serde_json::to_vec(&Launch {
                config_digest: config_digest.clone(),
                pid: None,
                process_token: None,
            })
            .map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?,
        )
        .map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            // A spawn error proves this attempted child never existed.
            owner
                .write_exact(
                    &serde_json::to_vec(&Launch {
                        config_digest: config_digest.clone(),
                        pid: Some(0),
                        process_token: None,
                    })
                    .unwrap(),
                )
                .map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
            return Err(local("RUNTIME_START_FAILED"));
        }
    };
    let launch = Launch {
        config_digest,
        pid: Some(child.id()),
        process_token: crate::communication_store::process_token(child.id()),
    };
    owner
        .write_exact(
            &serde_json::to_vec(&launch).map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?,
        )
        .map_err(|_| local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
    for _ in 0..50 {
        if RuntimeClient::connect(
            selected.endpoint_path.clone(),
            &selected.origin,
            &selected.actor_id,
        )
        .await
        .is_ok()
        {
            return Ok((selected, runtime_dir.join("admin.json")));
        }
        if child
            .try_wait()
            .map_err(|_| local("RUNTIME_START_FAILED"))?
            .is_some()
        {
            return Err(local("RUNTIME_START_FAILED_CHECK_ORIGINAL_STATE_OWNER"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(local("RUNTIME_STARTING_REOBSERVE_SAME_BINDING"))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnedRuntime {
    pub config: RuntimeConfig,
    pub registration: Registration,
    launch: Option<Launch>,
    #[serde(default)]
    config_path: Option<PathBuf>,
}
impl OwnedRuntime {
    pub fn path(&self) -> PathBuf { self.config_path.clone().unwrap_or_else(||self.config.state_directory.join("config.json")) }
    fn load(&self) -> Result<RuntimeConfig> {
        serde_json::from_value(crate::communication_store::private_json(&self.path(),65536)
            .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))
    }
    pub fn same_engine(&self, target:&RuntimeConfig)->Result<()> {
        let mut expected=self.config.clone();expected.hosts=target.hosts.clone();
        if serde_json::to_value(expected).ok()!=serde_json::to_value(target).ok(){return Err(local("ORIGINAL_RUNTIME_CONFIG_CHANGED"));}
        Ok(())
    }
    pub async fn stop(&self) -> Result<()> {
        if serde_json::to_value(self.load()?).ok()!=serde_json::to_value(&self.config).ok(){return Err(local("ORIGINAL_RUNTIME_CONFIG_CHANGED"));}
        if let Some(launch)=&self.launch {
            let pid=launch.pid.ok_or_else(||local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
            if !alive(pid,launch.process_token.as_deref())? {return Ok(());}
        } else if let Ok(_fence)=SecureStateStore::open(&self.config.state_directory.join("runtime.state")) {
            return Ok(());
        }
        // Management authority comes from the selected authenticated admin.
        // The original ownership fence, not process discovery, proves release.
        let admin=self.config.state_directory.join("admin.json");
        let result=crate::communication_runtime::call(&admin,json!({"method":"stop"})).await;
        for _ in 0..100 {
            if let Ok(_fence)=SecureStateStore::open(&self.config.state_directory.join("runtime.state")) {return Ok(());}
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if let Err(error)=result {return Err(error);}
        Err(local("ORIGINAL_RUNTIME_STOP_PENDING"))
    }
    pub async fn restart(&self, committed:&RuntimeConfig)->Result<()> {
        self.same_engine(committed)?;
        if serde_json::to_value(self.load()?).ok()!=serde_json::to_value(committed).ok(){return Err(local("ORIGINAL_RUNTIME_CONFIG_CHANGED"));}
        let marker=self.config.state_directory.join("bootstrap.state");
        {
            let store=SecureStateStore::open(&marker).map_err(|_|local("RUNTIME_LAUNCH_ALREADY_OWNED_OR_UNSAFE"))?;
            let previous=store.read_exact().map_err(|_|local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?
                .map(|wire|serde_json::from_slice::<Launch>(&wire).map_err(|_|local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))).transpose()?;
            let target=sha256_hex(&serde_json::to_vec(committed).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?);
            let original=sha256_hex(&serde_json::to_vec(&self.config).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?);
            if previous.as_ref().is_some_and(|p|p.config_digest!=original && p.config_digest!=target) {return Err(local("LOCAL_BINDING_CONFLICT"));}
            if previous.as_ref().is_none_or(|p|p.config_digest!=target) {
                let _fence=SecureStateStore::open(&committed.state_directory.join("runtime.state")).map_err(|_|local("HOST_REBIND_STOP_RUNTIME_FIRST"))?;
                if let Some(previous)=&previous {if alive(previous.pid.ok_or_else(||local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?,previous.process_token.as_deref())? {return Err(local("HOST_REBIND_STOP_RUNTIME_FIRST"));}}
                store.write_exact(&serde_json::to_vec(&Launch{config_digest:target,pid:Some(0),process_token:None}).unwrap())
                    .map_err(|_|local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
            }
        }
        launch_at(committed.clone(),self.registration.clone(),self.path()).await?;
        Ok(())
    }
}
pub(super) fn owned_runtime(connect:&Connect, handle:&str)->Result<OwnedRuntime> {
    let registration=connect.registry.participants.get(handle).cloned().ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
    let admin=connect.registry.local_runtime_admins.get(handle).ok_or_else(||local("LOCAL_RUNTIME_TAKEOVER_REQUIRED"))?;
    let directory=connect.directory.join(format!("runtime-{handle}"));
    if *admin!=directory.join("admin.json") || registration.endpoint_path!=directory.join("client-bootstrap.json") {return Err(local("LOCAL_RUNTIME_TAKEOVER_REQUIRED"));}
    let config:RuntimeConfig=serde_json::from_value(crate::communication_store::private_json(&directory.join("config.json"),65536)
        .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?;
    let launch:Launch=serde_json::from_slice(&SecureStateStore::read_snapshot(&directory.join("bootstrap.state"),65536)
        .map_err(|_|local("LOCAL_RUNTIME_TAKEOVER_REQUIRED"))?).map_err(|_|local("RUNTIME_LAUNCH_RECOVERY_REQUIRED"))?;
    if config.state_directory!=directory || launch.config_digest!=sha256_hex(&serde_json::to_vec(&config).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?) {return Err(local("LOCAL_BINDING_CONFLICT"));}
    Ok(OwnedRuntime{config,registration,launch:Some(launch),config_path:None})
}

impl Connect {
    pub(super) async fn runtime_admin(&mut self, handle:&str, selection:Option<&RuntimeSelection>)->Result<PathBuf> {
        self.require_writer()?;
        let client=self.original_client(handle).await?;
        let binding=client.call(json!({"method":"binding"})).await?;
        let admin=selection.map(|s|s.admin_endpoint.clone()).or_else(||self.registry.local_runtime_admins.get(handle).cloned())
            .ok_or_else(||local("EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED"))?;
        if !admin.is_absolute(){return Err(local("HOST_SELECTION_INVALID"));}
        let status=crate::communication_runtime::call(&admin,json!({"method":"status"})).await?;
        if status["ok"]!=true || !status["value"]["engines"].as_array().is_some_and(|engines|engines.iter().any(|e|
            ["actor_id","origin","engine_digest","state_binding"].iter().all(|field|e[*field]==binding[*field]))) {
            return Err(local("HOST_RUNTIME_BINDING_MISMATCH"));
        }
        self.registry.local_runtime_admins.insert(handle.into(),admin.clone());self.save()?;
        Ok(admin)
    }
    /// Source adoption authenticates the selected client in an existing runtime
    /// without imposing a host adapter's single-engine attachment shape.
    pub(super) async fn runtime_for_source(&mut self,handle:&str,selection:&RuntimeSelection)->Result<OwnedRuntime> {
        let path=selection.config_path.as_ref().ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_SELECTION_REQUIRED"))?;
        if !path.is_absolute(){return Err(local("LOCAL_SELECTION_INVALID"));}
        let config:RuntimeConfig=serde_json::from_value(crate::communication_store::private_json(path,65536)
            .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?;
        if config.format!="peerwork.participant-runtime.v1" || config.engines.is_empty() || config.engines.len()>8 || !config.state_directory.is_absolute()
            || selection.admin_endpoint!=config.state_directory.join("admin.json") {return Err(local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"));}
        let registration=self.registry.participants.get(handle).cloned().ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let client=self.original_client(handle).await?;
        let binding=client.call(json!({"method":"binding"})).await?;
        let name=binding["client_name"].as_str().filter(|name|identifier(name)).ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"))?;
        let mut matching=Vec::new();
        for engine in &config.engines {
            if engine.expected_actor==registration.actor_id
                && crate::transport::canonical_lifecycle_origin(&engine.origin,engine.allow_loopback_http).map_err(|_|local("ORIGIN_INVALID"))?==registration.origin
                && binding["engine_digest"]==engine.binding_digest()? {matching.push(engine);}
        }
        if matching.len()!=1 || registration.endpoint_path!=config.state_directory.join(format!("client-{name}.json")) {
            return Err(local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"));
        }
        if binding["client_generation"].is_null() {
            let configured=config.clients.iter().find(|c|c.name==name&&c.engine==matching[0].name).ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"))?;
            let capability=client.call(json!({"method":"capabilities"})).await?;
            if serde_json::to_value(&configured.capability).ok().as_ref()!=Some(&capability["capability"]){return Err(local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"));}
        }
        self.runtime_admin(handle,Some(selection)).await?;
        Ok(OwnedRuntime{config,registration,launch:None,config_path:Some(path.clone())})
    }
    pub(super) async fn runtime_for_attachment(&mut self,handle:&str,selection:Option<&RuntimeSelection>)->Result<OwnedRuntime> {
        if selection.is_none(){return owned_runtime(self,handle).map_err(|error|if error.code=="LOCAL_RUNTIME_TAKEOVER_REQUIRED"{local("ORIGINAL_RUNTIME_CONFIG_SELECTION_REQUIRED")}else{error});}
        // Discovery/admin delegation does not authorize taking over a process
        // supervised elsewhere. Direct restoration is an explicit local choice.
        let selection=selection.unwrap();
        let path=selection.config_path.as_ref().ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_SELECTION_REQUIRED"))?;
        if !path.is_absolute(){return Err(local("LOCAL_SELECTION_INVALID"));}
        let config:RuntimeConfig=serde_json::from_value(crate::communication_store::private_json(path,65536)
            .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?;
        if config.format!="peerwork.participant-runtime.v1" || config.engines.len()!=1 || !config.state_directory.is_absolute()
            || selection.admin_endpoint!=config.state_directory.join("admin.json") {return Err(local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"));}
        let registration=self.registry.participants.get(handle).cloned().ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let client=self.original_client(handle).await?;
        let binding=client.call(json!({"method":"binding"})).await?;
        let capability=client.call(json!({"method":"capabilities"})).await?;
        let engine=&config.engines[0];
        let name=binding["client_name"].as_str().ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"))?;
        let configured=config.clients.iter().find(|c|c.name==name&&c.engine==engine.name).ok_or_else(||local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"))?;
        if engine.expected_actor!=registration.actor_id || crate::transport::canonical_lifecycle_origin(&engine.origin,engine.allow_loopback_http).map_err(|_|local("ORIGIN_INVALID"))?!=registration.origin
            || binding["engine_digest"]!=engine.binding_digest()?
            || serde_json::to_value(&configured.capability).ok().as_ref()!=Some(&capability["capability"])
            || registration.endpoint_path!=config.state_directory.join(format!("client-{name}.json")) {
            return Err(local("ORIGINAL_RUNTIME_CONFIG_MISMATCH"));
        }
        self.runtime_admin(handle,Some(selection)).await?;
        Ok(OwnedRuntime{config,registration,launch:None,config_path:Some(path.clone())})
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn protected_index_does_not_authorize_automatic_signer_start_in_shared_namespace(){
        use std::os::unix::fs::PermissionsExt;
        let t=crate::test_support::protected_test_dir();let shared=t.path().join("shared");create_private_state_directory(&shared).unwrap();
        let key=shared.join("identity");let identity=crate::kernel_identity::KernelIdentity::create(&key).unwrap();let actor=identity.actor_id().to_owned();drop(identity);
        std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o775)).unwrap();let local=t.path().join("safe-index");create_private_state_directory(&local).unwrap();
        let engine=EngineConfig{name:"original".into(),origin:"https://api.peerwork.dev".into(),expected_actor:actor,identity_path:key,state_directory:shared.join("state"),journal_path:Some(shared.join("journal.sqlite")),authority:None,allow_loopback_http:false,transport:Default::default(),max_inflight:1,max_pending:2,max_stored_bytes:1024,migration_sources:vec![]};
        assert!(matches!(planned(&local,"worker",engine),Err(e)if e.code=="ORIGINAL_RUNTIME_OWNER_START_REQUIRED"));
        assert!(!shared.join("state").exists());assert!(!shared.join("journal.sqlite").exists());assert!(!local.join("runtime-worker").exists());
    }

    use super::*;
    #[test]
    fn original_launch_config_accepts_omitted_defaults_without_rewriting_or_ignoring_changes() {
        let root = crate::test_support::protected_test_dir();
        // Match owner-written legacy JSON, rather than serializing a Rust value
        // which already materializes every default before this comparison.
        let original = json!({"format":"peerwork.participant-runtime.v1",
            "state_directory":root.path().join("runtime"),
            "engines":[{"name":"original","origin":"https://example.invalid/",
                "expected_actor":"actor","identity_path":root.path().join("identity"),
                "state_directory":root.path().join("engine"),
                "journal_path":root.path().join("journal.sqlite"),
                "transport":{"request_timeout_ms":10000}}],"clients":[]});
        let path = root.path().join("original-runtime.json");
        let bytes = serde_json::to_vec(&original).unwrap();
        write_private(&path, &bytes).unwrap();
        let config: RuntimeConfig = serde_json::from_value(original.clone()).unwrap();
        verify_existing_launch_config(&path, &config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let mut changed = config.clone();
        changed.engines[0].journal_path = Some(root.path().join("another-journal.sqlite"));
        assert_eq!(verify_existing_launch_config(&path, &changed).unwrap_err().code, "LOCAL_BINDING_CONFLICT");
        changed = config.clone();
        changed.engines[0].max_pending += 1;
        assert_eq!(verify_existing_launch_config(&path, &changed).unwrap_err().code, "LOCAL_BINDING_CONFLICT");
        let mut unknown = original;
        unknown["engines"][0]["unrecognized_authority"] = json!(true);
        let unknown_path = root.path().join("unknown-runtime.json");
        write_private(&unknown_path, &serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert_eq!(verify_existing_launch_config(&unknown_path, &config).unwrap_err().code, "RUNTIME_CONFIG_INVALID");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(!config.state_directory.exists());
    }
    #[test]
    fn selected_existing_engine_keeps_journal_authority_and_transport() {
        let root = crate::test_support::protected_test_dir();
        let identity = root.path().join("identity");
        let actor = crate::kernel_identity::KernelIdentity::create(&identity)
            .unwrap()
            .actor_id()
            .to_owned();
        let state = root.path().join("original-state");
        let journal = root.path().join("original-journal.sqlite");
        let ca = root.path().join("local-ca.pem");
        let values: BTreeMap<String, String> = [
            ("--identity", identity.to_str().unwrap()),
            ("--engine-state", state.to_str().unwrap()),
            ("--journal", journal.to_str().unwrap()),
            ("--origin", "https://example.invalid"),
            ("--authority", "original-authority"),
            ("--request-timeout-ms", "24000"),
            ("--ca-root", ca.to_str().unwrap()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let selected = engine(&values).unwrap().unwrap();
        assert_eq!(selected.expected_actor, actor);
        assert_eq!(selected.state_directory, state);
        assert_eq!(selected.journal_path, Some(journal));
        assert_eq!(selected.authority.as_deref(), Some("original-authority"));
        assert_eq!(selected.transport.request_timeout_ms, 24000);
        assert_eq!(selected.transport.additional_root_pem_files, vec![ca]);
        assert!(
            !selected.state_directory.exists(),
            "selection created another signing journal"
        );
        let config = root.path().join("engine.json");
        write_private(&config, &serde_json::to_vec(&selected).unwrap()).unwrap();
        let mut flags: BTreeMap<String, String> =
            [("--engine-config".into(), config.to_str().unwrap().into())].into();
        assert_eq!(
            serde_json::to_value(engine(&flags).unwrap().unwrap()).unwrap(),
            serde_json::to_value(selected).unwrap()
        );
        flags.insert("--identity".into(), identity.to_str().unwrap().into());
        assert_eq!(
            engine(&flags).err().unwrap().code,
            "LOCAL_SELECTION_CONFLICT"
        );
        assert!(!alive(0, None).unwrap());
    }
    #[tokio::test]
    async fn registered_handle_conflicts_and_missing_provenance_have_no_launch_side_effects() {
        let root = crate::test_support::protected_test_dir();
        let identity = root.path().join("identity");
        let actor = crate::kernel_identity::KernelIdentity::create(&identity)
            .unwrap()
            .actor_id()
            .to_owned();
        let engine = EngineConfig {
            name: "selected".into(),
            origin: "https://example.invalid/".into(),
            expected_actor: actor.clone(),
            identity_path: identity,
            state_directory: root.path().join("original"),
            journal_path: Some(root.path().join("custom-journal")),
            authority: None,
            allow_loopback_http: false,
            transport: Default::default(),
            max_inflight: 1,
            max_pending: 8,
            max_stored_bytes: 1024 * 1024,
            migration_sources: Vec::new(),
        };
        let local = root.path().join("local");
        let mut connect = Connect::open(&local).unwrap();
        connect.registry.participants.insert(
            "worker".into(),
            Registration {
                origin: engine.origin.clone(),
                actor_id: actor,
                endpoint_path: root.path().join("external-endpoint"),
            },
        );
        assert_eq!(
            connect
                .bootstrap("worker", engine.clone())
                .await
                .err()
                .unwrap()
                .code,
            "LOCAL_BINDING_CONFLICT"
        );
        assert!(!local.join("runtime-worker").exists());
        assert!(!engine.state_directory.exists());
        let (_, proposed) = planned(&local, "worker", engine.clone()).unwrap();
        connect
            .registry
            .participants
            .insert("worker".into(), proposed);
        assert_eq!(
            connect
                .bootstrap("worker", engine.clone())
                .await
                .err()
                .unwrap()
                .code,
            "EXPLICIT_RUNTIME_ADMIN_SELECTION_REQUIRED"
        );
        assert!(!local.join("runtime-worker").exists());
        assert!(!engine.state_directory.exists());
        assert_eq!(
            alive(std::process::id(), None).err().unwrap().code,
            "PROCESS_IDENTITY_UNCONFIRMED"
        );
    }
    #[test]
    fn existing_state_cannot_silently_select_a_different_default_journal() {
        let root = crate::test_support::protected_test_dir();
        let identity = root.path().join("identity");
        crate::kernel_identity::KernelIdentity::create(&identity).unwrap();
        let state = root.path().join("original");
        create_private_state_directory(&state).unwrap();
        write_private(&state.join("existing-owner-state"), b"preserve").unwrap();
        let values: BTreeMap<String, String> = [
            ("--identity", identity.to_str().unwrap()),
            ("--engine-state", state.to_str().unwrap()),
            ("--origin", "https://example.invalid/"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(
            engine(&values).err().unwrap().code,
            "ORIGINAL_ENGINE_CONFIG_REQUIRED"
        );
        assert!(!state.join("kernel.sqlite").exists());
        assert_eq!(
            std::fs::read(state.join("existing-owner-state")).unwrap(),
            b"preserve"
        );
    }
}
