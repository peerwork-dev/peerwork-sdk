//! Explicit stopped-runtime physical host replacement. The identity, encrypted
//! inbox, receiver keys and original host calls stay in their original stores.
//! A sealed job and the engine-owner fence make every boundary resumable.
use crate::{
    communication_host::Host,
    communication_runtime::RuntimeConfig,
    communication_store::{identifier, private_json},
    kernel_access::KernelAccess,
    kernel_identity::KernelIdentity,
    kernel_intents::parent_operations::{open_bounded, seal_bounded},
    participant::{ParticipantError, Result, WatchOptions},
    participant_inbox::{HostBinding, HostRebind, InboxStore},
    participant_owner::{self, MaintenancePin},
    participant_watch::Binding,
    secure_state::{read_private_file_bounded, validate_private_file, SecureStateStore},
    KernelCancellationToken,
};
use peerwork_core::{
    communication::MailboxPins,
    crypto::{base64url, sha256, sha256_hex},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

const MAX_JOB: usize = 512 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRebindRequest {
    pub format: String,
    pub operation_id: String,
    pub engine: String,
    pub host: String,
    /// An explicit existing-session adapter, never a command to start a model.
    pub adapter: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    workspace_id: String,
    mailbox_id: String,
    membership_id: String,
    receiver_id: String,
    epoch: u64,
    destination_digest: String,
    binding_version: u64,
    after_sequence: u64,
    after_control_sequence: Option<u64>,
}
impl From<&MailboxPins> for Pins {
    fn from(p: &MailboxPins) -> Self {
        Self {
            workspace_id: p.workspace_id.clone(),
            mailbox_id: p.mailbox_id.clone(),
            membership_id: p.membership_id.clone(),
            receiver_id: p.receiver_id.clone(),
            epoch: p.epoch,
            destination_digest: p.destination_digest.clone(),
            binding_version: p.binding_version,
            after_sequence: p.after_sequence,
            after_control_sequence: p.after_control_sequence,
        }
    }
}
impl Pins {
    fn native(&self) -> MailboxPins {
        MailboxPins {
            workspace_id: self.workspace_id.clone(),
            mailbox_id: self.mailbox_id.clone(),
            membership_id: self.membership_id.clone(),
            receiver_id: self.receiver_id.clone(),
            epoch: self.epoch,
            destination_digest: self.destination_digest.clone(),
            binding_version: self.binding_version,
            after_sequence: self.after_sequence,
            after_control_sequence: self.after_control_sequence,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Subscription {
    namespace: String,
    old: WatchOptions,
    expected: Pins,
    claim_id: String,
    claim_wire: Option<String>,
    confirmed: Option<Pins>,
    committed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    format: String,
    request: HostRebindRequest,
    pin: MaintenancePin,
    original: RuntimeConfig,
    target: RuntimeConfig,
    destination: HostBinding,
    host_key: String,
    host_state_before: Option<Vec<u8>>,
    scopes: Vec<Subscription>,
    ready: bool,
}
fn error(code: &str) -> ParticipantError {
    ParticipantError::local(code, "HOST_REBIND")
}
fn token(parts: Value) -> String {
    base64url(&sha256(parts.to_string().as_bytes()))
}
fn save(store: &SecureStateStore, identity: &KernelIdentity, aad: &str, job: &Job) -> Result<()> {
    let wire = serde_json::to_string(job).map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
    let sealed = seal_bounded(identity, aad, &wire, MAX_JOB)
        .map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
    store
        .write_exact(&sealed)
        .map_err(|_| error("HOST_REBIND_STATE_FAILED"))
}
fn load(store: &SecureStateStore, identity: &KernelIdentity, aad: &str) -> Result<Option<Job>> {
    store
        .read_exact()
        .map_err(|_| error("HOST_REBIND_STATE_INVALID"))?
        .map(|sealed| {
            let wire = open_bounded(identity, aad, &sealed, MAX_JOB)
                .map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
            let value = peerwork_core::strict_json::parse_strict_json(wire.as_bytes())
                .map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
            let job: Job =
                serde_json::from_value(value).map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
            if job.format != "peerwork.host-rebind-job.v1"
                || job.scopes.is_empty()
                || job.scopes.len() > 8
            {
                return Err(error("HOST_REBIND_STATE_INVALID"));
            }
            Ok(job)
        })
        .transpose()
}
fn result(job: &Job) -> Value {
    json!({"state":"HOST_REBIND_READY","operation_id":job.request.operation_id,"engine":job.request.engine,
        "host":job.request.host,"scopes":job.scopes.len(),"destination_digest":job.destination.digest,
        "original_host_calls":"RETAINED_AT_ORIGINAL_BINDINGS","model_response":"NOT_ATTESTED",
        "readiness":"CONFIGURATION_COMMITTED_START_RUNTIME_TO_OBSERVE_CURRENT_READINESS"})
}
/// Stop the owning runtime/embedded client first. One call completes all selected
/// subscriptions. After interruption repeat the exact request and operation ID;
/// never create a new operation to resolve an unknown replacement claim.
pub async fn rebind_host(config: &Path, request: HostRebindRequest) -> Result<Value> {
    let config = config.to_owned();
    tokio::task::spawn_blocking(move || rebind_with(&config, request, |_| Ok(())))
        .await
        .map_err(|_| error("HOST_REBIND_EXECUTOR_FAILED"))?
}
fn rebind_with(
    config_path: &Path,
    request: HostRebindRequest,
    mut boundary: impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    if request.format != "peerwork.host-rebind.v1"
        || !identifier(&request.operation_id)
        || !identifier(&request.engine)
        || !identifier(&request.host)
        || !config_path.is_absolute()
    {
        return Err(error("HOST_REBIND_SELECTION_INVALID"));
    }
    let config: RuntimeConfig = serde_json::from_value(
        private_json(config_path, 65536).map_err(|_| error("RUNTIME_CONFIG_NOT_PRIVATE"))?,
    )
    .map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    if config.format != "peerwork.participant-runtime.v1"
        || config
            .engines
            .iter()
            .filter(|e| e.name == request.engine)
            .count()
            != 1
        || config
            .hosts
            .iter()
            .filter(|h| h.name == request.host)
            .count()
            != 1
    {
        return Err(error("HOST_REBIND_SELECTION_INVALID"));
    }
    let engine = config
        .engines
        .iter()
        .find(|e| e.name == request.engine)
        .unwrap()
        .clone();
    let identity =
        KernelIdentity::open(&engine.identity_path).map_err(|_| error("IDENTITY_STATE_INVALID"))?;
    if identity.actor_id() != engine.expected_actor {
        return Err(error("IDENTITY_MISMATCH"));
    }
    let origin =
        crate::transport::canonical_lifecycle_origin(&engine.origin, engine.allow_loopback_http)
            .map_err(|_| error("ORIGIN_INVALID"))?;
    let authority = engine
        .authority
        .clone()
        .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
    let logical = participant_owner::logical_binding(&identity, &origin, &authority);
    let id = token(json!([
        "peerwork.host-rebind-job.v1",
        config_path,
        request.engine,
        request.operation_id
    ]));
    let aad = json!([
        "peerwork.host-rebind-job.v1",
        String::from_utf8_lossy(&logical),
        id
    ])
    .to_string();
    let selection = sha256_hex(
        serde_json::to_string(&request)
            .map_err(|_| error("HOST_REBIND_SELECTION_INVALID"))?
            .as_bytes(),
    );
    let job_store = SecureStateStore::open(
        &config
            .state_directory
            .join(format!("host-rebind-{id}.state")),
    )
    .map_err(|_| error("HOST_REBIND_JOB_ALREADY_OWNED"))?;
    let existing = load(&job_store, &identity, &aad)?;
    if let Some(job) = &existing {
        if job.pin.operation_id != id
            || job.pin.selection_digest != selection
            || serde_json::to_value(&job.request).ok() != serde_json::to_value(&request).ok()
        {
            return Err(error("HOST_REBIND_ORIGINAL_SELECTION_REQUIRED"));
        }
        // Observational completed retry before engine ownership or host IO.
        if job.ready {
            return Ok(result(job));
        }
    }
    let _runtime = SecureStateStore::open(&config.state_directory.join("runtime.state"))
        .map_err(|_| error("HOST_REBIND_STOP_RUNTIME_FIRST"))?;
    validate_private_file(&engine.state_directory.join("engine-owner.state"))
        .map_err(|_| error("HOST_REBIND_ENGINE_NOT_INITIALIZED"))?;
    let owner = SecureStateStore::open(&engine.state_directory.join("engine-owner.state"))
        .map_err(|_| error("HOST_REBIND_STOP_ENGINE_FIRST"))?;
    crate::participant_transfer::check_open(&engine.state_directory)?;
    let options = engine.participant_config();
    let _journal = SecureStateStore::open(
        &options
            .journal_path
            .with_extension("participant-owner.state"),
    )
    .map_err(|_| error("HOST_REBIND_STOP_JOURNAL_OWNER_FIRST"))?;
    let mut inbox = InboxStore::open_local(&engine.state_directory, &identity, &origin)?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| error("HOST_REBIND_EXECUTOR_FAILED"))?;
    let mut host_guard = None;
    let mut job = if let Some(job) = existing {
        job
    } else {
        let selected = config
            .hosts
            .iter()
            .find(|h| h.name == request.host)
            .unwrap();
        let key = selected.key()?;
        if config
            .hosts
            .iter()
            .filter(|h| h.key().ok().as_ref() == Some(&key))
            .count()
            != 1
        {
            return Err(error("HOST_REBIND_SELECT_ONE_HOST_GROUP"));
        }
        let mut target = config.clone();
        let target_host = target
            .hosts
            .iter_mut()
            .find(|h| h.name == request.host)
            .unwrap();
        target_host.adapter = request.adapter.clone();
        let host_key = target_host.key()?;
        let revision = participant_owner::revision(&owner, &logical)?;
        let mut host =
            Host::open(request.adapter.clone(), executor.handle().clone()).map_err(error)?;
        let destination = HostBinding::new(host.destination.clone())?;
        let mut scopes = Vec::new();
        for (index, subscription) in selected.subscriptions.iter().enumerate() {
            let clients = config
                .clients
                .iter()
                .filter(|c| c.name == subscription.client)
                .collect::<Vec<_>>();
            if clients.len() != 1 || clients[0].engine != engine.name {
                return Err(error("HOST_REBIND_SELECTED_HOST_ENGINE_MISMATCH"));
            }
            subscription.watch.authorize(&clients[0].capability)?;
            let namespace = format!("program:{}", subscription.client);
            let binding = inbox.selected_watch(&namespace, &subscription.watch)?;
            inbox.host_scope_check(&namespace, &binding.options)?;
            inbox.rebind_reports_unblocked(&binding.options)?;
            let pins = binding
                .pins
                .ok_or_else(|| error("HOST_REBIND_MAILBOX_NOT_INITIALIZED"))?;
            pins.validate()
                .map_err(|_| error("HOST_REBIND_PINS_INVALID"))?;
            if pins.receiver_id != binding.receiver
                || binding.options.host_destination.as_deref() != Some(&pins.destination_digest)
                || destination.digest == pins.destination_digest
                || scopes.iter().any(|s: &Subscription| {
                    s.old.workspace_id == binding.options.workspace_id
                        && s.old.mailbox_id == binding.options.mailbox_id
                })
            {
                return Err(error("HOST_REBIND_SELECTION_INVALID"));
            }
            let mut access = inbox.host_access_scope(&namespace, &binding.options)?;
            access["destination_digest"] = json!(destination.digest);
            host.health(&access).map_err(error)?;
            target_host.subscriptions[index].watch.host_destination =
                Some(destination.digest.clone());
            scopes.push(Subscription {
                namespace,
                old: binding.options,
                expected: Pins::from(&pins),
                claim_id: token(json!([id, index, "replace"])),
                claim_wire: None,
                confirmed: None,
                committed: false,
            });
        }
        let host_state = SecureStateStore::open(
            &config
                .state_directory
                .join(format!("host-{host_key}.state")),
        )
        .map_err(|_| error("HOST_REBIND_TARGET_DISPATCHER_STILL_OWNED"))?;
        let host_state_before = host_state
            .read_exact()
            .map_err(|_| error("HOST_REBIND_HOST_STATE_INVALID"))?;
        if let Some(bytes) = &host_state_before {
            let old: HostBinding = serde_json::from_slice(bytes)
                .map_err(|_| error("HOST_REBIND_HOST_STATE_INVALID"))?;
            if old != destination
                && !(host_key == key
                    && scopes
                        .iter()
                        .all(|s| s.expected.destination_digest == old.digest))
            {
                return Err(error("HOST_REBIND_TARGET_HOST_STATE_CONFLICT"));
            }
        }
        if serde_json::to_vec(&target)
            .map_err(|_| error("RUNTIME_CONFIG_INVALID"))?
            .len()
            > 65536
        {
            return Err(error("RUNTIME_CONFIG_INVALID"));
        }
        host_guard = Some(host);
        let job = Job {
            format: "peerwork.host-rebind-job.v1".into(),
            request,
            pin: MaintenancePin {
                operation_id: id,
                selection_digest: selection,
                expected_revision: revision,
            },
            original: config,
            target,
            destination,
            host_key,
            host_state_before,
            scopes,
            ready: false,
        };
        // Capability discovery is a preflight: no owner fence on unsupported service.
        let access = access(&engine);
        executor
            .block_on(access.open_async(&KernelCancellationToken::new()))
            .map_err(|e| native_error(e, None))?;
        executor.block_on(access.close_session_executor_async());
        save(&job_store, &identity, &aad, &job)?;
        boundary("PREPARED")?;
        job
    };
    // User edits are never overwritten, including after a partial remote move.
    check_config(config_path, &job)?;
    if job
        .target
        .hosts
        .iter()
        .find(|h| h.name == job.request.host)
        .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?
        .key()?
        != job.host_key
    {
        return Err(error("HOST_REBIND_TARGET_CREDENTIAL_CHANGED"));
    }
    let host_state = SecureStateStore::open(
        &job.target
            .state_directory
            .join(format!("host-{}.state", job.host_key)),
    )
    .map_err(|_| error("HOST_REBIND_TARGET_DISPATCHER_STILL_OWNED"))?;
    let host_pin =
        serde_json::to_vec(&job.destination).map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
    let saved_host = host_state
        .read_exact()
        .map_err(|_| error("HOST_REBIND_HOST_STATE_INVALID"))?;
    if saved_host != job.host_state_before && saved_host.as_deref() != Some(host_pin.as_slice()) {
        return Err(error("HOST_REBIND_TARGET_HOST_STATE_CONFLICT"));
    }
    if host_guard.is_none() && job.scopes.iter().any(|s| s.confirmed.is_none()) {
        let mut host =
            Host::open(job.request.adapter.clone(), executor.handle().clone()).map_err(error)?;
        if HostBinding::new(host.destination.clone())? != job.destination {
            return Err(error("HOST_REBIND_TARGET_SESSION_CHANGED"));
        }
        for s in job.scopes.iter().filter(|s| s.confirmed.is_none()) {
            let mut binding = inbox.host_access_scope(&s.namespace, &s.old)?;
            binding["destination_digest"] = json!(job.destination.digest);
            host.health(&binding).map_err(error)?;
        }
        host_guard = Some(host);
    }
    let _host_guard = host_guard;
    if !participant_owner::begin(&owner, &logical, &job.pin)? {
        job.ready = true;
        save(&job_store, &identity, &aad, &job)?;
        return Ok(result(&job));
    }
    boundary("FENCED")?;
    let access = access(&engine);
    let work = (|| {
        for index in 0..job.scopes.len() {
            if job.scopes[index].committed {
                continue;
            }
            if job.scopes[index].confirmed.is_none() {
                let s = &job.scopes[index];
                let binding = Binding {
                    namespace: s.namespace.clone(),
                    options: s.old.clone(),
                    receiver: s.expected.receiver_id.clone(),
                    claim_id: s.claim_id.clone(),
                    claim_wire: None,
                    pins: Some(s.expected.native()),
                };
                inbox.disable_watch(&s.namespace, &s.old)?;
                if s.claim_wire.is_none() {
                    inbox.rebind_reports_unblocked(&s.old)?;
                    let current = executor.block_on(call(
                        &access,
                        "structure.mailbox.get",
                        &s.old.workspace_id,
                        json!({"mailbox_id":s.old.mailbox_id}),
                        None,
                    ))?;
                    validate_mailbox(
                        &current["mailbox"],
                        &s.expected,
                        &engine.expected_actor,
                        &s.expected.destination_digest,
                        s.expected.epoch,
                        s.expected.binding_version,
                    )?;
                    // Renew the original fence even when its old lease expired.
                    executor.block_on(call(&access,"structure.mailbox.pulse",&s.old.workspace_id,json!({"mailbox_id":s.old.mailbox_id,
                        "receiver_id":s.expected.receiver_id,"epoch":s.expected.epoch,"ready":false,"execution_state":"OFFLINE"}),None))?;
                    while let Some((call_id, version, report)) =
                        inbox.pending_host_report(&identity, &s.namespace, &s.old)?
                    {
                        executor.block_on(call(&access,"structure.mailbox.report",&s.old.workspace_id,json!({"mailbox_id":s.old.mailbox_id,
                            "receiver_id":s.expected.receiver_id,"epoch":s.expected.epoch,"report":report}),None))?;
                        inbox.host_reported(
                            &s.old.workspace_id,
                            &s.old.mailbox_id,
                            &call_id,
                            version,
                        )?;
                    }
                    boundary("REPORTS_FLUSHED")?;
                    let mut body = json!({"claim_command_id":s.claim_id,"mailbox_id":s.old.mailbox_id,"receiver_id":s.expected.receiver_id,
                        "expected_epoch":s.expected.epoch,"destination_digest":job.destination.digest,"replace":true});
                    body["continuity_proof"] =
                        json!(inbox.receiver_proof(&identity, &binding, &body)?);
                    let wire=json!({"action":"structure.mailbox.claim","workspace_id":s.old.workspace_id,"command_id":s.claim_id,"body":body}).to_string();
                    job.scopes[index].claim_wire = Some(wire);
                    save(&job_store, &identity, &aad, &job)?;
                    boundary("CLAIM_FROZEN")?;
                }
                let s = &job.scopes[index];
                let wire = s
                    .claim_wire
                    .as_deref()
                    .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?;
                let claimed = executor.block_on(execute(&access, wire, Some(&s.claim_id)))?;
                let epoch = s
                    .expected
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| error("HOST_REBIND_PINS_INVALID"))?;
                let version = s
                    .expected
                    .binding_version
                    .checked_add(1)
                    .ok_or_else(|| error("HOST_REBIND_PINS_INVALID"))?;
                validate_mailbox(
                    &claimed["mailbox"],
                    &s.expected,
                    &engine.expected_actor,
                    &job.destination.digest,
                    epoch,
                    version,
                )?;
                boundary("CLAIM_CONFIRMED_BEFORE_SAVE")?;
                let mut confirmed = s.expected.clone();
                confirmed.epoch = epoch;
                confirmed.binding_version = version;
                confirmed.destination_digest = job.destination.digest.clone();
                job.scopes[index].confirmed = Some(confirmed);
                save(&job_store, &identity, &aad, &job)?;
            }
            let s = &job.scopes[index];
            let mut new = s.old.clone();
            new.host_destination = Some(job.destination.digest.clone());
            inbox.host_rebind_commit(&HostRebind {
                operation_id: job.pin.operation_id.clone(),
                namespace: s.namespace.clone(),
                old: s.old.clone(),
                new,
                expected: s.expected.native(),
                confirmed: s
                    .confirmed
                    .as_ref()
                    .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?
                    .native(),
                host: job.destination.clone(),
            })?;
            boundary("LOCAL_COMMITTED_BEFORE_SAVE")?;
            job.scopes[index].committed = true;
            save(&job_store, &identity, &aad, &job)?;
        }
        check_config(config_path, &job)?;
        host_state
            .write_exact(&host_pin)
            .map_err(|_| error("HOST_REBIND_HOST_STATE_FAILED"))?;
        boundary("HOST_PIN_COMMITTED")?;
        crate::communication_bridge::replace_descriptor(
            config_path,
            &serde_json::to_value(&job.target).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?,
        )
        .map_err(error)?;
        boundary("CONFIG_COMMITTED")?;
        participant_owner::complete(&owner, &logical, &job.pin)?;
        boundary("OWNER_COMPLETED")?;
        job.ready = true;
        save(&job_store, &identity, &aad, &job)?;
        Ok(result(&job))
    })();
    executor.block_on(access.close_session_executor_async());
    work
}
fn check_config(path: &Path, job: &Job) -> Result<()> {
    let current = private_json(path, 65536).map_err(|_| error("RUNTIME_CONFIG_NOT_PRIVATE"))?;
    let original =
        serde_json::to_value(&job.original).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    let target = serde_json::to_value(&job.target).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    // Normalize omitted default fields without ignoring unknown ones.
    let parsed: RuntimeConfig =
        serde_json::from_value(current).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    let value = serde_json::to_value(parsed).map_err(|_| error("RUNTIME_CONFIG_INVALID"))?;
    if value != original && value != target {
        return Err(error(
            "HOST_REBIND_CONFIG_CHANGED_RESTORE_ORIGINAL_SELECTION",
        ));
    }
    Ok(())
}
fn access(engine: &crate::communication_runtime::EngineConfig) -> KernelAccess {
    KernelAccess::new(
        &engine.origin,
        engine.participant_config().journal_path,
        &engine.identity_path,
        &[
            "native-mailbox-v1".into(),
            "native-mailbox-rebind-v1".into(),
        ],
        engine.allow_loopback_http,
    )
    .with_authority(engine.authority.clone())
    .with_transport_options(engine.transport.clone())
    .with_persistent_session()
}
fn native_error(
    error: crate::kernel_access::KernelAccessError,
    command: Option<&str>,
) -> ParticipantError {
    let value = crate::participant_outcome::native_error(error);
    ParticipantError {
        code: value["code"]
            .as_str()
            .unwrap_or("HOST_REBIND_REMOTE_FAILED")
            .into(),
        phase: value["phase"]
            .as_str()
            .unwrap_or("HOST_REBIND_REMOTE")
            .into(),
        effect_certainty: value["effect_certainty"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .into(),
        recovery: "RESUME_SAME_HOST_REBIND_OPERATION".into(),
        operation_id: command.map(str::to_owned),
    }
}
async fn call(
    access: &KernelAccess,
    action: &str,
    workspace: &str,
    body: Value,
    command: Option<&str>,
) -> Result<Value> {
    let mut wire = json!({"action":action,"workspace_id":workspace,"body":body});
    if let Some(id) = command {
        wire["command_id"] = json!(id);
    }
    execute(access, &wire.to_string(), command).await
}
async fn execute(access: &KernelAccess, wire: &str, command: Option<&str>) -> Result<Value> {
    let outcome = access
        .execute_structure_intent_async(wire.as_bytes(), &KernelCancellationToken::new())
        .await
        .map_err(|e| native_error(e, command))?;
    let value = crate::participant_outcome::outcome(outcome);
    if matches!(value["state"].as_str(), Some("ACCEPTED" | "COMPLETED")) {
        let structure = &value["result"]["structure"];
        if structure.is_object() {
            return Ok(structure.clone());
        }
    }
    let refusal = value["result"]["structure"]["status"] == "REJECTED_NO_EFFECT";
    Err(ParticipantError {
        code: value["result"]["structure"]["error"]["code"]
            .as_str()
            .or(value["code"].as_str())
            .unwrap_or("HOST_REBIND_RESULT_INVALID")
            .into(),
        phase: value["phase"]
            .as_str()
            .unwrap_or("HOST_REBIND_REMOTE")
            .into(),
        effect_certainty: if refusal {
            "REJECTED_NO_EFFECT"
        } else {
            value["effect_certainty"].as_str().unwrap_or("UNKNOWN")
        }
        .into(),
        recovery: "RESUME_SAME_HOST_REBIND_OPERATION".into(),
        operation_id: command.map(str::to_owned),
    })
}
fn validate_mailbox(
    value: &Value,
    old: &Pins,
    actor: &str,
    destination: &str,
    epoch: u64,
    version: u64,
) -> Result<()> {
    if value["mailbox_id"] != old.mailbox_id
        || value["membership_id"] != old.membership_id
        || value["actor_id"] != actor
        || value["receiver_id"] != old.receiver_id
        || value["destination_digest"] != destination
        || value["epoch"] != epoch
        || value["binding_version"] != version
    {
        return Err(error("HOST_REBIND_VERIFIED_MAILBOX_MISMATCH"));
    }
    Ok(())
}
pub(crate) fn cli(config: &Path, request: &Path) -> Result<Value> {
    let bytes = read_private_file_bounded(request, 16384)
        .map_err(|_| error("HOST_REBIND_REQUEST_NOT_PRIVATE"))?;
    let request: HostRebindRequest = serde_json::from_value(
        peerwork_core::strict_json::parse_strict_json(&bytes)
            .map_err(|_| error("HOST_REBIND_SELECTION_INVALID"))?,
    )
    .map_err(|_| error("HOST_REBIND_SELECTION_INVALID"))?;
    rebind_with(config, request, |_| Ok(()))
}

#[cfg(test)]
#[path = "participant_rebind_tests.rs"]
mod tests;
