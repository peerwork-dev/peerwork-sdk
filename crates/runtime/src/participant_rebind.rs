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
const MAX_DECISIONS: usize = 16;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostRebindRecoveryAction {
    RetryRejected,
    Abort,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostRebindRecoveryRequest {
    pub format: String,
    pub decision_id: String,
    pub action: HostRebindRecoveryAction,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedAttempt {
    claim_id: String,
    claim_wire: String,
    result_digest: String,
}
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
    #[serde(default)]
    was_enabled: bool,
    #[serde(default)]
    rejected: Vec<RejectedAttempt>,
    #[serde(default)]
    refresh_epoch_on_retry: bool,
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
    #[serde(default)]
    decisions: Vec<HostRebindRecoveryRequest>,
    #[serde(default)]
    aborting: Option<String>,
    #[serde(default)]
    aborted: bool,
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
                || job.decisions.len() > MAX_DECISIONS + 1
                || job.scopes.iter().any(|s| s.rejected.len() > MAX_DECISIONS)
            {
                return Err(error("HOST_REBIND_STATE_INVALID"));
            }
            Ok(job)
        })
        .transpose()
}
fn result(job: &Job) -> Value {
    json!({"state":if job.aborted{"HOST_REBIND_ABORTED"}else{"HOST_REBIND_READY"},"operation_id":job.request.operation_id,"engine":job.request.engine,
        "host":job.request.host,"scopes":job.scopes.len(),"destination_digest":job.destination.digest,
        "original_host_calls":"RETAINED_AT_ORIGINAL_BINDINGS","model_response":"NOT_ATTESTED",
        "readiness":if job.aborted{"ORIGINAL_CONFIGURATION_RETAINED_START_RUNTIME_TO_OBSERVE_CURRENT_READINESS"}else{"CONFIGURATION_COMMITTED_START_RUNTIME_TO_OBSERVE_CURRENT_READINESS"}})
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
/// Explicit operator decision. Unknown claims cannot be cancelled or assigned
/// fresh IDs. A confirmed no-effect claim may be retried at the same selected
/// destination; abort is possible only before any mailbox replacement commits.
pub async fn recover_host_rebind(
    config: &Path,
    request: HostRebindRequest,
    recovery: HostRebindRecoveryRequest,
) -> Result<Value> {
    let config = config.to_owned();
    tokio::task::spawn_blocking(move || rebind_action(&config, request, Some(recovery), |_| Ok(())))
        .await
        .map_err(|_| error("HOST_REBIND_EXECUTOR_FAILED"))?
}
fn rebind_with(
    config_path: &Path,
    request: HostRebindRequest,
    mut boundary: impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    rebind_action(config_path, request, None, &mut boundary)
}
fn rebind_action(
    config_path: &Path,
    request: HostRebindRequest,
    recovery: Option<HostRebindRecoveryRequest>,
    mut boundary: impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    if let Some(r) = &recovery {
        if r.format != "peerwork.host-rebind-recovery.v1" || !identifier(&r.decision_id) {
            return Err(error("HOST_REBIND_RECOVERY_SELECTION_INVALID"));
        }
    }
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
        validate_decision(job, recovery.as_ref())?;
        if job.ready || job.aborted {
            return Ok(result(job));
        }
        if participant_owner::completed_snapshot(
            &engine.state_directory.join("engine-owner.state"),
            &logical,
            &job.pin,
        )? {
            let mut job = existing.unwrap();
            if job.aborting.is_some() {
                job.aborted = true;
            } else if job.scopes.iter().all(|s| s.committed) {
                job.ready = true;
            } else {
                return Err(error("HOST_REBIND_STATE_INVALID"));
            }
            save(&job_store, &identity, &aad, &job)?;
            return Ok(result(&job));
        }
    } else if recovery.is_some() {
        return Err(error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"));
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
                was_enabled: inbox.rebind_watch_enabled(&namespace, &binding.options)?,
                namespace,
                old: binding.options,
                expected: Pins::from(&pins),
                claim_id: token(json!([id, index, "replace"])),
                claim_wire: None,
                confirmed: None,
                committed: false,
                rejected: vec![],
                refresh_epoch_on_retry: false,
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
            decisions: vec![],
            aborting: None,
            aborted: false,
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
    if job.aborting.is_some()
        || recovery
            .as_ref()
            .is_some_and(|r| r.action == HostRebindRecoveryAction::Abort)
    {
        participant_owner::begin(&owner, &logical, &job.pin)?;
        return abort_job(
            &mut job,
            recovery.as_ref(),
            &job_store,
            &identity,
            &aad,
            &owner,
            &logical,
            &mut inbox,
            &engine,
            &executor,
            &mut boundary,
        );
    }
    if let Some(recovery) = &recovery {
        if !job
            .decisions
            .iter()
            .any(|r| r.decision_id == recovery.decision_id)
        {
            retry_rejected(&mut job, recovery, &identity, &engine)?;
            save(&job_store, &identity, &aad, &job)?;
            boundary("RETRY_REJECTED_FROZEN")?;
        }
    }
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
                    let refreshed_epoch = if s.refresh_epoch_on_retry {
                        let epoch = current["mailbox"]["epoch"]
                            .as_u64()
                            .filter(|e| *e >= s.expected.epoch)
                            .ok_or_else(|| error("HOST_REBIND_VERIFIED_MAILBOX_MISMATCH"))?;
                        epoch
                    } else {
                        s.expected.epoch
                    };
                    validate_mailbox(
                        &current["mailbox"],
                        &s.expected,
                        &engine.expected_actor,
                        &s.expected.destination_digest,
                        refreshed_epoch,
                        s.expected.binding_version,
                    )?;
                    if s.refresh_epoch_on_retry {
                        let mut pins = s.expected.native();
                        pins.epoch = refreshed_epoch;
                        inbox.register(&pins)?;
                        job.scopes[index].expected = Pins::from(&pins);
                        job.scopes[index].refresh_epoch_on_retry = false;
                        save(&job_store, &identity, &aad, &job)?;
                    }
                    let s = &job.scopes[index];
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
fn validate_decision(job: &Job, recovery: Option<&HostRebindRecoveryRequest>) -> Result<()> {
    let Some(r) = recovery else {
        return Ok(());
    };
    if let Some(old) = job
        .decisions
        .iter()
        .find(|d| d.decision_id == r.decision_id)
    {
        if old != r {
            return Err(error("HOST_REBIND_ORIGINAL_RECOVERY_DECISION_REQUIRED"));
        }
    } else if job.decisions.len() >= MAX_DECISIONS
        && r.action == HostRebindRecoveryAction::RetryRejected
    {
        return Err(error("HOST_REBIND_RECOVERY_DECISION_LIMIT"));
    }
    if job.ready && r.action == HostRebindRecoveryAction::Abort {
        return Err(error("HOST_REBIND_COMMITTED_FORWARD_RECOVERY_REQUIRED"));
    }
    if job.aborted && r.action == HostRebindRecoveryAction::RetryRejected {
        return Err(error("HOST_REBIND_ABORTED_NEW_JOB_REQUIRED"));
    }
    if let Some(id) = &job.aborting {
        if r.action != HostRebindRecoveryAction::Abort || &r.decision_id != id {
            return Err(error(
                "HOST_REBIND_ABORT_IN_PROGRESS_RESUME_ORIGINAL_DECISION",
            ));
        }
    }
    Ok(())
}
enum ClaimEvidence {
    NotSubmitted,
    Rejected(String),
    Unknown,
    Committed,
}
fn uncertain_claim(id: &str) -> ParticipantError {
    ParticipantError {
        code: "HOST_REBIND_UNKNOWN_CLAIM_RESUME_ORIGINAL".into(),
        phase: "HOST_REBIND_RECOVERY".into(),
        effect_certainty: "UNKNOWN".into(),
        recovery: "RESUME_SAME_HOST_REBIND_OPERATION".into(),
        operation_id: Some(id.into()),
    }
}
/// Selected offline verification, never a status inference from HTTP or a
/// server's mutable current mailbox. Every saved packet and receipt is checked
/// against the original identity, discovery, authority and complete claim body.
fn claim_evidence(
    journal: &crate::kernel_intents::KernelIntentJournal,
    identity: &KernelIdentity,
    origin: &str,
    authority: &str,
    id: &str,
    wire: &str,
) -> Result<ClaimEvidence> {
    let discovery = journal
        .pinned_discovery(origin)
        .map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))?;
    let Some(packet) = journal
        .verified_pending(id, identity.key_id(), discovery.audience_utf16())
        .map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))?
    else {
        return Ok(ClaimEvidence::NotSubmitted);
    };
    let frozen: Value =
        serde_json::from_str(wire).map_err(|_| error("HOST_REBIND_STATE_INVALID"))?;
    let command: Value = serde_json::from_str(packet.proof.command_canonical_json())
        .map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))?;
    // Native structure preparation makes this required field explicit before
    // signing. Compare the complete prepared body, including that exact profile.
    let mut expected_body = frozen["body"].clone();
    if expected_body
        .get("profile")
        .is_some_and(|v| v != peerwork_core::structure_execution::PROFILE)
    {
        return Err(error("HOST_REBIND_ORIGINAL_CLAIM_MISMATCH"));
    }
    expected_body
        .as_object_mut()
        .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?
        .insert(
            "profile".into(),
            json!(peerwork_core::structure_execution::PROFILE),
        );
    if packet.proof.actor_id() != identity.actor_id()
        || packet.proof.action_id() != "structure.mailbox.claim"
        || packet.proof.workspace_id() != frozen["workspace_id"].as_str()
        || command["authority"] != authority
        || command["body"] != expected_body
        || frozen["command_id"] != id
        || frozen["action"] != "structure.mailbox.claim"
    {
        return Err(error("HOST_REBIND_ORIGINAL_CLAIM_MISMATCH"));
    }
    let Some(response) = journal
        .accepted_response(&packet, discovery.receipt_public_key())
        .map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))?
    else {
        return Ok(ClaimEvidence::Unknown);
    };
    let result: Value = serde_json::from_str(response.result_canonical_json())
        .map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))?;
    if result["status"] == "REJECTED_NO_EFFECT" {
        Ok(ClaimEvidence::Rejected(response.result_digest().into()))
    } else {
        Ok(ClaimEvidence::Committed)
    }
}
fn open_evidence_journal(
    engine: &crate::communication_runtime::EngineConfig,
) -> Result<crate::kernel_intents::KernelIntentJournal> {
    let path = engine.participant_config().journal_path;
    validate_private_file(&path).map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))?;
    crate::kernel_intents::KernelIntentJournal::open(&path)
        .map_err(|_| error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID"))
}
fn retry_rejected(
    job: &mut Job,
    recovery: &HostRebindRecoveryRequest,
    identity: &KernelIdentity,
    engine: &crate::communication_runtime::EngineConfig,
) -> Result<()> {
    if recovery.action != HostRebindRecoveryAction::RetryRejected {
        return Err(error("HOST_REBIND_RECOVERY_SELECTION_INVALID"));
    }
    let journal = open_evidence_journal(engine)?;
    let origin =
        crate::transport::canonical_lifecycle_origin(&engine.origin, engine.allow_loopback_http)
            .map_err(|_| error("ORIGIN_INVALID"))?;
    let authority = engine
        .authority
        .clone()
        .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
    let mut retry = Vec::new();
    for (index, s) in job
        .scopes
        .iter()
        .enumerate()
        .filter(|(_, s)| s.confirmed.is_none())
    {
        if let Some(wire) = &s.claim_wire {
            if let ClaimEvidence::Rejected(digest) =
                claim_evidence(&journal, identity, &origin, &authority, &s.claim_id, wire)?
            {
                retry.push((
                    index,
                    RejectedAttempt {
                        claim_id: s.claim_id.clone(),
                        claim_wire: wire.clone(),
                        result_digest: digest,
                    },
                ));
            }
        }
    }
    if retry.is_empty() {
        return Err(error(
            "HOST_REBIND_NO_VERIFIED_REJECTED_CLAIM_RESUME_ORIGINAL",
        ));
    }
    for (index, old) in retry {
        let s = &mut job.scopes[index];
        s.rejected.push(old);
        s.claim_id = token(json!([
            job.pin.operation_id,
            recovery.decision_id,
            index,
            "retry-rejected"
        ]));
        s.claim_wire = None;
        s.refresh_epoch_on_retry = true;
    }
    job.decisions.push(recovery.clone());
    Ok(())
}
fn abort_job(
    job: &mut Job,
    recovery: Option<&HostRebindRecoveryRequest>,
    store: &SecureStateStore,
    identity: &KernelIdentity,
    aad: &str,
    owner: &SecureStateStore,
    logical: &[u8],
    inbox: &mut InboxStore,
    engine: &crate::communication_runtime::EngineConfig,
    executor: &tokio::runtime::Runtime,
    boundary: &mut impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    if job
        .scopes
        .iter()
        .any(|s| s.confirmed.is_some() || s.committed)
    {
        return Err(error("HOST_REBIND_COMMITTED_FORWARD_RECOVERY_REQUIRED"));
    }
    if job.aborting.is_none() {
        let journal = open_evidence_journal(engine)?;
        let origin = crate::transport::canonical_lifecycle_origin(
            &engine.origin,
            engine.allow_loopback_http,
        )
        .map_err(|_| error("ORIGIN_INVALID"))?;
        let authority = engine
            .authority
            .clone()
            .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
        for s in &job.scopes {
            for old in &s.rejected {
                match claim_evidence(
                    &journal,
                    identity,
                    &origin,
                    &authority,
                    &old.claim_id,
                    &old.claim_wire,
                )? {
                    ClaimEvidence::Rejected(digest) if digest == old.result_digest => (),
                    _ => return Err(error("HOST_REBIND_ORIGINAL_JOURNAL_INVALID")),
                }
            }
            if let Some(wire) = &s.claim_wire {
                match claim_evidence(&journal, identity, &origin, &authority, &s.claim_id, wire)? {
                    ClaimEvidence::NotSubmitted | ClaimEvidence::Rejected(_) => (),
                    ClaimEvidence::Unknown => return Err(uncertain_claim(&s.claim_id)),
                    ClaimEvidence::Committed => {
                        return Err(error("HOST_REBIND_COMMITTED_FORWARD_RECOVERY_REQUIRED"))
                    }
                }
            }
        }
        let r = recovery.ok_or_else(|| error("HOST_REBIND_ABORT_DECISION_REQUIRED"))?;
        job.aborting = Some(r.decision_id.clone());
        job.decisions.push(r.clone());
        save(store, identity, aad, job)?;
        boundary("ABORT_FROZEN")?;
    }
    let access = access(engine);
    let work = (|| {
        for (index, s) in job.scopes.iter().enumerate() {
            let current = executor.block_on(call(
                &access,
                "structure.mailbox.get",
                &s.old.workspace_id,
                json!({"mailbox_id":s.old.mailbox_id}),
                None,
            ))?;
            let epoch = current["mailbox"]["epoch"]
                .as_u64()
                .filter(|v| *v >= s.expected.epoch)
                .ok_or_else(|| error("HOST_REBIND_VERIFIED_MAILBOX_MISMATCH"))?;
            validate_mailbox(
                &current["mailbox"],
                &s.expected,
                &engine.expected_actor,
                &s.expected.destination_digest,
                epoch,
                s.expected.binding_version,
            )?;
            let mut pins = s.expected.native();
            pins.epoch = epoch;
            inbox.register(&pins)?;
            executor.block_on(call(&access,"structure.mailbox.close",&s.old.workspace_id,json!({"mailbox_id":s.old.mailbox_id,"receiver_id":s.expected.receiver_id,"epoch":epoch}),None))?;
            let claim = token(json!([
                job.pin.operation_id,
                job.aborting,
                index,
                "abort-watch-restart"
            ]));
            inbox.rebind_restore_watch(
                &s.namespace,
                &s.old,
                &s.expected.receiver_id,
                s.was_enabled,
                &claim,
            )?;
            boundary("ABORT_WATCH_RESTORED")?;
        }
        participant_owner::complete(owner, logical, &job.pin)?;
        boundary("ABORT_OWNER_COMPLETED")?;
        job.aborted = true;
        save(store, identity, aad, job)?;
        Ok(result(job))
    })();
    executor.block_on(access.close_session_executor_async());
    work
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
        recovery: if refusal {
            "EXPLICIT_HOST_REBIND_RECOVERY_DECISION_REQUIRED"
        } else {
            "RESUME_SAME_HOST_REBIND_OPERATION"
        }
        .into(),
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
pub(crate) fn recovery_cli(config: &Path, request: &Path, recovery: &Path) -> Result<Value> {
    let load = |path: &Path| {
        private_json(path, 16384).map_err(|_| error("HOST_REBIND_REQUEST_NOT_PRIVATE"))
    };
    let request: HostRebindRequest = serde_json::from_value(load(request)?)
        .map_err(|_| error("HOST_REBIND_SELECTION_INVALID"))?;
    let recovery: HostRebindRecoveryRequest = serde_json::from_value(load(recovery)?)
        .map_err(|_| error("HOST_REBIND_RECOVERY_SELECTION_INVALID"))?;
    rebind_action(config, request, Some(recovery), |_| Ok(()))
}

#[cfg(test)]
#[path = "participant_rebind_tests.rs"]
mod tests;
