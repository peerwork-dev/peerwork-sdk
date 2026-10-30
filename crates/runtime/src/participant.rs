//! Program/Agent participant client. Public async calls never run a nested
//! executor on the caller's thread. One owned engine multiplexes native futures
//! and exact-operation recovery; language and host adapters share this boundary.
#[cfg(test)]
#[path = "participant_http_tests.rs"]
pub(crate) mod http_tests;
pub use crate::participant_migration::MigrationSource;
pub use crate::participant_result::ResultSelection;
pub use crate::participant_watch::{DeliveryReference, WatchOptions, WatchSnapshot};
use crate::{
    kernel_access::{KernelAccess, KernelAccessError, KernelPublicError},
    kernel_identity::KernelIdentity,
    participant_outcome::native_error,
    participant_store::Store,
    secure_state::{create_private_state_directory, SecureStateStore},
    KernelCancellationToken,
};
use peerwork_core::{
    crypto::sha256_hex,
    structure_execution::{self as catalog, StructureOperationKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

pub type Result<T> = std::result::Result<T, ParticipantError>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantError {
    pub code: String,
    pub phase: String,
    pub effect_certainty: String,
    pub recovery: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}
impl ParticipantError {
    pub(crate) fn local(code: &str, phase: &str) -> Self {
        Self {
            code: code.into(),
            phase: phase.into(),
            effect_certainty: "NOT_SUBMITTED".into(),
            recovery: "INSPECT_INPUT_OR_CONFIGURATION".into(),
            operation_id: None,
        }
    }
    fn unavailable() -> Self {
        Self {
            code: "ENGINE_UNAVAILABLE".into(),
            phase: "LOCAL_IPC".into(),
            effect_certainty: "UNKNOWN".into(),
            recovery: "OBSERVE_OR_RECOVER_ORIGINAL_OPERATION".into(),
            operation_id: None,
        }
    }
    fn original(mut self, id: &str) -> Self {
        self.operation_id = Some(id.into());
        self
    }
    fn observation(self, id: &str) -> Self {
        let mut error = self.original(id);
        error.effect_certainty = "UNKNOWN".into();
        error.recovery = "OBSERVE_OR_RECOVER_ORIGINAL_OPERATION".into();
        error
    }
}
impl std::fmt::Display for ParticipantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.code, self.phase)
    }
}
impl std::error::Error for ParticipantError {}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoke {
    pub operation_id: String,
    pub action: String,
    #[serde(default)]
    pub scope: Scope,
    pub body: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_contents: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_workspace_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_instance_revision: Option<u64>,
    #[serde(default)]
    pub exact_input_refs: Vec<Value>,
}
impl Invoke {
    pub fn new(
        id: impl Into<String>,
        action: impl Into<String>,
        scope: Scope,
        body: Value,
    ) -> Self {
        Self {
            operation_id: id.into(),
            action: action.into(),
            scope,
            body,
            plaintext_contents: None,
            plaintext_message: None,
            expected_workspace_revision: None,
            expected_instance_revision: None,
            exact_input_refs: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        let invalid = || ParticipantError::local("REQUEST_INVALID", "VALIDATION");
        if !crate::communication_store::identifier(&self.operation_id)
            || crate::participant_actions::kind(&self.action).is_none()
            || !self.body.is_object()
        {
            return Err(invalid());
        }
        for id in [&self.scope.workspace_id, &self.scope.instance_id]
            .into_iter()
            .flatten()
        {
            if !crate::communication_store::identifier(id) {
                return Err(invalid());
            }
        }
        if self.scope.instance_id.is_some()
            && (self.scope.workspace_id.is_none() || self.scope.protocol_digest.is_none())
        {
            return Err(invalid());
        }
        if self.scope.protocol_digest.as_ref().is_some_and(|v| {
            v.len() != 64
                || !v
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }) {
            return Err(invalid());
        }
        if self.exact_input_refs.len() > 32
            || self.exact_input_refs.iter().any(|v| {
                v.as_object().is_none_or(|o| o.len() != 2)
                    || v["record_id"]
                        .as_str()
                        .is_none_or(|s| !crate::communication_store::identifier(s))
                    || v["revision"]
                        .as_u64()
                        .is_none_or(|n| n == 0 || n > 9_007_199_254_740_991)
            })
        {
            return Err(invalid());
        }
        if [
            self.expected_instance_revision,
            self.expected_workspace_revision,
        ]
        .into_iter()
        .flatten()
        .any(|n| n == 0 || n > 9_007_199_254_740_991)
        {
            return Err(invalid());
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > 500_000 {
            return Err(ParticipantError::local("INPUT_TOO_LARGE", "VALIDATION"));
        }
        crate::participant_actions::validate(self)
    }
    pub(crate) fn wire(&self, namespace: &str, actor: &str, origin: &str, durable: bool) -> Value {
        let mut v = json!({"action":self.action,"workspace_id":self.scope.workspace_id,"instance_id":self.scope.instance_id,"protocol_digest":self.scope.protocol_digest,"body":self.body,"exact_input_refs":self.exact_input_refs});
        if self.action == "structure.mailbox.claim" {
            // The device proof authorizes this exact command, including a
            // refused claim. A different operation cannot reuse it at the same
            // receiver epoch after lease expiry.
            v["command_id"] = self.body["claim_command_id"].clone();
        } else if durable {
            v["idempotency_key"] = json!(format!(
                "participant:{}",
                sha256_hex(
                    json!([actor, origin, namespace, self.operation_id])
                        .to_string()
                        .as_bytes()
                )
            ));
        }
        if let Some(c) = &self.plaintext_contents {
            v["plaintext_contents"] = c.clone();
        }
        if let Some(text) = &self.plaintext_message {
            v["plaintext_message"] = json!(text);
        }
        if let Some(n) = self.expected_workspace_revision {
            v["expected_workspace_revision"] = json!(n);
        }
        if let Some(n) = self.expected_instance_revision {
            v["expected_instance_revision"] = json!(n);
        }
        if catalog::has_body_instance_selector(&self.action) {
            v["instance_id"] = Value::Null;
            v["protocol_digest"] = Value::Null;
            if let Some(instance) = &self.scope.instance_id {
                v["body"]["instance_id"] = json!(instance);
            }
        }
        v
    }
    fn verify_result_scope(&self, value: Value) -> Result<Value> {
        if !matches!(value["state"].as_str(), Some("ACCEPTED" | "COMPLETED")) {
            return Ok(value);
        }
        for (field, expected) in [
            ("workspace_id", &self.scope.workspace_id),
            ("protocol_digest", &self.scope.protocol_digest),
            ("instance_id", &self.scope.instance_id),
        ] {
            let Some(expected) = expected else {
                continue;
            };
            let selected = value["result"][field]
                .as_str()
                .or_else(|| value["result"]["structure"][field].as_str())
                .or_else(|| value["result"]["structure"]["instance"][field].as_str());
            if selected.is_some_and(|actual| actual != expected) {
                return Err(ParticipantError {
                    code: "VERIFIED_SCOPE_MISMATCH".into(),
                    phase: "VERIFICATION".into(),
                    effect_certainty: "UNKNOWN".into(),
                    recovery: "INSPECT_PINNED_SCOPE".into(),
                    operation_id: Some(self.operation_id.clone()),
                });
            }
            if field == "protocol_digest"
                && catalog::has_body_instance_selector(&self.action)
                && selected.is_none()
            {
                return Err(ParticipantError::local(
                    "VERIFIED_SCOPE_MISSING",
                    "VERIFICATION",
                ));
            }
        }
        Ok(value)
    }
}

/// None means all; Some(empty set) means none. This is local caller authority,
/// intersected with current backend membership/grants on every service action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub operations: BTreeSet<String>,
    pub allow_root: bool,
    pub workspace_ids: Option<BTreeSet<String>>,
    pub instance_ids: Option<BTreeSet<String>>,
    pub protocol_digests: Option<BTreeSet<String>>,
    pub business_actions: Option<BTreeSet<String>>,
    #[serde(default)]
    pub mailbox_ids: Option<BTreeSet<String>>,
}
impl Capability {
    pub fn owner() -> Self {
        Self {
            operations: catalog::STRUCTURE_MUTATIONS
                .iter()
                .chain(catalog::STRUCTURE_READS)
                .chain(catalog::STRUCTURE_CONTROLS)
                .chain(crate::participant_actions::HELPERS)
                .map(|v| v.to_string())
                .collect(),
            allow_root: true,
            workspace_ids: None,
            instance_ids: None,
            protocol_digests: None,
            business_actions: None,
            mailbox_ids: None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.operations.is_empty()
            || self
                .operations
                .iter()
                .any(|v| crate::participant_actions::kind(v).is_none())
        {
            return Err(ParticipantError::local(
                "CAPABILITY_INVALID",
                "AUTHORIZATION",
            ));
        }
        Ok(())
    }
    pub fn authorize(&self, r: &Invoke) -> Result<()> {
        r.validate()?;
        let denied = || ParticipantError::local("LOCAL_SCOPE_DENIED", "AUTHORIZATION");
        if !self.operations.contains(&r.action) {
            return Err(denied());
        }
        let communication = catalog::is_communication_action(&r.action);
        if communication {
            self.authorize_communication(r)?;
        }
        if !communication
            && (self.instance_ids.is_some() || self.protocol_digests.is_some())
            && !crate::participant_actions::instance_scoped(&r.action)
        {
            return Err(denied());
        }
        match &r.scope.workspace_id {
            None if !self.allow_root => return Err(denied()),
            Some(id) if !allows(&self.workspace_ids, id) => return Err(denied()),
            _ => {}
        }
        if let Some(id) = &r.scope.instance_id {
            if !allows(&self.instance_ids, id) {
                return Err(denied());
            }
        } else if self.instance_ids.is_some() && !communication {
            return Err(denied());
        }
        if let Some(id) = &r.scope.protocol_digest {
            if !allows(&self.protocol_digests, id) {
                return Err(denied());
            }
        } else if self.protocol_digests.is_some() && !communication {
            return Err(denied());
        }
        if r.action == "structure.action"
            && self
                .business_actions
                .as_ref()
                .is_some_and(|a| r.body["action_id"].as_str().is_none_or(|v| !a.contains(v)))
        {
            return Err(denied());
        }
        if catalog::has_body_instance_selector(&r.action) {
            if let Some(instance) = &r.scope.instance_id {
                if r.body.get("package_digest").is_some()
                    || r.body
                        .get("instance_id")
                        .is_some_and(|v| v.as_str() != Some(instance))
                {
                    return Err(denied());
                }
            }
        }
        Ok(())
    }
    fn authorize_communication(&self, r: &Invoke) -> Result<()> {
        let denied = || ParticipantError::local("LOCAL_SCOPE_DENIED", "AUTHORIZATION");
        let mailbox = |v: &Value| -> Result<()> {
            let id = v
                .as_str()
                .filter(|v| crate::communication_store::identifier(v))
                .ok_or_else(denied)?;
            if allows(&self.mailbox_ids, id) {
                Ok(())
            } else {
                Err(denied())
            }
        };
        let instance = |v: &Value| -> Result<()> {
            let id = v["instance_id"].as_str().ok_or_else(denied)?;
            let protocol = v["protocol_digest"].as_str().ok_or_else(denied)?;
            if !allows(&self.instance_ids, id) || !allows(&self.protocol_digests, protocol) {
                return Err(denied());
            }
            Ok(())
        };
        // Communication is independent of business instances. A client with a
        // business boundary must separately pin its communication mailboxes.
        if (self.instance_ids.is_some() || self.protocol_digests.is_some())
            && self.mailbox_ids.is_none()
        {
            return Err(denied());
        }
        if r.action == "structure.communication.stream.get" {
            let scopes = r.body["scopes"]
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 8)
                .ok_or_else(denied)?;
            for scope in scopes {
                let ws = scope["workspace_id"].as_str().ok_or_else(denied)?;
                if !allows(&self.workspace_ids, ws) {
                    return Err(denied());
                }
                mailbox(&scope["mailbox_id"])?;
            }
        } else if r.action == "structure.message.send" {
            let targets = r.body["recipients"]
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 8)
                .ok_or_else(denied)?;
            for target in targets {
                mailbox(&target["mailbox_id"])?;
            }
            if !r.body["reply_address"].is_null() {
                mailbox(&r.body["reply_address"]["mailbox_id"])?;
            }
            if r.body["content"]["mode"] == "SOURCE" {
                instance(&r.body["content"])?;
            }
        } else if r.action == "structure.communication.subscription.set" {
            mailbox(&r.body["mailbox_id"])?;
            instance(&r.body)?;
        } else if self.mailbox_ids.is_some()
            && [
                "structure.mailboxes.read",
                "structure.mailbox.create",
                "structure.communication.grant.set",
                "structure.communication.grant.get",
                "structure.communication.subscriptions.read",
                "structure.message.get",
                "structure.message.withdraw",
                "structure.message.receipts.read",
            ]
            .contains(&r.action.as_str())
        {
            // These selectors do not establish a mailbox boundary. A future
            // handle convenience may narrow them; adding an ignored field cannot.
            return Err(denied());
        } else if r.action.starts_with("structure.mailbox.")
            && r.action != "structure.mailbox.create"
        {
            mailbox(&r.body["mailbox_id"])?;
        } else if r.action == "structure.communication.subscriptions.read" {
            instance(&r.body)?;
        }
        Ok(())
    }
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.operations.is_subset(&parent.operations)
            && (!self.allow_root || parent.allow_root)
            && subset(&self.workspace_ids, &parent.workspace_ids)
            && subset(&self.instance_ids, &parent.instance_ids)
            && subset(&self.protocol_digests, &parent.protocol_digests)
            && subset(&self.business_actions, &parent.business_actions)
            && subset(&self.mailbox_ids, &parent.mailbox_ids)
    }
}
fn allows(set: &Option<BTreeSet<String>>, id: &str) -> bool {
    set.as_ref().is_none_or(|s| s.contains(id))
}
fn subset(child: &Option<BTreeSet<String>>, parent: &Option<BTreeSet<String>>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (Some(a), Some(b)) => a.is_subset(b),
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct ParticipantConfig {
    pub origin: String,
    pub expected_actor: String,
    pub authority: Option<String>,
    pub identity_path: PathBuf,
    pub state_directory: PathBuf,
    pub journal_path: PathBuf,
    pub allow_loopback_http: bool,
    pub transport: crate::transport::TransportOptions,
    pub max_inflight: usize,
    pub max_pending: usize,
    pub max_stored_bytes: usize,
    pub migration_sources: Vec<MigrationSource>,
}
impl ParticipantConfig {
    pub fn new(
        origin: impl Into<String>,
        expected_actor: impl Into<String>,
        identity_path: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
    ) -> Self {
        let state_directory = state_directory.into();
        Self {
            origin: origin.into(),
            expected_actor: expected_actor.into(),
            authority: None,
            identity_path: identity_path.into(),
            journal_path: state_directory.join("kernel.sqlite"),
            state_directory,
            allow_loopback_http: false,
            transport: Default::default(),
            max_inflight: 4,
            max_pending: 64,
            max_stored_bytes: 32 * 1024 * 1024,
            migration_sources: Vec::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub operation_id: String,
    pub state: String,
    pub command_id: Option<String>,
    pub effect_certainty: String,
    pub outcome: Option<Value>,
    pub observation: String,
}
impl Operation {
    pub fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "ACCEPTED" | "REJECTED_NO_EFFECT")
    }
}
struct Admission {
    operation: Operation,
    completed: oneshot::Receiver<Operation>,
}
struct ReplyContext {
    namespace: String,
    capability: Capability,
}
enum Command {
    Watch {
        context: ReplyContext,
        request: crate::participant_watch::Command,
    },
    Invoke {
        context: ReplyContext,
        request: Invoke,
        reply: oneshot::Sender<Result<Admission>>,
    },
    Request {
        context: ReplyContext,
        request: Invoke,
        reply: oneshot::Sender<Result<Value>>,
    },
    Get {
        context: ReplyContext,
        id: String,
        recover: bool,
        reply: oneshot::Sender<Result<Operation>>,
    },
    List {
        context: ReplyContext,
        after: String,
        limit: usize,
        reply: oneshot::Sender<Result<Value>>,
    },
    Result {
        context: ReplyContext,
        id: String,
        selection: ResultSelection,
        reply: oneshot::Sender<Result<Value>>,
    },
    Metrics {
        reply: oneshot::Sender<Value>,
    },
}
struct Shared {
    sender: mpsc::Sender<Command>,
    cancel: KernelCancellationToken,
    thread: Mutex<Option<JoinHandle<()>>>,
    actor: String,
    origin: String,
}
impl Drop for Shared {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
#[derive(Clone)]
pub struct ParticipantClient {
    shared: Arc<Shared>,
    namespace: String,
    capability: Capability,
}
impl ParticipantClient {
    /// Opens protected local state without requiring a network connection.
    /// Discovery is verified before the engine makes any signed service call.
    pub async fn open(config: ParticipantConfig) -> Result<Self> {
        crate::participant_migration::validate_sources(&config.migration_sources)?;
        if config
            .authority
            .as_deref()
            .is_some_and(|s| !crate::participant_migration::digest(s))
        {
            return Err(ParticipantError::local("AUTHORITY_INVALID", "OPEN"));
        }
        if !config.identity_path.is_absolute()
            || !config.state_directory.is_absolute()
            || !config.journal_path.is_absolute()
            || config.max_inflight == 0
            || config.max_inflight > 32
            || config.max_pending == 0
            || config.max_pending > 1024
            || config.max_stored_bytes < 2 * crate::participant_store::OUTCOME_RESERVE
            || config.max_stored_bytes > 48 * 1024 * 1024
        {
            return Err(ParticipantError::local("CONFIG_INVALID", "OPEN"));
        }
        let (tx, rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let cancel = KernelCancellationToken::new();
        let stop = cancel.clone();
        let thread = std::thread::Builder::new()
            .name("peerwork-participant".into())
            .spawn(move || {
                let setup = (|| -> Result<_> {
                    let identity = KernelIdentity::open(&config.identity_path)
                        .map_err(|_| ParticipantError::local("IDENTITY_STATE_INVALID", "OPEN"))?;
                    if identity.actor_id() != config.expected_actor {
                        return Err(ParticipantError::local("IDENTITY_MISMATCH", "OPEN"));
                    }
                    create_private_state_directory(&config.state_directory)
                        .map_err(|_| ParticipantError::local("STATE_NOT_PRIVATE", "OPEN"))?;
                    let owner =
                        SecureStateStore::open(&config.state_directory.join("engine-owner.state"))
                            .map_err(|_| ParticipantError::local("STATE_ALREADY_OWNED", "OPEN"))?;
                    crate::participant_transfer::check_open(&config.state_directory)?;
                    let journal_owner = SecureStateStore::open(
                        &config
                            .journal_path
                            .with_extension("participant-owner.state"),
                    )
                    .map_err(|_| ParticipantError::local("JOURNAL_ALREADY_OWNED", "OPEN"))?;
                    let origin = crate::transport::canonical_lifecycle_origin(
                        &config.origin,
                        config.allow_loopback_http,
                    )
                    .map_err(|_| ParticipantError::local("ORIGIN_INVALID", "OPEN"))?;
                    let authority=config.authority.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
                    let binding=json!({"format":"peerwork.participant-owner.v1","actor":identity.actor_id(),"key":identity.key_id(),"origin":origin,"authority":authority}).to_string();
                    match owner.read_exact().map_err(|_|ParticipantError::local("STATE_BINDING_INVALID","OPEN"))?{
                        Some(saved) if saved!=binding.as_bytes()=>return Err(ParticipantError::local("STATE_BINDING_MISMATCH","OPEN")),
                        Some(_)=>(),
                        None=>{
                            // Earlier candidate indexes used only the default
                            // authority. They cannot be silently rebound.
                            if config.authority.as_ref().is_some_and(|a|a!=&sha256_hex(identity.actor_id().as_bytes()))&&config.state_directory.join("participant.sqlite").is_file(){
                                return Err(ParticipantError::local("STATE_AUTHORITY_UNPINNED","OPEN"));
                            }
                            owner.write_exact(binding.as_bytes()).map_err(|_|ParticipantError::local("STATE_BINDING_FAILED","OPEN"))?;
                        }
                    }
                    let store = Store::open(&config.state_directory, &identity, &origin)?;
                    store.reset_running()?;
                    let inbox = crate::participant_inbox::InboxStore::open_local(
                        &config.state_directory,
                        &identity,
                        &origin,
                    )?;
                    let access = KernelAccess::new(
                        &origin,
                        &config.journal_path,
                        &config.identity_path,
                        &[],
                        config.allow_loopback_http,
                    )
                    .with_authority(config.authority.clone())
                    .with_transport_options(config.transport.clone())
                    .with_persistent_session();
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ParticipantError::local("EXECUTOR_FAILED", "OPEN"))?;
                    Ok((
                        identity,
                        origin,
                        store,
                        inbox,
                        access,
                        runtime,
                        owner,
                        journal_owner,
                    ))
                })();
                let (identity, origin, store, inbox, access, runtime, _owner, _journal_owner) =
                    match setup {
                        Ok(v) => v,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                let _ = ready_tx.send(Ok((identity.actor_id().to_owned(), origin.clone())));
                let local = tokio::task::LocalSet::new();
                local.block_on(
                    &runtime,
                    engine_loop(config, identity, origin, store, inbox, access, rx, stop),
                );
            })
            .map_err(|_| ParticipantError::local("EXECUTOR_FAILED", "OPEN"))?;
        let (actor, origin) = match ready_rx.await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(e);
            }
            Err(_) => return Err(ParticipantError::unavailable()),
        };
        Ok(Self {
            shared: Arc::new(Shared {
                sender: tx,
                cancel,
                thread: Mutex::new(Some(thread)),
                actor,
                origin,
            }),
            namespace: "program".into(),
            capability: Capability::owner(),
        })
    }
    pub fn actor_id(&self) -> &str {
        &self.shared.actor
    }
    pub fn origin(&self) -> &str {
        &self.shared.origin
    }
    pub fn capability(&self) -> &Capability {
        &self.capability
    }
    /// An Agent or program session can only narrow its parent's authority.
    pub fn restrict(&self, name: &str, capability: Capability) -> Result<Self> {
        capability.validate()?;
        if !crate::communication_store::identifier(name)
            || !capability.is_subset_of(&self.capability)
        {
            return Err(ParticipantError::local(
                "CAPABILITY_ESCALATION",
                "AUTHORIZATION",
            ));
        }
        let namespace = format!("{}:{name}", self.namespace);
        if namespace.len() > 256 {
            return Err(ParticipantError::local("SESSION_INVALID", "AUTHORIZATION"));
        }
        Ok(Self {
            shared: self.shared.clone(),
            namespace,
            capability,
        })
    }
    fn context(&self) -> ReplyContext {
        ReplyContext {
            namespace: self.namespace.clone(),
            capability: self.capability.clone(),
        }
    }
    fn send(&self, command: Command) -> Result<()> {
        self.shared.sender.try_send(command).map_err(|e| {
            if matches!(e, mpsc::error::TrySendError::Full(_)) {
                ParticipantError::local("NOT_ADMITTED_BUSY", "ADMISSION")
            } else {
                ParticipantError::unavailable()
            }
        })
    }
    /// The wait budget covers service acceptance, never a model reply. Once
    /// admitted, dropping this future does not cancel the durable operation.
    pub async fn invoke(&self, request: Invoke, wait_budget: Duration) -> Result<Operation> {
        self.capability.authorize(&request)?;
        if crate::participant_actions::kind(&request.action)
            != Some(StructureOperationKind::Mutation)
        {
            return Err(ParticipantError::local(
                "USE_REQUEST_FOR_READ_OR_CONTROL",
                "VALIDATION",
            ));
        }
        let id = request.operation_id.clone();
        let (tx, rx) = oneshot::channel();
        self.send(Command::Invoke {
            context: self.context(),
            request,
            reply: tx,
        })
        .map_err(|error| error.original(&id))?;
        let admitted = rx
            .await
            .map_err(|_| ParticipantError::unavailable().original(&id))?
            .map_err(|error| error.original(&id))?;
        if admitted.operation.is_terminal() || wait_budget.is_zero() {
            return Ok(admitted.operation);
        }
        match tokio::time::timeout(wait_budget.min(Duration::from_secs(30)), admitted.completed)
            .await
        {
            Ok(Ok(done)) => Ok(done),
            _ => self.operation(&id).await.map_err(|mut error| {
                if admitted.operation.effect_certainty == "COMMITTED" {
                    error.effect_certainty = "COMMITTED".into();
                }
                error
            }),
        }
    }
    pub async fn request(&self, request: Invoke) -> Result<Value> {
        self.capability.authorize(&request)?;
        if crate::participant_actions::kind(&request.action)
            == Some(StructureOperationKind::Mutation)
        {
            return Err(ParticipantError::local(
                "USE_INVOKE_FOR_MUTATION",
                "VALIDATION",
            ));
        }
        let (tx, rx) = oneshot::channel();
        self.send(Command::Request {
            context: self.context(),
            request,
            reply: tx,
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    pub async fn operation(&self, id: &str) -> Result<Operation> {
        self.get(id, false).await
    }
    pub async fn recover(&self, id: &str) -> Result<Operation> {
        self.get(id, true).await
    }
    async fn get(&self, id: &str, recover: bool) -> Result<Operation> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Get {
            context: self.context(),
            id: id.into(),
            recover,
            reply: tx,
        })
        .map_err(|error| error.observation(id))?;
        rx.await
            .map_err(|_| ParticipantError::unavailable().observation(id))?
            .map_err(|error| error.observation(id))
    }
    pub async fn operations(&self, after: &str, limit: usize) -> Result<Value> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::List {
            context: self.context(),
            after: after.into(),
            limit,
            reply: tx,
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    /// Select one result by original operation ID. Chunks are bounded to 64KiB
    /// and continuation hashes detect changed local body-opening projections.
    /// This never submits or reconciles a remote operation.
    pub async fn operation_result(&self, id: &str, selection: ResultSelection) -> Result<Value> {
        selection.validate().map_err(|e| e.observation(id))?;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Result {
            context: self.context(),
            id: id.into(),
            selection,
            reply: tx,
        })
        .map_err(|e| e.observation(id))?;
        rx.await
            .map_err(|_| ParticipantError::unavailable().observation(id))?
            .map_err(|e| {
                if e.operation_id.is_none() {
                    e.observation(id)
                } else {
                    e
                }
            })
    }
    /// Configure a durable mailbox consumer. The returned handle coalesces
    /// notifications; each next() reads a bounded, verified local snapshot.
    /// Dropping a handle does not cancel persisted reception or ACK recovery.
    pub async fn watch(&self, options: WatchOptions) -> Result<ProgramWatch> {
        options.authorize(&self.capability)?;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Watch {
            context: self.context(),
            request: crate::participant_watch::Command::Attach {
                namespace: self.namespace.clone(),
                options: options.clone(),
                reply: tx,
            },
        })?;
        let signals = rx.await.map_err(|_| ParticipantError::unavailable())??;
        Ok(ProgramWatch {
            client: self.clone(),
            options,
            signals,
        })
    }
    pub async fn unwatch(&self, options: &WatchOptions) -> Result<()> {
        options.authorize(&self.capability)?;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Watch {
            context: self.context(),
            request: crate::participant_watch::Command::Stop {
                namespace: self.namespace.clone(),
                options: options.clone(),
                reply: tx,
            },
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    // Connector-only boundary. Local client credentials cannot manufacture
    // host evidence through the public JSONL/MCP operation catalog.
    pub(crate) async fn host_operation(
        &self,
        options: &WatchOptions,
        operation: crate::participant_inbox::HostOperation,
    ) -> Result<crate::participant_inbox::HostReply> {
        options.authorize(&self.capability)?;
        let (tx, rx) = oneshot::channel();
        self.send(Command::Watch {
            context: self.context(),
            request: crate::participant_watch::Command::Host {
                namespace: self.namespace.clone(),
                options: options.clone(),
                operation,
                reply: tx,
            },
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    /// Selected receiver-attested host facts, independent of remote acceptance
    /// and application consumption. This never invokes or retries a host call.
    pub async fn delivery_status(
        &self,
        options: &WatchOptions,
        item: DeliveryReference,
    ) -> Result<Value> {
        match self
            .host_operation(
                options,
                crate::participant_inbox::HostOperation::Status { item },
            )
            .await?
        {
            crate::participant_inbox::HostReply::Status(value) => Ok(value),
            _ => Err(ParticipantError::local(
                "HOST_STATE_INVALID",
                "HOST_OBSERVATION",
            )),
        }
    }
    /// Bounded local configured scopes owned by this exact client namespace.
    /// This does not claim a mailbox or grant access to another profile.
    pub async fn watch_bindings(&self) -> Result<Vec<WatchOptions>> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Watch {
            context: self.context(),
            request: crate::participant_watch::Command::Bindings {
                namespace: self.namespace.clone(),
                capability: self.capability.clone(),
                reply: tx,
            },
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    pub async fn inbox(
        &self,
        options: &WatchOptions,
        after: u64,
        limit: usize,
    ) -> Result<WatchSnapshot> {
        options.authorize(&self.capability)?;
        if !(1..=32).contains(&limit) || after > 9_007_199_254_740_991 {
            return Err(ParticipantError::local(
                "INBOX_SELECTION_INVALID",
                "VALIDATION",
            ));
        }
        let (tx, rx) = oneshot::channel();
        self.send(Command::Watch {
            context: self.context(),
            request: crate::participant_watch::Command::Snapshot {
                namespace: self.namespace.clone(),
                options: options.clone(),
                after,
                limit,
                reply: tx,
            },
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    /// Record application consumption locally. Fenced remote ACK upload is
    /// automatic and independent; this is not a business/model completion claim.
    pub async fn consume(
        &self,
        options: &WatchOptions,
        items: Vec<DeliveryReference>,
    ) -> Result<()> {
        options.authorize(&self.capability)?;
        if items.is_empty()
            || items.len() > 32
            || items.iter().any(|r| {
                r.sequence == 0
                    || r.sequence > 9_007_199_254_740_991
                    || !crate::communication_store::identifier(&r.delivery_id)
            })
        {
            return Err(ParticipantError::local(
                "INBOX_SELECTION_INVALID",
                "VALIDATION",
            ));
        }
        let (tx, rx) = oneshot::channel();
        self.send(Command::Watch {
            context: self.context(),
            request: crate::participant_watch::Command::Consume {
                namespace: self.namespace.clone(),
                options: options.clone(),
                items,
                reply: tx,
            },
        })?;
        rx.await.map_err(|_| ParticipantError::unavailable())?
    }
    pub async fn metrics(&self) -> Result<Value> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Metrics { reply: tx })?;
        rx.await.map_err(|_| ParticipantError::unavailable())
    }
    /// Only the owner client controls engine lifetime; restricted sessions do
    /// not receive a shutdown method through runtime/MCP projections.
    pub async fn close(&self) -> Result<()> {
        if self.namespace != "program" {
            return Err(ParticipantError::local("ADMIN_REQUIRED", "AUTHORIZATION"));
        }
        self.shared.cancel.cancel();
        let thread = self
            .shared
            .thread
            .lock()
            .map_err(|_| ParticipantError::unavailable())?
            .take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(|_| ParticipantError::unavailable())?
                .map_err(|_| ParticipantError::unavailable())?;
        }
        Ok(())
    }
}

/// A notification handle is lightweight; the engine, not this application
/// future, owns connection lifetime and durable custody.
pub struct ProgramWatch {
    client: ParticipantClient,
    options: WatchOptions,
    signals: mpsc::Receiver<()>,
}
impl ProgramWatch {
    pub fn options(&self) -> &WatchOptions {
        &self.options
    }
    pub(crate) async fn changed(&mut self) -> Result<()> {
        self.signals
            .recv()
            .await
            .ok_or_else(ParticipantError::unavailable)
    }
    pub async fn next(&mut self) -> Result<WatchSnapshot> {
        self.changed().await?;
        self.client.inbox(&self.options, 0, 32).await
    }
    pub async fn stop(&self) -> Result<()> {
        self.client.unwatch(&self.options).await
    }
    pub async fn page(&self, after: u64, limit: usize) -> Result<WatchSnapshot> {
        self.client.inbox(&self.options, after, limit).await
    }
    pub async fn consume(&self, items: Vec<DeliveryReference>) -> Result<()> {
        self.client.consume(&self.options, items).await
    }
}

#[derive(Clone)]
enum JobKind {
    Mutation((String, String)),
    Request,
    Refresh,
}
enum JobResult {
    Mutation(Value),
    Request,
    Refresh,
}

async fn engine_loop(
    config: ParticipantConfig,
    identity: KernelIdentity,
    origin: String,
    mut store: Store,
    inbox: crate::participant_inbox::InboxStore,
    access: KernelAccess,
    mut receiver: mpsc::Receiver<Command>,
    cancel: KernelCancellationToken,
) {
    let access = Arc::new(access);
    let sources = Arc::new(config.migration_sources.clone());
    let identity = Arc::new(identity);
    let (watch_tx, watch_rx) = mpsc::channel(32);
    let watch_task = tokio::task::spawn_local(crate::participant_watch::run(
        inbox,
        identity.clone(),
        origin.clone(),
        access.clone(),
        watch_rx,
        cancel.clone(),
    ));
    let result_cache = Arc::new(Mutex::new(crate::participant_result::ResultCache::default()));
    let mut jobs: tokio::task::JoinSet<JobResult> = tokio::task::JoinSet::new();
    let mut active: BTreeSet<(String, String)> = BTreeSet::new();
    let mut job_kinds: HashMap<tokio::task::Id, JobKind> = HashMap::new();
    let mut waiters: BTreeMap<(String, String), Vec<oneshot::Sender<Operation>>> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut refresh = tokio::time::interval(Duration::from_secs(40));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut refresh_running = false;
    let mut maintenance: BTreeSet<(String, String)> = BTreeSet::new();
    // A verified result awaiting local persistence still occupies a worker
    // slot. Storage failure must not grow memory or cause another submission.
    let mut retry_persistence: BTreeMap<(String, String), Value> = BTreeMap::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            completed=jobs.join_next_with_id(),if !jobs.is_empty()=>{
                if let Some(completed)=completed{
                    let (id,result)=match completed{Ok((id,result))=>(id,Some(result)),Err(error)=>(error.id(),None)};
                    match job_kinds.remove(&id){
                        Some(JobKind::Refresh)=>refresh_running=false,
                        Some(JobKind::Mutation(key))=>{
                            let value=match result{Some(JobResult::Mutation(value))=>value,_=>json!({"state":"FAILED","code":"ENGINE_TASK_FAILED","retryable":false,"effect_certainty":"UNKNOWN","recovery":"OBSERVE_OR_RECOVER_ORIGINAL_OPERATION"})};
                            retry_persistence.insert(key,value);
                        },
                        _=>{},
                    }
                }
            },
            command=receiver.recv()=>match command{
                None=>break,
                Some(Command::Watch{context,request})=>{
                    // The driver is an internal owner task, not another SDK
                    // client with authority to select arbitrary local profiles.
                    let authorized=match &request{
                        crate::participant_watch::Command::Bindings{..}=>Ok(()),
                        crate::participant_watch::Command::Attach{options,..}|crate::participant_watch::Command::Snapshot{options,..}|crate::participant_watch::Command::Consume{options,..}|crate::participant_watch::Command::Stop{options,..}|crate::participant_watch::Command::Host{options,..}=>options.authorize(&context.capability),
                    };
                    if let Err(e)=authorized{crate::participant_watch::reject(request,e);}
                    else if let Err(e)=watch_tx.try_send(request){crate::participant_watch::reject(e.into_inner(),ParticipantError::local("WATCH_QUEUE_FULL","ADMISSION"));}
                },
                Some(Command::Invoke{context,request,reply})=>{
                    let result=(||{
                        context.capability.authorize(&request)?;
                        if crate::participant_actions::kind(&request.action)!=Some(StructureOperationKind::Mutation){return Err(ParticipantError::local("MUTATION_REQUIRED","VALIDATION"));}
                        let existing=if request.action=="participant.archive.migrate"{store.existing(&context.namespace,&request,&identity)?}else{None};
                        if request.action=="participant.archive.migrate"&&existing.is_none(){
                            if let crate::participant_actions::Selection::Migrate{workspace,source_id,name}=crate::participant_actions::selection(&request,"validation")?{
                                crate::participant_migration::resolve(&sources,&workspace,&source_id,"validation",name)?;
                            }
                        }
                        let reserving=access.phase(crate::transport::ClientPhase::AdmissionReserve);
                        let op=match existing{Some(op)=>op,None=>store.reserve(&context.namespace,&request,&identity,config.max_pending,config.max_stored_bytes)?};
                        drop(reserving);
                        let (done_tx,done_rx)=oneshot::channel();
                        if op.is_terminal(){let _=done_tx.send(op.clone());}
                        else{let list=waiters.entry((context.namespace,request.operation_id)).or_default();list.retain(|w|!w.is_closed());if list.len()<16{list.push(done_tx);}}
                        Ok(Admission{operation:op,completed:done_rx})
                    })();let _=reply.send(result);
                },
                Some(Command::Get{context,id,recover,reply})=>{
                    let result=(||{let r=store.request(&context.namespace,&id,&identity)?;context.capability.authorize(&r)?;if recover&&!active.contains(&(context.namespace.clone(),id.clone())){store.recover(&context.namespace,&id)?;}store.get(&context.namespace,&id,&identity)})();let _=reply.send(result);
                },
                Some(Command::List{context,after,limit,reply})=>{let _=reply.send(store.list(&context.namespace,&context.capability,&identity,&after,limit));},
                Some(Command::Result{context,id,selection,reply})=>{
                    let selected=(||{selection.validate()?;let request=store.request(&context.namespace,&id,&identity)?;context.capability.authorize(&request)?;let op=store.get(&context.namespace,&id,&identity)?;Ok((request,op))})();
                    let (request,op)=match selected{Ok(v)=>v,Err(e)=>{let _=reply.send(Err(e));continue;}};
                    if jobs.len()-usize::from(refresh_running)+retry_persistence.len()>=config.max_inflight{let mut e=ParticipantError::local("NOT_ADMITTED_BUSY","ADMISSION").original(&id);e.effect_certainty=op.effect_certainty;let _=reply.send(Err(e));continue;}
                    let access=access.clone();let stop=cancel.clone();let cache=result_cache.clone();
                    let handle=jobs.spawn_local(async move{
                        let original=id.clone();let certainty=op.effect_certainty.clone();
                        // Receipt re-verification/JSON selection of one large result
                        // must not stall the SSE/lease owner. This worker remains
                        // inside the counted job until it has actually finished.
                        let result=tokio::task::spawn_blocking(move||{
                            let cached=cache.lock().map_err(|_|ParticipantError::local("RESULT_CACHE_FAILED","OBSERVATION"))?.get(&context.namespace,&id,&selection);
                            if let Some(data)=cached{return selection.chunk(&id,&op.effect_certainty,&data);}
                            let value=op.outcome.as_ref().ok_or_else(||ParticipantError::local("RESULT_NOT_AVAILABLE","OBSERVATION"))?;
                            let prepared=if value["detail_source"]=="VERIFIED_NATIVE_JOURNAL"{
                                let command=op.command_id.as_deref().ok_or_else(||ParticipantError::local("RESULT_NOT_AVAILABLE","OBSERVATION"))?;
                                let result=access.cached_participant_result(command,&stop).map_err(|e|ParticipantError{code:KernelPublicError::from(e).code.into(),phase:"RESULT_VERIFICATION".into(),effect_certainty:op.effect_certainty.clone(),recovery:"INSPECT_ORIGINAL_OPERATION".into(),operation_id:Some(id.clone())})?
                                    .ok_or_else(||ParticipantError::local("RESULT_NOT_AVAILABLE","OBSERVATION"))?;
                                let verified=request.verify_result_scope(crate::participant_outcome::accepted(result))?;
                                selection.prepare("VERIFIED_NATIVE_COMMAND_RESULT",&verified)?
                            }else{selection.prepare("LOCAL_DURABLE_OUTCOME",value)?};
                            cache.lock().map_err(|_|ParticipantError::local("RESULT_CACHE_FAILED","OBSERVATION"))?.insert(context.namespace,id.clone(),selection.pointer.clone(),prepared.clone());
                            selection.chunk(&id,&op.effect_certainty,&prepared)
                        }).await.unwrap_or_else(|_|Err(ParticipantError::local("RESULT_TASK_FAILED","OBSERVATION")))
                            .map_err(|mut e|{e.operation_id=Some(original);e.effect_certainty=certainty;e});
                        let _=reply.send(result);JobResult::Request
                    });job_kinds.insert(handle.id(),JobKind::Request);
                },
                Some(Command::Request{context,request,reply})=>{
                    if jobs.len()-usize::from(refresh_running)+retry_persistence.len()>=config.max_inflight{let _=reply.send(Err(ParticipantError::local("NOT_ADMITTED_BUSY","ADMISSION")));continue;}
                    if let Err(e)=context.capability.authorize(&request){let _=reply.send(Err(e));continue;}
                    let access=access.clone();let stop=cancel.clone();let namespace=context.namespace;let actor=identity.actor_id().to_owned();let request_origin=origin.clone();let sources=sources.clone();
                    let handle=jobs.spawn_local(async move{
                        let r=access.execute_participant_async(&request,&namespace,&actor,&request_origin,false,&stop,&sources).await.map_err(|e|{
                            let e=KernelPublicError::from(e);ParticipantError{code:e.code.into(),phase:"REQUEST".into(),effect_certainty:"UNKNOWN".into(),recovery:"REPEAT_SELECTED_READ_OR_CONTROL".into(),operation_id:Some(request.operation_id.clone())}
                        }).and_then(|value|request.verify_result_scope(value));let _=reply.send(r);JobResult::Request
                    });
                    job_kinds.insert(handle.id(),JobKind::Request);
                },
                Some(Command::Metrics{reply})=>{let _=reply.send(json!({"actor_id":identity.actor_id(),"origin":origin,"active_operations":active.len(),"active_tasks":jobs.len(),"max_inflight":config.max_inflight,"background_tasks":usize::from(refresh_running),"watch_driver_owned":!watch_task.is_finished(),"pending_local_persistence":retry_persistence.len(),"http":access.session_metrics(),"result_cache":result_cache.lock().ok().map(|c|c.metrics())}));},
            },
            _=refresh.tick(),if !refresh_running=>{
                let access=access.clone();let stop=cancel.clone();refresh_running=true;
                let handle=jobs.spawn_local(async move{let _=access.refresh_session_async(&stop).await;JobResult::Refresh});
                job_kinds.insert(handle.id(),JobKind::Refresh);
            },
            _=tick.tick()=>{},
        }
        retry_persistence.retain(|key, value| {
            let _phase = access.phase(crate::transport::ClientPhase::CompletionStore);
            match store.finish(&key.0, &key.1, &identity, value) {
                Ok(op) => {
                    active.remove(key);
                    maintenance.remove(key);
                    if let Some(list) = waiters.remove(key) {
                        for waiter in list {
                            let _ = waiter.send(op.clone());
                        }
                    }
                    false
                }
                Err(_) => true,
            }
        });
        while jobs.len() - usize::from(refresh_running) + retry_persistence.len()
            < config.max_inflight
        {
            let due = match store.due(config.max_pending) {
                Ok(v) => v,
                Err(_) => break,
            };
            let Some((key, request)) = due.into_iter().find_map(|key| {
                if active.contains(&key) { return None; }
                let request = store.request(&key.0, &key.1, &identity).ok()?;
                if crate::participant_actions::maintenance(&request.action) && !maintenance.is_empty() {
                    return None;
                }
                Some((key, request))
            }) else {
                break;
            };
            let running = access.phase(crate::transport::ClientPhase::RunningStore);
            if store.running(&key.0, &key.1).is_err() {
                break;
            }
            drop(running);
            active.insert(key.clone());
            if crate::participant_actions::maintenance(&request.action) {
                maintenance.insert(key.clone());
            }
            let access = access.clone();
            let stop = cancel.clone();
            let identity = identity.clone();
            let origin = origin.clone();
            let job_key = key.clone();
            let sources = sources.clone();
            let handle = jobs.spawn_local(async move {
                let result = if request.action == "participant.archive.migrate" {
                    tokio::task::spawn_blocking(move || {
                        access.execute_participant_migration(
                            &request,
                            &key.0,
                            identity.actor_id(),
                            &origin,
                            &stop,
                            &sources,
                        )
                    })
                    .await
                    .unwrap_or(Err(KernelAccessError::Runtime))
                } else {
                    access
                        .execute_participant_async(
                            &request,
                            &key.0,
                            identity.actor_id(),
                            &origin,
                            true,
                            &stop,
                            &sources,
                        )
                        .await
                };
                let value = match result {
                    Ok(v) => v,
                    Err(e) => {
                        let retry = matches!(
                            e,
                            KernelAccessError::Client(
                                crate::kernel_client::KernelClientError::Transport(
                                    crate::transport::TransportError::Network
                                        | crate::transport::TransportError::Timeout
                                        | crate::transport::TransportError::SubmittedUncertain
                                )
                            )
                        );
                        let mut value = native_error(e);
                        value["retryable"] = json!(retry);
                        value
                    }
                };
                JobResult::Mutation(value)
            });
            job_kinds.insert(handle.id(), JobKind::Mutation(job_key));
        }
    }
    receiver.close();
    cancel.cancel();
    // Native operations preserve their exact plans/packets on cancellation.
    // Await all owned tasks before releasing state locks; no detached worker.
    while let Some(result) = jobs.join_next_with_id().await {
        if let Ok((id, JobResult::Mutation(value))) = result {
            if let Some(JobKind::Mutation(key)) = job_kinds.remove(&id) {
                retry_persistence.insert(key, value);
            }
        }
    }
    let _ = watch_task.await;
    access.close_session_executor_async().await;
    for (key, value) in retry_persistence {
        let _ = store.finish(&key.0, &key.1, &identity, &value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn offline_protocol_tools_simulate_without_network_or_legacy_apply() {
        let dir = crate::test_support::protected_test_dir();
        let path = dir.path().join("identity");
        let identity = KernelIdentity::create(&path).unwrap();
        let mut config = ParticipantConfig::new(
            "http://127.0.0.1:1",
            identity.actor_id(),
            path,
            dir.path().join("engine"),
        );
        config.allow_loopback_http = true;
        let client = ParticipantClient::open(config.clone()).await.unwrap();
        let manifest = json!({"name":"test.counter","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{"count":0},"actions":[{"id":"set","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[{"op":"eq","left":{"from":"state","path":["count"]},"right":{"from":"literal","value":0}}],"effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}}]}]}]});
        let fixture=client.request(Invoke::new("fixture","participant.protocol.offline",Scope::default(),json!({"operation":"fixture","input":{"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"counter","manifest":manifest}]}}))).await.unwrap();
        assert_eq!(fixture["result"]["ok"], true, "{fixture}");
        let simulation=client.request(Invoke::new("simulate","participant.protocol.offline",Scope::default(),json!({"operation":"simulate","input":{"schema":"peerwork.protocol-simulation.v1","fixture":fixture["result"]["value"],"steps":[{"instance_id":"counter","action_id":"set"}]}}))).await.unwrap();
        assert_eq!(simulation["authoritative"], false);
        assert_eq!(simulation["result"]["ok"], true, "{simulation}");
        assert_eq!(
            simulation["result"]["value"]["steps"][0]["output_state"]["count"],
            1
        );
        assert_eq!(simulation["result"]["value"]["authoritative"], false);
        assert!(simulation.get("receipt").is_none());
        for operation in ["export", "apply"] {
            assert_eq!(client.request(Invoke::new("retired","participant.protocol.offline",Scope::default(),json!({"operation":operation,"input":{"profile":{"identity_path":"/nonexistent/private-key","state_dir":"/nonexistent"}}}))).await.unwrap_err().code,"HELPER_SELECTION_INVALID");
        }
        assert!(client.operations("", 32).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(
            !config.journal_path.exists(),
            "offline tools must not open the native transport journal"
        );
        client.close().await.unwrap();
    }
    fn worker() -> Capability {
        Capability {
            operations: ["structure.action".into(), "structure.records.read".into()].into(),
            allow_root: false,
            workspace_ids: Some(["space-a".into()].into()),
            instance_ids: Some(["tasks".into()].into()),
            protocol_digests: Some(["a".repeat(64)].into()),
            business_actions: Some(["task.report".into()].into()),
            mailbox_ids: None,
        }
    }
    fn report() -> Invoke {
        Invoke::new(
            "one",
            "structure.action",
            Scope {
                workspace_id: Some("space-a".into()),
                instance_id: Some("tasks".into()),
                protocol_digest: Some("a".repeat(64)),
            },
            json!({"action_id":"task.report","structure":{}}),
        )
    }
    #[test]
    fn native_mail_capabilities_check_nested_scope_and_mailbox_selectors() {
        let ws = "W".repeat(43);
        let box_id = "M".repeat(43);
        let other = "N".repeat(43);
        let mut cap = Capability::owner();
        cap.workspace_ids = Some([ws.clone()].into());
        cap.mailbox_ids = Some([box_id.clone()].into());
        let scope = Scope {
            workspace_id: Some(ws.clone()),
            ..Default::default()
        };
        let send = Invoke::new(
            "mail",
            "structure.message.send",
            scope.clone(),
            json!({"recipients":[{"mailbox_id":box_id,"membership_id":"G".repeat(43)}],"content":{"mode":"WORKSPACE_E2EE"}}),
        );
        cap.authorize(&send).unwrap();
        let mut wrong = send.clone();
        wrong.body["recipients"][0]["mailbox_id"] = json!(other);
        assert!(cap.authorize(&wrong).is_err());
        wrong = send.clone();
        wrong.body["reply_address"] = json!({"mailbox_id":other,"membership_id":"G".repeat(43)});
        assert!(cap.authorize(&wrong).is_err());
        let mut stream = Invoke::new(
            "stream",
            "structure.communication.stream.get",
            Scope::default(),
            json!({"scopes":[{"workspace_id":ws,"mailbox_id":box_id}]}),
        );
        cap.authorize(&stream).unwrap();
        stream.body["scopes"][0]["workspace_id"] = json!("Z".repeat(43));
        assert!(cap.authorize(&stream).is_err());
        cap.instance_ids = Some(["I".repeat(43)].into());
        cap.protocol_digests = Some(["a".repeat(64)].into());
        cap.authorize(&send).unwrap();
        let mut source = send;
        source.body["content"] = json!({"mode":"SOURCE","instance_id":"J".repeat(43),"protocol_digest":"a".repeat(64),"record_id":"C".repeat(43),"revision":1});
        assert!(cap.authorize(&source).is_err());
        source.body["content"]["instance_id"] = json!("I".repeat(43));
        cap.authorize(&source).unwrap();
        assert!(cap
            .authorize(&Invoke::new(
                "unsafe",
                "structure.message.get",
                scope,
                json!({"message_id":"C".repeat(43),"mailbox_id":box_id})
            ))
            .is_err());
        let mut expanded = cap.clone();
        expanded.mailbox_ids = None;
        assert!(!expanded.is_subset_of(&cap));
    }
    #[tokio::test]
    async fn admitted_wait_observation_failure_preserves_original_identity_and_certainty() {
        for certainty in ["NOT_SUBMITTED", "COMMITTED"] {
            let (sender, mut receiver) = mpsc::channel(1);
            let (release_tx, release_rx) = oneshot::channel::<()>();
            let client = ParticipantClient {
                shared: Arc::new(Shared {
                    sender: sender.clone(),
                    cancel: KernelCancellationToken::new(),
                    thread: Mutex::new(None),
                    actor: "synthetic".into(),
                    origin: "https://service.invalid/".into(),
                }),
                namespace: "program".into(),
                capability: Capability::owner(),
            };
            let initial = certainty.to_owned();
            let helper = tokio::spawn(async move {
                let Some(Command::Invoke { reply, .. }) = receiver.recv().await else {
                    panic!("expected admission")
                };
                let (done_tx, done_rx) = oneshot::channel();
                let (unused, _) = oneshot::channel();
                sender
                    .try_send(Command::Metrics { reply: unused })
                    .unwrap_or_else(|_| panic!("queue should be empty"));
                let operation = Operation {
                    operation_id: "original".into(),
                    state: "PENDING".into(),
                    command_id: None,
                    effect_certainty: initial,
                    outcome: None,
                    observation: "LOCAL_DURABLE".into(),
                };
                assert!(reply
                    .send(Ok(Admission {
                        operation,
                        completed: done_rx
                    }))
                    .is_ok());
                let _ = release_rx.await;
                drop(done_tx);
                drop(receiver);
            });
            let error = client
                .invoke(
                    Invoke::new(
                        "original",
                        "structure.workspace.create",
                        Scope::default(),
                        json!({"name":"Synthetic"}),
                    ),
                    Duration::from_millis(2),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, "NOT_ADMITTED_BUSY");
            assert_eq!(error.operation_id.as_deref(), Some("original"));
            assert_eq!(
                error.effect_certainty,
                if certainty == "COMMITTED" {
                    "COMMITTED"
                } else {
                    "UNKNOWN"
                }
            );
            let _ = release_tx.send(());
            helper.await.unwrap();
        }
    }
    #[test]
    fn root_lifecycle_does_not_require_an_existing_instance() {
        let request = Invoke::new(
            "create",
            "structure.workspace.create",
            Scope::default(),
            json!({"name":"Synthetic"}),
        );
        Capability::owner().authorize(&request).unwrap();
        assert!(worker().authorize(&request).is_err());
    }
    #[test]
    fn worker_cannot_expand_workspace_protocol_or_business_authority() {
        let cap = worker();
        cap.authorize(&report()).unwrap();
        assert!(cap.is_subset_of(&Capability::owner()));
        assert!(!Capability::owner().is_subset_of(&cap));
        for field in ["workspace", "instance", "protocol", "action"] {
            let mut r = report();
            match field {
                "workspace" => r.scope.workspace_id = Some("space-b".into()),
                "instance" => r.scope.instance_id = Some("research".into()),
                "protocol" => r.scope.protocol_digest = Some("b".repeat(64)),
                _ => r.body["action_id"] = json!("task.delete"),
            };
            assert_eq!(cap.authorize(&r).unwrap_err().code, "LOCAL_SCOPE_DENIED");
        }
        let mut injection = serde_json::to_value(report()).unwrap();
        injection["identity_path"] = json!("/someone/else");
        assert!(serde_json::from_value::<Invoke>(injection).is_err());
    }
    #[test]
    fn instance_authority_cannot_be_attached_to_workspace_wide_operations() {
        let mut cap = worker();
        cap.operations.insert("structure.instances.read".into());
        let request = Invoke::new(
            "all-instances",
            "structure.instances.read",
            report().scope,
            json!({}),
        );
        assert_eq!(
            cap.authorize(&request).unwrap_err().code,
            "LOCAL_SCOPE_DENIED"
        );
        cap.operations.insert("structure.protocol.resolve".into());
        let mut request = Invoke::new(
            "bound-protocol",
            "structure.protocol.resolve",
            report().scope,
            json!({"instance_id":"another-instance"}),
        );
        assert!(cap.authorize(&request).is_err());
        request.body = json!({"view":"inspect"});
        cap.authorize(&request).unwrap();
        let wire = request.wire("program", "actor", "https://service.invalid/", false);
        assert!(wire["instance_id"].is_null());
        assert_eq!(wire["body"]["instance_id"], "tasks");
        assert!(request.verify_result_scope(json!({"state":"ACCEPTED","result":{"structure":{"protocol_digest":"b".repeat(64)}}})).is_err());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedded_client_is_send_scoped_and_owns_its_state() {
        let temp = crate::test_support::protected_test_dir();
        let identity_path = temp.path().join("identity");
        let identity = KernelIdentity::create(&identity_path).unwrap();
        let mut config = ParticipantConfig::new(
            "http://127.0.0.1:1",
            identity.actor_id(),
            &identity_path,
            temp.path().join("engine"),
        );
        config.allow_loopback_http = true;
        let client = ParticipantClient::open(config.clone()).await.unwrap();
        assert_eq!(
            ParticipantClient::open(config.clone())
                .await
                .err()
                .unwrap()
                .code,
            "STATE_ALREADY_OWNED"
        );
        let restricted = client.restrict("worker", worker()).unwrap();
        assert_eq!(restricted.close().await.unwrap_err().code, "ADMIN_REQUIRED");
        assert!(restricted.restrict("root", Capability::owner()).is_err());
        assert_eq!(
            restricted
                .invoke(
                    Invoke::new(
                        "no",
                        "structure.workspace.create",
                        Scope::default(),
                        json!({})
                    ),
                    Duration::ZERO
                )
                .await
                .unwrap_err()
                .code,
            "LOCAL_SCOPE_DENIED"
        );
        let clone = client.clone();
        let metrics = tokio::spawn(async move { clone.metrics().await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(metrics["actor_id"], identity.actor_id());
        client.close().await.unwrap();
        let reopened = ParticipantClient::open(config).await.unwrap();
        reopened.close().await.unwrap();
    }
    #[tokio::test]
    async fn offline_admission_is_bounded_and_survives_owner_restart() {
        let temp = crate::test_support::protected_test_dir();
        let path = temp.path().join("identity");
        let identity = KernelIdentity::create(&path).unwrap();
        let mut cfg = ParticipantConfig::new(
            "http://127.0.0.1:1",
            identity.actor_id(),
            &path,
            temp.path().join("engine"),
        );
        cfg.allow_loopback_http = true;
        cfg.max_pending = 2;
        cfg.max_inflight = 1;
        let client = ParticipantClient::open(cfg.clone()).await.unwrap();
        let first = Invoke::new(
            "a",
            "structure.workspace.create",
            Scope::default(),
            json!({"name":"Private synthetic input"}),
        );
        client.invoke(first.clone(), Duration::ZERO).await.unwrap();
        client
            .invoke(
                Invoke::new(
                    "b",
                    "structure.workspace.create",
                    Scope::default(),
                    json!({"name":"Second"}),
                ),
                Duration::ZERO,
            )
            .await
            .unwrap();
        let err = client
            .invoke(
                Invoke::new(
                    "c",
                    "structure.workspace.create",
                    Scope::default(),
                    json!({"name":"Overflow"}),
                ),
                Duration::ZERO,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, "NOT_ADMITTED_CAPACITY");
        assert_eq!(
            client
                .invoke(first.clone(), Duration::ZERO)
                .await
                .unwrap()
                .operation_id,
            "a"
        );
        let mut changed = first.clone();
        changed.body["name"] = json!("Replacement");
        assert_eq!(
            client
                .invoke(changed, Duration::ZERO)
                .await
                .unwrap_err()
                .code,
            "OPERATION_INPUT_CONFLICT"
        );
        client.close().await.unwrap();
        let bytes = std::fs::read(cfg.state_directory.join("participant.sqlite")).unwrap();
        assert!(!bytes.windows(23).any(|v| v == b"Private synthetic input"));
        let client = ParticipantClient::open(cfg).await.unwrap();
        let saved = client.operation("a").await.unwrap();
        assert!(!saved.is_terminal());
        assert_eq!(
            client.operations("", 32).await.unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let metrics = client.metrics().await.unwrap();
        assert!(
            metrics["active_tasks"].as_u64().unwrap()
                <= metrics["max_inflight"].as_u64().unwrap() + 1
        );
        client.close().await.unwrap();
    }
}
