//! One engine-owned mailbox driver: shared SSE, durable local custody and
//! independent fenced control work. No model process or nested executor.
use crate::{
    kernel_access::{KernelAccess, KernelPublicError},
    kernel_client::StructureIntentOutcome,
    kernel_identity::KernelIdentity,
    participant::{Capability, Invoke, ParticipantError, Result, Scope},
    participant_inbox::InboxStore,
    transport::HttpTransport,
    KernelCancellationToken,
};
use peerwork_core::{
    communication::{
        verify_mailbox_frame_detailed, FramePins, MailboxPins, VerifiedMailboxPage, MAX_FRAME_BYTES,
    },
    crypto::{decode_base64url, sha256_hex},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
fn error(code: &str) -> ParticipantError {
    ParticipantError {
        details: None, code: code.into(),
        phase: "MAILBOX_WATCH".into(),
        effect_certainty: "UNKNOWN".into(),
        recovery: "RETAIN_ORIGINAL_BINDING_AND_RECONNECT".into(),
        operation_id: None,
    }
}
fn token(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WatchOptions {
    pub workspace_id: String,
    pub mailbox_id: String,
    pub membership_id: String,
    /// Stable application endpoint, not an Agent role or a guessed conversation.
    pub consumer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_destination: Option<String>,
}
impl WatchOptions {
    pub fn validate(&self) -> Result<()> {
        if ![&self.workspace_id, &self.mailbox_id, &self.membership_id]
            .iter()
            .all(|v| token(v))
            || !crate::communication_store::identifier(&self.consumer_id)
            || self
                .host_destination
                .as_deref()
                .is_some_and(|v| !crate::participant_migration::digest(v))
        {
            return Err(error("WATCH_OPTIONS_INVALID"));
        }
        Ok(())
    }
    pub(crate) fn key(&self) -> String {
        format!("{}:{}", self.workspace_id, self.mailbox_id)
    }
    pub(crate) fn authorize(&self, cap: &Capability) -> Result<()> {
        self.validate()?;
        for action in [
            "structure.mailbox.get",
            "structure.mailbox.claim",
            "structure.mailbox.inbox.read",
            "structure.mailbox.pulse",
            "structure.mailbox.ack",
        ] {
            cap.authorize(&Invoke::new(
                "watch",
                action,
                Scope {
                    workspace_id: Some(self.workspace_id.clone()),
                    ..Default::default()
                },
                json!({"mailbox_id":self.mailbox_id}),
            ))?;
        }
        if self.host_destination.is_some() {
            cap.authorize(&Invoke::new(
                "watch-host-report",
                "structure.mailbox.report",
                Scope {
                    workspace_id: Some(self.workspace_id.clone()),
                    ..Default::default()
                },
                json!({"mailbox_id":self.mailbox_id}),
            ))?;
        }
        Ok(())
    }
    pub(crate) fn destination(&self, actor: &str, origin: &str, namespace: &str) -> String {
        if let Some(digest) = &self.host_destination {
            return digest.clone();
        }
        sha256_hex(
            json!([
                "peerwork.program-consumer.v1",
                actor,
                origin,
                namespace,
                self.consumer_id
            ])
            .to_string()
            .as_bytes(),
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReference {
    pub sequence: u64,
    pub delivery_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSnapshot {
    pub reporting_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_failure: Option<Value>,
    pub presence: Value,
    pub workspace_id: String,
    pub mailbox_id: String,
    pub generation: u64,
    pub state: String,
    pub receiver_link_verified: bool,
    pub model_response: String,
    pub code: Option<String>,
    pub checkpoint: u64,
    pub control_checkpoint: Option<u64>,
    pub items: Vec<Value>,
    pub next_after: Option<u64>,
    pub receiver_ack_pending: bool,
    pub application_ack_pending: bool,
    pub stream_id: Option<String>,
    pub disconnects: u64,
}
#[derive(Clone)]
pub(crate) struct Binding {
    pub namespace: String,
    pub options: WatchOptions,
    pub receiver: String,
    pub claim_id: String,
    pub claim_wire: Option<String>,
    pub pins: Option<MailboxPins>,
}
#[derive(Clone)]
pub(crate) struct MailSession {
    pub transport: HttpTransport,
    pub audience: Vec<u16>,
    pub service_key: String,
    pub conversation_format: bool,
}
impl MailSession {
    fn now(&self) -> Result<u64> {
        self.transport
            .cached_context(&self.service_key)
            .map(|v| v.server_time_ms())
            .ok_or_else(|| error("AUTHORIZATION_ANCHOR_EXPIRED"))
    }
}
pub(crate) enum Command {
    Resident {
        request: crate::participant_rebind::resident::Request,
        reply: oneshot::Sender<Result<Option<crate::participant_rebind::resident::Snapshot>>>,
    },
    Bindings {
        namespace: String,
        capability: Capability,
        reply: oneshot::Sender<Result<Vec<WatchOptions>>>,
    },
    Host {
        local_live:Arc<std::sync::atomic::AtomicBool>,
        namespace: String,
        options: WatchOptions,
        operation: crate::participant_inbox::HostOperation,
        reply: oneshot::Sender<Result<crate::participant_inbox::HostReply>>,
    },
    Stop {
        namespace: String,
        options: WatchOptions,
        reply: oneshot::Sender<Result<()>>,
    },
    Attach {
        local_live:Arc<std::sync::atomic::AtomicBool>,
        namespace: String,
        options: WatchOptions,
        reply: oneshot::Sender<Result<mpsc::Receiver<()>>>,
    },
    Snapshot {
        namespace: String,
        options: WatchOptions,
        after: u64,
        limit: usize,
        reply: oneshot::Sender<Result<WatchSnapshot>>,
    },
    Consume {
        namespace: String,
        options: WatchOptions,
        items: Vec<DeliveryReference>,
        reply: oneshot::Sender<Result<()>>,
    },
}
pub(crate) fn reject(command: Command, e: ParticipantError) {
    match command {
        Command::Resident { reply, .. } => { let _ = reply.send(Err(e)); },
        Command::Bindings { reply, .. } => {
            let _ = reply.send(Err(e));
        }
        Command::Host { reply, .. } => {
            let _ = reply.send(Err(e));
        }
        Command::Stop { reply, .. } => {
            let _ = reply.send(Err(e));
        }
        Command::Attach { reply, .. } => {
            let _ = reply.send(Err(e));
        }
        Command::Snapshot { reply, .. } => {
            let _ = reply.send(Err(e));
        }
        Command::Consume { reply, .. } => {
            let _ = reply.send(Err(e));
        }
    }
}

struct Slot {
    enabled: bool,
    binding: Binding,
    signals: Vec<mpsc::Sender<()>>,
    generation: u64,
    state: String,
    code: Option<String>,
    link_verified: bool,
    stream_id: Option<String>,
    disconnects: u64,
    lease_until: Option<Instant>,
    next_control: Instant,
    retry_at: Instant,
    failures: u8,
    busy: bool,
    control_cancel: Option<KernelCancellationToken>,
    blocked: bool,
    receive_fault: Option<Value>,
    time_retries: u8,
    pulse_busy: bool,
    lifecycle: u64,
    pulse_retry_at: Instant,
    pulse_failures: u8,
    pulse_cancel: Option<KernelCancellationToken>,
    presence: crate::participant_presence::Presence,
    next_keys: Instant,
    report_retry: Instant,
    report_code: Option<String>,
    prefer_consumed_ack: bool,
    custody_ack_not_before: Option<Instant>,
}
impl Slot {
    fn missing_keys(&mut self) {
        let mut data = self.presence.local()["body_key"].clone();
        data["state"] = json!("MISSING");
        self.presence.keys(data);
        self.next_keys = Instant::now();
        self.next_control = Instant::now();
    }
    fn notify(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.signals.retain(|s| !s.is_closed());
        for s in &self.signals {
            let _ = s.try_send(());
        }
    }
    fn state(&mut self, state: &str, code: Option<String>) {
        let (state, code) = if !self.enabled { ("LOCAL_STOPPED", code) }
            else if self.blocked { ("BLOCKED", self.code.clone().or(code)) }
            else if self.receive_fault.is_some() { ("BLOCKED", Some("STREAM_VERIFICATION_FAILED".into())) }
            else { (state, code) };
        if self.state != state || self.code != code {
            self.state = state.into();
            self.code = code;
            self.notify();
        }
    }
    fn fail(&mut self, e: Failure) {
        self.link_verified = false;
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Instant::now() + receiver_retry_delay(self.failures, e.capacity());
        if !self.blocked && !e.retryable {self.code=Some(e.code.clone());}
        self.blocked |= !e.retryable;
        self.state(
            if e.retryable {
                "RECONNECTING"
            } else {
                "BLOCKED"
            },
            Some(e.code),
        );
    }
}
struct Failure {
    // Set only from a verified signed REJECTED_NO_EFFECT result.
    no_effect: bool,
    code: String,
    retryable: bool,
}
impl Failure {
    fn capacity(&self) -> bool {
        !self.no_effect && matches!(self.code.as_str(),
            "RESOURCE_EXHAUSTED" | "CAPACITY_RESERVATION_EXHAUSTED")
    }
    fn for_receiver(mut self) -> Self {
        // A resource diagnostic is not a terminal signed outcome. Maintenance
        // may probe again; an uncertain claim still uses its frozen command ID.
        // Do not change the general business-operation recovery contract.
        self.retryable |= self.capacity();
        self
    }
    fn code(code: &str) -> Self {
        Self {
            no_effect: false,
            code: code.into(),
            retryable: true,
        }
    }
}
fn receiver_retry_delay(failures: u8, capacity: bool) -> Duration {
    Duration::from_millis(if capacity {
        (2000u64 << failures.saturating_sub(1).min(4)).min(30000)
    } else {
        (250u64 << failures.min(5)).min(8000)
    })
}
fn result(
    out: std::result::Result<StructureIntentOutcome, crate::kernel_access::KernelAccessError>,
) -> std::result::Result<Value, Failure> {
    let outcome = match out {
        Ok(StructureIntentOutcome::Accepted(value)) => {
            let data: Value = serde_json::from_str(
                value
                    .structure_result_json
                    .as_deref()
                    .ok_or_else(|| Failure::code("RESULT_INVALID"))?,
            )
            .map_err(|_| Failure::code("RESULT_INVALID"))?;
            if value.outcome_state() == "REJECTED" {
                return Err(Failure {
                    no_effect: data["status"] == "REJECTED_NO_EFFECT",
                    code: data["error"]["code"]
                        .as_str()
                        .unwrap_or("SERVICE_REFUSED")
                        .into(),
                    retryable: false,
                });
            }
            Ok(data)
        }
        Ok(StructureIntentOutcome::Pending {
            code, retryable, ..
        }) => Err(Failure {
            no_effect: false,
            code: code.into(),
            retryable,
        }),
        Ok(_) => Err(Failure::code("RESULT_INVALID")),
        Err(e) => {
            let e = KernelPublicError::from(e);
            Err(Failure {
                no_effect: false,
                code: e.code.into(),
                retryable: !matches!(
                    e.code,
                    "CONFIG_INVALID"
                        | "DISCOVERY_CHANGED"
                        | "CONTENT_KEY_STATE"
                        | "VERIFICATION_FAILED"
                ),
            })
        }
    };
    outcome.map_err(Failure::for_receiver)
}
fn scope_refusal(code: &str) -> bool {
    matches!(
        code,
        "COMMUNICATION_NOT_AUTHORIZED"
            | "COMMUNICATION_GRANT_CHANGED"
            | "FORBIDDEN"
            | "ACCESS_EXPIRED"
            | "MAILBOX_NOT_FOUND"
            | "MAILBOX_EPOCH_MISMATCH"
            | "MAILBOX_LEASE_EXPIRED"
            | "MAILBOX_STATE_RECOVERY_REQUIRED"
            | "MAILBOX_CONTINUITY_PROOF_INVALID"
            | "WORKSPACE_NOT_FOUND"
            | "WORKSPACE_ARCHIVED"
            | "WORKSPACE_DELETING"
    )
}
fn validate_claim(
    binding: &Binding,
    wire: &str,
    actor: &str,
    origin: &str,
    audience: &str,
) -> Result<()> {
    let request = parse_wire_json_bounded(wire.as_bytes(), 8, 8192)
        .map_err(|_| error("WATCH_CLAIM_STATE_INVALID"))?;
    let expected = binding
        .options
        .destination(actor, origin, &binding.namespace);
    let text = |v: &WireValue, k: &str| v.get(k).and_then(WireValue::as_string);
    let body = request
        .get("body")
        .ok_or_else(|| error("WATCH_CLAIM_STATE_INVALID"))?;
    let value: Value = serde_json::from_str(
        &canonical_wire_value(body, peerwork_core::canonical::Path::STRUCTURED)
            .map_err(|_| error("WATCH_CLAIM_STATE_INVALID"))?,
    )
    .map_err(|_| error("WATCH_CLAIM_STATE_INVALID"))?;
    peerwork_core::communication::verify_receiver_claim_proof(
        audience,
        actor,
        &binding.options.workspace_id,
        &value,
    )
    .map_err(|_| error("WATCH_CLAIM_STATE_INVALID"))?;
    if request.object_len() != Some(4)
        || text(&request, "action").as_deref() != Some("structure.mailbox.claim")
        || text(&request, "workspace_id").as_deref() != Some(&binding.options.workspace_id)
        || text(&request, "command_id").as_deref() != Some(&binding.claim_id)
        || body.object_len() != Some(if body.get("event_format").is_some(){8}else{7})
        || body.get("event_format").is_some() && text(body,"event_format").as_deref()!=Some(peerwork_core::communication::WORKSPACE_EVENT_FORMAT)
        || text(body, "claim_command_id").as_deref() != Some(&binding.claim_id)
        || text(body, "mailbox_id").as_deref() != Some(&binding.options.mailbox_id)
        || text(body, "receiver_id").as_deref() != Some(&binding.receiver)
        || text(body, "destination_digest").as_deref() != Some(&expected)
        || body.get("replace") != Some(&WireValue::Bool(false))
        || !match body.get("expected_epoch") {
            Some(WireValue::Null) => true,
            Some(WireValue::Number(n)) => {
                n.is_finite() && n.fract() == 0.0 && *n >= 1.0 && *n < 9_007_199_254_740_991.0
            }
            _ => false,
        }
    {
        return Err(error("WATCH_CLAIM_STATE_INVALID"));
    }
    Ok(())
}
async fn call(
    access: &KernelAccess,
    action: &str,
    workspace: Option<&str>,
    body: Value,
    cancel: &KernelCancellationToken,
) -> std::result::Result<Value, Failure> {
    let wire = json!({"action":action,"workspace_id":workspace,"body":body}).to_string();
    let outcome = result(
        access
            .execute_structure_intent_async(wire.as_bytes(), cancel)
            .await,
    );
    if action == "structure.mailbox.pulse"
        && outcome
            .as_ref()
            .err()
            .is_some_and(|e| e.code == "MAILBOX_LEASE_EXPIRED")
    {
        // A confirmed no-effect heartbeat may have crossed its short issuance
        // window. Refresh nonce-bound service time once; preserve the fence.
        access
            .refresh_mailbox_clock(cancel)
            .await
            .map_err(|e| Failure::code(KernelPublicError::from(e).code))?;
        return result(
            access
                .execute_structure_intent_async(wire.as_bytes(), cancel)
                .await,
        );
    }
    outcome
}
enum JobKind {
    Resident,
    Session,
    Stream,
    Control(String, u64),
    Pulse(String, u64),
    Keys(String),
}
enum Work {
    Resident(crate::participant_rebind::resident::Completed),
    Session(std::result::Result<MailSession, Failure>),
    Inspect(String, std::result::Result<Value, Failure>),
    Claim(String, std::result::Result<Value, Failure>),
    Pulse(String, Instant, u64, Option<Instant>, std::result::Result<Value, Failure>),
    Keys(String, Vec<String>, std::result::Result<Value, Failure>),
    Ack(
        String,
        Vec<(u64, String)>,
        bool,
        std::result::Result<Value, Failure>,
    ),
    Report(String, String, u64, std::result::Result<Value, Failure>),
    Stream(std::result::Result<(), Failure>),
}
enum Frame {
    Fault { generation: u64, keys: Vec<String>, diagnostic: Value, reply: oneshot::Sender<()> },
    Bootstrap(u64, Vec<MailboxPins>, oneshot::Sender<Result<()>>),
    Data {
        generation: u64,
        stream_id: String,
        page: VerifiedMailboxPage,
        valid_until: tokio::time::Instant,
        stored: oneshot::Sender<Result<()>>,
    },
}
pub(crate) async fn run(
    mut store: InboxStore,
    identity: Arc<KernelIdentity>,
    origin: String,
    access: Arc<KernelAccess>,
    mut resident: crate::participant_rebind::resident::Controller,
    mut commands: mpsc::Receiver<Command>,
    cancel: KernelCancellationToken,
) {
    let mut slots: BTreeMap<String, Slot> = BTreeMap::new();
    let bindings = match store.watch_bindings() {
        Ok(v) => v,
        Err(e) => loop {
            tokio::select! {_=cancel.cancelled()=>return,command=commands.recv()=>match command{Some(command)=>reject(command,e.clone()),None=>return}}
        },
    };
    for binding in bindings {
        let fault=store.receive_fault(&binding.options.workspace_id,&binding.options.mailbox_id);
        let mut value=slot(binding);
        match fault {Ok(fault)=>value.receive_fault=fault,Err(e)=>value.fail(Failure{no_effect:false,code:e.code,retryable:false})}
        if value.receive_fault.is_some(){value.state("BLOCKED",Some("STREAM_VERIFICATION_FAILED".into()));}
        slots.insert(value.binding.options.key(),value);
    }
    match resident.paused_bindings(&store) {
        Ok(bindings)=>for binding in bindings {
            let _=store.disable_watch(&binding.namespace,&binding.options);
            let mut value=slot(binding);value.enabled=false;
            value.receive_fault=store.receive_fault(&value.binding.options.workspace_id,&value.binding.options.mailbox_id).ok().flatten();
            value.code=Some("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION".into());
            slots.insert(value.binding.options.key(),value);
        },
        Err(problem)=>{resident.record_error(problem);},
    }
    let mut session: Option<MailSession> = None;
    let mut session_busy = false;
    let mut session_retry = Instant::now();
    let mut jobs = tokio::task::JoinSet::new();
    let mut kinds: HashMap<tokio::task::Id, JobKind> = HashMap::new();
    let (frames_tx, mut frames) = mpsc::channel::<Frame>(2);
    let mut stream_cancel: Option<KernelCancellationToken> = None;
    let mut stream_scopes = String::new();
    let mut stream_running = false;
    let mut stream_generation = 0u64;
    let mut active_generation = None;
    let mut stream_failures = 0u8;
    let mut stream_retry = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut compact_at = Instant::now();
    let mut last_key_workspace: Option<String> = None;
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            command=commands.recv()=>match command{
                None=>break,
                Some(Command::Resident{request,reply})=>{
                    use crate::participant_rebind::resident::Request as R;
                    let value=match request {
                        R::Preflight=>Err(error("HOST_REBIND_PREFLIGHT_OWNER_REQUIRED")),
                        R::Status=>resident.status(),
                        R::Lookup(request)=>resident.lookup(&request,&identity),
                        R::Recover{request,decision}=>resident.recover(&request,&decision,&identity).map(Some),
                        R::Problem{operation,problem}=>{
                            if resident.status().ok().flatten().is_some_and(|s|s.request.operation_id==operation){resident.record_error(problem);}
                            resident.status()
                        },
                        R::Prepare(selection)=>resident.prepare(selection,&mut store,&identity).map(Some),
                        R::Authorize{operation,sources}=>resident.authorize(&operation,sources,&store).and_then(|_|resident.status()),
                        R::Published{operation}=>{
                            let bindings=resident.paused_bindings(&store);
                            let resume=resident.status().ok().flatten().map(|s|s.resume).unwrap_or_default();
                            match bindings {
                                Err(e)=>Err(e),
                                Ok(bindings)=>(||{
                                    for (index,binding) in bindings.into_iter().enumerate() {
                                        if !resume.get(index).copied().unwrap_or(false){
                                            store.disable_watch(&binding.namespace,&binding.options)?;
                                            slots.remove(&binding.options.key());continue;
                                        }
                                        let restored=store.attach_watch(&identity,&binding.namespace,&binding.options)?;
                                        let mut value=slot(restored);
                                        value.receive_fault=store.receive_fault(&value.binding.options.workspace_id,&value.binding.options.mailbox_id)?;
                                        slots.insert(value.binding.options.key(),value);
                                    }
                                    resident.published(&operation,&identity).map(Some)
                                })(),
                            }
                        },
                    };
                    // A prepared job may already be durable even if the final
                    // response write failed. Its scope fence always takes effect.
                    if let Ok(bindings)=resident.paused_bindings(&store) {
                        for binding in bindings {
                            if !slots.contains_key(&binding.options.key()) {
                                let mut value=slot(binding);value.enabled=false;
                                value.receive_fault=store.receive_fault(&value.binding.options.workspace_id,&value.binding.options.mailbox_id).ok().flatten();
                                slots.insert(value.binding.options.key(),value);
                            }
                        }
                    }
                    for s in slots.values_mut().filter(|s|resident.paused(&s.binding.options)) {
                        if s.enabled {
                            let _=store.disable_watch(&s.binding.namespace,&s.binding.options);
                            s.enabled=false;s.lifecycle=s.lifecycle.saturating_add(1);
                            if let Some(c)=s.control_cancel.take(){c.cancel();}
                            if let Some(c)=s.pulse_cancel.take(){c.cancel();}
                        }
                        s.link_verified=false;s.code=Some("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION".into());
                        s.state("LOCAL_STOPPED",s.code.clone());
                    }
                    let _=reply.send(value);
                },
                Some(Command::Bindings{namespace,capability,reply})=>{
                    let selected=slots.values().filter(|s|s.enabled&&s.binding.namespace==namespace&&s.binding.options.authorize(&capability).is_ok()).map(|s|s.binding.options.clone()).collect::<Vec<_>>();let _=reply.send(Ok(selected));
                },
                Some(Command::Host{local_live,namespace,options,operation,reply})=>{
                    use crate::participant_inbox::{HostOperation as Op,HostReply as Reply};
                    let value=(||->Result<Reply>{
                        if resident.paused(&options) && !matches!(&operation,Op::Finish{..}|Op::Status{..}|Op::Summary|Op::AccessScope|Op::RetirementCommit(_)) {
                            return Err(error("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));
                        }
                        let selected=slots.get(&options.key()).filter(|s|s.binding.namespace==namespace&&s.binding.options==options);
                        let live=selected.is_some_and(|s|s.enabled&&s.link_verified&&!s.blocked&&s.receive_fault.is_none()&&s.lease_until.is_some_and(|until|until>Instant::now()));
                        Ok(match operation{
                            Op::RetirementPlan=>Reply::Retirement(store.host_retirement_plan(&identity,&namespace,&options)?),
                            Op::RetirementCommit(plan)=>{store.host_retirement_commit(&identity,&namespace,&options,&plan)?;Reply::Saved},
                            Op::Summary=>Reply::Status(store.host_summary(&identity,&namespace,&options)?),
                            Op::AccessScope=>Reply::AccessScope(store.host_access_scope(&namespace,&options)?),
                            Op::ReconcileDue=>Reply::Call(if live{store.host_reconcile_due(&identity,&namespace,&options)?}else{None}),
                            Op::Presence{value,observed_at}=>{store.host_scope_check(&namespace,&options)?;let s=slots.get_mut(&options.key()).ok_or_else(||error("WATCH_NOT_FOUND"))?;let before=s.presence.version;s.presence.host_observed(value,observed_at)?;if before!=s.presence.version{s.next_control=Instant::now();}s.notify();Reply::Saved},
                            Op::Attach(host)=>{if !local_live.load(std::sync::atomic::Ordering::Acquire){return Err(error("LOCAL_CLIENT_REVOKED"));}if selected.is_none(){return Err(error("WATCH_NOT_FOUND"));}store.host_attach(&namespace,&options,&host)?;Reply::Saved},
                            Op::Due{limit}=>Reply::Due(if live{store.host_due(&namespace,&options,limit)?}else{Vec::new()}),
                            Op::Begin{item,frame}=>{if !local_live.load(std::sync::atomic::Ordering::Acquire){return Err(error("LOCAL_CLIENT_REVOKED"));}if !live{return Err(error("WATCH_NOT_CONNECTED"));}Reply::Call(store.host_begin(&identity,&namespace,&options,&item,frame)?)},
                            Op::Finish{call,outcome}=>{store.host_finish(&identity,&namespace,&options,&call,outcome)?;if let Some(s)=slots.get_mut(&options.key()){s.presence.version=s.presence.version.saturating_add(1);s.next_control=Instant::now();s.notify();}Reply::Saved},
                            Op::Defer{item,code}=>{
                                store.host_defer(&namespace,&options,&item,&code)?;
                                if code=="CONTENT_KEY_REQUIRED"{
                                    let mut page=store.pending(&identity,&options.workspace_id,&options.mailbox_id,item.sequence.saturating_sub(1),1)?;
                                    if let Some(entry)=page.first_mut().filter(|v|v["delivery_id"]==item.delivery_id){
                                        access.open_cached_mail(entry,store.audience());
                                        if entry["opened_message"]["state"]=="KEY_UNAVAILABLE"{
                                            if let Some(id)=entry["opened_message"]["key_id"].as_str(){store.key_unavailable(&options.workspace_id,&options.mailbox_id,item.sequence,id)?;let s=slots.get_mut(&options.key()).ok_or_else(||error("WATCH_NOT_FOUND"))?;s.missing_keys();}
                                        }
                                    }
                                }Reply::Saved
                            },
                            Op::Status{item}=>Reply::Status(store.host_status(&identity,&namespace,&options,&item)?),
                        })
                    })();let _=reply.send(value);
                },
                Some(Command::Stop{namespace,options,reply})=>{
                    let stopped=store.disable_watch(&namespace,&options).and_then(|_|{
                        // disable_watch verified the exact persisted namespace and descriptor.
                        // The in-memory slot may already have been reaped after
                        // another stop; this same binding remains stopped.
                        if let Some(slot)=slots.get_mut(&options.key()){
                            if slot.binding.namespace!=namespace||slot.binding.options!=options{return Err(error("WATCH_BINDING_MISMATCH"));}
                            // An explicit stop/start permits a fresh verified probe;
                            // an ordinary process restart does not erase quarantine.
                            if !resident.paused(&options) {
                                store.reset_receive_probe(&options.workspace_id,&options.mailbox_id)?;
                                slot.receive_fault=None;slot.time_retries=0;
                            }
                            slot.lifecycle=slot.lifecycle.saturating_add(1);
                            slot.enabled=false;if let Some(c)=slot.control_cancel.take(){c.cancel();}if let Some(c)=slot.pulse_cancel.take(){c.cancel();}slot.link_verified=false;slot.state("LOCAL_STOPPED",None);
                        }Ok(())
                    });let _=reply.send(stopped);
                },
                Some(Command::Attach{local_live,namespace,options,reply})=>{
                    let attached=(||->Result<_>{
                        if resident.paused(&options){return Err(error("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));}
                        if !local_live.load(std::sync::atomic::Ordering::Acquire){return Err(error("LOCAL_CLIENT_REVOKED"));}
                        // Maintenance pauses execution, not the original scope's
                        // admission reservation. Preserve room to restore it.
                        let reserved=slots.get(&options.key()).is_some_and(|s|s.enabled||resident.paused(&s.binding.options));
                        if !reserved&&slots.values().filter(|s|s.enabled||resident.paused(&s.binding.options)).count()>=8{return Err(error("WATCH_SCOPE_LIMIT"));}
                        if let Some(s)=slots.get_mut(&options.key()){s.signals.retain(|s|!s.is_closed());if s.signals.len()>=16{return Err(error("WATCH_LISTENER_LIMIT"));}}
                        let binding=store.attach_watch(&identity, &namespace,&options)?;
                        let key=options.key();
                        if !slots.contains_key(&key) {
                            let fault=store.receive_fault(&options.workspace_id,&options.mailbox_id)?;
                            let mut value=slot(binding);value.receive_fault=fault;
                            if value.receive_fault.is_some(){value.state("BLOCKED",Some("STREAM_VERIFICATION_FAILED".into()));}
                            slots.insert(key.clone(),value);
                        }
                        let entry=slots.get_mut(&key).unwrap();entry.enabled=true;
                        let (tx,rx)=mpsc::channel(1);let _=tx.try_send(());entry.signals.push(tx);Ok(rx)
                    })();let _=reply.send(attached);
                },
                Some(Command::Snapshot{namespace,options,after,limit,reply})=>{
                    let value=(||->Result<WatchSnapshot>{
                        let slot=slots.get_mut(&options.key()).filter(|s|s.binding.namespace==namespace&&s.binding.options==options).ok_or_else(||error("WATCH_NOT_FOUND"))?;
                        let cursor=store.cursor(&options.workspace_id,&options.mailbox_id)?;
                        let mut items=store.pending(&identity,&options.workspace_id,&options.mailbox_id,after,limit)?;
                        let audience=session.as_ref().map(|s|s.audience.as_slice()).unwrap_or(store.audience());
                        for item in &mut items{
                            access.open_cached_mail(item,audience);
                            if item["opened_message"]["state"]=="KEY_UNAVAILABLE"{if let (Some(id),Some(seq))=(item["opened_message"]["key_id"].as_str(),item["sequence"].as_u64()){store.key_unavailable(&options.workspace_id,&options.mailbox_id,seq,id)?;slot.missing_keys();}}
                        }
                        let next_after=if items.len()==limit{items.last().and_then(|v|v["sequence"].as_u64())}else{None};
                        Ok(WatchSnapshot{verification_failure:slot.receive_fault.clone(),presence:slot.presence.local(),reporting_code:slot.report_code.clone(),workspace_id:options.workspace_id.clone(),mailbox_id:options.mailbox_id.clone(),generation:slot.generation,state:slot.state.clone(),receiver_link_verified:slot.link_verified,model_response:"NOT_ATTESTED".into(),code:slot.code.clone(),checkpoint:cursor.as_ref().map(|c|c.item).unwrap_or(0),control_checkpoint:cursor.and_then(|c|c.control),items,next_after,
                            receiver_ack_pending:store.receiver_ack_pending(&options.workspace_id,&options.mailbox_id)?,
                            application_ack_pending:!store.acknowledgements(&options.workspace_id,&options.mailbox_id,true)?.is_empty(),stream_id:slot.stream_id.clone(),disconnects:slot.disconnects})
                    })();let _=reply.send(value);
                },
                Some(Command::Consume{namespace,options,items,reply})=>{
                    let value=(||->Result<()>{
                        if resident.paused(&options){return Err(error("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));}
                        let slot=slots.get_mut(&options.key()).filter(|s|s.binding.namespace==namespace&&s.binding.options==options).ok_or_else(||error("WATCH_NOT_FOUND"))?;
                        store.consume(&options.workspace_id,&options.mailbox_id,&items.iter().map(|r|(r.sequence,r.delivery_id.clone())).collect::<Vec<_>>())?;
                        // Consumption is durable local work for the ACK queue,
                        // not a change of lease/readiness. The loop schedules
                        // the ACK immediately without forcing a preceding pulse.
                        slot.notify();Ok(())
                    })();let _=reply.send(value);
                },
            },
            frame=frames.recv()=>if let Some(frame)=frame{
                let (page,stream_id,valid_until,reply)=match frame{
                    Frame::Fault{generation,keys,diagnostic,reply}=>{
                        if active_generation==Some(generation){
                            // Only an authenticated scope can select a mailbox.
                            // Unauthenticated input isolates this connection, not
                            // an attacker-selected routing field.
                            for (id,s) in slots.iter_mut().filter(|(id,s)|s.enabled && !s.blocked && keys.iter().any(|key|key==*id)) {
                                s.link_verified=false;
                                s.presence.version=s.presence.version.saturating_add(1);
                                s.next_control=Instant::now();
                                if diagnostic["code"]=="STREAM_TIME_WINDOW_INVALID" && s.time_retries<2 {
                                    s.time_retries+=1;
                                    s.state("RECONNECTING",Some("STREAM_TIME_WINDOW_INVALID".into()));
                                    continue;
                                }
                                let saved=store.quarantine_receive(&s.binding.options.workspace_id,&s.binding.options.mailbox_id,&diagnostic);
                                let _=id;
                                s.receive_fault=Some(diagnostic.clone());
                                if let Err(e)=saved{s.blocked=true;s.code=Some(e.code);}
                                s.next_control=Instant::now();
                                s.state("BLOCKED",Some("STREAM_VERIFICATION_FAILED".into()));
                            }
                        }
                        let _=reply.send(());continue;
                    },
                    Frame::Bootstrap(generation,scopes,reply)=>{
                        if active_generation!=Some(generation){let _=reply.send(Err(error("WATCH_STREAM_REPLACED")));continue;}
                        let bootstrap=(||->Result<()>{for p in scopes{
                            let key=format!("{}:{}",p.workspace_id,p.mailbox_id);
                            let slot=slots.get_mut(&key).ok_or_else(||error("WATCH_NOT_FOUND"))?;
                            if resident.paused(&slot.binding.options){continue;}
                            let current=slot.binding.pins.as_mut().ok_or_else(||error("WATCH_NOT_CLAIMED"))?;
                            if current.epoch!=p.epoch||current.receiver_id!=p.receiver_id{return Err(error("MAILBOX_EPOCH_MISMATCH"));}
                            if current.after_control_sequence.is_none(){let cursor=p.after_control_sequence.ok_or_else(||error("STREAM_GRANT_INVALID"))?;store.bootstrap_control(current,cursor)?;current.after_control_sequence=Some(cursor);}
                        }Ok(())})();let _=reply.send(bootstrap);continue;
                    },
                    Frame::Data{generation,stream_id,page,valid_until,stored}=>{
                        if active_generation!=Some(generation){let _=stored.send(Err(error("WATCH_STREAM_REPLACED")));continue;}
                        (page,stream_id,valid_until,stored)
                    },
                };
                let key=format!("{}:{}",page.mailbox().workspace_id,page.mailbox().mailbox_id);
                let stored=if tokio::time::Instant::now()>=valid_until{Err(error("STREAM_GRANT_EXPIRED"))}else if let Some(slot)=slots.get_mut(&key){
                    if resident.paused(&slot.binding.options){Err(error("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"))}
                    else if !slot.binding.pins.as_ref().is_some_and(|p|p.epoch==page.mailbox().epoch&&p.receiver_id==page.mailbox().receiver_id){Err(error("MAILBOX_EPOCH_MISMATCH"))}
                    else if slot.receive_fault.is_some(){Err(error("STREAM_SCOPE_QUARANTINED"))}
                    else{
                        let ids=page.items().iter().filter_map(|item|item.sealed_message_content().map(|body|body.key_id.clone())).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>();
                        let known=access.cached_mail_keys(&page.mailbox().workspace_id,&ids).unwrap_or_default();
                        store.ingest_with_keys(&identity,&page,64*1024*1024,&known).map(|cursor|{
                        // Wake consumers immediately. Only custody upload has
                        // a short non-extending coalescing window; an explicit
                        // application consume can acknowledge both facts.
                        if !page.items().is_empty()&&slot.custody_ack_not_before.is_none(){slot.custody_ack_not_before=Some(Instant::now()+Duration::from_millis(25));}
                        if let Some(p)=slot.binding.pins.as_mut(){p.after_sequence=cursor.item;p.after_control_sequence=cursor.control;}
                        if !slot.link_verified{slot.next_control=Instant::now();slot.presence.version=slot.presence.version.saturating_add(1);}
                        if store.key_missing(&slot.binding.options.workspace_id).unwrap_or(true){slot.missing_keys();}
                        slot.link_verified=true;slot.stream_id=Some(stream_id);slot.failures=0;slot.time_retries=0;slot.state("RECEIVER_LINK_VERIFIED",None);slot.notify();
                    })}
                }else{Err(error("WATCH_NOT_FOUND"))};
                if let Err(e)=&stored{if let Some(slot)=slots.get_mut(&key).filter(|s|s.receive_fault.is_none()&&!resident.paused(&s.binding.options)){slot.fail(Failure{no_effect:false,code:e.code.clone(),retryable:matches!(e.code.as_str(),"INBOX_CAPACITY"|"INBOX_STATE_FAILED"|"INBOX_CURSOR_CONFLICT"|"STREAM_GRANT_EXPIRED")});}}
                let _=reply.send(stored);
            },
            work=jobs.join_next_with_id(),if !jobs.is_empty()=>if let Some(work)=work{
                match work{
                    Err(e)=>{match kinds.remove(&e.id()){
                        Some(JobKind::Resident)=>resident.interrupted(),
                        Some(JobKind::Control(key,generation))=>if let Some(s)=slots.get_mut(&key){s.busy=false;s.control_cancel=None;if s.lifecycle==generation{s.fail(Failure::code("WATCH_TASK_FAILED"));}},
                        Some(JobKind::Pulse(key,generation))=>if let Some(s)=slots.get_mut(&key){s.pulse_busy=false;s.pulse_cancel=None;if s.lifecycle==generation{s.link_verified=false;s.pulse_retry_at=Instant::now()+Duration::from_secs(1);s.state("RECONNECTING",Some("PULSE_TASK_FAILED".into()));}},
                        Some(JobKind::Keys(workspace))=>{for s in slots.values_mut().filter(|s|s.enabled&&s.binding.options.workspace_id==workspace){s.presence.keys(json!({"state":"UNKNOWN","key_id":null,"epoch":null,"code":"KEY_TASK_FAILED"}));s.next_keys=Instant::now()+Duration::from_secs(2);s.next_control=Instant::now();s.notify();}},
                        Some(JobKind::Session)=>{session_busy=false;session_retry=Instant::now()+Duration::from_secs(2);},
                        Some(JobKind::Stream)=>{stream_running=false;active_generation=None;if let Some(c)=stream_cancel.take(){c.cancel();}stream_retry=Instant::now()+Duration::from_secs(1);for s in slots.values_mut(){s.link_verified=false;s.state("RECONNECTING",Some("STREAM_TASK_FAILED".into()));}},_=>{},
                    }},
                    Ok((id,work))=>{
                        let kind=kinds.remove(&id);
                        let stale=match &kind {
                            Some(JobKind::Control(key,generation))=>slots.get_mut(key).is_some_and(|s|{if s.lifecycle!=*generation{s.busy=false;s.control_cancel=None;true}else{false}}),
                            Some(JobKind::Pulse(key,generation))=>slots.get_mut(key).is_some_and(|s|{if s.lifecycle!=*generation{s.pulse_busy=false;s.pulse_cancel=None;true}else{false}}),
                            _=>false,
                        };
                        if stale{continue;}
                        match work{
                            Work::Resident(completed)=>{if let Err(e)=resident.completed(completed,&mut store,&identity){resident.record_error(e);}},
                            Work::Session(value)=>{session_busy=false;match value{Ok(value)=>match store.bind_service(&value.audience,&value.service_key){Ok(())=>session=Some(value),Err(e)=>{for s in slots.values_mut(){s.fail(Failure{no_effect:false,code:e.code.clone(),retryable:false});}}},Err(e)=>{session_retry=Instant::now()+Duration::from_secs(2);for s in slots.values_mut().filter(|s|!s.blocked){if e.retryable{s.state("RECONNECTING",Some(e.code.clone()));}else{s.fail(Failure{no_effect:false,code:e.code.clone(),retryable:false});}}}}},
                            Work::Inspect(key,value)=>if let Some(s)=slots.get_mut(&key){s.busy=false;s.control_cancel=None;match value{
                                Ok(value)=>{
                                    let mailbox=&value["mailbox"];let target=s.binding.options.destination(identity.actor_id(),&origin,&s.binding.namespace);
                                    let valid=mailbox["mailbox_id"]==s.binding.options.mailbox_id&&mailbox["membership_id"]==s.binding.options.membership_id&&mailbox["actor_id"]==identity.actor_id();
                                    if !valid{s.fail(Failure{no_effect:false,code:"MAILBOX_BINDING_MISMATCH".into(),retryable:false});continue;}
                                    // A previous receiver's live lease is not an invitation
                                    // to repeatedly submit fresh claims or request replace.
                                    if mailbox["lease_until"].as_u64().zip(mailbox["server_time"].as_u64()).is_some_and(|(until,now)|until>now){
                                        s.fail(Failure{no_effect:false,code:"MAILBOX_RECEIVER_BUSY".into(),retryable:true});continue;
                                    }
                                    let epoch=mailbox["epoch"].as_u64().unwrap_or(0);
                                    if epoch>0&&mailbox["receiver_id"]!=s.binding.receiver{s.fail(Failure{no_effect:false,code:"MAILBOX_STATE_RECOVERY_REQUIRED".into(),retryable:false});continue;}
                                    let mut body=json!({"claim_command_id":s.binding.claim_id,"mailbox_id":s.binding.options.mailbox_id,"receiver_id":s.binding.receiver,"expected_epoch":if epoch==0{None}else{Some(epoch)},"destination_digest":target,"replace":false,"event_format":peerwork_core::communication::WORKSPACE_EVENT_FORMAT});
                                    match store.receiver_proof(&identity,&s.binding,&body){Ok(proof)=>body["continuity_proof"]=json!(proof),Err(e)=>{s.fail(Failure{no_effect:false,code:e.code,retryable:false});continue;}}
                                    let wire=json!({"action":"structure.mailbox.claim","workspace_id":s.binding.options.workspace_id,"command_id":s.binding.claim_id,"body":body}).to_string();
                                    match store.freeze_claim(&s.binding,&wire){Ok(())=>s.binding.claim_wire=Some(wire),Err(e)=>s.fail(Failure{no_effect:false,code:e.code,retryable:false})}
                                },Err(e)=>s.fail(e),
                            }},
                            Work::Claim(key,value)=>if let Some(s)=slots.get_mut(&key){s.busy=false;s.control_cancel=None;match value{Ok(value)=>{
                                let m=&value["mailbox"];let target=s.binding.options.destination(identity.actor_id(),&origin,&s.binding.namespace);
                                let parsed=(||->Result<MailboxPins>{
                                    let p=MailboxPins{workspace_id:s.binding.options.workspace_id.clone(),mailbox_id:s.binding.options.mailbox_id.clone(),membership_id:s.binding.options.membership_id.clone(),receiver_id:s.binding.receiver.clone(),epoch:m["epoch"].as_u64().ok_or_else(||error("CLAIM_RESULT_INVALID"))?,destination_digest:target,binding_version:m["binding_version"].as_u64().ok_or_else(||error("CLAIM_RESULT_INVALID"))?,after_sequence:0,after_control_sequence:None};
                                    p.validate().map_err(|_|error("CLAIM_RESULT_INVALID"))?;
                                    if m["mailbox_id"]!=p.mailbox_id||m["membership_id"]!=p.membership_id||m["actor_id"]!=identity.actor_id()||m["destination_digest"]!=p.destination_digest{return Err(error("CLAIM_RESULT_INVALID"));}Ok(p)
                                })();
                                match parsed.and_then(|p|{store.register(&p)?;Ok(p)}){Ok(p)=>{s.binding.pins=Some(p);s.state("CLAIMED",None);},Err(e)=>s.fail(Failure{no_effect:false,code:e.code,retryable:false})}
                            },Err(mut e)=>{
                                if e.no_effect&&e.code=="MAILBOX_RECEIVER_BUSY"{
                                    e.retryable=true;
                                    // A late refusal after Stop stays in the original journal;
                                    // reattach can verify it again before advancing selection.
                                    if s.enabled{match store.rotate_refused_claim(&s.binding){
                                        Ok(id)=>{s.binding.claim_id=id;s.binding.claim_wire=None;},
                                        Err(saved)=>{e=Failure{no_effect:false,code:saved.code,retryable:false};}
                                    }}
                                }
                                s.fail(e)
                            }}},
                            Work::Pulse(key,started,version,keys_at,value)=>if let Some(s)=slots.get_mut(&key){s.pulse_busy=false;s.pulse_cancel=None;match value{Ok(value)=>{
                                let m=&value["mailbox"];let ttl=m["lease_until"].as_u64().unwrap_or(0).saturating_sub(m["server_time"].as_u64().unwrap_or(u64::MAX));
                                let remaining=Duration::from_millis(ttl.min(15000)).saturating_sub(started.elapsed());
                                if remaining.is_zero(){s.fail(Failure::code("MAILBOX_LEASE_EXPIRED"));}else{s.lease_until=Some(Instant::now()+remaining);s.presence.keys_uploaded_at=keys_at;s.next_control=s.presence.next_pulse(Instant::now()+if version==s.presence.version{Duration::from_secs(6)}else{Duration::ZERO});s.pulse_failures=0;s.pulse_retry_at=Instant::now();}
                            },Err(mut e)=>{s.lease_until=None;s.pulse_failures=s.pulse_failures.saturating_add(1);s.pulse_retry_at=Instant::now()+if e.capacity(){receiver_retry_delay(s.pulse_failures,true)}else{Duration::from_millis((250u64<<s.pulse_failures.min(4)).min(4000))};
                                if e.code=="MAILBOX_LEASE_EXPIRED"{e.retryable=true;}
                                if e.retryable{s.link_verified=false;s.state("RECONNECTING",Some(e.code));}else{s.fail(e);}
                            }}},
                            Work::Ack(key,items,consumed,value)=>if let Some(s)=slots.get_mut(&key){s.busy=false;s.control_cancel=None;match value{Ok(value)=>{
                                let stage=if consumed{"APPLICATION_CONSUMED"}else{"RECEIVER_STORED"};
                                let expected=items.iter().map(|(sequence,id)|json!({"sequence":sequence,"delivery_id":id})).collect::<Vec<_>>();
                                if value["stage"]!=stage||value["acknowledged"]!=json!(expected){s.fail(Failure{no_effect:false,code:"ACK_RESULT_INVALID".into(),retryable:false});}
                                else if let Err(e)=store.acknowledged(&s.binding.options.workspace_id,&s.binding.options.mailbox_id,&items,consumed){s.fail(Failure::code(&e.code));}else{
                                    if store.receiver_ack_pending(&s.binding.options.workspace_id,&s.binding.options.mailbox_id).is_ok_and(|pending|!pending){s.custody_ack_not_before=None;}
                                    s.failures=0;s.notify();
                                }
                            },Err(mut e)=>{if e.code=="MAILBOX_LEASE_EXPIRED"{s.lease_until=None;e.retryable=true;}s.fail(e)}}},
                            Work::Keys(workspace,selected,value)=>{
                                let mut data=match value{Ok(v)=>v,Err(e)=>json!({"state":if matches!(e.code.as_str(),"CONTENT_KEY_STATE"|"VERIFICATION_FAILED"){"INVALID"}else{"UNKNOWN"},"key_id":null,"epoch":null,"code":e.code})};
                                if let Some(missing)=data["missing_key_ids"].as_array(){
                                    let missing=missing.iter().filter_map(Value::as_str).map(str::to_string).collect();
                                    let mut checked=selected;if let Some(id)=data["key_id"].as_str(){if !checked.iter().any(|v|v==id){checked.push(id.into());}}
                                    if let Err(e)=store.keys_checked(&workspace,&checked,&missing){data=json!({"state":"INVALID","code":e.code});}
                                }
                                if store.key_missing(&workspace).unwrap_or(true)&&matches!(data["state"].as_str(),Some("READY"|"NOT_REQUIRED")){data["state"]=json!("MISSING");}
                                let _=store.wake_key_heads(&workspace);
                                for s in slots.values_mut().filter(|s|s.binding.options.workspace_id==workspace){
                                    let before=s.presence.version;s.presence.keys(data.clone());s.next_keys=Instant::now()+Duration::from_secs(if matches!(data["state"].as_str(),Some("READY"|"NOT_REQUIRED")){10}else{2});if before!=s.presence.version{s.next_control=Instant::now();}else{s.next_control=s.presence.next_pulse(s.next_control);}s.notify();
                                }
                            },
                            Work::Report(key,id,version,value)=>if let Some(s)=slots.get_mut(&key){
                                s.busy=false;s.control_cancel=None;
                                match value{
                                    Ok(value)=>{
                                        let report=&value["report"];
                                        if report["call_id"]!=id||report["report_sequence"].as_u64().is_none_or(|v|v<version){s.report_code=Some("HOST_REPORT_RESULT_INVALID".into());s.report_retry=Instant::now()+Duration::from_secs(3600);}
                                        else if let Err(e)=store.host_reported(&s.binding.options.workspace_id,&s.binding.options.mailbox_id,&id,version){s.report_code=Some(e.code);s.report_retry=Instant::now()+Duration::from_secs(1);}
                                        else{s.report_code=None;s.report_retry=Instant::now();}s.notify();
                                    },
                                    Err(e)=>{
                                        if scope_refusal(&e.code){s.lease_until=None;s.fail(Failure{no_effect:false,code:e.code.clone(),retryable:true});}
                                        // Report retry re-attests the same facts; temporary
                                        // quota/rate refusal does not invalidate their input.
                                        let retryable=e.retryable||matches!(e.code.as_str(),"RATE_LIMITED"|"RESOURCE_EXHAUSTED"|"CAPACITY_RESERVATION_EXHAUSTED");
                                        if !retryable&&!scope_refusal(&e.code){
                                            if let Err(store_error)=store.host_report_failed(&s.binding.options.workspace_id,&s.binding.options.mailbox_id,&id,version,&e.code){s.report_code=Some(store_error.code);s.report_retry=Instant::now()+Duration::from_secs(1);}else{s.report_code=Some(e.code);s.report_retry=Instant::now();}
                                        }else{s.report_code=Some(e.code);s.report_retry=Instant::now()+Duration::from_secs(2);}s.notify();
                                    }
                                }
                            },
                            Work::Stream(value)=>{stream_running=false;active_generation=None;stream_cancel=None;stream_scopes.clear();
                                let code=value.as_ref().err().map(|e|e.code.clone());
                                let fatal=value.as_ref().err().is_some_and(|e|!e.retryable);
                                if value.is_err(){stream_failures=stream_failures.saturating_add(1);}else{stream_failures=0;}
                                stream_retry=Instant::now()+if value.as_ref().err().is_some_and(Failure::capacity){receiver_retry_delay(stream_failures,true)}else{Duration::from_millis(if value.is_ok(){50}else{(250u64<<stream_failures.min(5)).min(8000)})};
                                for s in slots.values_mut().filter(|s|!s.blocked&&s.receive_fault.is_none()){s.link_verified=false;s.disconnects=s.disconnects.saturating_add(1);
                                    if fatal{s.fail(Failure{no_effect:false,code:code.clone().unwrap_or_else(||"STREAM_VERIFICATION_FAILED".into()),retryable:false});}
                                    else{s.state("RECONNECTING",code.clone());
                                        // Revalidate each fenced mailbox independently after a
                                        // union grant refusal; one revoked scope cannot strand peers.
                                        if code.as_deref().is_some_and(scope_refusal){s.lease_until=None;s.next_control=Instant::now();}
                                    }
                                }
                            },
                        }
                    },
                }
            },
            _=tick.tick(),if !slots.is_empty()=>{},
        }
        if !slots.values().any(|s|resident.paused(&s.binding.options)&&(s.busy||s.pulse_busy)) {
            match resident.next(&mut store,&identity) {
                Ok(Some(work))=>{let access=access.clone();let handle=jobs.spawn_local(async move{Work::Resident(work.execute(access).await)});kinds.insert(handle.id(),JobKind::Resident);},
                Ok(None)=>(),Err(e)=>resident.record_error(e),
            }
        }
        slots.retain(|_, s| resident.paused(&s.binding.options) || s.enabled || s.busy || s.pulse_busy || s.signals.iter().any(|c| !c.is_closed()));
        if slots.is_empty() {
            continue;
        }
        if session.is_none()
            && slots.values().any(|s| s.enabled && !s.blocked)
            && !session_busy
            && Instant::now() >= session_retry
        {
            session_busy = true;
            let access = access.clone();
            let stop = cancel.clone();
            let h = jobs.spawn_local(async move {
                Work::Session(access.mailbox_session(&stop).await.map_err(|e| {
                    let e = KernelPublicError::from(e);
                    Failure {
                        no_effect: false,
                        code: e.code.into(),
                        retryable: !matches!(
                            e.code,
                            "CAPABILITY_UNAVAILABLE"
                                | "CONFIG_INVALID"
                                | "DISCOVERY_CHANGED"
                                | "VERIFICATION_FAILED"
                        ),
                    }
                }))
            });
            kinds.insert(h.id(), JobKind::Session);
        }
        let Some(current) = &session else {
            continue;
        };
        if kinds.values().filter(|kind| matches!(kind, JobKind::Keys(_))).count() < 2 {
            let due = |s: &&Slot| s.enabled && !s.blocked && s.binding.pins.is_some()
                && s.lease_until.is_some_and(|until| until > Instant::now()) && Instant::now() >= s.next_keys
                && !kinds.values().any(|kind| matches!(kind,JobKind::Keys(ws) if ws==&s.binding.options.workspace_id));
            let selected = slots.values().filter(due).find(|s| last_key_workspace.as_ref().is_none_or(|last| &s.binding.options.workspace_id > last))
                .or_else(|| slots.values().find(due));
            if let Some(s) = selected {
                let workspace = s.binding.options.workspace_id.clone();
                last_key_workspace=Some(workspace.clone());
                let key_workspace=workspace.clone();
                let mailbox = s.binding.options.mailbox_id.clone();
                let needed = match store.key_batch(&identity, &workspace) {
                    Ok(ids) => ids,
                    Err(e) => {
                        for s in slots
                            .values_mut()
                            .filter(|s| s.binding.options.workspace_id == workspace)
                        {
                            s.presence.keys(json!({"state":"INVALID","code":e.code}));
                            s.next_keys = Instant::now() + Duration::from_secs(2);
                            s.next_control = Instant::now();
                            s.notify();
                        }
                        continue;
                    }
                };
                let access = access.clone();
                let stop = cancel.clone();
                let handle = jobs.spawn_local(async move {
                    let result = tokio::time::timeout(
                        Duration::from_secs(10),
                        access.prepare_mailbox_keys(&workspace, &mailbox, &needed, &stop),
                    )
                    .await;
                    let result = match result {
                        Ok(Ok(value)) => Ok(value),
                        Ok(Err(e)) => Err(Failure::code(KernelPublicError::from(e).code)),
                        Err(_) => Err(Failure::code("KEY_SYNC_TIMEOUT")),
                    };
                    Work::Keys(workspace, needed, result)
                });
                kinds.insert(handle.id(), JobKind::Keys(key_workspace));
            }
        }
        for workspace in slots
            .values()
            .filter(|s| s.enabled && !s.blocked)
            .map(|s| s.binding.options.workspace_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let _ = store.wake_key_heads(&workspace);
        }
        for (key, s) in slots.iter_mut() {
            s.signals.retain(|c| !c.is_closed());
            if s.link_verified && s.lease_until.is_none_or(|at| at <= Instant::now()) {
                s.link_verified=false;
                s.state("RECONNECTING",Some("MAILBOX_LEASE_EXPIRED".into()));
            }
            if !s.enabled || s.blocked || resident.paused(&s.binding.options) { continue; }
            let options=s.binding.options.clone();
            let access=access.clone();
            let stop=cancel.child_token();
            let work_key=key.clone();
            if let Some(pins)=&s.binding.pins {
                if !s.pulse_busy && kinds.values().filter(|kind|matches!(kind,JobKind::Pulse(..))).count()<8 && Instant::now()>=s.pulse_retry_at && (Instant::now()>=s.next_control || s.lease_until.is_none_or(|at|at<=Instant::now()+Duration::from_secs(3))) {
                    s.pulse_cancel=Some(stop.clone());
                    let mut fence=json!({"mailbox_id":pins.mailbox_id,"receiver_id":pins.receiver_id,"epoch":pins.epoch});
                    fence["ready"] = json!(s.receive_fault.is_none() && s.link_verified && !s.signals.is_empty());
                    if let Some(destination) = &options.host_destination {
                        fence["presence"] = s.presence.wire(
                            destination,
                            !store
                                .host_has_unknown(&options.workspace_id, &options.mailbox_id)
                                .unwrap_or(true),
                        );
                    }
                    let presence_version = s.presence.version;
                    let keys_at=options.host_destination.as_ref().and(s.presence.keys_at);
                    fence["event_format"]=json!(peerwork_core::communication::WORKSPACE_EVENT_FORMAT);
                    fence["execution_state"] = json!(if s.signals.is_empty() {
                        "OFFLINE"
                    } else {
                        "UNKNOWN"
                    });
                    let handle=jobs.spawn_local(async move {
                        let started = Instant::now();
                        Work::Pulse(
                            work_key,
                            started,
                            presence_version,
                            keys_at,
                            match tokio::time::timeout(Duration::from_secs(5), call(
                                &access,
                                "structure.mailbox.pulse",
                                Some(&options.workspace_id),
                                fence,
                                &stop,
                            )
                            ).await {
                                Ok(value)=>value,
                                Err(_)=>Err(Failure::code("PULSE_TIMEOUT")),
                            },
                        )
                    });
                    s.pulse_busy=true;
                    kinds.insert(handle.id(),JobKind::Pulse(key.clone(),s.lifecycle));
                    continue;

                }
            }
            if s.busy || Instant::now()<s.retry_at || kinds.values().filter(|k|matches!(k,JobKind::Control(..))).count()>=8 {continue;}
            s.control_cancel=Some(stop.clone());
            let job=if let Some(pins)=&s.binding.pins {
                let mut fence=json!({"mailbox_id":pins.mailbox_id,"receiver_id":pins.receiver_id,"epoch":pins.epoch});
                {
                    let selected = (|| {
                        let consumed = store.acknowledgements(
                            &options.workspace_id,
                            &options.mailbox_id,
                            true,
                        )?;
                        let stored = if s
                            .custody_ack_not_before
                            .is_some_and(|at| Instant::now() < at)
                        {
                            Vec::new()
                        } else {
                            store.acknowledgements(
                                &options.workspace_id,
                                &options.mailbox_id,
                                false,
                            )?
                        };
                        Ok::<_, crate::participant::ParticipantError>(
                            if !consumed.is_empty() && (s.prefer_consumed_ack || stored.is_empty())
                            {
                                (consumed, true)
                            } else {
                                (stored, false)
                            },
                        )
                    })();
                    match selected {
                        Ok((items, consumed)) if !items.is_empty() => {
                            // Alternate ready stages under mixed sustained load;
                            // neither custody nor application ACKs may starve.
                            s.prefer_consumed_ack = !consumed;
                            fence["stage"] = json!(if consumed {
                                "APPLICATION_CONSUMED"
                            } else {
                                "RECEIVER_STORED"
                            });
                            fence["items"] = json!(items
                                .iter()
                                .map(|(sequence, id)| json!({"sequence":sequence,"delivery_id":id}))
                                .collect::<Vec<_>>());
                            Some(jobs.spawn_local(async move {
                                Work::Ack(
                                    work_key,
                                    items,
                                    consumed,
                                    call(
                                        &access,
                                        "structure.mailbox.ack",
                                        Some(&options.workspace_id),
                                        fence,
                                        &stop,
                                    )
                                    .await,
                                )
                            }))
                        }
                        Err(e) => {
                            s.fail(Failure::code(&e.code));
                            None
                        }
                        _ if options.host_destination.is_some()
                            && Instant::now() >= s.report_retry =>
                        {
                            match store.pending_host_report(
                                &identity,
                                &s.binding.namespace,
                                &options,
                            ) {
                                Ok(Some((id, version, report))) => {
                                    fence["report"] = report;
                                    Some(jobs.spawn_local(async move {
                                        Work::Report(
                                            work_key,
                                            id,
                                            version,
                                            call(
                                                &access,
                                                "structure.mailbox.report",
                                                Some(&options.workspace_id),
                                                fence,
                                                &stop,
                                            )
                                            .await,
                                        )
                                    }))
                                }
                                Ok(None) => None,
                                Err(e) => {
                                    s.report_code = Some(e.code);
                                    s.report_retry = Instant::now() + Duration::from_secs(60);
                                    s.notify();
                                    None
                                }
                            }
                        }
                        _ => None,
                    }
                }
            } else if let Some(wire) = &s.binding.claim_wire {
                if let Err(e) = validate_claim(
                    &s.binding,
                    wire,
                    identity.actor_id(),
                    &origin,
                    &String::from_utf16(store.audience()).unwrap_or_default(),
                ) {
                    s.fail(Failure {
                        no_effect: false,
                        code: e.code,
                        retryable: false,
                    });
                    continue;
                }
                let wire = wire.clone();
                Some(jobs.spawn_local(async move {
                    Work::Claim(
                        work_key,
                        result(
                            access
                                .execute_structure_intent_async(wire.as_bytes(), &stop)
                                .await,
                        ),
                    )
                }))
            } else {
                Some(jobs.spawn_local(async move {
                    Work::Inspect(
                        work_key,
                        call(
                            &access,
                            "structure.mailbox.get",
                            Some(&options.workspace_id),
                            json!({"mailbox_id":options.mailbox_id}),
                            &stop,
                        )
                        .await,
                    )
                }))
            };
            if let Some(h) = job {
                s.busy = true;
                kinds.insert(h.id(), JobKind::Control(key.clone(),s.lifecycle));
            }
        }
        if Instant::now() >= compact_at {
            for s in slots
                .values()
                .filter(|s| s.enabled && s.binding.pins.is_some())
            {
                let _ = store.compact(
                    &s.binding.options.workspace_id,
                    &s.binding.options.mailbox_id,
                );
            }
            compact_at = Instant::now() + Duration::from_secs(1);
        }
        let mut selected = Vec::new();
        for s in slots.values().filter(|s| {
            s.enabled
                && !resident.paused(&s.binding.options)
                && !s.blocked
                && s.receive_fault.is_none()
                && s.lease_until
                    .is_some_and(|at| at > Instant::now() + Duration::from_secs(2))
        }) {
            if let Some(p) = &s.binding.pins {
                selected.push(p.clone());
            }
        }
        // Cursor changes do not restart a live stream; only scope/epoch changes do.
        let scope_key = selected
            .iter()
            .map(|p| json!([p.workspace_id, p.mailbox_id, p.receiver_id, p.epoch]))
            .collect::<Vec<_>>();
        let scope_key = json!(scope_key).to_string();
        if stream_running && stream_scopes != scope_key {
            active_generation = None;
            if let Some(c) = &stream_cancel {
                c.cancel();
            }
            for s in slots.values_mut().filter(|s| !s.blocked && s.receive_fault.is_none()) {
                s.link_verified = false;
                s.state("RECONNECTING", None);
            }
        }
        if !stream_running && !selected.is_empty() && Instant::now() >= stream_retry {
            stream_generation = stream_generation.saturating_add(1);
            let generation = stream_generation;
            active_generation = Some(generation);
            stream_running = true;
            stream_scopes = scope_key;
            let stop = cancel.child_token();
            stream_cancel = Some(stop.clone());
            let access = access.clone();
            let session = current.clone();
            let actor = identity.actor_id().to_owned();
            let frames = frames_tx.clone();
            let h = jobs.spawn_local(async move {
                Work::Stream(
                    stream(
                        &access, &session, &actor, selected, frames, generation, &stop,
                    )
                    .await,
                )
            });
            kinds.insert(h.id(), JobKind::Stream);
        }
    }
    cancel.cancel();
    if let Some(c) = stream_cancel {
        c.cancel();
    }
    while jobs.join_next().await.is_some() {}
}
fn slot(binding: Binding) -> Slot {
    Slot {
        enabled: true,
        binding,
        signals: Vec::new(),
        generation: 1,
        state: "LOCAL_CONFIGURED".into(),
        code: None,
        link_verified: false,
        stream_id: None,
        disconnects: 0,
        lease_until: None,
        next_control: Instant::now(),
        retry_at: Instant::now(),
        failures: 0,
        busy: false,
        control_cancel: None,
        blocked: false,
        receive_fault: None,
        time_retries: 0,
        pulse_busy: false,
        lifecycle: 1,
        pulse_retry_at: Instant::now(),
        pulse_failures: 0,
        pulse_cancel: None,
        presence: Default::default(),
        next_keys: Instant::now(),
        report_retry: Instant::now(),
        report_code: None,
        prefer_consumed_ack: true,
        custody_ack_not_before: None,
    }
}

/// HTTP chunks are transport fragments, not SSE frame boundaries. Scan each
/// byte once and bound the unfinished block while draining completed frames.
#[derive(Default)]
struct SseBuffer { bytes:Vec<u8>, scan:usize }
impl SseBuffer {
    fn append(&mut self,fragment:&[u8]) {self.bytes.extend_from_slice(fragment);}
    fn next(&mut self)->std::result::Result<Option<Vec<u8>>,&'static str> {
        let limit=MAX_FRAME_BYTES+8192;
        if let Some(relative)=self.bytes[self.scan..].windows(2).position(|pair|pair==b"\n\n") {
            let end=self.scan+relative+2;
            if end>limit{return Err("STREAM_FRAME_TOO_LARGE");}
            let block=self.bytes.drain(..end).collect();self.scan=0;return Ok(Some(block));
        }
        self.scan=self.bytes.len().saturating_sub(1);
        if self.bytes.len()>limit{return Err("STREAM_FRAME_TOO_LARGE");}
        Ok(None)
    }
}
/// Persist a rejection against authenticated local scopes, never against an
/// unverified routing field. All error paths use this boundary before retry.
async fn reject_frame(frames:&mpsc::Sender<Frame>,generation:u64,pins:&[MailboxPins],code:&str,wire:&[u8],cancel:&KernelCancellationToken)->Failure {
    let diagnostic=json!({"code":code,"phase":"FRAME_VERIFICATION","scope_authenticated":false,"stream_generation":generation,"frame_digest":sha256_hex(wire)});
    let keys=pins.iter().map(|p|format!("{}:{}",p.workspace_id,p.mailbox_id)).collect();
    let (reply,rx)=oneshot::channel();
    tokio::select! {_=cancel.cancelled()=>return Failure::code("CANCELLED"),sent=frames.send(Frame::Fault{generation,keys,diagnostic,reply})=>if sent.is_err(){return Failure::code("INBOX_DRIVER_STOPPED");}};
    tokio::select! {_=cancel.cancelled()=>{},_=rx=>{}};
    Failure::code("STREAM_SCOPE_VERIFICATION_FAILED")
}
fn frame_scope(data:&[u8],pins:&[MailboxPins])->std::result::Result<usize,&'static str> {
    let malformed=||"STREAM_FRAME_FORMAT_INVALID";
    let envelope=parse_wire_json_bounded(data,40,MAX_FRAME_BYTES).map_err(|_|malformed())?;
    let jws=envelope.get("proof").and_then(WireValue::as_string).ok_or_else(malformed)?;
    if jws.len()>8192 || !jws.is_ascii(){return Err(malformed());}
    let payload=decode_base64url(jws.split('.').nth(1).ok_or_else(malformed)?).map_err(|_|malformed())?;
    let routing=parse_wire_json_bounded(&payload,8,8192).map_err(|_|malformed())?;
    let ws=routing.get("workspace_id").and_then(WireValue::as_string);
    let mailbox=routing.get("mailbox_id").and_then(WireValue::as_string);
    pins.iter().position(|p|Some(p.workspace_id.as_str())==ws.as_deref()&&Some(p.mailbox_id.as_str())==mailbox.as_deref()).ok_or("STREAM_SCOPE_MISMATCH")
}
// The signed service deadline remains authoritative. Old60s grants retain
// their original lifetime; extended grants no longer reconnect after60s.
fn stream_remaining_ms(expires:u64,floor:u64)->u64 {
    expires.saturating_sub(floor).min(300_000)
}
async fn stream(
    access: &KernelAccess,
    session: &MailSession,
    actor: &str,
    mut pins: Vec<MailboxPins>,
    frames: mpsc::Sender<Frame>,
    generation: u64,
    cancel: &KernelCancellationToken,
) -> std::result::Result<(), Failure> {
    let scopes=pins.iter().map(|p|{let mut value=json!({"workspace_id":p.workspace_id,"mailbox_id":p.mailbox_id,"receiver_id":p.receiver_id,"epoch":p.epoch,"after_sequence":p.after_sequence,"after_control_sequence":p.after_control_sequence});if session.conversation_format{value["conversation_format"]=json!(peerwork_core::communication::CONVERSATION_FORMAT);}value}).collect::<Vec<_>>();
    let result = call(
        access,
        "structure.communication.stream.get",
        None,
        json!({"scopes":scopes}),
        cancel,
    )
    .await
    .map_err(|mut e| {
        if scope_refusal(&e.code) {
            e.retryable = true;
        }
        e
    })?;
    let grant = &result["stream"];
    for (p, scope) in pins.iter_mut().zip(
        grant["scopes"]
            .as_array()
            .ok_or_else(|| Failure::code("STREAM_GRANT_INVALID"))?,
    ) {
        // The ordinary receipt verifier already authenticated token/body scope equality.
        if p.after_control_sequence.is_none() {
            p.after_control_sequence = scope["after_control_sequence"].as_u64();
        }
    }
    let expires = grant["expires_at"]
        .as_u64()
        .ok_or_else(|| Failure::code("STREAM_GRANT_INVALID"))?;
    let stream_id = grant["stream_id"]
        .as_str()
        .ok_or_else(|| Failure::code("STREAM_GRANT_INVALID"))?;
    let token = grant["token"]
        .as_str()
        .ok_or_else(|| Failure::code("STREAM_GRANT_INVALID"))?;
    let floor = session.now().map_err(|e| Failure::code(&e.code))?;
    let remaining = stream_remaining_ms(expires,floor);
    if remaining == 0 {
        return Err(Failure::code("STREAM_GRANT_EXPIRED"));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(remaining);
    let (tx, rx) = oneshot::channel();
    tokio::select! {_=cancel.cancelled()=>return Ok(()),sent=frames.send(Frame::Bootstrap(generation,pins.clone(),tx))=>sent.map_err(|_|Failure::code("INBOX_DRIVER_STOPPED"))?};
    tokio::select! {_=cancel.cancelled()=>return Ok(()),stored=rx=>stored.map_err(|_|Failure::code("INBOX_DRIVER_STOPPED"))?.map_err(|e|Failure::code(&e.code))?};
    let mut response = session
        .transport
        .mailbox_stream(token, cancel)
        .await
        .map_err(|_| Failure::code("STREAM_UNAVAILABLE"))?;
    let mut buffer = SseBuffer::default();
    loop {
        let chunk = tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep_until(deadline)=>return Ok(()),chunk=response.chunk()=>chunk.map_err(|_|Failure::code("STREAM_DISCONNECTED"))?};
        let Some(chunk) = chunk else {
            return Err(Failure::code(if buffer.bytes.is_empty(){"STREAM_DISCONNECTED"}else{"STREAM_TRUNCATED"}));
        };
        for fragment in chunk.chunks(8192) {
            buffer.append(fragment);
            loop {
            let block=match buffer.next(){Ok(Some(block))=>block,Ok(None)=>break,Err(code)=>return Err(reject_frame(&frames,generation,&pins,code,&buffer.bytes,cancel).await)};
            let text=match std::str::from_utf8(&block){Ok(text)=>text,Err(_)=>return Err(reject_frame(&frames,generation,&pins,"STREAM_ENCODING_INVALID",&block,cancel).await)};
            let mut event = "";
            let mut data = "";
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("event: ") {
                    event = value;
                }
                if let Some(value) = line.strip_prefix("data: ") {
                    data = value;
                }
            }
            if event != "delivery" {
                continue;
            }
            let index=match frame_scope(data.as_bytes(),&pins){Ok(index)=>index,Err(code)=>return Err(reject_frame(&frames,generation,&pins,code,data.as_bytes(),cancel).await)};
            let p=&mut pins[index];
            let page = match verify_mailbox_frame_detailed(
                data.as_bytes(),
                &FramePins {
                    audience: &session.audience,
                    actor_id: actor,
                    stream_id,
                    mailbox: p,
                    service_key: &session.service_key,
                    server_time_floor: floor.saturating_sub(1000),
                    expires_at: expires,
                },
            ) {
                Ok(page) => page,
                Err(error) => {
                    let (tx, rx) = oneshot::channel();
                    let diagnostic=json!({"code":error.code(),"phase":"FRAME_VERIFICATION","scope_authenticated":error.authenticated_scope(),"stream_generation":generation,"frame_digest":sha256_hex(data.as_bytes()),"after_sequence":p.after_sequence,"after_control_sequence":p.after_control_sequence});
                    let keys=if error.authenticated_scope(){vec![format!("{}:{}",p.workspace_id,p.mailbox_id)]}else{pins.iter().map(|p|format!("{}:{}",p.workspace_id,p.mailbox_id)).collect()};
                    tokio::select! {_=cancel.cancelled()=>return Ok(()),sent=frames.send(Frame::Fault{generation,keys,diagnostic,reply:tx})=>sent.map_err(|_|Failure::code("INBOX_DRIVER_STOPPED"))?};
                    tokio::select! {_=cancel.cancelled()=>return Ok(()),_=rx=>{}};
                    if error==peerwork_core::communication::FrameVerificationError::Time {
                        access.refresh_mailbox_clock(cancel).await.map_err(|e|Failure::code(KernelPublicError::from(e).code))?;
                    }
                    return Err(Failure::code("STREAM_SCOPE_VERIFICATION_FAILED"));
                }
            };
            let checkpoint = page.checkpoint();
            let control = page.control_checkpoint();
            let (tx, rx) = oneshot::channel();
            tokio::select! {_=cancel.cancelled()=>return Ok(()),sent=frames.send(Frame::Data{generation,stream_id:stream_id.into(),page,valid_until:deadline,stored:tx})=>sent.map_err(|_|Failure::code("INBOX_DRIVER_STOPPED"))?};
            tokio::select! {_=cancel.cancelled()=>return Ok(()),stored=rx=>stored.map_err(|_|Failure::code("INBOX_DRIVER_STOPPED"))?.map_err(|e|Failure::code(&e.code))?};
            p.after_sequence = checkpoint;
            p.after_control_sequence = Some(control);
            }
        }
    }
}

#[cfg(test)]
mod reliability_tests {
    use super::*;
    fn selected()->Slot {
        slot(Binding{namespace:"program:test".into(),options:WatchOptions{workspace_id:"w".repeat(43),mailbox_id:"m".repeat(43),membership_id:"g".repeat(43),consumer_id:"test".into(),host_destination:None},receiver:"r".repeat(43),claim_id:"c".repeat(43),claim_wire:None,pins:None})
    }
    #[test]
    fn stream_deadline_honors_legacy_short_and_extended_signed_grants() {
        assert_eq!(stream_remaining_ms(61_000,1_000),60_000);
        assert_eq!(stream_remaining_ms(301_000,1_000),300_000);
        assert_eq!(stream_remaining_ms(241_000,1_000),240_000);
        assert_eq!(stream_remaining_ms(1_000,1_000),0);
        assert_eq!(stream_remaining_ms(999,1_000),0);
        assert_eq!(stream_remaining_ms(u64::MAX,1_000),300_000);
    }
    #[test]
    fn sse_fragmentation_and_coalescing_preserve_frames_and_bound_unfinished_input() {
        let frame=[b"event: delivery\ndata: ".as_slice(),&vec![b'x';MAX_FRAME_BYTES/2+128],b"\n\n"].concat();
        let combined=[frame.as_slice(),frame.as_slice()].concat();
        for chunk_size in [1,17,8192,combined.len()] {
            let mut buffer=SseBuffer::default();let mut blocks=Vec::new();
            for chunk in combined.chunks(chunk_size) {
                for fragment in chunk.chunks(8192) {
                    buffer.append(fragment);
                    while let Some(block)=buffer.next().unwrap(){blocks.push(block);}
                }
            }
            assert_eq!(blocks,vec![frame.clone(),frame.clone()]);assert!(buffer.bytes.is_empty());
        }
        let mut buffer=SseBuffer::default();let mut rejected=false;
        for fragment in vec![b'x';MAX_FRAME_BYTES+16384].chunks(8192) {
            buffer.append(fragment);
            if buffer.next().is_err(){rejected=true;break;}
        }
        assert!(rejected);
    }
    #[test]
    fn unrelated_async_results_cannot_clear_receive_or_authority_quarantine() {
        let mut s=selected();
        s.receive_fault=Some(json!({"code":"STREAM_ITEM_EVIDENCE_INVALID"}));
        s.state("BLOCKED",Some("STREAM_VERIFICATION_FAILED".into()));
        s.fail(Failure::code("NETWORK_TIMEOUT"));
        assert!(!s.blocked,"receive quarantine does not prohibit authenticated maintenance");
        assert_eq!(s.state,"BLOCKED");
        assert_eq!(s.code.as_deref(),Some("STREAM_VERIFICATION_FAILED"));
        s.state("RECEIVER_LINK_VERIFIED",None);
        assert_eq!(s.state,"BLOCKED");
        let mut s=selected();
        s.fail(Failure{no_effect:false,code:"MAILBOX_EPOCH_MISMATCH".into(),retryable:false});
        s.fail(Failure::code("NETWORK_TIMEOUT"));
        assert!(s.blocked);
        assert_eq!(s.code.as_deref(),Some("MAILBOX_EPOCH_MISMATCH"));
    }
    #[test]
    fn capacity_diagnostics_do_not_latch_receiver_or_erase_authority_failures() {
        for code in ["RESOURCE_EXHAUSTED", "CAPACITY_RESERVATION_EXHAUSTED"] {
            let mut s=selected();
            let e=Failure{no_effect:false,code:code.into(),retryable:false}.for_receiver();
            assert!(e.retryable);
            s.fail(e);
            assert!(!s.blocked);
            assert!(!s.link_verified);
            assert_eq!(s.state,"RECONNECTING");
            assert_eq!(s.code.as_deref(),Some(code));
            assert!(s.retry_at>Instant::now());
            s.state("RECEIVER_LINK_VERIFIED",None);
            assert_eq!(s.state,"RECEIVER_LINK_VERIFIED");
            s.fail(Failure{no_effect:false,code:"MAILBOX_EPOCH_MISMATCH".into(),retryable:false});
            s.fail(Failure{no_effect:false,code:code.into(),retryable:false}.for_receiver());
            assert!(s.blocked);
            assert_eq!(s.code.as_deref(),Some("MAILBOX_EPOCH_MISMATCH"));
        }
        let signed_refusal=Failure{no_effect:true,code:"RESOURCE_EXHAUSTED".into(),retryable:false}.for_receiver();
        assert!(!signed_refusal.retryable,"a signed terminal result cannot become an uncertain retry");
        assert_eq!(receiver_retry_delay(1,true),Duration::from_secs(2));
        assert_eq!(receiver_retry_delay(2,true),Duration::from_secs(4));
        assert_eq!(receiver_retry_delay(u8::MAX,true),Duration::from_secs(30));
    }
}
