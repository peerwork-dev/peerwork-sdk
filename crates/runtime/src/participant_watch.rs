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
        verify_mailbox_frame, FramePins, MailboxPins, VerifiedMailboxPage, MAX_FRAME_BYTES,
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
        code: code.into(),
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
    fn destination(&self, actor: &str, origin: &str, namespace: &str) -> String {
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
    Bindings {
        namespace: String,
        capability: Capability,
        reply: oneshot::Sender<Result<Vec<WatchOptions>>>,
    },
    Host {
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
        let state = if self.enabled { state } else { "LOCAL_STOPPED" };
        if self.state != state || self.code != code {
            self.state = state.into();
            self.code = code;
            self.notify();
        }
    }
    fn fail(&mut self, e: Failure) {
        self.link_verified = false;
        self.failures = self.failures.saturating_add(1);
        self.retry_at =
            Instant::now() + Duration::from_millis((250u64 << self.failures.min(5)).min(8000));
        self.blocked = !e.retryable;
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
    fn code(code: &str) -> Self {
        Self {
            no_effect: false,
            code: code.into(),
            retryable: true,
        }
    }
}
fn result(
    out: std::result::Result<StructureIntentOutcome, crate::kernel_access::KernelAccessError>,
) -> std::result::Result<Value, Failure> {
    match out {
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
    }
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
        || body.object_len() != Some(7)
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
    Session,
    Stream,
    Control(String),
    Keys,
}
enum Work {
    Session(std::result::Result<MailSession, Failure>),
    Inspect(String, std::result::Result<Value, Failure>),
    Claim(String, std::result::Result<Value, Failure>),
    Pulse(String, Instant, u64, std::result::Result<Value, Failure>),
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
    Fault(u64, String, oneshot::Sender<()>),
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
        slots.insert(binding.options.key(), slot(binding));
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
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            command=commands.recv()=>match command{
                None=>break,
                Some(Command::Bindings{namespace,capability,reply})=>{
                    let selected=slots.values().filter(|s|s.enabled&&s.binding.namespace==namespace&&s.binding.options.authorize(&capability).is_ok()).map(|s|s.binding.options.clone()).collect::<Vec<_>>();let _=reply.send(Ok(selected));
                },
                Some(Command::Host{namespace,options,operation,reply})=>{
                    use crate::participant_inbox::{HostOperation as Op,HostReply as Reply};
                    let value=(||->Result<Reply>{
                        let selected=slots.get(&options.key()).filter(|s|s.binding.namespace==namespace&&s.binding.options==options);
                        let live=selected.is_some_and(|s|s.enabled&&s.link_verified&&!s.blocked&&s.lease_until.is_some_and(|until|until>Instant::now()));
                        Ok(match operation{
                            Op::RetirementPlan=>Reply::Retirement(store.host_retirement_plan(&identity,&namespace,&options)?),
                            Op::RetirementCommit(plan)=>{store.host_retirement_commit(&identity,&namespace,&options,&plan)?;Reply::Saved},
                            Op::AccessScope=>Reply::AccessScope(store.host_access_scope(&namespace,&options)?),
                            Op::ReconcileDue=>Reply::Call(if live{store.host_reconcile_due(&identity,&namespace,&options)?}else{None}),
                            Op::Presence{value,observed_at}=>{store.host_scope_check(&namespace,&options)?;let s=slots.get_mut(&options.key()).ok_or_else(||error("WATCH_NOT_FOUND"))?;s.presence.host_observed(value,observed_at)?;s.next_control=Instant::now();s.notify();Reply::Saved},
                            Op::Attach(host)=>{if selected.is_none(){return Err(error("WATCH_NOT_FOUND"));}store.host_attach(&namespace,&options,&host)?;Reply::Saved},
                            Op::Due{limit}=>Reply::Due(if live{store.host_due(&namespace,&options,limit)?}else{Vec::new()}),
                            Op::Begin{item,frame}=>{if !live{return Err(error("WATCH_NOT_CONNECTED"));}Reply::Call(store.host_begin(&identity,&namespace,&options,&item,frame)?)},
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
                        let slot=slots.get_mut(&options.key()).ok_or_else(||error("WATCH_NOT_FOUND"))?;slot.enabled=false;if let Some(c)=slot.control_cancel.take(){c.cancel();}slot.link_verified=false;slot.state("LOCAL_STOPPED",None);Ok(())
                    });let _=reply.send(stopped);
                },
                Some(Command::Attach{namespace,options,reply})=>{
                    let attached=(||->Result<_>{
                        if let Some(s)=slots.get_mut(&options.key()){s.signals.retain(|s|!s.is_closed());if s.signals.len()>=16{return Err(error("WATCH_LISTENER_LIMIT"));}}
                        let binding=store.attach_watch(&identity, &namespace,&options)?;
                        let entry=slots.entry(options.key()).or_insert_with(||slot(binding));entry.enabled=true;
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
                        Ok(WatchSnapshot{presence:slot.presence.local(),reporting_code:slot.report_code.clone(),workspace_id:options.workspace_id.clone(),mailbox_id:options.mailbox_id.clone(),generation:slot.generation,state:slot.state.clone(),receiver_link_verified:slot.link_verified,model_response:"NOT_ATTESTED".into(),code:slot.code.clone(),checkpoint:cursor.as_ref().map(|c|c.item).unwrap_or(0),control_checkpoint:cursor.and_then(|c|c.control),items,next_after,
                            receiver_ack_pending:store.receiver_ack_pending(&options.workspace_id,&options.mailbox_id)?,
                            application_ack_pending:!store.acknowledgements(&options.workspace_id,&options.mailbox_id,true)?.is_empty(),stream_id:slot.stream_id.clone(),disconnects:slot.disconnects})
                    })();let _=reply.send(value);
                },
                Some(Command::Consume{namespace,options,items,reply})=>{
                    let value=(||->Result<()>{
                        let slot=slots.get_mut(&options.key()).filter(|s|s.binding.namespace==namespace&&s.binding.options==options).ok_or_else(||error("WATCH_NOT_FOUND"))?;
                        store.consume(&options.workspace_id,&options.mailbox_id,&items.iter().map(|r|(r.sequence,r.delivery_id.clone())).collect::<Vec<_>>())?;
                        slot.next_control=Instant::now();slot.notify();Ok(())
                    })();let _=reply.send(value);
                },
            },
            frame=frames.recv()=>if let Some(frame)=frame{
                let (page,stream_id,valid_until,reply)=match frame{
                    Frame::Fault(generation,key,reply)=>{
                        if active_generation==Some(generation){if let Some(s)=slots.get_mut(&key){s.fail(Failure{no_effect:false,code:"STREAM_VERIFICATION_FAILED".into(),retryable:false});}}
                        let _=reply.send(());continue;
                    },
                    Frame::Bootstrap(generation,scopes,reply)=>{
                        if active_generation!=Some(generation){let _=reply.send(Err(error("WATCH_STREAM_REPLACED")));continue;}
                        let bootstrap=(||->Result<()>{for p in scopes{
                            let key=format!("{}:{}",p.workspace_id,p.mailbox_id);
                            let slot=slots.get_mut(&key).ok_or_else(||error("WATCH_NOT_FOUND"))?;
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
                    if !slot.binding.pins.as_ref().is_some_and(|p|p.epoch==page.mailbox().epoch&&p.receiver_id==page.mailbox().receiver_id){Err(error("MAILBOX_EPOCH_MISMATCH"))}
                    else{
                        let ids=page.items().iter().filter_map(|item| match item.message()?.content(){peerwork_core::communication::MessageContent::WorkspaceE2ee{body}=>Some(body.key_id.clone()),_=>None}).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>();
                        let known=access.cached_mail_keys(&page.mailbox().workspace_id,&ids).unwrap_or_default();
                        store.ingest_with_keys(&identity,&page,64*1024*1024,&known).map(|cursor|{
                        // Wake consumers immediately. Only custody upload has
                        // a short non-extending coalescing window; an explicit
                        // application consume can acknowledge both facts.
                        if !page.items().is_empty()&&slot.custody_ack_not_before.is_none(){slot.custody_ack_not_before=Some(Instant::now()+Duration::from_millis(25));}
                        if let Some(p)=slot.binding.pins.as_mut(){p.after_sequence=cursor.item;p.after_control_sequence=cursor.control;}
                        if !slot.link_verified{slot.next_control=Instant::now();slot.presence.version=slot.presence.version.saturating_add(1);}
                        if store.key_missing(&slot.binding.options.workspace_id).unwrap_or(true){slot.missing_keys();}
                        slot.link_verified=true;slot.stream_id=Some(stream_id);slot.failures=0;slot.state("RECEIVER_LINK_VERIFIED",None);slot.notify();
                    })}
                }else{Err(error("WATCH_NOT_FOUND"))};
                if let Err(e)=&stored{if let Some(slot)=slots.get_mut(&key){slot.fail(Failure{no_effect:false,code:e.code.clone(),retryable:matches!(e.code.as_str(),"INBOX_CAPACITY"|"INBOX_STATE_FAILED"|"INBOX_CURSOR_CONFLICT"|"STREAM_GRANT_EXPIRED")});}}
                let _=reply.send(stored);
            },
            work=jobs.join_next_with_id(),if !jobs.is_empty()=>if let Some(work)=work{
                match work{
                    Err(e)=>{match kinds.remove(&e.id()){
                        Some(JobKind::Control(key))=>if let Some(s)=slots.get_mut(&key){s.busy=false;s.control_cancel=None;s.fail(Failure::code("WATCH_TASK_FAILED"));},
                        Some(JobKind::Keys)=>{for s in slots.values_mut().filter(|s|s.enabled){s.presence.keys(json!({"state":"UNKNOWN","key_id":null,"epoch":null,"code":"KEY_TASK_FAILED"}));s.next_keys=Instant::now()+Duration::from_secs(2);s.next_control=Instant::now();s.notify();}},
                        Some(JobKind::Session)=>{session_busy=false;session_retry=Instant::now()+Duration::from_secs(2);},
                        Some(JobKind::Stream)=>{stream_running=false;active_generation=None;if let Some(c)=stream_cancel.take(){c.cancel();}stream_retry=Instant::now()+Duration::from_secs(1);for s in slots.values_mut(){s.link_verified=false;s.state("RECONNECTING",Some("STREAM_TASK_FAILED".into()));}},_=>{},
                    }},
                    Ok((id,work))=>{
                        kinds.remove(&id);
                        match work{
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
                                    let mut body=json!({"claim_command_id":s.binding.claim_id,"mailbox_id":s.binding.options.mailbox_id,"receiver_id":s.binding.receiver,"expected_epoch":if epoch==0{None}else{Some(epoch)},"destination_digest":target,"replace":false});
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
                            Work::Pulse(key,started,version,value)=>if let Some(s)=slots.get_mut(&key){s.busy=false;s.control_cancel=None;match value{Ok(value)=>{
                                let m=&value["mailbox"];let ttl=m["lease_until"].as_u64().unwrap_or(0).saturating_sub(m["server_time"].as_u64().unwrap_or(u64::MAX));
                                let remaining=Duration::from_millis(ttl.min(15000)).saturating_sub(started.elapsed());
                                if remaining.is_zero(){s.fail(Failure::code("MAILBOX_LEASE_EXPIRED"));}else{s.lease_until=Some(Instant::now()+remaining);s.next_control=Instant::now()+if version==s.presence.version{Duration::from_secs(6)}else{Duration::ZERO};s.failures=0;}
                            },Err(e)=>{s.lease_until=None;s.fail(e);}}},
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
                                    s.presence.keys(data.clone());s.next_keys=Instant::now()+Duration::from_secs(if matches!(data["state"].as_str(),Some("READY"|"NOT_REQUIRED")){10}else{2});s.next_control=Instant::now();s.notify();
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
                                stream_retry=Instant::now()+Duration::from_millis(if value.is_ok(){50}else{(250u64<<stream_failures.min(5)).min(8000)});
                                for s in slots.values_mut().filter(|s|!s.blocked){s.link_verified=false;s.disconnects=s.disconnects.saturating_add(1);
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
        slots.retain(|_, s| s.enabled || s.busy || s.signals.iter().any(|c| !c.is_closed()));
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
        if !kinds.values().any(|kind| matches!(kind, JobKind::Keys)) {
            if let Some(s) = slots.values().find(|s| {
                s.enabled
                    && !s.blocked
                    && s.binding.pins.is_some()
                    && s.lease_until.is_some_and(|until| until > Instant::now())
                    && Instant::now() >= s.next_keys
            }) {
                let workspace = s.binding.options.workspace_id.clone();
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
                kinds.insert(handle.id(), JobKind::Keys);
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
                s.link_verified = false;
                s.state("RECONNECTING", Some("MAILBOX_LEASE_EXPIRED".into()));
            }
            if !s.enabled || s.busy || s.blocked || Instant::now() < s.retry_at {
                continue;
            }
            if kinds
                .values()
                .filter(|k| matches!(k, JobKind::Control(_)))
                .count()
                >= 8
            {
                break;
            }
            let options = s.binding.options.clone();
            let access = access.clone();
            let stop = cancel.child_token();
            s.control_cancel = Some(stop.clone());
            let work_key = key.clone();
            let job = if let Some(pins) = &s.binding.pins {
                let mut fence = json!({"mailbox_id":pins.mailbox_id,"receiver_id":pins.receiver_id,"epoch":pins.epoch});
                if Instant::now() >= s.next_control
                    || s.lease_until
                        .is_none_or(|at| at <= Instant::now() + Duration::from_secs(3))
                {
                    fence["ready"] = json!(s.link_verified && !s.signals.is_empty());
                    if let Some(destination) = &options.host_destination {
                        fence["presence"] = s.presence.wire(
                            destination,
                            !store
                                .host_has_unknown(&options.workspace_id, &options.mailbox_id)
                                .unwrap_or(true),
                        );
                    }
                    let presence_version = s.presence.version;
                    fence["execution_state"] = json!(if s.signals.is_empty() {
                        "OFFLINE"
                    } else {
                        "UNKNOWN"
                    });
                    Some(jobs.spawn_local(async move {
                        let started = Instant::now();
                        Work::Pulse(
                            work_key,
                            started,
                            presence_version,
                            call(
                                &access,
                                "structure.mailbox.pulse",
                                Some(&options.workspace_id),
                                fence,
                                &stop,
                            )
                            .await,
                        )
                    }))
                } else {
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
                kinds.insert(h.id(), JobKind::Control(key.clone()));
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
                && !s.blocked
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
            for s in slots.values_mut().filter(|s| !s.blocked) {
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
        presence: Default::default(),
        next_keys: Instant::now(),
        report_retry: Instant::now(),
        report_code: None,
        prefer_consumed_ack: true,
        custody_ack_not_before: None,
    }
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
    let scopes=pins.iter().map(|p|json!({"workspace_id":p.workspace_id,"mailbox_id":p.mailbox_id,"receiver_id":p.receiver_id,"epoch":p.epoch,"after_sequence":p.after_sequence,"after_control_sequence":p.after_control_sequence})).collect::<Vec<_>>();
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
    let remaining = expires.saturating_sub(floor).min(60000);
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
    let mut buffer = Vec::new();
    loop {
        let chunk = tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep_until(deadline)=>return Ok(()),chunk=response.chunk()=>chunk.map_err(|_|Failure::code("STREAM_DISCONNECTED"))?};
        let Some(chunk) = chunk else {
            return Ok(());
        };
        if buffer.len() + chunk.len() > MAX_FRAME_BYTES + 8192 {
            return Err(Failure::code("STREAM_FRAME_TOO_LARGE"));
        }
        buffer.extend_from_slice(&chunk);
        while let Some(end) = buffer.windows(2).position(|w| w == b"\n\n") {
            let block = buffer.drain(..end + 2).collect::<Vec<_>>();
            let text = std::str::from_utf8(&block)
                .map_err(|_| Failure::code("STREAM_ENCODING_INVALID"))?;
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
            let envelope = parse_wire_json_bounded(data.as_bytes(), 40, MAX_FRAME_BYTES)
                .map_err(|_| Failure::code("STREAM_FRAME_INVALID"))?;
            let jws = envelope
                .get("proof")
                .and_then(WireValue::as_string)
                .ok_or_else(|| Failure::code("STREAM_FRAME_INVALID"))?;
            if jws.len() > 8192 || !jws.is_ascii() {
                return Err(Failure::code("STREAM_FRAME_INVALID"));
            }
            let payload = decode_base64url(
                jws.split('.')
                    .nth(1)
                    .ok_or_else(|| Failure::code("STREAM_FRAME_INVALID"))?,
            )
            .map_err(|_| Failure::code("STREAM_FRAME_INVALID"))?;
            let routing = parse_wire_json_bounded(&payload, 8, 8192)
                .map_err(|_| Failure::code("STREAM_FRAME_INVALID"))?;
            let ws = routing.get("workspace_id").and_then(WireValue::as_string);
            let box_id = routing.get("mailbox_id").and_then(WireValue::as_string);
            let p = pins
                .iter_mut()
                .find(|p| {
                    Some(p.workspace_id.as_str()) == ws.as_deref()
                        && Some(p.mailbox_id.as_str()) == box_id.as_deref()
                })
                .ok_or_else(|| Failure::code("STREAM_SCOPE_MISMATCH"))?;
            let page = match verify_mailbox_frame(
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
                Err(_) => {
                    let (tx, rx) = oneshot::channel();
                    let key = format!("{}:{}", p.workspace_id, p.mailbox_id);
                    tokio::select! {_=cancel.cancelled()=>return Ok(()),sent=frames.send(Frame::Fault(generation,key,tx))=>sent.map_err(|_|Failure::code("INBOX_DRIVER_STOPPED"))?};
                    tokio::select! {_=cancel.cancelled()=>return Ok(()),_=rx=>{}};
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
