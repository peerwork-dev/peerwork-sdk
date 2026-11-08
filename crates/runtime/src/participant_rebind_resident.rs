//! One resident maintenance job per engine. The watch owner keeps its original
//! InboxStore and KernelAccess. The legacy global pin remains set until host
//! publication is durable, so older readers cannot reopen a partial binding.
use super::*;
use crate::participant::{ParticipantClient, ParticipantConfig};
use crate::participant_dispatch::{HostConfig, HostSubscription};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::{Duration, Instant}};

#[derive(Clone)]
pub(crate) struct Source {
    pub subscription: HostSubscription,
    pub client: ParticipantClient,
}
#[derive(Clone)]
pub(crate) struct Selection {
    pub config: RuntimeConfig,
    pub request: HostRebindRequest,
    pub destination: HostBinding,
    pub sources: Vec<Source>,
}
pub(crate) enum Request {
    Preflight,
    Status,
    Lookup(HostRebindRequest),
    Prepare(Selection),
    Authorize { operation: String, sources: Vec<Source> },
    Published { operation: String },
    Recover { request:HostRebindRequest, decision:HostRebindRecoveryRequest },
    Problem { operation:String, problem:ParticipantError },
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub request: HostRebindRequest,
    pub original: RuntimeConfig,
    pub target: HostConfig,
    pub destination: HostBinding,
    pub subscriptions: Vec<HostSubscription>,
    pub access_scopes: Vec<Value>,
    pub local_committed: bool,
    pub finished: bool,
    pub aborted: bool,
    pub aborting: bool,
    pub rollback_ready: bool,
    pub resume: Vec<bool>,
    pub error: Option<ParticipantError>,
}
impl Snapshot {
    pub(crate) fn result(&self)->Value{
        json!({"state":if self.finished{"HOST_REBIND_READY"}else if self.aborted{"HOST_REBIND_ABORTED"}else{"PENDING"},
            "operation_id":self.request.operation_id,"engine":self.request.engine,"host":self.request.host,
            "destination_digest":if self.aborted{Value::Null}else{json!(self.destination.digest)},"selected_destination_digest":self.destination.digest,
            "subscriptions":if self.aborted{&self.subscriptions}else{&self.target.subscriptions},
            "engine_restarted":false,"runtime_restarted":false,"local_binding_committed":self.local_committed,
            "blocker":self.error,"recovery":if self.finished||self.aborted{"OBSERVE_CURRENT_HOST_AND_RECEIVER"}else{self.error.as_ref().map(|e|e.recovery.as_str()).unwrap_or("RESUME_SAME_HOST_REBIND_OPERATION")},
            "readiness":"CURRENT_RECEIVER_AND_HOST_READINESS_SEPARATELY_OBSERVED","model_response":"NOT_ATTESTED"})
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index { active: Option<String>, jobs: Vec<String> }
struct Active {
    store: SecureStateStore,
    aad: String,
    job: Job,
    sources: Vec<Source>,
    authorized: bool,
    drained:bool,
    progress: Option<(usize, core::ReplacementProgress)>,
    dirty: bool,
    inflight: bool,
    retry_at: Instant,
    error: Option<ParticipantError>,
    abort_scope:usize,
    abort_epoch:Option<u64>,
}
pub(crate) struct Controller {
    directory: PathBuf,
    config: ParticipantConfig,
    origin:String,
    logical: Vec<u8>,
    inbox_binding: String,
    owner: Arc<SecureStateStore>,
    index_store: SecureStateStore,
    index: Index,
    active: Option<Active>,
}
pub(crate) struct Work {
    operation: String,
    scope: usize,
    work: Step,
}
enum Step {
    Replace(core::ReplacementWork),
    AbortInspect {workspace:String,mailbox:String},
    AbortClose {workspace:String,mailbox:String,receiver:String,epoch:u64},
}
pub(crate) struct Completed { work: Work, result: Result<Value> }
impl Work {
    pub(crate) async fn execute(self, access: Arc<KernelAccess>) -> Completed {
        let result = match &self.work {
            Step::Replace(work)=>work.execute(&access).await,
            Step::AbortInspect{workspace,mailbox}=>call(&access,"structure.mailbox.get",workspace,json!({"mailbox_id":mailbox}),None).await,
            Step::AbortClose{workspace,mailbox,receiver,epoch}=>call(&access,"structure.mailbox.close",workspace,json!({"mailbox_id":mailbox,"receiver_id":receiver,"epoch":epoch}),None).await,
        };
        Completed { work: self, result }
    }
}
impl Controller {
    fn aad(logical: &[u8], id: &str) -> String {
        json!(["peerwork.host-rebind-job.v1", String::from_utf8_lossy(logical), id]).to_string()
    }
    fn save_index(&self) -> Result<()> {
        self.index_store.write_exact(&serde_json::to_vec(&self.index)
            .map_err(|_| error("HOST_REBIND_STATE_INVALID"))?)
            .map_err(|_| error("HOST_REBIND_STATE_FAILED"))
    }
    fn open_job(&self, id: &str, identity: &KernelIdentity) -> Result<Active> {
        let store = SecureStateStore::open(&self.directory.join(format!("resident-rebind-{id}.state")))
            .map_err(|_| error("HOST_REBIND_JOB_ALREADY_OWNED"))?;
        let aad = Self::aad(&self.logical, id);
        let job = load(&store, identity, &aad)?.ok_or_else(|| error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"))?;
        if job.pin.operation_id != id { return Err(error("HOST_REBIND_STATE_INVALID")); }
        self.check_engine(&job.original, &job.request.engine)?;
        Ok(Active { store, aad, job, sources: vec![], authorized: false, drained:false,progress: None,
            dirty: false, inflight: false, retry_at: Instant::now(), error: None, abort_scope:0,abort_epoch:None })
    }
    /// Called while the original engine/journal owner locks are held, before
    /// startup publishes readiness or attaches any persisted watch/dispatcher.
    pub(crate) fn open(config: &ParticipantConfig, identity: &KernelIdentity, origin: &str,
        owner: Arc<SecureStateStore>) -> Result<Self> {
        let authority = config.authority.clone().unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
        let logical = participant_owner::logical_binding(identity, origin, &authority);
        let index_store = SecureStateStore::open(&config.state_directory.join("resident-rebind-index.state"))
            .map_err(|_| error("HOST_REBIND_INDEX_ALREADY_OWNED"))?;
        let index: Index = index_store.read_exact().map_err(|_| error("HOST_REBIND_STATE_INVALID"))?
            .map(|wire| serde_json::from_slice(&wire).map_err(|_| error("HOST_REBIND_STATE_INVALID")))
            .transpose()?.unwrap_or_default();
        if index.jobs.len() > 64 || index.jobs.iter().any(|id| id.len()!=43 || !id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'))
            || index.jobs.iter().collect::<BTreeSet<_>>().len() != index.jobs.len()
            || index.active.as_ref().is_some_and(|id| !index.jobs.contains(id)) {
            return Err(error("HOST_REBIND_STATE_INVALID"));
        }
        let inbox_binding=json!({"format":"peerwork.participant-inbox.v1","actor":identity.actor_id(),"key":identity.key_id(),"origin":origin}).to_string();
        let mut out = Self { directory: config.state_directory.clone(), config: config.clone(), origin:origin.into(),logical,inbox_binding,
            owner, index_store, index, active: None };
        if let Some(id) = out.index.active.clone() {
            let mut active = out.open_job(&id, identity)?;
            if let Some(pin) = participant_owner::pending_pin(&out.owner, &out.logical)? {
                if pin != active.job.pin || active.job.ready || active.job.aborted { return Err(error("HOST_REBIND_OWNER_SELECTION_CHANGED")); }
            } else if !active.job.ready && !active.job.aborted {
                if participant_owner::completed_snapshot(&out.directory.join("engine-owner.state"),&out.logical,&active.job.pin)? {
                    // Durable host publication precedes completion; recognize
                    // the same completed revision after a final response crash.
                    if active.job.aborting.is_some(){active.job.aborted=true;}else{active.job.ready=true;}
                    save(&active.store,identity,&active.aad,&active.job)?;
                    out.index.active=None;out.save_index()?;
                }else{
                    participant_owner::begin(&out.owner, &out.logical, &active.job.pin)?;
                }
            } else {
                if !participant_owner::completed_snapshot(&out.directory.join("engine-owner.state"),
                    &out.logical, &active.job.pin)? { return Err(error("HOST_REBIND_OWNER_SELECTION_CHANGED")); }
                out.index.active = None;
                out.save_index()?;
            }
            if out.index.active.is_some() { out.active = Some(active); }
        } else {
            participant_owner::validate_ready(&out.owner, &out.logical)?;
        }
        Ok(out)
    }
    fn check_engine(&self, config: &RuntimeConfig, engine: &str) -> Result<()> {
        let selected = config.engines.iter().filter(|e| e.name == engine).collect::<Vec<_>>();
        if selected.len()!=1 { return Err(error("HOST_REBIND_SELECTION_INVALID")); }
        let e = selected[0].participant_config();
        let c = &self.config;
        if e.origin != c.origin || e.expected_actor != c.expected_actor || e.identity_path != c.identity_path
            || e.state_directory != c.state_directory || e.journal_path != c.journal_path || e.authority != c.authority
            || serde_json::to_value(&e.transport).ok() != serde_json::to_value(&c.transport).ok() {
            return Err(error("HOST_REBIND_ORIGINAL_ENGINE_MISMATCH"));
        }
        Ok(())
    }
    pub(crate) fn paused(&self, options: &WatchOptions) -> bool {
        self.active.as_ref().is_some_and(|a| !a.job.ready&&!a.job.aborted&&a.job.scopes.iter().any(|s| s.old.key()==options.key()))
    }
    pub(crate) fn paused_bindings(&self, inbox: &InboxStore) -> Result<Vec<Binding>> {
        self.active.as_ref().map(|a| a.job.scopes.iter().map(|s| {
            let mut selected=s.old.clone();
            if s.committed { selected.host_destination=Some(a.job.destination.digest.clone()); }
            inbox.selected_watch(&s.namespace, &selected).or_else(|problem|{
                if s.confirmed.is_none(){return Err(problem);}
                selected.host_destination=Some(a.job.destination.digest.clone());
                inbox.selected_watch(&s.namespace,&selected)
            })
        }).collect()).unwrap_or_else(|| Ok(vec![]))
    }
    fn snapshot_job(job: &Job, problem: Option<ParticipantError>,owner:&str) -> Result<Snapshot> {
        let target = job.target.hosts.iter().find(|h| h.name == job.request.host)
            .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))?.clone();
        let subscriptions = job.scopes.iter().map(|s| s.source_client.clone()
            .ok_or_else(|| error("HOST_REBIND_STATE_INVALID"))).collect::<Result<Vec<_>>>()?;
        let access_scopes=job.scopes.iter().map(|s| json!({"format":"peerwork.host-access.v1",
            "owner":owner,"namespace":s.namespace,"workspace_id":s.old.workspace_id,
            "mailbox_id":s.old.mailbox_id,"membership_id":s.old.membership_id,
            "destination_digest":job.destination.digest})).collect();
        Ok(Snapshot { request: job.request.clone(), original: job.original.clone(), target,
            destination: job.destination.clone(), subscriptions, access_scopes,
            local_committed: job.scopes.iter().all(|s| s.committed), finished: job.ready,
            aborted: job.aborted, aborting:job.aborting.is_some(),rollback_ready:false,resume:job.scopes.iter().map(|s|s.was_enabled).collect(),error: problem })
    }
    pub(crate) fn status(&self) -> Result<Option<Snapshot>> {
        self.active.as_ref().map(|a| {
            let mut snapshot=Self::snapshot_job(&a.job,a.error.clone(),&self.inbox_binding)?;
            snapshot.rollback_ready=a.job.aborting.is_some()&&a.abort_scope==a.job.scopes.len();
            for (index,enabled) in snapshot.resume.iter_mut().enumerate(){*enabled&=a.sources.get(index).is_some_and(|source|source.client.locally_live());}
            Ok(snapshot)
        }).transpose()
    }
    pub(crate) fn lookup(&self,request:&HostRebindRequest,identity:&KernelIdentity)->Result<Option<Snapshot>>{
        let id=token(json!(["peerwork.resident-host-rebind.v1",self.logical,self.directory,request.operation_id]));
        let selection=sha256_hex(serde_json::to_string(request).map_err(|_|error("HOST_REBIND_SELECTION_INVALID"))?.as_bytes());
        if let Some(a)=&self.active {
            if a.job.pin.operation_id!=id||a.job.pin.selection_digest!=selection{return Err(error("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));}
            return self.status();
        }
        if !self.index.jobs.contains(&id){return Ok(None);}
        let a=self.open_job(&id,identity)?;
        if a.job.pin.selection_digest!=selection{return Err(error("HOST_REBIND_ORIGINAL_SELECTION_REQUIRED"));}
        Self::snapshot_job(&a.job,None,&self.inbox_binding).map(Some)
    }
    pub(crate) fn prepare(&mut self, selected: Selection, inbox: &mut InboxStore,
        identity: &KernelIdentity) -> Result<Snapshot> {
        self.check_engine(&selected.config, &selected.request.engine)?;
        let r=&selected.request;
        if r.format!="peerwork.host-rebind.v1" || !identifier(&r.operation_id) || !identifier(&r.host)
            || selected.sources.is_empty() || selected.sources.len()>8 { return Err(error("HOST_REBIND_SELECTION_INVALID")); }
        let id=token(json!(["peerwork.resident-host-rebind.v1", self.logical, self.directory, r.operation_id]));
        let selection=sha256_hex(serde_json::to_string(r).map_err(|_|error("HOST_REBIND_SELECTION_INVALID"))?.as_bytes());
        if let Some(active)=&self.active {
            if active.job.pin.operation_id!=id || active.job.pin.selection_digest!=selection {
                return Err(error("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));
            }
            return Self::snapshot_job(&active.job, active.error.clone(),&self.inbox_binding);
        }
        if self.index.jobs.contains(&id) {
            let previous=self.open_job(&id,identity)?;
            if previous.job.pin.selection_digest!=selection { return Err(error("HOST_REBIND_ORIGINAL_SELECTION_REQUIRED")); }
            return Self::snapshot_job(&previous.job,None,&self.inbox_binding);
        }
        if self.index.jobs.len()>=64 { return Err(error("HOST_REBIND_JOB_LIMIT")); }
        let first=r.initial_subscriptions.is_some();
        let mut scopes=Vec::new();
        for source in &selected.sources {
            let c=&source.client; let sub=&source.subscription;
            if !c.locally_live() || c.actor_id()!=identity.actor_id() || c.origin()!=self.origin {
                return Err(error("HOST_REBIND_SOURCE_CLIENT_CHANGED"));
            }
            sub.watch.authorize(c.capability())?;
            let mut hosted=sub.watch.clone();hosted.host_destination=Some(selected.destination.digest.clone());
            hosted.authorize(c.capability())?;
            let binding=inbox.selected_watch(c.local_namespace(),&sub.watch)?;
            let expected=binding.pins.ok_or_else(||error("HOST_REBIND_MAILBOX_NOT_INITIALIZED"))?;
            expected.validate().map_err(|_|error("HOST_REBIND_PINS_INVALID"))?;
            if expected.receiver_id!=binding.receiver || expected.destination_digest!=sub.watch.destination(identity.actor_id(),&self.origin,c.local_namespace()) {
                return Err(error("HOST_REBIND_SELECTION_INVALID"));
            }
            if scopes.iter().any(|s:&Subscription|s.old.key()==sub.watch.key()) || expected.destination_digest==selected.destination.digest {
                return Err(error("HOST_REBIND_SELECTION_INVALID"));
            }
            if first { inbox.initial_host_scope(c.local_namespace(),&sub.watch,&expected)?; }
            else { inbox.host_scope_check(c.local_namespace(),&sub.watch)?;inbox.rebind_reports_unblocked(&sub.watch)?; }
            scopes.push(Subscription { namespace:c.local_namespace().into(), old:sub.watch.clone(), expected:Pins::from(&expected),
                claim_id:token(json!([id,scopes.len(),"replace"])),claim_wire:None,confirmed:None,committed:false,
                was_enabled:inbox.rebind_watch_enabled(c.local_namespace(),&sub.watch)?,rejected:vec![],refresh_epoch_on_retry:false,
                source_client:Some(sub.clone()) });
        }
        let mut target=selected.config.clone();
        if first { target.hosts.push(HostConfig{name:r.host.clone(),adapter:r.adapter.clone(),subscriptions:selected.sources.iter().map(|s|s.subscription.clone()).collect()}); }
        let host=target.hosts.iter_mut().find(|h|h.name==r.host).ok_or_else(||error("HOST_REBIND_SELECTION_INVALID"))?;
        host.adapter=r.adapter.clone();for s in &mut host.subscriptions{s.watch.host_destination=Some(selected.destination.digest.clone());}
        let host_key=host.key()?;
        let pin=MaintenancePin{operation_id:id.clone(),selection_digest:selection,expected_revision:participant_owner::revision(&self.owner,&self.logical)?};
        let job=Job{format:"peerwork.host-rebind-job.v1".into(),request:selected.request,pin,original:selected.config,target,
            destination:selected.destination,host_key,host_state_before:None,scopes,ready:false,decisions:vec![],aborting:None,aborted:false};
        let store=SecureStateStore::open(&self.directory.join(format!("resident-rebind-{id}.state"))).map_err(|_|error("HOST_REBIND_JOB_ALREADY_OWNED"))?;
        let aad=Self::aad(&self.logical,&id);save(&store,identity,&aad,&job)?;
        self.index.jobs.push(id.clone());self.index.active=Some(id);
        self.active=Some(Active{store,aad,job,sources:selected.sources,authorized:false,drained:false,progress:None,dirty:false,inflight:false,retry_at:Instant::now(),error:None,abort_scope:0,abort_epoch:None});
        self.save_index()?;
        let a=self.active.as_ref().unwrap();
        participant_owner::begin(&self.owner,&self.logical,&a.job.pin)?;
        for s in &a.job.scopes {inbox.disable_watch(&s.namespace,&s.old)?;}
        Self::snapshot_job(&a.job,None,&self.inbox_binding)
    }
    pub(crate) fn recover(&mut self,request:&HostRebindRequest,decision:&HostRebindRecoveryRequest,identity:&KernelIdentity)->Result<Snapshot>{
        if decision.format!="peerwork.host-rebind-recovery.v1"||!identifier(&decision.decision_id){return Err(error("HOST_REBIND_RECOVERY_SELECTION_INVALID"));}
        let snapshot=self.lookup(request,identity)?.ok_or_else(||error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"))?;
        if self.active.is_some(){self.save_index()?;let pin=&self.active.as_ref().unwrap().job.pin;participant_owner::begin(&self.owner,&self.logical,pin)?;}
        if let Some(a)=&mut self.active {
            validate_decision(&a.job,Some(decision))?;
            if a.inflight{return Err(error("HOST_REBIND_WORK_PENDING_RESUME_DECISION"));}
            if !a.job.decisions.iter().any(|d|d.decision_id==decision.decision_id){
                let engine=a.job.original.engines.iter().find(|e|e.name==a.job.request.engine).ok_or_else(||error("HOST_REBIND_STATE_INVALID"))?.clone();
                match decision.action {
                    HostRebindRecoveryAction::RetryRejected=>retry_rejected(&mut a.job,decision,identity,&engine)?,
                    HostRebindRecoveryAction::Abort=>begin_abort(&mut a.job,Some(decision),identity,&engine)?,
                }
                a.dirty=true;
                a.progress=None;a.error=None;a.retry_at=Instant::now();
                // The original drain must still be observed after restart.
                a.authorized=a.drained;
            }
            if a.dirty {save(&a.store,identity,&a.aad,&a.job)?;a.dirty=false;}
            return self.status()?.ok_or_else(||error("HOST_REBIND_STATE_INVALID"));
        }
        let id=token(json!(["peerwork.resident-host-rebind.v1",self.logical,self.directory,request.operation_id]));
        let previous=self.open_job(&id,identity)?;validate_decision(&previous.job,Some(decision))?;Ok(snapshot)
    }
    pub(crate) fn authorize(&mut self, operation: &str, sources: Vec<Source>, inbox:&InboxStore) -> Result<()> {
        // Retry partial prepare publication before any network stage. Both
        // persistent indexes and the legacy exclusion must precede claim IO.
        self.save_index()?;
        let pin=&self.active.as_ref().ok_or_else(||error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"))?.job.pin;
        participant_owner::begin(&self.owner,&self.logical,pin)?;
        let a=self.active.as_mut().ok_or_else(||error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"))?;
        if a.job.request.operation_id!=operation {return Err(error("HOST_REBIND_ORIGINAL_SELECTION_REQUIRED"));}
        if sources.is_empty() && (a.job.aborting.is_some()||a.job.scopes.iter().any(|s|s.claim_wire.is_some()||s.confirmed.is_some())) {
            for s in &a.job.scopes {inbox.host_scope_drained(&s.old)?;}
            a.sources.clear();a.drained=true;a.authorized=true;a.retry_at=Instant::now();return Ok(());
        }
        if sources.len()!=a.job.scopes.len(){return Err(error("HOST_REBIND_SOURCE_CLIENT_CHANGED"));}
        for (s,current) in a.job.scopes.iter().zip(&sources) {
            inbox.host_scope_drained(&s.old)?;
            if s.source_client.as_ref().is_none_or(|old| serde_json::to_value(old).ok()!=serde_json::to_value(&current.subscription).ok())
                || current.client.local_namespace()!=s.namespace || !current.client.locally_live() {
                return Err(error("HOST_REBIND_SOURCE_CLIENT_CHANGED"));
            }
        }
        // Before any frozen replacement, an interrupted prepare may have left
        // an old binary free to advance the original receiver. Re-pin only that
        // same receiver/version and its monotonic cursors, never frozen claims.
        for s in &mut a.job.scopes {
            if s.claim_wire.is_none() && s.confirmed.is_none() && s.rejected.is_empty() {
                let current=inbox.selected_watch(&s.namespace,&s.old)?.pins.ok_or_else(||error("HOST_REBIND_MAILBOX_NOT_INITIALIZED"))?;
                if current.receiver_id!=s.expected.receiver_id||current.destination_digest!=s.expected.destination_digest
                    ||current.binding_version!=s.expected.binding_version||current.epoch<s.expected.epoch
                    ||current.after_sequence<s.expected.after_sequence {
                    return Err(error("HOST_REBIND_ORIGINAL_BINDING_CHANGED"));
                }
                s.expected=Pins::from(&current);a.dirty=true;
            }
        }
        a.sources=sources;a.drained=true;a.authorized=true;a.retry_at=Instant::now();Ok(())
    }
    pub(crate) fn next(&mut self, inbox: &mut InboxStore, identity: &KernelIdentity) -> Result<Option<Work>> {
        let Some(a)=self.active.as_mut() else{return Ok(None);};
        if a.inflight || !a.authorized || Instant::now()<a.retry_at {return Ok(None);}
        if a.dirty {
            save(&a.store,identity,&a.aad,&a.job)?;
            if let Some((_,progress))=&mut a.progress{progress.saved();}a.dirty=false;
        }
        if a.job.aborting.is_some() {
            let index=a.abort_scope;
            let Some(scope)=a.job.scopes.get(index) else{return Ok(None);};
            let work=if let Some(epoch)=a.abort_epoch {
                Step::AbortClose{workspace:scope.old.workspace_id.clone(),mailbox:scope.old.mailbox_id.clone(),receiver:scope.expected.receiver_id.clone(),epoch}
            }else{Step::AbortInspect{workspace:scope.old.workspace_id.clone(),mailbox:scope.old.mailbox_id.clone()}};
            a.inflight=true;return Ok(Some(Work{operation:a.job.pin.operation_id.clone(),scope:index,work}));
        }
        let Some(index)=a.job.scopes.iter().position(|s|!s.committed) else{return Ok(None);};
        if (a.sources.len()!=a.job.scopes.len()||a.sources.iter().any(|s|!s.client.locally_live())) && a.job.scopes[index].claim_wire.is_none() {
            return Err(error("HOST_REBIND_SOURCE_CLIENT_CHANGED"));
        }
        if a.job.scopes[index].confirmed.is_some() {
            let selected=a.job.scopes[index].local_replacement(&a.job.pin.operation_id,&a.job.destination)?;
            if inbox.host_rebind_page(&selected)?.is_some() {a.job.scopes[index].committed=true;a.dirty=true;a.progress=None;}
            return Ok(None);
        }
        if a.progress.as_ref().is_none_or(|(i,_)|*i!=index) {a.progress=Some((index,core::ReplacementProgress::new(&a.job.scopes[index])));}
        let progress=&mut a.progress.as_mut().unwrap().1;
        let Some(work)=progress.next(&a.job.scopes[index],inbox,identity)? else{return Err(error("HOST_REBIND_STATE_INVALID"));};
        if matches!(&work,core::ReplacementWork::Freeze) {
            match progress.apply(&work,&Value::Null,&mut a.job.scopes[index],inbox,identity,&self.config.expected_actor,&a.job.destination.digest) {
                Ok(dirty)=>a.dirty|=dirty,
                Err(problem)=>{a.progress=None;return Err(problem);},
            }
            return Ok(None);
        }
        a.inflight=true;
        Ok(Some(Work{operation:a.job.pin.operation_id.clone(),scope:index,work:Step::Replace(work)}))
    }
    pub(crate) fn completed(&mut self, completed: Completed, inbox:&mut InboxStore,identity:&KernelIdentity)->Result<()> {
        let a=self.active.as_mut().ok_or_else(||error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"))?;
        if completed.work.operation!=a.job.pin.operation_id || !a.inflight {return Err(error("HOST_REBIND_WORK_SELECTION_CHANGED"));}
        a.inflight=false;
        match completed.result {
            Ok(value)=>{
                let applied=(||{
                    let index=completed.work.scope;
                    match &completed.work.work {
                        Step::Replace(work)=>{
                            let (selected,progress)=a.progress.as_mut().ok_or_else(||error("HOST_REBIND_STATE_INVALID"))?;
                            if *selected!=index{return Err(error("HOST_REBIND_WORK_SELECTION_CHANGED"));}
                            a.dirty|=progress.apply(work,&value,&mut a.job.scopes[index],inbox,identity,&self.config.expected_actor,&a.job.destination.digest)?;
                        },
                        Step::AbortInspect{..}=>{
                            if index!=a.abort_scope{return Err(error("HOST_REBIND_WORK_SELECTION_CHANGED"));}
                            a.abort_epoch=Some(a.job.scopes[index].abort_inspection(&value,&self.config.expected_actor,inbox)?);
                        },
                        Step::AbortClose{..}=>{
                            if index!=a.abort_scope{return Err(error("HOST_REBIND_WORK_SELECTION_CHANGED"));}
                            a.job.scopes[index].restore_aborted_watch(inbox,&a.job.pin.operation_id,a.job.aborting.as_deref(),index)?;
                            // Remain fenced until the host registry has restored
                            // original sources and owner completion is durable.
                            inbox.disable_watch(&a.job.scopes[index].namespace,&a.job.scopes[index].old)?;
                            a.abort_scope+=1;a.abort_epoch=None;
                        },
                    }
                    Ok(())
                })();
                if let Err(problem)=applied {a.progress=None;a.abort_epoch=None;a.error=Some(problem);a.retry_at=Instant::now()+Duration::from_secs(2);}
                else{a.error=None;}
            },
            Err(problem)=>{
                // Discard only the disposable cursor. A frozen claim retains
                // its exact wire/ID; uncertain submissions are reconciled.
                a.progress=None;a.abort_epoch=None;
                if problem.effect_certainty=="REJECTED_NO_EFFECT" && a.job.aborting.is_none()
                    && matches!(&completed.work.work,Step::Replace(core::ReplacementWork::Submit{..})) {a.authorized=false;}
                a.error=Some(problem);a.retry_at=Instant::now()+Duration::from_secs(2);
            }
        }Ok(())
    }
    pub(crate) fn record_error(&mut self, mut problem:ParticipantError) {
        if let Some(a)=&mut self.active {
            if problem.effect_certainty=="NOT_SUBMITTED"&&a.job.scopes.iter().any(|s|s.claim_wire.is_some()||s.confirmed.is_some()) {
                problem.effect_certainty="UNKNOWN".into();problem.recovery="RESUME_SAME_HOST_REBIND_OPERATION".into();
            }
            a.error=Some(problem);a.retry_at=Instant::now()+Duration::from_secs(2);
        }
    }
    pub(crate) fn interrupted(&mut self) {
        if let Some(a)=&mut self.active {a.inflight=false;a.progress=None;a.abort_epoch=None;}
        self.record_error(error("HOST_REBIND_TASK_INTERRUPTED_RESUME_ORIGINAL"));
    }
    /// Runtime host registry calls this only after durable source publication.
    pub(crate) fn published(&mut self, operation:&str, identity:&KernelIdentity)->Result<Snapshot>{
        let a=self.active.as_mut().ok_or_else(||error("HOST_REBIND_ORIGINAL_JOB_REQUIRED"))?;
        if a.job.request.operation_id!=operation || a.inflight || if a.job.aborting.is_some(){a.abort_scope!=a.job.scopes.len()}else{!a.job.scopes.iter().all(|s|s.committed)} {return Err(error("HOST_REBIND_NOT_COMMITTED"));}
        if a.dirty {save(&a.store,identity,&a.aad,&a.job)?;a.dirty=false;}
        participant_owner::complete(&self.owner,&self.logical,&a.job.pin)?;
        if a.job.aborting.is_some(){a.job.aborted=true;}else{a.job.ready=true;}save(&a.store,identity,&a.aad,&a.job)?;
        let result=Self::snapshot_job(&a.job,None,&self.inbox_binding)?;
        self.index.active=None;self.save_index()?;self.active=None;Ok(result)
    }
}


#[cfg(test)]
#[path="participant_rebind_resident_tests.rs"]
mod tests;
