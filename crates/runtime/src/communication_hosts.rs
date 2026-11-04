//! Narrow live host subscriptions. A physical dispatcher survives role/scope
//! additions; only the separately authenticated runtime administrator selects it.
use super::*;
use crate::participant_dispatch::{HostConfig, HostSubscription, RunningHost};
pub(super) struct Hosts {
    store: Arc<SecureStateStore>,
    configs: Vec<HostConfig>,
    base_configs:Vec<HostConfig>,
    jobs: BTreeMap<String, RunningHost>,
    blocked: Vec<Value>,
    suppressed_base: Vec<HostConfig>,
    reservations: BTreeMap<String,(BTreeSet<String>,String,String)>,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedHosts { format:String, configs:Vec<HostConfig>, suppressed_base:Vec<HostConfig> }
fn decode_saved(wire:&[u8])->Result<(Vec<HostConfig>,Vec<HostConfig>)>{
    let value=peerwork_core::strict_json::parse_strict_json(wire).map_err(|_|local("HOST_REGISTRY_RECOVERY_REQUIRED"))?;
    if value.is_array(){return Ok((serde_json::from_value(value).map_err(|_|local("HOST_REGISTRY_RECOVERY_REQUIRED"))?,vec![]));}
    let saved:SavedHosts=serde_json::from_value(value).map_err(|_|local("HOST_REGISTRY_RECOVERY_REQUIRED"))?;
    if saved.format!="peerwork.runtime-hosts.v2"||saved.suppressed_base.len()>64{return Err(local("HOST_REGISTRY_RECOVERY_REQUIRED"));}
    Ok((saved.configs,saved.suppressed_base))
}
fn encoded(configs:&[HostConfig],suppressed:&[HostConfig])->Result<Vec<u8>>{
    let wire=if suppressed.is_empty(){serde_json::to_vec(configs)}else{
        serde_json::to_vec(&SavedHosts{format:"peerwork.runtime-hosts.v2".into(),configs:configs.to_vec(),suppressed_base:suppressed.to_vec()})
    }.map_err(|_|local("HOST_REGISTRY_INVALID"))?;
    if wire.len()>512*1024{return Err(local("HOST_REGISTRY_LIMIT"));}Ok(wire)
}
fn same_config(a:&HostConfig,b:&HostConfig)->bool{serde_json::to_value(a).ok()==serde_json::to_value(b).ok()}
fn base_active(base:&HostConfig,suppressed:&[HostConfig])->Result<bool>{
    let matching=suppressed.iter().filter(|old|old.name==base.name).collect::<Vec<_>>();
    if matching.is_empty(){return Ok(true);}
    if matching.iter().any(|old|same_config(old,base)){return Ok(false);}
    Err(local("HOST_REBIND_BASE_CONFIGURATION_CHANGED"))
}
fn merge(configs: &mut Vec<HostConfig>, incoming: HostConfig) -> Result<()> {
    let key = incoming.key()?;
    for old in configs.iter_mut() {
        if old.key()? == key {
            if old.adapter != incoming.adapter {
                return Err(local("HOST_SELECTION_CONFLICT"));
            }
            for mut source in incoming.subscriptions {
                // An omitted destination selects this already verified host;
                // it is not a request to erase its explicit binding. Keep one
                // canonical subscription when connect repeats after rebind.
                if source.watch.host_destination.is_none() {
                    if let Some(existing)=old.subscriptions.iter().find(|e| {
                        let mut same=e.watch.clone();same.host_destination=None;
                        e.client==source.client&&same==source.watch
                    }) {source.watch=existing.watch.clone();}
                }
                if let Some(existing) = old
                    .subscriptions
                    .iter_mut()
                    .find(|s| s.client == source.client && s.watch == source.watch)
                {
                    *existing = source;
                } else {
                    old.subscriptions.push(source);
                }
            }
            if old.subscriptions.len() > 8 {
                return Err(local("HOST_SUBSCRIPTION_LIMIT"));
            }
            return Ok(());
        }
        if old.name == incoming.name {
            return Err(local("HOST_SELECTION_CONFLICT"));
        }
    }
    if configs.len() >= 8 {
        return Err(local("HOST_CONFIG_LIMIT"));
    }
    configs.push(incoming);
    Ok(())
}
fn sources(
    config: &HostConfig,
    clients: &BTreeMap<String, ParticipantClient>,
    generations: &BTreeMap<String, Option<u64>>,
) -> Result<Vec<(ParticipantClient, WatchOptions)>> {
    let selected: Vec<_> = config
        .subscriptions
        .iter()
        .map(|s| {
            let client = clients
                .get(&s.client)
                .ok_or_else(|| local("HOST_CLIENT_NOT_FOUND"))?;
            if !client.locally_live() {
                return Err(local("HOST_CLIENT_REVOKED"));
            }
            let generation = generations
                .get(&s.client)
                .ok_or_else(|| local("HOST_CLIENT_NOT_FOUND"))?;
            if generation != &s.client_generation {
                return Err(local(
                    if generation.is_some() && s.client_generation.is_none() {
                        "HOST_CLIENT_GENERATION_REQUIRED"
                    } else {
                        "HOST_CLIENT_BINDING_CHANGED"
                    },
                ));
            }
            s.watch.authorize(client.capability())?;
            Ok((client.clone(), s.watch.clone()))
        })
        .collect::<Result<_>>()?;
    for (index, (client, watch)) in selected.iter().enumerate() {
        for (other, previous) in &selected[..index] {
            if watch.key() == previous.key() && (!client.same_client(other) || watch != previous) {
                return Err(local("HOST_SUBSCRIPTION_CONFLICT"));
            }
        }
    }
    Ok(selected)
}
fn active_configs(
    configs: &[HostConfig],
    clients: &BTreeMap<String, ParticipantClient>,
    generations: &BTreeMap<String, Option<u64>>,
) -> (Vec<HostConfig>, Vec<Value>) {
    let mut active = Vec::new();
    let mut blocked = Vec::new();
    for config in configs {
        let mut selected = config.clone();
        selected.subscriptions.clear();
        for source in &config.subscriptions {
            let mut one = config.clone();
            one.subscriptions = vec![source.clone()];
            match sources(&one,clients,generations){
                Ok(_)=>selected.subscriptions.push(source.clone()),
                Err(problem)=>blocked.push(json!({"name":config.name,"client":source.client,"workspace_id":source.watch.workspace_id,"mailbox_id":source.watch.mailbox_id,"code":problem.code,"state":"BLOCKED"})),
            }
        }
        if !selected.subscriptions.is_empty() {
            match sources(&selected,clients,generations){
                Ok(_)=>active.push(selected),
                Err(problem)=>blocked.push(json!({"name":config.name,"code":problem.code,"state":"BLOCKED","scope":"PHYSICAL_HOST_SELECTION"})),
            }
        }
    }
    (active, blocked)
}
impl Hosts {
    pub fn open(
        directory: &Path,
        base: &[HostConfig],
        clients: &BTreeMap<String, ParticipantClient>,
        generations: &BTreeMap<String, Option<u64>>,
        cancel: KernelCancellationToken,
    ) -> Result<Self> {
        let store = Arc::new(
            SecureStateStore::open(&directory.join("runtime-hosts.state"))
                .map_err(|_| local("HOST_REGISTRY_RECOVERY_REQUIRED"))?,
        );
        let (saved,suppressed_base) = match store
            .read_exact()
            .map_err(|_| local("HOST_REGISTRY_RECOVERY_REQUIRED"))?
        {
            Some(wire) => decode_saved(&wire)?,
            None => (Vec::new(),Vec::new()),
        };
        if saved.len() > 8 {
            return Err(local("HOST_CONFIG_LIMIT"));
        }
        let mut configs = Vec::new();
        for config in base {
            if base_active(config,&suppressed_base)? {merge(&mut configs,config.clone())?;}
        }
        for config in &saved {
            merge(&mut configs, config.clone())?;
        }
        let (active, blocked) = active_configs(&configs, clients, generations);
        for config in &active {
            sources(config, clients, generations)?;
        }
        let started = crate::participant_dispatch::start(&active, clients, directory, cancel)?;
        let mut keys = active
            .iter()
            .map(HostConfig::key)
            .collect::<Result<Vec<_>>>()?;
        keys.sort();
        let jobs = keys.into_iter().zip(started).collect();
        Ok(Self {
            store,
            configs,
            base_configs:base.to_vec(),
            jobs,
            blocked,
            suppressed_base,reservations:Default::default(),
        })
    }
    pub fn statuses(&self) -> Vec<Value> {
        let mut values: Vec<Value> = self
            .jobs
            .iter()
            .map(|(key, job)| {
                let mut value = job
                    .status
                    .lock()
                    .map(|v| v.clone())
                    .unwrap_or_else(|_| json!({"state":"UNKNOWN"}));
                value["selection_id"] = json!(key);
                if let Some(config)=self.configs.iter().find(|c|c.key().ok().as_ref()==Some(key)) {
                    value["source_bindings"]=json!(config.subscriptions);
                    value["source_name"]=json!(config.name);
                }
                value
            })
            .collect();
        if !self.blocked.is_empty() {
            values.push(json!({"state":"BLOCKED_SOURCES","sources":self.blocked,"model_response":"NOT_ATTESTED"}));
        }
        values
    }
    pub async fn ensure(
        &mut self,
        config: HostConfig,
        clients: &BTreeMap<String, ParticipantClient>,
        generations: &BTreeMap<String, Option<u64>>,
        directory: &Path,
        cancel: KernelCancellationToken,
    ) -> Result<Value> {
        let key = config.key()?;
        if self.reservations.values().any(|(scopes,target,name)|target==&key||name==&config.name||config.subscriptions.iter().any(|s|scopes.contains(&s.watch.key()))) {
            return Err(local("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));
        }
        sources(&config, clients, generations)?;
        let mut desired = self.configs.clone();
        merge(&mut desired, config)?;
        let (active, blocked) = active_configs(&desired, clients, generations);
        let selected = active
            .iter()
            .find(|c| c.key().is_ok_and(|k| k == key))
            .ok_or_else(|| local("HOST_REGISTRY_INVALID"))?
            .clone();
        let selected_sources = sources(&selected, clients, generations)?;
        if let Some(job) = self.jobs.get(&key) {
            if job.task.is_finished() {
                return Err(local("HOST_DISPATCHER_RECOVERY_REQUIRED"));
            }
            job.validate_sources(&selected_sources)?;
        }
        self.blocked = blocked;
        let wire = encoded(&desired,&self.suppressed_base)?;
        if encoded(&self.configs,&self.suppressed_base).ok().as_ref() != Some(&wire) {
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || store.write_exact(&wire))
                .await
                .map_err(|_| local("HOST_REGISTRY_WRITE_FAILED"))?
                .map_err(|_| local("HOST_REGISTRY_WRITE_FAILED"))?;
            self.configs = desired;
        }
        if let Some(job) = self.jobs.get(&key) {
            job.set_sources(selected_sources)?;
        } else {
            let mut started =
                crate::participant_dispatch::start(&[selected], clients, directory, cancel)?;
            self.jobs.insert(key.clone(), started.remove(0));
        }
        let observed = self.jobs[&key]
            .status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| json!({"state":"UNKNOWN"}));
        Ok(
            json!({"state":"HOST_SELECTION_REGISTERED","selection_id":key,"observation":observed,"engine_restarted":false,"model_response":"NOT_ATTESTED"}),
        )
    }
    pub async fn remove_clients(
        &mut self,
        names: &BTreeSet<String>,
        clients: &BTreeMap<String, ParticipantClient>,
        generations: &BTreeMap<String, Option<u64>>,
    ) -> Result<()> {
        let mut desired = self.configs.clone();
        for config in &mut desired {
            config.subscriptions.retain(|s| !names.contains(&s.client));
        }
        desired.retain(|c| !c.subscriptions.is_empty());
        let (active, blocked) = active_configs(&desired, clients, generations);
        // Remove actual dispatch references before attempting durable cleanup.
        // A failed write leaves the persisted revocation available on restart.
        for (key, job) in &self.jobs {
            let selected = active.iter().find(|c| c.key().is_ok_and(|k| k == *key));
            let selected = match selected {
                Some(config) => sources(config, clients, generations)?,
                None => Vec::new(),
            };
            job.set_sources(selected)?;
        }
        self.blocked = blocked;
        let wire = encoded(&desired,&self.suppressed_base)?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.write_exact(&wire))
            .await
            .map_err(|_| local("HOST_REGISTRY_WRITE_FAILED"))?
            .map_err(|_| local("HOST_REGISTRY_WRITE_FAILED"))?;
        self.configs = desired;
        Ok(())
    }
    pub async fn close(&mut self) {
        let jobs = std::mem::take(&mut self.jobs);
        for (_, job) in jobs {
            let _ = job.task.await;
        }
    }
    pub(super) fn configurations(&self)->Vec<HostConfig>{self.configs.clone()}
    pub(super) fn preflight_rebind(&self, request:&crate::participant_rebind::HostRebindRequest)->Result<Vec<HostSubscription>>{
        let sources=if let Some(selected)=&request.initial_subscriptions {
            if self.configs.iter().any(|h|h.name==request.host||h.subscriptions.iter().any(|s|selected.iter().any(|a|a.watch.key()==s.watch.key()))) {
                return Err(local("HOST_INITIAL_SELECTION_INVALID"));
            }selected.clone()
        }else{self.configs.iter().find(|h|h.name==request.host).ok_or_else(||local("HOST_REBIND_SELECTION_INVALID"))?.subscriptions.clone()};
        let target=HostConfig{name:request.host.clone(),adapter:request.adapter.clone(),subscriptions:sources.clone()};
        let key=target.key()?;
        if sources.is_empty()||sources.len()>8{return Err(local("HOST_REBIND_SELECTION_INVALID"));}
        for config in self.configs.iter().filter(|h|h.key().ok().as_ref()==Some(&key)) {
            if config.adapter!=target.adapter && config.subscriptions.iter().any(|s|!sources.iter().any(|a|a.client==s.client&&a.watch==s.watch)) {
                return Err(local("HOST_REBIND_SELECT_ONE_HOST_GROUP"));
            }
        }
        Ok(sources)
    }
    pub(super) fn reserve_rebind(&mut self,snapshot:&crate::participant_rebind::resident::Snapshot)->Result<()> {
        let scopes=snapshot.subscriptions.iter().map(|s|s.watch.key()).collect::<BTreeSet<_>>();
        let key=format!("{}:{}",snapshot.request.engine,snapshot.request.operation_id);
        let target=snapshot.target.key()?;
        if self.reservations.iter().any(|(other,(old,physical,_))|other!=&key&&(!old.is_disjoint(&scopes)||physical==&target)) {
            return Err(local("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));
        }
        self.reservations.insert(key,(scopes,target,snapshot.request.host.clone()));Ok(())
    }
    pub(super) fn drain_rebind(&mut self,snapshot:&crate::participant_rebind::resident::Snapshot)->Result<bool>{
        self.reserve_rebind(snapshot)?;
        let keys=snapshot.subscriptions.iter().map(|s|s.watch.key()).collect::<BTreeSet<_>>();
        let mut done=true;
        for (key,job) in &self.jobs {
            if self.configs.iter().filter(|h|h.key().ok().as_ref()==Some(key)).any(|h|h.subscriptions.iter().any(|s|keys.contains(&s.watch.key()))) {
                job.request_drain(&keys)?;done&=job.drain_complete(&keys)?;
            }
        }Ok(done)
    }
    /// Only fully drained original groups can release a physical owner. Other
    /// subscriptions keep their existing dispatcher and host connection.
    pub(super) fn take_drained_dispatchers(&mut self,snapshot:&crate::participant_rebind::resident::Snapshot)->Result<Vec<RunningHost>>{
        let scopes=snapshot.subscriptions.iter().map(|s|s.watch.key()).collect::<BTreeSet<_>>();
        let keys=self.jobs.keys().filter(|key|{
            let selected=self.configs.iter().filter(|h|h.key().ok().as_ref()==Some(*key)).flat_map(|h|h.subscriptions.iter()).collect::<Vec<_>>();
            !selected.is_empty()&&selected.iter().all(|s|scopes.contains(&s.watch.key()))
        }).cloned().collect::<Vec<_>>();
        let mut stopped=Vec::new();
        for key in keys {
            let job=self.jobs.get(&key).unwrap();
            if !job.drain_complete(&scopes)?{return Err(local("HOST_REBIND_ORIGINAL_DISPATCHER_PENDING"));}
            let job=self.jobs.remove(&key).unwrap();job.cancel.cancel();stopped.push(job);
        }Ok(stopped)
    }
    pub(super) fn rebind_adapter(&self,snapshot:&crate::participant_rebind::resident::Snapshot)->Result<Option<Arc<std::sync::Mutex<crate::communication_host::Host>>>> {
        let key=snapshot.target.key()?;
        let Some(job)=self.jobs.get(&key)else{return Ok(None);};
        if self.configs.iter().filter(|c|c.key().ok().as_ref()==Some(&key)).any(|c|c.adapter!=snapshot.target.adapter){return Err(local("HOST_SELECTION_CONFLICT"));}
        job.borrowed_adapter()?.map(Some).ok_or_else(||local("HOST_REBIND_TARGET_HOST_NOT_READY"))
    }
    pub(super) async fn publish_rebind(&mut self,snapshot:&crate::participant_rebind::resident::Snapshot,
        clients:&BTreeMap<String,ParticipantClient>,generations:&BTreeMap<String,Option<u64>>,directory:&Path,cancel:KernelCancellationToken)->Result<()> {
        if !snapshot.local_committed{return Err(local("HOST_REBIND_NOT_COMMITTED"));}
        let keys=snapshot.subscriptions.iter().map(|s|s.watch.key()).collect::<BTreeSet<_>>();
        let mut desired=self.configs.clone();
        let mut suppressed=self.suppressed_base.clone();
        for original in &self.base_configs {
            if original.subscriptions.iter().any(|s|keys.contains(&s.watch.key()))&&!suppressed.iter().any(|old|same_config(old,original)) {
                suppressed.push(original.clone());
            }
        }
        if suppressed.len()>64{return Err(local("HOST_REGISTRY_LIMIT"));}
        for config in &mut desired {config.subscriptions.retain(|s|!keys.contains(&s.watch.key()));}
        desired.retain(|h|!h.subscriptions.is_empty());
        merge(&mut desired,snapshot.target.clone())?;
        // We own the dispatcher lifecycle. Open its pin only if no resident
        // dispatcher holds it; an identical already-running target is reused.
        let physical=snapshot.target.key()?;
        if !self.jobs.contains_key(&physical) {
            let pin=SecureStateStore::open(&directory.join(format!("host-{physical}.state"))).map_err(|_|local("HOST_REBIND_TARGET_DISPATCHER_STILL_OWNED"))?;
            pin.write_exact(&serde_json::to_vec(&snapshot.destination).map_err(|_|local("HOST_BINDING_INVALID"))?).map_err(|_|local("HOST_STATE_FAILED"))?;
        }
        let wire=encoded(&desired,&suppressed)?;let store=self.store.clone();
        tokio::task::spawn_blocking(move||store.write_exact(&wire)).await.map_err(|_|local("HOST_REGISTRY_WRITE_FAILED"))?.map_err(|_|local("HOST_REGISTRY_WRITE_FAILED"))?;
        self.configs=desired;self.suppressed_base=suppressed;
        let (active,blocked)=active_configs(&self.configs,clients,generations);self.blocked=blocked;
        if let Some(config)=active.iter().find(|h|h.key().ok().as_ref()==Some(&physical)) {
            let selected=sources(config,clients,generations)?;
            if let Some(job)=self.jobs.get(&physical){job.set_sources(selected)?;}
            else {let mut jobs=crate::participant_dispatch::start(&[config.clone()],clients,directory,cancel)?;self.jobs.insert(physical,jobs.remove(0));}
        }
        Ok(())
    }
    pub(super) fn restore_rebind(&mut self,snapshot:&crate::participant_rebind::resident::Snapshot,
        clients:&BTreeMap<String,ParticipantClient>,generations:&BTreeMap<String,Option<u64>>,directory:&Path,cancel:KernelCancellationToken)->Result<()> {
        if !snapshot.rollback_ready{return Err(local("HOST_REBIND_ABORT_NOT_READY"));}
        let (active,blocked)=active_configs(&self.configs,clients,generations);self.blocked=blocked;
        let selected=snapshot.subscriptions.iter().map(|s|s.watch.key()).collect::<BTreeSet<_>>();
        let own=format!("{}:{}",snapshot.request.engine,snapshot.request.operation_id);
        let other=self.reservations.iter().filter(|(key,_)|*key!=&own).flat_map(|(_, (keys,_,_))|keys.iter().cloned()).collect::<BTreeSet<_>>();
        for mut config in active.into_iter().filter(|c|c.subscriptions.iter().any(|s|selected.contains(&s.watch.key()))) {
            config.subscriptions.retain(|s|!other.contains(&s.watch.key()));
            if config.subscriptions.is_empty(){continue;}
            let restored=sources(&config,clients,generations)?;
            let key=config.key()?;
            if self.jobs.get(&key).is_some_and(|job|job.task.is_finished()){self.jobs.remove(&key);}
            if let Some(job)=self.jobs.get(&key){job.set_sources(restored)?;}
            else {let mut jobs=crate::participant_dispatch::start(&[config],clients,directory,cancel.clone())?;self.jobs.insert(key,jobs.remove(0));}
        }Ok(())
    }
    pub(super) fn finish_rebind(&mut self,snapshot:&crate::participant_rebind::resident::Snapshot){
        self.reservations.remove(&format!("{}:{}",snapshot.request.engine,snapshot.request.operation_id));
    }
}

/// First binding may share an identical physical host with other scopes. It
/// cannot overwrite a named host or merge an already-selected source scope.
pub(super) fn initial_host_available(directory:&Path,base:&[HostConfig],target:&HostConfig)->Result<()> {
    let path=directory.join("runtime-hosts.state");
    let (saved,suppressed)=if path.exists(){
        let store=SecureStateStore::open(&path).map_err(|_|local("HOST_REGISTRY_RECOVERY_REQUIRED"))?;
        match store.read_exact().map_err(|_|local("HOST_REGISTRY_RECOVERY_REQUIRED"))?{
            Some(wire)=>decode_saved(&wire)?,None=>(Vec::new(),Vec::new()),
        }
    }else{(Vec::new(),Vec::new())};
    let base=base.iter().filter_map(|config|match base_active(config,&suppressed){Ok(true)=>Some(Ok(config)),Ok(false)=>None,Err(e)=>Some(Err(e))}).collect::<Result<Vec<_>>>()?;
    if saved.len()>8{return Err(local("HOST_CONFIG_LIMIT"));}
    let key=target.key()?;
    if base.iter().any(|old|old.key().ok().as_ref()==Some(&key)){return Err(local("HOST_INITIAL_EXISTING_BASE_HOST_GROUP"));}
    let mut merged=Vec::new();
    for old in base.into_iter().chain(saved.iter()){
        if old.name==target.name||old.subscriptions.iter().any(|a|target.subscriptions.iter().any(|b|a.watch.key()==b.watch.key())){return Err(local("HOST_REBIND_INITIAL_TARGET_CONFLICT"));}
        merge(&mut merged,old.clone())?;
    }
    merge(&mut merged,target.clone())?;
    Ok(())
}

#[cfg(test)]
mod initial_selection_tests {
    use super::*;
    #[test]
    fn first_host_does_not_write_duplicate_base_physical_host_groups() {
        let root=crate::test_support::protected_test_dir();
        let watch=WatchOptions{workspace_id:"w".repeat(43),mailbox_id:"m".repeat(43),membership_id:"g".repeat(43),consumer_id:"inbox".into(),host_destination:None};
        let existing=HostConfig{name:"canonical".into(),adapter:json!({"kind":"codex","endpoint":"ws://127.0.0.1:1","thread_id":"selected","expected_session_id":"session"}),subscriptions:vec![crate::participant_dispatch::HostSubscription{client:"worker".into(),client_generation:None,watch:watch.clone()}]};
        let mut target=existing.clone();target.name="another-name".into();target.subscriptions[0].watch.mailbox_id="n".repeat(43);
        assert_eq!(initial_host_available(root.path(),&[existing],&target).unwrap_err().code,"HOST_INITIAL_EXISTING_BASE_HOST_GROUP");
        assert!(!root.path().join("runtime-hosts.state").exists());
    }
}
