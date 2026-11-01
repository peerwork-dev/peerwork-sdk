//! Narrow live host subscriptions. A physical dispatcher survives role/scope
//! additions; only the separately authenticated runtime administrator selects it.
use super::*;
use crate::participant_dispatch::{HostConfig, RunningHost};
pub(super) struct Hosts {
    store: Arc<SecureStateStore>,
    configs: Vec<HostConfig>,
    jobs: BTreeMap<String, RunningHost>,
    blocked: Vec<Value>,
}
fn merge(configs: &mut Vec<HostConfig>, incoming: HostConfig) -> Result<()> {
    let key = incoming.key()?;
    for old in configs.iter_mut() {
        if old.key()? == key {
            if old.adapter != incoming.adapter {
                return Err(local("HOST_SELECTION_CONFLICT"));
            }
            for source in incoming.subscriptions {
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
        let saved: Vec<HostConfig> = match store
            .read_exact()
            .map_err(|_| local("HOST_REGISTRY_RECOVERY_REQUIRED"))?
        {
            Some(wire) => serde_json::from_value(
                peerwork_core::strict_json::parse_strict_json(&wire)
                    .map_err(|_| local("HOST_REGISTRY_RECOVERY_REQUIRED"))?,
            )
            .map_err(|_| local("HOST_REGISTRY_RECOVERY_REQUIRED"))?,
            None => Vec::new(),
        };
        if saved.len() > 8 {
            return Err(local("HOST_CONFIG_LIMIT"));
        }
        let mut configs = Vec::new();
        for config in base.iter().chain(&saved) {
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
            jobs,
            blocked,
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
        let wire = serde_json::to_vec(&desired).map_err(|_| local("HOST_REGISTRY_INVALID"))?;
        if serde_json::to_vec(&self.configs).ok().as_ref() != Some(&wire) {
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
        let wire = serde_json::to_vec(&desired).map_err(|_| local("HOST_REGISTRY_INVALID"))?;
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
}
