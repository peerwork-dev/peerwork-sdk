//! Narrow live host subscriptions. A physical dispatcher survives role/scope
//! additions; only the separately authenticated runtime administrator selects it.
use super::*;
use crate::participant_dispatch::{HostConfig, RunningHost};
pub(super) struct Hosts {
    store: Arc<SecureStateStore>,
    configs: Vec<HostConfig>,
    jobs: BTreeMap<String, RunningHost>,
}
fn merge(configs: &mut Vec<HostConfig>, incoming: HostConfig) -> Result<()> {
    let key = incoming.key()?;
    for old in configs.iter_mut() {
        if old.key()? == key {
            if old.adapter != incoming.adapter {
                return Err(local("HOST_SELECTION_CONFLICT"));
            }
            for source in incoming.subscriptions {
                if !old
                    .subscriptions
                    .iter()
                    .any(|s| s.client == source.client && s.watch == source.watch)
                {
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
) -> Result<Vec<(ParticipantClient, WatchOptions)>> {
    config
        .subscriptions
        .iter()
        .map(|s| {
            let client = clients
                .get(&s.client)
                .ok_or_else(|| local("HOST_CLIENT_NOT_FOUND"))?;
            s.watch.authorize(client.capability())?;
            Ok((client.clone(), s.watch.clone()))
        })
        .collect()
}
impl Hosts {
    pub fn open(
        directory: &Path,
        base: &[HostConfig],
        clients: &BTreeMap<String, ParticipantClient>,
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
        for config in &configs {
            sources(config, clients)?;
        }
        let started=crate::participant_dispatch::start(&configs,clients,directory,cancel)?;
        let mut keys=configs.iter().map(HostConfig::key).collect::<Result<Vec<_>>>()?;keys.sort();
        let jobs=keys.into_iter().zip(started).collect();
        Ok(Self {
            store,
            configs,
            jobs,
        })
    }
    pub fn statuses(&self) -> Vec<Value> {
        self.jobs
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
            .collect()
    }
    pub async fn ensure(
        &mut self,
        config: HostConfig,
        clients: &BTreeMap<String, ParticipantClient>,
        directory: &Path,
        cancel: KernelCancellationToken,
    ) -> Result<Value> {
        let key = config.key()?;
        let mut desired = self.configs.clone();
        merge(&mut desired, config)?;
        let selected = desired
            .iter()
            .find(|c| c.key().is_ok_and(|k| k == key))
            .ok_or_else(|| local("HOST_REGISTRY_INVALID"))?
            .clone();
        let selected_sources = sources(&selected, clients)?;
        if let Some(job) = self.jobs.get(&key) {
            job.validate_sources(&selected_sources)?;
        }
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
    pub async fn close(&mut self) {
        let jobs = std::mem::take(&mut self.jobs);
        for (_, job) in jobs {
            let _ = job.task.await;
        }
    }
}
