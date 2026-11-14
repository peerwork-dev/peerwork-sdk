//! Restricted local clients and resumable revocation. No identity, message
//! payload or second signing journal is stored in this bounded registry.
use super::*;
use peerwork_core::crypto::sha256_hex;
const LIMIT: usize = 128;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    parent: String,
    alias: String,
    name: String,
    capability: Capability,
    #[serde(default)]
    generation: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootBinding {
    name: String,
    actor: String,
    origin: String,
    namespace: String,
    state_binding: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revocation {
    pub target: String,
    pub binding: String,
    removed: Vec<Entry>,
    #[serde(default)]
    root: Option<RootBinding>,
    #[serde(default)]
    ancestors: Vec<Entry>,
    #[serde(default)]
    endpoints: BTreeMap<String, String>,
}
impl Revocation {
    pub fn names(&self) -> std::collections::BTreeSet<String> {
        self.removed.iter().map(|e| e.name.clone()).collect()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    generation: u64,
    entries: Vec<Entry>,
    revocations: Vec<Revocation>,
}
impl Default for Saved {
    fn default() -> Self {
        Self {
            version: 2,
            generation: 0,
            entries: Vec::new(),
            revocations: Vec::new(),
        }
    }
}
pub(super) struct Clients {
    store: SecureStateStore,
    data: Saved,
}
fn name(parent: &str, alias: &str) -> String {
    format!(
        "derived-{}",
        &sha256_hex(json!([parent, alias]).to_string().as_bytes())[..40]
    )
}
fn binding(entry: &Entry) -> String {
    sha256_hex(serde_json::to_vec(entry).unwrap().as_slice())
}
impl Clients {
    pub fn open(directory: &Path) -> Result<Self> {
        let store = SecureStateStore::open(&directory.join("derived-clients.state"))
            .map_err(|_| local("CLIENT_REGISTRY_NOT_PRIVATE"))?;
        let data = match store
            .read_exact()
            .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?
        {
            None => Saved::default(),
            Some(bytes) => {
                let value = peerwork_core::strict_json::parse_strict_json(&bytes)
                    .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
                if value.is_array() {
                    // Local candidate checkpoint migration only. Signed packets,
                    // state namespaces and old capabilities are not rewritten.
                    let mut entries: Vec<Entry> = serde_json::from_value(value)
                        .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
                    for (i, entry) in entries.iter_mut().enumerate() {
                        entry.generation = i as u64 + 1;
                    }
                    Saved {
                        generation: entries.len() as u64,
                        entries,
                        ..Saved::default()
                    }
                } else {
                    serde_json::from_value(value)
                        .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?
                }
            }
        };
        if data.version != 2
            || data.entries.len()
                + data
                    .revocations
                    .iter()
                    .map(|r| r.removed.len())
                    .sum::<usize>()
                > LIMIT
            || data
                .entries
                .iter()
                .chain(data.revocations.iter().flat_map(|r| &r.removed))
                .any(|e| {
                    e.generation == 0
                        || e.generation > data.generation
                        || !identifier(&e.alias)
                        || e.name != name(&e.parent, &e.alias)
                })
        {
            return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
        }
        Ok(Self { store, data })
    }
    fn save(&mut self, data: Saved) -> Result<()> {
        self.store
            .write_exact(&serde_json::to_vec(&data).map_err(|_| local("CLIENT_REGISTRY_INVALID"))?)
            .map_err(|_| local("CLIENT_REGISTRY_WRITE_FAILED"))?;
        self.data = data;
        Ok(())
    }
    pub fn restore(&self, sessions: &mut Vec<Session>) -> Result<()> {
        for entry in &self.data.entries {
            if sessions.iter().any(|s| s.name == entry.name) {
                return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
            }
            let parent = sessions
                .iter()
                .find(|s| s.name == entry.parent)
                .ok_or_else(|| local("CLIENT_PARENT_RECOVERY_REQUIRED"))?;
            sessions.push(Session {
                name: entry.name.clone(),
                client: parent
                    .client
                    .restrict(&entry.alias, entry.capability.clone())?,
                token: random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?,
                generation: Some(entry.generation),
                watches: Default::default(),
            });
        }
        Ok(())
    }
    pub fn pending(&self) -> Vec<Revocation> {
        self.data.revocations.clone()
    }
    pub fn detached(job: &Revocation, sessions: &[Session]) -> Result<Vec<ParticipantClient>> {
        let root = job
            .root
            .as_ref()
            .ok_or_else(|| local("CLIENT_REVOCATION_PROVENANCE_REQUIRED"))?;
        let selected = sessions
            .iter()
            .find(|s| {
                s.generation.is_none()
                    && s.name == root.name
                    && s.client.actor_id() == root.actor
                    && s.client.origin() == root.origin
                    && s.client.local_namespace() == root.namespace
                    && s.client.state_binding() == root.state_binding
            })
            .ok_or_else(|| local("CLIENT_ROOT_BINDING_CHANGED"))?;
        if job.ancestors.len() > LIMIT {
            return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
        }
        let mut available: BTreeMap<String, ParticipantClient> =
            [(root.name.clone(), selected.client.clone())].into();
        let mut revoked = Vec::new();
        for entry in job.ancestors.iter().chain(&job.removed) {
            let parent = available
                .get(&entry.parent)
                .ok_or_else(|| local("CLIENT_PARENT_RECOVERY_REQUIRED"))?;
            let client = parent.restrict(&entry.alias, entry.capability.clone())?;
            available.insert(entry.name.clone(), client.clone());
            if job.removed.iter().any(|removed| removed.name == entry.name) {
                revoked.push(client);
            }
        }
        Ok(revoked)
    }
    pub fn complete(&mut self, job: &Revocation) -> Result<()> {
        let mut data = self.data.clone();
        data.revocations
            .retain(|r| r.target != job.target || r.binding != job.binding);
        self.save(data)
    }
}
impl Runtime {
    pub(super) fn pending_revocation_status(&self) -> Result<Value> {
        let registry = self
            .derived
            .lock()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        Ok(json!(registry.data.revocations.iter().map(|job|json!({"client_name":job.target,"binding_version":job.binding,"count":job.removed.len(),"state":"CLEANUP_PENDING","next_actor":"LOCAL_RUNTIME","next_action":"AUTOMATIC_SAME_REVOCATION_RETRY"})).collect::<Vec<_>>()))
    }
    pub(super) async fn resume_revocations(self: Arc<Self>) {
        let mut retries: BTreeMap<String, (tokio::time::Instant, u8)> = BTreeMap::new();
        loop {
            tokio::select! {_=self.cancel.cancelled()=>return,_=tokio::time::sleep(Duration::from_millis(500))=>{}}
            let jobs = match self.derived.lock() {
                Ok(registry) => registry.pending(),
                Err(_) => return,
            };
            let names: BTreeSet<_> = jobs
                .iter()
                .map(|job| format!("{}:{}", job.target, job.binding))
                .collect();
            retries.retain(|key, _| names.contains(key));
            for job in jobs {
                if self.cancel.is_cancelled() {
                    return;
                }
                let key = format!("{}:{}", job.target, job.binding);
                if retries
                    .get(&key)
                    .is_some_and(|(at, _)| *at > tokio::time::Instant::now())
                {
                    continue;
                }
                match self.cleanup_revocation(&job).await {
                    Ok(true) => {
                        retries.remove(&key);
                    }
                    _ => {
                        let failures = retries
                            .get(&key)
                            .map_or(0, |(_, n)| *n)
                            .saturating_add(1)
                            .min(6);
                        retries.insert(
                            key,
                            (
                                tokio::time::Instant::now()
                                    + Duration::from_millis((500u64 << failures).min(30000)),
                                failures,
                            ),
                        );
                    }
                }
            }
        }
    }
    pub(super) fn client_snapshot(
        &self,
    ) -> Result<(
        BTreeMap<String, ParticipantClient>,
        BTreeMap<String, Option<u64>>,
    )> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        Ok((
            sessions
                .iter()
                .map(|s| (s.name.clone(), s.client.clone()))
                .collect(),
            sessions
                .iter()
                .map(|s| (s.name.clone(), s.generation))
                .collect(),
        ))
    }
    pub(super) async fn cleanup_revocation(&self, job: &Revocation) -> Result<bool> {
        // One cleanup per exact incarnation. Concurrent retries may observe
        // pending but cannot unwatch a subsequently reissued client.
        let key = format!("{}:{}", job.target, job.binding);
        if !self
            .cleanup_active
            .lock()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
            .insert(key.clone())
        {
            return Ok(false);
        }
        struct Guard<'a> {
            runtime: &'a Runtime,
            key: String,
        }
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if let Ok(mut active) = self.runtime.cleanup_active.lock() {
                    active.remove(&self.key);
                }
            }
        }
        let _guard = Guard { runtime: self, key };
        let detached = {
            let registry = self
                .derived
                .lock()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
            if !registry
                .data
                .revocations
                .iter()
                .any(|r| r.target == job.target && r.binding == job.binding)
            {
                return Ok(true);
            }
            let sessions = self
                .sessions
                .read()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
            Clients::detached(job, &sessions)?
        };
        {
            let mut hosts = self.hosts.lock().await;
            let (clients, generations) = self.client_snapshot()?;
            hosts
                .remove_clients(&job.names(), &clients, &generations)
                .await?;
        }
        for client in detached {
            for options in client.watch_bindings().await? {
                client.unwatch(&options).await?;
            }
        }
        for entry in &job.removed {
            let path = self.directory.join(format!("client-{}.json", entry.name));
            match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(local("CLIENT_ENDPOINT_CLEANUP_FAILED")),
                Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
                    return Err(local("CLIENT_ENDPOINT_CONFLICT"))
                }
                Ok(_) => (),
            }
            let descriptor = load_endpoint(&path)?;
            let digest = sha256_hex(
                &serde_json::to_vec(&descriptor).map_err(|_| local("CLIENT_ENDPOINT_INVALID"))?,
            );
            if job.endpoints.get(&entry.name) != Some(&digest) {
                return Err(local("CLIENT_ENDPOINT_CONFLICT"));
            }
            std::fs::remove_file(path).map_err(|_| local("CLIENT_ENDPOINT_CLEANUP_FAILED"))?;
        }
        self.derived
            .lock()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
            .complete(job)?;
        Ok(true)
    }
    pub(super) fn revoke_derived(
        &self,
        parent: &Session,
        alias: &str,
        expected: &str,
    ) -> Result<Option<Revocation>> {
        if !identifier(alias) || !crate::participant_migration::digest(expected) {
            return Err(local("CLIENT_BINDING_SELECTION_INVALID"));
        }
        let target = name(&parent.name, alias);
        let mut registry = self
            .derived
            .lock()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        if !self
            .sessions
            .read()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
            .iter()
            .any(|s| s.name == parent.name && s.token == parent.token)
        {
            return Err(local("IPC_UNAUTHORIZED"));
        }
        if let Some(job) = registry
            .data
            .revocations
            .iter()
            .find(|r| r.target == target)
        {
            if job.binding != expected {
                return Err(local("CLIENT_BINDING_CHANGED"));
            }
            return Ok(Some(job.clone()));
        }
        let Some(entry) = registry.data.entries.iter().find(|e| e.name == target) else {
            return Ok(None);
        };
        if binding(entry) != expected {
            return Err(local("CLIENT_BINDING_CHANGED"));
        }
        let mut names = std::collections::BTreeSet::from([target.clone()]);
        for entry in &registry.data.entries {
            if names.contains(&entry.parent) {
                names.insert(entry.name.clone());
            }
        }
        let removed: Vec<Entry> = registry
            .data
            .entries
            .iter()
            .filter(|e| names.contains(&e.name))
            .cloned()
            .collect();
        let mut ancestors = Vec::new();
        let mut root_name = parent.name.clone();
        while let Some(entry) = registry.data.entries.iter().find(|e| e.name == root_name) {
            if ancestors.len() >= LIMIT {
                return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
            }
            ancestors.push(entry.clone());
            root_name = entry.parent.clone();
        }
        ancestors.reverse();
        let sessions = self
            .sessions
            .read()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        let root_session = sessions
            .iter()
            .find(|s| s.name == root_name && s.generation.is_none())
            .ok_or_else(|| local("CLIENT_PARENT_RECOVERY_REQUIRED"))?;
        let root = RootBinding {
            name: root_name,
            actor: root_session.client.actor_id().into(),
            origin: root_session.client.origin().into(),
            namespace: root_session.client.local_namespace().into(),
            state_binding: root_session.client.state_binding().into(),
        };
        let mut endpoints = BTreeMap::new();
        for entry in &removed {
            let session = sessions
                .iter()
                .find(|s| s.name == entry.name && s.generation == Some(entry.generation))
                .ok_or_else(|| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
            let descriptor = Endpoint {
                format: ENDPOINT_FORMAT.into(),
                address: self.address,
                token: session.token.clone(),
                access: "CLIENT".into(),
                control_address:Some(self.control_address),
            };
            endpoints.insert(
                entry.name.clone(),
                sha256_hex(
                    &serde_json::to_vec(&descriptor)
                        .map_err(|_| local("CLIENT_ENDPOINT_INVALID"))?,
                ),
            );
        }
        drop(sessions);
        let job = Revocation {
            target,
            binding: expected.into(),
            removed,
            root: Some(root),
            ancestors,
            endpoints,
        };
        let mut data = registry.data.clone();
        data.entries.retain(|e| !names.contains(&e.name));
        data.revocations.push(job.clone());
        registry.save(data)?;
        let mut removed = Vec::new();
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
            sessions.retain(|s| {
                if names.contains(&s.name) {
                    s.client.revoke_local();
                    removed.push(s.clone());
                    false
                } else {
                    true
                }
            });
        }
        Ok(Some(job))
    }
    pub(super) fn derive_client(
        &self,
        parent: &Session,
        alias: &str,
        capability: Capability,
        expected_capability: Option<Capability>,
    ) -> Result<Value> {
        if !identifier(alias) {
            return Err(local("CLIENT_ALIAS_INVALID"));
        }
        let mut client = parent.client.restrict(alias, capability.clone())?;
        let name = name(&parent.name, alias);
        let path = self.directory.join(format!("client-{name}.json"));
        let mut registry = self
            .derived
            .lock()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        if !self
            .sessions
            .read()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
            .iter()
            .any(|s| s.name == parent.name && s.token == parent.token)
        {
            return Err(local("IPC_UNAUTHORIZED"));
        }
        if registry
            .data
            .revocations
            .iter()
            .any(|r| r.removed.iter().any(|e| e.name == name))
        {
            return Err(local("CLIENT_REVOCATION_PENDING"));
        }
        if let Some(index) = registry.data.entries.iter().position(|e| e.name == name) {
            let entry = registry.data.entries[index].clone();
            if entry.capability != capability {
                if !entry.capability.is_subset_of(&capability) {
                    return Err(local("CLIENT_NARROWING_REQUIRES_REVOCATION"));
                }
                if expected_capability.as_ref() != Some(&entry.capability) {
                    return Err(local("CLIENT_BINDING_CONFLICT"));
                }
                let mut data = registry.data.clone();
                data.entries[index].capability = capability.clone();
                registry.save(data)?;
                let mut sessions = self
                    .sessions
                    .write()
                    .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
                let session = sessions
                    .iter_mut()
                    .find(|s| s.name == name)
                    .ok_or_else(|| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
                client.inherit_lifecycle(&session.client);
                session.client = client;
            }
            let session = self
                .sessions
                .read()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
                .iter()
                .find(|s| s.name == name)
                .cloned()
                .ok_or_else(|| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    let existing = load_endpoint(&path)?;
                    if existing.token != session.token
                        || existing.address != self.address
                        || existing.access != "CLIENT"
                    {
                        return Err(local("CLIENT_ENDPOINT_CONFLICT"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    endpoint_control(&path, self.address, &session.token, "CLIENT",Some(self.control_address))?
                }
                Err(_) => return Err(local("CLIENT_ENDPOINT_CONFLICT")),
            }
        } else {
            if registry.data.entries.len()
                + registry
                    .data
                    .revocations
                    .iter()
                    .map(|r| r.removed.len())
                    .sum::<usize>()
                >= LIMIT
            {
                return Err(local("CLIENT_DERIVATION_LIMIT"));
            }
            if std::fs::symlink_metadata(&path).is_ok() {
                return Err(local("CLIENT_ENDPOINT_CONFLICT"));
            }
            let mut data = registry.data.clone();
            data.generation = data
                .generation
                .checked_add(1)
                .ok_or_else(|| local("CLIENT_GENERATION_LIMIT"))?;
            let session = Session {
                name: name.clone(),
                client,
                token: random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?,
                generation: Some(data.generation),
                watches: Default::default(),
            };
            data.entries.push(Entry {
                parent: parent.name.clone(),
                alias: alias.into(),
                name: name.clone(),
                capability: capability.clone(),
                generation: data.generation,
            });
            registry.save(data)?;
            let token = session.token.clone();
            self.sessions
                .write()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
                .push(session);
            endpoint_control(&path, self.address, &token, "CLIENT",Some(self.control_address))?;
        }
        let entry = registry
            .data
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
        Ok(
            json!({"state":"LOCAL_CLIENT_READY","client_name":name,"endpoint_path":path,"actor_id":parent.client.actor_id(),"origin":parent.client.origin(),"capability":capability,"engine_restarted":false,"client_generation":entry.generation,"binding_version":binding(entry)}),
        )
    }
}

/// Read the original derived-client lineage while the runtime is stopped. Do
/// not materialize derived clients as static roots to make a binding succeed.
pub(super) fn resolve_rebind_client(directory:&Path,roots:&[ClientConfig],name:&str)->Result<RebindClient> {
    let saved=if directory.join("derived-clients.state").exists(){Some(Clients::open(directory)?)}else{None};
    let entries=saved.as_ref().map(|s|s.data.entries.as_slice()).unwrap_or(&[]);
    let revocations=saved.as_ref().map(|s|s.data.revocations.as_slice()).unwrap_or(&[]);
    fn walk(name:&str,roots:&[ClientConfig],entries:&[Entry],revocations:&[Revocation],seen:&mut BTreeSet<String>)->Result<RebindClient> {
        if !identifier(name)||!seen.insert(name.into())||seen.len()>LIMIT {return Err(local("HOST_REBIND_CLIENT_LINEAGE_INVALID"));}
        if revocations.iter().any(|r|r.target==name||r.removed.iter().any(|e|e.name==name)) {return Err(local("HOST_REBIND_CLIENT_REVOCATION_PENDING"));}
        let root=roots.iter().filter(|r|r.name==name).collect::<Vec<_>>();
        let derived=entries.iter().filter(|e|e.name==name).collect::<Vec<_>>();
        if root.len()+derived.len()!=1{return Err(local("HOST_REBIND_CLIENT_SELECTION_INVALID"));}
        let resolved=if let Some(root)=root.first(){
            root.capability.validate()?;
            RebindClient{engine:root.engine.clone(),namespace:format!("program:{}",root.name),capability:root.capability.clone(),generation:None}
        }else{
            let entry=derived[0];let parent=walk(&entry.parent,roots,entries,revocations,seen)?;
            entry.capability.validate()?;
            if !entry.capability.is_subset_of(&parent.capability){return Err(local("HOST_REBIND_CLIENT_CAPABILITY_CHANGED"));}
            RebindClient{engine:parent.engine,namespace:format!("{}:{}",parent.namespace,entry.alias),capability:entry.capability.clone(),generation:Some(entry.generation)}
        };
        if resolved.namespace.len()>256{return Err(local("HOST_REBIND_CLIENT_LINEAGE_INVALID"));}
        Ok(resolved)
    }
    walk(name,roots,entries,revocations,&mut BTreeSet::new())
}

#[cfg(test)]
mod rebind_selection_tests {
    use super::*;
    fn save(directory:&Path,data:Value){
        let store=SecureStateStore::open(&directory.join("derived-clients.state")).unwrap();store.write_exact(&serde_json::to_vec(&data).unwrap()).unwrap();
    }
    #[test]
    fn first_host_resolver_uses_original_alias_chain_and_refuses_expansion_or_pending_revocation() {
        let root=crate::test_support::protected_test_dir();let roots=vec![ClientConfig{name:"root".into(),engine:"engine".into(),capability:Capability::owner()}];
        let first=name("root","one");let second=name(&first,"two");
        let mut narrow=Capability::owner();narrow.allow_root=false;narrow.operations=["structure.mailbox.get".into()].into();
        let entries=json!([{"parent":"root","alias":"one","name":first,"capability":narrow,"generation":1},{"parent":first,"alias":"two","name":second,"capability":narrow,"generation":2}]);
        let mut data=json!({"version":2,"generation":2,"entries":entries,"revocations":[]});save(root.path(),data.clone());
        let selected=resolve_rebind_client(root.path(),&roots,&second).unwrap();assert_eq!(selected.namespace,"program:root:one:two");assert_eq!(selected.generation,Some(2));
        data["entries"][1]["capability"]=json!(Capability::owner());save(root.path(),data.clone());
        assert_eq!(resolve_rebind_client(root.path(),&roots,&second).err().unwrap().code,"HOST_REBIND_CLIENT_CAPABILITY_CHANGED");
        data["entries"]=entries;data["revocations"]=json!([{"target":"root","binding":"pending","removed":[],"root":null,"ancestors":[],"endpoints":{}}]);save(root.path(),data);
        assert_eq!(resolve_rebind_client(root.path(),&roots,&second).err().unwrap().code,"HOST_REBIND_CLIENT_REVOCATION_PENDING");
    }
}
