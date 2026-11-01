//! Narrow client derivation on a running engine. This registry stores only local
//! capability bindings, never a second message queue or a signing identity.
use super::*;
use peerwork_core::crypto::sha256_hex;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    parent: String,
    alias: String,
    name: String,
    capability: Capability,
}
pub(super) struct Clients {
    store: SecureStateStore,
    entries: Vec<Entry>,
}
impl Clients {
    pub fn open(directory: &Path) -> Result<Self> {
        let store = SecureStateStore::open(&directory.join("derived-clients.state"))
            .map_err(|_| local("CLIENT_REGISTRY_NOT_PRIVATE"))?;
        let entries: Vec<Entry> = match store
            .read_exact()
            .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?
        {
            Some(wire) => serde_json::from_value(
                peerwork_core::strict_json::parse_strict_json(&wire)
                    .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?,
            )
            .map_err(|_| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?,
            None => Vec::new(),
        };
        if entries.len() > 32 {
            return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
        }
        Ok(Self { store, entries })
    }
    pub fn restore(&self, sessions: &mut Vec<Session>) -> Result<()> {
        for entry in &self.entries {
            if !identifier(&entry.alias)
                || entry.name != name(&entry.parent, &entry.alias)
                || sessions.iter().any(|s| s.name == entry.name)
            {
                return Err(local("CLIENT_REGISTRY_RECOVERY_REQUIRED"));
            }
            let parent = sessions
                .iter()
                .find(|s| s.name == entry.parent)
                .ok_or_else(|| local("CLIENT_PARENT_RECOVERY_REQUIRED"))?;
            let client = parent
                .client
                .restrict(&entry.alias, entry.capability.clone())?;
            sessions.push(Session {
                name: entry.name.clone(),
                client,
                token: random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?,
                watches: Default::default(),
            });
        }
        Ok(())
    }
}
fn name(parent: &str, alias: &str) -> String {
    format!(
        "derived-{}",
        &sha256_hex(json!([parent, alias]).to_string().as_bytes())[..40]
    )
}
impl Runtime {
    pub(super) fn revoke_derived(&self, parent: &Session, alias: &str) -> Result<Vec<Session>> {
        if !identifier(alias) {
            return Err(local("CLIENT_ALIAS_INVALID"));
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
        let mut names = std::collections::BTreeSet::from([target]);
        // Registry order is parent-before-child and bounded to32 entries.
        for entry in &registry.entries {
            if names.contains(&entry.parent) {
                names.insert(entry.name.clone());
            }
        }
        let entries: Vec<_> = registry
            .entries
            .iter()
            .filter(|e| !names.contains(&e.name))
            .cloned()
            .collect();
        if entries.len() == registry.entries.len() {
            return Ok(Vec::new());
        }
        registry
            .store
            .write_exact(
                &serde_json::to_vec(&entries).map_err(|_| local("CLIENT_REGISTRY_INVALID"))?,
            )
            .map_err(|_| local("CLIENT_REGISTRY_WRITE_FAILED"))?;
        registry.entries = entries;
        let mut revoked = Vec::new();
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?;
        sessions.retain(|s| {
            if names.contains(&s.name) {
                revoked.push(s.clone());
                false
            } else {
                true
            }
        });
        drop(sessions);
        for session in &revoked {
            let path = self.directory.join(format!("client-{}.json", session.name));
            // Remove only this exact generated credential; a conflicting output
            // remains for explicit repair while the credential is already dead.
            if load_endpoint(&path)
                .is_ok_and(|e| e.token == session.token && e.address == self.address)
            {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(revoked)
    }
    pub(super) fn derive_client(
        &self,
        parent: &Session,
        alias: &str,
        capability: Capability,
    ) -> Result<Value> {
        if !identifier(alias) {
            return Err(local("CLIENT_ALIAS_INVALID"));
        }
        // Authorize even a repeated request against the current parent ceiling.
        let client = parent.client.restrict(alias, capability.clone())?;
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
        if let Some(entry) = registry.entries.iter().find(|e| e.name == name) {
            if entry.capability != capability {
                return Err(local("CLIENT_BINDING_CONFLICT"));
            }
            let session = self
                .sessions
                .read()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
                .iter()
                .find(|s| s.name == name)
                .cloned()
                .ok_or_else(|| local("CLIENT_REGISTRY_RECOVERY_REQUIRED"))?;
            // Reconstruct missing derived output; never rotate a live credential.
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
                    endpoint(&path, self.address, &session.token, "CLIENT")?
                }
                Err(_) => return Err(local("CLIENT_ENDPOINT_CONFLICT")),
            }
        } else {
            if registry.entries.len() >= 32 {
                return Err(local("CLIENT_DERIVATION_LIMIT"));
            }
            if std::fs::symlink_metadata(&path).is_ok() {
                return Err(local("CLIENT_ENDPOINT_CONFLICT"));
            }
            let session = Session {
                name: name.clone(),
                client,
                watches: Default::default(),
                token: random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?,
            };
            let entry = Entry {
                parent: parent.name.clone(),
                alias: alias.into(),
                name: name.clone(),
                capability: capability.clone(),
            };
            let mut entries = registry.entries.clone();
            entries.push(entry);
            let wire =
                serde_json::to_vec(&entries).map_err(|_| local("CLIENT_REGISTRY_INVALID"))?;
            registry
                .store
                .write_exact(&wire)
                .map_err(|_| local("CLIENT_REGISTRY_WRITE_FAILED"))?;
            registry.entries = entries;
            // Publish memory before endpoint output. A lost response or output
            // failure resumes the same namespace instead of another client.
            let token = session.token.clone();
            self.sessions
                .write()
                .map_err(|_| local("CLIENT_REGISTRY_UNAVAILABLE"))?
                .push(session);
            endpoint(&path, self.address, &token, "CLIENT")?;
        }
        Ok(
            json!({"state":"LOCAL_CLIENT_READY","endpoint_path":path,"actor_id":parent.client.actor_id(),
            "origin":parent.client.origin(),"capability":capability,"engine_restarted":false}),
        )
    }
}
