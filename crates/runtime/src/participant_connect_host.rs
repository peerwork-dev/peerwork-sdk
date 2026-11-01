//! Explicit host-user selections. MCP refers to opaque handles only; it cannot
//! supply socket paths, executables, credentials or replacement conversations.
use super::*;
use crate::participant_dispatch::{HostConfig, HostSubscription};
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostSelection {
    pub participant: String,
    pub admin_endpoint: PathBuf,
    pub adapter: Value,
}
impl Connect {
    pub async fn register_host(&mut self, name: &str, selected: HostSelection) -> Result<Value> {
        self.require_writer()?;
        if !identifier(name) || !selected.admin_endpoint.is_absolute() {
            return Err(local("HOST_SELECTION_INVALID"));
        }
        let participant = self
            .registry
            .participants
            .get(&selected.participant)
            .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let placeholder = WatchOptions {
            workspace_id: "A".repeat(43),
            mailbox_id: "B".repeat(43),
            membership_id: "C".repeat(43),
            consumer_id: "selected".into(),
            host_destination: None,
        };
        HostConfig {
            name: name.into(),
            adapter: selected.adapter.clone(),
            subscriptions: vec![HostSubscription {
                client: "selected".into(),
                watch: placeholder,
            }],
        }
        .key()?;
        if selected.adapter["kind"] == "agy-stdio" && selected.adapter["managed"] != true {
            return Err(local("EXISTING_AGY_SESSION_INTERFACE_REQUIRED"));
        }
        let status = crate::communication_runtime::call(
            &selected.admin_endpoint,
            json!({"method":"status"}),
        )
        .await?;
        if status["ok"] != true
            || !status["value"]["engines"]
                .as_array()
                .is_some_and(|engines| {
                    engines.iter().any(|e| {
                        e["actor_id"] == participant.actor_id && e["origin"] == participant.origin
                    })
                })
        {
            return Err(local("HOST_RUNTIME_IDENTITY_OR_ORIGIN_MISMATCH"));
        }
        if let Some(old) = self.registry.hosts.get(name) {
            if old != &selected {
                return Err(local("HOST_SELECTION_CHANGED_REBIND_REQUIRED"));
            }
        } else {
            if self.registry.hosts.len() >= 8 {
                return Err(local("HOST_SELECTION_LIMIT"));
            }
            self.registry.hosts.insert(name.into(), selected);
            self.save()?;
        }
        Ok(json!({"state":"LOCAL_HOST_REGISTERED","host":name,"model_response":"NOT_ATTESTED"}))
    }
    pub(super) async fn ensure_host(
        &self,
        name: &str,
        request: &ConnectRequest,
        registration: &Registration,
        client_name: &str,
        watch: WatchOptions,
    ) -> Result<Value> {
        let selected = self
            .registry
            .hosts
            .get(name)
            .ok_or_else(|| local("HOST_BINDING_REQUIRED"))?;
        if selected.participant != request.participant {
            return Err(local("HOST_IDENTITY_PIN_MISMATCH"));
        }
        let config = HostConfig {
            name: name.into(),
            adapter: selected.adapter.clone(),
            subscriptions: vec![HostSubscription {
                client: client_name.into(),
                watch,
            }],
        };
        let value = crate::communication_runtime::call(
            &selected.admin_endpoint,
            json!({"method":"host_ensure","config":config,
            "expected_actor":registration.actor_id,"expected_origin":registration.origin}),
        )
        .await?;
        if value["ok"] != true {
            return Err(serde_json::from_value(value["error"].clone())
                .unwrap_or_else(|_| local("HOST_ATTACH_FAILED")));
        }
        Ok(value["value"].clone())
    }
}

pub(super) fn adapter(values: &BTreeMap<String, String>) -> Result<Option<Value>> {
    let has = |name: &str| values.contains_key(name);
    let text = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| local("HOST_SELECTION_ARGUMENT_MISSING"))
    };
    let absolute =
        |name: &str| std::path::absolute(text(name)?).map_err(|_| local("HOST_SELECTION_INVALID"));
    let codex = [
        "--codex-endpoint",
        "--codex-thread",
        "--codex-session",
        "--codex-auth-env",
    ]
    .iter()
    .any(|s| has(s));
    let managed = has("--agy-managed");
    let app = has("--agy-api");
    if usize::from(codex) + usize::from(managed) + usize::from(app) > 1 {
        return Err(local("SELECT_ONE_HOST_ADAPTER"));
    }
    if codex {
        if ["--agy-executable", "--agy-conversation", "--agy-inbox"]
            .iter()
            .any(|s| has(s))
        {
            return Err(local("SELECT_ONE_HOST_ADAPTER"));
        }
        let mut selected = json!({"kind":"codex","endpoint":text("--codex-endpoint")?,"thread_id":text("--codex-thread")?});
        if let Some(session) = values.get("--codex-session") {
            selected["expected_session_id"] = json!(session);
        }
        if let Some(env) = values.get("--codex-auth-env") {
            if env.is_empty()
                || env.len() > 128
                || !env.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return Err(local("HOST_SELECTION_INVALID"));
            }
            selected["auth_token_env"] = json!(env);
        }
        return Ok(Some(selected));
    }
    if managed {
        if has("--agy-inbox") {
            return Err(local("SELECT_ONE_HOST_ADAPTER"));
        }
        return Ok(Some(
            json!({"kind":"agy-stdio","managed":true,"executable":absolute("--agy-executable")?,
            "working_directory":absolute("--project")?,"conversation_id":text("--agy-conversation")?}),
        ));
    }
    if app {
        if has("--agy-executable") {
            return Err(local("SELECT_ONE_HOST_ADAPTER"));
        }
        return Ok(Some(
            json!({"kind":"agy-app","agentapi_path":absolute("--agy-api")?,"inbox_directory":absolute("--agy-inbox")?,"conversation_id":text("--agy-conversation")?}),
        ));
    }
    if ["--agy-executable", "--agy-conversation", "--agy-inbox"]
        .iter()
        .any(|s| has(s))
    {
        return Err(local("EXISTING_AGY_SESSION_INTERFACE_REQUIRED"));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    #[test]
    fn session_selection_is_explicit_and_managed_agy_never_implies_bypass() {
        assert!(adapter(&BTreeMap::new()).unwrap().is_none());
        assert_eq!(
            adapter(&flags(&[("--agy-conversation", "existing")]))
                .unwrap_err()
                .code,
            "EXISTING_AGY_SESSION_INTERFACE_REQUIRED"
        );
        let codex = adapter(&flags(&[
            ("--codex-endpoint", "ws://127.0.0.1:1"),
            ("--codex-thread", "selected-thread"),
            ("--codex-session", "selected-session"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(codex["thread_id"], "selected-thread");
        assert_eq!(codex["expected_session_id"], "selected-session");
        let managed = adapter(&flags(&[
            ("--agy-managed", "true"),
            ("--agy-executable", "agy"),
            ("--project", "."),
            ("--agy-conversation", "owned-session"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(managed["managed"], true);
        assert!(managed.get("args").is_none());
        assert!(!managed.to_string().contains("skip-permissions"));
        assert!(adapter(&flags(&[("--codex-thread", "thread")])).is_err());
        assert_eq!(
            adapter(&flags(&[
                ("--codex-thread", "thread"),
                ("--agy-managed", "true")
            ]))
            .unwrap_err()
            .code,
            "SELECT_ONE_HOST_ADAPTER"
        );
    }
}
