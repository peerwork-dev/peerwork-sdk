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
