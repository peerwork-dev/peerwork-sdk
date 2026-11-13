//! A tool invocation reuses either an authenticated runtime or an already-open
//! participant. Attaching tools never changes the client's operation namespace.
use crate::{
    communication_runtime::{ClientRequest, RuntimeClient},
    participant::{ParticipantClient, Result},
    participant_client_tools::{self, Watches},
};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::OnceCell;

#[derive(Clone)]
pub(crate) enum Client {
    Resident(Arc<RuntimeClient>),
    Deferred(Arc<Deferred>),
    Attached { client: ParticipantClient, watches: Arc<Watches> },
}
pub(crate) struct Deferred {
    path: PathBuf,
    origin: String,
    actor: String,
    binding: Option<Value>,
    management: Option<crate::agent_tools::ManagementScope>,
    client: OnceCell<RuntimeClient>,
}
impl From<RuntimeClient> for Client {
    fn from(client: RuntimeClient) -> Self { Self::Resident(Arc::new(client)) }
}
impl Client {
    /// Optional routes are authenticated when selected. A failed connection is
    /// not cached: restoring the same endpoint allows the next call to retry.
    pub fn deferred(path: PathBuf, origin: &str, actor: &str, binding: Option<Value>, management: Option<crate::agent_tools::ManagementScope>) -> Self {
        Self::Deferred(Arc::new(Deferred { path, origin: origin.into(), actor: actor.into(), binding, management, client: OnceCell::new() }))
    }
    pub fn attached(client: ParticipantClient) -> Self {
        Self::Attached { client, watches: Default::default() }
    }
    pub fn actor_id(&self) -> &str {
        match self { Self::Resident(c) => c.actor_id(), Self::Deferred(c) => &c.actor, Self::Attached { client, .. } => client.actor_id() }
    }
    pub fn origin(&self) -> &str {
        match self { Self::Resident(c) => c.origin(), Self::Deferred(c) => &c.origin, Self::Attached { client, .. } => client.origin() }
    }
    pub fn attached_mode(&self) -> bool { matches!(self, Self::Attached { .. }) }
    pub fn attached_namespace_binding(&self) -> Option<String> {
        match self {
            Self::Attached { client, .. } => Some(serde_json::json!(["attached",client.actor_id(),client.origin(),client.state_binding(),client.local_namespace()]).to_string()),
            _ => None,
        }
    }
    pub async fn call(&self, request: Value) -> Result<Value> {
        match self {
            Self::Resident(c) => c.call(request).await,
            Self::Deferred(route) => {
                let client = route.client.get_or_try_init(|| async {
                    let client = match &route.binding {
                        Some(binding) => RuntimeClient::connect_bound(route.path.clone(), &route.origin, &route.actor, binding.clone()).await?,
                        None => RuntimeClient::connect(route.path.clone(), &route.origin, &route.actor).await?,
                    };
                    if let Some(view) = &route.management {
                        let observed = client.call(serde_json::json!({"method":"capabilities"})).await?;
                        let binding = client.call(serde_json::json!({"method":"binding"})).await?;
                        let capability: crate::participant::Capability = serde_json::from_value(observed["capability"].clone())
                            .map_err(|_| crate::participant::ParticipantError::local("MANAGEMENT_VIEW_BINDING_INVALID", "AGENT_TOOLS"))?;
                        if binding["client_generation"] != view.client_generation || capability.allow_root || capability.operations != view.operations
                            || capability.workspace_ids.as_ref() != Some(&[view.workspace_id.clone()].into()) {
                            return Err(crate::participant::ParticipantError::local("MANAGEMENT_VIEW_BINDING_INVALID", "AGENT_TOOLS"));
                        }
                    }
                    Ok::<_, crate::participant::ParticipantError>(client)
                }).await?;
                client.call(request).await
            },
            Self::Attached { client, watches } => {
                participant_client_tools::call(client, watches, ClientRequest::parse(request)?).await
            }
        }
    }
}
