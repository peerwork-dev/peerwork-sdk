//! Call-local namespace observations, never an operation or authority registry.
//! Scope filtering stays with each caller: a miss in one Space or instance is
//! not a miss in another. Final invocation still performs atomic admission.
use super::*;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ClientKey {
    Resident(usize),
    Deferred(usize),
    Attached(String),
}
fn key(client: &Client) -> ClientKey {
    match client {
        Client::Resident(value) => ClientKey::Resident(Arc::as_ptr(value) as usize),
        Client::Deferred(value) => ClientKey::Deferred(Arc::as_ptr(value) as usize),
        Client::Attached { .. } => ClientKey::Attached(client.attached_namespace_binding().unwrap()),
    }
}
/// Credentials/generations fence routes; durable operation identity is the
/// original journal namespace. An owner-issued view does not create new work.
pub(super) fn operation_namespace(binding:&str)->String {
    let Ok(value)=serde_json::from_str::<Value>(binding) else{return binding.into();};
    if value.is_object() && ["actor_id","origin","state_binding","namespace"].iter().all(|key|value[*key].is_string()) {
        json!([value["actor_id"],value["origin"],value["state_binding"],value["namespace"]]).to_string()
    }else{binding.into()}
}
#[derive(Default)]
pub(super) struct Observations {
    // Retain each handle until this call ends, so pointer keys cannot be reused.
    bindings: Mutex<BTreeMap<ClientKey, (Client, String)>>,
    operations: Mutex<BTreeMap<(String, String), Result<Value>>>,
    #[cfg(test)]
    reads: std::sync::atomic::AtomicUsize,
}
impl AgentTools {
    pub(crate) fn for_request(&self, request: &AgentRequest) -> std::borrow::Cow<'_, Self> {
        let routing = match request {
            AgentRequest::Send { .. } | AgentRequest::Reply { .. } | AgentRequest::Post { .. }
            | AgentRequest::Act { .. } | AgentRequest::Availability { .. } | AgentRequest::MemberName { .. }
            | AgentRequest::Status { .. } | AgentRequest::Recover { .. } => true,
            AgentRequest::Manage { mode, operation_id, .. } => mode == "invoke" && operation_id.is_some(),
            AgentRequest::Subscriptions { mode, operation_id, .. } => mode != "list" && operation_id.is_some(),
            _ => false,
        };
        if routing { std::borrow::Cow::Owned(self.for_call()) } else { std::borrow::Cow::Borrowed(self) }
    }
    /// Every public invocation gets its own observations. Address-selection
    /// clones within that invocation reuse them; concurrent calls never do.
    pub(crate) fn for_call(&self) -> Self {
        let mut selected = self.clone();
        selected.operation_observations = Some(Arc::new(Observations::default()));
        selected
    }
    pub(super) async fn observed_binding(&self, client: &Client) -> Result<String> {
        let key = key(client);
        if let Some(observations) = &self.operation_observations {
            if let Some((_, binding)) = observations.bindings.lock().await.get(&key) {
                return Ok(binding.clone());
            }
        }
        let binding = match client.attached_namespace_binding() {
            Some(binding) => binding,
            None => crate::communication_runtime::canonical_binding(
                &client.call(json!({"method":"binding"})).await?,
            ).to_string(),
        };
        if let Some(observations) = &self.operation_observations {
            observations.bindings.lock().await.insert(key, (client.clone(), binding.clone()));
        }
        Ok(binding)
    }
    pub(super) async fn observed_operation(&self, client: &Client, binding: &str, id: &str) -> Result<Value> {
        let key = (binding.to_owned(), id.to_owned());
        if let Some(observations) = &self.operation_observations {
            if let Some(value) = observations.operations.lock().await.get(&key) {
                return value.clone();
            }
            #[cfg(test)]
            observations.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let value = client.call(json!({"method":"operation","operation_id":id})).await;
        // A transport, authentication or storage failure is never a negative
        // operation observation. Preserve its original typed error unchanged.
        if value.is_ok() || value.as_ref().is_err_and(|error| error.code == "OPERATION_NOT_FOUND") {
            if let Some(observations) = &self.operation_observations {
                observations.operations.lock().await.insert(key, value.clone());
            }
        }
        value
    }
    pub(super) async fn forget_operation_observation(&self, id: &str) {
        if let Some(observations) = &self.operation_observations {
            observations.operations.lock().await.retain(|(_, operation), _| operation != id);
        }
    }
}

#[cfg(test)]
#[path = "agent_operation_observations_tests.rs"]
mod tests;
