//! A tool invocation reuses either an authenticated runtime or an already-open
//! participant. Attaching tools never changes the client's operation namespace.
use crate::{
    communication_runtime::{ClientRequest, RuntimeClient},
    participant::{ParticipantClient, Result},
    participant_client_tools::{self, Watches},
};
use serde_json::Value;

pub(crate) enum Client {
    Resident(RuntimeClient),
    Attached { client: ParticipantClient, watches: Watches },
}
impl From<RuntimeClient> for Client {
    fn from(client: RuntimeClient) -> Self { Self::Resident(client) }
}
impl Client {
    pub fn attached(client: ParticipantClient) -> Self {
        Self::Attached { client, watches: Default::default() }
    }
    pub fn actor_id(&self) -> &str {
        match self { Self::Resident(c) => c.actor_id(), Self::Attached { client, .. } => client.actor_id() }
    }
    pub fn origin(&self) -> &str {
        match self { Self::Resident(c) => c.origin(), Self::Attached { client, .. } => client.origin() }
    }
    pub fn attached_mode(&self) -> bool { matches!(self, Self::Attached { .. }) }
    pub async fn call(&self, request: Value) -> Result<Value> {
        match self {
            Self::Resident(c) => c.call(request).await,
            Self::Attached { client, watches } => {
                participant_client_tools::call(client, watches, ClientRequest::parse(request)?).await
            }
        }
    }
}
