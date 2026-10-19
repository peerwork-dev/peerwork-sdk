//! Durable logical-intent namespace shared by the context's producers.
//! This index never establishes delivery or acceptance; producer journals do.
use crate::{secure_read_profile::SecureReadProfileConfig, secure_state::SecureStateStore};
use peerwork_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub(crate) enum OperationIndexError {
    #[error("operation id or intent kind is invalid")]
    Input,
    #[error("operation index could not be verified or persisted")]
    State,
    #[error("operation id is already bound to a different intent")]
    Conflict,
    #[error("operation index belongs to a different context")]
    Context,
    #[error("operation index capacity reached")]
    Limit,
}
impl OperationIndexError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Input => "ACTION_INPUT_INVALID",
            Self::State => "OPERATION_STATE",
            Self::Conflict => "INTENT_CONFLICT",
            Self::Context => "CONTEXT_BINDING",
            Self::Limit => "OPERATION_LIMIT",
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    kind: String,
    digest: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    scope: Value,
    rows: BTreeMap<String, Row>,
}

fn scope(config: &SecureReadProfileConfig, actor: &str) -> Value {
    json!({"origin":config.origin,"workspace_id":config.workspace_id,"actor_id":actor,
        "owner_actor_id":config.owner_actor_id,"owner_key_id":config.owner_key_id,
        "authority":config.authority})
}
fn load(store: &SecureStateStore, expected: Value) -> Result<Index, OperationIndexError> {
    let Some(wire) = store
        .read_exact_secret()
        .map_err(|_| OperationIndexError::State)?
    else {
        return Ok(Index {
            version: 1,
            scope: expected,
            rows: BTreeMap::new(),
        });
    };
    if wire.len() > 4 * 1024 * 1024 {
        return Err(OperationIndexError::Limit);
    }
    let index: Index = serde_json::from_slice(&wire).map_err(|_| OperationIndexError::State)?;
    if index.version != 1 || index.scope != expected {
        return Err(OperationIndexError::Context);
    }
    if index.rows.len() > 10_000 {
        return Err(OperationIndexError::Limit);
    }
    Ok(index)
}
pub(crate) fn bind(
    config: &SecureReadProfileConfig,
    actor: &str,
    id: &str,
    kind: &str,
    intent: &Value,
) -> Result<(), OperationIndexError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || !matches!(kind, "protocol.action" | "browser.approve")
    {
        return Err(OperationIndexError::Input);
    }
    let store = SecureStateStore::open(&config.state_dir.join("context-operations.state"))
        .map_err(|_| OperationIndexError::State)?;
    let mut index = load(&store, scope(config, actor))?;
    // serde_json's default map is sorted; nested object key ordering is stable.
    let digest = sha256_hex(&serde_json::to_vec(intent).map_err(|_| OperationIndexError::Input)?);
    if let Some(row) = index.rows.get(id) {
        return if row.kind == kind && row.digest == digest {
            Ok(())
        } else {
            Err(OperationIndexError::Conflict)
        };
    }
    if index.rows.len() >= 10_000 {
        return Err(OperationIndexError::Limit);
    }
    index.rows.insert(
        id.into(),
        Row {
            kind: kind.into(),
            digest,
        },
    );
    let wire = serde_json::to_vec(&index).map_err(|_| OperationIndexError::State)?;
    store
        .write_exact(&wire)
        .map_err(|_| OperationIndexError::State)
}
pub(crate) fn kind(
    config: &SecureReadProfileConfig,
    actor: &str,
    id: &str,
) -> Result<Option<String>, OperationIndexError> {
    let path = config.state_dir.join("context-operations.state");
    if crate::secure_state::missing_in_private_parent(&path) {
        return Ok(None);
    }
    let store = SecureStateStore::open(&path).map_err(|_| OperationIndexError::State)?;
    Ok(load(&store, scope(config, actor))?
        .rows
        .get(id)
        .map(|r| r.kind.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_logical_intent_across_producers_and_restart() {
        let dir = crate::test_support::protected_test_dir();
        let config:SecureReadProfileConfig=serde_json::from_value(json!({"origin":"https://example.invalid/","state_dir":dir.path(),"identity_path":dir.path().join("identity.state"),"workspace_id":"workspace"})).unwrap();
        assert!(kind(&config, "actor", "logical").unwrap().is_none());
        assert!(!dir.path().join("context-operations.state").exists());
        let intent = json!({"kind":"protocol.action","values":{"a":1,"b":2}});
        bind(&config, "actor", "logical", "protocol.action", &intent).unwrap();
        bind(&config, "actor", "logical", "protocol.action", &intent).unwrap();
        assert_eq!(
            kind(&config, "actor", "logical").unwrap().as_deref(),
            Some("protocol.action")
        );
        assert!(matches!(
            bind(
                &config,
                "actor",
                "logical",
                "browser.approve",
                &json!({"reference":"different"})
            ),
            Err(OperationIndexError::Conflict)
        ));
        assert!(matches!(
            bind(
                &config,
                "actor",
                "logical",
                "protocol.action",
                &json!({"values":{"a":2}})
            ),
            Err(OperationIndexError::Conflict)
        ));
        assert!(matches!(
            kind(&config, "different-actor", "logical"),
            Err(OperationIndexError::Context)
        ));
        assert_eq!(
            kind(&config, "actor", "logical").unwrap().as_deref(),
            Some("protocol.action")
        );
    }
}
