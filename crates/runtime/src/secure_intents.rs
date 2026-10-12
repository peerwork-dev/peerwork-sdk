//! Pending-only secure packet journal. This records uncertain transport facts,
//! never an authenticated secure action result. Complete signed history replay
//! from peerwork-core is required before any future terminal transition.

use crate::secure_state::{SecureStateError, SecureStateStore};
use peerwork_core::{
    crypto::{base64url, decode_base64url, sha256_hex},
    wire_json::parse_wire_json_bounded,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
use thiserror::Error;

const MAX_PACKET: usize = 2 * 1024 * 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_OBSERVATIONS: usize = 8;
const MAX_DOCUMENT: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SecureIntentError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error("secure intent state has an unsupported version, shape, or pin")]
    Incompatible,
    #[error("secure intent metadata or packet is invalid")]
    Invalid,
    #[error("secure intent ID already binds different exact bytes or context")]
    Conflict,
    #[error("secure intent was not found")]
    NotFound,
    #[error("secure intent journal or observation limit exceeded")]
    TooLarge,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    trusted_origin: String,
    actor_id: String,
    rows: BTreeMap<String, Entry>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    action_id: String,
    workspace_id: Option<String>,
    trusted_owner_key: Option<String>,
    intent_digest: String,
    request_sha256: String,
    request_b64: String,
    response_b64: Vec<String>,
}

/// Unauthenticated local preparation context. Only a future core verified
/// prepared-packet proof may authorize transport submission of this row.
pub(crate) struct SecurePacketInput<'a> {
    pub intent_id: &'a str,
    pub path: &'a str,
    pub action_id: &'a str,
    pub workspace_id: Option<&'a str>,
    pub trusted_owner_key: Option<&'a str>,
    pub intent_digest: &'a str,
    pub exact_request: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSecureIntent {
    pub intent_id: String,
    pub workspace_id: Option<String>,
    pub action_id: String,
    pub observed_responses: usize,
}

pub(crate) struct SecureIntentJournal {
    store: SecureStateStore,
    document: Document,
}

impl SecureIntentJournal {
    pub(crate) fn open(
        path: &Path,
        trusted_origin: &str,
        actor_id: &str,
    ) -> Result<Self, SecureIntentError> {
        if !valid_origin(trusted_origin) || !valid_token(actor_id) {
            return Err(SecureIntentError::Invalid);
        }
        let store = SecureStateStore::open(path)?;
        let document = if let Some(bytes) = store.read_exact()? {
            parse_wire_json_bounded(&bytes, 8, MAX_DOCUMENT)
                .map_err(|_| SecureIntentError::Incompatible)?;
            serde_json::from_slice::<Document>(&bytes)
                .map_err(|_| SecureIntentError::Incompatible)?
        } else {
            Document {
                version: 1,
                trusted_origin: trusted_origin.into(),
                actor_id: actor_id.into(),
                rows: BTreeMap::new(),
            }
        };
        if document.version != 1
            || document.trusted_origin != trusted_origin
            || document.actor_id != actor_id
            || document.rows.len() > MAX_ENTRIES
            || document.rows.iter().any(|(id, row)| !valid_row(id, row))
        {
            return Err(SecureIntentError::Incompatible);
        }
        Ok(Self { store, document })
    }

    pub(crate) fn prepare(
        &mut self,
        input: SecurePacketInput<'_>,
    ) -> Result<PendingSecureIntent, SecureIntentError> {
        if !valid_id(input.intent_id)
            || !valid_secure_path(input.path)
            || !valid_action(input.action_id)
            || input.workspace_id.is_some_and(|id| !valid_token(id))
            || input.trusted_owner_key.is_some_and(|key| !valid_token(key))
            || !valid_digest(input.intent_digest)
            || input.exact_request.is_empty()
            || input.exact_request.len() > MAX_PACKET
        {
            return Err(SecureIntentError::Invalid);
        }
        let entry = Entry {
            path: input.path.into(),
            action_id: input.action_id.into(),
            workspace_id: input.workspace_id.map(str::to_owned),
            trusted_owner_key: input.trusted_owner_key.map(str::to_owned),
            intent_digest: input.intent_digest.into(),
            request_sha256: sha256_hex(input.exact_request),
            request_b64: base64url(input.exact_request),
            response_b64: Vec::new(),
        };
        if let Some(existing) = self.document.rows.get(input.intent_id) {
            let mut comparable = entry;
            comparable.response_b64 = existing.response_b64.clone();
            if existing != &comparable {
                return Err(SecureIntentError::Conflict);
            }
            return Ok(summary(input.intent_id, existing));
        }
        if self.document.rows.len() == MAX_ENTRIES {
            return Err(SecureIntentError::TooLarge);
        }
        let mut next = self.document.clone();
        next.rows.insert(input.intent_id.into(), entry);
        self.persist(next)?;
        Ok(summary(
            input.intent_id,
            self.document
                .rows
                .get(input.intent_id)
                .ok_or(SecureIntentError::Incompatible)?,
        ))
    }

    /// Persist an exact, unauthenticated HTTP response for later proof. HTTP
    /// 2xx, signed-looking content, and duplicate responses never mark ACCEPTED.
    pub(crate) fn observe_response(
        &mut self,
        intent_id: &str,
        exact_response: &[u8],
    ) -> Result<(), SecureIntentError> {
        if exact_response.is_empty() || exact_response.len() > MAX_RESPONSE {
            return Err(SecureIntentError::TooLarge);
        }
        let mut next = self.document.clone();
        let row = next
            .rows
            .get_mut(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        let encoded = base64url(exact_response);
        if row.response_b64.iter().any(|old| old == &encoded) {
            return Ok(());
        }
        if row.response_b64.len() == MAX_OBSERVATIONS {
            return Err(SecureIntentError::TooLarge);
        }
        row.response_b64.push(encoded);
        self.persist(next)
    }

    pub(crate) fn exact_request(&self, intent_id: &str) -> Result<Vec<u8>, SecureIntentError> {
        let row = self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        decode_base64url(&row.request_b64).map_err(|_| SecureIntentError::Incompatible)
    }

    pub(crate) fn exact_observations(
        &self,
        intent_id: &str,
    ) -> Result<Vec<Vec<u8>>, SecureIntentError> {
        let row = self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        row.response_b64
            .iter()
            .map(|item| decode_base64url(item).map_err(|_| SecureIntentError::Incompatible))
            .collect()
    }

    pub(crate) fn path(&self, intent_id: &str) -> Result<&str, SecureIntentError> {
        Ok(&self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?
            .path)
    }

    pub(crate) fn pending(&self) -> Vec<PendingSecureIntent> {
        self.document
            .rows
            .iter()
            .map(|(id, row)| summary(id, row))
            .collect()
    }

    fn persist(&mut self, next: Document) -> Result<(), SecureIntentError> {
        let bytes = serde_json::to_vec(&next).map_err(|_| SecureIntentError::Incompatible)?;
        if bytes.len() > MAX_DOCUMENT {
            return Err(SecureIntentError::TooLarge);
        }
        self.store.write_exact(&bytes)?;
        self.document = next;
        Ok(())
    }
}

fn summary(id: &str, row: &Entry) -> PendingSecureIntent {
    PendingSecureIntent {
        intent_id: id.into(),
        workspace_id: row.workspace_id.clone(),
        action_id: row.action_id.clone(),
        observed_responses: row.response_b64.len(),
    }
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_origin(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    (url.scheme() == "https" || url.scheme() == "http" && loopback)
        && url.as_str() == value
        && url.path() == "/"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_id(value: &str) -> bool {
    valid_token(value) || valid_digest(value)
}
fn valid_action(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
fn valid_secure_path(value: &str) -> bool {
    value.starts_with("/api/workspace/v1/secure/")
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_'))
        && !value.contains("//")
}
fn valid_row(id: &str, row: &Entry) -> bool {
    if !valid_id(id)
        || !valid_secure_path(&row.path)
        || !valid_action(&row.action_id)
        || row
            .workspace_id
            .as_deref()
            .is_some_and(|id| !valid_token(id))
        || row
            .trusted_owner_key
            .as_deref()
            .is_some_and(|key| !valid_token(key))
        || !valid_digest(&row.intent_digest)
        || !valid_digest(&row.request_sha256)
        || row.response_b64.len() > MAX_OBSERVATIONS
    {
        return false;
    }
    let Ok(request) = decode_base64url(&row.request_b64) else {
        return false;
    };
    if request.is_empty()
        || request.len() > MAX_PACKET
        || sha256_hex(&request) != row.request_sha256
        || base64url(&request) != row.request_b64
    {
        return false;
    }
    row.response_b64.iter().all(|item| {
        decode_base64url(item).is_ok_and(|bytes| {
            !bytes.is_empty() && bytes.len() <= MAX_RESPONSE && base64url(&bytes) == *item
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exact_packet_and_untrusted_response_survive_restart_without_acceptance() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("secure-intents.state");
        let actor = "a".repeat(43);
        let id = "b".repeat(43);
        let workspace = "c".repeat(43);
        let owner = "d".repeat(43);
        let digest = "0".repeat(64);
        let packet = b"{\"commit\":{\"signed\":\"opaque\"}}";
        let input = || SecurePacketInput {
            intent_id: &id,
            path: "/api/workspace/v1/secure/workspaces",
            action_id: "secure.bootstrap",
            workspace_id: Some(&workspace),
            trusted_owner_key: Some(&owner),
            intent_digest: &digest,
            exact_request: packet,
        };
        let mut first =
            SecureIntentJournal::open(&path, "https://peerwork.example/", &actor).unwrap();
        assert_eq!(first.prepare(input()).unwrap().observed_responses, 0);
        assert_eq!(first.prepare(input()).unwrap().observed_responses, 0);
        assert!(matches!(
            first.prepare(SecurePacketInput {
                exact_request: b"changed",
                ..input()
            }),
            Err(SecureIntentError::Conflict)
        ));
        first
            .observe_response(&id, b"HTTP-2xx-but-unverified")
            .unwrap();
        first
            .observe_response(&id, b"HTTP-2xx-but-unverified")
            .unwrap();
        assert_eq!(first.prepare(input()).unwrap().observed_responses, 1);
        assert_eq!(first.pending()[0].observed_responses, 1);
        drop(first);
        let reopened =
            SecureIntentJournal::open(&path, "https://peerwork.example/", &actor).unwrap();
        assert_eq!(reopened.exact_request(&id).unwrap(), packet);
        assert_eq!(
            reopened.exact_observations(&id).unwrap(),
            vec![b"HTTP-2xx-but-unverified".to_vec()]
        );
        assert_eq!(reopened.pending().len(), 1);
        drop(reopened);
        assert!(matches!(
            SecureIntentJournal::open(&path, "https://other.example/", &actor),
            Err(SecureIntentError::Incompatible)
        ));
        assert!(matches!(
            SecureIntentJournal::open(&path, "https://peerwork.example/", &"e".repeat(43)),
            Err(SecureIntentError::Incompatible)
        ));
    }
}
