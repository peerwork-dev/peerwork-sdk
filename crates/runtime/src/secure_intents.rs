//! Pending-only secure packet journal. This records uncertain transport facts,
//! never an authenticated secure action result. Complete signed history replay
//! from peerwork-core is required before any future terminal transition.

use crate::{
    kernel_identity::KernelIdentity,
    secure_lifecycle::SecureLifecycle,
    secure_state::{SecureStateError, SecureStateStore},
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, decode_base64url, sha256_hex},
    e2ee::{open_content_wire, SealedContent},
    prepared_secure_bootstrap::{
        verify_prepared_owner_bootstrap, BootstrapPins, BootstrapRequestError,
        VerifiedPreparedBootstrap,
    },
    prepared_secure_request::{
        verify_prepared_secure_commit_request, PreparedSecureRequestError, SecureCommitRequestPins,
        VerifiedPreparedSecureRequest,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

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
    #[error(transparent)]
    Proof(#[from] PreparedSecureRequestError),
    #[error(transparent)]
    BootstrapProof(#[from] BootstrapRequestError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("server rejected the saved secure request with HTTP {0}")]
    ServerRejected(u16),
    #[error("completed signed replay does not bind this saved action")]
    ReplayMismatch,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_receipt: Option<String>,
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

/// A protected result minted only after complete origin-bound signed replay
/// binds the exact saved packet to an ACTION receipt. Effects remain canonical
/// JSON so lossless UTF-16 wire values are preserved across restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcceptedSecureAction {
    pub intent_id: String,
    pub workspace_id: String,
    pub action_id: String,
    pub sequence: u64,
    pub commit_hash: String,
    pub receipt_canonical_json: String,
}

pub(crate) struct SecureIntentJournal {
    store: SecureStateStore,
    document: Document,
}

impl SecureIntentJournal {
    pub(crate) fn trusted_origin(&self) -> &str {
        &self.document.trusted_origin
    }

    pub(crate) fn actor_id(&self) -> &str {
        &self.document.actor_id
    }

    pub(crate) fn contains_id(&self, intent_id: &str) -> bool {
        self.document.rows.contains_key(intent_id)
    }

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
            || document
                .rows
                .iter()
                .any(|(id, row)| !valid_row(id, row, actor_id))
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
            accepted_receipt: None,
        };
        if let Some(existing) = self.document.rows.get(input.intent_id) {
            if existing.accepted_receipt.is_some() {
                return Err(SecureIntentError::Conflict);
            }
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

    /// Authenticate the exact saved packet and bind every row pin before an
    /// append send or retry. The trusted policy context is caller-supplied and
    /// must have been established from verified history by a higher layer.
    pub(crate) fn verified_saved_commit(
        &self,
        intent_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
        trusted_owner_key: &str,
        pins: &SecureCommitRequestPins<'_>,
    ) -> Result<(VerifiedPreparedSecureRequest, Vec<u8>), SecureIntentError> {
        if transport.trusted_origin() != self.document.trusted_origin
            || identity.actor_id() != self.document.actor_id
            || pins.actor_id != identity.actor_id()
            || pins.signing_key != identity.key_id()
        {
            return Err(SecureIntentError::Incompatible);
        }
        let row = self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        if row.accepted_receipt.is_some() {
            return Err(SecureIntentError::Conflict);
        }
        let request = self.exact_request(intent_id)?;
        let proof = verify_prepared_secure_commit_request(&request, &row.path, pins)?;
        if proof.command_id() != intent_id
            || proof.action_id() != row.action_id
            || Some(proof.workspace_id()) != row.workspace_id.as_deref()
            || row.trusted_owner_key.as_deref() != Some(trusted_owner_key)
            || proof.actor_id() != self.document.actor_id
            || proof.signing_key() != identity.key_id()
            || proof.path() != row.path
            || proof.request_sha256() != row.request_sha256
            || proof.commit_digest() != row.intent_digest
        {
            return Err(SecureIntentError::Incompatible);
        }
        Ok((proof, request))
    }

    /// Complete an ACTION only from the same configured-origin signed history
    /// that yields its exact command-bound receipt. The saved packet is
    /// reverified independently of any HTTP response, including after a lost
    /// reply. Recovered/skipped commands and pending-key histories have no
    /// eligible receipt.
    pub(crate) fn accept_replayed_action(
        &mut self,
        intent_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
        source: &TransportReplayedJournal,
    ) -> Result<AcceptedSecureAction, SecureIntentError> {
        source
            .verified_read()
            .map_err(|_| SecureIntentError::ReplayMismatch)?;
        if self.document.trusted_origin != transport.trusted_origin()
            || self.document.trusted_origin != source.origin()
            || self.document.actor_id != identity.actor_id()
            || source.source_actor_id() != identity.actor_id()
            || source.source_key_id() != identity.key_id()
        {
            return Err(SecureIntentError::ReplayMismatch);
        }
        let row = self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        if row.workspace_id.as_deref() != Some(source.replay().workspace_id())
            || row.trusted_owner_key.as_deref() != Some(source.replay().owner_signing_key())
        {
            return Err(SecureIntentError::ReplayMismatch);
        }
        let receipt = source
            .action_receipt(intent_id)
            .map_err(|_| SecureIntentError::ReplayMismatch)?
            .ok_or(SecureIntentError::ReplayMismatch)?;
        let request = self.exact_request(intent_id)?;
        let saved = parse_wire_json_bounded(&request, 64, MAX_PACKET)
            .map_err(|_| SecureIntentError::Incompatible)?;
        let payload = saved
            .get("commit")
            .and_then(|commit| commit.get("payload"))
            .ok_or(SecureIntentError::Incompatible)?;
        let workspace = wire_string(payload, "workspace_id")?;
        let policy_hash = wire_string(payload, "policy_hash")?;
        let previous = match payload.get("previous") {
            Some(WireValue::Null) => None,
            Some(WireValue::String(_)) => Some(wire_string(payload, "previous")?),
            _ => return Err(SecureIntentError::Incompatible),
        };
        let mode = wire_string(payload, "mode")?;
        let version = wire_unsigned(payload, "v")?;
        let protocol_format_ceiling = if version == 3 {
            Some(wire_unsigned(payload, "protocol_format_ceiling")?)
        } else {
            None
        };
        let pins = SecureCommitRequestPins {
            actor_id: identity.actor_id(),
            signing_key: identity.key_id(),
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence: wire_unsigned(payload, "sequence")?,
            previous: previous.as_deref(),
            epoch: wire_unsigned(payload, "epoch")?,
            mode: &mode,
            version,
            protocol_format_ceiling,
        };
        let proof = verify_prepared_secure_commit_request(&request, &row.path, &pins)?;
        let sequence = wire_unsigned(receipt, "sequence")?;
        let commit_hash = wire_string(receipt, "commit_hash")?;
        if proof.command_id() != intent_id
            || proof.action_id() != row.action_id
            || proof.workspace_id() != source.replay().workspace_id()
            || proof.actor_id() != identity.actor_id()
            || proof.signing_key() != identity.key_id()
            || proof.request_sha256() != row.request_sha256
            || proof.commit_digest() != row.intent_digest
            || proof.commit_digest() != commit_hash
            || receipt.object_len() != Some(7)
            || wire_string(receipt, "command_id")? != intent_id
            || wire_string(receipt, "actor_id")? != identity.actor_id()
            || wire_string(receipt, "action_id")? != row.action_id
            || receipt.get("instance_id") != payload.get("instance_id")
            || !matches!(receipt.get("effects"), Some(WireValue::Array(_)))
            || sequence != pins.sequence
            || !source
                .replay()
                .contains_checkpoint(sequence, Some(&commit_hash), &policy_hash)
        {
            return Err(SecureIntentError::ReplayMismatch);
        }
        let receipt_canonical_json = canonical_wire_value(receipt, CanonicalPath::SecureArtifact)
            .map_err(|_| SecureIntentError::ReplayMismatch)?;
        let action_id = row.action_id.clone();
        if let Some(stored) = &row.accepted_receipt {
            if stored != &receipt_canonical_json {
                return Err(SecureIntentError::Conflict);
            }
        } else {
            let mut next = self.document.clone();
            next.rows
                .get_mut(intent_id)
                .ok_or(SecureIntentError::NotFound)?
                .accepted_receipt = Some(receipt_canonical_json.clone());
            self.persist(next)?;
        }
        Ok(AcceptedSecureAction {
            intent_id: intent_id.to_owned(),
            workspace_id: workspace,
            action_id,
            sequence,
            commit_hash,
            receipt_canonical_json,
        })
    }

    /// Preserve PENDING across every HTTP result. An observed 2xx response is
    /// still untrusted until complete signed journal replay establishes effect.
    pub(crate) async fn submit_saved_commit(
        &mut self,
        intent_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
        trusted_owner_key: &str,
        pins: &SecureCommitRequestPins<'_>,
        cancel: &CancellationToken,
    ) -> Result<PendingSecureIntent, SecureIntentError> {
        let (proof, request) =
            self.verified_saved_commit(intent_id, identity, transport, trusted_owner_key, pins)?;
        let response = transport.post_exact(proof.path(), request, cancel).await?;
        if !response.wire.is_empty() {
            self.observe_response(intent_id, &response.wire)?;
        }
        if !(200..300).contains(&response.status) {
            return Err(SecureIntentError::ServerRejected(response.status));
        }
        self.document
            .rows
            .get(intent_id)
            .map(|row| summary(intent_id, row))
            .ok_or(SecureIntentError::Incompatible)
    }

    /// Reprove every immutable saved bootstrap field before the initial POST
    /// or an uncertain exact-byte retry. This never authorizes key activation.
    pub(crate) fn verified_saved_bootstrap(
        &self,
        intent_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
        lifecycle: &SecureLifecycle,
    ) -> Result<(VerifiedPreparedBootstrap, Vec<u8>), SecureIntentError> {
        if transport.trusted_origin() != self.document.trusted_origin
            || identity.actor_id() != self.document.actor_id
            || lifecycle.origin() != self.document.trusted_origin
            || lifecycle.actor_id() != identity.actor_id()
            || lifecycle.owner_actor_id() != identity.actor_id()
            || lifecycle.owner_key_id() != identity.key_id()
            || lifecycle.pending_bootstrap_key().is_none()
        {
            return Err(SecureIntentError::Incompatible);
        }
        let row = self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        let request = self.exact_request(intent_id)?;
        let proof = verify_prepared_owner_bootstrap(
            &request,
            &row.path,
            &BootstrapPins {
                workspace_id: lifecycle.workspace_id(),
                owner_actor: identity.actor_id(),
                owner_key: identity.key_id(),
            },
        )?;
        if proof.visibility() != "PRIVATE"
            || proof.command_id() != intent_id
            || proof.path() != row.path
            || row.action_id != "secure.bootstrap"
            || row.workspace_id.as_deref() != Some(proof.workspace_id())
            || row.trusted_owner_key.as_deref() != Some(identity.key_id())
            || row.intent_digest != proof.commit_digest()
            || row.request_sha256 != proof.request_sha256()
        {
            return Err(SecureIntentError::Incompatible);
        }
        // The signed packet alone does not bind the independently persisted
        // pending key. Prove this protected key opens exactly the saved body
        // before any initial submission or retry after restart.
        let saved = parse_wire_json_bounded(&request, 64, MAX_PACKET)
            .map_err(|_| SecureIntentError::Incompatible)?;
        let payload = saved
            .get("commit")
            .and_then(|commit| commit.get("payload"))
            .ok_or(SecureIntentError::Incompatible)?;
        let WireValue::Object(fields) = payload else {
            return Err(SecureIntentError::Incompatible);
        };
        let context = WireValue::Object(
            fields
                .iter()
                .filter(|(name, _)| {
                    !name.iter().copied().eq("mode".encode_utf16())
                        && !name.iter().copied().eq("body".encode_utf16())
                })
                .cloned()
                .collect(),
        );
        let context_wire = canonical_wire_value(&context, CanonicalPath::SecureArtifact)
            .map_err(|_| SecureIntentError::Incompatible)?;
        let body = payload.get("body").ok_or(SecureIntentError::Incompatible)?;
        let body_wire = canonical_wire_value(body, CanonicalPath::SecureArtifact)
            .map_err(|_| SecureIntentError::Incompatible)?;
        let sealed: SealedContent =
            serde_json::from_str(&body_wire).map_err(|_| SecureIntentError::Incompatible)?;
        let key = lifecycle
            .pending_bootstrap_key()
            .ok_or(SecureIntentError::Incompatible)?;
        let plaintext = Zeroizing::new(
            open_content_wire(key, &sealed, context_wire.as_bytes())
                .map_err(|_| SecureIntentError::Incompatible)?,
        );
        let mut operation = parse_wire_json_bounded(&plaintext, 64, 16 * 1024 * 1024)
            .map_err(|_| SecureIntentError::Incompatible)?;
        let valid_operation = operation.object_len() == Some(4)
            && operation.get("v").and_then(WireValue::as_number) == Some(1.0)
            && operation
                .get("kind")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("BOOTSTRAP")
            && matches!(operation.get("input"), Some(WireValue::Object(_)))
            && matches!(operation.get("objects"), Some(WireValue::Array(_)));
        wipe_wire(&mut operation);
        if !valid_operation {
            return Err(SecureIntentError::Incompatible);
        }
        Ok((proof, request))
    }

    pub(crate) async fn submit_saved_bootstrap(
        &mut self,
        intent_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
        lifecycle: &SecureLifecycle,
        cancel: &CancellationToken,
    ) -> Result<PendingSecureIntent, SecureIntentError> {
        let (proof, request) =
            self.verified_saved_bootstrap(intent_id, identity, transport, lifecycle)?;
        let response = transport.post_exact(proof.path(), request, cancel).await?;
        if !response.wire.is_empty() {
            self.observe_response(intent_id, &response.wire)?;
        }
        if !(200..300).contains(&response.status) {
            return Err(SecureIntentError::ServerRejected(response.status));
        }
        self.document
            .rows
            .get(intent_id)
            .map(|row| summary(intent_id, row))
            .ok_or(SecureIntentError::Incompatible)
    }

    /// PUBLIC bootstrap has no epoch key. Identity, configured origin, signed
    /// policy/commit and every immutable row field are rechecked before POST.
    pub(crate) fn verified_saved_public_bootstrap(
        &self,
        intent_id: &str,
        workspace_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
    ) -> Result<(VerifiedPreparedBootstrap, Vec<u8>), SecureIntentError> {
        if transport.trusted_origin() != self.document.trusted_origin
            || identity.actor_id() != self.document.actor_id
        {
            return Err(SecureIntentError::Incompatible);
        }
        let row = self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?;
        let request = self.exact_request(intent_id)?;
        let proof = verify_prepared_owner_bootstrap(
            &request,
            &row.path,
            &BootstrapPins {
                workspace_id,
                owner_actor: identity.actor_id(),
                owner_key: identity.key_id(),
            },
        )?;
        if proof.visibility() != "PUBLIC"
            || proof.command_id() != intent_id
            || proof.path() != row.path
            || row.action_id != "secure.bootstrap"
            || row.workspace_id.as_deref() != Some(workspace_id)
            || row.trusted_owner_key.as_deref() != Some(identity.key_id())
            || row.intent_digest != proof.commit_digest()
            || row.request_sha256 != proof.request_sha256()
        {
            return Err(SecureIntentError::Incompatible);
        }
        Ok((proof, request))
    }

    pub(crate) async fn submit_saved_public_bootstrap(
        &mut self,
        intent_id: &str,
        workspace_id: &str,
        identity: &KernelIdentity,
        transport: &HttpTransport,
        cancel: &CancellationToken,
    ) -> Result<PendingSecureIntent, SecureIntentError> {
        let (proof, request) =
            self.verified_saved_public_bootstrap(intent_id, workspace_id, identity, transport)?;
        let response = transport.post_exact(proof.path(), request, cancel).await?;
        if !response.wire.is_empty() {
            self.observe_response(intent_id, &response.wire)?;
        }
        if !(200..300).contains(&response.status) {
            return Err(SecureIntentError::ServerRejected(response.status));
        }
        self.document
            .rows
            .get(intent_id)
            .map(|row| summary(intent_id, row))
            .ok_or(SecureIntentError::Incompatible)
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
            .filter(|(_, row)| row.accepted_receipt.is_none())
            .map(|(id, row)| summary(id, row))
            .collect()
    }

    pub(crate) fn accepted_receipt(
        &self,
        intent_id: &str,
    ) -> Result<Option<&str>, SecureIntentError> {
        Ok(self
            .document
            .rows
            .get(intent_id)
            .ok_or(SecureIntentError::NotFound)?
            .accepted_receipt
            .as_deref())
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

fn wipe_wire(value: &mut WireValue) {
    match value {
        WireValue::String(units) => units.zeroize(),
        WireValue::Array(items) => items.iter_mut().for_each(wipe_wire),
        WireValue::Object(fields) => {
            for (name, item) in fields {
                name.zeroize();
                wipe_wire(item);
            }
        }
        WireValue::Null | WireValue::Bool(_) | WireValue::Number(_) => {}
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
fn wire_string(value: &WireValue, key: &str) -> Result<String, SecureIntentError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(SecureIntentError::Incompatible)
}
fn wire_unsigned(value: &WireValue, key: &str) -> Result<u64, SecureIntentError> {
    let number = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(SecureIntentError::Incompatible)?;
    if !number.is_finite()
        || number < 0.0
        || number > 9_007_199_254_740_991.0
        || number.fract() != 0.0
    {
        return Err(SecureIntentError::Incompatible);
    }
    Ok(number as u64)
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
fn valid_row(id: &str, row: &Entry, actor_id: &str) -> bool {
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
    let responses_valid = row.response_b64.iter().all(|item| {
        decode_base64url(item).is_ok_and(|bytes| {
            !bytes.is_empty() && bytes.len() <= MAX_RESPONSE && base64url(&bytes) == *item
        })
    });
    let accepted_valid = row.accepted_receipt.as_ref().is_none_or(|encoded| {
        let Ok(receipt) = parse_wire_json_bounded(encoded.as_bytes(), 16, MAX_DOCUMENT) else {
            return false;
        };
        receipt.object_len() == Some(7)
            && canonical_wire_value(&receipt, CanonicalPath::SecureArtifact)
                .is_ok_and(|canonical| canonical == *encoded)
            && receipt
                .get("command_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(id)
            && receipt
                .get("commit_hash")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(&row.intent_digest)
            && receipt
                .get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(actor_id)
            && receipt
                .get("action_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(&row.action_id)
            && wire_unsigned(&receipt, "sequence").is_ok()
            && receipt.get("instance_id").is_some()
            && matches!(receipt.get("effects"), Some(WireValue::Array(_)))
    });
    responses_valid && accepted_valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerwork_core::{
        canonical::{canonical, Path as CanonicalPath},
        crypto::sign_canonical,
    };
    use serde_json::json;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        fs,
        io::BufRead,
        process::{Child, Command, Stdio},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn signed_append(
        identity: &KernelIdentity,
        workspace: &str,
        policy: &str,
        previous: &str,
    ) -> (String, String, Vec<u8>, String) {
        let command = "c".repeat(43);
        let action = "discussion.post".to_string();
        let payload = json!({
            "v":3,"workspace_id":workspace,"sequence":2,"previous":previous,
            "policy_hash":policy,"epoch":1,"actor_id":identity.actor_id(),
            "signing_key":identity.key_id(),"command_id":command,"action_id":action,
            "instance_id":"i".repeat(43),"issued_at":1_700_000_000_000_u64,
            "delegation":null,"mode":"PRIVATE","protocol_format_ceiling":1,
            "body":{"v":1,"alg":"A256GCM","nonce":base64url(&[1;12]),"chunks":[base64url(&[2;16])]}
        });
        let signature = sign_canonical(
            "peerwork.secure.commit.v3",
            &payload,
            identity.signing_key(),
        )
        .unwrap();
        let commit = json!({"payload":payload,"signature":signature});
        let digest = sha256_hex(
            canonical(&commit, CanonicalPath::SecureArtifact)
                .unwrap()
                .as_bytes(),
        );
        let request = serde_json::to_vec(&json!({"commit":commit})).unwrap();
        (command, action, request, digest)
    }

    #[test]
    fn saved_signed_commit_requires_every_immutable_row_pin_before_transport() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&root.path().join("identity.state")).unwrap();
        let workspace = "w".repeat(43);
        let policy = "a".repeat(64);
        let previous = "b".repeat(64);
        let (id, action, request, digest) =
            signed_append(&identity, &workspace, &policy, &previous);
        let mut config = crate::transport::TransportConfig::new("http://127.0.0.1:12345/");
        config.allow_loopback_http = true;
        let transport = HttpTransport::new(config).unwrap();
        let path = format!("/api/workspace/v1/secure/workspaces/{workspace}/commits");
        let pins = SecureCommitRequestPins {
            actor_id: identity.actor_id(),
            signing_key: identity.key_id(),
            workspace_id: &workspace,
            policy_hash: &policy,
            sequence: 2,
            previous: Some(&previous),
            epoch: 1,
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let mut journal = SecureIntentJournal::open(
            &root.path().join("intent.state"),
            transport.trusted_origin(),
            identity.actor_id(),
        )
        .unwrap();
        journal
            .prepare(SecurePacketInput {
                intent_id: &id,
                path: &path,
                action_id: &action,
                workspace_id: Some(&workspace),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &digest,
                exact_request: &request,
            })
            .unwrap();
        assert!(journal
            .verified_saved_commit(&id, &identity, &transport, identity.key_id(), &pins)
            .is_ok());
        assert!(journal
            .verified_saved_commit(&id, &identity, &transport, &"x".repeat(43), &pins)
            .is_err());
        let bad_pins = SecureCommitRequestPins {
            policy_hash: &"0".repeat(64),
            ..pins
        };
        assert!(journal
            .verified_saved_commit(&id, &identity, &transport, identity.key_id(), &bad_pins)
            .is_err());
        let mut wrong = SecureIntentJournal::open(
            &root.path().join("wrong.state"),
            transport.trusted_origin(),
            identity.actor_id(),
        )
        .unwrap();
        wrong
            .prepare(SecurePacketInput {
                intent_id: &id,
                path: &path,
                action_id: "wiki.revise",
                workspace_id: Some(&workspace),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &digest,
                exact_request: &request,
            })
            .unwrap();
        assert!(wrong
            .verified_saved_commit(&id, &identity, &transport, identity.key_id(), &pins)
            .is_err());
    }

    #[tokio::test]
    async fn lost_http_reply_then_restart_retries_identical_verified_packet() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&root.path().join("identity.state")).unwrap();
        let workspace = "w".repeat(43);
        let policy = "a".repeat(64);
        let previous = "b".repeat(64);
        let (id, action, request, digest) =
            signed_append(&identity, &workspace, &policy, &previous);
        let path = format!("/api/workspace/v1/secure/workspaces/{workspace}/commits");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let expected = request.clone();
        let expected_path = path.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut received = Vec::new();
                let body_start = loop {
                    let mut chunk = [0u8; 2048];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0);
                    received.extend_from_slice(&chunk[..count]);
                    if let Some(pos) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let header = std::str::from_utf8(&received[..body_start]).unwrap();
                assert!(header.starts_with(&format!("POST {expected_path} HTTP/1.1")));
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                assert_eq!(content_length, expected.len());
                while received.len() - body_start < content_length {
                    let mut chunk = [0u8; 2048];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0);
                    received.extend_from_slice(&chunk[..count]);
                }
                assert_eq!(
                    &received[body_start..body_start + content_length],
                    expected.as_slice()
                );
                if attempt == 1 {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n{\"ok\":1}")
                        .await
                        .unwrap();
                    socket.shutdown().await.unwrap();
                }
                // First request was fully applied at the socket, then its reply
                // disappeared. No claim about a Peerwork service effect follows.
            }
        });
        let mut config = crate::transport::TransportConfig::new(origin);
        config.allow_loopback_http = true;
        let transport = HttpTransport::new(config).unwrap();
        let pins = SecureCommitRequestPins {
            actor_id: identity.actor_id(),
            signing_key: identity.key_id(),
            workspace_id: &workspace,
            policy_hash: &policy,
            sequence: 2,
            previous: Some(&previous),
            epoch: 1,
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let journal_path = root.path().join("intent.state");
        let mut journal = SecureIntentJournal::open(
            &journal_path,
            transport.trusted_origin(),
            identity.actor_id(),
        )
        .unwrap();
        journal
            .prepare(SecurePacketInput {
                intent_id: &id,
                path: &path,
                action_id: &action,
                workspace_id: Some(&workspace),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &digest,
                exact_request: &request,
            })
            .unwrap();
        let cancellation = CancellationToken::new();
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            journal.submit_saved_commit(
                &id,
                &identity,
                &transport,
                identity.key_id(),
                &pins,
                &cancellation,
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            first,
            Err(SecureIntentError::Transport(
                TransportError::SubmittedUncertain
            ))
        ));
        assert_eq!(journal.pending()[0].observed_responses, 0);
        drop(journal);
        let mut reopened = SecureIntentJournal::open(
            &journal_path,
            transport.trusted_origin(),
            identity.actor_id(),
        )
        .unwrap();
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reopened.submit_saved_commit(
                &id,
                &identity,
                &transport,
                identity.key_id(),
                &pins,
                &cancellation,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(second.intent_id, id);
        assert_eq!(second.observed_responses, 1);
        assert_eq!(
            reopened.exact_observations(&id).unwrap(),
            vec![b"{\"ok\":1}".to_vec()]
        );
        assert_eq!(reopened.pending().len(), 1);
        server.await.unwrap();
    }

    /// Opt-in actual tracked Peerwork service, with fresh synthetic state.
    /// The proxy forwards/applies the first append then drops its response.
    #[tokio::test]
    async fn actual_service_secure_append_retry_then_signed_receipt_acceptance() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_SECURE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "reference bridge exited before ready");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let text = |key: &str| ready["secure"][key].as_str().unwrap().to_owned();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let workspace = text("workspace_id");
        let actor = text("actor_id");
        let signing_key = text("signing_key");
        let owner = text("owner_key");
        let policy = text("policy_hash");
        let previous = text("previous");
        let id = text("command_id");
        let action = text("action_id");
        let digest = text("commit_digest");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &root.path().join("native-identity.state"),
            &root.path().join("synthetic-agent-ed25519.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), actor);
        assert_eq!(identity.key_id(), signing_key);
        let request = fs::read(root.path().join("synthetic-secure-request.json")).unwrap();
        let path = format!("/api/workspace/v1/secure/workspaces/{workspace}/commits");
        let mut config = crate::transport::TransportConfig::new(origin.clone());
        config.allow_loopback_http = true;
        let transport = HttpTransport::new(config).unwrap();
        let counts_url = format!("{origin}__test/secure-counts");
        let baseline_counts: serde_json::Value = serde_json::from_str(
            &reqwest::get(&counts_url)
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(baseline_counts["commits"].as_u64(), Some(1));
        assert_eq!(baseline_counts["head_sequence"].as_u64(), Some(1));
        let pins = SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &signing_key,
            workspace_id: &workspace,
            policy_hash: &policy,
            sequence: ready["secure"]["sequence"].as_u64().unwrap(),
            previous: Some(&previous),
            epoch: ready["secure"]["epoch"].as_u64().unwrap(),
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let state = root.path().join("native-secure-intents.state");
        let mut journal =
            SecureIntentJournal::open(&state, transport.trusted_origin(), &actor).unwrap();
        journal
            .prepare(SecurePacketInput {
                intent_id: &id,
                path: &path,
                action_id: &action,
                workspace_id: Some(&workspace),
                trusted_owner_key: Some(&owner),
                intent_digest: &digest,
                exact_request: &request,
            })
            .unwrap();
        let after_prepare: serde_json::Value = serde_json::from_str(
            &reqwest::get(&counts_url)
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after_prepare, baseline_counts);
        let cancel = CancellationToken::new();
        assert!(matches!(
            journal
                .submit_saved_commit(&id, &identity, &transport, &owner, &pins, &cancel)
                .await,
            Err(SecureIntentError::Transport(
                TransportError::SubmittedUncertain
            ))
        ));
        assert_eq!(journal.pending()[0].observed_responses, 0);
        drop(journal);
        let first_counts: serde_json::Value = serde_json::from_str(
            &reqwest::get(&counts_url)
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first_counts["commits"].as_u64(), Some(2));
        assert_eq!(first_counts["head_sequence"].as_u64(), Some(2));
        let mut reopened =
            SecureIntentJournal::open(&state, transport.trusted_origin(), &actor).unwrap();
        let status = reopened
            .submit_saved_commit(&id, &identity, &transport, &owner, &pins, &cancel)
            .await
            .unwrap();
        assert_eq!(status.intent_id, id);
        assert_eq!(status.observed_responses, 1);
        assert_eq!(reopened.pending().len(), 1);
        let second_counts: serde_json::Value = serde_json::from_str(
            &reqwest::get(&counts_url)
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second_counts, first_counts);
        // The fixture supplies a TS-created, signed and encrypted ACTION.
        // Importing its synthetic keyring is test-only setup; the acceptance
        // transition itself still requires real configured-origin page custody
        // and a complete signed replay receipt.
        let mut lifecycle = SecureLifecycle::open(
            &root.path().join("native-action-lifecycle.state"),
            transport.trusted_origin(),
            identity.actor_id(),
            &workspace,
            &actor,
            &owner,
        )
        .unwrap();
        lifecycle
            .import_active_for_test(
                &fs::read(root.path().join("synthetic-secure-keyring.json")).unwrap(),
            )
            .unwrap();
        let mut read_config = crate::transport::TransportConfig::new(origin.clone());
        read_config.allow_loopback_http = true;
        let client = crate::kernel_client::KernelClient::open(
            read_config,
            &root.path().join("native-action-discovery.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut reader = crate::secure_journal_read::SecureJournalRead::open(
            &root.path().join("native-action-journal.state"),
            &client,
            &identity,
            &workspace,
            text("authority").as_str(),
        )
        .unwrap();
        assert!(
            reader
                .fetch_next(&client, &identity, &CancellationToken::new())
                .await
                .unwrap()
                .complete_transport
        );
        let pages = reader.authenticated_pages(&client, &identity).unwrap();
        let replay =
            crate::secure_verified_read::replay_authenticated_pages(&pages, &lifecycle).unwrap();
        assert_eq!(replay.replay().sequence(), 2);
        assert!(replay.action_receipt(&id).unwrap().is_some());
        let mut wrong = SecureIntentJournal::open(
            &root.path().join("wrong-action.state"),
            transport.trusted_origin(),
            identity.actor_id(),
        )
        .unwrap();
        wrong
            .prepare(SecurePacketInput {
                intent_id: &id,
                path: &path,
                action_id: "discussion.other",
                workspace_id: Some(&workspace),
                trusted_owner_key: Some(&owner),
                intent_digest: &digest,
                exact_request: &request,
            })
            .unwrap();
        assert!(wrong
            .accept_replayed_action(&id, &identity, &transport, &replay)
            .is_err());
        assert_eq!(wrong.pending().len(), 1);
        let accepted = reopened
            .accept_replayed_action(&id, &identity, &transport, &replay)
            .unwrap();
        assert_eq!(accepted.sequence, 2);
        assert_eq!(accepted.commit_hash, digest);
        assert_eq!(accepted.action_id, action);
        assert_eq!(accepted.workspace_id, workspace);
        assert_eq!(reopened.pending().len(), 0);
        assert!(matches!(
            reopened
                .submit_saved_commit(&id, &identity, &transport, &owner, &pins, &cancel)
                .await,
            Err(SecureIntentError::Conflict)
        ));
        drop(reopened);
        let reopened =
            SecureIntentJournal::open(&state, transport.trusted_origin(), &actor).unwrap();
        assert_eq!(reopened.pending().len(), 0);
        assert_eq!(
            reopened.accepted_receipt(&id).unwrap(),
            Some(accepted.receipt_canonical_json.as_str())
        );
        drop(child);
    }

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
