//! PUBLIC owner invitation transport. The signed offer is persisted before
//! submission; HTTP replies and local rows never grant member authority.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_identity_directory::{
        IdentityDirectoryConfig, IdentityDirectoryError, SecureIdentityDirectory,
    },
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_journal_read::sign_read_proof,
    secure_lifecycle::{ReplayKeyringState, SecureLifecycle},
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    transport::{TransportConfig, TransportError},
};
use peerwork_core::{
    prepared_public_admission::{
        prepare_private_delivery, prepare_private_offer_utf16, prepare_public_delivery,
        prepare_public_offer_utf16, verify_saved_private_offer, verify_saved_public_offer,
        PublicAdmissionError,
    },
    wire_json::{parse_wire_json_js_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const OFFER_PATH: &str = "/api/workspace/v1/secure/invitations";

fn delivery_path(invite_id: &str) -> Result<String, PublicAdmissionRuntimeError> {
    if invite_id.len() != 43
        || !invite_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(PublicAdmissionRuntimeError::Input);
    }
    Ok(format!("{OFFER_PATH}/{invite_id}/key-grants"))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicOfferInput {
    pub recipient_certificate_json: String,
    pub scopes_json: String,
    #[serde(default)]
    pub message: String,
    /// Exact JavaScript UTF-16 code units when a message includes an unpaired
    /// surrogate. Omit for ordinary Unicode text.
    #[serde(default)]
    pub message_utf16: Option<Vec<u16>>,
    #[serde(default)]
    pub invite_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicOfferResult {
    pub status: String,
    pub invite_id: String,
    pub workspace_id: String,
    pub offer_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPublicOffer {
    pub invite_id: String,
    pub workspace_id: String,
    pub offer_hash: String,
    pub observed_responses: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicDeliveryResult {
    pub status: String,
    pub invite_id: String,
    pub grant_id: String,
    pub workspace_id: String,
    pub grant_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPublicDelivery {
    pub grant_id: String,
    pub workspace_id: String,
    pub grant_hash: String,
    pub observed_responses: usize,
}

#[derive(Debug, Error)]
pub enum PublicAdmissionRuntimeError {
    #[error(transparent)]
    Read(#[from] SecureReadAccessError),
    #[error(transparent)]
    Intent(#[from] SecureIntentError),
    #[error(transparent)]
    Offer(#[from] PublicAdmissionError),
    #[error(transparent)]
    Directory(#[from] IdentityDirectoryError),
    #[error("signed admission control proof could not be created")]
    ReadProof,
    #[error("protected owner identity or PUBLIC policy differs")]
    Identity,
    #[error("admission input or saved packet is invalid")]
    Input,
    #[error("configured admission transport failed")]
    Transport,
    #[error("server rejected signed offer with HTTP {0}")]
    ServerRejected(u16),
    #[error(transparent)]
    Rejected(crate::operation_diagnostics::ServerRejection),
    #[error("system clock is invalid")]
    Clock,
    #[error("async runtime could not start")]
    Runtime,
    #[error("admission result could not be encoded")]
    Encoding,
}

impl PublicAdmissionRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(error) => error.code(),
            Self::Intent(SecureIntentError::Conflict) => "INTENT_CONFLICT",
            Self::Intent(SecureIntentError::NotFound) => "INTENT_NOT_FOUND",
            Self::Intent(SecureIntentError::TooLarge) => "RESOURCE_LIMIT",
            Self::Intent(SecureIntentError::Transport(_)) | Self::Transport => "TRANSPORT_FAILED",
            Self::Rejected(detail) | Self::Intent(SecureIntentError::Rejected(detail)) => detail.code,
            Self::Intent(SecureIntentError::ServerRejected(_)) | Self::ServerRejected(_) => {
                "SERVER_REJECTED"
            }
            Self::Intent(SecureIntentError::ReplayMismatch) => "VERIFICATION_FAILED",
            Self::Intent(_) => "INTENT_STATE",
            Self::Offer(_) | Self::Input => "ADMISSION_INPUT_INVALID",
            Self::Directory(error) => error.code(),
            Self::ReadProof => "READ_PROOF_FAILED",
            Self::Identity => "IDENTITY_STATE",
            Self::Clock => "CLOCK_INVALID",
            Self::Runtime => "RUNTIME_FAILED",
            Self::Encoding => "RESULT_ENCODING_FAILED",
        }
    }
}

pub struct SecurePublicAdmission {
    config: SecureReadProfileConfig,
    private_mode: bool,
}

impl SecurePublicAdmission {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self {
            config,
            private_mode: false,
        }
    }

    pub(crate) fn new_private(config: SecureReadProfileConfig) -> Self {
        Self {
            config,
            private_mode: true,
        }
    }

    /// Author and persist the owner delivery only after a fresh complete
    /// replay and authenticated signed ACCEPT control record. The result is
    /// transport-pending until signed journal and grant evidence is replayed.
    pub fn deliver_accepted_json(
        &self,
        invite_id: &str,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.deliver_accepted_json_with_cancel(invite_id, &CancellationToken::new())
    }

    pub fn deliver_accepted_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.deliver_operation_json_with_cancel(invite_id, None, cancel)
    }

    pub(crate) fn deliver_operation_json_with_cancel(
        &self, invite_id: &str, operation: Option<(&str, &str)>, cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        let path = delivery_path(invite_id)?;
        if let Some((id, digest)) = operation {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            let journal = SecureIntentJournal::open(&self.config.state_dir.join("admission-intents.state"),
                &self.config.origin, identity.actor_id())?;
            let saved = journal.action_operation(id)?;
            drop(journal);
            if let Some((grant, saved_digest)) = saved {
                if saved_digest != digest { return Err(SecureIntentError::Conflict.into()); }
                return self.retry_delivery_json_with_cancel(&grant, cancel);
            }
        }
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            if !self.config.matches_verified_origin(source.origin())
                || source.replay().workspace_id() != self.config.workspace_id
                || source.replay().owner_actor_id() != identity.actor_id()
                || source.replay().owner_signing_key() != identity.key_id()
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            let control = self.read_owner_control(invite_id, &identity, cancel)?;
            let offer = control
                .get("offer")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let decision = control
                .get("decision")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            if self.private_mode {
                let certificate = offer
                    .get("payload")
                    .and_then(|payload| payload.get("recipient"))
                    .ok_or(PublicAdmissionRuntimeError::Input)?;
                self.verify_current_private_recipient(certificate, cancel)?;
            }
            if !matches!(control.get("grant"), None | Some(WireValue::Null))
                || control
                    .get("offer_hash")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(
                        peerwork_core::crypto::sha256_hex(
                            peerwork_core::wire_json::canonical_wire_value(
                                offer,
                                peerwork_core::canonical::Path::SecureArtifact,
                            )
                            .map_err(|_| PublicAdmissionRuntimeError::Input)?
                            .as_bytes(),
                        )
                        .as_str(),
                    )
            {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let current_policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let offer_wire = peerwork_core::wire_json::canonical_wire_value(
                offer,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let decision_wire = peerwork_core::wire_json::canonical_wire_value(
                decision,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let prepared = if self.private_mode {
                if source.keyring_state() != Some(ReplayKeyringState::Active) {
                    return Err(PublicAdmissionRuntimeError::Identity);
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    &self.config.workspace_id,
                    identity.actor_id(),
                    identity.key_id(),
                )
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
                let ring = lifecycle
                    .active_keyring_without_pending()
                    .ok_or(PublicAdmissionRuntimeError::Identity)?;
                prepare_private_delivery(
                    current_policy,
                    source.checkpoint_canonical_json().as_bytes(),
                    offer_wire.as_bytes(),
                    decision_wire.as_bytes(),
                    now_ms()?,
                    identity.signing_key(),
                    ring,
                )?
            } else {
                prepare_public_delivery(
                    current_policy,
                    source.checkpoint_canonical_json().as_bytes(),
                    offer_wire.as_bytes(),
                    decision_wire.as_bytes(),
                    now_ms()?,
                    identity.signing_key(),
                )?
            };
            if prepared.invite_id() != invite_id {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("admission-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            if journal.contains_id(prepared.grant_id()) {
                return Err(PublicAdmissionRuntimeError::Intent(
                    SecureIntentError::Conflict,
                ));
            }
            let packet = SecurePacketInput {
                intent_id: prepared.grant_id(), path: &path, action_id: "secure.invite.finalize",
                workspace_id: Some(&self.config.workspace_id), trusted_owner_key: Some(identity.key_id()),
                intent_digest: prepared.grant_hash(), exact_request: prepared.request_wire(),
            };
            if let Some((id, digest)) = operation {
                journal.prepare_action_operation(packet, id, digest)?;
            } else { journal.prepare(packet)?; }
            self.post_saved_delivery(&mut journal, prepared.grant_id(), &path, &identity, cancel)?;
            serde_json::to_string(&PublicDeliveryResult {
                status: "PENDING".into(),
                invite_id: invite_id.into(),
                grant_id: prepared.grant_id().into(),
                workspace_id: self.config.workspace_id.clone(),
                grant_hash: prepared.grant_hash().into(),
            })
            .map_err(|_| PublicAdmissionRuntimeError::Encoding)
        })
    }

    pub fn pending_deliveries_json(&self) -> Result<String, PublicAdmissionRuntimeError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
        if identity.actor_id() != scope.owner_actor_id || identity.key_id() != scope.owner_key_id {
            return Err(PublicAdmissionRuntimeError::Identity);
        }
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("admission-intents.state"),
            &scope.origin,
            identity.actor_id(),
        )?;
        let mut rows = Vec::new();
        for row in journal.pending() {
            if row.action_id != "secure.invite.finalize" {
                continue;
            }
            if row.workspace_id.as_deref() != Some(scope.workspace_id.as_str())
                || !journal
                    .path(&row.intent_id)?
                    .starts_with("/api/workspace/v1/secure/invitations/")
                || !journal.path(&row.intent_id)?.ends_with("/key-grants")
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            rows.push(PendingPublicDelivery {
                grant_id: row.intent_id.clone(),
                workspace_id: scope.workspace_id.clone(),
                grant_hash: journal.intent_digest(&row.intent_id)?.into(),
                observed_responses: row.observed_responses,
            });
        }
        serde_json::to_string(&rows).map_err(|_| PublicAdmissionRuntimeError::Encoding)
    }

    /// Reconcile an uncertain delivery with a fresh complete signed journal.
    /// If the signed transition is present, no packet is resubmitted. If it is
    /// absent, only the exact saved bytes may be retried from the original
    /// checkpoint. Neither an HTTP success nor a control state label suffices.
    pub fn retry_delivery_json(
        &self,
        grant_id: &str,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.retry_delivery_json_with_cancel(grant_id, &CancellationToken::new())
    }

    pub fn retry_delivery_json_with_cancel(
        &self, grant_id: &str, cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.delivery_status_json(grant_id, true, cancel)
    }

    pub(crate) fn reconcile_delivery_json_with_cancel(
        &self, grant_id: &str, cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.delivery_status_json(grant_id, false, cancel)
    }

    fn delivery_status_json(
        &self, grant_id: &str, submit: bool, cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            if !self.config.matches_verified_origin(source.origin())
                || source.replay().workspace_id() != self.config.workspace_id
                || source.replay().owner_actor_id() != identity.actor_id()
                || source.replay().owner_signing_key() != identity.key_id()
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("admission-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            let saved = journal.exact_request(grant_id)?;
            let request = parse_wire_json_js_bounded(&saved, 80, 220_000)
                .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            if request.object_len() != Some(3) {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let policy = request
                .get("policy")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let grant = request
                .get("grant")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let commit = request
                .get("commit")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let pp = policy
                .get("payload")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let gp = grant
                .get("payload")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let cp = commit
                .get("payload")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let invite_id = gp
                .get("invite_id")
                .and_then(WireValue::as_string)
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let path = delivery_path(&invite_id)?;
            if journal.path(grant_id)? != path
                || gp.get("grant_id").and_then(WireValue::as_string).as_deref() != Some(grant_id)
                || gp
                    .get("workspace_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(&self.config.workspace_id)
                || gp.get("actor_id").and_then(WireValue::as_string).as_deref()
                    != Some(identity.actor_id())
                || gp
                    .get("signing_key")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(identity.key_id())
                || cp
                    .get("action_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some("secure.invite.finalize")
                || cp
                    .get("workspace_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(&self.config.workspace_id)
                || cp.get("actor_id").and_then(WireValue::as_string).as_deref()
                    != Some(identity.actor_id())
                || cp
                    .get("signing_key")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(identity.key_id())
                || pp.get("owner_id").and_then(WireValue::as_string).as_deref()
                    != Some(identity.actor_id())
                || pp
                    .get("signing_key")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(identity.key_id())
            {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let policy_wire = peerwork_core::wire_json::canonical_wire_value(
                policy,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let grant_wire = peerwork_core::wire_json::canonical_wire_value(
                grant,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let commit_wire = peerwork_core::wire_json::canonical_wire_value(
                commit,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let policy_hash = peerwork_core::crypto::sha256_hex(policy_wire.as_bytes());
            let grant_hash = peerwork_core::crypto::sha256_hex(grant_wire.as_bytes());
            let commit_hash = peerwork_core::crypto::sha256_hex(commit_wire.as_bytes());
            let sequence = cp
                .get("sequence")
                .and_then(WireValue::as_number)
                .filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n <= 9_007_199_254_740_991.0)
                .ok_or(PublicAdmissionRuntimeError::Input)? as u64;
            let operation_matches = self.saved_delivery_operation_matches(
                cp,
                pp,
                &invite_id,
                source.origin(),
                &identity,
                source.keyring_state(),
            )?;
            if grant_hash != journal.intent_digest(grant_id)?
                || gp
                    .get("policy_hash")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(&policy_hash)
                || cp
                    .get("policy_hash")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(&policy_hash)
                || pp.get("effective_sequence").and_then(WireValue::as_number)
                    != Some(sequence as f64)
                || gp
                    .get("acceptance_hash")
                    .and_then(WireValue::as_string)
                    .is_none()
                || !operation_matches
                || !peerwork_core::crypto::verify_secure_signed_wire(
                    policy_wire.as_bytes(),
                    "peerwork.secure.policy.v3",
                    identity.key_id(),
                )
                .map_err(|_| PublicAdmissionRuntimeError::Input)?
                || !peerwork_core::crypto::verify_secure_signed_wire(
                    grant_wire.as_bytes(),
                    "peerwork.secure.key-grant.v1",
                    identity.key_id(),
                )
                .map_err(|_| PublicAdmissionRuntimeError::Input)?
                || !peerwork_core::crypto::verify_secure_signed_wire(
                    commit_wire.as_bytes(),
                    "peerwork.secure.commit.v3",
                    identity.key_id(),
                )
                .map_err(|_| PublicAdmissionRuntimeError::Input)?
            {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let control = self.read_owner_control(&invite_id, &identity, cancel)?;
            let offer = control
                .get("offer")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let decision = control
                .get("decision")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let recipient_actor = offer
                .get("payload")
                .and_then(|p| p.get("recipient"))
                .and_then(|c| c.get("payload"))
                .and_then(|p| p.get("actor_id"))
                .and_then(WireValue::as_string)
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let recipient_key = offer
                .get("payload")
                .and_then(|p| p.get("recipient"))
                .and_then(|c| c.get("payload"))
                .and_then(|p| p.get("signing_key"))
                .and_then(WireValue::as_string)
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let offer_wire = peerwork_core::wire_json::canonical_wire_value(
                offer,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let decision_wire = peerwork_core::wire_json::canonical_wire_value(
                decision,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let decision_request = format!("{{\"decision\":{decision_wire}}}");
            let checked = peerwork_core::prepared_public_admission::verify_saved_public_decision(
                decision_request.as_bytes(),
                offer_wire.as_bytes(),
                identity.actor_id(),
                identity.key_id(),
                &recipient_actor,
                &recipient_key,
                &self.config.workspace_id,
            )?;
            if checked.artifact_hash()
                != gp
                    .get("acceptance_hash")
                    .and_then(WireValue::as_string)
                    .unwrap_or_default()
                || checked.id() != invite_id
                || decision
                    .get("payload")
                    .and_then(|p| p.get("decision"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some("ACCEPT")
            {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            if source
                .replay()
                .contains_checkpoint(sequence, Some(&commit_hash), &policy_hash)
            {
                let signed_policy = source
                    .signed_policy_by_hash(&policy_hash)
                    .ok_or(PublicAdmissionRuntimeError::Input)?;
                if signed_policy != policy_wire.as_bytes()
                    || control.get("grant").is_none_or(|g| {
                        peerwork_core::wire_json::canonical_wire_value(
                            g,
                            peerwork_core::canonical::Path::SecureArtifact,
                        )
                        .map_or(true, |wire| wire != grant_wire)
                    })
                    || control.get("policy").is_none_or(|p| {
                        peerwork_core::wire_json::canonical_wire_value(
                            p,
                            peerwork_core::canonical::Path::SecureArtifact,
                        )
                        .map_or(true, |wire| wire != policy_wire)
                    })
                {
                    return Err(PublicAdmissionRuntimeError::Input);
                }
                return Ok(serde_json::json!({"status":"AUTHORIZED", "invite_id":invite_id,
                    "grant_id":grant_id,"workspace_id":self.config.workspace_id,"grant_hash":grant_hash,
                    "command_id":cp.get("command_id").and_then(WireValue::as_string),
                    "sequence":sequence,"commit_hash":commit_hash,"verification":"verified"}).to_string());
            }
            // A missing mandatory context is an intrinsically inadmissible
            // packet under the immutable v3 guard-time policy. We have checked
            // its signatures, decrypted intent, immutable invitation/ACCEPT and
            // complete authenticated history above. This is not a deduction
            // from an HTTP 409 or from a merely absent command.
            if self.private_mode && cp.get("guard_time").is_none() {
                if let Some(predecessor) = pp.get("previous_policy").and_then(WireValue::as_string)
                    .and_then(|h| source.signed_policy_by_hash(&h)) {
                    if let Ok(proof) = peerwork_core::prepared_public_admission::verify_inadmissible_guarded_delivery(
                        &saved,predecessor,identity.actor_id(),identity.key_id(),&self.config.workspace_id) {
                        return Ok(serde_json::json!({"status":"REPLACEMENT_SAFE", "invite_id":invite_id,
                            "grant_id":grant_id,"workspace_id":self.config.workspace_id,"grant_hash":grant_hash,
                            "proof":{"kind":"immutable_policy_packet_inadmissible","constraint":"guard_time.required",
                            "verifier":proof.verifier,"command_id":proof.command_id,"request_digest":proof.request_digest,
                            "predecessor_policy_hash":proof.predecessor_policy_hash,"policy_hash":proof.policy_hash,
                            "verified_through":source.replay().sequence(),"verified_head":source.replay().head()},
                            "effect_certainty":"not_accepted","future_acceptance":"closed"}).to_string());
                    }
                }
            }
            let current_policy_hash = source.replay().policy_hash();
            if sequence != source.replay().sequence().saturating_add(1)
                || cp.get("previous").and_then(WireValue::as_string).as_deref()
                    != source.replay().head()
                || pp
                    .get("previous_policy")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(current_policy_hash)
                || control
                    .get("grant")
                    .is_some_and(|g| !matches!(g, WireValue::Null))
            {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            if submit { self.post_saved_delivery(&mut journal, grant_id, &path, &identity, cancel)?; }
            serde_json::to_string(&PublicDeliveryResult {
                status: "PENDING".into(),
                invite_id,
                grant_id: grant_id.into(),
                workspace_id: self.config.workspace_id.clone(),
                grant_hash,
            })
            .map_err(|_| PublicAdmissionRuntimeError::Encoding)
        })
    }

    fn saved_delivery_operation_matches(
        &self,
        commit_payload: &WireValue,
        policy_payload: &WireValue,
        invite_id: &str,
        origin: &str,
        identity: &KernelIdentity,
        replay_keyring_state: Option<ReplayKeyringState>,
    ) -> Result<bool, PublicAdmissionRuntimeError> {
        let visibility = policy_payload
            .get("visibility")
            .and_then(WireValue::as_string);
        let mode = commit_payload.get("mode").and_then(WireValue::as_string);
        let operation = if self.private_mode {
            if visibility.as_deref() != Some("PRIVATE")
                || mode.as_deref() != Some("PRIVATE")
                || replay_keyring_state != Some(ReplayKeyringState::Active)
            {
                return Ok(false);
            }
            let lifecycle = SecureLifecycle::open(
                &self.config.state_dir.join("lifecycle.state"),
                origin,
                identity.actor_id(),
                &self.config.workspace_id,
                identity.actor_id(),
                identity.key_id(),
            )
            .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            let ring = lifecycle
                .active_keyring_without_pending()
                .ok_or(PublicAdmissionRuntimeError::Identity)?;
            let epoch = commit_payload
                .get("epoch")
                .and_then(WireValue::as_number)
                .filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n <= 9_007_199_254_740_991.0)
                .ok_or(PublicAdmissionRuntimeError::Input)? as u64;
            if policy_payload.get("epoch").and_then(WireValue::as_number) != Some(epoch as f64) {
                return Ok(false);
            }
            let key = ring
                .key_at(epoch)
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let body = commit_payload
                .get("body")
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            let sealed_wire = peerwork_core::wire_json::canonical_wire_value(
                body,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let sealed: peerwork_core::e2ee::SealedContent = serde_json::from_str(&sealed_wire)
                .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let WireValue::Object(fields) = commit_payload else {
                return Ok(false);
            };
            let context = WireValue::Object(
                fields
                    .iter()
                    .filter(|(name, _)| {
                        name.as_slice() != "mode".encode_utf16().collect::<Vec<_>>()
                            && name.as_slice() != "body".encode_utf16().collect::<Vec<_>>()
                    })
                    .cloned()
                    .collect(),
            );
            let context_wire = peerwork_core::wire_json::canonical_wire_value(
                &context,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
            let plaintext = Zeroizing::new(
                peerwork_core::e2ee::open_content_wire(key, &sealed, context_wire.as_bytes())
                    .map_err(|_| PublicAdmissionRuntimeError::Input)?,
            );
            peerwork_core::wire_json::parse_wire_json_js_bounded(&plaintext, 32, 196_608)
                .map_err(|_| PublicAdmissionRuntimeError::Input)?
        } else {
            if visibility.as_deref() != Some("PUBLIC") || mode.as_deref() != Some("PUBLIC") {
                return Ok(false);
            }
            commit_payload
                .get("body")
                .ok_or(PublicAdmissionRuntimeError::Input)?
                .clone()
        };
        Ok(
            operation.get("v").and_then(WireValue::as_number) == Some(1.0)
                && operation
                    .get("kind")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some("ADMIN")
                && operation.get("objects").is_some_and(
                    |objects| matches!(objects, WireValue::Array(rows) if rows.is_empty()),
                )
                && operation.get("input").is_some_and(|input| {
                    input.object_len() == Some(1)
                        && input
                            .get("invite_id")
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some(invite_id)
                }),
        )
    }

    fn post_saved_delivery(
        &self,
        journal: &mut SecureIntentJournal,
        grant_id: &str,
        path: &str,
        identity: &KernelIdentity,
        cancel: &CancellationToken,
    ) -> Result<(), PublicAdmissionRuntimeError> {
        if journal.path(grant_id)? != path {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        let saved = journal.exact_request(grant_id)?;
        let parsed = parse_wire_json_js_bounded(&saved, 80, 220_000)
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
        if parsed.object_len() != Some(3)
            || parsed
                .get("grant")
                .and_then(|g| g.get("payload"))
                .and_then(|p| p.get("grant_id"))
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(grant_id)
            || parsed.get("grant").is_none_or(|g| {
                peerwork_core::wire_json::canonical_wire_value(
                    g,
                    peerwork_core::canonical::Path::SecureArtifact,
                )
                .map_or(true, |wire| {
                    peerwork_core::crypto::sha256_hex(wire.as_bytes())
                        != journal.intent_digest(grant_id).unwrap_or_default()
                })
            })
        {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PublicAdmissionRuntimeError::Runtime)?;
        let mut transport = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|s| s.encode_utf16().collect())
            .collect::<Vec<Vec<u16>>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.state_dir.join("kernel.sqlite"),
                &features,
                cancel,
            ))
            .map_err(|_| PublicAdmissionRuntimeError::Transport)?;
        let proof = sign_read_proof(
            path,
            client.discovery(),
            identity,
            &self.config.authority.clone().unwrap_or_else(|| {
                peerwork_core::crypto::sha256_hex(identity.actor_id().as_bytes())
            }),
        )
        .map_err(|_| PublicAdmissionRuntimeError::ReadProof)?;
        match runtime.block_on(
            client
                .transport()
                .post_secure_admission_exact(path, saved, &proof, cancel),
        ) {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(grant_id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(PublicAdmissionRuntimeError::Rejected(crate::operation_diagnostics::ServerRejection::from_response(response.status, &response.wire)));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PublicAdmissionRuntimeError::Transport),
        }
        Ok(())
    }

    fn read_owner_control(
        &self,
        invite_id: &str,
        identity: &KernelIdentity,
        cancel: &CancellationToken,
    ) -> Result<WireValue, PublicAdmissionRuntimeError> {
        let path = format!("{OFFER_PATH}/{invite_id}");
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PublicAdmissionRuntimeError::Runtime)?;
        let mut transport = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|s| s.encode_utf16().collect())
            .collect::<Vec<Vec<u16>>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.state_dir.join("kernel.sqlite"),
                &features,
                cancel,
            ))
            .map_err(|_| PublicAdmissionRuntimeError::Transport)?;
        let proof = sign_read_proof(
            &path,
            client.discovery(),
            identity,
            &self.config.authority.clone().unwrap_or_else(|| {
                peerwork_core::crypto::sha256_hex(identity.actor_id().as_bytes())
            }),
        )
        .map_err(|_| PublicAdmissionRuntimeError::ReadProof)?;
        let response = runtime
            .block_on(
                client
                    .transport()
                    .get_secure_invitation_exact(&path, &proof, cancel),
            )
            .map_err(|_| PublicAdmissionRuntimeError::Transport)?;
        if response.status != 200 {
            return Err(PublicAdmissionRuntimeError::Rejected(crate::operation_diagnostics::ServerRejection::from_response(response.status, &response.wire)));
        }
        parse_wire_json_js_bounded(&response.wire, 80, 220_000)
            .map_err(|_| PublicAdmissionRuntimeError::Input)
    }

    /// Local protected ID discovery, usable while offline after cancellation.
    /// Rows are pending transport evidence, not consent or membership.
    pub fn pending_offers_json(&self) -> Result<String, PublicAdmissionRuntimeError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
        if identity.actor_id() != scope.owner_actor_id || identity.key_id() != scope.owner_key_id {
            return Err(PublicAdmissionRuntimeError::Identity);
        }
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("admission-intents.state"),
            &scope.origin,
            identity.actor_id(),
        )?;
        let mut result = Vec::new();
        for row in journal.pending() {
            if row.action_id != "secure.invite.offer" {
                continue;
            }
            if row.workspace_id.as_deref() != Some(scope.workspace_id.as_str())
                || journal.path(&row.intent_id)? != OFFER_PATH
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            result.push(PendingPublicOffer {
                offer_hash: journal.intent_digest(&row.intent_id)?.to_owned(),
                invite_id: row.intent_id,
                workspace_id: scope.workspace_id.clone(),
                observed_responses: row.observed_responses,
            });
        }
        serde_json::to_string(&result).map_err(|_| PublicAdmissionRuntimeError::Encoding)
    }

    pub fn submit_offer_json(
        &self,
        input: PublicOfferInput,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.submit_offer_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_offer_json_with_cancel(
        &self,
        input: PublicOfferInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        let now = now_ms()?;
        let issued_at = input.issued_at_ms.unwrap_or(now);
        let expires_at = input
            .expires_at_ms
            .unwrap_or(now.saturating_add(7 * 86_400_000));
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            if !self.config.matches_verified_origin(source.origin())
                || source.replay().workspace_id() != self.config.workspace_id
                || source.replay().owner_actor_id() != identity.actor_id()
                || source.replay().owner_signing_key() != identity.key_id()
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            let policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            if self.private_mode {
                let certificate = parse_wire_json_js_bounded(
                    input.recipient_certificate_json.as_bytes(),
                    64,
                    8192,
                )
                .map_err(|_| PublicAdmissionRuntimeError::Input)?;
                self.verify_current_private_recipient(&certificate, cancel)?;
            }
            if input.message_utf16.is_some() && !input.message.is_empty() {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let message = input
                .message_utf16
                .clone()
                .unwrap_or_else(|| input.message.encode_utf16().collect());
            let author = if self.private_mode {
                prepare_private_offer_utf16
            } else {
                prepare_public_offer_utf16
            };
            let prepared = author(
                policy,
                input.recipient_certificate_json.as_bytes(),
                input.scopes_json.as_bytes(),
                &message,
                input.invite_id.as_deref(),
                issued_at,
                expires_at,
                identity.signing_key(),
            )?;
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("admission-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            if journal.contains_id(prepared.id()) {
                return Err(PublicAdmissionRuntimeError::Intent(
                    SecureIntentError::Conflict,
                ));
            }
            journal.prepare(SecurePacketInput {
                intent_id: prepared.id(),
                path: OFFER_PATH,
                action_id: "secure.invite.offer",
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: prepared.artifact_hash(),
                exact_request: prepared.request_wire(),
            })?;
            self.send_saved_offer(&mut journal, prepared.id(), source, &identity, cancel)?;
            serde_json::to_string(&PublicOfferResult {
                status: "PENDING".into(),
                invite_id: prepared.id().to_owned(),
                workspace_id: self.config.workspace_id.clone(),
                offer_hash: prepared.artifact_hash().to_owned(),
            })
            .map_err(|_| PublicAdmissionRuntimeError::Encoding)
        })
    }

    /// Retry an uncertain POST using the exact protected bytes. The current
    /// signed replay must still include the offer's historical policy.
    pub fn retry_offer_json(&self, invite_id: &str) -> Result<String, PublicAdmissionRuntimeError> {
        self.retry_offer_json_with_cancel(invite_id, &CancellationToken::new())
    }

    pub fn retry_offer_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            if source.replay().owner_actor_id() != identity.actor_id()
                || source.replay().owner_signing_key() != identity.key_id()
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("admission-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            self.send_saved_offer(&mut journal, invite_id, source, &identity, cancel)?;
            serde_json::to_string(&PublicOfferResult {
                status: "PENDING".into(),
                invite_id: invite_id.to_owned(),
                workspace_id: self.config.workspace_id.clone(),
                offer_hash: journal.intent_digest(invite_id)?.to_owned(),
            })
            .map_err(|_| PublicAdmissionRuntimeError::Encoding)
        })
    }

    fn send_saved_offer(
        &self,
        journal: &mut SecureIntentJournal,
        invite_id: &str,
        source: &crate::secure_verified_read::TransportReplayedJournal,
        identity: &KernelIdentity,
        cancel: &CancellationToken,
    ) -> Result<(), PublicAdmissionRuntimeError> {
        if journal.path(invite_id)? != OFFER_PATH {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        let saved = journal.exact_request(invite_id)?;
        let parsed = parse_wire_json_js_bounded(&saved, 64, 220_000)
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
        let policy_hash = parsed
            .get("offer")
            .and_then(|offer| offer.get("payload"))
            .and_then(|payload| payload.get("policy_hash"))
            .and_then(WireValue::as_string)
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let policy = source
            .signed_policy_by_hash(&policy_hash)
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let verify = if self.private_mode {
            verify_saved_private_offer
        } else {
            verify_saved_public_offer
        };
        let checked = verify(
            &saved,
            policy,
            identity.actor_id(),
            identity.key_id(),
            &self.config.workspace_id,
        )?;
        if checked.id() != invite_id
            || checked.artifact_hash() != journal.intent_digest(invite_id)?
        {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PublicAdmissionRuntimeError::Runtime)?;
        let mut transport = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|feature| feature.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.state_dir.join("kernel.sqlite"),
                &features,
                cancel,
            ))
            .map_err(|_| PublicAdmissionRuntimeError::Transport)?;
        if client.origin() != source.origin()
            || source.source_actor_id() != identity.actor_id()
            || source.source_key_id() != identity.key_id()
        {
            return Err(PublicAdmissionRuntimeError::Identity);
        }
        let proof = sign_read_proof(OFFER_PATH, client.discovery(), identity, source.authority())
            .map_err(|_| PublicAdmissionRuntimeError::ReadProof)?;
        let response = runtime.block_on(
            client
                .transport()
                .post_secure_admission_exact(OFFER_PATH, saved, &proof, cancel),
        );
        match response {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(invite_id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(PublicAdmissionRuntimeError::Rejected(crate::operation_diagnostics::ServerRejection::from_response(response.status, &response.wire)));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PublicAdmissionRuntimeError::Transport),
        }
        Ok(())
    }

    fn verify_current_private_recipient(
        &self,
        certificate: &WireValue,
        cancel: &CancellationToken,
    ) -> Result<(), PublicAdmissionRuntimeError> {
        let payload = certificate
            .get("payload")
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let actor = payload
            .get("actor_id")
            .and_then(WireValue::as_string)
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let key = payload
            .get("signing_key")
            .and_then(WireValue::as_string)
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let directory = SecureIdentityDirectory::new(IdentityDirectoryConfig {
            transport: self.config.transport.clone(),
            origin: self.config.origin.clone(),
            identity_path: self.config.identity_path.clone(),
            kernel_journal_path: self.config.state_dir.join("kernel.sqlite"),
            pins_path: self.config.state_dir.join("identity-directory.state"),
            allow_loopback_http: self.config.allow_loopback_http,
        });
        let verified = directory.lookup_certificate_with_cancel(&actor, &key, cancel)?;
        let exact = peerwork_core::wire_json::canonical_wire_value(
            certificate,
            peerwork_core::canonical::Path::SecureArtifact,
        )
        .map_err(|_| PublicAdmissionRuntimeError::Input)?;
        if verified.certificate_json != exact {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        Ok(())
    }
}

/// PRIVATE Owner admission keeps the same redacted ID/result contract as
/// PUBLIC admission, but its internal producer and saved retry are mode-checked
/// and require a complete active replay plus the protected full keyring.
pub struct SecurePrivateAdmission {
    inner: SecurePublicAdmission,
}

impl SecurePrivateAdmission {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self {
            inner: SecurePublicAdmission::new_private(config),
        }
    }

    pub fn submit_offer_json_with_cancel(
        &self,
        input: PublicOfferInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.inner.submit_offer_json_with_cancel(input, cancel)
    }

    pub fn retry_offer_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.inner.retry_offer_json_with_cancel(invite_id, cancel)
    }

    pub fn pending_offers_json(&self) -> Result<String, PublicAdmissionRuntimeError> {
        self.inner.pending_offers_json()
    }

    pub fn deliver_accepted_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.inner
            .deliver_accepted_json_with_cancel(invite_id, cancel)
    }

    pub fn retry_delivery_json_with_cancel(
        &self,
        grant_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.inner.retry_delivery_json_with_cancel(grant_id, cancel)
    }

    pub fn pending_deliveries_json(&self) -> Result<String, PublicAdmissionRuntimeError> {
        self.inner.pending_deliveries_json()
    }
}

fn now_ms() -> Result<u64, PublicAdmissionRuntimeError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PublicAdmissionRuntimeError::Clock)?
        .as_millis();
    u64::try_from(ms).map_err(|_| PublicAdmissionRuntimeError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure_action_access::PublicActionInput,
        secure_owner_create::{
            SecureOwnerCreateConfig, SecureOwnerCreateInput, SecureOwnerWorkspaceCreate,
        },
        secure_public_decision::{PublicDecisionConfig, SecurePublicDecision},
        secure_recipient_enrollment::{RecipientEnrollmentConfig, SecureRecipientEnrollment},
    };
    use std::{
        fs,
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_native_owner_private_offer_delivery_and_receive() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopPrivate(Child);
        impl Drop for StopPrivate {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopPrivate(child);
        let mut ready_line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut ready_line)
            .unwrap();
        assert!(!ready_line.is_empty(), "pinned service failed to start");
        let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let owner = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        });
        let cancel = CancellationToken::new();
        let prepared = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native owner PRIVATE admission".into(),
                    name_utf16: None,
                    visibility: "PRIVATE".into(),
                    structured: false,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &cancel,
            )
            .unwrap();
        let created = owner.resume(&prepared.command_id, &cancel).unwrap();
        assert_eq!(created.status, "CREATED");
        let recipient_dir = root.path().join("recipient");
        let mut enrollment_config =
            RecipientEnrollmentConfig::for_state_dir(origin.clone(), &recipient_dir);
        enrollment_config.allow_loopback_http = true;
        let enrollment = SecureRecipientEnrollment::new(enrollment_config);
        let local = enrollment.create_local().unwrap();
        let published = enrollment.publish().unwrap();
        assert_eq!(published.status, "PUBLISHED");
        let admission = owner
            .private_admission_access(&created.workspace_id)
            .unwrap();
        let stale_certificate_json = enrollment.certificate_json().unwrap();
        let mut rotated = enrollment
            .update_key("ROTATE", &local.certificate_digest, None)
            .unwrap();
        if rotated.status == "PENDING" {
            rotated = enrollment.retry_key_update(&rotated.update_id).unwrap();
        }
        assert_eq!(rotated.status, "PUBLISHED");
        assert!(matches!(
            admission.submit_offer_json_with_cancel(
                PublicOfferInput {
                    recipient_certificate_json: stale_certificate_json,
                    scopes_json: "[]".into(),
                    message: "stale certificate".into(),
                    message_utf16: None,
                    invite_id: None,
                    issued_at_ms: None,
                    expires_at_ms: None,
                },
                &cancel,
            ),
            Err(PublicAdmissionRuntimeError::Input)
        ));
        let no_offer: Vec<PendingPublicOffer> =
            serde_json::from_str(&admission.pending_offers_json().unwrap()).unwrap();
        assert!(no_offer.is_empty());
        let offer: PublicOfferResult = serde_json::from_str(
            &admission
                .submit_offer_json_with_cancel(
                    PublicOfferInput {
                        recipient_certificate_json: enrollment.certificate_json().unwrap(),
                        scopes_json: "[]".into(),
                        message: "Native PRIVATE invitation".into(),
                        message_utf16: None,
                        invite_id: None,
                        issued_at_ms: None,
                        expires_at_ms: None,
                    },
                    &cancel,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(offer.status, "PENDING");
        let decision = SecurePublicDecision::new(PublicDecisionConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: recipient_dir.clone(),
            identity_path: recipient_dir.join("identity.state"),
            workspace_id: created.workspace_id.clone(),
            owner_actor_id: KernelIdentity::open(&root.path().join("owner/identity.state"))
                .unwrap()
                .actor_id()
                .into(),
            owner_key_id: KernelIdentity::open(&root.path().join("owner/identity.state"))
                .unwrap()
                .key_id()
                .into(),
            authority: peerwork_core::crypto::sha256_hex(local.actor_id.as_bytes()),
            allow_loopback_http: true,
            required_features: vec![],
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        });
        let decided: serde_json::Value =
            serde_json::from_str(&decision.decide_json(&offer.invite_id, "ACCEPT").unwrap())
                .unwrap();
        assert_eq!(decided["invite_id"], offer.invite_id);
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let delivered: PublicDeliveryResult = serde_json::from_str(
            &admission
                .deliver_accepted_json_with_cancel(&offer.invite_id, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(delivered.status, "PENDING");
        drop(admission);
        let reopened = owner
            .private_admission_access(&created.workspace_id)
            .unwrap();
        let pending: Vec<PendingPublicDelivery> =
            serde_json::from_str(&reopened.pending_deliveries_json().unwrap()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].grant_id, delivered.grant_id);
        assert_eq!(pending[0].grant_hash, delivered.grant_hash);
        let recovered: PublicDeliveryResult = serde_json::from_str(
            &reopened
                .retry_delivery_json_with_cancel(&delivered.grant_id, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(recovered.status, "AUTHORIZED");
        let after_delivery: serde_json::Value = serde_json::from_str(
            &owner
                .read_workspace_json(&created.workspace_id, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after_delivery["sequence"], 2);
        let mut received: serde_json::Value =
            serde_json::from_str(&decision.receive_json(&offer.invite_id).unwrap()).unwrap();
        if received["status"] == "PENDING" {
            received =
                serde_json::from_str(&decision.retry_receive_json(&offer.invite_id).unwrap())
                    .unwrap();
        }
        assert_eq!(received["status"], "READY");
        let owner_read: serde_json::Value = serde_json::from_str(
            &owner
                .read_workspace_json(&created.workspace_id, &cancel)
                .unwrap(),
        )
        .unwrap();
        let wiki_instance = owner_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "instances" && row["value"]["origin_entrypoint"] == "wiki")
            .and_then(|row| row["id"].as_str())
            .unwrap();
        let action = owner.private_action_access(&created.workspace_id).unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "wiki.create".into(),
                    instance_id: wiki_instance.into(),
                    body_json: r#"{"title":"Native private member readback","body":"Encrypted after grant"}"#.into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &action
                .retry_saved_json(submitted["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let record_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let recipient_read = SecureReadProfile::new(SecureReadProfileConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: recipient_dir.clone(),
            identity_path: recipient_dir.join("identity.state"),
            workspace_id: created.workspace_id.clone(),
            owner_actor_id: Some(
                KernelIdentity::open(&root.path().join("owner/identity.state"))
                    .unwrap()
                    .actor_id()
                    .into(),
            ),
            owner_key_id: Some(
                KernelIdentity::open(&root.path().join("owner/identity.state"))
                    .unwrap()
                    .key_id()
                    .into(),
            ),
            authority: Some(peerwork_core::crypto::sha256_hex(local.actor_id.as_bytes())),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        })
        .read_latest_json()
        .unwrap();
        let recipient_read: serde_json::Value = serde_json::from_str(&recipient_read).unwrap();
        assert!(recipient_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                row["kind"] == "records"
                    && row["id"] == record_id
                    && row["value"]["payload"]["title"] == "Native private member readback"
                    && row["value"]["payload"]["body"] == "Encrypted after grant"
            }));
    }

    #[test]
    fn actual_service_native_public_offer_saved_retry() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", temp.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .env("PEERWORK_TEST_ADMISSION", "1")
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
        let mut ready_line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut ready_line)
            .unwrap();
        assert!(!ready_line.is_empty(), "reference service failed to start");
        let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let workspace = ready["public_read"]["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner_actor = ready["public_read"]["actor_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner_key = ready["public_read"]["signing_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let authority = ready["public_read"]["authority"]
            .as_str()
            .unwrap()
            .to_owned();
        let identity_path = temp.path().join("native-owner.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &temp.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), owner_actor);
        let config = SecureReadProfileConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: temp.path().join("native-offer"),
            identity_path,
            workspace_id: workspace.clone(),
            owner_actor_id: Some(owner_actor.clone()),
            owner_key_id: Some(owner_key.clone()),
            authority: Some(authority.clone()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        SecureReadProfile::new(config.clone())
            .read_latest_json()
            .unwrap();
        let recipient_certificate_json = fs::read_to_string(
            temp.path()
                .join("synthetic-admission-recipient-certificate.json"),
        )
        .unwrap();
        let admission = SecurePublicAdmission::new(config.clone());
        let first = admission
            .submit_offer_json(PublicOfferInput {
                recipient_certificate_json,
                scopes_json: "[]".into(),
                message: "Native invitation consent".into(),
                message_utf16: None,
                invite_id: None,
                issued_at_ms: None,
                expires_at_ms: None,
            })
            .unwrap();
        let first: PublicOfferResult = serde_json::from_str(&first).unwrap();
        assert_eq!(first.status, "PENDING");
        let protected = config.state_dir.join("admission-intents.state");
        let journal = SecureIntentJournal::open(&protected, &origin, identity.actor_id()).unwrap();
        let exact = journal.exact_request(&first.invite_id).unwrap();
        drop(journal);
        let pending: Vec<PendingPublicOffer> =
            serde_json::from_str(&admission.pending_offers_json().unwrap()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invite_id, first.invite_id);
        assert_eq!(pending[0].offer_hash, first.offer_hash);
        let repeated: PublicOfferResult = serde_json::from_str(
            &SecurePublicAdmission::new(config.clone())
                .retry_offer_json(&first.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated, first);
        let journal = SecureIntentJournal::open(&protected, &origin, identity.actor_id()).unwrap();
        assert_eq!(journal.exact_request(&first.invite_id).unwrap(), exact);
        drop(journal);
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let mut transport = TransportConfig::new(origin.clone());
        transport.allow_loopback_http = true;
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &temp.path().join("native-offer/kernel.sqlite"),
                &[],
                &CancellationToken::new(),
            ))
            .unwrap();
        let path = format!("{OFFER_PATH}/{}", first.invite_id);
        let proof = sign_read_proof(&path, client.discovery(), &identity, &authority).unwrap();
        let control = runtime
            .block_on(client.transport().get_secure_invitation_exact(
                &path,
                &proof,
                &CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(control.status, 200);
        let observed: serde_json::Value = serde_json::from_slice(&control.wire).unwrap();
        assert_eq!(
            observed["offer_hash"].as_str(),
            Some(first.offer_hash.as_str())
        );
        assert_eq!(
            observed["offer"]["payload"]["invite_id"].as_str(),
            Some(first.invite_id.as_str())
        );
        assert!(observed["decision"].is_null());
        let recipient_identity_path = temp.path().join("native-recipient-identity.state");
        let recipient_identity = KernelIdentity::import_pkcs8_pem_file(
            &recipient_identity_path,
            &temp.path().join("synthetic-admission-recipient.pem"),
        )
        .unwrap();
        let recipient_dir = temp.path().join("native-recipient");
        fs::create_dir(&recipient_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&recipient_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let imported = crate::secure_recipient_state::RecipientState::import_unjoined_ts_state(
            &recipient_dir.join("recipient.state"),
            &recipient_identity,
            &temp.path().join("synthetic-admission-recipient.json"),
        )
        .unwrap();
        assert_eq!(
            imported.certificate().payload["actor_id"].as_str(),
            Some(recipient_identity.actor_id())
        );
        drop(imported);
        let recipient_config = crate::secure_public_decision::PublicDecisionConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: recipient_dir.clone(),
            identity_path: recipient_identity_path,
            workspace_id: workspace.clone(),
            owner_actor_id: identity.actor_id().into(),
            owner_key_id: identity.key_id().into(),
            authority: peerwork_core::crypto::sha256_hex(recipient_identity.actor_id().as_bytes()),
            allow_loopback_http: true,
            required_features: vec![],
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let drop_url = format!("{origin}__test/drop-next-post");
        let drop_result = runtime
            .block_on(reqwest::Client::new().post(drop_url).send())
            .unwrap();
        assert_eq!(drop_result.status().as_u16(), 200);
        let recipient_access =
            crate::secure_public_decision::SecurePublicDecision::new(recipient_config.clone());
        let first_decision: crate::secure_public_decision::PublicDecisionResult =
            serde_json::from_str(
                &recipient_access
                    .decide_json(&first.invite_id, "ACCEPT")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(first_decision.status, "PENDING");
        let decision_journal = SecureIntentJournal::open(
            &recipient_dir.join("admission-intents.state"),
            &origin,
            recipient_identity.actor_id(),
        )
        .unwrap();
        let decision_packet = decision_journal.exact_request(&first.invite_id).unwrap();
        drop(decision_journal);
        let pending_decisions: Vec<crate::secure_public_decision::PendingPublicDecision> =
            serde_json::from_str(&recipient_access.pending_json().unwrap()).unwrap();
        assert_eq!(pending_decisions.len(), 1);
        assert_eq!(pending_decisions[0].invite_id, first.invite_id);
        let repeated_decision: crate::secure_public_decision::PublicDecisionResult =
            serde_json::from_str(&recipient_access.retry_json(&first.invite_id).unwrap()).unwrap();
        assert_eq!(repeated_decision, first_decision);
        let decision_journal = SecureIntentJournal::open(
            &recipient_dir.join("admission-intents.state"),
            &origin,
            recipient_identity.actor_id(),
        )
        .unwrap();
        assert_eq!(
            decision_journal.exact_request(&first.invite_id).unwrap(),
            decision_packet
        );
        drop(decision_journal);
        let mut recipient_transport = TransportConfig::new(origin.clone());
        recipient_transport.allow_loopback_http = true;
        let recipient_client = runtime
            .block_on(KernelClient::open(
                recipient_transport,
                &recipient_dir.join("kernel.sqlite"),
                &[],
                &CancellationToken::new(),
            ))
            .unwrap();
        drop(recipient_client);
        let mut refreshed_transport = TransportConfig::new(origin.clone());
        refreshed_transport.allow_loopback_http = true;
        let recipient_client = runtime
            .block_on(KernelClient::open(
                refreshed_transport,
                &recipient_dir.join("kernel.sqlite"),
                &[],
                &CancellationToken::new(),
            ))
            .unwrap();
        let recipient_proof = sign_read_proof(
            &path,
            recipient_client.discovery(),
            &recipient_identity,
            &recipient_config.authority,
        )
        .unwrap();
        let accepted = runtime
            .block_on(recipient_client.transport().get_secure_invitation_exact(
                &path,
                &recipient_proof,
                &CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(accepted.status, 200);
        let accepted_wire =
            peerwork_core::wire_json::parse_wire_json_js_bounded(&accepted.wire, 80, 220_000)
                .unwrap();
        assert_eq!(
            accepted_wire
                .get("decision")
                .unwrap()
                .get("payload")
                .unwrap()
                .get("decision")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("ACCEPT")
        );
        let decision_wire = peerwork_core::wire_json::canonical_wire_value(
            accepted_wire.get("decision").unwrap(),
            peerwork_core::canonical::Path::SecureArtifact,
        )
        .unwrap();
        assert_eq!(
            peerwork_core::crypto::sha256_hex(decision_wire.as_bytes()),
            first_decision.decision_hash
        );
        SecureReadProfile::new(config.clone())
            .with_latest_replay(&CancellationToken::new(), |source| {
                let signed_policy = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .unwrap();
                let delivery = peerwork_core::prepared_public_admission::prepare_public_delivery(
                    signed_policy,
                    source.checkpoint_canonical_json().as_bytes(),
                    peerwork_core::wire_json::canonical_wire_value(
                        accepted_wire.get("offer").unwrap(),
                        peerwork_core::canonical::Path::SecureArtifact,
                    )
                    .unwrap()
                    .as_bytes(),
                    decision_wire.as_bytes(),
                    now_ms().unwrap(),
                    identity.signing_key(),
                )
                .unwrap();
                assert_eq!(delivery.invite_id(), first.invite_id);
                let value: serde_json::Value =
                    serde_json::from_slice(delivery.request_wire()).unwrap();
                assert_eq!(
                    value["policy"]["payload"]["members"]
                        .as_array()
                        .unwrap()
                        .len(),
                    2
                );
                assert_eq!(
                    value["grant"]["payload"]["box"]["suite"],
                    "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/A256GCM"
                );
                assert_eq!(
                    value["commit"]["payload"]["action_id"],
                    "secure.invite.finalize"
                );
                Ok::<_, PublicAdmissionRuntimeError>(())
            })
            .unwrap();
        let drop_result = runtime
            .block_on(
                reqwest::Client::new()
                    .post(format!("{origin}__test/drop-next-post"))
                    .send(),
            )
            .unwrap();
        assert_eq!(drop_result.status().as_u16(), 200);
        let delivery: PublicDeliveryResult = serde_json::from_str(
            &SecurePublicAdmission::new(config.clone())
                .deliver_accepted_json(&first.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(delivery.status, "PENDING");
        let delivery_journal = SecureIntentJournal::open(
            &config.state_dir.join("admission-intents.state"),
            &origin,
            identity.actor_id(),
        )
        .unwrap();
        let saved_delivery = delivery_journal.exact_request(&delivery.grant_id).unwrap();
        drop(delivery_journal);
        let pending_delivery: Vec<PendingPublicDelivery> = serde_json::from_str(
            &SecurePublicAdmission::new(config.clone())
                .pending_deliveries_json()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pending_delivery.len(), 1);
        assert_eq!(pending_delivery[0].grant_id, delivery.grant_id);
        let parsed: serde_json::Value = serde_json::from_slice(&saved_delivery).unwrap();
        assert_eq!(parsed["grant"]["payload"]["grant_id"], delivery.grant_id);
        let replayed: PublicDeliveryResult = serde_json::from_str(
            &SecurePublicAdmission::new(config.clone())
                .retry_delivery_json(&delivery.grant_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replayed.status, "AUTHORIZED");
        assert_eq!(replayed.grant_hash, delivery.grant_hash);
        let journal = SecureIntentJournal::open(
            &config.state_dir.join("admission-intents.state"),
            &origin,
            identity.actor_id(),
        )
        .unwrap();
        assert_eq!(
            journal.exact_request(&delivery.grant_id).unwrap(),
            saved_delivery
        );
        drop(journal);
        let recipient_proof = sign_read_proof(
            &path,
            recipient_client.discovery(),
            &recipient_identity,
            &recipient_config.authority,
        )
        .unwrap();
        let authorized = runtime
            .block_on(recipient_client.transport().get_secure_invitation_exact(
                &path,
                &recipient_proof,
                &CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(authorized.status, 200);
        let authorized =
            peerwork_core::wire_json::parse_wire_json_js_bounded(&authorized.wire, 80, 220_000)
                .unwrap();
        assert!(authorized.get("grant").is_some());
        let reject_receipt = runtime
            .block_on(
                reqwest::Client::new()
                    .post(format!("{origin}__test/reject-next-post-before-apply"))
                    .send(),
            )
            .unwrap();
        assert_eq!(reject_receipt.status().as_u16(), 200);
        assert!(matches!(
            crate::secure_public_decision::SecurePublicDecision::new(recipient_config.clone())
                .receive_json(&first.invite_id),
            Err(crate::secure_public_decision::PublicDecisionError::ServerRejected(503))
        ));
        let receipt_journal = SecureIntentJournal::open(
            &recipient_dir.join("admission-intents.state"),
            &origin,
            recipient_identity.actor_id(),
        )
        .unwrap();
        let saved_receipt = receipt_journal.exact_request(&delivery.grant_id).unwrap();
        let saved_receipt_hash = receipt_journal
            .intent_digest(&delivery.grant_id)
            .unwrap()
            .to_owned();
        assert!(saved_receipt.len() <= 4096);
        let grant_wire = peerwork_core::wire_json::canonical_wire_value(
            authorized.get("grant").unwrap(),
            peerwork_core::canonical::Path::SecureArtifact,
        )
        .unwrap();
        let mut altered_receipt = saved_receipt.clone();
        let prefix = b"grant_hash\":\"";
        let hash_start = altered_receipt
            .windows(prefix.len())
            .position(|window| window == prefix)
            .unwrap()
            + prefix.len();
        altered_receipt[hash_start] = if altered_receipt[hash_start] == b'a' {
            b'b'
        } else {
            b'a'
        };
        assert!(
            peerwork_core::prepared_public_admission::verify_saved_public_receipt(
                &altered_receipt,
                grant_wire.as_bytes(),
                &first.invite_id,
                recipient_identity.signing_key(),
            )
            .is_err()
        );
        drop(receipt_journal);
        let drop_receipt = runtime
            .block_on(
                reqwest::Client::new()
                    .post(format!("{origin}__test/drop-next-post"))
                    .send(),
            )
            .unwrap();
        assert_eq!(drop_receipt.status().as_u16(), 200);
        let uncertain: crate::secure_public_decision::PublicReceiveResult = serde_json::from_str(
            &crate::secure_public_decision::SecurePublicDecision::new(recipient_config.clone())
                .retry_receive_json(&first.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(uncertain.status, "PENDING");
        assert_eq!(uncertain.receipt_hash, saved_receipt_hash);
        let ready: crate::secure_public_decision::PublicReceiveResult = serde_json::from_str(
            &crate::secure_public_decision::SecurePublicDecision::new(recipient_config.clone())
                .retry_receive_json(&first.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ready.status, "READY");
        assert_eq!(ready.receipt_hash, saved_receipt_hash);
        let receipt_journal = SecureIntentJournal::open(
            &recipient_dir.join("admission-intents.state"),
            &origin,
            recipient_identity.actor_id(),
        )
        .unwrap();
        assert_eq!(
            receipt_journal.exact_request(&delivery.grant_id).unwrap(),
            saved_receipt
        );
        drop(receipt_journal);
        let recipient_profile = SecureReadProfileConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: recipient_dir.clone(),
            identity_path: recipient_config.identity_path.clone(),
            workspace_id: workspace.clone(),
            owner_actor_id: Some(owner_actor.clone()),
            owner_key_id: Some(owner_key.clone()),
            authority: Some(recipient_config.authority.clone()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let lifecycle = SecureLifecycle::open(
            &recipient_dir.join("lifecycle.state"),
            &origin,
            recipient_identity.actor_id(),
            &workspace,
            &owner_actor,
            &owner_key,
        )
        .unwrap();
        assert_eq!(lifecycle.status().active_epochs, Vec::<u64>::new());
        assert_eq!(
            lifecycle.replay_keyring_candidate().unwrap().state,
            crate::secure_lifecycle::ReplayKeyringState::Active
        );
        drop(lifecycle);
        let verified_read = SecureReadProfile::new(recipient_profile)
            .read_latest_json()
            .unwrap();
        let verified: serde_json::Value = serde_json::from_str(&verified_read).unwrap();
        assert_eq!(verified["sequence"], 2);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let pending_receipts: Vec<crate::secure_public_decision::PendingPublicReceipt> =
            serde_json::from_str(
                &crate::secure_public_decision::SecurePublicDecision::new(recipient_config)
                    .pending_receipts_json()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(pending_receipts.len(), 1);
        assert_eq!(pending_receipts[0].grant_id, delivery.grant_id);
        assert_eq!(pending_receipts[0].receipt_hash, ready.receipt_hash);
    }
}
