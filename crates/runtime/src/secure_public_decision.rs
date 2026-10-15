//! Recipient consent for a signed invitation. An authenticated control
//! GET and a locally pinned owner precede the exact saved decision POST.
//! Consent alone does not grant workspace read or member authority.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_grant_pending::{GrantEvidence, SecureGrantPending},
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_journal_read::{sign_read_proof, SecureJournalRead},
    secure_lifecycle::{ReplayKeyringState, SecureLifecycle},
    secure_private_grant_read::{select_direct_grant, select_member},
    secure_read_access::{SecureReadAccessError, SecureReadConfig},
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_recipient_state::RecipientState,
    secure_state::{SecureStateError, SecureStateStore},
    secure_verified_read::{
        collect_unverified_artifacts, replay_authenticated_pages_with_grant,
        SecureJournalReadBudget,
    },
    transport::{TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    prepared_public_admission::{
        prepare_public_decision, prepare_public_receipt, verify_saved_public_decision,
        verify_saved_public_receipt, PublicAdmissionError,
    },
    secure_recipient::RecipientCertificate,
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicDecisionConfig {
    #[serde(default)]
    pub transport: crate::transport::TransportOptions,
    pub origin: String,
    pub state_dir: PathBuf,
    pub identity_path: PathBuf,
    pub workspace_id: String,
    pub owner_actor_id: String,
    pub owner_key_id: String,
    pub authority: String,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default)]
    pub required_features: Vec<String>,
    #[serde(default = "default_replay_artifact_bytes")]
    pub max_replay_artifact_bytes: u64,
    #[serde(default = "crate::secure_verified_read::default_replay_commits")]
    pub max_replay_commits: u64,
}

fn default_replay_artifact_bytes() -> u64 {
    64 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicDecisionResult {
    pub status: String,
    pub invite_id: String,
    pub workspace_id: String,
    pub decision_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPublicDecision {
    pub invite_id: String,
    pub workspace_id: String,
    pub decision_hash: String,
    pub observed_responses: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReceiveResult {
    pub status: String,
    pub invite_id: String,
    pub workspace_id: String,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPublicReceipt {
    pub invite_id: String,
    pub grant_id: String,
    pub workspace_id: String,
    pub receipt_hash: String,
    pub observed_responses: usize,
}

#[derive(Debug, Error)]
pub enum PublicDecisionError {
    #[error("protected recipient or owner pin differs")]
    Identity,
    #[error("signed admission control item or decision is invalid")]
    Invalid,
    #[error(transparent)]
    Intent(#[from] SecureIntentError),
    #[error(transparent)]
    Core(#[from] PublicAdmissionError),
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error(transparent)]
    Read(#[from] SecureReadAccessError),
    #[error("signed grant cannot be bound to complete recipient replay")]
    Grant,
    #[error("protected recipient lifecycle rejected grant activation")]
    Lifecycle,
    #[error("configured control transport failed")]
    Transport,
    #[error("server rejected decision with HTTP {0}")]
    ServerRejected(u16),
    #[error("native async runtime could not start")]
    Runtime,
    #[error("system clock is invalid")]
    Clock,
    #[error("result encoding failed")]
    Encoding,
}

impl PublicDecisionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(error) => error.code(),
            Self::Intent(SecureIntentError::Conflict) => "INTENT_CONFLICT",
            Self::Intent(SecureIntentError::NotFound) => "INTENT_NOT_FOUND",
            Self::Intent(SecureIntentError::TooLarge) => "RESOURCE_LIMIT",
            Self::Intent(SecureIntentError::Transport(_)) | Self::Transport => "TRANSPORT_FAILED",
            Self::Intent(SecureIntentError::ServerRejected(_)) | Self::ServerRejected(_) => {
                "SERVER_REJECTED"
            }
            Self::Intent(SecureIntentError::ReplayMismatch) => "VERIFICATION_FAILED",
            Self::Intent(_) => "INTENT_STATE",
            Self::Core(_) | Self::Invalid => "DECISION_INVALID",
            Self::Identity => "IDENTITY_STATE",
            Self::Store(_) => "LOCAL_STATE_FAILED",
            Self::Grant => "GRANT_VERIFICATION_FAILED",
            Self::Lifecycle => "LIFECYCLE_STATE",
            Self::Runtime => "RUNTIME_FAILED",
            Self::Clock => "CLOCK_INVALID",
            Self::Encoding => "RESULT_ENCODING_FAILED",
        }
    }
}

impl PublicDecisionConfig {
    /// Bind the recipient's read authority to its protected local identity.
    /// An explicit nonempty authority remains an intentional override.
    pub fn resolve_default_authority(mut self) -> Result<Self, PublicDecisionError> {
        if self.identity_path != self.state_dir.join("identity.state") {
            return Err(PublicDecisionError::Identity);
        }
        let identity =
            KernelIdentity::open(&self.identity_path).map_err(|_| PublicDecisionError::Identity)?;
        if self.authority.is_empty() {
            self.authority = sha256_hex(identity.actor_id().as_bytes());
        }
        Ok(self)
    }
}

pub struct SecurePublicDecision {
    config: PublicDecisionConfig,
}

impl SecurePublicDecision {
    pub fn new(config: PublicDecisionConfig) -> Self {
        Self { config }
    }

    /// Redacted protected pending IDs; no network or unsigned service state.
    pub fn pending_json(&self) -> Result<String, PublicDecisionError> {
        self.pin_local()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicDecisionError::Identity)?;
        let recipient =
            RecipientState::open(&self.config.state_dir.join("recipient.state"), &identity)
                .map_err(|_| PublicDecisionError::Identity)?;
        let _ = recipient.certificate();
        let journal = self.open_journal(&identity)?;
        let mut rows = Vec::new();
        for pending in journal.pending() {
            if pending.action_id != "secure.invite.decision" {
                continue;
            }
            if pending.workspace_id.as_deref() != Some(self.config.workspace_id.as_str())
                || journal.path(&pending.intent_id)? != decision_path(&pending.intent_id)
            {
                return Err(PublicDecisionError::Identity);
            }
            rows.push(PendingPublicDecision {
                invite_id: pending.intent_id.clone(),
                workspace_id: self.config.workspace_id.clone(),
                decision_hash: journal.intent_digest(&pending.intent_id)?.to_owned(),
                observed_responses: pending.observed_responses,
            });
        }
        serde_json::to_string(&rows).map_err(|_| PublicDecisionError::Encoding)
    }

    /// Local protected receipt IDs remain discoverable after cancellation or
    /// offline restart. Listing is neither a signed READY result nor access.
    pub fn pending_receipts_json(&self) -> Result<String, PublicDecisionError> {
        self.pin_local()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicDecisionError::Identity)?;
        let recipient =
            RecipientState::open(&self.config.state_dir.join("recipient.state"), &identity)
                .map_err(|_| PublicDecisionError::Identity)?;
        let _ = recipient.certificate();
        let journal = self.open_journal(&identity)?;
        let mut rows = Vec::new();
        for row in journal.pending() {
            if row.action_id != "secure.invite.receipt" {
                continue;
            }
            let saved = journal.exact_request(&row.intent_id)?;
            let request = parse_wire_json_js_bounded(&saved, 16, 4096)
                .map_err(|_| PublicDecisionError::Invalid)?;
            let invite_id = request
                .get("receipt")
                .and_then(|r| r.get("payload"))
                .and_then(|p| p.get("invite_id"))
                .and_then(WireValue::as_string)
                .ok_or(PublicDecisionError::Invalid)?;
            if row.workspace_id.as_deref() != Some(self.config.workspace_id.as_str())
                || journal.path(&row.intent_id)? != format!("{}/receipt", control_path(&invite_id)?)
            {
                return Err(PublicDecisionError::Identity);
            }
            rows.push(PendingPublicReceipt {
                invite_id,
                grant_id: row.intent_id.clone(),
                workspace_id: self.config.workspace_id.clone(),
                receipt_hash: journal.intent_digest(&row.intent_id)?.into(),
                observed_responses: row.observed_responses,
            });
        }
        serde_json::to_string(&rows).map_err(|_| PublicDecisionError::Encoding)
    }

    pub fn decide_json(
        &self,
        invite_id: &str,
        decision: &str,
    ) -> Result<String, PublicDecisionError> {
        self.decide_json_with_cancel(invite_id, decision, &CancellationToken::new())
    }

    pub fn decide_json_with_cancel(
        &self,
        invite_id: &str,
        decision: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicDecisionError> {
        self.pin_local()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicDecisionError::Identity)?;
        let recipient =
            RecipientState::open(&self.config.state_dir.join("recipient.state"), &identity)
                .map_err(|_| PublicDecisionError::Identity)?;
        let mut journal = self.open_journal(&identity)?;
        if journal.contains_id(invite_id) {
            return Err(PublicDecisionError::Intent(SecureIntentError::Conflict));
        }
        let (runtime, client) = self.client(cancel)?;
        let path = control_path(invite_id)?;
        let (item, offer_wire) = self.read_control(&runtime, &client, &identity, &path, cancel)?;
        if !matches!(item.get("decision"), None | Some(WireValue::Null)) {
            return Err(PublicDecisionError::Invalid);
        }
        self.check_offer(&item, &offer_wire, &identity, &recipient, invite_id)?;
        let packet = prepare_public_decision(
            &offer_wire,
            &self.config.owner_actor_id,
            &self.config.owner_key_id,
            identity.signing_key(),
            decision,
            now_ms()?,
        )?;
        let decision_path = decision_path(invite_id);
        journal.prepare(SecurePacketInput {
            intent_id: invite_id,
            path: &decision_path,
            action_id: "secure.invite.decision",
            workspace_id: Some(&self.config.workspace_id),
            trusted_owner_key: Some(&self.config.owner_key_id),
            intent_digest: packet.artifact_hash(),
            exact_request: packet.request_wire(),
        })?;
        self.send_saved(
            &runtime,
            &client,
            &identity,
            &mut journal,
            invite_id,
            &offer_wire,
            cancel,
        )?;
        serde_json::to_string(&PublicDecisionResult {
            status: "PENDING".into(),
            invite_id: invite_id.into(),
            workspace_id: self.config.workspace_id.clone(),
            decision_hash: packet.artifact_hash().into(),
        })
        .map_err(|_| PublicDecisionError::Encoding)
    }

    pub fn retry_json(&self, invite_id: &str) -> Result<String, PublicDecisionError> {
        self.retry_json_with_cancel(invite_id, &CancellationToken::new())
    }

    pub fn retry_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicDecisionError> {
        self.pin_local()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicDecisionError::Identity)?;
        let recipient =
            RecipientState::open(&self.config.state_dir.join("recipient.state"), &identity)
                .map_err(|_| PublicDecisionError::Identity)?;
        let mut journal = self.open_journal(&identity)?;
        let (runtime, client) = self.client(cancel)?;
        let path = control_path(invite_id)?;
        let (item, offer_wire) = self.read_control(&runtime, &client, &identity, &path, cancel)?;
        self.check_offer(&item, &offer_wire, &identity, &recipient, invite_id)?;
        self.send_saved(
            &runtime,
            &client,
            &identity,
            &mut journal,
            invite_id,
            &offer_wire,
            cancel,
        )?;
        serde_json::to_string(&PublicDecisionResult {
            status: "PENDING".into(),
            invite_id: invite_id.into(),
            workspace_id: self.config.workspace_id.clone(),
            decision_hash: journal.intent_digest(invite_id)?.to_owned(),
        })
        .map_err(|_| PublicDecisionError::Encoding)
    }

    /// Receive an owner-delivered PUBLIC grant through a fresh, complete
    /// recipient replay. The exact signed receipt is durable before POST;
    /// transport success is reported as pending until signed control evidence
    /// confirms the same receipt. An active local ring derives only from the
    /// grant plus complete replay proof, never from the receipt HTTP reply.
    pub fn receive_json(&self, invite_id: &str) -> Result<String, PublicDecisionError> {
        self.receive_json_with_cancel(invite_id, &CancellationToken::new())
    }

    pub fn receive_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicDecisionError> {
        self.pin_local()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicDecisionError::Identity)?;
        let recipient =
            RecipientState::open(&self.config.state_dir.join("recipient.state"), &identity)
                .map_err(|_| PublicDecisionError::Identity)?;
        let (runtime, client) = self.client(cancel)?;
        let (control, offer_wire) = self.read_control(
            &runtime,
            &client,
            &identity,
            &control_path(invite_id)?,
            cancel,
        )?;
        self.check_offer(&control, &offer_wire, &identity, &recipient, invite_id)?;
        let decision = control
            .get("decision")
            .ok_or(PublicDecisionError::Invalid)?;
        let grant = control.get("grant").ok_or(PublicDecisionError::Invalid)?;
        let policy = control.get("policy").ok_or(PublicDecisionError::Invalid)?;
        let decision_wire = canonical_wire_value(decision, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let checked = verify_saved_public_decision(
            format!("{{\"decision\":{decision_wire}}}").as_bytes(),
            &offer_wire,
            &self.config.owner_actor_id,
            &self.config.owner_key_id,
            identity.actor_id(),
            identity.key_id(),
            &self.config.workspace_id,
        )?;
        if checked.id() != invite_id
            || decision
                .get("payload")
                .and_then(|p| p.get("decision"))
                .and_then(WireValue::as_string)
                .as_deref()
                != Some("ACCEPT")
        {
            return Err(PublicDecisionError::Invalid);
        }
        let grant_wire = canonical_wire_value(grant, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let policy_wire = canonical_wire_value(policy, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let grant_payload = grant.get("payload").ok_or(PublicDecisionError::Invalid)?;
        let grant_id = grant_payload
            .get("grant_id")
            .and_then(WireValue::as_string)
            .ok_or(PublicDecisionError::Invalid)?;
        let policy_hash = grant_payload
            .get("policy_hash")
            .and_then(WireValue::as_string)
            .ok_or(PublicDecisionError::Invalid)?;
        let cert = control
            .get("offer")
            .and_then(|v| v.get("payload"))
            .and_then(|v| v.get("recipient"))
            .ok_or(PublicDecisionError::Invalid)?;
        let cert_wire = canonical_wire_value(cert, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?;
        if policy
            .get("payload")
            .and_then(|payload| payload.get("visibility"))
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("PRIVATE")
        {
            return self.receive_private_invitation(
                &runtime,
                &client,
                &identity,
                &recipient,
                invite_id,
                &grant_id,
                &policy_hash,
                &offer_wire,
                decision_wire.as_bytes(),
                grant_wire.as_bytes(),
                policy_wire.as_bytes(),
                cert_wire.as_bytes(),
                cancel,
            );
        }
        let profile = SecureReadProfileConfig {
            transport: self.config.transport.clone(),
            origin: self.config.origin.clone(),
            state_dir: self.config.state_dir.clone(),
            identity_path: self.config.identity_path.clone(),
            workspace_id: self.config.workspace_id.clone(),
            owner_actor_id: Some(self.config.owner_actor_id.clone()),
            owner_key_id: Some(self.config.owner_key_id.clone()),
            authority: Some(self.config.authority.clone()),
            required_features: self.config.required_features.clone(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            max_replay_commits: self.config.max_replay_commits,
        };
        SecureReadProfile::new(profile).with_latest_replay(cancel, |source| {
            if source.origin() != self.config.origin
                || source.authority() != self.config.authority
                || source.source_actor_id() != identity.actor_id()
                || source.source_key_id() != identity.key_id()
                || source.replay().workspace_id() != self.config.workspace_id
                || source.replay().owner_actor_id() != self.config.owner_actor_id
                || source.replay().owner_signing_key() != self.config.owner_key_id
                || source.replay().policy_hash() != policy_hash
                || source.signed_policy_by_hash(&policy_hash) != Some(policy_wire.as_bytes())
            {
                return Err(PublicDecisionError::Invalid);
            }
            let policies = source
                .signed_policy_wires()
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let commits = source
                .signed_commit_wires()
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let mut pending = SecureGrantPending::open(
                &self.config.state_dir.join("pending-grant.state"),
                source.origin(),
                source.authority(),
                &self.config.workspace_id,
                &self.config.owner_actor_id,
                &self.config.owner_key_id,
                &identity,
                &recipient,
                now_ms()?,
            )
            .map_err(|_| PublicDecisionError::Grant)?;
            pending
                .stage(
                    GrantEvidence {
                        policies: &policies,
                        commits: &commits,
                        checkpoint: source.checkpoint_canonical_json().as_bytes(),
                        grant: grant_wire.as_bytes(),
                        certificate: cert_wire.as_bytes(),
                        invitation: Some((&offer_wire, decision_wire.as_bytes())),
                        delegation: None,
                    },
                    &recipient,
                    now_ms()?,
                )
                .map_err(|_| PublicDecisionError::Grant)?;
            let activation = pending
                .bind_to_replay(&recipient, now_ms()?, source)
                .map_err(|_| PublicDecisionError::Grant)?
                .ok_or(PublicDecisionError::Grant)?;
            let mut journal = self.open_journal(&identity)?;
            if journal.contains_id(&grant_id) {
                return Err(PublicDecisionError::Intent(SecureIntentError::Conflict));
            }
            let packet = prepare_public_receipt(
                grant_wire.as_bytes(),
                source.checkpoint_canonical_json().as_bytes(),
                invite_id,
                now_ms()?,
                identity.signing_key(),
            )?;
            let receipt_path = format!("{}/receipt", control_path(invite_id)?);
            journal.prepare(SecurePacketInput {
                intent_id: &grant_id,
                path: &receipt_path,
                action_id: "secure.invite.receipt",
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(&self.config.owner_key_id),
                intent_digest: packet.artifact_hash(),
                exact_request: packet.request_wire(),
            })?;
            let mut lifecycle = SecureLifecycle::open(
                &self.config.state_dir.join("lifecycle.state"),
                source.origin(),
                identity.actor_id(),
                &self.config.workspace_id,
                &self.config.owner_actor_id,
                &self.config.owner_key_id,
            )
            .map_err(|_| PublicDecisionError::Lifecycle)?;
            lifecycle
                .activate_verified_grant(activation)
                .map_err(|_| PublicDecisionError::Lifecycle)?;
            self.send_saved_receipt(
                &runtime,
                &client,
                &identity,
                &mut journal,
                &grant_id,
                &receipt_path,
                cancel,
            )?;
            serde_json::to_string(&PublicReceiveResult {
                status: "PENDING".into(),
                invite_id: invite_id.into(),
                workspace_id: self.config.workspace_id.clone(),
                receipt_hash: packet.artifact_hash().into(),
            })
            .map_err(|_| PublicDecisionError::Encoding)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_private_invitation(
        &self,
        runtime: &tokio::runtime::Runtime,
        client: &KernelClient,
        identity: &KernelIdentity,
        recipient: &RecipientState,
        invite_id: &str,
        grant_id: &str,
        policy_hash: &str,
        offer_wire: &[u8],
        decision_wire: &[u8],
        grant_wire: &[u8],
        policy_wire: &[u8],
        cert_wire: &[u8],
        cancel: &CancellationToken,
    ) -> Result<String, PublicDecisionError> {
        let config = SecureReadConfig {
            transport: self.config.transport.clone(),
            origin: self.config.origin.clone(),
            kernel_journal_path: self.config.state_dir.join("kernel.sqlite"),
            read_state_path: self.config.state_dir.join("private-admission-pages.state"),
            lifecycle_path: self.config.state_dir.join("lifecycle.state"),
            identity_path: self.config.identity_path.clone(),
            workspace_id: self.config.workspace_id.clone(),
            authority: self.config.authority.clone(),
            owner_actor_id: self.config.owner_actor_id.clone(),
            owner_key_id: self.config.owner_key_id.clone(),
            required_features: self.config.required_features.clone(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            max_replay_commits: self.config.max_replay_commits,
        };
        let budget = SecureJournalReadBudget::new_with_limits(config.max_replay_artifact_bytes, config.max_replay_commits)
            .ok_or(PublicDecisionError::Read(crate::secure_read_access::SecureReadAccessError::ResourceLimit))?;
        let mut reader = SecureJournalRead::open(
            &config.read_state_path,
            client,
            identity,
            &config.workspace_id,
            &config.authority,
        )
        .map_err(|_| PublicDecisionError::Grant)?;
        if reader
            .progress()
            .map_err(|_| PublicDecisionError::Grant)?
            .complete_transport
        {
            reader
                .reset_inactive_generation()
                .map_err(|_| PublicDecisionError::Grant)?;
        }
        while !reader
            .progress()
            .map_err(|_| PublicDecisionError::Grant)?
            .complete_transport
        {
            runtime
                .block_on(reader.fetch_next(client, identity, cancel))
                .map_err(|_| PublicDecisionError::Transport)?;
        }
        let pages = reader
            .authenticated_pages(client, identity)
            .map_err(|_| PublicDecisionError::Grant)?;
        let artifacts =
            collect_unverified_artifacts(&pages, budget).map_err(|e| match e { crate::secure_verified_read::VerifiedReadError::ResourceLimit => PublicDecisionError::Read(crate::secure_read_access::SecureReadAccessError::ResourceLimit), _ => PublicDecisionError::Grant })?;
        let last_policy = artifacts
            .policy_wires
            .last()
            .ok_or(PublicDecisionError::Grant)?;
        let historical = last_policy.as_slice() != policy_wire;
        let (historical_policy_count, historical_commit_count, historical_checkpoint) =
            historical_grant_prefix(
                &artifacts.policy_wires,
                &artifacts.commit_wires,
                policy_wire,
                policy_hash,
                &self.config.workspace_id,
                &self.config.owner_actor_id,
                &self.config.owner_key_id,
            )?;
        if !historical && sha256_hex(last_policy) != policy_hash {
            return Err(PublicDecisionError::Grant);
        }
        let policies = artifacts
            .policy_wires
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let commits = artifacts
            .commit_wires
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut pending = SecureGrantPending::open(
            &self.config.state_dir.join(if historical {
                "pending-grant-historical.state"
            } else {
                "pending-grant.state"
            }),
            client.origin(),
            &self.config.authority,
            &self.config.workspace_id,
            &self.config.owner_actor_id,
            &self.config.owner_key_id,
            identity,
            recipient,
            now_ms()?,
        )
        .map_err(|_| PublicDecisionError::Grant)?;
        let grant = pending
            .stage(
                GrantEvidence {
                    policies: &policies[..historical_policy_count],
                    commits: &commits[..historical_commit_count],
                    checkpoint: if historical {
                        &historical_checkpoint
                    } else {
                        pages.checkpoint_canonical_json().as_bytes()
                    },
                    grant: grant_wire,
                    certificate: cert_wire,
                    invitation: Some((offer_wire, decision_wire)),
                    delegation: None,
                },
                recipient,
                now_ms()?,
            )
            .map_err(|_| PublicDecisionError::Grant)?;
        let mut lifecycle = SecureLifecycle::open(
            &config.lifecycle_path,
            client.origin(),
            identity.actor_id(),
            &config.workspace_id,
            &config.owner_actor_id,
            &config.owner_key_id,
        )
        .map_err(|_| PublicDecisionError::Lifecycle)?;
        let (replay_grant, activation_pending) = if historical {
            let audience = String::from_utf16(client.discovery().audience_utf16())
                .map_err(|_| PublicDecisionError::Grant)?;
            let selection = select_member(&artifacts.policy_wires, identity, &config, audience)
                .map_err(|_| PublicDecisionError::Grant)?;
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/key-grants",
                config.workspace_id
            );
            let proof =
                sign_read_proof(&path, client.discovery(), identity, &self.config.authority)
                    .map_err(|_| PublicDecisionError::Grant)?;
            let response = runtime
                .block_on(
                    client
                        .transport()
                        .get_secure_key_grants_exact(&path, &proof, cancel),
                )
                .map_err(|_| PublicDecisionError::Transport)?;
            if response.status != 200 || response.wire.len() > 2 * 1024 * 1024 {
                return Err(PublicDecisionError::Grant);
            }
            let current_grant = select_direct_grant(&response.wire, &selection, &config)
                .map_err(|_| PublicDecisionError::Grant)?;
            let mut current = SecureGrantPending::open(
                &self.config.state_dir.join("pending-grant-current.state"),
                client.origin(),
                &self.config.authority,
                &self.config.workspace_id,
                &self.config.owner_actor_id,
                &self.config.owner_key_id,
                identity,
                recipient,
                now_ms()?,
            )
            .map_err(|_| PublicDecisionError::Grant)?;
            let current_material = current
                .stage(
                    GrantEvidence {
                        policies: &policies,
                        commits: &commits,
                        checkpoint: pages.checkpoint_canonical_json().as_bytes(),
                        grant: &current_grant,
                        certificate: &selection.certificate_wire,
                        invitation: None,
                        delegation: None,
                    },
                    recipient,
                    now_ms()?,
                )
                .map_err(|_| PublicDecisionError::Grant)?;
            if current_material.keyring().key_at(grant.epoch())
                != grant.keyring().key_at(grant.epoch())
            {
                return Err(PublicDecisionError::Grant);
            }
            (current_material, Some(current))
        } else {
            (grant, None)
        };
        let replay =
            replay_authenticated_pages_with_grant(&pages, &lifecycle, &replay_grant, budget)
                .map_err(|e| match e { crate::secure_verified_read::VerifiedReadError::ResourceLimit => PublicDecisionError::Read(crate::secure_read_access::SecureReadAccessError::ResourceLimit), _ => PublicDecisionError::Grant })?;
        let historical_head = if historical_commit_count == 0 {
            None
        } else {
            Some(sha256_hex(
                &artifacts.commit_wires[historical_commit_count - 1],
            ))
        };
        if historical
            && !replay.replay().contains_checkpoint(
                historical_commit_count as u64,
                historical_head.as_deref(),
                policy_hash,
            )
        {
            return Err(PublicDecisionError::Grant);
        }
        let activation = activation_pending
            .as_ref()
            .unwrap_or(&pending)
            .bind_to_replay(recipient, now_ms()?, &replay)
            .map_err(|_| PublicDecisionError::Grant)?
            .ok_or(PublicDecisionError::Grant)?;
        let mut journal = self.open_journal(identity)?;
        if journal.contains_id(grant_id) {
            return Err(PublicDecisionError::Intent(SecureIntentError::Conflict));
        }
        let packet = prepare_public_receipt(
            grant_wire,
            pages.checkpoint_canonical_json().as_bytes(),
            invite_id,
            now_ms()?,
            identity.signing_key(),
        )?;
        let receipt_path = format!("{}/receipt", control_path(invite_id)?);
        journal.prepare(SecurePacketInput {
            intent_id: grant_id,
            path: &receipt_path,
            action_id: "secure.invite.receipt",
            workspace_id: Some(&self.config.workspace_id),
            trusted_owner_key: Some(&self.config.owner_key_id),
            intent_digest: packet.artifact_hash(),
            exact_request: packet.request_wire(),
        })?;
        lifecycle
            .activate_verified_grant(activation)
            .map_err(|_| PublicDecisionError::Lifecycle)?;
        self.send_saved_receipt(
            runtime,
            client,
            identity,
            &mut journal,
            grant_id,
            &receipt_path,
            cancel,
        )?;
        serde_json::to_string(&PublicReceiveResult {
            status: "PENDING".into(),
            invite_id: invite_id.into(),
            workspace_id: self.config.workspace_id.clone(),
            receipt_hash: packet.artifact_hash().into(),
        })
        .map_err(|_| PublicDecisionError::Encoding)
    }

    fn send_saved_receipt(
        &self,
        runtime: &tokio::runtime::Runtime,
        client: &KernelClient,
        identity: &KernelIdentity,
        journal: &mut SecureIntentJournal,
        grant_id: &str,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<(), PublicDecisionError> {
        if journal.path(grant_id)? != path {
            return Err(PublicDecisionError::Invalid);
        }
        let saved = journal.exact_request(grant_id)?;
        let proof = sign_read_proof(path, client.discovery(), identity, &self.config.authority)
            .map_err(|_| PublicDecisionError::Invalid)?;
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
                    return Err(PublicDecisionError::ServerRejected(response.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PublicDecisionError::Transport),
        }
        Ok(())
    }

    /// Reconcile a saved receipt after an uncertain POST. A READY result
    /// requires the exact signed receipt in authenticated control evidence
    /// and its checkpoint as an ancestor of the current complete replay.
    pub fn retry_receive_json(&self, invite_id: &str) -> Result<String, PublicDecisionError> {
        self.retry_receive_json_with_cancel(invite_id, &CancellationToken::new())
    }

    pub fn retry_receive_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicDecisionError> {
        self.pin_local()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicDecisionError::Identity)?;
        let recipient =
            RecipientState::open(&self.config.state_dir.join("recipient.state"), &identity)
                .map_err(|_| PublicDecisionError::Identity)?;
        let (runtime, client) = self.client(cancel)?;
        let (control, offer_wire) = self.read_control(
            &runtime,
            &client,
            &identity,
            &control_path(invite_id)?,
            cancel,
        )?;
        self.check_offer(&control, &offer_wire, &identity, &recipient, invite_id)?;
        let grant = control.get("grant").ok_or(PublicDecisionError::Invalid)?;
        let grant_wire = canonical_wire_value(grant, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let policy_wire = canonical_wire_value(
            control.get("policy").ok_or(PublicDecisionError::Invalid)?,
            CanonicalPath::SecureArtifact,
        )
        .map_err(|_| PublicDecisionError::Invalid)?;
        let grant_id = grant
            .get("payload")
            .and_then(|p| p.get("grant_id"))
            .and_then(WireValue::as_string)
            .ok_or(PublicDecisionError::Invalid)?;
        let receipt_path = format!("{}/receipt", control_path(invite_id)?);
        let profile = SecureReadProfileConfig {
            transport: self.config.transport.clone(),
            origin: self.config.origin.clone(),
            state_dir: self.config.state_dir.clone(),
            identity_path: self.config.identity_path.clone(),
            workspace_id: self.config.workspace_id.clone(),
            owner_actor_id: Some(self.config.owner_actor_id.clone()),
            owner_key_id: Some(self.config.owner_key_id.clone()),
            authority: Some(self.config.authority.clone()),
            required_features: self.config.required_features.clone(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            max_replay_commits: self.config.max_replay_commits,
        };
        SecureReadProfile::new(profile).with_latest_replay(cancel, |source| {
            if source.origin() != self.config.origin
                || source.authority() != self.config.authority
                || source.source_actor_id() != identity.actor_id()
                || source.source_key_id() != identity.key_id()
                || source.replay().workspace_id() != self.config.workspace_id
                || source.replay().owner_actor_id() != self.config.owner_actor_id
                || source.replay().owner_signing_key() != self.config.owner_key_id
            {
                return Err(PublicDecisionError::Identity);
            }
            let mut journal = self.open_journal(&identity)?;
            if journal.path(&grant_id)? != receipt_path {
                return Err(PublicDecisionError::Invalid);
            }
            let saved = journal.exact_request(&grant_id)?;
            let checked = verify_saved_public_receipt(
                &saved,
                grant_wire.as_bytes(),
                invite_id,
                identity.signing_key(),
            )?;
            if journal.intent_digest(&grant_id)? != checked.artifact_hash() {
                return Err(PublicDecisionError::Invalid);
            }
            let request = parse_wire_json_js_bounded(&saved, 16, 4096)
                .map_err(|_| PublicDecisionError::Invalid)?;
            let payload = request
                .get("receipt")
                .and_then(|r| r.get("payload"))
                .ok_or(PublicDecisionError::Invalid)?;
            let cp = payload
                .get("checkpoint")
                .ok_or(PublicDecisionError::Invalid)?;
            let sequence = cp
                .get("sequence")
                .and_then(WireValue::as_number)
                .filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n <= 9_007_199_254_740_991.0)
                .ok_or(PublicDecisionError::Invalid)? as u64;
            let head = cp
                .get("head")
                .and_then(WireValue::as_string)
                .ok_or(PublicDecisionError::Invalid)?;
            let cp_policy_hash = cp
                .get("policy_hash")
                .and_then(WireValue::as_string)
                .ok_or(PublicDecisionError::Invalid)?;
            if !source
                .replay()
                .contains_checkpoint(sequence, Some(&head), &cp_policy_hash)
                || payload
                    .get("workspace_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(self.config.workspace_id.as_str())
            {
                return Err(PublicDecisionError::Invalid);
            }
            let old_policy_hash = grant
                .get("payload")
                .and_then(|p| p.get("policy_hash"))
                .and_then(WireValue::as_string)
                .ok_or(PublicDecisionError::Invalid)?;
            let historical = source.replay().policy_hash() != old_policy_hash;
            let pending = SecureGrantPending::open(
                &self.config.state_dir.join(if historical {
                    "pending-grant-historical.state"
                } else {
                    "pending-grant.state"
                }),
                source.origin(),
                source.authority(),
                &self.config.workspace_id,
                &self.config.owner_actor_id,
                &self.config.owner_key_id,
                &identity,
                &recipient,
                now_ms()?,
            )
            .map_err(|_| PublicDecisionError::Grant)?;
            let material = pending
                .verified_pending(&recipient, now_ms()?)
                .map_err(|_| PublicDecisionError::Grant)?
                .ok_or(PublicDecisionError::Grant)?;
            if pending
                .saved_grant_hash()
                .map_err(|_| PublicDecisionError::Grant)?
                != Some(sha256_hex(grant_wire.as_bytes()))
                || material.policy_hash() != old_policy_hash
            {
                return Err(PublicDecisionError::Grant);
            }
            let current = if historical {
                let (policy_count, commit_count, _) = historical_grant_prefix(
                    source.signed_policy_wires(),
                    source.signed_commit_wires(),
                    policy_wire.as_bytes(),
                    &old_policy_hash,
                    &self.config.workspace_id,
                    &self.config.owner_actor_id,
                    &self.config.owner_key_id,
                )?;
                let old_head = commit_count
                    .checked_sub(1)
                    .map(|index| sha256_hex(&source.signed_commit_wires()[index]));
                if policy_count == source.signed_policy_wires().len()
                    || !source.replay().contains_checkpoint(
                        commit_count as u64,
                        old_head.as_deref(),
                        &old_policy_hash,
                    )
                {
                    return Err(PublicDecisionError::Grant);
                }
                Some(
                    SecureGrantPending::open(
                        &self.config.state_dir.join("pending-grant-current.state"),
                        source.origin(),
                        source.authority(),
                        &self.config.workspace_id,
                        &self.config.owner_actor_id,
                        &self.config.owner_key_id,
                        &identity,
                        &recipient,
                        now_ms()?,
                    )
                    .map_err(|_| PublicDecisionError::Grant)?,
                )
            } else {
                None
            };
            let binding = current.as_ref().unwrap_or(&pending);
            let current_material = if historical {
                let current_material = binding
                    .verified_pending(&recipient, now_ms()?)
                    .map_err(|_| PublicDecisionError::Grant)?
                    .ok_or(PublicDecisionError::Grant)?;
                if material.keyring().key_at(material.epoch()).is_none()
                    || current_material.keyring().key_at(material.epoch())
                        != material.keyring().key_at(material.epoch())
                {
                    return Err(PublicDecisionError::Grant);
                }
                current_material
            } else {
                material
            };
            let mut lifecycle = SecureLifecycle::open(
                &self.config.state_dir.join("lifecycle.state"),
                source.origin(),
                identity.actor_id(),
                &self.config.workspace_id,
                &self.config.owner_actor_id,
                &self.config.owner_key_id,
            )
            .map_err(|_| PublicDecisionError::Lifecycle)?;
            if lifecycle.replay_keyring_candidate().is_none() {
                // A crash may occur after the receipt packet is saved and
                // before the grant proof is promoted. Rebuild that proof from
                // the same complete journal, never from the saved packet.
                let activation = binding
                    .bind_to_replay(&recipient, now_ms()?, source)
                    .map_err(|_| PublicDecisionError::Grant)?
                    .ok_or(PublicDecisionError::Grant)?;
                lifecycle
                    .activate_verified_grant(activation)
                    .map_err(|_| PublicDecisionError::Lifecycle)?;
            }
            let candidate = lifecycle
                .replay_keyring_candidate()
                .ok_or(PublicDecisionError::Lifecycle)?;
            if candidate.state != ReplayKeyringState::Active
                || candidate
                    .ring
                    .canonical_wire()
                    .map_err(|_| PublicDecisionError::Lifecycle)?
                    != current_material
                        .keyring()
                        .canonical_wire()
                        .map_err(|_| PublicDecisionError::Lifecycle)?
            {
                return Err(PublicDecisionError::Lifecycle);
            }
            if let Some(receipt) = control
                .get("receipt")
                .filter(|v| !matches!(v, WireValue::Null))
            {
                let observed = canonical_wire_value(receipt, CanonicalPath::SecureArtifact)
                    .map_err(|_| PublicDecisionError::Invalid)?;
                if observed.as_bytes() != checked.artifact_wire() {
                    return Err(PublicDecisionError::Invalid);
                }
                return serde_json::to_string(&PublicReceiveResult {
                    status: "READY".into(),
                    invite_id: invite_id.into(),
                    workspace_id: self.config.workspace_id.clone(),
                    receipt_hash: checked.artifact_hash().into(),
                })
                .map_err(|_| PublicDecisionError::Encoding);
            }
            // The saved receipt may refer to an earlier signed checkpoint
            // after unrelated valid commits. Its exact ancestor proof above
            // is the retry authority; re-authoring at the latest head would
            // silently replace the durable packet.
            self.send_saved_receipt(
                &runtime,
                &client,
                &identity,
                &mut journal,
                &grant_id,
                &receipt_path,
                cancel,
            )?;
            serde_json::to_string(&PublicReceiveResult {
                status: "PENDING".into(),
                invite_id: invite_id.into(),
                workspace_id: self.config.workspace_id.clone(),
                receipt_hash: checked.artifact_hash().into(),
            })
            .map_err(|_| PublicDecisionError::Encoding)
        })
    }

    fn send_saved(
        &self,
        runtime: &tokio::runtime::Runtime,
        client: &KernelClient,
        identity: &KernelIdentity,
        journal: &mut SecureIntentJournal,
        invite_id: &str,
        offer_wire: &[u8],
        cancel: &CancellationToken,
    ) -> Result<(), PublicDecisionError> {
        let path = decision_path(invite_id);
        if journal.path(invite_id)? != path {
            return Err(PublicDecisionError::Invalid);
        }
        let saved = journal.exact_request(invite_id)?;
        let checked = verify_saved_public_decision(
            &saved,
            offer_wire,
            &self.config.owner_actor_id,
            &self.config.owner_key_id,
            identity.actor_id(),
            identity.key_id(),
            &self.config.workspace_id,
        )?;
        if checked.id() != invite_id
            || checked.artifact_hash() != journal.intent_digest(invite_id)?
        {
            return Err(PublicDecisionError::Invalid);
        }
        let proof = sign_read_proof(&path, client.discovery(), identity, &self.config.authority)
            .map_err(|_| PublicDecisionError::Invalid)?;
        match runtime.block_on(
            client
                .transport()
                .post_secure_admission_exact(&path, saved, &proof, cancel),
        ) {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(invite_id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(PublicDecisionError::ServerRejected(response.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PublicDecisionError::Transport),
        }
        Ok(())
    }

    fn check_offer(
        &self,
        item: &WireValue,
        offer_wire: &[u8],
        identity: &KernelIdentity,
        recipient: &RecipientState,
        invite_id: &str,
    ) -> Result<(), PublicDecisionError> {
        let offer = parse_wire_json_js_bounded(offer_wire, 64, 220_000)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let payload = offer.get("payload").ok_or(PublicDecisionError::Invalid)?;
        if item
            .get("invite_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(invite_id)
            || payload
                .get("invite_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(invite_id)
            || payload
                .get("workspace_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(self.config.workspace_id.as_str())
            || payload
                .get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(self.config.owner_actor_id.as_str())
            || payload
                .get("signing_key")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(self.config.owner_key_id.as_str())
            || item
                .get("offer_hash")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(sha256_hex(offer_wire).as_str())
        {
            return Err(PublicDecisionError::Invalid);
        }
        let offered_cert = payload
            .get("recipient")
            .ok_or(PublicDecisionError::Invalid)?;
        let signed_cert = canonical_wire_value(offered_cert, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let certificate: RecipientCertificate =
            serde_json::from_str(&signed_cert).map_err(|_| PublicDecisionError::Invalid)?;
        if recipient.recipient_for_certificate(&certificate).is_err()
            || certificate.payload["actor_id"].as_str() != Some(identity.actor_id())
        {
            return Err(PublicDecisionError::Identity);
        }
        Ok(())
    }

    fn read_control(
        &self,
        runtime: &tokio::runtime::Runtime,
        client: &KernelClient,
        identity: &KernelIdentity,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<(WireValue, Vec<u8>), PublicDecisionError> {
        let proof = sign_read_proof(path, client.discovery(), identity, &self.config.authority)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let response = runtime
            .block_on(
                client
                    .transport()
                    .get_secure_invitation_exact(path, &proof, cancel),
            )
            .map_err(|_| PublicDecisionError::Transport)?;
        if !(200..300).contains(&response.status) {
            return Err(PublicDecisionError::ServerRejected(response.status));
        }
        let item = parse_wire_json_js_bounded(&response.wire, 80, 220_000)
            .map_err(|_| PublicDecisionError::Invalid)?;
        let offer = item.get("offer").ok_or(PublicDecisionError::Invalid)?;
        let offer_wire = canonical_wire_value(offer, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicDecisionError::Invalid)?
            .into_bytes();
        Ok((item, offer_wire))
    }

    fn open_journal(
        &self,
        identity: &KernelIdentity,
    ) -> Result<SecureIntentJournal, PublicDecisionError> {
        SecureIntentJournal::open(
            &self.config.state_dir.join("admission-intents.state"),
            &self.config.origin,
            identity.actor_id(),
        )
        .map_err(Into::into)
    }

    fn client(
        &self,
        cancel: &CancellationToken,
    ) -> Result<(tokio::runtime::Runtime, KernelClient), PublicDecisionError> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PublicDecisionError::Runtime)?;
        let mut transport = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|value| value.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.state_dir.join("kernel.sqlite"),
                &features,
                cancel,
            ))
            .map_err(|_| PublicDecisionError::Transport)?;
        if client.origin() != self.config.origin {
            return Err(PublicDecisionError::Identity);
        }
        Ok((runtime, client))
    }

    fn pin_local(&self) -> Result<(), PublicDecisionError> {
        let store = SecureStateStore::open(&self.config.state_dir.join("recipient-pins.state"))?;
        match store.read_exact()? {
            Some(wire) => {
                let saved: PublicDecisionConfig =
                    serde_json::from_slice(&wire).map_err(|_| PublicDecisionError::Identity)?;
                if saved != self.config {
                    return Err(PublicDecisionError::Identity);
                }
            }
            None => {
                // This first-contact owner is an explicit caller trust pin.
                // A signed offer/control read still gates any decision.
                let wire =
                    serde_json::to_vec(&self.config).map_err(|_| PublicDecisionError::Encoding)?;
                store.write_exact(&wire)?;
            }
        }
        Ok(())
    }
}

/// Select the last checkpoint at which the invitation policy was current.
/// These bytes are only grant-verifier input until the complete, origin-bound
/// replay proves the checkpoint is its ancestor.
fn historical_grant_prefix(
    policies: &[Vec<u8>],
    commits: &[Vec<u8>],
    policy_wire: &[u8],
    policy_hash: &str,
    workspace_id: &str,
    owner_id: &str,
    owner_key: &str,
) -> Result<(usize, usize, Vec<u8>), PublicDecisionError> {
    let index = policies
        .iter()
        .position(|wire| wire == policy_wire && sha256_hex(wire) == policy_hash)
        .ok_or(PublicDecisionError::Grant)?;
    let count = index + 1;
    let commit_count = if let Some(next) = policies.get(count) {
        let value = parse_wire_json_js_bounded(next, 64, 256 * 1024)
            .map_err(|_| PublicDecisionError::Grant)?;
        let effective = value
            .get("payload")
            .and_then(|p| p.get("effective_sequence"))
            .and_then(WireValue::as_number)
            .filter(|n| n.fract() == 0.0 && *n >= 1.0 && *n <= 9_007_199_254_740_991.0)
            .ok_or(PublicDecisionError::Grant)? as u64;
        usize::try_from(effective - 1).map_err(|_| PublicDecisionError::Grant)?
    } else {
        commits.len()
    };
    if commit_count > commits.len() {
        return Err(PublicDecisionError::Grant);
    }
    let head = commit_count.checked_sub(1).map(|i| sha256_hex(&commits[i]));
    let checkpoint = serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "workspace_id": workspace_id,
        "owner_id": owner_id,
        "owner_key": owner_key,
        "sequence": commit_count,
        "head": head,
        "policy_hash": policy_hash,
    }))
    .map_err(|_| PublicDecisionError::Encoding)?;
    Ok((count, commit_count, checkpoint))
}

fn control_path(invite_id: &str) -> Result<String, PublicDecisionError> {
    if invite_id.len() != 43
        || !invite_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(PublicDecisionError::Invalid);
    }
    Ok(format!("/api/workspace/v1/secure/invitations/{invite_id}"))
}
fn decision_path(invite_id: &str) -> String {
    format!("/api/workspace/v1/secure/invitations/{invite_id}/decision")
}
fn now_ms() -> Result<u64, PublicDecisionError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PublicDecisionError::Clock)?
        .as_millis();
    u64::try_from(ms).map_err(|_| PublicDecisionError::Clock)
}
