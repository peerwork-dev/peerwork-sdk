//! Explicit protected Owner format transitions. A saved encrypted packet is
//! discoverable before POST; only complete signed replay marks it ACCEPTED.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_lifecycle::SecureLifecycle,
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::{SecureStateError, SecureStateStore},
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    crypto::{base64url, decode_base64url},
    prepared_owner_format::{
        prepare_owner_private_format_transition, verify_saved_owner_private_format_transition,
        OwnerFormatPrepareError, OwnerFormatTransitionKind,
    },
    replayed_secure_journal::{replay_secure_journal_exact, JournalReplayInput, StructureStatus},
    wire_json::WireValue,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

const MAX_ROWS: usize = 128;
const MAX_DOCUMENT: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwnerFormatTransition {
    #[serde(rename = "UPGRADE_WIRE_V3")]
    UpgradeWireV3,
    #[serde(rename = "RAISE_PRIVATE_CEILING_TWO")]
    RaisePrivateCeilingTwo,
}
impl OwnerFormatTransition {
    fn kind(self) -> OwnerFormatTransitionKind {
        match self {
            Self::UpgradeWireV3 => OwnerFormatTransitionKind::UpgradeWireV3,
            Self::RaisePrivateCeilingTwo => OwnerFormatTransitionKind::RaisePrivateCeilingTwo,
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::UpgradeWireV3 => "secure.protocol-format.upgrade",
            Self::RaisePrivateCeilingTwo => "secure.protocol-format.raise",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFormatTransitionInput {
    pub workspace_id: String,
    pub transition: OwnerFormatTransition,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFormatTransitionResult {
    pub command_id: String,
    pub workspace_id: String,
    pub transition: OwnerFormatTransition,
    pub status: String,
    pub sequence: Option<u64>,
    pub policy_hash: Option<String>,
}

#[derive(Debug, Error)]
pub enum OwnerFormatTransitionError {
    #[error("format transition input or source state is invalid")]
    Input,
    #[error("protected Owner identity or source pins changed")]
    Identity,
    #[error("format transition requires complete signed Owner replay")]
    Verification,
    #[error("format transition conflicts with another saved operation")]
    Conflict,
    #[error("saved format transition was not found")]
    NotFound,
    #[error("format transition feature is unavailable")]
    FeatureUnavailable,
    #[error("protected format transition state failed")]
    Local,
    #[error("saved format transition packet failed exact reproof")]
    Packet,
    #[error("format transition transport failed")]
    Transport,
    #[error("format transition was cancelled; recover by ID or history")]
    Cancelled,
    #[error("server rejected format transition with HTTP {0}")]
    ServerRejected(u16),
}
impl OwnerFormatTransitionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input => "INPUT_INVALID",
            Self::Identity => "IDENTITY_CHANGED",
            Self::Verification => "VERIFICATION_FAILED",
            Self::Conflict => "TRANSITION_CONFLICT",
            Self::NotFound => "NOT_FOUND",
            Self::FeatureUnavailable => "FEATURE_UNAVAILABLE",
            Self::Local => "LOCAL_STATE_FAILED",
            Self::Packet => "PACKET_INVALID",
            Self::Transport => "TRANSPORT_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::ServerRejected(_) => "SERVER_REJECTED",
        }
    }
}
impl From<SecureReadAccessError> for OwnerFormatTransitionError {
    fn from(error: SecureReadAccessError) -> Self {
        if matches!(error, SecureReadAccessError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Verification
        }
    }
}
impl From<SecureStateError> for OwnerFormatTransitionError {
    fn from(_: SecureStateError) -> Self {
        Self::Local
    }
}
impl From<SecureIntentError> for OwnerFormatTransitionError {
    fn from(_: SecureIntentError) -> Self {
        Self::Packet
    }
}
impl From<OwnerFormatPrepareError> for OwnerFormatTransitionError {
    fn from(_: OwnerFormatPrepareError) -> Self {
        Self::Packet
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedTransition {
    transition: OwnerFormatTransition,
    issued_at_ms: u64,
    source_sequence: u64,
    source_head: String,
    source_policy_hash: String,
    request_b64: String,
    commit_hash: String,
    next_policy_hash: String,
    accepted_sequence: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionHistory {
    version: u8,
    origin: String,
    workspace_id: String,
    actor_id: String,
    owner_key_id: String,
    rows: BTreeMap<String, SavedTransition>,
}
impl TransitionHistory {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        identity: &KernelIdentity,
    ) -> Result<Self, OwnerFormatTransitionError> {
        let document = if let Some(bytes) = store.read_exact()? {
            if bytes.len() > MAX_DOCUMENT {
                return Err(OwnerFormatTransitionError::Local);
            }
            serde_json::from_slice::<Self>(&bytes).map_err(|_| OwnerFormatTransitionError::Local)?
        } else {
            Self {
                version: 1,
                origin: config.origin.clone(),
                workspace_id: config.workspace_id.clone(),
                actor_id: identity.actor_id().into(),
                owner_key_id: identity.key_id().into(),
                rows: BTreeMap::new(),
            }
        };
        if document.version != 1
            || document.origin != config.origin
            || document.workspace_id != config.workspace_id
            || document.actor_id != identity.actor_id()
            || document.owner_key_id != identity.key_id()
            || document.rows.len() > MAX_ROWS
            || document.rows.iter().any(|(id, row)| {
                !token(id)
                    || !digest(&row.source_head)
                    || !digest(&row.source_policy_hash)
                    || !digest(&row.commit_hash)
                    || !digest(&row.next_policy_hash)
                    || row.source_sequence == 0
                    || row.issued_at_ms > 9_007_199_254_740_991
                    || row
                        .accepted_sequence
                        .is_some_and(|n| n != row.source_sequence + 1)
                    || decode_base64url(&row.request_b64).is_err()
            })
        {
            return Err(OwnerFormatTransitionError::Local);
        }
        Ok(document)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), OwnerFormatTransitionError> {
        let bytes = serde_json::to_vec(self).map_err(|_| OwnerFormatTransitionError::Local)?;
        if bytes.len() > MAX_DOCUMENT {
            return Err(OwnerFormatTransitionError::Local);
        }
        store.write_exact(&bytes)?;
        Ok(())
    }
}
fn token(v: &str) -> bool {
    v.len() == 43
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn random_id() -> Result<String, OwnerFormatTransitionError> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| OwnerFormatTransitionError::Local)?;
    Ok(base64url(&bytes))
}
fn now_ms() -> Result<u64, OwnerFormatTransitionError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OwnerFormatTransitionError::Input)?
            .as_millis(),
    )
    .map_err(|_| OwnerFormatTransitionError::Input)
}
fn number(value: &WireValue, key: &str) -> Result<u64, OwnerFormatTransitionError> {
    let n = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(OwnerFormatTransitionError::Verification)?;
    if !n.is_finite() || n < 0.0 || n > 9_007_199_254_740_991.0 || n.fract() != 0.0 {
        return Err(OwnerFormatTransitionError::Verification);
    }
    Ok(n as u64)
}
fn result(
    id: &str,
    config: &SecureReadProfileConfig,
    row: &SavedTransition,
) -> OwnerFormatTransitionResult {
    OwnerFormatTransitionResult {
        command_id: id.into(),
        workspace_id: config.workspace_id.clone(),
        transition: row.transition,
        status: if row.accepted_sequence.is_some() {
            "ACCEPTED"
        } else {
            "PENDING"
        }
        .into(),
        sequence: row.accepted_sequence,
        policy_hash: row.accepted_sequence.map(|_| row.next_policy_hash.clone()),
    }
}

/// Reconstruct the exact authenticated source prefix for a saved transition.
/// Latest objects cannot stand in for these after a valid later format-two
/// installation. The full current replay first proves this checkpoint is an
/// ancestor; this second replay authenticates its historical object set.
fn source_objects_at_saved(
    source: &crate::secure_verified_read::TransportReplayedJournal,
    lifecycle: &SecureLifecycle,
    row: &SavedTransition,
    checkpoint_wire: &[u8],
) -> Result<Vec<WireValue>, OwnerFormatTransitionError> {
    let through = usize::try_from(row.source_sequence)
        .map_err(|_| OwnerFormatTransitionError::Verification)?;
    let commits = source.signed_commit_wires();
    if commits.len() < through {
        return Err(OwnerFormatTransitionError::Verification);
    }
    let commit_refs: Vec<&[u8]> = commits[..through].iter().map(Vec::as_slice).collect();
    let mut policy_refs = Vec::new();
    for wire in source.signed_policy_wires() {
        let signed = peerwork_core::wire_json::parse_wire_json_bounded(wire, 64, 196_608)
            .map_err(|_| OwnerFormatTransitionError::Verification)?;
        let payload = signed
            .get("payload")
            .ok_or(OwnerFormatTransitionError::Verification)?;
        if number(payload, "effective_sequence")? <= row.source_sequence {
            policy_refs.push(wire.as_slice());
        }
    }
    let ring = lifecycle
        .active_keyring_without_pending()
        .ok_or(OwnerFormatTransitionError::Conflict)?;
    let ring_wire = ring
        .canonical_wire()
        .map_err(|_| OwnerFormatTransitionError::Identity)?;
    let replay = replay_secure_journal_exact(JournalReplayInput {
        policy_wires: &policy_refs,
        commit_wires: &commit_refs,
        checkpoint_wire,
        workspace_id: source.replay().workspace_id(),
        owner_actor_id: source.replay().owner_actor_id(),
        owner_signing_key: source.replay().owner_signing_key(),
        final_sequence: row.source_sequence,
        final_head: Some(&row.source_head),
        final_policy_hash: &row.source_policy_hash,
        keyring_wire: Some(&ring_wire),
    })
    .map_err(|_| OwnerFormatTransitionError::Verification)?;
    Ok(replay.objects().to_vec())
}

pub struct SecureOwnerFormatTransition {
    config: SecureReadProfileConfig,
}
impl SecureOwnerFormatTransition {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }
    fn history_path(&self) -> std::path::PathBuf {
        self.config.state_dir.join("owner-format.state")
    }
    fn journal_path(&self) -> std::path::PathBuf {
        self.config.state_dir.join("owner-format-intents.state")
    }
    fn transport(&self) -> Result<HttpTransport, OwnerFormatTransitionError> {
        let mut c = TransportConfig::new(self.config.origin.clone());
        c.allow_loopback_http = self.config.allow_loopback_http;
        HttpTransport::new(c).map_err(|_| OwnerFormatTransitionError::Transport)
    }
    fn path(&self) -> String {
        format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            self.config.workspace_id
        )
    }

    fn require_feature(
        &self,
        transition: OwnerFormatTransition,
        cancel: &CancellationToken,
    ) -> Result<(), OwnerFormatTransitionError> {
        let transport = self.transport()?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| OwnerFormatTransitionError::Transport)?;
        let response =
            runtime
                .block_on(transport.discovery(cancel))
                .map_err(|error| match error {
                    TransportError::Cancelled => OwnerFormatTransitionError::Cancelled,
                    _ => OwnerFormatTransitionError::Transport,
                })?;
        if !(200..300).contains(&response.status) {
            return Err(OwnerFormatTransitionError::Transport);
        }
        let value: serde_json::Value = serde_json::from_slice(&response.wire)
            .map_err(|_| OwnerFormatTransitionError::Transport)?;
        let required = match transition {
            OwnerFormatTransition::UpgradeWireV3 => "signed-protocol-format-v3",
            OwnerFormatTransition::RaisePrivateCeilingTwo => "signed-protocol-format2-v1",
        };
        if !value["protocol_features"]
            .as_array()
            .is_some_and(|features| {
                features
                    .iter()
                    .any(|feature| feature.as_str() == Some(required))
            })
        {
            return Err(OwnerFormatTransitionError::FeatureUnavailable);
        }
        Ok(())
    }

    pub fn history_json(&self) -> Result<String, OwnerFormatTransitionError> {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| OwnerFormatTransitionError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())?;
        let doc = TransitionHistory::open(&store, &self.config, &identity)?;
        let rows: Vec<_> = doc
            .rows
            .iter()
            .map(|(id, row)| result(id, &self.config, row))
            .collect();
        serde_json::to_string(&rows).map_err(|_| OwnerFormatTransitionError::Local)
    }

    pub fn submit_json_with_cancel(
        &self,
        input: OwnerFormatTransitionInput,
        cancel: &CancellationToken,
    ) -> Result<String, OwnerFormatTransitionError> {
        if input.workspace_id != self.config.workspace_id
            || !token(&input.workspace_id)
            || input.command_id.as_deref().is_some_and(|id| !token(id))
        {
            return Err(OwnerFormatTransitionError::Input);
        }
        let id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        self.require_feature(input.transition, cancel)?;
        let selected =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                source
                    .verified_read()
                    .map_err(|_| OwnerFormatTransitionError::Verification)?;
                let identity = KernelIdentity::open(&self.config.identity_path)
                    .map_err(|_| OwnerFormatTransitionError::Identity)?;
                if source.origin() != self.config.origin
                    || source.source_actor_id() != identity.actor_id()
                    || source.source_key_id() != identity.key_id()
                    || source.replay().workspace_id() != self.config.workspace_id
                    || source.replay().owner_actor_id() != identity.actor_id()
                    || source.replay().owner_signing_key() != identity.key_id()
                    || source.replay().structure_status() == StructureStatus::Seeding
                {
                    return Err(OwnerFormatTransitionError::Identity);
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    source.replay().workspace_id(),
                    source.replay().owner_actor_id(),
                    source.replay().owner_signing_key(),
                )
                .map_err(|_| OwnerFormatTransitionError::Identity)?;
                if lifecycle.active_keyring_without_pending().is_none() {
                    return Err(OwnerFormatTransitionError::Conflict);
                }
                let policy_wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(OwnerFormatTransitionError::Verification)?;
                let policy: WireValue =
                    peerwork_core::wire_json::parse_wire_json_bounded(policy_wire, 64, 196_608)
                        .map_err(|_| OwnerFormatTransitionError::Verification)?;
                let epoch = number(
                    policy
                        .get("payload")
                        .ok_or(OwnerFormatTransitionError::Verification)?,
                    "epoch",
                )?;
                let key = lifecycle
                    .active_key(epoch)
                    .ok_or(OwnerFormatTransitionError::Identity)?;
                let prepared = prepare_owner_private_format_transition(
                    input.transition.kind(),
                    policy_wire,
                    source.checkpoint_canonical_json().as_bytes(),
                    source.replay().objects(),
                    key,
                    identity.signing_key(),
                    &id,
                    issued,
                )?;
                let store = SecureStateStore::open(&self.history_path())?;
                let mut doc = TransitionHistory::open(&store, &self.config, &identity)?;
                if doc.rows.len() >= MAX_ROWS
                    || doc.rows.contains_key(&id)
                    || doc.rows.values().any(|row| row.accepted_sequence.is_none())
                {
                    return Err(OwnerFormatTransitionError::Conflict);
                }
                let row = SavedTransition {
                    transition: input.transition,
                    issued_at_ms: issued,
                    source_sequence: source.replay().sequence(),
                    source_head: source.replay().head().unwrap_or("").into(),
                    source_policy_hash: source.replay().policy_hash().into(),
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().into(),
                    next_policy_hash: prepared.policy_hash().into(),
                    accepted_sequence: None,
                };
                doc.rows.insert(id.clone(), row.clone());
                doc.save(&store)?;
                let mut journal = SecureIntentJournal::open(
                    &self.journal_path(),
                    source.origin(),
                    identity.actor_id(),
                )?;
                journal.prepare(SecurePacketInput {
                    intent_id: &id,
                    path: &self.path(),
                    action_id: input.transition.action(),
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                })?;
                if journal.exact_request(&id)? != prepared.request_wire() {
                    return Err(OwnerFormatTransitionError::Packet);
                }
                self.post(&mut journal, &id, prepared.request_wire().to_vec(), cancel)?;
                Ok(result(&id, &self.config, &row))
            })?;
        serde_json::to_string(&selected).map_err(|_| OwnerFormatTransitionError::Local)
    }

    fn post(
        &self,
        journal: &mut SecureIntentJournal,
        id: &str,
        packet: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<(), OwnerFormatTransitionError> {
        let transport = self.transport()?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| OwnerFormatTransitionError::Transport)?;
        match runtime.block_on(transport.post_exact(&self.path(), packet, cancel)) {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(OwnerFormatTransitionError::ServerRejected(response.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => (),
            Err(TransportError::Cancelled) => return Err(OwnerFormatTransitionError::Cancelled),
            Err(_) => return Err(OwnerFormatTransitionError::Transport),
        }
        Ok(())
    }

    pub fn resume_json_with_cancel(
        &self,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, OwnerFormatTransitionError> {
        if !token(id) {
            return Err(OwnerFormatTransitionError::Input);
        }
        let selected=SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel,|source| {
            source.verified_read().map_err(|_| OwnerFormatTransitionError::Verification)?;
            let identity=KernelIdentity::open(&self.config.identity_path).map_err(|_| OwnerFormatTransitionError::Identity)?;
            if source.origin()!=self.config.origin || source.source_actor_id()!=identity.actor_id()
                || source.source_key_id()!=identity.key_id() || source.replay().owner_actor_id()!=identity.actor_id()
                || source.replay().owner_signing_key()!=identity.key_id()
            { return Err(OwnerFormatTransitionError::Identity); }
            let store=SecureStateStore::open(&self.history_path())?;
            let mut doc=TransitionHistory::open(&store,&self.config,&identity)?;
            let row=doc.rows.get(id).cloned().ok_or(OwnerFormatTransitionError::NotFound)?;
            if !source.replay().contains_checkpoint(row.source_sequence,Some(&row.source_head),&row.source_policy_hash)
            { return Err(OwnerFormatTransitionError::Verification); }
            let old_policy=source.signed_policy_by_hash(&row.source_policy_hash).ok_or(OwnerFormatTransitionError::Verification)?;
            let old:WireValue=peerwork_core::wire_json::parse_wire_json_bounded(old_policy,64,196_608)
                .map_err(|_|OwnerFormatTransitionError::Verification)?;
            let epoch=number(old.get("payload").ok_or(OwnerFormatTransitionError::Verification)?,"epoch")?;
            let lifecycle=SecureLifecycle::open(&self.config.state_dir.join("lifecycle.state"),source.origin(),
                identity.actor_id(),source.replay().workspace_id(),source.replay().owner_actor_id(),source.replay().owner_signing_key())
                .map_err(|_|OwnerFormatTransitionError::Identity)?;
            if lifecycle.active_keyring_without_pending().is_none() { return Err(OwnerFormatTransitionError::Conflict); }
            let key=lifecycle.active_key(epoch).ok_or(OwnerFormatTransitionError::Identity)?;
            let checkpoint=serde_json::json!({"v":1,"workspace_id":self.config.workspace_id,
                "owner_id":identity.actor_id(),"owner_key":identity.key_id(),"sequence":row.source_sequence,
                "head":row.source_head,"policy_hash":row.source_policy_hash});
            let checkpoint=peerwork_core::canonical::canonical(&checkpoint,peerwork_core::canonical::Path::SecureArtifact)
                .map_err(|_|OwnerFormatTransitionError::Packet)?;
            let packet=decode_base64url(&row.request_b64).map_err(|_|OwnerFormatTransitionError::Packet)?;
            let historical_objects=source_objects_at_saved(source,&lifecycle,&row,checkpoint.as_bytes())?;
            let proof=verify_saved_owner_private_format_transition(&packet,row.transition.kind(),old_policy,
                checkpoint.as_bytes(),&historical_objects,key,identity.signing_key(),id,row.issued_at_ms)?;
            if proof.commit_hash()!=row.commit_hash || proof.policy_hash()!=row.next_policy_hash
            { return Err(OwnerFormatTransitionError::Packet); }
            let mut journal=SecureIntentJournal::open(&self.journal_path(),source.origin(),identity.actor_id())?;
            journal.prepare(SecurePacketInput { intent_id:id,path:&self.path(),action_id:row.transition.action(),
                workspace_id:Some(&self.config.workspace_id),trusted_owner_key:Some(identity.key_id()),
                intent_digest:&row.commit_hash,exact_request:&packet })?;
            if journal.exact_request(id)?!=packet || journal.intent_digest(id)?!=row.commit_hash
            { return Err(OwnerFormatTransitionError::Packet); }
            if source.replay().contains_checkpoint(row.source_sequence+1,Some(&row.commit_hash),&row.next_policy_hash) {
                let saved=doc.rows.get_mut(id).ok_or(OwnerFormatTransitionError::Local)?;
                saved.accepted_sequence=Some(row.source_sequence+1);
                let accepted=result(id,&self.config,saved);
                doc.save(&store)?;
                return Ok(accepted);
            }
            if row.accepted_sequence.is_some() || source.replay().sequence()!=row.source_sequence
                || source.replay().head()!=Some(row.source_head.as_str())
                || source.replay().policy_hash()!=row.source_policy_hash
            { return Err(OwnerFormatTransitionError::Conflict); }
            self.post(&mut journal,id,packet,cancel)?;
            Ok(result(id,&self.config,&row))
        })?;
        serde_json::to_string(&selected).map_err(|_| OwnerFormatTransitionError::Local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure_action_access::PublicActionInput,
        secure_owner_attach::{HistoricalOwnerAttachInput, SecureHistoricalOwnerAttach},
        secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerWorkspaceCreate},
        secure_private_install::{
            PrivateDirectInstallBeginInput, PrivatePackageInstallBeginInput,
            PrivatePackageStageInput,
        },
        secure_public_admission::PublicOfferInput,
        secure_public_decision::{PublicDecisionConfig, SecurePublicDecision},
        secure_recipient_enrollment::{RecipientEnrollmentConfig, SecureRecipientEnrollment},
    };
    use std::{
        io::{BufRead, BufReader},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_enforced_legacy_private_owner_upgrade_and_raise() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let Ok(legacy_root) = std::env::var("PEERWORK_LEGACY_CLIENT_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .env("PEERWORK_TEST_OWNER_FORMAT", "1")
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
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let source = Command::new(&node)
            .arg(helper)
            .arg(&origin)
            .arg(root.path().join("legacy-owner"))
            .arg(legacy_root)
            .arg("legacy-record")
            .output()
            .unwrap();
        assert!(
            source.status.success(),
            "legacy setup: {}",
            String::from_utf8_lossy(&source.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&source.stdout).unwrap();
        assert_eq!(source["policy_v"], 1);
        let workspace_id = source["workspace_id"].as_str().unwrap().to_owned();
        let config = SecureOwnerCreateConfig {
            origin: origin.clone(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let cancel = CancellationToken::new();
        let attached = SecureHistoricalOwnerAttach::new(config.clone())
            .attach(
                HistoricalOwnerAttachInput {
                    workspace_id: workspace_id.clone(),
                    protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                    protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                    protected_ts_intent_db_path: PathBuf::from(
                        source["intent_db_path"].as_str().unwrap(),
                    ),
                    expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                    expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                },
                &cancel,
            )
            .unwrap();
        assert_eq!(attached.status, "ATTACHED");
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let post = |path: &str| {
            rt.block_on(async {
                reqwest::Client::new()
                    .post(format!("{origin}{path}"))
                    .body("{}")
                    .send()
                    .await
                    .unwrap()
            })
        };
        let activated = post("__test/activate-protocol-cutover");
        assert_eq!(activated.status(), 200);
        let activated: serde_json::Value =
            serde_json::from_slice(&rt.block_on(activated.bytes()).unwrap()).unwrap();
        assert_eq!(activated["phase"], "ENFORCE");
        let counts = || {
            rt.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        let before = counts()["commits"].as_u64().unwrap();
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let access = owner
            .private_format_transition_access(&workspace_id)
            .unwrap();
        assert_eq!(post("__test/drop-next-post").status(), 200);
        let first: serde_json::Value = serde_json::from_str(
            &access
                .submit_json_with_cancel(
                    OwnerFormatTransitionInput {
                        workspace_id: workspace_id.clone(),
                        transition: OwnerFormatTransition::UpgradeWireV3,
                        command_id: None,
                        issued_at_ms: None,
                    },
                    &cancel,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["status"], "PENDING");
        assert_eq!(counts()["commits"], before + 1);
        let id = first["command_id"].as_str().unwrap();
        let fresh = SecureOwnerWorkspaceCreate::new(config.clone())
            .private_format_transition_access(&workspace_id)
            .unwrap();
        let history: serde_json::Value =
            serde_json::from_str(&fresh.history_json().unwrap()).unwrap();
        assert_eq!(history[0]["command_id"], id);
        let advanced: serde_json::Value =
            serde_json::from_str(&fresh.resume_json_with_cancel(id, &cancel).unwrap()).unwrap();
        assert_eq!(advanced["status"], "ACCEPTED");
        let (policy, policy_hash, sequence): (serde_json::Value, String, u64) =
            SecureReadProfile::new(fresh.config.clone())
                .with_latest_replay(&cancel, |replay| {
                    let hash = replay.replay().policy_hash();
                    let wire = replay
                        .signed_policy_by_hash(hash)
                        .ok_or(OwnerFormatTransitionError::Verification)?;
                    let policy = serde_json::from_slice::<serde_json::Value>(wire)
                        .map_err(|_| OwnerFormatTransitionError::Verification)?;
                    Ok::<_, OwnerFormatTransitionError>((
                        policy,
                        hash.to_owned(),
                        replay.replay().sequence(),
                    ))
                })
                .unwrap();
        assert_eq!(policy["payload"]["v"], 3);
        assert_eq!(policy["payload"]["protocol_format_ceiling"], 1);
        assert_eq!(policy_hash, advanced["policy_hash"].as_str().unwrap());
        assert_eq!(sequence, advanced["sequence"].as_u64().unwrap());
        let read: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &cancel).unwrap())
                .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "records"
                && row["id"] == source["prior_record_id"]
                && row["value"]["payload"]["title"] == "Legacy encrypted record"
                && row["value"]["payload"]["body"] == "Old wire-v1 encrypted body"));
        let again: serde_json::Value =
            serde_json::from_str(&fresh.resume_json_with_cancel(id, &cancel).unwrap()).unwrap();
        assert_eq!(again["status"], "ACCEPTED");
        assert_eq!(counts()["commits"], before + 1);

        // The pinned client requires a STRUCTURED ACTIVE policy before
        // format-two staging. A format-one DIRECT install is the native path
        // from the genuine v1 workspace's upgraded v3/NONE policy.
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let install = owner.private_install_access(&workspace_id).unwrap();
        let begin:serde_json::Value=serde_json::from_str(&install.submit_direct_begin_json(PrivateDirectInstallBeginInput{
            closure_json:vector["closure"].to_string(),
            expected_root_package_digest:vector["closure"]["root_package_digest"].as_str().unwrap().into(),
            expected_protocol_digest:vector["protocol_digest"].as_str().unwrap().into(),
            instance_id:random_id().unwrap(),entrypoint:"proposal".into(),
            grants_json:serde_json::json!([{"actor_id":source["owner_actor_id"],
                "actions":["proposal.propose"],"protocol_roles":["AUTHOR"],"capabilities":["PROPOSE"]}]).to_string(),
            command_id:None,issued_at_ms:None}).unwrap()).unwrap();
        let begin_id = begin["begin_command_id"].as_str().unwrap();
        let mut step: serde_json::Value =
            serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
        for _ in 0..8 {
            if step["status"] == "ACCEPTED" {
                break;
            }
            step = serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
        }
        assert_eq!(step["status"], "ACCEPTED");
        let structured: serde_json::Value = SecureReadProfile::new(fresh.config.clone())
            .with_latest_replay(&cancel, |replay| {
                let wire = replay
                    .signed_policy_by_hash(replay.replay().policy_hash())
                    .ok_or(OwnerFormatTransitionError::Verification)?;
                serde_json::from_slice(wire).map_err(|_| OwnerFormatTransitionError::Verification)
            })
            .unwrap();
        assert_eq!(structured["payload"]["v"], 3);
        assert_eq!(structured["payload"]["structure_mode"], "STRUCTURED");
        assert_eq!(structured["payload"]["protocol_format_ceiling"], 1);
        let before_raise = counts()["commits"].as_u64().unwrap();
        assert_eq!(post("__test/drop-next-post").status(), 200);
        let raise: serde_json::Value = serde_json::from_str(
            &fresh
                .submit_json_with_cancel(
                    OwnerFormatTransitionInput {
                        workspace_id: workspace_id.clone(),
                        transition: OwnerFormatTransition::RaisePrivateCeilingTwo,
                        command_id: None,
                        issued_at_ms: None,
                    },
                    &cancel,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raise["status"], "PENDING");
        assert_eq!(counts()["commits"], before_raise + 1);
        let raise_id = raise["command_id"].as_str().unwrap();
        let raised: serde_json::Value =
            serde_json::from_str(&fresh.resume_json_with_cancel(raise_id, &cancel).unwrap())
                .unwrap();
        assert_eq!(raised["status"], "ACCEPTED");
        let raised_policy: serde_json::Value = SecureReadProfile::new(fresh.config.clone())
            .with_latest_replay(&cancel, |replay| {
                let wire = replay
                    .signed_policy_by_hash(replay.replay().policy_hash())
                    .ok_or(OwnerFormatTransitionError::Verification)?;
                serde_json::from_slice(wire).map_err(|_| OwnerFormatTransitionError::Verification)
            })
            .unwrap();
        assert_eq!(raised_policy["payload"]["v"], 3);
        assert_eq!(raised_policy["payload"]["structure_mode"], "STRUCTURED");
        assert_eq!(raised_policy["payload"]["protocol_format_ceiling"], 2);
        assert_eq!(counts()["commits"], before_raise + 1);

        // The raw package material comes from the pinned format-two source
        // fixture. Native staging compiles and authenticates both source parts.
        let material_helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/format-two-material.mjs");
        let built = Command::new(&node)
            .arg(material_helper)
            .arg(std::env::var("PEERWORK_REFERENCE_ROOT").unwrap())
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "typed material: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        let typed: serde_json::Value = serde_json::from_slice(&built.stdout).unwrap();
        assert_eq!(
            typed["material"]["closure"]["packages"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        let stage = owner.private_install_access(&workspace_id).unwrap();
        let before_stage = counts()["commits"].as_u64().unwrap();
        let mut staged: serde_json::Value = serde_json::from_str(
            &stage
                .stage_package_json(PrivatePackageStageInput {
                    material_json: typed["material"].to_string(),
                    expected_root_package_digest: typed["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: typed["protocol_digest"].as_str().unwrap().into(),
                    stage_id: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let stage_id = staged["stage_id"].as_str().unwrap().to_owned();
        let part_count = staged["part_count"].as_u64().unwrap();
        assert!(part_count >= 1);
        for _ in 0..4 {
            if staged["status"] == "STAGED" {
                break;
            }
            staged = serde_json::from_str(&stage.continue_stage_json(&stage_id).unwrap()).unwrap();
        }
        assert_eq!(staged["status"], "STAGED");
        assert_eq!(staged["applied_parts"], part_count);
        assert_eq!(counts()["commits"], before_stage + part_count);
        let typed_instance = random_id().unwrap();
        let mut installed: serde_json::Value = serde_json::from_str(
            &stage
                .submit_begin_json(PrivatePackageInstallBeginInput {
                    stage_id,
                    instance_id: typed_instance.clone(),
                    entrypoint: "typedPackage".into(),
                    grants_json: serde_json::json!([{
                        "actor_id":source["owner_actor_id"],
                        "actions":["lib.replace","lib.produce"],
                        "protocol_roles":[],"capabilities":[]
                    }])
                    .to_string(),
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let typed_begin_id = installed["begin_command_id"].as_str().unwrap().to_owned();
        for _ in 0..12 {
            if installed["status"] == "ACCEPTED" {
                break;
            }
            installed =
                serde_json::from_str(&stage.continue_install_json(&typed_begin_id).unwrap())
                    .unwrap();
        }
        assert_eq!(installed["status"], "ACCEPTED");
        assert_eq!(installed["protocol_digest"], typed["protocol_digest"]);
        assert_eq!(installed["instance_id"], typed_instance);
        let after_typed = counts()["commits"].as_u64().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &fresh.resume_json_with_cancel(id, &cancel).unwrap()
            )
            .unwrap()["status"],
            "ACCEPTED"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &fresh.resume_json_with_cancel(raise_id, &cancel).unwrap()
            )
            .unwrap()["status"],
            "ACCEPTED"
        );
        assert_eq!(counts()["commits"], after_typed);

        let installed_read: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &cancel).unwrap())
                .unwrap();
        let objects = installed_read["objects"].as_array().unwrap();
        assert!(objects.iter().any(|object| {
            object["kind"] == "protocols"
                && object["id"] == typed["protocol_digest"]
                && object["value"]["manifest"]["format_version"] == 2
                && object["value"]["package_source"]["root_package_digest"]
                    == typed["root_package_digest"]
        }));
        assert!(objects.iter().any(|object| {
            object["kind"] == "instances"
                && object["id"] == typed_instance
                && object["value"]["protocol_digest"] == typed["protocol_digest"]
                && object["value"]["package_source"]["root_package_digest"]
                    == typed["root_package_digest"]
        }));

        let action = owner.private_action_access(&workspace_id).unwrap();
        let replace: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "lib.replace".into(),
                    instance_id: typed_instance.clone(),
                    body_json: r#"{"value":[{"label":"native typed data"},true]}"#.into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let replaced: serde_json::Value = serde_json::from_str(
            &action
                .retry_saved_json(replace["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replaced["status"], "ACCEPTED");
        let after_replace: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &cancel).unwrap())
                .unwrap();
        let instance = after_replace["objects"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|object| object["kind"] == "instances" && object["id"] == typed_instance)
            .unwrap();
        assert_eq!(
            instance["value"]["state"]["lib"]["data"],
            serde_json::json!([{"label":"native typed data"}, true])
        );

        let produce: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "lib.produce".into(),
                    instance_id: typed_instance.clone(),
                    body_json: "{}".into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let produced: serde_json::Value = serde_json::from_str(
            &action
                .retry_saved_json(produce["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(produced["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(produced["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let produced_id = receipt["effects"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|effect| effect["record_id"].as_str())
            .unwrap();
        let after_produce: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &cancel).unwrap())
                .unwrap();
        let objects = after_produce["objects"].as_array().unwrap();
        assert!(objects.iter().any(|object| {
            object["kind"] == "records"
                && object["id"] == produced_id
                && object["value"]["payload"]["label"] == "private typed record"
        }));
        let instance = objects
            .iter()
            .rev()
            .find(|object| object["kind"] == "instances" && object["id"] == typed_instance)
            .unwrap();
        assert_eq!(
            instance["value"]["state"]["lib"]["refs"],
            serde_json::json!([{"record_id":produced_id,"revision":1}])
        );

        // Admit a separate native identity to consume the exact reference.
        let member_dir = root.path().join("native-member");
        let mut enrollment_config =
            RecipientEnrollmentConfig::for_state_dir(origin.clone(), &member_dir);
        enrollment_config.allow_loopback_http = true;
        let enrollment = SecureRecipientEnrollment::new(enrollment_config);
        let member = enrollment.create_local().unwrap();
        assert_eq!(enrollment.publish().unwrap().status, "PUBLISHED");
        let admission = owner.private_admission_access(&workspace_id).unwrap();
        let offer: serde_json::Value = serde_json::from_str(
            &admission
                .submit_offer_json_with_cancel(
                    PublicOfferInput {
                        recipient_certificate_json: enrollment.certificate_json().unwrap(),
                        scopes_json: serde_json::json!([{
                            "instance_id":typed_instance,
                            "actions":["lib.consume"],
                            "protocol_roles":[],"capabilities":[]
                        }])
                        .to_string(),
                        message: "Native format-two exact-ref member".into(),
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
        let invite_id = offer["invite_id"].as_str().unwrap();
        let decision = SecurePublicDecision::new(PublicDecisionConfig {
            origin: origin.clone(),
            state_dir: member_dir.clone(),
            identity_path: member_dir.join("identity.state"),
            workspace_id: workspace_id.clone(),
            owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
            owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
            authority: peerwork_core::crypto::sha256_hex(member.actor_id.as_bytes()),
            allow_loopback_http: true,
            required_features: vec![],
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        let decided: serde_json::Value =
            serde_json::from_str(&decision.decide_json(invite_id, "ACCEPT").unwrap()).unwrap();
        assert_eq!(decided["invite_id"], invite_id);
        let delivered: serde_json::Value = serde_json::from_str(
            &admission
                .deliver_accepted_json_with_cancel(invite_id, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            delivered["status"].as_str(),
            Some("PENDING" | "AUTHORIZED")
        ));
        if delivered["status"] == "PENDING" {
            let recovered: serde_json::Value = serde_json::from_str(
                &admission
                    .retry_delivery_json_with_cancel(
                        delivered["grant_id"].as_str().unwrap(),
                        &cancel,
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(recovered["status"], "AUTHORIZED");
        }
        let mut received: serde_json::Value =
            serde_json::from_str(&decision.receive_json(invite_id).unwrap()).unwrap();
        assert_eq!(received["status"], "PENDING");
        let receipt_hash = received["receipt_hash"].clone();
        let before_receipt_retry = counts()["commits"].as_u64().unwrap();
        for _ in 0..4 {
            if received["status"] == "READY" {
                break;
            }
            assert_eq!(received["status"], "PENDING");
            // The receipt POST and signed control projection are separate
            // service steps; keep the same saved ID and wait briefly for the
            // control observation, with an explicit four-attempt bound.
            std::thread::sleep(std::time::Duration::from_millis(150));
            received =
                serde_json::from_str(&decision.retry_receive_json(invite_id).unwrap()).unwrap();
            assert_eq!(received["receipt_hash"], receipt_hash);
        }
        assert_eq!(received["status"], "READY");
        assert_eq!(counts()["commits"], before_receipt_retry);
        let member_profile = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: member_dir.clone(),
            identity_path: member_dir.join("identity.state"),
            workspace_id: workspace_id.clone(),
            owner_actor_id: Some(source["owner_actor_id"].as_str().unwrap().into()),
            owner_key_id: Some(source["owner_key_id"].as_str().unwrap().into()),
            authority: Some(peerwork_core::crypto::sha256_hex(
                member.actor_id.as_bytes(),
            )),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let before_consume = counts()["commits"].as_u64().unwrap();
        let member_action =
            crate::secure_action_access::SecurePrivateActionAccess::new(member_profile.clone());
        let consume: serde_json::Value = serde_json::from_str(
            &member_action
                .submit_new_json(PublicActionInput {
                    action_id: "lib.consume".into(),
                    instance_id: typed_instance.clone(),
                    body_json: "{}".into(),
                    exact_input_refs_json: Some(
                        serde_json::json!([{"record_id":produced_id,"revision":1}]).to_string(),
                    ),
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let consumed: serde_json::Value = serde_json::from_str(
            &member_action
                .retry_saved_json(consume["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(consumed["status"], "ACCEPTED");
        assert_eq!(counts()["commits"], before_consume + 1);
        let consume_receipt: serde_json::Value =
            serde_json::from_str(consumed["receipt_canonical_json"].as_str().unwrap()).unwrap();
        assert_eq!(consume_receipt["actor_id"], member.actor_id);
        let duplicate: serde_json::Value = serde_json::from_str(
            &member_action
                .retry_saved_json(consume["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(duplicate["status"], "ACCEPTED");
        assert_eq!(counts()["commits"], before_consume + 1);
        let member_read: serde_json::Value = serde_json::from_str(
            &SecureReadProfile::new(member_profile)
                .read_latest_json()
                .unwrap(),
        )
        .unwrap();
        assert!(member_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "records"
                    && object["id"] == source["prior_record_id"]
                    && object["value"]["payload"]["title"] == "Legacy encrypted record"
                    && object["value"]["payload"]["body"] == "Old wire-v1 encrypted body"
            }));
        let member_instance = member_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|object| object["kind"] == "instances" && object["id"] == typed_instance)
            .unwrap();
        assert_eq!(
            member_instance["value"]["state"]["lib"]["refs"],
            serde_json::json!([{"record_id":produced_id,"revision":1}])
        );
    }
    #[test]
    fn actual_service_enforced_legacy_structured_v2_upgrade() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let Ok(legacy_root) = std::env::var("PEERWORK_LEGACY_CLIENT_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .env("PEERWORK_TEST_OWNER_FORMAT", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopV2(Child);
        impl Drop for StopV2 {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopV2(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let source = Command::new(&node)
            .arg(helper)
            .arg(&origin)
            .arg(root.path().join("legacy-owner"))
            .arg(legacy_root)
            .arg("legacy-structured")
            .output()
            .unwrap();
        assert!(
            source.status.success(),
            "legacy v2 setup: {}",
            String::from_utf8_lossy(&source.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&source.stdout).unwrap();
        assert_eq!(source["policy_v"], 2);
        let workspace_id = source["workspace_id"].as_str().unwrap().to_owned();
        let config = SecureOwnerCreateConfig {
            origin: origin.clone(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let cancel = CancellationToken::new();
        let attached = SecureHistoricalOwnerAttach::new(config.clone())
            .attach(
                HistoricalOwnerAttachInput {
                    workspace_id: workspace_id.clone(),
                    protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                    protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                    protected_ts_intent_db_path: PathBuf::from(
                        source["intent_db_path"].as_str().unwrap(),
                    ),
                    expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                    expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                },
                &cancel,
            )
            .unwrap();
        assert_eq!(attached.status, "ATTACHED");
        let owner = SecureOwnerWorkspaceCreate::new(config);
        let access = owner
            .private_format_transition_access(&workspace_id)
            .unwrap();
        let before = SecureReadProfile::new(access.config.clone())
            .with_latest_replay(&cancel, |source| {
                let wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(OwnerFormatTransitionError::Verification)?;
                let policy: serde_json::Value = serde_json::from_slice(wire)
                    .map_err(|_| OwnerFormatTransitionError::Verification)?;
                Ok::<_, OwnerFormatTransitionError>((
                    policy,
                    source.replay().policy_hash().to_owned(),
                    source.replay().sequence(),
                ))
            })
            .unwrap();
        assert_eq!(before.0["payload"]["v"], 2);
        assert!(before.0["payload"]["structure"].is_object());
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let activated = rt
            .block_on(
                reqwest::Client::new()
                    .post(format!("{origin}__test/activate-protocol-cutover"))
                    .body("{}")
                    .send(),
            )
            .unwrap();
        assert_eq!(activated.status(), 200);
        let phase: serde_json::Value =
            serde_json::from_slice(&rt.block_on(activated.bytes()).unwrap()).unwrap();
        assert_eq!(phase["phase"], "ENFORCE");
        let result: serde_json::Value = serde_json::from_str(
            &access
                .submit_json_with_cancel(
                    OwnerFormatTransitionInput {
                        workspace_id: workspace_id.clone(),
                        transition: OwnerFormatTransition::UpgradeWireV3,
                        command_id: None,
                        issued_at_ms: None,
                    },
                    &cancel,
                )
                .unwrap(),
        )
        .unwrap();
        let id = result["command_id"].as_str().unwrap();
        let accepted: serde_json::Value =
            serde_json::from_str(&access.resume_json_with_cancel(id, &cancel).unwrap()).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let after = SecureReadProfile::new(access.config.clone())
            .with_latest_replay(&cancel, |source| {
                let wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(OwnerFormatTransitionError::Verification)?;
                let policy: serde_json::Value = serde_json::from_slice(wire)
                    .map_err(|_| OwnerFormatTransitionError::Verification)?;
                Ok::<_, OwnerFormatTransitionError>((
                    policy,
                    source.replay().policy_hash().to_owned(),
                    source.replay().sequence(),
                ))
            })
            .unwrap();
        assert_eq!(after.0["payload"]["v"], 3);
        assert_eq!(after.0["payload"]["protocol_format_ceiling"], 1);
        assert_eq!(after.0["payload"]["structure_mode"], "STRUCTURED");
        assert_eq!(
            after.0["payload"]["structure"],
            before.0["payload"]["structure"]
        );
        for field in [
            "workspace_id",
            "owner_id",
            "signing_key",
            "visibility",
            "epoch",
            "members",
        ] {
            assert_eq!(
                after.0["payload"][field], before.0["payload"][field],
                "preserve {field}"
            );
        }
        assert_eq!(
            after.0["payload"]["version"].as_u64(),
            Some(before.0["payload"]["version"].as_u64().unwrap() + 1)
        );
        assert_eq!(after.0["payload"]["previous_policy"], before.1);
        assert_eq!(
            after.0["payload"]["effective_sequence"].as_u64(),
            Some(before.2 + 1)
        );
        assert_eq!(after.1, accepted["policy_hash"]);
        assert_eq!(after.2, before.2 + 1);
        let read: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &cancel).unwrap())
                .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "records"
                && row["id"] == source["prior_record_id"]
                && row["value"]["payload"]["title"] == "Legacy encrypted record"
                && row["value"]["payload"]["body"] == "Old wire-v1 encrypted body"));
        let retry: serde_json::Value =
            serde_json::from_str(&access.resume_json_with_cancel(id, &cancel).unwrap()).unwrap();
        assert_eq!(retry, accepted);
        let retry_sequence = SecureReadProfile::new(access.config.clone())
            .with_latest_replay(&cancel, |source| {
                Ok::<_, OwnerFormatTransitionError>(source.replay().sequence())
            })
            .unwrap();
        assert_eq!(retry_sequence, after.2);
    }
}
