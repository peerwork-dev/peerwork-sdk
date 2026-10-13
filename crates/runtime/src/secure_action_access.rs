//! PUBLIC action facade over the protected latest-read profile and exact
//! saved intent journal. HTTP results remain pending until signed replay
//! binds the command to an ACTION receipt.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentError, SecureIntentJournal},
    secure_lifecycle::SecureLifecycle,
    secure_native_prepare::{prepare_public_action_from_replay, NativePrepareError},
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig},
};
use peerwork_core::{
    crypto::{base64url, sha256_hex},
    prepared_secure_request::SecureCommitRequestPins,
    wire_json::{parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicActionInput {
    pub action_id: String,
    pub instance_id: String,
    /// Exact JSON text is parsed losslessly by the native ACTION evaluator.
    pub body_json: String,
    #[serde(default)]
    pub exact_input_refs_json: Option<String>,
    /// Omit for native OS-random allocations; an exact array is advanced
    /// control for callers that need deterministic tokens before preparation.
    #[serde(default)]
    pub allocations_json: Option<String>,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PublicActionResult {
    pub status: &'static str,
    pub command_id: String,
    pub workspace_id: String,
    pub action_id: String,
    pub sequence: Option<u64>,
    pub commit_hash: Option<String>,
    pub receipt_canonical_json: Option<String>,
}

/// Redacted protected state for recovering a generated command ID after the
/// caller exits or an async wrapper is cancelled before returning a result.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PendingPublicAction {
    pub command_id: String,
    pub actor_id: String,
    pub origin: String,
    pub workspace_id: String,
    pub action_id: String,
    pub request_sha256: String,
    pub commit_hash: String,
}

#[derive(Debug, Error)]
pub enum PublicActionError {
    #[error("latest signed journal read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("protected local identity or lifecycle does not match the replay")]
    LocalState,
    #[error("action input or selected policy is invalid for native PUBLIC authoring")]
    Input,
    #[error("OS entropy for a command ID is unavailable")]
    Entropy,
    #[error("native action preparation failed")]
    Prepare,
    #[error("saved secure action failed verification or persistence: {0}")]
    Intent(#[from] SecureIntentError),
    #[error("configured transport could not be opened")]
    Transport,
    #[error("native async runtime could not start")]
    Runtime,
    #[error("action result could not be encoded")]
    ResultEncoding,
}

impl PublicActionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(error) => error.code(),
            Self::LocalState => "LOCAL_STATE",
            Self::Input => "ACTION_INPUT_INVALID",
            Self::Entropy => "ENTROPY_UNAVAILABLE",
            Self::Prepare => "ACTION_PREPARE_FAILED",
            Self::Intent(_) => "INTENT_FAILED",
            Self::Transport => "TRANSPORT_FAILED",
            Self::Runtime => "RUNTIME_FAILED",
            Self::ResultEncoding => "RESULT_ENCODING_FAILED",
        }
    }
}

impl From<NativePrepareError> for PublicActionError {
    fn from(_: NativePrepareError) -> Self {
        Self::Prepare
    }
}

pub struct SecurePublicActionAccess {
    config: SecureReadProfileConfig,
}

impl SecurePublicActionAccess {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    pub fn list_pending_json(&self) -> Result<String, PublicActionError> {
        self.list_pending_json_with_cancel(&CancellationToken::new())
    }

    pub fn list_pending_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        if cancel.is_cancelled() {
            return Err(PublicActionError::Read(SecureReadAccessError::Cancelled));
        }
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicActionError::LocalState)?;
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PublicActionError::LocalState)?;
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("action-intents.state"),
            &scope.origin,
            identity.actor_id(),
        )?;
        let mut rows = Vec::new();
        for row in journal.pending() {
            if row.workspace_id.as_deref() != Some(scope.workspace_id.as_str()) {
                return Err(PublicActionError::LocalState);
            }
            rows.push(PendingPublicAction {
                request_sha256: sha256_hex(&journal.exact_request(&row.intent_id)?),
                commit_hash: journal.intent_digest(&row.intent_id)?.to_owned(),
                command_id: row.intent_id,
                actor_id: journal.actor_id().to_owned(),
                origin: journal.trusted_origin().to_owned(),
                workspace_id: scope.workspace_id.clone(),
                action_id: row.action_id,
            });
        }
        serde_json::to_string(&rows).map_err(|_| PublicActionError::ResultEncoding)
    }

    pub fn submit_new_json(&self, input: PublicActionInput) -> Result<String, PublicActionError> {
        self.submit_new_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_new_json_with_cancel(
        &self,
        input: PublicActionInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        let command_id = match input.command_id {
            Some(value) => value,
            None => new_command_id()?,
        };
        let issued_at = match input.issued_at_ms {
            Some(value) => value,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| PublicActionError::Input)?
                .as_millis() as u64,
        };
        let profile = SecureReadProfile::new(self.config.clone());
        let result = profile.with_latest_replay(cancel, |source| {
            let (identity, lifecycle, mut journal, transport) = self.open_local(source)?;
            if journal.contains_id(&command_id) {
                return Err(PublicActionError::Intent(SecureIntentError::Conflict));
            }
            let refs = input.exact_input_refs_json.as_deref().unwrap_or("[]");
            let allocations = input.allocations_json.as_deref().unwrap_or("null");
            prepare_public_action_from_replay(
                &mut journal,
                &identity,
                &lifecycle,
                source,
                &command_id,
                &input.action_id,
                &input.instance_id,
                issued_at,
                input.body_json.as_bytes(),
                refs.as_bytes(),
                allocations.as_bytes(),
            )?;
            let saved = saved_pins(&journal, &command_id)?;
            let pins = saved.borrow();
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| PublicActionError::Runtime)?;
            match runtime.block_on(journal.submit_saved_commit_from_replay(
                &command_id,
                &identity,
                &transport,
                source,
                &pins,
                cancel,
            )) {
                Ok(_) | Err(SecureIntentError::Transport(_)) => {}
                Err(error) => return Err(PublicActionError::Intent(error)),
            }
            Ok(PublicActionResult {
                status: "PENDING",
                command_id: command_id.clone(),
                workspace_id: self.config.workspace_id.clone(),
                action_id: input.action_id.clone(),
                sequence: None,
                commit_hash: None,
                receipt_canonical_json: None,
            })
        })?;
        serde_json::to_string(&result).map_err(|_| PublicActionError::ResultEncoding)
    }

    pub fn reconcile_json(&self, command_id: &str) -> Result<String, PublicActionError> {
        self.reconcile_json_with_cancel(command_id, &CancellationToken::new())
    }

    /// Reconcile first; if the signed effect is absent, submit the immutable
    /// saved packet under its authenticated pre-append checkpoint. A retry
    /// never regenerates context, allocations, command ID or ciphertext.
    pub fn retry_saved_json(&self, command_id: &str) -> Result<String, PublicActionError> {
        self.retry_saved_json_with_cancel(command_id, &CancellationToken::new())
    }

    pub fn retry_saved_json_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        let profile = SecureReadProfile::new(self.config.clone());
        let result = profile.with_latest_replay(cancel, |source| {
            let (identity, _lifecycle, mut journal, transport) = self.open_local(source)?;
            match journal.accept_replayed_action(command_id, &identity, &transport, source) {
                Ok(accepted) => {
                    return Ok(PublicActionResult {
                        status: "ACCEPTED",
                        command_id: accepted.intent_id,
                        workspace_id: accepted.workspace_id,
                        action_id: accepted.action_id,
                        sequence: Some(accepted.sequence),
                        commit_hash: Some(accepted.commit_hash),
                        receipt_canonical_json: Some(accepted.receipt_canonical_json),
                    });
                }
                Err(SecureIntentError::ReplayMismatch) => {}
                Err(error) => return Err(PublicActionError::Intent(error)),
            }
            let pending = journal
                .pending()
                .into_iter()
                .find(|row| row.intent_id == command_id)
                .ok_or(SecureIntentError::NotFound)?;
            let saved = saved_pins(&journal, command_id)?;
            let pins = saved.borrow();
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| PublicActionError::Runtime)?;
            match runtime.block_on(journal.submit_saved_commit_from_replay(
                command_id, &identity, &transport, source, &pins, cancel,
            )) {
                Ok(_) | Err(SecureIntentError::Transport(_)) => {}
                Err(error) => return Err(PublicActionError::Intent(error)),
            }
            Ok(PublicActionResult {
                status: "PENDING",
                command_id: pending.intent_id,
                workspace_id: pending.workspace_id.unwrap_or_default(),
                action_id: pending.action_id,
                sequence: None,
                commit_hash: None,
                receipt_canonical_json: None,
            })
        })?;
        serde_json::to_string(&result).map_err(|_| PublicActionError::ResultEncoding)
    }

    pub fn reconcile_json_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        let profile = SecureReadProfile::new(self.config.clone());
        let result = profile.with_latest_replay(cancel, |source| {
            let (identity, _lifecycle, mut journal, transport) = self.open_local(source)?;
            match journal.accept_replayed_action(command_id, &identity, &transport, source) {
                Ok(accepted) => Ok(PublicActionResult {
                    status: "ACCEPTED",
                    command_id: accepted.intent_id,
                    workspace_id: accepted.workspace_id,
                    action_id: accepted.action_id,
                    sequence: Some(accepted.sequence),
                    commit_hash: Some(accepted.commit_hash),
                    receipt_canonical_json: Some(accepted.receipt_canonical_json),
                }),
                Err(SecureIntentError::ReplayMismatch) => {
                    let pending = journal
                        .pending()
                        .into_iter()
                        .find(|row| row.intent_id == command_id)
                        .ok_or(SecureIntentError::NotFound)?;
                    Ok(PublicActionResult {
                        status: "PENDING",
                        command_id: pending.intent_id,
                        workspace_id: pending.workspace_id.unwrap_or_default(),
                        action_id: pending.action_id,
                        sequence: None,
                        commit_hash: None,
                        receipt_canonical_json: None,
                    })
                }
                Err(error) => Err(PublicActionError::Intent(error)),
            }
        })?;
        serde_json::to_string(&result).map_err(|_| PublicActionError::ResultEncoding)
    }

    fn open_local(
        &self,
        source: &TransportReplayedJournal,
    ) -> Result<
        (
            KernelIdentity,
            SecureLifecycle,
            SecureIntentJournal,
            HttpTransport,
        ),
        PublicActionError,
    > {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicActionError::LocalState)?;
        let lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            source.origin(),
            identity.actor_id(),
            source.replay().workspace_id(),
            source.replay().owner_actor_id(),
            source.replay().owner_signing_key(),
        )
        .map_err(|_| PublicActionError::LocalState)?;
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("action-intents.state"),
            source.origin(),
            identity.actor_id(),
        )?;
        let mut config = TransportConfig::new(self.config.origin.clone());
        config.allow_loopback_http = self.config.allow_loopback_http;
        let transport = HttpTransport::new(config).map_err(|_| PublicActionError::Transport)?;
        Ok((identity, lifecycle, journal, transport))
    }
}

fn new_command_id() -> Result<String, PublicActionError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PublicActionError::Entropy)?;
    Ok(base64url(&bytes))
}

struct SavedPins {
    actor: String,
    signing_key: String,
    workspace: String,
    policy_hash: String,
    sequence: u64,
    previous: Option<String>,
    epoch: u64,
    mode: String,
    version: u64,
    ceiling: Option<u64>,
}

impl SavedPins {
    fn borrow(&self) -> SecureCommitRequestPins<'_> {
        SecureCommitRequestPins {
            actor_id: &self.actor,
            signing_key: &self.signing_key,
            workspace_id: &self.workspace,
            policy_hash: &self.policy_hash,
            sequence: self.sequence,
            previous: self.previous.as_deref(),
            epoch: self.epoch,
            mode: &self.mode,
            version: self.version,
            protocol_format_ceiling: self.ceiling,
        }
    }
}

fn saved_pins(
    journal: &SecureIntentJournal,
    command_id: &str,
) -> Result<SavedPins, PublicActionError> {
    let wire = journal.exact_request(command_id)?;
    let parsed = parse_wire_json_bounded(&wire, 64, 2 * 1024 * 1024)
        .map_err(|_| PublicActionError::Input)?;
    let payload = parsed
        .get("commit")
        .and_then(|commit| commit.get("payload"))
        .ok_or(PublicActionError::Input)?;
    let text = |name: &str| {
        payload
            .get(name)
            .and_then(WireValue::as_string)
            .ok_or(PublicActionError::Input)
    };
    let number = |name: &str| {
        payload
            .get(name)
            .and_then(WireValue::as_number)
            .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
            .map(|value| value as u64)
            .ok_or(PublicActionError::Input)
    };
    let previous = match payload.get("previous") {
        Some(WireValue::Null) => None,
        Some(WireValue::String(_)) => Some(text("previous")?),
        _ => return Err(PublicActionError::Input),
    };
    let version = number("v")?;
    Ok(SavedPins {
        actor: text("actor_id")?,
        signing_key: text("signing_key")?,
        workspace: text("workspace_id")?,
        policy_hash: text("policy_hash")?,
        sequence: number("sequence")?,
        previous,
        epoch: number("epoch")?,
        mode: text("mode")?,
        version,
        ceiling: (version == 3)
            .then(|| number("protocol_format_ceiling"))
            .transpose()?,
    })
}
