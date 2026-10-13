//! Secure action facade over the protected latest-read profile and exact
//! saved intent journal. HTTP results remain pending until signed replay
//! binds the command to an ACTION receipt.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentError, SecureIntentJournal},
    secure_lifecycle::SecureLifecycle,
    secure_native_prepare::{
        prepare_private_action_from_replay, prepare_public_action_from_replay, NativePrepareError,
    },
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::SecureStateError,
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
    #[error("action input or selected policy is invalid for native authoring")]
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
            Self::Intent(error) => match error {
                SecureIntentError::Conflict => "INTENT_CONFLICT",
                SecureIntentError::NotFound => "INTENT_NOT_FOUND",
                SecureIntentError::TooLarge
                | SecureIntentError::Store(SecureStateError::TooLarge) => "RESOURCE_LIMIT",
                SecureIntentError::Store(SecureStateError::Busy) => "STATE_BUSY",
                SecureIntentError::Store(_)
                | SecureIntentError::Incompatible
                | SecureIntentError::Invalid => "INTENT_STATE",
                SecureIntentError::Proof(_) | SecureIntentError::BootstrapProof(_) => {
                    "INTENT_PROOF_FAILED"
                }
                SecureIntentError::Transport(_) => "TRANSPORT_FAILED",
                SecureIntentError::ServerRejected(_) => "SERVER_REJECTED",
                SecureIntentError::ReplayMismatch => "VERIFICATION_FAILED",
            },
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

#[cfg(test)]
mod error_code_tests {
    use super::*;

    #[test]
    fn protected_intent_refusals_have_recoverable_public_codes() {
        for (source, expected) in [
            (SecureIntentError::Conflict, "INTENT_CONFLICT"),
            (SecureIntentError::NotFound, "INTENT_NOT_FOUND"),
            (SecureIntentError::TooLarge, "RESOURCE_LIMIT"),
            (
                SecureIntentError::Store(SecureStateError::Busy),
                "STATE_BUSY",
            ),
            (SecureIntentError::ServerRejected(503), "SERVER_REJECTED"),
            (SecureIntentError::ReplayMismatch, "VERIFICATION_FAILED"),
        ] {
            assert_eq!(PublicActionError::Intent(source).code(), expected);
        }
    }
}

pub struct SecurePublicActionAccess {
    config: SecureReadProfileConfig,
    required_mode: &'static str,
}

impl SecurePublicActionAccess {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self {
            config,
            required_mode: "PUBLIC",
        }
    }

    fn new_private(config: SecureReadProfileConfig) -> Self {
        Self {
            config,
            required_mode: "PRIVATE",
        }
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
            if saved_pins(&journal, &row.intent_id)?.mode != self.required_mode {
                continue;
            }
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
            let policy_wire = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(PublicActionError::Input)?;
            let policy = parse_wire_json_bounded(policy_wire, 64, 16 * 1024 * 1024)
                .map_err(|_| PublicActionError::Input)?;
            let visibility = policy
                .get("payload")
                .and_then(|payload| payload.get("visibility"))
                .and_then(WireValue::as_string)
                .ok_or(PublicActionError::Input)?;
            if visibility != self.required_mode {
                return Err(PublicActionError::Input);
            }
            match visibility.as_str() {
                "PUBLIC" => prepare_public_action_from_replay(
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
                ),
                "PRIVATE" => prepare_private_action_from_replay(
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
                ),
                _ => return Err(PublicActionError::Input),
            }?;
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
            if saved_pins(&journal, command_id)?.mode != self.required_mode {
                return Err(PublicActionError::Input);
            }
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
            if saved_pins(&journal, command_id)?.mode != self.required_mode {
                return Err(PublicActionError::Input);
            }
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

/// PRIVATE action entry point. It shares exact packet persistence and signed
/// receipt reconciliation with PUBLIC while requiring an active PRIVATE read
/// and an epoch key selected from the protected lifecycle.
pub struct SecurePrivateActionAccess {
    inner: SecurePublicActionAccess,
}

impl SecurePrivateActionAccess {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self {
            inner: SecurePublicActionAccess::new_private(config),
        }
    }

    pub fn submit_new_json(&self, input: PublicActionInput) -> Result<String, PublicActionError> {
        self.inner.submit_new_json(input)
    }

    pub fn submit_new_json_with_cancel(
        &self,
        input: PublicActionInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        self.inner.submit_new_json_with_cancel(input, cancel)
    }

    pub fn reconcile_json(&self, command_id: &str) -> Result<String, PublicActionError> {
        self.inner.reconcile_json(command_id)
    }

    pub fn reconcile_json_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        self.inner.reconcile_json_with_cancel(command_id, cancel)
    }

    pub fn retry_saved_json(&self, command_id: &str) -> Result<String, PublicActionError> {
        self.inner.retry_saved_json(command_id)
    }

    pub fn retry_saved_json_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        self.inner.retry_saved_json_with_cancel(command_id, cancel)
    }

    pub fn list_pending_json(&self) -> Result<String, PublicActionError> {
        self.inner.list_pending_json()
    }

    pub fn list_pending_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, PublicActionError> {
        self.inner.list_pending_json_with_cancel(cancel)
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

#[cfg(test)]
mod private_action_tests {
    use super::*;
    use crate::{
        secure_public_decision::{PublicDecisionConfig, SecurePublicDecision},
        secure_recipient_state::RecipientState,
    };
    use std::{
        fs,
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_private_action_native_encrypted_effect_and_exact_retry() {
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
            .env("PEERWORK_TEST_PRIVATE_ACTION", "1")
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
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        if line.is_empty() {
            use std::io::Read;
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("private action fixture failed before ready: {stderr}");
        }
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let fixture = &ready["private_grant"];
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let state = temp.path().join("native-private-action-recipient");
        fs::create_dir(&state).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity_path = state.join("identity.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &temp.path().join("private-grant-recipient.pem"),
        )
        .unwrap();
        RecipientState::import_unjoined_ts_state(
            &state.join("recipient.state"),
            &identity,
            &temp.path().join("private-grant-recipient.json"),
        )
        .unwrap();
        drop(identity);
        let workspace_id = fixture["workspace_id"].as_str().unwrap().to_owned();
        let owner_actor_id = fixture["owner_actor_id"].as_str().unwrap().to_owned();
        let owner_key_id = fixture["owner_key_id"].as_str().unwrap().to_owned();
        let authority = fixture["recipient_authority"].as_str().unwrap().to_owned();
        let decision = SecurePublicDecision::new(PublicDecisionConfig {
            origin: origin.clone(),
            state_dir: state.clone(),
            identity_path: identity_path.clone(),
            workspace_id: workspace_id.clone(),
            owner_actor_id: owner_actor_id.clone(),
            owner_key_id: owner_key_id.clone(),
            authority: authority.clone(),
            allow_loopback_http: true,
            required_features: vec![],
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        let invite_id = fixture["invite_id"].as_str().unwrap();
        let received: serde_json::Value =
            serde_json::from_str(&decision.receive_json(invite_id).unwrap()).unwrap();
        assert_eq!(received["status"], "PENDING");
        let recovered: serde_json::Value =
            serde_json::from_str(&decision.retry_receive_json(invite_id).unwrap()).unwrap();
        assert_eq!(recovered["status"], "READY");
        let profile = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: state.clone(),
            identity_path,
            workspace_id: workspace_id.clone(),
            owner_actor_id: Some(owner_actor_id),
            owner_key_id: Some(owner_key_id),
            authority: Some(authority),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let submitted: serde_json::Value = serde_json::from_str(
            &SecurePrivateActionAccess::new(profile.clone())
                .submit_new_json(PublicActionInput {
                    action_id: "wiki.create".into(),
                    instance_id: fixture["instance_id"].as_str().unwrap().into(),
                    body_json:
                        r#"{"title":"Native private action","body":"Encrypted native effect"}"#
                            .into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: Some("z".repeat(43)),
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(submitted["status"], "PENDING");
        let reopened = SecurePrivateActionAccess::new(profile.clone());
        let accepted: serde_json::Value =
            serde_json::from_str(&reopened.reconcile_json(&"z".repeat(43)).unwrap()).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        assert_eq!(accepted["sequence"], 4);
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effects = receipt["effects"].as_array().unwrap();
        assert_eq!(effects.len(), 1);
        let effect_record_id = effects[0]["record_id"].as_str().unwrap();
        let retried: serde_json::Value =
            serde_json::from_str(&reopened.retry_saved_json(&"z".repeat(43)).unwrap()).unwrap();
        assert_eq!(retried["status"], "ACCEPTED");
        assert_eq!(retried["commit_hash"], accepted["commit_hash"]);
        let read: serde_json::Value =
            serde_json::from_str(&SecureReadProfile::new(profile).read_latest_json().unwrap())
                .unwrap();
        let records = read["objects"].as_array().unwrap();
        assert!(records.iter().any(|row| row["kind"] == "records"
            && row["id"] == effect_record_id
            && row["value"]["payload"]["title"] == "Native private action"
            && row["value"]["payload"]["body"] == "Encrypted native effect"));
        let counts: serde_json::Value = runtime.block_on(async {
            let response = reqwest::get(format!("{origin}__test/secure-counts"))
                .await
                .unwrap();
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
        });
        assert_eq!(counts["commits"], 4);
    }
}
