//! PUBLIC direct-install BEGIN from a locally pinned package closure and a
//! complete, origin-bound active journal. A saved BEGIN remains pending until
//! signed replay proves the structure transition; HTTP success is not proof.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{
        AcceptedPublicInstall, PublicInstallSelection, SecureIntentError, SecureIntentJournal,
        SecurePacketInput,
    },
    secure_lifecycle::SecureLifecycle,
    secure_read_access::{
        SecureReadAccess, SecureReadAccessError, SecureReadConfig, VerifiedReadFloor,
    },
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::SecureStateError,
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, sha256, sha256_hex},
    public_direct_install::{
        compile_public_package_closure_with_bindings, plan_public_install_snapshot,
        prepare_public_package_install_begin_with_bindings, sign_public_install_step, DirectInstallError,
        PublicInstallSnapshotPlan,
    },
    replayed_secure_journal::StructureStatus,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPackageInstallInput {
    /// Canonical package-closure JSON. Its exact selected digest and version
    /// remain protected locally because PUBLIC install wire has no source.
    pub closure_json: String,
    #[serde(default)]
    pub bindings_json: Option<String>,
    pub expected_package_id: String,
    pub expected_package_version: String,
    pub expected_package_digest: String,
    pub expected_protocol_digest: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicPackageInstallResult {
    pub status: &'static str,
    pub command_id: String,
    pub workspace_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_digest: String,
    pub protocol_digest: String,
    pub instance_id: String,
    pub commit_hash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicPackageInstallProgress {
    pub status: &'static str,
    pub begin_command_id: String,
    pub step_command_id: String,
    pub step_action_id: &'static str,
    pub workspace_id: String,
    pub package_digest: String,
    pub protocol_digest: String,
    pub instance_id: String,
    pub commit_hash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PendingPublicPackageInstall {
    pub begin_command_id: String,
    pub pending_step_id: String,
    pub pending_action_id: &'static str,
    pub workspace_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_digest: String,
    pub protocol_digest: String,
    pub instance_id: String,
}

#[derive(Debug, Error)]
pub enum PublicPackageInstallError {
    #[error("latest signed journal read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("protected owner identity does not match the signed journal")]
    Identity,
    #[error("selected package, grants, or install context is invalid")]
    Input,
    #[error("OS entropy for a command ID is unavailable")]
    Entropy,
    #[error("PUBLIC direct-install plan could not be proved")]
    Plan,
    #[error("protected install intent failed: {0}")]
    Intent(#[from] SecureIntentError),
    #[error("configured transport could not be opened")]
    Transport,
    #[error("native async runtime could not start")]
    Runtime,
    #[error("server rejected the saved install BEGIN with HTTP {0}")]
    ServerRejected(u16),
    #[error("install result could not be encoded")]
    ResultEncoding,
}

impl PublicPackageInstallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(error) => error.code(),
            Self::Identity => "IDENTITY_STATE",
            Self::Input => "INSTALL_INPUT_INVALID",
            Self::Entropy => "ENTROPY_UNAVAILABLE",
            Self::Plan => "INSTALL_PLAN_FAILED",
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
            Self::ServerRejected(_) => "SERVER_REJECTED",
            Self::ResultEncoding => "RESULT_ENCODING_FAILED",
        }
    }
}

impl From<DirectInstallError> for PublicPackageInstallError {
    fn from(_: DirectInstallError) -> Self {
        Self::Plan
    }
}

pub struct SecurePublicPackageInstall {
    config: SecureReadProfileConfig,
}

impl SecurePublicPackageInstall {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    /// Discover protected, redacted install intents after a caller crashes
    /// before seeing the generated command ID. No packet, signer or key leaves
    /// the protected store; listing does not imply server acceptance.
    pub fn list_pending_json(&self) -> Result<String, PublicPackageInstallError> {
        self.list_pending_json_with_cancel(&CancellationToken::new())
    }

    pub fn list_pending_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, PublicPackageInstallError> {
        if cancel.is_cancelled() {
            return Err(PublicPackageInstallError::Read(
                SecureReadAccessError::Cancelled,
            ));
        }
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicPackageInstallError::Identity)?;
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PublicPackageInstallError::Identity)?;
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("install-intents.state"),
            &scope.origin,
            identity.actor_id(),
        )?;
        let mut rows = Vec::new();
        for pending in journal.pending() {
            if pending.workspace_id.as_deref() != Some(scope.workspace_id.as_str()) {
                return Err(PublicPackageInstallError::Identity);
            }
            if pending.action_id != "secure.structure.begin" {
                continue;
            }
            let selection = journal.public_install_selection(&pending.intent_id)?;
            let (step_id, step_action) = pending_install_step(&journal, &pending.intent_id)?;
            rows.push(PendingPublicPackageInstall {
                begin_command_id: pending.intent_id.clone(),
                pending_step_id: step_id,
                pending_action_id: step_action,
                workspace_id: scope.workspace_id.clone(),
                package_id: selection.package_id.clone(),
                package_version: selection.package_version.clone(),
                package_digest: selection.package_digest.clone(),
                protocol_digest: selection.protocol_digest.clone(),
                instance_id: selection.instance_id.clone(),
            });
        }
        serde_json::to_string(&rows).map_err(|_| PublicPackageInstallError::ResultEncoding)
    }

    /// Keep the protected last ACTIVE floor locked while fetching and fully
    /// replaying a fresh journal that may be SEEDING. This candidate never
    /// updates the active read pointer or authorizes an ordinary action.
    fn with_install_replay<T, F>(
        &self,
        cancel: &CancellationToken,
        consume: F,
    ) -> Result<T, PublicPackageInstallError>
    where
        F: FnOnce(
            &TransportReplayedJournal,
            &TransportReplayedJournal,
        ) -> Result<T, PublicPackageInstallError>,
    {
        SecureReadProfile::new(self.config.clone()).with_pinned_replay(cancel, |prior| {
            let floor = VerifiedReadFloor {
                sequence: prior.replay().sequence(),
                head: prior.replay().head().map(str::to_owned),
                policy_hash: prior.replay().policy_hash().to_owned(),
            };
            let state_dir = &self.config.state_dir;
            let access = SecureReadAccess::new(SecureReadConfig {
                origin: prior.origin().to_owned(),
                kernel_journal_path: state_dir.join("kernel.sqlite"),
                read_state_path: state_dir.join("install-read.state"),
                lifecycle_path: state_dir.join("lifecycle.state"),
                identity_path: self.config.identity_path.clone(),
                workspace_id: prior.replay().workspace_id().to_owned(),
                authority: prior.authority().to_owned(),
                owner_actor_id: prior.replay().owner_actor_id().to_owned(),
                owner_key_id: prior.replay().owner_signing_key().to_owned(),
                required_features: self.config.required_features.clone(),
                allow_loopback_http: self.config.allow_loopback_http,
                max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            });
            let (fresh, _) = access.replay_checked_install_generation(cancel, &floor)?;
            if fresh.origin() != prior.origin()
                || fresh.authority() != prior.authority()
                || fresh.replay().workspace_id() != prior.replay().workspace_id()
                || fresh.replay().owner_actor_id() != prior.replay().owner_actor_id()
                || fresh.replay().owner_signing_key() != prior.replay().owner_signing_key()
            {
                return Err(PublicPackageInstallError::Identity);
            }
            consume(prior, &fresh)
        })
    }

    pub fn submit_begin_json(
        &self,
        input: PublicPackageInstallInput,
    ) -> Result<String, PublicPackageInstallError> {
        self.submit_begin_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_begin_json_with_cancel(
        &self,
        input: PublicPackageInstallInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicPackageInstallError> {
        let command_id = match input.command_id.as_deref() {
            Some(id) => id.to_owned(),
            None => random_id()?,
        };
        let issued_at = input.issued_at_ms.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis() as u64)
                .unwrap_or(0)
        });
        if issued_at == 0 || input.closure_json.len() > 6 * 1024 * 1024 {
            return Err(PublicPackageInstallError::Input);
        }
        let profile = SecureReadProfile::new(self.config.clone());
        let result = profile.with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicPackageInstallError::Identity)?;
            if identity.actor_id() != source.replay().owner_actor_id()
                || identity.key_id() != source.replay().owner_signing_key()
                || source.origin() != self.config.origin
                || source.replay().workspace_id() != self.config.workspace_id
            {
                return Err(PublicPackageInstallError::Identity);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("install-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            if journal.contains_id(&command_id) {
                return Err(PublicPackageInstallError::Intent(
                    SecureIntentError::Conflict,
                ));
            }
            let prior_policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(PublicPackageInstallError::Input)?;
            let grants = parse_wire_json_bounded(input.grants_json.as_bytes(), 32, 65_536)
                .map_err(|_| PublicPackageInstallError::Input)?;
            let grants_json = canonical_wire_value(&grants, CanonicalPath::SecureArtifact)
                .map_err(|_| PublicPackageInstallError::Input)?;
            let bindings = parse_wire_json_bounded(
                input.bindings_json.as_deref().unwrap_or("{}").as_bytes(), 32, 65_536,
            ).map_err(|_| PublicPackageInstallError::Input)?;
            if bindings.object_len().is_none() {
                return Err(PublicPackageInstallError::Input);
            }
            let bindings_json = canonical_wire_value(&bindings, CanonicalPath::SecureArtifact)
                .map_err(|_| PublicPackageInstallError::Input)?;
            let prepared = prepare_public_package_install_begin_with_bindings(
                input.closure_json.as_bytes(),
                bindings_json.as_bytes(),
                &input.expected_package_digest,
                &input.expected_protocol_digest,
                prior_policy,
                source.checkpoint_canonical_json().as_bytes(),
                source.replay().objects(),
                grants_json.as_bytes(),
                &input.instance_id,
                &input.entrypoint,
                &command_id,
                issued_at,
                identity.signing_key(),
            )?;
            if prepared.package_id() != input.expected_package_id
                || prepared.package_version() != input.expected_package_version
            {
                return Err(PublicPackageInstallError::Input);
            }
            let selection = PublicInstallSelection {
                package_id: prepared.package_id().to_owned(),
                package_version: prepared.package_version().to_owned(),
                package_digest: prepared.package_digest().to_owned(),
                protocol_digest: prepared.protocol_digest().to_owned(),
                instance_id: prepared.instance_id().to_owned(),
                entrypoint: input.entrypoint.clone(),
                closure_sha256: sha256_hex(input.closure_json.as_bytes()),
                closure_b64: base64url(input.closure_json.as_bytes()),
                bindings_json: Some(bindings_json),
                prior_checkpoint_json: source.checkpoint_canonical_json().to_owned(),
                grants_json,
            };
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            journal.prepare_public_install(
                SecurePacketInput {
                    intent_id: &command_id,
                    path: &path,
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                },
                selection,
            )?;
            // Rebuild from protected selection and the same authenticated
            // replay before transport; the saved packet is the only POST body.
            let saved = prove_saved_begin(&journal, &command_id, source, &identity)?;
            let mut transport_config = TransportConfig::new(self.config.origin.clone());
            transport_config.allow_loopback_http = self.config.allow_loopback_http;
            let transport = HttpTransport::new(transport_config)
                .map_err(|_| PublicPackageInstallError::Transport)?;
            if transport.trusted_origin() != source.origin() {
                return Err(PublicPackageInstallError::Transport);
            }
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| PublicPackageInstallError::Runtime)?;
            match runtime.block_on(transport.post_exact(&path, saved, cancel)) {
                Ok(response) => {
                    if !response.wire.is_empty() {
                        journal.observe_response(&command_id, &response.wire)?;
                    }
                    if !(200..300).contains(&response.status) {
                        return Err(PublicPackageInstallError::ServerRejected(response.status));
                    }
                }
                Err(TransportError::SubmittedUncertain) => {}
                Err(_) => return Err(PublicPackageInstallError::Transport),
            }
            Ok(PublicPackageInstallResult {
                status: "PENDING",
                command_id,
                workspace_id: self.config.workspace_id.clone(),
                package_id: prepared.package_id().to_owned(),
                package_version: prepared.package_version().to_owned(),
                package_digest: prepared.package_digest().to_owned(),
                protocol_digest: prepared.protocol_digest().to_owned(),
                instance_id: prepared.instance_id().to_owned(),
                commit_hash: prepared.commit_hash().to_owned(),
            })
        })?;
        serde_json::to_string(&result).map_err(|_| PublicPackageInstallError::ResultEncoding)
    }

    /// Compatibility alias for an existing empty-snapshot caller. It now uses
    /// the same authenticated PAGE/END continuation as nonempty installs.
    pub fn continue_empty_snapshot_json(
        &self,
        begin_command_id: &str,
    ) -> Result<String, PublicPackageInstallError> {
        self.continue_install_json(begin_command_id)
    }

    /// Resume a protected PUBLIC install by its BEGIN command ID. The saved
    /// packet is reused after an uncertain reply. Signed SEEDING replay binds
    /// each PAGE offset and END to the original snapshot root and checkpoint.
    pub fn continue_install_json(
        &self,
        begin_command_id: &str,
    ) -> Result<String, PublicPackageInstallError> {
        self.continue_install_json_with_cancel(begin_command_id, &CancellationToken::new())
    }

    pub fn continue_empty_snapshot_json_with_cancel(
        &self,
        begin_command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicPackageInstallError> {
        self.continue_install_json_with_cancel(begin_command_id, cancel)
    }

    pub fn continue_install_json_with_cancel(
        &self,
        begin_command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicPackageInstallError> {
        let result = self.with_install_replay(cancel, |prior, fresh| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicPackageInstallError::Identity)?;
            if identity.actor_id() != prior.replay().owner_actor_id()
                || identity.key_id() != prior.replay().owner_signing_key()
            {
                return Err(PublicPackageInstallError::Input);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("install-intents.state"),
                prior.origin(),
                identity.actor_id(),
            )?;
            if let Some(accepted) = journal.accepted_public_install(begin_command_id)?.cloned() {
                return reprove_completed_install(&journal, begin_command_id, &accepted, fresh);
            }
            let saved_begin = prove_saved_begin(&journal, begin_command_id, prior, &identity)?;
            let begin = parse_wire_json_bounded(&saved_begin, 64, 262_144)
                .map_err(|_| PublicPackageInstallError::Input)?;
            let begin_payload = begin
                .get("commit")
                .and_then(|value| value.get("payload"))
                .ok_or(PublicPackageInstallError::Input)?;
            let snapshot = begin_payload
                .get("structure")
                .and_then(|value| value.get("snapshot"))
                .ok_or(PublicPackageInstallError::Input)?;
            let selection = journal.public_install_selection(begin_command_id)?.clone();
            let begin_hash = journal.intent_digest(begin_command_id)?.to_owned();
            let begin_policy_hash = begin
                .get("policy_update")
                .ok_or(PublicPackageInstallError::Input)
                .and_then(|policy| {
                    canonical_wire_value(policy, CanonicalPath::SecureArtifact)
                        .map_err(|_| PublicPackageInstallError::Input)
                })
                .map(|wire| sha256_hex(wire.as_bytes()))?;
            if fresh.replay().sequence() == prior.replay().sequence()
                && fresh.replay().head() == prior.replay().head()
                && fresh.replay().policy_hash() == prior.replay().policy_hash()
                && fresh.replay().structure_status() == prior.replay().structure_status()
            {
                // A failed or interrupted first POST left no signed BEGIN.
                // Retry the protected packet, keeping its original command,
                // issued time, signature and source selection.
                post_saved_install_step(
                    &self.config,
                    fresh.origin(),
                    &mut journal,
                    begin_command_id,
                    saved_begin.clone(),
                    cancel,
                )?;
                return Ok(PublicPackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: begin_command_id.to_owned(),
                    step_command_id: begin_command_id.to_owned(),
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    package_digest: selection.package_digest,
                    protocol_digest: selection.protocol_digest,
                    instance_id: selection.instance_id,
                    commit_hash: begin_hash.clone(),
                });
            }
            if fresh.replay().structure_status() == StructureStatus::Active {
                return accept_completed_install(
                    &mut journal,
                    begin_command_id,
                    &selection,
                    &saved_begin,
                    snapshot,
                    &begin_policy_hash,
                    prior,
                    fresh,
                    &identity,
                );
            }
            if fresh.replay().structure_status() != StructureStatus::Seeding {
                return Err(PublicPackageInstallError::Input);
            }
            let begin_sequence = prior.replay().sequence() + 1;
            if !fresh.replay().contains_checkpoint(
                begin_sequence,
                Some(&begin_hash),
                &begin_policy_hash,
            ) || fresh.replay().policy_hash() != begin_policy_hash
            {
                return Err(PublicPackageInstallError::Input);
            }
            let signed_policy = fresh
                .signed_policy_by_hash(&begin_policy_hash)
                .ok_or(PublicPackageInstallError::Input)?;
            let plan = prove_snapshot_plan(prior, signed_policy, snapshot)?;
            let signed_snapshot = fresh
                .replay()
                .structure_snapshot()
                .ok_or(PublicPackageInstallError::Input)?;
            let offset = snapshot_offset(signed_snapshot)?;
            if !same_snapshot_state(signed_snapshot, snapshot) || offset > snapshot_total(&plan) {
                return Err(PublicPackageInstallError::Input);
            }
            let done = offset == snapshot_total(&plan);
            let step_command_id = install_step_id(begin_command_id, offset, done);
            let issued_at = if journal.contains_id(&step_command_id) {
                let saved = journal.exact_request(&step_command_id)?;
                let parsed = parse_wire_json_bounded(&saved, 64, 262_144)
                    .map_err(|_| PublicPackageInstallError::Input)?;
                parsed
                    .get("commit")
                    .and_then(|commit| commit.get("payload"))
                    .and_then(|payload| payload.get("issued_at"))
                    .and_then(WireValue::as_number)
                    .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
                    .map(|number| number as u64)
                    .ok_or(PublicPackageInstallError::Input)?
            } else {
                current_time_ms()?
            };
            let signed = sign_public_install_step(
                signed_policy,
                fresh.checkpoint_canonical_json().as_bytes(),
                signed_snapshot,
                &plan,
                &step_command_id,
                issued_at,
                identity.signing_key(),
            )?;
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            if !journal.contains_id(&step_command_id) {
                journal.prepare(SecurePacketInput {
                    intent_id: &step_command_id,
                    path: &path,
                    action_id: signed.action_id(),
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: signed.commit_hash(),
                    exact_request: signed.request_wire(),
                })?;
            }
            let saved = journal.exact_request(&step_command_id)?;
            if saved != signed.request_wire()
                || journal.intent_digest(&step_command_id)? != signed.commit_hash()
            {
                return Err(PublicPackageInstallError::Input);
            }
            post_saved_install_step(
                &self.config,
                fresh.origin(),
                &mut journal,
                &step_command_id,
                saved,
                cancel,
            )?;
            Ok(PublicPackageInstallProgress {
                status: "PENDING",
                begin_command_id: begin_command_id.to_owned(),
                step_command_id,
                step_action_id: signed.action_id(),
                workspace_id: self.config.workspace_id.clone(),
                package_digest: selection.package_digest,
                protocol_digest: selection.protocol_digest,
                instance_id: selection.instance_id,
                commit_hash: signed.commit_hash().to_owned(),
            })
        })?;
        serde_json::to_string(&result).map_err(|_| PublicPackageInstallError::ResultEncoding)
    }
}

fn post_saved_install_step(
    config: &SecureReadProfileConfig,
    trusted_origin: &str,
    journal: &mut SecureIntentJournal,
    command_id: &str,
    exact_request: Vec<u8>,
    cancel: &CancellationToken,
) -> Result<(), PublicPackageInstallError> {
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        config.workspace_id
    );
    let mut transport_config = TransportConfig::new(config.origin.clone());
    transport_config.allow_loopback_http = config.allow_loopback_http;
    let transport =
        HttpTransport::new(transport_config).map_err(|_| PublicPackageInstallError::Transport)?;
    if transport.trusted_origin() != trusted_origin {
        return Err(PublicPackageInstallError::Transport);
    }
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| PublicPackageInstallError::Runtime)?;
    match runtime.block_on(transport.post_exact(&path, exact_request, cancel)) {
        Ok(response) => {
            if !response.wire.is_empty() {
                journal.observe_response(command_id, &response.wire)?;
            }
            if !(200..300).contains(&response.status) {
                return Err(PublicPackageInstallError::ServerRejected(response.status));
            }
        }
        Err(TransportError::SubmittedUncertain) => {}
        Err(_) => return Err(PublicPackageInstallError::Transport),
    }
    Ok(())
}

fn snapshot_offset(snapshot: &WireValue) -> Result<usize, PublicPackageInstallError> {
    let number = snapshot
        .get("offset")
        .and_then(WireValue::as_number)
        .ok_or(PublicPackageInstallError::Input)?;
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > 100_000.0 {
        return Err(PublicPackageInstallError::Input);
    }
    Ok(number as usize)
}

fn snapshot_total(plan: &PublicInstallSnapshotPlan) -> usize {
    plan.records().len() + plan.heads().len()
}

fn snapshot_page_len(
    plan: &PublicInstallSnapshotPlan,
    offset: usize,
) -> Result<usize, PublicPackageInstallError> {
    let records = plan.records().len();
    let total = snapshot_total(plan);
    if offset >= total {
        return Err(PublicPackageInstallError::Input);
    }
    Ok(if offset < records {
        (records - offset).min(50)
    } else {
        (total - offset).min(50)
    })
}

fn snapshot_with_offset(
    initial: &WireValue,
    offset: usize,
) -> Result<WireValue, PublicPackageInstallError> {
    let mut snapshot = initial.clone();
    let WireValue::Object(fields) = &mut snapshot else {
        return Err(PublicPackageInstallError::Input);
    };
    let (_, current) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq("offset".encode_utf16()))
        .ok_or(PublicPackageInstallError::Input)?;
    *current = WireValue::Number(offset as f64);
    Ok(snapshot)
}

fn same_snapshot_state(left: &WireValue, right: &WireValue) -> bool {
    ["source", "root", "records", "heads"]
        .iter()
        .all(|field| left.get(field).is_some() && left.get(field) == right.get(field))
}

fn install_step_id(begin_id: &str, offset: usize, done: bool) -> String {
    let domain = if done {
        format!("peerwork.public.install.end.v1:{begin_id}")
    } else {
        format!("peerwork.public.install.page.v1:{begin_id}:{offset}")
    };
    base64url(&sha256(domain.as_bytes()))
}

fn pending_install_step(
    journal: &SecureIntentJournal,
    begin_id: &str,
) -> Result<(String, &'static str), PublicPackageInstallError> {
    let end_id = install_step_id(begin_id, 0, true);
    if journal.contains_id(&end_id) {
        return Ok((end_id, "secure.structure.end"));
    }
    let mut latest: Option<(usize, String)> = None;
    for row in journal.pending() {
        if row.action_id != "secure.structure.page" {
            continue;
        }
        let saved = journal.exact_request(&row.intent_id)?;
        let wire = parse_wire_json_bounded(&saved, 64, 262_144)
            .map_err(|_| PublicPackageInstallError::Input)?;
        let snapshot = wire
            .get("commit")
            .and_then(|commit| commit.get("payload"))
            .and_then(|payload| payload.get("structure"))
            .and_then(|structure| structure.get("snapshot"))
            .ok_or(PublicPackageInstallError::Input)?;
        let offset = snapshot_offset(snapshot)?;
        if row.intent_id == install_step_id(begin_id, offset, false)
            && latest.as_ref().is_none_or(|(old, _)| offset > *old)
        {
            latest = Some((offset, row.intent_id));
        }
    }
    Ok(match latest {
        Some((_, id)) => (id, "secure.structure.page"),
        None => (begin_id.to_owned(), "secure.structure.begin"),
    })
}

fn prove_snapshot_plan(
    prior: &TransportReplayedJournal,
    signed_policy_wire: &[u8],
    saved_begin_snapshot: &WireValue,
) -> Result<PublicInstallSnapshotPlan, PublicPackageInstallError> {
    let policy = parse_wire_json_bounded(signed_policy_wire, 64, 196_608)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let contract = policy
        .get("payload")
        .and_then(|payload| payload.get("structure"))
        .ok_or(PublicPackageInstallError::Input)?;
    let checkpoint =
        parse_wire_json_bounded(prior.checkpoint_canonical_json().as_bytes(), 32, 8192)
            .map_err(|_| PublicPackageInstallError::Input)?;
    let plan = plan_public_install_snapshot(prior.replay().objects(), contract, &checkpoint)?;
    let expected = canonical_wire_value(plan.snapshot(), CanonicalPath::SecureArtifact)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let saved = canonical_wire_value(saved_begin_snapshot, CanonicalPath::SecureArtifact)
        .map_err(|_| PublicPackageInstallError::Input)?;
    if expected != saved {
        return Err(PublicPackageInstallError::Input);
    }
    Ok(plan)
}

fn prove_saved_begin(
    journal: &SecureIntentJournal,
    command_id: &str,
    source: &TransportReplayedJournal,
    identity: &KernelIdentity,
) -> Result<Vec<u8>, PublicPackageInstallError> {
    let selection = journal.public_install_selection(command_id)?;
    if selection.prior_checkpoint_json != source.checkpoint_canonical_json() {
        return Err(PublicPackageInstallError::Input);
    }
    let closure = selection.closure_wire()?;
    let prior_policy = source
        .signed_policy_by_hash(source.replay().policy_hash())
        .ok_or(PublicPackageInstallError::Input)?;
    let saved = journal.exact_request(command_id)?;
    let parsed = parse_wire_json_bounded(&saved, 64, 262_144)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let issued_at = parsed
        .get("commit")
        .and_then(|commit| commit.get("payload"))
        .and_then(|payload| payload.get("issued_at"))
        .and_then(|value| value.as_number())
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .map(|value| value as u64)
        .ok_or(PublicPackageInstallError::Input)?;
    let regenerated = prepare_public_package_install_begin_with_bindings(
        &closure,
        selection.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
        &selection.package_digest,
        &selection.protocol_digest,
        prior_policy,
        source.checkpoint_canonical_json().as_bytes(),
        source.replay().objects(),
        selection.grants_json.as_bytes(),
        &selection.instance_id,
        &selection.entrypoint,
        command_id,
        issued_at,
        identity.signing_key(),
    )?;
    if regenerated.request_wire() != saved
        || regenerated.package_id() != selection.package_id
        || regenerated.package_version() != selection.package_version
        || regenerated.commit_hash() != journal.intent_digest(command_id)?
    {
        return Err(PublicPackageInstallError::Input);
    }
    Ok(saved)
}

fn reprove_completed_install(
    journal: &SecureIntentJournal,
    begin_command_id: &str,
    accepted: &AcceptedPublicInstall,
    fresh: &TransportReplayedJournal,
) -> Result<PublicPackageInstallProgress, PublicPackageInstallError> {
    let selection = journal.public_install_selection(begin_command_id)?;
    if accepted.begin_command_id != begin_command_id
        || accepted.workspace_id != fresh.replay().workspace_id()
        || accepted.instance_id != selection.instance_id
        || accepted.package_digest != selection.package_digest
        || accepted.protocol_digest != selection.protocol_digest
        || accepted.end_command_id != install_step_id(begin_command_id, 0, true)
        || journal.intent_digest(&accepted.end_command_id)? != accepted.end_commit_hash
    {
        return Err(PublicPackageInstallError::Input);
    }
    let prior_checkpoint =
        parse_wire_json_bounded(selection.prior_checkpoint_json.as_bytes(), 32, 8192)
            .map_err(|_| PublicPackageInstallError::Input)?;
    let prior_sequence = prior_checkpoint
        .get("sequence")
        .and_then(WireValue::as_number)
        .filter(|n| n.is_finite() && *n >= 0.0 && n.fract() == 0.0)
        .map(|n| n as u64)
        .ok_or(PublicPackageInstallError::Input)?;
    let begin_sequence = prior_sequence
        .checked_add(1)
        .ok_or(PublicPackageInstallError::Input)?;
    let saved_begin = journal.exact_request(begin_command_id)?;
    let begin = parse_wire_json_bounded(&saved_begin, 64, 262_144)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let policy = begin
        .get("policy_update")
        .ok_or(PublicPackageInstallError::Input)?;
    let policy_hash = sha256_hex(
        canonical_wire_value(policy, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicPackageInstallError::Input)?
            .as_bytes(),
    );
    if !fresh.replay().contains_checkpoint(
        begin_sequence,
        Some(journal.intent_digest(begin_command_id)?),
        &policy_hash,
    ) || !fresh.replay().contains_checkpoint(
        accepted.sequence,
        Some(&accepted.end_commit_hash),
        &policy_hash,
    ) {
        return Err(PublicPackageInstallError::Input);
    }
    Ok(PublicPackageInstallProgress {
        status: "ACCEPTED",
        begin_command_id: begin_command_id.to_owned(),
        step_command_id: accepted.end_command_id.clone(),
        step_action_id: "secure.structure.end",
        workspace_id: accepted.workspace_id.clone(),
        package_digest: accepted.package_digest.clone(),
        protocol_digest: accepted.protocol_digest.clone(),
        instance_id: accepted.instance_id.clone(),
        commit_hash: accepted.end_commit_hash.clone(),
    })
}

fn accept_completed_install(
    journal: &mut SecureIntentJournal,
    begin_command_id: &str,
    selection: &PublicInstallSelection,
    saved_begin: &[u8],
    snapshot: &WireValue,
    begin_policy_hash: &str,
    prior: &TransportReplayedJournal,
    fresh: &TransportReplayedJournal,
    identity: &KernelIdentity,
) -> Result<PublicPackageInstallProgress, PublicPackageInstallError> {
    let begin_hash = journal.intent_digest(begin_command_id)?.to_owned();
    let begin_sequence = prior
        .replay()
        .sequence()
        .checked_add(1)
        .ok_or(PublicPackageInstallError::Input)?;
    if fresh.replay().structure_status() != StructureStatus::Active
        || !fresh
            .replay()
            .contains_checkpoint(begin_sequence, Some(&begin_hash), begin_policy_hash)
    {
        return Err(PublicPackageInstallError::Input);
    }
    let begin = parse_wire_json_bounded(saved_begin, 64, 262_144)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let begin_operation = begin
        .get("commit")
        .and_then(|value| value.get("payload"))
        .and_then(|value| value.get("body"))
        .ok_or(PublicPackageInstallError::Input)?;
    let begin_operation_wire = canonical_wire_value(begin_operation, CanonicalPath::SecureArtifact)
        .map_err(|_| PublicPackageInstallError::Input)?;
    if !fresh.replay().operations().iter().any(|operation| {
        canonical_wire_value(operation, CanonicalPath::SecureArtifact)
            .is_ok_and(|wire| wire == begin_operation_wire)
    }) {
        return Err(PublicPackageInstallError::Input);
    }
    let closure = selection.closure_wire()?;
    let compiled = compile_public_package_closure_with_bindings(
        &closure,
        selection.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
    )?;
    if compiled.package_id() != selection.package_id
        || compiled.package_version() != selection.package_version
        || compiled.package_digest() != selection.package_digest
        || compiled.protocol_digest() != selection.protocol_digest
    {
        return Err(PublicPackageInstallError::Input);
    }
    let manifest = parse_wire_json_bounded(compiled.manifest_wire(), 64, 2_000_000)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let same = |a: &WireValue, b: &WireValue| match (
        canonical_wire_value(a, CanonicalPath::SecureArtifact),
        canonical_wire_value(b, CanonicalPath::SecureArtifact),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    };
    let protocol_found = fresh.replay().objects().iter().any(|object| {
        object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
            && object.get("id").and_then(WireValue::as_string).as_deref()
                == Some(selection.protocol_digest.as_str())
            && object.get("value").is_some_and(|value| {
                value
                    .get("workspace_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(fresh.replay().workspace_id())
                    && value
                        .get("manifest")
                        .is_some_and(|stored| same(stored, &manifest))
                    && value
                        .get("resolved_manifest")
                        .is_some_and(|stored| same(stored, &manifest))
            })
    });
    let instance_found = fresh.replay().objects().iter().any(|object| {
        object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
            && object.get("id").and_then(WireValue::as_string).as_deref()
                == Some(selection.instance_id.as_str())
            && object.get("value").is_some_and(|value| {
                value
                    .get("workspace_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(fresh.replay().workspace_id())
                    && value
                        .get("protocol_digest")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some(selection.protocol_digest.as_str())
                    && value
                        .get("origin_entrypoint")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some(selection.entrypoint.as_str())
                    && value
                        .get("state")
                        .zip(manifest.get("initial_state"))
                        .is_some_and(|(stored, expected)| same(stored, expected))
            })
    });
    if !protocol_found || !instance_found {
        return Err(PublicPackageInstallError::Input);
    }
    let policy = fresh
        .signed_policy_by_hash(begin_policy_hash)
        .ok_or(PublicPackageInstallError::Input)?;
    let plan = prove_snapshot_plan(prior, policy, snapshot)?;
    let mut offset = 0usize;
    let mut sequence = begin_sequence;
    let mut previous_hash = begin_hash;
    let mut page_ids = Vec::new();
    let (end_command_id, end_hash, end_sequence) = loop {
        let done = offset == snapshot_total(&plan);
        let step_id = install_step_id(begin_command_id, offset, done);
        let saved = journal.exact_request(&step_id)?;
        let parsed = parse_wire_json_bounded(&saved, 64, 262_144)
            .map_err(|_| PublicPackageInstallError::Input)?;
        let issued_at = parsed
            .get("commit")
            .and_then(|commit| commit.get("payload"))
            .and_then(|payload| payload.get("issued_at"))
            .and_then(WireValue::as_number)
            .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
            .map(|number| number as u64)
            .ok_or(PublicPackageInstallError::Input)?;
        let checkpoint = serde_json::json!({
            "v":1,
            "workspace_id":fresh.replay().workspace_id(),
            "owner_id":fresh.replay().owner_actor_id(),
            "owner_key":fresh.replay().owner_signing_key(),
            "sequence":sequence,
            "head":previous_hash,
            "policy_hash":begin_policy_hash,
        });
        let checkpoint_wire =
            serde_json::to_vec(&checkpoint).map_err(|_| PublicPackageInstallError::Input)?;
        let step_snapshot = snapshot_with_offset(snapshot, offset)?;
        let reproved = sign_public_install_step(
            policy,
            &checkpoint_wire,
            &step_snapshot,
            &plan,
            &step_id,
            issued_at,
            identity.signing_key(),
        )?;
        let step_hash = journal.intent_digest(&step_id)?.to_owned();
        if reproved.request_wire() != saved
            || reproved.commit_hash() != step_hash
            || reproved.action_id()
                != if done {
                    "secure.structure.end"
                } else {
                    "secure.structure.page"
                }
        {
            return Err(PublicPackageInstallError::Input);
        }
        sequence = sequence
            .checked_add(1)
            .ok_or(PublicPackageInstallError::Input)?;
        if !fresh
            .replay()
            .contains_checkpoint(sequence, Some(&step_hash), begin_policy_hash)
        {
            return Err(PublicPackageInstallError::Input);
        }
        if done {
            break (step_id, step_hash, sequence);
        }
        page_ids.push(step_id);
        previous_hash = step_hash;
        offset += snapshot_page_len(&plan, offset)?;
    };
    journal.accept_public_install(AcceptedPublicInstall {
        begin_command_id: begin_command_id.to_owned(),
        end_command_id: end_command_id.clone(),
        page_command_ids: page_ids,
        workspace_id: fresh.replay().workspace_id().to_owned(),
        instance_id: selection.instance_id.clone(),
        package_digest: selection.package_digest.clone(),
        protocol_digest: selection.protocol_digest.clone(),
        sequence: end_sequence,
        end_commit_hash: end_hash.clone(),
    })?;
    Ok(PublicPackageInstallProgress {
        status: "ACCEPTED",
        begin_command_id: begin_command_id.to_owned(),
        step_command_id: end_command_id,
        step_action_id: "secure.structure.end",
        workspace_id: fresh.replay().workspace_id().to_owned(),
        package_digest: selection.package_digest.clone(),
        protocol_digest: selection.protocol_digest.clone(),
        instance_id: selection.instance_id.clone(),
        commit_hash: end_hash,
    })
}

fn random_id() -> Result<String, PublicPackageInstallError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PublicPackageInstallError::Entropy)?;
    Ok(base64url(&bytes))
}

fn current_time_ms() -> Result<u64, PublicPackageInstallError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .map_err(|_| PublicPackageInstallError::Input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_action_access::{PublicActionInput, SecurePublicActionAccess};
    use std::{
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[tokio::test]
    async fn actual_service_public_install_begin_is_saved_before_uncertain_reply() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
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
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .env("PEERWORK_TEST_FIRST_POST_MODE", "drop")
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
        assert!(!line.is_empty(), "reference service did not become ready");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let fixture = &ready["public_read"];
        let identity_path = root.path().join("owner.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &root.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), fixture["actor_id"].as_str().unwrap());
        let config = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: root.path().join("profile"),
            identity_path,
            workspace_id: fixture["workspace_id"].as_str().unwrap().into(),
            owner_actor_id: Some(identity.actor_id().into()),
            owner_key_id: Some(identity.key_id().into()),
            authority: Some(fixture["authority"].as_str().unwrap().into()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        drop(identity);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let closure = vectors["closure"].to_string();
        let digest = vectors["protocol_digest"].as_str().unwrap().to_owned();
        let package_digest = vectors["package_digest"].as_str().unwrap().to_owned();
        let reject = reqwest::Client::new()
            .post(format!("{origin}__test/reject-next-post-before-apply"))
            .send()
            .await
            .unwrap();
        assert_eq!(reject.status(), reqwest::StatusCode::OK);
        let submit_config = config.clone();
        let result = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(submit_config).submit_begin_json(
                PublicPackageInstallInput {
                    closure_json: closure,
                    bindings_json: None,
                    expected_package_id: "peerwork-proposal-adoption".into(),
                    expected_package_version: "1.0.0".into(),
                    expected_package_digest: package_digest,
                    expected_protocol_digest: digest,
                    instance_id: "z".repeat(43),
                    entrypoint: "proposalAdoption".into(),
                    grants_json: "[]".into(),
                    command_id: Some("c".repeat(43)),
                    issued_at_ms: None,
                },
            )
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(matches!(
            result,
            PublicPackageInstallError::ServerRejected(503)
        ));
        let listed_config = config.clone();
        let pending = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(listed_config).list_pending_json()
        })
        .await
        .unwrap()
        .unwrap();
        let pending: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(pending.as_array().unwrap().len(), 1);
        assert_eq!(pending[0]["begin_command_id"], "c".repeat(43));
        assert_eq!(pending[0]["pending_action_id"], "secure.structure.begin");
        assert_eq!(pending[0]["package_id"], "peerwork-proposal-adoption");
        assert!(pending[0].get("exact_request").is_none());
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["head_sequence"], 1);
        let retry_config = config.clone();
        let result = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(retry_config)
                .continue_empty_snapshot_json(&"c".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let result: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(result["status"], "PENDING");
        assert_eq!(result["step_action_id"], "secure.structure.begin");
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["head_sequence"], 2);
        assert_eq!(counts["head_hash"], result["commit_hash"]);
        let reopened = SecureIntentJournal::open(
            &config.state_dir.join("install-intents.state"),
            &origin,
            fixture["actor_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.pending().len(), 1);
        assert_eq!(
            reopened
                .public_install_selection("c".repeat(43).as_str())
                .unwrap()
                .package_digest,
            vectors["package_digest"]
        );
        drop(reopened);
        let listed_config = config.clone();
        let pending = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(listed_config).list_pending_json()
        })
        .await
        .unwrap()
        .unwrap();
        let pending: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(pending[0]["pending_action_id"], "secure.structure.begin");
        let drop_end = reqwest::Client::new()
            .post(format!("{origin}__test/drop-next-post"))
            .send()
            .await
            .unwrap();
        assert_eq!(drop_end.status(), reqwest::StatusCode::OK);
        let continue_config = config.clone();
        let continued = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(continue_config)
                .continue_empty_snapshot_json(&"c".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let continued: serde_json::Value = serde_json::from_str(&continued).unwrap();
        assert_eq!(continued["status"], "PENDING");
        assert_eq!(continued["step_action_id"], "secure.structure.end");
        let listed_config = config.clone();
        let pending = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(listed_config).list_pending_json()
        })
        .await
        .unwrap()
        .unwrap();
        let pending: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(pending[0]["pending_action_id"], "secure.structure.end");
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["head_sequence"], 3);
        assert_eq!(counts["head_hash"], continued["commit_hash"]);
        let accept_config = config.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(accept_config)
                .continue_empty_snapshot_json(&"c".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(&accepted).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        assert_eq!(accepted["commit_hash"], continued["commit_hash"]);
        let settled = SecureIntentJournal::open(
            &config.state_dir.join("install-intents.state"),
            &origin,
            fixture["actor_id"].as_str().unwrap(),
        )
        .unwrap();
        assert!(settled.pending().is_empty());
        assert_eq!(
            settled
                .accepted_public_install(&"c".repeat(43))
                .unwrap()
                .unwrap()
                .end_commit_hash,
            continued["commit_hash"]
        );
        drop(settled);
        let listed_config = config.clone();
        let pending = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(listed_config).list_pending_json()
        })
        .await
        .unwrap()
        .unwrap();
        let pending: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert!(pending.as_array().unwrap().is_empty());
        let finished_config = config.clone();
        let finished = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(finished_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let finished: serde_json::Value = serde_json::from_str(&finished).unwrap();
        assert_eq!(finished["sequence"], 3);
        assert_eq!(finished["structure_status"], "ACTIVE");
        assert!(finished["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "instances" && object["id"] == "z".repeat(43)));
        let after_read_config = config.clone();
        let after_read = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(after_read_config)
                .continue_install_json(&"c".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let after_read: serde_json::Value = serde_json::from_str(&after_read).unwrap();
        assert_eq!(after_read["status"], "ACCEPTED");
        assert_eq!(after_read["commit_hash"], continued["commit_hash"]);

        // The installed STRUCTURED policy must remain usable by the public
        // native ACTION producer, including its exact server-readable DELTA.
        let action_config = config.clone();
        let preset_instance = fixture["instance_id"].as_str().unwrap().to_owned();
        let submitted = tokio::task::spawn_blocking(move || {
            SecurePublicActionAccess::new(action_config).submit_new_json(PublicActionInput {
                action_id: "discussion.post".into(),
                instance_id: preset_instance,
                body_json: r#"{"message":"structured public action after install"}"#.into(),
                exact_input_refs_json: None,
                allocations_json: None,
                command_id: Some("s".repeat(43)),
                issued_at_ms: None,
            })
        })
        .await
        .unwrap()
        .unwrap();
        let submitted: serde_json::Value = serde_json::from_str(&submitted).unwrap();
        assert_eq!(submitted["status"], "PENDING");
        let action_config = config.clone();
        let reconciled = tokio::task::spawn_blocking(move || {
            SecurePublicActionAccess::new(action_config).reconcile_json(&"s".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let reconciled: serde_json::Value = serde_json::from_str(&reconciled).unwrap();
        assert_eq!(reconciled["status"], "ACCEPTED");
        assert_eq!(reconciled["sequence"], 4);
        let receipt: serde_json::Value =
            serde_json::from_str(reconciled["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effects = receipt["effects"].as_array().unwrap();
        assert_eq!(effects.len(), 1);
        let record_id = effects[0]["record_id"].as_str().unwrap();
        let readback_config = config.clone();
        let readback = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(readback_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let readback: serde_json::Value = serde_json::from_str(&readback).unwrap();
        assert_eq!(readback["sequence"], 4);
        assert!(readback["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records" && object["id"] == record_id));
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["head_sequence"], 4);

        // A local pending ID remains discoverable when the service is gone.
        // The packet is synthetic because listing confers no acceptance.
        let identity = KernelIdentity::open(&config.identity_path).unwrap();
        let mut journal = SecureIntentJournal::open(
            &config.state_dir.join("install-intents.state"),
            &origin,
            identity.actor_id(),
        )
        .unwrap();
        let selection = journal
            .public_install_selection(&"c".repeat(43))
            .unwrap()
            .clone();
        let offline_id = "u".repeat(43);
        journal
            .prepare_public_install(
                SecurePacketInput {
                    intent_id: &offline_id,
                    path: &format!(
                        "/api/workspace/v1/secure/workspaces/{}/commits",
                        config.workspace_id
                    ),
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: &"a".repeat(64),
                    exact_request: br#"{"synthetic":"secret-install-packet"}"#,
                },
                selection,
            )
            .unwrap();
        drop(journal);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let offline = SecurePublicPackageInstall::new(config)
            .list_pending_json()
            .unwrap();
        assert!(!offline.contains("secret-install-packet"));
        let offline: serde_json::Value = serde_json::from_str(&offline).unwrap();
        assert_eq!(offline.as_array().unwrap().len(), 1);
        assert_eq!(offline[0]["begin_command_id"], offline_id);
        assert_eq!(offline[0]["workspace_id"], fixture["workspace_id"]);
    }

    #[tokio::test]
    async fn actual_service_public_install_pages_resume_after_uncertain_reply() {
        let (Ok(reference_root), Ok(_)) = (
            std::env::var("PEERWORK_REFERENCE_ROOT"),
            std::env::var("PEERWORK_TEST_NONEMPTY_INSTALL"),
        ) else {
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
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .env("PEERWORK_TEST_PUBLIC_INSTALL_PAGES", "1")
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
        assert!(!line.is_empty(), "nonempty reference fixture did not start");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let fixture = &ready["public_read"];
        assert_eq!(fixture["seeded_records"], 51);
        assert_eq!(fixture["seeded_heads"], 51);
        let identity_path = root.path().join("owner.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &root.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        let config = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: root.path().join("profile"),
            identity_path,
            workspace_id: fixture["workspace_id"].as_str().unwrap().into(),
            authority: Some(fixture["authority"].as_str().unwrap().into()),
            owner_actor_id: Some(identity.actor_id().into()),
            owner_key_id: Some(identity.key_id().into()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        drop(identity);
        let initial_config = config.clone();
        let initial = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(initial_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let initial: serde_json::Value = serde_json::from_str(&initial).unwrap();
        assert_eq!(initial["sequence"], 52);
        let ids_for = |value: &serde_json::Value, kind: &str| {
            let mut ids = value["objects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|object| object["kind"] == kind)
                .map(|object| object["id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            ids.sort();
            ids
        };
        let original_record_ids = ids_for(&initial, "records");
        let original_head_ids = ids_for(&initial, "entity_heads");
        assert_eq!(original_record_ids.len(), 51);
        assert_eq!(original_head_ids.len(), 51);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let submit_config = config.clone();
        let submitted = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(submit_config).submit_begin_json(
                PublicPackageInstallInput {
                    closure_json: vectors["closure"].to_string(),
                    bindings_json: None,
                    expected_package_id: "peerwork-proposal-adoption".into(),
                    expected_package_version: "1.0.0".into(),
                    expected_package_digest: vectors["package_digest"].as_str().unwrap().into(),
                    expected_protocol_digest: vectors["protocol_digest"].as_str().unwrap().into(),
                    instance_id: "z".repeat(43),
                    entrypoint: "proposalAdoption".into(),
                    grants_json: "[]".into(),
                    command_id: Some("b".repeat(43)),
                    issued_at_ms: None,
                },
            )
        })
        .await
        .unwrap()
        .unwrap();
        let submitted: serde_json::Value = serde_json::from_str(&submitted).unwrap();
        assert_eq!(submitted["status"], "PENDING");
        let reject = reqwest::Client::new()
            .post(format!("{origin}__test/reject-next-post-before-apply"))
            .send()
            .await
            .unwrap();
        assert_eq!(reject.status(), reqwest::StatusCode::OK);
        let retry_config = config.clone();
        let first = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(retry_config).continue_install_json(&"b".repeat(43))
        })
        .await
        .unwrap()
        .unwrap_err();
        assert!(matches!(
            first,
            PublicPackageInstallError::ServerRejected(503)
        ));
        let pending = SecurePublicPackageInstall::new(config.clone())
            .list_pending_json()
            .unwrap();
        let pending: serde_json::Value = serde_json::from_str(&pending).unwrap();
        assert_eq!(pending[0]["pending_action_id"], "secure.structure.page");
        let first_page_id = pending[0]["pending_step_id"].as_str().unwrap().to_owned();
        let retry_config = config.clone();
        let retried = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(retry_config).continue_install_json(&"b".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let retried: serde_json::Value = serde_json::from_str(&retried).unwrap();
        assert_eq!(retried["step_command_id"], first_page_id);
        assert_eq!(retried["step_action_id"], "secure.structure.page");
        let drop_reply = reqwest::Client::new()
            .post(format!("{origin}__test/drop-next-post"))
            .send()
            .await
            .unwrap();
        assert_eq!(drop_reply.status(), reqwest::StatusCode::OK);
        let mut steps = Vec::new();
        for _ in 0..4 {
            let next_config = config.clone();
            let result = tokio::task::spawn_blocking(move || {
                SecurePublicPackageInstall::new(next_config).continue_install_json(&"b".repeat(43))
            })
            .await
            .unwrap()
            .unwrap();
            let result: serde_json::Value = serde_json::from_str(&result).unwrap();
            steps.push(result);
        }
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["step_action_id"] == "secure.structure.page")
                .count(),
            3
        );
        assert_eq!(
            steps.last().unwrap()["step_action_id"],
            "secure.structure.end"
        );
        let accept_config = config.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(accept_config).continue_install_json(&"b".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(&accepted).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let read_config = config.clone();
        let readback = tokio::task::spawn_blocking(move || {
            SecureReadProfile::new(read_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let readback: serde_json::Value = serde_json::from_str(&readback).unwrap();
        assert_eq!(readback["sequence"], 58);
        assert_eq!(readback["structure_status"], "ACTIVE");
        assert_eq!(ids_for(&readback, "records"), original_record_ids);
        assert_eq!(ids_for(&readback, "entity_heads"), original_head_ids);
        let repeat_config = config.clone();
        let repeated = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(repeat_config).continue_install_json(&"b".repeat(43))
        })
        .await
        .unwrap()
        .unwrap();
        let repeated: serde_json::Value = serde_json::from_str(&repeated).unwrap();
        assert_eq!(repeated["status"], "ACCEPTED");
        assert_eq!(repeated["commit_hash"], accepted["commit_hash"]);
        let pending = SecurePublicPackageInstall::new(config.clone())
            .list_pending_json()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&pending).unwrap(),
            serde_json::json!([])
        );
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["head_sequence"], 58);
    }
}

#[cfg(test)]
mod selected_binding_service_test {
    use super::*;
    use crate::{
        secure_action_access::PublicActionInput,
        secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerCreateInput, SecureOwnerWorkspaceCreate},
    };
    use std::{
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_public_selected_binding_allows_guarded_vote() {
        if std::env::var("PEERWORK_TEST_PUBLIC_SELECTED_BINDING").as_deref() != Ok("1") {
            return;
        }
        let reference_root = std::env::var("PEERWORK_REFERENCE_ROOT").unwrap();
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = Path::new(env!("CARGO_MANIFEST_DIR"))
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
        let owner = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            origin: origin.clone(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        let token = CancellationToken::new();
        let created = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native PUBLIC selected binding".into(),
                    name_utf16: None,
                    visibility: "PUBLIC".into(),
                    structured: true,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        assert_eq!(owner.resume(&created.command_id, &token).unwrap().status, "CREATED");
        let install = owner.public_install_access(&created.workspace_id).unwrap();
        let actor = KernelIdentity::open(&install.config.identity_path)
            .unwrap()
            .actor_id()
            .to_owned();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/private-package-options-reference.json"
        ))
        .unwrap();
        let binding = &fixture["binding"];
        let selected_digest = binding["selected_protocol_digest"].as_str().unwrap();
        assert_ne!(binding["default_protocol_digest"], binding["selected_protocol_digest"]);
        let instance_id = random_id().unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &install
                .submit_begin_json(PublicPackageInstallInput {
                    closure_json: binding["closure"].to_string(),
                    bindings_json: Some(binding["selected_bindings"].to_string()),
                    expected_package_id: "binding-option".into(),
                    expected_package_version: "1.0.0".into(),
                    expected_package_digest: binding["root_package_digest"].as_str().unwrap().into(),
                    expected_protocol_digest: selected_digest.into(),
                    instance_id: instance_id.clone(),
                    entrypoint: "binding".into(),
                    grants_json: serde_json::json!([{
                        "actor_id": actor,
                        "actions": ["vote"],
                        "protocol_roles": ["AUTHOR"],
                        "capabilities": []
                    }])
                    .to_string(),
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let begin_id = submitted["command_id"].as_str().unwrap().to_owned();
        let mut progress = submitted;
        for _ in 0..8 {
            if progress["status"] == "ACCEPTED" {
                break;
            }
            progress = serde_json::from_str(&install.continue_install_json(&begin_id).unwrap())
                .unwrap();
        }
        assert_eq!(progress["status"], "ACCEPTED");
        let installed: serde_json::Value = serde_json::from_str(
            &owner.read_workspace_json(&created.workspace_id, &token).unwrap(),
        )
        .unwrap();
        assert!(installed["objects"].as_array().unwrap().iter().any(|row|
            row["kind"] == "protocols" && row["id"] == selected_digest));
        assert!(installed["objects"].as_array().unwrap().iter().any(|row|
            row["kind"] == "instances" && row["id"] == instance_id
                && row["value"]["protocol_digest"] == selected_digest));
        let counts = || {
            Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await.unwrap().bytes().await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["commits"]
                    .as_u64().unwrap()
            })
        };
        let before_retry = counts();
        assert_eq!(serde_json::from_str::<serde_json::Value>(
            &install.continue_install_json(&begin_id).unwrap()).unwrap(), progress);
        assert_eq!(counts(), before_retry);
        // The same package without the selected binding guards vote with
        // REVIEWER. This Owner has only an instance AUTHOR grant, so the
        // source's default variant must fail native guard preparation without
        // a secure commit. The preparer executes the pinned role guard before
        // signing or posting an action packet.
        let default_instance_id = random_id().unwrap();
        let default_begin: serde_json::Value = serde_json::from_str(
            &install.submit_begin_json(PublicPackageInstallInput {
                closure_json: binding["closure"].to_string(),
                bindings_json: None,
                expected_package_id: "binding-option".into(),
                expected_package_version: "1.0.0".into(),
                expected_package_digest: binding["root_package_digest"].as_str().unwrap().into(),
                expected_protocol_digest: binding["default_protocol_digest"].as_str().unwrap().into(),
                instance_id: default_instance_id.clone(),
                entrypoint: "binding".into(),
                grants_json: serde_json::json!([{
                    "actor_id": actor,
                    "actions": ["vote"],
                    "protocol_roles": ["AUTHOR"],
                    "capabilities": []
                }]).to_string(),
                command_id: None,
                issued_at_ms: None,
            }).unwrap(),
        ).unwrap();
        let default_id = default_begin["command_id"].as_str().unwrap().to_owned();
        let mut default_progress = default_begin;
        for _ in 0..8 {
            if default_progress["status"] == "ACCEPTED" { break; }
            default_progress = serde_json::from_str(
                &install.continue_install_json(&default_id).unwrap()).unwrap();
        }
        assert_eq!(default_progress["status"], "ACCEPTED");
        let action = owner.public_action_access(&created.workspace_id).unwrap();
        let before_rejected_vote = counts();
        let rejected = action.submit_new_json(PublicActionInput {
            action_id: "vote".into(),
            instance_id: default_instance_id,
            body_json: "{}".into(),
            exact_input_refs_json: None,
            allocations_json: None,
            command_id: None,
            issued_at_ms: None,
        });
        assert!(matches!(&rejected,
            Err(crate::secure_action_access::PublicActionError::Prepare)),
            "unexpected default-guard result: {rejected:?}");
        assert_eq!(counts(), before_rejected_vote);
        let submitted: serde_json::Value = serde_json::from_str(
            &action.submit_new_json(PublicActionInput {
                action_id: "vote".into(),
                instance_id: instance_id.clone(),
                body_json: "{}".into(),
                exact_input_refs_json: None,
                allocations_json: None,
                command_id: None,
                issued_at_ms: None,
            }).unwrap(),
        ).unwrap();
        let action_id = submitted["command_id"].as_str().unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &action.retry_saved_json(action_id).unwrap(),
        ).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        assert_eq!(counts(), before_rejected_vote + 1);
        let read: serde_json::Value = serde_json::from_str(
            &owner.read_workspace_json(&created.workspace_id, &token).unwrap(),
        ).unwrap();
        let instance = read["objects"].as_array().unwrap().iter()
            .find(|row| row["kind"] == "instances" && row["id"] == instance_id)
            .unwrap();
        assert_eq!(instance["value"]["protocol_digest"], selected_digest);
        assert_eq!(instance["value"]["state"]["count"], 1);
        let before_action_retry = counts();
        assert_eq!(serde_json::from_str::<serde_json::Value>(
            &action.retry_saved_json(action_id).unwrap()).unwrap(), accepted);
        assert_eq!(counts(), before_action_retry);
    }
}
