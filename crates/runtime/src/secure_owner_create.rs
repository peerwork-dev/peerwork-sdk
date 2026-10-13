//! Native Owner workspace creation from the pinned collaboration presets.
//! Generated IDs and exact signed BOOTSTRAP are protected before POST. A
//! response or local key never establishes CREATED: complete signed replay
//! and the ordinary protected read profile must both verify first.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_action_access::{SecurePrivateActionAccess, SecurePublicActionAccess},
    secure_intents::{SecureIntentError, SecureIntentJournal},
    secure_journal_read::SecureJournalRead,
    secure_lifecycle::SecureLifecycle,
    secure_native_prepare::{
        owner_objects_wire, owner_operation_wire, prepare_coordinated_private_owner_workspace,
        prepare_coordinated_public_owner_workspace_with_options,
        prepare_owner_workspace_with_utf16_name, prepare_private_owner_workspace_with_options,
        prepare_public_owner_workspace_with_options, NativePrepareError,
    },
    secure_owner_attach::{HistoricalOwnerAttachError, SecureHistoricalOwnerAttach},
    secure_owner_format_transition::SecureOwnerFormatTransition,
    secure_public_admission::{SecurePrivateAdmission, SecurePublicAdmission},
    secure_public_install::SecurePublicPackageInstall,
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_recipient_enrollment::{RecipientEnrollmentConfig, SecureRecipientEnrollment},
    secure_recipient_state::RecipientState,
    secure_state::SecureStateStore,
    secure_verified_read::{replay_authenticated_pages_with_budget, SecureJournalReadBudget},
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    bootstrap_objects::{
        owner_bootstrap_objects_with_coordination, owner_bootstrap_objects_with_visibility,
    },
    crypto::{base64url, sha256_hex},
    genesis_structure_policy::{
        derive_genesis_structure_policy_with_coordination_and_keep_encrypted,
        derive_genesis_structure_policy_with_keep_encrypted,
    },
    prepared_secure_bootstrap::{verify_prepared_owner_bootstrap, BootstrapPins},
    replayed_secure_journal::StructureStatus,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

const MAX_HISTORY: usize = 4096;
const MAX_DOCUMENT: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureOwnerCreateConfig {
    pub origin: String,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default = "default_budget")]
    pub max_replay_artifact_bytes: u64,
}

fn default_budget() -> u64 {
    SecureJournalReadBudget::default().max_replay_artifact_bytes
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecureOwnerCreateInput {
    pub name: String,
    /// Exact JavaScript UTF-16 for a name containing unpaired surrogates.
    /// When present, `name` must be empty; wrappers derive this internally.
    #[serde(default)]
    pub name_utf16: Option<Vec<u16>>,
    pub visibility: String,
    #[serde(default)]
    pub structured: bool,
    #[serde(default = "empty_keep_encrypted")]
    pub keep_encrypted_json: String,
    #[serde(default)]
    pub coordination_version: Option<u8>,
}

fn empty_keep_encrypted() -> String {
    "[]".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecureOwnerCreateResult {
    pub status: String,
    pub command_id: String,
    pub workspace_id: String,
    pub visibility: String,
    pub sequence: Option<u64>,
    pub head: Option<String>,
}

#[derive(Debug, Error)]
pub enum SecureOwnerCreateError {
    #[error("owner-create input or protected history is invalid")]
    Invalid,
    #[error("protected owner identity or origin changed")]
    Identity,
    #[error("owner-create operation was not found")]
    NotFound,
    #[error("attached Owner package stage requires explicit saved-command recovery")]
    PendingPackageStageUnresolved,
    #[error("owner-create local resource limit exceeded")]
    ResourceLimit,
    #[error("owner-create local state failed")]
    Local,
    #[error("owner enrollment or directory publication failed")]
    Enrollment,
    #[error("saved owner bootstrap failed source verification")]
    Bootstrap,
    #[error("complete signed owner journal or read profile did not verify")]
    Verification,
    #[error("owner-create transport failed")]
    Transport,
    #[error("owner-create was cancelled; recover by command ID or list")]
    Cancelled,
    #[error("server rejected owner bootstrap with HTTP {0}")]
    ServerRejected(u16),
}

impl SecureOwnerCreateError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "INPUT_INVALID",
            Self::Identity => "IDENTITY_CHANGED",
            Self::NotFound => "NOT_FOUND",
            Self::PendingPackageStageUnresolved => "PENDING_PACKAGE_STAGE_UNRESOLVED",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::Local => "LOCAL_STATE_FAILED",
            Self::Enrollment => "ENROLLMENT_FAILED",
            Self::Bootstrap => "BOOTSTRAP_INVALID",
            Self::Verification => "VERIFICATION_FAILED",
            Self::Transport => "TRANSPORT_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::ServerRejected(_) => "SERVER_REJECTED",
        }
    }
}

impl From<SecureReadAccessError> for SecureOwnerCreateError {
    fn from(_: SecureReadAccessError) -> Self {
        Self::Verification
    }
}

fn map_attach_error(error: HistoricalOwnerAttachError) -> SecureOwnerCreateError {
    match error {
        HistoricalOwnerAttachError::NotFound => SecureOwnerCreateError::NotFound,
        HistoricalOwnerAttachError::PendingPackageStageUnresolved =>
            SecureOwnerCreateError::PendingPackageStageUnresolved,
        HistoricalOwnerAttachError::Identity => SecureOwnerCreateError::Identity,
        HistoricalOwnerAttachError::Cancelled => SecureOwnerCreateError::Cancelled,
        HistoricalOwnerAttachError::Local => SecureOwnerCreateError::Local,
        _ => SecureOwnerCreateError::Verification,
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedCreate {
    workspace_id: String,
    created: u64,
    instance_ids: Vec<String>,
    input: SecureOwnerCreateInput,
    created_sequence: Option<u64>,
    created_head: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerHistory {
    version: u8,
    origin: String,
    actor_id: String,
    signing_key_id: String,
    rows: BTreeMap<String, SavedCreate>,
}

pub struct SecureOwnerWorkspaceCreate {
    config: SecureOwnerCreateConfig,
}

impl SecureOwnerWorkspaceCreate {
    pub fn new(config: SecureOwnerCreateConfig) -> Self {
        Self { config }
    }

    pub(crate) fn has_saved_workspace_for_attach(
        &self,
        workspace_id: &str,
        identity: &KernelIdentity,
    ) -> Result<bool, SecureOwnerCreateError> {
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let history = read_history(&store, &self.config, identity)?;
        Ok(history
            .rows
            .values()
            .any(|row| row.workspace_id == workspace_id))
    }

    /// Reuse the saved Owner identity and per-workspace verified profile for
    /// ordinary PUBLIC action authoring. The returned facade still requires
    /// a fresh complete signed replay before preparing an ACTION.
    pub fn public_action_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecurePublicActionAccess, SecureOwnerCreateError> {
        Ok(SecurePublicActionAccess::new(
            self.created_profile_config(workspace_id, "PUBLIC")?,
        ))
    }

    pub fn private_action_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecurePrivateActionAccess, SecureOwnerCreateError> {
        Ok(SecurePrivateActionAccess::new(
            self.created_profile_config(workspace_id, "PRIVATE")?,
        ))
    }

    /// PUBLIC custom protocol installation consumes this same Owner profile;
    /// the install facade separately validates the selected package closure,
    /// signed BEGIN/PAGE/END and completed structure replay.
    pub fn public_install_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecurePublicPackageInstall, SecureOwnerCreateError> {
        Ok(SecurePublicPackageInstall::new(
            self.created_profile_config(workspace_id, "PUBLIC")?,
        ))
    }

    /// Select PRIVATE package installation through a protected CREATED
    /// workspace row. Staging and install continuation perform their own
    /// complete replay, active-key, and exact saved-command checks.
    pub fn private_install_access(
        &self,
        workspace_id: &str,
    ) -> Result<crate::secure_private_install::SecurePrivatePackageInstall, SecureOwnerCreateError>
    {
        Ok(
            crate::secure_private_install::SecurePrivatePackageInstall::new(
                self.created_profile_config(workspace_id, "PRIVATE")?,
            ),
        )
    }

    /// Select a protected PRIVATE Owner workspace for an explicit signed
    /// format transition. The transition itself replays the latest journal
    /// and refuses pending local key or saved-command state.
    pub fn private_format_transition_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecureOwnerFormatTransition, SecureOwnerCreateError> {
        Ok(SecureOwnerFormatTransition::new(
            self.created_profile_config(workspace_id, "PRIVATE")?,
        ))
    }

    /// Select Owner format transitions from a protected CREATED or ATTACHED
    /// workspace binding. The selected visibility is never caller supplied.
    pub fn format_transition_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecureOwnerFormatTransition, SecureOwnerCreateError> {
        let private = self.created_profile_config(workspace_id, "PRIVATE");
        let public = self.created_profile_config(workspace_id, "PUBLIC");
        match (private, public) {
            (Ok(_), Ok(_)) => Err(SecureOwnerCreateError::Invalid),
            (Ok(config), Err(SecureOwnerCreateError::NotFound)) => {
                Ok(SecureOwnerFormatTransition::new(config))
            }
            (Err(SecureOwnerCreateError::NotFound), Ok(config)) => {
                Ok(SecureOwnerFormatTransition::new_public(config))
            }
            (Err(SecureOwnerCreateError::NotFound), Err(SecureOwnerCreateError::NotFound)) => {
                let attached = SecureHistoricalOwnerAttach::new(self.config.clone());
                let private = attached.restricted_format_profile_config(workspace_id, "PRIVATE");
                let public = attached.restricted_format_profile_config(workspace_id, "PUBLIC");
                match (private, public) {
                    (Ok(_), Ok(_)) => Err(SecureOwnerCreateError::Invalid),
                    (Ok((config, id)), Err(HistoricalOwnerAttachError::NotFound)) => {
                        Ok(SecureOwnerFormatTransition::new_restricted(
                            config,
                            "PRIVATE",
                            self.config.clone(),
                            id,
                        ))
                    }
                    (Err(HistoricalOwnerAttachError::NotFound), Ok((config, id))) => {
                        Ok(SecureOwnerFormatTransition::new_restricted(
                            config,
                            "PUBLIC",
                            self.config.clone(),
                            id,
                        ))
                    }
                    (Err(HistoricalOwnerAttachError::NotFound), Err(HistoricalOwnerAttachError::NotFound)) => {
                        Err(SecureOwnerCreateError::NotFound)
                    }
                    (Err(error), _) | (_, Err(error)) => Err(map_attach_error(error)),
                }
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    /// Invite and deliver for an Owner-created PUBLIC workspace using the
    /// verified, protected Owner profile selected by its public workspace ID.
    /// Recipient identity and consent remain separate admission checks.
    pub fn public_admission_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecurePublicAdmission, SecureOwnerCreateError> {
        Ok(SecurePublicAdmission::new(
            self.created_profile_config(workspace_id, "PUBLIC")?,
        ))
    }

    /// Select PRIVATE Owner admission through the protected CREATED workspace
    /// row. No caller-supplied local key or internal profile path is accepted.
    pub fn private_admission_access(
        &self,
        workspace_id: &str,
    ) -> Result<SecurePrivateAdmission, SecureOwnerCreateError> {
        Ok(SecurePrivateAdmission::new(
            self.created_profile_config(workspace_id, "PRIVATE")?,
        ))
    }

    fn created_profile_config(
        &self,
        workspace_id: &str,
        visibility: &str,
    ) -> Result<SecureReadProfileConfig, SecureOwnerCreateError> {
        let identity = KernelIdentity::open(&self.identity_path())
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let history = read_history(&store, &self.config, &identity)?;
        if history.rows.values().any(|row| {
            row.workspace_id == workspace_id
                && row.input.visibility == visibility
                && row.created_sequence.is_some()
        }) {
            return Ok(self.profile_config(workspace_id, identity.actor_id(), identity.key_id()));
        }
        if history
            .rows
            .values()
            .any(|row| row.workspace_id == workspace_id)
        {
            return Err(SecureOwnerCreateError::NotFound);
        }
        drop(history);
        drop(store);
        drop(identity);
        SecureHistoricalOwnerAttach::new(self.config.clone())
            .attached_profile_config(workspace_id, visibility)
            .map_err(map_attach_error)
    }

    /// Explicit local preparation also performs the previously requested
    /// identity registration/directory publication. It does not POST the
    /// workspace. The returned generated ID remains in protected history.
    pub fn prepare(
        &self,
        input: SecureOwnerCreateInput,
        cancel: &CancellationToken,
    ) -> Result<SecureOwnerCreateResult, SecureOwnerCreateError> {
        validate_input(&input)?;
        if cancel.is_cancelled() {
            return Err(SecureOwnerCreateError::Cancelled);
        }
        let enrollment = self.enrollment();
        enrollment
            .create_local()
            .map_err(|_| SecureOwnerCreateError::Enrollment)?;
        let published = enrollment
            .publish_with_cancel(cancel)
            .map_err(|_| SecureOwnerCreateError::Enrollment)?;
        if published.status != "PUBLISHED" {
            return Err(SecureOwnerCreateError::Enrollment);
        }
        let identity = KernelIdentity::open(&self.identity_path())
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let recipient = RecipientState::open(&self.recipient_path(), &identity)
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let mut history = read_history(&store, &self.config, &identity)?;
        if history.rows.len() >= MAX_HISTORY {
            return Err(SecureOwnerCreateError::ResourceLimit);
        }
        let mut command = random_token();
        while history.rows.contains_key(&command) {
            command = random_token();
        }
        let mut workspace = random_token();
        while workspace == command
            || history
                .rows
                .values()
                .any(|row| row.workspace_id == workspace)
        {
            workspace = random_token();
        }
        let mut used = std::collections::HashSet::from([workspace.clone(), command.clone()]);
        let instance_count = if input.coordination_version.is_some() {
            7
        } else {
            6
        };
        let mut instance_ids = Vec::with_capacity(instance_count);
        for _ in 0..instance_count {
            let mut instance = random_token();
            while !used.insert(instance.clone()) {
                instance = random_token();
            }
            instance_ids.push(instance);
        }
        let row = SavedCreate {
            workspace_id: workspace.clone(),
            created: now_ms()?,
            instance_ids,
            input,
            created_sequence: None,
            created_head: None,
        };
        // Reject malformed structure/field selections before they become a
        // permanent protected PENDING ID. The same generated IDs and preset
        // builder are used again when saving the signed request.
        validate_plan(&row, identity.actor_id())?;
        history.rows.insert(command.clone(), row.clone());
        write_history(&store, &history)?;
        drop(history);
        drop(store);
        self.stage_saved(&identity, &recipient, &command, &row)?;
        Ok(summary(&command, &row))
    }

    /// Protected local discovery includes PENDING and CREATED rows, including
    /// a result hidden by process cancellation. It does not assert current
    /// server state or expose requests, keys, or encrypted bodies.
    pub fn operations(&self) -> Result<Vec<SecureOwnerCreateResult>, SecureOwnerCreateError> {
        let identity = KernelIdentity::open(&self.identity_path())
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let history = read_history(&store, &self.config, &identity)?;
        Ok(history
            .rows
            .iter()
            .map(|(id, row)| summary(id, row))
            .collect())
    }

    /// Read an Owner-created workspace through its normal protected profile.
    /// The caller supplies only the public workspace ID; the shared local
    /// identity and per-workspace profile paths come from saved state.
    pub fn read_workspace_json(
        &self,
        workspace_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, SecureOwnerCreateError> {
        let identity = KernelIdentity::open(&self.identity_path())
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let history = read_history(&store, &self.config, &identity)?;
        let selected = history
            .rows
            .iter()
            .find(|(_, row)| row.workspace_id == workspace_id && row.created_sequence.is_some())
            .map(|(command, row)| (command.clone(), row.clone()));
        let Some((command, row)) = selected else {
            let pending_create = history
                .rows
                .values()
                .any(|row| row.workspace_id == workspace_id);
            drop(history);
            drop(store);
            drop(identity);
            if pending_create {
                return Err(SecureOwnerCreateError::NotFound);
            }
            return SecureHistoricalOwnerAttach::new(self.config.clone())
                .read_workspace_json(workspace_id, cancel)
                .map_err(map_attach_error);
        };
        drop(history);
        drop(store);
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("secure-intents.state"),
            &self.config.origin,
            identity.actor_id(),
        )
        .map_err(|_| SecureOwnerCreateError::Local)?;
        let request = journal
            .exact_request(&command)
            .map_err(|_| SecureOwnerCreateError::Bootstrap)?;
        let proof = verify_prepared_owner_bootstrap(
            &request,
            journal
                .path(&command)
                .map_err(|_| SecureOwnerCreateError::Bootstrap)?,
            &BootstrapPins {
                workspace_id,
                owner_actor: identity.actor_id(),
                owner_key: identity.key_id(),
            },
        )
        .map_err(|_| SecureOwnerCreateError::Bootstrap)?;
        if proof.command_id() != command
            || proof.visibility() != row.input.visibility
            || journal
                .intent_digest(&command)
                .map_err(|_| SecureOwnerCreateError::Bootstrap)?
                != proof.commit_digest()
        {
            return Err(SecureOwnerCreateError::Bootstrap);
        }
        let profile = self.profile(&row.workspace_id, identity.actor_id(), identity.key_id());
        drop(journal);
        drop(identity);
        let json = profile.read_latest_json_with_cancel(cancel)?;
        profile.with_pinned_replay(cancel, |latest| {
            if latest.origin() != self.config.origin
                || latest.replay().workspace_id() != workspace_id
                || !latest.replay().contains_checkpoint(
                    1,
                    Some(proof.commit_digest()),
                    proof.policy_hash(),
                )
            {
                return Err(SecureOwnerCreateError::Verification);
            }
            latest
                .verified_read()
                .map_err(|_| SecureOwnerCreateError::Verification)?;
            Ok(())
        })?;
        Ok(json)
    }

    pub fn resume(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<SecureOwnerCreateResult, SecureOwnerCreateError> {
        if cancel.is_cancelled() {
            return Err(SecureOwnerCreateError::Cancelled);
        }
        let identity = KernelIdentity::open(&self.identity_path())
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let recipient = RecipientState::open(&self.recipient_path(), &identity)
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let history = read_history(&store, &self.config, &identity)?;
        let row = history
            .rows
            .get(command_id)
            .ok_or(SecureOwnerCreateError::NotFound)?
            .clone();
        drop(history);
        drop(store);
        self.stage_saved(&identity, &recipient, command_id, &row)?;
        self.finish_saved(identity, command_id, row, cancel)
    }

    pub fn create(
        &self,
        input: SecureOwnerCreateInput,
        cancel: &CancellationToken,
    ) -> Result<SecureOwnerCreateResult, SecureOwnerCreateError> {
        let prepared = self.prepare(input, cancel)?;
        self.resume(&prepared.command_id, cancel)
    }

    fn stage_saved(
        &self,
        identity: &KernelIdentity,
        recipient: &RecipientState,
        command: &str,
        row: &SavedCreate,
    ) -> Result<(), SecureOwnerCreateError> {
        let workspace_dir = self.workspace_dir(&row.workspace_id);
        ensure_private_dir(&workspace_dir)?;
        let mut journal = SecureIntentJournal::open(
            &self.config.state_dir.join("secure-intents.state"),
            &self.config.origin,
            identity.actor_id(),
        )
        .map_err(|_| SecureOwnerCreateError::Local)?;
        if journal.contains_id(command) {
            return Ok(());
        }
        let six: [String; 6] = std::array::from_fn(|i| row.instance_ids[i].clone());
        let keep = row.input.keep_encrypted_json.as_bytes();
        if let Some(name_units) = row.input.name_utf16.as_deref() {
            let mut lifecycle = if row.input.visibility == "PRIVATE" {
                Some(self.lifecycle(identity, &row.workspace_id)?)
            } else {
                None
            };
            prepare_owner_workspace_with_utf16_name(
                &mut journal,
                identity,
                recipient,
                lifecycle.as_mut(),
                &row.workspace_id,
                command,
                name_units,
                row.created,
                &row.instance_ids,
                &row.input.visibility,
                row.input.structured,
                row.input.coordination_version,
                keep,
            )
            .map_err(map_prepare)?;
            return Ok(());
        }
        match (
            row.input.visibility.as_str(),
            row.input.coordination_version,
        ) {
            ("PRIVATE", Some(version)) => {
                let seven: [String; 7] = std::array::from_fn(|i| row.instance_ids[i].clone());
                let mut lifecycle = self.lifecycle(identity, &row.workspace_id)?;
                prepare_coordinated_private_owner_workspace(
                    &mut journal,
                    identity,
                    recipient,
                    &mut lifecycle,
                    command,
                    &row.input.name,
                    row.created,
                    &seven,
                    version,
                    keep,
                )
                .map_err(map_prepare)?;
            }
            ("PRIVATE", None) => {
                let mut lifecycle = self.lifecycle(identity, &row.workspace_id)?;
                prepare_private_owner_workspace_with_options(
                    &mut journal,
                    identity,
                    recipient,
                    &mut lifecycle,
                    command,
                    &row.input.name,
                    row.created,
                    &six,
                    row.input.structured,
                    keep,
                )
                .map_err(map_prepare)?;
            }
            ("PUBLIC", Some(version)) => {
                let seven: [String; 7] = std::array::from_fn(|i| row.instance_ids[i].clone());
                prepare_coordinated_public_owner_workspace_with_options(
                    &mut journal,
                    identity,
                    recipient,
                    &row.workspace_id,
                    command,
                    &row.input.name,
                    row.created,
                    &seven,
                    version,
                    keep,
                )
                .map_err(map_prepare)?;
            }
            ("PUBLIC", None) => {
                if row.input.structured {
                    prepare_public_owner_workspace_with_options(
                        &mut journal,
                        identity,
                        recipient,
                        &row.workspace_id,
                        command,
                        &row.input.name,
                        row.created,
                        &six,
                        keep,
                    )
                    .map_err(map_prepare)?;
                } else {
                    crate::secure_native_prepare::prepare_default_public_owner_workspace(
                        &mut journal,
                        identity,
                        recipient,
                        &row.workspace_id,
                        command,
                        &row.input.name,
                        row.created,
                        &six,
                    )
                    .map_err(map_prepare)?;
                }
            }
            _ => return Err(SecureOwnerCreateError::Invalid),
        }
        Ok(())
    }

    fn finish_saved(
        &self,
        identity: KernelIdentity,
        command: &str,
        row: SavedCreate,
        cancel: &CancellationToken,
    ) -> Result<SecureOwnerCreateResult, SecureOwnerCreateError> {
        let mut journal = SecureIntentJournal::open(
            &self.config.state_dir.join("secure-intents.state"),
            &self.config.origin,
            identity.actor_id(),
        )
        .map_err(|_| SecureOwnerCreateError::Local)?;
        let mut transport_config = TransportConfig::new(self.config.origin.clone());
        transport_config.allow_loopback_http = self.config.allow_loopback_http;
        let transport =
            HttpTransport::new(transport_config).map_err(|_| SecureOwnerCreateError::Transport)?;
        let mut lifecycle = self.lifecycle(&identity, &row.workspace_id)?;
        let (proof, request) = if row.input.visibility == "PRIVATE"
            && lifecycle.pending_bootstrap_key().is_some()
        {
            journal
                .verified_saved_bootstrap(command, &identity, &transport, &lifecycle)
                .map_err(|_| SecureOwnerCreateError::Bootstrap)?
        } else if row.input.visibility == "PUBLIC" {
            journal
                .verified_saved_public_bootstrap(command, &row.workspace_id, &identity, &transport)
                .map_err(|_| SecureOwnerCreateError::Bootstrap)?
        } else {
            let request = journal
                .exact_request(command)
                .map_err(|_| SecureOwnerCreateError::Bootstrap)?;
            let proof = verify_prepared_owner_bootstrap(
                &request,
                journal
                    .path(command)
                    .map_err(|_| SecureOwnerCreateError::Bootstrap)?,
                &BootstrapPins {
                    workspace_id: &row.workspace_id,
                    owner_actor: identity.actor_id(),
                    owner_key: identity.key_id(),
                },
            )
            .map_err(|_| SecureOwnerCreateError::Bootstrap)?;
            if proof.visibility() != "PRIVATE"
                || journal
                    .intent_digest(command)
                    .map_err(|_| SecureOwnerCreateError::Bootstrap)?
                    != proof.commit_digest()
                || lifecycle.active_key(1).is_none()
            {
                return Err(SecureOwnerCreateError::Bootstrap);
            }
            (proof, request)
        };
        if !request.is_empty() && proof.command_id() != command {
            return Err(SecureOwnerCreateError::Bootstrap);
        }
        if row.created_sequence.is_none()
            && (row.input.visibility == "PUBLIC" || lifecycle.pending_bootstrap_key().is_some())
        {
            let submitted = if row.input.visibility == "PUBLIC" {
                self.runtime()?
                    .block_on(journal.submit_saved_public_bootstrap(
                        command,
                        &row.workspace_id,
                        &identity,
                        &transport,
                        cancel,
                    ))
            } else {
                self.runtime()?.block_on(
                    journal
                        .submit_saved_bootstrap(command, &identity, &transport, &lifecycle, cancel),
                )
            };
            match submitted {
                Ok(_) => (),
                Err(SecureIntentError::Transport(TransportError::SubmittedUncertain)) => {
                    return Ok(summary(command, &row))
                }
                Err(SecureIntentError::Transport(TransportError::Cancelled)) => {
                    return Ok(summary(command, &row))
                }
                Err(SecureIntentError::ServerRejected(code)) => {
                    return Err(SecureOwnerCreateError::ServerRejected(code))
                }
                Err(_) => return Err(SecureOwnerCreateError::Transport),
            }
        }
        if cancel.is_cancelled() {
            return Ok(summary(command, &row));
        }
        let mut client_config = TransportConfig::new(self.config.origin.clone());
        client_config.allow_loopback_http = self.config.allow_loopback_http;
        let runtime = self.runtime()?;
        let client = runtime
            .block_on(KernelClient::open(
                client_config,
                &self.workspace_dir(&row.workspace_id).join("kernel.sqlite"),
                &[],
                cancel,
            ))
            .map_err(|_| SecureOwnerCreateError::Transport)?;
        let authority = sha256_hex(identity.actor_id().as_bytes());
        let mut reader = SecureJournalRead::open(
            &self
                .workspace_dir(&row.workspace_id)
                .join("owner-genesis-pages.state"),
            &client,
            &identity,
            &row.workspace_id,
            &authority,
        )
        .map_err(|_| SecureOwnerCreateError::Verification)?;
        while !reader
            .progress()
            .map_err(|_| SecureOwnerCreateError::Verification)?
            .complete_transport
        {
            if cancel.is_cancelled() {
                return Ok(summary(command, &row));
            }
            runtime
                .block_on(reader.fetch_next(&client, &identity, cancel))
                .map_err(|_| SecureOwnerCreateError::Transport)?;
        }
        let pages = reader
            .authenticated_pages(&client, &identity)
            .map_err(|_| SecureOwnerCreateError::Verification)?;
        let budget = SecureJournalReadBudget::new(self.config.max_replay_artifact_bytes)
            .ok_or(SecureOwnerCreateError::ResourceLimit)?;
        let replay = replay_authenticated_pages_with_budget(&pages, &lifecycle, budget)
            .map_err(|_| SecureOwnerCreateError::Verification)?;
        if replay.origin() != self.config.origin
            || replay.source_actor_id() != identity.actor_id()
            || replay.source_key_id() != identity.key_id()
            || replay.replay().workspace_id() != row.workspace_id
            || replay.replay().structure_status() == StructureStatus::Seeding
            || !replay.replay().contains_checkpoint(
                1,
                Some(proof.commit_digest()),
                proof.policy_hash(),
            )
        {
            return Err(SecureOwnerCreateError::Verification);
        }
        let sequence = replay.replay().sequence();
        let head = replay.replay().head().map(str::to_owned);
        if row.input.visibility == "PRIVATE" {
            lifecycle
                .activate_verified_owner_bootstrap(&proof, &replay)
                .map_err(|_| SecureOwnerCreateError::Verification)?;
        } else {
            replay
                .verified_read()
                .map_err(|_| SecureOwnerCreateError::Verification)?;
        }
        let owner_actor = identity.actor_id().to_owned();
        let owner_key = identity.key_id().to_owned();
        drop(reader);
        drop(client);
        drop(journal);
        drop(lifecycle);
        drop(identity);
        // Establish the ordinary profile with the same protected Owner pins.
        // Its slot/floor verification is independent of the bootstrap reader.
        let profile = self.profile(&row.workspace_id, &owner_actor, &owner_key);
        let _ = profile
            .read_latest_json_with_cancel(cancel)
            .map_err(|_| SecureOwnerCreateError::Verification)?;
        profile.with_pinned_replay(cancel, |latest| {
            if latest.origin() != self.config.origin
                || latest.replay().workspace_id() != row.workspace_id
                || !latest.replay().contains_checkpoint(
                    1,
                    Some(proof.commit_digest()),
                    proof.policy_hash(),
                )
            {
                return Err(SecureOwnerCreateError::Verification);
            }
            latest
                .verified_read()
                .map_err(|_| SecureOwnerCreateError::Verification)?;
            Ok(())
        })?;
        let identity = KernelIdentity::open(&self.identity_path())
            .map_err(|_| SecureOwnerCreateError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let mut history = read_history(&store, &self.config, &identity)?;
        let saved = history
            .rows
            .get_mut(command)
            .ok_or(SecureOwnerCreateError::NotFound)?;
        if saved.workspace_id != row.workspace_id || saved.input != row.input {
            return Err(SecureOwnerCreateError::Identity);
        }
        saved.created_sequence = Some(sequence);
        saved.created_head = head;
        let final_row = saved.clone();
        write_history(&store, &history)?;
        let mut result = summary(command, &final_row);
        result.status = "CREATED".into();
        Ok(result)
    }

    fn enrollment(&self) -> SecureRecipientEnrollment {
        let mut config = RecipientEnrollmentConfig::for_state_dir(
            self.config.origin.clone(),
            &self.config.state_dir,
        );
        config.allow_loopback_http = self.config.allow_loopback_http;
        SecureRecipientEnrollment::new(config)
    }
    fn identity_path(&self) -> PathBuf {
        self.config.state_dir.join("identity.state")
    }
    fn recipient_path(&self) -> PathBuf {
        self.config.state_dir.join("recipient.state")
    }
    fn history_path(&self) -> PathBuf {
        self.config.state_dir.join("owner-create.state")
    }
    fn profile(&self, workspace_id: &str, owner_actor: &str, owner_key: &str) -> SecureReadProfile {
        SecureReadProfile::new(self.profile_config(workspace_id, owner_actor, owner_key))
    }
    fn profile_config(
        &self,
        workspace_id: &str,
        owner_actor: &str,
        owner_key: &str,
    ) -> SecureReadProfileConfig {
        SecureReadProfileConfig {
            origin: self.config.origin.clone(),
            state_dir: self.workspace_dir(workspace_id),
            identity_path: self.identity_path(),
            workspace_id: workspace_id.to_owned(),
            owner_actor_id: Some(owner_actor.to_owned()),
            owner_key_id: Some(owner_key.to_owned()),
            authority: Some(sha256_hex(owner_actor.as_bytes())),
            required_features: Vec::new(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
        }
    }
    fn workspace_dir(&self, workspace_id: &str) -> PathBuf {
        self.config.state_dir.join("workspaces").join(workspace_id)
    }
    fn lifecycle(
        &self,
        identity: &KernelIdentity,
        workspace_id: &str,
    ) -> Result<SecureLifecycle, SecureOwnerCreateError> {
        SecureLifecycle::open(
            &self.workspace_dir(workspace_id).join("lifecycle.state"),
            &self.config.origin,
            identity.actor_id(),
            workspace_id,
            identity.actor_id(),
            identity.key_id(),
        )
        .map_err(|_| SecureOwnerCreateError::Local)
    }
    fn runtime(&self) -> Result<tokio::runtime::Runtime, SecureOwnerCreateError> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SecureOwnerCreateError::Transport)
    }
}

fn validate_input(input: &SecureOwnerCreateInput) -> Result<(), SecureOwnerCreateError> {
    let name_bytes = if let Some(units) = input.name_utf16.as_deref() {
        if !input.name.is_empty() || units.is_empty() {
            return Err(SecureOwnerCreateError::Invalid);
        }
        // TextEncoder replaces each unpaired surrogate for the length check
        // only; `units` remain unchanged in protected state and signed wire.
        String::from_utf16_lossy(units).len()
    } else {
        input.name.len()
    };
    if name_bytes == 0
        || name_bytes > 240
        || !matches!(input.visibility.as_str(), "PUBLIC" | "PRIVATE")
        || input
            .coordination_version
            .is_some_and(|v| !matches!(v, 1 | 2))
        || (input.coordination_version.is_some() && !input.structured)
        || (!input.structured && input.keep_encrypted_json != "[]")
    {
        return Err(SecureOwnerCreateError::Invalid);
    }
    let keep: serde_json::Value = serde_json::from_str(&input.keep_encrypted_json)
        .map_err(|_| SecureOwnerCreateError::Invalid)?;
    if !keep.is_array() {
        return Err(SecureOwnerCreateError::Invalid);
    }
    Ok(())
}

fn validate_plan(row: &SavedCreate, owner_actor: &str) -> Result<(), SecureOwnerCreateError> {
    let six: [String; 6] = std::array::from_fn(|i| row.instance_ids[i].clone());
    let builder_name = if row.input.name_utf16.is_some() {
        "_"
    } else {
        &row.input.name
    };
    let built = if let Some(version) = row.input.coordination_version {
        let seven: [String; 7] = std::array::from_fn(|i| row.instance_ids[i].clone());
        owner_bootstrap_objects_with_coordination(
            builder_name,
            &row.workspace_id,
            owner_actor,
            row.created,
            &seven,
            &row.input.visibility,
            version,
        )
    } else {
        owner_bootstrap_objects_with_visibility(
            builder_name,
            &row.workspace_id,
            owner_actor,
            row.created,
            &six,
            &row.input.visibility,
        )
    }
    .map_err(|_| SecureOwnerCreateError::Invalid)?;
    let operation = owner_operation_wire(&built, row.input.name_utf16.as_deref())
        .map_err(|_| SecureOwnerCreateError::Invalid)?;
    if row.input.structured {
        let objects =
            owner_objects_wire(&operation).map_err(|_| SecureOwnerCreateError::Invalid)?;
        if let Some(version) = row.input.coordination_version {
            let digest = built.operation()["objects"][13]["id"]
                .as_str()
                .ok_or(SecureOwnerCreateError::Invalid)?;
            derive_genesis_structure_policy_with_coordination_and_keep_encrypted(
                &objects,
                row.input.keep_encrypted_json.as_bytes(),
                &row.instance_ids[6],
                digest,
                owner_actor,
                version,
            )
            .map_err(|_| SecureOwnerCreateError::Invalid)?;
        } else {
            derive_genesis_structure_policy_with_keep_encrypted(
                &objects,
                row.input.keep_encrypted_json.as_bytes(),
            )
            .map_err(|_| SecureOwnerCreateError::Invalid)?;
        }
    }
    Ok(())
}

fn read_history(
    store: &SecureStateStore,
    config: &SecureOwnerCreateConfig,
    identity: &KernelIdentity,
) -> Result<OwnerHistory, SecureOwnerCreateError> {
    let Some(bytes) = store
        .read_exact()
        .map_err(|_| SecureOwnerCreateError::Local)?
    else {
        return Ok(OwnerHistory {
            version: 1,
            origin: config.origin.clone(),
            actor_id: identity.actor_id().into(),
            signing_key_id: identity.key_id().into(),
            rows: BTreeMap::new(),
        });
    };
    if bytes.len() > MAX_DOCUMENT {
        return Err(SecureOwnerCreateError::ResourceLimit);
    }
    let history: OwnerHistory =
        serde_json::from_slice(&bytes).map_err(|_| SecureOwnerCreateError::Invalid)?;
    if history.version != 1
        || history.origin != config.origin
        || history.actor_id != identity.actor_id()
        || history.signing_key_id != identity.key_id()
    {
        return Err(SecureOwnerCreateError::Identity);
    }
    if history.rows.len() > MAX_HISTORY
        || history.rows.iter().any(|(id, row)| {
            !valid_token(id)
                || !valid_token(&row.workspace_id)
                || row.instance_ids.len()
                    != if row.input.coordination_version.is_some() {
                        7
                    } else {
                        6
                    }
                || row
                    .instance_ids
                    .iter()
                    .any(|instance| !valid_token(instance))
                || validate_input(&row.input).is_err()
                || row.created_sequence.is_some() != row.created_head.is_some()
        })
    {
        return Err(SecureOwnerCreateError::Invalid);
    }
    Ok(history)
}

fn write_history(
    store: &SecureStateStore,
    history: &OwnerHistory,
) -> Result<(), SecureOwnerCreateError> {
    let bytes = serde_json::to_vec(history).map_err(|_| SecureOwnerCreateError::Invalid)?;
    if bytes.len() > MAX_DOCUMENT {
        return Err(SecureOwnerCreateError::ResourceLimit);
    }
    store
        .write_exact(&bytes)
        .map_err(|_| SecureOwnerCreateError::Local)
}

fn summary(command: &str, row: &SavedCreate) -> SecureOwnerCreateResult {
    SecureOwnerCreateResult {
        status: if row.created_sequence.is_some() {
            "CREATED_LOCAL".into()
        } else {
            "PENDING".into()
        },
        command_id: command.into(),
        workspace_id: row.workspace_id.clone(),
        visibility: row.input.visibility.clone(),
        sequence: row.created_sequence,
        head: row.created_head.clone(),
    }
}

fn map_prepare(error: NativePrepareError) -> SecureOwnerCreateError {
    match error {
        NativePrepareError::Existing => SecureOwnerCreateError::Bootstrap,
        _ => SecureOwnerCreateError::Invalid,
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64url(&bytes)
}

fn now_ms() -> Result<u64, SecureOwnerCreateError> {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SecureOwnerCreateError::Invalid)?
        .as_millis();
    u64::try_from(at)
        .ok()
        .filter(|v| *v <= 9_007_199_254_740_991)
        .ok_or(SecureOwnerCreateError::Invalid)
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn ensure_private_dir(path: &Path) -> Result<(), SecureOwnerCreateError> {
    let parent = path.parent().ok_or(SecureOwnerCreateError::Local)?;
    for directory in [parent, path] {
        fs::create_dir(directory)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_| SecureOwnerCreateError::Local)?;
        let metadata =
            fs::symlink_metadata(directory).map_err(|_| SecureOwnerCreateError::Local)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(SecureOwnerCreateError::Local);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .map_err(|_| SecureOwnerCreateError::Local)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_action_access::PublicActionInput;
    use peerwork_core::wire_json::{parse_wire_json_bounded, WireValue};
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_native_public_and_private_owner_create_recover_lost_reply() {
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
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
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
        let config = SecureOwnerCreateConfig {
            origin: origin.clone(),
            state_dir: root.path().join("sdk-state"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: default_budget(),
        };
        let token = CancellationToken::new();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let counts = || {
            runtime.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        let mut created_workspaces = Vec::new();
        for visibility in ["PUBLIC", "PRIVATE"] {
            let access = SecureOwnerWorkspaceCreate::new(config.clone());
            let prepared = access
                .prepare(
                    SecureOwnerCreateInput {
                        name: format!("Native {visibility} owner workspace"),
                        name_utf16: None,
                        visibility: visibility.into(),
                        structured: false,
                        keep_encrypted_json: "[]".into(),
                        coordination_version: None,
                    },
                    &token,
                )
                .unwrap();
            let before = counts();
            assert_eq!(
                before["head_sequence"].as_u64().unwrap_or(0),
                if visibility == "PUBLIC" { 0 } else { 1 }
            );
            runtime.block_on(async {
                let response = reqwest::Client::new()
                    .post(format!("{origin}__test/drop-next-post"))
                    .body("{}")
                    .send()
                    .await
                    .unwrap();
                assert!(response.status().is_success());
            });
            let uncertain = access.resume(&prepared.command_id, &token).unwrap();
            assert_eq!(uncertain.status, "PENDING");
            let applied = counts();
            assert_eq!(
                applied["commits"].as_u64().unwrap(),
                before["commits"].as_u64().unwrap() + 1
            );
            drop(access);
            let reopened = SecureOwnerWorkspaceCreate::new(config.clone());
            assert!(reopened
                .operations()
                .unwrap()
                .iter()
                .any(|operation| operation.command_id == prepared.command_id
                    && operation.workspace_id == prepared.workspace_id
                    && operation.status == "PENDING"));
            let result = reopened.resume(&prepared.command_id, &token).unwrap();
            assert_eq!(result.status, "CREATED");
            assert_eq!(result.sequence, Some(1));
            assert!(result.head.as_deref().is_some_and(|head| head.len() == 64));
            let after_retry = counts();
            assert_eq!(
                after_retry["commits"], applied["commits"],
                "exact saved retry must not duplicate genesis"
            );
            assert_eq!(after_retry["head_hash"], applied["head_hash"]);
            assert!(reopened
                .operations()
                .unwrap()
                .iter()
                .any(|operation| operation.command_id == prepared.command_id
                    && operation.status == "CREATED_LOCAL"));
            let again = reopened.resume(&prepared.command_id, &token).unwrap();
            assert_eq!(again, result);
            assert_eq!(counts()["commits"], applied["commits"]);
            let read: serde_json::Value = serde_json::from_str(
                &reopened
                    .read_workspace_json(&prepared.workspace_id, &token)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(read["workspace_id"], prepared.workspace_id);
            assert_eq!(read["sequence"], 1);
            assert_eq!(read["objects"].as_array().unwrap().len(), 13);
            created_workspaces.push((visibility, prepared.workspace_id));
        }
        assert_eq!(
            SecureOwnerWorkspaceCreate::new(config.clone())
                .operations()
                .unwrap()
                .len(),
            2
        );

        // The high-level dispatcher must consume all pinned preset/structure
        // choices with its protected generated IDs, not merely accept a DTO.
        let selector = r#"[{"schema":"discussion.message","fields":["author"]}]"#;
        let variants = [
            ("PUBLIC", true, None, "[]", 6),
            ("PRIVATE", true, None, "[]", 6),
            ("PUBLIC", true, Some(1), "[]", 7),
            ("PRIVATE", true, Some(1), "[]", 7),
            ("PUBLIC", true, Some(2), selector, 7),
            ("PRIVATE", true, Some(2), selector, 7),
        ];
        for (visibility, structured, coordination_version, keep, protocol_count) in variants {
            let access = SecureOwnerWorkspaceCreate::new(config.clone());
            let result = access
                .prepare(
                    SecureOwnerCreateInput {
                        name: format!("Option matrix {visibility} {coordination_version:?}"),
                        name_utf16: None,
                        visibility: visibility.into(),
                        structured,
                        keep_encrypted_json: keep.into(),
                        coordination_version,
                    },
                    &token,
                )
                .unwrap();
            assert_eq!(result.status, "PENDING");
            let identity = KernelIdentity::open(&config.state_dir.join("identity.state")).unwrap();
            let journal = SecureIntentJournal::open(
                &config.state_dir.join("secure-intents.state"),
                &config.origin,
                identity.actor_id(),
            )
            .unwrap();
            let request: serde_json::Value =
                serde_json::from_slice(&journal.exact_request(&result.command_id).unwrap())
                    .unwrap();
            let policy = &request["policy"]["payload"];
            assert_eq!(policy["visibility"], visibility);
            assert_eq!(policy["structure_mode"], "STRUCTURED");
            assert_eq!(
                policy["structure"]["protocols"].as_array().unwrap().len(),
                protocol_count
            );
            if let Some(version) = coordination_version {
                assert_eq!(policy["structure"]["coordination"]["v"], version);
            } else {
                assert!(policy["structure"]["coordination"].is_null());
            }
            if keep != "[]" {
                assert!(policy["structure"].to_string().contains("author"));
            }
        }
        assert_eq!(counts()["commits"], 2, "preparation must not POST genesis");
        let access = SecureOwnerWorkspaceCreate::new(config.clone());
        let before_invalid = access.operations().unwrap().len();
        for input in [
            SecureOwnerCreateInput {
                name: "Bad version".into(),
                name_utf16: None,
                visibility: "PUBLIC".into(),
                structured: true,
                keep_encrypted_json: "[]".into(),
                coordination_version: Some(3),
            },
            SecureOwnerCreateInput {
                name: "Coordination without structure".into(),
                name_utf16: None,
                visibility: "PRIVATE".into(),
                structured: false,
                keep_encrypted_json: "[]".into(),
                coordination_version: Some(1),
            },
            SecureOwnerCreateInput {
                name: "Unknown protected field".into(),
                name_utf16: None,
                visibility: "PUBLIC".into(),
                structured: true,
                keep_encrypted_json:
                    r#"[{"schema":"discussion.message","fields":["not_a_field"]}]"#.into(),
                coordination_version: None,
            },
            SecureOwnerCreateInput {
                name: "ambiguous".into(),
                name_utf16: Some(vec![0xd800]),
                visibility: "PUBLIC".into(),
                structured: false,
                keep_encrypted_json: "[]".into(),
                coordination_version: None,
            },
            SecureOwnerCreateInput {
                name: String::new(),
                name_utf16: Some(vec![0xd800; 81]),
                visibility: "PUBLIC".into(),
                structured: false,
                keep_encrypted_json: "[]".into(),
                coordination_version: None,
            },
        ] {
            assert!(matches!(
                access.prepare(input, &token),
                Err(SecureOwnerCreateError::Invalid)
            ));
            assert_eq!(access.operations().unwrap().len(), before_invalid);
        }

        let lone_name = vec![0xd800_u16];
        let surrogate = access
            .prepare(
                SecureOwnerCreateInput {
                    name: String::new(),
                    name_utf16: Some(lone_name.clone()),
                    visibility: "PUBLIC".into(),
                    structured: false,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        assert_eq!(
            access.resume(&surrogate.command_id, &token).unwrap().status,
            "CREATED"
        );
        let signed_read = access
            .read_workspace_json(&surrogate.workspace_id, &token)
            .unwrap();
        let parsed = parse_wire_json_bounded(signed_read.as_bytes(), 64, 2_000_000).unwrap();
        let WireValue::Array(objects) = parsed.get("objects").unwrap() else {
            panic!("verified Owner read lacks objects");
        };
        let workspace = objects
            .iter()
            .find(|row| {
                row.get("kind").and_then(WireValue::as_string).as_deref() == Some("workspaces")
            })
            .unwrap();
        assert_eq!(
            workspace
                .get("value")
                .unwrap()
                .get("name")
                .unwrap()
                .as_utf16(),
            Some(lone_name.as_slice()),
            "signed service readback must retain original UTF-16 units"
        );

        let identity = KernelIdentity::open(&config.state_dir.join("identity.state")).unwrap();
        let store = SecureStateStore::open(&config.state_dir.join("owner-create.state")).unwrap();
        let history = read_history(&store, &config, &identity).unwrap();
        let created_with_wiki = created_workspaces
            .into_iter()
            .map(|(visibility, workspace_id)| {
                let wiki_instance = history
                    .rows
                    .values()
                    .find(|row| row.workspace_id == workspace_id)
                    .unwrap()
                    .instance_ids[1]
                    .clone();
                (visibility, workspace_id, wiki_instance)
            })
            .collect::<Vec<_>>();
        drop(history);
        drop(store);
        drop(identity);
        for (visibility, workspace_id, wiki_instance) in created_with_wiki {
            let access = SecureOwnerWorkspaceCreate::new(config.clone());
            if visibility == "PUBLIC" {
                access.public_install_access(&workspace_id).unwrap();
            } else {
                assert!(matches!(
                    access.public_install_access(&workspace_id),
                    Err(SecureOwnerCreateError::NotFound)
                ));
            }
            let action = PublicActionInput {
                action_id: "wiki.create".into(),
                instance_id: wiki_instance,
                body_json: format!(
                    r#"{{"title":"Owner {visibility} action","body":"Created workspace effect"}}"#
                ),
                exact_input_refs_json: None,
                allocations_json: None,
                command_id: None,
                issued_at_ms: None,
            };
            let submitted: serde_json::Value = if visibility == "PUBLIC" {
                serde_json::from_str(
                    &access
                        .public_action_access(&workspace_id)
                        .unwrap()
                        .submit_new_json(action)
                        .unwrap(),
                )
                .unwrap()
            } else {
                serde_json::from_str(
                    &access
                        .private_action_access(&workspace_id)
                        .unwrap()
                        .submit_new_json(action)
                        .unwrap(),
                )
                .unwrap()
            };
            let command = submitted["command_id"].as_str().unwrap();
            let accepted: serde_json::Value = if visibility == "PUBLIC" {
                serde_json::from_str(
                    &access
                        .public_action_access(&workspace_id)
                        .unwrap()
                        .retry_saved_json(command)
                        .unwrap(),
                )
                .unwrap()
            } else {
                serde_json::from_str(
                    &access
                        .private_action_access(&workspace_id)
                        .unwrap()
                        .retry_saved_json(command)
                        .unwrap(),
                )
                .unwrap()
            };
            assert_eq!(accepted["status"], "ACCEPTED");
            let receipt: serde_json::Value =
                serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
            let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
            let read: serde_json::Value =
                serde_json::from_str(&access.read_workspace_json(&workspace_id, &token).unwrap())
                    .unwrap();
            assert_eq!(read["sequence"], 2);
            assert!(read["objects"].as_array().unwrap().iter().any(|row| {
                row["kind"] == "records"
                    && row["id"] == effect_id
                    && row["value"]["payload"]["title"] == format!("Owner {visibility} action")
            }));
        }
    }
}
