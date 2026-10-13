//! Explicit attachment of an exportable, protected TypeScript Owner state.
//! Source files remain untouched. A saved local binding and pending epoch ring
//! are never Owner authority until a complete configured-origin signed replay
//! proves the source checkpoint, current policy, and all encrypted history.

use crate::{
    kernel_identity::{KernelIdentity, KernelIdentityError},
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_lifecycle::SecureLifecycle,
    secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerWorkspaceCreate},
    secure_read_access::{SecureReadAccess, SecureReadConfig},
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::{read_private_file_bounded, SecureStateStore},
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    prepared_secure_request::{
        verify_prepared_secure_commit_request_with_policy, SecureCommitRequestPins,
    },
    replayed_secure_journal::StructureStatus,
    secure_keyring::SecretKeyring,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(test)]
static TEST_STOP_AFTER_ATTACH_ROW: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_IMPORTED_ACTION_POSTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TEST_STOP_AFTER_IMPORTED_ACTION_ACCEPTED: AtomicBool = AtomicBool::new(false);

const MAX_SOURCE: usize = 64 * 1024 * 1024;
const MAX_HISTORY: usize = 4096;
const MAX_HISTORY_WIRE: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalOwnerAttachInput {
    pub workspace_id: String,
    pub protected_ts_state_path: PathBuf,
    pub protected_owner_pkcs8_path: PathBuf,
    pub protected_ts_intent_db_path: PathBuf,
    pub expected_owner_actor_id: String,
    pub expected_owner_key_id: String,
    /// Explicitly authorize exact recovery of one saved legacy Owner ACTION.
    /// An attach without this opt-in refuses any pending signed packet.
    /// Stop the old client and keep its state, key, and intent database unchanged
    /// throughout attach/resume; native locking does not lock the old client.
    #[serde(default)]
    pub recover_pending_action: bool,
    /// Explicitly retain every pending kernel JWS signed for this workspace.
    /// Attachment imports these exact packets but never submits them. A caller
    /// must invoke per-command recovery separately after inspecting history.
    #[serde(default)]
    pub kernel_pending_command_ids: Vec<String>,
    /// Bind selected IDs to the exact inspected SQLite intent snapshot,
    /// including each signed JWS, command body, status, and saved response.
    /// Required when kernel_pending_command_ids is nonempty.
    #[serde(default)]
    pub expected_kernel_intent_db_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalOwnerAttachResult {
    pub attach_id: String,
    pub workspace_id: String,
    pub provenance: String,
    pub status: String,
    pub owner_actor_id: String,
    pub owner_key_id: String,
    pub sequence: Option<u64>,
    pub head: Option<String>,
    pub selected_kernel_count: usize,
    pub retained_other_kernel_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalKernelCommandStatus {
    pub command_id: String,
    pub intent_digest: String,
    pub expires_at_ms: u64,
    pub status: String,
    pub last_http_status: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalKernelPendingInventory {
    /// SHA-256 of the canonical protected SQLite intent snapshot, including
    /// all rows. This does not hash the separate TS agent state or Owner PEM.
    pub intent_db_digest: String,
    /// All commands here are verified PENDING in the source database. Each
    /// status is a local recovery advisory; EXPIRED_UNRESOLVED does not prove
    /// the service rejected or never applied the original signed command.
    pub commands: Vec<HistoricalKernelCommandStatus>,
    pub retained_other_pending_count: usize,
    pub retained_nonworkspace_pending_count: usize,
}

#[derive(Debug, Error)]
pub enum HistoricalOwnerAttachError {
    #[error("historical Owner attachment input is invalid")]
    Input,
    #[error("protected legacy Owner source is unavailable or changed")]
    SourceChanged,
    #[error("legacy Owner state has unresolved operations that require the original client")]
    SourceUnresolved,
    #[error("protected native Owner identity conflicts with imported Owner")]
    Identity,
    #[error("another protected Owner workspace binding conflicts")]
    Conflict,
    #[error("historical Owner attachment was not found")]
    NotFound,
    #[error("protected historical Owner state failed")]
    Local,
    #[error("complete signed historical Owner replay or current policy failed")]
    Verification,
    #[error("historical Owner attachment was cancelled")]
    Cancelled,
    #[error("saved historical ACTION could not be retried yet")]
    PendingActionRetry,
    #[error("saved historical ACTION no longer matches the current head")]
    PendingActionConflict,
    #[error("selected historical kernel command is unresolved and retained")]
    KernelCommandUnresolved,
}

impl HistoricalOwnerAttachError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input => "INPUT_INVALID",
            Self::SourceChanged => "SOURCE_CHANGED",
            Self::SourceUnresolved => "SOURCE_UNRESOLVED",
            Self::Identity => "IDENTITY_CHANGED",
            Self::Conflict => "ATTACH_CONFLICT",
            Self::NotFound => "NOT_FOUND",
            Self::Local => "LOCAL_STATE_FAILED",
            Self::Verification => "VERIFICATION_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::PendingActionRetry => "PENDING_ACTION_RETRY",
            Self::PendingActionConflict => "PENDING_ACTION_CONFLICT",
            Self::KernelCommandUnresolved => "KERNEL_COMMAND_UNRESOLVED",
        }
    }
}

impl From<crate::secure_read_access::SecureReadAccessError> for HistoricalOwnerAttachError {
    fn from(_: crate::secure_read_access::SecureReadAccessError) -> Self {
        Self::Verification
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedAttach {
    input: HistoricalOwnerAttachInput,
    #[serde(default = "private_visibility")]
    visibility: String,
    ts_state_sha256: String,
    owner_pem_sha256: String,
    ts_intent_sha256: String,
    source_sequence: u64,
    source_head: Option<String>,
    source_policy_hash: String,
    attached_sequence: Option<u64>,
    attached_head: Option<String>,
    #[serde(default)]
    kernel_import: Option<SavedKernelImport>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SavedKernelImport {
    backup_digest: String,
    selected: Vec<crate::kernel_intents::SelectedKernelSourceRow>,
    retained_other_pending_count: usize,
    retained_nonworkspace_pending_count: usize,
    #[serde(default)]
    last_http_status: BTreeMap<String, u16>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachHistory {
    version: u8,
    origin: String,
    rows: BTreeMap<String, SavedAttach>,
}

struct LegacySource {
    visibility: String,
    ring: Option<SecretKeyring>,
    sequence: u64,
    head: Option<String>,
    policy_hash: String,
    retained_member_commands: Vec<String>,
    retained_inbox_receipts: Vec<RetainedInboxReceipt>,
    pending_action: Option<LegacyPendingAction>,
}

struct LegacyPendingAction {
    command_id: String,
    action_id: String,
    path: String,
    request: Zeroizing<Vec<u8>>,
    sequence: u64,
    previous: Option<String>,
    policy_hash: String,
    epoch: u64,
    visibility: String,
    version: u64,
    protocol_format_ceiling: Option<u64>,
}

#[derive(Clone)]
struct RetainedInboxReceipt {
    item_id: String,
    workspace_id: String,
    source_record_id: String,
    source_revision: u64,
    source_hash: String,
}

fn private_visibility() -> String {
    "PRIVATE".into()
}

pub struct SecureHistoricalOwnerAttach {
    config: SecureOwnerCreateConfig,
}

impl SecureHistoricalOwnerAttach {
    pub fn new(config: SecureOwnerCreateConfig) -> Self {
        Self { config }
    }

    /// Read-only verified selection inventory. The checked local backup may
    /// be created, but no attach row, keyring, intent, or POST is produced.
    /// The old client must stay quiescent through the subsequent attach.
    pub fn inspect_kernel_pending(
        &self,
        input: &HistoricalOwnerAttachInput,
        cancel: &CancellationToken,
    ) -> Result<HistoricalKernelPendingInventory, HistoricalOwnerAttachError> {
        validate_input(input)?;
        let (_, _, _, digest) = self.inspect_sources(input)?;
        let selected = self.preflight_kernel_source(input, cancel, None)?;
        let current = crate::ts_migration::source_snapshot_digest_allow_pending(
            &input.protected_ts_intent_db_path,
        )
        .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        if current != digest {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| HistoricalOwnerAttachError::Local)?
            .as_millis() as u64;
        Ok(HistoricalKernelPendingInventory {
            intent_db_digest: digest,
            commands: selected
                .selected
                .into_iter()
                .map(|row| HistoricalKernelCommandStatus {
                    command_id: row.command_id,
                    intent_digest: row.intent_digest,
                    expires_at_ms: row.expires_at_ms,
                    status: if now >= row.expires_at_ms {
                        "EXPIRED_UNRESOLVED"
                    } else {
                        "PENDING"
                    }
                    .into(),
                    last_http_status: None,
                })
                .collect(),
            retained_other_pending_count: selected.retained_other_pending_count,
            retained_nonworkspace_pending_count: selected.retained_nonworkspace_pending_count,
        })
    }

    fn preflight_kernel_source(
        &self,
        input: &HistoricalOwnerAttachInput,
        cancel: &CancellationToken,
        selected_ids: Option<&[String]>,
    ) -> Result<crate::kernel_intents::SelectedKernelImport, HistoricalOwnerAttachError> {
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        ensure_dir(&self.config.state_dir)?;
        let directory = self.workspace_dir(&input.workspace_id);
        ensure_dir(&directory)?;
        let mut transport_config = TransportConfig::new(self.config.origin.clone());
        transport_config.allow_loopback_http = self.config.allow_loopback_http;
        let transport =
            HttpTransport::new(transport_config).map_err(|_| HistoricalOwnerAttachError::Input)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let response = runtime
            .block_on(transport.discovery(cancel))
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        if !(200..300).contains(&response.status) {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        let discovery = peerwork_core::discovery::parse_discovery_wire(
            &response.wire,
            crate::transport::MAX_DISCOVERY_BYTES,
        )
        .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        crate::kernel_intents::inspect_ts_backup_selected(
            &input.protected_ts_intent_db_path,
            &directory.join("historical-ts-intents-backup.sqlite"),
            &discovery,
            &input.expected_owner_actor_id,
            &input.expected_owner_key_id,
            &input.workspace_id,
            selected_ids,
        )
        .map_err(|error| match error {
            crate::ts_migration::TsMigrationError::Unresolved => {
                HistoricalOwnerAttachError::SourceUnresolved
            }
            _ => HistoricalOwnerAttachError::SourceChanged,
        })
    }

    pub fn attach(
        &self,
        input: HistoricalOwnerAttachInput,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        validate_input(&input)?;
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        let (source, ts_digest, pem_digest, intent_digest) = self.inspect_sources(&input)?;
        if !input.kernel_pending_command_ids.is_empty()
            && input.expected_kernel_intent_db_digest.is_none()
        {
            return Err(HistoricalOwnerAttachError::Input);
        }
        if input
            .expected_kernel_intent_db_digest
            .as_deref()
            .is_some_and(|expected| expected != intent_digest)
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let root = &self.config.state_dir;
        ensure_dir(root)?;
        let source_owner =
            KernelIdentity::inspect_pkcs8_pem_file(&input.protected_owner_pkcs8_path)
                .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        match KernelIdentity::open(&self.identity_path()) {
            Ok(existing)
                if existing.actor_id() == source_owner.actor_id()
                    && existing.key_id() == source_owner.key_id() =>
            {
                ()
            }
            Err(KernelIdentityError::NotFound) => (),
            _ => return Err(HistoricalOwnerAttachError::Identity),
        }
        if SecureOwnerWorkspaceCreate::new(self.config.clone())
            .has_saved_workspace_for_attach(&input.workspace_id, &source_owner)
            .map_err(|_| HistoricalOwnerAttachError::Conflict)?
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        // Validate the complete signed target selection before an immutable
        // PREPARED row, pending ring, or optional secure ACTION can be written.
        self.preflight_kernel_source(&input, cancel, Some(&input.kernel_pending_command_ids))?;
        if crate::ts_migration::source_snapshot_digest_allow_pending(
            &input.protected_ts_intent_db_path,
        )
        .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?
            != intent_digest
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let store = SecureStateStore::open(&root.join("owner-attach.state"))
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let mut history = read_history(&store, &self.config.origin)?;
        if let Some((id, row)) = history
            .rows
            .iter()
            .find(|(_, row)| row.input.workspace_id == input.workspace_id)
        {
            if row.input != input
                || row.visibility != source.visibility
                || row.ts_state_sha256 != ts_digest
                || row.owner_pem_sha256 != pem_digest
                || row.ts_intent_sha256 != intent_digest
                || row.source_sequence != source.sequence
                || row.source_head != source.head
                || row.source_policy_hash != source.policy_hash
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            let id = id.clone();
            drop(history);
            drop(store);
            return self.resume_attachment(&id, cancel);
        }
        if history.rows.len() >= MAX_HISTORY {
            return Err(HistoricalOwnerAttachError::Local);
        }
        let id = random_token()?;
        let row = SavedAttach {
            input,
            visibility: source.visibility,
            ts_state_sha256: ts_digest,
            owner_pem_sha256: pem_digest,
            ts_intent_sha256: intent_digest,
            source_sequence: source.sequence,
            source_head: source.head,
            source_policy_hash: source.policy_hash,
            attached_sequence: None,
            attached_head: None,
            kernel_import: None,
        };
        history.rows.insert(id.clone(), row);
        save_history(&store, &history)?;
        drop(history);
        drop(store);
        #[cfg(test)]
        if TEST_STOP_AFTER_ATTACH_ROW.swap(false, Ordering::SeqCst) {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        self.resume_attachment(&id, cancel)
    }

    pub fn resume_attachment(
        &self,
        attach_id: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_token(attach_id) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        // Hold one root-scoped migration lock across history, action-intent,
        // network and ATTACHED writes. Two resumes must not both observe an
        // unapplied packet and submit it before either can persist the receipt.
        let _recovery_lock =
            SecureStateStore::open(&self.config.state_dir.join("owner-attach-recovery.state"))
                .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let history = read_history(&store, &self.config.origin)?;
        let row = history
            .rows
            .get(attach_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)?
            .clone();
        drop(history);
        drop(store);
        if row.attached_sequence.is_some() && row.kernel_import.is_some() {
            self.checked_kernel_commands(attach_id)?;
            SecureReadProfile::new(self.profile_config(&row.input))
                .read_latest_json_with_cancel(cancel)
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
            return Ok(summary(attach_id, &row));
        }
        let (source, ts_digest, pem_digest, intent_digest) = self.inspect_sources(&row.input)?;
        if ts_digest != row.ts_state_sha256
            || source.visibility != row.visibility
            || pem_digest != row.owner_pem_sha256
            || intent_digest != row.ts_intent_sha256
            || source.sequence != row.source_sequence
            || source.head != row.source_head
            || source.policy_hash != row.source_policy_hash
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let owner = match KernelIdentity::open(&self.identity_path()) {
            Ok(identity) => identity,
            Err(KernelIdentityError::NotFound) => KernelIdentity::import_pkcs8_pem_file(
                &self.identity_path(),
                &row.input.protected_owner_pkcs8_path,
            )
            .map_err(|_| HistoricalOwnerAttachError::Identity)?,
            Err(_) => return Err(HistoricalOwnerAttachError::Identity),
        };
        if owner.actor_id() != row.input.expected_owner_actor_id
            || owner.key_id() != row.input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        let directory = self.workspace_dir(&row.input.workspace_id);
        ensure_dir(&directory)?;
        if let Some(ring) = source.ring.as_ref() {
            let mut lifecycle = SecureLifecycle::open(
                &directory.join("lifecycle.state"),
                &self.config.origin,
                owner.actor_id(),
                &row.input.workspace_id,
                owner.actor_id(),
                owner.key_id(),
            )
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
            lifecycle
                .stage_historical_owner_ring(ring)
                .map_err(|_| HistoricalOwnerAttachError::Conflict)?;
        }
        let access = SecureReadAccess::new(self.attach_read_config(&row.input));
        let mut replayed = access
            .replay_checked_attach_generation(cancel)
            .map_err(|_| {
                if cancel.is_cancelled() {
                    HistoricalOwnerAttachError::Cancelled
                } else {
                    HistoricalOwnerAttachError::Verification
                }
            })?;
        for command in &source.retained_member_commands {
            let completed = replayed.signed_commit_wires().iter().any(|wire| {
                parse_wire_json_bounded(wire, 64, 262_144)
                    .ok()
                    .and_then(|commit| commit.get("payload")?.get("command_id")?.as_string())
                    .as_deref()
                    == Some(command.as_str())
            });
            if !completed {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
        }
        for receipt in &source.retained_inbox_receipts {
            let completed = replayed.signed_commit_wires().iter().any(|wire| {
                parse_wire_json_bounded(wire, 64, 262_144)
                    .ok()
                    .is_some_and(|commit| {
                        signed_owner_ack_matches(
                            &commit,
                            receipt,
                            &row.input.expected_owner_actor_id,
                            &row.input.expected_owner_key_id,
                        )
                    })
            });
            if !completed {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
        }
        let policy_wire = replayed
            .signed_policy_by_hash(replayed.replay().policy_hash())
            .ok_or(HistoricalOwnerAttachError::Verification)?;
        let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        let payload = policy
            .get("payload")
            .ok_or(HistoricalOwnerAttachError::Verification)?;
        let epoch =
            exact_u64(payload.get("epoch")).ok_or(HistoricalOwnerAttachError::Verification)?;
        let owner_member = match payload.get("members") {
            Some(WireValue::Array(members)) => members.iter().any(|member| {
                member
                    .get("actor_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(row.input.expected_owner_actor_id.as_str())
                    && member.get("role").and_then(WireValue::as_string).as_deref() == Some("OWNER")
                    && member
                        .get("certificate")
                        .and_then(|cert| cert.get("payload"))
                        .and_then(|cert| cert.get("signing_key"))
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some(row.input.expected_owner_key_id.as_str())
            }),
            _ => false,
        };
        if payload
            .get("visibility")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(row.visibility.as_str())
            || !owner_member
            || (row.visibility == "PRIVATE"
                && source.ring.as_ref().and_then(|ring| ring.epochs().last()) != Some(epoch))
            || (row.visibility == "PUBLIC" && (epoch != 0 || source.ring.is_some()))
            || replayed.replay().structure_status() == StructureStatus::Seeding
            || !replayed.replay().contains_checkpoint(
                row.source_sequence,
                row.source_head.as_deref(),
                &row.source_policy_hash,
            )
        {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        let profile = SecureReadProfile::new(self.profile_config(&row.input));
        if let Some(floor) = profile
            .existing_floor_for_attach()
            .map_err(|_| HistoricalOwnerAttachError::Conflict)?
        {
            if !replayed.replay().contains_checkpoint(
                floor.sequence,
                floor.head.as_deref(),
                &floor.policy_hash,
            ) {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
        }
        if let Some(pending) = source.pending_action.as_ref() {
            self.recover_pending_action(&row, pending, &owner, &access, &mut replayed, cancel)?;
            #[cfg(test)]
            if TEST_STOP_AFTER_IMPORTED_ACTION_ACCEPTED.swap(false, Ordering::SeqCst) {
                return Err(HistoricalOwnerAttachError::Cancelled);
            }
        }
        let kernel_import = self.import_selected_kernel_source(&row, &owner, cancel)?;
        {
            let store = SecureStateStore::open(&self.history_path())
                .map_err(|_| HistoricalOwnerAttachError::Local)?;
            let mut history = read_history(&store, &self.config.origin)?;
            let saved = history
                .rows
                .get_mut(attach_id)
                .ok_or(HistoricalOwnerAttachError::NotFound)?;
            if saved.input != row.input || saved.ts_intent_sha256 != row.ts_intent_sha256 {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            if saved
                .kernel_import
                .as_ref()
                .is_some_and(|old| old != &kernel_import)
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            if saved.kernel_import.is_none() {
                saved.kernel_import = Some(kernel_import.clone());
                save_history(&store, &history)?;
            }
        }
        if let Some(ring) = source.ring.as_ref() {
            let mut lifecycle = SecureLifecycle::open(
                &directory.join("lifecycle.state"),
                &self.config.origin,
                owner.actor_id(),
                &row.input.workspace_id,
                owner.actor_id(),
                owner.key_id(),
            )
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
            lifecycle
                .activate_verified_historical_owner(
                    ring,
                    &replayed,
                    row.source_sequence,
                    row.source_head.as_deref(),
                    &row.source_policy_hash,
                )
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        }
        profile.read_latest_json_with_cancel(cancel).map_err(|_| {
            if cancel.is_cancelled() {
                HistoricalOwnerAttachError::Cancelled
            } else {
                HistoricalOwnerAttachError::Verification
            }
        })?;
        self.assert_source_unchanged(&row)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let mut history = read_history(&store, &self.config.origin)?;
        let saved = history
            .rows
            .get_mut(attach_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)?;
        if saved.input != row.input
            || saved.ts_state_sha256 != row.ts_state_sha256
            || saved.owner_pem_sha256 != row.owner_pem_sha256
            || saved.ts_intent_sha256 != row.ts_intent_sha256
            || saved.kernel_import.as_ref() != Some(&kernel_import)
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        saved.attached_sequence = Some(replayed.replay().sequence());
        saved.attached_head = replayed.replay().head().map(str::to_owned);
        let completed = saved.clone();
        save_history(&store, &history)?;
        Ok(summary(attach_id, &completed))
    }

    fn import_selected_kernel_source(
        &self,
        row: &SavedAttach,
        owner: &KernelIdentity,
        cancel: &CancellationToken,
    ) -> Result<SavedKernelImport, HistoricalOwnerAttachError> {
        let directory = self.workspace_dir(&row.input.workspace_id);
        let access = crate::kernel_access::KernelAccess::new(
            &self.config.origin,
            directory.join("historical-kernel.sqlite"),
            self.identity_path(),
            &[],
            self.config.allow_loopback_http,
        );
        let backup = directory.join("historical-ts-intents-backup.sqlite");
        let imported = access
            .migrate_ts_store_selected(
                &row.input.protected_ts_intent_db_path,
                &backup,
                &row.input.workspace_id,
                &row.input.kernel_pending_command_ids,
                cancel,
            )
            .map_err(|error| match error {
                crate::kernel_access::KernelAccessError::Client(
                    crate::kernel_client::KernelClientError::Migration(
                        crate::ts_migration::TsMigrationError::Unresolved,
                    ),
                ) => HistoricalOwnerAttachError::SourceUnresolved,
                _ => HistoricalOwnerAttachError::SourceChanged,
            })?;
        if owner.actor_id() != row.input.expected_owner_actor_id
            || owner.key_id() != row.input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        let backup_digest = crate::ts_migration::source_snapshot_digest_allow_pending(&backup)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        if backup_digest != row.ts_intent_sha256 {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        self.assert_source_unchanged(row)?;
        let mut last_http_status = row
            .kernel_import
            .as_ref()
            .map_or_else(BTreeMap::new, |saved| saved.last_http_status.clone());
        last_http_status
            .retain(|id, _| imported.selected.iter().any(|item| &item.command_id == id));
        let result = SavedKernelImport {
            backup_digest,
            selected: imported.selected,
            retained_other_pending_count: imported.retained_other_pending_count,
            retained_nonworkspace_pending_count: imported.retained_nonworkspace_pending_count,
            last_http_status,
        };
        if row
            .kernel_import
            .as_ref()
            .is_some_and(|saved| saved != &result)
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        Ok(result)
    }

    fn recover_pending_action(
        &self,
        row: &SavedAttach,
        pending: &LegacyPendingAction,
        owner: &KernelIdentity,
        access: &SecureReadAccess,
        replayed: &mut TransportReplayedJournal,
        cancel: &CancellationToken,
    ) -> Result<(), HistoricalOwnerAttachError> {
        if !row.input.recover_pending_action
            || row.visibility != pending.visibility
            || !replayed.replay().contains_checkpoint(
                row.source_sequence,
                row.source_head.as_deref(),
                &row.source_policy_hash,
            )
        {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        let policy_wire = replayed
            .signed_policy_by_hash(&pending.policy_hash)
            .ok_or(HistoricalOwnerAttachError::Verification)?;
        let pins = SecureCommitRequestPins {
            actor_id: owner.actor_id(),
            signing_key: owner.key_id(),
            workspace_id: &row.input.workspace_id,
            policy_hash: &pending.policy_hash,
            sequence: pending.sequence,
            previous: pending.previous.as_deref(),
            epoch: pending.epoch,
            mode: &pending.visibility,
            version: pending.version,
            protocol_format_ceiling: pending.protocol_format_ceiling,
        };
        let proof = verify_prepared_secure_commit_request_with_policy(
            &pending.request,
            &pending.path,
            &pins,
            policy_wire,
            owner.key_id(),
        )
        .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        if proof.command_id() != pending.command_id
            || proof.action_id() != pending.action_id
            || proof.workspace_id() != row.input.workspace_id
            || proof.actor_id() != owner.actor_id()
            || proof.signing_key() != owner.key_id()
        {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        let packet = || SecurePacketInput {
            intent_id: &pending.command_id,
            path: &pending.path,
            action_id: &pending.action_id,
            workspace_id: Some(&row.input.workspace_id),
            trusted_owner_key: Some(owner.key_id()),
            intent_digest: proof.commit_digest(),
            exact_request: &pending.request,
        };
        let mut journal = SecureIntentJournal::open(
            &self
                .workspace_dir(&row.input.workspace_id)
                .join("action-intents.state"),
            &self.config.origin,
            owner.actor_id(),
        )
        .map_err(|_| HistoricalOwnerAttachError::Local)?;
        if journal.contains_id(&pending.command_id) {
            journal
                .exact_imported_action_matches(packet())
                .map_err(|_| HistoricalOwnerAttachError::Conflict)?;
        } else {
            journal
                .prepare(packet())
                .map_err(|_| HistoricalOwnerAttachError::Local)?;
        }
        let mut transport_config = TransportConfig::new(self.config.origin.clone());
        transport_config.allow_loopback_http = self.config.allow_loopback_http;
        let transport = HttpTransport::new(transport_config)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        match journal.accept_replayed_imported_owner_action(
            &pending.command_id,
            owner,
            &transport,
            replayed,
        ) {
            Ok(_) => return Ok(()),
            Err(SecureIntentError::ReplayMismatch) => (),
            Err(_) => return Err(HistoricalOwnerAttachError::Verification),
        }
        if replayed.replay().sequence().checked_add(1) != Some(pending.sequence)
            || replayed.replay().head() != pending.previous.as_deref()
            || replayed.replay().policy_hash() != pending.policy_hash
        {
            return Err(HistoricalOwnerAttachError::PendingActionConflict);
        }
        self.assert_source_unchanged(row)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        #[cfg(test)]
        TEST_IMPORTED_ACTION_POSTS.fetch_add(1, Ordering::SeqCst);
        let submitted = runtime.block_on(journal.submit_saved_imported_owner_commit_from_replay(
            &pending.command_id,
            owner,
            &transport,
            replayed,
            &pins,
            cancel,
        ));
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        let refreshed = access
            .replay_checked_attach_generation(cancel)
            .map_err(|_| HistoricalOwnerAttachError::PendingActionRetry)?;
        if !refreshed.replay().contains_checkpoint(
            row.source_sequence,
            row.source_head.as_deref(),
            &row.source_policy_hash,
        ) {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        *replayed = refreshed;
        match journal.accept_replayed_imported_owner_action(
            &pending.command_id,
            owner,
            &transport,
            replayed,
        ) {
            Ok(_) => Ok(()),
            Err(SecureIntentError::ReplayMismatch) => {
                if replayed.replay().sequence().checked_add(1) != Some(pending.sequence)
                    || replayed.replay().head() != pending.previous.as_deref()
                {
                    Err(HistoricalOwnerAttachError::PendingActionConflict)
                } else {
                    match submitted {
                        Ok(_)
                        | Err(SecureIntentError::Transport(_))
                        | Err(SecureIntentError::ServerRejected(500..=599)) => {
                            Err(HistoricalOwnerAttachError::PendingActionRetry)
                        }
                        Err(SecureIntentError::ServerRejected(_))
                        | Err(SecureIntentError::ReplayMismatch) => {
                            Err(HistoricalOwnerAttachError::PendingActionConflict)
                        }
                        Err(_) => Err(HistoricalOwnerAttachError::Verification),
                    }
                }
            }
            Err(_) => Err(HistoricalOwnerAttachError::Verification),
        }
    }

    fn assert_source_unchanged(&self, row: &SavedAttach) -> Result<(), HistoricalOwnerAttachError> {
        let (source, state_digest, pem_digest, intent_digest) = self.inspect_sources(&row.input)?;
        if state_digest != row.ts_state_sha256
            || pem_digest != row.owner_pem_sha256
            || intent_digest != row.ts_intent_sha256
            || source.visibility != row.visibility
            || source.sequence != row.source_sequence
            || source.head != row.source_head
            || source.policy_hash != row.source_policy_hash
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        Ok(())
    }

    fn checked_kernel_commands(
        &self,
        attach_id: &str,
    ) -> Result<(SavedAttach, Vec<HistoricalKernelCommandStatus>), HistoricalOwnerAttachError> {
        if !valid_history_config(&self.config) || !valid_token(attach_id) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let history = read_history(&store, &self.config.origin)?;
        let row = history
            .rows
            .get(attach_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)?
            .clone();
        drop(history);
        drop(store);
        if row.attached_sequence.is_none() {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        let kernel = row
            .kernel_import
            .as_ref()
            .ok_or(HistoricalOwnerAttachError::Local)?;
        let backup = self
            .workspace_dir(&row.input.workspace_id)
            .join("historical-ts-intents-backup.sqlite");
        let digest = crate::ts_migration::source_snapshot_digest_allow_pending(&backup)
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        if digest != kernel.backup_digest || digest != row.ts_intent_sha256 {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let owner = KernelIdentity::open(&self.identity_path())
            .map_err(|_| HistoricalOwnerAttachError::Identity)?;
        if owner.actor_id() != row.input.expected_owner_actor_id
            || owner.key_id() != row.input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        let journal = crate::kernel_intents::KernelIntentJournal::open(
            &self
                .workspace_dir(&row.input.workspace_id)
                .join("historical-kernel.sqlite"),
        )
        .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| HistoricalOwnerAttachError::Local)?
            .as_millis() as u64;
        let mut statuses = Vec::with_capacity(kernel.selected.len());
        for selected in &kernel.selected {
            let local = journal
                .locally_verified_status(&selected.command_id, owner.key_id(), &self.config.origin)
                .map_err(|_| HistoricalOwnerAttachError::Local)?
                .ok_or(HistoricalOwnerAttachError::Local)?;
            if local.actor_id != owner.actor_id()
                || local.workspace_id.as_deref() != Some(row.input.workspace_id.as_str())
                || local.intent_digest != selected.intent_digest
                || local.expires_at_ms != selected.expires_at_ms
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            let last_http_status = kernel.last_http_status.get(&selected.command_id).copied();
            statuses.push(HistoricalKernelCommandStatus {
                command_id: selected.command_id.clone(),
                intent_digest: selected.intent_digest.clone(),
                expires_at_ms: selected.expires_at_ms,
                status: if local.accepted {
                    "ACCEPTED"
                } else if now >= selected.expires_at_ms {
                    "EXPIRED_UNRESOLVED"
                } else if last_http_status.is_some() {
                    "RETAINED_UNRESOLVED"
                } else {
                    "PENDING"
                }
                .into(),
                last_http_status,
            });
        }
        Ok((row, statuses))
    }

    /// Read-only local history. No command is transmitted by listing status.
    pub fn kernel_command_status(
        &self,
        attach_id: &str,
    ) -> Result<Vec<HistoricalKernelCommandStatus>, HistoricalOwnerAttachError> {
        Ok(self.checked_kernel_commands(attach_id)?.1)
    }

    /// Explicitly retry one selected original JWS. Rejection or expiry leaves
    /// the protected packet intact and does not imply a signed terminal result.
    pub fn recover_kernel_command(
        &self,
        attach_id: &str,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalKernelCommandStatus, HistoricalOwnerAttachError> {
        if !valid_token(command_id) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        let _recovery_lock =
            SecureStateStore::open(&self.config.state_dir.join("owner-attach-recovery.state"))
                .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let (row, statuses) = self.checked_kernel_commands(attach_id)?;
        let selected = statuses
            .into_iter()
            .find(|item| item.command_id == command_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)?;
        if selected.status == "ACCEPTED" || selected.status == "EXPIRED_UNRESOLVED" {
            return Ok(selected);
        }
        let replayed = SecureReadAccess::new(self.attach_read_config(&row.input))
            .replay_checked_attach_generation(cancel)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        if !replayed.replay().contains_checkpoint(
            row.source_sequence,
            row.source_head.as_deref(),
            &row.source_policy_hash,
        ) || replayed.replay().sequence() < row.attached_sequence.unwrap_or(u64::MAX)
        {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        SecureReadProfile::new(self.profile_config(&row.input))
            .read_latest_json_with_cancel(cancel)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        let kernel_access = crate::kernel_access::KernelAccess::new(
            &self.config.origin,
            self.workspace_dir(&row.input.workspace_id)
                .join("historical-kernel.sqlite"),
            self.identity_path(),
            &[],
            self.config.allow_loopback_http,
        );
        let result = kernel_access.submit_saved_with_cancel(command_id, cancel);
        let mut observed_http = None;
        match result {
            Ok(accepted)
                if accepted.command_id == command_id
                    && accepted.workspace_id.as_deref()
                        == Some(row.input.workspace_id.as_str()) => {}
            Ok(_) => return Err(HistoricalOwnerAttachError::Verification),
            Err(crate::kernel_access::KernelAccessError::Client(
                crate::kernel_client::KernelClientError::ServerRejected(status),
            )) => observed_http = Some(status),
            Err(_) => return Err(HistoricalOwnerAttachError::KernelCommandUnresolved),
        }
        if let Some(status) = observed_http {
            let store = SecureStateStore::open(&self.history_path())
                .map_err(|_| HistoricalOwnerAttachError::Local)?;
            let mut history = read_history(&store, &self.config.origin)?;
            let saved = history
                .rows
                .get_mut(attach_id)
                .ok_or(HistoricalOwnerAttachError::NotFound)?;
            if saved.input != row.input
                || saved.ts_intent_sha256 != row.ts_intent_sha256
                || saved
                    .kernel_import
                    .as_ref()
                    .map(|kernel| kernel.backup_digest.as_str())
                    != row
                        .kernel_import
                        .as_ref()
                        .map(|kernel| kernel.backup_digest.as_str())
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            saved
                .kernel_import
                .as_mut()
                .unwrap()
                .last_http_status
                .insert(command_id.into(), status);
            save_history(&store, &history)?;
        }
        self.checked_kernel_commands(attach_id)?
            .1
            .into_iter()
            .find(|item| item.command_id == command_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)
    }

    pub fn attachments(
        &self,
    ) -> Result<Vec<HistoricalOwnerAttachResult>, HistoricalOwnerAttachError> {
        if !valid_history_config(&self.config) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        match std::fs::symlink_metadata(&self.config.state_dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(HistoricalOwnerAttachError::Local),
            Ok(_) => ensure_dir(&self.config.state_dir)?,
        }
        let history_path = self.history_path();
        let lock_path = history_path.with_extension("state.lock");
        if matches!(std::fs::symlink_metadata(&history_path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
            && matches!(std::fs::symlink_metadata(&lock_path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(Vec::new());
        }
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let history = read_history(&store, &self.config.origin)?;
        Ok(history
            .rows
            .iter()
            .map(|(id, row)| summary(id, row))
            .collect())
    }

    /// Only an ATTACHED row may select an ordinary profile. The consumer still
    /// refreshes and verifies the signed current state before authoring.
    pub(crate) fn attached_profile_config(
        &self,
        workspace_id: &str,
        visibility: &str,
    ) -> Result<SecureReadProfileConfig, HistoricalOwnerAttachError> {
        let owner = KernelIdentity::open(&self.identity_path())
            .map_err(|_| HistoricalOwnerAttachError::Identity)?;
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let history = read_history(&store, &self.config.origin)?;
        let row = history
            .rows
            .values()
            .find(|row| {
                row.input.workspace_id == workspace_id
                    && row.visibility == visibility
                    && row.attached_sequence.is_some()
            })
            .ok_or(HistoricalOwnerAttachError::NotFound)?;
        if owner.actor_id() != row.input.expected_owner_actor_id
            || owner.key_id() != row.input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        Ok(self.profile_config(&row.input))
    }

    pub(crate) fn read_workspace_json(
        &self,
        workspace_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, HistoricalOwnerAttachError> {
        let store = SecureStateStore::open(&self.history_path())
            .map_err(|_| HistoricalOwnerAttachError::Local)?;
        let history = read_history(&store, &self.config.origin)?;
        let row = history
            .rows
            .values()
            .find(|row| row.input.workspace_id == workspace_id && row.attached_sequence.is_some())
            .ok_or(HistoricalOwnerAttachError::NotFound)?
            .clone();
        drop(history);
        drop(store);
        let config = self.attached_profile_config(workspace_id, &row.visibility)?;
        let profile = SecureReadProfile::new(config);
        let json = profile.read_latest_json_with_cancel(cancel).map_err(|_| {
            if cancel.is_cancelled() {
                HistoricalOwnerAttachError::Cancelled
            } else {
                HistoricalOwnerAttachError::Verification
            }
        })?;
        profile.with_pinned_replay(cancel, |replayed| {
            if !replayed.replay().contains_checkpoint(
                row.source_sequence,
                row.source_head.as_deref(),
                &row.source_policy_hash,
            ) {
                return Err(HistoricalOwnerAttachError::Verification);
            }
            replayed
                .verified_read()
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
            Ok(())
        })?;
        Ok(json)
    }

    fn inspect_sources(
        &self,
        input: &HistoricalOwnerAttachInput,
    ) -> Result<(LegacySource, String, String, String), HistoricalOwnerAttachError> {
        let pem = read_private_file_bounded(&input.protected_owner_pkcs8_path, 2048)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        let owner = KernelIdentity::inspect_pkcs8_pem_file(&input.protected_owner_pkcs8_path)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        if owner.actor_id() != input.expected_owner_actor_id
            || owner.key_id() != input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        let pem_digest = sha256_hex(&pem);
        let state = read_private_file_bounded(&input.protected_ts_state_path, MAX_SOURCE)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        let digest = sha256_hex(&state);
        let source = parse_legacy_source(&state, input)?;
        let intent_digest = crate::ts_migration::source_snapshot_digest_allow_pending(
            &input.protected_ts_intent_db_path,
        )
        .map_err(|error| match error {
            crate::ts_migration::TsMigrationError::Unresolved => {
                HistoricalOwnerAttachError::SourceUnresolved
            }
            _ => HistoricalOwnerAttachError::SourceChanged,
        })?;
        Ok((source, digest, pem_digest, intent_digest))
    }

    fn history_path(&self) -> PathBuf {
        self.config.state_dir.join("owner-attach.state")
    }
    fn identity_path(&self) -> PathBuf {
        self.config.state_dir.join("identity.state")
    }
    fn workspace_dir(&self, id: &str) -> PathBuf {
        self.config.state_dir.join("workspaces").join(id)
    }
    fn profile_config(&self, input: &HistoricalOwnerAttachInput) -> SecureReadProfileConfig {
        SecureReadProfileConfig {
            origin: self.config.origin.clone(),
            state_dir: self.workspace_dir(&input.workspace_id),
            identity_path: self.identity_path(),
            workspace_id: input.workspace_id.clone(),
            owner_actor_id: Some(input.expected_owner_actor_id.clone()),
            owner_key_id: Some(input.expected_owner_key_id.clone()),
            authority: Some(sha256_hex(input.expected_owner_actor_id.as_bytes())),
            required_features: Vec::new(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
        }
    }
    fn attach_read_config(&self, input: &HistoricalOwnerAttachInput) -> SecureReadConfig {
        let directory = self.workspace_dir(&input.workspace_id);
        SecureReadConfig {
            origin: self.config.origin.clone(),
            kernel_journal_path: directory.join("kernel.sqlite"),
            read_state_path: directory.join("owner-attach-pages.state"),
            lifecycle_path: directory.join("lifecycle.state"),
            identity_path: self.identity_path(),
            workspace_id: input.workspace_id.clone(),
            authority: sha256_hex(input.expected_owner_actor_id.as_bytes()),
            owner_actor_id: input.expected_owner_actor_id.clone(),
            owner_key_id: input.expected_owner_key_id.clone(),
            required_features: Vec::new(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
        }
    }
}

fn valid_history_config(config: &SecureOwnerCreateConfig) -> bool {
    if !config.state_dir.is_absolute() {
        return false;
    }
    let mut transport_config = TransportConfig::new(config.origin.clone());
    transport_config.allow_loopback_http = config.allow_loopback_http;
    let Ok(transport) = HttpTransport::new(transport_config) else {
        return false;
    };
    transport.trusted_origin() == config.origin
        || transport.trusted_origin().strip_suffix('/') == Some(&config.origin)
}

fn summary(id: &str, row: &SavedAttach) -> HistoricalOwnerAttachResult {
    HistoricalOwnerAttachResult {
        attach_id: id.into(),
        workspace_id: row.input.workspace_id.clone(),
        provenance: "HISTORICAL_TS_OWNER".into(),
        status: if row.attached_sequence.is_some() {
            "ATTACHED"
        } else {
            "PREPARED"
        }
        .into(),
        owner_actor_id: row.input.expected_owner_actor_id.clone(),
        owner_key_id: row.input.expected_owner_key_id.clone(),
        sequence: row.attached_sequence,
        head: row.attached_head.clone(),
        selected_kernel_count: row
            .kernel_import
            .as_ref()
            .map_or(0, |kernel| kernel.selected.len()),
        retained_other_kernel_count: row.kernel_import.as_ref().map_or(0, |kernel| {
            kernel.retained_other_pending_count + kernel.retained_nonworkspace_pending_count
        }),
    }
}

fn read_history(
    store: &SecureStateStore,
    origin: &str,
) -> Result<AttachHistory, HistoricalOwnerAttachError> {
    let bytes = store
        .read_exact()
        .map_err(|_| HistoricalOwnerAttachError::Local)?;
    let doc = match bytes {
        Some(bytes) => {
            if bytes.len() > MAX_HISTORY_WIRE {
                return Err(HistoricalOwnerAttachError::Local);
            }
            serde_json::from_slice::<AttachHistory>(&bytes)
                .map_err(|_| HistoricalOwnerAttachError::Local)?
        }
        None => AttachHistory {
            version: 1,
            origin: origin.into(),
            rows: BTreeMap::new(),
        },
    };
    if doc.version != 1
        || doc.origin != origin
        || doc.rows.len() > MAX_HISTORY
        || doc.rows.iter().any(|(id, row)| {
            !valid_token(id)
                || validate_input(&row.input).is_err()
                || !matches!(row.visibility.as_str(), "PRIVATE" | "PUBLIC")
        })
    {
        return Err(HistoricalOwnerAttachError::Conflict);
    }
    Ok(doc)
}

fn save_history(
    store: &SecureStateStore,
    doc: &AttachHistory,
) -> Result<(), HistoricalOwnerAttachError> {
    let bytes = serde_json::to_vec(doc).map_err(|_| HistoricalOwnerAttachError::Local)?;
    if bytes.len() > MAX_HISTORY_WIRE {
        return Err(HistoricalOwnerAttachError::Local);
    }
    store
        .write_exact(&bytes)
        .map_err(|_| HistoricalOwnerAttachError::Local)
}

fn validate_input(input: &HistoricalOwnerAttachInput) -> Result<(), HistoricalOwnerAttachError> {
    if input.kernel_pending_command_ids.len() > 4096
        || input
            .expected_kernel_intent_db_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
        || input
            .kernel_pending_command_ids
            .iter()
            .any(|id| !valid_token(id))
        || input
            .kernel_pending_command_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != input.kernel_pending_command_ids.len()
    {
        return Err(HistoricalOwnerAttachError::Input);
    }
    if !valid_token(&input.workspace_id)
        || !valid_token(&input.expected_owner_actor_id)
        || !valid_token(&input.expected_owner_key_id)
        || !input.protected_ts_state_path.is_absolute()
        || !input.protected_owner_pkcs8_path.is_absolute()
        || !input.protected_ts_intent_db_path.is_absolute()
        || input.protected_ts_state_path == input.protected_owner_pkcs8_path
        || input.protected_ts_intent_db_path == input.protected_ts_state_path
        || input.protected_ts_intent_db_path == input.protected_owner_pkcs8_path
    {
        return Err(HistoricalOwnerAttachError::Input);
    }
    Ok(())
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn parse_pending_owner_action(
    value: Option<&WireValue>,
    input: &HistoricalOwnerAttachInput,
) -> Result<Option<LegacyPendingAction>, HistoricalOwnerAttachError> {
    let Some(WireValue::Object(rows)) = value else {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    };
    if rows.is_empty() {
        return Ok(None);
    }
    if !input.recover_pending_action || rows.len() != 1 {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    let (id_units, row) = &rows[0];
    let command_id =
        String::from_utf16(id_units).map_err(|_| HistoricalOwnerAttachError::SourceUnresolved)?;
    if !valid_token(&command_id) || row.object_len() != Some(2) {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    let path = row
        .get("path")
        .and_then(WireValue::as_string)
        .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    if path
        != format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            input.workspace_id
        )
    {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    let body = row
        .get("body")
        .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    if body.object_len() != Some(1) {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    let commit = body
        .get("commit")
        .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    if commit.object_len() != Some(2)
        || commit
            .get("signature")
            .and_then(WireValue::as_string)
            .is_none()
    {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    let payload = commit
        .get("payload")
        .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    let string = |key| {
        payload
            .get(key)
            .and_then(WireValue::as_string)
            .ok_or(HistoricalOwnerAttachError::SourceUnresolved)
    };
    let action_id = string("action_id")?;
    let sequence =
        exact_u64(payload.get("sequence")).ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    let epoch =
        exact_u64(payload.get("epoch")).ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    let previous = payload
        .get("previous")
        .and_then(WireValue::as_string)
        .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    let policy_hash = string("policy_hash")?;
    let visibility = string("mode")?;
    let version =
        exact_u64(payload.get("v")).ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
    let protocol_format_ceiling = if version == 3 {
        Some(
            exact_u64(payload.get("protocol_format_ceiling"))
                .filter(|ceiling| matches!(ceiling, 1 | 2))
                .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?,
        )
    } else {
        None
    };
    if action_id.is_empty()
        || action_id.len() > 120
        || string("workspace_id")? != input.workspace_id
        || string("actor_id")? != input.expected_owner_actor_id
        || string("signing_key")? != input.expected_owner_key_id
        || string("command_id")? != command_id
        || !matches!(visibility.as_str(), "PRIVATE" | "PUBLIC")
        || !matches!(version, 1 | 2 | 3)
        || (visibility == "PRIVATE" && epoch == 0)
        || (visibility == "PUBLIC" && epoch != 0)
        || (version != 3 && payload.get("protocol_format_ceiling").is_some())
        || !valid_token(&string("instance_id")?)
        || !valid_digest(&previous)
        || !valid_digest(&policy_hash)
    {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    let request = canonical_wire_value(body, CanonicalPath::SecureArtifact)
        .map_err(|_| HistoricalOwnerAttachError::SourceUnresolved)?
        .into_bytes();
    if request.is_empty() || request.len() > 2 * 1024 * 1024 {
        return Err(HistoricalOwnerAttachError::SourceUnresolved);
    }
    Ok(Some(LegacyPendingAction {
        command_id,
        action_id,
        path,
        request: Zeroizing::new(request),
        sequence,
        previous: Some(previous),
        policy_hash,
        epoch,
        visibility,
        version,
        protocol_format_ceiling,
    }))
}

fn parse_inbox_receipts(
    value: Option<&WireValue>,
    input: &HistoricalOwnerAttachInput,
) -> Result<Vec<RetainedInboxReceipt>, HistoricalOwnerAttachError> {
    let rows = match value {
        None => return Ok(Vec::new()),
        Some(WireValue::Object(rows)) => rows,
        _ => return Err(HistoricalOwnerAttachError::SourceUnresolved),
    };
    rows.iter()
        .map(|(id, row)| {
            let item_id =
                String::from_utf16(id).map_err(|_| HistoricalOwnerAttachError::SourceUnresolved)?;
            let workspace_id = row
                .get("workspace_id")
                .and_then(WireValue::as_string)
                .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
            let source = row
                .get("source")
                .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
            let source_record_id = source
                .get("record_id")
                .and_then(WireValue::as_string)
                .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
            let source_revision = exact_u64(source.get("revision"))
                .filter(|revision| *revision > 0)
                .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
            let source_hash = row
                .get("source_hash")
                .and_then(WireValue::as_string)
                .ok_or(HistoricalOwnerAttachError::SourceUnresolved)?;
            if row.object_len() != Some(3)
                || source.object_len() != Some(2)
                || workspace_id != input.workspace_id
                || !valid_token(&source_record_id)
                || !valid_digest(&source_hash)
                || item_id
                    != format!(
                        "{}.{}.{}",
                        workspace_id, source_record_id, input.expected_owner_actor_id
                    )
            {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
            Ok(RetainedInboxReceipt {
                item_id,
                workspace_id,
                source_record_id,
                source_revision,
                source_hash,
            })
        })
        .collect()
}

fn signed_owner_ack_matches(
    commit: &WireValue,
    receipt: &RetainedInboxReceipt,
    owner_actor_id: &str,
    owner_key_id: &str,
) -> bool {
    let Some(payload) = commit.get("payload") else {
        return false;
    };
    if payload
        .get("workspace_id")
        .and_then(WireValue::as_string)
        .as_deref()
        != Some(&receipt.workspace_id)
        || payload
            .get("action_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some("coordination.ack")
        || payload
            .get("actor_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(owner_actor_id)
        || payload
            .get("signing_key")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(owner_key_id)
    {
        return false;
    }
    let Some(WireValue::Array(records)) = payload.get("structure").and_then(|s| s.get("records"))
    else {
        return false;
    };
    records.iter().any(|record| {
        let Some(fields) = record.get("fields") else {
            return false;
        };
        let Some(source) = fields.get("source_ref") else {
            return false;
        };
        record
            .get("schema_ref")
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("coordination.ack")
            && fields
                .get("author")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(owner_actor_id)
            && fields
                .get("item_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(&receipt.item_id)
            && fields
                .get("source_hash")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(&receipt.source_hash)
            && source
                .get("record_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(&receipt.source_record_id)
            && exact_u64(source.get("revision")) == Some(receipt.source_revision)
    })
}
fn exact_u64(value: Option<&WireValue>) -> Option<u64> {
    value?
        .as_number()
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= 9_007_199_254_740_991.0 && n.fract() == 0.0)
        .map(|n| n as u64)
}
fn empty_optional_map(value: Option<&WireValue>) -> bool {
    match value {
        None => true,
        Some(WireValue::Object(fields)) => fields.is_empty(),
        _ => false,
    }
}

fn object_optional_map(value: Option<&WireValue>) -> bool {
    matches!(value, None | Some(WireValue::Object(_)))
}

fn completed_signed_cache(value: Option<&WireValue>) -> bool {
    match value {
        None => true,
        Some(WireValue::Object(rows)) => rows.iter().all(|(id, signed)| {
            let id = String::from_utf16(id).ok();
            id.as_deref().is_some_and(valid_token)
                && signed.object_len() == Some(2)
                && matches!(signed.get("payload"), Some(WireValue::Object(_)))
                && signed
                    .get("signature")
                    .and_then(WireValue::as_string)
                    .is_some()
        }),
        _ => false,
    }
}

fn completed_evidence_cache(value: Option<&WireValue>) -> bool {
    match value {
        None => true,
        Some(WireValue::Object(rows)) => rows.iter().all(|(key, item)| {
            let key = String::from_utf16(key).ok();
            let kind = item.get("kind").and_then(WireValue::as_string);
            let id = item.get("id").and_then(WireValue::as_string);
            let phase = item.get("phase").and_then(WireValue::as_string);
            kind.as_deref()
                .is_some_and(|k| ["intakes", "applications", "invitations"].contains(&k))
                && id.as_deref().is_some_and(valid_token)
                && key.as_deref()
                    == Some(&format!(
                        "{}.{}",
                        kind.as_deref().unwrap(),
                        id.as_deref().unwrap()
                    ))
                && item
                    .get("root")
                    .and_then(WireValue::as_string)
                    .is_some_and(|s| s.len() == 64)
                && phase.as_deref().is_some_and(|p| {
                    [
                        "OPEN",
                        "ACCEPTED",
                        "DECLINED",
                        "CANCELLED",
                        "CLOSED",
                        "DECIDED",
                    ]
                    .contains(&p)
                })
                && matches!(
                    item.get("decision"),
                    Some(WireValue::Null | WireValue::String(_))
                )
                && ["grant", "receipt"].iter().all(|field| {
                    matches!(
                        item.get(field),
                        None | Some(WireValue::Null | WireValue::String(_))
                    )
                })
        }),
        _ => false,
    }
}

fn confirmed_browser_approvals(
    value: Option<&WireValue>,
    input: &HistoricalOwnerAttachInput,
) -> bool {
    match value {
        None => true,
        Some(WireValue::Object(rows)) => rows.iter().all(|(id, item)| {
            let id = String::from_utf16(id).ok();
            let request = item.get("request");
            let grant = item.get("grant");
            id.as_deref().is_some_and(valid_token)
                && item.object_len() == Some(4)
                && matches!(item.get("confirmed"), Some(WireValue::Bool(true)))
                && item
                    .get("code")
                    .and_then(WireValue::as_string)
                    .is_some_and(|s| valid_token(&s))
                && request
                    .and_then(|r| r.get("payload"))
                    .and_then(|p| p.get("request_id"))
                    .and_then(WireValue::as_string)
                    == id
                && grant
                    .and_then(|g| g.get("payload"))
                    .and_then(|p| p.get("request_id"))
                    .and_then(WireValue::as_string)
                    == id
                && grant
                    .and_then(|g| g.get("payload"))
                    .and_then(|p| p.get("actor_id"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&input.expected_owner_actor_id)
                && grant
                    .and_then(|g| g.get("payload"))
                    .and_then(|p| p.get("signing_key"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&input.expected_owner_key_id)
                && request
                    .and_then(|r| r.get("signature"))
                    .and_then(WireValue::as_string)
                    .is_some()
                && grant
                    .and_then(|g| g.get("signature"))
                    .and_then(WireValue::as_string)
                    .is_some()
        }),
        _ => false,
    }
}

fn parse_legacy_source(
    bytes: &[u8],
    input: &HistoricalOwnerAttachInput,
) -> Result<LegacySource, HistoricalOwnerAttachError> {
    let mut value = parse_wire_json_bounded(bytes, 48, MAX_SOURCE)
        .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
    let parsed = (|| {
        let WireValue::Object(root_fields) = &value else {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        };
        const KNOWN: &[&str] = &[
            "v",
            "actor_id",
            "certificate",
            "encryption_private_key",
            "workspaces",
            "pending",
            "encryption_history",
            "identity_key_intents",
            "member_key_intents",
            "intake_closures",
            "application_decisions",
            "intake_intents",
            "application_intents",
            "application_decision_intents",
            "field_policy_intents",
            "protocol_install_intents",
            "package_stage_intents",
            "protocol_object_stage_intents",
            "coordination_intents",
            "inbox_receipts",
            "identity_pins",
            "intent_archive",
            "intent_journal_pins",
            "wire_upgrade_observations",
            "control_evidence",
            "admission_browser_approvals",
            "admission_browser_revocations",
            "configuration_receipts",
        ];
        if root_fields.iter().any(|(key, _)| {
            !KNOWN
                .iter()
                .any(|known| key.iter().copied().eq(known.encode_utf16()))
        }) {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        if exact_u64(value.get("v")) != Some(1)
            || value
                .get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(&input.expected_owner_actor_id)
            || value
                .get("certificate")
                .and_then(|c| c.get("payload"))
                .and_then(|p| p.get("signing_key"))
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(&input.expected_owner_key_id)
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        if !confirmed_browser_approvals(value.get("admission_browser_approvals"), input)
            || !completed_signed_cache(value.get("intake_closures"))
            || !completed_signed_cache(value.get("application_decisions"))
            || !completed_evidence_cache(value.get("control_evidence"))
        {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        let retained_inbox_receipts = parse_inbox_receipts(value.get("inbox_receipts"), input)?;
        for key in [
            "admission_browser_revocations",
            "configuration_receipts",
            "wire_upgrade_observations",
        ] {
            if !empty_optional_map(value.get(key)) {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
        }
        if !object_optional_map(value.get("identity_key_intents")) {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        if let Some(WireValue::Object(intents)) = value.get("identity_key_intents") {
            for (_, intent) in intents {
                let WireValue::Object(fields) = intent else {
                    return Err(HistoricalOwnerAttachError::SourceUnresolved);
                };
                if fields.len() != 5
                    || fields.iter().any(|(key, _)| {
                        ![
                            "input_hash",
                            "previous_certificate_hash",
                            "entry",
                            "private_key",
                            "state",
                        ]
                        .iter()
                        .any(|known| key.iter().copied().eq(known.encode_utf16()))
                    })
                    || intent
                        .get("input_hash")
                        .and_then(WireValue::as_string)
                        .is_none()
                    || intent
                        .get("previous_certificate_hash")
                        .and_then(WireValue::as_string)
                        .is_none()
                    || !matches!(intent.get("entry"), Some(WireValue::Object(_)))
                    || intent
                        .get("private_key")
                        .and_then(WireValue::as_string)
                        .is_none()
                    || intent
                        .get("state")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        != Some("PUBLISHED")
                {
                    return Err(HistoricalOwnerAttachError::SourceUnresolved);
                }
            }
        }
        // Retain all unsupported exact signed intents in the legacy source;
        // never silently discard them during a one-workspace attach.
        for key in [
            "protocol_install_intents",
            "package_stage_intents",
            "protocol_object_stage_intents",
            "coordination_intents",
            "field_policy_intents",
            "intake_intents",
            "application_intents",
            "application_decision_intents",
        ] {
            if !empty_optional_map(value.get(key)) {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
        }
        for key in [
            "encryption_history",
            "identity_pins",
            "intent_archive",
            "intent_journal_pins",
        ] {
            if !object_optional_map(value.get(key)) {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
        }
        let retained_member_commands = match value.get("member_key_intents") {
            None => Vec::new(),
            Some(WireValue::Object(rows)) => rows
                .iter()
                .map(|(_, command)| {
                    command
                        .as_string()
                        .filter(|id| valid_token(id))
                        .ok_or(HistoricalOwnerAttachError::SourceUnresolved)
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(HistoricalOwnerAttachError::SourceUnresolved),
        };
        let workspaces = value
            .get("workspaces")
            .ok_or(HistoricalOwnerAttachError::SourceChanged)?;
        let WireValue::Object(workspace_rows) = workspaces else {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        };
        if workspace_rows.iter().any(|(_, workspace)| {
            let WireValue::Object(fields) = workspace else {
                return true;
            };
            fields.iter().any(|(key, _)| {
                ![
                    "keyring",
                    "pending_keyring",
                    "conversion",
                    "policies",
                    "checkpoint",
                    "trusted_owner",
                ]
                .iter()
                .any(|known| key.iter().copied().eq(known.encode_utf16()))
            }) || workspace.get("pending_keyring").is_some()
                || workspace.get("conversion").is_some()
        }) {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        let local = workspaces
            .get(&input.workspace_id)
            .ok_or(HistoricalOwnerAttachError::SourceChanged)?;
        let trust = local
            .get("trusted_owner")
            .ok_or(HistoricalOwnerAttachError::SourceChanged)?;
        if trust
            .get("actorId")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(&input.expected_owner_actor_id)
            || trust.get("key").and_then(WireValue::as_string).as_deref()
                != Some(&input.expected_owner_key_id)
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let checkpoint = local
            .get("checkpoint")
            .ok_or(HistoricalOwnerAttachError::SourceChanged)?;
        if checkpoint
            .get("workspace_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(&input.workspace_id)
            || checkpoint
                .get("owner_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(&input.expected_owner_actor_id)
            || checkpoint
                .get("owner_key")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(&input.expected_owner_key_id)
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let sequence = exact_u64(checkpoint.get("sequence"))
            .ok_or(HistoricalOwnerAttachError::SourceChanged)?;
        let head = match checkpoint.get("head") {
            Some(WireValue::Null) => None,
            Some(v) => Some(
                v.as_string()
                    .ok_or(HistoricalOwnerAttachError::SourceChanged)?,
            ),
            None => return Err(HistoricalOwnerAttachError::SourceChanged),
        };
        if sequence == 0 || head.as_deref().is_none_or(|h| h.len() != 64) {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let policy_hash = checkpoint
            .get("policy_hash")
            .and_then(WireValue::as_string)
            .filter(|p| p.len() == 64)
            .ok_or(HistoricalOwnerAttachError::SourceChanged)?;
        let ring = if let Some(ring_value) = local.get("keyring") {
            let ring_wire = Zeroizing::new(
                canonical_wire_value(ring_value, CanonicalPath::SecureArtifact)
                    .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?,
            );
            let ring = SecretKeyring::parse_wire(ring_wire.as_bytes())
                .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
            if ring.workspace_id() != input.workspace_id {
                return Err(HistoricalOwnerAttachError::SourceChanged);
            }
            Some(ring)
        } else {
            None
        };
        let pending_action = parse_pending_owner_action(value.get("pending"), input)?;
        if let Some(action) = pending_action.as_ref() {
            if action.visibility != if ring.is_some() { "PRIVATE" } else { "PUBLIC" }
                || sequence.checked_add(1) != Some(action.sequence)
                || action.previous != head
                || action.policy_hash != policy_hash
            {
                return Err(HistoricalOwnerAttachError::SourceUnresolved);
            }
        }
        Ok(LegacySource {
            visibility: if ring.is_some() { "PRIVATE" } else { "PUBLIC" }.into(),
            ring,
            sequence,
            head,
            policy_hash,
            retained_member_commands,
            retained_inbox_receipts,
            pending_action,
        })
    })();
    scrub(&mut value);
    parsed
}

fn scrub(value: &mut WireValue) {
    match value {
        WireValue::String(units) => units.zeroize(),
        WireValue::Array(values) => values.iter_mut().for_each(scrub),
        WireValue::Object(fields) => fields.iter_mut().for_each(|(key, value)| {
            key.zeroize();
            scrub(value);
        }),
        _ => (),
    }
}

fn random_token() -> Result<String, HistoricalOwnerAttachError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| HistoricalOwnerAttachError::Local)?;
    let result = peerwork_core::crypto::base64url(&bytes);
    bytes.zeroize();
    Ok(result)
}

fn ensure_dir(path: &Path) -> Result<(), HistoricalOwnerAttachError> {
    if !path.is_absolute() {
        return Err(HistoricalOwnerAttachError::Input);
    }
    if let Some(parent) = path.parent() {
        if parent != path && parent.file_name().is_some_and(|name| name == "workspaces") {
            ensure_dir(parent)?;
        }
    }
    #[cfg(windows)]
    crate::windows_fs::create_private_directory(path)
        .map_err(|_| HistoricalOwnerAttachError::Local)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(HistoricalOwnerAttachError::Local),
        }
        let meta =
            std::fs::symlink_metadata(path).map_err(|_| HistoricalOwnerAttachError::Local)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(HistoricalOwnerAttachError::Local);
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(HistoricalOwnerAttachError::Local);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure_action_access::PublicActionInput, secure_owner_create::SecureOwnerWorkspaceCreate,
    };
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    static ATTACH_FAULT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn actual_service_completed_inbox_marker_requires_exact_owner_ack() {
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopInbox(Child);
        impl Drop for StopInbox {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopInbox(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/legacy-completed-inbox-source.mjs");
        let setup = |mode: &str| {
            let output = Command::new(&node)
                .arg(&helper)
                .arg(origin)
                .arg(root.path().join(mode))
                .arg(&legacy_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "legacy inbox setup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
        };
        let unfinished = setup("before-ack");
        assert_eq!(unfinished["policy_v"], 2);
        assert_eq!(unfinished["signed_ack"], false);
        let config = |name: &str| SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join(name),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let input = |source: &serde_json::Value| HistoricalOwnerAttachInput {
            workspace_id: source["workspace_id"].as_str().unwrap().into(),
            protected_ts_state_path: source["state_path"].as_str().unwrap().into(),
            protected_ts_intent_db_path: source["intent_db_path"].as_str().unwrap().into(),
            protected_owner_pkcs8_path: source["pem_path"].as_str().unwrap().into(),
            expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
            expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
            recover_pending_action: false,
            kernel_pending_command_ids: Vec::new(),
            expected_kernel_intent_db_digest: None,
        };
        let cancel = CancellationToken::new();
        let bad_config = config("native-unfinished");
        let bad = SecureHistoricalOwnerAttach::new(bad_config.clone());
        assert!(matches!(
            bad.attach(input(&unfinished), &cancel),
            Err(HistoricalOwnerAttachError::SourceUnresolved)
        ));
        assert!(bad
            .attachments()
            .unwrap()
            .iter()
            .all(|row| row.status != "ATTACHED"));
        assert!(SecureOwnerWorkspaceCreate::new(bad_config)
            .private_action_access(unfinished["workspace_id"].as_str().unwrap())
            .is_err());
        let completed = setup("complete");
        assert_eq!(completed["policy_v"], 2);
        assert_eq!(completed["signed_ack"], true);
        let good_config = config("native-completed");
        let good = SecureHistoricalOwnerAttach::new(good_config.clone());
        let attached = good.attach(input(&completed), &cancel).unwrap();
        assert_eq!(attached.status, "ATTACHED");
        let workspace = completed["workspace_id"].as_str().unwrap();
        let access = SecureReadAccess::new(good.attach_read_config(&input(&completed)));
        let replayed = access.replay_checked_attach_generation(&cancel).unwrap();
        let marker = RetainedInboxReceipt {
            item_id: completed["item_id"].as_str().unwrap().into(),
            workspace_id: workspace.into(),
            source_record_id: completed["source"]["record_id"].as_str().unwrap().into(),
            source_revision: completed["source"]["revision"].as_u64().unwrap(),
            source_hash: completed["source_hash"].as_str().unwrap().into(),
        };
        let ack = replayed
            .signed_commit_wires()
            .iter()
            .find_map(|wire| {
                let commit = parse_wire_json_bounded(wire, 64, 262_144).ok()?;
                signed_owner_ack_matches(
                    &commit,
                    &marker,
                    completed["owner_actor_id"].as_str().unwrap(),
                    completed["owner_key_id"].as_str().unwrap(),
                )
                .then_some(commit)
            })
            .expect("complete signed Owner ACK");
        let owner_actor = completed["owner_actor_id"].as_str().unwrap();
        let owner_key = completed["owner_key_id"].as_str().unwrap();
        let mut wrong = marker.clone();
        wrong.source_hash = "0".repeat(64);
        assert!(!signed_owner_ack_matches(
            &ack,
            &wrong,
            owner_actor,
            owner_key
        ));
        wrong = marker.clone();
        wrong.item_id = "z".repeat(43);
        assert!(!signed_owner_ack_matches(
            &ack,
            &wrong,
            owner_actor,
            owner_key
        ));
        assert!(!signed_owner_ack_matches(
            &ack,
            &marker,
            &"y".repeat(43),
            owner_key
        ));
        let owner = SecureOwnerWorkspaceCreate::new(good_config.clone());
        let before: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(workspace, &cancel).unwrap()).unwrap();
        assert_eq!(before["sequence"], completed["sequence"]);
        std::fs::rename(
            root.path().join("complete"),
            root.path().join("complete-archived"),
        )
        .unwrap();
        let reopened: serde_json::Value = serde_json::from_str(
            &SecureOwnerWorkspaceCreate::new(good_config)
                .read_workspace_json(workspace, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reopened["sequence"], before["sequence"]);
        assert_eq!(reopened["head"], before["head"]);
    }

    #[test]
    fn actual_service_imports_one_explicit_private_pending_action_exactly_once() {
        let _fault_guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopPending(Child);
        impl Drop for StopPending {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopPending(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let setup = |directory: &str, mode: &str| {
            let output = Command::new(&node)
                .arg(&helper)
                .arg(origin)
                .arg(root.path().join(directory))
                .arg(&legacy_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "legacy pending setup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(source["policy_v"], 1);
            assert_eq!(source["pending_count"], 1);
            assert!(source["pending_command_id"].as_str().is_some());
            assert!(source["pending_commit_hash"].as_str().is_some());
            source
        };
        let config = |directory: &str| SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join(directory),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let input = |source: &serde_json::Value, recover| HistoricalOwnerAttachInput {
            workspace_id: source["workspace_id"].as_str().unwrap().into(),
            protected_ts_state_path: source["state_path"].as_str().unwrap().into(),
            protected_ts_intent_db_path: source["intent_db_path"].as_str().unwrap().into(),
            protected_owner_pkcs8_path: source["pem_path"].as_str().unwrap().into(),
            expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
            expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
            recover_pending_action: recover,
            kernel_pending_command_ids: Vec::new(),
            expected_kernel_intent_db_digest: None,
        };
        let cancel = CancellationToken::new();
        let applied = setup("legacy-applied", "pending");
        let refused = SecureHistoricalOwnerAttach::new(config("native-refused"));
        assert!(matches!(
            refused.attach(input(&applied, false), &cancel),
            Err(HistoricalOwnerAttachError::SourceUnresolved)
        ));
        assert!(refused.attachments().unwrap().is_empty());
        let applied_config = config("native-applied");
        let applied_owner = SecureHistoricalOwnerAttach::new(applied_config.clone());
        let posts = TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst);
        let accepted = applied_owner
            .attach(input(&applied, true), &cancel)
            .unwrap();
        assert_eq!(accepted.status, "ATTACHED");
        assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts);
        let applied_workspace = applied["workspace_id"].as_str().unwrap();
        let applied_command = applied["pending_command_id"].as_str().unwrap();
        let result: serde_json::Value = serde_json::from_str(
            &SecureOwnerWorkspaceCreate::new(applied_config.clone())
                .private_action_access(applied_workspace)
                .unwrap()
                .reconcile_json(applied_command)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result["status"], "ACCEPTED");
        assert_eq!(result["sequence"], 2);
        assert_eq!(result["command_id"], applied_command);
        assert_eq!(result["commit_hash"], applied["pending_commit_hash"]);
        let read: serde_json::Value = serde_json::from_str(
            &SecureOwnerWorkspaceCreate::new(applied_config)
                .read_workspace_json(applied_workspace, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"].as_array().unwrap().iter().any(|row| {
            row["kind"] == "records"
                && row["value"]["payload"]["title"] == "Pending legacy Owner action"
                && row["value"]["payload"]["body"] == "Exact signed packet remains local"
        }));

        let unsent = setup("legacy-unsent", "pending-before-post");
        let unsent_config = config("native-unsent");
        let unsent_owner = SecureHistoricalOwnerAttach::new(unsent_config.clone());
        TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
        assert!(matches!(
            unsent_owner.attach(input(&unsent, true), &cancel),
            Err(HistoricalOwnerAttachError::Cancelled)
        ));
        let saved = unsent_owner.attachments().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].status, "PREPARED");
        assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts);
        TEST_STOP_AFTER_IMPORTED_ACTION_ACCEPTED.store(true, Ordering::SeqCst);
        assert!(matches!(
            unsent_owner.resume_attachment(&saved[0].attach_id, &cancel),
            Err(HistoricalOwnerAttachError::Cancelled)
        ));
        assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts + 1);
        assert_eq!(unsent_owner.attachments().unwrap()[0].status, "PREPARED");
        let completed = SecureHistoricalOwnerAttach::new(unsent_config.clone())
            .resume_attachment(&saved[0].attach_id, &cancel)
            .unwrap();
        assert_eq!(completed.status, "ATTACHED");
        assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts + 1);
        let unsent_workspace = unsent["workspace_id"].as_str().unwrap();
        let unsent_command = unsent["pending_command_id"].as_str().unwrap();
        let action = SecureOwnerWorkspaceCreate::new(unsent_config.clone())
            .private_action_access(unsent_workspace)
            .unwrap();
        let reconciled: serde_json::Value =
            serde_json::from_str(&action.reconcile_json(unsent_command).unwrap()).unwrap();
        assert_eq!(reconciled["status"], "ACCEPTED");
        assert_eq!(reconciled["sequence"], 2);
        assert_eq!(reconciled["commit_hash"], unsent["pending_commit_hash"]);
        std::fs::rename(
            root.path().join("legacy-unsent"),
            root.path().join("legacy-unsent-archived"),
        )
        .unwrap();
        let reopened: serde_json::Value = serde_json::from_str(
            &SecureOwnerWorkspaceCreate::new(unsent_config)
                .read_workspace_json(unsent_workspace, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reopened["sequence"], 2);
        assert!(reopened["objects"].as_array().unwrap().iter().any(|row| {
            row["kind"] == "records"
                && row["value"]["payload"]["title"] == "Pending legacy Owner action"
                && row["value"]["payload"]["body"] == "Exact signed packet remains local"
        }));
    }

    #[test]
    fn actual_service_imports_old_structured_and_public_pending_actions() {
        let _fault_guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopPending(Child);
        impl Drop for StopPending {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopPending(child);
        let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
        let line = lines.next().unwrap().unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let cancel = CancellationToken::new();
        for (index, mode, visibility, version, structured, before_post) in [
            (0, "pending-private-structured", "PRIVATE", 2, true, false),
            (
                1,
                "pending-private-structured-before-post",
                "PRIVATE",
                2,
                true,
                true,
            ),
            (2, "pending-public", "PUBLIC", 1, false, false),
            (3, "pending-public-before-post", "PUBLIC", 1, false, true),
            (4, "pending-public-structured", "PUBLIC", 2, true, false),
            (
                5,
                "pending-public-structured-before-post",
                "PUBLIC",
                2,
                true,
                true,
            ),
        ] {
            let output = Command::new(&node)
                .arg(&helper)
                .arg(origin)
                .arg(root.path().join(format!("legacy-family-{index}")))
                .arg(&legacy_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "legacy family setup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(source["policy_v"], version);
            assert_eq!(source["visibility"], visibility);
            assert_eq!(source["structured"], structured);
            assert_eq!(source["sequence"], 1);
            assert_eq!(source["pending_count"], 1);
            let workspace = source["workspace_id"].as_str().unwrap();
            let command = source["pending_command_id"].as_str().unwrap();
            let config = SecureOwnerCreateConfig {
                origin: origin.into(),
                state_dir: root.path().join(format!("native-family-{index}")),
                allow_loopback_http: true,
                max_replay_artifact_bytes: 64 * 1024 * 1024,
            };
            let input = HistoricalOwnerAttachInput {
                workspace_id: workspace.into(),
                protected_ts_state_path: source["state_path"].as_str().unwrap().into(),
                protected_ts_intent_db_path: source["intent_db_path"].as_str().unwrap().into(),
                protected_owner_pkcs8_path: source["pem_path"].as_str().unwrap().into(),
                expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                recover_pending_action: true,
                kernel_pending_command_ids: Vec::new(),
                expected_kernel_intent_db_digest: None,
            };
            if mode == "pending-public-structured-before-post" {
                let signer =
                    KernelIdentity::inspect_pkcs8_pem_file(&input.protected_owner_pkcs8_path)
                        .unwrap();
                let original: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&input.protected_ts_state_path).unwrap())
                        .unwrap();
                for (negative_index, expected) in [
                    HistoricalOwnerAttachError::SourceUnresolved,
                    HistoricalOwnerAttachError::SourceUnresolved,
                    HistoricalOwnerAttachError::Verification,
                ]
                .into_iter()
                .enumerate()
                {
                    let mut altered = original.clone();
                    let signed = &mut altered["pending"][command]["body"]["commit"];
                    match negative_index {
                        0 => {
                            signed["payload"]["mode"] = serde_json::json!("PRIVATE");
                            signed["payload"]["epoch"] = serde_json::json!(1);
                        }
                        1 => signed["payload"]["epoch"] = serde_json::json!(1),
                        2 => {
                            signed["payload"]["structure"]["mode"] =
                                serde_json::json!("SNAPSHOT_BEGIN");
                        }
                        _ => unreachable!(),
                    }
                    let payload = signed["payload"].clone();
                    let domain = peerwork_core::crypto::secure_artifact_domain(
                        "peerwork.secure.commit.v1",
                        &payload,
                    );
                    signed["signature"] = serde_json::json!(peerwork_core::crypto::sign_canonical(
                        &domain,
                        &payload,
                        signer.signing_key(),
                    )
                    .unwrap());
                    let path = root
                        .path()
                        .join(format!("altered-public-structured-{negative_index}.state"));
                    std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                    let mut negative_input = input.clone();
                    negative_input.protected_ts_state_path = path;
                    let negative = SecureHistoricalOwnerAttach::new(SecureOwnerCreateConfig {
                        state_dir: root
                            .path()
                            .join(format!("negative-family-{negative_index}")),
                        ..config.clone()
                    });
                    let before_negative_posts = TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst);
                    let result = negative.attach(negative_input, &cancel);
                    assert!(matches!(
                        (&result, &expected),
                        (
                            Err(HistoricalOwnerAttachError::SourceUnresolved),
                            HistoricalOwnerAttachError::SourceUnresolved
                        ) | (
                            Err(HistoricalOwnerAttachError::Verification),
                            HistoricalOwnerAttachError::Verification
                        )
                    ));
                    assert!(negative
                        .attachments()
                        .unwrap()
                        .iter()
                        .all(|row| row.status != "ATTACHED"));
                    assert_eq!(
                        TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst),
                        before_negative_posts
                    );
                }
            }
            let owner = SecureHistoricalOwnerAttach::new(config.clone());
            let posts = TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst);
            let completed = if before_post {
                TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
                assert!(matches!(
                    owner.attach(input.clone(), &cancel),
                    Err(HistoricalOwnerAttachError::Cancelled)
                ));
                let saved = owner.attachments().unwrap();
                assert_eq!(saved.len(), 1);
                assert_eq!(saved[0].status, "PREPARED");
                assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts);
                let completed = owner
                    .resume_attachment(&saved[0].attach_id, &cancel)
                    .unwrap();
                assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts + 1);
                completed
            } else {
                let completed = owner.attach(input.clone(), &cancel).unwrap();
                assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts);
                completed
            };
            assert_eq!(completed.status, "ATTACHED");
            assert_eq!(completed.sequence, Some(2));
            assert_eq!(
                owner
                    .resume_attachment(&completed.attach_id, &cancel)
                    .unwrap(),
                completed
            );
            assert_eq!(
                TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst),
                posts + usize::from(before_post)
            );
            let facade = SecureOwnerWorkspaceCreate::new(config);
            let reconciled = if visibility == "PUBLIC" {
                facade
                    .public_action_access(workspace)
                    .unwrap()
                    .reconcile_json(command)
                    .unwrap()
            } else {
                facade
                    .private_action_access(workspace)
                    .unwrap()
                    .reconcile_json(command)
                    .unwrap()
            };
            let action: serde_json::Value = serde_json::from_str(&reconciled).unwrap();
            assert_eq!(action["status"], "ACCEPTED");
            assert_eq!(action["sequence"], 2);
            assert_eq!(action["commit_hash"], source["pending_commit_hash"]);
            let read: serde_json::Value =
                serde_json::from_str(&facade.read_workspace_json(workspace, &cancel).unwrap())
                    .unwrap();
            assert_eq!(read["sequence"], 2);
            assert!(read["objects"].as_array().unwrap().iter().any(|row| {
                row["kind"] == "records"
                    && row["value"]["payload"]["title"] == "Pending legacy Owner action"
                    && row["value"]["payload"]["body"] == "Exact signed packet remains local"
            }));
        }
    }

    #[test]
    fn actual_service_imports_current_wire_v3_pending_actions() {
        let _fault_guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
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
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", &reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopPending(Child);
        impl Drop for StopPending {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopPending(child);
        let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
        let line = lines.next().unwrap().unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let cancel = CancellationToken::new();
        for (index, mode, visibility, structure_mode, ceiling, source_sequence, before_post) in [
            (0, "pending-current-private", "PRIVATE", "NONE", 1, 1, false),
            (
                1,
                "pending-current-private-before-post",
                "PRIVATE",
                "NONE",
                1,
                1,
                true,
            ),
            (
                2,
                "pending-current-private-structured",
                "PRIVATE",
                "STRUCTURED",
                1,
                1,
                false,
            ),
            (
                3,
                "pending-current-private-structured-before-post",
                "PRIVATE",
                "STRUCTURED",
                1,
                1,
                true,
            ),
            (
                4,
                "pending-current-private-structured-ceiling2",
                "PRIVATE",
                "STRUCTURED",
                2,
                2,
                false,
            ),
            (
                5,
                "pending-current-private-structured-ceiling2-before-post",
                "PRIVATE",
                "STRUCTURED",
                2,
                2,
                true,
            ),
            (6, "pending-current-public", "PUBLIC", "NONE", 1, 1, false),
            (
                7,
                "pending-current-public-before-post",
                "PUBLIC",
                "NONE",
                1,
                1,
                true,
            ),
            (
                8,
                "pending-current-public-structured",
                "PUBLIC",
                "STRUCTURED",
                1,
                1,
                false,
            ),
            (
                9,
                "pending-current-public-structured-before-post",
                "PUBLIC",
                "STRUCTURED",
                1,
                1,
                true,
            ),
        ] {
            let output = Command::new(&node)
                .arg(&helper)
                .arg(origin)
                .arg(root.path().join(format!("current-v3-{index}")))
                .arg(&reference_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "current v3 source setup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(source["policy_v"], 3);
            assert_eq!(source["visibility"], visibility);
            assert_eq!(source["structure_mode"], structure_mode);
            assert_eq!(source["protocol_format_ceiling"], ceiling);
            assert_eq!(source["sequence"], source_sequence);
            assert_eq!(source["pending_count"], 1);
            let workspace = source["workspace_id"].as_str().unwrap();
            let command = source["pending_command_id"].as_str().unwrap();
            let config = SecureOwnerCreateConfig {
                origin: origin.into(),
                state_dir: root.path().join(format!("native-current-v3-{index}")),
                allow_loopback_http: true,
                max_replay_artifact_bytes: 64 * 1024 * 1024,
            };
            let input = HistoricalOwnerAttachInput {
                workspace_id: workspace.into(),
                protected_ts_state_path: source["state_path"].as_str().unwrap().into(),
                protected_ts_intent_db_path: source["intent_db_path"].as_str().unwrap().into(),
                protected_owner_pkcs8_path: source["pem_path"].as_str().unwrap().into(),
                expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                recover_pending_action: true,
                kernel_pending_command_ids: Vec::new(),
                expected_kernel_intent_db_digest: None,
            };
            let owner = SecureHistoricalOwnerAttach::new(config.clone());
            let posts = TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst);
            let completed = if before_post {
                TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
                assert!(matches!(
                    owner.attach(input, &cancel),
                    Err(HistoricalOwnerAttachError::Cancelled)
                ));
                let saved = owner.attachments().unwrap();
                assert_eq!(saved.len(), 1);
                assert_eq!(saved[0].status, "PREPARED");
                assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts);
                let completed = owner
                    .resume_attachment(&saved[0].attach_id, &cancel)
                    .unwrap();
                assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts + 1);
                completed
            } else {
                let completed = owner.attach(input, &cancel).unwrap();
                assert_eq!(TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst), posts);
                completed
            };
            assert_eq!(completed.status, "ATTACHED");
            assert_eq!(completed.sequence, Some(source_sequence + 1));
            assert_eq!(
                owner
                    .resume_attachment(&completed.attach_id, &cancel)
                    .unwrap(),
                completed
            );
            assert_eq!(
                TEST_IMPORTED_ACTION_POSTS.load(Ordering::SeqCst),
                posts + usize::from(before_post)
            );
            let facade = SecureOwnerWorkspaceCreate::new(config);
            let reconciled = if visibility == "PUBLIC" {
                facade
                    .public_action_access(workspace)
                    .unwrap()
                    .reconcile_json(command)
                    .unwrap()
            } else {
                facade
                    .private_action_access(workspace)
                    .unwrap()
                    .reconcile_json(command)
                    .unwrap()
            };
            let action: serde_json::Value = serde_json::from_str(&reconciled).unwrap();
            assert_eq!(action["status"], "ACCEPTED");
            assert_eq!(action["sequence"], source_sequence + 1);
            assert_eq!(action["commit_hash"], source["pending_commit_hash"]);
            let read: serde_json::Value =
                serde_json::from_str(&facade.read_workspace_json(workspace, &cancel).unwrap())
                    .unwrap();
            assert_eq!(read["sequence"], source_sequence + 1);
            assert!(read["objects"].as_array().unwrap().iter().any(|row| {
                row["kind"] == "records"
                    && row["value"]["payload"]["title"] == "Pending legacy Owner action"
                    && row["value"]["payload"]["body"] == "Exact signed packet remains local"
            }));
        }
    }

    #[test]
    fn actual_service_imports_distinct_kernel_jws_rows_without_submitting_them() {
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
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", &reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopKernelSource(Child);
        impl Drop for StopKernelSource {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopKernelSource(child);
        let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
        let line = lines.next().unwrap().unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let output = Command::new(&node)
            .arg(helper)
            .arg(origin)
            .arg(root.path().join("kernel-jws-source"))
            .arg(&reference_root)
            .arg("kernel-jws-source")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "current WorkspaceClient fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(source["policy_v"], 3);
        assert_ne!(
            source["workspace_id"],
            source["kernel_source"]["unrelated_workspace_id"]
        );
        let selected = source["kernel_source"]["selected_command_id"]
            .as_str()
            .unwrap();
        let other = source["kernel_source"]["unrelated_command_id"]
            .as_str()
            .unwrap();
        let accepted = source["kernel_source"]["accepted_command_id"]
            .as_str()
            .unwrap();
        assert_ne!(selected, other);
        assert_eq!(
            source["kernel_source"]["pending_ids"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let native = root.path().join("native-kernel");
        std::fs::create_dir(&native).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity_path = native.join("identity.state");
        let identity = crate::kernel_identity::KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            Path::new(source["pem_path"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), source["owner_actor_id"]);
        assert_eq!(identity.key_id(), source["owner_key_id"]);
        let access = crate::kernel_access::KernelAccess::new(
            origin,
            native.join("kernel-intents.sqlite"),
            &identity_path,
            &[],
            true,
        );
        let cancel = CancellationToken::new();
        let report = access
            .migrate_ts_store(
                Path::new(source["intent_db_path"].as_str().unwrap()),
                &native.join("source-backup.sqlite"),
                &[source["owner_key_id"].as_str().unwrap().into()],
                &cancel,
            )
            .unwrap();
        assert_eq!(report.pending_count, 2);
        // Each secure create first registers the Owner through WorkspaceClient.
        assert_eq!(report.accepted_count, 3);
        let mut pending = access.pending().unwrap();
        pending.sort_by(|a, b| a.command_id.cmp(&b.command_id));
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|row| {
            row.command_id == selected
                && row.intent_digest
                    == source["kernel_source"]["selected_intent_digest"]
                        .as_str()
                        .unwrap()
        }));
        assert!(pending.iter().any(|row| {
            row.command_id == other
                && row.intent_digest
                    == source["kernel_source"]["unrelated_intent_digest"]
                        .as_str()
                        .unwrap()
        }));
        assert!(matches!(
            access.status(selected).unwrap(),
            Some(crate::kernel_client::KernelOperationStatus::Pending)
        ));
        assert!(matches!(
            access.status(other).unwrap(),
            Some(crate::kernel_client::KernelOperationStatus::Pending)
        ));
        let Some(crate::kernel_client::KernelOperationStatus::Accepted(result)) =
            access.status(accepted).unwrap()
        else {
            panic!("signed old-client receipt was not imported");
        };
        assert_eq!(result.command_id, accepted);
        assert_eq!(
            result.workspace_id.as_deref(),
            source["kernel_source"]["accepted_workspace_id"].as_str()
        );
        let journal =
            crate::kernel_intents::KernelIntentJournal::open(&native.join("kernel-intents.sqlite"))
                .unwrap();
        let audience: Vec<u16> = source["kernel_source"]["audience"]
            .as_str()
            .unwrap()
            .encode_utf16()
            .collect();
        let saved = journal
            .verified_pending(accepted, identity.key_id(), &audience)
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.proof.intent_digest(),
            source["kernel_source"]["accepted_intent_digest"]
                .as_str()
                .unwrap()
        );
        assert!(matches!(
            crate::ts_migration::quiescent_source_digest(Path::new(
                source["intent_db_path"].as_str().unwrap()
            )),
            Err(crate::ts_migration::TsMigrationError::Unresolved)
        ));
        let mut reopened_pending = access.pending().unwrap();
        reopened_pending.sort_by(|a, b| a.command_id.cmp(&b.command_id));
        assert_eq!(reopened_pending, pending);
    }

    #[test]
    fn actual_service_distinguishes_cached_kernel_jws_from_unsent_after_conversion() {
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
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", &reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopKernelLifecycle(Child);
        impl Drop for StopKernelLifecycle {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopKernelLifecycle(child);
        let line = BufReader::new(child.0.stdout.take().unwrap())
            .lines()
            .next()
            .unwrap()
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/historical-kernel-pending-source.mjs");
        let cancel = CancellationToken::new();
        for mode in ["applied-loss", "pre-send"] {
            let output = Command::new(&node)
                .arg(&helper)
                .arg(origin)
                .arg(root.path().join(format!("source-{mode}")))
                .arg(&reference_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "current-client kernel lifecycle fixture: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(source["mode"], mode);
            assert_eq!(source["policy_v"], 1);
            assert_eq!(source["policy_visibility"], "PUBLIC");
            assert_eq!(source["secure_sequence"], 2);
            assert_eq!(source["pending_count"], 2);
            assert_eq!(
                source["dropped_responses"],
                usize::from(mode == "applied-loss")
            );
            let selected = source["selected_command_id"].as_str().unwrap();
            let other = source["unrelated_command_id"].as_str().unwrap();
            let workspace = source["workspace_id"].as_str().unwrap();
            let unrelated = source["unrelated_workspace_id"].as_str().unwrap();
            assert_ne!(selected, other);
            assert_ne!(workspace, unrelated);
            let public_db = rusqlite::Connection::open_with_flags(
                root.path().join("control.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let view_effects = || -> i64 {
                public_db
                    .query_row(
                        "SELECT count(*) FROM events WHERE workspace_id=?1 AND kind='admin.view.set'",
                        [workspace],
                        |row| row.get(0),
                    )
                    .unwrap()
            };
            let expected_effects = i64::from(mode == "applied-loss");
            assert_eq!(view_effects(), expected_effects);
            let native = root.path().join(format!("native-{mode}"));
            std::fs::create_dir(&native).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let identity_path = native.join("identity.state");
            let identity = crate::kernel_identity::KernelIdentity::import_pkcs8_pem_file(
                &identity_path,
                Path::new(source["pem_path"].as_str().unwrap()),
            )
            .unwrap();
            assert_eq!(identity.actor_id(), source["owner_actor_id"]);
            assert_eq!(identity.key_id(), source["owner_key_id"]);
            let access = crate::kernel_access::KernelAccess::new(
                origin,
                native.join("kernel-intents.sqlite"),
                &identity_path,
                &[],
                true,
            );
            let report = access
                .migrate_ts_store(
                    Path::new(source["intent_db_path"].as_str().unwrap()),
                    &native.join("source-backup.sqlite"),
                    &[identity.key_id().into()],
                    &cancel,
                )
                .unwrap();
            assert_eq!(report.pending_count, 2);
            let pending = access.pending().unwrap();
            assert_eq!(pending.len(), 2);
            for (id, digest) in [
                (selected, source["selected_intent_digest"].as_str().unwrap()),
                (other, source["unrelated_intent_digest"].as_str().unwrap()),
            ] {
                assert!(pending
                    .iter()
                    .any(|row| row.command_id == id && row.intent_digest == digest));
            }
            let journal = crate::kernel_intents::KernelIntentJournal::open(
                &native.join("kernel-intents.sqlite"),
            )
            .unwrap();
            let audience: Vec<u16> = source["audience"]
                .as_str()
                .unwrap()
                .encode_utf16()
                .collect();
            let original = journal
                .verified_pending(selected, identity.key_id(), &audience)
                .unwrap()
                .unwrap();
            assert_eq!(
                original.proof.intent_digest(),
                source["selected_intent_digest"]
            );
            if mode == "applied-loss" {
                let accepted = access.submit_saved(selected).unwrap();
                assert_eq!(accepted.command_id, selected);
                assert_eq!(accepted.workspace_id.as_deref(), Some(workspace));
                assert_eq!(access.submit_saved(selected).unwrap(), accepted);
                assert!(matches!(
                    access.status(selected).unwrap(),
                    Some(crate::kernel_client::KernelOperationStatus::Accepted(_))
                ));
            } else {
                assert!(matches!(
                    access.submit_saved(selected),
                    Err(crate::kernel_access::KernelAccessError::Client(
                        crate::kernel_client::KernelClientError::ServerRejected(409)
                    ))
                ));
                assert!(matches!(
                    access.status(selected).unwrap(),
                    Some(crate::kernel_client::KernelOperationStatus::Pending)
                ));
            }
            assert!(matches!(
                access.status(other).unwrap(),
                Some(crate::kernel_client::KernelOperationStatus::Pending)
            ));
            let after = journal
                .verified_pending(selected, identity.key_id(), &audience)
                .unwrap()
                .unwrap();
            assert_eq!(after.jws, original.jws);
            assert_eq!(after.body, original.body);
            assert_eq!(view_effects(), expected_effects);
        }
    }

    #[test]
    fn actual_service_attaches_with_selected_kernel_jws_and_recovers_only_explicit_id() {
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
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", &reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct StopSelectedKernel(Child);
        impl Drop for StopSelectedKernel {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopSelectedKernel(child);
        let line = BufReader::new(child.0.stdout.take().unwrap())
            .lines()
            .next()
            .unwrap()
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/historical-kernel-pending-source.mjs");
        let cancel = CancellationToken::new();
        // A genuine old-client same-ID retry changes the SQLite source from
        // PENDING to ACCEPTED. The earlier inspected snapshot cannot then
        // authorize attachment, even though the command ID did not change.
        let changed_dir = root.path().join("source-changed-snapshot");
        let changed_output = Command::new(&node)
            .arg(&helper)
            .arg(origin)
            .arg(&changed_dir)
            .arg(&reference_root)
            .arg("applied-loss-global")
            .output()
            .unwrap();
        assert!(
            changed_output.status.success(),
            "source-change setup: {}",
            String::from_utf8_lossy(&changed_output.stderr)
        );
        let changed: serde_json::Value = serde_json::from_slice(&changed_output.stdout).unwrap();
        let changed_id = changed["selected_command_id"].as_str().unwrap();
        let changed_owner = SecureHistoricalOwnerAttach::new(SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join("native-changed-snapshot"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        let mut changed_input = HistoricalOwnerAttachInput {
            workspace_id: changed["workspace_id"].as_str().unwrap().into(),
            protected_ts_state_path: changed["state_path"].as_str().unwrap().into(),
            protected_owner_pkcs8_path: changed["pem_path"].as_str().unwrap().into(),
            protected_ts_intent_db_path: changed["intent_db_path"].as_str().unwrap().into(),
            expected_owner_actor_id: changed["owner_actor_id"].as_str().unwrap().into(),
            expected_owner_key_id: changed["owner_key_id"].as_str().unwrap().into(),
            recover_pending_action: false,
            kernel_pending_command_ids: vec![changed_id.into()],
            expected_kernel_intent_db_digest: None,
        };
        let inspected = changed_owner
            .inspect_kernel_pending(&changed_input, &cancel)
            .unwrap();
        assert_eq!(inspected.commands.len(), 1);
        assert_eq!(inspected.commands[0].command_id, changed_id);
        changed_input.expected_kernel_intent_db_digest = Some(inspected.intent_db_digest);
        let resolved_output = Command::new(&node)
            .arg(&helper)
            .arg(origin)
            .arg(&changed_dir)
            .arg(&reference_root)
            .arg("resolve-existing")
            .arg(changed_id)
            .output()
            .unwrap();
        assert!(
            resolved_output.status.success(),
            "source-change retry: {}",
            String::from_utf8_lossy(&resolved_output.stderr)
        );
        let resolved: serde_json::Value = serde_json::from_slice(&resolved_output.stdout).unwrap();
        assert_eq!(resolved["command_id"], changed_id);
        assert_eq!(resolved["workspace_id"], changed["workspace_id"]);
        assert!(matches!(
            changed_owner.attach(changed_input, &cancel),
            Err(HistoricalOwnerAttachError::SourceChanged)
        ));
        assert!(changed_owner.attachments().unwrap().is_empty());
        for (mode, applied, expired) in [
            ("applied-loss-global", true, false),
            ("pre-send-global", false, false),
            ("expired-global", false, true),
        ] {
            let source_dir = root.path().join(format!("source-{mode}"));
            let output = Command::new(&node)
                .arg(&helper)
                .arg(origin)
                .arg(&source_dir)
                .arg(&reference_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "selected kernel source fixture: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(source["policy_v"], 1);
            assert_eq!(source["policy_visibility"], "PUBLIC");
            assert_eq!(source["pending_count"], 3);
            assert_eq!(source["dropped_responses"], usize::from(applied));
            let workspace = source["workspace_id"].as_str().unwrap();
            let selected = source["selected_command_id"].as_str().unwrap();
            let unrelated = source["unrelated_command_id"].as_str().unwrap();
            let global = source["global_command_id"].as_str().unwrap();
            assert_ne!(selected, unrelated);
            assert_ne!(selected, global);
            let oracle = rusqlite::Connection::open_with_flags(
                root.path().join("control.sqlite"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let target_effects = || -> i64 {
                oracle
                    .query_row(
                        "SELECT count(*) FROM events WHERE workspace_id=?1 AND kind='admin.view.set'",
                        [workspace],
                        |row| row.get(0),
                    )
                    .unwrap()
            };
            let accepted_command_count = |id: &str| -> i64 {
                oracle
                    .query_row(
                        "SELECT count(*) FROM commands WHERE command_id=?1",
                        [id],
                        |row| row.get(0),
                    )
                    .unwrap()
            };
            let prior_effects = i64::from(applied);
            assert_eq!(target_effects(), prior_effects);
            assert_eq!(accepted_command_count(selected), prior_effects);
            assert_eq!(accepted_command_count(unrelated), 0);
            assert_eq!(accepted_command_count(global), 0);
            let config = SecureOwnerCreateConfig {
                origin: origin.into(),
                state_dir: root.path().join(format!("native-{mode}")),
                allow_loopback_http: true,
                max_replay_artifact_bytes: 64 * 1024 * 1024,
            };
            let owner = SecureHistoricalOwnerAttach::new(config.clone());
            let mut input = HistoricalOwnerAttachInput {
                workspace_id: workspace.into(),
                protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                protected_ts_intent_db_path: PathBuf::from(
                    source["intent_db_path"].as_str().unwrap(),
                ),
                expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                recover_pending_action: false,
                kernel_pending_command_ids: vec![selected.into()],
                expected_kernel_intent_db_digest: None,
            };
            let inventory = owner.inspect_kernel_pending(&input, &cancel).unwrap();
            assert_eq!(inventory.commands.len(), 1);
            assert_eq!(inventory.commands[0].command_id, selected);
            assert_eq!(
                inventory.commands[0].intent_digest,
                source["selected_intent_digest"]
            );
            assert_eq!(
                inventory.commands[0].status,
                if expired {
                    "EXPIRED_UNRESOLVED"
                } else {
                    "PENDING"
                }
            );
            assert_eq!(inventory.retained_other_pending_count, 1);
            assert_eq!(inventory.retained_nonworkspace_pending_count, 1);
            assert!(matches!(
                owner.attach(input.clone(), &cancel),
                Err(HistoricalOwnerAttachError::Input)
            ));
            input.expected_kernel_intent_db_digest = Some(inventory.intent_db_digest.clone());
            let mut wrong_snapshot = input.clone();
            wrong_snapshot.expected_kernel_intent_db_digest = Some("0".repeat(64));
            assert!(matches!(
                owner.attach(wrong_snapshot, &cancel),
                Err(HistoricalOwnerAttachError::SourceChanged)
            ));
            let mut incomplete = input.clone();
            incomplete.kernel_pending_command_ids.clear();
            assert!(matches!(
                owner.attach(incomplete, &cancel),
                Err(HistoricalOwnerAttachError::SourceUnresolved)
            ));
            assert!(owner.attachments().unwrap().is_empty());
            assert!(!config.state_dir.join("owner-attach.state").exists());
            assert!(!config
                .state_dir
                .join("workspaces")
                .join(workspace)
                .join("lifecycle.state")
                .exists());
            assert_eq!(target_effects(), prior_effects);
            let attached = owner.attach(input, &cancel).unwrap();
            assert_eq!(attached.status, "ATTACHED");
            assert_eq!(attached.selected_kernel_count, 1);
            assert_eq!(attached.retained_other_kernel_count, 2);
            assert_eq!(target_effects(), prior_effects);
            assert_eq!(accepted_command_count(unrelated), 0);
            assert_eq!(accepted_command_count(global), 0);
            let local = owner.kernel_command_status(&attached.attach_id).unwrap();
            assert_eq!(local.len(), 1);
            assert_eq!(local[0].command_id, selected);
            assert_eq!(local[0].intent_digest, source["selected_intent_digest"]);
            assert_eq!(
                local[0].status,
                if expired {
                    "EXPIRED_UNRESOLVED"
                } else {
                    "PENDING"
                }
            );
            std::fs::rename(&source_dir, root.path().join(format!("archived-{mode}"))).unwrap();
            assert_eq!(
                SecureHistoricalOwnerAttach::new(config.clone())
                    .resume_attachment(&attached.attach_id, &cancel)
                    .unwrap()
                    .status,
                "ATTACHED"
            );
            let recovered = SecureHistoricalOwnerAttach::new(config)
                .recover_kernel_command(&attached.attach_id, selected, &cancel)
                .unwrap();
            assert_eq!(recovered.command_id, selected);
            if applied {
                assert_eq!(recovered.status, "ACCEPTED");
                assert_eq!(recovered.last_http_status, None);
                assert_eq!(accepted_command_count(selected), 1);
            } else if expired {
                assert_eq!(recovered.status, "EXPIRED_UNRESOLVED");
                assert_eq!(recovered.last_http_status, None);
                assert_eq!(accepted_command_count(selected), 0);
            } else {
                assert_eq!(recovered.status, "RETAINED_UNRESOLVED");
                assert_eq!(recovered.last_http_status, Some(409));
                assert_eq!(accepted_command_count(selected), 0);
            }
            assert_eq!(target_effects(), prior_effects);
            assert_eq!(accepted_command_count(unrelated), 0);
            assert_eq!(accepted_command_count(global), 0);
        }
    }

    #[test]
    fn absent_attachment_history_is_empty_but_corrupt_existing_state_refuses() {
        let root = tempfile::tempdir().unwrap();
        let state_dir = root.path().join("native-owner");
        let attach = SecureHistoricalOwnerAttach::new(SecureOwnerCreateConfig {
            origin: "http://127.0.0.1:12345".into(),
            state_dir: state_dir.clone(),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        assert!(attach.attachments().unwrap().is_empty());
        assert!(!state_dir.exists());
        ensure_dir(&state_dir).unwrap();
        let path = state_dir.join("owner-attach.state");
        std::fs::write(&path, b"{").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            attach.attachments(),
            Err(HistoricalOwnerAttachError::Local)
        ));
    }

    #[test]
    fn actual_service_legacy_public_owner_attach_and_read() {
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
        struct StopPublic(Child);
        impl Drop for StopPublic {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopPublic(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        // A test-created PRIVATE source with its local ring removed must not
        // be reclassified as an attached PUBLIC workspace. Signed replay is
        // the authority for the workspace's visibility and encrypted history.
        let missing_ring = Command::new(&node)
            .arg(&helper)
            .arg(origin)
            .arg(root.path().join("legacy-missing-ring"))
            .arg(&legacy_root)
            .arg("private-missing-ring")
            .output()
            .unwrap();
        assert!(
            missing_ring.status.success(),
            "missing-ring setup: {}",
            String::from_utf8_lossy(&missing_ring.stderr)
        );
        let missing: serde_json::Value = serde_json::from_slice(&missing_ring.stdout).unwrap();
        let missing_workspace = missing["workspace_id"].as_str().unwrap();
        let bad_config = SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join("native-missing-ring"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let cancel = CancellationToken::new();
        let bad_attach = SecureHistoricalOwnerAttach::new(bad_config.clone());
        assert!(matches!(
            bad_attach.attach(
                HistoricalOwnerAttachInput {
                    workspace_id: missing_workspace.into(),
                    protected_ts_state_path: PathBuf::from(missing["state_path"].as_str().unwrap()),
                    protected_owner_pkcs8_path: PathBuf::from(
                        missing["pem_path"].as_str().unwrap()
                    ),
                    protected_ts_intent_db_path: PathBuf::from(
                        missing["intent_db_path"].as_str().unwrap()
                    ),
                    expected_owner_actor_id: missing["owner_actor_id"].as_str().unwrap().into(),
                    expected_owner_key_id: missing["owner_key_id"].as_str().unwrap().into(),
                    recover_pending_action: false,
                    kernel_pending_command_ids: Vec::new(),
                    expected_kernel_intent_db_digest: None,
                },
                &cancel
            ),
            Err(HistoricalOwnerAttachError::Verification)
        ));
        assert!(bad_attach
            .attachments()
            .unwrap()
            .iter()
            .all(|row| row.status != "ATTACHED"));
        assert!(SecureOwnerWorkspaceCreate::new(bad_config)
            .public_action_access(missing_workspace)
            .is_err());
        let setup = Command::new(&node)
            .arg(helper)
            .arg(origin)
            .arg(root.path().join("legacy-public"))
            .arg(legacy_root)
            .arg("legacy-public")
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "legacy public setup: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
        assert_eq!(source["policy_v"], 1);
        let workspace_id = source["workspace_id"].as_str().unwrap();
        let config = SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let cancel = CancellationToken::new();
        let attach = SecureHistoricalOwnerAttach::new(config.clone());
        let attached = attach
            .attach(
                HistoricalOwnerAttachInput {
                    workspace_id: workspace_id.into(),
                    protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                    protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                    protected_ts_intent_db_path: PathBuf::from(
                        source["intent_db_path"].as_str().unwrap(),
                    ),
                    expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                    expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                    recover_pending_action: false,
                    kernel_pending_command_ids: Vec::new(),
                    expected_kernel_intent_db_digest: None,
                },
                &cancel,
            )
            .unwrap();
        assert_eq!(attached.status, "ATTACHED");
        assert!(SecureOwnerWorkspaceCreate::new(config.clone())
            .public_action_access(workspace_id)
            .is_ok());
        assert!(matches!(
            SecureOwnerWorkspaceCreate::new(config.clone()).private_action_access(workspace_id),
            Err(_)
        ));
        let read: serde_json::Value = serde_json::from_str(
            &SecureOwnerWorkspaceCreate::new(config)
                .read_workspace_json(workspace_id, &cancel)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(read["workspace_id"], workspace_id);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
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
        let owner = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        let access = owner.format_transition_access(workspace_id).unwrap();
        let before = SecureReadProfile::new(access.profile_config().clone()).with_latest_replay(&cancel, |source| {
            let wire=source.signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(crate::secure_owner_format_transition::OwnerFormatTransitionError::Verification)?;
            let policy:serde_json::Value=serde_json::from_slice(wire)
                .map_err(|_|crate::secure_owner_format_transition::OwnerFormatTransitionError::Verification)?;
            Ok::<_,crate::secure_owner_format_transition::OwnerFormatTransitionError>((policy,source.replay().policy_hash().to_owned(),source.replay().sequence()))
        }).unwrap();
        assert_eq!(before.0["payload"]["v"], 1);
        assert_eq!(before.0["payload"]["visibility"], "PUBLIC");
        assert_eq!(before.0["payload"]["epoch"], 0);
        assert_eq!(
            rt.block_on(
                reqwest::Client::new()
                    .post(format!("{origin}__test/drop-next-post"))
                    .body("{}")
                    .send()
            )
            .unwrap()
            .status(),
            200
        );
        let input = crate::secure_owner_format_transition::OwnerFormatTransitionInput {
            workspace_id: workspace_id.into(),
            transition: crate::secure_owner_format_transition::OwnerFormatTransition::UpgradeWireV3,
            command_id: None,
            issued_at_ms: None,
        };
        let first: serde_json::Value =
            serde_json::from_str(&access.submit_json_with_cancel(input, &cancel).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        let command_id = first["command_id"].as_str().unwrap();
        let fresh = owner.format_transition_access(workspace_id).unwrap();
        let history: serde_json::Value =
            serde_json::from_str(&fresh.history_json().unwrap()).unwrap();
        assert_eq!(history[0]["command_id"], command_id);
        let accepted: serde_json::Value =
            serde_json::from_str(&fresh.resume_json_with_cancel(command_id, &cancel).unwrap())
                .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let after = SecureReadProfile::new(fresh.profile_config().clone()).with_latest_replay(&cancel, |source| {
            let wire=source.signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(crate::secure_owner_format_transition::OwnerFormatTransitionError::Verification)?;
            let policy:serde_json::Value=serde_json::from_slice(wire)
                .map_err(|_|crate::secure_owner_format_transition::OwnerFormatTransitionError::Verification)?;
            Ok::<_,crate::secure_owner_format_transition::OwnerFormatTransitionError>((policy,source.replay().policy_hash().to_owned(),source.replay().sequence()))
        }).unwrap();
        assert_eq!(after.0["payload"]["v"], 3);
        assert_eq!(after.0["payload"]["visibility"], "PUBLIC");
        assert_eq!(after.0["payload"]["epoch"], 0);
        assert_eq!(after.0["payload"]["protocol_format_ceiling"], 1);
        assert_eq!(after.0["payload"]["structure_mode"], "NONE");
        for field in ["workspace_id", "owner_id", "signing_key", "members"] {
            assert_eq!(after.0["payload"][field], before.0["payload"][field]);
        }
        assert_eq!(after.0["payload"]["previous_policy"], before.1);
        assert_eq!(
            after.0["payload"]["effective_sequence"].as_u64(),
            Some(before.2 + 1)
        );
        assert_eq!(after.1, accepted["policy_hash"]);
        assert_eq!(after.2, before.2 + 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &fresh.resume_json_with_cancel(command_id, &cancel).unwrap()
            )
            .unwrap(),
            accepted
        );
        let final_sequence = SecureReadProfile::new(fresh.profile_config().clone())
            .with_latest_replay(&cancel, |source| {
                Ok::<_, crate::secure_owner_format_transition::OwnerFormatTransitionError>(
                    source.replay().sequence(),
                )
            })
            .unwrap();
        assert_eq!(final_sequence, after.2);
        let forbidden = crate::secure_owner_format_transition::OwnerFormatTransitionInput {
            workspace_id: workspace_id.into(),
            transition:
                crate::secure_owner_format_transition::OwnerFormatTransition::RaisePrivateCeilingTwo,
            command_id: None,
            issued_at_ms: None,
        };
        assert!(matches!(
            fresh.submit_json_with_cancel(forbidden, &cancel),
            Err(crate::secure_owner_format_transition::OwnerFormatTransitionError::Input)
        ));
        assert_eq!(
            SecureReadProfile::new(fresh.profile_config().clone())
                .with_latest_replay(&cancel, |source| Ok::<
                    _,
                    crate::secure_owner_format_transition::OwnerFormatTransitionError,
                >(
                    source.replay().sequence()
                ))
                .unwrap(),
            after.2
        );
    }

    #[test]
    fn actual_service_legacy_structured_public_owner_upgrade() {
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
        struct StopStructured(Child);
        impl Drop for StopStructured {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = StopStructured(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let setup = Command::new(&node)
            .arg(helper)
            .arg(origin)
            .arg(root.path().join("legacy-public-structured"))
            .arg(legacy_root)
            .arg("legacy-public-structured")
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "legacy structured PUBLIC setup: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
        assert_eq!(source["policy_v"], 2);
        let workspace_id = source["workspace_id"].as_str().unwrap();
        let config = SecureOwnerCreateConfig {
            origin: origin.into(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let cancel = CancellationToken::new();
        let attached = SecureHistoricalOwnerAttach::new(config.clone())
            .attach(
                HistoricalOwnerAttachInput {
                    workspace_id: workspace_id.into(),
                    protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                    protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                    protected_ts_intent_db_path: PathBuf::from(
                        source["intent_db_path"].as_str().unwrap(),
                    ),
                    expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                    expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                    recover_pending_action: false,
                    kernel_pending_command_ids: Vec::new(),
                    expected_kernel_intent_db_digest: None,
                },
                &cancel,
            )
            .unwrap();
        assert_eq!(attached.status, "ATTACHED");
        let owner = SecureOwnerWorkspaceCreate::new(config);
        let access = owner.format_transition_access(workspace_id).unwrap();
        let policy =
            |access: &crate::secure_owner_format_transition::SecureOwnerFormatTransition| {
                SecureReadProfile::new(access.profile_config().clone()).with_latest_replay(&cancel,|source| {
                let wire=source.signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(crate::secure_owner_format_transition::OwnerFormatTransitionError::Verification)?;
                let policy:serde_json::Value=serde_json::from_slice(wire)
                    .map_err(|_|crate::secure_owner_format_transition::OwnerFormatTransitionError::Verification)?;
                Ok::<_,crate::secure_owner_format_transition::OwnerFormatTransitionError>((policy,source.replay().policy_hash().to_owned(),source.replay().sequence()))
            }).unwrap()
            };
        let before = policy(&access);
        assert_eq!(before.0["payload"]["v"], 2);
        assert_eq!(before.0["payload"]["visibility"], "PUBLIC");
        assert!(before.0["payload"]["structure"].is_object());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
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
        let result:serde_json::Value=serde_json::from_str(&access.submit_json_with_cancel(
            crate::secure_owner_format_transition::OwnerFormatTransitionInput {
                workspace_id:workspace_id.into(),transition:crate::secure_owner_format_transition::OwnerFormatTransition::UpgradeWireV3,
                command_id:None,issued_at_ms:None },&cancel).unwrap()).unwrap();
        let id = result["command_id"].as_str().unwrap();
        let accepted: serde_json::Value =
            serde_json::from_str(&access.resume_json_with_cancel(id, &cancel).unwrap()).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let after = policy(&access);
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
            assert_eq!(after.0["payload"][field], before.0["payload"][field]);
        }
        assert_eq!(after.0["payload"]["previous_policy"], before.1);
        assert_eq!(
            after.0["payload"]["effective_sequence"].as_u64(),
            Some(before.2 + 1)
        );
        assert_eq!(after.1, accepted["policy_hash"]);
        assert_eq!(after.2, before.2 + 1);
        assert_eq!(policy(&access).2, after.2);
    }

    #[test]
    fn actual_service_legacy_private_owner_attach_then_native_action() {
        let _fault_guard = ATTACH_FAULT_TEST_LOCK.lock().unwrap();
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
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let config = SecureOwnerCreateConfig {
            origin: origin.clone(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let token = CancellationToken::new();
        let attach = SecureHistoricalOwnerAttach::new(config.clone());
        for mode in ["pending", "unknown-store", "malformed-store"] {
            let source_dir = root.path().join(format!("legacy-{mode}-owner"));
            let setup = Command::new(&node)
                .arg(&helper)
                .arg(&origin)
                .arg(&source_dir)
                .arg(&legacy_root)
                .arg(mode)
                .output()
                .unwrap();
            assert!(
                setup.status.success(),
                "legacy {mode} setup failed: {}",
                String::from_utf8_lossy(&setup.stderr)
            );
            let source: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
            assert_eq!(source["policy_v"], 1);
            if mode == "pending" {
                assert_eq!(source["pending_count"], 1);
            }
            let input = HistoricalOwnerAttachInput {
                workspace_id: source["workspace_id"].as_str().unwrap().into(),
                protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                protected_ts_intent_db_path: PathBuf::from(
                    source["intent_db_path"].as_str().unwrap(),
                ),
                expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                recover_pending_action: false,
                kernel_pending_command_ids: Vec::new(),
                expected_kernel_intent_db_digest: None,
            };
            assert!(
                matches!(
                    attach.attach(input, &token),
                    Err(HistoricalOwnerAttachError::SourceUnresolved)
                ),
                "{mode} must refuse before activation"
            );
            assert!(
                attach.attachments().unwrap().is_empty(),
                "{mode} must not create an attach row"
            );
        }
        let source_dir = root.path().join("legacy-owner");
        let setup = Command::new(&node)
            .arg(helper)
            .arg(&origin)
            .arg(&source_dir)
            .arg(legacy_root)
            .arg("completed")
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "legacy source setup failed: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
        assert_eq!(
            source["policy_v"], 1,
            "the old client must actually sign wire v1"
        );
        assert_eq!(source["completed_identity_updates"], 1);
        let workspace_id = source["workspace_id"].as_str().unwrap().to_owned();
        let input = HistoricalOwnerAttachInput {
            workspace_id: workspace_id.clone(),
            protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
            protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
            protected_ts_intent_db_path: PathBuf::from(source["intent_db_path"].as_str().unwrap()),
            expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
            expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
            recover_pending_action: false,
            kernel_pending_command_ids: Vec::new(),
            expected_kernel_intent_db_digest: None,
        };
        let mut wrong_owner = input.clone();
        wrong_owner.expected_owner_key_id = "z".repeat(43);
        assert!(matches!(
            attach.attach(wrong_owner, &token),
            Err(HistoricalOwnerAttachError::Identity)
        ));
        assert!(!config.state_dir.join("owner-attach.state").exists());
        TEST_STOP_AFTER_ATTACH_ROW.store(true, Ordering::SeqCst);
        assert!(matches!(
            attach.attach(input.clone(), &token),
            Err(HistoricalOwnerAttachError::Cancelled)
        ));
        let prepared = attach.attachments().unwrap();
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].status, "PREPARED");
        assert!(prepared[0].sequence.is_none());
        let attached = SecureHistoricalOwnerAttach::new(config.clone())
            .resume_attachment(&prepared[0].attach_id, &token)
            .unwrap();
        assert_eq!(attached.attach_id, prepared[0].attach_id);
        assert_eq!(attached.status, "ATTACHED");
        assert_eq!(attached.provenance, "HISTORICAL_TS_OWNER");
        assert_eq!(attached.workspace_id, workspace_id);
        assert!(attached.sequence.unwrap() >= 1);
        assert_eq!(
            attach
                .resume_attachment(&attached.attach_id, &token)
                .unwrap(),
            attached
        );
        assert_eq!(attach.attachments().unwrap(), vec![attached.clone()]);
        let old_source = root.path().join("legacy-rollback");
        std::fs::rename(&source_dir, &old_source).unwrap();
        let owner = SecureOwnerWorkspaceCreate::new(config);
        let read: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &token).unwrap())
                .unwrap();
        assert_eq!(read["workspace_id"], workspace_id);
        let wiki = read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "instances" && row["value"]["origin_entrypoint"] == "wiki")
            .and_then(|row| row["id"].as_str())
            .unwrap()
            .to_owned();
        let action = owner.private_action_access(&workspace_id).unwrap();
        let submitted: serde_json::Value =
            serde_json::from_str(
                &action
                    .submit_new_json(PublicActionInput {
                        action_id: "wiki.create".into(),
                        instance_id: wiki,
                        body_json:
                            r#"{"title":"Legacy attached Owner","body":"Native PREPARE action"}"#
                                .into(),
                        exact_input_refs_json: None,
                        allocations_json: None,
                        command_id: None,
                        issued_at_ms: None,
                    })
                    .unwrap(),
            )
            .unwrap();
        let command = submitted["command_id"].as_str().unwrap();
        let accepted: serde_json::Value =
            serde_json::from_str(&action.retry_saved_json(command).unwrap()).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let after: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &token).unwrap())
                .unwrap();
        assert!(after["sequence"].as_u64().unwrap() > read["sequence"].as_u64().unwrap());
        assert!(after["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "records"
                && row["id"] == effect_id
                && row["value"]["payload"]["title"] == "Legacy attached Owner"));
        let repeated: serde_json::Value =
            serde_json::from_str(&action.retry_saved_json(command).unwrap()).unwrap();
        assert_eq!(
            repeated["receipt_canonical_json"],
            accepted["receipt_canonical_json"]
        );
        let after_retry: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &token).unwrap())
                .unwrap();
        assert_eq!(after_retry["sequence"], after["sequence"]);
    }
}
