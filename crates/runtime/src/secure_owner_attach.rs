//! Explicit attachment of an exportable, protected TypeScript Owner state.
//! Source files remain untouched. A saved local binding and pending epoch ring
//! are never Owner authority until a complete configured-origin signed replay
//! proves the source checkpoint, current policy, and all encrypted history.

use crate::{
    kernel_identity::{KernelIdentity, KernelIdentityError},
    secure_lifecycle::SecureLifecycle,
    secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerWorkspaceCreate},
    secure_read_access::{SecureReadAccess, SecureReadConfig},
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::{read_private_file_bounded, SecureStateStore},
    transport::{HttpTransport, TransportConfig},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
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
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static TEST_STOP_AFTER_ATTACH_ROW: AtomicBool = AtomicBool::new(false);

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
        let replayed = access
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
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        saved.attached_sequence = Some(replayed.replay().sequence());
        saved.attached_head = replayed.replay().head().map(str::to_owned);
        let completed = saved.clone();
        save_history(&store, &history)?;
        Ok(summary(attach_id, &completed))
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
        let intent_digest =
            crate::ts_migration::quiescent_source_digest(&input.protected_ts_intent_db_path)
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
        if !matches!(value.get("pending"), Some(WireValue::Object(fields)) if fields.is_empty()) {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        if !confirmed_browser_approvals(value.get("admission_browser_approvals"), input)
            || !completed_signed_cache(value.get("intake_closures"))
            || !completed_signed_cache(value.get("application_decisions"))
            || !completed_evidence_cache(value.get("control_evidence"))
        {
            return Err(HistoricalOwnerAttachError::SourceUnresolved);
        }
        for key in [
            "admission_browser_revocations",
            "configuration_receipts",
            "inbox_receipts",
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
        Ok(LegacySource {
            visibility: if ring.is_some() { "PRIVATE" } else { "PUBLIC" }.into(),
            ring,
            sequence,
            head,
            policy_hash,
            retained_member_commands,
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
