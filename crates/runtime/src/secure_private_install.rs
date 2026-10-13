//! Protected PRIVATE package staging against a complete Owner replay. A POST
//! response is only an observation; exact signed commits prove each part.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_lifecycle::SecureLifecycle,
    secure_read_access::{
        SecureReadAccess, SecureReadAccessError, SecureReadConfig, VerifiedReadFloor,
    },
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::{SecureStateError, SecureStateStore},
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, decode_base64url, sha256, sha256_hex},
    prepared_private_install::{
        prepare_private_direct_install_begin, prepare_private_package_install_begin,
        prepare_private_package_install_step, prepare_private_package_stage,
        verify_saved_private_direct_install_begin, verify_saved_private_package_install_begin,
        verify_saved_private_package_install_step, verify_saved_private_package_stage,
        PrivateInstallError,
    },
    public_direct_install::plan_public_install_snapshot,
    replayed_secure_journal::StructureStatus,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
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

#[cfg(test)]
static TEST_CRASH_AFTER_BEGIN_ROW: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn test_crash_after_begin_row() -> Result<(), PrivatePackageInstallError> {
    #[cfg(test)]
    if TEST_CRASH_AFTER_BEGIN_ROW.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(PrivatePackageInstallError::Runtime);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PrivatePackageInstallError {
    #[error("complete PRIVATE Owner journal read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("protected Owner identity, lifecycle, or local stage scope is invalid")]
    Identity,
    #[error("package selection or staging context is invalid")]
    Input,
    #[error("native package staging proof failed")]
    Plan,
    #[error("protected stage state failed: {0}")]
    State(#[from] SecureStateError),
    #[error("protected exact command intent failed: {0}")]
    Intent(#[from] SecureIntentError),
    #[error("OS entropy is unavailable")]
    Entropy,
    #[error("configured transport failed")]
    Transport,
    #[error("native async runtime failed")]
    Runtime,
    #[error("service rejected the exact saved stage packet with HTTP {0}")]
    ServerRejected(u16),
    #[error("result could not be encoded")]
    Encoding,
}
impl From<PrivateInstallError> for PrivatePackageInstallError {
    fn from(error: PrivateInstallError) -> Self {
        match error {
            PrivateInstallError::Resource => Self::State(SecureStateError::TooLarge),
            _ => Self::Plan,
        }
    }
}
impl PrivatePackageInstallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(error) => error.code(),
            Self::Identity => "IDENTITY_STATE",
            Self::Input => "INSTALL_INPUT_INVALID",
            Self::Plan => "INSTALL_PLAN_FAILED",
            Self::State(SecureStateError::TooLarge) => "RESOURCE_LIMIT",
            Self::State(SecureStateError::Busy) => "STATE_BUSY",
            Self::State(_) => "INSTALL_STATE",
            Self::Intent(_) => "INTENT_STATE",
            Self::Entropy => "ENTROPY_UNAVAILABLE",
            Self::Transport => "TRANSPORT_FAILED",
            Self::Runtime => "RUNTIME_FAILED",
            Self::ServerRejected(_) => "SERVER_REJECTED",
            Self::Encoding => "RESULT_ENCODING_FAILED",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePackageStageInput {
    pub material_json: String,
    pub expected_root_package_digest: String,
    pub expected_protocol_digest: String,
    #[serde(default)]
    pub stage_id: Option<String>,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrivatePackageStageResult {
    pub status: &'static str,
    pub stage_id: String,
    pub workspace_id: String,
    pub source_id: String,
    pub root_package_digest: String,
    pub protocol_digest: String,
    pub part_count: usize,
    pub applied_parts: usize,
    pub pending_command_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePackageInstallBeginInput {
    pub stage_id: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateDirectInstallBeginInput {
    pub closure_json: String,
    pub expected_root_package_digest: String,
    pub expected_protocol_digest: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivatePackageInstallProgress {
    pub status: &'static str,
    pub begin_command_id: String,
    pub step_command_id: String,
    pub step_action_id: &'static str,
    pub workspace_id: String,
    pub protocol_digest: String,
    pub instance_id: String,
    pub commit_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRow {
    #[serde(default)]
    source_kind: Option<InstallSourceKind>,
    #[serde(default)]
    stage_id: Option<String>,
    #[serde(default)]
    direct_source: Option<DirectInstallSource>,
    instance_id: String,
    entrypoint: String,
    grants_json: String,
    issued_at_ms: u64,
    request_b64: String,
    commit_hash: String,
    policy_hash: String,
    snapshot_json: String,
    protocol_digest: String,
    #[serde(default)]
    steps: Vec<InstallStep>,
    #[serde(default)]
    accepted: Option<AcceptedInstall>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum InstallSourceKind {
    Staged,
    Direct,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectInstallSource {
    material_b64: String,
    source_checkpoint_json: String,
    root_package_digest: String,
}
impl InstallRow {
    fn source_kind(&self) -> Result<InstallSourceKind, PrivatePackageInstallError> {
        match (
            self.source_kind,
            self.stage_id.as_deref(),
            &self.direct_source,
        ) {
            (None | Some(InstallSourceKind::Staged), Some(id), None) if token(id) => {
                Ok(InstallSourceKind::Staged)
            }
            (Some(InstallSourceKind::Direct), None, Some(source))
                if !source.material_b64.is_empty()
                    && !source.source_checkpoint_json.is_empty()
                    && source.root_package_digest.len() == 64 =>
            {
                Ok(InstallSourceKind::Direct)
            }
            _ => Err(PrivatePackageInstallError::Identity),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallStep {
    command_id: String,
    issued_at_ms: u64,
    request_b64: String,
    commit_hash: String,
    action_id: String,
    offset: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedInstall {
    sequence: u64,
    head: String,
    policy_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallDocument {
    v: u8,
    origin: String,
    actor_id: String,
    workspace_id: String,
    owner_key_id: String,
    rows: BTreeMap<String, InstallRow>,
}
impl InstallDocument {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        actor: &str,
        key: &str,
    ) -> Result<Self, PrivatePackageInstallError> {
        let doc = match store.read_exact_secret()? {
            Some(bytes) => serde_json::from_slice::<Self>(&bytes)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            None => Self {
                v: 1,
                origin: config.origin.clone(),
                actor_id: actor.into(),
                workspace_id: config.workspace_id.clone(),
                owner_key_id: key.into(),
                rows: BTreeMap::new(),
            },
        };
        if doc.v != 1
            || doc.origin != config.origin
            || doc.actor_id != actor
            || doc.workspace_id != config.workspace_id
            || doc.owner_key_id != key
            || doc.rows.len() > 16
            || doc
                .rows
                .iter()
                .any(|(id, row)| !token(id) || row.source_kind().is_err())
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        Ok(doc)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), PrivatePackageInstallError> {
        store.write_exact(
            &serde_json::to_vec(self).map_err(|_| PrivatePackageInstallError::Encoding)?,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageStep {
    command_id: String,
    issued_at_ms: u64,
    request_b64: String,
    commit_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageRow {
    material_b64: String,
    source_checkpoint_json: String,
    policy_hash: String,
    source_id: String,
    root_package_digest: String,
    protocol_digest: String,
    part_count: usize,
    steps: Vec<StageStep>,
    completed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageDocument {
    v: u8,
    origin: String,
    actor_id: String,
    workspace_id: String,
    owner_actor_id: String,
    owner_key_id: String,
    rows: BTreeMap<String, StageRow>,
}
impl StageDocument {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        actor_id: &str,
        owner_actor_id: &str,
        owner_key_id: &str,
    ) -> Result<Self, PrivatePackageInstallError> {
        let doc = match store.read_exact_secret()? {
            Some(bytes) => serde_json::from_slice::<Self>(&bytes)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            None => Self {
                v: 1,
                origin: config.origin.clone(),
                actor_id: actor_id.to_owned(),
                workspace_id: config.workspace_id.clone(),
                owner_actor_id: owner_actor_id.to_owned(),
                owner_key_id: owner_key_id.to_owned(),
                rows: BTreeMap::new(),
            },
        };
        if doc.v != 1
            || doc.origin != config.origin
            || doc.actor_id != actor_id
            || doc.workspace_id != config.workspace_id
            || doc.owner_actor_id != owner_actor_id
            || doc.owner_key_id != owner_key_id
            || doc.rows.len() > 16
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        Ok(doc)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), PrivatePackageInstallError> {
        store.write_exact(
            &serde_json::to_vec(self).map_err(|_| PrivatePackageInstallError::Encoding)?,
        )?;
        Ok(())
    }
}

fn random_id() -> Result<String, PrivatePackageInstallError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PrivatePackageInstallError::Entropy)?;
    Ok(base64url(&bytes))
}
fn now_ms() -> Result<u64, PrivatePackageInstallError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PrivatePackageInstallError::Input)?;
    u64::try_from(now.as_millis()).map_err(|_| PrivatePackageInstallError::Input)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn number(value: &WireValue, key: &str) -> Result<u64, PrivatePackageInstallError> {
    let n = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(PrivatePackageInstallError::Input)?;
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(PrivatePackageInstallError::Input);
    };
    Ok(n as u64)
}
fn scalar(value: &WireValue, key: &str) -> Result<String, PrivatePackageInstallError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(PrivatePackageInstallError::Input)
}
fn checkpoint_json(
    source: &TransportReplayedJournal,
    sequence: u64,
    head: &str,
    policy_hash: &str,
) -> Result<String, PrivatePackageInstallError> {
    let value = serde_json::json!({"v":1,"workspace_id":source.replay().workspace_id(),
        "owner_id":source.replay().owner_actor_id(),"owner_key":source.replay().owner_signing_key(),
        "sequence":sequence,"head":head,"policy_hash":policy_hash});
    serde_json::to_string(&value).map_err(|_| PrivatePackageInstallError::Encoding)
}

fn install_step_id(begin_id: &str, offset: usize, done: bool) -> String {
    let domain = if done {
        format!("peerwork.private.install.end.v1:{begin_id}")
    } else {
        format!("peerwork.private.install.page.v1:{begin_id}:{offset}")
    };
    base64url(&sha256(domain.as_bytes()))
}
fn same_snapshot(left: &WireValue, right: &WireValue) -> bool {
    ["source", "root", "records", "heads"]
        .iter()
        .all(|field| left.get(field).is_some() && left.get(field) == right.get(field))
}
fn post_saved_private(
    config: &SecureReadProfileConfig,
    origin: &str,
    journal: &mut SecureIntentJournal,
    id: &str,
    packet: Vec<u8>,
    cancel: &CancellationToken,
) -> Result<(), PrivatePackageInstallError> {
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        config.workspace_id
    );
    let mut transport_config = TransportConfig::new(config.origin.clone());
    transport_config.allow_loopback_http = config.allow_loopback_http;
    let transport =
        HttpTransport::new(transport_config).map_err(|_| PrivatePackageInstallError::Transport)?;
    if transport.trusted_origin() != origin {
        return Err(PrivatePackageInstallError::Transport);
    }
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| PrivatePackageInstallError::Runtime)?;
    match runtime.block_on(transport.post_exact(&path, packet, cancel)) {
        Ok(response) => {
            if !response.wire.is_empty() {
                journal.observe_response(id, &response.wire)?
            }
            if !(200..300).contains(&response.status) {
                return Err(PrivatePackageInstallError::ServerRejected(response.status));
            }
        }
        Err(TransportError::SubmittedUncertain) => {}
        Err(_) => return Err(PrivatePackageInstallError::Transport),
    }
    Ok(())
}

pub struct SecurePrivatePackageInstall {
    config: SecureReadProfileConfig,
}
impl SecurePrivatePackageInstall {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    /// Fetch a complete signed SEEDING candidate while retaining the last
    /// verified ACTIVE profile floor. Candidate bytes cannot authorize a
    /// normal read or replace the protected active generation.
    fn with_install_replay<T, F>(
        &self,
        cancel: &CancellationToken,
        consume: F,
    ) -> Result<T, PrivatePackageInstallError>
    where
        F: FnOnce(
            &TransportReplayedJournal,
            &TransportReplayedJournal,
        ) -> Result<T, PrivatePackageInstallError>,
    {
        SecureReadProfile::new(self.config.clone()).with_pinned_replay(cancel, |prior| {
            let floor = VerifiedReadFloor {
                sequence: prior.replay().sequence(),
                head: prior.replay().head().map(str::to_owned),
                policy_hash: prior.replay().policy_hash().to_owned(),
            };
            let access = SecureReadAccess::new(SecureReadConfig {
                origin: prior.origin().to_owned(),
                kernel_journal_path: self.config.state_dir.join("kernel.sqlite"),
                read_state_path: self.config.state_dir.join("private-install-read.state"),
                lifecycle_path: self.config.state_dir.join("lifecycle.state"),
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
                return Err(PrivatePackageInstallError::Identity);
            }
            consume(prior, &fresh)
        })
    }

    /// Discover protected generated BEGIN IDs without a network request.
    /// A row is an intent, never evidence that installation was accepted.
    pub fn installs_json(&self) -> Result<String, PrivatePackageInstallError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || scope.owner_actor_id != identity.actor_id()
            || scope.owner_key_id != identity.key_id()
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        let store = SecureStateStore::open(
            &self
                .config
                .state_dir
                .join("private-install-operations.state"),
        )?;
        let doc =
            InstallDocument::open(&store, &self.config, identity.actor_id(), identity.key_id())?;
        let rows: Result<Vec<_>, PrivatePackageInstallError> = doc
            .rows
            .iter()
            .map(|(id, row)| {
                let kind = row.source_kind()?;
                let mut item = serde_json::json!({
                    "begin_command_id":id,
                    "source_kind":kind,
                    "workspace_id":doc.workspace_id,
                    "instance_id":row.instance_id,
                    "protocol_digest":row.protocol_digest,
                    "locally_saved":true
                });
                if let Some(stage_id) = &row.stage_id {
                    item["stage_id"] = serde_json::Value::String(stage_id.clone());
                }
                Ok(item)
            })
            .collect();
        let rows = rows?;
        serde_json::to_string(&rows).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    pub fn submit_begin_json(
        &self,
        input: PrivatePackageInstallBeginInput,
    ) -> Result<String, PrivatePackageInstallError> {
        self.submit_begin_json_with_cancel(input, &CancellationToken::new())
    }
    pub fn submit_begin_json_with_cancel(
        &self,
        input: PrivatePackageInstallBeginInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(&input.stage_id)
            || !token(&input.instance_id)
            || input.command_id.as_deref().is_some_and(|id| !token(id))
            || input.entrypoint.is_empty()
            || input.entrypoint.len() > 64
            || !input.entrypoint.as_bytes()[0].is_ascii_alphabetic()
            || !input
                .entrypoint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || input.entrypoint == "coordination"
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let command_id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued_at = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        let result =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                source
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let identity = KernelIdentity::open(&self.config.identity_path)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                if source.origin() != self.config.origin
                    || source.source_actor_id() != identity.actor_id()
                    || source.source_key_id() != identity.key_id()
                    || source.replay().owner_actor_id() != identity.actor_id()
                    || source.replay().owner_signing_key() != identity.key_id()
                    || source.replay().workspace_id() != self.config.workspace_id
                    || source.replay().structure_status() != StructureStatus::Active
                {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let stage_store =
                    SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
                let stage_doc = StageDocument::open(
                    &stage_store,
                    &self.config,
                    identity.actor_id(),
                    identity.actor_id(),
                    identity.key_id(),
                )?;
                let stage = stage_doc
                    .rows
                    .get(&input.stage_id)
                    .ok_or(PrivatePackageInstallError::Input)?
                    .clone();
                drop(stage_doc);
                drop(stage_store);
                let base =
                    parse_wire_json_bounded(stage.source_checkpoint_json.as_bytes(), 32, 8192)
                        .map_err(|_| PrivatePackageInstallError::Input)?;
                let base_sequence = number(&base, "sequence")?;
                let base_head = scalar(&base, "head")?;
                if !stage.completed
                    || stage.steps.len() != stage.part_count
                    || source.replay().sequence() != base_sequence + stage.part_count as u64
                    || source.replay().policy_hash() != stage.policy_hash
                    || !source.replay().contains_checkpoint(
                        base_sequence,
                        Some(&base_head),
                        &stage.policy_hash,
                    )
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                for (offset, step) in stage.steps.iter().enumerate() {
                    if !source.replay().contains_checkpoint(
                        base_sequence + offset as u64 + 1,
                        Some(&step.commit_hash),
                        &stage.policy_hash,
                    ) {
                        return Err(PrivatePackageInstallError::Plan);
                    }
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    source.replay().workspace_id(),
                    source.replay().owner_actor_id(),
                    source.replay().owner_signing_key(),
                )
                .map_err(|_| PrivatePackageInstallError::Identity)?;
                if lifecycle.active_keyring_without_pending().is_none() {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let policy_wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Input)?;
                let epoch = number(
                    policy
                        .get("payload")
                        .ok_or(PrivatePackageInstallError::Input)?,
                    "epoch",
                )?;
                let key = lifecycle
                    .active_key(epoch)
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let material = decode_base64url(&stage.material_b64)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let prepared = prepare_private_package_install_begin(
                    &material,
                    stage.source_checkpoint_json.as_bytes(),
                    source.checkpoint_canonical_json().as_bytes(),
                    policy_wire,
                    source.replay().objects(),
                    input.grants_json.as_bytes(),
                    &input.instance_id,
                    &input.entrypoint,
                    &command_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                if prepared.protocol_digest() != stage.protocol_digest {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let store = SecureStateStore::open(
                    &self
                        .config
                        .state_dir
                        .join("private-install-operations.state"),
                )?;
                let mut doc = InstallDocument::open(
                    &store,
                    &self.config,
                    identity.actor_id(),
                    identity.key_id(),
                )?;
                if doc.rows.len() >= 16
                    || doc
                        .rows
                        .values()
                        .any(|existing| existing.accepted.is_none())
                    || doc.rows.contains_key(&command_id)
                {
                    return Err(PrivatePackageInstallError::Input);
                }
                let snapshot_json = peerwork_core::wire_json::canonical_wire_value(
                    prepared.snapshot(),
                    peerwork_core::canonical::Path::SecureArtifact,
                )
                .map_err(|_| PrivatePackageInstallError::Plan)?;
                let row = InstallRow {
                    source_kind: Some(InstallSourceKind::Staged),
                    stage_id: Some(input.stage_id.clone()),
                    direct_source: None,
                    instance_id: input.instance_id.clone(),
                    entrypoint: input.entrypoint.clone(),
                    grants_json: input.grants_json.clone(),
                    issued_at_ms: issued_at,
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().to_owned(),
                    policy_hash: prepared.policy_hash().to_owned(),
                    snapshot_json,
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    steps: Vec::new(),
                    accepted: None,
                };
                doc.rows.insert(command_id.clone(), row);
                doc.save(&store)?;
                test_crash_after_begin_row()?;
                let mut journal = SecureIntentJournal::open(
                    &self.config.state_dir.join("private-install-intents.state"),
                    source.origin(),
                    identity.actor_id(),
                )?;
                let path = format!(
                    "/api/workspace/v1/secure/workspaces/{}/commits",
                    self.config.workspace_id
                );
                journal.prepare(SecurePacketInput {
                    intent_id: &command_id,
                    path: &path,
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                })?;
                if journal.exact_request(&command_id)? != prepared.request_wire()
                    || journal.intent_digest(&command_id)? != prepared.commit_hash()
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let mut transport_config = TransportConfig::new(self.config.origin.clone());
                transport_config.allow_loopback_http = self.config.allow_loopback_http;
                let transport = HttpTransport::new(transport_config)
                    .map_err(|_| PrivatePackageInstallError::Transport)?;
                if transport.trusted_origin() != source.origin() {
                    return Err(PrivatePackageInstallError::Transport);
                }
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| PrivatePackageInstallError::Runtime)?;
                match runtime.block_on(transport.post_exact(
                    &path,
                    prepared.request_wire().to_vec(),
                    cancel,
                )) {
                    Ok(response) => {
                        if !response.wire.is_empty() {
                            journal.observe_response(&command_id, &response.wire)?
                        }
                        if !(200..300).contains(&response.status) {
                            return Err(PrivatePackageInstallError::ServerRejected(
                                response.status,
                            ));
                        }
                    }
                    Err(TransportError::SubmittedUncertain) => {}
                    Err(_) => return Err(PrivatePackageInstallError::Transport),
                }
                Ok(PrivatePackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: command_id.clone(),
                    step_command_id: command_id,
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    instance_id: prepared.instance_id().to_owned(),
                    commit_hash: prepared.commit_hash().to_owned(),
                })
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Begin a direct install from protected local package selection. This
    /// shares the staged install's durable BEGIN/PAGE/END operation journal;
    /// no package stage ID or stage packet is synthesized.
    pub fn submit_direct_begin_json(
        &self,
        input: PrivateDirectInstallBeginInput,
    ) -> Result<String, PrivatePackageInstallError> {
        self.submit_direct_begin_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_direct_begin_json_with_cancel(
        &self,
        input: PrivateDirectInstallBeginInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(&input.instance_id)
            || input.command_id.as_deref().is_some_and(|id| !token(id))
            || input.entrypoint.is_empty()
            || input.entrypoint.len() > 64
            || !input.entrypoint.as_bytes()[0].is_ascii_alphabetic()
            || !input
                .entrypoint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || input.entrypoint == "coordination"
            || input.closure_json.is_empty()
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let command_id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued_at = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        let result =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                source
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let identity = KernelIdentity::open(&self.config.identity_path)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                if source.origin() != self.config.origin
                    || source.source_actor_id() != identity.actor_id()
                    || source.source_key_id() != identity.key_id()
                    || source.replay().owner_actor_id() != identity.actor_id()
                    || source.replay().owner_signing_key() != identity.key_id()
                    || source.replay().workspace_id() != self.config.workspace_id
                    || source.replay().structure_status() == StructureStatus::Seeding
                {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    source.replay().workspace_id(),
                    source.replay().owner_actor_id(),
                    source.replay().owner_signing_key(),
                )
                .map_err(|_| PrivatePackageInstallError::Identity)?;
                if lifecycle.active_keyring_without_pending().is_none() {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let policy_wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Input)?;
                let epoch = number(
                    policy
                        .get("payload")
                        .ok_or(PrivatePackageInstallError::Input)?,
                    "epoch",
                )?;
                let key = lifecycle
                    .active_key(epoch)
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let prepared = prepare_private_direct_install_begin(
                    input.closure_json.as_bytes(),
                    &input.expected_root_package_digest,
                    &input.expected_protocol_digest,
                    source.checkpoint_canonical_json().as_bytes(),
                    policy_wire,
                    source.replay().objects(),
                    input.grants_json.as_bytes(),
                    &input.instance_id,
                    &input.entrypoint,
                    &command_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                let store = SecureStateStore::open(
                    &self
                        .config
                        .state_dir
                        .join("private-install-operations.state"),
                )?;
                let mut doc = InstallDocument::open(
                    &store,
                    &self.config,
                    identity.actor_id(),
                    identity.key_id(),
                )?;
                if doc.rows.len() >= 16
                    || doc
                        .rows
                        .values()
                        .any(|existing| existing.accepted.is_none())
                    || doc.rows.contains_key(&command_id)
                {
                    return Err(PrivatePackageInstallError::Input);
                }
                let snapshot_json =
                    canonical_wire_value(prepared.snapshot(), CanonicalPath::SecureArtifact)
                        .map_err(|_| PrivatePackageInstallError::Plan)?;
                let row = InstallRow {
                    source_kind: Some(InstallSourceKind::Direct),
                    stage_id: None,
                    direct_source: Some(DirectInstallSource {
                        material_b64: base64url(input.closure_json.as_bytes()),
                        source_checkpoint_json: source.checkpoint_canonical_json().to_owned(),
                        root_package_digest: input.expected_root_package_digest.clone(),
                    }),
                    instance_id: input.instance_id.clone(),
                    entrypoint: input.entrypoint.clone(),
                    grants_json: input.grants_json.clone(),
                    issued_at_ms: issued_at,
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().to_owned(),
                    policy_hash: prepared.policy_hash().to_owned(),
                    snapshot_json,
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    steps: Vec::new(),
                    accepted: None,
                };
                doc.rows.insert(command_id.clone(), row);
                doc.save(&store)?;
                test_crash_after_begin_row()?;
                let mut journal = SecureIntentJournal::open(
                    &self.config.state_dir.join("private-install-intents.state"),
                    source.origin(),
                    identity.actor_id(),
                )?;
                let path = format!(
                    "/api/workspace/v1/secure/workspaces/{}/commits",
                    self.config.workspace_id,
                );
                journal.prepare(SecurePacketInput {
                    intent_id: &command_id,
                    path: &path,
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                })?;
                if journal.exact_request(&command_id)? != prepared.request_wire()
                    || journal.intent_digest(&command_id)? != prepared.commit_hash()
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let mut transport_config = TransportConfig::new(self.config.origin.clone());
                transport_config.allow_loopback_http = self.config.allow_loopback_http;
                let transport = HttpTransport::new(transport_config)
                    .map_err(|_| PrivatePackageInstallError::Transport)?;
                if transport.trusted_origin() != source.origin() {
                    return Err(PrivatePackageInstallError::Transport);
                }
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| PrivatePackageInstallError::Runtime)?;
                match runtime.block_on(transport.post_exact(
                    &path,
                    prepared.request_wire().to_vec(),
                    cancel,
                )) {
                    Ok(response) => {
                        if !response.wire.is_empty() {
                            journal.observe_response(&command_id, &response.wire)?;
                        }
                        if !(200..300).contains(&response.status) {
                            return Err(PrivatePackageInstallError::ServerRejected(
                                response.status,
                            ));
                        }
                    }
                    Err(TransportError::SubmittedUncertain) => {}
                    Err(_) => return Err(PrivatePackageInstallError::Transport),
                }
                Ok(PrivatePackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: command_id.clone(),
                    step_command_id: command_id,
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    instance_id: prepared.instance_id().to_owned(),
                    commit_hash: prepared.commit_hash().to_owned(),
                })
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    pub fn continue_install_json(
        &self,
        begin_id: &str,
    ) -> Result<String, PrivatePackageInstallError> {
        self.continue_install_json_with_cancel(begin_id, &CancellationToken::new())
    }
    pub fn continue_install_json_with_cancel(
        &self,
        begin_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(begin_id) {
            return Err(PrivatePackageInstallError::Input);
        }
        let result = self.with_install_replay(cancel, |prior, fresh| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
            if identity.actor_id() != prior.replay().owner_actor_id()
                || identity.key_id() != prior.replay().owner_signing_key()
            {
                return Err(PrivatePackageInstallError::Identity);
            }
            let store = SecureStateStore::open(
                &self
                    .config
                    .state_dir
                    .join("private-install-operations.state"),
            )?;
            let mut doc = InstallDocument::open(
                &store,
                &self.config,
                identity.actor_id(),
                identity.key_id(),
            )?;
            let mut row = doc
                .rows
                .get(begin_id)
                .cloned()
                .ok_or(PrivatePackageInstallError::Input)?;
            if let Some(accepted) = &row.accepted {
                if !prior.replay().contains_checkpoint(
                    accepted.sequence,
                    Some(&accepted.head),
                    &accepted.policy_hash,
                ) && !fresh.replay().contains_checkpoint(
                    accepted.sequence,
                    Some(&accepted.head),
                    &accepted.policy_hash,
                ) {
                    return Err(PrivatePackageInstallError::Plan);
                }
                return Ok(PrivatePackageInstallProgress {
                    status: "ACCEPTED",
                    begin_command_id: begin_id.into(),
                    step_command_id: row
                        .steps
                        .last()
                        .map(|s| s.command_id.clone())
                        .unwrap_or_else(|| begin_id.into()),
                    step_action_id: "secure.structure.end",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: row.protocol_digest,
                    instance_id: row.instance_id,
                    commit_hash: row
                        .steps
                        .last()
                        .map(|s| s.commit_hash.clone())
                        .unwrap_or(row.commit_hash),
                });
            }
            let (material, source_checkpoint_json) = match row.source_kind()? {
                InstallSourceKind::Staged => {
                    let stage_store = SecureStateStore::open(
                        &self.config.state_dir.join("private-install.state"),
                    )?;
                    let stage_doc = StageDocument::open(
                        &stage_store,
                        &self.config,
                        identity.actor_id(),
                        identity.actor_id(),
                        identity.key_id(),
                    )?;
                    let stage = stage_doc
                        .rows
                        .get(
                            row.stage_id
                                .as_deref()
                                .ok_or(PrivatePackageInstallError::Identity)?,
                        )
                        .cloned()
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    let base =
                        parse_wire_json_bounded(stage.source_checkpoint_json.as_bytes(), 32, 8192)
                            .map_err(|_| PrivatePackageInstallError::Input)?;
                    let base_sequence = number(&base, "sequence")?;
                    let base_head = scalar(&base, "head")?;
                    if !stage.completed
                        || stage.steps.len() != stage.part_count
                        || prior.replay().sequence() != base_sequence + stage.part_count as u64
                        || prior.replay().policy_hash() != stage.policy_hash
                        || !prior.replay().contains_checkpoint(
                            base_sequence,
                            Some(&base_head),
                            &stage.policy_hash,
                        )
                    {
                        return Err(PrivatePackageInstallError::Plan);
                    }
                    for (offset, step) in stage.steps.iter().enumerate() {
                        if !prior.replay().contains_checkpoint(
                            base_sequence + offset as u64 + 1,
                            Some(&step.commit_hash),
                            &stage.policy_hash,
                        ) {
                            return Err(PrivatePackageInstallError::Plan);
                        }
                    }
                    (
                        decode_base64url(&stage.material_b64)
                            .map_err(|_| PrivatePackageInstallError::Identity)?,
                        stage.source_checkpoint_json,
                    )
                }
                InstallSourceKind::Direct => {
                    let source = row
                        .direct_source
                        .as_ref()
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    if source.source_checkpoint_json != prior.checkpoint_canonical_json()
                        || prior.replay().policy_hash()
                            != scalar(
                                &parse_wire_json_bounded(
                                    source.source_checkpoint_json.as_bytes(),
                                    32,
                                    8192,
                                )
                                .map_err(|_| PrivatePackageInstallError::Identity)?,
                                "policy_hash",
                            )?
                    {
                        return Err(PrivatePackageInstallError::Plan);
                    }
                    (
                        decode_base64url(&source.material_b64)
                            .map_err(|_| PrivatePackageInstallError::Identity)?,
                        source.source_checkpoint_json.clone(),
                    )
                }
            };
            let lifecycle = SecureLifecycle::open(
                &self.config.state_dir.join("lifecycle.state"),
                prior.origin(),
                identity.actor_id(),
                prior.replay().workspace_id(),
                prior.replay().owner_actor_id(),
                prior.replay().owner_signing_key(),
            )
            .map_err(|_| PrivatePackageInstallError::Identity)?;
            if lifecycle.active_keyring_without_pending().is_none() {
                return Err(PrivatePackageInstallError::Identity);
            }
            let prior_policy = prior
                .signed_policy_by_hash(prior.replay().policy_hash())
                .ok_or(PrivatePackageInstallError::Identity)?;
            let prior_policy_value = parse_wire_json_bounded(prior_policy, 64, 196_608)
                .map_err(|_| PrivatePackageInstallError::Input)?;
            let prior_epoch = number(
                prior_policy_value
                    .get("payload")
                    .ok_or(PrivatePackageInstallError::Input)?,
                "epoch",
            )?;
            let key = lifecycle
                .active_key(prior_epoch)
                .ok_or(PrivatePackageInstallError::Identity)?;
            let exact_begin = decode_base64url(&row.request_b64)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
            let checked = match row.source_kind()? {
                InstallSourceKind::Staged => verify_saved_private_package_install_begin(
                    &exact_begin,
                    &material,
                    source_checkpoint_json.as_bytes(),
                    prior.checkpoint_canonical_json().as_bytes(),
                    prior_policy,
                    prior.replay().objects(),
                    row.grants_json.as_bytes(),
                    &row.instance_id,
                    &row.entrypoint,
                    begin_id,
                    row.issued_at_ms,
                    identity.signing_key(),
                    key,
                )?,
                InstallSourceKind::Direct => {
                    let source = row
                        .direct_source
                        .as_ref()
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    verify_saved_private_direct_install_begin(
                        &exact_begin,
                        &material,
                        &source.root_package_digest,
                        &row.protocol_digest,
                        source_checkpoint_json.as_bytes(),
                        prior_policy,
                        prior.replay().objects(),
                        row.grants_json.as_bytes(),
                        &row.instance_id,
                        &row.entrypoint,
                        begin_id,
                        row.issued_at_ms,
                        identity.signing_key(),
                        key,
                    )?
                }
            };
            if checked.commit_hash() != row.commit_hash
                || checked.policy_hash() != row.policy_hash
                || checked.protocol_digest() != row.protocol_digest
                || canonical_wire_value(checked.snapshot(), CanonicalPath::SecureArtifact)
                    .map_err(|_| PrivatePackageInstallError::Plan)?
                    != row.snapshot_json
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("private-install-intents.state"),
                prior.origin(),
                identity.actor_id(),
            )?;
            // The operation row is saved first so a crash before journal
            // preparation cannot lose a generated BEGIN ID. Reconstruct only
            // this already re-proved exact packet. prepare is idempotent for
            // an exact existing entry and refuses any mismatched metadata.
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            journal.prepare(SecurePacketInput {
                intent_id: begin_id,
                path: &path,
                action_id: "secure.structure.begin",
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &row.commit_hash,
                exact_request: &exact_begin,
            })?;
            if journal.exact_request(begin_id)? != exact_begin
                || journal.intent_digest(begin_id)? != row.commit_hash
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            if fresh.replay().sequence() == prior.replay().sequence()
                && fresh.replay().head() == prior.replay().head()
                && fresh.replay().policy_hash() == prior.replay().policy_hash()
            {
                post_saved_private(
                    &self.config,
                    prior.origin(),
                    &mut journal,
                    begin_id,
                    exact_begin,
                    cancel,
                )?;
                return Ok(PrivatePackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: begin_id.into(),
                    step_command_id: begin_id.into(),
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: row.protocol_digest,
                    instance_id: row.instance_id,
                    commit_hash: row.commit_hash,
                });
            }
            if !fresh.replay().contains_checkpoint(
                prior.replay().sequence() + 1,
                Some(&row.commit_hash),
                &row.policy_hash,
            ) || fresh.replay().policy_hash() != row.policy_hash
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            for (index, step) in row.steps.iter().enumerate() {
                let sequence = prior.replay().sequence() + 2 + index as u64;
                if fresh.replay().sequence() >= sequence
                    && !fresh.replay().contains_checkpoint(
                        sequence,
                        Some(&step.commit_hash),
                        &row.policy_hash,
                    )
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
            }
            if fresh.replay().structure_status() == StructureStatus::Active {
                let end = row.steps.last().ok_or(PrivatePackageInstallError::Plan)?;
                if end.action_id != "secure.structure.end"
                    || !fresh.replay().contains_checkpoint(
                        prior.replay().sequence() + 1 + row.steps.len() as u64,
                        Some(&end.commit_hash),
                        &row.policy_hash,
                    )
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                fresh
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let found = fresh.replay().objects().iter().any(|object| {
                    object.get("kind").and_then(WireValue::as_string).as_deref()
                        == Some("instances")
                        && object.get("id").and_then(WireValue::as_string).as_deref()
                            == Some(&row.instance_id)
                        && object
                            .get("value")
                            .and_then(|value| value.get("protocol_digest"))
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some(&row.protocol_digest)
                });
                if !found {
                    return Err(PrivatePackageInstallError::Plan);
                }
                row.accepted = Some(AcceptedInstall {
                    sequence: fresh.replay().sequence(),
                    head: fresh
                        .replay()
                        .head()
                        .ok_or(PrivatePackageInstallError::Plan)?
                        .into(),
                    policy_hash: fresh.replay().policy_hash().into(),
                });
                doc.rows.insert(begin_id.into(), row.clone());
                doc.save(&store)?;
                return Ok(PrivatePackageInstallProgress {
                    status: "ACCEPTED",
                    begin_command_id: begin_id.into(),
                    step_command_id: end.command_id.clone(),
                    step_action_id: "secure.structure.end",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: row.protocol_digest,
                    instance_id: row.instance_id,
                    commit_hash: end.commit_hash.clone(),
                });
            }
            if fresh.replay().structure_status() != StructureStatus::Seeding {
                return Err(PrivatePackageInstallError::Plan);
            }
            let signed_snapshot = fresh
                .replay()
                .structure_snapshot()
                .ok_or(PrivatePackageInstallError::Plan)?;
            let beginning = parse_wire_json_bounded(row.snapshot_json.as_bytes(), 32, 8192)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            if !same_snapshot(signed_snapshot, &beginning) {
                return Err(PrivatePackageInstallError::Plan);
            }
            let signed_policy = fresh
                .signed_policy_by_hash(&row.policy_hash)
                .ok_or(PrivatePackageInstallError::Plan)?;
            let policy = parse_wire_json_bounded(signed_policy, 64, 196_608)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            let structure = policy
                .get("payload")
                .and_then(|p| p.get("structure"))
                .ok_or(PrivatePackageInstallError::Plan)?;
            let plan = plan_public_install_snapshot(
                prior.replay().objects(),
                structure,
                &parse_wire_json_bounded(prior.checkpoint_canonical_json().as_bytes(), 32, 8192)
                    .map_err(|_| PrivatePackageInstallError::Plan)?,
            )
            .map_err(|_| PrivatePackageInstallError::Plan)?;
            if !same_snapshot(plan.snapshot(), &beginning) {
                return Err(PrivatePackageInstallError::Plan);
            }
            let offset = usize::try_from(number(signed_snapshot, "offset")?)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            let total = plan
                .records()
                .len()
                .checked_add(plan.heads().len())
                .ok_or(PrivatePackageInstallError::Plan)?;
            if offset > total {
                return Err(PrivatePackageInstallError::Plan);
            }
            let done = offset == total;
            let step_id = install_step_id(begin_id, offset, done);
            let existing = row
                .steps
                .iter()
                .find(|step| step.command_id == step_id)
                .cloned();
            let issued_at = existing
                .as_ref()
                .map(|step| step.issued_at_ms)
                .unwrap_or(now_ms()?);
            let signed = if let Some(step) = &existing {
                if step.offset != offset
                    || step.action_id
                        != if done {
                            "secure.structure.end"
                        } else {
                            "secure.structure.page"
                        }
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let saved = decode_base64url(&step.request_b64)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let verified = verify_saved_private_package_install_step(
                    &saved,
                    signed_policy,
                    fresh.checkpoint_canonical_json().as_bytes(),
                    signed_snapshot,
                    &plan,
                    &step_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                if verified.commit_hash() != step.commit_hash {
                    return Err(PrivatePackageInstallError::Plan);
                }
                verified
            } else {
                if fresh.replay().sequence()
                    != prior.replay().sequence() + 1 + row.steps.len() as u64
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let authored = prepare_private_package_install_step(
                    signed_policy,
                    fresh.checkpoint_canonical_json().as_bytes(),
                    signed_snapshot,
                    &plan,
                    &step_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                row.steps.push(InstallStep {
                    command_id: step_id.clone(),
                    issued_at_ms: issued_at,
                    request_b64: base64url(authored.request_wire()),
                    commit_hash: authored.commit_hash().into(),
                    action_id: authored.action_id().into(),
                    offset,
                });
                doc.rows.insert(begin_id.into(), row.clone());
                doc.save(&store)?;
                authored
            };
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            journal.prepare(SecurePacketInput {
                intent_id: &step_id,
                path: &path,
                action_id: signed.action_id(),
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: signed.commit_hash(),
                exact_request: signed.request_wire(),
            })?;
            if journal.exact_request(&step_id)? != signed.request_wire()
                || journal.intent_digest(&step_id)? != signed.commit_hash()
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            post_saved_private(
                &self.config,
                fresh.origin(),
                &mut journal,
                &step_id,
                signed.request_wire().to_vec(),
                cancel,
            )?;
            Ok(PrivatePackageInstallProgress {
                status: "PENDING",
                begin_command_id: begin_id.into(),
                step_command_id: step_id,
                step_action_id: signed.action_id(),
                workspace_id: self.config.workspace_id.clone(),
                protocol_digest: row.protocol_digest,
                instance_id: row.instance_id,
                commit_hash: signed.commit_hash().into(),
            })
        })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Local protected discovery, including completed stage IDs. This does
    /// not fetch the journal or claim that any saved packet was accepted.
    pub fn stages_json(&self) -> Result<String, PrivatePackageInstallError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || identity.actor_id() != scope.owner_actor_id
            || identity.key_id() != scope.owner_key_id
        {
            return Err(PrivatePackageInstallError::Identity);
        };
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store,
            &self.config,
            identity.actor_id(),
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )?;
        let rows:Vec<_>=doc.rows.iter().map(|(id,row)|serde_json::json!({"stage_id":id,"workspace_id":doc.workspace_id,
            "source_id":row.source_id,"root_package_digest":row.root_package_digest,"protocol_digest":row.protocol_digest,
            "part_count":row.part_count,"saved_steps":row.steps.len(),"locally_verified_complete":row.completed})).collect();
        serde_json::to_string(&rows).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    pub fn stage_package_json(
        &self,
        input: PrivatePackageStageInput,
    ) -> Result<String, PrivatePackageInstallError> {
        self.stage_package_json_with_cancel(input, &CancellationToken::new())
    }
    pub fn stage_package_json_with_cancel(
        &self,
        input: PrivatePackageStageInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !digest(&input.expected_root_package_digest)
            || !digest(&input.expected_protocol_digest)
            || input.material_json.is_empty()
            || input.material_json.len() > 8 * 1024 * 1024
            || input.stage_id.as_deref().is_some_and(|id| !token(id))
            || input.command_id.as_deref().is_some_and(|id| !token(id))
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let stage_id = input.stage_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let command_id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued_at = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        let result =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                self.stage_from_replay(source, &input, &stage_id, &command_id, issued_at, cancel)
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Resume a locally discoverable stage without caller-held material or
    /// internal paths. The saved packet remains the only candidate for retry.
    pub fn continue_stage_json(
        &self,
        stage_id: &str,
    ) -> Result<String, PrivatePackageInstallError> {
        self.continue_stage_json_with_cancel(stage_id, &CancellationToken::new())
    }
    pub fn continue_stage_json_with_cancel(
        &self,
        stage_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(stage_id) {
            return Err(PrivatePackageInstallError::Input);
        };
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || scope.owner_actor_id != identity.actor_id()
            || scope.owner_key_id != identity.key_id()
        {
            return Err(PrivatePackageInstallError::Identity);
        };
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store,
            &self.config,
            identity.actor_id(),
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )?;
        let row = doc
            .rows
            .get(stage_id)
            .ok_or(PrivatePackageInstallError::Input)?;
        let material = decode_base64url(&row.material_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let input = PrivatePackageStageInput {
            material_json: String::from_utf8(material)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            expected_root_package_digest: row.root_package_digest.clone(),
            expected_protocol_digest: row.protocol_digest.clone(),
            stage_id: Some(stage_id.to_owned()),
            command_id: None,
            issued_at_ms: None,
        };
        drop(doc);
        drop(store);
        let result = SecureReadProfile::new(self.config.clone())
            .with_latest_replay(cancel, |source| {
                self.stage_from_replay(source, &input, stage_id, stage_id, 0, cancel)
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    fn stage_from_replay(
        &self,
        source: &TransportReplayedJournal,
        input: &PrivatePackageStageInput,
        stage_id: &str,
        command_id: &str,
        issued_at: u64,
        cancel: &CancellationToken,
    ) -> Result<PrivatePackageStageResult, PrivatePackageInstallError> {
        source
            .verified_read()
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if source.origin() != self.config.origin
            || source.source_actor_id() != identity.actor_id()
            || source.source_key_id() != identity.key_id()
            || source.replay().workspace_id() != self.config.workspace_id
            || source.replay().owner_actor_id() != identity.actor_id()
            || source.replay().owner_signing_key() != identity.key_id()
            || source.replay().structure_status() != StructureStatus::Active
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        let lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            source.origin(),
            identity.actor_id(),
            source.replay().workspace_id(),
            source.replay().owner_actor_id(),
            source.replay().owner_signing_key(),
        )
        .map_err(|_| PrivatePackageInstallError::Identity)?;
        if lifecycle.active_keyring_without_pending().is_none() {
            return Err(PrivatePackageInstallError::Identity);
        }
        let policy_wire = source
            .signed_policy_by_hash(source.replay().policy_hash())
            .ok_or(PrivatePackageInstallError::Identity)?;
        let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
            .map_err(|_| PrivatePackageInstallError::Input)?;
        let payload = policy
            .get("payload")
            .ok_or(PrivatePackageInstallError::Input)?;
        if scalar(payload, "visibility")? != "PRIVATE" || !matches!(number(payload, "v")?, 2 | 3) {
            return Err(PrivatePackageInstallError::Input);
        };
        let epoch = number(payload, "epoch")?;
        let key = lifecycle
            .active_key(epoch)
            .ok_or(PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let mut doc = StageDocument::open(
            &store,
            &self.config,
            identity.actor_id(),
            source.replay().owner_actor_id(),
            source.replay().owner_signing_key(),
        )?;
        let mut journal = SecureIntentJournal::open(
            &self.config.state_dir.join("private-install-intents.state"),
            source.origin(),
            identity.actor_id(),
        )?;
        if !doc.rows.contains_key(stage_id) {
            if doc.rows.len() == 16 || doc.rows.values().any(|row| !row.completed) {
                return Err(PrivatePackageInstallError::State(
                    SecureStateError::TooLarge,
                ));
            };
            let prepared = prepare_private_package_stage(
                input.material_json.as_bytes(),
                source.checkpoint_canonical_json().as_bytes(),
                source.checkpoint_canonical_json().as_bytes(),
                policy_wire,
                0,
                command_id,
                issued_at,
                identity.signing_key(),
                key,
            )?;
            if prepared.root_package_digest() != input.expected_root_package_digest
                || prepared.protocol_digest() != input.expected_protocol_digest
            {
                return Err(PrivatePackageInstallError::Input);
            };
            let row = StageRow {
                material_b64: base64url(input.material_json.as_bytes()),
                source_checkpoint_json: source.checkpoint_canonical_json().to_owned(),
                policy_hash: source.replay().policy_hash().to_owned(),
                source_id: prepared.source_id().to_owned(),
                root_package_digest: prepared.root_package_digest().to_owned(),
                protocol_digest: prepared.protocol_digest().to_owned(),
                part_count: prepared.part_count(),
                steps: vec![StageStep {
                    command_id: command_id.to_owned(),
                    issued_at_ms: issued_at,
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().to_owned(),
                }],
                completed: false,
            };
            doc.rows.insert(stage_id.to_owned(), row);
            doc.save(&store)?;
        }
        let mut row = doc
            .rows
            .get(stage_id)
            .cloned()
            .ok_or(PrivatePackageInstallError::Identity)?;
        if sha256_hex(
            &decode_base64url(&row.material_b64)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
        ) != sha256_hex(input.material_json.as_bytes())
            || row.root_package_digest != input.expected_root_package_digest
            || row.protocol_digest != input.expected_protocol_digest
        {
            return Err(PrivatePackageInstallError::Input);
        };
        let source_checkpoint =
            parse_wire_json_bounded(row.source_checkpoint_json.as_bytes(), 32, 8192)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
        let base = number(&source_checkpoint, "sequence")?;
        let base_head = scalar(&source_checkpoint, "head")?;
        if !source
            .replay()
            .contains_checkpoint(base, Some(&base_head), &row.policy_hash)
        {
            return Err(PrivatePackageInstallError::Plan);
        };
        let mut applied = 0usize;
        for (index, step) in row.steps.iter().enumerate() {
            let sequence = base + index as u64 + 1;
            if source.replay().contains_checkpoint(
                sequence,
                Some(&step.commit_hash),
                &row.policy_hash,
            ) {
                applied += 1;
            } else if source.replay().sequence() >= sequence {
                return Err(PrivatePackageInstallError::Plan);
            } else {
                break;
            }
        }
        if applied == row.part_count {
            if !row.completed {
                row.completed = true;
                doc.rows.insert(stage_id.to_owned(), row.clone());
                doc.save(&store)?;
            }
            return Ok(PrivatePackageStageResult {
                status: "STAGED",
                stage_id: stage_id.to_owned(),
                workspace_id: self.config.workspace_id.clone(),
                source_id: row.source_id.clone(),
                root_package_digest: row.root_package_digest.clone(),
                protocol_digest: row.protocol_digest.clone(),
                part_count: row.part_count,
                applied_parts: applied,
                pending_command_id: None,
            });
        }
        if source.replay().sequence() != base + applied as u64
            || source.replay().policy_hash() != row.policy_hash
            || applied < row.steps.len().saturating_sub(1)
        {
            return Err(PrivatePackageInstallError::Plan);
        };
        let previous = if applied == 0 {
            base_head
        } else {
            row.steps[applied - 1].commit_hash.clone()
        };
        let current_checkpoint =
            checkpoint_json(source, base + applied as u64, &previous, &row.policy_hash)?;
        if row.steps.len() == applied {
            let next_id = random_id()?;
            let next_at = now_ms()?;
            let material = decode_base64url(&row.material_b64)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
            let prepared = prepare_private_package_stage(
                &material,
                row.source_checkpoint_json.as_bytes(),
                current_checkpoint.as_bytes(),
                policy_wire,
                applied,
                &next_id,
                next_at,
                identity.signing_key(),
                key,
            )?;
            if prepared.source_id() != row.source_id
                || prepared.protocol_digest() != row.protocol_digest
                || prepared.part_count() != row.part_count
            {
                return Err(PrivatePackageInstallError::Plan);
            };
            row.steps.push(StageStep {
                command_id: next_id,
                issued_at_ms: next_at,
                request_b64: base64url(prepared.request_wire()),
                commit_hash: prepared.commit_hash().to_owned(),
            });
            doc.rows.insert(stage_id.to_owned(), row.clone());
            doc.save(&store)?;
        }
        let step = &row.steps[applied];
        let material = decode_base64url(&row.material_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let exact = decode_base64url(&step.request_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let checked = verify_saved_private_package_stage(
            &exact,
            &material,
            row.source_checkpoint_json.as_bytes(),
            current_checkpoint.as_bytes(),
            policy_wire,
            applied,
            &step.command_id,
            step.issued_at_ms,
            identity.signing_key(),
            key,
        )?;
        if checked.commit_hash() != step.commit_hash || checked.source_id() != row.source_id {
            return Err(PrivatePackageInstallError::Plan);
        };
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            self.config.workspace_id
        );
        journal.prepare(SecurePacketInput {
            intent_id: &step.command_id,
            path: &path,
            action_id: "secure.protocol-package.stage",
            workspace_id: Some(&self.config.workspace_id),
            trusted_owner_key: Some(identity.key_id()),
            intent_digest: &step.commit_hash,
            exact_request: &exact,
        })?;
        if journal.exact_request(&step.command_id)? != exact
            || journal.intent_digest(&step.command_id)? != step.commit_hash
        {
            return Err(PrivatePackageInstallError::Plan);
        };
        let mut transport_config = TransportConfig::new(self.config.origin.clone());
        transport_config.allow_loopback_http = self.config.allow_loopback_http;
        let transport = HttpTransport::new(transport_config)
            .map_err(|_| PrivatePackageInstallError::Transport)?;
        if transport.trusted_origin() != source.origin() {
            return Err(PrivatePackageInstallError::Transport);
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PrivatePackageInstallError::Runtime)?;
        match runtime.block_on(transport.post_exact(&path, exact, cancel)) {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(&step.command_id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(PrivatePackageInstallError::ServerRejected(response.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PrivatePackageInstallError::Transport),
        }
        Ok(PrivatePackageStageResult {
            status: "PENDING",
            stage_id: stage_id.to_owned(),
            workspace_id: self.config.workspace_id.clone(),
            source_id: row.source_id.clone(),
            root_package_digest: row.root_package_digest.clone(),
            protocol_digest: row.protocol_digest.clone(),
            part_count: row.part_count,
            applied_parts: applied,
            pending_command_id: Some(step.command_id.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_action_access::PublicActionInput;
    use crate::secure_owner_create::{
        SecureOwnerCreateConfig, SecureOwnerCreateInput, SecureOwnerWorkspaceCreate,
    };
    use std::{
        fs,
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_private_package_stage_install_action_recovers_lost_replies() {
        run_actual_service_private_package_install(false);
    }

    #[test]
    fn actual_service_private_package_install_preserves_nonempty_pages_after_lost_reply() {
        run_actual_service_private_package_install(true);
    }

    fn run_actual_service_private_package_install(nonempty: bool) {
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
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let token = CancellationToken::new();
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let created = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native PRIVATE package stage".into(),
                    name_utf16: None,
                    visibility: "PRIVATE".into(),
                    structured: true,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        let result = owner.resume(&created.command_id, &token).unwrap();
        assert_eq!(result.status, "CREATED");
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let material = serde_json::json!({"v":1,"closure":vector["closure"],"bindings":{}});
        let stage = owner.private_install_access(&created.workspace_id).unwrap();
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
        let prior_record = if nonempty {
            let read: serde_json::Value = serde_json::from_str(
                &owner
                    .read_workspace_json(&created.workspace_id, &token)
                    .unwrap(),
            )
            .unwrap();
            let objects = read["objects"].as_array().unwrap();
            let wiki_digest = objects
                .iter()
                .find(|object| {
                    object["kind"] == "protocols"
                        && object["value"]["manifest"]["name"] == "peerwork.wiki.v1"
                })
                .unwrap()["id"]
                .as_str()
                .unwrap();
            let wiki_instance = objects
                .iter()
                .find(|object| {
                    object["kind"] == "instances"
                        && object["value"]["protocol_digest"] == wiki_digest
                })
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let action = owner.private_action_access(&created.workspace_id).unwrap();
            let mut first_record = None;
            for index in 0..51 {
                let title = format!("Prior encrypted wiki {index}");
                let body = format!("Encrypted source history {index}");
                let submitted: serde_json::Value = serde_json::from_str(
                    &action
                        .submit_new_json(PublicActionInput {
                            action_id: "wiki.create".into(),
                            instance_id: wiki_instance.clone(),
                            body_json: serde_json::json!({"title":title,"body":body}).to_string(),
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
                    serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap())
                        .unwrap();
                if index == 0 {
                    first_record = Some((
                        receipt["effects"][0]["record_id"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                        title,
                        body,
                    ));
                }
            }
            let read: serde_json::Value = serde_json::from_str(
                &owner
                    .read_workspace_json(&created.workspace_id, &token)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                read["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|object| object["kind"] == "records")
                    .count(),
                51
            );
            first_record
        } else {
            None
        };
        let before = counts()["commits"].as_u64().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let first: serde_json::Value = serde_json::from_str(
            &stage
                .stage_package_json(PrivatePackageStageInput {
                    material_json: material.to_string(),
                    expected_root_package_digest: vector["closure"]["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                    stage_id: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["status"], "PENDING");
        assert!(first["pending_command_id"].as_str().is_some());
        assert_eq!(counts()["commits"], before + 1);
        let stage_id = first["stage_id"].as_str().unwrap();
        drop(stage);
        drop(owner);
        let reopened = SecureOwnerWorkspaceCreate::new(config);
        let stage = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        let rows: serde_json::Value = serde_json::from_str(&stage.stages_json().unwrap()).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["stage_id"], stage_id);
        let mut next: serde_json::Value =
            serde_json::from_str(&stage.continue_stage_json(stage_id).unwrap()).unwrap();
        for _ in 0..first["part_count"].as_u64().unwrap() + 1 {
            if next["status"] == "STAGED" {
                break;
            }
            next = serde_json::from_str(&stage.continue_stage_json(stage_id).unwrap()).unwrap();
        }
        assert_eq!(next["status"], "STAGED");
        assert_eq!(next["applied_parts"], next["part_count"]);
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        let again: serde_json::Value =
            serde_json::from_str(&stage.continue_stage_json(stage_id).unwrap()).unwrap();
        assert_eq!(again["status"], "STAGED");
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        // Lose the process after the saved row and before journal.prepare.
        let owner_actor = KernelIdentity::open(&stage.config.identity_path)
            .unwrap()
            .actor_id()
            .to_owned();
        let grants_json=serde_json::json!([{"actor_id":owner_actor,"actions":["proposal.propose"],"protocol_roles":["AUTHOR"],"capabilities":["PROPOSE"]}]).to_string();
        TEST_CRASH_AFTER_BEGIN_ROW.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            stage.submit_begin_json(PrivatePackageInstallBeginInput {
                stage_id: stage_id.to_owned(),
                instance_id: random_id().unwrap(),
                entrypoint: "proposal".into(),
                grants_json,
                command_id: None,
                issued_at_ms: None,
            }),
            Err(PrivatePackageInstallError::Runtime)
        ));
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        drop(stage);
        drop(reopened);
        let reopened = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            origin: origin.clone(),
            state_dir: root.path().join("sdk-state"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        });
        let stage = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        let installs: serde_json::Value =
            serde_json::from_str(&stage.installs_json().unwrap()).unwrap();
        assert_eq!(installs.as_array().unwrap().len(), 1);
        assert_eq!(installs[0]["stage_id"], stage_id);
        let begin_id = installs[0]["begin_command_id"].as_str().unwrap();
        assert_eq!(installs[0]["source_kind"], "STAGED");
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
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
        let first: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        assert_eq!(first["step_action_id"], "secure.structure.begin");
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap() + 1
        );
        let mut progress: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(progress["status"], "PENDING");
        assert_eq!(
            progress["step_action_id"],
            if nonempty {
                "secure.structure.page"
            } else {
                "secure.structure.end"
            }
        );
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap() + 2
        );
        // Reopen again after the first PAGE was applied but its POST reply was
        // lost. The protected BEGIN ID and exact saved PAGE must suffice.
        let (reopened, stage) = if nonempty {
            drop(stage);
            drop(reopened);
            let reopened = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
                origin: origin.clone(),
                state_dir: root.path().join("sdk-state"),
                allow_loopback_http: true,
                max_replay_artifact_bytes: 64 * 1024 * 1024,
            });
            let stage = reopened
                .private_install_access(&created.workspace_id)
                .unwrap();
            let saved: serde_json::Value =
                serde_json::from_str(&stage.installs_json().unwrap()).unwrap();
            assert_eq!(saved[0]["begin_command_id"], begin_id);
            (reopened, stage)
        } else {
            (reopened, stage)
        };
        let mut page_ids = std::collections::BTreeSet::new();
        if nonempty {
            page_ids.insert(progress["step_command_id"].as_str().unwrap().to_owned());
        }
        for _ in 0..8 {
            if progress["status"] == "ACCEPTED" {
                break;
            }
            progress =
                serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
            if progress["step_action_id"] == "secure.structure.page" {
                page_ids.insert(progress["step_command_id"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(progress["status"], "ACCEPTED");
        if nonempty {
            assert_eq!(page_ids.len(), 4, "51 records and 51 heads need four PAGEs");
            assert_eq!(
                counts()["commits"],
                before + next["part_count"].as_u64().unwrap() + 6,
                "one BEGIN, four PAGEs, one END; retries add no commits"
            );
        }
        let read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "instances"
                && object["id"] == first["instance_id"]
                && object["value"]["protocol_digest"] == first["protocol_digest"]));
        if let Some((record_id, title, body)) = &prior_record {
            assert!(read["objects"].as_array().unwrap().iter().any(|object| {
                object["kind"] == "records"
                    && object["id"] == *record_id
                    && object["value"]["payload"]["title"] == *title
                    && object["value"]["payload"]["body"] == *body
            }));
        }
        let repeat: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(repeat["status"], "ACCEPTED");
        let action = PublicActionInput {
            action_id: "proposal.propose".into(),
            instance_id: first["instance_id"].as_str().unwrap().into(),
            body_json: r#"{"title":"PRIVATE installed wiki","body":"Encrypted after install"}"#
                .into(),
            exact_input_refs_json: None,
            allocations_json: None,
            command_id: None,
            issued_at_ms: None,
        };
        let submitted: serde_json::Value = serde_json::from_str(
            &reopened
                .private_action_access(&created.workspace_id)
                .unwrap()
                .submit_new_json(action)
                .unwrap(),
        )
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &reopened
                .private_action_access(&created.workspace_id)
                .unwrap()
                .retry_saved_json(submitted["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records"
                && object["id"] == effect_id
                && object["value"]["payload"]["title"] == "PRIVATE installed wiki"
                && object["value"]["payload"]["body"] == "Encrypted after install"));

        // The prior protocol keeps its first package-source provenance. A
        // second instance needs a freshly staged proof at the current policy.
        let identity = KernelIdentity::open(&stage.config.identity_path).unwrap();
        let stage_store =
            SecureStateStore::open(&stage.config.state_dir.join("private-install.state")).unwrap();
        let first_stage_doc = StageDocument::open(
            &stage_store,
            &stage.config,
            identity.actor_id(),
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let first_stage_row = first_stage_doc.rows.get(stage_id).unwrap().clone();
        drop(stage_store);
        let current_stage_scope = SecureReadProfile::new(stage.config.clone())
            .with_latest_replay(&token, |source| {
                Ok::<_, PrivatePackageInstallError>((
                    source.replay().policy_hash().to_owned(),
                    source.checkpoint_canonical_json().to_owned(),
                ))
            })
            .unwrap();
        let second_stage: serde_json::Value = serde_json::from_str(
            &stage
                .stage_package_json(PrivatePackageStageInput {
                    material_json: material.to_string(),
                    expected_root_package_digest: vector["closure"]["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                    stage_id: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let second_stage_id = second_stage["stage_id"].as_str().unwrap().to_owned();
        assert_ne!(second_stage_id, stage_id);
        let mut second_stage_progress = second_stage;
        for _ in 0..8 {
            if second_stage_progress["status"] == "STAGED" {
                break;
            }
            second_stage_progress =
                serde_json::from_str(&stage.continue_stage_json(&second_stage_id).unwrap())
                    .unwrap();
        }
        assert_eq!(second_stage_progress["status"], "STAGED");
        let stage_store =
            SecureStateStore::open(&stage.config.state_dir.join("private-install.state")).unwrap();
        let second_stage_doc = StageDocument::open(
            &stage_store,
            &stage.config,
            identity.actor_id(),
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let second_stage_row = second_stage_doc.rows.get(&second_stage_id).unwrap();
        assert_ne!(second_stage_row.policy_hash, first_stage_row.policy_hash);
        assert_ne!(
            second_stage_row.source_checkpoint_json,
            first_stage_row.source_checkpoint_json
        );
        assert_eq!(second_stage_row.policy_hash, current_stage_scope.0);
        assert_eq!(
            second_stage_row.source_checkpoint_json,
            current_stage_scope.1
        );
        drop(stage_store);
        let second_instance_id = random_id().unwrap();
        let second_begin: serde_json::Value = serde_json::from_str(
            &stage
                .submit_begin_json(PrivatePackageInstallBeginInput {
                    stage_id: second_stage_id.clone(),
                    instance_id: second_instance_id.clone(),
                    entrypoint: "proposal".into(),
                    grants_json: serde_json::json!([{
                        "actor_id": owner_actor,
                        "actions": ["proposal.propose"],
                        "protocol_roles": ["AUTHOR"],
                        "capabilities": ["PROPOSE"]
                    }])
                    .to_string(),
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let second_begin_id = second_begin["begin_command_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut second_progress = second_begin;
        for _ in 0..12 {
            if second_progress["status"] == "ACCEPTED" {
                break;
            }
            second_progress =
                serde_json::from_str(&stage.continue_install_json(&second_begin_id).unwrap())
                    .unwrap();
        }
        assert_eq!(second_progress["status"], "ACCEPTED");
        let before_repeat = counts()["commits"].as_u64().unwrap();
        let repeat: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(&second_begin_id).unwrap()).unwrap();
        assert_eq!(repeat["status"], "ACCEPTED");
        assert_eq!(counts()["commits"], before_repeat);
        let both: serde_json::Value =
            serde_json::from_str(&stage.installs_json().unwrap()).unwrap();
        assert_eq!(both.as_array().unwrap().len(), 2);
        let final_read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            final_read["objects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|object| {
                    object["kind"] == "protocols" && object["id"] == vector["protocol_digest"]
                })
                .count(),
            1
        );
        let instance_ids: std::collections::BTreeSet<_> = final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|object| {
                object["kind"] == "instances"
                    && object["value"]["protocol_digest"] == vector["protocol_digest"]
            })
            .map(|object| object["id"].as_str().unwrap())
            .collect();
        assert_eq!(instance_ids.len(), 2);
        assert!(instance_ids.contains(first["instance_id"].as_str().unwrap()));
        assert!(instance_ids.contains(second_instance_id.as_str()));
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "instances"
                    && object["id"] == second_instance_id
                    && object["value"]["protocol_digest"] == vector["protocol_digest"]
                    && object["value"]["package_source"].is_object()
            }));
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "records"
                    && object["id"] == effect_id
                    && object["value"]["payload"]["title"] == "PRIVATE installed wiki"
                    && object["value"]["payload"]["body"] == "Encrypted after install"
            }));
    }

    #[test]
    fn actual_service_private_direct_install_from_unstructured_owner_recovers_page() {
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
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let token = CancellationToken::new();
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let created = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native PRIVATE direct install".into(),
                    name_utf16: None,
                    visibility: "PRIVATE".into(),
                    structured: false,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        assert_eq!(
            owner.resume(&created.command_id, &token).unwrap().status,
            "CREATED"
        );
        let initial: serde_json::Value = serde_json::from_str(
            &owner
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        let objects = initial["objects"].as_array().unwrap();
        let wiki_digest = objects
            .iter()
            .find(|object| {
                object["kind"] == "protocols"
                    && object["value"]["manifest"]["name"] == "peerwork.wiki.v1"
            })
            .unwrap()["id"]
            .as_str()
            .unwrap();
        let wiki_instance = objects
            .iter()
            .find(|object| {
                object["kind"] == "instances" && object["value"]["protocol_digest"] == wiki_digest
            })
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let action = owner.private_action_access(&created.workspace_id).unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "wiki.create".into(),
                    instance_id: wiki_instance,
                    body_json: r#"{"title":"Before direct install","body":"Encrypted old body"}"#
                        .into(),
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
        let prior_id = receipt["effects"][0]["record_id"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(action);
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let material = vector["closure"].clone();
        let install = owner.private_install_access(&created.workspace_id).unwrap();
        let prior_policy = SecureReadProfile::new(install.config.clone())
            .with_latest_replay(&token, |source| {
                let wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Plan)?;
                let signed = parse_wire_json_bounded(wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let payload = signed
                    .get("payload")
                    .ok_or(PrivatePackageInstallError::Plan)?;
                Ok::<_, PrivatePackageInstallError>((
                    number(payload, "v")?,
                    scalar(payload, "structure_mode")?,
                    number(payload, "version")?,
                ))
            })
            .unwrap();
        assert_eq!(prior_policy.0, 3);
        assert_eq!(prior_policy.1, "NONE");
        let owner_actor = KernelIdentity::open(&install.config.identity_path)
            .unwrap()
            .actor_id()
            .to_owned();
        let grants_json = serde_json::json!([{
            "actor_id": owner_actor,
            "actions": ["proposal.propose"],
            "protocol_roles": ["AUTHOR"],
            "capabilities": ["PROPOSE"]
        }])
        .to_string();
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
        let before = counts()["commits"].as_u64().unwrap();
        TEST_CRASH_AFTER_BEGIN_ROW.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            install.submit_direct_begin_json(PrivateDirectInstallBeginInput {
                closure_json: material.to_string(),
                expected_root_package_digest: vector["closure"]["root_package_digest"]
                    .as_str()
                    .unwrap()
                    .into(),
                expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                instance_id: random_id().unwrap(),
                entrypoint: "proposal".into(),
                grants_json,
                command_id: None,
                issued_at_ms: None,
            }),
            Err(PrivatePackageInstallError::Runtime)
        ));
        assert_eq!(counts()["commits"], before);
        drop(install);
        drop(owner);
        let reopened = SecureOwnerWorkspaceCreate::new(config);
        let install = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        let rows: serde_json::Value =
            serde_json::from_str(&install.installs_json().unwrap()).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["source_kind"], "DIRECT");
        assert!(rows[0].get("stage_id").is_none());
        let begin_id = rows[0]["begin_command_id"].as_str().unwrap();
        let identity = KernelIdentity::open(&install.config.identity_path).unwrap();
        let operation_store = SecureStateStore::open(
            &install
                .config
                .state_dir
                .join("private-install-operations.state"),
        )
        .unwrap();
        let saved = InstallDocument::open(
            &operation_store,
            &install.config,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let saved_row = saved.rows.get(begin_id).unwrap();
        let exact_begin = decode_base64url(&saved_row.request_b64).unwrap();
        let commit_hash = saved_row.commit_hash.clone();
        drop(operation_store);
        let journal_path = install
            .config
            .state_dir
            .join("private-install-intents.state");
        let mut conflicting =
            SecureIntentJournal::open(&journal_path, &origin, identity.actor_id()).unwrap();
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            created.workspace_id
        );
        conflicting
            .prepare(SecurePacketInput {
                intent_id: begin_id,
                path: &path,
                action_id: "wiki.create",
                workspace_id: Some(&created.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &commit_hash,
                exact_request: &exact_begin,
            })
            .unwrap();
        drop(conflicting);
        assert!(matches!(
            install.continue_install_json(begin_id),
            Err(PrivatePackageInstallError::Intent(
                SecureIntentError::Conflict
            ))
        ));
        assert_eq!(counts()["commits"], before);
        std::fs::remove_file(&journal_path).unwrap();
        std::fs::write(&journal_path, b"{").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        assert!(matches!(
            install.continue_install_json(begin_id),
            Err(PrivatePackageInstallError::Intent(
                SecureIntentError::Store(SecureStateError::MigrationRequired)
            ))
        ));
        assert_eq!(counts()["commits"], before);
        std::fs::remove_file(&journal_path).unwrap();
        runtime.block_on(async {
            assert!(reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap()
                .status()
                .is_success());
        });
        let first: serde_json::Value =
            serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        assert_eq!(first["step_action_id"], "secure.structure.begin");
        assert_eq!(counts()["commits"], before + 1);
        runtime.block_on(async {
            assert!(reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap()
                .status()
                .is_success());
        });
        let mut progress: serde_json::Value =
            serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(progress["status"], "PENDING");
        assert_eq!(progress["step_action_id"], "secure.structure.page");
        let saved_page_id = progress["step_command_id"].as_str().unwrap().to_owned();
        let mut page_ids = std::collections::BTreeSet::from([saved_page_id.clone()]);
        drop(install);
        let install = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        for _ in 0..5 {
            if progress["status"] == "ACCEPTED" {
                break;
            }
            progress =
                serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
            if progress["step_action_id"] == "secure.structure.page" {
                page_ids.insert(progress["step_command_id"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(progress["status"], "ACCEPTED");
        assert_eq!(page_ids.len(), 2, "one record and one head need two PAGEs");
        assert_eq!(
            counts()["commits"],
            before + 4,
            "BEGIN, two PAGEs, END; no duplicate"
        );
        assert_ne!(saved_page_id, begin_id);
        let read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records"
                && object["id"] == prior_id
                && object["value"]["payload"]["title"] == "Before direct install"
                && object["value"]["payload"]["body"] == "Encrypted old body"));
        let action = reopened
            .private_action_access(&created.workspace_id)
            .unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "proposal.propose".into(),
                    instance_id: first["instance_id"].as_str().unwrap().into(),
                    body_json:
                        r#"{"title":"After direct install","body":"Encrypted proposal body"}"#
                            .into(),
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
        let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let final_read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        let installed_policy = SecureReadProfile::new(install.config.clone())
            .with_latest_replay(&token, |source| {
                let wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Plan)?;
                let signed = parse_wire_json_bounded(wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let payload = signed
                    .get("payload")
                    .ok_or(PrivatePackageInstallError::Plan)?;
                Ok::<_, PrivatePackageInstallError>((
                    number(payload, "v")?,
                    scalar(payload, "structure_mode")?,
                    number(payload, "version")?,
                ))
            })
            .unwrap();
        assert_eq!(
            installed_policy,
            (3, "STRUCTURED".into(), prior_policy.2 + 1)
        );
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records"
                && object["id"] == effect_id
                && object["value"]["payload"]["title"] == "After direct install"
                && object["value"]["payload"]["body"] == "Encrypted proposal body"));
        assert_eq!(
            install
                .continue_install_json(begin_id)
                .unwrap()
                .contains("\"ACCEPTED\""),
            true
        );
        // A completed row stays discoverable while the same signed protocol
        // is installed as a second instance. The new BEGIN adds one instance
        // and reuses the existing protocol object.
        let second_instance_id = random_id().unwrap();
        let second: serde_json::Value = serde_json::from_str(
            &install
                .submit_direct_begin_json(PrivateDirectInstallBeginInput {
                    closure_json: material.to_string(),
                    expected_root_package_digest: vector["closure"]["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                    instance_id: second_instance_id.clone(),
                    entrypoint: "proposal".into(),
                    grants_json: serde_json::json!([{
                        "actor_id": owner_actor,
                        "actions": ["proposal.propose"],
                        "protocol_roles": ["AUTHOR"],
                        "capabilities": ["PROPOSE"]
                    }])
                    .to_string(),
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second["status"], "PENDING");
        let second_begin_id = second["begin_command_id"].as_str().unwrap().to_owned();
        assert_ne!(second_begin_id, begin_id);
        let mut second_progress = second;
        for _ in 0..12 {
            if second_progress["status"] == "ACCEPTED" {
                break;
            }
            second_progress =
                serde_json::from_str(&install.continue_install_json(&second_begin_id).unwrap())
                    .unwrap();
        }
        assert_eq!(second_progress["status"], "ACCEPTED");
        let all_installs: serde_json::Value =
            serde_json::from_str(&install.installs_json().unwrap()).unwrap();
        assert_eq!(all_installs.as_array().unwrap().len(), 2);
        assert!(all_installs
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["begin_command_id"] == begin_id));
        assert!(all_installs
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["begin_command_id"] == second_begin_id));
        let before_retries = counts()["commits"].as_u64().unwrap();
        for id in [begin_id, second_begin_id.as_str()] {
            let repeat: serde_json::Value =
                serde_json::from_str(&install.continue_install_json(id).unwrap()).unwrap();
            assert_eq!(repeat["status"], "ACCEPTED");
        }
        assert_eq!(counts()["commits"], before_retries);
        let final_read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "instances"
                    && object["id"] == second_instance_id
                    && object["value"]["protocol_digest"] == vector["protocol_digest"]
            }));
    }
}
