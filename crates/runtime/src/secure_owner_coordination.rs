//! Dedicated, restartable pinned coordination enable. Ordinary installations
//! never enter this route and restricted attachment is not an authority source.
use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentJournal, SecurePacketInput},
    secure_lifecycle::SecureLifecycle,
    secure_read_access::{
        SecureReadAccess, SecureReadAccessError, SecureReadConfig, VerifiedReadFloor,
    },
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::SecureStateStore,
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    crypto::{base64url, decode_base64url},
    prepared_owner_coordination::{self as core, CoordinationPlan, CoordinationPrepareError},
    replayed_secure_journal::{
        replay_secure_journal_exact, JournalReplayInput, ReplayedSecureJournal, StructureStatus,
    },
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCoordinationEnableInput {
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub participants: Option<Vec<String>>,
}
impl OwnerCoordinationEnableInput {
    fn normalized(&self) -> Result<Self> {
        let version = self.version.unwrap_or(1);
        if !matches!(version, 1 | 2) {
            return Err(Error::Input);
        }
        let participants = self
            .participants
            .as_ref()
            .map(|p| {
                if p.len() > 128
                    || p.iter().any(|s| !core::token(s))
                    || p.iter().collect::<std::collections::HashSet<_>>().len() != p.len()
                {
                    return Err(Error::Input);
                }
                let mut sorted = p.clone();
                sorted.sort();
                Ok(sorted)
            })
            .transpose()?;
        Ok(Self {
            version: Some(version),
            participants,
        })
    }
    fn matches_pending(&self, other: &Self, actor: &str) -> bool {
        fn selected(p: &Option<Vec<String>>, actor: &str) -> Vec<String> {
            let mut values = p.clone().unwrap_or_default();
            values.push(actor.into());
            values.sort();
            values.dedup();
            values
        }
        // f828 only constrains a pending install's chosen participants when
        // the new caller explicitly supplies participants. Omission recovers
        // the original choice; it never authors a different grant set.
        self.version == other.version
            && (self.participants.is_none()
                || selected(&self.participants, actor) == selected(&other.participants, actor))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCoordinationProgress {
    pub status: String,
    pub workspace_id: String,
    pub version: u8,
    pub protocol_digest: String,
    pub instance_id: String,
    pub begin_command_id: Option<String>,
    pub step_command_id: Option<String>,
    pub step_action_id: Option<String>,
    pub sequence: Option<u64>,
    pub head: Option<String>,
    pub policy_hash: Option<String>,
}
#[derive(Debug, Error)]
pub enum OwnerCoordinationError {
    #[error(
        "coordination input must specify only version 1|2 and optional unique existing member IDs"
    )]
    Input,
    #[error("coordination requires the protected current Owner identity")]
    Identity,
    #[error("coordination requires complete authenticated source replay")]
    Verification,
    #[error("coordination conflicts with an existing configuration or saved operation")]
    Conflict,
    #[error("coordination participant must already be a signed workspace member")]
    ParticipantNotMember,
    #[error("saved coordination BEGIN was not found")]
    NotFound,
    #[error("protected coordination state failed")]
    Local,
    #[error("saved coordination packet failed exact reproof")]
    Packet,
    #[error("coordination transport failed; recover the saved BEGIN from operations")]
    Transport,
    #[error("coordination cancelled; recover the saved BEGIN from operations")]
    Cancelled,
    #[error("server rejected coordination with HTTP {0}")]
    ServerRejected(u16),
}
impl OwnerCoordinationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input => "INPUT_INVALID",
            Self::Identity => "IDENTITY_CHANGED",
            Self::Verification => "VERIFICATION_FAILED",
            Self::Conflict => "COORDINATION_CONFLICT",
            Self::ParticipantNotMember => "PARTICIPANT_NOT_MEMBER",
            Self::NotFound => "NOT_FOUND",
            Self::Local => "LOCAL_STATE_FAILED",
            Self::Packet => "PACKET_INVALID",
            Self::Transport => "TRANSPORT_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::ServerRejected(_) => "SERVER_REJECTED",
        }
    }
}
type Error = OwnerCoordinationError;
type Result<T> = std::result::Result<T, Error>;
impl From<SecureReadAccessError> for Error {
    fn from(e: SecureReadAccessError) -> Self {
        if matches!(e, SecureReadAccessError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Verification
        }
    }
}
impl From<CoordinationPrepareError> for Error {
    fn from(e: CoordinationPrepareError) -> Self {
        match e {
            CoordinationPrepareError::Conflict => Self::Conflict,
            CoordinationPrepareError::ParticipantNotMember => Self::ParticipantNotMember,
            _ => Self::Packet,
        }
    }
}
fn parse(wire: &[u8]) -> Result<Value> {
    serde_json::from_slice(wire).map_err(|_| Error::Packet)
}
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().ok_or(Error::Packet)
}
fn random_id() -> Result<String> {
    let mut b = [0; 32];
    OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Local)?;
    Ok(base64url(&b))
}
fn now() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Local)?
            .as_millis(),
    )
    .map_err(|_| Error::Local)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedStep {
    id: String,
    issued: u64,
    checkpoint: String,
    snapshot: Option<Value>,
    request_b64: String,
    commit_hash: String,
    action: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedOperation {
    input: OwnerCoordinationEnableInput,
    instance: String,
    source_checkpoint: String,
    steps: Vec<SavedStep>,
    progress: OwnerCoordinationProgress,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    v: u8,
    origin: String,
    workspace: String,
    actor: String,
    key: String,
    visibility: String,
    rows: BTreeMap<String, SavedOperation>,
}
impl History {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        identity: &KernelIdentity,
        visibility: &str,
    ) -> Result<Self> {
        let d = if let Some(b) = store.read_exact().map_err(|_| Error::Local)? {
            if b.len() > 32 * 1024 * 1024 {
                return Err(Error::Local);
            }
            serde_json::from_slice::<Self>(&b).map_err(|_| Error::Local)?
        } else {
            Self {
                v: 1,
                origin: config.origin.clone(),
                workspace: config.workspace_id.clone(),
                actor: identity.actor_id().into(),
                key: identity.key_id().into(),
                visibility: visibility.into(),
                rows: BTreeMap::new(),
            }
        };
        if d.v != 1
            || d.origin != config.origin
            || d.workspace != config.workspace_id
            || d.actor != identity.actor_id()
            || d.key != identity.key_id()
            || d.visibility != visibility
            || d.rows.len() > 128
        {
            return Err(Error::Local);
        }
        for (id, row) in &d.rows {
            if !core::token(id)
                || !core::token(&row.instance)
                || row.steps.is_empty()
                || row.steps.len() > 2002
                || row.steps[0].id != *id
                || row.steps[0].action != "secure.structure.begin"
                || row.input.normalized()? != row.input
                || row.progress.workspace_id != d.workspace
                || row.progress.begin_command_id.as_deref() != Some(id)
                || row.progress.instance_id != row.instance
                || row.progress.version != row.input.version.ok_or(Error::Local)?
                || !matches!(row.progress.status.as_str(), "PENDING" | "ACCEPTED")
                || row.steps.iter().any(|s| {
                    !core::token(&s.id)
                        || s.issued > 9_007_199_254_740_991
                        || !matches!(
                            s.action.as_str(),
                            "secure.structure.begin"
                                | "secure.structure.page"
                                | "secure.structure.end"
                        )
                        || decode_base64url(&s.request_b64).is_err()
                })
            {
                return Err(Error::Local);
            }
        }
        Ok(d)
    }
    fn save(&self, store: &SecureStateStore) -> Result<()> {
        let b = serde_json::to_vec(self).map_err(|_| Error::Local)?;
        if b.len() > 32 * 1024 * 1024 {
            return Err(Error::Local);
        }
        store.write_exact(&b).map_err(|_| Error::Local)
    }
}

pub struct SecureOwnerCoordination {
    config: SecureReadProfileConfig,
    visibility: &'static str,
}
impl SecureOwnerCoordination {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self {
            config,
            visibility: "PRIVATE",
        }
    }
    pub fn new_public(config: SecureReadProfileConfig) -> Self {
        Self {
            config,
            visibility: "PUBLIC",
        }
    }
    fn history_path(&self) -> std::path::PathBuf {
        self.config.state_dir.join("owner-coordination.state")
    }
    fn journal_path(&self) -> std::path::PathBuf {
        self.config
            .state_dir
            .join("owner-coordination-intents.state")
    }
    fn path(&self) -> String {
        format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            self.config.workspace_id
        )
    }
    fn identity(&self) -> Result<KernelIdentity> {
        KernelIdentity::open(&self.config.identity_path).map_err(|_| Error::Identity)
    }
    pub fn operations(&self) -> Result<Vec<OwnerCoordinationProgress>> {
        let identity = self.identity()?;
        let store = SecureStateStore::open(&self.history_path()).map_err(|_| Error::Local)?;
        let d = History::open(&store, &self.config, &identity, self.visibility)?;
        Ok(d.rows.values().map(|r| r.progress.clone()).collect())
    }
    pub fn operations_json(&self) -> Result<String> {
        serde_json::to_string(&self.operations()?).map_err(|_| Error::Local)
    }
    pub fn enable_json_with_cancel(
        &self,
        input: OwnerCoordinationEnableInput,
        cancel: &CancellationToken,
    ) -> Result<String> {
        serde_json::to_string(&self.enable_with_cancel(input, cancel)?).map_err(|_| Error::Local)
    }
    pub fn resume_json_with_cancel(&self, id: &str, cancel: &CancellationToken) -> Result<String> {
        serde_json::to_string(&self.resume_with_cancel(id, cancel)?).map_err(|_| Error::Local)
    }
    fn check_identity(
        &self,
        source: &TransportReplayedJournal,
        identity: &KernelIdentity,
    ) -> Result<()> {
        if source.origin() != self.config.origin
            || source.source_actor_id() != identity.actor_id()
            || source.source_key_id() != identity.key_id()
            || source.replay().workspace_id() != self.config.workspace_id
            || source.replay().owner_actor_id() != identity.actor_id()
            || source.replay().owner_signing_key() != identity.key_id()
        {
            return Err(Error::Identity);
        }
        let policy = parse(
            source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(Error::Verification)?,
        )?;
        if policy["payload"]["visibility"] != self.visibility {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn lifecycle(
        &self,
        source: &TransportReplayedJournal,
        identity: &KernelIdentity,
    ) -> Result<Option<SecureLifecycle>> {
        if self.visibility == "PUBLIC" {
            return Ok(None);
        }
        let l = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            source.origin(),
            identity.actor_id(),
            source.replay().workspace_id(),
            source.replay().owner_actor_id(),
            source.replay().owner_signing_key(),
        )
        .map_err(|_| Error::Identity)?;
        if l.active_keyring_without_pending().is_none() {
            return Err(Error::Conflict);
        }
        Ok(Some(l))
    }
    fn conflict_other(
        &self,
        identity: &KernelIdentity,
        source: &TransportReplayedJournal,
    ) -> Result<()> {
        // Existing dedicated histories remain separate. Never adopt another route's pending packet.
        for file in [
            "private-install-intents.state",
            "install-intents.state",
            "owner-format-intents.state",
            "field-policy-intents.state",
        ] {
            let path = self.config.state_dir.join(file);
            if !path.exists() {
                continue;
            }
            let j = SecureIntentJournal::open(&path, &self.config.origin, identity.actor_id())
                .map_err(|_| Error::Local)?;
            for row in j
                .pending()
                .iter()
                .filter(|r| r.workspace_id.as_deref() == Some(&self.config.workspace_id))
            {
                let request = j.exact_request(&row.intent_id).map_err(|_| Error::Packet)?;
                let request = parse(&request)?;
                let payload = &request["commit"]["payload"];
                let digest = j.intent_digest(&row.intent_id).map_err(|_| Error::Packet)?;
                if !source.replay().contains_checkpoint(
                    num(payload, "sequence")?,
                    Some(digest),
                    payload["policy_hash"].as_str().ok_or(Error::Packet)?,
                ) {
                    return Err(Error::Conflict);
                }
            }
        }
        Ok(())
    }
    pub fn enable_with_cancel(
        &self,
        input: OwnerCoordinationEnableInput,
        cancel: &CancellationToken,
    ) -> Result<OwnerCoordinationProgress> {
        let input = input.normalized()?;
        let pending = {
            let identity = self.identity()?;
            let store = SecureStateStore::open(&self.history_path()).map_err(|_| Error::Local)?;
            let d = History::open(&store, &self.config, &identity, self.visibility)?;
            let rows: Vec<_> = d
                .rows
                .iter()
                .filter(|(_, r)| r.progress.status == "PENDING")
                .collect();
            if rows.len() > 1 {
                return Err(Error::Conflict);
            }
            if let Some((id, row)) = rows.first() {
                if !input.matches_pending(&row.input, identity.actor_id()) {
                    return Err(Error::Conflict);
                }
                Some((*id).clone())
            } else {
                None
            }
        };
        if let Some(id) = pending {
            return self.resume_with_cancel(&id, cancel);
        }
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            source.verified_read().map_err(|_| Error::Verification)?;
            let identity = self.identity()?;
            self.check_identity(source, &identity)?;
            self.conflict_other(&identity, source)?;
            let store = SecureStateStore::open(&self.history_path()).map_err(|_| Error::Local)?;
            let mut d = History::open(&store, &self.config, &identity, self.visibility)?;
            if d.rows.len() >= 128 || d.rows.values().any(|r| r.progress.status == "PENDING") {
                return Err(Error::Conflict);
            }
            let instance = random_id()?;
            let issued = now()?;
            let policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(Error::Verification)?;
            let plan = core::plan(
                policy,
                source.checkpoint_canonical_json().as_bytes(),
                source.replay().objects(),
                input.version.unwrap(),
                input.participants.as_deref(),
                &instance,
                issued,
                identity.signing_key(),
            )?;
            if plan.already_enabled {
                let prior = d
                    .rows
                    .values()
                    .find(|r| r.instance == plan.instance_id && r.progress.status == "ACCEPTED");
                let mut p = if let Some(row) = prior {
                    row.progress.clone()
                } else {
                    progress(&self.config, &plan, None, None, "ACCEPTED", source)
                };
                p.sequence = Some(source.replay().sequence());
                p.head = source.replay().head().map(str::to_owned);
                p.policy_hash = Some(source.replay().policy_hash().into());
                return Ok(p);
            }
            let id = random_id()?;
            let lifecycle = self.lifecycle(source, &identity)?;
            let p = parse(policy)?;
            let epoch = num(&p["payload"], "epoch")?;
            let key = lifecycle
                .as_ref()
                .map(|l| l.active_key(epoch).ok_or(Error::Identity))
                .transpose()?;
            let packet = core::packet(
                &plan,
                source.checkpoint_canonical_json().as_bytes(),
                None,
                &id,
                issued,
                identity.signing_key(),
                key,
                None,
            )?;
            drop(lifecycle);
            let step = SavedStep {
                id: id.clone(),
                issued,
                checkpoint: source.checkpoint_canonical_json().into(),
                snapshot: None,
                request_b64: base64url(&packet.request),
                commit_hash: packet.commit_hash.clone(),
                action: packet.action_id.clone(),
            };
            let p = progress(
                &self.config,
                &plan,
                Some(&id),
                Some(&step),
                "PENDING",
                source,
            );
            let row = SavedOperation {
                input: input.clone(),
                instance,
                source_checkpoint: source.checkpoint_canonical_json().into(),
                steps: vec![step.clone()],
                progress: p.clone(),
            };
            d.rows.insert(id.clone(), row);
            d.save(&store)?;
            self.post(&identity, &step, &packet.request, cancel)?;
            Ok(p)
        })
    }
    fn post(
        &self,
        identity: &KernelIdentity,
        step: &SavedStep,
        request: &[u8],
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut journal = SecureIntentJournal::open(
            &self.journal_path(),
            &self.config.origin,
            identity.actor_id(),
        )
        .map_err(|_| Error::Local)?;
        journal
            .prepare(SecurePacketInput {
                intent_id: &step.id,
                path: &self.path(),
                action_id: &step.action,
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &step.commit_hash,
                exact_request: request,
            })
            .map_err(|_| Error::Packet)?;
        if journal.exact_request(&step.id).map_err(|_| Error::Packet)? != request {
            return Err(Error::Packet);
        }
        let mut config = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        config.allow_loopback_http = self.config.allow_loopback_http;
        let transport = HttpTransport::new(config).map_err(|_| Error::Transport)?;
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Transport)?;
        match rt.block_on(transport.post_exact(&self.path(), request.to_vec(), cancel)) {
            Ok(r) => {
                if !r.wire.is_empty() {
                    journal
                        .observe_response(&step.id, &r.wire)
                        .map_err(|_| Error::Packet)?;
                }
                if !(200..300).contains(&r.status) {
                    return Err(Error::ServerRejected(r.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => (),
            Err(TransportError::Cancelled) => return Err(Error::Cancelled),
            Err(_) => return Err(Error::Transport),
        }
        Ok(())
    }
    fn with_replay<T, F>(&self, cancel: &CancellationToken, consume: F) -> Result<T>
    where
        F: FnOnce(&TransportReplayedJournal) -> Result<T>,
    {
        SecureReadProfile::new(self.config.clone()).with_pinned_replay(cancel, |prior| {
            let floor = VerifiedReadFloor {
                sequence: prior.replay().sequence(),
                head: prior.replay().head().map(str::to_owned),
                policy_hash: prior.replay().policy_hash().into(),
            };
            let access = SecureReadAccess::new(SecureReadConfig {
            transport: self.config.transport.clone(),
                origin: prior.origin().into(),
                kernel_journal_path: self.config.state_dir.join("kernel.sqlite"),
                read_state_path: self.config.state_dir.join("owner-coordination-read.state"),
                lifecycle_path: self.config.state_dir.join("lifecycle.state"),
                identity_path: self.config.identity_path.clone(),
                workspace_id: self.config.workspace_id.clone(),
                authority: prior.authority().into(),
                owner_actor_id: prior.replay().owner_actor_id().into(),
                owner_key_id: prior.replay().owner_signing_key().into(),
                required_features: self.config.required_features.clone(),
                allow_loopback_http: self.config.allow_loopback_http,
                max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            max_replay_commits: self.config.max_replay_commits,
            });
            let (fresh, _) = access.replay_checked_install_generation(cancel, &floor)?;
            if fresh.origin() != prior.origin() || fresh.authority() != prior.authority() {
                return Err(Error::Identity);
            }
            consume(&fresh)
        })
    }
    pub fn resume_with_cancel(
        &self,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<OwnerCoordinationProgress> {
        if !core::token(id) {
            return Err(Error::Input);
        }
        let _identity = self.identity()?;
        let p = self.with_replay(cancel, |source| {
            let identity = self.identity()?;
            self.check_identity(source, &identity)?;
            self.conflict_other(&identity, source)?;
            let store = SecureStateStore::open(&self.history_path()).map_err(|_| Error::Local)?;
            let mut d = History::open(&store, &self.config, &identity, self.visibility)?;
            let mut row = d.rows.get(id).cloned().ok_or(Error::NotFound)?;
            let lifecycle = self.lifecycle(source, &identity)?;
            let original = parse(row.source_checkpoint.as_bytes())?;
            let historical = prefix(source, lifecycle.as_ref(), row.source_checkpoint.as_bytes())?;
            if historical.structure_status() == StructureStatus::Seeding {
                return Err(Error::Packet);
            }
            let old_policy = source
                .signed_policy_by_hash(original["policy_hash"].as_str().ok_or(Error::Packet)?)
                .ok_or(Error::Verification)?;
            let begin_issued = row.steps[0].issued;
            let plan = core::plan(
                old_policy,
                row.source_checkpoint.as_bytes(),
                historical.objects(),
                row.input.version.unwrap(),
                row.input.participants.as_deref(),
                &row.instance,
                begin_issued,
                identity.signing_key(),
            )?;
            if plan.already_enabled || plan.protocol_digest != row.progress.protocol_digest {
                return Err(Error::Packet);
            }
            let p = parse(old_policy)?;
            let epoch = num(&p["payload"], "epoch")?;
            // Epoch changes while a saved install is unfinished are not silently adopted.
            let current_policy = parse(
                source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(Error::Verification)?,
            )?;
            let key = lifecycle
                .as_ref()
                .map(|l| l.active_key(epoch).ok_or(Error::Identity))
                .transpose()?;
            let mut all_applied = true;
            for (index, step) in row.steps.iter().enumerate() {
                let cp = parse(step.checkpoint.as_bytes())?;
                if index == 0 {
                    if step.checkpoint != row.source_checkpoint || step.snapshot.is_some() {
                        return Err(Error::Packet);
                    }
                } else {
                    let prev = &row.steps[index - 1];
                    let previous_cp = parse(prev.checkpoint.as_bytes())?;
                    if cp["sequence"] != num(&previous_cp, "sequence")? + 1
                        || cp["head"] != prev.commit_hash
                        || cp["policy_hash"] != row.steps[0].policy_hash()?
                        || prev.action == "secure.structure.end"
                    {
                        return Err(Error::Packet);
                    }
                    let before = prefix(source, lifecycle.as_ref(), step.checkpoint.as_bytes())?;
                    if before.structure_status() != StructureStatus::Seeding
                        || before.structure_snapshot().map(core::value).transpose()?
                            != step.snapshot
                    {
                        return Err(Error::Packet);
                    }
                }
                let request = decode_base64url(&step.request_b64).map_err(|_| Error::Packet)?;
                let snap = step.snapshot.as_ref().map(core::wire).transpose()?;
                let proof = core::packet(
                    &plan,
                    step.checkpoint.as_bytes(),
                    snap.as_ref(),
                    &step.id,
                    step.issued,
                    identity.signing_key(),
                    key,
                    Some(&request),
                )?;
                if proof.commit_hash != step.commit_hash || proof.action_id != step.action {
                    return Err(Error::Packet);
                }
                let seq = num(&cp, "sequence")? + 1;
                let applied = source.replay().contains_checkpoint(
                    seq,
                    Some(&step.commit_hash),
                    &proof.policy_hash,
                );
                if !applied {
                    if index + 1 != row.steps.len()
                        || source.replay().sequence() != seq - 1
                        || source.replay().head() != cp["head"].as_str()
                        || source.replay().policy_hash()
                            != cp["policy_hash"].as_str().ok_or(Error::Packet)?
                        || row.progress.status == "ACCEPTED"
                    {
                        return Err(Error::Conflict);
                    }
                    all_applied = false;
                }
            }
            let last = row.steps.last().ok_or(Error::Local)?.clone();
            if all_applied && last.action == "secure.structure.end" {
                if source.replay().structure_status() != StructureStatus::Active {
                    return Err(Error::Verification);
                }
                row.progress = progress(
                    &self.config,
                    &plan,
                    Some(id),
                    Some(&last),
                    "ACCEPTED",
                    source,
                );
                let p = row.progress.clone();
                d.rows.insert(id.into(), row);
                d.save(&store)?;
                return Ok(p);
            }
            if current_policy["payload"]["epoch"] != p["payload"]["epoch"] {
                return Err(Error::Conflict);
            }
            if all_applied {
                if source.replay().policy_hash() != row.steps[0].policy_hash()?
                    || source.replay().structure_status() != StructureStatus::Seeding
                {
                    return Err(Error::Conflict);
                }
                let snap = source
                    .replay()
                    .structure_snapshot()
                    .ok_or(Error::Verification)?;
                let step_id = random_id()?;
                let issued = now()?;
                let packet = core::packet(
                    &plan,
                    source.checkpoint_canonical_json().as_bytes(),
                    Some(snap),
                    &step_id,
                    issued,
                    identity.signing_key(),
                    key,
                    None,
                )?;
                let step = SavedStep {
                    id: step_id,
                    issued,
                    checkpoint: source.checkpoint_canonical_json().into(),
                    snapshot: Some(core::value(snap)?),
                    request_b64: base64url(&packet.request),
                    commit_hash: packet.commit_hash,
                    action: packet.action_id,
                };
                row.steps.push(step);
            }
            drop(lifecycle);
            let step = row.steps.last().ok_or(Error::Local)?.clone();
            let request = decode_base64url(&step.request_b64).map_err(|_| Error::Packet)?;
            row.progress = progress(
                &self.config,
                &plan,
                Some(id),
                Some(&step),
                "PENDING",
                source,
            );
            let p = row.progress.clone();
            d.rows.insert(id.into(), row);
            d.save(&store)?;
            self.post(&identity, &step, &request, cancel)?;
            Ok(p)
        })?;
        if p.status == "ACCEPTED" {
            SecureReadProfile::new(self.config.clone()).read_latest_json_with_cancel(cancel)?;
        }
        Ok(p)
    }
}
impl SavedStep {
    fn policy_hash(&self) -> Result<String> {
        let b = decode_base64url(&self.request_b64).map_err(|_| Error::Packet)?;
        parse(&b)?["commit"]["payload"]["policy_hash"]
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::Packet)
    }
}
fn progress(
    config: &SecureReadProfileConfig,
    plan: &CoordinationPlan,
    begin: Option<&str>,
    step: Option<&SavedStep>,
    status: &str,
    source: &TransportReplayedJournal,
) -> OwnerCoordinationProgress {
    OwnerCoordinationProgress {
        status: status.into(),
        workspace_id: config.workspace_id.clone(),
        version: plan.version,
        protocol_digest: plan.protocol_digest.clone(),
        instance_id: plan.instance_id.clone(),
        begin_command_id: begin.map(str::to_owned),
        step_command_id: step.map(|s| s.id.clone()),
        step_action_id: step.map(|s| s.action.clone()),
        sequence: Some(source.replay().sequence()),
        head: source.replay().head().map(str::to_owned),
        policy_hash: Some(source.replay().policy_hash().into()),
    }
}
fn prefix(
    source: &TransportReplayedJournal,
    lifecycle: Option<&SecureLifecycle>,
    cp_wire: &[u8],
) -> Result<ReplayedSecureJournal> {
    let cp = parse(cp_wire)?;
    let seq = num(&cp, "sequence")?;
    let head = cp["head"].as_str().ok_or(Error::Packet)?;
    let ph = cp["policy_hash"].as_str().ok_or(Error::Packet)?;
    if !source.replay().contains_checkpoint(seq, Some(head), ph) {
        return Err(Error::Verification);
    }
    let all = source.signed_commit_wires();
    let through = usize::try_from(seq).map_err(|_| Error::Packet)?;
    if through > all.len() {
        return Err(Error::Verification);
    }
    let commits: Vec<_> = all[..through].iter().map(Vec::as_slice).collect();
    let mut policies = vec![];
    for w in source.signed_policy_wires() {
        let p = parse(w)?;
        if num(&p["payload"], "effective_sequence")? <= seq {
            policies.push(w.as_slice());
        }
    }
    let ring = lifecycle
        .map(|l| {
            l.active_keyring_without_pending()
                .ok_or(Error::Conflict)?
                .canonical_wire()
                .map_err(|_| Error::Identity)
        })
        .transpose()?;
    replay_secure_journal_exact(JournalReplayInput {
        policy_wires: &policies,
        commit_wires: &commits,
        checkpoint_wire: cp_wire,
        workspace_id: source.replay().workspace_id(),
        owner_actor_id: source.replay().owner_actor_id(),
        owner_signing_key: source.replay().owner_signing_key(),
        final_sequence: seq,
        final_head: Some(head),
        final_policy_hash: ph,
        keyring_wire: ring.as_deref().map(Vec::as_slice),
    })
    .map_err(|_| Error::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_owner_attach::{HistoricalOwnerAttachInput, SecureHistoricalOwnerAttach};
    use crate::secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerWorkspaceCreate};
    use std::{
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };
    fn token_id(n: u8) -> String {
        base64url(&[n; 32])
    }
    #[test]
    fn input_defaults_omission_and_identity_are_strict() {
        let empty: OwnerCoordinationEnableInput = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.normalized().unwrap().version, Some(1));
        assert!(serde_json::from_str::<OwnerCoordinationEnableInput>(r#"{"grants":[]}"#).is_err());
        assert!(OwnerCoordinationEnableInput {
            version: Some(3),
            participants: None
        }
        .normalized()
        .is_err());
        let explicit = OwnerCoordinationEnableInput {
            version: None,
            participants: Some(vec![]),
        }
        .normalized()
        .unwrap();
        assert_ne!(empty.normalized().unwrap(), explicit);
        assert!(empty
            .normalized()
            .unwrap()
            .matches_pending(&explicit, &token_id(1)));
        assert!(explicit.matches_pending(
            &OwnerCoordinationEnableInput {
                version: Some(1),
                participants: Some(vec![token_id(1)])
            },
            &token_id(1)
        ));
        let saved_member = OwnerCoordinationEnableInput {
            version: Some(1),
            participants: Some(vec![token_id(4)]),
        };
        assert!(empty
            .normalized()
            .unwrap()
            .matches_pending(&saved_member, &token_id(1)));
        assert!(!explicit.matches_pending(&saved_member, &token_id(1)));
        assert!(explicit.matches_pending(&empty.normalized().unwrap(), &token_id(1)));
        assert!(!OwnerCoordinationEnableInput {
            version: Some(2),
            participants: None
        }
        .matches_pending(&saved_member, &token_id(1)));
        let root = crate::test_support::protected_test_dir();
        let path = root.path().join("missing").join("identity.state");
        let access = SecureOwnerCoordination::new(SecureReadProfileConfig {
            transport: Default::default(),
            origin: "https://example.invalid/".into(),
            state_dir: root.path().join("missing"),
            identity_path: path.clone(),
            workspace_id: token_id(2),
            owner_actor_id: None,
            owner_key_id: None,
            authority: None,
            required_features: vec![],
            allow_loopback_http: false,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        });
        assert!(matches!(access.operations(), Err(Error::Identity)));
        assert!(!path.parent().unwrap().exists());
        assert!(matches!(
            access.enable_with_cancel(empty, &CancellationToken::new()),
            Err(Error::Identity)
        ));
        assert!(!path.parent().unwrap().exists());
        assert!(matches!(
            access.resume_with_cancel(&token_id(3), &CancellationToken::new()),
            Err(Error::Identity)
        ));
        assert!(!path.parent().unwrap().exists());
    }
    struct Stop(Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let status = self.0.wait().unwrap();
            eprintln!("COORDINATION_SERVICE_STOPPED {status}");
        }
    }
    fn actual(visibility: &str) {
        let reference =
            std::env::var("PEERWORK_REFERENCE_ROOT").expect("explicit reference gate required");
        let node = std::env::var("PEERWORK_NODE_BIN").expect("explicit node required");
        let root = std::env::var("PEERWORK_COORDINATION_TEST_DIR")
            .expect("retained protected test directory required");
        let root = Path::new(&root);
        assert!(!root.exists());
        std::fs::create_dir(root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let server_log = std::fs::File::create(root.join("server.stderr")).unwrap();
        let mut child = Stop(
            Command::new(&node)
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../tests/reference-kernel-server.mjs"),
                )
                .env("PEERWORK_REFERENCE_ROOT", &reference)
                .env("PEERWORK_TEST_STATE", root)
                .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
                .stdout(Stdio::piped())
                .stderr(server_log)
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty());
        std::fs::write(root.join("server-ready.json"), &line).unwrap();
        let ready: Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let source = Command::new(&node)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/owner-coordination-source.mjs"),
            )
            .arg(origin)
            .arg(root.join("source"))
            .arg(&reference)
            .arg(visibility)
            .output()
            .unwrap();
        std::fs::write(root.join("source.stdout"), &source.stdout).unwrap();
        std::fs::write(root.join("source.stderr"), &source.stderr).unwrap();
        assert!(
            source.status.success(),
            "{}",
            String::from_utf8_lossy(&source.stderr)
        );
        let source: Value = serde_json::from_slice(&source.stdout).unwrap();
        let workspace = source["workspace_id"].as_str().unwrap();
        let actor = source["owner_actor_id"].as_str().unwrap();
        let config = SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.into(),
            state_dir: root.join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let cancel = CancellationToken::new();
        let attached = SecureHistoricalOwnerAttach::new(config.clone())
            .attach(
                HistoricalOwnerAttachInput {
                    workspace_id: workspace.into(),
                    protected_ts_state_path: source["state_path"].as_str().unwrap().into(),
                    protected_owner_pkcs8_path: source["pem_path"].as_str().unwrap().into(),
                    protected_ts_intent_db_path: source["intent_db_path"].as_str().unwrap().into(),
                    expected_owner_actor_id: actor.into(),
                    expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                    recover_pending_action: false,
                    retain_pending_action_command_id: None,
                    selected_pending_package_stage_command_id: None,
                    selected_orphan_package_stage_command_id: None,
                    expected_ts_state_digest: None,
                    kernel_pending_command_ids: vec![],
                    expected_kernel_intent_db_digest: None,
                },
                &cancel,
            )
            .unwrap();
        assert_eq!(attached.status, "ATTACHED");
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let access = owner.coordination_access(workspace).unwrap();
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let count = || -> u64 {
            rt.block_on(async {
                serde_json::from_slice::<Value>(
                    &reqwest::get(format!("{origin}__test/secure-counts"))
                        .await
                        .unwrap()
                        .bytes()
                        .await
                        .unwrap(),
                )
                .unwrap()["commits"]
                    .as_u64()
                    .unwrap()
            })
        };
        let drop_next = || {
            rt.block_on(async {
                assert!(reqwest::Client::new()
                    .post(format!("{origin}__test/drop-next-post"))
                    .body("{}")
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success());
            })
        };
        let baseline = count();
        assert_eq!(baseline, source["sequence"].as_u64().unwrap());
        assert!(matches!(
            access.enable_with_cancel(
                OwnerCoordinationEnableInput {
                    version: None,
                    participants: Some(vec![token_id(210)])
                },
                &cancel
            ),
            Err(Error::ParticipantNotMember)
        ));
        assert_eq!(count(), baseline);
        assert!(access.operations().unwrap().is_empty());
        let participants = if visibility == "PRIVATE" {
            Some(vec![source["member_actor_id"].as_str().unwrap().into()])
        } else {
            None
        };
        drop_next();
        let first = access
            .enable_with_cancel(
                OwnerCoordinationEnableInput {
                    version: None,
                    participants: participants.clone(),
                },
                &cancel,
            )
            .unwrap();
        assert_eq!(first.status, "PENDING");
        let begin = first.begin_command_id.clone().unwrap();
        assert_eq!(
            first.step_action_id.as_deref(),
            Some("secure.structure.begin")
        );
        assert_eq!(count(), baseline + 1);
        assert!(matches!(
            access.enable_with_cancel(
                OwnerCoordinationEnableInput {
                    version: Some(2),
                    participants: participants.clone()
                },
                &cancel
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(count(), baseline + 1);
        drop(access);
        let fresh = SecureOwnerWorkspaceCreate::new(config.clone())
            .coordination_access(workspace)
            .unwrap();
        assert_eq!(
            fresh.operations().unwrap()[0].begin_command_id.as_deref(),
            Some(begin.as_str())
        );
        let mut progress = first;
        for _ in 0..8 {
            progress = fresh.resume_with_cancel(&begin, &cancel).unwrap();
            if progress.status == "ACCEPTED" {
                break;
            }
        }
        assert_eq!(progress.status, "ACCEPTED");
        assert_eq!(progress.begin_command_id.as_deref(), Some(begin.as_str()));
        let accepted_count = count();
        assert!(accepted_count >= baseline + 2);
        let read: Value =
            serde_json::from_str(&owner.read_workspace_json(workspace, &cancel).unwrap()).unwrap();
        std::fs::write(
            root.join("v1-read.json"),
            serde_json::to_vec(&read).unwrap(),
        )
        .unwrap();
        let (policy, objects) = SecureReadProfile::new(fresh.config.clone())
            .with_latest_replay(&cancel, |replay| {
                Ok::<_, Error>((
                    parse(
                        replay
                            .signed_policy_by_hash(replay.replay().policy_hash())
                            .unwrap(),
                    )?,
                    replay.replay().objects().to_vec(),
                ))
            })
            .unwrap();
        let old: Value =
            serde_json::from_slice(&std::fs::read(root.join("source/source-policy.json")).unwrap())
                .unwrap();
        let oldrecord: Value =
            serde_json::from_slice(&std::fs::read(root.join("source/source-record.json")).unwrap())
                .unwrap();
        assert!(objects.iter().any(|o| core::value(o).unwrap() == oldrecord));
        let contract = &policy["payload"]["structure"];
        let coord = &contract["coordination"];
        assert_eq!(coord["v"], 1);
        assert_eq!(coord["instance_id"], progress.instance_id);
        assert_eq!(coord["protocol_digest"], core::preset(1).unwrap().1);
        assert_eq!(coord["coordinator"], actor);
        assert_eq!(coord["escalate_after"], 5);
        for m in old["payload"]["members"].as_array().unwrap() {
            let updated = policy["payload"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["actor_id"] == m["actor_id"])
                .unwrap();
            for scope in m["scopes"].as_array().unwrap() {
                assert!(updated["scopes"].as_array().unwrap().contains(scope));
            }
        }
        let selected = if visibility == "PRIVATE" {
            vec![actor, source["member_actor_id"].as_str().unwrap()]
        } else {
            vec![actor]
        };
        for id in selected {
            let m = policy["payload"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["actor_id"] == id)
                .unwrap();
            assert!(m["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["instance_id"] == progress.instance_id
                    && s["protocol_roles"] == serde_json::json!(["COLLABORATOR"])
                    && s["capabilities"] == serde_json::json!(["COORDINATE"])));
        }
        if visibility == "PRIVATE" {
            for p in contract["protocols"].as_array().unwrap() {
                if p["protocol_digest"] != progress.protocol_digest {
                    for def in p["schemas"].as_object().unwrap().values() {
                        for field in def["fields"].as_object().unwrap().values() {
                            assert_eq!(field["protection"], "e2ee");
                        }
                    }
                }
            }
        } else {
            for p in old["payload"]["structure"]["protocols"].as_array().unwrap() {
                assert!(contract["protocols"].as_array().unwrap().contains(p));
            }
        }
        let repeat = fresh
            .enable_with_cancel(OwnerCoordinationEnableInput::default(), &cancel)
            .unwrap();
        assert_eq!(repeat.status, "ACCEPTED");
        assert_eq!(repeat.begin_command_id.as_deref(), Some(begin.as_str()));
        assert_eq!(count(), accepted_count);
        assert!(matches!(
            fresh.enable_with_cancel(
                OwnerCoordinationEnableInput {
                    version: Some(1),
                    participants: Some(vec![token_id(210)])
                },
                &cancel
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(count(), accepted_count);
        let mut upgrade = fresh
            .enable_with_cancel(
                OwnerCoordinationEnableInput {
                    version: Some(2),
                    participants: participants.clone(),
                },
                &cancel,
            )
            .unwrap();
        let upgrade_id = upgrade.begin_command_id.clone().unwrap();
        assert_ne!(upgrade_id, begin);
        for _ in 0..8 {
            upgrade = fresh.resume_with_cancel(&upgrade_id, &cancel).unwrap();
            if upgrade.status == "ACCEPTED" {
                break;
            }
        }
        assert_eq!(upgrade.status, "ACCEPTED");
        assert_ne!(upgrade.instance_id, progress.instance_id);
        let after_upgrade = count();
        let final_read: Value =
            serde_json::from_str(&owner.read_workspace_json(workspace, &cancel).unwrap()).unwrap();
        std::fs::write(
            root.join("v2-read.json"),
            serde_json::to_vec(&final_read).unwrap(),
        )
        .unwrap();
        let final_policy = SecureReadProfile::new(fresh.config.clone())
            .with_latest_replay(&cancel, |r| {
                parse(r.signed_policy_by_hash(r.replay().policy_hash()).unwrap())
            })
            .unwrap();
        let final_coord = &final_policy["payload"]["structure"]["coordination"];
        assert_eq!(final_coord["v"], 2);
        assert_eq!(final_coord["protocol_digest"], core::preset(2).unwrap().1);
        for key in [
            "coordinator",
            "initial_delay_ms",
            "max_delay_ms",
            "escalate_after",
            "window_ms",
            "workspace_limit",
            "sender_limit",
            "recipient_limit",
        ] {
            assert_eq!(final_coord[key], coord[key]);
        }
        for p in contract["protocols"].as_array().unwrap() {
            assert!(final_policy["payload"]["structure"]["protocols"]
                .as_array()
                .unwrap()
                .contains(p));
        }
        for m in policy["payload"]["members"].as_array().unwrap() {
            let updated = final_policy["payload"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["actor_id"] == m["actor_id"])
                .unwrap();
            for scope in m["scopes"].as_array().unwrap() {
                assert!(updated["scopes"].as_array().unwrap().contains(scope));
            }
        }
        assert!(matches!(
            fresh.enable_with_cancel(
                OwnerCoordinationEnableInput {
                    version: Some(1),
                    participants: None
                },
                &cancel
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(count(), after_upgrade);
        assert_eq!(
            fresh
                .resume_with_cancel(&upgrade_id, &cancel)
                .unwrap()
                .status,
            "ACCEPTED"
        );
        assert_eq!(count(), after_upgrade);
        eprintln!("COORDINATION_HTTP {visibility} PASS baseline={baseline} v1={accepted_count} v2={after_upgrade} original_begin={begin} upgrade_begin={upgrade_id}");
    }
    #[test]
    fn actual_service_private_coordination_enable_upgrade_recovery() {
        actual("PRIVATE")
    }
    #[test]
    fn actual_service_public_coordination_enable_upgrade_recovery() {
        actual("PUBLIC")
    }
}
