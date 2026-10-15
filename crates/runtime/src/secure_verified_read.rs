//! Private bridge from configured-origin, complete journal pages to signed
//! replay. No language API, key promotion, or final action acceptance here.

use crate::{
    secure_journal_read::{AuthenticatedJournalPages, JournalReadError},
    secure_lifecycle::{ReplayKeyringState, SecureLifecycle},
};
use peerwork_core::{
    canonical::Path,
    crypto::sha256_hex,
    replayed_secure_journal::{
        replay_secure_journal_exact, JournalReplayError, JournalReplayInput, ReplayedSecureJournal,
        StructureStatus,
    },
    secure_keyring::SecretKeyring,
    verified_secure_grant::VerifiedGrantMaterial,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use thiserror::Error;

const MAX_PAGE: usize = 64 * 1024 * 1024;
const DEFAULT_REPLAY_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POLICIES: usize = 1024;

/// Bounded canonical artifacts from exact transport pages. This is only an
/// input to signed grant and journal verification, never an authority token.
pub(crate) struct UnverifiedSignedArtifacts {
    pub policy_wires: Vec<Vec<u8>>,
    pub commit_wires: Vec<Vec<u8>>,
}

/// Client memory budget for canonical policy and commit wires retained during
/// signed replay. Larger valid conversion histories may require a larger
/// caller-selected value. This does not bound the decoded replay graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureJournalReadBudget {
    pub max_replay_artifact_bytes: u64,
}

impl SecureJournalReadBudget {
    pub fn new(max_replay_artifact_bytes: u64) -> Option<Self> {
        (max_replay_artifact_bytes > 0).then_some(Self {
            max_replay_artifact_bytes,
        })
    }
}

impl Default for SecureJournalReadBudget {
    fn default() -> Self {
        Self {
            max_replay_artifact_bytes: DEFAULT_REPLAY_ARTIFACT_BYTES,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum VerifiedReadError {
    #[error("complete journal page provenance changed")]
    Page(#[from] JournalReadError),
    #[error("protected lifecycle does not match the journal source")]
    Identity,
    #[error("journal page/checkpoint has invalid exact content")]
    Content,
    #[error("signed journal replay failed: {0}")]
    Replay(#[from] JournalReplayError),
    #[error("secure journal exceeds the configured replay resource budget")]
    ResourceLimit,
    #[error("secure journal is not active for verified reads")]
    NotActive,
}

/// Private-constructor, origin-bound replay candidate. Supported signed
/// histories are checked here; remaining valid-input replay families must be
/// closed before this can authorize a public read or accepted action.
pub(crate) struct TransportReplayedJournal {
    origin: String,
    authority: String,
    source_actor_id: String,
    source_key_id: String,
    keyring_state: Option<ReplayKeyringState>,
    checkpoint_canonical_json: String,
    grant_keyring_sha256: Option<String>,
    signed_policy_wires: Vec<Vec<u8>>,
    signed_commit_wires: Vec<Vec<u8>>,
    replay: ReplayedSecureJournal,
}

/// Read-only view of an origin-bound, fully replayed active history. A
/// PRIVATE history can reach this only with an active protected keyring; the
/// core verifier requires epoch keys for every PRIVATE commit. PUBLIC history
/// can be read without one. Pending and SEEDING histories cannot enter.
pub(crate) struct VerifiedSecureRead<'a> {
    source: &'a TransportReplayedJournal,
}

impl VerifiedSecureRead<'_> {
    pub(crate) fn workspace_id(&self) -> &str {
        self.source.replay.workspace_id()
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.source.replay.sequence()
    }

    pub(crate) fn head(&self) -> Option<&str> {
        self.source.replay.head()
    }

    pub(crate) fn policy_hash(&self) -> &str {
        self.source.replay.policy_hash()
    }

    pub(crate) fn structure_status(&self) -> StructureStatus {
        self.source.replay.structure_status()
    }

    pub(crate) fn objects(&self) -> &[WireValue] {
        self.source.replay.objects()
    }

    pub(crate) fn operations(&self) -> &[WireValue] {
        self.source.replay.operations()
    }

    pub(crate) fn recoveries(&self) -> &[WireValue] {
        self.source.replay.recoveries()
    }
}

fn push_bounded(
    rows: &mut Vec<Vec<u8>>,
    encoded: Vec<u8>,
    total_bytes: &mut usize,
    max_rows: usize,
    max_bytes: usize,
) -> Result<(), JournalReadError> {
    let next = total_bytes
        .checked_add(encoded.len())
        .filter(|total| *total <= max_bytes)
        .ok_or(JournalReadError::TooLarge)?;
    if rows.len() >= max_rows {
        return Err(JournalReadError::TooLarge);
    }
    rows.push(encoded);
    *total_bytes = next;
    Ok(())
}

impl TransportReplayedJournal {
    /// Reconstruct an exact historical ACTIVE predecessor only from a complete
    /// origin-bound replay that still contains its checkpoint. This remains a
    /// private install proof context; it does not publish an older read floor.
    pub(crate) fn authenticated_active_prefix(
        &self,
        checkpoint_wire: &[u8],
        keyring: &SecretKeyring,
    ) -> Result<Self, VerifiedReadError> {
        let checkpoint = parse_wire_json_bounded(checkpoint_wire, 32, 8192)
            .map_err(|_| VerifiedReadError::Content)?;
        let canonical = canonical_wire_value(&checkpoint, Path::SecureArtifact)
            .map_err(|_| VerifiedReadError::Content)?;
        let sequence = checkpoint.get("sequence").and_then(WireValue::as_number)
            .filter(|n| n.is_finite() && *n >= 1.0 && *n <= 9_007_199_254_740_991.0
                && n.fract() == 0.0)
            .ok_or(VerifiedReadError::Content)? as u64;
        let head = checkpoint.get("head").and_then(WireValue::as_string)
            .ok_or(VerifiedReadError::Content)?;
        let policy_hash = checkpoint.get("policy_hash").and_then(WireValue::as_string)
            .ok_or(VerifiedReadError::Content)?;
        if checkpoint.get("workspace_id").and_then(WireValue::as_string).as_deref()
                != Some(self.replay.workspace_id())
            || checkpoint.get("owner_id").and_then(WireValue::as_string).as_deref()
                != Some(self.replay.owner_actor_id())
            || checkpoint.get("owner_key").and_then(WireValue::as_string).as_deref()
                != Some(self.replay.owner_signing_key())
            || !self.replay.contains_checkpoint(sequence, Some(&head), &policy_hash)
        { return Err(VerifiedReadError::Content); }
        let through = usize::try_from(sequence).map_err(|_| VerifiedReadError::Content)?;
        let commits = self.signed_commit_wires.get(..through)
            .ok_or(VerifiedReadError::Content)?.to_vec();
        let mut policies = Vec::new();
        for wire in &self.signed_policy_wires {
            let signed = parse_wire_json_bounded(wire, 64, 196_608)
                .map_err(|_| VerifiedReadError::Content)?;
            let effective = signed.get("payload").and_then(|p| p.get("effective_sequence"))
                .and_then(WireValue::as_number)
                .filter(|n| n.is_finite() && *n >= 1.0 && n.fract() == 0.0)
                .ok_or(VerifiedReadError::Content)? as u64;
            if effective <= sequence { policies.push(wire.clone()); }
        }
        let ring_wire = keyring.canonical_wire().map_err(|_| VerifiedReadError::Content)?;
        let policy_refs = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let commit_refs = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let replay = replay_secure_journal_exact(JournalReplayInput {
            policy_wires: &policy_refs, commit_wires: &commit_refs,
            checkpoint_wire: canonical.as_bytes(),
            workspace_id: self.replay.workspace_id(),
            owner_actor_id: self.replay.owner_actor_id(),
            owner_signing_key: self.replay.owner_signing_key(),
            final_sequence: sequence, final_head: Some(&head),
            final_policy_hash: &policy_hash, keyring_wire: Some(&ring_wire),
        })?;
        if replay.structure_status() != StructureStatus::Active {
            return Err(VerifiedReadError::NotActive);
        }
        Ok(Self {
            origin: self.origin.clone(), authority: self.authority.clone(),
            source_actor_id: self.source_actor_id.clone(),
            source_key_id: self.source_key_id.clone(),
            keyring_state: self.keyring_state,
            checkpoint_canonical_json: canonical,
            grant_keyring_sha256: self.grant_keyring_sha256.clone(),
            signed_policy_wires: policies, signed_commit_wires: commits, replay,
        })
    }

    pub(crate) fn verified_read(&self) -> Result<VerifiedSecureRead<'_>, VerifiedReadError> {
        if self.keyring_state == Some(ReplayKeyringState::Pending)
            || self.replay.structure_status() == StructureStatus::Seeding
        {
            return Err(VerifiedReadError::NotActive);
        }
        Ok(VerifiedSecureRead { source: self })
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }
    pub(crate) fn replay(&self) -> &ReplayedSecureJournal {
        &self.replay
    }
    pub(crate) fn keyring_state(&self) -> Option<ReplayKeyringState> {
        self.keyring_state
    }
    pub(crate) fn checkpoint_canonical_json(&self) -> &str {
        &self.checkpoint_canonical_json
    }
    pub(crate) fn grant_keyring_sha256(&self) -> Option<&str> {
        self.grant_keyring_sha256.as_deref()
    }
    pub(crate) fn source_actor_id(&self) -> &str {
        &self.source_actor_id
    }
    pub(crate) fn source_key_id(&self) -> &str {
        &self.source_key_id
    }
    pub(crate) fn signed_policy_by_hash(&self, policy_hash: &str) -> Option<&[u8]> {
        self.signed_policy_wires
            .iter()
            .find(|wire| sha256_hex(wire) == policy_hash)
            .map(Vec::as_slice)
    }
    /// Exact signed artifacts already consumed by complete origin-bound replay.
    /// These bytes are only for composing a separately checked grant proof.
    pub(crate) fn signed_policy_wires(&self) -> &[Vec<u8>] {
        &self.signed_policy_wires
    }
    pub(crate) fn signed_commit_wires(&self) -> &[Vec<u8>] {
        &self.signed_commit_wires
    }
    pub(crate) fn action_receipt(
        &self,
        command_id: &str,
    ) -> Result<Option<&WireValue>, VerifiedReadError> {
        if self.keyring_state == Some(ReplayKeyringState::Pending)
            || self.replay.structure_status() == StructureStatus::Seeding
        {
            return Ok(None);
        }
        self.replay.action_receipt(command_id).map_err(Into::into)
    }
}

/// The only constructor accepts a transport handle that the configured-origin
/// reader produced after complete pagination, plus protected lifecycle state.
/// The callback's provisional bytes cannot escape before final chain recheck.
pub(crate) fn replay_authenticated_pages(
    pages: &AuthenticatedJournalPages<'_>,
    lifecycle: &SecureLifecycle,
) -> Result<TransportReplayedJournal, VerifiedReadError> {
    replay_authenticated_pages_with_budget(pages, lifecycle, SecureJournalReadBudget::default())
}

pub(crate) fn replay_authenticated_pages_with_budget(
    pages: &AuthenticatedJournalPages<'_>,
    lifecycle: &SecureLifecycle,
    budget: SecureJournalReadBudget,
) -> Result<TransportReplayedJournal, VerifiedReadError> {
    let keyring = lifecycle.replay_keyring_candidate();
    replay_authenticated_pages_with_material(
        pages,
        lifecycle,
        keyring.as_ref().map(|material| material.ring),
        keyring.map(|material| material.state),
        None,
        budget,
    )
}

/// Grant material is allowed to decrypt a candidate replay before it becomes
/// active. The returned proof remains Pending; a separate exact-checkpoint
/// grant binding must succeed before lifecycle promotion.
pub(crate) fn replay_authenticated_pages_with_grant(
    pages: &AuthenticatedJournalPages<'_>,
    lifecycle: &SecureLifecycle,
    grant: &VerifiedGrantMaterial,
    budget: SecureJournalReadBudget,
) -> Result<TransportReplayedJournal, VerifiedReadError> {
    if grant.workspace_id() != pages.workspace_id()
        || grant.recipient_actor() != pages.actor_id()
        || grant.recipient_key() != pages.key_id()
    {
        return Err(VerifiedReadError::Identity);
    }
    let ring_wire = grant
        .keyring()
        .canonical_wire()
        .map_err(|_| VerifiedReadError::Content)?;
    let ring_hash = sha256_hex(&ring_wire);
    replay_authenticated_pages_with_material(
        pages,
        lifecycle,
        Some(grant.keyring()),
        Some(ReplayKeyringState::Pending),
        Some(ring_hash),
        budget,
    )
}

fn replay_authenticated_pages_with_material(
    pages: &AuthenticatedJournalPages<'_>,
    lifecycle: &SecureLifecycle,
    keyring: Option<&SecretKeyring>,
    keyring_state: Option<ReplayKeyringState>,
    grant_keyring_sha256: Option<String>,
    budget: SecureJournalReadBudget,
) -> Result<TransportReplayedJournal, VerifiedReadError> {
    if pages.origin() != lifecycle.origin()
        || pages.workspace_id() != lifecycle.workspace_id()
        || pages.actor_id() != lifecycle.actor_id()
    {
        return Err(VerifiedReadError::Identity);
    }
    let UnverifiedSignedArtifacts {
        policy_wires,
        commit_wires,
    } = collect_unverified_artifacts(pages, budget)?;
    let checkpoint_wire = pages.checkpoint_canonical_json().as_bytes();
    let checkpoint = parse_wire_json_bounded(checkpoint_wire, 8, 4096)
        .map_err(|_| VerifiedReadError::Content)?;
    let text = |key| {
        checkpoint
            .get(key)
            .and_then(WireValue::as_string)
            .ok_or(VerifiedReadError::Content)
    };
    let owner_actor = text("owner_id")?;
    let owner_key = text("owner_key")?;
    let policy_hash = text("policy_hash")?;
    let head = match checkpoint.get("head") {
        Some(WireValue::Null) => None,
        Some(value) => Some(value.as_string().ok_or(VerifiedReadError::Content)?),
        None => return Err(VerifiedReadError::Content),
    };
    let sequence = checkpoint
        .get("sequence")
        .and_then(WireValue::as_number)
        .filter(|n| n.is_finite() && *n >= 1.0 && *n <= 9_007_199_254_740_991.0 && n.fract() == 0.0)
        .ok_or(VerifiedReadError::Content)? as u64;
    if sequence != pages.sequence()
        || owner_actor != lifecycle.owner_actor_id()
        || owner_key != lifecycle.owner_key_id()
    {
        return Err(VerifiedReadError::Identity);
    }
    let keyring_wire = keyring
        .map(SecretKeyring::canonical_wire)
        .transpose()
        .map_err(|_| VerifiedReadError::Content)?;
    let policy_refs = policy_wires.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let commit_refs = commit_wires.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let replay = replay_secure_journal_exact(JournalReplayInput {
        policy_wires: &policy_refs,
        commit_wires: &commit_refs,
        checkpoint_wire,
        workspace_id: pages.workspace_id(),
        owner_actor_id: &owner_actor,
        owner_signing_key: &owner_key,
        final_sequence: sequence,
        final_head: head.as_deref(),
        final_policy_hash: &policy_hash,
        keyring_wire: keyring_wire.as_deref().map(Vec::as_slice),
    })?;
    Ok(TransportReplayedJournal {
        origin: pages.origin().to_owned(),
        authority: pages.authority().to_owned(),
        source_actor_id: pages.actor_id().to_owned(),
        source_key_id: pages.key_id().to_owned(),
        keyring_state,
        checkpoint_canonical_json: pages.checkpoint_canonical_json().to_owned(),
        grant_keyring_sha256,
        signed_policy_wires: policy_wires,
        signed_commit_wires: commit_wires,
        replay,
    })
}

pub(crate) fn collect_unverified_artifacts(
    pages: &AuthenticatedJournalPages<'_>,
    budget: SecureJournalReadBudget,
) -> Result<UnverifiedSignedArtifacts, VerifiedReadError> {
    let max_artifact_bytes = usize::try_from(budget.max_replay_artifact_bytes)
        .ok()
        .filter(|limit| *limit > 0)
        .ok_or(VerifiedReadError::ResourceLimit)?;
    let mut policy_wires = Vec::<Vec<u8>>::new();
    let mut commit_wires = Vec::<Vec<u8>>::new();
    let mut total_bytes = 0usize;
    let mut first = true;
    pages
        .for_each_exact_page(|wire| {
            let page = parse_wire_json_bounded(wire, 64, MAX_PAGE)
                .map_err(|_| JournalReadError::Incompatible)?;
            if first {
                let WireValue::Array(policies) =
                    page.get("policies").ok_or(JournalReadError::Incompatible)?
                else {
                    return Err(JournalReadError::Incompatible);
                };
                for policy in policies {
                    let encoded = canonical_wire_value(policy, Path::SecureArtifact)
                        .map_err(|_| JournalReadError::Incompatible)?
                        .into_bytes();
                    push_bounded(
                        &mut policy_wires,
                        encoded,
                        &mut total_bytes,
                        MAX_POLICIES,
                        max_artifact_bytes,
                    )?;
                }
                first = false;
            }
            let WireValue::Array(commits) =
                page.get("commits").ok_or(JournalReadError::Incompatible)?
            else {
                return Err(JournalReadError::Incompatible);
            };
            for commit in commits {
                let encoded = canonical_wire_value(commit, Path::SecureArtifact)
                    .map_err(|_| JournalReadError::Incompatible)?
                    .into_bytes();
                push_bounded(
                    &mut commit_wires,
                    encoded,
                    &mut total_bytes,
                    usize::MAX,
                    max_artifact_bytes,
                )?;
            }
            Ok(())
        })
        .map_err(|error| match error {
            JournalReadError::TooLarge => VerifiedReadError::ResourceLimit,
            other => VerifiedReadError::Page(other),
        })?;
    Ok(UnverifiedSignedArtifacts {
        policy_wires,
        commit_wires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_artifact_buffer_overflow_refuses_before_insertion() {
        let mut rows = Vec::new();
        let mut total = usize::MAX;
        assert!(matches!(
            push_bounded(&mut rows, vec![1], &mut total, usize::MAX, usize::MAX),
            Err(JournalReadError::TooLarge)
        ));
        assert!(rows.is_empty());
        assert_eq!(total, usize::MAX);
    }

    #[test]
    fn replay_artifact_buffer_checks_total_bytes_and_count_before_insertion() {
        assert_eq!(
            SecureJournalReadBudget::default().max_replay_artifact_bytes,
            64 * 1024 * 1024
        );
        assert!(SecureJournalReadBudget::new(0).is_none());
        assert_eq!(
            SecureJournalReadBudget::new(5)
                .unwrap()
                .max_replay_artifact_bytes,
            5
        );
        let mut rows = Vec::new();
        let mut total = 0;
        push_bounded(&mut rows, vec![1, 2, 3], &mut total, 1, 4).unwrap();
        assert_eq!(total, 3);
        assert!(matches!(
            push_bounded(&mut rows, vec![4], &mut total, 1, 4),
            Err(JournalReadError::TooLarge)
        ));
        assert!(matches!(
            push_bounded(&mut rows, vec![4, 5], &mut total, 2, 4),
            Err(JournalReadError::TooLarge)
        ));
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 1);
    }
}
