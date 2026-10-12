//! Private bridge from configured-origin, complete journal pages to signed
//! replay. No language API, key promotion, or final action acceptance here.

use crate::{
    secure_journal_read::{AuthenticatedJournalPages, JournalReadError},
    secure_lifecycle::{ReplayKeyringState, SecureLifecycle},
};
use peerwork_core::{
    canonical::Path,
    replayed_secure_journal::{
        replay_secure_journal_exact, JournalReplayError, JournalReplayInput, ReplayedSecureJournal,
        StructureStatus,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use thiserror::Error;

const MAX_PAGE: usize = 64 * 1024 * 1024;
// The pinned service limits stored workspace artifacts to 32 MiB. Allow
// canonical re-encoding room while core still consumes borrowed slices.
// A streaming replay API is needed before lifting this supported-source cap.
const MAX_REPLAY_ARTIFACTS: usize = 64 * 1024 * 1024;
const MAX_POLICIES: usize = 1024;

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
}

/// Private-constructor, origin-bound replay candidate. Supported signed
/// histories are checked here; remaining valid-input replay families must be
/// closed before this can authorize a public read or accepted action.
pub(crate) struct TransportReplayedJournal {
    origin: String,
    source_actor_id: String,
    source_key_id: String,
    keyring_state: Option<ReplayKeyringState>,
    replay: ReplayedSecureJournal,
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
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }
    pub(crate) fn replay(&self) -> &ReplayedSecureJournal {
        &self.replay
    }
    pub(crate) fn keyring_state(&self) -> Option<ReplayKeyringState> {
        self.keyring_state
    }
    pub(crate) fn source_actor_id(&self) -> &str {
        &self.source_actor_id
    }
    pub(crate) fn source_key_id(&self) -> &str {
        &self.source_key_id
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
    if pages.origin() != lifecycle.origin()
        || pages.workspace_id() != lifecycle.workspace_id()
        || pages.actor_id() != lifecycle.actor_id()
    {
        return Err(VerifiedReadError::Identity);
    }
    let mut policy_wires = Vec::<Vec<u8>>::new();
    let mut commit_wires = Vec::<Vec<u8>>::new();
    let mut total_bytes = 0usize;
    let mut first = true;
    pages.for_each_exact_page(|wire| {
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
                    MAX_REPLAY_ARTIFACTS,
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
                MAX_REPLAY_ARTIFACTS,
            )?;
        }
        Ok(())
    })?;
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
    let keyring = lifecycle.replay_keyring_candidate();
    let keyring_wire = keyring
        .as_ref()
        .map(|material| material.ring.canonical_wire())
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
        source_actor_id: pages.actor_id().to_owned(),
        source_key_id: pages.key_id().to_owned(),
        keyring_state: keyring.map(|material| material.state),
        replay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_artifact_buffer_checks_total_bytes_and_count_before_insertion() {
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
