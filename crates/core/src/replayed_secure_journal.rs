//! Complete pass through the current signed replay implementation over exact
//! journal artifacts. This low-level result has no transport provenance and
//! grants no read, action, or key-activation authority by itself.

use crate::{
    secure_chain::{CheckpointPin, OwnerPin},
    secure_replay::{replay_basic_content_with_limit, ReplayError},
    wire_json::WireValue,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JournalReplayError {
    #[error("signed replay exceeds configured commit budget")]
    ResourceLimit,
    #[error("signed journal or its exact final pins did not validate")]
    Invalid,
    #[error("structured journal is still seeding")]
    Seeding,
}

/// Caller-selected complete replay commit count, including restored archives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalReplayLimits { max_commits: usize }
impl JournalReplayLimits {
    pub fn new(max_replay_commits: u64) -> Option<Self> {
        usize::try_from(max_replay_commits).ok().filter(|n| *n > 0).map(|max_commits| Self { max_commits })
    }
    pub fn max_commits(self) -> usize { self.max_commits }
}
impl Default for JournalReplayLimits { fn default() -> Self { Self { max_commits: 102_400 } } }

/// Pins must come from the runtime's protected identity, configured workspace,
/// and previously accepted checkpoint. The low-level verifier cannot attest
/// where an HTTP response came from.
pub struct JournalReplayInput<'a> {
    pub policy_wires: &'a [&'a [u8]],
    pub commit_wires: &'a [&'a [u8]],
    pub checkpoint_wire: &'a [u8],
    pub workspace_id: &'a str,
    pub owner_actor_id: &'a str,
    pub owner_signing_key: &'a str,
    pub final_sequence: u64,
    pub final_head: Option<&'a str>,
    pub final_policy_hash: &'a str,
    pub keyring_wire: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureStatus {
    Unstructured,
    Seeding,
    Active,
}

/// Private-constructor replay data. Only the runtime can add the configured
/// HTTPS origin and durable page-custody evidence needed for a business proof.
#[derive(Debug)]
pub struct ReplayedSecureJournal {
    workspace_id: String,
    owner_actor_id: String,
    owner_signing_key: String,
    sequence: u64,
    head: Option<String>,
    policy_hash: String,
    policy_hashes: Vec<String>,
    policy_effective_sequences: Vec<u64>,
    commit_hashes: Vec<String>,
    objects: Vec<WireValue>,
    operations: Vec<WireValue>,
    recoveries: Vec<WireValue>,
    action_receipts: Vec<WireValue>,
    structure_status: StructureStatus,
    structure_snapshot: Option<WireValue>,
    legacy: bool,
}

impl ReplayedSecureJournal {
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn owner_actor_id(&self) -> &str {
        &self.owner_actor_id
    }
    pub fn owner_signing_key(&self) -> &str {
        &self.owner_signing_key
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    /// Check whether an independently protected, previously verified
    /// checkpoint is an ancestor of this complete signed history. The caller
    /// must bind the old workspace/owner/origin separately; arbitrary caller
    /// strings do not become a trusted floor through this method.
    pub fn contains_checkpoint(
        &self,
        sequence: u64,
        head: Option<&str>,
        policy_hash: &str,
    ) -> bool {
        let selected_policy = self
            .policy_hashes
            .iter()
            .zip(&self.policy_effective_sequences)
            .rev()
            .find(|(_, effective_sequence)| **effective_sequence <= sequence.max(1))
            .map(|(hash, _)| hash.as_str());
        if sequence > self.sequence || selected_policy != Some(policy_hash) {
            return false;
        }
        match sequence {
            0 => head.is_none(),
            _ => {
                usize::try_from(sequence - 1)
                    .ok()
                    .and_then(|index| self.commit_hashes.get(index))
                    .map(String::as_str)
                    == head
            }
        }
    }
    pub fn structure_status(&self) -> StructureStatus {
        self.structure_status
    }
    /// The signed, fully replayed SEEDING offset. This is absent for ACTIVE
    /// histories and must not be treated as authority for ordinary actions.
    pub fn structure_snapshot(&self) -> Option<&WireValue> {
        self.structure_snapshot.as_ref()
    }
    pub fn legacy(&self) -> bool {
        self.legacy
    }
    pub fn objects(&self) -> &[WireValue] {
        &self.objects
    }
    pub fn operations(&self) -> &[WireValue] {
        &self.operations
    }
    pub fn recoveries(&self) -> &[WireValue] {
        &self.recoveries
    }

    /// A recovered, skipped commit never receives an ACTION receipt. A
    /// structured snapshot prefix cannot authorize an active action.
    pub fn action_receipt(
        &self,
        command_id: &str,
    ) -> Result<Option<&WireValue>, JournalReplayError> {
        if self.structure_status == StructureStatus::Seeding {
            return Err(JournalReplayError::Seeding);
        }
        Ok(self.action_receipts.iter().find(|receipt| {
            receipt
                .get("command_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(command_id)
        }))
    }
}

pub fn replay_secure_journal_exact(
    input: JournalReplayInput<'_>,
) -> Result<ReplayedSecureJournal, JournalReplayError> {
    replay_secure_journal_exact_with_limits(input, JournalReplayLimits::default())
}

pub fn replay_secure_journal_exact_with_limits(
    input: JournalReplayInput<'_>,
    limits: JournalReplayLimits,
) -> Result<ReplayedSecureJournal, JournalReplayError> {
    let owner = OwnerPin {
        actor_id: input.owner_actor_id,
        signing_key: input.owner_signing_key,
    };
    let final_pin = CheckpointPin {
        sequence: input.final_sequence,
        head: input.final_head,
        policy_hash: input.final_policy_hash,
    };
    let facts = replay_basic_content_with_limit(
        input.policy_wires,
        input.commit_wires,
        input.checkpoint_wire,
        input.workspace_id,
        Some(&owner),
        Some(&final_pin),
        input.keyring_wire,
        limits.max_commits(),
    )
    .map_err(|error| match error { ReplayError::ResourceLimit => JournalReplayError::ResourceLimit, _ => JournalReplayError::Invalid })?;
    // Replay may restore an authenticated archived PUBLIC prefix from signed
    // migration fragments. Reuse its scanner result, not the original
    // truncated transport suffix, for the final checkpoint binding.
    let chain = facts.chain;
    if chain.sequence != input.final_sequence
        || chain.head.as_deref() != input.final_head
        || chain.policy_hash != input.final_policy_hash
        || chain.owner_id != input.owner_actor_id
        || chain.owner_key != input.owner_signing_key
    {
        return Err(JournalReplayError::Invalid);
    }
    let structure_status = match facts.structure_state {
        None => StructureStatus::Unstructured,
        Some("SEEDING") => StructureStatus::Seeding,
        Some("ACTIVE") => StructureStatus::Active,
        _ => return Err(JournalReplayError::Invalid),
    };
    Ok(ReplayedSecureJournal {
        workspace_id: chain.workspace_id,
        owner_actor_id: chain.owner_id,
        owner_signing_key: chain.owner_key,
        sequence: chain.sequence,
        head: chain.head,
        policy_hash: chain.policy_hash,
        policy_hashes: chain.policy_hashes,
        policy_effective_sequences: chain.policy_effective_sequences,
        commit_hashes: chain.commit_hashes,
        objects: facts.objects,
        operations: facts.operations,
        recoveries: facts.recoveries,
        action_receipts: facts.action_receipts,
        structure_status,
        structure_snapshot: facts.structure_snapshot,
        legacy: facts.legacy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::{canonical_wire_value, parse_wire_json_bounded};
    use serde_json::Value;

    #[test]
    fn signed_replay_receipts_bind_exact_final_checkpoint_and_skip_recovery() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../conformance/signed-recovery-vectors.json"
        ))
        .unwrap();
        for name in [
            "signed_delegated_wiki_action_corrected",
            "signed_delegated_zero_record_action",
            "recovered_invalid_encrypted_commit",
            "v3_recovery_after_v1_wire_upgrade",
            "v2_structured_recovery_snapshot_base",
        ] {
            let case = fixture["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap();
            let policies = case["policies"].as_array().map_or_else(
                || vec![serde_json::to_vec(&case["policy"]).unwrap()],
                |items| {
                    items
                        .iter()
                        .map(|item| serde_json::to_vec(item).unwrap())
                        .collect()
                },
            );
            let policy_refs = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let commits = case["commits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| serde_json::to_vec(item).unwrap())
                .collect::<Vec<_>>();
            let commit_refs = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let checkpoint = serde_json::to_vec(&case["checkpoint"]).unwrap();
            let keyring = serde_json::to_vec(&case["keyring"]).unwrap();
            let pins = || JournalReplayInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint,
                workspace_id: case["workspace_id"].as_str().unwrap(),
                owner_actor_id: case["owner"]["actor_id"].as_str().unwrap(),
                owner_signing_key: case["owner"]["key"].as_str().unwrap(),
                final_sequence: case["checkpoint"]["sequence"].as_u64().unwrap(),
                final_head: case["checkpoint"]["head"].as_str(),
                final_policy_hash: case["checkpoint"]["policy_hash"].as_str().unwrap(),
                keyring_wire: Some(&keyring),
            };
            let replay = replay_secure_journal_exact(pins()).unwrap();
            assert_eq!(replay.sequence(), pins().final_sequence, "{name}");
            assert_eq!(replay.head(), pins().final_head, "{name}");
            assert!(replay.contains_checkpoint(
                replay.sequence(),
                replay.head(),
                replay.policy_hash()
            ));
            assert!(!replay.contains_checkpoint(
                replay.sequence(),
                Some("wrong-head"),
                replay.policy_hash()
            ));
            assert!(!replay.contains_checkpoint(replay.sequence(), replay.head(), "wrong-policy"));
            if replay.sequence() > 1 {
                assert!(replay.contains_checkpoint(
                    1,
                    Some(&replay.commit_hashes[0]),
                    &replay.policy_hashes[0],
                ));
            }
            if replay.policy_hashes.len() > 1 {
                assert!(
                    !replay.contains_checkpoint(
                        1,
                        Some(&replay.commit_hashes[0]),
                        &replay.policy_hashes[1],
                    ),
                    "{name}: future policy cannot satisfy an earlier checkpoint"
                );
            }
            if name == "v2_structured_recovery_snapshot_base" {
                assert_eq!(replay.structure_status(), StructureStatus::Seeding);
                assert!(matches!(
                    replay.action_receipt("any"),
                    Err(JournalReplayError::Seeding)
                ));
            } else if name == "recovered_invalid_encrypted_commit"
                || name == "v3_recovery_after_v1_wire_upgrade"
            {
                assert!(replay
                    .action_receipt("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                    .unwrap()
                    .is_none());
                assert_eq!(replay.recoveries().len(), 1);
            } else {
                let command = case["action_receipts"][0]["command_id"].as_str().unwrap();
                let receipt = replay.action_receipt(command).unwrap().unwrap();
                let WireValue::Array(effects) = receipt.get("effects").unwrap() else {
                    panic!("effects")
                };
                assert_eq!(
                    effects.len(),
                    usize::from(name == "signed_delegated_wiki_action_corrected")
                );
            }
            let mut wrong = pins();
            wrong.final_sequence -= 1;
            assert!(
                replay_secure_journal_exact(wrong).is_err(),
                "{name}: wrong final pin"
            );
        }
    }

    #[test]
    fn writer_generated_two_record_action_binds_both_effects_and_rejects_wrong_head() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../conformance/signed-many-action-vectors.json"
        ))
        .unwrap();
        let policies = fixture["policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|wire| serde_json::to_vec(wire).unwrap())
            .collect::<Vec<_>>();
        let policy_refs = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let commits = fixture["commits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|wire| serde_json::to_vec(wire).unwrap())
            .collect::<Vec<_>>();
        let commit_refs = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let checkpoint = serde_json::to_vec(&fixture["checkpoint"]).unwrap();
        let keyring = serde_json::to_vec(&fixture["keyring"]).unwrap();
        let pins = || JournalReplayInput {
            policy_wires: &policy_refs,
            commit_wires: &commit_refs,
            checkpoint_wire: &checkpoint,
            workspace_id: fixture["workspace_id"].as_str().unwrap(),
            owner_actor_id: fixture["owner"]["actor_id"].as_str().unwrap(),
            owner_signing_key: fixture["owner"]["key"].as_str().unwrap(),
            final_sequence: 2,
            final_head: fixture["checkpoint"]["head"].as_str(),
            final_policy_hash: fixture["checkpoint"]["policy_hash"].as_str().unwrap(),
            keyring_wire: Some(&keyring),
        };
        let replay = replay_secure_journal_exact(pins()).unwrap();
        let command = fixture["receipt"]["command_id"].as_str().unwrap();
        let receipt = replay.action_receipt(command).unwrap().unwrap();
        let expected = parse_wire_json_bounded(
            &serde_json::to_vec(&fixture["receipt"]).unwrap(),
            16,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(receipt, crate::canonical::Path::SecureArtifact).unwrap(),
            canonical_wire_value(&expected, crate::canonical::Path::SecureArtifact).unwrap()
        );
        assert!(
            matches!(receipt.get("effects"), Some(WireValue::Array(effects)) if effects.len() == 2)
        );
        assert_eq!(fixture["wrong_head"]["error"], "PROTOCOL_OUTPUT_MISMATCH");
        let bad_commits = fixture["wrong_head"]["commits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|wire| serde_json::to_vec(wire).unwrap())
            .collect::<Vec<_>>();
        let bad_refs = bad_commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let bad_checkpoint = serde_json::to_vec(&fixture["wrong_head"]["checkpoint"]).unwrap();
        assert!(replay_secure_journal_exact(JournalReplayInput {
            commit_wires: &bad_refs,
            checkpoint_wire: &bad_checkpoint,
            final_head: fixture["wrong_head"]["checkpoint"]["head"].as_str(),
            ..pins()
        })
        .is_err());
    }
}

#[cfg(test)]
mod replay_limit_tests {
    use super::*;
    #[test]
    fn checked_commit_limits_preserve_default_and_refuse_zero() {
        assert_eq!(JournalReplayLimits::default().max_commits(), 102_400);
        assert!(JournalReplayLimits::new(0).is_none());
        assert_eq!(JournalReplayLimits::new(27).unwrap().max_commits(), 27);
        if usize::BITS < 64 { assert!(JournalReplayLimits::new(u64::MAX).is_none()); }
    }
}
