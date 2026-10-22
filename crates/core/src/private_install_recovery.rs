//! Checked recovery of one invalid inline PRIVATE install BEGIN. Original
//! artifacts remain signed history. This cannot recover key or signature errors.
use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, sha256_hex},
    prepared_secure_author::sign_private_commit,
    public_direct_install::plan_public_install_snapshot,
    replayed_secure_journal::{
        replay_secure_journal_exact_with_guard_time_attestations_and_limits, JournalReplayError,
        JournalReplayInput, JournalReplayLimits, ReplayedSecureJournal,
    },
    secure_chain::{scan_signed_chain_headers_with_limit, CheckpointPin, OwnerPin},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InstallRecoveryError {
    #[error("recovery requires the exact signed single-BEGIN suffix, verified predecessor, and reproduced inline object-size failure")]
    Invalid,
    #[error("recovery candidate verification failed (class={class}, check={check}, sequence={sequence:?})")]
    Verification {
        class: &'static str,
        check: &'static str,
        sequence: Option<u64>,
    },
}
fn text(v: &WireValue, k: &str) -> Result<String, InstallRecoveryError> {
    v.get(k)
        .and_then(WireValue::as_string)
        .ok_or(InstallRecoveryError::Invalid)
}
fn n(v: &WireValue, k: &str) -> Result<u64, InstallRecoveryError> {
    v.get(k)
        .and_then(WireValue::as_number)
        .filter(|v| v.is_finite() && *v >= 0.0 && v.fract() == 0.0 && *v <= 9_007_199_254_740_991.0)
        .map(|v| v as u64)
        .ok_or(InstallRecoveryError::Invalid)
}
fn s(v: &str) -> WireValue {
    WireValue::String(v.encode_utf16().collect())
}
fn o(v: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        v.into_iter()
            .map(|(k, v)| (k.encode_utf16().collect(), v))
            .collect(),
    )
}
fn canonical(v: &WireValue) -> Result<String, InstallRecoveryError> {
    canonical_wire_value(v, Path::SecureArtifact).map_err(|_| InstallRecoveryError::Invalid)
}
fn field<'a>(v: &'a WireValue, k: &str) -> Result<&'a WireValue, InstallRecoveryError> {
    v.get(k).ok_or(InstallRecoveryError::Invalid)
}
fn put(v: &mut WireValue, k: &str, x: WireValue) -> Result<(), InstallRecoveryError> {
    let WireValue::Object(fields) = v else {
        return Err(InstallRecoveryError::Invalid);
    };
    if let Some((_, v)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(k.encode_utf16()))
    {
        *v = x
    } else {
        fields.push((k.encode_utf16().collect(), x))
    }
    Ok(())
}
pub enum InstallRecoveryCandidate {
    Verified(ReplayedSecureJournal),
    Invalid(CheckedInvalidInstallRecovery),
}
pub struct CheckedInvalidInstallRecovery {
    report_json: String,
    review_hash: String,
    current_policy: WireValue,
    base_structure: WireValue,
    recovery: WireValue,
    snapshot: WireValue,
    checkpoint: WireValue,
}
impl CheckedInvalidInstallRecovery {
    pub fn report_json(&self) -> &str {
        &self.report_json
    }
    pub fn review_hash(&self) -> &str {
        &self.review_hash
    }
    fn expected_fields(
        &self,
        key: &SigningKey,
        operation_id: &str,
        issued_at: u64,
    ) -> Result<(WireValue, WireValue), InstallRecoveryError> {
        if operation_id.len() != 43
            || !operation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || issued_at > 9_007_199_254_740_991
        {
            return Err(InstallRecoveryError::Invalid);
        }
        let mut payload = field(&self.current_policy, "payload")?.clone();
        let actor = actor_id(&key.verifying_key().to_bytes());
        let signer = base64url(&key.verifying_key().to_bytes());
        if text(&payload, "owner_id")? != actor
            || text(&payload, "signing_key")? != signer
            || issued_at < n(&payload, "issued_at")?
        {
            return Err(InstallRecoveryError::Invalid);
        }
        let current_hash = sha256_hex(canonical(&self.current_policy)?.as_bytes());
        put(&mut payload, "structure", self.base_structure.clone())?;
        let version = n(&payload, "version")? + 1;
        put(&mut payload, "version", WireValue::Number(version as f64))?;
        let sequence = n(&self.checkpoint, "sequence")? + 1;
        put(&mut payload, "previous_policy", s(&current_hash))?;
        put(
            &mut payload,
            "effective_sequence",
            WireValue::Number(sequence as f64),
        )?;
        put(
            &mut payload,
            "issued_at",
            WireValue::Number(issued_at as f64),
        )?;
        let mut message = b"peerwork.secure.policy.v3\0".to_vec();
        message.extend_from_slice(canonical(&payload)?.as_bytes());
        let policy = o(vec![
            ("payload", payload.clone()),
            ("signature", s(&base64url(&key.sign(&message).to_bytes()))),
        ]);
        let policy_hash = sha256_hex(canonical(&policy)?.as_bytes());
        let mut context = o(vec![
            ("v", WireValue::Number(3.0)),
            ("workspace_id", field(&payload, "workspace_id")?.clone()),
            ("sequence", WireValue::Number(sequence as f64)),
            ("previous", field(&self.checkpoint, "head")?.clone()),
            ("policy_hash", s(&policy_hash)),
            ("epoch", field(&payload, "epoch")?.clone()),
            ("actor_id", s(&actor)),
            ("signing_key", s(&signer)),
            ("command_id", s(operation_id)),
            ("action_id", s("secure.recover")),
            ("instance_id", WireValue::Null),
            ("issued_at", WireValue::Number(issued_at as f64)),
            ("delegation", WireValue::Null),
            (
                "protocol_format_ceiling",
                field(&payload, "protocol_format_ceiling")?.clone(),
            ),
            ("recovery", self.recovery.clone()),
            (
                "structure",
                o(vec![
                    ("v", WireValue::Number(1.0)),
                    ("mode", s("SNAPSHOT_BEGIN")),
                    ("records", WireValue::Array(vec![])),
                    ("heads", WireValue::Array(vec![])),
                    ("snapshot", self.snapshot.clone()),
                ]),
            ),
        ]);
        if let Some(guard) = crate::guard_time::administrative_guard_context(&payload)
            .map_err(|_| InstallRecoveryError::Invalid)?
        {
            put(&mut context, "guard_time", guard)?;
        }
        Ok((policy, context))
    }
    pub fn prepare(
        &self,
        key: &SigningKey,
        epoch_key: &[u8; 32],
        operation_id: &str,
        issued_at: u64,
    ) -> Result<(Vec<u8>, String, String), InstallRecoveryError> {
        let (policy, context) = self.expected_fields(key, operation_id, issued_at)?;
        let payload = field(&policy, "payload")?;
        let actor = text(payload, "owner_id")?;
        let signer = text(payload, "signing_key")?;
        let policy_hash = sha256_hex(canonical(&policy)?.as_bytes());
        let sequence = n(&context, "sequence")?;
        let operation = o(vec![
            ("v", WireValue::Number(1.0)),
            ("kind", s("ADMIN")),
            ("input", o(vec![])),
            ("objects", WireValue::Array(vec![])),
        ]);
        let commit = sign_private_commit(
            &context,
            canonical(&operation)?.as_bytes(),
            epoch_key,
            key,
            &crate::prepared_secure_request::SecureCommitRequestPins {
                actor_id: &actor,
                signing_key: &signer,
                workspace_id: &text(&payload, "workspace_id")?,
                policy_hash: &policy_hash,
                sequence,
                previous: Some(&text(&self.checkpoint, "head")?),
                epoch: n(&payload, "epoch")?,
                mode: "PRIVATE",
                version: 3,
                protocol_format_ceiling: Some(n(&payload, "protocol_format_ceiling")?),
            },
        )
        .map_err(|_| InstallRecoveryError::Invalid)?;
        let wire = format!(
            "{{\"commit\":{commit},\"policy_update\":{}}}",
            canonical(&policy)?
        )
        .into_bytes();
        if wire.len() > 220_000 {
            return Err(InstallRecoveryError::Invalid);
        }
        Ok((wire, sha256_hex(commit.as_bytes()), policy_hash))
    }
    pub fn verify_saved(
        &self,
        wire: &[u8],
        key: &SigningKey,
        epoch_key: &[u8; 32],
        operation_id: &str,
        issued_at: u64,
    ) -> Result<(String, String), InstallRecoveryError> {
        use crate::{
            crypto::verify_secure_signed_wire,
            e2ee::{open_content_wire, SealedContent},
        };
        let (expected_policy, expected_context) =
            self.expected_fields(key, operation_id, issued_at)?;
        let request = parse_wire_json_bounded(wire, 64, 220_000)
            .map_err(|_| InstallRecoveryError::Invalid)?;
        if request.object_len() != Some(2)
            || canonical(field(&request, "policy_update")?)? != canonical(&expected_policy)?
        {
            return Err(InstallRecoveryError::Invalid);
        }
        let commit = field(&request, "commit")?;
        let commit_wire = canonical(commit)?;
        let signer = base64url(&key.verifying_key().to_bytes());
        if !verify_secure_signed_wire(commit_wire.as_bytes(), "peerwork.secure.commit.v1", &signer)
            .map_err(|_| InstallRecoveryError::Invalid)?
        {
            return Err(InstallRecoveryError::Invalid);
        }
        let payload = field(commit, "payload")?;
        let WireValue::Object(fields) = payload else {
            return Err(InstallRecoveryError::Invalid);
        };
        let context = WireValue::Object(
            fields
                .iter()
                .filter(|(key, _)| {
                    !["body", "mode"]
                        .iter()
                        .any(|name| key.iter().copied().eq(name.encode_utf16()))
                })
                .cloned()
                .collect(),
        );
        if text(payload, "mode")? != "PRIVATE"
            || canonical(&context)? != canonical(&expected_context)?
        {
            return Err(InstallRecoveryError::Invalid);
        }
        let sealed: SealedContent = serde_json::from_str(&canonical(field(payload, "body")?)?)
            .map_err(|_| InstallRecoveryError::Invalid)?;
        let plain = zeroize::Zeroizing::new(
            open_content_wire(epoch_key, &sealed, canonical(&context)?.as_bytes())
                .map_err(|_| InstallRecoveryError::Invalid)?,
        );
        let operation = o(vec![
            ("v", WireValue::Number(1.0)),
            ("kind", s("ADMIN")),
            ("input", o(vec![])),
            ("objects", WireValue::Array(vec![])),
        ]);
        if plain.as_slice() != canonical(&operation)?.as_bytes() {
            return Err(InstallRecoveryError::Invalid);
        }
        Ok((
            sha256_hex(commit_wire.as_bytes()),
            sha256_hex(canonical(&expected_policy)?.as_bytes()),
        ))
    }
}

/// All complete signatures, guard attestations, content and predecessor pins
/// are checked before an invalid candidate can become a recovery proposal.
pub fn inspect_invalid_install_recovery(
    prior: &ReplayedSecureJournal,
    input: JournalReplayInput<'_>,
    limits: JournalReplayLimits,
    proofs: &HashMap<String, Vec<u8>>,
    begin_id: &str,
    begin_hash: &str,
) -> Result<InstallRecoveryCandidate, InstallRecoveryError> {
    let owner = OwnerPin {
        actor_id: input.owner_actor_id,
        signing_key: input.owner_signing_key,
    };
    let floor = CheckpointPin {
        sequence: prior.sequence(),
        head: prior.head(),
        policy_hash: prior.policy_hash(),
    };
    let chain = scan_signed_chain_headers_with_limit(
        input.policy_wires,
        input.commit_wires,
        input.checkpoint_wire,
        input.workspace_id,
        Some(&owner),
        Some(&floor),
        limits.max_commits(),
    )
    .map_err(|_| InstallRecoveryError::Invalid)?;
    if prior.workspace_id() != input.workspace_id
        || prior.owner_actor_id() != input.owner_actor_id
        || prior.owner_signing_key() != input.owner_signing_key
    {
        return Err(InstallRecoveryError::Invalid);
    }
    let policy_wires = input.policy_wires;
    let commits = input.commit_wires;
    let checkpoint_wire = input.checkpoint_wire;
    match replay_secure_journal_exact_with_guard_time_attestations_and_limits(
        input,
        limits,
        Some(proofs),
    ) {
        Ok(verified) => return Ok(InstallRecoveryCandidate::Verified(verified)),
        Err(JournalReplayError::Detailed {
            class: "content",
            sequence: Some(seq),
            check: "object.size",
        }) if seq == prior.sequence() + 1 && seq == chain.sequence => {}
        Err(JournalReplayError::Detailed {
            class,
            sequence,
            check,
        }) => {
            return Err(InstallRecoveryError::Verification {
                class,
                check,
                sequence,
            })
        }
        _ => return Err(InstallRecoveryError::Invalid),
    }
    let last = commits.last().ok_or(InstallRecoveryError::Invalid)?;
    let commit =
        parse_wire_json_bounded(last, 64, 196_608).map_err(|_| InstallRecoveryError::Invalid)?;
    let context = field(&commit, "payload")?;
    if text(context, "command_id")? != begin_id
        || text(context, "action_id")? != "secure.structure.begin"
        || sha256_hex(last) != begin_hash
    {
        return Err(InstallRecoveryError::Invalid);
    }
    let find_policy = |hash: &str| -> Result<WireValue, InstallRecoveryError> {
        let wire = policy_wires
            .iter()
            .find(|w| sha256_hex(w) == hash)
            .ok_or(InstallRecoveryError::Invalid)?;
        parse_wire_json_bounded(wire, 64, 196_608).map_err(|_| InstallRecoveryError::Invalid)
    };
    let current_policy = find_policy(&chain.policy_hash)?;
    let base_policy = find_policy(prior.policy_hash())?;
    let current = field(&current_policy, "payload")?;
    let base = field(&base_policy, "payload")?;
    if n(current, "v")? != 3
        || n(base, "v")? != 3
        || text(current, "visibility")? != "PRIVATE"
        || text(base, "structure_mode")? != "STRUCTURED"
    {
        return Err(InstallRecoveryError::Invalid);
    }
    let checkpoint = parse_wire_json_bounded(checkpoint_wire, 32, 8192)
        .map_err(|_| InstallRecoveryError::Invalid)?;
    let base_cp = o(vec![
        ("v", WireValue::Number(1.0)),
        ("workspace_id", s(prior.workspace_id())),
        ("owner_id", s(prior.owner_actor_id())),
        ("owner_key", s(prior.owner_signing_key())),
        ("sequence", WireValue::Number(prior.sequence() as f64)),
        (
            "head",
            s(prior.head().ok_or(InstallRecoveryError::Invalid)?),
        ),
        ("policy_hash", s(prior.policy_hash())),
    ]);
    let excluded = WireValue::Array(vec![o(vec![
        ("sequence", WireValue::Number(chain.sequence as f64)),
        ("hash", s(begin_hash)),
    ])]);
    let recovery = o(vec![
        ("v", WireValue::Number(1.0)),
        ("reason", s("INVALID_ENCRYPTED_OPERATION")),
        ("base", base_cp.clone()),
        ("through", checkpoint.clone()),
        (
            "excluded_root",
            s(&sha256_hex(canonical(&excluded)?.as_bytes())),
        ),
    ]);
    let structure = field(base, "structure")?.clone();
    let snapshot = plan_public_install_snapshot(prior.objects(), &structure, &base_cp)
        .map_err(|_| InstallRecoveryError::Invalid)?
        .snapshot()
        .clone();
    let report = o(vec![
        ("schema", s("peerwork.install-recovery-plan.v1")),
        ("original_begin_id", s(begin_id)),
        ("recovery", recovery.clone()),
        (
            "target_structure_hash",
            s(&sha256_hex(canonical(&structure)?.as_bytes())),
        ),
        ("new_begin_required", WireValue::Bool(true)),
        ("submitted", WireValue::Bool(false)),
    ]);
    let review_hash = sha256_hex(canonical(&report)?.as_bytes());
    let mut report = report;
    put(&mut report, "review_hash", s(&review_hash))?;
    Ok(InstallRecoveryCandidate::Invalid(
        CheckedInvalidInstallRecovery {
            report_json: canonical(&report)?,
            review_hash,
            current_policy,
            base_structure: structure,
            recovery,
            snapshot,
            checkpoint,
        },
    ))
}
