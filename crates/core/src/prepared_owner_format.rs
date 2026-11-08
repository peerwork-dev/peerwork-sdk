//! Owner-only signed format transitions. This author does not establish source
//! authority: callers must supply the current policy/checkpoint from complete
//! authenticated replay and persist the returned exact packet before POST.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{open_content_wire, SealedContent},
    migration_fragments::assert_protocol_format_ceiling,
    prepared_secure_author::sign_private_commit,
    prepared_secure_request::SecureCommitRequestPins,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFormatTransitionKind {
    UpgradeWireV3,
    RaisePrivateCeilingTwo,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnerFormatPrepareError {
    #[error("format transition source, owner, or policy is invalid")]
    Invalid,
    #[error("format transition packet exceeds resource budget")]
    Resource,
    #[error("format transition signing or encryption failed")]
    Author,
}

pub struct PreparedOwnerFormatTransition {
    request_wire: Vec<u8>,
    commit_hash: String,
    policy_hash: String,
}

impl PreparedOwnerFormatTransition {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
}

fn string(value: &WireValue, key: &str) -> Result<String, OwnerFormatPrepareError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(OwnerFormatPrepareError::Invalid)
}
fn number(value: &WireValue, key: &str) -> Result<u64, OwnerFormatPrepareError> {
    let n = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(OwnerFormatPrepareError::Invalid)?;
    if !n.is_finite() || n < 0.0 || n > 9_007_199_254_740_991.0 || n.fract() != 0.0 {
        return Err(OwnerFormatPrepareError::Invalid);
    }
    Ok(n as u64)
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn s(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn obj(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}
fn set(value: &mut WireValue, key: &str, next: WireValue) -> Result<(), OwnerFormatPrepareError> {
    let WireValue::Object(fields) = value else {
        return Err(OwnerFormatPrepareError::Invalid);
    };
    if let Some((_, slot)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(key.encode_utf16()))
    {
        *slot = next;
    } else {
        fields.push((key.encode_utf16().collect(), next));
    }
    Ok(())
}

/// The runtime must separately prove that `signed_policy_wire` and
/// `checkpoint_wire` are the current complete origin-bound replay result, that
/// every retained protocol format is ceiling-one eligible, and that there is
/// no in-flight Owner intent or pending epoch transition.
#[allow(clippy::too_many_arguments)]
pub fn prepare_owner_private_format_transition(
    kind: OwnerFormatTransitionKind,
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    epoch_key: &[u8; 32],
    signer: &SigningKey,
    command_id: &str,
    issued_at_ms: u64,
) -> Result<PreparedOwnerFormatTransition, OwnerFormatPrepareError> {
    let bad = || OwnerFormatPrepareError::Invalid;
    assert_protocol_format_ceiling(prior_objects, 1).map_err(|_| bad())?;
    if !token(command_id) || issued_at_ms > 9_007_199_254_740_991 {
        return Err(bad());
    }
    let signed = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let checkpoint = parse_wire_json_bounded(checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let policy = signed.get("payload").ok_or_else(bad)?;
    let policy_wire = canonical_wire_value(&signed, Path::SecureArtifact).map_err(|_| bad())?;
    let owner_key = base64url(&signer.verifying_key().to_bytes());
    let owner_actor = actor_id(&signer.verifying_key().to_bytes());
    let workspace_id = string(policy, "workspace_id")?;
    let old_v = number(policy, "v")?;
    let epoch = number(policy, "epoch")?;
    let sequence = number(&checkpoint, "sequence")?
        .checked_add(1)
        .ok_or_else(bad)?;
    let old_policy_hash = sha256_hex(policy_wire.as_bytes());
    let old_head = string(&checkpoint, "head")?;
    if !verify_secure_signed_wire(
        policy_wire.as_bytes(),
        "peerwork.secure.policy.v1",
        &owner_key,
    )
    .map_err(|_| bad())?
        || string(policy, "visibility")? != "PRIVATE"
        || string(policy, "owner_id")? != owner_actor
        || string(policy, "signing_key")? != owner_key
        || string(&checkpoint, "workspace_id")? != workspace_id
        || string(&checkpoint, "owner_id")? != owner_actor
        || string(&checkpoint, "owner_key")? != owner_key
        || string(&checkpoint, "policy_hash")? != old_policy_hash
        || !token(&workspace_id)
        || old_head.len() != 64
        || !old_head
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || epoch == 0
        || number(&checkpoint, "v")? != 1
    {
        return Err(bad());
    }
    let (action, input) = match kind {
        OwnerFormatTransitionKind::UpgradeWireV3 => {
            if !matches!(old_v, 1 | 2) {
                return Err(bad());
            }
            ("secure.protocol-format.upgrade", obj(vec![]))
        }
        OwnerFormatTransitionKind::RaisePrivateCeilingTwo => {
            if old_v != 3 || number(policy, "protocol_format_ceiling")? != 1 {
                return Err(bad());
            }
            (
                "secure.protocol-format.raise",
                obj(vec![
                    ("from", WireValue::Number(1.0)),
                    ("to", WireValue::Number(2.0)),
                ]),
            )
        }
    };
    let mut next_policy = policy.clone();
    if kind == OwnerFormatTransitionKind::UpgradeWireV3 {
        set(&mut next_policy, "v", WireValue::Number(3.0))?;
        set(
            &mut next_policy,
            "protocol_format_ceiling",
            WireValue::Number(1.0),
        )?;
        set(
            &mut next_policy,
            "structure_mode",
            s(if old_v == 2 { "STRUCTURED" } else { "NONE" }),
        )?;
    } else {
        set(
            &mut next_policy,
            "protocol_format_ceiling",
            WireValue::Number(2.0),
        )?;
    }
    set(
        &mut next_policy,
        "version",
        WireValue::Number(number(policy, "version")?.checked_add(1).ok_or_else(bad)? as f64),
    )?;
    set(&mut next_policy, "previous_policy", s(&old_policy_hash))?;
    set(
        &mut next_policy,
        "effective_sequence",
        WireValue::Number(sequence as f64),
    )?;
    set(
        &mut next_policy,
        "issued_at",
        WireValue::Number(issued_at_ms as f64),
    )?;
    let payload_wire =
        canonical_wire_value(&next_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let mut message = Zeroizing::new(Vec::with_capacity(payload_wire.len() + 32));
    message.extend_from_slice(b"peerwork.secure.policy.v3\0");
    message.extend_from_slice(payload_wire.as_bytes());
    let new_policy = obj(vec![
        ("payload", next_policy.clone()),
        (
            "signature",
            s(&base64url(&signer.sign(&message).to_bytes())),
        ),
    ]);
    let new_policy_wire =
        canonical_wire_value(&new_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let new_policy_hash = sha256_hex(new_policy_wire.as_bytes());
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", s("ADMIN")),
        ("input", input),
        ("objects", WireValue::Array(vec![])),
    ]);
    let operation_wire =
        canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| bad())?;
    let mut context = vec![
        ("v", WireValue::Number(3.0)),
        ("workspace_id", s(&workspace_id)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&old_head)),
        ("policy_hash", s(&new_policy_hash)),
        ("epoch", WireValue::Number(epoch as f64)),
        ("actor_id", s(&owner_actor)),
        ("signing_key", s(&owner_key)),
        ("command_id", s(command_id)),
        ("action_id", s(action)),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at_ms as f64)),
        ("delegation", WireValue::Null),
        (
            "protocol_format_ceiling",
            WireValue::Number(
                if kind == OwnerFormatTransitionKind::RaisePrivateCeilingTwo {
                    2.0
                } else {
                    1.0
                },
            ),
        ),
    ];
    if next_policy
        .get("structure_mode")
        .and_then(WireValue::as_string)
        .as_deref()
        == Some("STRUCTURED")
    {
        context.push((
            "structure",
            obj(vec![
                ("v", WireValue::Number(1.0)),
                ("mode", s("DELTA")),
                ("records", WireValue::Array(vec![])),
                ("heads", WireValue::Array(vec![])),
            ]),
        ));
    }
    if next_policy.get("guard_time").is_some() {
        context.push((
            "guard_time",
            crate::guard_time::GuardTimeContextV1::universal().to_wire(),
        ));
    }
    let commit = sign_private_commit(
        &obj(context),
        operation_wire.as_bytes(),
        epoch_key,
        signer,
        &SecureCommitRequestPins {
            actor_id: &owner_actor,
            signing_key: &owner_key,
            workspace_id: &workspace_id,
            policy_hash: &new_policy_hash,
            sequence,
            previous: Some(&old_head),
            epoch,
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(
                if kind == OwnerFormatTransitionKind::RaisePrivateCeilingTwo {
                    2
                } else {
                    1
                },
            ),
        },
    )
    .map_err(|_| OwnerFormatPrepareError::Author)?;
    let commit_hash = sha256_hex(commit.as_bytes());
    let request_wire =
        format!("{{\"commit\":{commit},\"policy_update\":{new_policy_wire}}}").into_bytes();
    if request_wire.len() > 220_000 {
        return Err(OwnerFormatPrepareError::Resource);
    }
    Ok(PreparedOwnerFormatTransition {
        request_wire,
        commit_hash,
        policy_hash: new_policy_hash,
    })
}

/// Reprove a persisted encrypted request against the exact old replay source.
/// Fresh authoring is used only to recompute deterministic policy/context;
/// the saved ciphertext/nonce remain the sole bytes returned for retry.
#[allow(clippy::too_many_arguments)]
pub fn verify_saved_owner_private_format_transition(
    saved_request_wire: &[u8],
    kind: OwnerFormatTransitionKind,
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    epoch_key: &[u8; 32],
    signer: &SigningKey,
    command_id: &str,
    issued_at_ms: u64,
) -> Result<PreparedOwnerFormatTransition, OwnerFormatPrepareError> {
    let bad = || OwnerFormatPrepareError::Invalid;
    if saved_request_wire.is_empty() || saved_request_wire.len() > 220_000 {
        return Err(bad());
    }
    let expected = prepare_owner_private_format_transition(
        kind,
        signed_policy_wire,
        checkpoint_wire,
        prior_objects,
        epoch_key,
        signer,
        command_id,
        issued_at_ms,
    )?;
    let saved = parse_wire_json_bounded(saved_request_wire, 64, 220_000).map_err(|_| bad())?;
    let fresh = parse_wire_json_bounded(expected.request_wire(), 64, 220_000).map_err(|_| bad())?;
    if saved.object_len() != Some(2) || saved.get("policy_update") != fresh.get("policy_update") {
        return Err(bad());
    }
    let saved_commit = saved.get("commit").ok_or_else(bad)?;
    let fresh_commit = fresh.get("commit").ok_or_else(bad)?;
    let saved_commit_wire =
        canonical_wire_value(saved_commit, Path::SecureArtifact).map_err(|_| bad())?;
    let owner_key = base64url(&signer.verifying_key().to_bytes());
    if !verify_secure_signed_wire(
        saved_commit_wire.as_bytes(),
        "peerwork.secure.commit.v3",
        &owner_key,
    )
    .map_err(|_| bad())?
    {
        return Err(bad());
    }
    fn context(payload: &WireValue) -> Result<WireValue, OwnerFormatPrepareError> {
        let WireValue::Object(fields) = payload else {
            return Err(OwnerFormatPrepareError::Invalid);
        };
        Ok(WireValue::Object(
            fields
                .iter()
                .filter(|(name, _)| {
                    !name.iter().copied().eq("mode".encode_utf16())
                        && !name.iter().copied().eq("body".encode_utf16())
                })
                .cloned()
                .collect(),
        ))
    }
    let saved_payload = saved_commit.get("payload").ok_or_else(bad)?;
    let fresh_payload = fresh_commit.get("payload").ok_or_else(bad)?;
    if saved_payload.get("mode") != Some(&s("PRIVATE"))
        || context(saved_payload)? != context(fresh_payload)?
    {
        return Err(bad());
    }
    let saved_body = canonical_wire_value(
        saved_payload.get("body").ok_or_else(bad)?,
        Path::SecureArtifact,
    )
    .map_err(|_| bad())?;
    let fresh_body = canonical_wire_value(
        fresh_payload.get("body").ok_or_else(bad)?,
        Path::SecureArtifact,
    )
    .map_err(|_| bad())?;
    let saved_sealed: SealedContent = serde_json::from_str(&saved_body).map_err(|_| bad())?;
    let fresh_sealed: SealedContent = serde_json::from_str(&fresh_body).map_err(|_| bad())?;
    let context_wire =
        canonical_wire_value(&context(saved_payload)?, Path::SecureArtifact).map_err(|_| bad())?;
    let saved_plain =
        open_content_wire(epoch_key, &saved_sealed, context_wire.as_bytes()).map_err(|_| bad())?;
    let fresh_plain =
        open_content_wire(epoch_key, &fresh_sealed, context_wire.as_bytes()).map_err(|_| bad())?;
    if saved_plain != fresh_plain
        || canonical_wire_value(&saved, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes()
            != saved_request_wire
    {
        return Err(bad());
    }
    Ok(PreparedOwnerFormatTransition {
        request_wire: saved_request_wire.to_vec(),
        commit_hash: sha256_hex(saved_commit_wire.as_bytes()),
        policy_hash: expected.policy_hash,
    })
}

/// PUBLIC Owner wire upgrade. The plaintext ADMIN operation is part of the
/// signed commit and is re-proved byte-for-byte before a saved retry. The
/// caller still must supply current complete origin-bound replay evidence.
#[allow(clippy::too_many_arguments)]
pub fn prepare_owner_public_format_upgrade(
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    signer: &SigningKey,
    command_id: &str,
    issued_at_ms: u64,
) -> Result<PreparedOwnerFormatTransition, OwnerFormatPrepareError> {
    let bad = || OwnerFormatPrepareError::Invalid;
    assert_protocol_format_ceiling(prior_objects, 1).map_err(|_| bad())?;
    if !token(command_id) || issued_at_ms > 9_007_199_254_740_991 {
        return Err(bad());
    }
    let signed = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let checkpoint = parse_wire_json_bounded(checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let policy = signed.get("payload").ok_or_else(bad)?;
    let policy_wire = canonical_wire_value(&signed, Path::SecureArtifact).map_err(|_| bad())?;
    let owner_key = base64url(&signer.verifying_key().to_bytes());
    let owner_actor = actor_id(&signer.verifying_key().to_bytes());
    let workspace_id = string(policy, "workspace_id")?;
    let old_v = number(policy, "v")?;
    let sequence = number(&checkpoint, "sequence")?
        .checked_add(1)
        .ok_or_else(bad)?;
    let old_policy_hash = sha256_hex(policy_wire.as_bytes());
    let old_head = string(&checkpoint, "head")?;
    if !verify_secure_signed_wire(
        policy_wire.as_bytes(),
        "peerwork.secure.policy.v1",
        &owner_key,
    )
    .map_err(|_| bad())?
        || string(policy, "visibility")? != "PUBLIC"
        || string(policy, "owner_id")? != owner_actor
        || string(policy, "signing_key")? != owner_key
        || !matches!(old_v, 1 | 2)
        || number(policy, "epoch")? != 0
        || string(&checkpoint, "workspace_id")? != workspace_id
        || string(&checkpoint, "owner_id")? != owner_actor
        || string(&checkpoint, "owner_key")? != owner_key
        || string(&checkpoint, "policy_hash")? != old_policy_hash
        || number(&checkpoint, "v")? != 1
        || !token(&workspace_id)
        || old_head.len() != 64
        || !old_head
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(bad());
    }
    let mut next_policy = policy.clone();
    set(&mut next_policy, "v", WireValue::Number(3.0))?;
    set(
        &mut next_policy,
        "protocol_format_ceiling",
        WireValue::Number(1.0),
    )?;
    let structured = old_v == 2;
    set(
        &mut next_policy,
        "structure_mode",
        s(if structured { "STRUCTURED" } else { "NONE" }),
    )?;
    set(
        &mut next_policy,
        "version",
        WireValue::Number(number(policy, "version")?.checked_add(1).ok_or_else(bad)? as f64),
    )?;
    set(&mut next_policy, "previous_policy", s(&old_policy_hash))?;
    set(
        &mut next_policy,
        "effective_sequence",
        WireValue::Number(sequence as f64),
    )?;
    set(
        &mut next_policy,
        "issued_at",
        WireValue::Number(issued_at_ms as f64),
    )?;
    let payload_wire =
        canonical_wire_value(&next_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let mut policy_message = Zeroizing::new(Vec::with_capacity(payload_wire.len() + 32));
    policy_message.extend_from_slice(b"peerwork.secure.policy.v3\0");
    policy_message.extend_from_slice(payload_wire.as_bytes());
    let next_signed_policy = obj(vec![
        ("payload", next_policy),
        (
            "signature",
            s(&base64url(&signer.sign(&policy_message).to_bytes())),
        ),
    ]);
    let next_policy_wire =
        canonical_wire_value(&next_signed_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let next_policy_hash = sha256_hex(next_policy_wire.as_bytes());
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", s("ADMIN")),
        ("input", obj(vec![])),
        ("objects", WireValue::Array(vec![])),
    ]);
    let mut payload_fields = vec![
        ("v", WireValue::Number(3.0)),
        ("workspace_id", s(&workspace_id)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&old_head)),
        ("policy_hash", s(&next_policy_hash)),
        ("epoch", WireValue::Number(0.0)),
        ("actor_id", s(&owner_actor)),
        ("signing_key", s(&owner_key)),
        ("command_id", s(command_id)),
        ("action_id", s("secure.protocol-format.upgrade")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at_ms as f64)),
        ("delegation", WireValue::Null),
        ("protocol_format_ceiling", WireValue::Number(1.0)),
    ];
    if structured {
        payload_fields.push((
            "structure",
            obj(vec![
                ("v", WireValue::Number(1.0)),
                ("mode", s("DELTA")),
                ("records", WireValue::Array(vec![])),
                ("heads", WireValue::Array(vec![])),
            ]),
        ));
    }
    payload_fields.push(("mode", s("PUBLIC")));
    payload_fields.push(("body", operation));
    let commit_payload = obj(payload_fields);
    let commit_payload_wire =
        canonical_wire_value(&commit_payload, Path::SecureArtifact).map_err(|_| bad())?;
    let mut commit_message = Zeroizing::new(Vec::with_capacity(commit_payload_wire.len() + 32));
    commit_message.extend_from_slice(b"peerwork.secure.commit.v3\0");
    commit_message.extend_from_slice(commit_payload_wire.as_bytes());
    let commit = obj(vec![
        ("payload", commit_payload),
        (
            "signature",
            s(&base64url(&signer.sign(&commit_message).to_bytes())),
        ),
    ]);
    let commit_wire = canonical_wire_value(&commit, Path::SecureArtifact).map_err(|_| bad())?;
    let commit_hash = sha256_hex(commit_wire.as_bytes());
    let request_wire =
        format!("{{\"commit\":{commit_wire},\"policy_update\":{next_policy_wire}}}").into_bytes();
    if request_wire.len() > 220_000 {
        return Err(OwnerFormatPrepareError::Resource);
    }
    Ok(PreparedOwnerFormatTransition {
        request_wire,
        commit_hash,
        policy_hash: next_policy_hash,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_saved_owner_public_format_upgrade(
    saved_request_wire: &[u8],
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    signer: &SigningKey,
    command_id: &str,
    issued_at_ms: u64,
) -> Result<PreparedOwnerFormatTransition, OwnerFormatPrepareError> {
    let expected = prepare_owner_public_format_upgrade(
        signed_policy_wire,
        checkpoint_wire,
        prior_objects,
        signer,
        command_id,
        issued_at_ms,
    )?;
    if saved_request_wire != expected.request_wire() {
        return Err(OwnerFormatPrepareError::Invalid);
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign_canonical;

    #[test]
    fn public_upgrade_is_cleartext_exact_and_refuses_private_source() {
        let signer = SigningKey::from_bytes(&[9; 32]);
        let actor = actor_id(&signer.verifying_key().to_bytes());
        let key = base64url(&signer.verifying_key().to_bytes());
        let workspace = base64url(&[3; 32]);
        let command = base64url(&[4; 32]);
        let old = serde_json::json!({"v":1,"workspace_id":workspace,"owner_id":actor,
            "signing_key":key,"visibility":"PUBLIC","epoch":0,"version":1,
            "issued_at":1000,"members":[],"previous_policy":null,"effective_sequence":1});
        let signed = serde_json::json!({"payload":old,
            "signature":sign_canonical("peerwork.secure.policy.v1", &old, &signer).unwrap()});
        let policy_wire = crate::canonical::canonical(&signed, Path::SecureArtifact).unwrap();
        let checkpoint = serde_json::json!({"v":1,"workspace_id":workspace,"owner_id":actor,
            "owner_key":key,"sequence":2,"head":"a".repeat(64),
            "policy_hash":sha256_hex(policy_wire.as_bytes())});
        let checkpoint_wire =
            crate::canonical::canonical(&checkpoint, Path::SecureArtifact).unwrap();
        let prepared = prepare_owner_public_format_upgrade(
            policy_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            &[],
            &signer,
            &command,
            2000,
        )
        .unwrap();
        let request: serde_json::Value = serde_json::from_slice(prepared.request_wire()).unwrap();
        assert_eq!(request["commit"]["payload"]["mode"], "PUBLIC");
        assert_eq!(request["commit"]["payload"]["epoch"], 0);
        assert_eq!(
            request["commit"]["payload"]["body"],
            serde_json::json!({"v":1,"kind":"ADMIN","input":{},"objects":[]})
        );
        assert_eq!(request["policy_update"]["payload"]["visibility"], "PUBLIC");
        assert_eq!(
            request["policy_update"]["payload"]["protocol_format_ceiling"],
            1
        );
        assert_eq!(
            request["policy_update"]["payload"]["structure_mode"],
            "NONE"
        );
        assert_eq!(
            verify_saved_owner_public_format_upgrade(
                prepared.request_wire(),
                policy_wire.as_bytes(),
                checkpoint_wire.as_bytes(),
                &[],
                &signer,
                &command,
                2000
            )
            .unwrap()
            .commit_hash(),
            prepared.commit_hash()
        );
        let mut altered = prepared.request_wire().to_vec();
        altered.push(b' ');
        assert!(matches!(
            verify_saved_owner_public_format_upgrade(
                &altered,
                policy_wire.as_bytes(),
                checkpoint_wire.as_bytes(),
                &[],
                &signer,
                &command,
                2000
            ),
            Err(OwnerFormatPrepareError::Invalid)
        ));
        let mut private = old.clone();
        private["visibility"] = serde_json::json!("PRIVATE");
        private["epoch"] = serde_json::json!(1);
        let signed_private = serde_json::json!({"payload":private,
            "signature":sign_canonical("peerwork.secure.policy.v1", &private, &signer).unwrap()});
        let private_wire =
            crate::canonical::canonical(&signed_private, Path::SecureArtifact).unwrap();
        assert!(matches!(
            prepare_owner_public_format_upgrade(
                private_wire.as_bytes(),
                checkpoint_wire.as_bytes(),
                &[],
                &signer,
                &command,
                2000
            ),
            Err(OwnerFormatPrepareError::Invalid)
        ));
    }

    #[test]
    fn old_private_policy_upgrade_and_saved_packet_are_exact() {
        let signer = SigningKey::from_bytes(&[9; 32]);
        let actor = actor_id(&signer.verifying_key().to_bytes());
        let key = base64url(&signer.verifying_key().to_bytes());
        let workspace = base64url(&[3; 32]);
        let command = base64url(&[4; 32]);
        let old = serde_json::json!({"v":1,"workspace_id":workspace,"owner_id":actor,
            "signing_key":key,"visibility":"PRIVATE","epoch":1,"version":1,
            "issued_at":1000,"members":[],"previous_policy":null,"effective_sequence":1});
        let signed = serde_json::json!({"payload":old,
            "signature":sign_canonical("peerwork.secure.policy.v1", &old, &signer).unwrap()});
        let policy_wire = crate::canonical::canonical(&signed, Path::SecureArtifact).unwrap();
        let checkpoint = serde_json::json!({"v":1,"workspace_id":workspace,"owner_id":actor,
            "owner_key":key,"sequence":2,"head":"a".repeat(64),
            "policy_hash":sha256_hex(policy_wire.as_bytes())});
        let checkpoint_wire =
            crate::canonical::canonical(&checkpoint, Path::SecureArtifact).unwrap();
        let prepared = prepare_owner_private_format_transition(
            OwnerFormatTransitionKind::UpgradeWireV3,
            policy_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            &[],
            &[7; 32],
            &signer,
            &command,
            2000,
        )
        .unwrap();
        let verified = verify_saved_owner_private_format_transition(
            prepared.request_wire(),
            OwnerFormatTransitionKind::UpgradeWireV3,
            policy_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            &[],
            &[7; 32],
            &signer,
            &command,
            2000,
        )
        .unwrap();
        assert_eq!(verified.request_wire(), prepared.request_wire());
        assert_eq!(verified.commit_hash(), prepared.commit_hash());
        assert_eq!(verified.policy_hash(), prepared.policy_hash());
        let request: serde_json::Value = serde_json::from_slice(prepared.request_wire()).unwrap();
        assert_eq!(request["policy_update"]["payload"]["v"], 3);
        assert_eq!(
            request["policy_update"]["payload"]["protocol_format_ceiling"],
            1
        );
        assert_eq!(
            request["policy_update"]["payload"]["structure_mode"],
            "NONE"
        );
        assert!(verify_saved_owner_private_format_transition(
            prepared.request_wire(),
            OwnerFormatTransitionKind::RaisePrivateCeilingTwo,
            policy_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            &[],
            &[7; 32],
            &signer,
            &command,
            2000
        )
        .is_err());
        let mut changed = prepared.request_wire().to_vec();
        let last = changed.len() - 1;
        changed[last] = b' ';
        assert!(verify_saved_owner_private_format_transition(
            &changed,
            OwnerFormatTransitionKind::UpgradeWireV3,
            policy_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            &[],
            &[7; 32],
            &signer,
            &command,
            2000
        )
        .is_err());

        // The pinned nested-format vector carries a protocol in archived
        // public history. A v1 manifest is an eligible old prefix; changing
        // only the two nested manifest format fields to v2 must refuse this
        // same otherwise-valid PRIVATE Owner transition before authoring.
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/migration-format-vectors.json"
        ))
        .unwrap();
        let archived_v2 = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "archive_v2_denied")
            .unwrap()["objects"]
            .clone();
        let mut archived_v1 = archived_v2.clone();
        let nested = &mut archived_v1[0]["value"]["payload"]["body"]["objects"][0]["value"];
        nested["manifest"]
            .as_object_mut()
            .unwrap()
            .remove("format_version");
        nested["resolved_manifest"]
            .as_object_mut()
            .unwrap()
            .remove("format_version");
        let parse_objects = |value: &serde_json::Value| {
            let bytes = serde_json::to_vec(value).unwrap();
            let WireValue::Array(rows) = parse_wire_json_bounded(&bytes, 64, 1024 * 1024).unwrap()
            else {
                panic!("archive vector must contain objects")
            };
            rows
        };
        let eligible = parse_objects(&archived_v1);
        let forbidden = parse_objects(&archived_v2);
        let with_old_archive = prepare_owner_private_format_transition(
            OwnerFormatTransitionKind::UpgradeWireV3,
            policy_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            &eligible,
            &[7; 32],
            &signer,
            &command,
            2000,
        )
        .unwrap();
        assert_eq!(with_old_archive.policy_hash(), prepared.policy_hash());
        assert!(matches!(
            prepare_owner_private_format_transition(
                OwnerFormatTransitionKind::UpgradeWireV3,
                policy_wire.as_bytes(),
                checkpoint_wire.as_bytes(),
                &forbidden,
                &[7; 32],
                &signer,
                &command,
                2000,
            ),
            Err(OwnerFormatPrepareError::Invalid)
        ));
        assert!(matches!(
            verify_saved_owner_private_format_transition(
                prepared.request_wire(),
                OwnerFormatTransitionKind::UpgradeWireV3,
                policy_wire.as_bytes(),
                checkpoint_wire.as_bytes(),
                &forbidden,
                &[7; 32],
                &signer,
                &command,
                2000,
            ),
            Err(OwnerFormatPrepareError::Invalid)
        ));
    }
}
