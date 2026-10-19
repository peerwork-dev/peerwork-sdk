//! Owner-only guard-time enablement with explicit disclosure and service pins. This author does not establish source
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnerFormatPrepareError {
    #[error("guard-time activation source, owner, or policy is invalid")]
    Invalid,
    #[error("guard-time activation packet exceeds resource budget")]
    Resource,
    #[error("guard-time activation signing or encryption failed")]
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
/// every retained protocol respects the current format ceiling, and that there is
/// no in-flight Owner intent or pending epoch transition.
#[allow(clippy::too_many_arguments)]
pub fn prepare_owner_guard_time_enable(
    guard_policy_wire: &[u8],
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    epoch_key: &[u8; 32],
    signer: &SigningKey,
    command_id: &str,
    issued_at_ms: u64,
) -> Result<PreparedOwnerFormatTransition, OwnerFormatPrepareError> {
    let bad = || OwnerFormatPrepareError::Invalid;

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
    if old_v != 3 || policy.get("guard_time").is_some() {
        return Err(bad());
    }
    let ceiling = number(policy, "protocol_format_ceiling")?;
    if !matches!(ceiling, 1 | 2)
        || sequence > 9_007_199_254_740_991
        || number(policy, "version")? >= 9_007_199_254_740_991
    {
        return Err(bad());
    }
    assert_protocol_format_ceiling(prior_objects, ceiling).map_err(|_| bad())?;
    let guard = parse_wire_json_bounded(guard_policy_wire, 8, 8192).map_err(|_| bad())?;
    crate::guard_time::parse_guard_time_policy(&guard).map_err(|_| bad())?;
    let action = "secure.guard-time.enable";
    let input = obj(vec![]);
    let mut next_policy = policy.clone();
    set(&mut next_policy, "guard_time", guard)?;
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
        ("protocol_format_ceiling", WireValue::Number(ceiling as f64)),
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
            protocol_format_ceiling: Some(ceiling),
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
pub fn verify_saved_owner_guard_time_enable(
    saved_request_wire: &[u8],
    guard_policy_wire: &[u8],
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
    let expected = prepare_owner_guard_time_enable(
        guard_policy_wire,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign_canonical;
    #[test]
    fn owner_guard_time_enable_exact_packet_reproof_and_pins() {
        let signer = SigningKey::from_bytes(&[19; 32]);
        let actor = actor_id(&signer.verifying_key().to_bytes());
        let key = base64url(&signer.verifying_key().to_bytes());
        let workspace = base64url(&[13; 32]);
        let command = base64url(&[14; 32]);
        let old = serde_json::json!({"v":3,"workspace_id":workspace,"owner_id":actor,"signing_key":key,"visibility":"PRIVATE","epoch":1,"version":1,"issued_at":1000,"members":[],"previous_policy":null,"effective_sequence":1,"structure_mode":"NONE","protocol_format_ceiling":1});
        let signed = serde_json::json!({"payload":old,"signature":sign_canonical("peerwork.secure.policy.v3",&old,&signer).unwrap()});
        let old = crate::canonical::canonical(&signed, Path::SecureArtifact).unwrap();
        let checkpoint = serde_json::json!({"v":1,"workspace_id":workspace,"owner_id":actor,"owner_key":key,"sequence":2,"head":"a".repeat(64),"policy_hash":sha256_hex(old.as_bytes())});
        let checkpoint = crate::canonical::canonical(&checkpoint, Path::SecureArtifact).unwrap();
        let guard=serde_json::json!({"v":1,"mode":"ALL_COMMITS","audience":"guard-test","service_key":base64url(&[21;32]),"disclosure":"GUARD_WINDOW"}).to_string();
        let prepared = prepare_owner_guard_time_enable(
            guard.as_bytes(),
            old.as_bytes(),
            checkpoint.as_bytes(),
            &[],
            &[17; 32],
            &signer,
            &command,
            2000,
        )
        .unwrap();
        let verified = verify_saved_owner_guard_time_enable(
            prepared.request_wire(),
            guard.as_bytes(),
            old.as_bytes(),
            checkpoint.as_bytes(),
            &[],
            &[17; 32],
            &signer,
            &command,
            2000,
        )
        .unwrap();
        assert_eq!(verified.request_wire(), prepared.request_wire());
        let packet: serde_json::Value = serde_json::from_slice(prepared.request_wire()).unwrap();
        assert_eq!(
            packet["commit"]["payload"]["action_id"],
            "secure.guard-time.enable"
        );
        assert_eq!(
            packet["commit"]["payload"]["guard_time"],
            serde_json::json!({"v":1,"lower_ms":0,"upper_ms":9007199254740991u64})
        );
        assert_eq!(
            packet["policy_update"]["payload"]["guard_time"],
            serde_json::from_str::<serde_json::Value>(&guard).unwrap()
        );
        let wrong = guard.replace("guard-test", "wrong-service");
        assert!(verify_saved_owner_guard_time_enable(
            prepared.request_wire(),
            wrong.as_bytes(),
            old.as_bytes(),
            checkpoint.as_bytes(),
            &[],
            &[17; 32],
            &signer,
            &command,
            2000
        )
        .is_err());
        assert!(verify_saved_owner_guard_time_enable(
            prepared.request_wire(),
            guard.as_bytes(),
            old.as_bytes(),
            checkpoint.as_bytes(),
            &[],
            &[18; 32],
            &signer,
            &command,
            2000
        )
        .is_err());
        let mut changed = packet;
        changed["commit"]["signature"] = "a".repeat(86).into();
        assert!(verify_saved_owner_guard_time_enable(
            changed.to_string().as_bytes(),
            guard.as_bytes(),
            old.as_bytes(),
            checkpoint.as_bytes(),
            &[],
            &[17; 32],
            &signer,
            &command,
            2000
        )
        .is_err());
    }
}
