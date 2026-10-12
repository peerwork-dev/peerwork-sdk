//! Signed key-grant cryptographic material proof. This is not sufficient to
//! activate keys: full authenticated journal replay through the checkpoint,
//! configured HTTPS origin continuity, and recipient custody are separate.

use crate::{
    canonical::Path,
    crypto::{decode_base64url, verify_secure_signed_wire},
    e2ee::{hpke_open_wire, KeyBox},
    secure_chain::{scan_signed_chain_headers, OwnerPin},
    secure_keyring::SecretKeyring,
    secure_recipient::{RecipientCertificate, SecretRecipient},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_ARTIFACT: usize = 2 * 1024 * 1024;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("signed secure key grant, policy, recipient or keyring is invalid")]
    Invalid,
    #[error("key grant requires invitation or delegation proof not supplied")]
    RelatedProofRequired,
}

/// Caller-owned policy/journal bytes and owner pin must come from the
/// configured origin and persisted continuity. This verifier authenticates
/// crypto and header links but does not itself establish that provenance or
/// complete replay/effect authority.
pub struct GrantProofInput<'a> {
    pub policy_wires: &'a [&'a [u8]],
    pub commit_wires: &'a [&'a [u8]],
    pub checkpoint_wire: &'a [u8],
    pub grant_wire: &'a [u8],
    pub recipient_certificate_wire: &'a [u8],
    pub recipient: &'a SecretRecipient,
    pub workspace_id: &'a str,
    pub trusted_owner_actor: &'a str,
    pub trusted_owner_key: &'a str,
    pub now: u64,
}

/// Private-constructor proof of signed grant material, not an activation or
/// action grant. Runtime may stage this keyring but must wait for complete
/// replay/checkpoint and origin-bound custody proof before promoting it.
pub struct VerifiedGrantMaterial {
    keyring: SecretKeyring,
    workspace_id: String,
    policy_hash: String,
    epoch: u64,
    recipient_actor: String,
    recipient_key: String,
}

impl VerifiedGrantMaterial {
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn recipient_actor(&self) -> &str {
        &self.recipient_actor
    }
    pub fn recipient_key(&self) -> &str {
        &self.recipient_key
    }
    /// Trusted Rust composition only; this does not convey action authority.
    pub fn keyring(&self) -> &SecretKeyring {
        &self.keyring
    }
}

/// Verify the direct member/owner delivery path. Invitation and delegation
/// artifacts require additional signed related-proof checks and currently
/// fail closed. This is one bounded route, not the whole grant contract.
pub fn verify_direct_key_grant(
    input: GrantProofInput<'_>,
) -> Result<VerifiedGrantMaterial, GrantError> {
    let bad = || GrantError::Invalid;
    if input.now > MAX_SAFE || input.grant_wire.len() > MAX_ARTIFACT {
        return Err(bad());
    }
    let chain = scan_signed_chain_headers(
        input.policy_wires,
        input.commit_wires,
        input.checkpoint_wire,
        input.workspace_id,
        Some(&OwnerPin {
            actor_id: input.trusted_owner_actor,
            signing_key: input.trusted_owner_key,
        }),
        None,
    )
    .map_err(|_| bad())?;
    if chain.owner_id != input.trusted_owner_actor
        || chain.owner_key != input.trusted_owner_key
        || input.policy_wires.len() != chain.policy_hashes.len()
    {
        return Err(bad());
    }
    let grant =
        parse_wire_json_js_bounded(input.grant_wire, 64, MAX_ARTIFACT).map_err(|_| bad())?;
    let payload = envelope_payload(&grant)?;
    let policy_hash = string(payload, "policy_hash")?;
    let selected_index = chain
        .policy_hashes
        .iter()
        .position(|hash| hash == &policy_hash)
        .ok_or_else(bad)?;
    let selected = parse_wire_json_js_bounded(input.policy_wires[selected_index], 64, MAX_ARTIFACT)
        .map_err(|_| bad())?;
    let latest =
        parse_wire_json_js_bounded(input.policy_wires.last().ok_or_else(bad)?, 64, MAX_ARTIFACT)
            .map_err(|_| bad())?;
    let selected_payload = envelope_payload(&selected)?;
    let latest_payload = envelope_payload(&latest)?;
    let epoch = unsigned(selected_payload, "epoch")?;
    let issued = unsigned(payload, "issued_at")?;
    let recipient = parse_wire_json_js_bounded(input.recipient_certificate_wire, 32, 32_768)
        .map_err(|_| bad())?;
    let recipient_payload = envelope_payload(&recipient)?;
    let recipient_actor = string(recipient_payload, "actor_id")?;
    let recipient_key = string(recipient_payload, "signing_key")?;
    let cert_wire = canonical_wire_value(&recipient, Path::SecureArtifact).map_err(|_| bad())?;
    let cert: RecipientCertificate = serde_json::from_str(&cert_wire).map_err(|_| bad())?;
    input
        .recipient
        .verify_local_certificate(&cert, &recipient_actor, &recipient_key, issued)
        .map_err(|_| bad())?;
    if unsigned(payload, "v")? != 1
        || !token(&string(payload, "grant_id")?)
        || string(payload, "workspace_id")? != input.workspace_id
        || string(selected_payload, "workspace_id")? != input.workspace_id
        || string(payload, "policy_hash")? != chain.policy_hashes[selected_index]
        || unsigned(payload, "epoch")? != epoch
        || unsigned(latest_payload, "epoch")? != epoch
        || string(selected_payload, "owner_id")? != input.trusted_owner_actor
        || string(selected_payload, "signing_key")? != input.trusted_owner_key
        || string(latest_payload, "owner_id")? != input.trusted_owner_actor
        || string(latest_payload, "signing_key")? != input.trusted_owner_key
        || string(selected_payload, "visibility")? != "PRIVATE"
        || issued > input.now
        || !same(payload.get("recipient").ok_or_else(bad)?, &recipient)?
        || !matches!(payload.get("invite_id"), Some(WireValue::Null))
        || !matches!(payload.get("acceptance_hash"), Some(WireValue::Null))
        || !matches!(payload.get("delegation"), Some(WireValue::Null))
        || !has_member(latest_payload, &recipient_actor, &recipient_key, &recipient)?
    {
        return Err(bad());
    }
    let grantor_actor = string(payload, "actor_id")?;
    let grantor_key = string(payload, "signing_key")?;
    if !has_owner_member(selected_payload, &grantor_actor, &grantor_key)?
        || !verify_secure_signed_wire(
            input.grant_wire,
            "peerwork.secure.key-grant.v1",
            &grantor_key,
        )
        .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let box_value = payload.get("box").ok_or_else(bad)?;
    let box_wire = canonical_wire_value(box_value, Path::SecureArtifact).map_err(|_| bad())?;
    let key_box: KeyBox = serde_json::from_str(&box_wire).map_err(|_| bad())?;
    let WireValue::Object(fields) = payload else {
        return Err(bad());
    };
    let context = WireValue::Object(
        fields
            .iter()
            .filter(|(name, _)| name != &"box".encode_utf16().collect::<Vec<_>>())
            .cloned()
            .collect(),
    );
    let context_wire = canonical_wire_value(&context, Path::SecureArtifact).map_err(|_| bad())?;
    let mut opened = hpke_open_wire(
        input.recipient.private_bytes(),
        &key_box,
        context_wire.as_bytes(),
    )
    .map_err(|_| bad())?;
    let canonical_result = canonical_wire_value(&opened, Path::SecureArtifact).map_err(|_| bad());
    wipe_wire(&mut opened);
    let canonical = Zeroizing::new(canonical_result?);
    let keyring = SecretKeyring::parse_wire(canonical.as_bytes()).map_err(|_| bad())?;
    if keyring.workspace_id() != input.workspace_id
        || keyring.epochs().next().is_none()
        || keyring.epochs().count() > 1024
        || keyring.epochs().any(|item| item > epoch)
        || keyring.key_at(epoch).is_none()
    {
        return Err(bad());
    }
    Ok(VerifiedGrantMaterial {
        keyring,
        workspace_id: input.workspace_id.into(),
        policy_hash,
        epoch,
        recipient_actor,
        recipient_key,
    })
}

fn envelope_payload(value: &WireValue) -> Result<&WireValue, GrantError> {
    if value.object_len() != Some(2)
        || value
            .get("signature")
            .and_then(WireValue::as_string)
            .is_none()
    {
        return Err(GrantError::Invalid);
    }
    value.get("payload").ok_or(GrantError::Invalid)
}
fn string(value: &WireValue, name: &str) -> Result<String, GrantError> {
    value
        .get(name)
        .and_then(WireValue::as_string)
        .ok_or(GrantError::Invalid)
}
fn unsigned(value: &WireValue, name: &str) -> Result<u64, GrantError> {
    let number = value
        .get(name)
        .and_then(WireValue::as_number)
        .ok_or(GrantError::Invalid)?;
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 || number > MAX_SAFE as f64 {
        return Err(GrantError::Invalid);
    }
    Ok(number as u64)
}
fn token(value: &str) -> bool {
    value.len() == 43 && decode_base64url(value).is_ok_and(|bytes| bytes.len() == 32)
}
fn same(left: &WireValue, right: &WireValue) -> Result<bool, GrantError> {
    Ok(
        canonical_wire_value(left, Path::SecureArtifact).map_err(|_| GrantError::Invalid)?
            == canonical_wire_value(right, Path::SecureArtifact)
                .map_err(|_| GrantError::Invalid)?,
    )
}
fn members(policy: &WireValue) -> Result<&[WireValue], GrantError> {
    match policy.get("members") {
        Some(WireValue::Array(items)) => Ok(items),
        _ => Err(GrantError::Invalid),
    }
}
fn has_owner_member(policy: &WireValue, actor: &str, key: &str) -> Result<bool, GrantError> {
    for member in members(policy)? {
        let cert = member.get("certificate").ok_or(GrantError::Invalid)?;
        let cert_payload = envelope_payload(cert)?;
        if string(member, "actor_id")? == actor
            && string(member, "role")? == "OWNER"
            && string(cert_payload, "signing_key")? == key
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn has_member(
    policy: &WireValue,
    actor: &str,
    key: &str,
    cert: &WireValue,
) -> Result<bool, GrantError> {
    for member in members(policy)? {
        let saved = member.get("certificate").ok_or(GrantError::Invalid)?;
        if string(member, "actor_id")? == actor
            && string(envelope_payload(saved)?, "signing_key")? == key
            && same(saved, cert)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn wipe_wire(value: &mut WireValue) {
    match value {
        WireValue::String(units) => units.zeroize(),
        WireValue::Array(items) => items.iter_mut().for_each(wipe_wire),
        WireValue::Object(fields) => {
            for (name, item) in fields {
                name.zeroize();
                wipe_wire(item);
            }
        }
        WireValue::Null | WireValue::Bool(_) | WireValue::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn direct_ts_owner_grant_vector() {
        let Ok(path) = std::env::var("PEERWORK_GRANT_VECTOR") else {
            return; // Opt-in direct TS oracle, run by secure-grant-cross-open.mjs.
        };
        let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let decoded = Zeroizing::new(
            decode_base64url(vector["recipient_private"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(decoded.len(), 32);
        let mut private = Zeroizing::new([0u8; 32]);
        private.copy_from_slice(&decoded);
        let recipient = SecretRecipient::from_private(private).unwrap();
        let policy_wire = serde_json::to_vec(&vector["policy"]).unwrap();
        let checkpoint_wire = serde_json::to_vec(&vector["checkpoint"]).unwrap();
        let grant_wire = serde_json::to_vec(&vector["grant"]).unwrap();
        let certificate_wire = serde_json::to_vec(&vector["certificate"]).unwrap();
        let policy_refs: [&[u8]; 1] = [&policy_wire];
        let workspace = vector["workspace"].as_str().unwrap();
        let owner_actor = vector["owner_actor"].as_str().unwrap();
        let owner_key = vector["owner_key"].as_str().unwrap();
        let now = vector["now"].as_u64().unwrap();
        let verify = |grant: &[u8], certificate: &[u8], policies: &[&[u8]]| {
            verify_direct_key_grant(GrantProofInput {
                policy_wires: policies,
                commit_wires: &[],
                checkpoint_wire: &checkpoint_wire,
                grant_wire: grant,
                recipient_certificate_wire: certificate,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
            })
        };
        let verified = verify(&grant_wire, &certificate_wire, &policy_refs).unwrap();
        assert_eq!(verified.workspace_id(), workspace);
        assert_eq!(verified.epoch(), 1);
        assert_eq!(verified.recipient_actor(), owner_actor);
        assert_eq!(verified.recipient_key(), owner_key);
        assert!(verified.keyring().key_at(1).is_some());

        let mut bad_grant = vector["grant"].clone();
        bad_grant["payload"]["epoch"] = serde_json::json!(2);
        assert!(verify(
            &serde_json::to_vec(&bad_grant).unwrap(),
            &certificate_wire,
            &policy_refs
        )
        .is_err());
        bad_grant = vector["grant"].clone();
        bad_grant["payload"]["policy_hash"] = serde_json::json!("a".repeat(64));
        assert!(verify(
            &serde_json::to_vec(&bad_grant).unwrap(),
            &certificate_wire,
            &policy_refs
        )
        .is_err());
        let wrong_recipient = serde_json::to_vec(&vector["wrong_recipient"]).unwrap();
        assert!(verify(&grant_wire, &wrong_recipient, &policy_refs).is_err());
        bad_grant = vector["grant"].clone();
        bad_grant["signature"] = serde_json::json!("a".repeat(86));
        assert!(verify(
            &serde_json::to_vec(&bad_grant).unwrap(),
            &certificate_wire,
            &policy_refs
        )
        .is_err());
    }
}
