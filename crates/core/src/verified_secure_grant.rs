//! Signed key-grant cryptographic material proof. This is not sufficient to
//! activate keys: full authenticated journal replay through the checkpoint,
//! configured HTTPS origin continuity, and recipient custody are separate.

use crate::{
    canonical::Path,
    crypto::{decode_base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{hpke_open_wire, KeyBox},
    secure_chain::{scan_signed_chain_headers, OwnerPin},
    secure_keyring::SecretKeyring,
    secure_recipient::{RecipientCertificate, SecretRecipient},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use std::collections::HashSet;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_ARTIFACT: usize = 2 * 1024 * 1024;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const INVITATION_LIFETIME: u64 = 7 * 86_400_000;

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
    pub expected_invitation: Option<InvitationProofInput<'a>>,
    pub expected_delegation_wire: Option<&'a [u8]>,
    /// Configured runtime provenance, not inferred from the signed grant.
    pub expected_delegation_origin: Option<&'a str>,
    pub expected_delegation_audience: Option<&'a str>,
}

pub struct InvitationProofInput<'a> {
    pub offer_wire: &'a [u8],
    pub decision_wire: &'a [u8],
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

/// Verify signed direct, accepted-invitation, or delegated key delivery.
/// A matching full signed replay/checkpoint proof is still required before
/// any key material may be activated for content or action authoring.
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
    let visibility = string(selected_payload, "visibility")?;
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
        || !matches!(visibility.as_str(), "PRIVATE" | "PUBLIC")
        || (visibility == "PUBLIC" && epoch != 0)
        || (visibility == "PRIVATE" && epoch == 0)
        || issued > input.now
        || !same(payload.get("recipient").ok_or_else(bad)?, &recipient)?
    {
        return Err(bad());
    }
    let grantor_actor = string(payload, "actor_id")?;
    let grantor_key = string(payload, "signing_key")?;
    let grantor_role = member_role(selected_payload, &grantor_actor, &grantor_key)?;
    if grantor_role.is_none()
        || !verify_secure_signed_wire(
            input.grant_wire,
            "peerwork.secure.key-grant.v1",
            &grantor_key,
        )
        .map_err(|_| bad())?
    {
        return Err(bad());
    }
    match input.expected_invitation {
        Some(related) => verify_invitation(
            payload,
            related,
            &recipient,
            &recipient_actor,
            &recipient_key,
            input.workspace_id,
            input.trusted_owner_actor,
            input.trusted_owner_key,
            issued,
            grantor_role.as_deref() == Some("OWNER"),
        )?,
        None if matches!(payload.get("invite_id"), Some(WireValue::Null))
            && matches!(payload.get("acceptance_hash"), Some(WireValue::Null)) => {}
        None => return Err(GrantError::RelatedProofRequired),
    }
    match input.expected_delegation_wire {
        Some(related) => verify_delegation(
            payload,
            related,
            &recipient,
            &grantor_actor,
            &grantor_key,
            latest_payload,
            input.workspace_id,
            issued,
            input.now,
            input.expected_delegation_origin.ok_or_else(bad)?,
            input.expected_delegation_audience.ok_or_else(bad)?,
        )?,
        None if matches!(payload.get("delegation"), Some(WireValue::Null))
            && input.expected_delegation_origin.is_none()
            && input.expected_delegation_audience.is_none()
            && has_member(latest_payload, &recipient_actor, &recipient_key, &recipient)? => {}
        None if matches!(payload.get("delegation"), Some(WireValue::Null)) => return Err(bad()),
        None => return Err(GrantError::RelatedProofRequired),
    }
    if grantor_role.as_deref() != Some("OWNER") && input.expected_delegation_wire.is_none() {
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
        || (visibility == "PUBLIC" && keyring.epochs().next().is_some())
        || (visibility == "PRIVATE"
            && (keyring.epochs().next().is_none()
                || keyring.epochs().count() > 1024
                || keyring.epochs().any(|item| item > epoch)
                || keyring.key_at(epoch).is_none()))
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
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
fn member_role(policy: &WireValue, actor: &str, key: &str) -> Result<Option<String>, GrantError> {
    for member in members(policy)? {
        let cert = member.get("certificate").ok_or(GrantError::Invalid)?;
        let cert_payload = envelope_payload(cert)?;
        if string(member, "actor_id")? == actor && string(cert_payload, "signing_key")? == key {
            return Ok(Some(string(member, "role")?));
        }
    }
    Ok(None)
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
fn artifact_hash(value: &WireValue) -> Result<String, GrantError> {
    let wire =
        canonical_wire_value(value, Path::SecureArtifact).map_err(|_| GrantError::Invalid)?;
    Ok(sha256_hex(wire.as_bytes()))
}
fn signed_artifact(value: &WireValue, domain: &str, key: &str) -> Result<(), GrantError> {
    let wire =
        canonical_wire_value(value, Path::SecureArtifact).map_err(|_| GrantError::Invalid)?;
    if verify_secure_signed_wire(wire.as_bytes(), domain, key).map_err(|_| GrantError::Invalid)? {
        Ok(())
    } else {
        Err(GrantError::Invalid)
    }
}
fn related_artifact(wire: &[u8]) -> Result<WireValue, GrantError> {
    if wire.len() > MAX_ARTIFACT {
        return Err(GrantError::Invalid);
    }
    parse_wire_json_js_bounded(wire, 64, MAX_ARTIFACT).map_err(|_| GrantError::Invalid)
}
fn verify_invitation(
    grant: &WireValue,
    related: InvitationProofInput<'_>,
    recipient: &WireValue,
    recipient_actor: &str,
    recipient_key: &str,
    workspace: &str,
    owner_actor: &str,
    owner_key: &str,
    issued: u64,
    grantor_is_owner: bool,
) -> Result<(), GrantError> {
    if !grantor_is_owner {
        return Err(GrantError::Invalid);
    }
    let offer = related_artifact(related.offer_wire)?;
    let decision = related_artifact(related.decision_wire)?;
    let op = envelope_payload(&offer)?;
    let dp = envelope_payload(&decision)?;
    let start = unsigned(op, "issued_at")?;
    let end = unsigned(op, "expires_at")?;
    let decided = unsigned(dp, "issued_at")?;
    let invite = string(op, "invite_id")?;
    if unsigned(op, "v")? != 1
        || unsigned(dp, "v")? != 1
        || !token(&invite)
        || !token(&string(op, "workspace_id")?)
        || string(op, "workspace_id")? != workspace
        || string(op, "actor_id")? != owner_actor
        || string(op, "signing_key")? != owner_key
        || !hex_digest(&string(op, "policy_hash")?)
        || !valid_scopes(op.get("scopes").ok_or(GrantError::Invalid)?)?
        || end <= issued
        || start > issued
        || end
            .checked_sub(start)
            .is_none_or(|span| span > INVITATION_LIFETIME)
        || !same(op.get("recipient").ok_or(GrantError::Invalid)?, recipient)?
        || string(dp, "decision")? != "ACCEPT"
        || string(dp, "invite_id")? != invite
        || string(dp, "workspace_id")? != workspace
        || string(dp, "actor_id")? != recipient_actor
        || string(dp, "signing_key")? != recipient_key
        || string(dp, "offer_hash")? != artifact_hash(&offer)?
        || decided < start
        || decided >= end
        || decided > issued
        || string(grant, "invite_id")? != invite
        || string(grant, "acceptance_hash")? != artifact_hash(&decision)?
    {
        return Err(GrantError::Invalid);
    }
    signed_artifact(&offer, "peerwork.secure.invitation.v1", owner_key)?;
    signed_artifact(
        &decision,
        "peerwork.secure.invite-decision.v1",
        recipient_key,
    )?;
    Ok(())
}
fn verify_delegation(
    grant: &WireValue,
    related_wire: &[u8],
    recipient: &WireValue,
    grantor_actor: &str,
    grantor_key: &str,
    latest: &WireValue,
    workspace: &str,
    issued: u64,
    now: u64,
    expected_origin: &str,
    expected_audience: &str,
) -> Result<(), GrantError> {
    let related = related_artifact(related_wire)?;
    let saved = grant.get("delegation").ok_or(GrantError::Invalid)?;
    let dp = envelope_payload(&related)?;
    let start = unsigned(dp, "issued_at")?;
    let end = unsigned(dp, "expires_at")?;
    if !same(saved, &related)?
        || unsigned(dp, "v")? != 1
        || string(dp, "actor_id")? != grantor_actor
        || string(dp, "signing_key")? != grantor_key
        || string(dp, "workspace_id")? != workspace
        || string(dp, "origin")? != expected_origin
        || string(dp, "audience")? != expected_audience
        || !token(&string(dp, "request_id")?)
        || !valid_scopes(dp.get("scope").ok_or(GrantError::Invalid)?)?
        || !same(dp.get("device").ok_or(GrantError::Invalid)?, recipient)?
        || !matches!(dp.get("read"), Some(WireValue::Bool(true)))
        || start > issued
        || end <= issued
        || start > now
        || end <= now
        || !has_member_actor_key(latest, grantor_actor, grantor_key)?
    {
        return Err(GrantError::Invalid);
    }
    signed_artifact(
        &related,
        "peerwork.secure.device-delegation.v1",
        grantor_key,
    )
}
fn has_member_actor_key(policy: &WireValue, actor: &str, key: &str) -> Result<bool, GrantError> {
    Ok(member_role(policy, actor, key)?.is_some())
}
fn valid_scopes(scopes: &WireValue) -> Result<bool, GrantError> {
    let WireValue::Array(items) = scopes else {
        return Ok(false);
    };
    if items.len() > 128 {
        return Ok(false);
    }
    for scope in items {
        let WireValue::Object(fields) = scope else {
            return Ok(false);
        };
        if fields.iter().any(|(name, _)| {
            ![
                "instance_id",
                "actions",
                "protocol_roles",
                "capabilities",
                "expires_at",
            ]
            .iter()
            .any(|allowed| name == &allowed.encode_utf16().collect::<Vec<_>>())
        }) {
            return Ok(false);
        }
        if !matches!(scope.get("instance_id"), Some(WireValue::Null))
            && !scope
                .get("instance_id")
                .and_then(WireValue::as_string)
                .is_some_and(|id| token(&id))
        {
            return Ok(false);
        }
        if scope
            .get("expires_at")
            .is_some_and(|value| !matches!(value, WireValue::Null))
            && unsigned(scope, "expires_at").map_or(true, |time| time < 1)
        {
            return Ok(false);
        }
        for field in ["actions", "protocol_roles", "capabilities"] {
            let Some(WireValue::Array(values)) = scope.get(field) else {
                return Ok(false);
            };
            if values.len() > 64 {
                return Ok(false);
            }
            let mut seen = HashSet::new();
            for value in values {
                let Some(units) = value.as_utf16() else {
                    return Ok(false);
                };
                if units.is_empty() || units.len() > 120 || !seen.insert(units.to_vec()) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
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
    fn opaque_scope_ids_follow_pinned_token_syntax() {
        // A source-valid installed composed instance uses a noncanonical
        // base64url suffix. Opaque IDs are regex tokens, not key material.
        assert!(token(&"z".repeat(43)));
        assert!(!token(&"z".repeat(42)));
        assert!(!token(&format!("{}+", "z".repeat(42))));
    }

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
        let policy_wires: Vec<Vec<u8>> = vector
            .get("policies")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| serde_json::to_vec(item).unwrap())
                    .collect()
            })
            .unwrap_or_else(|| vec![serde_json::to_vec(&vector["policy"]).unwrap()]);
        let commit_wires: Vec<Vec<u8>> = vector
            .get("commits")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| serde_json::to_vec(item).unwrap())
                    .collect()
            })
            .unwrap_or_default();
        let policy_refs: Vec<&[u8]> = policy_wires.iter().map(Vec::as_slice).collect();
        let commit_refs: Vec<&[u8]> = commit_wires.iter().map(Vec::as_slice).collect();
        let checkpoint_wire = serde_json::to_vec(&vector["checkpoint"]).unwrap();
        let grant_wire = serde_json::to_vec(&vector["grant"]).unwrap();
        let certificate_wire = serde_json::to_vec(&vector["certificate"]).unwrap();
        let workspace = vector["workspace"].as_str().unwrap();
        let owner_actor = vector["owner_actor"].as_str().unwrap();
        let owner_key = vector["owner_key"].as_str().unwrap();
        let now = vector["now"].as_u64().unwrap();
        let offer_wire = vector.get("offer").map(|v| serde_json::to_vec(v).unwrap());
        let decision_wire = vector
            .get("decision")
            .map(|v| serde_json::to_vec(v).unwrap());
        let delegation_wire = vector
            .get("delegation")
            .map(|v| serde_json::to_vec(v).unwrap());
        let delegation_origin = delegation_wire
            .as_ref()
            .map(|_| "https://synthetic.invalid");
        let delegation_audience = delegation_wire.as_ref().map(|_| "synthetic");
        let verify = |grant: &[u8], certificate: &[u8], policies: &[&[u8]]| {
            verify_direct_key_grant(GrantProofInput {
                policy_wires: policies,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: grant,
                recipient_certificate_wire: certificate,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
                expected_invitation: offer_wire.as_ref().zip(decision_wire.as_ref()).map(
                    |(offer, decision)| InvitationProofInput {
                        offer_wire: offer,
                        decision_wire: decision,
                    },
                ),
                expected_delegation_wire: delegation_wire.as_deref(),
                expected_delegation_origin: delegation_origin,
                expected_delegation_audience: delegation_audience,
            })
        };
        let verified = verify(&grant_wire, &certificate_wire, &policy_refs).unwrap();
        assert_eq!(verified.workspace_id(), workspace);
        assert_eq!(verified.epoch(), 1);
        assert_eq!(
            verified.recipient_actor(),
            vector["recipient_actor"].as_str().unwrap()
        );
        assert_eq!(
            verified.recipient_key(),
            vector["recipient_key"].as_str().unwrap()
        );
        assert!(verified.keyring().key_at(1).is_some());
        if offer_wire.is_some() {
            let omitted = verify_direct_key_grant(GrantProofInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: &grant_wire,
                recipient_certificate_wire: &certificate_wire,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
                expected_invitation: None,
                expected_delegation_wire: delegation_wire.as_deref(),
                expected_delegation_origin: delegation_origin,
                expected_delegation_audience: delegation_audience,
            });
            assert!(matches!(omitted, Err(GrantError::RelatedProofRequired)));
            let mut bad_offer = vector["offer"].clone();
            bad_offer["signature"] = serde_json::json!("a".repeat(86));
            let bad_offer_wire = serde_json::to_vec(&bad_offer).unwrap();
            let altered = verify_direct_key_grant(GrantProofInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: &grant_wire,
                recipient_certificate_wire: &certificate_wire,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
                expected_invitation: Some(InvitationProofInput {
                    offer_wire: &bad_offer_wire,
                    decision_wire: decision_wire.as_ref().unwrap(),
                }),
                expected_delegation_wire: None,
                expected_delegation_origin: None,
                expected_delegation_audience: None,
            });
            assert!(altered.is_err());
            let mut bad_decision = vector["decision"].clone();
            bad_decision["signature"] = serde_json::json!("a".repeat(86));
            let bad_decision_wire = serde_json::to_vec(&bad_decision).unwrap();
            let altered = verify_direct_key_grant(GrantProofInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: &grant_wire,
                recipient_certificate_wire: &certificate_wire,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
                expected_invitation: Some(InvitationProofInput {
                    offer_wire: offer_wire.as_ref().unwrap(),
                    decision_wire: &bad_decision_wire,
                }),
                expected_delegation_wire: None,
                expected_delegation_origin: None,
                expected_delegation_audience: None,
            });
            assert!(altered.is_err());
        }
        if delegation_wire.is_some() {
            let omitted = verify_direct_key_grant(GrantProofInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: &grant_wire,
                recipient_certificate_wire: &certificate_wire,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
                expected_invitation: offer_wire.as_ref().zip(decision_wire.as_ref()).map(
                    |(offer, decision)| InvitationProofInput {
                        offer_wire: offer,
                        decision_wire: decision,
                    },
                ),
                expected_delegation_wire: None,
                expected_delegation_origin: None,
                expected_delegation_audience: None,
            });
            assert!(matches!(
                omitted,
                Err(GrantError::RelatedProofRequired) | Err(GrantError::Invalid)
            ));
            let mut bad_delegation = vector["delegation"].clone();
            bad_delegation["signature"] = serde_json::json!("a".repeat(86));
            let bad_delegation_wire = serde_json::to_vec(&bad_delegation).unwrap();
            let altered = verify_direct_key_grant(GrantProofInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: &grant_wire,
                recipient_certificate_wire: &certificate_wire,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now,
                expected_invitation: None,
                expected_delegation_wire: Some(&bad_delegation_wire),
                expected_delegation_origin: delegation_origin,
                expected_delegation_audience: delegation_audience,
            });
            assert!(altered.is_err());
            let expired = verify_direct_key_grant(GrantProofInput {
                policy_wires: &policy_refs,
                commit_wires: &commit_refs,
                checkpoint_wire: &checkpoint_wire,
                grant_wire: &grant_wire,
                recipient_certificate_wire: &certificate_wire,
                recipient: &recipient,
                workspace_id: workspace,
                trusted_owner_actor: owner_actor,
                trusted_owner_key: owner_key,
                now: vector["delegation_expired_now"].as_u64().unwrap(),
                expected_invitation: None,
                expected_delegation_wire: delegation_wire.as_deref(),
                expected_delegation_origin: delegation_origin,
                expected_delegation_audience: delegation_audience,
            });
            assert!(expired.is_err());
        }

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
