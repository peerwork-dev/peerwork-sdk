//! Low-level PUBLIC invitation and consent packets. A caller must bind the
//! signed policy/offer to authenticated HTTPS control state before sending.
//! Persist each exact request before POST; neither result grants membership.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, decode_base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{encryption_key_id, hpke_seal_wire, RecipientPublicJwk},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
const INVITATION_LIFETIME: u64 = 7 * 86_400_000;
const CERTIFICATE_LIFETIME: u64 = 366 * 86_400_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PublicAdmissionError {
    #[error("signed PUBLIC admission input or identity is invalid")]
    Invalid,
    #[error("OS entropy for invitation ID or HPKE box is unavailable")]
    Entropy,
    #[error("recipient invitation message could not be encrypted")]
    Encryption,
}

pub struct PreparedAdmissionPacket {
    request_wire: Vec<u8>,
    artifact_wire: Vec<u8>,
    id: String,
    artifact_hash: String,
}

/// Exact owner delivery packet. The caller must obtain the current policy and
/// checkpoint from complete authenticated replay and the offer/decision from
/// authenticated control evidence before persisting and posting these bytes.
pub struct PreparedPublicDelivery {
    request_wire: Vec<u8>,
    invite_id: String,
    grant_id: String,
    policy_hash: String,
    grant_hash: String,
    commit_hash: String,
}

impl PreparedPublicDelivery {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn invite_id(&self) -> &str {
        &self.invite_id
    }
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn grant_hash(&self) -> &str {
        &self.grant_hash
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
}

/// Produce the pinned v3 PUBLIC owner delivery transition. This only authors
/// cryptographic material; it is not a membership or server-acceptance proof.
pub fn prepare_public_delivery(
    current_policy_wire: &[u8],
    prior_checkpoint_wire: &[u8],
    offer_wire: &[u8],
    decision_wire: &[u8],
    issued_at: u64,
    owner_signing_key: &SigningKey,
) -> Result<PreparedPublicDelivery, PublicAdmissionError> {
    let bad = || PublicAdmissionError::Invalid;
    if issued_at > MAX_SAFE {
        return Err(bad());
    }
    let owner_key = base64url(&owner_signing_key.verifying_key().to_bytes());
    let owner_actor = actor_id(&owner_signing_key.verifying_key().to_bytes());
    let current =
        parse_wire_json_js_bounded(current_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let old = current.get("payload").ok_or_else(bad)?;
    let workspace = string(old, "workspace_id")?;
    if unsigned(old, "v")? != 3
        || unsigned(old, "epoch")? != 0
        || string(old, "visibility")? != "PUBLIC"
        || string(old, "owner_id")? != owner_actor
        || string(old, "signing_key")? != owner_key
        || !verify_secure_signed_wire(current_policy_wire, "peerwork.secure.policy.v3", &owner_key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let current_wire = canonical_wire_value(&current, Path::SecureArtifact).map_err(|_| bad())?;
    let current_hash = sha256_hex(current_wire.as_bytes());
    let checkpoint =
        parse_wire_json_js_bounded(prior_checkpoint_wire, 64, 16_384).map_err(|_| bad())?;
    let sequence = unsigned(&checkpoint, "sequence")?;
    let next_sequence = sequence
        .checked_add(1)
        .filter(|n| *n <= MAX_SAFE)
        .ok_or_else(bad)?;
    if string(&checkpoint, "workspace_id")? != workspace
        || string(&checkpoint, "owner_id")? != owner_actor
        || string(&checkpoint, "owner_key")? != owner_key
        || string(&checkpoint, "policy_hash")? != current_hash
    {
        return Err(bad());
    }
    let previous = checkpoint.get("head").ok_or_else(bad)?.clone();
    let offer = parse_wire_json_js_bounded(offer_wire, 64, 220_000).map_err(|_| bad())?;
    let op = offer.get("payload").ok_or_else(bad)?;
    let invite_id = string(op, "invite_id")?;
    let recipient = op.get("recipient").ok_or_else(bad)?;
    let rp = recipient.get("payload").ok_or_else(bad)?;
    let recipient_actor = string(rp, "actor_id")?;
    let recipient_key = string(rp, "signing_key")?;
    let scopes = op.get("scopes").ok_or_else(bad)?.clone();
    if !token(&invite_id)
        || !valid_scopes(&scopes)
        || string(op, "workspace_id")? != workspace
        || string(op, "actor_id")? != owner_actor
        || string(op, "signing_key")? != owner_key
        || unsigned(op, "issued_at")? > issued_at
        || unsigned(op, "expires_at")? <= issued_at
        || !verify_secure_signed_wire(offer_wire, "peerwork.secure.invitation.v1", &owner_key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let recipient_jwk = verify_certificate(recipient, issued_at)?;
    let decision = parse_wire_json_js_bounded(decision_wire, 64, 220_000).map_err(|_| bad())?;
    let decision_request = format!(
        "{{\"decision\":{}}}",
        canonical_wire_value(&decision, Path::SecureArtifact).map_err(|_| bad())?
    );
    let checked = verify_saved_public_decision(
        decision_request.as_bytes(),
        offer_wire,
        &owner_actor,
        &owner_key,
        &recipient_actor,
        &recipient_key,
        &workspace,
    )?;
    if string(decision.get("payload").ok_or_else(bad)?, "decision")? != "ACCEPT"
        || unsigned(decision.get("payload").ok_or_else(bad)?, "issued_at")? > issued_at
        || checked.id() != invite_id
    {
        return Err(bad());
    }
    let members = old.get("members").ok_or_else(bad)?;
    let WireValue::Array(existing) = members else {
        return Err(bad());
    };
    if existing.iter().any(|member| {
        member
            .get("actor_id")
            .and_then(WireValue::as_string)
            .as_deref()
            == Some(&recipient_actor)
    }) {
        return Err(bad());
    }
    let mut new_members = existing.clone();
    new_members.push(object(vec![
        ("actor_id", s(&recipient_actor)),
        ("certificate", recipient.clone()),
        ("role", s("MEMBER")),
        ("scopes", scopes),
    ]));
    let mut next_payload = old.clone();
    set(
        &mut next_payload,
        "version",
        WireValue::Number((unsigned(old, "version")?.checked_add(1).ok_or_else(bad)?) as f64),
    )?;
    set(&mut next_payload, "previous_policy", s(&current_hash))?;
    set(
        &mut next_payload,
        "effective_sequence",
        WireValue::Number(next_sequence as f64),
    )?;
    set(
        &mut next_payload,
        "issued_at",
        WireValue::Number(issued_at as f64),
    )?;
    set(&mut next_payload, "members", WireValue::Array(new_members))?;
    let policy = sign_payload(
        next_payload.clone(),
        "peerwork.secure.policy.v3",
        owner_signing_key,
    )?;
    let policy_wire = canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| bad())?;
    let policy_hash = sha256_hex(policy_wire.as_bytes());
    let grant_id = random_token()?;
    let grant_context = object(vec![
        ("v", WireValue::Number(1.0)),
        ("grant_id", s(&grant_id)),
        ("workspace_id", s(&workspace)),
        ("actor_id", s(&owner_actor)),
        ("signing_key", s(&owner_key)),
        ("recipient", recipient.clone()),
        ("policy_hash", s(&policy_hash)),
        ("epoch", WireValue::Number(0.0)),
        ("invite_id", s(&invite_id)),
        ("acceptance_hash", s(checked.artifact_hash())),
        ("delegation", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
    ]);
    let keyring = object(vec![
        ("v", WireValue::Number(1.0)),
        ("workspace_id", s(&workspace)),
        ("keys", WireValue::Array(vec![])),
    ]);
    let keyring_wire = canonical_wire_value(&keyring, Path::SecureArtifact).map_err(|_| bad())?;
    let context_wire =
        canonical_wire_value(&grant_context, Path::SecureArtifact).map_err(|_| bad())?;
    let boxed = hpke_seal_wire(
        &recipient_jwk,
        keyring_wire.as_bytes(),
        context_wire.as_bytes(),
    )
    .map_err(|_| PublicAdmissionError::Encryption)?;
    let box_bytes = serde_json::to_vec(&boxed).map_err(|_| bad())?;
    let box_value = parse_wire_json_js_bounded(&box_bytes, 16, 65_536).map_err(|_| bad())?;
    let mut grant_payload = grant_context;
    set(&mut grant_payload, "box", box_value)?;
    let grant = sign_payload(
        grant_payload,
        "peerwork.secure.key-grant.v1",
        owner_signing_key,
    )?;
    let grant_wire = canonical_wire_value(&grant, Path::SecureArtifact).map_err(|_| bad())?;
    let grant_hash = sha256_hex(grant_wire.as_bytes());
    let command_id = random_token()?;
    let operation = object(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", s("ADMIN")),
        ("input", object(vec![("invite_id", s(&invite_id))])),
        ("objects", WireValue::Array(vec![])),
    ]);
    let mut context_fields = vec![
        ("v", WireValue::Number(3.0)),
        ("workspace_id", s(&workspace)),
        ("sequence", WireValue::Number(next_sequence as f64)),
        ("previous", previous),
        ("policy_hash", s(&policy_hash)),
        ("epoch", WireValue::Number(0.0)),
        ("actor_id", s(&owner_actor)),
        ("signing_key", s(&owner_key)),
        ("command_id", s(&command_id)),
        ("action_id", s("secure.invite.finalize")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
    ];
    if let Some(ceiling) = next_payload.get("protocol_format_ceiling") {
        context_fields.push(("protocol_format_ceiling", ceiling.clone()));
    }
    if next_payload
        .get("structure_mode")
        .and_then(WireValue::as_string)
        .as_deref()
        == Some("STRUCTURED")
    {
        context_fields.push((
            "structure",
            object(vec![
                ("v", WireValue::Number(1.0)),
                ("mode", s("DELTA")),
                ("records", WireValue::Array(vec![])),
                ("heads", WireValue::Array(vec![])),
            ]),
        ));
    }
    context_fields.push(("mode", s("PUBLIC")));
    context_fields.push(("body", operation));
    let commit = sign_payload(
        object(context_fields),
        "peerwork.secure.commit.v3",
        owner_signing_key,
    )?;
    let commit_wire = canonical_wire_value(&commit, Path::SecureArtifact).map_err(|_| bad())?;
    let commit_hash = sha256_hex(commit_wire.as_bytes());
    let request = object(vec![
        ("policy", policy),
        ("grant", grant),
        ("commit", commit),
    ]);
    let request_wire = canonical_wire_value(&request, Path::SecureArtifact)
        .map_err(|_| bad())?
        .into_bytes();
    if request_wire.len() > 220_000 {
        return Err(bad());
    }
    Ok(PreparedPublicDelivery {
        request_wire,
        invite_id,
        grant_id,
        policy_hash,
        grant_hash,
        commit_hash,
    })
}

fn random_token() -> Result<String, PublicAdmissionError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PublicAdmissionError::Entropy)?;
    Ok(base64url(&bytes))
}

fn set(
    value: &mut WireValue,
    name: &str,
    replacement: WireValue,
) -> Result<(), PublicAdmissionError> {
    let WireValue::Object(fields) = value else {
        return Err(PublicAdmissionError::Invalid);
    };
    let key = name.encode_utf16().collect::<Vec<_>>();
    let existing = fields.iter_mut().find(|(field, _)| *field == key);
    if let Some((_, item)) = existing {
        *item = replacement;
    } else {
        fields.push((key, replacement));
    }
    Ok(())
}

impl PreparedAdmissionPacket {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn artifact_wire(&self) -> &[u8] {
        &self.artifact_wire
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn artifact_hash(&self) -> &str {
        &self.artifact_hash
    }
}

/// Reprove an exact saved owner offer against a policy recovered from signed
/// journal history. This does not interpret an HTTP response as acceptance.
pub fn verify_saved_public_offer(
    request_wire: &[u8],
    signed_policy_wire: &[u8],
    owner_actor: &str,
    owner_key: &str,
    workspace_id: &str,
) -> Result<PreparedAdmissionPacket, PublicAdmissionError> {
    let bad = || PublicAdmissionError::Invalid;
    let request = parse_wire_json_js_bounded(request_wire, 64, 220_000).map_err(|_| bad())?;
    if request.object_len() != Some(1) {
        return Err(bad());
    }
    let artifact = request.get("offer").ok_or_else(bad)?;
    let artifact_wire = canonical_wire_value(artifact, Path::SecureArtifact)
        .map_err(|_| bad())?
        .into_bytes();
    if !verify_secure_signed_wire(&artifact_wire, "peerwork.secure.invitation.v1", owner_key)
        .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let payload = artifact.get("payload").ok_or_else(bad)?;
    let id = string(payload, "invite_id")?;
    if !token(&id)
        || string(payload, "workspace_id")? != workspace_id
        || string(payload, "actor_id")? != owner_actor
        || string(payload, "signing_key")? != owner_key
        || unsigned(payload, "v")? != 1
        || !payload.get("scopes").is_some_and(valid_scopes)
        || payload.get("recipient").is_none()
        || payload.get("message").is_none()
    {
        return Err(bad());
    }
    let issued_at = unsigned(payload, "issued_at")?;
    let expires_at = unsigned(payload, "expires_at")?;
    if expires_at <= issued_at || expires_at - issued_at > INVITATION_LIFETIME {
        return Err(bad());
    }
    verify_certificate(payload.get("recipient").ok_or_else(bad)?, issued_at)?;
    let policy = parse_wire_json_js_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let pp = policy.get("payload").ok_or_else(bad)?;
    if string(pp, "workspace_id")? != workspace_id
        || string(pp, "owner_id")? != owner_actor
        || string(pp, "signing_key")? != owner_key
        || string(pp, "visibility")? != "PUBLIC"
        || unsigned(pp, "epoch")? != 0
        || !verify_secure_signed_wire(signed_policy_wire, "peerwork.secure.policy.v1", owner_key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let policy_hash = sha256_hex(
        canonical_wire_value(&policy, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes(),
    );
    if string(payload, "policy_hash")? != policy_hash {
        return Err(bad());
    }
    let canonical_request =
        format!("{{\"offer\":{}}}", String::from_utf8_lossy(&artifact_wire)).into_bytes();
    if canonical_request != request_wire {
        return Err(bad());
    }
    Ok(PreparedAdmissionPacket {
        artifact_hash: sha256_hex(&artifact_wire),
        request_wire: canonical_request,
        artifact_wire,
        id,
    })
}

/// Construct the owner-signed offer and its exact POST body. The caller must
/// supply the latest policy from a complete origin-bound replay and check the
/// recipient certificate against current directory state before sending.
pub fn prepare_public_offer(
    signed_policy_wire: &[u8],
    recipient_certificate_wire: &[u8],
    scopes_wire: &[u8],
    message: &str,
    invite_id: Option<&str>,
    issued_at: u64,
    expires_at: u64,
    owner_signing_key: &SigningKey,
) -> Result<PreparedAdmissionPacket, PublicAdmissionError> {
    let utf16 = message.encode_utf16().collect::<Vec<_>>();
    prepare_public_offer_utf16(
        signed_policy_wire,
        recipient_certificate_wire,
        scopes_wire,
        &utf16,
        invite_id,
        issued_at,
        expires_at,
        owner_signing_key,
    )
}

/// Lossless JavaScript-string producer, including lone UTF-16 surrogates.
/// TextEncoder's replacement encoding is used only for the 8192-byte limit;
/// JSON serialization retains the original UTF-16 units.
pub fn prepare_public_offer_utf16(
    signed_policy_wire: &[u8],
    recipient_certificate_wire: &[u8],
    scopes_wire: &[u8],
    message: &[u16],
    invite_id: Option<&str>,
    issued_at: u64,
    expires_at: u64,
    owner_signing_key: &SigningKey,
) -> Result<PreparedAdmissionPacket, PublicAdmissionError> {
    let bad = || PublicAdmissionError::Invalid;
    if String::from_utf16_lossy(message).len() > 8192
        || issued_at > MAX_SAFE
        || expires_at > MAX_SAFE
        || expires_at <= issued_at
        || expires_at - issued_at > INVITATION_LIFETIME
    {
        return Err(bad());
    }
    let owner_key = base64url(&owner_signing_key.verifying_key().to_bytes());
    let owner_actor = actor_id(&owner_signing_key.verifying_key().to_bytes());
    let policy = parse_wire_json_js_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let p = policy.get("payload").ok_or_else(bad)?;
    let workspace = string(p, "workspace_id")?;
    if string(p, "owner_id")? != owner_actor
        || string(p, "signing_key")? != owner_key
        || string(p, "visibility")? != "PUBLIC"
        || unsigned(p, "epoch")? != 0
        || !verify_secure_signed_wire(signed_policy_wire, "peerwork.secure.policy.v1", &owner_key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let policy_hash = sha256_hex(
        canonical_wire_value(&policy, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes(),
    );
    let certificate =
        parse_wire_json_js_bounded(recipient_certificate_wire, 64, 8192).map_err(|_| bad())?;
    let recipient_jwk = verify_certificate(&certificate, issued_at)?;
    let scopes = parse_wire_json_js_bounded(scopes_wire, 32, 65_536).map_err(|_| bad())?;
    if !valid_scopes(&scopes) {
        return Err(bad());
    }
    let id = match invite_id {
        Some(id) if token(id) => id.to_owned(),
        Some(_) => return Err(bad()),
        None => {
            let mut bytes = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| PublicAdmissionError::Entropy)?;
            base64url(&bytes)
        }
    };
    let context = object(vec![
        ("v", WireValue::Number(1.0)),
        ("invite_id", s(&id)),
        ("workspace_id", s(&workspace)),
        ("actor_id", s(&owner_actor)),
        ("signing_key", s(&owner_key)),
        ("recipient", certificate),
        ("policy_hash", s(&policy_hash)),
        ("scopes", scopes),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("expires_at", WireValue::Number(expires_at as f64)),
    ]);
    let plaintext = object(vec![("message", WireValue::String(message.to_vec()))]);
    let box_value = hpke_seal_wire(
        &recipient_jwk,
        canonical_wire_value(&plaintext, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes(),
        canonical_wire_value(&context, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes(),
    )
    .map_err(|_| PublicAdmissionError::Encryption)?;
    let box_wire = serde_json::to_vec(&box_value).map_err(|_| bad())?;
    let box_value = parse_wire_json_js_bounded(&box_wire, 32, 196_608).map_err(|_| bad())?;
    let WireValue::Object(mut fields) = context else {
        return Err(bad());
    };
    fields.push(("message".encode_utf16().collect(), box_value));
    let artifact = sign_payload(
        WireValue::Object(fields),
        "peerwork.secure.invitation.v1",
        owner_signing_key,
    )?;
    let artifact_wire = canonical_wire_value(&artifact, Path::SecureArtifact)
        .map_err(|_| bad())?
        .into_bytes();
    let request_wire =
        format!("{{\"offer\":{}}}", String::from_utf8_lossy(&artifact_wire)).into_bytes();
    Ok(PreparedAdmissionPacket {
        artifact_hash: sha256_hex(&artifact_wire),
        request_wire,
        artifact_wire,
        id,
    })
}

/// Sign consent to an exact owner offer. The recipient actor and certificate
/// must match the local signing identity. Transport and directory proof remain
/// runtime responsibilities.
pub fn prepare_public_decision(
    offer_wire: &[u8],
    owner_actor: &str,
    owner_key: &str,
    recipient_signing_key: &SigningKey,
    decision: &str,
    issued_at: u64,
) -> Result<PreparedAdmissionPacket, PublicAdmissionError> {
    let bad = || PublicAdmissionError::Invalid;
    if !matches!(decision, "ACCEPT" | "DECLINE") || issued_at > MAX_SAFE {
        return Err(bad());
    }
    let offer = parse_wire_json_js_bounded(offer_wire, 64, 220_000).map_err(|_| bad())?;
    let op = offer.get("payload").ok_or_else(bad)?;
    let id = string(op, "invite_id")?;
    let workspace = string(op, "workspace_id")?;
    let recipient = op.get("recipient").ok_or_else(bad)?;
    let rp = recipient.get("payload").ok_or_else(bad)?;
    let actor = actor_id(&recipient_signing_key.verifying_key().to_bytes());
    let key = base64url(&recipient_signing_key.verifying_key().to_bytes());
    let offered_at = unsigned(op, "issued_at")?;
    let expires_at = unsigned(op, "expires_at")?;
    if unsigned(op, "v")? != 1
        || !token(&id)
        || !token(&workspace)
        || !token(owner_actor)
        || !token(owner_key)
        || string(op, "actor_id")? != owner_actor
        || string(op, "signing_key")? != owner_key
        || !hex_digest(&string(op, "policy_hash")?)
        || !op.get("scopes").is_some_and(valid_scopes)
        || string(rp, "actor_id")? != actor
        || string(rp, "signing_key")? != key
        || offered_at > issued_at
        || expires_at <= issued_at
        || expires_at - offered_at > INVITATION_LIFETIME
        || !verify_secure_signed_wire(offer_wire, "peerwork.secure.invitation.v1", owner_key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    verify_certificate(recipient, issued_at)?;
    let offer_hash = sha256_hex(
        canonical_wire_value(&offer, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes(),
    );
    let payload = object(vec![
        ("v", WireValue::Number(1.0)),
        ("invite_id", s(&id)),
        ("workspace_id", s(&workspace)),
        ("actor_id", s(&actor)),
        ("signing_key", s(&key)),
        ("offer_hash", s(&offer_hash)),
        ("decision", s(decision)),
        ("issued_at", WireValue::Number(issued_at as f64)),
    ]);
    let artifact = sign_payload(
        payload,
        "peerwork.secure.invite-decision.v1",
        recipient_signing_key,
    )?;
    let artifact_wire = canonical_wire_value(&artifact, Path::SecureArtifact)
        .map_err(|_| bad())?
        .into_bytes();
    let request_wire = format!(
        "{{\"decision\":{}}}",
        String::from_utf8_lossy(&artifact_wire)
    )
    .into_bytes();
    Ok(PreparedAdmissionPacket {
        artifact_hash: sha256_hex(&artifact_wire),
        request_wire,
        artifact_wire,
        id,
    })
}

/// Reprove an exact saved recipient decision against the signed owner offer.
/// The surrounding authenticated control read is the runtime's responsibility.
pub fn verify_saved_public_decision(
    request_wire: &[u8],
    offer_wire: &[u8],
    owner_actor: &str,
    owner_key: &str,
    recipient_actor: &str,
    recipient_key: &str,
    workspace_id: &str,
) -> Result<PreparedAdmissionPacket, PublicAdmissionError> {
    let bad = || PublicAdmissionError::Invalid;
    let request = parse_wire_json_js_bounded(request_wire, 64, 220_000).map_err(|_| bad())?;
    if request.object_len() != Some(1) {
        return Err(bad());
    }
    let artifact = request.get("decision").ok_or_else(bad)?;
    let artifact_wire = canonical_wire_value(artifact, Path::SecureArtifact)
        .map_err(|_| bad())?
        .into_bytes();
    let offer = parse_wire_json_js_bounded(offer_wire, 64, 220_000).map_err(|_| bad())?;
    let op = offer.get("payload").ok_or_else(bad)?;
    let id = string(op, "invite_id")?;
    let recipient = op.get("recipient").ok_or_else(bad)?;
    let rp = recipient.get("payload").ok_or_else(bad)?;
    let issued_at = unsigned(op, "issued_at")?;
    let expires_at = unsigned(op, "expires_at")?;
    if !token(&id)
        || string(op, "workspace_id")? != workspace_id
        || string(op, "actor_id")? != owner_actor
        || string(op, "signing_key")? != owner_key
        || string(rp, "actor_id")? != recipient_actor
        || string(rp, "signing_key")? != recipient_key
        || expires_at <= issued_at
        || !verify_secure_signed_wire(offer_wire, "peerwork.secure.invitation.v1", owner_key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let payload = artifact.get("payload").ok_or_else(bad)?;
    let WireValue::Object(fields) = payload else {
        return Err(bad());
    };
    if fields.len() != 8
        || ![
            "v",
            "invite_id",
            "workspace_id",
            "actor_id",
            "signing_key",
            "offer_hash",
            "decision",
            "issued_at",
        ]
        .iter()
        .all(|name| payload.get(name).is_some())
        || unsigned(payload, "v")? != 1
        || string(payload, "invite_id")? != id
        || string(payload, "workspace_id")? != workspace_id
        || string(payload, "actor_id")? != recipient_actor
        || string(payload, "signing_key")? != recipient_key
        || !matches!(string(payload, "decision")?.as_str(), "ACCEPT" | "DECLINE")
        || unsigned(payload, "issued_at")? < issued_at
        || unsigned(payload, "issued_at")? >= expires_at
        || string(payload, "offer_hash")?
            != sha256_hex(
                canonical_wire_value(&offer, Path::SecureArtifact)
                    .map_err(|_| bad())?
                    .as_bytes(),
            )
        || !verify_secure_signed_wire(
            &artifact_wire,
            "peerwork.secure.invite-decision.v1",
            recipient_key,
        )
        .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let canonical_request = format!(
        "{{\"decision\":{}}}",
        String::from_utf8_lossy(&artifact_wire)
    )
    .into_bytes();
    if canonical_request != request_wire {
        return Err(bad());
    }
    Ok(PreparedAdmissionPacket {
        artifact_hash: sha256_hex(&artifact_wire),
        request_wire: canonical_request,
        artifact_wire,
        id,
    })
}

fn verify_certificate(
    certificate: &WireValue,
    at: u64,
) -> Result<RecipientPublicJwk, PublicAdmissionError> {
    let bad = || PublicAdmissionError::Invalid;
    let payload = certificate.get("payload").ok_or_else(bad)?;
    let actor = string(payload, "actor_id")?;
    let key = string(payload, "signing_key")?;
    let issued = unsigned(payload, "issued_at")?;
    let expiry = unsigned(payload, "expires_at")?;
    let raw: [u8; 32] = decode_base64url(&key)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    if unsigned(payload, "v")? != 1
        || actor_id(&raw) != actor
        || !token(&actor)
        || issued > at
        || expiry <= at
        || expiry - issued > CERTIFICATE_LIFETIME
    {
        return Err(bad());
    }
    let jwk_value = payload.get("encryption_key").ok_or_else(bad)?;
    if jwk_value.object_len() != Some(4) {
        return Err(bad());
    }
    let jwk_wire = canonical_wire_value(jwk_value, Path::SecureArtifact).map_err(|_| bad())?;
    let jwk: RecipientPublicJwk = serde_json::from_str(&jwk_wire).map_err(|_| bad())?;
    if string(payload, "encryption_key_id")? != encryption_key_id(&jwk).map_err(|_| bad())? {
        return Err(bad());
    }
    let cert_wire = canonical_wire_value(certificate, Path::SecureArtifact).map_err(|_| bad())?;
    if !verify_secure_signed_wire(
        cert_wire.as_bytes(),
        "peerwork.secure.key-certificate.v1",
        &key,
    )
    .map_err(|_| bad())?
    {
        return Err(bad());
    }
    Ok(jwk)
}

fn sign_payload(
    payload: WireValue,
    domain: &str,
    signing_key: &SigningKey,
) -> Result<WireValue, PublicAdmissionError> {
    let canonical = canonical_wire_value(&payload, Path::SecureArtifact)
        .map_err(|_| PublicAdmissionError::Invalid)?;
    let mut message = Zeroizing::new(Vec::with_capacity(domain.len() + 1 + canonical.len()));
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical.as_bytes());
    let signature = base64url(&signing_key.sign(&message).to_bytes());
    Ok(object(vec![
        ("payload", payload),
        ("signature", s(&signature)),
    ]))
}

fn valid_scopes(value: &WireValue) -> bool {
    let WireValue::Array(scopes) = value else {
        return false;
    };
    if scopes.len() > 128 {
        return false;
    }
    for scope in scopes {
        let WireValue::Object(fields) = scope else {
            return false;
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
            .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
        }) || !matches!(scope.get("instance_id"), Some(WireValue::Null))
            && !scope
                .get("instance_id")
                .and_then(WireValue::as_string)
                .is_some_and(|id| token(&id))
        {
            return false;
        }
        if scope.get("expires_at").is_some_and(|expiry| {
            !matches!(expiry, WireValue::Null)
                && !expiry
                    .as_number()
                    .is_some_and(|n| n >= 1.0 && n <= MAX_SAFE as f64 && n.fract() == 0.0)
        }) {
            return false;
        }
        for field in ["actions", "protocol_roles", "capabilities"] {
            let Some(WireValue::Array(values)) = scope.get(field) else {
                return false;
            };
            if values.len() > 64 {
                return false;
            }
            let mut seen = HashSet::new();
            for value in values {
                let Some(units) = value.as_utf16() else {
                    return false;
                };
                if units.is_empty() || units.len() > 120 || !seen.insert(units.to_vec()) {
                    return false;
                }
            }
        }
    }
    true
}

fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.encode_utf16().collect(), value))
            .collect(),
    )
}
fn s(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn string(value: &WireValue, name: &str) -> Result<String, PublicAdmissionError> {
    value
        .get(name)
        .and_then(WireValue::as_string)
        .ok_or(PublicAdmissionError::Invalid)
}
fn unsigned(value: &WireValue, name: &str) -> Result<u64, PublicAdmissionError> {
    let number = value
        .get(name)
        .and_then(WireValue::as_number)
        .ok_or(PublicAdmissionError::Invalid)?;
    if !number.is_finite() || number < 0.0 || number > MAX_SAFE as f64 || number.fract() != 0.0 {
        return Err(PublicAdmissionError::Invalid);
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
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        e2ee::{hpke_open_wire, KeyBox},
        secure_recipient::SecretRecipient,
    };

    #[test]
    fn public_offer_and_recipient_consent_bind_exact_signed_artifacts() {
        let now = 1_700_000_000_000;
        let owner = SigningKey::from_bytes(&[17; 32]);
        let recipient = SigningKey::from_bytes(&[19; 32]);
        let recipient_secret = SecretRecipient::generate().unwrap();
        let cert = recipient_secret.certify(&recipient, now).unwrap();
        let certificate_wire = serde_json::to_vec(&cert).unwrap();
        let workspace = base64url(&[13; 32]);
        let owner_key = base64url(&owner.verifying_key().to_bytes());
        let owner_actor = actor_id(&owner.verifying_key().to_bytes());
        let policy = sign_payload(
            object(vec![
                ("v", WireValue::Number(1.0)),
                ("workspace_id", s(&workspace)),
                ("owner_id", s(&owner_actor)),
                ("signing_key", s(&owner_key)),
                ("version", WireValue::Number(1.0)),
                ("previous_policy", WireValue::Null),
                ("effective_sequence", WireValue::Number(1.0)),
                ("visibility", s("PUBLIC")),
                ("epoch", WireValue::Number(0.0)),
                ("members", WireValue::Array(Vec::new())),
                ("issued_at", WireValue::Number(now as f64)),
            ]),
            "peerwork.secure.policy.v1",
            &owner,
        )
        .unwrap();
        let policy_wire = canonical_wire_value(&policy, Path::SecureArtifact).unwrap();
        let scopes_wire = br#"[{"instance_id":null,"actions":["proposal.adopt"],"protocol_roles":["ADOPTER"],"capabilities":[]}]"#;
        let offer = prepare_public_offer(
            policy_wire.as_bytes(),
            &certificate_wire,
            scopes_wire,
            "consent message",
            Some(&base64url(&[14; 32])),
            now + 1,
            now + 86_400_000,
            &owner,
        )
        .unwrap();
        assert!(verify_secure_signed_wire(
            offer.artifact_wire(),
            "peerwork.secure.invitation.v1",
            &owner_key
        )
        .unwrap());
        let offer_value = parse_wire_json_js_bounded(offer.artifact_wire(), 64, 220_000).unwrap();
        let WireValue::Object(fields) = offer_value.get("payload").unwrap().clone() else {
            panic!("offer payload");
        };
        let box_value = fields
            .iter()
            .find(|(name, _)| name.iter().copied().eq("message".encode_utf16()))
            .unwrap()
            .1
            .clone();
        let context = WireValue::Object(
            fields
                .into_iter()
                .filter(|(name, _)| !name.iter().copied().eq("message".encode_utf16()))
                .collect(),
        );
        let box_wire = canonical_wire_value(&box_value, Path::SecureArtifact).unwrap();
        let key_box: KeyBox = serde_json::from_str(&box_wire).unwrap();
        let context_wire = canonical_wire_value(&context, Path::SecureArtifact).unwrap();
        let opened = hpke_open_wire(
            recipient_secret.private_bytes(),
            &key_box,
            context_wire.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            opened
                .get("message")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("consent message")
        );
        let decision = prepare_public_decision(
            offer.artifact_wire(),
            &owner_actor,
            &owner_key,
            &recipient,
            "ACCEPT",
            now + 2,
        )
        .unwrap();
        assert!(verify_secure_signed_wire(
            decision.artifact_wire(),
            "peerwork.secure.invite-decision.v1",
            &base64url(&recipient.verifying_key().to_bytes())
        )
        .unwrap());
        let decision_value =
            parse_wire_json_js_bounded(decision.artifact_wire(), 32, 8192).unwrap();
        assert_eq!(
            decision_value
                .get("payload")
                .unwrap()
                .get("offer_hash")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some(offer.artifact_hash())
        );
        assert_eq!(decision.id(), offer.id());
        let mut uppercase_payload = offer_value.get("payload").unwrap().clone();
        let WireValue::Object(ref mut values) = uppercase_payload else {
            panic!("offer payload");
        };
        let (_, digest_value) = values
            .iter_mut()
            .find(|(name, _)| name.iter().copied().eq("policy_hash".encode_utf16()))
            .unwrap();
        let uppercase_digest = digest_value.as_string().unwrap().to_ascii_uppercase();
        assert_ne!(uppercase_digest, digest_value.as_string().unwrap());
        *digest_value = s(&uppercase_digest);
        let uppercase_offer =
            sign_payload(uppercase_payload, "peerwork.secure.invitation.v1", &owner).unwrap();
        let uppercase_wire = canonical_wire_value(&uppercase_offer, Path::SecureArtifact).unwrap();
        assert!(verify_secure_signed_wire(
            uppercase_wire.as_bytes(),
            "peerwork.secure.invitation.v1",
            &owner_key
        )
        .unwrap());
        assert!(prepare_public_decision(
            uppercase_wire.as_bytes(),
            &owner_actor,
            &owner_key,
            &recipient,
            "ACCEPT",
            now + 2,
        )
        .is_err());
        let surrogate_offer = prepare_public_offer_utf16(
            policy_wire.as_bytes(),
            &certificate_wire,
            scopes_wire,
            &[0xd800],
            Some(&base64url(&[15; 32])),
            now + 1,
            now + 86_400_000,
            &owner,
        )
        .unwrap();
        let surrogate_value =
            parse_wire_json_js_bounded(surrogate_offer.artifact_wire(), 64, 220_000).unwrap();
        let WireValue::Object(surrogate_fields) = surrogate_value.get("payload").unwrap().clone()
        else {
            panic!("surrogate offer payload");
        };
        let surrogate_box = surrogate_fields
            .iter()
            .find(|(name, _)| name.iter().copied().eq("message".encode_utf16()))
            .unwrap()
            .1
            .clone();
        let surrogate_context = WireValue::Object(
            surrogate_fields
                .into_iter()
                .filter(|(name, _)| !name.iter().copied().eq("message".encode_utf16()))
                .collect(),
        );
        let box_json = canonical_wire_value(&surrogate_box, Path::SecureArtifact).unwrap();
        let surrogate_key_box: KeyBox = serde_json::from_str(&box_json).unwrap();
        let context_json = canonical_wire_value(&surrogate_context, Path::SecureArtifact).unwrap();
        let surrogate_opened = hpke_open_wire(
            recipient_secret.private_bytes(),
            &surrogate_key_box,
            context_json.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            surrogate_opened
                .get("message")
                .and_then(WireValue::as_utf16),
            Some(&[0xd800][..])
        );
        let noncanonical_id = format!("{}B", "A".repeat(42));
        assert!(decode_base64url(&noncanonical_id).is_err());
        let noncanonical_offer = prepare_public_offer(
            policy_wire.as_bytes(),
            &certificate_wire,
            scopes_wire,
            "message",
            Some(&noncanonical_id),
            now + 1,
            now + 86_400_000,
            &owner,
        )
        .unwrap();
        assert_eq!(noncanonical_offer.id(), noncanonical_id);
        let wrong = SigningKey::from_bytes(&[21; 32]);
        assert!(prepare_public_decision(
            offer.artifact_wire(),
            &owner_actor,
            &owner_key,
            &wrong,
            "ACCEPT",
            now + 2,
        )
        .is_err());
        if let Ok(path) = std::env::var("PEERWORK_ADMISSION_VECTOR") {
            let public_vector = serde_json::json!({
                "offer":serde_json::from_slice::<serde_json::Value>(offer.artifact_wire()).unwrap(),
                "decision":serde_json::from_slice::<serde_json::Value>(decision.artifact_wire()).unwrap(),
                "uppercase_offer":serde_json::from_str::<serde_json::Value>(&uppercase_wire).unwrap(),
                "surrogate_offer":std::str::from_utf8(surrogate_offer.artifact_wire()).unwrap(),
                "noncanonical_offer":serde_json::from_slice::<serde_json::Value>(noncanonical_offer.artifact_wire()).unwrap(),
                "owner_actor":owner_actor,
                "owner_key":owner_key,
                "recipient_actor":actor_id(&recipient.verifying_key().to_bytes()),
                "recipient_key":base64url(&recipient.verifying_key().to_bytes()),
                "now":now+2,
            });
            std::fs::write(path, serde_json::to_vec(&public_vector).unwrap()).unwrap();
        }
    }
}
