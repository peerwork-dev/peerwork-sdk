//! Ed25519, SHA-256, and strict base64url wire building blocks.

use crate::canonical::{canonical, CanonicalError, Path};
use crate::wire_json::{
    canonical_wire_json, canonical_wire_value, parse_wire_json_js_bounded, WireValue,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key, signature, or encoding")]
    InvalidEncoding,
    #[error("invalid signing domain")]
    InvalidDomain,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    #[error("invalid lossless wire JSON")]
    Wire,
}

pub fn verify_canonical_wire(
    domain: &str,
    payload_wire: &[u8],
    signature: &str,
    key_id: &str,
) -> Result<bool, CryptoError> {
    if domain.is_empty() || domain.contains('\0') || domain.len() > 128 {
        return Err(CryptoError::InvalidDomain);
    }
    let canonical =
        canonical_wire_json(payload_wire, Path::SecureArtifact).map_err(|_| CryptoError::Wire)?;
    let mut message = domain.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(canonical.as_bytes());
    let sig: [u8; 64] = decode_base64url(signature)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(verifying_key(key_id)?
        .verify(&message, &Signature::from_bytes(&sig))
        .is_ok())
}

pub fn verify_secure_signed_wire(
    envelope_wire: &[u8],
    domain: &str,
    signer_key_id: &str,
) -> Result<bool, CryptoError> {
    let envelope = parse_wire_json_js_bounded(envelope_wire, 2048, 512 * 1024 * 1024)
        .map_err(|_| CryptoError::Wire)?;
    if envelope.object_len() != Some(2) {
        return Ok(false);
    }
    let payload = envelope.get("payload").ok_or(CryptoError::Wire)?;
    let signature = envelope
        .get("signature")
        .and_then(WireValue::as_string)
        .ok_or(CryptoError::Wire)?;
    let version = payload.get("v").and_then(WireValue::as_number);
    let exact_domain = if matches!(
        domain,
        "peerwork.secure.policy.v1" | "peerwork.secure.commit.v1"
    ) {
        match version {
            Some(3.0) => domain.replace(".v1", ".v3"),
            Some(2.0) => domain.replace(".v1", ".v2"),
            _ => domain.into(),
        }
    } else {
        domain.into()
    };
    if exact_domain.is_empty() || exact_domain.contains('\0') || exact_domain.len() > 128 {
        return Err(CryptoError::InvalidDomain);
    }
    let canonical =
        canonical_wire_value(payload, Path::SecureArtifact).map_err(|_| CryptoError::Wire)?;
    let mut message = exact_domain.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(canonical.as_bytes());
    let sig: [u8; 64] = decode_base64url(&signature)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    Ok(verifying_key(signer_key_id)?
        .verify(&message, &Signature::from_bytes(&sig))
        .is_ok())
}

pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_base64url(text: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if base64url(&bytes) != text {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(bytes)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn key_id(public_key: &[u8; 32]) -> String {
    base64url(public_key)
}
pub fn actor_id(public_key: &[u8; 32]) -> String {
    let mut input = b"peerwork.identity.v1\0".to_vec();
    input.extend_from_slice(public_key);
    base64url(&sha256(&input))
}

pub fn verifying_key(key_id: &str) -> Result<VerifyingKey, CryptoError> {
    let key: [u8; 32] = decode_base64url(key_id)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    VerifyingKey::from_bytes(&key).map_err(|_| CryptoError::InvalidEncoding)
}

fn domain_message(domain: &str, payload: &Value) -> Result<Vec<u8>, CryptoError> {
    if domain.is_empty() || domain.contains('\0') || domain.len() > 128 {
        return Err(CryptoError::InvalidDomain);
    }
    let mut message = domain.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(canonical(payload, Path::SecureArtifact)?.as_bytes());
    Ok(message)
}

pub fn sign_canonical(
    domain: &str,
    payload: &Value,
    key: &SigningKey,
) -> Result<String, CryptoError> {
    Ok(base64url(
        &key.sign(&domain_message(domain, payload)?).to_bytes(),
    ))
}

pub fn verify_canonical(
    domain: &str,
    payload: &Value,
    signature: &str,
    key_id: &str,
) -> Result<bool, CryptoError> {
    let sig: [u8; 64] = decode_base64url(signature)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let key = verifying_key(key_id)?;
    Ok(key
        .verify(
            &domain_message(domain, payload)?,
            &Signature::from_bytes(&sig),
        )
        .is_ok())
}

/// Verify the entire signed artifact, including signer identity and domain.
/// The caller must still validate the domain-specific body schema and authority.
pub fn verify_artifact(
    artifact: &Value,
    expected_domain: &str,
    expected_actor: Option<&str>,
) -> Result<bool, CryptoError> {
    let object = artifact.as_object().ok_or(CryptoError::InvalidEncoding)?;
    if object.len() != 5
        || !["v", "domain", "signer", "body", "signature"]
            .iter()
            .all(|key| object.contains_key(*key))
        || object.get("v").and_then(Value::as_u64) != Some(1)
    {
        return Ok(false);
    }
    let domain = object
        .get("domain")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidEncoding)?;
    if domain != expected_domain || domain.is_empty() || domain.contains('\0') || domain.len() > 128
    {
        return Ok(false);
    }
    let signer = object
        .get("signer")
        .and_then(Value::as_object)
        .ok_or(CryptoError::InvalidEncoding)?;
    if signer.len() != 2 || !signer.contains_key("actor_id") || !signer.contains_key("key_id") {
        return Ok(false);
    }
    let signer_actor = signer
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidEncoding)?;
    let signer_key = signer
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidEncoding)?;
    if expected_actor.is_some_and(|actor| actor != signer_actor) {
        return Ok(false);
    }
    let raw: [u8; 32] = decode_base64url(signer_key)?
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding)?;
    if actor_id(&raw) != signer_actor {
        return Ok(false);
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidEncoding)?;
    let mut unsigned = object.clone();
    unsigned.remove("signature");
    verify_canonical(
        &format!("peerwork.signed-artifact.v1:{domain}"),
        &Value::Object(unsigned),
        signature,
        signer_key,
    )
}

/// Verify the two-field signed envelopes used by secure workspace journals.
/// Policy and commit v2/v3 use distinct signing domains selected from the
/// authenticated payload version. This verifies bytes only; replay must still
/// check the policy chain, author scopes, and command-bound effects.
pub fn verify_secure_signed(
    envelope: &Value,
    domain: &str,
    signer_key_id: &str,
) -> Result<bool, CryptoError> {
    let object = envelope.as_object().ok_or(CryptoError::InvalidEncoding)?;
    if object.len() != 2 || !object.contains_key("payload") || !object.contains_key("signature") {
        return Ok(false);
    }
    let payload = &object["payload"];
    let signature = object["signature"]
        .as_str()
        .ok_or(CryptoError::InvalidEncoding)?;
    let exact_domain = secure_artifact_domain(domain, payload);
    verify_canonical(&exact_domain, payload, signature, signer_key_id)
}

pub fn secure_artifact_domain(domain: &str, payload: &Value) -> String {
    let version = payload.get("v").and_then(Value::as_f64);
    if matches!(
        domain,
        "peerwork.secure.policy.v1" | "peerwork.secure.commit.v1"
    ) {
        if version == Some(3.0) {
            return domain.replace(".v1", ".v3");
        }
        if version == Some(2.0) {
            return domain.replace(".v1", ".v2");
        }
    }
    domain.into()
}

pub fn sign_compact(
    header: &Value,
    payload: &Value,
    key: &SigningKey,
) -> Result<String, CryptoError> {
    let h = base64url(canonical(header, Path::KERNEL)?.as_bytes());
    let p = base64url(canonical(payload, Path::COMMAND)?.as_bytes());
    let signing_input = format!("{h}.{p}");
    let signature = base64url(&key.sign(signing_input.as_bytes()).to_bytes());
    let jws = format!("{signing_input}.{signature}");
    if jws.len() > 250_000 {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(jws)
}
