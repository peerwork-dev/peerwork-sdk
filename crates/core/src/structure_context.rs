//! Nonce-bound service authorization time for backend structure intents.
//! Business predicates still use the backend transaction time exclusively.

use crate::{
    crypto::{decode_base64url, verifying_key},
    structure_execution::PROFILE,
    wire_json::{parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signature, Verifier};
use thiserror::Error;

pub const CONTEXT_TYPE: &str = "peerwork.structure-context.v1+jws";
pub const AUTHORIZATION_TTL_MS: u64 = 600_000;

#[derive(Debug, Error)]
#[error("invalid or mismatched signed structure authorization context")]
pub struct StructureContextError;

pub struct VerifiedStructureContext {
    server_time_ms: u64,
}
impl VerifiedStructureContext {
    pub fn server_time_ms(&self) -> u64 { self.server_time_ms }
    pub fn expires_at_ms(&self) -> u64 { self.server_time_ms + AUTHORIZATION_TTL_MS }
}

pub fn verify_structure_context(
    response_wire: &[u8],
    nonce: &str,
    audience_utf16: &[u16],
    service_key: &str,
) -> Result<VerifiedStructureContext, StructureContextError> {
    let invalid = || StructureContextError;
    let response = parse_wire_json_bounded(response_wire, 3, 8192).map_err(|_| invalid())?;
    if response.object_len() != Some(1) { return Err(invalid()); }
    let context = response.get("context").and_then(WireValue::as_string).ok_or_else(invalid)?;
    if context.len() > 6000 || nonce.len() != 43 || decode_base64url(nonce).map_err(|_| invalid())?.len() != 32 {
        return Err(invalid());
    }
    let parts: Vec<_> = context.split('.').collect();
    if parts.len() != 3 { return Err(invalid()); }
    let header = decode_base64url(parts[0]).map_err(|_| invalid())?;
    let payload = decode_base64url(parts[1]).map_err(|_| invalid())?;
    let signature: [u8; 64] = decode_base64url(parts[2]).map_err(|_| invalid())?.try_into().map_err(|_| invalid())?;
    let header = parse_wire_json_bounded(&header, 3, 256).map_err(|_| invalid())?;
    let text = |v: &WireValue, field: &str| v.get(field).and_then(WireValue::as_string);
    if header.object_len() != Some(3) || text(&header, "alg").as_deref() != Some("EdDSA")
        || text(&header, "typ").as_deref() != Some(CONTEXT_TYPE)
        || text(&header, "kid").as_deref() != Some(service_key) {
        return Err(invalid());
    }
    verifying_key(service_key).map_err(|_| invalid())?
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| invalid())?;
    let payload = parse_wire_json_bounded(&payload, 4, 4096).map_err(|_| invalid())?;
    if payload.object_len() != Some(8)
        || payload.get("v").and_then(WireValue::as_number) != Some(1.0)
        || payload.get("audience").and_then(WireValue::as_utf16) != Some(audience_utf16)
        || text(&payload, "profile").as_deref() != Some(PROFILE)
        || text(&payload, "nonce").as_deref() != Some(nonce)
        || text(&payload, "idempotency").as_deref() != Some("BUSINESS_INTENT_V1")
        || text(&payload, "assurance").as_deref() != Some("BACKEND_CURRENT_STATE")
        || payload.get("authorization_ttl_ms").and_then(WireValue::as_number) != Some(AUTHORIZATION_TTL_MS as f64) {
        return Err(invalid());
    }
    let time = payload.get("server_time_ms").and_then(WireValue::as_number).ok_or_else(invalid)?;
    if !time.is_finite() || time < 0.0 || time.fract() != 0.0 || time > (9_007_199_254_740_991_u64 - AUTHORIZATION_TTL_MS) as f64 {
        return Err(invalid());
    }
    Ok(VerifiedStructureContext { server_time_ms: time as u64 })
}
