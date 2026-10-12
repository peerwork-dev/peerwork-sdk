//! Verify signed server receipts against a discovery pin and exact command.

use ed25519_dalek::{Signature, Verifier};
use serde_json::{Map, Value};
use thiserror::Error;
use crate::canonical::{canonical, Path};
use crate::crypto::{decode_base64url, sha256_hex, verifying_key};
use crate::strict_json::parse_strict_json;

const RECEIPT_TYPE: &str = "peerwork.kernel-receipt.v1+jws";

#[derive(Debug, Clone)]
pub struct ReceiptExpectation<'a> {
    pub audience: &'a str,
    pub receipt_key_id: &'a str,
    pub actor_id: &'a str,
    pub command_id: &'a str,
    pub intent_digest: &'a str,
    pub workspace_id: Option<&'a str>,
    pub protocol_digest: Option<&'a str>,
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("invalid receipt")]
    Invalid,
    #[error("receipt does not match command or discovery")]
    Mismatch,
}

fn decode_json_part(encoded: &str, max: usize) -> Result<Value, ReceiptError> {
    if encoded.is_empty() { return Err(ReceiptError::Invalid); }
    let bytes = decode_base64url(encoded).map_err(|_| ReceiptError::Invalid)?;
    if bytes.len() > max { return Err(ReceiptError::Invalid); }
    parse_strict_json(&bytes).map_err(|_| ReceiptError::Invalid)
}

fn exact_fields(map: &Map<String, Value>, fields: &[&str]) -> bool {
    map.len() == fields.len() && fields.iter().all(|field| map.contains_key(*field))
}

pub fn verify_receipt(jws: &str, expected: &ReceiptExpectation<'_>) -> Result<Value, ReceiptError> {
    if jws.len() > 250_000 { return Err(ReceiptError::Invalid); }
    let pieces: Vec<&str> = jws.split('.').collect();
    if pieces.len() != 3 { return Err(ReceiptError::Invalid); }
    let header = decode_json_part(pieces[0], 256)?;
    let h = header.as_object().ok_or(ReceiptError::Invalid)?;
    if !exact_fields(h, &["alg", "typ", "kid"]) || h.get("alg").and_then(Value::as_str) != Some("EdDSA") || h.get("typ").and_then(Value::as_str) != Some(RECEIPT_TYPE) || h.get("kid").and_then(Value::as_str) != Some(expected.receipt_key_id) {
        return Err(ReceiptError::Invalid);
    }
    let signature: [u8; 64] = decode_base64url(pieces[2]).map_err(|_| ReceiptError::Invalid)?.try_into().map_err(|_| ReceiptError::Invalid)?;
    let key = verifying_key(expected.receipt_key_id).map_err(|_| ReceiptError::Invalid)?;
    let input = format!("{}.{}", pieces[0], pieces[1]);
    key.verify(input.as_bytes(), &Signature::from_bytes(&signature)).map_err(|_| ReceiptError::Invalid)?;
    let payload = decode_json_part(pieces[1], 180_000)?;
    let p = payload.as_object().ok_or(ReceiptError::Invalid)?;
    if !exact_fields(p, &["v","audience","actor_id","workspace_id","command_id","intent_digest","result_digest","protocol_digest","event_sequence","instance_revision","accepted_at"]) || nonnegative_integer(p.get("v")) != Some(1) || p.get("audience").and_then(Value::as_str) != Some(expected.audience) || p.get("actor_id").and_then(Value::as_str) != Some(expected.actor_id) || p.get("command_id").and_then(Value::as_str) != Some(expected.command_id) || p.get("intent_digest").and_then(Value::as_str) != Some(expected.intent_digest) || p.get("workspace_id").and_then(Value::as_str) != expected.workspace_id || p.get("protocol_digest").and_then(Value::as_str) != expected.protocol_digest {
        return Err(ReceiptError::Mismatch);
    }
    if !valid_digest(p.get("intent_digest")) || !valid_digest(p.get("result_digest")) || !optional_digest(p.get("protocol_digest")) || !optional_token(p.get("workspace_id")) || !valid_token(p.get("actor_id")) || !valid_token(p.get("command_id")) || !nullable_nonnegative(p.get("event_sequence")) || !nullable_nonnegative(p.get("instance_revision")) || nonnegative_integer(p.get("accepted_at")).is_none() {
        return Err(ReceiptError::Invalid);
    }
    Ok(payload)
}

pub fn verify_response_result(receipt: &Value, result: &Value) -> Result<(), ReceiptError> {
    let encoded = canonical(result, Path::KERNEL).map_err(|_| ReceiptError::Invalid)?;
    let digest = sha256_hex(encoded.as_bytes());
    if receipt.get("result_digest").and_then(Value::as_str) != Some(digest.as_str()) { return Err(ReceiptError::Mismatch); }
    let sequence = nonnegative_integer(result.get("event_sequence"));
    let revision = nonnegative_integer(result.get("revision"));
    if nonnegative_integer(receipt.get("event_sequence")) != sequence || nonnegative_integer(receipt.get("instance_revision")) != revision { return Err(ReceiptError::Mismatch); }
    Ok(())
}

fn valid_token(v: Option<&Value>) -> bool { v.and_then(Value::as_str).is_some_and(|s| s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) }
fn optional_token(v: Option<&Value>) -> bool { v == Some(&Value::Null) || valid_token(v) }
fn valid_digest(v: Option<&Value>) -> bool { v.and_then(Value::as_str).is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())) }
fn optional_digest(v: Option<&Value>) -> bool { v == Some(&Value::Null) || valid_digest(v) }
fn nullable_nonnegative(v: Option<&Value>) -> bool { v == Some(&Value::Null) || nonnegative_integer(v).is_some() }
fn nonnegative_integer(v: Option<&Value>) -> Option<u64> {
    let number = v?.as_number()?;
    if let Some(value) = number.as_u64() { return Some(value); }
    let float = number.as_f64()?;
    if float.is_finite() && float >= 0.0 && float.fract() == 0.0 && float < u64::MAX as f64 { Some(float as u64) } else { None }
}
