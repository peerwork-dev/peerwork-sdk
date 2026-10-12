//! Exact-byte kernel receipt verification with lossless JavaScript strings.

use crate::{
    canonical::Path,
    crypto::{decode_base64url, sha256_hex, verifying_key},
    prepared_command::VerifiedPreparedCommand,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signature, Verifier};
use thiserror::Error;

const RECEIPT_TYPE: &str = "peerwork.kernel-receipt.v1+jws";

#[derive(Debug, Clone)]
pub struct WireReceiptExpectation<'a> {
    pub audience_utf16: &'a [u16],
    pub receipt_key_id: &'a str,
    pub actor_id: &'a str,
    pub command_id: &'a str,
    pub intent_digest: &'a str,
    pub workspace_id: Option<&'a str>,
    pub protocol_digest: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct VerifiedCommandResponse {
    command_id: String,
    actor_id: String,
    intent_digest: String,
    receipt_key_id: String,
    audience_utf16: Vec<u16>,
    workspace_id: Option<String>,
    protocol_digest: Option<String>,
    result_digest: String,
    event_sequence: Option<u64>,
    instance_revision: Option<u64>,
}

impl VerifiedCommandResponse {
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
    pub fn receipt_key_id(&self) -> &str {
        &self.receipt_key_id
    }
    pub fn audience_utf16(&self) -> &[u16] {
        &self.audience_utf16
    }
    pub fn workspace_id(&self) -> Option<&str> {
        self.workspace_id.as_deref()
    }
    pub fn protocol_digest(&self) -> Option<&str> {
        self.protocol_digest.as_deref()
    }
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
    pub fn event_sequence(&self) -> Option<u64> {
        self.event_sequence
    }
    pub fn instance_revision(&self) -> Option<u64> {
        self.instance_revision
    }
}

#[derive(Debug, Error)]
pub enum VerifyWireReceiptError {
    #[error("receipt or result wire format invalid")]
    Invalid,
    #[error("receipt does not bind the expected command and result")]
    Mismatch,
}

pub fn verify_command_response_wire(
    jws: &str,
    result_wire: &[u8],
    expected: &WireReceiptExpectation<'_>,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    if jws.len() > 250_000 {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let header = decode_part(parts[0], 256)?;
    if header.object_len() != Some(3)
        || ascii_field(&header, "alg") != Some("EdDSA".into())
        || ascii_field(&header, "typ") != Some(RECEIPT_TYPE.into())
        || ascii_field(&header, "kid") != Some(expected.receipt_key_id.into())
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let sig: [u8; 64] = decode_base64url(parts[2])
        .map_err(|_| VerifyWireReceiptError::Invalid)?
        .try_into()
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let key =
        verifying_key(expected.receipt_key_id).map_err(|_| VerifyWireReceiptError::Invalid)?;
    key.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let receipt = decode_part(parts[1], 180_000)?;
    if receipt.object_len() != Some(11)
        || ![
            "v",
            "audience",
            "actor_id",
            "workspace_id",
            "command_id",
            "intent_digest",
            "result_digest",
            "protocol_digest",
            "event_sequence",
            "instance_revision",
            "accepted_at",
        ]
        .iter()
        .all(|field| receipt.get(field).is_some())
        || number(&receipt, "v") != Some(1)
        || !receipt
            .get("audience")
            .and_then(WireValue::as_utf16)
            .is_some_and(|value| value == expected.audience_utf16)
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    if ascii_field(&receipt, "actor_id").as_deref() != Some(expected.actor_id)
        || ascii_field(&receipt, "command_id").as_deref() != Some(expected.command_id)
        || ascii_field(&receipt, "intent_digest").as_deref() != Some(expected.intent_digest)
        || !optional_field_equals(&receipt, "workspace_id", expected.workspace_id)
        || !optional_field_equals(&receipt, "protocol_digest", expected.protocol_digest)
    {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    let digest = ascii_field(&receipt, "result_digest").ok_or(VerifyWireReceiptError::Invalid)?;
    if !valid_token(expected.actor_id)
        || !valid_token(expected.command_id)
        || !valid_token(expected.receipt_key_id)
        || !valid_digest(expected.intent_digest)
        || !valid_digest(&digest)
        || !expected.workspace_id.is_none_or(valid_token)
        || !expected.protocol_digest.is_none_or(valid_digest)
        || number(&receipt, "accepted_at").is_none()
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let sequence = optional_number(&receipt, "event_sequence")?;
    let revision = optional_number(&receipt, "instance_revision")?;
    let result = parse_wire_json_bounded(result_wire, 12, 32 * 1024 * 1024)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    if result.object_len().is_none() {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let canonical =
        canonical_wire_value(&result, Path::KERNEL).map_err(|_| VerifyWireReceiptError::Invalid)?;
    if sha256_hex(canonical.as_bytes()) != digest
        || optional_number(&result, "event_sequence")? != sequence
        || optional_number(&result, "revision")? != revision
    {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    Ok(VerifiedCommandResponse {
        command_id: expected.command_id.into(),
        actor_id: expected.actor_id.into(),
        intent_digest: expected.intent_digest.into(),
        receipt_key_id: expected.receipt_key_id.into(),
        audience_utf16: expected.audience_utf16.into(),
        workspace_id: expected.workspace_id.map(str::to_owned),
        protocol_digest: expected.protocol_digest.map(str::to_owned),
        result_digest: digest,
        event_sequence: sequence,
        instance_revision: revision,
    })
}

/// Verify a complete HTTP response body without converting its result through
/// Rust `String`/`serde_json::Value`. A runtime may mark a kernel intent accepted
/// only after this returns successfully for its stored command expectation.
pub fn verify_http_response_wire(
    response_wire: &[u8],
    expected: &WireReceiptExpectation<'_>,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    let response = parse_wire_json_bounded(response_wire, 13, 32 * 1024 * 1024)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    if response.object_len() != Some(3)
        || !["command_id", "receipt", "result"]
            .iter()
            .all(|field| response.get(field).is_some())
        || ascii_field(&response, "command_id").as_deref() != Some(expected.command_id)
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let jws = ascii_field(&response, "receipt").ok_or(VerifyWireReceiptError::Invalid)?;
    let result = response
        .get("result")
        .ok_or(VerifyWireReceiptError::Invalid)?;
    let result_wire =
        canonical_wire_value(result, Path::KERNEL).map_err(|_| VerifyWireReceiptError::Invalid)?;
    verify_command_response_wire(&jws, result_wire.as_bytes(), expected)
}

/// Bind a response to a locally authenticated exact signed command. The
/// receipt authority key must come from the caller's pinned discovery.
pub fn verify_http_response_for_prepared(
    response_wire: &[u8],
    prepared: &VerifiedPreparedCommand,
    receipt_key_id: &str,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    let response = parse_wire_json_bounded(response_wire, 13, 32 * 1024 * 1024)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let result = response
        .get("result")
        .ok_or(VerifyWireReceiptError::Invalid)?;
    let workspace = result_string_or_fallback(result, "workspace_id", prepared.workspace_id())?;
    let protocol =
        result_string_or_fallback(result, "protocol_digest", prepared.protocol_digest())?;
    verify_http_response_wire(
        response_wire,
        &WireReceiptExpectation {
            audience_utf16: prepared.audience_utf16(),
            receipt_key_id,
            actor_id: prepared.actor_id(),
            command_id: prepared.command_id(),
            intent_digest: prepared.intent_digest(),
            workspace_id: workspace.as_deref(),
            protocol_digest: protocol.as_deref(),
        },
    )
}

fn result_string_or_fallback(
    result: &WireValue,
    field: &str,
    fallback: Option<&str>,
) -> Result<Option<String>, VerifyWireReceiptError> {
    match result.get(field) {
        Some(WireValue::String(units)) => String::from_utf16(units)
            .map(Some)
            .map_err(|_| VerifyWireReceiptError::Invalid),
        _ => Ok(fallback.map(str::to_owned)),
    }
}

fn decode_part(text: &str, max: usize) -> Result<WireValue, VerifyWireReceiptError> {
    if text.is_empty() {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let bytes = decode_base64url(text).map_err(|_| VerifyWireReceiptError::Invalid)?;
    if bytes.len() > max {
        return Err(VerifyWireReceiptError::Invalid);
    }
    parse_wire_json_bounded(&bytes, 16, max).map_err(|_| VerifyWireReceiptError::Invalid)
}
fn ascii_field(value: &WireValue, field: &str) -> Option<String> {
    value.get(field)?.as_string()
}
fn number(value: &WireValue, field: &str) -> Option<u64> {
    let value = value.get(field)?.as_number()?;
    (value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= 9_007_199_254_740_991.0)
        .then_some(value as u64)
}
fn optional_number(value: &WireValue, field: &str) -> Result<Option<u64>, VerifyWireReceiptError> {
    match value.get(field) {
        Some(WireValue::Null) => Ok(None),
        Some(_) => number(value, field)
            .map(Some)
            .ok_or(VerifyWireReceiptError::Invalid),
        None => Ok(None),
    }
}
fn optional_field_equals(value: &WireValue, field: &str, expected: Option<&str>) -> bool {
    match (value.get(field), expected) {
        (Some(WireValue::Null), None) => true,
        (Some(value), Some(expected)) => value.as_string().as_deref() == Some(expected),
        _ => false,
    }
}
fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
