//! Authenticate exact saved kernel command bytes before using them as receipt pins.

use crate::{
    canonical::Path,
    crypto::{actor_id, decode_base64url, sha256_hex, verifying_key},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signature, Verifier};
use thiserror::Error;

const COMMAND_TYPE: &str = "peerwork.kernel-command.v1+jws";

#[derive(Debug, Error)]
pub enum PreparedCommandError {
    #[error("signed command, body, or pinned identity is invalid")]
    Invalid,
}

/// The caller must obtain these pins from its local identity and pinned discovery.
pub struct CommandPins<'a> {
    pub local_key_id: &'a str,
    pub audience_utf16: &'a [u16],
}

/// Private-constructor evidence bound to a verified signature and exact HTTP body.
#[derive(Debug, Clone)]
pub struct VerifiedPreparedCommand {
    command_id: String,
    actor_id: String,
    intent_digest: String,
    path: String,
    audience_utf16: Vec<u16>,
    workspace_id: Option<String>,
    protocol_digest: Option<String>,
}

impl VerifiedPreparedCommand {
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
    pub fn path(&self) -> &str {
        &self.path
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
}

pub fn verify_prepared_command_wire(
    jws: &str,
    http_body: &[u8],
    pins: &CommandPins<'_>,
) -> Result<VerifiedPreparedCommand, PreparedCommandError> {
    let invalid = || PreparedCommandError::Invalid;
    if jws.len() > 250_000 || http_body.len() > 262_144 {
        return Err(invalid());
    }
    let parts: Vec<_> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let header_bytes = decode_base64url(parts[0]).map_err(|_| invalid())?;
    let payload_bytes = decode_base64url(parts[1]).map_err(|_| invalid())?;
    let sig: [u8; 64] = decode_base64url(parts[2])
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let header = parse_wire_json_bounded(&header_bytes, 3, 256).map_err(|_| invalid())?;
    if header.object_len() != Some(3)
        || string(&header, "alg").as_deref() != Some("EdDSA")
        || string(&header, "typ").as_deref() != Some(COMMAND_TYPE)
        || string(&header, "kid").as_deref() != Some(pins.local_key_id)
        || pins.audience_utf16.is_empty()
        || pins.audience_utf16.len() > 200
    {
        return Err(invalid());
    }
    let key = verifying_key(pins.local_key_id).map_err(|_| invalid())?;
    key.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| invalid())?;
    let payload = parse_wire_json_bounded(&payload_bytes, 40, 180_000).map_err(|_| invalid())?;
    let fields = [
        "v",
        "audience",
        "command_id",
        "actor_id",
        "authority",
        "method",
        "path",
        "workspace_id",
        "instance_id",
        "protocol_digest",
        "action_id",
        "expected_workspace_revision",
        "expected_instance_revision",
        "exact_input_refs",
        "body",
        "issued_at",
        "expires_at",
    ];
    if payload.object_len() != Some(fields.len())
        || fields.iter().any(|name| payload.get(name).is_none())
        || payload.get("v").and_then(WireValue::as_number) != Some(1.0)
        || payload.get("audience").and_then(WireValue::as_utf16) != Some(pins.audience_utf16)
        || string(&payload, "method").as_deref() != Some("POST")
        || canonical_wire_value(&payload, Path::COMMAND)
            .map_err(|_| invalid())?
            .as_bytes()
            != payload_bytes.as_slice()
    {
        return Err(invalid());
    }
    let command_id = string(&payload, "command_id").ok_or_else(invalid)?;
    let claimed_actor = string(&payload, "actor_id").ok_or_else(invalid)?;
    let expected_actor = actor_id(&key.to_bytes());
    let path = string(&payload, "path").ok_or_else(invalid)?;
    if !token(&command_id)
        || claimed_actor != expected_actor
        || !matches!(
            path.as_str(),
            "/api/workspace/v1/commands"
                | "/api/workspace/v1/catalog/upload"
                | "/api/workspace/v1/private/packages/upload"
        ) && !(path.starts_with("/api/workspace/v1/browser/sessions/")
            && path.ends_with("/commands")
            && path.len() == "/api/workspace/v1/browser/sessions/".len() + 43 + "/commands".len()
            && token(
                &path["/api/workspace/v1/browser/sessions/".len()..path.len() - "/commands".len()],
            ))
    {
        return Err(invalid());
    }
    let workspace_id = nullable_string(&payload, "workspace_id").ok_or_else(invalid)?;
    let protocol_digest = nullable_string(&payload, "protocol_digest").ok_or_else(invalid)?;
    let body = parse_wire_json_bounded(http_body, 42, 262_144).map_err(|_| invalid())?;
    let body_jws = if path == "/api/workspace/v1/catalog/upload" {
        if body.object_len() != Some(2) {
            return Err(invalid());
        }
        let nested = body.get("command").ok_or_else(invalid)?;
        let chunk = body
            .get("chunk")
            .and_then(WireValue::as_string)
            .ok_or_else(invalid)?;
        let chunk_bytes = decode_base64url(&chunk).map_err(|_| invalid())?;
        let declared_bytes = payload
            .get("body")
            .and_then(|v| v.get("byte_length"))
            .and_then(WireValue::as_number);
        let declared_digest = payload
            .get("body")
            .and_then(|v| v.get("chunk_digest"))
            .and_then(WireValue::as_string);
        if nested.object_len() != Some(1)
            || string(&payload, "action_id").as_deref() != Some("catalog.upload.chunk")
            || chunk_bytes.is_empty()
            || chunk_bytes.len() > 64 * 1024
            || declared_bytes != Some(chunk_bytes.len() as f64)
            || declared_digest.as_deref() != Some(sha256_hex(&chunk_bytes).as_str())
        {
            return Err(invalid());
        }
        string(nested, "jws")
    } else {
        if body.object_len() != Some(1) {
            return Err(invalid());
        }
        string(&body, "jws")
    };
    if body_jws.as_deref() != Some(jws)
        || canonical_wire_value(&body, Path::Kernel { max_depth: 42 })
            .map_err(|_| invalid())?
            .as_bytes()
            != http_body
    {
        return Err(invalid());
    }
    Ok(VerifiedPreparedCommand {
        command_id,
        actor_id: expected_actor,
        intent_digest: sha256_hex(jws.as_bytes()),
        path,
        audience_utf16: pins.audience_utf16.to_vec(),
        workspace_id,
        protocol_digest,
    })
}

fn string(value: &WireValue, field: &str) -> Option<String> {
    value.get(field)?.as_string()
}
fn nullable_string(value: &WireValue, field: &str) -> Option<Option<String>> {
    match value.get(field)? {
        WireValue::Null => Some(None),
        v => v.as_string().map(Some),
    }
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
