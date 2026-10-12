//! Authenticate exact saved kernel command bytes before using them as receipt pins.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, decode_base64url, key_id, sha256_hex, verifying_key},
    discovery::ParsedDiscovery,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use thiserror::Error;

const COMMAND_TYPE: &str = "peerwork.kernel-command.v1+jws";

#[derive(Debug, Error)]
pub enum PreparedCommandError {
    #[error("signed command, body, or pinned identity is invalid")]
    Invalid,
}

/// Exact signed bytes for the durable intent journal. Keep this internal to
/// runtime; bindings should expose only redacted command metadata.
pub struct SignedPreparedCommand {
    command_canonical: String,
    jws: String,
    http_body: Vec<u8>,
    proof: VerifiedPreparedCommand,
}

impl SignedPreparedCommand {
    pub fn command_canonical(&self) -> &str {
        &self.command_canonical
    }
    pub fn jws(&self) -> &str {
        &self.jws
    }
    pub fn http_body(&self) -> &[u8] {
        &self.http_body
    }
    pub fn proof(&self) -> &VerifiedPreparedCommand {
        &self.proof
    }
}

/// Sign a fully specified command after tracked schema and byte validation.
/// The caller supplies the command ID and timestamps before durable insertion;
/// the signing key remains in the caller's protected in-memory identity store.
pub fn prepare_signed_command_wire(
    command: &WireValue,
    signing_key: &SigningKey,
    discovery: &ParsedDiscovery,
    upload_chunk: Option<&[u8]>,
) -> Result<SignedPreparedCommand, PreparedCommandError> {
    let invalid = || PreparedCommandError::Invalid;
    let public = signing_key.verifying_key().to_bytes();
    let kid = key_id(&public);
    let actor = actor_id(&public);
    validate_command_schema(command, discovery.audience_utf16(), &actor).map_err(|_| invalid())?;
    let command_canonical = canonical_wire_value(command, Path::COMMAND).map_err(|_| invalid())?;
    if command_canonical.len() > 180_000 {
        return Err(invalid());
    }
    // Constructed WireValue objects may contain duplicate members even though
    // wire parsing rejects them. Reparse the exact signed bytes in strict mode.
    parse_wire_json_bounded(command_canonical.as_bytes(), 40, 180_000).map_err(|_| invalid())?;
    let header = WireValue::Object(vec![
        (
            "alg".encode_utf16().collect(),
            WireValue::String("EdDSA".encode_utf16().collect()),
        ),
        (
            "typ".encode_utf16().collect(),
            WireValue::String(COMMAND_TYPE.encode_utf16().collect()),
        ),
        (
            "kid".encode_utf16().collect(),
            WireValue::String(kid.encode_utf16().collect()),
        ),
    ]);
    let header_canonical = canonical_wire_value(&header, Path::KERNEL).map_err(|_| invalid())?;
    let signing_input = format!(
        "{}.{}",
        base64url(header_canonical.as_bytes()),
        base64url(command_canonical.as_bytes())
    );
    let signature = base64url(&signing_key.sign(signing_input.as_bytes()).to_bytes());
    let jws = format!("{signing_input}.{signature}");
    if jws.len() > 250_000 {
        return Err(invalid());
    }
    let path = command
        .get("path")
        .and_then(WireValue::as_string)
        .ok_or_else(invalid)?;
    let mut body = String::new();
    if path == "/api/workspace/v1/catalog/upload" {
        let chunk = upload_chunk.ok_or_else(invalid)?;
        if chunk.is_empty() || chunk.len() > 64 * 1024 {
            return Err(invalid());
        }
        validate_catalog_chunk(command.get("body").ok_or_else(invalid)?, chunk)
            .map_err(|_| invalid())?;
        body.push_str("{\"chunk\":\"");
        body.push_str(&base64url(chunk));
        body.push_str("\",\"command\":{\"jws\":\"");
        body.push_str(&jws);
        body.push_str("\"}}");
    } else {
        if upload_chunk.is_some() {
            return Err(invalid());
        }
        body.push_str("{\"jws\":\"");
        body.push_str(&jws);
        body.push_str("\"}");
    }
    let http_body = body.into_bytes();
    let proof = verify_prepared_command_wire(
        &jws,
        &http_body,
        &CommandPins {
            local_key_id: &kid,
            audience_utf16: discovery.audience_utf16(),
        },
    )?;
    Ok(SignedPreparedCommand {
        command_canonical,
        jws,
        http_body,
        proof,
    })
}

fn validate_catalog_chunk(body: &WireValue, chunk: &[u8]) -> Result<(), ()> {
    let WireValue::Object(fields) = body else {
        return Err(());
    };
    let required = [
        "bundle_digest",
        "byte_length",
        "chunk_digest",
        "index",
        "offset",
        "upload_id",
    ];
    if fields.len() != required.len() || required.iter().any(|name| body.get(name).is_none()) {
        return Err(());
    }
    if !body
        .get("bundle_digest")
        .and_then(WireValue::as_string)
        .is_some_and(|value| hex_digest(&value))
        || body.get("byte_length").and_then(WireValue::as_number) != Some(chunk.len() as f64)
        || body
            .get("chunk_digest")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(sha256_hex(chunk).as_str())
        || !safe_number(body.get("index"), false)
        || !safe_number(body.get("offset"), false)
        || !body
            .get("upload_id")
            .and_then(WireValue::as_string)
            .is_some_and(|value| token(&value))
    {
        return Err(());
    }
    Ok(())
}

fn validate_command_schema(command: &WireValue, audience: &[u16], actor: &str) -> Result<(), ()> {
    const FIELDS: [&str; 17] = [
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
    let WireValue::Object(fields) = command else {
        return Err(());
    };
    if fields.len() != FIELDS.len() || FIELDS.iter().any(|name| command.get(name).is_none()) {
        return Err(());
    }
    if command.get("v").and_then(WireValue::as_number) != Some(1.0)
        || command.get("audience").and_then(WireValue::as_utf16) != Some(audience)
        || command
            .get("actor_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(actor)
        || command
            .get("method")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some("POST")
    {
        return Err(());
    }
    if !command
        .get("command_id")
        .and_then(WireValue::as_string)
        .is_some_and(|s| token(&s))
        || !command
            .get("authority")
            .and_then(WireValue::as_string)
            .is_some_and(|s| hex_digest(&s))
    {
        return Err(());
    }
    let path = command
        .get("path")
        .and_then(WireValue::as_string)
        .ok_or(())?;
    if !matches!(
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
        return Err(());
    }
    for name in ["workspace_id", "instance_id"] {
        if !nullable(command.get(name), token) {
            return Err(());
        }
    }
    if !nullable(command.get("protocol_digest"), hex_digest) {
        return Err(());
    }
    if !command
        .get("action_id")
        .and_then(WireValue::as_utf16)
        .is_some_and(|s| !s.is_empty() && s.len() <= 120)
    {
        return Err(());
    }
    for name in ["expected_workspace_revision", "expected_instance_revision"] {
        if !nullable_number(command.get(name), false) {
            return Err(());
        }
    }
    for (name, positive) in [("issued_at", false), ("expires_at", true)] {
        if !safe_number(command.get(name), positive) {
            return Err(());
        }
    }
    let Some(WireValue::Array(refs)) = command.get("exact_input_refs") else {
        return Err(());
    };
    if refs.len() > 32 {
        return Err(());
    }
    for reference in refs {
        let WireValue::Object(fields) = reference else {
            return Err(());
        };
        if fields.len() != 2
            || !reference
                .get("record_id")
                .and_then(WireValue::as_string)
                .is_some_and(|s| token(&s))
            || !safe_number(reference.get("revision"), true)
        {
            return Err(());
        }
    }
    let body = command.get("body").ok_or(())?;
    let special = matches!(
        command
            .get("action_id")
            .and_then(WireValue::as_string)
            .as_deref(),
        Some(
            "protocol.publish"
                | "admin.draft.create"
                | "admin.draft.update"
                | "protocol.package.derive.preview"
        )
    );
    validate_json_strings(body)?;
    canonical_wire_value(
        body,
        Path::Kernel {
            max_depth: if special { 32 } else { 12 },
        },
    )
    .map_err(|_| ())?;
    Ok(())
}
fn validate_json_strings(value: &WireValue) -> Result<(), ()> {
    match value {
        WireValue::String(units) => {
            if String::from_utf16_lossy(units).len() > 8192 {
                return Err(());
            }
        }
        WireValue::Array(items) => {
            for item in items {
                validate_json_strings(item)?
            }
        }
        WireValue::Object(fields) => {
            for (_, item) in fields {
                validate_json_strings(item)?
            }
        }
        _ => {}
    }
    Ok(())
}
fn safe_number(value: Option<&WireValue>, positive: bool) -> bool {
    value.and_then(WireValue::as_number).is_some_and(|n| {
        n.is_finite()
            && n.fract() == 0.0
            && n <= 9_007_199_254_740_991.0
            && if positive { n > 0.0 } else { n >= 0.0 }
    })
}
fn nullable_number(value: Option<&WireValue>, positive: bool) -> bool {
    matches!(value, Some(WireValue::Null)) || safe_number(value, positive)
}
fn nullable(value: Option<&WireValue>, check: fn(&str) -> bool) -> bool {
    matches!(value, Some(WireValue::Null))
        || value
            .and_then(WireValue::as_string)
            .is_some_and(|s| check(&s))
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

/// The caller must obtain these pins from its local identity and pinned discovery.
pub struct CommandPins<'a> {
    pub local_key_id: &'a str,
    pub audience_utf16: &'a [u16],
}

/// Private-constructor evidence bound to a verified signature and exact HTTP body.
#[derive(Debug, Clone)]
pub struct VerifiedPreparedCommand {
    command_canonical_json: String,
    command_id: String,
    actor_id: String,
    intent_digest: String,
    path: String,
    audience_utf16: Vec<u16>,
    workspace_id: Option<String>,
    protocol_digest: Option<String>,
}

impl VerifiedPreparedCommand {
    /// Canonical payload from the authenticated, schema-validated JWS.
    /// Keep this within trusted runtime code; do not expose it in bindings.
    pub fn command_canonical_json(&self) -> &str {
        &self.command_canonical_json
    }
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
    let expected_actor = actor_id(&key.to_bytes());
    validate_command_schema(&payload, pins.audience_utf16, &expected_actor)
        .map_err(|_| invalid())?;
    if canonical_wire_value(&payload, Path::COMMAND)
        .map_err(|_| invalid())?
        .as_bytes()
        != payload_bytes.as_slice()
    {
        return Err(invalid());
    }
    let command_id = string(&payload, "command_id").ok_or_else(invalid)?;
    let path = string(&payload, "path").ok_or_else(invalid)?;
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
        if nested.object_len() != Some(1)
            || string(&payload, "action_id").as_deref() != Some("catalog.upload.chunk")
            || chunk_bytes.is_empty()
            || chunk_bytes.len() > 64 * 1024
            || validate_catalog_chunk(payload.get("body").ok_or_else(invalid)?, &chunk_bytes)
                .is_err()
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
        command_canonical_json: String::from_utf8(payload_bytes).map_err(|_| invalid())?,
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
