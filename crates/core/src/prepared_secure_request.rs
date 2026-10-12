//! Pre-submit integrity proof for one narrow secure append request shape.
//! This does not establish policy scope, journal acceptance, or an action effect.

use crate::{
    canonical::Path,
    crypto::{actor_id, decode_base64url, sha256_hex, verify_secure_signed_wire},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use thiserror::Error;

const PREFIX: &str = "/api/workspace/v1/secure/workspaces/";
const SUFFIX: &str = "/commits";
const REQUEST_LIMIT: usize = 220_000;
const COMMIT_LIMIT: usize = 196_608;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PreparedSecureRequestError {
    #[error("saved secure request or pinned context is invalid")]
    Invalid,
}

/// Pins must be derived by runtime from protected local identity and a verified,
/// persisted workspace context. Supplying arbitrary pins cannot grant authority.
pub struct SecureCommitRequestPins<'a> {
    pub actor_id: &'a str,
    pub signing_key: &'a str,
    pub workspace_id: &'a str,
    pub policy_hash: &'a str,
    pub sequence: u64,
    pub previous: Option<&'a str>,
    pub epoch: u64,
    pub mode: &'a str,
    pub version: u64,
    pub protocol_format_ceiling: Option<u64>,
}

/// Private-constructor proof of the exact signed packet and HTTP body. This
/// permits a later runtime row comparison before transport, never ACCEPTED.
pub struct VerifiedPreparedSecureRequest {
    command_id: String,
    workspace_id: String,
    actor_id: String,
    signing_key: String,
    action_id: String,
    path: String,
    policy_hash: String,
    request_sha256: String,
    commit_digest: String,
}

impl VerifiedPreparedSecureRequest {
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub fn signing_key(&self) -> &str {
        &self.signing_key
    }
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn commit_digest(&self) -> &str {
        &self.commit_digest
    }
}

/// Validate a saved commit-only append request. The service readJson parser
/// rejects duplicate decoded member names before admitting a request. No
/// request with policy_update, key_grants, delegation, or bootstrap is accepted.
pub fn verify_prepared_secure_commit_request(
    exact_request: &[u8],
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<VerifiedPreparedSecureRequest, PreparedSecureRequestError> {
    let invalid = || PreparedSecureRequestError::Invalid;
    if exact_request.is_empty()
        || exact_request.len() > REQUEST_LIMIT
        || !token(pins.actor_id)
        || !token(pins.signing_key)
        || !token(pins.workspace_id)
        || !digest(pins.policy_hash)
        || pins.previous.is_some_and(|value| !digest(value))
        || pins.sequence == 0
        || pins.sequence as f64 > MAX_SAFE
        || pins.epoch as f64 > MAX_SAFE
        || !matches!(pins.version, 1 | 3)
        || pins.mode != "PRIVATE"
        || pins.version == 3 && !matches!(pins.protocol_format_ceiling, Some(1 | 2))
        || pins.version != 3 && pins.protocol_format_ceiling.is_some()
    {
        return Err(invalid());
    }
    let Some(workspace) = path
        .strip_prefix(PREFIX)
        .and_then(|s| s.strip_suffix(SUFFIX))
    else {
        return Err(invalid());
    };
    if workspace != pins.workspace_id || !token(workspace) {
        return Err(invalid());
    }
    let request =
        parse_wire_json_bounded(exact_request, 64, REQUEST_LIMIT).map_err(|_| invalid())?;
    exact_keys(&request, &["commit"])?;
    let commit = request.get("commit").ok_or_else(invalid)?;
    exact_keys(commit, &["payload", "signature"])?;
    let payload = commit.get("payload").ok_or_else(invalid)?;
    // Only unstructured, direct-author commits are admitted by this proof.
    // Structured and delegated variants need independent full-context proof.
    let mut required = vec![
        "v",
        "workspace_id",
        "sequence",
        "previous",
        "policy_hash",
        "epoch",
        "actor_id",
        "signing_key",
        "command_id",
        "action_id",
        "instance_id",
        "issued_at",
        "delegation",
        "mode",
        "body",
    ];
    if pins.version == 3 {
        required.push("protocol_format_ceiling");
    }
    exact_keys(payload, &required)?;
    if number(payload, "v")? != pins.version
        || number(payload, "sequence")? != pins.sequence
        || number(payload, "epoch")? != pins.epoch
        || number(payload, "issued_at").is_err()
        || string(payload, "workspace_id")? != pins.workspace_id
        || string(payload, "actor_id")? != pins.actor_id
        || string(payload, "signing_key")? != pins.signing_key
        || string(payload, "policy_hash")? != pins.policy_hash
        || string(payload, "mode")? != pins.mode
        || nullable_string(payload, "previous")?.as_deref() != pins.previous
        || !matches!(payload.get("delegation"), Some(WireValue::Null))
        || payload.get("instance_id").is_none()
        || nullable_token(payload, "instance_id").is_err()
        || pins.version == 3
            && number(payload, "protocol_format_ceiling")?
                != pins.protocol_format_ceiling.unwrap_or(0)
    {
        return Err(invalid());
    }
    let key: [u8; 32] = decode_base64url(pins.signing_key)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    if actor_id(&key) != pins.actor_id {
        return Err(invalid());
    }
    let command_id = string(payload, "command_id")?;
    let action_id = string(payload, "action_id")?;
    if !token(&command_id)
        || action_id.is_empty()
        || action_id.len() > 120
        || action_id.starts_with("secure.convert.")
        || action_id == "secure.bootstrap"
        || action_id == "secure.recover"
        || action_id == "secure.protocol-format.upgrade"
        || payload.get("migration").is_some()
        || payload.get("recovery").is_some()
        || payload.get("conversion_excluded_members").is_some()
    {
        return Err(invalid());
    }
    let body = payload.get("body").ok_or_else(invalid)?;
    validate_ciphertext(body)?;
    let commit_canonical =
        canonical_wire_value(commit, Path::SecureArtifact).map_err(|_| invalid())?;
    if commit_canonical.len() > COMMIT_LIMIT
        || !verify_secure_signed_wire(
            commit_canonical.as_bytes(),
            "peerwork.secure.commit.v1",
            pins.signing_key,
        )
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(VerifiedPreparedSecureRequest {
        command_id,
        workspace_id: pins.workspace_id.into(),
        actor_id: pins.actor_id.into(),
        signing_key: pins.signing_key.into(),
        action_id,
        path: path.into(),
        policy_hash: pins.policy_hash.into(),
        request_sha256: sha256_hex(exact_request),
        commit_digest: sha256_hex(commit_canonical.as_bytes()),
    })
}

fn exact_keys(value: &WireValue, keys: &[&str]) -> Result<(), PreparedSecureRequestError> {
    let WireValue::Object(fields) = value else {
        return Err(PreparedSecureRequestError::Invalid);
    };
    if fields.len() != keys.len() || keys.iter().any(|key| value.get(key).is_none()) {
        return Err(PreparedSecureRequestError::Invalid);
    }
    Ok(())
}
fn string(value: &WireValue, key: &str) -> Result<String, PreparedSecureRequestError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(PreparedSecureRequestError::Invalid)
}
fn number(value: &WireValue, key: &str) -> Result<u64, PreparedSecureRequestError> {
    let n = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(PreparedSecureRequestError::Invalid)?;
    if !n.is_finite() || n < 0.0 || n > MAX_SAFE || n.fract() != 0.0 {
        return Err(PreparedSecureRequestError::Invalid);
    }
    Ok(n as u64)
}
fn nullable_string(
    value: &WireValue,
    key: &str,
) -> Result<Option<String>, PreparedSecureRequestError> {
    match value.get(key) {
        Some(WireValue::Null) => Ok(None),
        Some(_) => string(value, key).map(Some),
        None => Err(PreparedSecureRequestError::Invalid),
    }
}
fn nullable_token(value: &WireValue, key: &str) -> Result<(), PreparedSecureRequestError> {
    if nullable_string(value, key)?.is_some_and(|s| !token(&s)) {
        return Err(PreparedSecureRequestError::Invalid);
    }
    Ok(())
}
fn token(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn validate_ciphertext(body: &WireValue) -> Result<(), PreparedSecureRequestError> {
    exact_keys(body, &["v", "alg", "nonce", "chunks"])?;
    if number(body, "v")? != 1 || string(body, "alg")? != "A256GCM" {
        return Err(PreparedSecureRequestError::Invalid);
    }
    let nonce = string(body, "nonce")?;
    let bytes = decode_base64url(&nonce).map_err(|_| PreparedSecureRequestError::Invalid)?;
    if bytes.len() != 12 {
        return Err(PreparedSecureRequestError::Invalid);
    }
    let Some(WireValue::Array(chunks)) = body.get("chunks") else {
        return Err(PreparedSecureRequestError::Invalid);
    };
    if chunks.is_empty() || chunks.len() > 128 {
        return Err(PreparedSecureRequestError::Invalid);
    }
    for chunk in chunks {
        let s = chunk
            .as_string()
            .ok_or(PreparedSecureRequestError::Invalid)?;
        if s.is_empty()
            || s.len() > 8192
            || decode_base64url(&s)
                .map_err(|_| PreparedSecureRequestError::Invalid)?
                .is_empty()
        {
            return Err(PreparedSecureRequestError::Invalid);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{base64url, sign_canonical};
    use ed25519_dalek::SigningKey;
    use serde_json::{json, Value};

    fn fixture() -> (Vec<u8>, String, String, String, String, String) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let key = base64url(&signing.verifying_key().to_bytes());
        let actor = actor_id(&signing.verifying_key().to_bytes());
        let workspace = "w".repeat(43);
        let policy = "a".repeat(64);
        let path = format!("{PREFIX}{workspace}{SUFFIX}");
        let payload = json!({
            "v": 3, "workspace_id": workspace, "sequence": 2, "previous": "b".repeat(64),
            "policy_hash": policy, "epoch": 1, "actor_id": actor, "signing_key": key,
            "command_id": "c".repeat(43), "action_id": "discussion.post",
            "instance_id": "i".repeat(43), "issued_at": 1_700_000_000_000_u64,
            "delegation": null, "mode": "PRIVATE", "protocol_format_ceiling": 1,
            "body": {"v":1,"alg":"A256GCM","nonce":base64url(&[1;12]),"chunks":[base64url(&[2;16])]}
        });
        let wire = request_for(payload);
        (wire, path, actor, key, workspace, policy)
    }

    fn request_for(payload: Value) -> Vec<u8> {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let domain = match payload["v"].as_u64() {
            Some(3) => "peerwork.secure.commit.v3",
            Some(2) => "peerwork.secure.commit.v2",
            _ => "peerwork.secure.commit.v1",
        };
        let signature = sign_canonical(domain, &payload, &signing).unwrap();
        serde_json::to_vec(&json!({"commit":{"payload":payload,"signature":signature}})).unwrap()
    }

    fn verify(
        wire: &[u8],
        path: &str,
        actor: &str,
        key: &str,
        workspace: &str,
        policy: &str,
    ) -> Result<VerifiedPreparedSecureRequest, PreparedSecureRequestError> {
        verify_prepared_secure_commit_request(
            wire,
            path,
            &SecureCommitRequestPins {
                actor_id: actor,
                signing_key: key,
                workspace_id: workspace,
                policy_hash: policy,
                sequence: 2,
                previous: Some(&"b".repeat(64)),
                epoch: 1,
                mode: "PRIVATE",
                version: 3,
                protocol_format_ceiling: Some(1),
            },
        )
    }

    #[test]
    fn signed_saved_request_binds_exact_route_and_pins() {
        let (wire, path, actor, key, workspace, policy) = fixture();
        let proof = verify(&wire, &path, &actor, &key, &workspace, &policy).unwrap();
        assert_eq!(proof.command_id(), "c".repeat(43));
        assert_eq!(proof.action_id(), "discussion.post");
        assert_eq!(proof.request_sha256(), sha256_hex(&wire));
        assert!(verify(
            &wire,
            "/api/workspace/v1/secure/workspaces/wrong/commits",
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_err());
        assert!(verify(&wire, &path, &actor, &key, &"x".repeat(43), &policy).is_err());
        assert!(verify(&wire, &path, &actor, &key, &workspace, &"0".repeat(64)).is_err());
        assert!(verify(&wire, &path, &"x".repeat(43), &key, &workspace, &policy).is_err());
        assert!(verify(&wire, &path, &actor, &"x".repeat(43), &workspace, &policy).is_err());
    }

    #[test]
    fn signed_wrong_context_and_unsigned_mutation_refused() {
        let (wire, path, actor, key, workspace, policy) = fixture();
        let parsed: Value = serde_json::from_slice(&wire).unwrap();
        for (field, replacement) in [
            ("workspace_id", json!("x".repeat(43))),
            ("actor_id", json!("x".repeat(43))),
            ("signing_key", json!("x".repeat(43))),
            ("policy_hash", json!("0".repeat(64))),
            ("sequence", json!(3)),
            ("previous", json!(null)),
            ("epoch", json!(2)),
            ("mode", json!("PUBLIC")),
            ("v", json!(2)),
            ("protocol_format_ceiling", json!(2)),
        ] {
            let mut changed = parsed["commit"]["payload"].clone();
            changed[field] = replacement;
            let resigned = request_for(changed);
            assert!(
                verify(&resigned, &path, &actor, &key, &workspace, &policy).is_err(),
                "{field}"
            );
        }
        let mut unsigned = parsed;
        unsigned["commit"]["payload"]["action_id"] = json!("wiki.revise");
        assert!(verify(
            &serde_json::to_vec(&unsigned).unwrap(),
            &path,
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_err());
    }

    #[test]
    fn unsupported_and_duplicate_request_shapes_refused() {
        let (wire, path, actor, key, workspace, policy) = fixture();
        let mut parsed: Value = serde_json::from_slice(&wire).unwrap();
        parsed["policy_update"] = json!(null);
        assert!(verify(
            &serde_json::to_vec(&parsed).unwrap(),
            &path,
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_err());
        let duplicate = format!(
            "{{\"commit\":null,{}",
            &String::from_utf8(wire).unwrap()[1..]
        );
        assert!(verify(
            duplicate.as_bytes(),
            &path,
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_err());
    }
}
