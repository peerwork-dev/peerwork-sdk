//! Pre-submit integrity proof for one narrow secure append request shape.
//! This does not establish policy scope, journal acceptance, or an action effect.

use crate::{
    canonical::Path,
    crypto::{actor_id, decode_base64url, sha256_hex, verify_secure_signed_wire},
    secure_action_delegation::resolve_action_scope,
    structure_delta::validate_projection_page,
    structure_policy::validate_structure_policy,
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

/// Validate the original direct, unstructured saved commit-only append shape.
/// The service readJson parser rejects duplicate decoded member names. New
/// structured/delegated submissions use the policy-bound variant below.
pub fn verify_prepared_secure_commit_request(
    exact_request: &[u8],
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<VerifiedPreparedSecureRequest, PreparedSecureRequestError> {
    verify_prepared_secure_commit_request_inner(exact_request, path, pins, None)
}

/// Pre-submit integrity for a commit under the exact signed selected policy.
/// The runtime must obtain this policy from a complete, origin-bound replay;
/// arbitrary caller-supplied policy bytes cannot establish action authority.
/// Server admission, delegation session state and final effects remain separate.
pub fn verify_prepared_secure_commit_request_with_policy(
    exact_request: &[u8],
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
    signed_policy_wire: &[u8],
    trusted_owner_key: &str,
) -> Result<VerifiedPreparedSecureRequest, PreparedSecureRequestError> {
    let invalid = || PreparedSecureRequestError::Invalid;
    if signed_policy_wire.is_empty() || signed_policy_wire.len() > COMMIT_LIMIT {
        return Err(invalid());
    }
    let policy =
        parse_wire_json_bounded(signed_policy_wire, 64, COMMIT_LIMIT).map_err(|_| invalid())?;
    exact_keys(&policy, &["payload", "signature"])?;
    let policy_payload = policy.get("payload").ok_or_else(invalid)?;
    let canonical = canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| invalid())?;
    if sha256_hex(canonical.as_bytes()) != pins.policy_hash
        || string(policy_payload, "signing_key")? != trusted_owner_key
        || string(policy_payload, "owner_id")?
            != actor_id(
                &decode_base64url(trusted_owner_key)
                    .map_err(|_| invalid())?
                    .try_into()
                    .map_err(|_| invalid())?,
            )
        || string(policy_payload, "workspace_id")? != pins.workspace_id
        || number(policy_payload, "v")? != pins.version
        || number(policy_payload, "epoch")? != pins.epoch
        || number(policy_payload, "effective_sequence")? > pins.sequence
        || string(policy_payload, "visibility")? != pins.mode
        || !verify_secure_signed_wire(
            canonical.as_bytes(),
            "peerwork.secure.policy.v1",
            trusted_owner_key,
        )
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let structured = match pins.version {
        1 => false,
        2 => true,
        3 => {
            if number(policy_payload, "protocol_format_ceiling")?
                != pins.protocol_format_ceiling.ok_or_else(invalid)?
            {
                return Err(invalid());
            }
            match string(policy_payload, "structure_mode")?.as_str() {
                "NONE" => false,
                "STRUCTURED" => true,
                _ => return Err(invalid()),
            }
        }
        _ => return Err(invalid()),
    };
    if structured {
        validate_structure_policy(policy_payload.get("structure").ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    } else if policy_payload.get("structure").is_some() {
        return Err(invalid());
    }
    verify_prepared_secure_commit_request_inner(
        exact_request,
        path,
        pins,
        Some((policy_payload, structured)),
    )
}

fn verify_prepared_secure_commit_request_inner(
    exact_request: &[u8],
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
    authenticated_policy: Option<(&WireValue, bool)>,
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
        || !matches!(pins.version, 1 | 3) && authenticated_policy.is_none()
        || !matches!(pins.version, 1 | 2 | 3)
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
    let structured = authenticated_policy.is_some_and(|(_, structured)| structured);
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
    if structured {
        required.push("structure");
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
        || authenticated_policy.is_none()
            && !matches!(payload.get("delegation"), Some(WireValue::Null))
        || payload.get("instance_id").is_none()
        || nullable_token(payload, "instance_id").is_err()
        || pins.version == 3
            && number(payload, "protocol_format_ceiling")?
                != pins.protocol_format_ceiling.unwrap_or(0)
    {
        return Err(invalid());
    }
    if structured {
        let envelope = payload.get("structure").ok_or_else(invalid)?;
        // ACTION preparation emits a DELTA. Snapshot-family authoring remains
        // a separate signed migration/recovery path.
        exact_keys(envelope, &["v", "mode", "records", "heads"])?;
        if number(envelope, "v")? != 1 || string(envelope, "mode")? != "DELTA" {
            return Err(invalid());
        }
        let Some(WireValue::Array(records)) = envelope.get("records") else {
            return Err(invalid());
        };
        let Some(WireValue::Array(heads)) = envelope.get("heads") else {
            return Err(invalid());
        };
        if records.len() > 128 || heads.len() > 128 {
            return Err(invalid());
        }
        let contract = authenticated_policy
            .and_then(|(policy, _)| policy.get("structure"))
            .ok_or_else(invalid)?;
        validate_projection_page(records, heads, contract).map_err(|_| invalid())?;
    }
    if let Some((policy_payload, _)) = authenticated_policy {
        let delegation = match payload.get("delegation") {
            Some(WireValue::Null) => None,
            Some(value) => {
                Some(canonical_wire_value(value, Path::SecureArtifact).map_err(|_| invalid())?)
            }
            None => return Err(invalid()),
        };
        let scope = resolve_action_scope(
            payload,
            policy_payload,
            delegation.as_deref().map(str::as_bytes),
        )
        .map_err(|_| invalid())?;
        if !scope.permits_action() {
            return Err(invalid());
        }
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
    let mut ciphertext_len = 0usize;
    for chunk in chunks {
        let s = chunk
            .as_string()
            .ok_or(PreparedSecureRequestError::Invalid)?;
        if s.is_empty() || s.len() > 8192 {
            return Err(PreparedSecureRequestError::Invalid);
        }
        let bytes = decode_base64url(&s).map_err(|_| PreparedSecureRequestError::Invalid)?;
        if bytes.is_empty() {
            return Err(PreparedSecureRequestError::Invalid);
        }
        ciphertext_len = ciphertext_len
            .checked_add(bytes.len())
            .ok_or(PreparedSecureRequestError::Invalid)?;
    }
    if !(16..=16 * 1024 * 1024 + 16).contains(&ciphertext_len) {
        return Err(PreparedSecureRequestError::Invalid);
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

    #[test]
    fn signed_ciphertext_meets_server_and_decoder_bounds() {
        let (wire, path, actor, key, workspace, policy) = fixture();
        let parsed: Value = serde_json::from_slice(&wire).unwrap();
        let mut payload = parsed["commit"]["payload"].clone();
        payload["body"]["chunks"] = json!([base64url(&[1])]);
        assert!(verify(
            &request_for(payload.clone()),
            &path,
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_err());
        payload["body"]["chunks"] = json!([base64url(&[1; 8]), base64url(&[2; 8])]);
        assert!(verify(
            &request_for(payload.clone()),
            &path,
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_ok());
        // The local decoder permits an empty component, but the HTTP server's
        // validateCommit rejects it before appending a commit.
        payload["body"]["chunks"] = json!(["", base64url(&[2; 16])]);
        assert!(verify(
            &request_for(payload),
            &path,
            &actor,
            &key,
            &workspace,
            &policy
        )
        .is_err());
    }

    #[test]
    fn signed_structured_delegated_source_packet_requires_exact_selected_policy() {
        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/signed-recovery-vectors.json"
        ))
        .unwrap();
        for name in [
            "signed_delegated_wiki_action_corrected",
            "signed_delegated_zero_record_action",
        ] {
            let case = vectors["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap();
            let policy = &case["policy"];
            let commit = &case["commits"][1];
            let payload = &commit["payload"];
            let request = serde_json::to_vec(&json!({"commit":commit})).unwrap();
            let policy_wire = serde_json::to_vec(policy).unwrap();
            let workspace = payload["workspace_id"].as_str().unwrap();
            let path = format!("{PREFIX}{workspace}{SUFFIX}");
            let previous = payload["previous"].as_str();
            let pins = SecureCommitRequestPins {
                actor_id: payload["actor_id"].as_str().unwrap(),
                signing_key: payload["signing_key"].as_str().unwrap(),
                workspace_id: workspace,
                policy_hash: payload["policy_hash"].as_str().unwrap(),
                sequence: payload["sequence"].as_u64().unwrap(),
                previous,
                epoch: payload["epoch"].as_u64().unwrap(),
                mode: payload["mode"].as_str().unwrap(),
                version: payload["v"].as_u64().unwrap(),
                protocol_format_ceiling: None,
            };
            assert!(verify_prepared_secure_commit_request(&request, &path, &pins).is_err());
            let proof = verify_prepared_secure_commit_request_with_policy(
                &request,
                &path,
                &pins,
                &policy_wire,
                policy["payload"]["signing_key"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(proof.command_id(), payload["command_id"].as_str().unwrap());
            let mut wrong_policy = policy.clone();
            wrong_policy["payload"]["epoch"] = json!(2);
            assert!(verify_prepared_secure_commit_request_with_policy(
                &request,
                &path,
                &pins,
                &serde_json::to_vec(&wrong_policy).unwrap(),
                policy["payload"]["signing_key"].as_str().unwrap(),
            )
            .is_err());
            let mut wrong_delegation = commit.clone();
            wrong_delegation["payload"]["delegation"] = Value::Null;
            assert!(verify_prepared_secure_commit_request_with_policy(
                &serde_json::to_vec(&json!({"commit":wrong_delegation})).unwrap(),
                &path,
                &pins,
                &policy_wire,
                policy["payload"]["signing_key"].as_str().unwrap(),
            )
            .is_err());
        }
    }
}
