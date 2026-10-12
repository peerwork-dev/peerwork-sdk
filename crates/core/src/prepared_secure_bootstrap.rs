//! Exact signed owner-bootstrap request integrity before transport. This
//! proof does not decrypt/evaluate BOOTSTRAP objects or establish acceptance.

use crate::{
    canonical::Path,
    crypto::{actor_id, decode_base64url, sha256_hex},
    secure_chain::{scan_signed_chain_headers, OwnerPin},
    structure_bindings::validate_object_bindings,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use thiserror::Error;

const ROUTE: &str = "/api/workspace/v1/secure/workspaces";
const REQUEST_LIMIT: usize = 220_000;
const COMMIT_LIMIT: usize = 196_608;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapRequestError {
    #[error("saved owner-bootstrap request or trusted local identity is invalid")]
    Invalid,
}

/// Caller must derive the owner from the protected local signer and bind
/// `origin` through the configured TLS transport. These pins are not
/// independent authorization.
pub struct BootstrapPins<'a> {
    pub workspace_id: &'a str,
    pub owner_actor: &'a str,
    pub owner_key: &'a str,
}

/// Private-constructor pre-submit fact; do not treat this as a replayed
/// workspace, accepted command, usable epoch key, or public SDK capability.
pub struct VerifiedPreparedBootstrap {
    workspace_id: String,
    command_id: String,
    policy_hash: String,
    commit_digest: String,
    request_sha256: String,
    visibility: &'static str,
}
impl VerifiedPreparedBootstrap {
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn commit_digest(&self) -> &str {
        &self.commit_digest
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn path(&self) -> &'static str {
        ROUTE
    }
    pub fn visibility(&self) -> &'static str {
        self.visibility
    }
}

/// The tracked POST body is exactly `{policy,commit}`. Header verification
/// authenticates the owner, genesis policy, commit signature and sequence;
/// complete encrypted BOOTSTRAP operation replay remains a separate gate.
pub fn verify_prepared_owner_bootstrap(
    exact_request: &[u8],
    path: &str,
    pins: &BootstrapPins<'_>,
) -> Result<VerifiedPreparedBootstrap, BootstrapRequestError> {
    let bad = || BootstrapRequestError::Invalid;
    if path != ROUTE
        || exact_request.is_empty()
        || exact_request.len() > REQUEST_LIMIT
        || !token(pins.workspace_id)
        || !token(pins.owner_actor)
        || !token(pins.owner_key)
    {
        return Err(bad());
    }
    let owner_bytes: [u8; 32] = decode_base64url(pins.owner_key)
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())?;
    if actor_id(&owner_bytes) != pins.owner_actor {
        return Err(bad());
    }
    let request = parse_wire_json_bounded(exact_request, 64, REQUEST_LIMIT).map_err(|_| bad())?;
    exact_keys(&request, &["policy", "commit"])?;
    let policy = request.get("policy").ok_or_else(bad)?;
    let commit = request.get("commit").ok_or_else(bad)?;
    exact_keys(policy, &["payload", "signature"])?;
    exact_keys(commit, &["payload", "signature"])?;
    let pp = policy.get("payload").ok_or_else(bad)?;
    let cp = commit.get("payload").ok_or_else(bad)?;
    let visibility = string(pp, "visibility")?;
    let epoch = if visibility == "PRIVATE" {
        1
    } else if visibility == "PUBLIC" {
        0
    } else {
        return Err(bad());
    };
    if number(pp, "version")? != 1
        || number(pp, "effective_sequence")? != 1
        || !matches!(pp.get("previous_policy"), Some(WireValue::Null))
        || string(pp, "workspace_id")? != pins.workspace_id
        || string(pp, "owner_id")? != pins.owner_actor
        || string(pp, "signing_key")? != pins.owner_key
        || number(pp, "epoch")? != epoch
        || number(cp, "sequence")? != 1
        || !matches!(cp.get("previous"), Some(WireValue::Null))
        || string(cp, "workspace_id")? != pins.workspace_id
        || string(cp, "actor_id")? != pins.owner_actor
        || string(cp, "signing_key")? != pins.owner_key
        || string(cp, "action_id")? != "secure.bootstrap"
        || !matches!(cp.get("instance_id"), Some(WireValue::Null))
        || !matches!(cp.get("delegation"), Some(WireValue::Null))
        || string(cp, "mode")? != visibility
        || number(cp, "epoch")? != epoch
        || number(cp, "v")? == 3
            && ["migration", "recovery", "conversion_excluded_members"]
                .iter()
                .any(|name| cp.get(name).is_some())
    {
        return Err(bad());
    }
    let body = cp.get("body").ok_or_else(bad)?;
    if visibility == "PRIVATE" {
        validate_ciphertext(body)?;
    } else {
        validate_public_bootstrap(body)?;
        if let Some(structure) = pp.get("structure") {
            let Some(WireValue::Array(objects)) = body.get("objects") else {
                return Err(bad());
            };
            validate_object_bindings(structure, objects).map_err(|_| bad())?;
        }
    }
    let command_id = string(cp, "command_id")?;
    if !token(&command_id) {
        return Err(bad());
    }
    let policy_wire = canonical_wire_value(policy, Path::SecureArtifact).map_err(|_| bad())?;
    let commit_wire = canonical_wire_value(commit, Path::SecureArtifact).map_err(|_| bad())?;
    if commit_wire.len() > COMMIT_LIMIT {
        return Err(bad());
    }
    let policy_hash = sha256_hex(policy_wire.as_bytes());
    let commit_digest = sha256_hex(commit_wire.as_bytes());
    if string(cp, "policy_hash")? != policy_hash {
        return Err(bad());
    }
    let checkpoint = serde_json::json!({"v":1,"workspace_id":pins.workspace_id,
        "owner_id":pins.owner_actor,"owner_key":pins.owner_key,
        "sequence":1,"head":commit_digest,"policy_hash":policy_hash});
    let checkpoint_wire = serde_json::to_vec(&checkpoint).map_err(|_| bad())?;
    let chain = scan_signed_chain_headers(
        &[policy_wire.as_bytes()],
        &[commit_wire.as_bytes()],
        &checkpoint_wire,
        pins.workspace_id,
        Some(&OwnerPin {
            actor_id: pins.owner_actor,
            signing_key: pins.owner_key,
        }),
        None,
    )
    .map_err(|_| bad())?;
    if chain.sequence != 1
        || chain.head.as_deref() != Some(&commit_digest)
        || chain.policy_hash != policy_hash
    {
        return Err(bad());
    }
    Ok(VerifiedPreparedBootstrap {
        workspace_id: pins.workspace_id.into(),
        command_id,
        policy_hash,
        commit_digest,
        request_sha256: sha256_hex(exact_request),
        visibility: if visibility == "PUBLIC" {
            "PUBLIC"
        } else {
            "PRIVATE"
        },
    })
}

fn exact_keys(value: &WireValue, names: &[&str]) -> Result<(), BootstrapRequestError> {
    if value.object_len() != Some(names.len()) || names.iter().any(|name| value.get(name).is_none())
    {
        return Err(BootstrapRequestError::Invalid);
    }
    Ok(())
}
fn string(value: &WireValue, name: &str) -> Result<String, BootstrapRequestError> {
    value
        .get(name)
        .and_then(WireValue::as_string)
        .ok_or(BootstrapRequestError::Invalid)
}
fn number(value: &WireValue, name: &str) -> Result<u64, BootstrapRequestError> {
    let n = value
        .get(name)
        .and_then(WireValue::as_number)
        .ok_or(BootstrapRequestError::Invalid)?;
    if !n.is_finite() || n < 0.0 || n > MAX_SAFE || n.fract() != 0.0 {
        return Err(BootstrapRequestError::Invalid);
    }
    Ok(n as u64)
}
fn token(value: &str) -> bool {
    value.len() == 43 && decode_base64url(value).is_ok_and(|bytes| bytes.len() == 32)
}
fn validate_ciphertext(value: &WireValue) -> Result<(), BootstrapRequestError> {
    let bad = || BootstrapRequestError::Invalid;
    exact_keys(value, &["v", "alg", "nonce", "chunks"])?;
    if number(value, "v")? != 1 || string(value, "alg")? != "A256GCM" {
        return Err(bad());
    }
    let nonce = decode_base64url(&string(value, "nonce")?).map_err(|_| bad())?;
    if nonce.len() != 12 {
        return Err(bad());
    }
    let Some(WireValue::Array(chunks)) = value.get("chunks") else {
        return Err(bad());
    };
    if chunks.is_empty() || chunks.len() > 128 {
        return Err(bad());
    }
    let mut length = 0usize;
    for item in chunks {
        let encoded = item.as_string().ok_or_else(bad)?;
        if encoded.is_empty() || encoded.len() > 8192 {
            return Err(bad());
        }
        let decoded = decode_base64url(&encoded).map_err(|_| bad())?;
        if decoded.is_empty() {
            return Err(bad());
        }
        length = length.checked_add(decoded.len()).ok_or_else(bad)?;
    }
    if !(16..=16 * 1024 * 1024 + 16).contains(&length) {
        return Err(bad());
    }
    Ok(())
}

fn validate_public_bootstrap(value: &WireValue) -> Result<(), BootstrapRequestError> {
    let bad = || BootstrapRequestError::Invalid;
    exact_keys(value, &["v", "kind", "input", "objects"])?;
    if number(value, "v")? != 1
        || string(value, "kind")? != "BOOTSTRAP"
        || value.get("input").and_then(WireValue::object_len) != Some(0)
    {
        return Err(bad());
    }
    let Some(WireValue::Array(objects)) = value.get("objects") else {
        return Err(bad());
    };
    if objects.len() > 128 {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::canonical,
        crypto::{base64url, sign_canonical},
        secure_recipient::SecretRecipient,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::{json, Value};

    fn signed(payload: Value, domain: &str, key: &SigningKey) -> Value {
        json!({"signature":sign_canonical(domain,&payload,key).unwrap(),"payload":payload})
    }
    #[test]
    fn genesis_owner_packet_is_bound_to_exact_route_and_signatures() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let owner_key = base64url(&key.verifying_key().to_bytes());
        let owner_actor = actor_id(&key.verifying_key().to_bytes());
        let workspace = base64url(&[8u8; 32]);
        let certificate = SecretRecipient::generate()
            .unwrap()
            .certify(&key, 100)
            .unwrap();
        let policy = signed(
            json!({"v":1,"workspace_id":workspace,"owner_id":owner_actor,
            "signing_key":owner_key,"version":1,"previous_policy":null,
            "effective_sequence":1,"visibility":"PRIVATE","epoch":1,
            "members":[{"actor_id":owner_actor,"certificate":certificate,
                "role":"OWNER","scopes":[]}],"issued_at":100}),
            "peerwork.secure.policy.v1",
            &key,
        );
        let policy_hash = sha256_hex(canonical(&policy, Path::SecureArtifact).unwrap().as_bytes());
        let commit = signed(
            json!({"v":1,"workspace_id":workspace,"sequence":1,
            "previous":null,"policy_hash":policy_hash,"epoch":1,"actor_id":owner_actor,
            "signing_key":owner_key,"command_id":base64url(&[9u8;32]),
            "action_id":"secure.bootstrap","instance_id":null,"issued_at":100,
            "delegation":null,"mode":"PRIVATE",
            "body":{"v":1,"alg":"A256GCM","nonce":base64url(&[10u8;12]),
                "chunks":[base64url(&[11u8;32])]}}),
            "peerwork.secure.commit.v1",
            &key,
        );
        let request = json!({"policy":policy,"commit":commit});
        let wire = serde_json::to_vec(&request).unwrap();
        let pins = BootstrapPins {
            workspace_id: &workspace,
            owner_actor: &owner_actor,
            owner_key: &owner_key,
        };
        let proof = verify_prepared_owner_bootstrap(&wire, ROUTE, &pins).unwrap();
        assert_eq!(proof.path(), ROUTE);
        assert_eq!(proof.workspace_id(), workspace);
        assert_eq!(proof.command_id(), base64url(&[9u8; 32]));
        assert_eq!(proof.request_sha256(), sha256_hex(&wire));
        assert!(verify_prepared_owner_bootstrap(
            &wire,
            "/api/workspace/v1/secure/workspaces/x",
            &pins
        )
        .is_err());
        let mut changed = request.clone();
        changed["commit"]["payload"]["action_id"] = json!("secure.other");
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&changed).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());
        changed = request.clone();
        changed["policy"]["payload"]["owner_id"] = json!(base64url(&[12u8; 32]));
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&changed).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());
        changed = request.clone();
        changed["commit"]["signature"] = json!("a".repeat(86));
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&changed).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());

        // v3's generic signed shape permits these optional properties, but
        // WorkspaceSecureStore.bootstrap rejects their very presence.
        let mut v3 = request.clone();
        v3["policy"]["payload"]["v"] = json!(3);
        v3["policy"]["payload"]["structure_mode"] = json!("NONE");
        v3["policy"]["payload"]["protocol_format_ceiling"] = json!(1);
        v3["policy"]["signature"] =
            json!(
                sign_canonical("peerwork.secure.policy.v3", &v3["policy"]["payload"], &key)
                    .unwrap()
            );
        v3["commit"]["payload"]["v"] = json!(3);
        v3["commit"]["payload"]["protocol_format_ceiling"] = json!(1);
        v3["commit"]["payload"]["policy_hash"] = json!(sha256_hex(
            canonical(&v3["policy"], Path::SecureArtifact)
                .unwrap()
                .as_bytes()
        ));
        v3["commit"]["signature"] =
            json!(
                sign_canonical("peerwork.secure.commit.v3", &v3["commit"]["payload"], &key)
                    .unwrap()
            );
        assert!(
            verify_prepared_owner_bootstrap(&serde_json::to_vec(&v3).unwrap(), ROUTE, &pins)
                .is_ok()
        );
        let mut public = v3.clone();
        public["policy"]["payload"]["visibility"] = json!("PUBLIC");
        public["policy"]["payload"]["epoch"] = json!(0);
        public["policy"]["signature"] = json!(sign_canonical(
            "peerwork.secure.policy.v3",
            &public["policy"]["payload"],
            &key
        )
        .unwrap());
        public["commit"]["payload"]["policy_hash"] = json!(sha256_hex(
            canonical(&public["policy"], Path::SecureArtifact)
                .unwrap()
                .as_bytes()
        ));
        public["commit"]["payload"]["epoch"] = json!(0);
        public["commit"]["payload"]["mode"] = json!("PUBLIC");
        public["commit"]["payload"]["body"] =
            json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":[]});
        public["commit"]["signature"] = json!(sign_canonical(
            "peerwork.secure.commit.v3",
            &public["commit"]["payload"],
            &key
        )
        .unwrap());
        let public_proof =
            verify_prepared_owner_bootstrap(&serde_json::to_vec(&public).unwrap(), ROUTE, &pins)
                .unwrap();
        assert_eq!(public_proof.visibility(), "PUBLIC");
        let mut structured = public.clone();
        structured["policy"]["payload"]["structure_mode"] = json!("STRUCTURED");
        structured["policy"]["payload"]["structure"] =
            json!({"v":1,"protocols":[],"disclosure":[],"instances":[]});
        structured["policy"]["signature"] = json!(sign_canonical(
            "peerwork.secure.policy.v3",
            &structured["policy"]["payload"],
            &key
        )
        .unwrap());
        structured["commit"]["payload"]["policy_hash"] = json!(sha256_hex(
            canonical(&structured["policy"], Path::SecureArtifact)
                .unwrap()
                .as_bytes()
        ));
        structured["commit"]["payload"]["structure"] =
            json!({"v":1,"mode":"DELTA","records":[],"heads":[]});
        structured["commit"]["signature"] = json!(sign_canonical(
            "peerwork.secure.commit.v3",
            &structured["commit"]["payload"],
            &key
        )
        .unwrap());
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&structured).unwrap(),
            ROUTE,
            &pins
        )
        .is_ok());
        structured["commit"]["payload"]["body"]["objects"] = json!([
            {"kind":"protocols","id":base64url(&[51u8;32]),"revision":1,
             "provenance":"AUTHOR_SIGNED","value":{}}
        ]);
        structured["commit"]["signature"] = json!(sign_canonical(
            "peerwork.secure.commit.v3",
            &structured["commit"]["payload"],
            &key
        )
        .unwrap());
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&structured).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());
        let mut wrong_mode = public.clone();
        wrong_mode["commit"]["payload"]["mode"] = json!("PRIVATE");
        wrong_mode["commit"]["signature"] = json!(sign_canonical(
            "peerwork.secure.commit.v3",
            &wrong_mode["commit"]["payload"],
            &key
        )
        .unwrap());
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&wrong_mode).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());
        let mut malformed = public.clone();
        malformed["commit"]["payload"]["body"]["objects"] = json!("not an array");
        malformed["commit"]["signature"] = json!(sign_canonical(
            "peerwork.secure.commit.v3",
            &malformed["commit"]["payload"],
            &key
        )
        .unwrap());
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&malformed).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());
        for name in ["migration", "recovery", "conversion_excluded_members"] {
            let mut forbidden = v3.clone();
            forbidden["commit"]["payload"][name] = Value::Null;
            forbidden["commit"]["signature"] = json!(sign_canonical(
                "peerwork.secure.commit.v3",
                &forbidden["commit"]["payload"],
                &key
            )
            .unwrap());
            assert!(
                verify_prepared_owner_bootstrap(
                    &serde_json::to_vec(&forbidden).unwrap(),
                    ROUTE,
                    &pins
                )
                .is_err(),
                "{name}"
            );
        }
        changed = request;
        changed["commit"]["payload"]["body"]["chunks"] = json!([base64url(&[1u8; 1])]);
        changed["commit"]["signature"] = json!(sign_canonical(
            "peerwork.secure.commit.v1",
            &changed["commit"]["payload"],
            &key
        )
        .unwrap());
        assert!(verify_prepared_owner_bootstrap(
            &serde_json::to_vec(&changed).unwrap(),
            ROUTE,
            &pins
        )
        .is_err());
    }
}
