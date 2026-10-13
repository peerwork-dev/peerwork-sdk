//! Low-level native secure commit authoring. Caller-supplied operation/context
//! have no action authority until complete replay/evaluator proof exists.
//! This Rust API is public only for trusted runtime composition; it must not
//! be exposed as a language SDK action or final-outcome verifier.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url},
    prepared_secure_action::ValidatedPreparedAction,
    prepared_secure_bootstrap::{
        verify_prepared_owner_bootstrap, BootstrapPins, VerifiedPreparedBootstrap,
    },
    prepared_secure_request::{
        verify_prepared_secure_commit_request, verify_prepared_secure_commit_request_with_policy,
        SecureCommitRequestPins, VerifiedPreparedSecureRequest,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;
const CHUNK: usize = 6144;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureAuthorError {
    #[error("secure operation, context, or pinned identity is invalid")]
    Invalid,
    #[error("OS random source failed")]
    Entropy,
    #[error("secure encryption failed")]
    Encryption,
}

/// Internal result, never a language DTO. Persist `request_wire` exactly once
/// before transport and reuse those same bytes for every uncertain retry.
pub struct AuthoredSecureCommit {
    request_wire: Vec<u8>,
    proof: VerifiedPreparedSecureRequest,
}
pub struct AuthoredSecureBootstrap {
    request_wire: Vec<u8>,
    proof: VerifiedPreparedBootstrap,
}
impl AuthoredSecureBootstrap {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn proof(&self) -> &VerifiedPreparedBootstrap {
        &self.proof
    }
}

impl AuthoredSecureCommit {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn proof(&self) -> &VerifiedPreparedSecureRequest {
        &self.proof
    }
}

/// Low-level cryptographic authoring only. The caller must supply a typed,
/// complete verified policy/checkpoint/operation proof before this becomes a
/// public action path. New authoring uses a fresh OS nonce; retries MUST NOT
/// call this function again because that would create a different commit.
pub fn author_private_commit(
    context_wire: &[u8],
    operation_wire: &[u8],
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<AuthoredSecureCommit, SecureAuthorError> {
    author_private_commit_inner(
        context_wire,
        operation_wire,
        epoch_key,
        signing_key,
        path,
        pins,
        None,
    )
}

/// Low-level signer for a signed selected policy. The caller must supply the
/// exact policy from authenticated current replay; this function alone does
/// not authorize the operation or prove the next journal checkpoint.
pub fn author_private_commit_with_policy(
    context_wire: &[u8],
    operation_wire: &[u8],
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
    signed_policy_wire: &[u8],
    trusted_owner_key: &str,
) -> Result<AuthoredSecureCommit, SecureAuthorError> {
    author_private_commit_inner(
        context_wire,
        operation_wire,
        epoch_key,
        signing_key,
        path,
        pins,
        Some((signed_policy_wire, trusted_owner_key)),
    )
}

/// Author only an operation already recomputed from authenticated prior state
/// for this exact context and signed policy. This remains low-level Rust API;
/// runtime must bind the replay origin and checkpoint before calling it.
pub fn author_private_validated_action(
    context_wire: &[u8],
    action: &ValidatedPreparedAction,
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
    signed_policy_wire: &[u8],
    trusted_owner_key: &str,
) -> Result<AuthoredSecureCommit, SecureAuthorError> {
    if !action.matches_context_and_policy(context_wire, signed_policy_wire) {
        return Err(SecureAuthorError::Invalid);
    }
    author_private_commit_with_policy(
        context_wire,
        action.operation_wire(),
        epoch_key,
        signing_key,
        path,
        pins,
        signed_policy_wire,
        trusted_owner_key,
    )
}

/// Sign a PUBLIC ACTION after the evaluator has checked the exact operation
/// against authenticated prior objects and this signed policy. The runtime
/// still must bind the pre-append checkpoint and persist the packet before POST.
pub fn author_public_validated_action(
    context_wire: &[u8],
    action: &ValidatedPreparedAction,
    signing_key: &SigningKey,
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
    signed_policy_wire: &[u8],
    trusted_owner_key: &str,
) -> Result<AuthoredSecureCommit, SecureAuthorError> {
    let invalid = || SecureAuthorError::Invalid;
    if pins.mode != "PUBLIC"
        || pins.epoch != 0
        || !matches!(pins.version, 1 | 2 | 3)
        || pins.actor_id != actor_id(&signing_key.verifying_key().to_bytes())
        || pins.signing_key != base64url(&signing_key.verifying_key().to_bytes())
        || !action.matches_context_and_policy(context_wire, signed_policy_wire)
    {
        return Err(invalid());
    }
    let context = parse_wire_json_bounded(context_wire, 64, 196_608).map_err(|_| invalid())?;
    let WireValue::Object(fields) = &context else {
        return Err(invalid());
    };
    if context.get("mode").is_some() || context.get("body").is_some() {
        return Err(invalid());
    }
    let operation = parse_wire_json_bounded(action.operation_wire(), 64, MAX_PLAINTEXT)
        .map_err(|_| invalid())?;
    let mut payload_fields = fields.clone();
    payload_fields.push((units("mode"), WireValue::String(units("PUBLIC"))));
    payload_fields.push((units("body"), operation));
    let payload = WireValue::Object(payload_fields);
    let canonical_payload =
        canonical_wire_value(&payload, Path::SecureArtifact).map_err(|_| invalid())?;
    let domain = match pins.version {
        1 => "peerwork.secure.commit.v1",
        2 => "peerwork.secure.commit.v2",
        3 => "peerwork.secure.commit.v3",
        _ => return Err(invalid()),
    };
    let mut message = Zeroizing::new(Vec::with_capacity(canonical_payload.len() + 32));
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical_payload.as_bytes());
    let signature = base64url(&signing_key.sign(&message).to_bytes());
    let commit = WireValue::Object(vec![
        (units("payload"), payload),
        (units("signature"), WireValue::String(units(&signature))),
    ]);
    let canonical_commit =
        canonical_wire_value(&commit, Path::SecureArtifact).map_err(|_| invalid())?;
    let request_wire = format!("{{\"commit\":{canonical_commit}}}").into_bytes();
    let proof = verify_prepared_secure_commit_request_with_policy(
        &request_wire,
        path,
        pins,
        signed_policy_wire,
        trusted_owner_key,
    )
    .map_err(|_| invalid())?;
    Ok(AuthoredSecureCommit {
        request_wire,
        proof,
    })
}

fn author_private_commit_inner(
    context_wire: &[u8],
    operation_wire: &[u8],
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
    policy: Option<(&[u8], &str)>,
) -> Result<AuthoredSecureCommit, SecureAuthorError> {
    let invalid = || SecureAuthorError::Invalid;
    if pins.mode != "PRIVATE"
        || !matches!(pins.version, 1 | 3) && policy.is_none()
        || !matches!(pins.version, 1 | 2 | 3)
        || pins.actor_id != actor_id(&signing_key.verifying_key().to_bytes())
        || pins.signing_key != base64url(&signing_key.verifying_key().to_bytes())
        || operation_wire.is_empty()
        || operation_wire.len() > MAX_PLAINTEXT
    {
        return Err(invalid());
    }
    let mut context = parse_wire_json_bounded(context_wire, 64, 196_608).map_err(|_| invalid())?;
    let result = sign_private_commit(&context, operation_wire, epoch_key, signing_key, pins)
        .and_then(|commit| {
            let request_wire = format!("{{\"commit\":{commit}}}").into_bytes();
            let proof = if let Some((signed_policy_wire, trusted_owner_key)) = policy {
                verify_prepared_secure_commit_request_with_policy(
                    &request_wire,
                    path,
                    pins,
                    signed_policy_wire,
                    trusted_owner_key,
                )
            } else {
                verify_prepared_secure_commit_request(&request_wire, path, pins)
            }
            .map_err(|_| invalid())?;
            Ok(AuthoredSecureCommit {
                request_wire,
                proof,
            })
        });
    wipe_wire(&mut context);
    result
}

/// Owner bootstrap uses the staged initial epoch key and the separate
/// `{policy,commit}` route. The caller must save these exact bytes before
/// transport and cannot activate the key from this pre-submit proof.
pub fn author_private_bootstrap(
    policy_wire: &[u8],
    context_wire: &[u8],
    operation_wire: &[u8],
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<AuthoredSecureBootstrap, SecureAuthorError> {
    let invalid = || SecureAuthorError::Invalid;
    if pins.mode != "PRIVATE"
        || !matches!(pins.version, 1 | 3)
        || pins.sequence != 1
        || pins.previous.is_some()
        || pins.epoch != 1
        || pins.actor_id != actor_id(&signing_key.verifying_key().to_bytes())
        || pins.signing_key != base64url(&signing_key.verifying_key().to_bytes())
        || operation_wire.is_empty()
        || operation_wire.len() > MAX_PLAINTEXT
    {
        return Err(invalid());
    }
    let mut operation =
        parse_wire_json_bounded(operation_wire, 64, MAX_PLAINTEXT).map_err(|_| invalid())?;
    let bootstrap_kind = operation.object_len() == Some(4)
        && operation.get("v").and_then(WireValue::as_number) == Some(1.0)
        && operation
            .get("kind")
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("BOOTSTRAP")
        && matches!(operation.get("input"), Some(WireValue::Object(_)))
        && matches!(operation.get("objects"), Some(WireValue::Array(_)));
    wipe_wire(&mut operation);
    if !bootstrap_kind {
        return Err(invalid());
    }
    let mut context = parse_wire_json_bounded(context_wire, 64, 196_608).map_err(|_| invalid())?;
    let commit_result = sign_private_commit(&context, operation_wire, epoch_key, signing_key, pins);
    wipe_wire(&mut context);
    let commit = commit_result?;
    let mut policy = parse_wire_json_bounded(policy_wire, 64, 196_608).map_err(|_| invalid())?;
    let policy_result = canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| invalid());
    wipe_wire(&mut policy);
    let policy = policy_result?;
    let request_wire = format!("{{\"commit\":{commit},\"policy\":{policy}}}").into_bytes();
    let proof = verify_prepared_owner_bootstrap(
        &request_wire,
        "/api/workspace/v1/secure/workspaces",
        &BootstrapPins {
            workspace_id: pins.workspace_id,
            owner_actor: pins.actor_id,
            owner_key: pins.signing_key,
        },
    )
    .map_err(|_| invalid())?;
    Ok(AuthoredSecureBootstrap {
        request_wire,
        proof,
    })
}

/// Low-level PUBLIC owner bootstrap. No epoch secret is created or required;
/// the signed operation is plaintext and the resulting proof is pre-submit only.
pub fn author_public_bootstrap(
    policy_wire: &[u8],
    context_wire: &[u8],
    operation_wire: &[u8],
    signing_key: &SigningKey,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<AuthoredSecureBootstrap, SecureAuthorError> {
    let invalid = || SecureAuthorError::Invalid;
    if pins.mode != "PUBLIC"
        || !matches!(pins.version, 1 | 3)
        || pins.sequence != 1
        || pins.previous.is_some()
        || pins.epoch != 0
        || pins.actor_id != actor_id(&signing_key.verifying_key().to_bytes())
        || pins.signing_key != base64url(&signing_key.verifying_key().to_bytes())
        || operation_wire.is_empty()
        || operation_wire.len() > MAX_PLAINTEXT
    {
        return Err(invalid());
    }
    let mut operation =
        parse_wire_json_bounded(operation_wire, 64, MAX_PLAINTEXT).map_err(|_| invalid())?;
    let valid = operation.object_len() == Some(4)
        && operation.get("v").and_then(WireValue::as_number) == Some(1.0)
        && operation
            .get("kind")
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("BOOTSTRAP")
        && operation.get("input").and_then(WireValue::object_len) == Some(0)
        && matches!(operation.get("objects"), Some(WireValue::Array(items)) if items.len() <= 128);
    if !valid {
        wipe_wire(&mut operation);
        return Err(invalid());
    }
    let operation_result =
        canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| invalid());
    wipe_wire(&mut operation);
    let operation_canonical = operation_result?;
    let mut context = parse_wire_json_bounded(context_wire, 64, 196_608).map_err(|_| invalid())?;
    let commit_result = (|| {
        let WireValue::Object(context_fields) = &context else {
            return Err(invalid());
        };
        if context.get("mode").is_some() || context.get("body").is_some() {
            return Err(invalid());
        }
        let body = parse_wire_json_bounded(operation_canonical.as_bytes(), 64, MAX_PLAINTEXT)
            .map_err(|_| invalid())?;
        let mut fields = context_fields.clone();
        fields.push((units("mode"), WireValue::String(units("PUBLIC"))));
        fields.push((units("body"), body));
        let payload = WireValue::Object(fields);
        let canonical_payload =
            canonical_wire_value(&payload, Path::SecureArtifact).map_err(|_| invalid())?;
        let domain = if pins.version == 3 {
            "peerwork.secure.commit.v3"
        } else {
            "peerwork.secure.commit.v1"
        };
        let mut message = Zeroizing::new(Vec::with_capacity(
            domain.len() + 1 + canonical_payload.len(),
        ));
        message.extend_from_slice(domain.as_bytes());
        message.push(0);
        message.extend_from_slice(canonical_payload.as_bytes());
        let signature = base64url(&signing_key.sign(&message).to_bytes());
        canonical_wire_value(
            &WireValue::Object(vec![
                (units("payload"), payload),
                (units("signature"), WireValue::String(units(&signature))),
            ]),
            Path::SecureArtifact,
        )
        .map_err(|_| invalid())
    })();
    wipe_wire(&mut context);
    let commit = commit_result?;
    let mut policy = parse_wire_json_bounded(policy_wire, 64, 196_608).map_err(|_| invalid())?;
    let policy_result = canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| invalid());
    wipe_wire(&mut policy);
    let request_wire =
        format!("{{\"commit\":{commit},\"policy\":{}}}", policy_result?).into_bytes();
    let proof = verify_prepared_owner_bootstrap(
        &request_wire,
        "/api/workspace/v1/secure/workspaces",
        &BootstrapPins {
            workspace_id: pins.workspace_id,
            owner_actor: pins.actor_id,
            owner_key: pins.signing_key,
        },
    )
    .map_err(|_| invalid())?;
    if proof.visibility() != "PUBLIC" {
        return Err(invalid());
    }
    Ok(AuthoredSecureBootstrap {
        request_wire,
        proof,
    })
}

pub(crate) fn sign_private_commit(
    context: &WireValue,
    operation_wire: &[u8],
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<String, SecureAuthorError> {
    let invalid = || SecureAuthorError::Invalid;
    let WireValue::Object(context_fields) = context else {
        return Err(invalid());
    };
    if context.get("mode").is_some() || context.get("body").is_some() {
        return Err(invalid());
    }
    let mut operation =
        parse_wire_json_bounded(operation_wire, 64, MAX_PLAINTEXT).map_err(|_| invalid())?;
    let plaintext_result =
        canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| invalid());
    wipe_wire(&mut operation);
    let plaintext = Zeroizing::new(plaintext_result?);
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(invalid());
    }
    let aad_wrapper = WireValue::Object(vec![
        (
            units("domain"),
            WireValue::String(units("peerwork.content-object.v1")),
        ),
        (units("context"), context.clone()),
    ]);
    let aad = Zeroizing::new(
        canonical_wire_value(&aad_wrapper, Path::SecureArtifact).map_err(|_| invalid())?,
    );
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| SecureAuthorError::Entropy)?;
    let mut key_copy = Zeroizing::new([0u8; 32]);
    key_copy.copy_from_slice(epoch_key);
    let cipher = Aes256Gcm::new_from_slice(&*key_copy).map_err(|_| invalid())?;
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecureAuthorError::Encryption)?,
    );
    let chunks = ciphertext
        .chunks(CHUNK)
        .map(|chunk| WireValue::String(units(&base64url(chunk))))
        .collect();
    let sealed = WireValue::Object(vec![
        (units("v"), WireValue::Number(1.0)),
        (units("alg"), WireValue::String(units("A256GCM"))),
        (units("nonce"), WireValue::String(units(&base64url(&nonce)))),
        (units("chunks"), WireValue::Array(chunks)),
    ]);
    let mut payload_fields = context_fields.clone();
    payload_fields.push((units("mode"), WireValue::String(units("PRIVATE"))));
    payload_fields.push((units("body"), sealed));
    let payload = WireValue::Object(payload_fields);
    let canonical_payload =
        canonical_wire_value(&payload, Path::SecureArtifact).map_err(|_| invalid())?;
    let mut message = Zeroizing::new(Vec::with_capacity(canonical_payload.len() + 32));
    let domain = match pins.version {
        1 => "peerwork.secure.commit.v1",
        2 => "peerwork.secure.commit.v2",
        3 => "peerwork.secure.commit.v3",
        _ => return Err(invalid()),
    };
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical_payload.as_bytes());
    let signature = base64url(&signing_key.sign(&message).to_bytes());
    let commit = WireValue::Object(vec![
        (units("payload"), payload),
        (units("signature"), WireValue::String(units(&signature))),
    ]);
    let canonical_commit =
        canonical_wire_value(&commit, Path::SecureArtifact).map_err(|_| invalid())?;
    Ok(canonical_commit)
}

fn units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn wipe_wire(value: &mut WireValue) {
    match value {
        WireValue::String(units) => units.zeroize(),
        WireValue::Array(items) => {
            for item in items {
                wipe_wire(item);
            }
        }
        WireValue::Object(fields) => {
            for (name, item) in fields {
                name.zeroize();
                wipe_wire(item);
            }
        }
        WireValue::Null | WireValue::Bool(_) | WireValue::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::canonical,
        crypto::{decode_base64url, sha256_hex, sign_canonical},
        e2ee::{open_content_wire, SealedContent},
        secure_recipient::SecretRecipient,
    };
    use serde_json::{json, Value};

    #[test]
    fn native_v2_structured_author_requires_signed_selected_policy() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let actor = actor_id(&signing.verifying_key().to_bytes());
        let key = base64url(&signing.verifying_key().to_bytes());
        let workspace = base64url(&[8; 32]);
        let instance = base64url(&[9; 32]);
        let policy_payload = json!({
            "v":2,"workspace_id":workspace,"owner_id":actor,"signing_key":key,
            "version":1,"previous_policy":null,"effective_sequence":1,
            "visibility":"PRIVATE","epoch":1,"issued_at":100,
            "members":[{"actor_id":actor,"certificate":{"payload":{"signing_key":key}},
                "role":"OWNER","scopes":[{"instance_id":instance,"actions":["wiki.create"],
                    "protocol_roles":[],"capabilities":[]}]}],
            "structure":{"v":1,"protocols":[],"disclosure":[],"instances":[]}
        });
        let policy = json!({"payload":policy_payload,"signature":sign_canonical(
            "peerwork.secure.policy.v2",&policy_payload,&signing).unwrap()});
        let policy_wire = serde_json::to_vec(&policy).unwrap();
        let policy_hash = sha256_hex(canonical(&policy, Path::SecureArtifact).unwrap().as_bytes());
        let previous = "b".repeat(64);
        let context = json!({"v":2,"workspace_id":workspace,"sequence":2,
            "previous":previous,"policy_hash":policy_hash,"epoch":1,
            "actor_id":actor,"signing_key":key,"command_id":base64url(&[12;32]),
            "action_id":"wiki.create","instance_id":instance,"issued_at":101,
            "delegation":null,"structure":{"v":1,"mode":"DELTA","records":[],"heads":[]}});
        let operation = json!({"v":1,"kind":"ACTION","input":{},"objects":[]});
        let path = format!("/api/workspace/v1/secure/workspaces/{workspace}/commits");
        let pins = SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key,
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence: 2,
            previous: Some(&previous),
            epoch: 1,
            mode: "PRIVATE",
            version: 2,
            protocol_format_ceiling: None,
        };
        let authored = author_private_commit_with_policy(
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(&operation).unwrap(),
            &[23; 32],
            &signing,
            &path,
            &pins,
            &policy_wire,
            &key,
        )
        .unwrap();
        let saved: Value = serde_json::from_slice(authored.request_wire()).unwrap();
        assert_eq!(saved["commit"]["payload"]["v"], 2);
        let sealed: SealedContent =
            serde_json::from_value(saved["commit"]["payload"]["body"].clone()).unwrap();
        let plaintext =
            open_content_wire(&[23; 32], &sealed, &serde_json::to_vec(&context).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&plaintext).unwrap(),
            operation
        );
        assert!(author_private_commit(
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(&operation).unwrap(),
            &[23; 32],
            &signing,
            &path,
            &pins,
        )
        .is_err());
        let mut denied = policy_payload.clone();
        denied["members"][0]["scopes"][0]["actions"] = json!([]);
        let denied_policy = json!({"payload":denied,"signature":sign_canonical(
            "peerwork.secure.policy.v2",&denied,&signing).unwrap()});
        assert!(author_private_commit_with_policy(
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(&operation).unwrap(),
            &[23; 32],
            &signing,
            &path,
            &pins,
            &serde_json::to_vec(&denied_policy).unwrap(),
            &key,
        )
        .is_err());
        let mut bad_context = context.clone();
        bad_context["structure"]["mode"] = json!("SNAPSHOT_PAGE");
        assert!(author_private_commit_with_policy(
            &serde_json::to_vec(&bad_context).unwrap(),
            &serde_json::to_vec(&operation).unwrap(),
            &[23; 32],
            &signing,
            &path,
            &pins,
            &policy_wire,
            &key,
        )
        .is_err());
    }

    #[test]
    fn native_owner_bootstrap_authors_policy_and_commit_once() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let actor = actor_id(&signing.verifying_key().to_bytes());
        let key = base64url(&signing.verifying_key().to_bytes());
        let workspace = base64url(&[8; 32]);
        let certificate = SecretRecipient::generate()
            .unwrap()
            .certify(&signing, 100)
            .unwrap();
        let policy_payload = json!({"v":1,"workspace_id":workspace,"owner_id":actor,
            "signing_key":key,"version":1,"previous_policy":null,"effective_sequence":1,
            "visibility":"PRIVATE","epoch":1,"members":[{"actor_id":actor,
                "certificate":certificate,"role":"OWNER","scopes":[]}],"issued_at":100});
        let policy = json!({"payload":policy_payload,"signature":sign_canonical(
            "peerwork.secure.policy.v1",&policy_payload,&signing).unwrap()});
        let policy_hash = sha256_hex(canonical(&policy, Path::SecureArtifact).unwrap().as_bytes());
        let context = json!({"v":1,"workspace_id":workspace,"sequence":1,"previous":null,
            "policy_hash":policy_hash,"epoch":1,"actor_id":actor,"signing_key":key,
            "command_id":base64url(&[9;32]),"action_id":"secure.bootstrap",
            "instance_id":null,"issued_at":100,"delegation":null});
        let operation = json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":[]});
        let pins = SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key,
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence: 1,
            previous: None,
            epoch: 1,
            mode: "PRIVATE",
            version: 1,
            protocol_format_ceiling: None,
        };
        let authored = author_private_bootstrap(
            &serde_json::to_vec(&policy).unwrap(),
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(&operation).unwrap(),
            &[23; 32],
            &signing,
            &pins,
        )
        .unwrap();
        assert_eq!(authored.proof().command_id(), base64url(&[9; 32]));
        assert_eq!(authored.proof().workspace_id(), workspace);
        let saved: Value = serde_json::from_slice(authored.request_wire()).unwrap();
        assert_eq!(saved["policy"], policy);
        let sealed: SealedContent =
            serde_json::from_value(saved["commit"]["payload"]["body"].clone()).unwrap();
        let plaintext =
            open_content_wire(&[23; 32], &sealed, &serde_json::to_vec(&context).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&plaintext).unwrap(),
            operation
        );
    }

    #[test]
    fn native_private_author_signs_and_seals_exact_saved_request() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let actor = actor_id(&signing.verifying_key().to_bytes());
        let key_id = base64url(&signing.verifying_key().to_bytes());
        let workspace = "w".repeat(43);
        let policy = "a".repeat(64);
        let previous = "b".repeat(64);
        let context = json!({
            "v":3,"workspace_id":workspace,"sequence":2,"previous":previous,
            "policy_hash":policy,"epoch":1,"actor_id":actor,"signing_key":key_id,
            "command_id":"c".repeat(43),"action_id":"discussion.post",
            "instance_id":"i".repeat(43),"issued_at":1_700_000_000_000_u64,
            "delegation":null,"protocol_format_ceiling":1
        });
        let operation =
            json!({"v":1,"kind":"ACTION","input":{"message":"native sealed test"},"objects":[]});
        let context_wire = serde_json::to_vec(&context).unwrap();
        let operation_wire = serde_json::to_vec(&operation).unwrap();
        let path = format!("/api/workspace/v1/secure/workspaces/{workspace}/commits");
        let pins = SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key_id,
            workspace_id: &workspace,
            policy_hash: &policy,
            sequence: 2,
            previous: Some(&previous),
            epoch: 1,
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let epoch_key = [23u8; 32];
        let authored = author_private_commit(
            &context_wire,
            &operation_wire,
            &epoch_key,
            &signing,
            &path,
            &pins,
        )
        .unwrap();
        assert_eq!(authored.proof().command_id(), "c".repeat(43));
        assert_eq!(authored.proof().action_id(), "discussion.post");
        let saved: Value = serde_json::from_slice(authored.request_wire()).unwrap();
        let sealed: SealedContent =
            serde_json::from_value(saved["commit"]["payload"]["body"].clone()).unwrap();
        let plain = open_content_wire(&epoch_key, &sealed, &context_wire).unwrap();
        let reopened: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(reopened, operation);
        assert_eq!(decode_base64url(&sealed.nonce).unwrap().len(), 12);
        let next = author_private_commit(
            &context_wire,
            &operation_wire,
            &epoch_key,
            &signing,
            &path,
            &pins,
        )
        .unwrap();
        assert_ne!(
            next.request_wire(),
            authored.request_wire(),
            "new authoring must use a fresh nonce"
        );
        if let Ok(out) = std::env::var("PEERWORK_AUTHOR_VECTOR_OUT") {
            let vector = json!({
                "request":String::from_utf8(authored.request_wire().to_vec()).unwrap(),
                "context":context,"operation":operation,
                "epoch_key":base64url(&epoch_key),"signing_key":key_id,
            });
            std::fs::write(out, serde_json::to_vec(&vector).unwrap()).unwrap();
        }
    }
}
