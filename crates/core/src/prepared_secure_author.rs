//! Low-level native secure commit authoring. Caller-supplied operation/context
//! have no action authority until complete replay/evaluator proof exists.
//! This Rust API is public only for trusted runtime composition; it must not
//! be exposed as a language SDK action or final-outcome verifier.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url},
    prepared_secure_request::{
        verify_prepared_secure_commit_request, SecureCommitRequestPins,
        VerifiedPreparedSecureRequest,
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
    let invalid = || SecureAuthorError::Invalid;
    if pins.mode != "PRIVATE"
        || !matches!(pins.version, 1 | 3)
        || pins.actor_id != actor_id(&signing_key.verifying_key().to_bytes())
        || pins.signing_key != base64url(&signing_key.verifying_key().to_bytes())
        || operation_wire.is_empty()
        || operation_wire.len() > MAX_PLAINTEXT
    {
        return Err(invalid());
    }
    let mut context = parse_wire_json_bounded(context_wire, 64, 196_608).map_err(|_| invalid())?;
    let result = author_with_context(&context, operation_wire, epoch_key, signing_key, path, pins);
    wipe_wire(&mut context);
    result
}

fn author_with_context(
    context: &WireValue,
    operation_wire: &[u8],
    epoch_key: &[u8; 32],
    signing_key: &SigningKey,
    path: &str,
    pins: &SecureCommitRequestPins<'_>,
) -> Result<AuthoredSecureCommit, SecureAuthorError> {
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
    let domain = if pins.version == 3 {
        "peerwork.secure.commit.v3"
    } else {
        "peerwork.secure.commit.v1"
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
    let request_wire = format!("{{\"commit\":{canonical_commit}}}").into_bytes();
    let proof =
        verify_prepared_secure_commit_request(&request_wire, path, pins).map_err(|_| invalid())?;
    Ok(AuthoredSecureCommit {
        request_wire,
        proof,
    })
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
        crypto::decode_base64url,
        e2ee::{open_content_wire, SealedContent},
    };
    use serde_json::{json, Value};

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
