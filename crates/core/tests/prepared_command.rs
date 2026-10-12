use ed25519_dalek::{Signer, SigningKey};
use peerwork_core::{
    canonical::{canonical, Path},
    crypto::{actor_id, base64url, key_id, sha256_hex, sign_compact},
    prepared_command::{verify_prepared_command_wire, CommandPins},
    receipt_wire::verify_http_response_for_prepared,
};
use serde_json::json;

#[test]
fn signed_prepared_command_binds_identity_discovery_body_and_digest() {
    let signing = SigningKey::from_bytes(&[21; 32]);
    let public = signing.verifying_key().to_bytes();
    let kid = key_id(&public);
    let actor = actor_id(&public);
    let command_id = key_id(&[23; 32]);
    let audience: Vec<u16> = "https://workspace.example".encode_utf16().collect();
    let header = canonical(
        &json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid}),
        Path::SecureArtifact,
    )
    .unwrap();
    let command = json!({
        "v":1,"audience":"https://workspace.example","command_id":command_id,
        "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
        "path":"/api/workspace/v1/commands","workspace_id":null,"instance_id":null,
        "protocol_digest":null,"action_id":"catalog.namespace.claim",
        "expected_workspace_revision":null,"expected_instance_revision":null,
        "exact_input_refs":[],"body":{"namespace":actor},"issued_at":1,"expires_at":600001
    });
    let payload = canonical(&command, Path::COMMAND).unwrap();
    let input = format!(
        "{}.{}",
        base64url(header.as_bytes()),
        base64url(payload.as_bytes())
    );
    let jws = format!(
        "{}.{}",
        input,
        base64url(&signing.sign(input.as_bytes()).to_bytes())
    );
    let body = canonical(&json!({"jws":jws}), Path::COMMAND).unwrap();
    let pins = CommandPins {
        local_key_id: &kid,
        audience_utf16: &audience,
    };
    let proof = verify_prepared_command_wire(&jws, body.as_bytes(), &pins).unwrap();
    assert_eq!(proof.command_id(), command_id);
    assert_eq!(proof.actor_id(), actor);
    assert_eq!(proof.path(), "/api/workspace/v1/commands");
    assert_eq!(proof.intent_digest(), sha256_hex(jws.as_bytes()));
    let result = json!({"workspace_id":null,"event_sequence":null,"revision":null});
    let result_digest = sha256_hex(canonical(&result, Path::KERNEL).unwrap().as_bytes());
    let receipt_header = json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid});
    let receipt_payload = json!({
        "v":1,"audience":"https://workspace.example","actor_id":actor,"workspace_id":null,
        "command_id":command_id,"intent_digest":proof.intent_digest(),"result_digest":result_digest,
        "protocol_digest":null,"event_sequence":null,"instance_revision":null,"accepted_at":1
    });
    let receipt = sign_compact(&receipt_header, &receipt_payload, &signing).unwrap();
    let response = canonical(
        &json!({"command_id":command_id,"receipt":receipt,"result":result}),
        Path::RESPONSE,
    )
    .unwrap();
    let accepted = verify_http_response_for_prepared(response.as_bytes(), &proof, &kid).unwrap();
    assert_eq!(accepted.intent_digest(), proof.intent_digest());
    let wrong_receipt_key = key_id(&[25; 32]);
    assert!(
        verify_http_response_for_prepared(response.as_bytes(), &proof, &wrong_receipt_key).is_err()
    );
    assert!(verify_prepared_command_wire(&jws, br#"{"jws":"different"}"#, &pins).is_err());
    let wrong_audience: Vec<u16> = "https://other.example".encode_utf16().collect();
    let wrong_pins = CommandPins {
        local_key_id: &kid,
        audience_utf16: &wrong_audience,
    };
    assert!(verify_prepared_command_wire(&jws, body.as_bytes(), &wrong_pins).is_err());
    let wrong_key = key_id(&[24; 32]);
    let wrong_pins = CommandPins {
        local_key_id: &wrong_key,
        audience_utf16: &audience,
    };
    assert!(verify_prepared_command_wire(&jws, body.as_bytes(), &wrong_pins).is_err());

    let chunk = b"test catalog chunk";
    let mut upload = command;
    upload["path"] = json!("/api/workspace/v1/catalog/upload");
    upload["action_id"] = json!("catalog.upload.chunk");
    upload["body"] = json!({"byte_length":chunk.len(),"chunk_digest":sha256_hex(chunk)});
    let payload = canonical(&upload, Path::COMMAND).unwrap();
    let input = format!(
        "{}.{}",
        base64url(header.as_bytes()),
        base64url(payload.as_bytes())
    );
    let upload_jws = format!(
        "{}.{}",
        input,
        base64url(&signing.sign(input.as_bytes()).to_bytes())
    );
    let upload_body = canonical(
        &json!({"command":{"jws":upload_jws},"chunk":base64url(chunk)}),
        Path::COMMAND,
    )
    .unwrap();
    assert!(verify_prepared_command_wire(&upload_jws, upload_body.as_bytes(), &pins).is_ok());
    let changed_chunk = canonical(
        &json!({"command":{"jws":upload_jws},"chunk":base64url(b"different chunk")}),
        Path::COMMAND,
    )
    .unwrap();
    assert!(verify_prepared_command_wire(&upload_jws, changed_chunk.as_bytes(), &pins).is_err());
}
