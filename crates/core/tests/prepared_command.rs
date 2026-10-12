use ed25519_dalek::{Signer, SigningKey};
use peerwork_core::{
    canonical::{canonical, Path},
    crypto::{actor_id, base64url, key_id, sha256_hex, sign_compact},
    discovery::parse_discovery_wire,
    prepared_command::{prepare_signed_command_wire, verify_prepared_command_wire, CommandPins},
    receipt_wire::verify_http_response_for_prepared,
    wire_json::parse_wire_json_bounded,
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

    let discovery_wire = format!(
        r#"{{"semantics":"peerwork.kernel.v1","audience":"https://workspace.example","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":"{kid}","limits":{{"max":1}}}}"#
    );
    let discovery = parse_discovery_wire(discovery_wire.as_bytes(), discovery_wire.len()).unwrap();
    let command_wire = serde_json::to_vec(&command).unwrap();
    let command_value = parse_wire_json_bounded(&command_wire, 40, 180_000).unwrap();
    let signed = prepare_signed_command_wire(&command_value, &signing, &discovery, None).unwrap();
    assert_eq!(signed.jws(), jws);
    assert_eq!(signed.http_body(), body.as_bytes());
    assert_eq!(signed.proof().intent_digest(), proof.intent_digest());
    assert_eq!(signed.command_canonical(), payload);
    let mut wrong_actor = command.clone();
    wrong_actor["actor_id"] = json!(key_id(&[31; 32]));
    let wrong_wire = serde_json::to_vec(&wrong_actor).unwrap();
    let wrong_value = parse_wire_json_bounded(&wrong_wire, 40, 180_000).unwrap();
    assert!(prepare_signed_command_wire(&wrong_value, &signing, &discovery, None).is_err());
    let mut unsafe_command = command.clone();
    unsafe_command["issued_at"] = json!(9_007_199_254_740_992_u64);
    let unsafe_wire = serde_json::to_vec(&unsafe_command).unwrap();
    let unsafe_value = parse_wire_json_bounded(&unsafe_wire, 40, 180_000).unwrap();
    assert!(prepare_signed_command_wire(&unsafe_value, &signing, &discovery, None).is_err());
    let surrogate_command = payload.replace(
        &format!("\"namespace\":\"{actor}\""),
        "\"namespace\":\"\\ud800\"",
    );
    let surrogate_value =
        parse_wire_json_bounded(surrogate_command.as_bytes(), 40, 180_000).unwrap();
    let surrogate_signed =
        prepare_signed_command_wire(&surrogate_value, &signing, &discovery, None).unwrap();
    assert!(surrogate_signed
        .command_canonical()
        .contains(r#""namespace":"\ud800""#));
    let missing = payload.replace("\"method\":\"POST\",", "");
    let missing_value = parse_wire_json_bounded(missing.as_bytes(), 40, 180_000).unwrap();
    assert!(prepare_signed_command_wire(&missing_value, &signing, &discovery, None).is_err());
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
    upload["body"] = json!({"bundle_digest":sha256_hex(b"bundle"),"byte_length":chunk.len(),
        "chunk_digest":sha256_hex(chunk),"index":0,"offset":0,"upload_id":key_id(&[30;32])});
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
    let upload_wire = serde_json::to_vec(&upload).unwrap();
    let upload_value = parse_wire_json_bounded(&upload_wire, 40, 180_000).unwrap();
    let signed_upload =
        prepare_signed_command_wire(&upload_value, &signing, &discovery, Some(chunk)).unwrap();
    assert_eq!(signed_upload.jws(), upload_jws);
    assert_eq!(signed_upload.http_body(), upload_body.as_bytes());
    assert!(
        prepare_signed_command_wire(&upload_value, &signing, &discovery, Some(b"wrong chunk"))
            .is_err()
    );
    let mut incomplete = upload.clone();
    incomplete["body"]
        .as_object_mut()
        .unwrap()
        .remove("bundle_digest");
    let incomplete_wire = serde_json::to_vec(&incomplete).unwrap();
    let incomplete_value = parse_wire_json_bounded(&incomplete_wire, 40, 180_000).unwrap();
    assert!(
        prepare_signed_command_wire(&incomplete_value, &signing, &discovery, Some(chunk)).is_err()
    );
    let changed_chunk = canonical(
        &json!({"command":{"jws":upload_jws},"chunk":base64url(b"different chunk")}),
        Path::COMMAND,
    )
    .unwrap();
    assert!(verify_prepared_command_wire(&upload_jws, changed_chunk.as_bytes(), &pins).is_err());
}
