use ed25519_dalek::{Signature, Verifier};
use peerwork_core::canonical::{canonical, Path};
use peerwork_core::crypto::{actor_id, base64url, decode_base64url, key_id, sign_canonical, sign_compact, sha256_hex, verify_artifact, verifying_key};
use peerwork_core::receipt::{verify_receipt, verify_response_result, ReceiptExpectation};
use peerwork_core::strict_json::parse_strict_json;
use serde_json::{json, Value};

#[test]
fn tracked_typescript_differential_canonicalization() {
    let vectors: Value = serde_json::from_str(include_str!("../../../conformance/ts-differential-vectors.json")).unwrap();
    assert_eq!(vectors["source_commit"], "dd8a9d2");
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if name == "lone_surrogate" {
            // serde_json rejects an unpaired surrogate at parsing. The TS
            // reference accepts it and re-emits the escape; tracked gap.
            let raw = decode_base64url(case["input_wire_base64"].as_str().unwrap()).unwrap();
            assert!(parse_strict_json(&raw).is_err());
            continue;
        }
        if let Some(input) = case.get("input") {
            for (path, mode) in [("kernel", Path::KERNEL), ("secure", Path::SecureArtifact)] {
                let actual = canonical(input, mode);
                if let Some(expected) = case[path].as_str() {
                    assert_eq!(actual.unwrap(), expected, "{name}/{path}");
                } else {
                    assert!(actual.is_err(), "{name}/{path} unexpectedly accepted");
                }
            }
        }
    }
    assert_eq!(canonical(&parse_strict_json(b"-0").unwrap(), Path::KERNEL).unwrap(), "0");
    assert!(canonical(&json!({"a": 9_007_199_254_740_992_u64}), Path::SecureArtifact).is_err());
    assert_eq!(canonical(&json!({"": 1}), Path::SecureArtifact).unwrap(), "{\"\":1}");
    assert!(canonical(&json!({"": 1}), Path::KERNEL).is_err());
    assert!(parse_strict_json(br#"{"value":"\ud800"}"#).is_err());
}

#[test]
fn independent_rfc8032_ed25519_known_answer() {
    // RFC 8032 §7.1, test 1: empty message, public key and signature only.
    let raw: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").try_into().unwrap();
    let signature: [u8; 64] = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").try_into().unwrap();
    let key = verifying_key(&key_id(&raw)).unwrap();
    key.verify(b"", &Signature::from_bytes(&signature)).unwrap();
    assert!(key.verify(b"changed", &Signature::from_bytes(&signature)).is_err());
    assert_eq!(decode_base64url(&key_id(&raw)).unwrap(), raw);
    assert_eq!(actor_id(&raw).len(), 43);
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn reject_noncanonical_encoding_and_duplicate_json_members() {
    for value in ["A", "a=", "+/8", "_w==", "a b"] { assert!(decode_base64url(value).is_err(), "{value}"); }
    for raw in [br#"{"a":1,"a":2}"#.as_slice(), br#"{"a":1,"\u0061":2}"#, br#"{"a":{"x":1,"x":2}}"#] {
        assert!(parse_strict_json(raw).is_err());
    }
    assert!(parse_strict_json(br#"{"a":1} garbage"#).is_err());
}

#[test]
fn receipt_is_bound_to_discovery_command_and_result() {
    // Local deterministic test signing key, never serialized as a fixture.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let kid = key_id(&signing.verifying_key().to_bytes());
    let actor = actor_id(&signing.verifying_key().to_bytes());
    let command = base64url(&[1; 32]);
    let result = json!({"workspace_id": null, "event_sequence": 0, "revision": 1});
    let result_digest = sha256_hex(canonical(&result, Path::KERNEL).unwrap().as_bytes());
    let intent = "a".repeat(64);
    let payload = json!({"v":1,"audience":"local-test","actor_id":actor,"workspace_id":null,
        "command_id":command,"intent_digest":intent,"result_digest":result_digest,
        "protocol_digest":null,"event_sequence":0,"instance_revision":1,"accepted_at":1});
    let header = json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid});
    let jws = sign_compact(&header, &payload, &signing).unwrap();
    let expectation = ReceiptExpectation { audience: "local-test", receipt_key_id: &kid,
        actor_id: &actor, command_id: &command, intent_digest: &intent,
        workspace_id: None, protocol_digest: None };
    let receipt = verify_receipt(&jws, &expectation).unwrap();
    verify_response_result(&receipt, &result).unwrap();
    assert!(verify_response_result(&receipt, &json!({"workspace_id":null,"event_sequence":1,"revision":1})).is_err());
    let wrong = ReceiptExpectation { audience: "wrong", ..expectation };
    assert!(verify_receipt(&jws, &wrong).is_err());
    let mut altered = jws.into_bytes();
    *altered.last_mut().unwrap() = b'A';
    assert!(verify_receipt(std::str::from_utf8(&altered).unwrap(), &wrong).is_err());
}

#[test]
fn signed_artifact_binds_actor_domain_and_body() {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public = signing.verifying_key().to_bytes();
    let actor = actor_id(&public);
    let key = key_id(&public);
    let unsigned = json!({"v":1,"domain":"test.domain.v1","signer":{"actor_id":actor,"key_id":key},"body":{"a":1}});
    let signature = sign_canonical("peerwork.signed-artifact.v1:test.domain.v1", &unsigned, &signing).unwrap();
    let mut artifact = unsigned;
    artifact.as_object_mut().unwrap().insert("signature".into(), signature.into());
    assert!(verify_artifact(&artifact, "test.domain.v1", Some(&actor)).unwrap());
    assert!(!verify_artifact(&artifact, "other.domain.v1", Some(&actor)).unwrap());
    assert!(!verify_artifact(&artifact, "test.domain.v1", Some(&base64url(&[0; 32]))).unwrap());
    artifact["body"]["a"] = json!(2);
    assert!(!verify_artifact(&artifact, "test.domain.v1", Some(&actor)).unwrap());
}

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes().chunks_exact(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}
