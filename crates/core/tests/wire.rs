use ed25519_dalek::{Signature, Signer, Verifier};
use peerwork_core::canonical::{canonical, Path};
use peerwork_core::crypto::{
    actor_id, base64url, decode_base64url, key_id, sha256_hex, sign_canonical, sign_compact,
    verify_artifact, verify_canonical_wire, verify_secure_signed, verify_secure_signed_wire,
    verifying_key,
};
use peerwork_core::receipt::{verify_receipt, verify_response_result, ReceiptExpectation};
use peerwork_core::receipt_wire::{
    verify_command_response_wire, verify_http_response_wire, WireReceiptExpectation,
};
use peerwork_core::strict_json::parse_strict_json;
use peerwork_core::wire_json::canonical_wire_json;
use serde_json::{json, Value};

#[test]
fn tracked_typescript_differential_canonicalization() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../conformance/ts-differential-vectors.json"
    ))
    .unwrap();
    assert_eq!(vectors["source_commit"], "dd8a9d2");
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if name == "lone_surrogate" {
            let raw = decode_base64url(case["input_wire_base64"].as_str().unwrap()).unwrap();
            assert!(parse_strict_json(&raw).is_err());
            for (field, mode) in [
                ("kernel_base64", Path::KERNEL),
                ("secure_base64", Path::SecureArtifact),
            ] {
                let expected = decode_base64url(case[field].as_str().unwrap()).unwrap();
                assert_eq!(
                    canonical_wire_json(&raw, mode).unwrap().as_bytes(),
                    expected
                );
            }
            continue;
        }
        if let Some(input) = case.get("input") {
            let raw = serde_json::to_vec(input).unwrap();
            for (path, mode) in [("kernel", Path::KERNEL), ("secure", Path::SecureArtifact)] {
                let actual = canonical(input, mode);
                if let Some(expected) = case[path].as_str() {
                    assert_eq!(actual.unwrap(), expected, "{name}/{path}");
                    assert_eq!(
                        canonical_wire_json(&raw, mode).unwrap(),
                        expected,
                        "wire {name}/{path}"
                    );
                } else {
                    assert!(actual.is_err(), "{name}/{path} unexpectedly accepted");
                    assert!(
                        canonical_wire_json(&raw, mode).is_err(),
                        "wire {name}/{path} unexpectedly accepted"
                    );
                }
            }
        }
    }
    for case in vectors["raw_cases"].as_array().unwrap() {
        let raw = decode_base64url(case["input_wire_base64"].as_str().unwrap()).unwrap();
        for (field, mode) in [
            ("kernel_base64", Path::KERNEL),
            ("secure_base64", Path::SecureArtifact),
        ] {
            let expected = decode_base64url(case[field].as_str().unwrap()).unwrap();
            if field == "kernel_base64" && case["kernel_wire_reject"] == true {
                assert!(canonical_wire_json(&raw, mode).is_err(), "{}", case["name"]);
                continue;
            }
            assert_eq!(
                canonical_wire_json(&raw, mode).unwrap().as_bytes(),
                expected,
                "{} {field}",
                case["name"]
            );
        }
    }
    assert_eq!(
        canonical(&parse_strict_json(b"-0").unwrap(), Path::KERNEL).unwrap(),
        "0"
    );
    assert!(canonical(
        &json!({"a": 9_007_199_254_740_992_u64}),
        Path::SecureArtifact
    )
    .is_err());
    assert_eq!(
        canonical(&json!({"": 1}), Path::SecureArtifact).unwrap(),
        "{\"\":1}"
    );
    assert!(canonical(&json!({"": 1}), Path::KERNEL).is_err());
    assert!(parse_strict_json(br#"{"value":"\ud800"}"#).is_err());
    let deeply_nested = format!("{}0{}", "[".repeat(20), "]".repeat(20));
    assert!(canonical_wire_json(deeply_nested.as_bytes(), Path::KERNEL).is_err());
}

#[test]
fn lossless_utf16_wire_parser_preserves_signed_bytes_and_decoded_duplicates() {
    let raw = br#"{"\ud800":"\udfff","pair":"\ud800\udc00","numeric":{"10":1,"2":2}}"#;
    let secure = canonical_wire_json(raw, Path::SecureArtifact).unwrap();
    assert_eq!(
        secure,
        "{\"numeric\":{\"10\":1,\"2\":2},\"pair\":\"𐀀\",\"\\ud800\":\"\\udfff\"}"
    );
    let kernel = canonical_wire_json(raw, Path::KERNEL).unwrap();
    assert!(kernel.contains("{\"2\":2,\"10\":1}"));
    for duplicate in [
        br#"{"\ud800":1,"\ud800":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#,
    ] {
        assert!(canonical_wire_json(duplicate, Path::KERNEL).is_err());
        assert!(canonical_wire_json(duplicate, Path::SecureArtifact).is_ok());
    }
    assert_eq!(
        canonical_wire_json(br#"{"a":1,"\u0061":2}"#, Path::SecureArtifact).unwrap(),
        "{\"a\":2}"
    );
    assert_eq!(
        canonical_wire_json(b"\xef\xbb\xbf{\"a\":1}", Path::SecureArtifact).unwrap(),
        "{\"a\":1}"
    );
    assert!(canonical_wire_json(br#"{"x":"\u12xz"}"#, Path::SecureArtifact).is_err());
    let signing = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
    let key = key_id(&signing.verifying_key().to_bytes());
    let payload = br#"{"v":1,"body":"\ud800"}"#;
    let canonical_payload = canonical_wire_json(payload, Path::SecureArtifact).unwrap();
    let signature = base64url(
        &signing
            .sign(format!("peerwork.secure.checkpoint.v1\0{canonical_payload}").as_bytes())
            .to_bytes(),
    );
    assert!(
        verify_canonical_wire("peerwork.secure.checkpoint.v1", payload, &signature, &key).unwrap()
    );
    let envelope =
        format!("{{\"payload\":{{\"v\":1,\"body\":\"\\ud800\"}},\"signature\":\"{signature}\"}}");
    assert!(
        verify_secure_signed_wire(envelope.as_bytes(), "peerwork.secure.checkpoint.v1", &key)
            .unwrap()
    );
    let last_wins = format!("{{\"payload\":{{\"v\":1,\"body\":\"\\ud800\"}},\"signature\":\"wrong\",\"signature\":\"{signature}\"}}");
    assert!(
        verify_secure_signed_wire(last_wins.as_bytes(), "peerwork.secure.checkpoint.v1", &key)
            .unwrap()
    );
    assert!(
        !verify_secure_signed_wire(envelope.as_bytes(), "peerwork.secure.commit.v1", &key).unwrap()
    );
}

#[test]
fn independent_rfc8032_ed25519_known_answer() {
    // RFC 8032 §7.1, test 1: empty message, public key and signature only.
    let raw: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .try_into()
        .unwrap();
    let signature: [u8; 64] = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").try_into().unwrap();
    let key = verifying_key(&key_id(&raw)).unwrap();
    key.verify(b"", &Signature::from_bytes(&signature)).unwrap();
    assert!(key
        .verify(b"changed", &Signature::from_bytes(&signature))
        .is_err());
    assert_eq!(decode_base64url(&key_id(&raw)).unwrap(), raw);
    assert_eq!(actor_id(&raw).len(), 43);
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn reject_noncanonical_encoding_and_duplicate_json_members() {
    for value in ["A", "a=", "+/8", "_w==", "a b"] {
        assert!(decode_base64url(value).is_err(), "{value}");
    }
    for raw in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":1,"\u0061":2}"#,
        br#"{"a":{"x":1,"x":2}}"#,
    ] {
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
    let expectation = ReceiptExpectation {
        audience: "local-test",
        receipt_key_id: &kid,
        actor_id: &actor,
        command_id: &command,
        intent_digest: &intent,
        workspace_id: None,
        protocol_digest: None,
    };
    let receipt = verify_receipt(&jws, &expectation).unwrap();
    verify_response_result(&receipt, &result).unwrap();
    assert!(verify_response_result(
        &receipt,
        &json!({"workspace_id":null,"event_sequence":1,"revision":1})
    )
    .is_err());
    let wrong = ReceiptExpectation {
        audience: "wrong",
        ..expectation
    };
    assert!(verify_receipt(&jws, &wrong).is_err());
    let mut altered = jws.into_bytes();
    *altered.last_mut().unwrap() = b'A';
    assert!(verify_receipt(std::str::from_utf8(&altered).unwrap(), &wrong).is_err());
}

#[test]
fn lossless_receipt_and_result_accept_utf16_surrogates_without_coercion() {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[14; 32]);
    let key = key_id(&signing.verifying_key().to_bytes());
    let actor = actor_id(&signing.verifying_key().to_bytes());
    let command = base64url(&[4; 32]);
    let intent = "b".repeat(64);
    let result = br#"{"text":"\udfff","event_sequence":null,"revision":null}"#;
    let canonical = canonical_wire_json(result, Path::KERNEL).unwrap();
    let digest = sha256_hex(canonical.as_bytes());
    let header = base64url(canonical_wire_json(format!("{{\"alg\":\"EdDSA\",\"typ\":\"peerwork.kernel-receipt.v1+jws\",\"kid\":\"{key}\"}}").as_bytes(), Path::KERNEL).unwrap().as_bytes());
    let receipt = format!("{{\"v\":1,\"audience\":\"\\ud800\",\"actor_id\":\"{actor}\",\"workspace_id\":null,\"command_id\":\"{command}\",\"intent_digest\":\"{intent}\",\"result_digest\":\"{digest}\",\"protocol_digest\":null,\"event_sequence\":null,\"instance_revision\":null,\"accepted_at\":1}}");
    let input = format!("{header}.{}", base64url(receipt.as_bytes()));
    let jws = format!(
        "{input}.{}",
        base64url(&signing.sign(input.as_bytes()).to_bytes())
    );
    let audience = [0xd800];
    let expected = WireReceiptExpectation {
        audience_utf16: &audience,
        receipt_key_id: &key,
        actor_id: &actor,
        command_id: &command,
        intent_digest: &intent,
        workspace_id: None,
        protocol_digest: None,
    };
    let proof = verify_command_response_wire(&jws, result, &expected).unwrap();
    assert_eq!(proof.command_id(), command);
    assert_eq!(proof.result_digest(), digest);
    assert_eq!(proof.result_canonical_json(), canonical);
    let outer = format!(
        "{{\"command_id\":\"{command}\",\"receipt\":\"{jws}\",\"result\":{}}}",
        std::str::from_utf8(result).unwrap()
    );
    let outer_proof = verify_http_response_wire(outer.as_bytes(), &expected).unwrap();
    assert_eq!(outer_proof.result_digest(), digest);
    assert_eq!(outer_proof.result_canonical_json(), canonical);
    assert!(verify_command_response_wire(
        &jws,
        br#"{"text":"\udffe","event_sequence":null,"revision":null}"#,
        &expected
    )
    .is_err());
    assert!(verify_command_response_wire(
        &jws,
        br#"{"text":"\udfff","text":"\udfff","event_sequence":null,"revision":null}"#,
        &expected
    )
    .is_err());
}

#[test]
fn signed_receipt_accepts_integer_decimal_and_exponent_lexemes() {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let kid = key_id(&signing.verifying_key().to_bytes());
    let actor = actor_id(&signing.verifying_key().to_bytes());
    let command = base64url(&[2; 32]);
    let intent = "a".repeat(64);
    let result = parse_strict_json(br#"{"event_sequence":1e0,"revision":1.0}"#).unwrap();
    let result_digest = sha256_hex(canonical(&result, Path::KERNEL).unwrap().as_bytes());
    let header = base64url(
        canonical(
            &json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid}),
            Path::KERNEL,
        )
        .unwrap()
        .as_bytes(),
    );
    let raw_payload = format!("{{\"v\":1.0,\"audience\":\"local-test\",\"actor_id\":\"{actor}\",\"workspace_id\":null,\"command_id\":\"{command}\",\"intent_digest\":\"{intent}\",\"result_digest\":\"{result_digest}\",\"protocol_digest\":null,\"event_sequence\":1e0,\"instance_revision\":1.0,\"accepted_at\":1e0}}");
    let input = format!("{header}.{}", base64url(raw_payload.as_bytes()));
    let receipt = format!(
        "{input}.{}",
        base64url(&signing.sign(input.as_bytes()).to_bytes())
    );
    let expected = ReceiptExpectation {
        audience: "local-test",
        receipt_key_id: &kid,
        actor_id: &actor,
        command_id: &command,
        intent_digest: &intent,
        workspace_id: None,
        protocol_digest: None,
    };
    let verified = verify_receipt(&receipt, &expected).unwrap();
    verify_response_result(&verified, &result).unwrap();
    let bad_raw = raw_payload.replace("\"accepted_at\":1e0", "\"accepted_at\":-0e0");
    let bad_input = format!("{header}.{}", base64url(bad_raw.as_bytes()));
    let bad_receipt = format!(
        "{bad_input}.{}",
        base64url(&signing.sign(bad_input.as_bytes()).to_bytes())
    );
    // JS treats -0 as nonnegative and integer; this edge is retained explicitly.
    assert!(verify_receipt(&bad_receipt, &expected).is_ok());
    let unsafe_raw = raw_payload.replace("\"accepted_at\":1e0", "\"accepted_at\":9007199254740992");
    let unsafe_input = format!("{header}.{}", base64url(unsafe_raw.as_bytes()));
    let unsafe_receipt = format!(
        "{unsafe_input}.{}",
        base64url(&signing.sign(unsafe_input.as_bytes()).to_bytes())
    );
    // The pinned Zod 4.5.4 `.int()` rejects values beyond MAX_SAFE_INTEGER.
    assert!(verify_receipt(&unsafe_receipt, &expected).is_err());
    let audience_units: Vec<u16> = "local-test".encode_utf16().collect();
    let wire_expected = WireReceiptExpectation {
        audience_utf16: &audience_units,
        receipt_key_id: &kid,
        actor_id: &actor,
        command_id: &command,
        intent_digest: &intent,
        workspace_id: None,
        protocol_digest: None,
    };
    assert!(verify_command_response_wire(
        &unsafe_receipt,
        br#"{"event_sequence":1,"revision":1}"#,
        &wire_expected
    )
    .is_err());
}

#[test]
fn signed_artifact_binds_actor_domain_and_body() {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public = signing.verifying_key().to_bytes();
    let actor = actor_id(&public);
    let key = key_id(&public);
    let unsigned = json!({"v":1,"domain":"test.domain.v1","signer":{"actor_id":actor,"key_id":key},"body":{"a":1}});
    let signature = sign_canonical(
        "peerwork.signed-artifact.v1:test.domain.v1",
        &unsigned,
        &signing,
    )
    .unwrap();
    let mut artifact = unsigned;
    artifact
        .as_object_mut()
        .unwrap()
        .insert("signature".into(), signature.into());
    assert!(verify_artifact(&artifact, "test.domain.v1", Some(&actor)).unwrap());
    assert!(!verify_artifact(&artifact, "other.domain.v1", Some(&actor)).unwrap());
    assert!(!verify_artifact(&artifact, "test.domain.v1", Some(&base64url(&[0; 32]))).unwrap());
    artifact["body"]["a"] = json!(2);
    assert!(!verify_artifact(&artifact, "test.domain.v1", Some(&actor)).unwrap());
}

#[test]
fn journal_signature_domain_tracks_authenticated_wire_version() {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let key = key_id(&signing.verifying_key().to_bytes());
    for kind in ["commit", "policy"] {
        for version in [1, 2, 3] {
            let base = format!("peerwork.secure.{kind}.v1");
            let exact = format!("peerwork.secure.{kind}.v{version}");
            let payload = json!({"v":version,"workspace_id":"test"});
            let signature = sign_canonical(&exact, &payload, &signing).unwrap();
            let envelope = json!({"payload":payload,"signature":signature});
            assert!(
                verify_secure_signed(&envelope, &base, &key).unwrap(),
                "{kind} v{version}"
            );
            assert!(
                !verify_secure_signed(&envelope, "peerwork.secure.checkpoint.v1", &key).unwrap()
            );
            let mut changed_version = envelope.clone();
            changed_version["payload"]["v"] = json!(if version == 1 { 2 } else { 1 });
            assert!(!verify_secure_signed(&changed_version, &base, &key).unwrap());
            let mut extra = envelope;
            extra["unexpected"] = json!(true);
            assert!(!verify_secure_signed(&extra, &base, &key).unwrap());
        }
    }
    let payload = serde_json::from_str::<Value>("{\"v\":3.0}").unwrap();
    let sig = sign_canonical("peerwork.secure.commit.v3", &payload, &signing).unwrap();
    assert!(verify_secure_signed(
        &json!({"payload":payload,"signature":sig}),
        "peerwork.secure.commit.v1",
        &key
    )
    .unwrap());
}

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
