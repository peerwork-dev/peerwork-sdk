use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, Serializable,
};
use peerwork_core::{
    crypto::base64url,
    e2ee::{
        encryption_key_id, hpke_open, hpke_open_wire, hpke_seal, hpke_seal_wire,
        open_content_bytes, open_content_wire, seal_content_bytes, seal_content_wire,
        RecipientPublicJwk,
    },
};
use serde_json::json;

#[test]
fn rfc9180_p256_aes256gcm_known_answer_first_two_messages() {
    // CFRG's immutable test-vectors.json, suite (mode=0, KEM=0x0010, KDF=1, AEAD=2).
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../conformance/rfc9180-p256-aes256gcm.json"
    ))
    .unwrap();
    assert_eq!(
        vector["source_commit"],
        "5f503c564da00b0687b3de75f1dfbdfc4079ad31"
    );
    let (private, public) =
        DhP256HkdfSha256::derive_keypair(&hex(vector["ikmR"].as_str().unwrap()));
    assert_eq!(
        private.to_bytes().as_slice(),
        hex(vector["skRm"].as_str().unwrap())
    );
    assert_eq!(
        public.to_bytes().as_slice(),
        hex(vector["pkRm"].as_str().unwrap())
    );
    let (ephemeral_private, ephemeral_public) =
        DhP256HkdfSha256::derive_keypair(&hex(vector["ikmE"].as_str().unwrap()));
    assert_eq!(
        ephemeral_private.to_bytes().as_slice(),
        hex(vector["skEm"].as_str().unwrap())
    );
    assert_eq!(
        ephemeral_public.to_bytes().as_slice(),
        hex(vector["pkEm"].as_str().unwrap())
    );
    let enc = <DhP256HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&hex(vector["enc"]
        .as_str()
        .unwrap()))
    .unwrap();
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &private,
        &enc,
        &hex(vector["info"].as_str().unwrap()),
    )
    .unwrap();
    let encryptions = vector["encryptions"].as_array().unwrap();
    for item in encryptions {
        let aad = hex(item["aad"].as_str().unwrap());
        let plaintext = hex(item["pt"].as_str().unwrap());
        let ciphertext = hex(item["ct"].as_str().unwrap());
        assert_eq!(receiver.open(&ciphertext, &aad).unwrap(), plaintext);
    }
    let mut wrong_context = hpke::setup_receiver::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &private,
        &enc,
        b"wrong-info",
    )
    .unwrap();
    let item = &encryptions[0];
    assert!(wrong_context
        .open(
            &hex(item["ct"].as_str().unwrap()),
            &hex(item["aad"].as_str().unwrap())
        )
        .is_err());
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn aes_content_roundtrip_and_aad_tamper_rejection() {
    let key = [17u8; 32];
    let context = json!({"workspace_id":"example","epoch":1});
    let plaintext = vec![42u8; 15_000];
    let sealed = seal_content_bytes(&key, &plaintext, &context).unwrap();
    assert_eq!(sealed.v, 1);
    assert_eq!(sealed.alg, "A256GCM");
    assert_eq!(sealed.chunks.len(), 3);
    assert_eq!(
        open_content_bytes(&key, &sealed, &context).unwrap(),
        plaintext
    );
    assert!(open_content_bytes(&key, &sealed, &json!({"workspace_id":"other","epoch":1})).is_err());
    assert!(open_content_bytes(&[18u8; 32], &sealed, &context).is_err());
    let mut tampered = sealed.clone();
    let replacement = if &tampered.chunks[0][0..1] == "A" {
        "B"
    } else {
        "A"
    };
    tampered.chunks[0].replace_range(0..1, replacement);
    assert!(open_content_bytes(&key, &tampered, &context).is_err());
    tampered = sealed;
    tampered.nonce = "AA".into();
    assert!(open_content_bytes(&key, &tampered, &context).is_err());
}

#[test]
fn aes_wire_context_and_plaintext_preserve_lone_utf16_surrogates() {
    let key = [31u8; 32];
    let context = br#"{"workspace_id":"\ud800","epoch":1}"#;
    let plaintext = br#"{"body":"\udfff"}"#;
    let sealed = seal_content_wire(&key, plaintext, context).unwrap();
    assert_eq!(
        open_content_wire(&key, &sealed, context).unwrap(),
        plaintext
    );
    assert!(open_content_wire(&key, &sealed, br#"{"workspace_id":"\ud801","epoch":1}"#).is_err());
}

#[test]
fn p256_hpke_keybox_roundtrip_and_suite_context_rejection() {
    let (private, public) = DhP256HkdfSha256::gen_keypair();
    let point = public.to_bytes();
    let jwk = RecipientPublicJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: base64url(&point[1..33]),
        y: base64url(&point[33..65]),
    };
    assert_eq!(point.len(), 65);
    assert_eq!(encryption_key_id(&jwk).unwrap().len(), 43);
    let context = json!({"workspace_id":"example","epoch":1});
    let plaintext = json!({"key":"test-only-content","epoch":1});
    let box_value = hpke_seal(&jwk, &plaintext, &context).unwrap();
    assert_eq!(
        box_value.suite,
        "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/A256GCM"
    );
    assert_eq!(
        hpke_open(&private.to_bytes(), &box_value, &context).unwrap(),
        plaintext
    );
    assert!(hpke_open(
        &private.to_bytes(),
        &box_value,
        &json!({"workspace_id":"other","epoch":1})
    )
    .is_err());
    let (wrong_private, _) = DhP256HkdfSha256::gen_keypair();
    assert!(hpke_open(&wrong_private.to_bytes(), &box_value, &context).is_err());
    let mut bad = box_value.clone();
    bad.suite = "other".into();
    assert!(hpke_open(&private.to_bytes(), &bad, &context).is_err());
    bad = box_value;
    bad.enc = "AA".into();
    assert!(hpke_open(&private.to_bytes(), &bad, &context).is_err());
}

#[test]
fn hpke_wire_context_and_plaintext_preserve_lone_utf16_surrogates() {
    let (private, public) = DhP256HkdfSha256::gen_keypair();
    let point = public.to_bytes();
    let jwk = RecipientPublicJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: base64url(&point[1..33]),
        y: base64url(&point[33..65]),
    };
    let context = br#"{"workspace_id":"\ud800"}"#;
    let plaintext = br#"{"key":"\udfff"}"#;
    let box_value = hpke_seal_wire(&jwk, plaintext, context).unwrap();
    let opened = hpke_open_wire(&private.to_bytes(), &box_value, context).unwrap();
    assert_eq!(
        opened.get("key").unwrap().as_utf16(),
        Some([0xdfff_u16].as_slice())
    );
    assert!(hpke_open_wire(
        &private.to_bytes(),
        &box_value,
        br#"{"workspace_id":"\ud801"}"#
    )
    .is_err());
}
