//! Workspace encrypted content and key-box wire formats.

use crate::{
    canonical::{canonical, Path},
    crypto::{base64url, decode_base64url, sha256},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 6144;
const KEYBOX_SUITE: &str = "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/A256GCM";

#[derive(Debug, Error)]
pub enum E2eeError {
    #[error("invalid encrypted wire format")]
    Format,
    #[error("encrypted content too large")]
    TooLarge,
    #[error("authentication failed")]
    Authentication,
    #[error("OS random source failed")]
    Entropy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedContent {
    pub v: u8,
    pub alg: String,
    pub nonce: String,
    pub chunks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBox {
    pub v: u8,
    pub suite: String,
    pub enc: String,
    pub chunks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

pub fn encryption_key_id(jwk: &RecipientPublicJwk) -> Result<String, E2eeError> {
    public_key_bytes(jwk)?;
    let canonical = canonical(
        &serde_json::to_value(jwk).map_err(|_| E2eeError::Format)?,
        Path::SecureArtifact,
    )
    .map_err(|_| E2eeError::Format)?;
    Ok(base64url(&sha256(canonical.as_bytes())))
}

fn public_key_bytes(jwk: &RecipientPublicJwk) -> Result<[u8; 65], E2eeError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(E2eeError::Format);
    }
    let x: [u8; 32] = decode_base64url(&jwk.x)
        .map_err(|_| E2eeError::Format)?
        .try_into()
        .map_err(|_| E2eeError::Format)?;
    let y: [u8; 32] = decode_base64url(&jwk.y)
        .map_err(|_| E2eeError::Format)?
        .try_into()
        .map_err(|_| E2eeError::Format)?;
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    <DhP256HkdfSha256 as KemTrait>::PublicKey::from_bytes(&point).map_err(|_| E2eeError::Format)?;
    Ok(point)
}

pub fn seal_content_bytes(
    key: &[u8; 32],
    plaintext: &[u8],
    context: &Value,
) -> Result<SealedContent, E2eeError> {
    let aad = canonical(
        &json!({"domain":"peerwork.content-object.v1","context":context}),
        Path::SecureArtifact,
    )
    .map_err(|_| E2eeError::Format)?;
    seal_content_with_aad(key, plaintext, aad.as_bytes())
}

/// Lossless UTF-16 path for signed/decrypted SecureJson and authenticated AAD.
pub fn seal_content_wire(
    key: &[u8; 32],
    plaintext_wire: &[u8],
    context_wire: &[u8],
) -> Result<SealedContent, E2eeError> {
    let mut plaintext = parse_wire_json_js_bounded(plaintext_wire, 64, MAX_CIPHERTEXT_BYTES)
        .map_err(|_| E2eeError::Format)?;
    let context =
        parse_wire_json_js_bounded(context_wire, 64, 196_608).map_err(|_| E2eeError::Format)?;
    let canonical =
        canonical_wire_value(&plaintext, Path::SecureArtifact).map_err(|_| E2eeError::Format);
    wipe_wire(&mut plaintext);
    let plaintext = Zeroizing::new(canonical?);
    let aad = content_aad_wire(&context)?;
    seal_content_with_aad(key, plaintext.as_bytes(), aad.as_bytes())
}

fn content_aad_wire(context: &WireValue) -> Result<String, E2eeError> {
    let wrapper = WireValue::Object(vec![
        (
            "domain".encode_utf16().collect(),
            WireValue::String("peerwork.content-object.v1".encode_utf16().collect()),
        ),
        ("context".encode_utf16().collect(), context.clone()),
    ]);
    canonical_wire_value(&wrapper, Path::SecureArtifact).map_err(|_| E2eeError::Format)
}

fn seal_content_with_aad(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedContent, E2eeError> {
    if plaintext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(E2eeError::TooLarge);
    }
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| E2eeError::Entropy)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| E2eeError::Format)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| E2eeError::Authentication)?;
    Ok(SealedContent {
        v: 1,
        alg: "A256GCM".into(),
        nonce: base64url(&nonce),
        chunks: chunk(&ciphertext),
    })
}

pub fn open_content_bytes(
    key: &[u8; 32],
    sealed: &SealedContent,
    context: &Value,
) -> Result<Vec<u8>, E2eeError> {
    let aad = canonical(
        &json!({"domain":"peerwork.content-object.v1","context":context}),
        Path::SecureArtifact,
    )
    .map_err(|_| E2eeError::Format)?;
    open_content_with_aad(key, sealed, aad.as_bytes())
}

/// Open ciphertext using exact JS-compatible context canonicalization. The
/// returned plaintext bytes remain untrusted until the caller parses and
/// validates the operation against the verified journal context.
pub fn open_content_wire(
    key: &[u8; 32],
    sealed: &SealedContent,
    context_wire: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let context =
        parse_wire_json_js_bounded(context_wire, 64, 196_608).map_err(|_| E2eeError::Format)?;
    let aad = content_aad_wire(&context)?;
    open_content_with_aad(key, sealed, aad.as_bytes())
}

fn open_content_with_aad(
    key: &[u8; 32],
    sealed: &SealedContent,
    aad: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    if sealed.v != 1
        || sealed.alg != "A256GCM"
        || sealed.chunks.is_empty()
        || sealed.chunks.len() > (MAX_CIPHERTEXT_BYTES + 16).div_ceil(CHUNK_BYTES)
    {
        return Err(E2eeError::Format);
    }
    let nonce: [u8; 12] = decode_base64url(&sealed.nonce)
        .map_err(|_| E2eeError::Format)?
        .try_into()
        .map_err(|_| E2eeError::Format)?;
    let ciphertext = join_chunks(&sealed.chunks, MAX_CIPHERTEXT_BYTES + 16)?;
    if ciphertext.len() < 16 {
        return Err(E2eeError::Format);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| E2eeError::Format)?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| E2eeError::Authentication)
}

pub fn hpke_seal(
    recipient: &RecipientPublicJwk,
    plaintext: &Value,
    context: &Value,
) -> Result<KeyBox, E2eeError> {
    let aad = canonical(
        &json!({"domain":"peerwork.secure.key-box.v1","context":context}),
        Path::SecureArtifact,
    )
    .map_err(|_| E2eeError::Format)?;
    let plaintext =
        Zeroizing::new(canonical(plaintext, Path::SecureArtifact).map_err(|_| E2eeError::Format)?);
    hpke_seal_with_aad(recipient, plaintext.as_bytes(), aad.as_bytes())
}

pub fn hpke_seal_wire(
    recipient: &RecipientPublicJwk,
    plaintext_wire: &[u8],
    context_wire: &[u8],
) -> Result<KeyBox, E2eeError> {
    let mut plaintext = parse_wire_json_js_bounded(plaintext_wire, 64, MAX_CIPHERTEXT_BYTES)
        .map_err(|_| E2eeError::Format)?;
    let context =
        parse_wire_json_js_bounded(context_wire, 64, 196_608).map_err(|_| E2eeError::Format)?;
    let canonical =
        canonical_wire_value(&plaintext, Path::SecureArtifact).map_err(|_| E2eeError::Format);
    wipe_wire(&mut plaintext);
    let plaintext = Zeroizing::new(canonical?);
    let aad = keybox_aad_wire(&context)?;
    hpke_seal_with_aad(recipient, plaintext.as_bytes(), aad.as_bytes())
}

fn keybox_aad_wire(context: &WireValue) -> Result<String, E2eeError> {
    let wrapper = WireValue::Object(vec![
        (
            "domain".encode_utf16().collect(),
            WireValue::String("peerwork.secure.key-box.v1".encode_utf16().collect()),
        ),
        ("context".encode_utf16().collect(), context.clone()),
    ]);
    canonical_wire_value(&wrapper, Path::SecureArtifact).map_err(|_| E2eeError::Format)
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

fn hpke_seal_with_aad(
    recipient: &RecipientPublicJwk,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<KeyBox, E2eeError> {
    let point = public_key_bytes(recipient)?;
    let key = <DhP256HkdfSha256 as KemTrait>::PublicKey::from_bytes(&point)
        .map_err(|_| E2eeError::Format)?;
    let (enc, mut sender) = hpke::setup_sender::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeS::Base,
        &key,
        b"peerwork.secure.key-box.v1",
    )
    .map_err(|_| E2eeError::Format)?;
    let ciphertext = sender
        .seal(plaintext, aad)
        .map_err(|_| E2eeError::Authentication)?;
    let chunks = chunk(&ciphertext);
    if chunks.len() > 128 {
        return Err(E2eeError::TooLarge);
    }
    Ok(KeyBox {
        v: 1,
        suite: KEYBOX_SUITE.into(),
        enc: base64url(&enc.to_bytes()),
        chunks,
    })
}

pub fn hpke_open(
    recipient_private_key: &[u8],
    box_value: &KeyBox,
    context: &Value,
) -> Result<Value, E2eeError> {
    let aad = canonical(
        &json!({"domain":"peerwork.secure.key-box.v1","context":context}),
        Path::SecureArtifact,
    )
    .map_err(|_| E2eeError::Format)?;
    let plaintext = Zeroizing::new(hpke_open_with_aad(
        recipient_private_key,
        box_value,
        aad.as_bytes(),
    )?);
    // TS decodeJson uses JSON.parse here: decoded duplicate names take the last
    // value. The lossless wire API remains necessary for lone UTF-16 surrogates.
    serde_json::from_slice(&plaintext).map_err(|_| E2eeError::Format)
}

pub fn hpke_open_wire(
    recipient_private_key: &[u8],
    box_value: &KeyBox,
    context_wire: &[u8],
) -> Result<WireValue, E2eeError> {
    let context =
        parse_wire_json_js_bounded(context_wire, 64, 196_608).map_err(|_| E2eeError::Format)?;
    let aad = keybox_aad_wire(&context)?;
    let plaintext = Zeroizing::new(hpke_open_with_aad(
        recipient_private_key,
        box_value,
        aad.as_bytes(),
    )?);
    parse_wire_json_js_bounded(&plaintext, 64, MAX_CIPHERTEXT_BYTES).map_err(|_| E2eeError::Format)
}

fn hpke_open_with_aad(
    recipient_private_key: &[u8],
    box_value: &KeyBox,
    aad: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    if box_value.v != 1
        || box_value.suite != KEYBOX_SUITE
        || box_value.chunks.is_empty()
        || box_value.chunks.len() > 128
    {
        return Err(E2eeError::Format);
    }
    let private = <DhP256HkdfSha256 as KemTrait>::PrivateKey::from_bytes(recipient_private_key)
        .map_err(|_| E2eeError::Format)?;
    let enc = <DhP256HkdfSha256 as KemTrait>::EncappedKey::from_bytes(
        &decode_base64url(&box_value.enc).map_err(|_| E2eeError::Format)?,
    )
    .map_err(|_| E2eeError::Format)?;
    let ciphertext = join_chunks(&box_value.chunks, MAX_CIPHERTEXT_BYTES)?;
    if ciphertext.len() < 16 {
        return Err(E2eeError::Format);
    }
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &private,
        &enc,
        b"peerwork.secure.key-box.v1",
    )
    .map_err(|_| E2eeError::Authentication)?;
    receiver
        .open(&ciphertext, aad)
        .map_err(|_| E2eeError::Authentication)
}

fn chunk(ciphertext: &[u8]) -> Vec<String> {
    ciphertext.chunks(CHUNK_BYTES).map(base64url).collect()
}

fn join_chunks(chunks: &[String], max: usize) -> Result<Vec<u8>, E2eeError> {
    let mut out = Vec::new();
    for piece in chunks {
        if piece.len() > 8192 {
            return Err(E2eeError::Format);
        }
        let bytes = decode_base64url(piece).map_err(|_| E2eeError::Format)?;
        if out.len().saturating_add(bytes.len()) > max {
            return Err(E2eeError::TooLarge);
        }
        out.extend(bytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_convenience_open_uses_js_duplicate_member_semantics() {
        let (private, public) = DhP256HkdfSha256::gen_keypair();
        let point = public.to_bytes();
        let jwk = RecipientPublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: base64url(&point[1..33]),
            y: base64url(&point[33..65]),
        };
        let context = json!({"workspace_id":"example"});
        let aad = canonical(
            &json!({"domain":"peerwork.secure.key-box.v1","context":context}),
            Path::SecureArtifact,
        )
        .unwrap();
        let keybox =
            hpke_seal_with_aad(&jwk, br#"{"key":1,"\u006bey":2}"#, aad.as_bytes()).unwrap();
        assert_eq!(
            hpke_open(&private.to_bytes(), &keybox, &context).unwrap(),
            json!({"key":2})
        );
    }
}
