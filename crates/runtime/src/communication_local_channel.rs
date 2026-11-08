//! Mutually authenticated local capability channel. A process that steals the
//! loopback port learns neither the key nor plaintext and cannot forge an ACK.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use peerwork_core::crypto::{base64url, decode_base64url, sha256, sha256_hex};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use zeroize::Zeroizing;
type R<T> = Result<T, &'static str>;
const FORMAT: &str = "peerwork.local-channel.v1";
fn aad(direction: &str, method: &str, request: Option<&[u8]>) -> Vec<u8> {
    json!([FORMAT, direction, method, request.map(sha256_hex)])
        .to_string()
        .into_bytes()
}
fn cipher(key: &str, direction: &str) -> R<Aes256Gcm> {
    if key.len() != 43
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        return Err("BRIDGE_CHANNEL_INVALID");
    }
    let derived = Zeroizing::new(sha256(format!("{FORMAT}\0{direction}\0{key}").as_bytes()));
    Aes256Gcm::new_from_slice(&*derived).map_err(|_| "BRIDGE_CHANNEL_INVALID")
}
fn seal(
    key: &str,
    direction: &str,
    method: &str,
    request: Option<&[u8]>,
    value: &Value,
    max: usize,
) -> R<String> {
    let plain = Zeroizing::new(value.to_string());
    if plain.len() > max {
        return Err("BRIDGE_CHANNEL_INVALID");
    }
    let mut nonce = [0; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| "ENTROPY_UNAVAILABLE")?;
    let bytes = cipher(key, direction)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain.as_bytes(),
                aad: &aad(direction, method, request),
            },
        )
        .map_err(|_| "BRIDGE_CHANNEL_INVALID")?;
    Ok(
        json!({"format":FORMAT,"nonce":base64url(&nonce),"ciphertext":base64url(&bytes)})
            .to_string(),
    )
}
fn open(
    key: &str,
    direction: &str,
    method: &str,
    request: Option<&[u8]>,
    wire: &[u8],
    max: usize,
) -> R<Value> {
    if wire.len() > max * 2 + 1024 {
        return Err("BRIDGE_CHANNEL_INVALID");
    }
    let value = peerwork_core::strict_json::parse_strict_json(wire)
        .map_err(|_| "BRIDGE_CHANNEL_INVALID")?;
    if value.as_object().is_none_or(|o| o.len() != 3) || value["format"] != FORMAT {
        return Err("BRIDGE_CHANNEL_INVALID");
    }
    let nonce = decode_base64url(value["nonce"].as_str().ok_or("BRIDGE_CHANNEL_INVALID")?)
        .map_err(|_| "BRIDGE_CHANNEL_INVALID")?;
    let bytes = decode_base64url(
        value["ciphertext"]
            .as_str()
            .ok_or("BRIDGE_CHANNEL_INVALID")?,
    )
    .map_err(|_| "BRIDGE_CHANNEL_INVALID")?;
    if nonce.len() != 12 || bytes.len() > max + 16 {
        return Err("BRIDGE_CHANNEL_INVALID");
    }
    let plain = Zeroizing::new(
        cipher(key, direction)?
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: &aad(direction, method, request),
                },
            )
            .map_err(|_| "BRIDGE_CHANNEL_INVALID")?,
    );
    peerwork_core::strict_json::parse_strict_json(&plain).map_err(|_| "BRIDGE_CHANNEL_INVALID")
}
pub(crate) fn key_id(key: &str) -> String {
    base64url(&sha256(
        format!("peerwork.local.access-id.v1\0{key}").as_bytes(),
    ))
}
pub(crate) fn request(key: &str, method: &str, value: &Value) -> R<String> {
    seal(key, "REQUEST", method, None, value, 131072)
}
pub(crate) fn open_request(key: &str, method: &str, wire: &[u8]) -> R<Value> {
    open(key, "REQUEST", method, None, wire, 131072)
}
pub(crate) fn response(key: &str, method: &str, request: &[u8], value: &Value) -> R<String> {
    seal(key, "RESPONSE", method, Some(request), value, 32768)
}
pub(crate) fn open_response(key: &str, method: &str, request: &[u8], wire: &[u8]) -> R<Value> {
    open(key, "RESPONSE", method, Some(request), wire, 32768)
}
pub(crate) fn request_bounded(key: &str, method: &str, value: &Value, max: usize) -> R<String> {
    seal(key, "REQUEST", method, None, value, max)
}
pub(crate) fn open_request_bounded(key: &str, method: &str, wire: &[u8], max: usize) -> R<Value> {
    open(key, "REQUEST", method, None, wire, max)
}
pub(crate) fn response_bounded(
    key: &str,
    method: &str,
    request: &[u8],
    value: &Value,
    max: usize,
) -> R<String> {
    seal(key, "RESPONSE", method, Some(request), value, max)
}
pub(crate) fn open_response_bounded(
    key: &str,
    method: &str,
    request: &[u8],
    wire: &[u8],
    max: usize,
) -> R<Value> {
    open(key, "RESPONSE", method, Some(request), wire, max)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channel_hides_bodies_and_binds_method_direction_and_fresh_request() {
        let key = "K".repeat(43);
        let body = json!({"message":"private bridge channel payload"});
        let first = request(&key, "deliver", &body).unwrap();
        let second = request(&key, "deliver", &body).unwrap();
        assert_ne!(first, second);
        assert!(!first.contains("private bridge"));
        assert!(!first.contains(&key));
        assert_eq!(
            open_request(&key, "deliver", first.as_bytes()).unwrap(),
            body
        );
        assert!(open_request(&key, "receipt", first.as_bytes()).is_err());
        assert!(open_request(&"Z".repeat(43), "deliver", first.as_bytes()).is_err());
        let reply = response(
            &key,
            "deliver",
            first.as_bytes(),
            &json!({"state":"HOST_ACCEPTED"}),
        )
        .unwrap();
        assert_eq!(
            open_response(&key, "deliver", first.as_bytes(), reply.as_bytes()).unwrap()["state"],
            "HOST_ACCEPTED"
        );
        assert!(open_response(&key, "deliver", second.as_bytes(), reply.as_bytes()).is_err());
        assert!(open_request(&key, "deliver", reply.as_bytes()).is_err());
        assert!(open_response(
            &key,
            "deliver",
            first.as_bytes(),
            br#"{"state":"HOST_ACCEPTED"}"#
        )
        .is_err());
    }
}
