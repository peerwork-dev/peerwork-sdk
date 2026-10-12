//! Conformance-only stdin bridge. Test-only key material never enters argv or fixtures.
use peerwork_core::{
    crypto::{base64url, decode_base64url},
    e2ee::{
        hpke_open, hpke_seal, open_content_bytes, seal_content_bytes, KeyBox, RecipientPublicJwk,
        SealedContent,
    },
};
use serde_json::{json, Value};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: Value = serde_json::from_str(&input)?;
    let context = &request["context"];
    let response = match request["op"].as_str().ok_or("missing op")? {
        "open_key_box" => {
            let private = decode_base64url(request["private_key"].as_str().ok_or("private key")?)?;
            let sealed: KeyBox = serde_json::from_value(request["sealed"].clone())?;
            hpke_open(&private, &sealed, context)?
        }
        "seal_key_box" => {
            let recipient: RecipientPublicJwk =
                serde_json::from_value(request["recipient"].clone())?;
            serde_json::to_value(hpke_seal(&recipient, &request["plaintext"], context)?)?
        }
        "open_content" => {
            let key: [u8; 32] = decode_base64url(request["key"].as_str().ok_or("key")?)?
                .try_into()
                .map_err(|_| "key length")?;
            let sealed: SealedContent = serde_json::from_value(request["sealed"].clone())?;
            json!({"plaintext":base64url(&open_content_bytes(&key, &sealed, context)?)})
        }
        "seal_content" => {
            let key: [u8; 32] = decode_base64url(request["key"].as_str().ok_or("key")?)?
                .try_into()
                .map_err(|_| "key length")?;
            let plaintext = decode_base64url(request["plaintext"].as_str().ok_or("plaintext")?)?;
            serde_json::to_value(seal_content_bytes(&key, &plaintext, context)?)?
        }
        _ => return Err("unknown op".into()),
    };
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}
