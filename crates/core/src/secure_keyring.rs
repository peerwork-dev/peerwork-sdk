//! Secret epoch keys and HPKE box interoperability. This is cryptographic
//! material handling, not evidence that a grant or policy is authorized.

use crate::{
    canonical::Path,
    crypto::{base64url, decode_base64url},
    e2ee::{hpke_open_wire, hpke_seal_wire, KeyBox, RecipientPublicJwk},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_EPOCHS: usize = 1024;
const MAX_WIRE: usize = 131_072;
const MAX_SAFE_EPOCH: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyringError {
    #[error("secure keyring is invalid")]
    Invalid,
    #[error("OS random source failed")]
    Entropy,
    #[error("secure key box could not be sealed or opened")]
    Crypto,
}

struct EpochSecret {
    epoch: u64,
    key: Zeroizing<[u8; 32]>,
}

/// Secret local material. No `Debug`, serialization, or language DTO impl.
/// Callers must separately verify signed policy, certificate, recipient,
/// invite/delegation and owner continuity before using a key box.
pub struct SecretKeyring {
    workspace_id: String,
    keys: Vec<EpochSecret>,
}

impl SecretKeyring {
    pub fn new_private(workspace_id: &str, epoch: u64) -> Result<Self, KeyringError> {
        if !valid_token(workspace_id) || !valid_epoch(epoch) {
            return Err(KeyringError::Invalid);
        }
        let mut result = Self {
            workspace_id: workspace_id.to_owned(),
            keys: Vec::new(),
        };
        result.rotate(epoch)?;
        Ok(result)
    }

    /// TS rotation permits gaps, but the new epoch must exceed every saved
    /// epoch. A caller should persist a pending rotation before any POST and
    /// reuse its exact saved key material after an uncertain response.
    pub fn rotate(&mut self, epoch: u64) -> Result<(), KeyringError> {
        if !valid_epoch(epoch)
            || self.keys.len() >= MAX_EPOCHS
            || self.keys.iter().any(|saved| saved.epoch >= epoch)
        {
            return Err(KeyringError::Invalid);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut *key)
            .map_err(|_| KeyringError::Entropy)?;
        self.keys.push(EpochSecret { epoch, key });
        Ok(())
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.keys.iter().map(|entry| entry.epoch)
    }
    /// Trusted Rust consumers only. Never return this through a binding.
    pub fn key_at(&self, epoch: u64) -> Option<&[u8; 32]> {
        self.keys
            .iter()
            .find(|entry| entry.epoch == epoch)
            .map(|entry| &*entry.key)
    }

    pub fn parse_wire(input: &[u8]) -> Result<Self, KeyringError> {
        let mut value =
            parse_wire_json_bounded(input, 8, MAX_WIRE).map_err(|_| KeyringError::Invalid)?;
        let parsed = Self::from_value(&value);
        wipe_wire(&mut value);
        parsed
    }

    fn from_value(value: &WireValue) -> Result<Self, KeyringError> {
        if value.object_len() != Some(3)
            || value.get("v").and_then(WireValue::as_number) != Some(1.0)
        {
            return Err(KeyringError::Invalid);
        }
        let workspace_id = value
            .get("workspace_id")
            .and_then(WireValue::as_string)
            .ok_or(KeyringError::Invalid)?;
        if !valid_token(&workspace_id) {
            return Err(KeyringError::Invalid);
        }
        let WireValue::Array(rows) = value.get("keys").ok_or(KeyringError::Invalid)? else {
            return Err(KeyringError::Invalid);
        };
        if rows.len() > MAX_EPOCHS {
            return Err(KeyringError::Invalid);
        }
        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            if row.object_len() != Some(2) {
                return Err(KeyringError::Invalid);
            }
            let number = row
                .get("epoch")
                .and_then(WireValue::as_number)
                .ok_or(KeyringError::Invalid)?;
            if !number.is_finite()
                || number.fract() != 0.0
                || number < 1.0
                || number > MAX_SAFE_EPOCH as f64
            {
                return Err(KeyringError::Invalid);
            }
            let epoch = number as u64;
            if keys.iter().any(|saved: &EpochSecret| saved.epoch == epoch) {
                return Err(KeyringError::Invalid);
            }
            let encoded = Zeroizing::new(
                String::from_utf16(
                    row.get("key")
                        .and_then(WireValue::as_utf16)
                        .ok_or(KeyringError::Invalid)?,
                )
                .map_err(|_| KeyringError::Invalid)?,
            );
            if encoded.len() != 43 {
                return Err(KeyringError::Invalid);
            }
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| KeyringError::Invalid)?,
            );
            let reencoded = Zeroizing::new(base64url(&decoded));
            if decoded.len() != 32 || reencoded.as_str() != encoded.as_str() {
                return Err(KeyringError::Invalid);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&decoded);
            keys.push(EpochSecret { epoch, key });
        }
        Ok(Self { workspace_id, keys })
    }

    /// Canonical secret wire for protected storage or immediate HPKE sealing.
    /// The returned bytes and all temporary encoded keys are zeroized on drop.
    pub fn canonical_wire(&self) -> Result<Zeroizing<Vec<u8>>, KeyringError> {
        let mut rows = Vec::with_capacity(self.keys.len());
        for entry in &self.keys {
            let encoded = Zeroizing::new(base64url(&*entry.key));
            rows.push(WireValue::Object(vec![
                (units("epoch"), WireValue::Number(entry.epoch as f64)),
                (units("key"), WireValue::String(units(&encoded))),
            ]));
        }
        let mut value = WireValue::Object(vec![
            (units("v"), WireValue::Number(1.0)),
            (
                units("workspace_id"),
                WireValue::String(units(&self.workspace_id)),
            ),
            (units("keys"), WireValue::Array(rows)),
        ]);
        let canonical =
            canonical_wire_value(&value, Path::SecureArtifact).map_err(|_| KeyringError::Invalid);
        wipe_wire(&mut value);
        let canonical = Zeroizing::new(canonical?);
        if canonical.len() > MAX_WIRE {
            return Err(KeyringError::Invalid);
        }
        Ok(Zeroizing::new(canonical.as_bytes().to_vec()))
    }

    /// HPKE integrity only. Caller-supplied context is not a policy proof.
    pub fn seal_to(
        &self,
        recipient: &RecipientPublicJwk,
        context_wire: &[u8],
    ) -> Result<KeyBox, KeyringError> {
        let wire = self.canonical_wire()?;
        hpke_seal_wire(recipient, &wire, context_wire).map_err(|_| KeyringError::Crypto)
    }

    /// HPKE integrity only. Verify the surrounding signed grant and expected
    /// workspace/policy/recipient before staging returned keys locally.
    pub fn open_from(
        recipient_private_key: &[u8],
        key_box: &KeyBox,
        context_wire: &[u8],
        expected_workspace: &str,
    ) -> Result<Self, KeyringError> {
        let mut value = hpke_open_wire(recipient_private_key, key_box, context_wire)
            .map_err(|_| KeyringError::Crypto)?;
        let parsed = Self::from_value(&value);
        wipe_wire(&mut value);
        let result = parsed?;
        if result.workspace_id != expected_workspace {
            return Err(KeyringError::Invalid);
        }
        Ok(result)
    }
}

fn valid_epoch(epoch: u64) -> bool {
    (1..=MAX_SAFE_EPOCH).contains(&epoch)
}
fn valid_token(input: &str) -> bool {
    input.len() == 43
        && input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && decode_base64url(input).is_ok_and(|decoded| decoded.len() == 32)
}
fn units(input: &str) -> Vec<u16> {
    input.encode_utf16().collect()
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
    use serde_json::json;

    #[test]
    fn strict_epoch_history_and_rotation() {
        let workspace = "w".repeat(43);
        let mut keys = SecretKeyring::new_private(&workspace, 1).unwrap();
        let first = *keys.key_at(1).unwrap();
        keys.rotate(3).unwrap(); // Gaps are valid in the tracked TS rotation.
        assert_eq!(keys.epochs().collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(keys.key_at(1), Some(&first));
        assert_eq!(keys.rotate(3), Err(KeyringError::Invalid));
        assert_eq!(keys.rotate(2), Err(KeyringError::Invalid));
        let wire = keys.canonical_wire().unwrap();
        let loaded = SecretKeyring::parse_wire(&wire).unwrap();
        assert_eq!(loaded.epochs().collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(loaded.key_at(1), Some(&first));
        let duplicate = json!({"v":1,"workspace_id":workspace,"keys":[
            {"epoch":1,"key":base64url(&first)},
            {"epoch":1,"key":base64url(&first)}
        ]});
        assert!(matches!(
            SecretKeyring::parse_wire(duplicate.to_string().as_bytes()),
            Err(KeyringError::Invalid)
        ));
        assert!(matches!(
            SecretKeyring::parse_wire(br#"{"v":1,"workspace_id":"bad","keys":[]}"#),
            Err(KeyringError::Invalid)
        ));
    }
}
