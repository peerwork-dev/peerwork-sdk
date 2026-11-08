//! Native P-256 HPKE recipient identity and public self-certificate. The
//! certificate proves possession of a signing key, not current directory,
//! member, policy, invitation, delegation or grant authority.

use crate::{
    crypto::{actor_id, base64url, key_id, sign_canonical, verify_canonical, verifying_key},
    e2ee::{encryption_key_id, RecipientPublicJwk},
};
use ed25519_dalek::SigningKey;
use hpke::{kem::DhP256HkdfSha256, Deserializable, Kem as KemTrait, Serializable};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const CERT_LIFETIME_MS: u64 = 366 * 86_400_000;
const MAX_SAFE_TIME: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecipientError {
    #[error("secure recipient identity or certificate is invalid")]
    Invalid,
    #[error("OS random source failed")]
    Entropy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientCertificate {
    pub payload: Value,
    pub signature: String,
}

/// Secret recipient material. Only protected runtime storage may retain its
/// private scalar; language DTOs may expose the public JWK and certificate.
pub struct SecretRecipient {
    private: Zeroizing<[u8; 32]>,
    public: RecipientPublicJwk,
    encryption_key_id: String,
}

impl SecretRecipient {
    /// Use fallible OS entropy, then RFC 9180 deterministic P-256 derivation.
    /// This avoids the HPKE crate's infallible RNG wrapper on entropy failure.
    pub fn generate() -> Result<Self, RecipientError> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut *ikm)
            .map_err(|_| RecipientError::Entropy)?;
        let (private, _) = DhP256HkdfSha256::derive_keypair(&*ikm);
        let mut serialized = private.to_bytes();
        let mut bytes = Zeroizing::new([0u8; 32]);
        if serialized.len() != 32 {
            serialized.as_mut_slice().zeroize();
            return Err(RecipientError::Invalid);
        }
        bytes.copy_from_slice(&serialized);
        serialized.as_mut_slice().zeroize();
        Self::from_private(bytes)
    }

    /// Accept the exact 32-byte HPKE private serialization also exported by
    /// the tracked TypeScript recipient helper. Caller-supplied source bytes
    /// must themselves be protected and wiped by their owner.
    pub fn from_private(private: Zeroizing<[u8; 32]>) -> Result<Self, RecipientError> {
        let secret = <DhP256HkdfSha256 as KemTrait>::PrivateKey::from_bytes(&*private)
            .map_err(|_| RecipientError::Invalid)?;
        let public = DhP256HkdfSha256::sk_to_pk(&secret).to_bytes();
        if public.len() != 65 || public[0] != 4 {
            return Err(RecipientError::Invalid);
        }
        let jwk = RecipientPublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: base64url(&public[1..33]),
            y: base64url(&public[33..65]),
        };
        let encryption_key_id = encryption_key_id(&jwk).map_err(|_| RecipientError::Invalid)?;
        Ok(Self {
            private,
            public: jwk,
            encryption_key_id,
        })
    }

    pub fn public_jwk(&self) -> &RecipientPublicJwk {
        &self.public
    }
    pub fn encryption_key_id(&self) -> &str {
        &self.encryption_key_id
    }
    /// Trusted Rust consumers only. Never return through a language binding.
    pub fn private_bytes(&self) -> &[u8; 32] {
        &self.private
    }

    /// Tracked v1 self-certificate shape and lifetime. Issuance does not
    /// publish a directory entry or authorize key delivery.
    pub fn certify(
        &self,
        signing_key: &SigningKey,
        issued_at: u64,
    ) -> Result<RecipientCertificate, RecipientError> {
        let expires_at = issued_at
            .checked_add(CERT_LIFETIME_MS)
            .filter(|time| *time <= MAX_SAFE_TIME)
            .ok_or(RecipientError::Invalid)?;
        let public = signing_key.verifying_key().to_bytes();
        let payload = json!({
            "v":1,
            "actor_id":actor_id(&public),
            "signing_key":key_id(&public),
            "encryption_key":self.public,
            "encryption_key_id":self.encryption_key_id,
            "issued_at":issued_at,
            "expires_at":expires_at,
        });
        let signature = sign_canonical("peerwork.secure.key-certificate.v1", &payload, signing_key)
            .map_err(|_| RecipientError::Invalid)?;
        Ok(RecipientCertificate { payload, signature })
    }

    pub fn verify_local_certificate(
        &self,
        certificate: &RecipientCertificate,
        expected_actor: &str,
        expected_signing_key: &str,
        at: u64,
    ) -> Result<(), RecipientError> {
        let payload = &certificate.payload;
        if payload["v"] != 1
            || payload["actor_id"] != expected_actor
            || payload["signing_key"] != expected_signing_key
            || payload["encryption_key"] != serde_json::to_value(&self.public).unwrap()
            || payload["encryption_key_id"] != self.encryption_key_id
            || payload["issued_at"].as_u64().is_none()
            || payload["expires_at"].as_u64().is_none()
        {
            return Err(RecipientError::Invalid);
        }
        let issued = payload["issued_at"].as_u64().unwrap();
        let expires = payload["expires_at"].as_u64().unwrap();
        let signer = verifying_key(expected_signing_key).map_err(|_| RecipientError::Invalid)?;
        if actor_id(&signer.to_bytes()) != expected_actor
            || at > MAX_SAFE_TIME
            || issued > at
            || at >= expires
            || expires <= issued
            || expires - issued > CERT_LIFETIME_MS
            || expires > MAX_SAFE_TIME
        {
            return Err(RecipientError::Invalid);
        }
        if !verify_canonical(
            "peerwork.secure.key-certificate.v1",
            payload,
            &certificate.signature,
            expected_signing_key,
        )
        .map_err(|_| RecipientError::Invalid)?
        {
            return Err(RecipientError::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn generated_recipient_roundtrips_and_self_certificate_is_pinned() {
        let recipient = SecretRecipient::generate().unwrap();
        let copied = Zeroizing::new(*recipient.private_bytes());
        let reopened = SecretRecipient::from_private(copied).unwrap();
        assert_eq!(reopened.public_jwk().x, recipient.public_jwk().x);
        assert_eq!(reopened.public_jwk().y, recipient.public_jwk().y);
        assert_eq!(reopened.encryption_key_id(), recipient.encryption_key_id());
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let public = signer.verifying_key().to_bytes();
        let actor = actor_id(&public);
        let key = key_id(&public);
        let at = 1_700_000_000_000;
        let cert = recipient.certify(&signer, at).unwrap();
        reopened
            .verify_local_certificate(&cert, &actor, &key, at)
            .unwrap();
        assert!(reopened
            .verify_local_certificate(&cert, &actor, &key, at + CERT_LIFETIME_MS)
            .is_err());
        assert!(reopened
            .verify_local_certificate(&cert, &actor, &"a".repeat(43), at)
            .is_err());
        let mut overlong = cert.clone();
        overlong.payload["expires_at"] = json!(at + 367 * 86_400_000);
        overlong.signature = sign_canonical(
            "peerwork.secure.key-certificate.v1",
            &overlong.payload,
            &signer,
        )
        .unwrap();
        assert!(reopened
            .verify_local_certificate(&overlong, &actor, &key, at)
            .is_err());
    }

    #[test]
    fn tracked_ts_recipient_certificate_vector() {
        let Ok(out) = std::env::var("PEERWORK_RECIPIENT_VECTOR_OUT") else {
            return;
        };
        let recipient = SecretRecipient::generate().unwrap();
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let public = signer.verifying_key().to_bytes();
        let at = 1_700_000_000_000;
        let cert = recipient.certify(&signer, at).unwrap();
        let output = json!({
            "recipient_public":recipient.public_jwk(),
            "recipient_private":base64url(recipient.private_bytes()),
            "encryption_key_id":recipient.encryption_key_id(),
            "actor_id":actor_id(&public),
            "signing_key":key_id(&public),
            "certificate":cert,
            "issued_at":at,
        });
        std::fs::write(Path::new(&out), serde_json::to_vec(&output).unwrap()).unwrap();
    }
}
