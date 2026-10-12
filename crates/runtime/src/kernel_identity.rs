//! Explicit native signing identity lifecycle. The 32-byte seed is held only
//! in protected local state and runtime memory, never a public DTO or CLI arg.

use crate::secure_state::{SecureStateError, SecureStateStore};
use ed25519_dalek::SigningKey;
use peerwork_core::{
    crypto::{actor_id, base64url, decode_base64url, key_id},
    wire_json::{canonical_wire_json, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_KIND: &str = "peerwork.native-identity.v1";

#[derive(Debug, Error)]
pub enum KernelIdentityError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error("native identity already exists at this path")]
    AlreadyExists,
    #[error("native identity does not exist at this path")]
    NotFound,
    #[error("native identity state is invalid")]
    Invalid,
}

pub struct KernelIdentity {
    signing_key: SigningKey,
    key_id: String,
    actor_id: String,
}

impl KernelIdentity {
    /// Generate a new Ed25519 identity from the OS CSPRNG. This is a local
    /// operation; enrollment with a service remains a separate signed action.
    pub fn create(path: &Path) -> Result<Self, KernelIdentityError> {
        let store = SecureStateStore::open(path)?;
        if store.read_exact()?.is_some() {
            return Err(KernelIdentityError::AlreadyExists);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *seed);
        let encoded = Zeroizing::new(base64url(&*seed));
        let wire = Zeroizing::new(format!(
            "{{\"kind\":\"{IDENTITY_KIND}\",\"seed\":\"{}\"}}",
            encoded.as_str()
        ));
        store.write_exact(wire.as_bytes())?;
        let key = SigningKey::from_bytes(&seed);
        Ok(Self::from_signing_key(key))
    }

    /// Open a previously created native identity. Old TypeScript identity
    /// files and malformed/changed bytes fail closed without rewriting them.
    pub fn open(path: &Path) -> Result<Self, KernelIdentityError> {
        let store = SecureStateStore::open(path)?;
        let wire = Zeroizing::new(store.read_exact()?.ok_or(KernelIdentityError::NotFound)?);
        let parsed =
            parse_wire_json_bounded(&wire, 3, 256).map_err(|_| KernelIdentityError::Invalid)?;
        if parsed.object_len() != Some(2)
            || parsed.get("kind").and_then(WireValue::as_string).as_deref() != Some(IDENTITY_KIND)
        {
            return Err(KernelIdentityError::Invalid);
        }
        let encoded = Zeroizing::new(
            parsed
                .get("seed")
                .and_then(WireValue::as_string)
                .ok_or(KernelIdentityError::Invalid)?,
        );
        let decoded =
            Zeroizing::new(decode_base64url(&encoded).map_err(|_| KernelIdentityError::Invalid)?);
        let seed: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KernelIdentityError::Invalid)?;
        let seed = Zeroizing::new(seed);
        if base64url(&*seed) != encoded.as_str()
            || canonical_wire_json(&wire, peerwork_core::canonical::Path::SecureArtifact)
                .map_err(|_| KernelIdentityError::Invalid)?
                .as_bytes()
                != wire.as_slice()
        {
            return Err(KernelIdentityError::Invalid);
        }
        let key = SigningKey::from_bytes(&seed);
        Ok(Self::from_signing_key(key))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let public = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            key_id: key_id(&public),
            actor_id: actor_id(&public),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn explicit_create_reopen_and_incompatible_refusal() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("identity.state");
        assert!(matches!(
            KernelIdentity::open(&path),
            Err(KernelIdentityError::NotFound)
        ));
        let created = KernelIdentity::create(&path).unwrap();
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(created.key_id().len(), 43);
        assert_eq!(created.actor_id().len(), 43);
        assert!(matches!(
            KernelIdentity::create(&path),
            Err(KernelIdentityError::AlreadyExists)
        ));
        let reopened = KernelIdentity::open(&path).unwrap();
        assert_eq!(reopened.key_id(), created.key_id());
        assert_eq!(reopened.actor_id(), created.actor_id());
        assert_ne!(reopened.key_id(), reopened.actor_id());
        drop(reopened);
        drop(created);
        let store = SecureStateStore::open(&path).unwrap();
        store
            .write_exact(b"{\"kind\":\"peerwork.native-identity.v1\",\"seed\":\"invalid\"}")
            .unwrap();
        drop(store);
        assert!(matches!(
            KernelIdentity::open(&path),
            Err(KernelIdentityError::Invalid)
        ));
        assert!(fs::metadata(path).unwrap().len() > 32);
    }
}
