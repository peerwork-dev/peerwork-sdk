//! Explicit native signing identity lifecycle. The 32-byte seed is held only
//! in protected local state and runtime memory, never a public DTO or CLI arg.

use crate::secure_state::{read_private_seed_file, SecureStateError, SecureStateStore};
use ed25519_dalek::SigningKey;
use peerwork_core::crypto::{actor_id, base64url, decode_base64url, key_id};
use rand_core::{OsRng, RngCore};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_KIND: &str = "peerwork.native-identity.v1";
const IDENTITY_PREFIX: &[u8] = b"{\"kind\":\"peerwork.native-identity.v1\",\"seed\":\"";
const IDENTITY_SUFFIX: &[u8] = b"\"}";

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
    #[error("OS random source failed")]
    Entropy,
    #[error("identity seed source must contain exactly 32 protected bytes")]
    InvalidSeedSource,
}

pub struct KernelIdentity {
    signing_key: SigningKey,
    key_id: String,
    actor_id: String,
}

impl KernelIdentity {
    /// Import a local raw Ed25519 seed from a protected file. This is an
    /// explicit migration operation: the seed never appears in an argument,
    /// result DTO, or log, and the source file remains the caller's property.
    pub fn import_seed_file(path: &Path, source_path: &Path) -> Result<Self, KernelIdentityError> {
        if path == source_path
            || std::fs::canonicalize(path)
                .ok()
                .zip(std::fs::canonicalize(source_path).ok())
                .is_some_and(|(target, source)| target == source)
        {
            return Err(KernelIdentityError::InvalidSeedSource);
        }
        let seed =
            read_private_seed_file(source_path)?.ok_or(KernelIdentityError::InvalidSeedSource)?;
        let store = SecureStateStore::open(path)?;
        if store.read_exact()?.is_some() {
            return Err(KernelIdentityError::AlreadyExists);
        }
        let encoded = Zeroizing::new(base64url(&*seed));
        let wire = Zeroizing::new(format!(
            "{{\"kind\":\"{IDENTITY_KIND}\",\"seed\":\"{}\"}}",
            encoded.as_str()
        ));
        store.write_exact(wire.as_bytes())?;
        Ok(Self::from_signing_key(SigningKey::from_bytes(&seed)))
    }

    /// Generate a new Ed25519 identity from the OS CSPRNG. This is a local
    /// operation; enrollment with a service remains a separate signed action.
    pub fn create(path: &Path) -> Result<Self, KernelIdentityError> {
        let store = SecureStateStore::open(path)?;
        if store.read_exact()?.is_some() {
            return Err(KernelIdentityError::AlreadyExists);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut *seed)
            .map_err(|_| KernelIdentityError::Entropy)?;
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
        let encoded_bytes = wire
            .strip_prefix(IDENTITY_PREFIX)
            .and_then(|value| value.strip_suffix(IDENTITY_SUFFIX))
            .filter(|value| value.len() == 43)
            .ok_or(KernelIdentityError::Invalid)?;
        let encoded =
            std::str::from_utf8(encoded_bytes).map_err(|_| KernelIdentityError::Invalid)?;
        let decoded =
            Zeroizing::new(decode_base64url(encoded).map_err(|_| KernelIdentityError::Invalid)?);
        if decoded.len() != 32 {
            return Err(KernelIdentityError::Invalid);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&decoded);
        let reencoded = Zeroizing::new(base64url(&*seed));
        if reencoded.as_str() != encoded {
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

    #[test]
    fn protected_seed_import_preserves_source_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source_path = dir.path().join("legacy-seed.bin");
        let target_path = dir.path().join("identity.state");
        let seed = [7u8; 32];
        fs::write(&source_path, seed).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
        let imported = KernelIdentity::import_seed_file(&target_path, &source_path).unwrap();
        let expected = KernelIdentity::from_signing_key(SigningKey::from_bytes(&seed));
        assert_eq!(imported.key_id(), expected.key_id());
        assert_eq!(imported.actor_id(), expected.actor_id());
        assert_eq!(
            KernelIdentity::open(&target_path).unwrap().key_id(),
            imported.key_id()
        );
        assert_eq!(fs::read(&source_path).unwrap(), seed);
        assert!(matches!(
            KernelIdentity::import_seed_file(&target_path, &source_path),
            Err(KernelIdentityError::AlreadyExists)
        ));
        assert!(matches!(
            KernelIdentity::import_seed_file(&source_path, &source_path),
            Err(KernelIdentityError::InvalidSeedSource)
        ));
    }
}
