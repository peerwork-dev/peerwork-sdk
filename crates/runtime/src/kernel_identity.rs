//! Explicit native signing identity lifecycle. The 32-byte seed is held only
//! in protected local state and runtime memory, never a public DTO or CLI arg.

use crate::secure_state::{
    missing_in_private_parent, read_private_file_bounded, read_private_seed_file,
    SecureStateError, SecureStateStore,
};
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
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
    #[error("legacy Ed25519 PKCS#8 PEM identity source is invalid")]
    InvalidPemSource,
}

impl KernelIdentityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "IDENTITY_MISSING",
            _ => "IDENTITY_STATE",
        }
    }

    pub fn actionable_message(&self) -> String {
        match self {
            Self::NotFound => "native identity is missing at this path; if it belongs to a legacy Owner profile, explicitly run identity import-legacy-owner-pem OWNER_CONFIG_JSON_FILE PROTECTED_PEM_FILE to import the already selected PEM into configured state_dir/identity.state. This read does not create identity state".to_owned(),
            _ => self.to_string(),
        }
    }
}

pub struct KernelIdentity {
    signing_key: SigningKey,
    key_id: String,
    actor_id: String,
}

impl KernelIdentity {
    /// Inspect an exportable protected legacy Owner key without creating any
    /// native identity state. Historical attachment uses this before saving
    /// its PREPARED source binding; the source file is never modified.
    pub(crate) fn inspect_pkcs8_pem_file(source_path: &Path) -> Result<Self, KernelIdentityError> {
        let bytes = read_private_file_bounded(source_path, 2048)?;
        Self::inspect_pkcs8_pem_bytes(&bytes)
    }
    /// Revalidate a protected copy of the exact legacy PEM after its original
    /// file is unavailable. The bytes must already have passed a protected
    /// store read and remain private to the migration path.
    pub(crate) fn inspect_pkcs8_pem_bytes(bytes: &[u8]) -> Result<Self, KernelIdentityError> {
        let pem = std::str::from_utf8(&bytes).map_err(|_| KernelIdentityError::InvalidPemSource)?;
        validate_single_private_pem(pem)?;
        let parsed =
            SigningKey::from_pkcs8_pem(pem).map_err(|_| KernelIdentityError::InvalidPemSource)?;
        Ok(Self::from_signing_key(parsed))
    }
    /// Import the exact protected PKCS#8 PEM format written by the legacy
    /// TypeScript agent initializer. Other algorithms, extra PEM objects,
    /// changed bytes, and trailing data fail closed. The source is untouched.
    pub fn import_pkcs8_pem_file(
        path: &Path,
        source_path: &Path,
    ) -> Result<Self, KernelIdentityError> {
        if same_path(path, source_path) {
            return Err(KernelIdentityError::InvalidPemSource);
        }
        let bytes = read_private_file_bounded(source_path, 2048)?;
        Self::import_pkcs8_pem_bytes(path, &bytes)
    }
    /// Import a separately protected, digest-bound legacy PEM copy. This
    /// retains the same strict PEM checks as direct file import and never
    /// changes the signature or creates a fresh Owner key.
    pub(crate) fn import_pkcs8_pem_bytes(
        path: &Path,
        bytes: &[u8],
    ) -> Result<Self, KernelIdentityError> {
        let pem = std::str::from_utf8(&bytes).map_err(|_| KernelIdentityError::InvalidPemSource)?;
        validate_single_private_pem(pem)?;
        let parsed =
            SigningKey::from_pkcs8_pem(pem).map_err(|_| KernelIdentityError::InvalidPemSource)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(parsed.as_bytes());
        let store = SecureStateStore::open(path)?;
        if store.read_exact_secret()?.is_some() {
            return Err(KernelIdentityError::AlreadyExists);
        }
        let encoded = Zeroizing::new(base64url(&*seed));
        let wire = Zeroizing::new(format!(
            "{{\"kind\":\"{IDENTITY_KIND}\",\"seed\":\"{}\"}}",
            encoded.as_str()
        ));
        store.write_exact(wire.as_bytes())?;
        Ok(Self::from_signing_key(parsed))
    }

    /// Import a local raw Ed25519 seed from a protected file. This is an
    /// explicit migration operation: the seed never appears in an argument,
    /// result DTO, or log, and the source file remains the caller's property.
    pub fn import_seed_file(path: &Path, source_path: &Path) -> Result<Self, KernelIdentityError> {
        if same_path(path, source_path) {
            return Err(KernelIdentityError::InvalidSeedSource);
        }
        let seed =
            read_private_seed_file(source_path)?.ok_or(KernelIdentityError::InvalidSeedSource)?;
        let store = SecureStateStore::open(path)?;
        if store.read_exact_secret()?.is_some() {
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
        if store.read_exact_secret()?.is_some() {
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
        // Classify only an absent identity file, or its single absent parent
        // directory, after validating the existing protected ancestor. This
        // avoids creating a SecureStateStore lock file merely to report that
        // the configured native identity has not been imported yet.
        if missing_in_private_parent(path)
            || path.parent().is_some_and(missing_in_private_parent)
        {
            return Err(KernelIdentityError::NotFound);
        }
        let store = SecureStateStore::open(path)?;
        let wire = store
            .read_exact_secret()?
            .ok_or(KernelIdentityError::NotFound)?;
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

fn same_path(path: &Path, source_path: &Path) -> bool {
    path == source_path
        || std::fs::canonicalize(path)
            .ok()
            .zip(std::fs::canonicalize(source_path).ok())
            .is_some_and(|(target, source)| target == source)
}

fn validate_single_private_pem(pem: &str) -> Result<(), KernelIdentityError> {
    let body = pem
        .strip_prefix("-----BEGIN PRIVATE KEY-----\n")
        .and_then(|value| value.strip_suffix("-----END PRIVATE KEY-----\n"))
        .ok_or(KernelIdentityError::InvalidPemSource)?;
    if body.is_empty() || body.len() > 1024 || !body.ends_with('\n') {
        return Err(KernelIdentityError::InvalidPemSource);
    }
    for line in body.trim_end_matches('\n').split('\n') {
        if line.is_empty()
            || line.len() > 64
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(KernelIdentityError::InvalidPemSource);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::protected_test_dir;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn explicit_create_reopen_and_incompatible_refusal() {
        let dir = protected_test_dir();
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
    fn missing_identity_is_classified_without_creating_state_or_lock() {
        let parent = protected_test_dir();
        let direct = parent.path().join("missing.state");
        assert!(matches!(KernelIdentity::open(&direct), Err(KernelIdentityError::NotFound)));
        assert!(!direct.exists());
        assert!(!direct.with_extension("state.lock").exists());

        let missing_leaf = parent.path().join("native-state");
        let configured = missing_leaf.join("identity.state");
        assert!(matches!(KernelIdentity::open(&configured), Err(KernelIdentityError::NotFound)));
        assert!(!missing_leaf.exists());
        assert!(!configured.with_extension("state.lock").exists());

        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let unsafe_parent = parent.path().join("unsafe");
            fs::create_dir(&unsafe_parent).unwrap();
            fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o755)).unwrap();
            let unsafe_identity = unsafe_parent.join("identity.state");
            assert!(matches!(KernelIdentity::open(&unsafe_identity),
                Err(KernelIdentityError::Store(SecureStateError::Protection))));
            assert!(!unsafe_identity.exists());
            assert!(!unsafe_identity.with_extension("state.lock").exists());

            let target = parent.path().join("target");
            fs::create_dir(&target).unwrap();
            let symlink_parent = parent.path().join("linked");
            std::os::unix::fs::symlink(&target, &symlink_parent).unwrap();
            let linked_identity = symlink_parent.join("identity.state");
            assert!(matches!(KernelIdentity::open(&linked_identity),
                Err(KernelIdentityError::Store(SecureStateError::Protection))));
            assert!(!target.join("identity.state").exists());
        }
    }

    #[test]
    fn protected_seed_import_preserves_source_and_refuses_overwrite() {
        let dir = protected_test_dir();
        let source_path = dir.path().join("legacy-seed.bin");
        let target_path = dir.path().join("identity.state");
        let seed = [7u8; 32];
        #[cfg(windows)]
        crate::windows_fs::create_or_check_file(&source_path).unwrap();
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

    #[test]
    fn protected_pkcs8_pem_import_preserves_source_and_refuses_bad_input() {
        let dir = protected_test_dir();
        let source_path = dir.path().join("legacy.pem");
        let target_path = dir.path().join("identity.state");
        let expected = SigningKey::from_bytes(&[9u8; 32]);
        let der = expected.to_pkcs8_der().unwrap();
        let mut base64 = base64url(der.as_bytes())
            .replace('-', "+")
            .replace('_', "/");
        while base64.len() % 4 != 0 {
            base64.push('=');
        }
        let wrapped = base64
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----\n");
        assert!(
            validate_single_private_pem(&pem).is_ok(),
            "PEM envelope rejected"
        );
        assert!(
            SigningKey::from_pkcs8_pem(&pem).is_ok(),
            "maintained PEM parser rejected generated key"
        );
        #[cfg(windows)]
        crate::windows_fs::create_or_check_file(&source_path).unwrap();
        fs::write(&source_path, pem.as_bytes()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
        let original = fs::read(&source_path).unwrap();
        let imported = KernelIdentity::import_pkcs8_pem_file(&target_path, &source_path).unwrap();
        assert_eq!(
            imported.key_id(),
            key_id(&expected.verifying_key().to_bytes())
        );
        assert_eq!(
            KernelIdentity::open(&target_path).unwrap().key_id(),
            imported.key_id()
        );
        assert_eq!(fs::read(&source_path).unwrap(), original);
        assert!(matches!(
            KernelIdentity::import_pkcs8_pem_file(&target_path, &source_path),
            Err(KernelIdentityError::AlreadyExists)
        ));

        let bad_path = dir.path().join("bad.pem");
        #[cfg(windows)]
        crate::windows_fs::create_or_check_file(&bad_path).unwrap();
        for bad in [
            original[..original.len() - 1].to_vec(),
            [original.as_slice(), original.as_slice()].concat(),
            b"-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----\n".to_vec(),
        ] {
            fs::write(&bad_path, bad).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&bad_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                KernelIdentity::import_pkcs8_pem_file(&dir.path().join("unused.state"), &bad_path),
                Err(KernelIdentityError::InvalidPemSource)
            ));
        }
        #[cfg(unix)]
        {
            let linked = dir.path().join("linked.pem");
            fs::hard_link(&source_path, &linked).unwrap();
            assert!(KernelIdentity::import_pkcs8_pem_file(
                &dir.path().join("unused.state"),
                &linked
            )
            .is_err());
            fs::remove_file(linked).unwrap();
            let symlink = dir.path().join("symlink.pem");
            std::os::unix::fs::symlink(&source_path, &symlink).unwrap();
            assert!(KernelIdentity::import_pkcs8_pem_file(
                &dir.path().join("unused.state"),
                &symlink
            )
            .is_err());
            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(KernelIdentity::import_pkcs8_pem_file(
                &dir.path().join("unused.state"),
                &source_path
            )
            .is_err());
        }
        assert_eq!(fs::read(&target_path).is_ok(), true);
        fs::remove_file(&source_path).unwrap();
        let copied = KernelIdentity::import_pkcs8_pem_bytes(
            &dir.path().join("copied-identity.state"), &original,
        ).unwrap();
        assert_eq!(copied.key_id(), imported.key_id());
        assert_eq!(KernelIdentity::inspect_pkcs8_pem_bytes(&original).unwrap().actor_id(), copied.actor_id());
    }
}
