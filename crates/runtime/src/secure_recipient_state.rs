//! Protected native P-256 recipient identity, bound to the local Ed25519
//! signing actor. A local certificate is not directory or grant authority.

use crate::{
    kernel_identity::KernelIdentity,
    secure_state::{read_private_file_bounded, SecureStateError, SecureStateStore},
};
use peerwork_core::crypto::decode_base64url;
use peerwork_core::secure_recipient::{RecipientCertificate, RecipientError, SecretRecipient};
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"PEERWORK-NATIVE-RECIPIENT\n1\n";
const MAGIC_V2: &[u8] = b"PEERWORK-NATIVE-RECIPIENT\n2\n";
const MAX_CERT: usize = 16_384;
const MAX_HISTORY: usize = 128;

#[derive(Debug, Error)]
pub enum RecipientStateError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error(transparent)]
    Recipient(#[from] RecipientError),
    #[error("recipient identity already exists")]
    AlreadyExists,
    #[error("recipient identity does not exist")]
    NotFound,
    #[error("recipient identity state is invalid")]
    Invalid,
    #[error("recipient identity belongs to another signing actor")]
    IdentityChanged,
}

pub(crate) struct RecipientState {
    store: SecureStateStore,
    recipient: SecretRecipient,
    certificate: RecipientCertificate,
    history: Vec<(RecipientCertificate, SecretRecipient)>,
}

impl RecipientState {
    /// Import a fresh, separately protected tracked TS recipient state. Only
    /// an unjoined identity can cross this boundary; existing workspace or
    /// pending state must be migrated by the full journal/state workflow.
    /// The source file is never rewritten or deleted.
    pub(crate) fn import_unjoined_ts_state(
        path: &Path,
        identity: &KernelIdentity,
        source_path: &Path,
    ) -> Result<Self, RecipientStateError> {
        if path == source_path {
            return Err(RecipientStateError::Invalid);
        }
        let mut raw = read_private_file_bounded(source_path, 2 * 1024 * 1024)?;
        let parsed = serde_json::from_slice::<serde_json::Value>(&raw);
        raw.zeroize();
        let mut source = parsed.map_err(|_| RecipientStateError::Invalid)?;
        let encoded = source
            .get("encryption_private_key")
            .and_then(serde_json::Value::as_str)
            .ok_or(RecipientStateError::Invalid)?;
        let decoded = decode_base64url(encoded);
        if let Some(serde_json::Value::String(secret)) = source.get_mut("encryption_private_key") {
            secret.zeroize();
        }
        let decoded = Zeroizing::new(decoded.map_err(|_| RecipientStateError::Invalid)?);
        if decoded.len() != 32
            || source.get("v").and_then(serde_json::Value::as_u64) != Some(1)
            || source.get("actor_id").and_then(serde_json::Value::as_str)
                != Some(identity.actor_id())
            || source
                .get("workspaces")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|rows| !rows.is_empty())
            || source
                .get("pending")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|rows| !rows.is_empty())
        {
            return Err(RecipientStateError::Invalid);
        }
        let certificate: RecipientCertificate = serde_json::from_value(
            source
                .get("certificate")
                .cloned()
                .ok_or(RecipientStateError::Invalid)?,
        )
        .map_err(|_| RecipientStateError::Invalid)?;
        let mut private = Zeroizing::new([0u8; 32]);
        private.copy_from_slice(&decoded);
        let recipient = SecretRecipient::from_private(private)?;
        let at = certificate.payload["issued_at"]
            .as_u64()
            .ok_or(RecipientStateError::Invalid)?;
        recipient.verify_local_certificate(
            &certificate,
            identity.actor_id(),
            identity.key_id(),
            at,
        )?;
        let store = SecureStateStore::open(path)?;
        if store.read_exact_secret()?.is_some() {
            return Err(RecipientStateError::AlreadyExists);
        }
        let bytes = encode(identity, &recipient, &certificate)?;
        store.write_exact(&bytes)?;
        Ok(Self {
            store,
            recipient,
            certificate,
            history: Vec::new(),
        })
    }
    /// Offline create; preserves an existing target and never publishes the
    /// self-certificate. Caller owns the signing identity's protected path.
    pub(crate) fn create(
        path: &Path,
        identity: &KernelIdentity,
        issued_at: u64,
    ) -> Result<Self, RecipientStateError> {
        let store = SecureStateStore::open(path)?;
        if store.read_exact_secret()?.is_some() {
            return Err(RecipientStateError::AlreadyExists);
        }
        let recipient = SecretRecipient::generate()?;
        let certificate = recipient.certify(identity.signing_key(), issued_at)?;
        let bytes = encode(identity, &recipient, &certificate)?;
        store.write_exact(&bytes)?;
        Ok(Self {
            store,
            recipient,
            certificate,
            history: Vec::new(),
        })
    }

    /// Reopen validates local signer/recipient continuity and the exact
    /// self-certificate signature. Expiry is assessed by later use rather than
    /// discarding historical decryption material on an old certificate.
    pub(crate) fn open(
        path: &Path,
        identity: &KernelIdentity,
    ) -> Result<Self, RecipientStateError> {
        let store = SecureStateStore::open(path)?;
        let bytes = store
            .read_exact_secret()?
            .ok_or(RecipientStateError::NotFound)?;
        let (recipient, certificate, history) = decode(&bytes, identity)?;
        Ok(Self {
            store,
            recipient,
            certificate,
            history,
        })
    }

    pub(crate) fn recipient(&self) -> &SecretRecipient {
        &self.recipient
    }
    pub(crate) fn certificate(&self) -> &RecipientCertificate {
        &self.certificate
    }

    pub(crate) fn recipient_for_certificate(
        &self,
        certificate: &RecipientCertificate,
    ) -> Result<&SecretRecipient, RecipientStateError> {
        let requested = certificate_hash(certificate)?;
        if requested == certificate_hash(&self.certificate)? {
            return Ok(&self.recipient);
        }
        self.history
            .iter()
            .find_map(|(saved, recipient)| {
                (certificate_hash(saved).ok().as_deref() == Some(requested.as_str()))
                    .then_some(recipient)
            })
            .ok_or(RecipientStateError::NotFound)
    }

    /// Switch only after the new signed directory entry is verified through
    /// its protected chain. Old key/certificate pairs remain available for
    /// grants and invitations signed before rotation.
    pub(crate) fn promote_published(
        &mut self,
        identity: &KernelIdentity,
        expected_previous_hash: &str,
        next: SecretRecipient,
        certificate: RecipientCertificate,
        at: u64,
    ) -> Result<(), RecipientStateError> {
        if certificate_hash(&self.certificate)? != expected_previous_hash
            || self.history.len() >= MAX_HISTORY
        {
            return Err(RecipientStateError::Invalid);
        }
        next.verify_local_certificate(&certificate, identity.actor_id(), identity.key_id(), at)?;
        let mut entries = Vec::with_capacity(self.history.len() + 2);
        entries.push((&certificate, &next));
        entries.push((&self.certificate, &self.recipient));
        entries.extend(
            self.history
                .iter()
                .map(|(certificate, recipient)| (certificate, recipient)),
        );
        let bytes = encode_v2(identity, &entries)?;
        self.store.write_exact(&bytes)?;
        self.history.insert(
            0,
            (
                std::mem::replace(&mut self.certificate, certificate),
                std::mem::replace(&mut self.recipient, next),
            ),
        );
        Ok(())
    }
}

fn certificate_hash(certificate: &RecipientCertificate) -> Result<String, RecipientStateError> {
    let value = serde_json::to_value(certificate).map_err(|_| RecipientStateError::Invalid)?;
    let canonical =
        peerwork_core::canonical::canonical(&value, peerwork_core::canonical::Path::SecureArtifact)
            .map_err(|_| RecipientStateError::Invalid)?;
    Ok(peerwork_core::crypto::sha256_hex(canonical.as_bytes()))
}

fn encode(
    identity: &KernelIdentity,
    recipient: &SecretRecipient,
    certificate: &RecipientCertificate,
) -> Result<Zeroizing<Vec<u8>>, RecipientStateError> {
    let cert = serde_json::to_vec(certificate).map_err(|_| RecipientStateError::Invalid)?;
    if cert.is_empty() || cert.len() > MAX_CERT {
        return Err(RecipientStateError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        MAGIC.len() + 43 + 43 + 32 + 4 + cert.len(),
    ));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(identity.actor_id().as_bytes());
    bytes.extend_from_slice(identity.key_id().as_bytes());
    bytes.extend_from_slice(recipient.private_bytes());
    bytes.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&cert);
    Ok(bytes)
}

fn encode_v2(
    identity: &KernelIdentity,
    entries: &[(&RecipientCertificate, &SecretRecipient)],
) -> Result<Zeroizing<Vec<u8>>, RecipientStateError> {
    if entries.is_empty() || entries.len() > MAX_HISTORY + 1 {
        return Err(RecipientStateError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        MAGIC_V2.len() + 88 + entries.len() * 800,
    ));
    bytes.extend_from_slice(MAGIC_V2);
    bytes.extend_from_slice(identity.actor_id().as_bytes());
    bytes.extend_from_slice(identity.key_id().as_bytes());
    bytes.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    let mut seen = std::collections::HashSet::new();
    for (certificate, recipient) in entries {
        if !seen.insert(certificate_hash(certificate)?) {
            return Err(RecipientStateError::Invalid);
        }
        let cert = serde_json::to_vec(certificate).map_err(|_| RecipientStateError::Invalid)?;
        if cert.is_empty() || cert.len() > MAX_CERT {
            return Err(RecipientStateError::Invalid);
        }
        bytes.extend_from_slice(recipient.private_bytes());
        bytes.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&cert);
    }
    Ok(bytes)
}

fn decode(
    bytes: &[u8],
    identity: &KernelIdentity,
) -> Result<
    (
        SecretRecipient,
        RecipientCertificate,
        Vec<(RecipientCertificate, SecretRecipient)>,
    ),
    RecipientStateError,
> {
    let (bytes, count, offset) = if let Some(rest) = bytes.strip_prefix(MAGIC) {
        (rest, 1usize, 86usize)
    } else if let Some(rest) = bytes.strip_prefix(MAGIC_V2) {
        if rest.len() < 88 {
            return Err(RecipientStateError::Invalid);
        }
        let count = u16::from_be_bytes([rest[86], rest[87]]) as usize;
        if count == 0 || count > MAX_HISTORY + 1 {
            return Err(RecipientStateError::Invalid);
        }
        (rest, count, 88usize)
    } else {
        return Err(RecipientStateError::Invalid);
    };
    decode_entries(bytes, identity, count, offset)
}

fn decode_entries(
    bytes: &[u8],
    identity: &KernelIdentity,
    count: usize,
    offset: usize,
) -> Result<
    (
        SecretRecipient,
        RecipientCertificate,
        Vec<(RecipientCertificate, SecretRecipient)>,
    ),
    RecipientStateError,
> {
    if bytes.len() < offset + count * (32 + 4 + 1) {
        return Err(RecipientStateError::Invalid);
    }
    if &bytes[..43] != identity.actor_id().as_bytes()
        || &bytes[43..86] != identity.key_id().as_bytes()
    {
        return Err(RecipientStateError::IdentityChanged);
    }
    let mut cursor = offset;
    let mut entries = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..count {
        let end = cursor.checked_add(36).ok_or(RecipientStateError::Invalid)?;
        if end > bytes.len() {
            return Err(RecipientStateError::Invalid);
        }
        let mut private = Zeroizing::new([0u8; 32]);
        private.copy_from_slice(&bytes[cursor..cursor + 32]);
        let cert_len = u32::from_be_bytes(
            bytes[cursor + 32..end]
                .try_into()
                .map_err(|_| RecipientStateError::Invalid)?,
        ) as usize;
        if cert_len == 0
            || cert_len > MAX_CERT
            || end
                .checked_add(cert_len)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(RecipientStateError::Invalid);
        }
        let certificate: RecipientCertificate = serde_json::from_slice(&bytes[end..end + cert_len])
            .map_err(|_| RecipientStateError::Invalid)?;
        let recipient = SecretRecipient::from_private(private)?;
        let at = certificate.payload["issued_at"]
            .as_u64()
            .ok_or(RecipientStateError::Invalid)?;
        recipient.verify_local_certificate(
            &certificate,
            identity.actor_id(),
            identity.key_id(),
            at,
        )?;
        if !seen.insert(certificate_hash(&certificate)?) {
            return Err(RecipientStateError::Invalid);
        }
        entries.push((certificate, recipient));
        cursor = end + cert_len;
    }
    if cursor != bytes.len() {
        return Err(RecipientStateError::Invalid);
    }
    let (certificate, recipient) = entries.remove(0);
    Ok((recipient, certificate, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::protected_test_dir;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn published_rotation_preserves_exact_historical_recipient() {
        let dir = protected_test_dir();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let path = dir.path().join("recipient.state");
        let at = 1_700_000_000_000;
        let mut state = RecipientState::create(&path, &identity, at).unwrap();
        let prior = state.certificate().clone();
        let prior_hash = certificate_hash(&prior).unwrap();
        let prior_public = state.recipient().public_jwk().x.clone();
        let next = SecretRecipient::generate().unwrap();
        let next_cert = next.certify(identity.signing_key(), at + 1000).unwrap();
        assert!(state
            .promote_published(
                &identity,
                &"0".repeat(64),
                SecretRecipient::generate().unwrap(),
                next_cert.clone(),
                at + 1000
            )
            .is_err());
        state
            .promote_published(&identity, &prior_hash, next, next_cert.clone(), at + 1000)
            .unwrap();
        assert_ne!(state.recipient().public_jwk().x, prior_public);
        assert_eq!(
            state
                .recipient_for_certificate(&prior)
                .unwrap()
                .public_jwk()
                .x,
            prior_public
        );
        drop(state);
        let reopened = RecipientState::open(&path, &identity).unwrap();
        assert_eq!(reopened.certificate().signature, next_cert.signature);
        assert_eq!(
            reopened
                .recipient_for_certificate(&prior)
                .unwrap()
                .public_jwk()
                .x,
            prior_public
        );
        assert_eq!(
            reopened
                .recipient_for_certificate(&next_cert)
                .unwrap()
                .public_jwk()
                .x,
            reopened.recipient().public_jwk().x
        );
    }

    #[test]
    fn recipient_create_reopen_and_signer_continuity() {
        let dir = protected_test_dir();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let path = dir.path().join("recipient.state");
        assert!(matches!(
            RecipientState::open(&path, &identity),
            Err(RecipientStateError::NotFound)
        ));
        let created = RecipientState::create(&path, &identity, 1_700_000_000_000).unwrap();
        assert!(matches!(
            RecipientState::open(&path, &identity),
            Err(RecipientStateError::Store(SecureStateError::Busy))
        ));
        let public = created.recipient().public_jwk().x.clone();
        drop(created);
        assert!(matches!(
            RecipientState::create(&path, &identity, 1_700_000_000_001),
            Err(RecipientStateError::AlreadyExists)
        ));
        let reopened = RecipientState::open(&path, &identity).unwrap();
        assert_eq!(reopened.recipient().public_jwk().x, public);
        assert_eq!(
            reopened.certificate().payload["actor_id"],
            identity.actor_id()
        );
        drop(reopened);
        let other = KernelIdentity::create(&dir.path().join("other-identity.state")).unwrap();
        assert!(matches!(
            RecipientState::open(&path, &other),
            Err(RecipientStateError::IdentityChanged)
        ));
    }
}
