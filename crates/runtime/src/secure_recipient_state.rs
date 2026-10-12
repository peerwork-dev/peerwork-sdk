//! Protected native P-256 recipient identity, bound to the local Ed25519
//! signing actor. A local certificate is not directory or grant authority.

use crate::{
    kernel_identity::KernelIdentity,
    secure_state::{SecureStateError, SecureStateStore},
};
use peerwork_core::secure_recipient::{RecipientCertificate, RecipientError, SecretRecipient};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"PEERWORK-NATIVE-RECIPIENT\n1\n";
const MAX_CERT: usize = 16_384;

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
    recipient: SecretRecipient,
    certificate: RecipientCertificate,
}

impl RecipientState {
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
            recipient,
            certificate,
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
        decode(&bytes, identity)
    }

    pub(crate) fn recipient(&self) -> &SecretRecipient {
        &self.recipient
    }
    pub(crate) fn certificate(&self) -> &RecipientCertificate {
        &self.certificate
    }
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

fn decode(bytes: &[u8], identity: &KernelIdentity) -> Result<RecipientState, RecipientStateError> {
    if !bytes.starts_with(MAGIC) || bytes.len() < MAGIC.len() + 43 + 43 + 32 + 4 {
        return Err(RecipientStateError::Invalid);
    }
    let bytes = &bytes[MAGIC.len()..];
    if &bytes[..43] != identity.actor_id().as_bytes()
        || &bytes[43..86] != identity.key_id().as_bytes()
    {
        return Err(RecipientStateError::IdentityChanged);
    }
    let mut private = Zeroizing::new([0u8; 32]);
    private.copy_from_slice(&bytes[86..118]);
    let cert_len = u32::from_be_bytes(bytes[118..122].try_into().unwrap()) as usize;
    if cert_len == 0 || cert_len > MAX_CERT || bytes.len() != 122 + cert_len {
        return Err(RecipientStateError::Invalid);
    }
    let recipient = SecretRecipient::from_private(private)?;
    let certificate: RecipientCertificate =
        serde_json::from_slice(&bytes[122..]).map_err(|_| RecipientStateError::Invalid)?;
    let at = certificate.payload["issued_at"]
        .as_u64()
        .ok_or(RecipientStateError::Invalid)?;
    recipient.verify_local_certificate(&certificate, identity.actor_id(), identity.key_id(), at)?;
    Ok(RecipientState {
        recipient,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn recipient_create_reopen_and_signer_continuity() {
        let dir = tempfile::tempdir().unwrap();
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
            RecipientState::create(&path, &identity, 1_700_000_000_001),
            Err(RecipientStateError::AlreadyExists)
        ));
        let public = created.recipient().public_jwk().x.clone();
        drop(created);
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
