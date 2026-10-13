//! Protected per-workspace epoch-key lifecycle. Key creation and rotation are
//! local pending state only; no pending key becomes active without a future
//! complete signed journal/policy or key-grant proof.

use crate::secure_grant_pending::GrantActivationProof;
use crate::secure_state::{SecureStateError, SecureStateStore};
use crate::secure_verified_read::TransportReplayedJournal;
use peerwork_core::crypto::decode_base64url;
use peerwork_core::prepared_secure_bootstrap::VerifiedPreparedBootstrap;
use peerwork_core::replayed_secure_journal::StructureStatus;
use peerwork_core::secure_keyring::{KeyringError, SecretKeyring};
use reqwest::Url;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"PEERWORK-SECURE-KEYRING\n1\n";
const MAX_WIRE: usize = 300_000;

#[derive(Debug, Error)]
pub enum SecureLifecycleError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error("secure lifecycle context or state is invalid")]
    Invalid,
    #[error("secure lifecycle identity, origin or owner pin changed")]
    PinChanged,
    #[error("a different pending keyring transition already exists")]
    PendingConflict,
    #[error("complete signed owner bootstrap does not bind the staged epoch key")]
    BootstrapProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringStatus {
    pub workspace_id: String,
    pub active_epochs: Vec<u64>,
    pub pending_epochs: Vec<u64>,
}

/// One protected file per workspace. Origin/actor/workspace/trusted owner are
/// immutable. This is local key custody, not a policy or grant verifier.
pub struct SecureLifecycle {
    store: SecureStateStore,
    origin: String,
    actor_id: String,
    workspace_id: String,
    owner_actor_id: String,
    owner_key_id: String,
    active: Option<SecretKeyring>,
    pending: Option<SecretKeyring>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayKeyringState {
    Active,
    Pending,
}

pub(crate) struct ReplayKeyringCandidate<'a> {
    pub ring: &'a SecretKeyring,
    pub state: ReplayKeyringState,
}

impl SecureLifecycle {
    pub fn open(
        path: &Path,
        origin: &str,
        actor_id: &str,
        workspace_id: &str,
        owner_actor_id: &str,
        owner_key_id: &str,
    ) -> Result<Self, SecureLifecycleError> {
        if !valid_origin(origin)
            || ![actor_id, workspace_id, owner_actor_id, owner_key_id]
                .iter()
                .all(|value| valid_token(value))
        {
            return Err(SecureLifecycleError::Invalid);
        }
        let store = SecureStateStore::open(path)?;
        let mut state = Self {
            store,
            origin: origin.to_owned(),
            actor_id: actor_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            owner_actor_id: owner_actor_id.to_owned(),
            owner_key_id: owner_key_id.to_owned(),
            active: None,
            pending: None,
        };
        if let Some(bytes) = state.store.read_exact_secret()? {
            state.decode(&bytes)?;
        } else {
            // PUBLIC reads may have no local epoch key. Persist the explicit
            // trust-on-first-open origin/owner pins before accepting a read,
            // so a later caller cannot silently repin an empty lifecycle.
            state.save_with(None, None)?;
        }
        Ok(state)
    }

    pub fn status(&self) -> KeyringStatus {
        KeyringStatus {
            workspace_id: self.workspace_id.clone(),
            active_epochs: self
                .active
                .as_ref()
                .map(|ring| ring.epochs().collect())
                .unwrap_or_default(),
            pending_epochs: self
                .pending
                .as_ref()
                .map(|ring| ring.epochs().collect())
                .unwrap_or_default(),
        }
    }

    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }

    pub(crate) fn actor_id(&self) -> &str {
        &self.actor_id
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub(crate) fn owner_key_id(&self) -> &str {
        &self.owner_key_id
    }

    pub(crate) fn owner_actor_id(&self) -> &str {
        &self.owner_actor_id
    }

    /// A staged genesis key may author only the first BOOTSTRAP request. It
    /// remains pending until complete signed replay proves activation.
    pub(crate) fn pending_bootstrap_key(&self) -> Option<&[u8; 32]> {
        if self.active.is_some() || self.pending.as_ref()?.epochs().collect::<Vec<_>>() != [1] {
            return None;
        }
        self.pending.as_ref()?.key_at(1)
    }

    /// Only an authenticated active ring may author a new PRIVATE commit.
    /// Pending keys are reserved for a future signed transition proof.
    pub(crate) fn active_key(&self, epoch: u64) -> Option<&[u8; 32]> {
        self.active.as_ref()?.key_at(epoch)
    }

    /// Full active owner ring for an authenticated PRIVATE delivery. A staged
    /// epoch must not be sent to a recipient before its signed transition.
    pub(crate) fn active_keyring_without_pending(&self) -> Option<&SecretKeyring> {
        if self.pending.is_some() {
            return None;
        }
        self.active.as_ref()
    }

    /// The pending ring may decrypt a candidate journal during verification,
    /// but its presence does not authorize key promotion, reads, or actions.
    /// A staged rotation contains the active prefix and its pending epoch.
    pub(crate) fn replay_keyring_candidate(&self) -> Option<ReplayKeyringCandidate<'_>> {
        if let Some(ring) = self.pending.as_ref() {
            return Some(ReplayKeyringCandidate {
                ring,
                state: ReplayKeyringState::Pending,
            });
        }
        self.active.as_ref().map(|ring| ReplayKeyringCandidate {
            ring,
            state: ReplayKeyringState::Active,
        })
    }

    /// A new Owner has no external key grant. Its staged epoch-one key can
    /// become active only after configured-origin complete replay decrypts
    /// the signed BOOTSTRAP and proves the exact saved commit at sequence one.
    /// This is separate from recipient grant activation and is idempotent
    /// after a crash between key promotion and result persistence.
    pub(crate) fn activate_verified_owner_bootstrap(
        &mut self,
        prepared: &VerifiedPreparedBootstrap,
        source: &TransportReplayedJournal,
    ) -> Result<KeyringStatus, SecureLifecycleError> {
        if prepared.visibility() != "PRIVATE"
            || prepared.workspace_id() != self.workspace_id
            || source.origin() != self.origin
            || source.source_actor_id() != self.actor_id
            || source.source_key_id() != self.owner_key_id
            || self.actor_id != self.owner_actor_id
            || source.replay().workspace_id() != self.workspace_id
            || source.replay().owner_actor_id() != self.owner_actor_id
            || source.replay().owner_signing_key() != self.owner_key_id
            || source.replay().structure_status() == StructureStatus::Seeding
            || !source.replay().contains_checkpoint(
                1,
                Some(prepared.commit_digest()),
                prepared.policy_hash(),
            )
            || source
                .signed_policy_by_hash(prepared.policy_hash())
                .is_none()
        {
            return Err(SecureLifecycleError::BootstrapProof);
        }
        if self.active.is_some() && self.pending.is_none() {
            if source.keyring_state() != Some(ReplayKeyringState::Active)
                || self.active_key(1).is_none()
            {
                return Err(SecureLifecycleError::BootstrapProof);
            }
            return Ok(self.status());
        }
        if source.keyring_state() != Some(ReplayKeyringState::Pending) || self.active.is_some() {
            return Err(SecureLifecycleError::BootstrapProof);
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(SecureLifecycleError::BootstrapProof)?;
        if !pending.epochs().eq([1]) {
            return Err(SecureLifecycleError::BootstrapProof);
        }
        let active = SecretKeyring::parse_wire(&pending.canonical_wire()?)?;
        self.save_with(Some(&active), None)?;
        self.active = Some(active);
        self.pending = None;
        Ok(self.status())
    }

    /// Stage a protected legacy Owner ring for provisional full replay. The
    /// caller binds a protected source snapshot first; neither this method nor
    /// the pending ring authorizes an action, grant, or read.
    pub(crate) fn stage_historical_owner_ring(
        &mut self,
        imported: &SecretKeyring,
    ) -> Result<KeyringStatus, SecureLifecycleError> {
        if self.actor_id != self.owner_actor_id
            || imported.workspace_id() != self.workspace_id
            || imported.epochs().next().is_none()
        {
            return Err(SecureLifecycleError::Invalid);
        }
        let wire = imported.canonical_wire()?;
        if let Some(active) = &self.active {
            return if self.pending.is_none()
                && active.canonical_wire()?.as_slice() == wire.as_slice()
            {
                Ok(self.status())
            } else {
                Err(SecureLifecycleError::PendingConflict)
            };
        }
        if let Some(pending) = &self.pending {
            return if pending.canonical_wire()?.as_slice() == wire.as_slice() {
                Ok(self.status())
            } else {
                Err(SecureLifecycleError::PendingConflict)
            };
        }
        let pending = SecretKeyring::parse_wire(&wire)?;
        self.save_with(None, Some(&pending))?;
        self.pending = Some(pending);
        Ok(self.status())
    }

    /// Promote only after the imported Owner ring has decrypted and verified
    /// a complete origin-bound history whose protected source checkpoint is
    /// an ancestor. A crash after promotion is an exact-ring no-op on retry.
    pub(crate) fn activate_verified_historical_owner(
        &mut self,
        imported: &SecretKeyring,
        source: &TransportReplayedJournal,
        old_sequence: u64,
        old_head: Option<&str>,
        old_policy_hash: &str,
    ) -> Result<KeyringStatus, SecureLifecycleError> {
        if source.origin() != self.origin
            || source.source_actor_id() != self.actor_id
            || source.source_key_id() != self.owner_key_id
            || self.actor_id != self.owner_actor_id
            || source.replay().workspace_id() != self.workspace_id
            || source.replay().owner_actor_id() != self.owner_actor_id
            || source.replay().owner_signing_key() != self.owner_key_id
            || source.replay().structure_status() == StructureStatus::Seeding
            || !source
                .replay()
                .contains_checkpoint(old_sequence, old_head, old_policy_hash)
        {
            return Err(SecureLifecycleError::BootstrapProof);
        }
        let wire = imported.canonical_wire()?;
        if let Some(active) = &self.active {
            return if self.pending.is_none()
                && source.keyring_state() == Some(ReplayKeyringState::Active)
                && active.canonical_wire()?.as_slice() == wire.as_slice()
            {
                Ok(self.status())
            } else {
                Err(SecureLifecycleError::BootstrapProof)
            };
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(SecureLifecycleError::BootstrapProof)?;
        if source.keyring_state() != Some(ReplayKeyringState::Pending)
            || pending.canonical_wire()?.as_slice() != wire.as_slice()
        {
            return Err(SecureLifecycleError::BootstrapProof);
        }
        let active = SecretKeyring::parse_wire(&wire)?;
        self.save_with(Some(&active), None)?;
        self.active = Some(active);
        self.pending = None;
        Ok(self.status())
    }

    /// Promote only a signed grant reverified against the exact completed
    /// origin-bound journal replay. A staged local transition, if present,
    /// must contain precisely the same protected key material. A recipient
    /// can also learn a later epoch from a verified direct grant without a
    /// locally staged owner rotation; in that case every previously active
    /// epoch and key must be an exact prefix of the granted history.
    /// Persistence completes before in-memory active state changes.
    pub(crate) fn activate_verified_grant(
        &mut self,
        proof: GrantActivationProof,
    ) -> Result<KeyringStatus, SecureLifecycleError> {
        if proof.origin() != self.origin
            || proof.workspace() != self.workspace_id
            || proof.owner_actor() != self.owner_actor_id
            || proof.owner_key() != self.owner_key_id
            || proof.local_actor() != self.actor_id
            || !(proof.epoch() == 0 && proof.keyring().epochs().next().is_none()
                || proof.keyring().epochs().last() == Some(proof.epoch()))
        {
            return Err(SecureLifecycleError::PinChanged);
        }
        let wire = proof.keyring().canonical_wire()?;
        if let Some(pending) = &self.pending {
            if pending.canonical_wire()?.as_slice() != wire.as_slice() {
                return Err(SecureLifecycleError::PendingConflict);
            }
        } else if let Some(active) = &self.active {
            if active.canonical_wire()?.as_slice() == wire.as_slice() {
                return Ok(self.status());
            }
            if !exact_keyring_extension(active, proof.keyring()) {
                return Err(SecureLifecycleError::PendingConflict);
            }
        }
        let active = SecretKeyring::parse_wire(&wire)?;
        self.save_with(Some(&active), None)?;
        self.active = Some(active);
        self.pending = None;
        Ok(self.status())
    }

    /// Stage a new private epoch key before a signed workspace bootstrap. An
    /// exact repeated stage reuses existing pending bytes, never fresh entropy.
    pub fn stage_initial(&mut self, epoch: u64) -> Result<KeyringStatus, SecureLifecycleError> {
        if self.active.is_some() {
            return Err(SecureLifecycleError::PendingConflict);
        }
        if let Some(pending) = &self.pending {
            return if pending.epochs().eq([epoch]) {
                Ok(self.status())
            } else {
                Err(SecureLifecycleError::PendingConflict)
            };
        }
        let pending = SecretKeyring::new_private(&self.workspace_id, epoch)?;
        self.save_with(self.active.as_ref(), Some(&pending))?;
        self.pending = Some(pending);
        Ok(self.status())
    }

    /// Stage a key rotation from an already verified active history. This
    /// store cannot activate it; a later journal proof must establish that.
    pub fn stage_rotation(&mut self, epoch: u64) -> Result<KeyringStatus, SecureLifecycleError> {
        let active = self.active.as_ref().ok_or(SecureLifecycleError::Invalid)?;
        if let Some(pending) = &self.pending {
            return if pending.epochs().last() == Some(epoch) {
                Ok(self.status())
            } else {
                Err(SecureLifecycleError::PendingConflict)
            };
        }
        let wire = active.canonical_wire()?;
        let mut pending = SecretKeyring::parse_wire(&wire)?;
        pending.rotate(epoch)?;
        self.save_with(Some(active), Some(&pending))?;
        self.pending = Some(pending);
        Ok(self.status())
    }

    fn save_with(
        &self,
        active: Option<&SecretKeyring>,
        pending: Option<&SecretKeyring>,
    ) -> Result<(), SecureLifecycleError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(1024));
        bytes.extend_from_slice(MAGIC);
        for value in [
            self.origin.as_str(),
            self.actor_id.as_str(),
            self.workspace_id.as_str(),
            self.owner_actor_id.as_str(),
            self.owner_key_id.as_str(),
        ] {
            put_public(&mut bytes, value)?;
        }
        put_ring(&mut bytes, active)?;
        put_ring(&mut bytes, pending)?;
        if bytes.len() > MAX_WIRE {
            return Err(SecureLifecycleError::Invalid);
        }
        self.store.write_exact(&bytes)?;
        Ok(())
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<(), SecureLifecycleError> {
        if bytes.len() > MAX_WIRE {
            return Err(SecureLifecycleError::Invalid);
        }
        let mut reader = Reader::new(
            bytes
                .strip_prefix(MAGIC)
                .ok_or(SecureLifecycleError::Invalid)?,
        );
        for expected in [
            self.origin.as_str(),
            self.actor_id.as_str(),
            self.workspace_id.as_str(),
            self.owner_actor_id.as_str(),
            self.owner_key_id.as_str(),
        ] {
            if reader.public()? != expected {
                return Err(SecureLifecycleError::PinChanged);
            }
        }
        let active = reader.ring(&self.workspace_id)?;
        let pending = reader.ring(&self.workspace_id)?;
        if !reader.remaining.is_empty() {
            return Err(SecureLifecycleError::Invalid);
        }
        // A verified PUBLIC grant activates an empty epoch-zero ring. Pending
        // rings and PRIVATE rotations still require actual epoch key material;
        // full signed replay refuses PRIVATE content without its epoch key.
        if pending
            .as_ref()
            .is_some_and(|ring| ring.epochs().next().is_none())
            || (pending.is_some()
                && active
                    .as_ref()
                    .is_some_and(|ring| ring.epochs().next().is_none()))
        {
            return Err(SecureLifecycleError::Invalid);
        }
        if let (Some(active), Some(pending)) = (&active, &pending) {
            let active_epochs: Vec<_> = active.epochs().collect();
            let pending_epochs: Vec<_> = pending.epochs().collect();
            if pending_epochs.len() != active_epochs.len() + 1
                || !pending_epochs.starts_with(&active_epochs)
                || pending_epochs.last() <= active_epochs.last()
                || active_epochs
                    .iter()
                    .any(|epoch| active.key_at(*epoch) != pending.key_at(*epoch))
            {
                return Err(SecureLifecycleError::Invalid);
            }
        }
        self.active = active;
        self.pending = pending;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn confirm_pending_for_test(&mut self) -> Result<(), SecureLifecycleError> {
        let pending = self.pending.as_ref().ok_or(SecureLifecycleError::Invalid)?;
        self.save_with(Some(pending), None)?;
        self.active = self.pending.take();
        Ok(())
    }

    /// Fixture-only grant stand-in. Production import requires signed policy,
    /// grant, recipient, and history proof before an active ring may be saved.
    #[cfg(test)]
    pub(crate) fn import_active_for_test(
        &mut self,
        wire: &[u8],
    ) -> Result<(), SecureLifecycleError> {
        if self.active.is_some() || self.pending.is_some() {
            return Err(SecureLifecycleError::PendingConflict);
        }
        let ring = SecretKeyring::parse_wire(wire)?;
        if ring.workspace_id() != self.workspace_id || ring.epochs().next().is_none() {
            return Err(SecureLifecycleError::Invalid);
        }
        self.save_with(Some(&ring), None)?;
        self.active = Some(ring);
        Ok(())
    }
}

fn exact_keyring_extension(active: &SecretKeyring, granted: &SecretKeyring) -> bool {
    if active.workspace_id() != granted.workspace_id() {
        return false;
    }
    let old_epochs = active.epochs().collect::<Vec<_>>();
    let new_epochs = granted.epochs().collect::<Vec<_>>();
    if old_epochs.is_empty()
        || new_epochs.len() <= old_epochs.len()
        || !new_epochs.windows(2).all(|pair| pair[0] < pair[1])
        || new_epochs[..old_epochs.len()] != old_epochs
    {
        return false;
    }
    old_epochs.iter().all(|epoch| {
        active.key_at(*epoch).is_some() && active.key_at(*epoch) == granted.key_at(*epoch)
    })
}

fn put_public(out: &mut Vec<u8>, value: &str) -> Result<(), SecureLifecycleError> {
    let len: u16 = value
        .len()
        .try_into()
        .map_err(|_| SecureLifecycleError::Invalid)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn put_ring(out: &mut Vec<u8>, value: Option<&SecretKeyring>) -> Result<(), SecureLifecycleError> {
    if let Some(value) = value {
        let wire = value.canonical_wire()?;
        let len: u32 = wire
            .len()
            .try_into()
            .map_err(|_| SecureLifecycleError::Invalid)?;
        out.push(1);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&wire);
    } else {
        out.push(0);
    }
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], SecureLifecycleError> {
        if len > self.remaining.len() {
            return Err(SecureLifecycleError::Invalid);
        }
        let (taken, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(taken)
    }
    fn public(&mut self) -> Result<&'a str, SecureLifecycleError> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        std::str::from_utf8(self.take(len)?).map_err(|_| SecureLifecycleError::Invalid)
    }
    fn ring(&mut self, workspace_id: &str) -> Result<Option<SecretKeyring>, SecureLifecycleError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => {
                let len = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
                if len == 0 || len > MAX_WIRE {
                    return Err(SecureLifecycleError::Invalid);
                }
                let ring = SecretKeyring::parse_wire(self.take(len)?)?;
                if ring.workspace_id() != workspace_id {
                    return Err(SecureLifecycleError::PinChanged);
                }
                Ok(Some(ring))
            }
            _ => Err(SecureLifecycleError::Invalid),
        }
    }
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && decode_base64url(value).is_ok_and(|decoded| decoded.len() == 32)
}
fn valid_origin(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    (url.scheme() == "https" || url.scheme() == "http" && loopback)
        && url.as_str() == value
        && url.path() == "/"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerwork_core::crypto::base64url;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn verified_grant_extension_preserves_every_active_epoch_key() {
        let workspace = base64url(&[7u8; 32]);
        let active = SecretKeyring::new_private(&workspace, 1).unwrap();
        let mut extended = SecretKeyring::parse_wire(&active.canonical_wire().unwrap()).unwrap();
        extended.rotate(3).unwrap();
        assert!(exact_keyring_extension(&active, &extended));

        let missing_old = SecretKeyring::new_private(&workspace, 3).unwrap();
        assert!(!exact_keyring_extension(&active, &missing_old));
        let mut changed_old = SecretKeyring::new_private(&workspace, 1).unwrap();
        changed_old.rotate(3).unwrap();
        assert!(!exact_keyring_extension(&active, &changed_old));
        assert!(!exact_keyring_extension(&active, &active));
    }

    #[test]
    fn empty_lifecycle_persists_first_owner_pin() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.path().join("public.state");
        let actor = base64url(&[1u8; 32]);
        let workspace = base64url(&[2u8; 32]);
        let owner = base64url(&[3u8; 32]);
        let owner_key = base64url(&[4u8; 32]);
        let state = SecureLifecycle::open(
            &file,
            "https://example.invalid/",
            &actor,
            &workspace,
            &owner,
            &owner_key,
        )
        .unwrap();
        assert!(file.exists());
        assert!(state.status().active_epochs.is_empty());
        drop(state);
        let reopened = SecureLifecycle::open(
            &file,
            "https://example.invalid/",
            &actor,
            &workspace,
            &owner,
            &owner_key,
        )
        .unwrap();
        assert!(reopened.status().active_epochs.is_empty());
        drop(reopened);
        assert!(matches!(
            SecureLifecycle::open(
                &file,
                "https://example.invalid/",
                &actor,
                &workspace,
                &base64url(&[5u8; 32]),
                &owner_key,
            ),
            Err(SecureLifecycleError::PinChanged)
        ));
    }

    #[test]
    fn pending_keys_survive_reopen_without_regeneration_or_promotion() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.path().join("keys.state");
        let id = base64url(&[1u8; 32]);
        let workspace = base64url(&[2u8; 32]);
        let owner = base64url(&[3u8; 32]);
        let owner_key = base64url(&[4u8; 32]);
        let open = || {
            SecureLifecycle::open(
                &file,
                "https://example.invalid/",
                &id,
                &workspace,
                &owner,
                &owner_key,
            )
        };
        let mut store = open().unwrap();
        assert!(file.exists(), "empty lifecycle must persist owner pins");
        assert_eq!(store.stage_initial(1).unwrap().pending_epochs, vec![1]);
        let first_bytes = fs::read(&file).unwrap();
        assert_eq!(store.stage_initial(1).unwrap().pending_epochs, vec![1]);
        assert_eq!(fs::read(&file).unwrap(), first_bytes);
        assert!(matches!(
            store.stage_initial(2),
            Err(SecureLifecycleError::PendingConflict)
        ));
        drop(store);
        let mut reopened = open().unwrap();
        assert_eq!(reopened.status().active_epochs, Vec::<u64>::new());
        assert_eq!(reopened.status().pending_epochs, vec![1]);
        assert_eq!(reopened.stage_initial(1).unwrap().pending_epochs, vec![1]);
        assert_eq!(fs::read(&file).unwrap(), first_bytes);
        reopened.confirm_pending_for_test().unwrap();
        assert_eq!(
            reopened.stage_rotation(3).unwrap().pending_epochs,
            vec![1, 3]
        );
        let pending_bytes = fs::read(&file).unwrap();
        assert_eq!(
            reopened.stage_rotation(3).unwrap().pending_epochs,
            vec![1, 3]
        );
        assert_eq!(fs::read(&file).unwrap(), pending_bytes);
        assert!(matches!(
            reopened.stage_rotation(4),
            Err(SecureLifecycleError::PendingConflict)
        ));
        drop(reopened);
        let recovered = open().unwrap();
        assert_eq!(recovered.status().active_epochs, vec![1]);
        assert_eq!(recovered.status().pending_epochs, vec![1, 3]);
        drop(recovered);
        assert!(matches!(
            SecureLifecycle::open(
                &file,
                "https://other.invalid/",
                &id,
                &workspace,
                &owner,
                &owner_key
            ),
            Err(SecureLifecycleError::PinChanged)
        ));
        assert!(matches!(
            SecureLifecycle::open(
                &file,
                "https://example.invalid/",
                &id,
                &workspace,
                &owner,
                &id
            ),
            Err(SecureLifecycleError::PinChanged)
        ));
    }

    #[test]
    fn empty_pending_or_active_history_is_corrupt_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let origin = "https://example.invalid/";
        let actor = base64url(&[1u8; 32]);
        let workspace = base64url(&[2u8; 32]);
        let owner = base64url(&[3u8; 32]);
        let owner_key = base64url(&[4u8; 32]);
        let empty_wire = serde_json::json!({"v":1,"workspace_id":workspace,"keys":[]}).to_string();
        let empty = SecretKeyring::parse_wire(empty_wire.as_bytes()).unwrap();
        let pending = SecretKeyring::new_private(&workspace, 1).unwrap();
        for (name, active_ring, pending_ring) in [
            ("empty-pending", None, Some(&empty)),
            ("empty-active", Some(&empty), Some(&pending)),
        ] {
            let path = dir.path().join(name);
            let store =
                SecureLifecycle::open(&path, origin, &actor, &workspace, &owner, &owner_key)
                    .unwrap();
            store.save_with(active_ring, pending_ring).unwrap();
            drop(store);
            assert!(matches!(
                SecureLifecycle::open(&path, origin, &actor, &workspace, &owner, &owner_key),
                Err(SecureLifecycleError::Invalid)
            ));
        }
    }
}
