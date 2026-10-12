//! Protected custody of exact package material and its proposed source
//! checkpoint. These bytes are unverified inputs, not a stage or install proof.
//! No method in this module sends HTTP or marks a secure operation accepted.

use crate::secure_state::{SecureStateError, SecureStateStore};
use peerwork_core::crypto::sha256_hex;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"PEERWORK-PENDING-PACKAGE\n1\n";
const FIELDS: usize = 6;
const MAX_PIN_BYTES: usize = 2048;
const MAX_SOURCE_BYTES: usize = 8192;
// Tracked protocolPackageSourceLimits.materialBytes is smaller than 8 MiB.
// The eventual compiler proof applies its exact, narrower semantic bound.
const MAX_MATERIAL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum PendingPackageError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error("pending package material is incomplete or corrupt")]
    Invalid,
    #[error("pending package origin, identity or workspace changed")]
    PinChanged,
    #[error("different package material or source checkpoint is already saved")]
    Conflict,
    #[error("pending package material exceeds local resource bounds")]
    Resource,
}

pub(crate) struct PackagePins<'a> {
    pub origin: &'a str,
    pub workspace: &'a str,
    pub owner_actor: &'a str,
    pub owner_key: &'a str,
}

pub(crate) struct PendingPackageCustody {
    store: SecureStateStore,
    saved: Option<Zeroizing<Vec<u8>>>,
    origin: String,
    workspace: String,
    owner_actor: String,
    owner_key: String,
}

impl PendingPackageCustody {
    pub(crate) fn open(path: &Path, pins: PackagePins<'_>) -> Result<Self, PendingPackageError> {
        if [
            pins.origin,
            pins.workspace,
            pins.owner_actor,
            pins.owner_key,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_PIN_BYTES)
        {
            return Err(PendingPackageError::Invalid);
        }
        let store = SecureStateStore::open(path)?;
        let saved = store.read_exact_secret()?;
        let result = Self {
            store,
            saved,
            origin: pins.origin.to_owned(),
            workspace: pins.workspace.to_owned(),
            owner_actor: pins.owner_actor.to_owned(),
            owner_key: pins.owner_key.to_owned(),
        };
        if let Some(bytes) = result.saved.as_ref() {
            result.check_pins(bytes)?;
        }
        Ok(result)
    }

    /// Saves the exact caller-supplied bytes once. Semantic compilation,
    /// checkpoint authority, signed part packets and POST remain separate.
    pub(crate) fn stage_unverified(
        &mut self,
        source_checkpoint_wire: &[u8],
        material_wire: &[u8],
    ) -> Result<(), PendingPackageError> {
        if source_checkpoint_wire.is_empty()
            || source_checkpoint_wire.len() > MAX_SOURCE_BYTES
            || material_wire.is_empty()
            || material_wire.len() > MAX_MATERIAL_BYTES
        {
            return Err(PendingPackageError::Resource);
        }
        let encoded = encode(
            &self.origin,
            &self.workspace,
            &self.owner_actor,
            &self.owner_key,
            source_checkpoint_wire,
            material_wire,
        )?;
        if let Some(saved) = self.saved.as_ref() {
            if saved.as_slice() != encoded.as_slice() {
                return Err(PendingPackageError::Conflict);
            }
            return Ok(());
        }
        self.store.write_exact(&encoded)?;
        self.saved = Some(encoded);
        Ok(())
    }

    /// The callback receives unverified exact bytes while this protected
    /// handle owns the state lock. It must not interpret them as authority.
    pub(crate) fn with_pending<T>(
        &self,
        consume: impl FnOnce(&[u8], &[u8]) -> T,
    ) -> Result<Option<T>, PendingPackageError> {
        let Some(saved) = self.saved.as_ref() else {
            return Ok(None);
        };
        let fields = self.check_pins(saved)?;
        Ok(Some(consume(fields[4], fields[5])))
    }

    fn check_pins<'a>(&self, bytes: &'a [u8]) -> Result<[&'a [u8]; FIELDS], PendingPackageError> {
        let fields = decode(bytes)?;
        if fields[0] != self.origin.as_bytes()
            || fields[1] != self.workspace.as_bytes()
            || fields[2] != self.owner_actor.as_bytes()
            || fields[3] != self.owner_key.as_bytes()
        {
            return Err(PendingPackageError::PinChanged);
        }
        Ok(fields)
    }
}

fn encode(
    origin: &str,
    workspace: &str,
    owner_actor: &str,
    owner_key: &str,
    source: &[u8],
    material: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PendingPackageError> {
    let fields: [&[u8]; FIELDS] = [
        origin.as_bytes(),
        workspace.as_bytes(),
        owner_actor.as_bytes(),
        owner_key.as_bytes(),
        source,
        material,
    ];
    let size =
        MAGIC.len() + FIELDS * 4 + fields.iter().map(|field| field.len()).sum::<usize>() + 64;
    let mut encoded = Zeroizing::new(Vec::with_capacity(size));
    encoded.extend_from_slice(MAGIC);
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| PendingPackageError::Resource)?;
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    let checksum = sha256_hex(&encoded);
    encoded.extend_from_slice(checksum.as_bytes());
    Ok(encoded)
}

fn decode(bytes: &[u8]) -> Result<[&[u8]; FIELDS], PendingPackageError> {
    if !bytes.starts_with(MAGIC) || bytes.len() < MAGIC.len() + FIELDS * 4 + 64 {
        return Err(PendingPackageError::Invalid);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 64);
    if sha256_hex(payload).as_bytes() != checksum {
        return Err(PendingPackageError::Invalid);
    }
    let mut offset = MAGIC.len();
    let mut fields = [&[][..]; FIELDS];
    for field in &mut fields {
        let end = offset.checked_add(4).ok_or(PendingPackageError::Invalid)?;
        let len = u32::from_be_bytes(
            payload
                .get(offset..end)
                .ok_or(PendingPackageError::Invalid)?
                .try_into()
                .map_err(|_| PendingPackageError::Invalid)?,
        ) as usize;
        offset = end;
        let end = offset
            .checked_add(len)
            .ok_or(PendingPackageError::Invalid)?;
        *field = payload
            .get(offset..end)
            .ok_or(PendingPackageError::Invalid)?;
        offset = end;
    }
    if offset != payload.len()
        || fields[..4]
            .iter()
            .any(|field| field.is_empty() || field.len() > MAX_PIN_BYTES)
        || fields[4].is_empty()
        || fields[4].len() > MAX_SOURCE_BYTES
        || fields[5].is_empty()
        || fields[5].len() > MAX_MATERIAL_BYTES
    {
        return Err(PendingPackageError::Invalid);
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn pins<'a>(origin: &'a str) -> PackagePins<'a> {
        PackagePins {
            origin,
            workspace: "workspace",
            owner_actor: "actor",
            owner_key: "key",
        }
    }

    #[test]
    fn exact_material_survives_restart_and_rejects_context_or_byte_change() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("package.state");
        let mut pending =
            PendingPackageCustody::open(&path, pins("https://origin.example")).unwrap();
        assert!(pending.with_pending(|_, _| ()).unwrap().is_none());
        pending
            .stage_unverified(b"checkpoint-exact", b"material-exact")
            .unwrap();
        pending
            .stage_unverified(b"checkpoint-exact", b"material-exact")
            .unwrap();
        assert!(matches!(
            pending.stage_unverified(b"checkpoint-exact", b"other"),
            Err(PendingPackageError::Conflict)
        ));
        drop(pending);
        assert!(matches!(
            PendingPackageCustody::open(&path, pins("https://other.example")),
            Err(PendingPackageError::PinChanged)
        ));
        let pending = PendingPackageCustody::open(&path, pins("https://origin.example")).unwrap();
        assert_eq!(
            pending
                .with_pending(|source, material| (source.to_vec(), material.to_vec()))
                .unwrap(),
            Some((b"checkpoint-exact".to_vec(), b"material-exact".to_vec()))
        );
    }

    #[test]
    fn input_bounds_refuse_before_first_write() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("package.state");
        let mut pending =
            PendingPackageCustody::open(&path, pins("https://origin.example")).unwrap();
        assert!(matches!(
            pending.stage_unverified(b"", b"material"),
            Err(PendingPackageError::Resource)
        ));
        assert!(matches!(
            pending.stage_unverified(b"source", b""),
            Err(PendingPackageError::Resource)
        ));
        assert!(pending.with_pending(|_, _| ()).unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn damaged_saved_material_refuses_reopen() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("package.state");
        let mut pending =
            PendingPackageCustody::open(&path, pins("https://origin.example")).unwrap();
        pending
            .stage_unverified(b"checkpoint", b"material")
            .unwrap();
        drop(pending);
        let store = SecureStateStore::open(&path).unwrap();
        let mut exact = store.read_exact_secret().unwrap().unwrap();
        let payload_at = exact.len() - 65;
        exact[payload_at] ^= 1;
        store.write_exact(&exact).unwrap();
        drop(store);
        assert!(matches!(
            PendingPackageCustody::open(&path, pins("https://origin.example")),
            Err(PendingPackageError::Invalid)
        ));
    }
}
