//! Fixed logical ownership and versioned, durable maintenance exclusion.
//! This descriptor is not an encryption AAD. Upgrading it must never rekey or
//! rewrite the operation journal, inbox frames or receiver/body keys.
use crate::{
    participant::{ParticipantError, Result},
    secure_state::SecureStateStore,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaintenancePin {
    pub operation_id: String,
    pub selection_digest: String,
    pub expected_revision: u64,
}
impl MaintenancePin {
    fn validate(&self) -> Result<()> {
        if self.operation_id.len() != 43
            || !self
                .operation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !crate::participant_migration::digest(&self.selection_digest)
            || self.expected_revision >= 9_007_199_254_740_991
        {
            return Err(error("OWNER_MAINTENANCE_SELECTION_INVALID"));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    format: String,
    binding: String,
    revision: u64,
    pending: Option<MaintenancePin>,
    completed: Option<MaintenancePin>,
}
fn error(code: &str) -> ParticipantError {
    ParticipantError::local(code, "ENGINE_OWNER")
}
fn read(owner: &SecureStateStore, binding: &[u8]) -> Result<Descriptor> {
    let bytes = owner
        .read_exact()
        .map_err(|_| error("STATE_BINDING_INVALID"))?
        .ok_or_else(|| error("OWNER_NOT_INITIALIZED"))?;
    decode(&bytes, binding)
}
fn decode(bytes: &[u8], binding: &[u8]) -> Result<Descriptor> {
    let binding = std::str::from_utf8(binding).map_err(|_| error("STATE_BINDING_INVALID"))?;
    if bytes == binding.as_bytes() {
        return Ok(Descriptor {
            format: "peerwork.participant-owner.v2".into(),
            binding: binding.into(),
            revision: 0,
            pending: None,
            completed: None,
        });
    }
    let value: serde_json::Value = peerwork_core::strict_json::parse_strict_json(&bytes)
        .map_err(|_| error("STATE_BINDING_INVALID"))?;
    if value.as_object().is_none_or(|o| o.len() != 5) {
        return Err(error("STATE_BINDING_MISMATCH"));
    }
    let saved: Descriptor =
        serde_json::from_value(value).map_err(|_| error("STATE_BINDING_MISMATCH"))?;
    if saved.format != "peerwork.participant-owner.v2" || saved.binding != binding {
        return Err(error("STATE_BINDING_MISMATCH"));
    }
    for pin in [&saved.pending, &saved.completed].into_iter().flatten() {
        pin.validate()?;
    }
    if saved.pending.is_some() && saved.pending == saved.completed {
        return Err(error("STATE_BINDING_INVALID"));
    }
    if saved.revision > 9_007_199_254_740_991
        || match (&saved.pending, &saved.completed) {
            (Some(current), old) => {
                current.expected_revision + 1 != saved.revision
                    || match old {
                        Some(old) => old.expected_revision + 1 != current.expected_revision,
                        None => current.expected_revision != 0,
                    }
            }
            (None, Some(old)) => old.expected_revision + 1 != saved.revision,
            (None, None) => saved.revision != 0,
        }
    {
        return Err(error("STATE_BINDING_INVALID"));
    }
    Ok(saved)
}
/// Observation only: a completed job retry must not acquire a running engine
/// or overwrite subsequent work. A partial/concurrent descriptor fails closed.
pub(crate) fn completed_snapshot(
    path: &std::path::Path,
    binding: &[u8],
    pin: &MaintenancePin,
) -> Result<bool> {
    pin.validate()?;
    let bytes =
        SecureStateStore::read_snapshot(path, 16384).map_err(|_| error("STATE_BINDING_INVALID"))?;
    let state = decode(&bytes, binding)?;
    Ok(state.pending.is_none() && state.completed.as_ref() == Some(pin))
}
fn write(owner: &SecureStateStore, state: &Descriptor) -> Result<()> {
    owner
        .write_exact(&serde_json::to_vec(state).map_err(|_| error("STATE_BINDING_FAILED"))?)
        .map_err(|_| error("STATE_BINDING_FAILED"))
}
fn pending(pin: &MaintenancePin) -> ParticipantError {
    ParticipantError {
        code: "OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION".into(),
        phase: "ENGINE_OWNER".into(),
        effect_certainty: "UNKNOWN".into(),
        recovery: "RESUME_SAME_HOST_REBIND_OPERATION".into(),
        operation_id: Some(pin.operation_id.clone()),
    }
}
pub(crate) fn validate_ready(owner: &SecureStateStore, binding: &[u8]) -> Result<()> {
    let state = read(owner, binding)?;
    if let Some(pin) = state.pending {
        return Err(pending(&pin));
    }
    Ok(())
}
pub(crate) fn revision(owner: &SecureStateStore, binding: &[u8]) -> Result<u64> {
    let state = read(owner, binding)?;
    if let Some(pin) = state.pending {
        return Err(pending(&pin));
    }
    Ok(state.revision)
}
/// The original owner lock must remain held. False means this exact operation
/// was already completed; never fence/replay it or overwrite newer work.
pub(crate) fn begin(
    owner: &SecureStateStore,
    binding: &[u8],
    pin: &MaintenancePin,
) -> Result<bool> {
    pin.validate()?;
    let mut state = read(owner, binding)?;
    if let Some(old) = &state.pending {
        return if old == pin {
            Ok(true)
        } else {
            Err(pending(old))
        };
    }
    if let Some(old) = &state.completed {
        if old.operation_id == pin.operation_id {
            return if old == pin {
                Ok(false)
            } else {
                Err(error("OWNER_ORIGINAL_MAINTENANCE_SELECTION_REQUIRED"))
            };
        }
    }
    if pin.expected_revision != state.revision {
        return Err(error("OWNER_MAINTENANCE_REVISION_MISMATCH"));
    }
    state.revision += 1;
    state.pending = Some(pin.clone());
    write(owner, &state)?;
    Ok(true)
}
pub(crate) fn complete(
    owner: &SecureStateStore,
    binding: &[u8],
    pin: &MaintenancePin,
) -> Result<()> {
    pin.validate()?;
    let mut state = read(owner, binding)?;
    match &state.pending {
        Some(current) if current == pin => {
            state.pending = None;
            state.completed = Some(pin.clone());
            write(owner, &state)
        }
        Some(current) => Err(pending(current)),
        None if state.completed.as_ref() == Some(pin) => Ok(()),
        None => Err(error("OWNER_ORIGINAL_MAINTENANCE_SELECTION_REQUIRED")),
    }
}
pub(crate) fn logical_binding(
    identity: &crate::kernel_identity::KernelIdentity,
    origin: &str,
    authority: &str,
) -> Vec<u8> {
    json!({"format":"peerwork.participant-owner.v1","actor":identity.actor_id(),"key":identity.key_id(),"origin":origin,"authority":authority}).to_string().into_bytes()
}

#[cfg(test)]
#[path = "participant_owner_qualification_tests.rs"]
mod qualification_tests;
#[cfg(test)]
#[path = "participant_owner_tests.rs"]
mod tests;
