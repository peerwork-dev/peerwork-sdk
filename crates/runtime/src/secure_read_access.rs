//! Configured-origin secure read facade. Only a completed, source-bound journal
//! that passes signed replay can yield public object data. Current production
//! positives are PUBLIC histories; PRIVATE pending keys cannot authorize reads.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_journal_read::{JournalReadError, SecureJournalRead},
    secure_lifecycle::SecureLifecycle,
    secure_verified_read::{
        replay_authenticated_pages_with_budget, SecureJournalReadBudget, TransportReplayedJournal,
        VerifiedReadError,
    },
    transport::{TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    replayed_secure_journal::StructureStatus,
    wire_json::{canonical_wire_value, WireValue},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use thiserror::Error;
use tokio::{runtime::Builder, runtime::Runtime};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureReadConfig {
    pub origin: String,
    pub kernel_journal_path: PathBuf,
    pub read_state_path: PathBuf,
    pub lifecycle_path: PathBuf,
    pub identity_path: PathBuf,
    pub workspace_id: String,
    pub authority: String,
    /// Explicit trusted owner pins, required even on first open. Never infer
    /// these values from an unverified page or from HTTP discovery.
    pub owner_actor_id: String,
    pub owner_key_id: String,
    #[serde(default)]
    pub required_features: Vec<String>,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default = "default_replay_budget")]
    pub max_replay_artifact_bytes: u64,
}

fn default_replay_budget() -> u64 {
    SecureJournalReadBudget::default().max_replay_artifact_bytes
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecureReadAccessError {
    #[error("configured origin discovery or continuity failed")]
    Discovery,
    #[error("protected local identity could not be opened")]
    Identity,
    #[error("protected lifecycle identity or owner pin changed")]
    Lifecycle,
    #[error("protected secure read profile is missing or incompatible")]
    Profile,
    #[error("secure journal read or saved page check failed")]
    ReadFailed,
    #[error("secure journal exceeded the selected resource budget")]
    ResourceLimit,
    #[error("signed journal verification failed or this history is not yet supported")]
    VerificationFailed,
    #[error("secure workspace is not active for verified reads")]
    NotActive,
    #[error("secure read was cancelled")]
    Cancelled,
    #[error("native async runtime could not start")]
    Runtime,
    #[error("verified result could not be encoded")]
    ResultEncoding,
}

impl SecureReadAccessError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Discovery => "DISCOVERY_FAILED",
            Self::Identity => "IDENTITY_STATE",
            Self::Lifecycle => "LIFECYCLE_PIN_CHANGED",
            Self::Profile => "PROFILE_STATE",
            Self::ReadFailed => "READ_FAILED",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::NotActive => "NOT_ACTIVE",
            Self::Cancelled => "CANCELLED",
            Self::Runtime => "RUNTIME_FAILED",
            Self::ResultEncoding => "RESULT_ENCODING_FAILED",
        }
    }
}

pub struct SecureReadAccess {
    config: SecureReadConfig,
}

/// Persisted only after the corresponding complete signed replay succeeded.
/// The profile binds its source and owner separately; this floor prevents a
/// later generation from replacing it with a rollback or fork.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct VerifiedReadFloor {
    pub sequence: u64,
    pub head: Option<String>,
    pub policy_hash: String,
}

impl SecureReadAccess {
    pub fn new(config: SecureReadConfig) -> Self {
        Self { config }
    }

    fn runtime() -> Result<Runtime, SecureReadAccessError> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SecureReadAccessError::Runtime)
    }

    /// Return a JSON object containing only verified content and checkpoint
    /// metadata. Authenticated object values are embedded as lossless canonical
    /// JSON, preserving UTF-16 escape behavior across Python, Node and CLI.
    pub fn read_json(&self) -> Result<String, SecureReadAccessError> {
        self.read_json_with_cancel(&CancellationToken::new())
    }

    /// Reset only the inactive profile generation before marking it
    /// resumable. A crash after this returns but before the profile marker is
    /// written simply repeats this reset; no HTTP page was fetched yet.
    pub(crate) fn reset_inactive_generation(
        &self,
        cancel: &CancellationToken,
    ) -> Result<(), SecureReadAccessError> {
        if cancel.is_cancelled() {
            return Err(SecureReadAccessError::Cancelled);
        }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| SecureReadAccessError::Identity)?;
        let runtime = Self::runtime()?;
        let mut transport = TransportConfig::new(self.config.origin.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|feature| feature.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.kernel_journal_path,
                &features,
                cancel,
            ))
            .map_err(|_| {
                if cancel.is_cancelled() {
                    SecureReadAccessError::Cancelled
                } else {
                    SecureReadAccessError::Discovery
                }
            })?;
        let mut reader = SecureJournalRead::open(
            &self.config.read_state_path,
            &client,
            &identity,
            &self.config.workspace_id,
            &self.config.authority,
        )
        .map_err(map_read_error)?;
        reader.reset_inactive_generation().map_err(map_read_error)
    }

    pub fn read_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, SecureReadAccessError> {
        self.read_checked_generation(cancel, None, false)
            .map(|(value, _)| value)
    }

    pub(crate) fn read_checked_generation(
        &self,
        cancel: &CancellationToken,
        floor: Option<&VerifiedReadFloor>,
        reset_inactive: bool,
    ) -> Result<(String, VerifiedReadFloor), SecureReadAccessError> {
        let (replayed, new_floor) =
            self.replay_checked_generation(cancel, floor, reset_inactive)?;
        let verified = replayed.verified_read().map_err(map_verify_error)?;
        let objects = canonical_array(verified.objects())?;
        let operations = canonical_array(verified.operations())?;
        let recoveries = canonical_array(verified.recoveries())?;
        let structure_status = match verified.structure_status() {
            StructureStatus::Unstructured => "UNSTRUCTURED",
            StructureStatus::Active => "ACTIVE",
            StructureStatus::Seeding => return Err(SecureReadAccessError::NotActive),
        };
        let metadata = json!({
            "origin": replayed.origin(),
            "workspace_id": verified.workspace_id(),
            "sequence": verified.sequence(),
            "head": verified.head(),
            "policy_hash": verified.policy_hash(),
            "structure_status": structure_status,
        });
        let mut result =
            serde_json::to_string(&metadata).map_err(|_| SecureReadAccessError::ResultEncoding)?;
        if cancel.is_cancelled() {
            return Err(SecureReadAccessError::Cancelled);
        }
        assert_eq!(result.pop(), Some('}'));
        result.push_str(",\"objects\":");
        result.push_str(&objects);
        result.push_str(",\"operations\":");
        result.push_str(&operations);
        result.push_str(",\"recoveries\":");
        result.push_str(&recoveries);
        result.push('}');
        Ok((result, new_floor))
    }

    pub(crate) fn replay_checked_generation(
        &self,
        cancel: &CancellationToken,
        floor: Option<&VerifiedReadFloor>,
        reset_inactive: bool,
    ) -> Result<(TransportReplayedJournal, VerifiedReadFloor), SecureReadAccessError> {
        if cancel.is_cancelled() {
            return Err(SecureReadAccessError::Cancelled);
        }
        let budget = SecureJournalReadBudget::new(self.config.max_replay_artifact_bytes)
            .ok_or(SecureReadAccessError::ResourceLimit)?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| SecureReadAccessError::Identity)?;
        let runtime = Self::runtime()?;
        let mut transport = TransportConfig::new(self.config.origin.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|feature| feature.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.kernel_journal_path,
                &features,
                cancel,
            ))
            .map_err(|error| {
                if cancel.is_cancelled() {
                    SecureReadAccessError::Cancelled
                } else {
                    let _ = error;
                    SecureReadAccessError::Discovery
                }
            })?;
        let mut reader = SecureJournalRead::open(
            &self.config.read_state_path,
            &client,
            &identity,
            &self.config.workspace_id,
            &self.config.authority,
        )
        .map_err(map_read_error)?;
        if reset_inactive {
            reader.reset_inactive_generation().map_err(map_read_error)?;
        }
        while !reader
            .progress()
            .map_err(map_read_error)?
            .complete_transport
        {
            if cancel.is_cancelled() {
                return Err(SecureReadAccessError::Cancelled);
            }
            runtime
                .block_on(reader.fetch_next(&client, &identity, cancel))
                .map_err(map_read_error)?;
        }
        if cancel.is_cancelled() {
            return Err(SecureReadAccessError::Cancelled);
        }
        let lifecycle = SecureLifecycle::open(
            &self.config.lifecycle_path,
            client.origin(),
            identity.actor_id(),
            &self.config.workspace_id,
            &self.config.owner_actor_id,
            &self.config.owner_key_id,
        )
        .map_err(|_| SecureReadAccessError::Lifecycle)?;
        let pages = reader
            .authenticated_pages(&client, &identity)
            .map_err(map_read_error)?;
        let replayed = replay_authenticated_pages_with_budget(&pages, &lifecycle, budget)
            .map_err(map_verify_error)?;
        if floor.is_some_and(|saved| {
            !replayed.replay().contains_checkpoint(
                saved.sequence,
                saved.head.as_deref(),
                &saved.policy_hash,
            )
        }) {
            return Err(SecureReadAccessError::VerificationFailed);
        }
        let verified = replayed.verified_read().map_err(map_verify_error)?;
        let new_floor = VerifiedReadFloor {
            sequence: verified.sequence(),
            head: verified.head().map(str::to_owned),
            policy_hash: verified.policy_hash().to_owned(),
        };
        Ok((replayed, new_floor))
    }
}

fn canonical_array(values: &[WireValue]) -> Result<String, SecureReadAccessError> {
    let mut result = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            result.push(',');
        }
        let canonical = canonical_wire_value(value, CanonicalPath::SecureArtifact)
            .map_err(|_| SecureReadAccessError::ResultEncoding)?;
        result.push_str(&canonical);
    }
    result.push(']');
    Ok(result)
}

fn map_read_error(error: JournalReadError) -> SecureReadAccessError {
    match error {
        JournalReadError::Transport(TransportError::Cancelled) => SecureReadAccessError::Cancelled,
        JournalReadError::Transport(TransportError::ResponseTooLarge)
        | JournalReadError::TooLarge => SecureReadAccessError::ResourceLimit,
        _ => SecureReadAccessError::ReadFailed,
    }
}

fn map_verify_error(error: VerifiedReadError) -> SecureReadAccessError {
    match error {
        VerifiedReadError::ResourceLimit => SecureReadAccessError::ResourceLimit,
        VerifiedReadError::NotActive => SecureReadAccessError::NotActive,
        VerifiedReadError::Page(error) => map_read_error(error),
        _ => SecureReadAccessError::VerificationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unused_config() -> SecureReadConfig {
        SecureReadConfig {
            origin: "https://example.invalid/".into(),
            kernel_journal_path: "not-used-kernel".into(),
            read_state_path: "not-used-read".into(),
            lifecycle_path: "not-used-lifecycle".into(),
            identity_path: "not-used-identity".into(),
            workspace_id: "unused".into(),
            authority: "0".repeat(64),
            owner_actor_id: "unused".into(),
            owner_key_id: "unused".into(),
            required_features: vec![],
            allow_loopback_http: false,
            max_replay_artifact_bytes: 0,
        }
    }

    #[test]
    fn cancellation_and_budget_refuse_before_local_state_or_http() {
        let access = SecureReadAccess::new(unused_config());
        assert_eq!(
            access.read_json().unwrap_err(),
            SecureReadAccessError::ResourceLimit
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            access.read_json_with_cancel(&cancel).unwrap_err(),
            SecureReadAccessError::Cancelled
        );
    }

    #[test]
    fn verified_json_projection_preserves_escaped_utf16() {
        let result = canonical_array(&[WireValue::String(vec![0xdfff])]).unwrap();
        assert_eq!(result, "[\"\\udfff\"]");
    }
}
