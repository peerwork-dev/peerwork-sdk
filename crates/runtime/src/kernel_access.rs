//! Public, redacted kernel access boundary for language bindings. Each call
//! reopens discovery and protected local state, so a process restart follows
//! the same continuity and exact saved-command checks as an in-process retry.

use crate::kernel_client::{
    KernelAcceptedResult, KernelClient, KernelClientError, KernelOperationStatus, TsMigrationReport,
};
use crate::kernel_identity::{KernelIdentity, KernelIdentityError};
use crate::kernel_intents::PendingKernelIntent;
use crate::transport::TransportConfig;
use peerwork_core::crypto::sha256_hex;
use peerwork_core::wire_json::{parse_wire_json_bounded, WireValue};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::runtime::{Builder, Runtime};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum KernelAccessError {
    #[error(transparent)]
    Client(#[from] KernelClientError),
    #[error(transparent)]
    Identity(#[from] KernelIdentityError),
    #[error("native async runtime could not start")]
    Runtime,
    #[error("command authority differs from configured local authority")]
    Authority,
    #[error("kernel operation was cancelled")]
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct KernelAccess {
    origin: String,
    journal_path: PathBuf,
    identity_path: PathBuf,
    required_features: Vec<Vec<u16>>,
    allow_loopback_http: bool,
    authority_override: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelOpenInfo {
    pub actor_id: String,
    pub key_id: String,
    pub origin: String,
}

impl KernelAccess {
    /// The origin is an explicit local trust input. Plain HTTP is restricted
    /// to loopback and must be opted into for local development or tests.
    pub fn new(
        origin: impl Into<String>,
        journal_path: impl AsRef<Path>,
        identity_path: impl AsRef<Path>,
        required_features: &[String],
        allow_loopback_http: bool,
    ) -> Self {
        Self {
            origin: origin.into(),
            journal_path: journal_path.as_ref().to_owned(),
            identity_path: identity_path.as_ref().to_owned(),
            required_features: required_features
                .iter()
                .map(|feature| feature.encode_utf16().collect())
                .collect(),
            allow_loopback_http,
            authority_override: None,
        }
    }

    /// Use an explicitly configured authority digest. The default matches
    /// the TypeScript client's SHA-256 digest of this local actor ID.
    pub fn with_authority(mut self, authority: Option<String>) -> Self {
        self.authority_override = authority;
        self
    }

    fn runtime(&self) -> Result<Runtime, KernelAccessError> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| KernelAccessError::Runtime)
    }

    fn transport_config(&self) -> TransportConfig {
        let mut config = TransportConfig::new(self.origin.clone());
        config.allow_loopback_http = self.allow_loopback_http;
        config
    }

    fn open_client(
        &self,
        runtime: &Runtime,
        cancel: &CancellationToken,
    ) -> Result<KernelClient, KernelAccessError> {
        Ok(runtime.block_on(KernelClient::open(
            self.transport_config(),
            &self.journal_path,
            &self.required_features,
            cancel,
        ))?)
    }

    fn identity(&self) -> Result<KernelIdentity, KernelAccessError> {
        Ok(KernelIdentity::open(&self.identity_path)?)
    }

    /// Fetch and continuity-pin discovery over the configured origin, then
    /// return only the local public identity IDs and normalized origin.
    pub fn open(&self) -> Result<KernelOpenInfo, KernelAccessError> {
        self.open_with_cancel(&CancellationToken::new())
    }

    pub fn open_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<KernelOpenInfo, KernelAccessError> {
        let identity = self.identity()?;
        let runtime = self.runtime()?;
        let client = self.open_client(&runtime, cancel)?;
        Ok(KernelOpenInfo {
            actor_id: identity.actor_id().to_owned(),
            key_id: identity.key_id().to_owned(),
            origin: client.origin().to_owned(),
        })
    }

    /// Core validates and signs the requested command, then the journal saves
    /// exact request bytes before this method returns. It performs no POST.
    pub fn prepare(
        &self,
        command_wire: &[u8],
        upload_chunk: Option<&[u8]>,
    ) -> Result<PendingKernelIntent, KernelAccessError> {
        self.prepare_with_cancel(command_wire, upload_chunk, &CancellationToken::new())
    }

    pub fn prepare_with_cancel(
        &self,
        command_wire: &[u8],
        upload_chunk: Option<&[u8]>,
        cancel: &CancellationToken,
    ) -> Result<PendingKernelIntent, KernelAccessError> {
        let identity = self.identity()?;
        let expected_authority = self
            .authority_override
            .clone()
            .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
        let parsed = parse_wire_json_bounded(command_wire, 40, 180_000)
            .map_err(|_| KernelAccessError::Authority)?;
        if parsed
            .get("authority")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(expected_authority.as_str())
        {
            return Err(KernelAccessError::Authority);
        }
        let runtime = self.runtime()?;
        let mut client = self.open_client(&runtime, cancel)?;
        if cancel.is_cancelled() {
            return Err(KernelAccessError::Cancelled);
        }
        Ok(client.prepare_command(&identity, command_wire, upload_chunk)?)
    }

    pub fn pending(&self) -> Result<Vec<PendingKernelIntent>, KernelAccessError> {
        self.pending_with_cancel(&CancellationToken::new())
    }

    /// Take and read back a protected SQLite backup of a quiesced legacy
    /// TypeScript store, then import only fully verified rows. Discovery is
    /// fetched from the explicitly configured origin before local writes.
    /// The signer IDs are public verification-key pins for every historical
    /// actor, not private keys or permission to execute their commands.
    pub fn migrate_ts_store(
        &self,
        source_path: &Path,
        backup_path: &Path,
        trusted_signer_key_ids: &[String],
        cancel: &CancellationToken,
    ) -> Result<TsMigrationReport, KernelAccessError> {
        let _identity = self.identity()?;
        let runtime = self.runtime()?;
        let mut client = self.open_client(&runtime, cancel)?;
        if cancel.is_cancelled() {
            return Err(KernelAccessError::Cancelled);
        }
        Ok(client.migrate_ts_store(source_path, backup_path, trusted_signer_key_ids)?)
    }

    pub fn pending_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Vec<PendingKernelIntent>, KernelAccessError> {
        let identity = self.identity()?;
        let runtime = self.runtime()?;
        let client = self.open_client(&runtime, cancel)?;
        Ok(client.pending(identity.key_id())?)
    }

    pub fn status(
        &self,
        command_id: &str,
    ) -> Result<Option<KernelOperationStatus>, KernelAccessError> {
        self.status_with_cancel(command_id, &CancellationToken::new())
    }

    pub fn status_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<KernelOperationStatus>, KernelAccessError> {
        let identity = self.identity()?;
        let runtime = self.runtime()?;
        let client = self.open_client(&runtime, cancel)?;
        Ok(client.status(command_id, identity.key_id())?)
    }

    /// A cancelled or unreadable in-flight reply leaves the exact saved row
    /// pending; reopening and resubmitting this ID is the recovery path.
    pub fn submit_saved(
        &self,
        command_id: &str,
    ) -> Result<KernelAcceptedResult, KernelAccessError> {
        self.submit_saved_with_cancel(command_id, &CancellationToken::new())
    }

    pub fn submit_saved_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<KernelAcceptedResult, KernelAccessError> {
        let identity = self.identity()?;
        let runtime = self.runtime()?;
        let mut client = self.open_client(&runtime, cancel)?;
        Ok(runtime.block_on(client.submit_saved(command_id, identity.key_id(), cancel))?)
    }
}
