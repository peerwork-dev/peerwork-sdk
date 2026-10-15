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

/// Stable, redacted public Kernel boundary. No underlying Display text is exposed.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct KernelPublicError {
    pub code: &'static str,
    pub message: &'static str,
}
impl KernelPublicError {
    pub fn envelope(self) -> serde_json::Value {
        serde_json::json!({"ok":false,"code":self.code,"message":self.message})
    }
}
impl From<&'static str> for KernelPublicError {
    fn from(message: &'static str) -> Self {
        Self {
            code: "INPUT_INVALID",
            message,
        }
    }
}
impl From<KernelAccessError> for KernelPublicError {
    fn from(error: KernelAccessError) -> Self {
        use crate::kernel_client::KernelClientError as C;
        use crate::kernel_intents::JournalError as J;
        use crate::transport::TransportError as T;
        use KernelAccessError as A;
        let (code, message) = match error {
            A::Identity(KernelIdentityError::NotFound) => {
                ("IDENTITY_MISSING", "selected kernel identity is missing")
            }
            A::Identity(_) => (
                "IDENTITY_STATE",
                "selected kernel identity could not be opened safely",
            ),
            A::Runtime => ("RUNTIME_FAILED", "native kernel runtime could not start"),
            A::Authority => (
                "AUTHORITY_MISMATCH",
                "command does not match the selected authority",
            ),
            A::Cancelled | A::Client(C::Transport(T::Cancelled)) => {
                ("CANCELLED", "kernel operation was cancelled")
            }
            A::Client(C::Transport(T::InvalidOrigin | T::InvalidTrust)) => (
                "CONFIG_INVALID",
                "kernel origin or transport configuration is invalid",
            ),
            A::Client(C::Transport(T::Timeout)) => ("TIMEOUT", "kernel request timed out"),
            A::Client(C::Transport(T::SubmittedUncertain)) => (
                "SUBMITTED_UNCERTAIN",
                "reconcile the original saved kernel command before another submission",
            ),
            A::Client(C::Transport(T::ResponseTooLarge)) => (
                "RESOURCE_LIMIT",
                "kernel response exceeds the supported resource limit",
            ),
            A::Client(C::Transport(_)) => ("TRANSPORT_FAILED", "kernel transport failed"),
            A::Client(C::Store(J::InvalidReceipt)) => {
                ("VERIFICATION_FAILED", "kernel receipt verification failed")
            }
            A::Client(C::Store(J::DiscoveryChanged)) => (
                "DISCOVERY_CHANGED",
                "kernel discovery differs from the pinned local state",
            ),
            A::Client(C::Store(J::IntentConflict)) => (
                "STATE_CONFLICT",
                "saved kernel command binds different bytes",
            ),
            A::Client(C::Store(
                J::InvalidIntent | J::IncompatibleStore | J::Protection | J::UnsupportedPlatform,
            )) => (
                "STATE_INVALID",
                "protected kernel state is invalid or unsupported",
            ),
            A::Client(C::Store(_)) => ("STATE_FAILED", "protected kernel state operation failed"),
            // Migration wraps heterogeneous sources; this is an operation category,
            // not an inferred transport, database, or verification cause.
            A::Client(C::Migration(_)) => (
                "MIGRATION_FAILED",
                "kernel migration failed; original source and saved commands remain authoritative",
            ),
            A::Client(C::DiscoveryStatus | C::UnsupportedDiscovery) => (
                "DISCOVERY_FAILED",
                "kernel discovery failed or is unsupported",
            ),
            A::Client(C::IntentNotFound) => ("NOT_FOUND", "saved kernel command was not found"),
            A::Client(C::ServerRejected(_)) => (
                "SERVICE_REJECTED",
                "kernel service rejected the saved command",
            ),
            A::Client(C::InvalidResult) => (
                "VERIFICATION_FAILED",
                "kernel result has an unsupported verified summary",
            ),
            A::Client(C::InvalidCommand) => (
                "COMMAND_INVALID",
                "kernel command does not match the selected discovery and identity",
            ),
        };
        Self { code, message }
    }
}

#[derive(Debug, Clone)]
pub struct KernelAccess {
    origin: String,
    journal_path: PathBuf,
    identity_path: PathBuf,
    required_features: Vec<Vec<u16>>,
    allow_loopback_http: bool,
    authority_override: Option<String>,
    transport: crate::transport::TransportOptions,
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
            transport: Default::default(),
        }
    }

    /// Use an explicitly configured authority digest. The default matches
    /// the TypeScript client's SHA-256 digest of this local actor ID.
    pub fn with_authority(mut self, authority: Option<String>) -> Self {
        self.authority_override = authority;
        self
    }

    pub fn with_transport_options(mut self, options: crate::transport::TransportOptions) -> Self {
        self.transport = options;
        self
    }

    fn runtime(&self) -> Result<Runtime, KernelAccessError> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| KernelAccessError::Runtime)
    }

    fn transport_config(&self) -> TransportConfig {
        let mut config =
            TransportConfig::new(self.origin.clone()).with_options(self.transport.clone());
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
            .map_err(|_| KernelClientError::InvalidCommand)?;
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

    pub(crate) fn migrate_ts_store_selected(
        &self,
        source_path: &Path,
        backup_path: &Path,
        workspace_id: &str,
        selected_pending_ids: &[String],
        cancel: &CancellationToken,
    ) -> Result<crate::kernel_intents::SelectedKernelImport, KernelAccessError> {
        let identity = self.identity()?;
        let runtime = self.runtime()?;
        let mut client = self.open_client(&runtime, cancel)?;
        Ok(client.migrate_ts_store_selected(
            source_path,
            backup_path,
            identity.actor_id(),
            identity.key_id(),
            workspace_id,
            selected_pending_ids,
        )?)
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

#[cfg(test)]
mod public_error_tests {
    use super::*;
    use crate::{
        kernel_client::KernelClientError as C, kernel_intents::JournalError as J,
        transport::TransportError as T,
    };
    #[test]
    fn malformed_command_is_not_an_authority_mismatch() {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity = state.path().join("identity");
        KernelIdentity::create(&identity).unwrap();
        let journal = state.path().join("journal");
        let access = KernelAccess::new("https://example.invalid", &journal, &identity, &[], false);
        let malformed = KernelPublicError::from(access.prepare(b"{", None).unwrap_err());
        assert_eq!(malformed.code, "COMMAND_INVALID");
        let authority = KernelPublicError::from(
            access
                .prepare(br#"{"authority":"wrong"}"#, None)
                .unwrap_err(),
        );
        assert_eq!(authority.code, "AUTHORITY_MISMATCH");
        assert!(!journal.exists());
    }
    #[test]
    fn typed_failures_are_redacted_and_stable() {
        let cases = [
            (
                KernelAccessError::from(C::Transport(T::InvalidOrigin)),
                "CONFIG_INVALID",
            ),
            (
                KernelAccessError::from(C::Transport(T::InvalidTrust)),
                "CONFIG_INVALID",
            ),
            (KernelAccessError::from(C::Transport(T::Timeout)), "TIMEOUT"),
            (
                KernelAccessError::from(C::Transport(T::SubmittedUncertain)),
                "SUBMITTED_UNCERTAIN",
            ),
            (KernelAccessError::Cancelled, "CANCELLED"),
            (
                KernelAccessError::from(C::Store(J::InvalidReceipt)),
                "VERIFICATION_FAILED",
            ),
            (
                KernelAccessError::from(C::Migration(
                    crate::ts_migration::TsMigrationError::MissingSigner(
                        "SECRET-JWS-KEY-PATH".into(),
                    ),
                )),
                "MIGRATION_FAILED",
            ),
            (
                KernelAccessError::from(C::Store(J::Io(std::io::Error::other(
                    "SECRET-BODY-PROXY",
                )))),
                "STATE_FAILED",
            ),
            (
                KernelAccessError::from(C::ServerRejected(503)),
                "SERVICE_REJECTED",
            ),
        ];
        for (source, code) in cases {
            let error = KernelPublicError::from(source);
            assert_eq!(error.code, code);
            let wire = error.envelope().to_string();
            assert!(!wire.contains("SECRET"));
            assert!(!wire.contains("503"));
        }
    }
}
