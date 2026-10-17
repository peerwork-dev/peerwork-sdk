//! Explicit native recipient cold start. Local keys, kernel registration and
//! signed directory publication are separate durable operations. None grants
//! workspace membership or accepts an invitation.

use crate::{
    kernel_client::{KernelClient, KernelClientError, KernelOperationStatus},
    kernel_identity::{KernelIdentity, KernelIdentityError},
    kernel_intents::JournalError,
    secure_identity_directory::{IdentityDirectoryConfig, SecureIdentityDirectory},
    secure_journal_read::sign_read_proof,
    secure_recipient_state::{RecipientState, RecipientStateError},
    secure_state::SecureStateStore,
    transport::{TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::{canonical, Path as CanonicalPath},
    crypto::{base64url, decode_base64url, sha256_hex, sign_canonical, verify_secure_signed_wire},
    secure_recipient::RecipientCertificate,
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const DIRECTORY_PATH: &str = "/api/workspace/v1/secure/identity-keys";
const DIRECTORY_DOMAIN: &str = "peerwork.secure.identity-directory.v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientEnrollmentConfig {
    #[serde(default)]
    pub transport: crate::transport::TransportOptions,
    pub origin: String,
    pub identity_path: PathBuf,
    pub recipient_path: PathBuf,
    pub enrollment_state_path: PathBuf,
    pub kernel_journal_path: PathBuf,
    #[serde(default)]
    pub allow_loopback_http: bool,
}

impl RecipientEnrollmentConfig {
    pub fn for_state_dir(origin: String, state_dir: &Path) -> Self {
        Self {
            transport: Default::default(),
            origin,
            identity_path: state_dir.join("identity.state"),
            recipient_path: state_dir.join("recipient.state"),
            enrollment_state_path: state_dir.join("enrollment.state"),
            kernel_journal_path: state_dir.join("kernel.sqlite"),
            allow_loopback_http: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientEnrollmentResult {
    pub status: String,
    pub actor_id: String,
    pub signing_key_id: String,
    pub encryption_key_id: String,
    pub certificate_digest: String,
    pub registration_command_id: Option<String>,
    pub directory_entry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientKeyUpdateResult {
    pub status: String,
    pub update_id: String,
    pub mode: String,
    pub previous_certificate_hash: String,
    pub certificate_digest: String,
    pub directory_version: usize,
    pub directory_head: String,
}

#[derive(Debug, Error)]
pub enum RecipientEnrollmentError {
    #[error("protected recipient enrollment state is invalid")]
    Invalid,
    #[error("protected enrollment identity or origin changed")]
    Identity,
    #[error("directory history changed or requires an unsupported rotation")]
    DirectoryContinuity,
    #[error("enrollment transport failed; check the configured origin and explicitly select PEERWORK_HTTP_PROXY from the runtime proxy route if required; generic HTTP_PROXY/HTTPS_PROXY/ALL_PROXY variables are ignored; keep the selected identity")]
    Transport,
    #[error("enrollment transport configuration is invalid; check the selected origin, explicit PEERWORK_HTTP_PROXY and trust-root settings; values are not included in this error")]
    TransportConfiguration,
    #[error("enrollment discovery returned an unsuccessful HTTP status; check the configured origin and selected proxy access policy")]
    DiscoveryStatus,
    #[error("enrollment discovery or signed command result did not verify; check the configured service and pinned authority; keep the selected identity")]
    Verification,
    #[error("protected local recipient state failed")]
    Local,
    #[error("server rejected recipient enrollment with HTTP {0}")]
    ServerRejected(u16),
    #[error("system clock or random source failed")]
    ClockOrEntropy,
    #[error("recipient key update was cancelled")]
    Cancelled,
}

impl RecipientEnrollmentError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "INPUT_INVALID",
            Self::Identity => "IDENTITY_CHANGED",
            Self::DirectoryContinuity => "DIRECTORY_CONTINUITY",
            Self::Transport => "TRANSPORT_FAILED",
            Self::TransportConfiguration => "TRANSPORT_CONFIGURATION_INVALID",
            Self::DiscoveryStatus => "DISCOVERY_FAILED",
            Self::Verification => "VERIFICATION_FAILED",
            Self::Local => "LOCAL_STATE_FAILED",
            Self::ServerRejected(_) => "SERVER_REJECTED",
            Self::ClockOrEntropy => "CLOCK_OR_ENTROPY",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentDocument {
    v: u8,
    origin: String,
    actor_id: String,
    signing_key_id: String,
    certificate_digest: String,
    registration_command_id: Option<String>,
    registration_command_wire: Option<String>,
    directory_entry_wire: Option<String>,
    directory_request_wire: Option<String>,
    directory_entry_hash: Option<String>,
    published_head: Option<String>,
    #[serde(default)]
    updates: Vec<PendingKeyUpdate>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingKeyUpdate {
    update_id: String,
    mode: String,
    previous_certificate_hash: String,
    entry_wire: String,
    request_wire: String,
    entry_hash: String,
    certificate_digest: String,
    private_key_b64: String,
    published: bool,
}

impl Drop for PendingKeyUpdate {
    fn drop(&mut self) {
        self.private_key_b64.zeroize();
    }
}

pub struct SecureRecipientEnrollment {
    config: RecipientEnrollmentConfig,
}

impl SecureRecipientEnrollment {
    pub fn new(config: RecipientEnrollmentConfig) -> Self {
        Self { config }
    }

    /// Export only the self-signed public certificate for an explicit owner
    /// invitation. This does not attest directory publication or membership.
    pub fn certificate_json(&self) -> Result<String, RecipientEnrollmentError> {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let recipient = RecipientState::open(&self.config.recipient_path, &identity)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        recipient
            .recipient()
            .verify_local_certificate(
                recipient.certificate(),
                identity.actor_id(),
                identity.key_id(),
                now_ms()?,
            )
            .map_err(|_| RecipientEnrollmentError::Invalid)?;
        canonical(
            &serde_json::to_value(recipient.certificate())
                .map_err(|_| RecipientEnrollmentError::Invalid)?,
            CanonicalPath::SecureArtifact,
        )
        .map_err(|_| RecipientEnrollmentError::Invalid)
    }

    /// Local-only recovery discovery. This reports saved work and the last
    /// verified local directory pin; it does not assert current server state.
    pub fn pending(&self) -> Result<Option<RecipientEnrollmentResult>, RecipientEnrollmentError> {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let recipient = RecipientState::open(&self.config.recipient_path, &identity)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let digest = certificate_digest(recipient.certificate())?;
        let store = SecureStateStore::open(&self.config.enrollment_state_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let Some(bytes) = store
            .read_exact_secret()
            .map_err(|_| RecipientEnrollmentError::Local)?
        else {
            return Ok(None);
        };
        let document: EnrollmentDocument =
            serde_json::from_slice(&bytes).map_err(|_| RecipientEnrollmentError::Invalid)?;
        if document.v != 1
            || document.origin != self.config.origin
            || document.actor_id != identity.actor_id()
            || document.signing_key_id != identity.key_id()
            || document.certificate_digest != digest
        {
            return Err(RecipientEnrollmentError::Identity);
        }
        if let Some(entry) = document.directory_entry_wire.as_deref() {
            verify_entry(entry, &identity, &recipient, now_ms()?)?;
            if document.directory_entry_hash.as_deref()
                != Some(sha256_hex(entry.as_bytes()).as_str())
            {
                return Err(RecipientEnrollmentError::Invalid);
            }
        }
        let status = if document.published_head.is_some() {
            "PUBLISHED_LOCAL"
        } else if document.directory_entry_wire.is_some() {
            "PUBLICATION_PENDING"
        } else {
            "REGISTRATION_PENDING"
        };
        Ok(Some(result(
            status,
            &identity,
            recipient.certificate(),
            &digest,
            document.registration_command_id.as_deref(),
            document.directory_entry_hash.as_deref(),
        )))
    }

    /// Prepare and submit a signed successor directory entry. The update ID,
    /// exact request, and replacement private key are protected before POST.
    /// A missing ID is generated and remains discoverable through
    /// `pending_key_updates` even if the caller loses the result.
    pub fn update_key(
        &self,
        mode: &str,
        expected_certificate_hash: &str,
        update_id: Option<&str>,
    ) -> Result<RecipientKeyUpdateResult, RecipientEnrollmentError> {
        self.update_key_with_cancel(
            mode,
            expected_certificate_hash,
            update_id,
            &CancellationToken::new(),
        )
    }

    pub fn update_key_with_cancel(
        &self,
        mode: &str,
        expected_certificate_hash: &str,
        update_id: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<RecipientKeyUpdateResult, RecipientEnrollmentError> {
        if !matches!(mode, "RENEW" | "ROTATE")
            || !valid_token_or_hash(expected_certificate_hash, false)
        {
            return Err(RecipientEnrollmentError::Invalid);
        }
        self.run_key_update(update_id, Some((mode, expected_certificate_hash)), cancel)
    }

    pub fn retry_key_update(
        &self,
        update_id: &str,
    ) -> Result<RecipientKeyUpdateResult, RecipientEnrollmentError> {
        self.retry_key_update_with_cancel(update_id, &CancellationToken::new())
    }

    pub fn retry_key_update_with_cancel(
        &self,
        update_id: &str,
        cancel: &CancellationToken,
    ) -> Result<RecipientKeyUpdateResult, RecipientEnrollmentError> {
        self.run_key_update(Some(update_id), None, cancel)
    }

    pub fn pending_key_updates(
        &self,
    ) -> Result<Vec<RecipientKeyUpdateResult>, RecipientEnrollmentError> {
        self.saved_key_updates(false)
    }

    /// Redacted protected local history, including published update IDs.
    /// This remains discoverable if a caller cancels after local promotion but
    /// before its async wrapper can deliver the result. A published row was
    /// promoted only after the exact signed directory head was verified.
    pub fn key_updates(&self) -> Result<Vec<RecipientKeyUpdateResult>, RecipientEnrollmentError> {
        self.saved_key_updates(true)
    }

    fn saved_key_updates(
        &self,
        include_published: bool,
    ) -> Result<Vec<RecipientKeyUpdateResult>, RecipientEnrollmentError> {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let store = SecureStateStore::open(&self.config.enrollment_state_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let bytes = store
            .read_exact_secret()
            .map_err(|_| RecipientEnrollmentError::Local)?
            .ok_or(RecipientEnrollmentError::Invalid)?;
        let doc: EnrollmentDocument =
            serde_json::from_slice(&bytes).map_err(|_| RecipientEnrollmentError::Invalid)?;
        if doc.v != 1
            || doc.origin != self.config.origin
            || doc.actor_id != identity.actor_id()
            || doc.signing_key_id != identity.key_id()
        {
            return Err(RecipientEnrollmentError::Identity);
        }
        Ok(doc
            .updates
            .iter()
            .filter(|update| include_published || !update.published)
            .map(|update| {
                update_result(
                    update,
                    if update.published {
                        "PUBLISHED"
                    } else {
                        "PENDING"
                    },
                )
            })
            .collect())
    }

    fn run_key_update(
        &self,
        requested_id: Option<&str>,
        requested: Option<(&str, &str)>,
        cancel: &CancellationToken,
    ) -> Result<RecipientKeyUpdateResult, RecipientEnrollmentError> {
        if cancel.is_cancelled() {
            return Err(RecipientEnrollmentError::Cancelled);
        }
        if requested_id.is_some_and(|id| !valid_token_or_hash(id, true)) {
            return Err(RecipientEnrollmentError::Invalid);
        }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let mut recipient = RecipientState::open(&self.config.recipient_path, &identity)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let store = SecureStateStore::open(&self.config.enrollment_state_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let bytes = store
            .read_exact_secret()
            .map_err(|_| RecipientEnrollmentError::Local)?
            .ok_or(RecipientEnrollmentError::Invalid)?;
        let mut doc: EnrollmentDocument =
            serde_json::from_slice(&bytes).map_err(|_| RecipientEnrollmentError::Invalid)?;
        if doc.v != 1
            || doc.origin != self.config.origin
            || doc.actor_id != identity.actor_id()
            || doc.signing_key_id != identity.key_id()
            || doc.published_head.is_none()
        {
            return Err(RecipientEnrollmentError::Identity);
        }
        let current_hash = certificate_digest(recipient.certificate())?;
        let selected = if let Some(id) = requested_id {
            doc.updates.iter().position(|u| u.update_id == id)
        } else {
            None
        };
        if let Some(index) = selected {
            let existing = &doc.updates[index];
            if requested.is_some_and(|(mode, hash)| {
                mode != existing.mode || hash != existing.previous_certificate_hash
            }) {
                return Err(RecipientEnrollmentError::Invalid);
            }
            if existing.published {
                return Ok(update_result(existing, "PUBLISHED"));
            }
        } else {
            if requested.is_none()
                || doc.updates.iter().any(|u| !u.published)
                || doc.certificate_digest != current_hash
                || doc.updates.len() >= 128
                || requested.is_some_and(|(_, hash)| hash != current_hash)
            {
                return Err(RecipientEnrollmentError::Invalid);
            }
            let directory = self.own_directory();
            let prior = directory
                .lookup_for_update(identity.actor_id(), identity.key_id(), cancel)
                .map_err(|_| directory_or_cancel(cancel))?;
            if Some(prior.directory_head.as_str()) != doc.published_head.as_deref()
                || prior.certificate_json != canonical_certificate(recipient.certificate())?
                || prior.directory_version >= 128
            {
                return Err(RecipientEnrollmentError::DirectoryContinuity);
            }
            let id = match requested_id {
                Some(id) => id.to_owned(),
                None => {
                    let mut bytes = [0u8; 32];
                    OsRng
                        .try_fill_bytes(&mut bytes)
                        .map_err(|_| RecipientEnrollmentError::ClockOrEntropy)?;
                    base64url(&bytes)
                }
            };
            let (mode, previous_hash) = requested.unwrap();
            let at = now_ms()?;
            let next = if mode == "ROTATE" {
                peerwork_core::secure_recipient::SecretRecipient::generate()
                    .map_err(|_| RecipientEnrollmentError::ClockOrEntropy)?
            } else {
                let mut private = Zeroizing::new([0u8; 32]);
                private.copy_from_slice(recipient.recipient().private_bytes());
                peerwork_core::secure_recipient::SecretRecipient::from_private(private)
                    .map_err(|_| RecipientEnrollmentError::Invalid)?
            };
            let cert = next
                .certify(identity.signing_key(), at)
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            if mode == "RENEW"
                && cert.payload["expires_at"].as_u64()
                    <= recipient.certificate().payload["expires_at"].as_u64()
            {
                return Err(RecipientEnrollmentError::Invalid);
            }
            let payload = json!({"v":1,"actor_id":identity.actor_id(),"signing_key":identity.key_id(),
                "version":prior.directory_version+1,"previous":prior.directory_head,"certificate":cert,"issued_at":at});
            let signature = sign_canonical(DIRECTORY_DOMAIN, &payload, identity.signing_key())
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            let entry = json!({"payload":payload,"signature":signature});
            let entry_wire = canonical(&entry, CanonicalPath::SecureArtifact)
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            let request_wire = canonical(&json!({"entry":entry}), CanonicalPath::SecureArtifact)
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            if request_wire.len() > 8192 {
                return Err(RecipientEnrollmentError::Invalid);
            }
            let cert_digest = certificate_digest(
                &serde_json::from_value(entry["payload"]["certificate"].clone())
                    .map_err(|_| RecipientEnrollmentError::Invalid)?,
            )?;
            doc.updates.push(PendingKeyUpdate {
                update_id: id,
                mode: mode.into(),
                previous_certificate_hash: previous_hash.into(),
                entry_hash: sha256_hex(entry_wire.as_bytes()),
                entry_wire,
                request_wire,
                certificate_digest: cert_digest,
                private_key_b64: base64url(next.private_bytes()),
                published: false,
            });
            save(&store, &doc)?;
        }
        let index = selected.unwrap_or(doc.updates.len() - 1);
        let pending = &doc.updates[index];
        if cancel.is_cancelled() {
            return Ok(update_result(pending, "PENDING"));
        }
        let (next, cert, version, previous) = validate_saved_update(pending, &identity)?;
        if pending.previous_certificate_hash != doc.certificate_digest
            || Some(previous.as_str()) != doc.published_head.as_deref()
        {
            return Err(RecipientEnrollmentError::DirectoryContinuity);
        }
        let directory = self.own_directory();
        let observed = directory
            .lookup_for_update(identity.actor_id(), identity.key_id(), cancel)
            .map_err(|_| directory_or_cancel(cancel));
        let observed = match observed {
            Ok(value) => value,
            Err(RecipientEnrollmentError::Cancelled) => {
                return Ok(update_result(pending, "PENDING"))
            }
            Err(error) => return Err(error),
        };
        if observed.directory_head != pending.entry_hash {
            if observed.directory_head != previous || observed.directory_version + 1 != version {
                return Err(RecipientEnrollmentError::DirectoryContinuity);
            }
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| RecipientEnrollmentError::Transport)?;
            let mut transport = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
            transport.allow_loopback_http = self.config.allow_loopback_http;
            let client = runtime
                .block_on(KernelClient::open(
                    transport,
                    &self.config.kernel_journal_path,
                    &[],
                    cancel,
                ))
                .map_err(|error| {
                    if cancel.is_cancelled() {
                        RecipientEnrollmentError::Cancelled
                    } else {
                        map_kernel(error)
                    }
                });
            let client = match client {
                Ok(value) => value,
                Err(RecipientEnrollmentError::Cancelled) => {
                    return Ok(update_result(pending, "PENDING"))
                }
                Err(error) => return Err(error),
            };
            let authority = sha256_hex(identity.actor_id().as_bytes());
            let proof = sign_read_proof(DIRECTORY_PATH, client.discovery(), &identity, &authority)
                .map_err(|_| RecipientEnrollmentError::Transport)?;
            let sent = runtime.block_on(client.transport().post_secure_identity_key_exact(
                pending.request_wire.as_bytes().to_vec(),
                &proof,
                cancel,
            ));
            match sent {
                Ok(response) if (200..300).contains(&response.status) => (),
                Ok(response) => {
                    return Err(RecipientEnrollmentError::ServerRejected(response.status))
                }
                Err(TransportError::SubmittedUncertain | TransportError::Cancelled) => {
                    return Ok(update_result(pending, "PENDING"))
                }
                Err(_) => return Err(RecipientEnrollmentError::Transport),
            }
            drop(client);
            drop(runtime);
        }
        let verified = directory
            .lookup_for_update(identity.actor_id(), identity.key_id(), cancel)
            .map_err(|_| directory_or_cancel(cancel));
        let verified = match verified {
            Ok(value) => value,
            Err(RecipientEnrollmentError::Cancelled) => {
                return Ok(update_result(pending, "PENDING"))
            }
            Err(error) => return Err(error),
        };
        if verified.directory_head != pending.entry_hash
            || verified.directory_version != version
            || verified.certificate_json != canonical_certificate(&cert)?
        {
            return Err(RecipientEnrollmentError::DirectoryContinuity);
        }
        if cancel.is_cancelled() {
            return Ok(update_result(pending, "PENDING"));
        }
        if current_hash == pending.previous_certificate_hash {
            recipient
                .promote_published(
                    &identity,
                    &pending.previous_certificate_hash,
                    next,
                    cert,
                    now_ms()?,
                )
                .map_err(|_| RecipientEnrollmentError::Local)?;
        } else if current_hash != pending.certificate_digest {
            return Err(RecipientEnrollmentError::DirectoryContinuity);
        }
        let pending = &mut doc.updates[index];
        pending.published = true;
        pending.private_key_b64.zeroize();
        pending.private_key_b64.clear();
        doc.certificate_digest = pending.certificate_digest.clone();
        doc.published_head = Some(pending.entry_hash.clone());
        save(&store, &doc)?;
        Ok(update_result(&doc.updates[index], "PUBLISHED"))
    }

    fn own_directory(&self) -> SecureIdentityDirectory {
        let parent = self
            .config
            .enrollment_state_path
            .parent()
            .unwrap_or(std::path::Path::new("/"));
        SecureIdentityDirectory::new(IdentityDirectoryConfig {
            transport: self.config.transport.clone(),
            origin: self.config.origin.clone(),
            identity_path: self.config.identity_path.clone(),
            kernel_journal_path: self.config.kernel_journal_path.clone(),
            pins_path: parent.join("identity-directory.state"),
            allow_loopback_http: self.config.allow_loopback_http,
        })
    }

    /// Validate an existing enrollment binding without creating identities or issuing HTTP.
    pub(crate) fn validate_existing_context(&self) -> Result<(), RecipientEnrollmentError> {
        match std::fs::symlink_metadata(&self.config.enrollment_state_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(RecipientEnrollmentError::Local),
            Ok(_) => {}
        }
        let identity = KernelIdentity::open(&self.config.identity_path).map_err(|_| RecipientEnrollmentError::Identity)?;
        let recipient = RecipientState::open(&self.config.recipient_path,&identity).map_err(|_| RecipientEnrollmentError::Identity)?;
        let store = SecureStateStore::open(&self.config.enrollment_state_path).map_err(|_| RecipientEnrollmentError::Local)?;
        let bytes = store.read_exact_secret().map_err(|_| RecipientEnrollmentError::Local)?.ok_or(RecipientEnrollmentError::Invalid)?;
        let document: EnrollmentDocument = serde_json::from_slice(&bytes).map_err(|_| RecipientEnrollmentError::Invalid)?;
        if document.v != 1 || document.origin != self.config.origin || document.actor_id != identity.actor_id() || document.signing_key_id != identity.key_id() || document.certificate_digest != certificate_digest(recipient.certificate())? {
            return Err(RecipientEnrollmentError::Identity);
        }
        Ok(())
    }

    /// Offline creation is explicit. A crash after identity creation may be
    /// retried: the already protected key is reopened, never regenerated.
    pub fn create_local(&self) -> Result<RecipientEnrollmentResult, RecipientEnrollmentError> {
        ensure_private_parent(&self.config.identity_path)?;
        ensure_private_parent(&self.config.recipient_path)?;
        ensure_private_parent(&self.config.enrollment_state_path)?;
        ensure_private_parent(&self.config.kernel_journal_path)?;
        let identity = match KernelIdentity::open(&self.config.identity_path) {
            Ok(identity) => identity,
            Err(KernelIdentityError::NotFound) => {
                KernelIdentity::create(&self.config.identity_path)
                    .map_err(|_| RecipientEnrollmentError::Local)?
            }
            Err(_) => return Err(RecipientEnrollmentError::Local),
        };
        let at = now_ms()?;
        let recipient = match RecipientState::open(&self.config.recipient_path, &identity) {
            Ok(recipient) => recipient,
            Err(RecipientStateError::NotFound) => {
                RecipientState::create(&self.config.recipient_path, &identity, at)
                    .map_err(|_| RecipientEnrollmentError::Local)?
            }
            Err(_) => return Err(RecipientEnrollmentError::Local),
        };
        let digest = certificate_digest(recipient.certificate())?;
        Ok(result(
            "LOCAL",
            &identity,
            recipient.certificate(),
            &digest,
            None,
            None,
        ))
    }

    pub fn publish(&self) -> Result<RecipientEnrollmentResult, RecipientEnrollmentError> {
        self.publish_with_cancel(&CancellationToken::new())
    }

    /// Registration is a signed kernel command with its own durable receipt;
    /// publication requires a separately verified directory GET. Every retry
    /// uses the exact saved command and directory entry.
    pub fn publish_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<RecipientEnrollmentResult, RecipientEnrollmentError> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| RecipientEnrollmentError::Transport)?;
        runtime.block_on(self.publish_async(cancel))
    }

    async fn publish_async(
        &self,
        cancel: &CancellationToken,
    ) -> Result<RecipientEnrollmentResult, RecipientEnrollmentError> {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let recipient = RecipientState::open(&self.config.recipient_path, &identity)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let digest = certificate_digest(recipient.certificate())?;
        let store = SecureStateStore::open(&self.config.enrollment_state_path)
            .map_err(|_| RecipientEnrollmentError::Local)?;
        let mut document = match store
            .read_exact_secret()
            .map_err(|_| RecipientEnrollmentError::Local)?
        {
            Some(bytes) => serde_json::from_slice::<EnrollmentDocument>(&bytes)
                .map_err(|_| RecipientEnrollmentError::Invalid)?,
            None => EnrollmentDocument {
                v: 1,
                origin: self.config.origin.clone(),
                actor_id: identity.actor_id().into(),
                signing_key_id: identity.key_id().into(),
                certificate_digest: digest.clone(),
                registration_command_id: None,
                registration_command_wire: None,
                directory_entry_wire: None,
                directory_request_wire: None,
                directory_entry_hash: None,
                published_head: None,
                updates: Vec::new(),
            },
        };
        if document.v != 1
            || document.origin != self.config.origin
            || document.actor_id != identity.actor_id()
            || document.signing_key_id != identity.key_id()
            || document.certificate_digest != digest
        {
            return Err(RecipientEnrollmentError::Identity);
        }
        if !document.updates.is_empty() {
            if document.updates.iter().any(|update| !update.published)
                || document
                    .updates
                    .last()
                    .map(|update| update.entry_hash.as_str())
                    != document.published_head.as_deref()
            {
                return Err(RecipientEnrollmentError::DirectoryContinuity);
            }
            let verified = self
                .own_directory()
                .lookup_async(identity.actor_id(), identity.key_id(), cancel, true)
                .await
                .map_err(|_| RecipientEnrollmentError::DirectoryContinuity)?;
            if Some(verified.directory_head.as_str()) != document.published_head.as_deref()
                || verified.certificate_json != canonical_certificate(recipient.certificate())?
            {
                return Err(RecipientEnrollmentError::DirectoryContinuity);
            }
            return Ok(result(
                "PUBLISHED",
                &identity,
                recipient.certificate(),
                &digest,
                document.registration_command_id.as_deref(),
                document.published_head.as_deref(),
            ));
        }
        let mut transport = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let mut client =
            KernelClient::open(transport, &self.config.kernel_journal_path, &[], cancel)
                .await
                .map_err(map_kernel)?;
        if client.origin() != self.config.origin {
            return Err(RecipientEnrollmentError::Identity);
        }
        if document.registration_command_id.is_none() {
            let mut random = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| RecipientEnrollmentError::ClockOrEntropy)?;
            let command_id = base64url(&random);
            let issued = now_ms()?;
            let audience = String::from_utf16(client.discovery().audience_utf16())
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            let command = json!({"v":1,"audience":audience,"command_id":command_id,"actor_id":identity.actor_id(),"authority":sha256_hex(identity.actor_id().as_bytes()),"method":"POST","path":"/api/workspace/v1/commands","workspace_id":null,"instance_id":null,"protocol_digest":null,"action_id":"identity.register","expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"body":{},"issued_at":issued,"expires_at":issued.checked_add(600_000).ok_or(RecipientEnrollmentError::ClockOrEntropy)?});
            document.registration_command_wire = Some(
                canonical(&command, CanonicalPath::COMMAND)
                    .map_err(|_| RecipientEnrollmentError::Invalid)?,
            );
            document.registration_command_id = Some(command_id);
            save(&store, &document)?;
        }
        let command_id = document
            .registration_command_id
            .as_deref()
            .ok_or(RecipientEnrollmentError::Invalid)?;
        let command_wire = document
            .registration_command_wire
            .as_deref()
            .ok_or(RecipientEnrollmentError::Invalid)?;
        let parsed: Value =
            serde_json::from_str(command_wire).map_err(|_| RecipientEnrollmentError::Invalid)?;
        validate_registration_command(
            &parsed,
            command_wire,
            command_id,
            &identity,
            client.discovery().audience_utf16(),
        )?;
        if client
            .status(command_id, identity.key_id())
            .map_err(map_kernel)?
            .is_none()
        {
            client
                .prepare_command(&identity, command_wire.as_bytes(), None)
                .map_err(map_kernel)?;
        }
        if !matches!(
            client
                .status(command_id, identity.key_id())
                .map_err(map_kernel)?,
            Some(KernelOperationStatus::Accepted(_))
        ) {
            match client
                .submit_saved(command_id, identity.key_id(), cancel)
                .await
            {
                Ok(_) => {}
                Err(KernelClientError::Transport(
                    TransportError::SubmittedUncertain
                    | TransportError::Cancelled
                    | TransportError::Timeout
                    | TransportError::Network,
                )) => {
                    return Ok(result(
                        "REGISTRATION_PENDING",
                        &identity,
                        recipient.certificate(),
                        &digest,
                        Some(command_id),
                        document.directory_entry_hash.as_deref(),
                    ))
                }
                Err(error) => return Err(map_kernel(error)),
            }
        }
        let path = format!("{DIRECTORY_PATH}/{}", identity.actor_id());
        let authority = sha256_hex(identity.actor_id().as_bytes());
        let before = get_directory(&client, &identity, &path, &authority, cancel).await?;
        if let Some(head) = existing_head(&before, &identity, &recipient, &document, now_ms()?)? {
            document.published_head = Some(head.clone());
            save(&store, &document)?;
            return Ok(result(
                "PUBLISHED",
                &identity,
                recipient.certificate(),
                &digest,
                Some(command_id),
                Some(&head),
            ));
        }
        if document.directory_entry_wire.is_none() {
            let payload = json!({"v":1,"actor_id":identity.actor_id(),"signing_key":identity.key_id(),"version":1,"previous":null,"certificate":recipient.certificate(),"issued_at":now_ms()?});
            let signature = sign_canonical(DIRECTORY_DOMAIN, &payload, identity.signing_key())
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            let entry = json!({"payload":payload,"signature":signature});
            let entry_wire = canonical(&entry, CanonicalPath::SecureArtifact)
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            let hash = sha256_hex(entry_wire.as_bytes());
            let request = canonical(&json!({"entry":entry}), CanonicalPath::SecureArtifact)
                .map_err(|_| RecipientEnrollmentError::Invalid)?;
            if request.len() > 8192 {
                return Err(RecipientEnrollmentError::Invalid);
            }
            document.directory_entry_wire = Some(entry_wire);
            document.directory_request_wire = Some(request);
            document.directory_entry_hash = Some(hash);
            save(&store, &document)?;
        }
        let entry_wire = document
            .directory_entry_wire
            .as_deref()
            .ok_or(RecipientEnrollmentError::Invalid)?;
        verify_entry(entry_wire, &identity, &recipient, now_ms()?)?;
        if document.directory_entry_hash.as_deref()
            != Some(sha256_hex(entry_wire.as_bytes()).as_str())
        {
            return Err(RecipientEnrollmentError::Invalid);
        }
        let request = document
            .directory_request_wire
            .as_deref()
            .ok_or(RecipientEnrollmentError::Invalid)?;
        let expected_request: Value =
            serde_json::from_str(request).map_err(|_| RecipientEnrollmentError::Invalid)?;
        if canonical(&expected_request, CanonicalPath::SecureArtifact)
            .map_err(|_| RecipientEnrollmentError::Invalid)?
            != request
            || expected_request.get("entry")
                != Some(
                    &serde_json::from_str::<Value>(entry_wire)
                        .map_err(|_| RecipientEnrollmentError::Invalid)?,
                )
        {
            return Err(RecipientEnrollmentError::Invalid);
        }
        let proof = sign_read_proof(DIRECTORY_PATH, client.discovery(), &identity, &authority)
            .map_err(|_| RecipientEnrollmentError::Transport)?;
        match client
            .transport()
            .post_secure_identity_key_exact(request.as_bytes().to_vec(), &proof, cancel)
            .await
        {
            Ok(response) if (200..300).contains(&response.status) => {}
            Ok(response) => return Err(RecipientEnrollmentError::ServerRejected(response.status)),
            Err(TransportError::SubmittedUncertain) => {
                return Ok(result(
                    "PUBLICATION_PENDING",
                    &identity,
                    recipient.certificate(),
                    &digest,
                    Some(command_id),
                    document.directory_entry_hash.as_deref(),
                ))
            }
            Err(_) => return Err(RecipientEnrollmentError::Transport),
        }
        let after = get_directory(&client, &identity, &path, &authority, cancel).await?;
        let head = existing_head(&after, &identity, &recipient, &document, now_ms()?)?
            .ok_or(RecipientEnrollmentError::DirectoryContinuity)?;
        document.published_head = Some(head.clone());
        save(&store, &document)?;
        Ok(result(
            "PUBLISHED",
            &identity,
            recipient.certificate(),
            &digest,
            Some(command_id),
            Some(&head),
        ))
    }
}

fn ensure_private_parent(path: &Path) -> Result<(), RecipientEnrollmentError> {
    if !path.is_absolute() {
        return Err(RecipientEnrollmentError::Local);
    }
    let parent = path.parent().ok_or(RecipientEnrollmentError::Local)?;
    #[cfg(windows)]
    {
        crate::windows_fs::create_private_directory(parent)
            .map_err(|_| RecipientEnrollmentError::Local)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(parent) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(RecipientEnrollmentError::Local),
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(RecipientEnrollmentError::Local);
    Ok(())
}

fn save(
    store: &SecureStateStore,
    document: &EnrollmentDocument,
) -> Result<(), RecipientEnrollmentError> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(document).map_err(|_| RecipientEnrollmentError::Invalid)?,
    );
    if bytes.len() > 512 * 1024 {
        return Err(RecipientEnrollmentError::Invalid);
    }
    store
        .write_exact(&bytes)
        .map_err(|_| RecipientEnrollmentError::Local)
}

fn now_ms() -> Result<u64, RecipientEnrollmentError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RecipientEnrollmentError::ClockOrEntropy)?
        .as_millis();
    u64::try_from(ms)
        .ok()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or(RecipientEnrollmentError::ClockOrEntropy)
}

fn certificate_digest(cert: &RecipientCertificate) -> Result<String, RecipientEnrollmentError> {
    let wire = canonical(
        &serde_json::to_value(cert).map_err(|_| RecipientEnrollmentError::Invalid)?,
        CanonicalPath::SecureArtifact,
    )
    .map_err(|_| RecipientEnrollmentError::Invalid)?;
    Ok(sha256_hex(wire.as_bytes()))
}

fn canonical_certificate(cert: &RecipientCertificate) -> Result<String, RecipientEnrollmentError> {
    canonical(
        &serde_json::to_value(cert).map_err(|_| RecipientEnrollmentError::Invalid)?,
        CanonicalPath::SecureArtifact,
    )
    .map_err(|_| RecipientEnrollmentError::Invalid)
}

fn valid_token_or_hash(value: &str, token: bool) -> bool {
    if token {
        value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    } else {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    }
}

fn update_result(update: &PendingKeyUpdate, status: &str) -> RecipientKeyUpdateResult {
    let entry: Value = serde_json::from_str(&update.entry_wire).unwrap_or(Value::Null);
    RecipientKeyUpdateResult {
        status: status.into(),
        update_id: update.update_id.clone(),
        mode: update.mode.clone(),
        previous_certificate_hash: update.previous_certificate_hash.clone(),
        certificate_digest: update.certificate_digest.clone(),
        directory_version: entry["payload"]["version"].as_u64().unwrap_or(0) as usize,
        directory_head: update.entry_hash.clone(),
    }
}

fn validate_saved_update(
    update: &PendingKeyUpdate,
    identity: &KernelIdentity,
) -> Result<
    (
        peerwork_core::secure_recipient::SecretRecipient,
        RecipientCertificate,
        usize,
        String,
    ),
    RecipientEnrollmentError,
> {
    if !valid_token_or_hash(&update.update_id, true)
        || !valid_token_or_hash(&update.previous_certificate_hash, false)
        || !valid_token_or_hash(&update.entry_hash, false)
        || !matches!(update.mode.as_str(), "RENEW" | "ROTATE")
        || update.request_wire.len() > 8192
        || update.private_key_b64.is_empty()
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    let decoded = Zeroizing::new(
        decode_base64url(&update.private_key_b64).map_err(|_| RecipientEnrollmentError::Invalid)?,
    );
    if decoded.len() != 32 {
        return Err(RecipientEnrollmentError::Invalid);
    }
    let mut private = Zeroizing::new([0u8; 32]);
    private.copy_from_slice(&decoded);
    let recipient = peerwork_core::secure_recipient::SecretRecipient::from_private(private)
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    if sha256_hex(update.entry_wire.as_bytes()) != update.entry_hash
        || !verify_secure_signed_wire(
            update.entry_wire.as_bytes(),
            DIRECTORY_DOMAIN,
            identity.key_id(),
        )
        .map_err(|_| RecipientEnrollmentError::Invalid)?
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    let entry: Value =
        serde_json::from_str(&update.entry_wire).map_err(|_| RecipientEnrollmentError::Invalid)?;
    let payload = &entry["payload"];
    let version = payload["version"]
        .as_u64()
        .ok_or(RecipientEnrollmentError::Invalid)? as usize;
    let previous = payload["previous"]
        .as_str()
        .ok_or(RecipientEnrollmentError::Invalid)?
        .to_owned();
    let cert: RecipientCertificate = serde_json::from_value(payload["certificate"].clone())
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    let at = payload["issued_at"]
        .as_u64()
        .ok_or(RecipientEnrollmentError::Invalid)?;
    if version < 2
        || version > 128
        || payload["v"].as_u64() != Some(1)
        || payload["actor_id"].as_str() != Some(identity.actor_id())
        || payload["signing_key"].as_str() != Some(identity.key_id())
        || certificate_digest(&cert)? != update.certificate_digest
        || recipient
            .verify_local_certificate(&cert, identity.actor_id(), identity.key_id(), at)
            .is_err()
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    let expected = canonical(&json!({"entry":entry}), CanonicalPath::SecureArtifact)
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    if expected != update.request_wire {
        return Err(RecipientEnrollmentError::Invalid);
    }
    Ok((recipient, cert, version, previous))
}

fn result(
    status: &str,
    identity: &KernelIdentity,
    cert: &RecipientCertificate,
    digest: &str,
    command: Option<&str>,
    head: Option<&str>,
) -> RecipientEnrollmentResult {
    RecipientEnrollmentResult {
        status: status.into(),
        actor_id: identity.actor_id().into(),
        signing_key_id: identity.key_id().into(),
        encryption_key_id: cert.payload["encryption_key_id"]
            .as_str()
            .unwrap_or_default()
            .into(),
        certificate_digest: digest.into(),
        registration_command_id: command.map(str::to_owned),
        directory_entry_hash: head.map(str::to_owned),
    }
}

fn directory_or_cancel(cancel: &CancellationToken) -> RecipientEnrollmentError {
    if cancel.is_cancelled() {
        RecipientEnrollmentError::Cancelled
    } else {
        RecipientEnrollmentError::DirectoryContinuity
    }
}

fn map_kernel(error: KernelClientError) -> RecipientEnrollmentError {
    match error {
        KernelClientError::Transport(error) => match error {
            TransportError::InvalidOrigin | TransportError::InvalidTrust | TransportError::Setup =>
                RecipientEnrollmentError::TransportConfiguration,
            TransportError::Cancelled => RecipientEnrollmentError::Cancelled,
            TransportError::Redirect | TransportError::ResponseTooLarge =>
                RecipientEnrollmentError::Verification,
            TransportError::Network | TransportError::Timeout | TransportError::SubmittedUncertain =>
                RecipientEnrollmentError::Transport,
        },
        KernelClientError::ServerRejected(status) => {
            RecipientEnrollmentError::ServerRejected(status)
        }
        KernelClientError::DiscoveryStatus => RecipientEnrollmentError::DiscoveryStatus,
        KernelClientError::UnsupportedDiscovery | KernelClientError::InvalidResult
            | KernelClientError::InvalidCommand => RecipientEnrollmentError::Verification,
        KernelClientError::Store(JournalError::DiscoveryChanged) => RecipientEnrollmentError::Identity,
        KernelClientError::Store(JournalError::InvalidReceipt) => RecipientEnrollmentError::Verification,
        KernelClientError::Store(JournalError::InvalidIntent | JournalError::IntentConflict)
            | KernelClientError::IntentNotFound | KernelClientError::Migration(_) => RecipientEnrollmentError::Invalid,
        KernelClientError::Store(_) => RecipientEnrollmentError::Local,
    }
}

fn validate_registration_command(
    command: &Value,
    wire: &str,
    command_id: &str,
    identity: &KernelIdentity,
    audience_utf16: &[u16],
) -> Result<(), RecipientEnrollmentError> {
    let object = command
        .as_object()
        .ok_or(RecipientEnrollmentError::Invalid)?;
    let audience =
        String::from_utf16(audience_utf16).map_err(|_| RecipientEnrollmentError::Invalid)?;
    let issued = command["issued_at"]
        .as_u64()
        .ok_or(RecipientEnrollmentError::Invalid)?;
    if object.len() != 17
        || command["v"].as_u64() != Some(1)
        || command["audience"].as_str() != Some(&audience)
        || command["command_id"].as_str() != Some(command_id)
        || command["actor_id"].as_str() != Some(identity.actor_id())
        || command["authority"].as_str()
            != Some(sha256_hex(identity.actor_id().as_bytes()).as_str())
        || command["method"].as_str() != Some("POST")
        || command["path"].as_str() != Some("/api/workspace/v1/commands")
        || command["action_id"].as_str() != Some("identity.register")
        || !command["workspace_id"].is_null()
        || !command["instance_id"].is_null()
        || !command["protocol_digest"].is_null()
        || !command["expected_workspace_revision"].is_null()
        || !command["expected_instance_revision"].is_null()
        || command["exact_input_refs"]
            .as_array()
            .is_none_or(|refs| !refs.is_empty())
        || command["body"]
            .as_object()
            .is_none_or(|body| !body.is_empty())
        || command["expires_at"].as_u64() != issued.checked_add(600_000)
        || canonical(command, CanonicalPath::COMMAND)
            .map_err(|_| RecipientEnrollmentError::Invalid)?
            != wire
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    Ok(())
}

async fn get_directory(
    client: &KernelClient,
    identity: &KernelIdentity,
    path: &str,
    authority: &str,
    cancel: &CancellationToken,
) -> Result<Value, RecipientEnrollmentError> {
    let proof = sign_read_proof(path, client.discovery(), identity, authority)
        .map_err(|_| RecipientEnrollmentError::Transport)?;
    let response = client
        .transport()
        .get_secure_identity_keys_exact(path, &proof, cancel)
        .await
        .map_err(|_| RecipientEnrollmentError::Transport)?;
    if !(200..300).contains(&response.status) {
        return Err(RecipientEnrollmentError::ServerRejected(response.status));
    }
    let parsed = parse_wire_json_js_bounded(&response.wire, 32, 64 * 1024)
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    let canonical = canonical_wire_value(&parsed, CanonicalPath::SecureArtifact)
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    serde_json::from_str(&canonical).map_err(|_| RecipientEnrollmentError::Invalid)
}

fn existing_head(
    directory: &Value,
    identity: &KernelIdentity,
    recipient: &RecipientState,
    saved: &EnrollmentDocument,
    now: u64,
) -> Result<Option<String>, RecipientEnrollmentError> {
    let object = directory
        .as_object()
        .ok_or(RecipientEnrollmentError::Invalid)?;
    if object.len() != 2 || directory["actor_id"].as_str() != Some(identity.actor_id()) {
        return Err(RecipientEnrollmentError::DirectoryContinuity);
    }
    let entries = directory["entries"]
        .as_array()
        .ok_or(RecipientEnrollmentError::Invalid)?;
    if entries.is_empty() {
        if saved.published_head.is_some() {
            return Err(RecipientEnrollmentError::DirectoryContinuity);
        }
        return Ok(None);
    }
    // Rotation and more than one entry remain a separate source-valid family.
    if entries.len() != 1 {
        return Err(RecipientEnrollmentError::DirectoryContinuity);
    }
    let wire = canonical(&entries[0], CanonicalPath::SecureArtifact)
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    verify_entry(&wire, identity, recipient, now)?;
    let hash = sha256_hex(wire.as_bytes());
    if saved
        .published_head
        .as_deref()
        .is_some_and(|head| head != hash)
        || saved
            .directory_entry_hash
            .as_deref()
            .is_some_and(|head| head != hash)
    {
        return Err(RecipientEnrollmentError::DirectoryContinuity);
    }
    Ok(Some(hash))
}

fn verify_entry(
    wire: &str,
    identity: &KernelIdentity,
    recipient: &RecipientState,
    now: u64,
) -> Result<(), RecipientEnrollmentError> {
    if !verify_secure_signed_wire(wire.as_bytes(), DIRECTORY_DOMAIN, identity.key_id())
        .map_err(|_| RecipientEnrollmentError::Invalid)?
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    let entry: Value = serde_json::from_str(wire).map_err(|_| RecipientEnrollmentError::Invalid)?;
    let outer = entry.as_object().ok_or(RecipientEnrollmentError::Invalid)?;
    let p = entry
        .get("payload")
        .ok_or(RecipientEnrollmentError::Invalid)?;
    let payload = p.as_object().ok_or(RecipientEnrollmentError::Invalid)?;
    if outer.len() != 2
        || !outer.contains_key("signature")
        || payload.len() != 7
        || p["v"].as_u64() != Some(1)
        || p["actor_id"].as_str() != Some(identity.actor_id())
        || p["signing_key"].as_str() != Some(identity.key_id())
        || p["version"].as_u64() != Some(1)
        || !p["previous"].is_null()
        || p["issued_at"].as_u64().is_none_or(|issued| issued > now)
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    let cert: RecipientCertificate = serde_json::from_value(p["certificate"].clone())
        .map_err(|_| RecipientEnrollmentError::Invalid)?;
    let issued = cert.payload["issued_at"]
        .as_u64()
        .ok_or(RecipientEnrollmentError::Invalid)?;
    if recipient
        .recipient_for_certificate(&cert)
        .map_err(|_| RecipientEnrollmentError::Invalid)?
        .verify_local_certificate(&cert, identity.actor_id(), identity.key_id(), issued)
        .is_err()
    {
        return Err(RecipientEnrollmentError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn enrollment_kernel_causes_are_typed_without_sensitive_error_details() {
        let cases = [
            (KernelClientError::Transport(TransportError::Network), "TRANSPORT_FAILED"),
            (KernelClientError::Transport(TransportError::Timeout), "TRANSPORT_FAILED"),
            (KernelClientError::Transport(TransportError::InvalidOrigin), "TRANSPORT_CONFIGURATION_INVALID"),
            (KernelClientError::Transport(TransportError::InvalidTrust), "TRANSPORT_CONFIGURATION_INVALID"),
            (KernelClientError::Transport(TransportError::Cancelled), "CANCELLED"),
            (KernelClientError::Transport(TransportError::Redirect), "VERIFICATION_FAILED"),
            (KernelClientError::DiscoveryStatus, "DISCOVERY_FAILED"),
            (KernelClientError::UnsupportedDiscovery, "VERIFICATION_FAILED"),
            (KernelClientError::InvalidResult, "VERIFICATION_FAILED"),
            (KernelClientError::ServerRejected(403), "SERVER_REJECTED"),
            (KernelClientError::Store(JournalError::DiscoveryChanged), "IDENTITY_CHANGED"),
            (KernelClientError::Store(JournalError::InvalidReceipt), "VERIFICATION_FAILED"),
            (KernelClientError::Store(JournalError::Io(std::io::Error::other(
                "http://private-user:private-secret@private-host/private-path"))), "LOCAL_STATE_FAILED"),
        ];
        for (cause, expected) in cases {
            let mapped = map_kernel(cause);
            assert_eq!(mapped.code(), expected);
            for word in ["private-user", "private-secret", "private-host", "private-path"] {
                assert!(!mapped.to_string().contains(word));
                assert!(!format!("{mapped:?}").contains(word));
            }
        }
        let route = RecipientEnrollmentError::Transport.to_string();
        assert!(route.contains("PEERWORK_HTTP_PROXY"));
        assert!(route.contains("ignored"));
        assert!(route.contains("keep the selected identity"));
    }

    #[test]
    fn actual_service_native_recipient_cold_start_and_exact_recovery() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", temp.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "reference service failed to start");
        let ready: Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let recipient_dir = temp.path().join("native-recipient");
        let mut config = RecipientEnrollmentConfig::for_state_dir(origin.clone(), &recipient_dir);
        config.allow_loopback_http = true;
        let enrollment = SecureRecipientEnrollment::new(config.clone());
        let local = enrollment.create_local().unwrap();
        assert_eq!(local.status, "LOCAL");
        assert!(local.registration_command_id.is_none());
        let first = enrollment.publish().unwrap();
        assert_eq!(first.status, "REGISTRATION_PENDING");
        let saved_command = first.registration_command_id.clone().unwrap();
        assert_eq!(
            SecureRecipientEnrollment::new(config.clone())
                .pending()
                .unwrap()
                .unwrap()
                .status,
            "REGISTRATION_PENDING"
        );
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-identity-directory"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let second = SecureRecipientEnrollment::new(config.clone())
            .publish()
            .unwrap();
        assert_eq!(second.status, "PUBLICATION_PENDING");
        assert_eq!(
            SecureRecipientEnrollment::new(config.clone())
                .pending()
                .unwrap()
                .unwrap()
                .status,
            "PUBLICATION_PENDING"
        );
        assert_eq!(
            second.registration_command_id.as_deref(),
            Some(saved_command.as_str())
        );
        let saved_entry_hash = second.directory_entry_hash.clone().unwrap();
        let saved = SecureStateStore::open(&config.enrollment_state_path).unwrap();
        let before = saved.read_exact().unwrap().unwrap();
        drop(saved);
        let final_result = SecureRecipientEnrollment::new(config.clone())
            .publish()
            .unwrap();
        assert_eq!(final_result.status, "PUBLISHED");
        assert_eq!(
            final_result.directory_entry_hash.as_deref(),
            Some(saved_entry_hash.as_str())
        );
        assert_eq!(
            final_result.registration_command_id.as_deref(),
            Some(saved_command.as_str())
        );
        assert_eq!(final_result.actor_id, local.actor_id);
        let saved = SecureStateStore::open(&config.enrollment_state_path).unwrap();
        let after = saved.read_exact().unwrap().unwrap();
        drop(saved);
        let old: EnrollmentDocument = serde_json::from_slice(&before).unwrap();
        let new: EnrollmentDocument = serde_json::from_slice(&after).unwrap();
        assert_eq!(old.registration_command_wire, new.registration_command_wire);
        assert_eq!(old.directory_request_wire, new.directory_request_wire);
        let repeated = SecureRecipientEnrollment::new(config.clone())
            .publish()
            .unwrap();
        assert_eq!(repeated, final_result);
        // The tracked TS fixture creates only the owner workspace. Native
        // Ed/P-256 recipient creation and directory publication now feed the
        // actual PUBLIC offer, consent, delivery and receipt path.
        let owner_path = temp.path().join("native-owner.identity");
        let owner = KernelIdentity::import_pkcs8_pem_file(
            &owner_path,
            &temp.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        let workspace = ready["public_read"]["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner_config = crate::secure_read_profile::SecureReadProfileConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: temp.path().join("native-owner-profile"),
            identity_path: owner_path,
            workspace_id: workspace.clone(),
            owner_actor_id: Some(owner.actor_id().into()),
            owner_key_id: Some(owner.key_id().into()),
            authority: Some(ready["public_read"]["authority"].as_str().unwrap().into()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        crate::secure_read_profile::SecureReadProfile::new(owner_config.clone())
            .read_latest_json()
            .unwrap();
        let recipient_identity = KernelIdentity::open(&enrollment.config.identity_path).unwrap();
        let certificate_json = enrollment.certificate_json().unwrap();
        let exported: RecipientCertificate = serde_json::from_str(&certificate_json).unwrap();
        assert_eq!(
            certificate_digest(&exported).unwrap(),
            local.certificate_digest
        );
        let offer: crate::secure_public_admission::PublicOfferResult = serde_json::from_str(
            &crate::secure_public_admission::SecurePublicAdmission::new(owner_config.clone())
                .submit_offer_json(crate::secure_public_admission::PublicOfferInput {
                    recipient_certificate_json: certificate_json,
                    scopes_json: "[]".into(),
                    message: "Native cold-start recipient".into(),
                    message_utf16: None,
                    invite_id: None,
                    issued_at_ms: None,
                    expires_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let decision_config = crate::secure_public_decision::PublicDecisionConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: recipient_dir,
            identity_path: enrollment.config.identity_path.clone(),
            workspace_id: workspace.clone(),
            owner_actor_id: owner.actor_id().into(),
            owner_key_id: owner.key_id().into(),
            authority: sha256_hex(recipient_identity.actor_id().as_bytes()),
            allow_loopback_http: true,
            required_features: vec![],
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let decision =
            crate::secure_public_decision::SecurePublicDecision::new(decision_config.clone());
        let accepted: crate::secure_public_decision::PublicDecisionResult =
            serde_json::from_str(&decision.decide_json(&offer.invite_id, "ACCEPT").unwrap())
                .unwrap();
        assert_eq!(accepted.status, "PENDING");
        let delivery: crate::secure_public_admission::PublicDeliveryResult = serde_json::from_str(
            &crate::secure_public_admission::SecurePublicAdmission::new(owner_config)
                .deliver_accepted_json(&offer.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(delivery.status, "PENDING");
        let receipt: crate::secure_public_decision::PublicReceiveResult = serde_json::from_str(
            &crate::secure_public_decision::SecurePublicDecision::new(decision_config.clone())
                .receive_json(&offer.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.status, "PENDING");
        let ready_receipt: crate::secure_public_decision::PublicReceiveResult =
            serde_json::from_str(
                &crate::secure_public_decision::SecurePublicDecision::new(decision_config)
                    .retry_receive_json(&offer.invite_id)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(ready_receipt.status, "READY");
        let original_certificate =
            RecipientState::open(&config.recipient_path, &recipient_identity)
                .unwrap()
                .certificate()
                .clone();
        let pre_cancel = CancellationToken::new();
        pre_cancel.cancel();
        assert!(matches!(
            enrollment.update_key_with_cancel(
                "ROTATE",
                &local.certificate_digest,
                None,
                &pre_cancel
            ),
            Err(RecipientEnrollmentError::Cancelled)
        ));
        assert!(enrollment.pending_key_updates().unwrap().is_empty());
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/delay-next-identity-directory-post"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let cancel = CancellationToken::new();
        let observed_cancel = cancel.clone();
        let observed_origin = origin.clone();
        let observer = std::thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async move {
                for _ in 0..100 {
                    let response = reqwest::Client::new()
                        .get(format!(
                            "{observed_origin}__test/identity-directory-post-delay-status"
                        ))
                        .send()
                        .await
                        .unwrap();
                    let body: serde_json::Value =
                        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
                    if body["applied"] == true {
                        observed_cancel.cancel();
                        return true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                }
                false
            })
        });
        let pending_rotation = enrollment
            .update_key_with_cancel("ROTATE", &local.certificate_digest, None, &cancel)
            .unwrap();
        assert!(
            observer.join().unwrap(),
            "tracked directory POST was not applied"
        );
        assert_eq!(pending_rotation.status, "PENDING");
        assert_eq!(pending_rotation.directory_version, 2);
        assert_eq!(enrollment.pending_key_updates().unwrap().len(), 1);
        assert_eq!(
            enrollment.pending_key_updates().unwrap()[0].update_id,
            pending_rotation.update_id
        );
        assert_eq!(enrollment.key_updates().unwrap()[0].status, "PENDING");
        let recovered_rotation = SecureRecipientEnrollment::new(config.clone())
            .retry_key_update(&pending_rotation.update_id)
            .unwrap();
        assert_eq!(recovered_rotation.status, "PUBLISHED");
        assert!(enrollment.pending_key_updates().unwrap().is_empty());
        assert_eq!(
            enrollment.key_updates().unwrap()[0].update_id,
            pending_rotation.update_id
        );
        assert_eq!(enrollment.key_updates().unwrap()[0].status, "PUBLISHED");
        assert_eq!(
            recovered_rotation.directory_head,
            pending_rotation.directory_head
        );
        let reopened = RecipientState::open(&config.recipient_path, &recipient_identity).unwrap();
        assert_eq!(
            certificate_digest(reopened.certificate()).unwrap(),
            recovered_rotation.certificate_digest
        );
        reopened
            .recipient_for_certificate(&original_certificate)
            .unwrap();
        drop(reopened);
        let renewed = enrollment
            .update_key("RENEW", &recovered_rotation.certificate_digest, None)
            .unwrap();
        let renewed = if renewed.status == "PENDING" {
            enrollment.retry_key_update(&renewed.update_id).unwrap()
        } else {
            renewed
        };
        assert_eq!(renewed.status, "PUBLISHED");
        assert_eq!(renewed.directory_version, 3);
        assert_ne!(
            renewed.certificate_digest,
            recovered_rotation.certificate_digest
        );
        assert_eq!(enrollment.publish().unwrap().status, "PUBLISHED");
        let reopened = RecipientState::open(&config.recipient_path, &recipient_identity).unwrap();
        reopened
            .recipient_for_certificate(&original_certificate)
            .unwrap();
        let _ = child.0.kill();
        drop(reopened);
        assert_eq!(
            enrollment.pending().unwrap().unwrap().status,
            "PUBLISHED_LOCAL"
        );
    }
}
