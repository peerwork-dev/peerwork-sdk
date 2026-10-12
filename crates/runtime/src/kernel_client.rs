//! HTTPS discovery with exact schema and durable origin/authority continuity.
//! Kernel command submission remains internal until verified outcome recovery
//! is persisted; this type currently supports discovery and pending listing.

use crate::{
    kernel_identity::KernelIdentity,
    kernel_intents::{
        JournalError, KernelIntentJournal, KernelPath, PendingKernelIntent, VerifiedPendingCommand,
    },
    transport::{HttpTransport, TransportConfig, TransportError, MAX_DISCOVERY_BYTES},
};
use peerwork_core::discovery::{parse_discovery_wire, ParsedDiscovery};
use peerwork_core::prepared_command::prepare_signed_command_wire;
use peerwork_core::prepared_command::VerifiedPreparedCommand;
use peerwork_core::receipt_wire::{verify_http_response_for_prepared, VerifiedCommandResponse};
use peerwork_core::wire_json::{parse_wire_json_bounded, WireValue};
use serde::Serialize;
use std::path::Path;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum KernelClientError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Store(#[from] JournalError),
    #[error(transparent)]
    Migration(#[from] crate::ts_migration::TsMigrationError),
    #[error("discovery HTTP status is not successful")]
    DiscoveryStatus,
    #[error("discovery schema or required features are unsupported")]
    UnsupportedDiscovery,
    #[error("saved command id was not found")]
    IntentNotFound,
    #[error("server rejected the saved command with HTTP {0}")]
    ServerRejected(u16),
    #[error("verified result has an unsupported public summary shape")]
    InvalidResult,
    #[error("command does not match pinned discovery, local identity, or supported signed shape")]
    InvalidCommand,
}

pub enum KernelOperationStatus {
    Pending,
    Accepted(KernelAcceptedResult),
}

/// Audited public fields of a command-bound, signed result. Arbitrary result
/// content, signed packets, identity material and private state stay internal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelAcceptedResult {
    pub command_id: String,
    pub workspace_id: Option<String>,
    pub protocol_digest: Option<String>,
    pub instance_id: Option<String>,
    pub event_sequence: Option<u64>,
    pub revision: Option<u64>,
    pub produced_record_ids: Vec<String>,
    pub catalog: Option<CatalogAcceptedResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogAcceptedResult {
    NamespaceClaim {
        namespace: String,
    },
    UploadBegin {
        upload_id: String,
        state: String,
        expires_at: u64,
    },
    UploadChunk {
        upload_id: String,
        index: u64,
        received_bytes: u64,
        state: String,
    },
    PackagePublish {
        namespace: String,
        package_id: String,
        version: String,
        bundle_digest: String,
        published: u64,
    },
}

impl KernelAcceptedResult {
    fn from_verified(
        proof: VerifiedCommandResponse,
        prepared: &VerifiedPreparedCommand,
        catalog_begin: Option<(u64, u64)>,
    ) -> Result<Self, KernelClientError> {
        let result = parse_wire_json_bounded(
            proof.result_canonical_json().as_bytes(),
            12,
            32 * 1024 * 1024,
        )
        .map_err(|_| KernelClientError::InvalidResult)?;
        let optional_token = |field: &str| -> Result<Option<String>, KernelClientError> {
            match result.get(field) {
                None | Some(WireValue::Null) => Ok(None),
                Some(WireValue::String(_)) => result
                    .get(field)
                    .and_then(WireValue::as_string)
                    .filter(|value| valid_token(value))
                    .map(Some)
                    .ok_or(KernelClientError::InvalidResult),
                _ => Err(KernelClientError::InvalidResult),
            }
        };
        let instance_id = optional_token("instance_id")?;
        let revision = match result.get("revision") {
            None | Some(WireValue::Null) => None,
            Some(WireValue::Number(number))
                if number.is_finite()
                    && *number >= 0.0
                    && *number <= 9_007_199_254_740_991.0
                    && number.fract() == 0.0 =>
            {
                Some(*number as u64)
            }
            _ => return Err(KernelClientError::InvalidResult),
        };
        if revision != proof.instance_revision() && proof.instance_revision().is_some() {
            return Err(KernelClientError::InvalidResult);
        }
        let produced_record_ids = match result.get("produced_record_ids") {
            None => Vec::new(),
            Some(WireValue::Array(values)) if values.len() <= 1024 => values
                .iter()
                .map(|value| {
                    value
                        .as_string()
                        .filter(|id| valid_token(id))
                        .ok_or(KernelClientError::InvalidResult)
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(KernelClientError::InvalidResult),
        };
        let command =
            parse_wire_json_bounded(prepared.command_canonical_json().as_bytes(), 40, 180_000)
                .map_err(|_| KernelClientError::InvalidResult)?;
        let action = required_text(&command, "action_id")?;
        let body = command
            .get("body")
            .ok_or(KernelClientError::InvalidResult)?;
        let catalog = match action.as_str() {
            "catalog.namespace.claim" => {
                let namespace = required_text(&result, "namespace")?;
                require_equal(&namespace, &required_text(body, "namespace")?)?;
                require_equal(&namespace, prepared.actor_id())?;
                require_equal(
                    &required_text(&result, "owner_actor_id")?,
                    prepared.actor_id(),
                )?;
                Some(CatalogAcceptedResult::NamespaceClaim { namespace })
            }
            "catalog.upload.begin" => {
                let upload_id = required_text(&result, "upload_id")?;
                require_equal(&upload_id, &required_text(body, "upload_id")?)?;
                require_equal(&required_text(&result, "state")?, "STAGING")?;
                Some(CatalogAcceptedResult::UploadBegin {
                    upload_id,
                    state: "STAGING".into(),
                    expires_at: required_u64(&result, "expires_at")?,
                })
            }
            "catalog.upload.chunk" => {
                let upload_id = required_text(&result, "upload_id")?;
                require_equal(&upload_id, &required_text(body, "upload_id")?)?;
                let index = required_u64(&result, "index")?;
                if index != required_u64(body, "index")? {
                    return Err(KernelClientError::InvalidResult);
                }
                let received_bytes = required_u64(&result, "received_bytes")?;
                if received_bytes
                    != required_u64(body, "offset")?
                        .checked_add(required_u64(body, "byte_length")?)
                        .ok_or(KernelClientError::InvalidResult)?
                {
                    return Err(KernelClientError::InvalidResult);
                }
                let state = required_text(&result, "state")?;
                let (total_bytes, chunk_count) =
                    catalog_begin.ok_or(KernelClientError::InvalidResult)?;
                let next_index = index
                    .checked_add(1)
                    .ok_or(KernelClientError::InvalidResult)?;
                let expected_state = if next_index == chunk_count && received_bytes == total_bytes {
                    "READY"
                } else if next_index < chunk_count && received_bytes < total_bytes {
                    "STAGING"
                } else {
                    return Err(KernelClientError::InvalidResult);
                };
                if state != expected_state {
                    return Err(KernelClientError::InvalidResult);
                }
                Some(CatalogAcceptedResult::UploadChunk {
                    upload_id,
                    index,
                    received_bytes,
                    state,
                })
            }
            "catalog.package.publish" => {
                let namespace = required_text(&result, "namespace")?;
                require_equal(&namespace, prepared.actor_id())?;
                let package_id = required_text(&result, "package_id")?;
                require_equal(&package_id, &required_text(body, "package_id")?)?;
                let version = required_text(&result, "version")?;
                require_equal(&version, &required_text(body, "version")?)?;
                let bundle_digest = required_text(&result, "bundle_digest")?;
                require_equal(&bundle_digest, &required_text(body, "bundle_digest")?)?;
                Some(CatalogAcceptedResult::PackagePublish {
                    namespace,
                    package_id,
                    version,
                    bundle_digest,
                    published: required_u64(&result, "published")?,
                })
            }
            _ => None,
        };
        Ok(Self {
            command_id: proof.command_id().to_owned(),
            workspace_id: proof.workspace_id().map(str::to_owned),
            protocol_digest: proof.protocol_digest().map(str::to_owned),
            instance_id,
            event_sequence: proof.event_sequence(),
            revision,
            produced_record_ids,
            catalog,
        })
    }
}

fn required_text(value: &WireValue, field: &str) -> Result<String, KernelClientError> {
    value
        .get(field)
        .and_then(WireValue::as_string)
        .ok_or(KernelClientError::InvalidResult)
}

fn required_u64(value: &WireValue, field: &str) -> Result<u64, KernelClientError> {
    match value.get(field) {
        Some(WireValue::Number(n))
            if n.is_finite() && *n >= 0.0 && *n <= 9_007_199_254_740_991.0 && n.fract() == 0.0 =>
        {
            Ok(*n as u64)
        }
        _ => Err(KernelClientError::InvalidResult),
    }
}

fn require_equal(actual: &str, expected: &str) -> Result<(), KernelClientError> {
    if actual == expected {
        Ok(())
    } else {
        Err(KernelClientError::InvalidResult)
    }
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsMigrationReport {
    pub pending_count: usize,
    pub accepted_count: usize,
}

pub struct KernelClient {
    transport: HttpTransport,
    journal: KernelIntentJournal,
    discovery: ParsedDiscovery,
}

impl KernelClient {
    /// Sign one fully specified kernel command inside the shared core, then
    /// persist its exact JWS and HTTP body before any network submission.
    /// The identity's private key and signed packet never enter a public DTO.
    pub fn prepare_command(
        &mut self,
        identity: &KernelIdentity,
        command_wire: &[u8],
        upload_chunk: Option<&[u8]>,
    ) -> Result<PendingKernelIntent, KernelClientError> {
        let command = parse_wire_json_bounded(command_wire, 40, 180_000)
            .map_err(|_| KernelClientError::InvalidCommand)?;
        let signed = prepare_signed_command_wire(
            &command,
            identity.signing_key(),
            &self.discovery,
            upload_chunk,
        )
        .map_err(|_| KernelClientError::InvalidCommand)?;
        let path = match signed.proof().path() {
            "/api/workspace/v1/commands" => KernelPath::Command,
            "/api/workspace/v1/catalog/upload" => KernelPath::CatalogUpload,
            _ => return Err(KernelClientError::InvalidCommand),
        };
        self.journal
            .prepare(
                signed.proof().command_id(),
                path,
                signed.jws(),
                signed.http_body(),
            )
            .map_err(KernelClientError::Store)
    }

    /// Import a quiesced TypeScript WorkspaceClient v1 SQLite store using
    /// this client's already fetched and origin-pinned discovery. The source
    /// remains untouched; the caller must retain the checked online backup.
    pub fn migrate_ts_store(
        &mut self,
        source_path: &Path,
        backup_path: &Path,
        trusted_local_key_ids: &[String],
    ) -> Result<TsMigrationReport, KernelClientError> {
        let (pending_count, accepted_count) = self.journal.import_ts_backup(
            source_path,
            backup_path,
            trusted_local_key_ids,
            &self.discovery,
        )?;
        Ok(TsMigrationReport {
            pending_count,
            accepted_count,
        })
    }

    pub async fn open(
        transport_config: TransportConfig,
        journal_path: &Path,
        required_features: &[Vec<u16>],
        cancel: &CancellationToken,
    ) -> Result<Self, KernelClientError> {
        let transport = HttpTransport::new(transport_config)?;
        let response = transport.discovery(cancel).await?;
        if !(200..300).contains(&response.status) {
            return Err(KernelClientError::DiscoveryStatus);
        }
        let discovery = parse_discovery_wire(&response.wire, MAX_DISCOVERY_BYTES)
            .map_err(|_| KernelClientError::UnsupportedDiscovery)?;
        if !discovery.supports_required_features(required_features) {
            return Err(KernelClientError::UnsupportedDiscovery);
        }
        let mut journal = KernelIntentJournal::open(journal_path)?;
        journal.bind_discovery(transport.trusted_origin(), &discovery)?;
        Ok(Self {
            transport,
            journal,
            discovery,
        })
    }

    pub fn origin(&self) -> &str {
        self.transport.trusted_origin()
    }

    pub fn discovery(&self) -> &ParsedDiscovery {
        &self.discovery
    }

    pub fn pending(
        &self,
        local_key_id: &str,
    ) -> Result<Vec<PendingKernelIntent>, KernelClientError> {
        let mut pending = Vec::new();
        for row in self
            .journal
            .all_prepared_for_key(local_key_id, self.discovery.audience_utf16())?
        {
            match self.status(&row.command_id, local_key_id)? {
                Some(KernelOperationStatus::Pending) => pending.push(row),
                Some(KernelOperationStatus::Accepted(_)) => {}
                None => return Err(KernelClientError::IntentNotFound),
            }
        }
        Ok(pending)
    }

    /// A chunk command does not carry the session's total or chunk count.
    /// Bind its public state to the separately accepted, exact signed begin
    /// command in this same durable journal before exposing or saving it.
    fn catalog_begin_context(
        &self,
        saved: &VerifiedPendingCommand,
        local_key_id: &str,
    ) -> Result<Option<(u64, u64)>, KernelClientError> {
        let command =
            parse_wire_json_bounded(saved.proof.command_canonical_json().as_bytes(), 40, 180_000)
                .map_err(|_| KernelClientError::InvalidResult)?;
        if required_text(&command, "action_id")? != "catalog.upload.chunk" {
            return Ok(None);
        }
        let body = command
            .get("body")
            .ok_or(KernelClientError::InvalidResult)?;
        let upload_id = required_text(body, "upload_id")?;
        let bundle_digest = required_text(body, "bundle_digest")?;
        let mut found = None;
        for row in self
            .journal
            .all_prepared_for_key(local_key_id, self.discovery.audience_utf16())?
        {
            let candidate = self
                .journal
                .verified_pending(
                    &row.command_id,
                    local_key_id,
                    self.discovery.audience_utf16(),
                )?
                .ok_or(KernelClientError::InvalidResult)?;
            let candidate_command = parse_wire_json_bounded(
                candidate.proof.command_canonical_json().as_bytes(),
                40,
                180_000,
            )
            .map_err(|_| KernelClientError::InvalidResult)?;
            if required_text(&candidate_command, "action_id")? != "catalog.upload.begin" {
                continue;
            }
            let candidate_body = candidate_command
                .get("body")
                .ok_or(KernelClientError::InvalidResult)?;
            if required_text(candidate_body, "upload_id")? != upload_id {
                continue;
            }
            require_equal(
                &required_text(candidate_body, "bundle_digest")?,
                &bundle_digest,
            )?;
            let Some(verified) = self
                .journal
                .accepted_response(&candidate, self.discovery.receipt_public_key())?
            else {
                continue;
            };
            if !matches!(
                KernelAcceptedResult::from_verified(verified, &candidate.proof, None)?.catalog,
                Some(CatalogAcceptedResult::UploadBegin { .. })
            ) {
                return Err(KernelClientError::InvalidResult);
            }
            let total = required_u64(candidate_body, "total_bytes")?;
            let count = required_u64(candidate_body, "chunk_count")?;
            if total == 0
                || total > 1024 * 1024
                || count == 0
                || count > 16
                || (total + 65_535) / 65_536 != count
                || found.replace((total, count)).is_some()
            {
                return Err(KernelClientError::InvalidResult);
            }
        }
        found.map(Some).ok_or(KernelClientError::InvalidResult)
    }

    /// Reads saved status after restart and re-verifies any accepted response
    /// against the exact signed request and this client's persisted authority.
    pub fn status(
        &self,
        command_id: &str,
        local_key_id: &str,
    ) -> Result<Option<KernelOperationStatus>, KernelClientError> {
        let Some(saved) = self.journal.verified_pending(
            command_id,
            local_key_id,
            self.discovery.audience_utf16(),
        )?
        else {
            return Ok(None);
        };
        match self
            .journal
            .accepted_response(&saved, self.discovery.receipt_public_key())?
        {
            Some(verified) => Ok(Some(KernelOperationStatus::Accepted(
                KernelAcceptedResult::from_verified(
                    verified,
                    &saved.proof,
                    self.catalog_begin_context(&saved, local_key_id)?,
                )?,
            ))),
            None => Ok(Some(KernelOperationStatus::Pending)),
        }
    }

    /// Sends the exact durable request. Cancellation or an unreadable reply
    /// leaves the row pending; retrying this same ID is the recovery path.
    pub async fn submit_saved(
        &mut self,
        command_id: &str,
        local_key_id: &str,
        cancel: &CancellationToken,
    ) -> Result<KernelAcceptedResult, KernelClientError> {
        let saved = self
            .journal
            .verified_pending(command_id, local_key_id, self.discovery.audience_utf16())?
            .ok_or(KernelClientError::IntentNotFound)?;
        let catalog_begin = self.catalog_begin_context(&saved, local_key_id)?;
        if let Some(verified) = self
            .journal
            .accepted_response(&saved, self.discovery.receipt_public_key())?
        {
            return KernelAcceptedResult::from_verified(verified, &saved.proof, catalog_begin);
        }
        let response = self
            .transport
            .post_exact(saved.proof.path(), saved.body.clone(), cancel)
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(KernelClientError::ServerRejected(response.status));
        }
        let proof = verify_http_response_for_prepared(
            &response.wire,
            &saved.proof,
            self.discovery.receipt_public_key(),
        )
        .map_err(|_| KernelClientError::Store(JournalError::InvalidReceipt))?;
        let public = KernelAcceptedResult::from_verified(proof, &saved.proof, catalog_begin)?;
        self.journal.record_verified_response(
            &saved,
            &response.wire,
            self.discovery.receipt_public_key(),
        )?;
        Ok(public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_intents::KernelPath;
    use ed25519_dalek::{Signer, SigningKey};
    use peerwork_core::{
        canonical::{canonical, Path as CanonicalPath},
        crypto::{actor_id, base64url, key_id, sha256_hex, sign_compact},
    };
    use serde_json::json;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[cfg(unix)]
    async fn discovery_server(bodies: Vec<Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for body in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 2048];
                let count = socket.read(&mut request).await.unwrap();
                assert!(request[..count].starts_with(b"GET /api/workspace/v1/discovery "));
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        (origin, task)
    }

    #[cfg(unix)]
    fn discovery_wire(receipt_key: &str, features: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "semantics":"peerwork.kernel.v1",
            "audience":"https://workspace.example",
            "command_type":"peerwork.kernel-command.v1+jws",
            "receipt_type":"peerwork.kernel-receipt.v1+jws",
            "receipt_public_key":receipt_key,
            "limits":{"command_bytes":262144},
            "protocol_features":features
        }))
        .unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn actual_http_discovery_pins_origin_and_refuses_receipt_key_rotation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = dir.path().join("intents.sqlite");
        let first_key = key_id(&[7; 32]);
        let changed_key = key_id(&[8; 32]);
        let first = discovery_wire(&first_key, &["base"]);
        let changed = discovery_wire(&changed_key, &["base"]);
        let added = discovery_wire(&first_key, &["base", "extra"]);
        let (origin, server) = discovery_server(vec![first.clone(), changed, added.clone()]).await;
        let mut config = TransportConfig::new(&origin);
        config.allow_loopback_http = true;
        let required = vec!["base".encode_utf16().collect()];
        let opened =
            KernelClient::open(config, &journal_path, &required, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(opened.origin(), origin);
        assert_eq!(opened.discovery().receipt_public_key(), first_key);
        drop(opened);

        let mut config = TransportConfig::new(&origin);
        config.allow_loopback_http = true;
        assert!(matches!(
            KernelClient::open(config, &journal_path, &required, &CancellationToken::new()).await,
            Err(KernelClientError::Store(JournalError::DiscoveryChanged))
        ));
        let db = rusqlite::Connection::open(&journal_path).unwrap();
        let persisted: Vec<u8> = db
            .query_row(
                "SELECT discovery_wire FROM pinned_discovery WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, first);
        drop(db);

        let mut config = TransportConfig::new(&origin);
        config.allow_loopback_http = true;
        let reopened =
            KernelClient::open(config, &journal_path, &required, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(reopened.discovery().raw_wire(), added);
        server.await.unwrap();

        let (other_origin, other_server) = discovery_server(vec![added]).await;
        let mut config = TransportConfig::new(other_origin);
        config.allow_loopback_http = true;
        assert!(matches!(
            KernelClient::open(config, &journal_path, &required, &CancellationToken::new()).await,
            Err(KernelClientError::Store(JournalError::DiscoveryChanged))
        ));
        other_server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lost_reply_and_invalid_receipt_remain_pending_until_exact_retry() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = dir.path().join("intents.sqlite");
        let signing = SigningKey::from_bytes(&[21; 32]);
        let public = signing.verifying_key().to_bytes();
        let kid = key_id(&public);
        let actor = actor_id(&public);
        let command_id = key_id(&[23; 32]);
        let header = canonical(
            &json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid}),
            CanonicalPath::SecureArtifact,
        )
        .unwrap();
        let command = json!({
            "v":1,"audience":"https://workspace.example","command_id":command_id,
            "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
            "path":"/api/workspace/v1/commands","workspace_id":null,"instance_id":null,
            "protocol_digest":null,"action_id":"catalog.namespace.claim",
            "expected_workspace_revision":null,"expected_instance_revision":null,
            "exact_input_refs":[],"body":{"namespace":actor},"issued_at":1,"expires_at":600001
        });
        let payload = canonical(&command, CanonicalPath::COMMAND).unwrap();
        let input = format!(
            "{}.{}",
            base64url(header.as_bytes()),
            base64url(payload.as_bytes())
        );
        let jws = format!(
            "{}.{}",
            input,
            base64url(&signing.sign(input.as_bytes()).to_bytes())
        );
        let body = canonical(&json!({"jws":jws}), CanonicalPath::COMMAND).unwrap();
        let result = json!({"namespace":actor,"owner_actor_id":actor});
        let result_digest = sha256_hex(
            canonical(&result, CanonicalPath::KERNEL)
                .unwrap()
                .as_bytes(),
        );
        let receipt_header =
            json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid});
        let receipt_payload = json!({
            "v":1,"audience":"https://workspace.example","actor_id":actor,"workspace_id":null,
            "command_id":command_id,"intent_digest":sha256_hex(jws.as_bytes()),
            "result_digest":result_digest,"protocol_digest":null,"event_sequence":null,
            "instance_revision":null,"accepted_at":1
        });
        let receipt = sign_compact(&receipt_header, &receipt_payload, &signing).unwrap();
        let accepted = canonical(
            &json!({"command_id":command_id,"receipt":receipt,"result":result}),
            CanonicalPath::RESPONSE,
        )
        .unwrap();
        let mismatched_result = json!({"namespace":key_id(&[99;32]),"owner_actor_id":actor});
        let mut mismatched_payload = receipt_payload.clone();
        mismatched_payload["result_digest"] = json!(sha256_hex(
            canonical(&mismatched_result, CanonicalPath::KERNEL)
                .unwrap()
                .as_bytes()
        ));
        let mismatched_receipt =
            sign_compact(&receipt_header, &mismatched_payload, &signing).unwrap();
        let mismatched = canonical(
            &json!({"command_id":command_id,"receipt":mismatched_receipt,"result":mismatched_result}),
            CanonicalPath::RESPONSE,
        )
        .unwrap();
        let invalid = b"{\"command_id\":\"wrong\",\"receipt\":\"invalid\",\"result\":{}}".to_vec();
        let discovery = discovery_wire(&kid, &[]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let saved_body = body.as_bytes().to_vec();
        let server = tokio::spawn(async move {
            for step in 0..7 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                if matches!(step, 0 | 2 | 6) {
                    assert!(request.starts_with(b"GET /api/workspace/v1/discovery "));
                    respond(&mut socket, &discovery).await;
                } else {
                    assert!(request.starts_with(b"POST /api/workspace/v1/commands "));
                    assert!(request.ends_with(&saved_body));
                    match step {
                        1 => {}
                        3 => respond(&mut socket, &invalid).await,
                        4 => respond(&mut socket, mismatched.as_bytes()).await,
                        5 => respond(&mut socket, accepted.as_bytes()).await,
                        _ => unreachable!(),
                    }
                }
            }
        });
        let config = || {
            let mut config = TransportConfig::new(&origin);
            config.allow_loopback_http = true;
            config
        };
        let mut client =
            KernelClient::open(config(), &journal_path, &[], &CancellationToken::new())
                .await
                .unwrap();
        client
            .journal
            .prepare(&command_id, KernelPath::Command, &jws, body.as_bytes())
            .unwrap();
        assert!(matches!(
            client
                .submit_saved(&command_id, &kid, &CancellationToken::new())
                .await,
            Err(KernelClientError::Transport(
                TransportError::SubmittedUncertain
            ))
        ));
        assert_eq!(client.pending(&kid).unwrap().len(), 1);
        drop(client);

        let mut client =
            KernelClient::open(config(), &journal_path, &[], &CancellationToken::new())
                .await
                .unwrap();
        assert!(matches!(
            client.status(&command_id, &kid).unwrap(),
            Some(KernelOperationStatus::Pending)
        ));
        assert!(matches!(
            client
                .submit_saved(&command_id, &kid, &CancellationToken::new())
                .await,
            Err(KernelClientError::Store(JournalError::InvalidReceipt))
        ));
        assert_eq!(client.pending(&kid).unwrap().len(), 1);
        assert!(matches!(
            client
                .submit_saved(&command_id, &kid, &CancellationToken::new())
                .await,
            Err(KernelClientError::InvalidResult)
        ));
        assert_eq!(client.pending(&kid).unwrap().len(), 1);
        let verified = client
            .submit_saved(&command_id, &kid, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(verified.command_id, command_id);
        assert!(client.pending(&kid).unwrap().is_empty());
        drop(client);

        let reopened = KernelClient::open(config(), &journal_path, &[], &CancellationToken::new())
            .await
            .unwrap();
        assert!(matches!(
            reopened.status(&command_id, &kid).unwrap(),
            Some(KernelOperationStatus::Accepted(_))
        ));
        assert!(reopened.pending(&kid).unwrap().is_empty());
        let db = rusqlite::Connection::open(&journal_path).unwrap();
        db.execute(
            "UPDATE accepted_responses SET response_wire=?1 WHERE command_id=?2",
            rusqlite::params![b"{}", command_id],
        )
        .unwrap();
        assert!(matches!(
            reopened.pending(&kid),
            Err(KernelClientError::Store(JournalError::IncompatibleStore))
        ));
        server.await.unwrap();
    }

    /// Opt-in test against the tracked TypeScript service, not a fake HTTP
    /// responder. The bridge forwards first POST, awaits the real committed
    /// response, then drops the client socket.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires PEERWORK_REFERENCE_ROOT and PEERWORK_TEST_NODE"]
    async fn real_reference_kernel_recovers_committed_lost_reply_and_deduplicates_two_clients() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::{SystemTime, UNIX_EPOCH};

        struct Server(std::process::Child);
        impl Drop for Server {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let reference =
            std::env::var("PEERWORK_REFERENCE_ROOT").expect("pinned reference checkout");
        let node = std::env::var("PEERWORK_TEST_NODE").expect("pinned Node 24 binary");
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = Server(
            Command::new(node)
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../tests/reference-kernel-server.mjs"
                ))
                .env("PEERWORK_REFERENCE_ROOT", reference)
                .env("PEERWORK_TEST_STATE", state.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let origin = serde_json::from_str::<serde_json::Value>(&line).unwrap()["origin"]
            .as_str()
            .unwrap()
            .to_owned();
        let config = || {
            let mut config = TransportConfig::new(&origin);
            config.allow_loopback_http = true;
            config
        };
        let identity = KernelIdentity::create(&state.path().join("owner.state")).unwrap();
        let kid = identity.key_id().to_owned();
        let actor = identity.actor_id().to_owned();
        let command_id = base64url(&[71; 32]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let command_wire = |id: &str,
                            action: &str,
                            body: serde_json::Value,
                            workspace: Option<&str>,
                            expected_revision: Option<u64>| {
            let command = json!({
                "v":1,"audience":"reference-kernel","command_id":id,
                "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),
                "method":"POST","path":"/api/workspace/v1/commands",
                "workspace_id":workspace,"instance_id":null,"protocol_digest":null,
                "action_id":action,"expected_workspace_revision":expected_revision,
                "expected_instance_revision":null,"exact_input_refs":[],
                "body":body,
                "issued_at":now,"expires_at":now+60_000
            });
            canonical(&command, CanonicalPath::COMMAND).unwrap()
        };
        let first_command = command_wire(
            &command_id,
            "workspace.create",
            json!({"name":"Recovery","visibility":"PUBLIC"}),
            None,
            None,
        );
        let mut first = KernelClient::open(
            config(),
            &state.path().join("first.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        first
            .prepare_command(&identity, first_command.as_bytes(), None)
            .unwrap();
        let (jws, body) = first
            .journal
            .exact_request_for_test(&command_id)
            .unwrap()
            .unwrap();
        assert!(matches!(
            first
                .submit_saved(&command_id, &kid, &CancellationToken::new())
                .await,
            Err(KernelClientError::Transport(
                TransportError::SubmittedUncertain
            ))
        ));
        assert!(matches!(
            first.status(&command_id, &kid).unwrap(),
            Some(KernelOperationStatus::Pending)
        ));
        let after_lost_reply = serde_json::from_slice::<serde_json::Value>(
            &reqwest::get(format!("{origin}__test/counts"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after_lost_reply["commands"], 1);
        assert_eq!(after_lost_reply["workspaces"], 1);
        drop(first);
        let mut first = KernelClient::open(
            config(),
            &state.path().join("first.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let accepted = first
            .submit_saved(&command_id, &kid, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(accepted.command_id, command_id);
        assert!(accepted.workspace_id.is_some());
        assert!(accepted.event_sequence.is_some());
        assert!(matches!(
            first.status(&command_id, &kid).unwrap(),
            Some(KernelOperationStatus::Accepted(_))
        ));
        // Exercise the public binding authority boundary after process-style
        // reopen: only redacted accepted data and new pending IDs leave it.
        let facade_origin = origin.clone();
        let facade_db = state.path().join("first.sqlite");
        let facade_identity = state.path().join("owner.state");
        let facade_accepted = accepted.clone();
        let facade_kid = kid.clone();
        let facade_command_id = command_id.clone();
        let unsent_id = base64url(&[74; 32]);
        let unsent_command = command_wire(
            &unsent_id,
            "workspace.create",
            json!({"name":"Not sent","visibility":"PUBLIC"}),
            None,
            None,
        );
        tokio::task::spawn_blocking(move || {
            let access = crate::kernel_access::KernelAccess::new(
                facade_origin,
                facade_db,
                facade_identity,
                &[],
                true,
            );
            let info = access.open().unwrap();
            assert_eq!(info.key_id, facade_kid);
            assert!(matches!(
                access.status(&facade_command_id).unwrap(),
                Some(KernelOperationStatus::Accepted(result)) if result == facade_accepted
            ));
            assert_eq!(
                access.submit_saved(&facade_command_id).unwrap(),
                facade_accepted
            );
            assert!(access.pending().unwrap().is_empty());
            let pending = access.prepare(unsent_command.as_bytes(), None).unwrap();
            assert_eq!(pending.command_id, unsent_id);
            assert!(matches!(
                access.status(&unsent_id).unwrap(),
                Some(KernelOperationStatus::Pending)
            ));
            assert_eq!(access.pending().unwrap().len(), 1);
            let mut wrong_authority: serde_json::Value =
                serde_json::from_str(&unsent_command).unwrap();
            wrong_authority["authority"] = serde_json::Value::String("0".repeat(64));
            assert!(matches!(
                access.prepare(wrong_authority.to_string().as_bytes(), None),
                Err(crate::kernel_access::KernelAccessError::Authority)
            ));
        })
        .await
        .unwrap();
        let signed_body = |command: String| {
            let parsed = parse_wire_json_bounded(command.as_bytes(), 40, 180_000).unwrap();
            prepare_signed_command_wire(&parsed, identity.signing_key(), first.discovery(), None)
                .unwrap()
                .http_body()
                .to_vec()
        };

        let mut second = KernelClient::open(
            config(),
            &state.path().join("second.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        second
            .journal
            .prepare(&command_id, KernelPath::Command, &jws, &body)
            .unwrap();
        assert_eq!(
            second
                .submit_saved(&command_id, &kid, &CancellationToken::new())
                .await
                .unwrap(),
            accepted
        );
        let changed = command_wire(
            &command_id,
            "workspace.create",
            json!({"name":"Different","visibility":"PUBLIC"}),
            None,
            None,
        );
        let conflict = reqwest::Client::new()
            .post(format!("{origin}api/workspace/v1/commands"))
            .header("content-type", "application/json")
            .body(signed_body(changed))
            .send()
            .await
            .unwrap();
        assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);
        let counts = serde_json::from_slice::<serde_json::Value>(
            &reqwest::get(format!("{origin}__test/counts"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(counts["commands"], 1);
        assert_eq!(counts["workspaces"], 1);
        let workspace = accepted.workspace_id.as_deref().unwrap();
        let manifest = json!({
            "name":"revision-race","display_version":"1","semantics":"peerwork.kernel.v1",
            "dependencies":[],"record_schemas":{},"initial_state":{},"actions":[]
        });
        let submit_publish = |id: String| {
            let command = command_wire(
                &id,
                "protocol.publish",
                json!({"manifest":manifest}),
                Some(workspace),
                Some(1),
            );
            signed_body(command)
        };
        let first_publish = reqwest::Client::new()
            .post(format!("{origin}api/workspace/v1/commands"))
            .header("content-type", "application/json")
            .body(submit_publish(base64url(&[72; 32])))
            .send()
            .await
            .unwrap();
        assert_eq!(first_publish.status(), reqwest::StatusCode::CREATED);
        let stale_publish = reqwest::Client::new()
            .post(format!("{origin}api/workspace/v1/commands"))
            .header("content-type", "application/json")
            .body(submit_publish(base64url(&[73; 32])))
            .send()
            .await
            .unwrap();
        assert_eq!(stale_publish.status(), reqwest::StatusCode::CONFLICT);
        let after_revision_conflict = serde_json::from_slice::<serde_json::Value>(
            &reqwest::get(format!("{origin}__test/counts"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(after_revision_conflict["commands"], 2);
        assert_eq!(after_revision_conflict["workspaces"], 1);
        assert_eq!(after_revision_conflict["protocols"], 1);
        assert_eq!(after_revision_conflict["workspace_revision"], 2);
        drop(child);
    }

    #[cfg(unix)]
    async fn respond(socket: &mut tokio::net::TcpStream, body: &[u8]) {
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        socket.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    async fn read_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&chunk[..count]);
            let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header = String::from_utf8_lossy(&request[..end]);
            let length = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                return request;
            }
        }
    }
}
