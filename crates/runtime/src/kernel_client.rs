//! HTTPS discovery with exact schema and durable origin/authority continuity.
//! Kernel command submission remains internal until verified outcome recovery
//! is persisted; this type currently supports discovery and pending listing.

use crate::{
    kernel_intents::{JournalError, KernelIntentJournal, PendingKernelIntent},
    transport::{HttpTransport, TransportConfig, TransportError, MAX_DISCOVERY_BYTES},
};
use peerwork_core::discovery::{parse_discovery_wire, ParsedDiscovery};
use peerwork_core::receipt_wire::VerifiedCommandResponse;
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
}

pub enum KernelOperationStatus {
    Pending,
    Accepted(VerifiedCommandResponse),
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
            Some(verified) => Ok(Some(KernelOperationStatus::Accepted(verified))),
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
    ) -> Result<VerifiedCommandResponse, KernelClientError> {
        let saved = self
            .journal
            .verified_pending(command_id, local_key_id, self.discovery.audience_utf16())?
            .ok_or(KernelClientError::IntentNotFound)?;
        if let Some(verified) = self
            .journal
            .accepted_response(&saved, self.discovery.receipt_public_key())?
        {
            return Ok(verified);
        }
        let response = self
            .transport
            .post_exact(saved.proof.path(), saved.body.clone(), cancel)
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(KernelClientError::ServerRejected(response.status));
        }
        Ok(self.journal.record_verified_response(
            &saved,
            &response.wire,
            self.discovery.receipt_public_key(),
        )?)
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
        let result = json!({"workspace_id":null,"event_sequence":null,"revision":null});
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
        let invalid = b"{\"command_id\":\"wrong\",\"receipt\":\"invalid\",\"result\":{}}".to_vec();
        let discovery = discovery_wire(&kid, &[]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let saved_body = body.as_bytes().to_vec();
        let server = tokio::spawn(async move {
            for step in 0..6 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                if matches!(step, 0 | 2 | 5) {
                    assert!(request.starts_with(b"GET /api/workspace/v1/discovery "));
                    respond(&mut socket, &discovery).await;
                } else {
                    assert!(request.starts_with(b"POST /api/workspace/v1/commands "));
                    assert!(request.ends_with(&saved_body));
                    match step {
                        1 => {}
                        3 => respond(&mut socket, &invalid).await,
                        4 => respond(&mut socket, accepted.as_bytes()).await,
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
        let verified = client
            .submit_saved(&command_id, &kid, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(verified.command_id(), command_id);
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
