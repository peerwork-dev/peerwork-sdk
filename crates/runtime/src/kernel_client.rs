//! HTTPS discovery with exact schema and durable origin/authority continuity.
//! Kernel command submission remains internal until verified outcome recovery
//! is persisted; this type currently supports discovery and pending listing.

use crate::{
    kernel_intents::{JournalError, KernelIntentJournal, PendingKernelIntent},
    transport::{HttpTransport, TransportConfig, TransportError, MAX_DISCOVERY_BYTES},
};
use peerwork_core::discovery::{parse_discovery_wire, ParsedDiscovery};
use std::path::Path;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum KernelClientError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Store(#[from] JournalError),
    #[error("discovery HTTP status is not successful")]
    DiscoveryStatus,
    #[error("discovery schema or required features are unsupported")]
    UnsupportedDiscovery,
}

pub struct KernelClient {
    transport: HttpTransport,
    journal: KernelIntentJournal,
    discovery: ParsedDiscovery,
}

impl KernelClient {
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

    pub fn pending(&self) -> Result<Vec<PendingKernelIntent>, KernelClientError> {
        Ok(self.journal.pending()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerwork_core::crypto::key_id;
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
}
