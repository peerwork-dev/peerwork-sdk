//! Exact-byte HTTP transport. Sending a command requires a separate verified
//! prepared-command proof and durable journal binding before this is exposed.

use reqwest::{redirect::Policy, Certificate, Client, Proxy, Url};
use std::time::Duration;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub(crate) const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
const MAX_COMMAND_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SECURE_JOURNAL_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid or unsupported server origin")]
    InvalidOrigin,
    #[error("invalid proxy or trust root")]
    InvalidTrust,
    #[error("HTTP client setup failed")]
    Setup,
    #[error("request was cancelled")]
    Cancelled,
    #[error("request timed out")]
    Timeout,
    #[error("network request failed")]
    Network,
    #[error("server response was redirected")]
    Redirect,
    #[error("server response exceeded size limit")]
    ResponseTooLarge,
    #[error("submitted command outcome is uncertain; reconcile saved intent")]
    SubmittedUncertain,
}

pub struct TransportConfig {
    pub origin: String,
    pub timeout: Duration,
    pub allow_loopback_http: bool,
    pub additional_root_pem: Vec<Vec<u8>>,
    pub proxy: Option<String>,
}

impl TransportConfig {
    pub fn new(origin: impl Into<String>) -> Self {
        Self {
            origin: origin.into(),
            timeout: Duration::from_secs(15),
            allow_loopback_http: false,
            additional_root_pem: Vec::new(),
            proxy: None,
        }
    }
}

#[derive(Debug)]
pub struct ExactHttpResponse {
    pub status: u16,
    /// Exact response bytes; never decoded or reserialized by the transport.
    pub wire: Vec<u8>,
}

pub struct HttpTransport {
    origin: Url,
    client: Client,
    #[cfg(test)]
    journal_get_probe: std::sync::Mutex<Option<Vec<String>>>,
}

impl HttpTransport {
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        let origin = Url::parse(&config.origin).map_err(|_| TransportError::InvalidOrigin)?;
        let loopback = matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if !(origin.scheme() == "https"
            || (config.allow_loopback_http && loopback && origin.scheme() == "http"))
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || config.timeout.is_zero()
        {
            return Err(TransportError::InvalidOrigin);
        }
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .timeout(config.timeout)
            .no_proxy();
        if let Some(proxy) = config.proxy {
            let url = Url::parse(&proxy).map_err(|_| TransportError::InvalidTrust)?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(TransportError::InvalidTrust);
            }
            builder = builder.proxy(Proxy::all(proxy).map_err(|_| TransportError::InvalidTrust)?);
        }
        for pem in config.additional_root_pem {
            let cert = Certificate::from_pem(&pem).map_err(|_| TransportError::InvalidTrust)?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder.build().map_err(|_| TransportError::Setup)?;
        Ok(Self {
            origin,
            client,
            #[cfg(test)]
            journal_get_probe: std::sync::Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_one_journal_get_and_record_proofs(&self) {
        *self.journal_get_probe.lock().unwrap() = Some(Vec::new());
    }

    #[cfg(test)]
    pub(crate) fn take_journal_get_probe_proofs(&self) -> Vec<String> {
        self.journal_get_probe.lock().unwrap().take().unwrap()
    }

    pub(crate) fn trusted_origin(&self) -> &str {
        self.origin.as_str()
    }

    pub async fn discovery(
        &self,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        let url = self.endpoint("/api/workspace/v1/discovery")?;
        let send = self.client.get(url).send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        read_bounded(response, MAX_DISCOVERY_BYTES, cancel).await
    }

    /// Anonymous public catalog GET. A caller must validate projected listing
    /// fields separately and re-hash exact package bytes before selection.
    pub(crate) async fn get_public_catalog(
        &self,
        path: &str,
        query: &[(&str, &str)],
        max_response_bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        if !matches!(path, "/api/protocol-catalog/v1/packages")
            && !path
                .strip_prefix("/api/protocol-catalog/v1/packages/by-digest/")
                .is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
        {
            return Err(TransportError::InvalidOrigin);
        }
        let mut url = self.endpoint(path)?;
        if !query.is_empty() {
            if path != "/api/protocol-catalog/v1/packages" {
                return Err(TransportError::InvalidOrigin);
            }
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let send = self.client.get(url).send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        read_bounded(response, max_response_bytes, cancel).await
    }

    /// Internal primitive only. The caller must first bind a core-authenticated
    /// prepared command to the exact pending SQLite row and pinned discovery.
    pub(crate) async fn post_exact(
        &self,
        path: &str,
        body: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        if !valid_command_path(path) || body.is_empty() || body.len() > 262_144 {
            return Err(TransportError::InvalidOrigin);
        }
        let url = self.endpoint(path)?;
        let send = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::SubmittedUncertain),
            result = send => result.map_err(|_| TransportError::SubmittedUncertain)?,
        };
        read_bounded(response, MAX_COMMAND_RESPONSE_BYTES, cancel)
            .await
            .map_err(|_| TransportError::SubmittedUncertain)
    }

    /// Submit a persisted exact admission packet with a fresh signed control
    /// proof for this route. Once sending starts, cancellation/network loss is
    /// uncertain and the caller must inspect signed control evidence first.
    pub(crate) async fn post_secure_admission_exact(
        &self,
        path: &str,
        body: Vec<u8>,
        read_proof: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        if !valid_admission_post_path(path)
            || body.is_empty()
            || body.len() > 220_000
            || read_proof.is_empty()
            || read_proof.len() > 12000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let url = self.endpoint(path)?;
        let send = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("X-Peerwork-Read", read_proof)
            .body(body)
            .send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::SubmittedUncertain),
            result = send => result.map_err(|_| TransportError::SubmittedUncertain)?,
        };
        read_bounded(response, MAX_COMMAND_RESPONSE_BYTES, cancel)
            .await
            .map_err(|_| TransportError::SubmittedUncertain)
    }

    /// Exact authenticated secure-journal GET. The caller supplies a fresh
    /// signed read proof bound to this complete canonical path and configured
    /// origin. The returned bytes are untrusted until full journal replay.
    pub(crate) async fn get_secure_journal_exact(
        &self,
        path: &str,
        read_proof: &str,
        max_response_bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_SECURE_JOURNAL_RESPONSE_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        let workspace = path
            .strip_prefix("/api/workspace/v1/secure/workspaces/")
            .and_then(|tail| tail.split_once("/journal?"));
        if !workspace.is_some_and(|(id, query)| {
            id.len() == 43
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                && !query.is_empty()
                && !query.contains('#')
                && !query.contains('?')
                && !query.contains('/')
        }) || path.len() > 2048
            || read_proof.is_empty()
            || read_proof.len() > 12000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let url = self.endpoint(path)?;
        #[cfg(test)]
        {
            if let Some(proofs) = self.journal_get_probe.lock().unwrap().as_mut() {
                proofs.push(peerwork_core::crypto::sha256_hex(read_proof.as_bytes()));
                if proofs.len() == 1 {
                    return Err(TransportError::Network);
                }
            }
        }
        let send = self
            .client
            .get(url)
            .header("X-Peerwork-Read", read_proof)
            .send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        read_bounded(response, max_response_bytes, cancel).await
    }

    /// Exact authenticated admission control GET. The signed read proof must
    /// bind this same path and configured origin; returned service labels are
    /// untrusted until signed artifacts and saved pins verify.
    pub(crate) async fn get_secure_invitation_exact(
        &self,
        path: &str,
        read_proof: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        let id = path.strip_prefix("/api/workspace/v1/secure/invitations/");
        if !id.is_some_and(|id| {
            id.len() == 43
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }) || read_proof.is_empty()
            || read_proof.len() > 12000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let url = self.endpoint(path)?;
        let send = self
            .client
            .get(url)
            .header("connection", "close")
            .header("X-Peerwork-Read", read_proof)
            .send();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        read_bounded(response, 220_000, cancel).await
    }

    /// Exact authenticated identity-directory read. A directory response is
    /// still untrusted until its signed chain and local continuity pin verify.
    pub(crate) async fn get_secure_identity_keys_exact(
        &self,
        path: &str,
        read_proof: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        let actor = path.strip_prefix("/api/workspace/v1/secure/identity-keys/");
        if !actor.is_some_and(valid_identity_token)
            || read_proof.is_empty()
            || read_proof.len() > 12_000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = self.client.get(self.endpoint(path)?)
                .header("X-Peerwork-Read", read_proof).send() =>
                result.map_err(map_network_error)?,
        };
        // A valid 128-entry history can exceed a single small control item.
        // Each published entry is capped at 8 KiB by the service route.
        read_bounded(response, 2 * 1024 * 1024, cancel).await
    }

    /// Authenticated recipient-scoped grant list. The response remains
    /// untrusted until every selected signed grant, policy, and journal
    /// checkpoint is reverified by the private activation consumer.
    pub(crate) async fn get_secure_key_grants_exact(
        &self,
        path: &str,
        read_proof: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        let workspace = path
            .strip_prefix("/api/workspace/v1/secure/workspaces/")
            .and_then(|tail| tail.strip_suffix("/key-grants"));
        if !workspace.is_some_and(valid_identity_token)
            || read_proof.is_empty()
            || read_proof.len() > 12_000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = self.client.get(self.endpoint(path)?)
                .header("X-Peerwork-Read", read_proof).send() =>
                result.map_err(map_network_error)?,
        };
        read_bounded(response, 2 * 1024 * 1024, cancel).await
    }

    /// Submit a previously protected exact signed v1 directory entry.
    /// Failure after sending begins leaves its outcome uncertain.
    pub(crate) async fn post_secure_identity_key_exact(
        &self,
        body: Vec<u8>,
        read_proof: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        if body.is_empty()
            || body.len() > 8_192
            || read_proof.is_empty()
            || read_proof.len() > 12_000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let path = "/api/workspace/v1/secure/identity-keys";
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::SubmittedUncertain),
            result = self.client.post(self.endpoint(path)?)
                .header("content-type", "application/json")
                .header("X-Peerwork-Read", read_proof)
                .body(body).send() =>
                result.map_err(|_| TransportError::SubmittedUncertain)?,
        };
        read_bounded(response, MAX_COMMAND_RESPONSE_BYTES, cancel)
            .await
            .map_err(|_| TransportError::SubmittedUncertain)
    }

    fn endpoint(&self, path: &str) -> Result<Url, TransportError> {
        self.origin
            .join(path)
            .map_err(|_| TransportError::InvalidOrigin)
    }
}

fn valid_identity_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_command_path(path: &str) -> bool {
    matches!(
        path,
        "/api/workspace/v1/commands"
            | "/api/workspace/v1/catalog/upload"
            | "/api/workspace/v1/private/packages/upload"
            | "/api/workspace/v1/secure/workspaces"
    ) || path
        .strip_prefix("/api/workspace/v1/browser/sessions/")
        .and_then(|tail| tail.strip_suffix("/commands"))
        .is_some_and(|id| {
            id.len() == 43
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        || path
            .strip_prefix("/api/workspace/v1/secure/workspaces/")
            .and_then(|tail| tail.strip_suffix("/commits"))
            .is_some_and(|id| {
                id.len() == 43
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
}

fn valid_admission_post_path(path: &str) -> bool {
    if path == "/api/workspace/v1/secure/invitations" {
        return true;
    }
    path.strip_prefix("/api/workspace/v1/secure/invitations/")
        .and_then(|tail| {
            tail.strip_suffix("/decision")
                .or_else(|| tail.strip_suffix("/key-grants"))
                .or_else(|| tail.strip_suffix("/receipt"))
        })
        .is_some_and(|id| {
            id.len() == 43
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn map_network_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        TransportError::Timeout
    } else {
        TransportError::Network
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<ExactHttpResponse, TransportError> {
    if response.status().is_redirection() {
        return Err(TransportError::Redirect);
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(TransportError::ResponseTooLarge);
    }
    let status = response.status().as_u16();
    let mut wire = Vec::new();
    loop {
        let chunk = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = response.chunk() => result.map_err(map_network_error)?,
        };
        match chunk {
            Some(chunk) if chunk.len() > limit.saturating_sub(wire.len()) => {
                return Err(TransportError::ResponseTooLarge);
            }
            Some(chunk) => wire.extend_from_slice(&chunk),
            None => return Ok(ExactHttpResponse { status, wire }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn one_response(response: &'static [u8]) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let _ = socket.read(&mut request).await.unwrap();
            socket.write_all(response).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        (origin, task)
    }

    fn local_config(origin: String) -> TransportConfig {
        let mut config = TransportConfig::new(origin);
        config.allow_loopback_http = true;
        config
    }

    #[tokio::test]
    async fn discovery_preserves_wire_bytes_without_following_redirect() {
        let (origin, server) =
            one_response(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"raw\":\"\\ud800\"}\n")
                .await;
        let transport = HttpTransport::new(local_config(origin)).unwrap();
        let response = transport
            .discovery(&CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.wire, b"{\"raw\":\"\\ud800\"}\n");
        server.await.unwrap();

        let (origin, server) = one_response(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let transport = HttpTransport::new(local_config(origin)).unwrap();
        assert!(matches!(
            transport.discovery(&CancellationToken::new()).await,
            Err(TransportError::Redirect)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn discovery_rejects_over_limit_before_reading_body() {
        let (origin, server) =
            one_response(b"HTTP/1.1 200 OK\r\nContent-Length: 262145\r\n\r\n").await;
        let transport = HttpTransport::new(local_config(origin)).unwrap();
        assert!(matches!(
            transport.discovery(&CancellationToken::new()).await,
            Err(TransportError::ResponseTooLarge)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_after_post_reaches_server_is_uncertain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let count = socket.read(&mut request).await.unwrap();
            assert!(request[..count].starts_with(b"POST /api/workspace/v1/commands "));
            seen_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let transport = HttpTransport::new(local_config(origin)).unwrap();
        let cancel = CancellationToken::new();
        let pending = transport.post_exact(
            "/api/workspace/v1/commands",
            b"{\"jws\":\"saved\"}".to_vec(),
            &cancel,
        );
        tokio::pin!(pending);
        tokio::select! {
            _ = &mut pending => panic!("server did not answer"),
            _ = seen_rx => cancel.cancel(),
        }
        assert!(matches!(
            pending.await,
            Err(TransportError::SubmittedUncertain)
        ));
        server.await.unwrap();
    }

    #[test]
    fn origin_refuses_credentials_and_non_loopback_cleartext() {
        assert!(matches!(
            HttpTransport::new(TransportConfig::new("http://example.com/")),
            Err(TransportError::InvalidOrigin)
        ));
        assert!(matches!(
            HttpTransport::new(TransportConfig::new("https://user:pass@example.com/")),
            Err(TransportError::InvalidOrigin)
        ));
    }

    #[test]
    fn bootstrap_post_route_is_exactly_allowlisted() {
        assert!(valid_command_path("/api/workspace/v1/secure/workspaces"));
        for path in [
            "/api/workspace/v1/secure/workspaces/",
            "/api/workspace/v1/secure/workspaces?x=1",
            "/api/workspace/v1/secure/workspaces/other",
            "/api/workspace/v1/secure/invitations",
        ] {
            assert!(!valid_command_path(path), "{path}");
        }
    }

    #[test]
    fn admission_write_routes_require_exact_token_and_signed_control_primitive() {
        let id = "a".repeat(43);
        for path in [
            "/api/workspace/v1/secure/invitations".to_owned(),
            format!("/api/workspace/v1/secure/invitations/{id}/decision"),
            format!("/api/workspace/v1/secure/invitations/{id}/key-grants"),
            format!("/api/workspace/v1/secure/invitations/{id}/receipt"),
        ] {
            assert!(valid_admission_post_path(&path));
            assert!(!valid_command_path(&path));
        }
        for path in [
            format!("/api/workspace/v1/secure/invitations/{id}/receipt?x=1"),
            format!("/api/workspace/v1/secure/invitations/{id}/decision?x=1"),
            "/api/workspace/v1/secure/invitations/short/decision".to_owned(),
        ] {
            assert!(!valid_admission_post_path(&path));
        }
    }
}
