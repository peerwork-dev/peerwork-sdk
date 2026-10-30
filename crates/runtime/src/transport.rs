//! Exact-byte HTTP transport. Sending a command requires a separate verified
//! prepared-command proof and durable journal binding before this is exposed.

use reqwest::{redirect::Policy, Certificate, Client, Proxy, Url};
use std::time::{Duration,Instant};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use std::sync::{Arc,atomic::{AtomicU64,Ordering}};

#[derive(Default)]
struct TransportMetrics{requests:AtomicU64,discovery:AtomicU64,context:AtomicU64,elapsed_us:AtomicU64,phases:[PhaseMetric;12],send_phases:[PhaseMetric;12]}

#[derive(Default)]
struct PhaseMetric { count:AtomicU64, elapsed_us:AtomicU64, max_us:AtomicU64 }
#[derive(Clone,Copy)]
pub(crate) enum ClientPhase { SessionOpen, BodyPrepare, PacketPrepare, SavedLoad, HttpRoundtrip, ResponseVerifyStore, AdmissionReserve, RunningStore, CompletionStore, BodyKeySelection, BodySealSign, BodyPersist }
const PHASE_NAMES:[&str;12]=["session_open","body_prepare","packet_prepare","saved_load","http_roundtrip","response_verify_store","admission_reserve","running_store","completion_store","body_key_selection","body_seal_sign","body_persist"];
tokio::task_local! { static FOREGROUND_SEND: (); }
/// Only nested work actually awaited by this send belongs to its execution
/// scope. A separate watch/ACK task never inherits this task-local marker.
pub(crate) async fn track_foreground_send<F:std::future::Future>(future:F)->F::Output{
    FOREGROUND_SEND.scope((),future).await
}
pub(crate) struct PhaseTimer { metrics:Arc<TransportMetrics>, phase:ClientPhase, started:Instant, foreground_send:bool }
impl PhaseMetric {
    fn record(&self,elapsed:u64){
        self.elapsed_us.fetch_add(elapsed,Ordering::Relaxed);
        self.max_us.fetch_max(elapsed,Ordering::Relaxed);
        self.count.fetch_add(1,Ordering::Relaxed);
    }
}
impl Drop for PhaseTimer {
    fn drop(&mut self){
        let elapsed=self.started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.metrics.phases[self.phase as usize].record(elapsed);
        if self.foreground_send{self.metrics.send_phases[self.phase as usize].record(elapsed);}
    }
}

#[cfg(test)]
static TEST_DROP_NEXT_SECURE_POST_RESPONSE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn test_drop_next_secure_post_response() {
    TEST_DROP_NEXT_SECURE_POST_RESPONSE.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub(crate) const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
const MAX_COMMAND_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SECURE_JOURNAL_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid or unsupported server origin")]
    InvalidOrigin,
    #[error("invalid transport options, proxy or trust root")]
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

/// Invocation-local caller choices; never stored as workspace authority.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TransportOptions {
    pub request_timeout_ms: u64,
    pub additional_root_pem_files: Vec<std::path::PathBuf>,
}
impl Default for TransportOptions {
    fn default() -> Self { Self { request_timeout_ms: 15_000, additional_root_pem_files: Vec::new() } }
}
impl TransportOptions {
    pub const MAX_ROOT_FILES: usize = 16;
    pub const MAX_ROOT_FILE_BYTES: usize = 65_536;
    pub const MAX_ROOT_TOTAL_BYTES: usize = 262_144;
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.request_timeout_ms == 0
            || std::time::Instant::now().checked_add(Duration::from_millis(self.request_timeout_ms)).is_none()
            || self.additional_root_pem_files.len() > Self::MAX_ROOT_FILES
            || self.additional_root_pem_files.iter().any(|p| p.as_os_str().is_empty()) {
            return Err(TransportError::InvalidTrust);
        }
        Ok(())
    }
    fn roots(&self) -> Result<Vec<Certificate>, TransportError> {
        use std::io::Read;
        self.validate()?;
        let mut roots = Vec::new(); let mut total = 0usize;
        for path in &self.additional_root_pem_files {
            // Public CA inputs need no secret-file ownership rule, but special
            // files must never block a client or evade the streaming bound.
            let metadata = std::fs::metadata(path).map_err(|_| TransportError::InvalidTrust)?;
            if !metadata.is_file() || metadata.len() == 0 || metadata.len() > Self::MAX_ROOT_FILE_BYTES as u64 {
                return Err(TransportError::InvalidTrust);
            }
            let mut open = std::fs::OpenOptions::new(); open.read(true);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; open.custom_flags(libc::O_NONBLOCK); }
            let file = open.open(path).map_err(|_| TransportError::InvalidTrust)?;
            let current = file.metadata().map_err(|_| TransportError::InvalidTrust)?;
            let remaining = Self::MAX_ROOT_TOTAL_BYTES.checked_sub(total).ok_or(TransportError::InvalidTrust)?;
            let bound = remaining.min(Self::MAX_ROOT_FILE_BYTES);
            if !current.is_file() || current.len() == 0 || current.len() > bound as u64 { return Err(TransportError::InvalidTrust); }
            let mut bytes = Vec::new();
            file.take((bound + 1) as u64).read_to_end(&mut bytes).map_err(|_| TransportError::InvalidTrust)?;
            if bytes.is_empty() || bytes.len() > bound { return Err(TransportError::InvalidTrust); }
            total = total.checked_add(bytes.len()).ok_or(TransportError::InvalidTrust)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| TransportError::InvalidTrust)?;
            let mut remaining_pem = text.trim();
            while !remaining_pem.is_empty() {
                if !remaining_pem.starts_with("-----BEGIN CERTIFICATE-----") { return Err(TransportError::InvalidTrust); }
                let end = remaining_pem.find("-----END CERTIFICATE-----").ok_or(TransportError::InvalidTrust)? + "-----END CERTIFICATE-----".len();
                remaining_pem = remaining_pem[end..].trim();
            }
            let parsed = Certificate::from_pem_bundle(&bytes).map_err(|_| TransportError::InvalidTrust)?;
            if parsed.is_empty() { return Err(TransportError::InvalidTrust); }
            roots.extend(parsed);
        }
        Ok(roots)
    }
}

pub struct TransportConfig {
    pub origin: String,
    pub timeout: Duration,
    pub allow_loopback_http: bool,
    pub additional_root_pem: Vec<Vec<u8>>,
    pub proxy: Option<String>,
    pub client_options: Option<TransportOptions>,
}

impl TransportConfig {
    pub fn with_options(mut self, options: TransportOptions) -> Self { self.client_options = Some(options); self }
    pub fn new(origin: impl Into<String>) -> Self {
        Self {
            origin: origin.into(),
            timeout: Duration::from_secs(15),
            allow_loopback_http: false,
            additional_root_pem: Vec::new(),
            proxy: None,
            client_options: None,
        }
    }
}

#[derive(Debug)]
pub struct ExactHttpResponse {
    pub status: u16,
    /// Exact response bytes; never decoded or reserialized by the transport.
    pub wire: Vec<u8>,
}

#[derive(Clone)]
pub struct HttpTransport {
    origin: Url,
    client: Client,
    metrics:Arc<TransportMetrics>,
    context_cache:Arc<std::sync::Mutex<Option<(String,peerwork_core::structure_context::VerifiedStructureContext,Instant)>>>,
    migration_source_clock:std::sync::Arc<std::sync::Mutex<Option<(u64,Instant)>>>,
    #[cfg(test)]
    journal_get_probe: std::sync::Arc<std::sync::Mutex<Option<Vec<String>>>>,
}

/// Canonical transport origin for local lifecycle pins only. Callers retain
/// their original config/history origin binding; no network request is made.
pub(crate) fn canonical_lifecycle_origin(origin: &str, allow_loopback_http: bool) -> Result<String, TransportError> {
    Ok(checked_origin(origin,allow_loopback_http)?.to_string())
}
fn checked_origin(origin:&str,allow_loopback_http:bool)->Result<Url,TransportError>{
    let origin=Url::parse(origin).map_err(|_|TransportError::InvalidOrigin)?;
    let loopback=matches!(origin.host_str(),Some("localhost"|"127.0.0.1"|"::1"));
    if !(origin.scheme()=="https" || allow_loopback_http&&loopback&&origin.scheme()=="http")
        || origin.host_str().is_none() || !origin.username().is_empty() || origin.password().is_some()
        || origin.path()!="/" || origin.query().is_some() || origin.fragment().is_some(){return Err(TransportError::InvalidOrigin);}
    Ok(origin)
}

/// Authorization timestamps estimated from a verified server anchor and local
/// monotonic elapsed time. This is not a new signed server-time proof, and its
/// expiry is never extended beyond that original anchor's authorization TTL.
pub(crate) struct AuthorizationWindow{issued:u64,expires:u64}
impl AuthorizationWindow{
    pub(crate) fn server_time_ms(&self)->u64{self.issued}
    pub(crate) fn expires_at_ms(&self)->u64{self.expires}
}
impl HttpTransport {
    pub(crate) async fn delivery_stream(&self, token:&str, cancel:&CancellationToken)->Result<reqwest::Response,TransportError>{
        if token.len()>8192 || !token.is_ascii(){return Err(TransportError::InvalidTrust);}
        let url=self.endpoint("/api/workspace/v1/structure/delivery/stream")?;
        let response=tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled),r=self.measured_send(self.client.get(url).bearer_auth(token).header("Accept","text/event-stream").timeout(Duration::from_secs(70)).send())=>r.map_err(map_network_error)?};
        if !response.status().is_success()||!response.headers().get("content-type").and_then(|v|v.to_str().ok()).is_some_and(|v|v.starts_with("text/event-stream")){return Err(TransportError::Network);}
        Ok(response)
    }
    pub(crate) async fn mailbox_stream(&self,token:&str,cancel:&CancellationToken)->Result<reqwest::Response,TransportError>{
        if token.len()>8192||!token.is_ascii(){return Err(TransportError::InvalidTrust);}
        let url=self.endpoint("/api/workspace/v1/structure/communication/stream")?;
        let response=tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled),r=self.measured_send(self.client.get(url).bearer_auth(token).header("Accept","text/event-stream").timeout(Duration::from_secs(65)).send())=>r.map_err(map_network_error)?};
        if !response.status().is_success()||!response.headers().get("content-type").and_then(|v|v.to_str().ok()).is_some_and(|v|v.starts_with("text/event-stream")){return Err(TransportError::Network);}
        Ok(response)
    }
    pub(crate) fn invalidate_context(&self,key:&str){
        if let Ok(mut slot)=self.context_cache.lock(){if slot.as_ref().is_some_and(|(pin,_,_)|pin==key){*slot=None;}}
    }
    pub(crate) fn cached_context(&self,key:&str)->Option<AuthorizationWindow>{
        let slot=self.context_cache.lock().ok()?;
        let (pin,context,at)=slot.as_ref()?;
        let elapsed=u64::try_from(at.elapsed().as_millis()).ok()?;
        if pin!=key || elapsed>=540_000{return None;}
        let issued=context.server_time_ms().checked_add(elapsed)?;
        let expires=context.expires_at_ms();
        if issued>=expires{return None;}Some(AuthorizationWindow{issued,expires})
    }
    pub(crate) fn remember_context(&self,key:&str,context:&peerwork_core::structure_context::VerifiedStructureContext,started:Instant){
        if let Ok(mut slot)=self.context_cache.lock(){*slot=Some((key.into(),context.clone(),started));}
    }
    async fn measured_send<F>(&self,future:F)->Result<reqwest::Response,reqwest::Error>
    where F:std::future::Future<Output=Result<reqwest::Response,reqwest::Error>>{
        self.metrics.requests.fetch_add(1,Ordering::Relaxed);let started=Instant::now();let out=future.await;
        self.metrics.elapsed_us.fetch_add(started.elapsed().as_micros().min(u64::MAX as u128) as u64,Ordering::Relaxed);out
    }
    pub(crate) fn phase(&self,phase:ClientPhase)->PhaseTimer{PhaseTimer{metrics:self.metrics.clone(),phase,started:Instant::now(),foreground_send:FOREGROUND_SEND.try_with(|_|true).unwrap_or(false)}}
    pub(crate) fn metrics(&self)->serde_json::Value{
        let values=|metrics:&[PhaseMetric]|->serde_json::Map<String,serde_json::Value>{PHASE_NAMES.iter().zip(metrics).map(|(name,metric)|((*name).into(),serde_json::json!({"count":metric.count.load(Ordering::Relaxed),"elapsed_us":metric.elapsed_us.load(Ordering::Relaxed),"max_us":metric.max_us.load(Ordering::Relaxed)}))).collect()};
        serde_json::json!({"scope":"SESSION_CUMULATIVE","http_requests_started":self.metrics.requests.load(Ordering::Relaxed),"discovery_requests":self.metrics.discovery.load(Ordering::Relaxed),"context_requests":self.metrics.context.load(Ordering::Relaxed),"http_response_headers_elapsed_us":self.metrics.elapsed_us.load(Ordering::Relaxed),"local_phases":values(&self.metrics.phases),"send_execution_phases":values(&self.metrics.send_phases),"send_execution_basis":"task-local structure.message.send execution and its awaited prerequisites only; separate ACK/watch tasks excluded; admission/running/completion store occur outside this scope","local_phase_basis":"monotonic completed spans, including failed/cancelled scope exits; concurrent/nested spans may overlap; maxima are lifetime, not delta maxima"})
    }
    pub fn new(mut config: TransportConfig) -> Result<Self, TransportError> {
        let extra_roots = if let Some(options) = &config.client_options {
            options.validate()?; config.timeout = Duration::from_millis(options.request_timeout_ms); options.roots()?
        } else { Vec::new() };
        let origin=checked_origin(&config.origin,config.allow_loopback_http)?;
        if config.timeout.is_zero() {
            return Err(TransportError::InvalidOrigin);
        }
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .timeout(config.timeout)
            .no_proxy();
        // This SDK-specific opt-in is shared by the language facades. Generic
        // HTTP_PROXY/HTTPS_PROXY/NO_PROXY remain ignored: changing the route
        // requires an explicit participant choice, including in a sandbox.
        let proxy = selected_proxy(config.proxy, std::env::var("PEERWORK_HTTP_PROXY"))?;
        if let Some(proxy) = proxy {
            let url = Url::parse(&proxy).map_err(|_| TransportError::InvalidTrust)?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(TransportError::InvalidTrust);
            }
            builder = builder.proxy(Proxy::all(proxy).map_err(|_| TransportError::InvalidTrust)?);
        }
        for cert in extra_roots { builder = builder.add_root_certificate(cert); }
        for pem in config.additional_root_pem {
            let cert = Certificate::from_pem(&pem).map_err(|_| TransportError::InvalidTrust)?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder.build().map_err(|_| TransportError::Setup)?;
        Ok(Self {
            origin,
            client,
            metrics:Default::default(),
            context_cache:Default::default(),
            migration_source_clock:Default::default(),
            #[cfg(test)]
            journal_get_probe: Default::default(),
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

    fn observe_migration_source_time(&self,response:&reqwest::Response){
        if !response.status().is_success(){return;}
        let value=response.headers().get("X-Peerwork-Server-Time").and_then(|h|h.to_str().ok()).and_then(|s|s.parse::<u64>().ok());
        if let Some(value)=value.filter(|v|*v>0&&*v<=9_007_199_254_680_991){if let Ok(mut clock)=self.migration_source_clock.lock(){*clock=Some((value,Instant::now()));}}
    }
    /// Fresh TLS-bound source time for one-way migration GET proofs only.
    /// Ordinary commands still require their signed structure context.
    pub(crate) fn migration_source_time_ms(&self)->Option<u64>{
        let clock=self.migration_source_clock.lock().ok()?;let (time,observed)=clock.as_ref()?;let elapsed=observed.elapsed().as_millis();if elapsed>60_000{return None;}time.checked_add(elapsed as u64)
    }

    pub async fn discovery(
        &self,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        self.metrics.discovery.fetch_add(1,Ordering::Relaxed);
        let url = self.endpoint("/api/workspace/v1/discovery")?;
        let send = self.measured_send(self.client.get(url).header("Cache-Control","no-cache, no-store").send());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        self.observe_migration_source_time(&response);
        read_bounded(response, MAX_DISCOVERY_BYTES, cancel).await
    }

    /// One anonymous selected publication page; never a journal fallback.
    pub(crate) async fn get_publication(&self,query:&[(String,String)],cancel:&CancellationToken)->Result<ExactHttpResponse,TransportError>{
        if query.len()>8||query.iter().any(|(k,v)|k.len()>32||v.len()>8192){return Err(TransportError::InvalidOrigin);}
        let mut url=self.endpoint("/api/workspace/v1/structure/public")?;
        {let mut pairs=url.query_pairs_mut();for(k,v)in query{pairs.append_pair(k,v);}}
        let response=tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled),result=self.measured_send(self.client.get(url).header("Cache-Control","no-store").send()) =>result.map_err(map_network_error)?};
        read_bounded(response,1_048_576,cancel).await
    }

    pub(crate) async fn guard_time_capabilities(&self,cancel:&CancellationToken)->Result<ExactHttpResponse,TransportError> {
        let url=self.endpoint("/api/workspace/v1/guard-time-capabilities")?;
        let response=tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled),result=self.measured_send(self.client.get(url).send()) =>result.map_err(map_network_error)?};
        read_bounded(response,16384,cancel).await
    }

    pub(crate) async fn structure_context(&self, nonce: &str, cancel: &CancellationToken) -> Result<ExactHttpResponse, TransportError> {
        self.metrics.context.fetch_add(1,Ordering::Relaxed);
        if nonce.len()!=43 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'_' || b==b'-') {
            return Err(TransportError::InvalidOrigin);
        }
        let mut url=self.endpoint("/api/workspace/v1/structure/context")?;
        url.query_pairs_mut().append_pair("nonce",nonce);
        let response=tokio::select! {
            _=cancel.cancelled()=>return Err(TransportError::Cancelled),
            result=self.measured_send(self.client.get(url).header("Cache-Control","no-store").send()) =>result.map_err(map_network_error)?,
        };
        read_bounded(response,8192,cancel).await
    }

    pub(crate) async fn install_capabilities(&self, cancel: &CancellationToken) -> Result<ExactHttpResponse, TransportError> {
        let url = self.endpoint("/api/workspace/v1/install-capabilities")?;
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = self.measured_send(self.client.get(url).send()) => result.map_err(map_network_error)?,
        };
        read_bounded(response, 16_384, cancel).await
    }

    /// Bounded anonymous read-view artifacts only. Never falls back to journal access.
    pub(crate) async fn get_public_read_view(&self, workspace: &str, artifact: &str, parameter: &str, max_bytes: usize, cancel: &CancellationToken) -> Result<ExactHttpResponse, TransportError> {
        let token = |v: &str| v.len() == 43 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        let hash = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let observe = artifact == "observe";
        let valid = if observe { token(parameter) && max_bytes <= 2*1024*1024 } else {
            (artifact.strip_prefix("nodes/").is_some_and(hash) || artifact.strip_prefix("commits/").is_some_and(hash)) && hash(parameter) && max_bytes <= 2*1024*1024+196608
        };
        if !token(workspace) || !valid { return Err(TransportError::InvalidOrigin); }
        let mut url = self.endpoint(&format!("/api/workspace/v1/public/workspaces/{workspace}/read-view/{artifact}"))?;
        url.query_pairs_mut().append_pair(if observe { "nonce" } else { "root" }, parameter);
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = self.measured_send(self.client.get(url).header("Cache-Control", "no-store").send()) => result.map_err(map_network_error)?,
        };
        read_bounded(response, max_bytes, cancel).await
    }

    /// Signed protected-profile reads; path construction is fixed and independently bounded.
    pub(crate) async fn get_secure_read_view(&self, workspace: &str, artifact: &str,
        parameter: &str, proof: &str, max_bytes: usize, cancel: &CancellationToken)
        -> Result<ExactHttpResponse,TransportError> {
        let token=|v:&str| v.len()==43 && v.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-');
        let hash=|v:&str| v.len()==64 && v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
        let observe=artifact=="observe";
        let valid=if observe {token(parameter)&&max_bytes<=2*1024*1024} else {
            (artifact.strip_prefix("nodes/").is_some_and(hash)||artifact.strip_prefix("commits/").is_some_and(hash))
                &&hash(parameter)&&max_bytes<=2*1024*1024+196608};
        if !token(workspace)||!valid||proof.is_empty()||proof.len()>12000 {return Err(TransportError::InvalidOrigin)}
        let mut url=self.endpoint(&format!("/api/workspace/v1/secure/workspaces/{workspace}/read-view/{artifact}"))?;
        url.query_pairs_mut().append_pair(if observe {"nonce"} else {"root"},parameter);
        let response=tokio::select! {
            _=cancel.cancelled()=>return Err(TransportError::Cancelled),
            result=self.measured_send(self.client.get(url).header("X-Peerwork-Read",proof).header("Cache-Control","no-store").send()) =>result.map_err(map_network_error)?,
        };
        read_bounded(response,max_bytes,cancel).await
    }

    /// Owner/publisher-signed read-model artifact publication. The body has its own signed command ID.
    pub(crate) async fn post_read_view_publication(&self, body:&[u8], proof:&str,
        cancel:&CancellationToken) -> Result<ExactHttpResponse,TransportError> {
        if body.len()>8*1024*1024||proof.is_empty()||proof.len()>12000{return Err(TransportError::ResponseTooLarge)}
        let url=self.endpoint("/api/workspace/v1/read-model/publications")?;
        let response=tokio::select! {
            _=cancel.cancelled()=>return Err(TransportError::Cancelled),
            result=self.measured_send(self.client.post(url).header("X-Peerwork-Read",proof).header("Content-Type","application/json").body(body.to_vec()).send()) =>result.map_err(map_network_error)?,
        };
        read_bounded(response,2*1024*1024,cancel).await
    }

    /// System-maintained structure page with original encrypted author evidence.
    pub(crate) async fn get_secure_current_page(&self, workspace:&str, nonce:&str, query:&str,
        proof:&str, cancel:&CancellationToken) -> Result<ExactHttpResponse,TransportError> {
        let token=|v:&str|v.len()==43&&v.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-');
        if !token(workspace)||!token(nonce)||query.len()>6000||query.is_empty()||!query.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-')||proof.is_empty()||proof.len()>16000{return Err(TransportError::InvalidOrigin)}
        let mut url=self.endpoint(&format!("/api/workspace/v1/secure/workspaces/{workspace}/current-page"))?;
        url.query_pairs_mut().append_pair("nonce",nonce).append_pair("query",query);
        let response=tokio::select! {
            _=cancel.cancelled()=>return Err(TransportError::Cancelled),
            result=self.measured_send(self.client.get(url).header("X-Peerwork-Read",proof).header("Cache-Control","no-store").send()) =>result.map_err(map_network_error)?,
        };
        read_bounded(response,8*1024*1024,cancel).await
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
        let send = self.measured_send(self.client.get(url).send());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        read_bounded(response, max_response_bytes, cancel).await
    }

    /// Bulk transfer is bound by a core-verified Owner command and digest.
    /// Never export a database credential or redirect a signed request.
    pub(crate) async fn migration_upload(&self,jws:&str,bytes:Vec<u8>,cancel:&CancellationToken)->Result<ExactHttpResponse,TransportError>{
        if jws.len()>32768||bytes.len()>64*1024*1024{return Err(TransportError::InvalidOrigin);}
        let request=self.measured_send(self.client.post(self.endpoint("/api/workspace/v1/structure/migration-upload")?).header("X-Peerwork-Migration-JWS",jws).header("Content-Type","application/octet-stream").body(bytes).send());
        let response=tokio::select!{_=cancel.cancelled()=>return Err(TransportError::SubmittedUncertain),result=request=>result.map_err(|_|TransportError::SubmittedUncertain)?};
        read_bounded(response,MAX_COMMAND_RESPONSE_BYTES,cancel).await
    }
    pub(crate) async fn migration_source(&self,jws:&str,cancel:&CancellationToken)->Result<(ExactHttpResponse,Vec<u8>),TransportError>{
        if jws.len()>32768{return Err(TransportError::InvalidOrigin);}
        let request=self.measured_send(self.client.post(self.endpoint("/api/workspace/v1/structure/migration-source")?).header("X-Peerwork-Migration-JWS",jws).send());
        let response=tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled),result=request=>result.map_err(map_network_error)?};
        if !response.status().is_success(){return Ok((read_bounded(response,MAX_COMMAND_RESPONSE_BYTES,cancel).await?,vec![]));}
        let receipt=response.headers().get("X-Peerwork-Migration-Receipt").and_then(|v|v.to_str().ok()).filter(|s|s.len()<=32768).ok_or(TransportError::InvalidOrigin)?;
        let wire=peerwork_core::crypto::decode_base64url(receipt).map_err(|_|TransportError::InvalidOrigin)?;
        let bytes=read_bounded(response,64*1024*1024,cancel).await?;
        Ok((ExactHttpResponse{status:bytes.status,wire},bytes.wire))
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
        let send = self.measured_send(self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::SubmittedUncertain),
            result = send => result.map_err(|_| TransportError::SubmittedUncertain)?,
        };
        let response = read_bounded(response, MAX_COMMAND_RESPONSE_BYTES, cancel)
            .await
            .map_err(|_| TransportError::SubmittedUncertain)?;
        #[cfg(test)]
        if TEST_DROP_NEXT_SECURE_POST_RESPONSE.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(TransportError::SubmittedUncertain);
        }
        Ok(response)
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
        let send = self.measured_send(self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("X-Peerwork-Read", read_proof)
            .body(body)
            .send());
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
        let send = self.measured_send(self
            .client
            .get(url)
            .header("X-Peerwork-Read", read_proof)
            .send());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        self.observe_migration_source_time(&response);
        read_bounded(response, max_response_bytes, cancel).await
    }

    /// Anonymous journal bytes. Only the shared signed replay can authorize content.
    pub(crate) async fn get_public_journal_exact(&self, workspace:&str, after:u64, cancel:&CancellationToken)->Result<ExactHttpResponse,TransportError>{
        if !valid_identity_token(workspace){return Err(TransportError::InvalidOrigin)}
        let path=format!("/api/workspace/v1/public/secure/workspaces/{workspace}/journal?after={after}&limit=50");
        let send=self.measured_send(self.client.get(self.endpoint(&path)?).send());
        let response=tokio::select!{_ = cancel.cancelled()=>return Err(TransportError::Cancelled),result=send=>result.map_err(map_network_error)?};
        read_bounded(response,8*1024*1024,cancel).await
    }

    /// Exact actor-authenticated PUBLIC workspace administration snapshot.
    /// The response is ordinary JSON; callers must compare it to the
    /// compiler-derived artifact and command-bound signed receipts.
    pub(crate) async fn get_public_workspace_snapshot(
        &self,
        workspace_id: &str,
        read_proof: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, TransportError> {
        let path = format!("/api/workspace/v1/admin/workspaces/{workspace_id}");
        if !valid_identity_token(workspace_id)
            || read_proof.is_empty()
            || read_proof.len() > 12_000
        {
            return Err(TransportError::InvalidOrigin);
        }
        let url = self.endpoint(&path)?;
        let send = self.measured_send(self
            .client
            .get(url)
            .header("X-Peerwork-Read", read_proof)
            .send());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(|_| TransportError::Network)?,
        };
        read_bounded(response, MAX_COMMAND_RESPONSE_BYTES, cancel).await
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
        let send = self.measured_send(self
            .client
            .get(url)
            .header("connection", "close")
            .header("X-Peerwork-Read", read_proof)
            .send());
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(TransportError::Cancelled),
            result = send => result.map_err(map_network_error)?,
        };
        read_bounded(response, 220_000, cancel).await
    }

    /// Fixed-origin exact browser request read; never accepts a caller URL.
    pub(crate) async fn get_browser_approval_request(&self, workspace:&str, request:&str, proof:&str, cancel:&CancellationToken)->Result<ExactHttpResponse,TransportError> {
        let valid=|v:&str|v.len()==43 && v.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'-'|b'_'));
        if !valid(workspace)||!valid(request)||proof.is_empty()||proof.len()>12000 { return Err(TransportError::InvalidOrigin); }
        let path=format!("/api/workspace/v1/admin/workspaces/{workspace}/browser-requests/{request}");
        let send=self.measured_send(self.client.get(self.endpoint(&path)?).header("X-Peerwork-Read",proof).send());
        let response=tokio::select! { _=cancel.cancelled()=>return Err(TransportError::Cancelled), result=send=>result.map_err(map_network_error)?, };
        read_bounded(response,262_144,cancel).await
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
            result = self.measured_send(self.client.get(self.endpoint(path)?)
                .header("X-Peerwork-Read", read_proof).send()) =>
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
            result = self.measured_send(self.client.get(self.endpoint(path)?)
                .header("X-Peerwork-Read", read_proof).send()) =>
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
            result = self.measured_send(self.client.post(self.endpoint(path)?)
                .header("content-type", "application/json")
                .header("X-Peerwork-Read", read_proof)
                .body(body).send()) =>
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

fn selected_proxy(
    configured: Option<String>,
    environment: Result<String, std::env::VarError>,
) -> Result<Option<String>, TransportError> {
    match configured {
        Some(proxy) => Ok(Some(proxy)),
        None => match environment {
            Ok(proxy) => Ok(Some(proxy)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(TransportError::InvalidTrust),
        },
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

    #[tokio::test]
    async fn send_phase_scope_excludes_interleaved_and_spawned_work_and_survives_cancellation(){
        let transport=HttpTransport::new(TransportConfig::new("https://example.invalid")).unwrap();
        tokio::join!(
            track_foreground_send(async{let _phase=transport.phase(ClientPhase::BodyPrepare);tokio::task::yield_now().await;}),
            async{let _phase=transport.phase(ClientPhase::BodyPrepare);tokio::task::yield_now().await;}
        );
        assert_eq!(transport.metrics()["local_phases"]["body_prepare"]["count"],2);
        assert_eq!(transport.metrics()["send_execution_phases"]["body_prepare"]["count"],1);
        let other=transport.clone();
        track_foreground_send(async{
            let _phase=transport.phase(ClientPhase::BodyPrepare);
            tokio::spawn(async move{let _phase=other.phase(ClientPhase::BodyPrepare);tokio::task::yield_now().await;}).await.unwrap();
        }).await;
        let(tx,rx)=tokio::sync::oneshot::channel();
        let mut pending=Box::pin(track_foreground_send(async{
            let _phase=transport.phase(ClientPhase::BodyPrepare);
            let _=tx.send(());
            std::future::pending::<()>().await;
        }));
        tokio::select!{_=pending.as_mut()=>panic!("pending scope unexpectedly finished"),_=rx=>{}}
        drop(pending);
        // Scope restoration and timer Drop must work even when the whole
        // caller future is cancelled, not just on the successful branch.
        drop(transport.phase(ClientPhase::BodyPrepare));
        assert_eq!(transport.metrics()["local_phases"]["body_prepare"]["count"],6);
        assert_eq!(transport.metrics()["send_execution_phases"]["body_prepare"]["count"],3);
        assert_eq!(transport.metrics()["send_execution_phases"]["http_roundtrip"]["count"],0);
    }

    #[test]
    fn authorization_cache_advances_monotonically_without_extending_verified_expiry(){
        use ed25519_dalek::{Signer,SigningKey};
        use peerwork_core::crypto::base64url;
        let signing=SigningKey::from_bytes(&[7u8;32]);let key=base64url(signing.verifying_key().as_bytes());
        let nonce=base64url(&[1u8;32]);let time=1230000000000u64;
        let header=base64url(serde_json::json!({"alg":"EdDSA","typ":peerwork_core::structure_context::CONTEXT_TYPE,"kid":key}).to_string().as_bytes());
        let payload=base64url(serde_json::json!({"v":1,"audience":"test","profile":"backend-structure-v1","nonce":nonce,"idempotency":"BUSINESS_INTENT_V1","assurance":"BACKEND_CURRENT_STATE","authorization_ttl_ms":600000,"server_time_ms":time}).to_string().as_bytes());
        let input=format!("{header}.{payload}");let signature=base64url(&signing.sign(input.as_bytes()).to_bytes());
        let wire=serde_json::json!({"context":format!("{input}.{signature}")}).to_string();
        let context=peerwork_core::structure_context::verify_structure_context(wire.as_bytes(),&nonce,&"test".encode_utf16().collect::<Vec<_>>(),&key).unwrap();
        let transport=HttpTransport::new(local_config("http://127.0.0.1:1".into())).unwrap();
        assert!(transport.cached_context(&key).is_none());
        transport.remember_context(&key,&context,Instant::now()-Duration::from_secs(45));
        let shared=transport.clone();let window=shared.cached_context(&key).unwrap();
        assert!((time+45000..time+46000).contains(&window.server_time_ms()));
        assert_eq!(window.expires_at_ms(),time+600000);
        assert!(shared.cached_context("another-service-key").is_none());
        transport.remember_context(&key,&context,Instant::now()-Duration::from_secs(540));
        assert!(shared.cached_context(&key).is_none(),"a cached anchor cannot extend itself");
    }

    #[tokio::test]
    async fn migration_source_clock_uses_service_time_and_monotonic_expiry(){
        let (origin,server)=one_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Peerwork-Server-Time: 1230000000000\r\nConnection: close\r\n\r\n{}").await;
        let transport=HttpTransport::new(local_config(origin)).unwrap();assert!(transport.migration_source_time_ms().is_none());transport.discovery(&CancellationToken::new()).await.unwrap();server.await.unwrap();let now=transport.migration_source_time_ms().unwrap();assert!((1230000000000..1230000002000).contains(&now));
        *transport.migration_source_clock.lock().unwrap()=Some((1230000000000,Instant::now()-Duration::from_secs(61)));assert!(transport.migration_source_time_ms().is_none());
    }
    #[tokio::test]
    async fn migration_source_clock_rejects_missing_invalid_and_error_response_headers(){
        for response in [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice(),b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Peerwork-Server-Time: -1\r\nConnection: close\r\n\r\n{}",b"HTTP/1.1 503 Unavailable\r\nContent-Length: 2\r\nX-Peerwork-Server-Time: 1230000000000\r\nConnection: close\r\n\r\n{}"]{let (origin,server)=one_response(response).await;let transport=HttpTransport::new(local_config(origin)).unwrap();transport.discovery(&CancellationToken::new()).await.unwrap();server.await.unwrap();assert!(transport.migration_source_time_ms().is_none());}
    }

    #[test]
    fn explicit_proxy_selection_is_opt_in_and_config_takes_precedence() {
        assert_eq!(selected_proxy(None, Err(std::env::VarError::NotPresent)).unwrap(), None);
        assert_eq!(selected_proxy(None, Ok("http://127.0.0.1:1234".into())).unwrap(),
            Some("http://127.0.0.1:1234".into()));
        assert_eq!(selected_proxy(Some("http://127.0.0.1:4321".into()),
            Ok("http://127.0.0.1:1234".into())).unwrap(),
            Some("http://127.0.0.1:4321".into()));
        assert!(matches!(selected_proxy(None, Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::from("invalid")))), Err(TransportError::InvalidTrust)));
    }

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

#[cfg(test)]
mod lifecycle_origin_contract_tests {
    use super::*;
    #[test]
    fn lifecycle_origin_is_canonical_without_rebinding_input() {
        let raw = String::from("http://127.0.0.1:34635");
        assert_eq!(canonical_lifecycle_origin(&raw, true).unwrap(), "http://127.0.0.1:34635/");
        assert_eq!(canonical_lifecycle_origin(&(raw.clone() + "/"), true).unwrap(), canonical_lifecycle_origin(&raw, true).unwrap());
        assert_eq!(raw, "http://127.0.0.1:34635");
        assert!(canonical_lifecycle_origin(&raw, false).is_err());
        assert!(canonical_lifecycle_origin("https://example.com/path", false).is_err());
        assert!(canonical_lifecycle_origin("https://user@example.com/", false).is_err());
    }
}

#[cfg(test)]
mod lifecycle_origin_reopen_tests {
use crate::secure_lifecycle::SecureLifecycle;
use peerwork_core::crypto::base64url;

#[test]
fn canonical_lifecycle_reopen_preserves_existing_bytes() {
    let directory = crate::test_support::protected_test_dir();
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap(); }
    let path = directory.path().join("lifecycle.state");
    let actor = base64url(&[31; 32]);
    let key = base64url(&[32; 32]);
    let workspace = base64url(&[33; 32]);
    assert!(SecureLifecycle::open(&path, "http://127.0.0.1:34635", &actor, &workspace, &actor, &key).is_err());
    assert!(!path.exists());
    drop(SecureLifecycle::open(&path, "http://127.0.0.1:34635/", &actor, &workspace, &actor, &key).unwrap());
    let before = std::fs::read(&path).unwrap(); // Fresh test state contains pins only, no epoch keys.
    drop(SecureLifecycle::open(&path, "http://127.0.0.1:34635/", &actor, &workspace, &actor, &key).unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

}

#[cfg(test)]
mod transport_options_tests {
    use super::*;
    #[test]
    fn defaults_and_invalid_inputs_remain_checked() {
        let default: TransportOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(default, TransportOptions::default()); assert_eq!(default.request_timeout_ms, 15_000);
        assert!(serde_json::from_str::<TransportOptions>(r#"{"request_timeout_ms":-1}"#).is_err());
        assert!(serde_json::from_str::<TransportOptions>(r#"{"unknown":1}"#).is_err());
        assert!(TransportOptions { request_timeout_ms: 0, ..default.clone() }.validate().is_err());
        // Platform representability is checked, with no invented daily ceiling.
        assert!(TransportOptions { request_timeout_ms: 86_400_001, ..default.clone() }.validate().is_ok());
        let _ = TransportOptions { request_timeout_ms: u64::MAX, ..default.clone() }.validate();
        assert!(TransportOptions { additional_root_pem_files: vec!["x".into();17], ..default.clone() }.validate().is_err());
        assert!(TransportOptions { additional_root_pem_files: vec!["".into()], ..default }.validate().is_err());
    }
    #[test]
    fn certificate_files_fail_closed_under_actual_read_bounds() {
        let root = tempfile::tempdir().unwrap();
        for (name, bytes) in [("empty",Vec::new()),("bad",b"not a certificate".to_vec()),("large",vec![b' ';65_537])] {
            let path = root.path().join(name);std::fs::write(&path,bytes).unwrap();
            assert!(TransportOptions { additional_root_pem_files:vec![path], ..Default::default() }.roots().is_err());
        }
        assert!(TransportOptions { additional_root_pem_files:vec![root.path().into()], ..Default::default() }.roots().is_err());
    }
    #[tokio::test]
    #[ignore = "requires the task-local actual HTTPS fixture"]
    async fn local_https_preserves_validation_and_selected_deadline() {
        let origin=std::env::var("PEERWORK_TLS_ORIGIN").unwrap();let ca=std::env::var("PEERWORK_TLS_CA").unwrap();
        let cancel=CancellationToken::new();
        let no_ca=HttpTransport::new(TransportConfig::new(&origin)).unwrap();
        assert!(no_ca.discovery(&cancel).await.is_err());
        let options=TransportOptions { request_timeout_ms:2_000,additional_root_pem_files:vec![ca.clone().into()] };
        let good=HttpTransport::new(TransportConfig::new(&origin).with_options(options.clone())).unwrap();
        assert_eq!(good.discovery(&cancel).await.unwrap().wire,b"{\"ok\":true}");
        let wrong=origin.replace("localhost","127.0.0.1");
        let wrong=HttpTransport::new(TransportConfig::new(&wrong).with_options(options.clone())).unwrap();
        assert!(wrong.discovery(&cancel).await.is_err());
        let short=HttpTransport::new(TransportConfig::new(&origin).with_options(TransportOptions { request_timeout_ms:40,..options.clone() })).unwrap();
        assert!(matches!(short.discovery(&cancel).await,Err(TransportError::Timeout)));
        assert_eq!(good.discovery(&cancel).await.unwrap().wire,b"{\"ok\":true}");
        let root=tempfile::tempdir().unwrap();let cert=std::fs::read(ca).unwrap();
        let mut padded=cert;padded.resize(65_536,b' ');
        let files=(0..5).map(|i| {let p=root.path().join(i.to_string());std::fs::write(&p,&padded).unwrap();p}).collect();
        assert!(TransportOptions { additional_root_pem_files:files,..options }.roots().is_err());
        println!("HTTPS_RESULT untrusted=REFUSED explicitCA=PASS hostname=REFUSED selected40ms=TIMEOUT recovery=PASS aggregateCA=REFUSED");
    }
}
