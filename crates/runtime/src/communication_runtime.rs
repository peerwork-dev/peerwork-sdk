//! Resident hosting of the same participant engine used by Rust applications.
//! A credential selects one identity and narrowed scope; administration uses
//! a separate credential. Requests cannot select keys, profiles or state paths.
#[cfg(test)]
#[path = "communication_runtime_tests.rs"]
mod tests;
use crate::communication_local_channel as channel;
#[path = "communication_client.rs"]
mod client;
use crate::{
    communication_host::{random_token, write_private},
    communication_store::{identifier, private_json},
    participant::{
        Capability, DeliveryReference, Invoke, MigrationSource, ParticipantClient,
        ParticipantConfig, ParticipantError, ProgramWatch, Result, ResultSelection, WatchOptions,
    },
    secure_state::{create_private_state_directory, SecureStateStore},
    KernelCancellationToken,
};
pub use client::RuntimeClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};

const REQUEST_FORMAT: &str = "peerwork.participant-request.v1";
const RESPONSE_FORMAT: &str = "peerwork.participant-response.v1";
const ENDPOINT_FORMAT: &str = "peerwork.participant-endpoint.v1";
const MAX_REQUEST: usize = 512 * 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024 + 4096;
const MAX_WIRE_REQUEST: usize = MAX_REQUEST * 2 + 4096;
const MAX_WIRE_RESPONSE: usize = MAX_RESPONSE * 2 + 4096;
const HELLO_FORMAT: &str = "peerwork.participant-hello.v1";
const CHALLENGE_FORMAT: &str = "peerwork.participant-challenge.v1";
const AUTH_FORMAT: &str = "peerwork.participant-auth.v1";
const SEALED_REQUEST: &str = "peerwork.participant-sealed-request.v1";
const SEALED_RESPONSE: &str = "peerwork.participant-sealed-response.v1";
const HANDSHAKE_METHOD: &str = "PARTICIPANT_HANDSHAKE";
const MAX_CONNECTION_REQUESTS: usize = 256;
const MAX_CONNECTIONS: usize = 16;
const MAX_CALLS_PER_CONNECTION: usize = 4;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
// Leave room for a queued legitimate peer while unauthenticated slots expire.
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
fn local(code: &str) -> ParticipantError {
    ParticipantError::local(code, "LOCAL_IPC")
}
fn observation(mut error: ParticipantError) -> ParticipantError {
    error.effect_certainty = "UNKNOWN".into();
    error.recovery = "OBSERVE_OR_RECOVER_ORIGINAL_OPERATION".into();
    error
}
fn defaults_inflight() -> usize {
    4
}
fn defaults_pending() -> usize {
    64
}
fn defaults_bytes() -> usize {
    32 * 1024 * 1024
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub name: String,
    pub origin: String,
    pub expected_actor: String,
    #[serde(default)]
    pub authority: Option<String>,
    pub identity_path: PathBuf,
    pub state_directory: PathBuf,
    #[serde(default)]
    pub journal_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default)]
    pub transport: crate::transport::TransportOptions,
    #[serde(default = "defaults_inflight")]
    pub max_inflight: usize,
    #[serde(default = "defaults_pending")]
    pub max_pending: usize,
    #[serde(default = "defaults_bytes")]
    pub max_stored_bytes: usize,
    #[serde(default)]
    pub migration_sources: Vec<MigrationSource>,
}
impl EngineConfig {
    pub fn load(path: &Path) -> Result<Self> {
        serde_json::from_value(
            private_json(path, 65536).map_err(|_| local("ENGINE_CONFIG_NOT_PRIVATE"))?,
        )
        .map_err(|_| local("ENGINE_CONFIG_INVALID"))
    }
    pub fn participant_config(&self) -> ParticipantConfig {
        let mut options = ParticipantConfig::new(
            &self.origin,
            &self.expected_actor,
            &self.identity_path,
            &self.state_directory,
        );
        if let Some(path) = &self.journal_path {
            options.journal_path = path.clone();
        }
        options.allow_loopback_http = self.allow_loopback_http;
        options.authority = self.authority.clone();
        options.transport = self.transport.clone();
        options.max_inflight = self.max_inflight;
        options.max_pending = self.max_pending;
        options.max_stored_bytes = self.max_stored_bytes;
        options.migration_sources = self.migration_sources.clone();
        options
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub name: String,
    pub engine: String,
    pub capability: Capability,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub format: String,
    pub state_directory: PathBuf,
    pub engines: Vec<EngineConfig>,
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub hosts: Vec<crate::participant_dispatch::HostConfig>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RuntimeReady {
    pub state: String,
    pub admin_endpoint: PathBuf,
    pub client_endpoints: BTreeMap<String, PathBuf>,
}
#[derive(Clone)]
struct Session {
    token: String,
    client: ParticipantClient,
    watches: Arc<tokio::sync::Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<ProgramWatch>>>>>,
}
struct Runtime {
    owners: BTreeMap<String, ParticipantClient>,
    sessions: Vec<Session>,
    admin_token: String,
    host_status: Vec<Arc<std::sync::Mutex<Value>>>,
    cancel: KernelCancellationToken,
}

/// Shared by CLI and thin program clients. Business actions remain data
/// discovered from the selected protocol, not another handwritten catalog.
#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRequest {
    DeliveryStatus {
        options: WatchOptions,
        item: DeliveryReference,
    },
    Watch {
        options: WatchOptions,
    },
    Unwatch {
        options: WatchOptions,
    },
    WatchNext {
        options: WatchOptions,
        wait_ms: u64,
    },
    WaitInbox {
        options: WatchOptions,
        #[serde(default)]
        after: u64,
        limit: usize,
        wait_ms: u64,
    },
    Inbox {
        options: WatchOptions,
        #[serde(default)]
        after: u64,
        limit: usize,
    },
    Consume {
        options: WatchOptions,
        items: Vec<DeliveryReference>,
    },
    Invoke {
        request: Invoke,
        #[serde(default)]
        wait_ms: u64,
    },
    Request {
        request: Invoke,
    },
    Operation {
        operation_id: String,
    },
    OperationResult {
        operation_id: String,
        selection: ResultSelection,
    },
    Recover {
        operation_id: String,
    },
    Operations {
        #[serde(default)]
        after: String,
        limit: usize,
    },
    Capabilities,
    Bindings,
}
impl ClientRequest {
    fn parse(value: Value) -> Result<Self> {
        // Non-unit variants use serde's deny_unknown_fields. The only unit
        // variant needs an explicit extra-field check; do not maintain a second
        // handwritten method/field catalog that can diverge from this enum.
        let request: Self =
            serde_json::from_value(value.clone()).map_err(|_| local("CLIENT_REQUEST_INVALID"))?;
        if matches!(request, Self::Capabilities | Self::Bindings)
            && value.as_object().is_none_or(|o| o.len() != 1)
        {
            return Err(local("CLIENT_REQUEST_INVALID"));
        }
        Ok(request)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    format: String,
    request_id: String,
    request: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    format: String,
    address: SocketAddr,
    token: String,
    access: String,
}
fn equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |v, (a, b)| v | (a ^ b)) == 0
}
fn response(id: &str, out: Result<Value>) -> Value {
    match out {
        Ok(value) => json!({"format":RESPONSE_FORMAT,"request_id":id,"ok":true,"value":value}),
        Err(error) => json!({"format":RESPONSE_FORMAT,"request_id":id,"ok":false,"error":error}),
    }
}
impl Runtime {
    fn credential(&self, id: &str) -> Option<&str> {
        std::iter::once(self.admin_token.as_str())
            .chain(self.sessions.iter().map(|s| s.token.as_str()))
            .find(|key| equal(&channel::key_id(key), id))
    }
    async fn request(&self, frame: Frame, credential: &str) -> Value {
        let id = &frame.request_id;
        if frame.format != REQUEST_FORMAT || !identifier(id) {
            return response(id, Err(local("IPC_FRAME_INVALID")));
        }
        if equal(credential, &self.admin_token) {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct AdminRequest {
                method: String,
            }
            let value=async{match serde_json::from_value::<AdminRequest>(frame.request){
                Ok(request)if request.method=="stop"=>Ok(json!({"state":"STOPPING"})),
                Ok(request)if request.method=="status"=>{
                    let mut engines=Vec::new();for (name,owner) in &self.owners{engines.push(json!({"name":name,"metrics":owner.metrics().await?}));}
                    Ok(json!({"state":"LOCAL_READY","engines":engines,"hosts":self.host_status.iter().map(|s|s.lock().map(|v|v.clone()).unwrap_or_else(|_|json!({"state":"UNKNOWN"}))).collect::<Vec<_>>(),"network_or_host_readiness":"NOT_ATTESTED"}))
                },_=>Err(local("ADMIN_COMMAND_INVALID")),
            }}.await;
            return response(id, value);
        }
        let Some(session) = self
            .sessions
            .iter()
            .find(|session| equal(&session.token, credential))
        else {
            return response(id, Err(local("IPC_UNAUTHORIZED")));
        };
        let value=async{
            let request=ClientRequest::parse(frame.request)?;
            let client=&session.client;
            match request{
                ClientRequest::DeliveryStatus{options,item}=>client.delivery_status(&options,item).await,
                ClientRequest::Unwatch{options}=>{client.unwatch(&options).await?;session.watches.lock().await.remove(&options.key());Ok(json!({"state":"LOCAL_STOPPED","lease_expires_within_ms":15000,"messages_deleted":false}))},
                ClientRequest::Watch{options}=>{
                    let mut watches=session.watches.lock().await;
                    if !watches.contains_key(&options.key()){
                        if watches.len()>=8{return Err(local("WATCH_SCOPE_LIMIT"));}
                        let watch=client.watch(options.clone()).await?;watches.insert(options.key(),Arc::new(tokio::sync::Mutex::new(watch)));
                    }else{
                        let watch=watches.get(&options.key()).unwrap().clone().try_lock_owned().map_err(|_|local("WATCH_WAIT_IN_PROGRESS"))?;
                        if watch.options()!=&options{return Err(local("WATCH_BINDING_MISMATCH"));}
                    }
                    drop(watches);
                    serde_json::to_value(client.inbox(&options,0,32).await?).map_err(|_|local("IPC_RESPONSE_INVALID"))
                },
                ClientRequest::WatchNext{options,wait_ms}=>{
                    if wait_ms==0||wait_ms>30_000{return Err(local("WAIT_BUDGET_INVALID"));}
                    let watch=session.watches.lock().await.get(&options.key()).cloned().ok_or_else(||local("WATCH_NOT_FOUND"))?;
                    let mut watch=watch.try_lock_owned().map_err(|_|local("WATCH_WAIT_IN_PROGRESS"))?;
                    if watch.options()!=&options{return Err(local("WATCH_BINDING_MISMATCH"));}
                    match tokio::time::timeout(Duration::from_millis(wait_ms),watch.next()).await{
                        Ok(value)=>serde_json::to_value(value?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                        Err(_)=>Ok(json!({"state":"WAIT_EXPIRED","scope":"LOCAL_OBSERVATION_ONLY","watch_continues":true})),
                    }
                },
                ClientRequest::WaitInbox{options,after,limit,wait_ms}=>{
                    if !(1..=32).contains(&limit)||after>9_007_199_254_740_991{return Err(local("INBOX_SELECTION_INVALID"));}
                    if wait_ms==0||wait_ms>30_000{return Err(local("WAIT_BUDGET_INVALID"));}
                    // Attach a notification handle to the same owned mailbox,
                    // not a second remote receiver. Snapshot after every wake
                    // so an initial state/heartbeat cannot satisfy an arrival.
                    let mut watch=client.watch(options).await?;
                    let observed=async{loop{
                        watch.changed().await?;
                        let page=watch.page(after,limit).await?;
                        if !page.items.is_empty(){return serde_json::to_value(page).map_err(|_|local("IPC_RESPONSE_INVALID"));}
                    }};
                    match tokio::time::timeout(Duration::from_millis(wait_ms),observed).await{
                        Ok(out)=>out,
                        Err(_)=>Ok(json!({"state":"WAIT_EXPIRED","scope":"LOCAL_OBSERVATION_ONLY","watch_continues":true})),
                    }
                },
                ClientRequest::Inbox{options,after,limit}=>serde_json::to_value(client.inbox(&options,after,limit).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::Consume{options,items}=>{client.consume(&options,items).await?;Ok(json!({"state":"LOCAL_CONSUMPTION_RECORDED","remote_ack":"ASYNCHRONOUS","model_response":"NOT_ATTESTED"}))},
                ClientRequest::Invoke{request,wait_ms}=>{if wait_ms>30_000{return Err(local("WAIT_BUDGET_INVALID"));}serde_json::to_value(client.invoke(request,Duration::from_millis(wait_ms)).await?).map_err(|_|local("IPC_RESPONSE_INVALID"))},
                ClientRequest::Request{request}=>client.request(request).await,
                ClientRequest::Operation{operation_id}=>serde_json::to_value(client.operation(&operation_id).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::OperationResult{operation_id,selection}=>client.operation_result(&operation_id,selection).await,
                ClientRequest::Recover{operation_id}=>serde_json::to_value(client.recover(&operation_id).await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::Operations{after,limit}=>client.operations(&after,limit).await,
                ClientRequest::Bindings=>serde_json::to_value(client.watch_bindings().await?).map_err(|_|local("IPC_RESPONSE_INVALID")),
                ClientRequest::Capabilities=>Ok(json!({"format":"peerwork.participant-capability.v1","actor_id":client.actor_id(),"origin":client.origin(),"capability":client.capability(),"admin":false,"availability":"UNRELEASED_CANDIDATE"})),
            }
        }.await;
        response(id, value)
    }
}
async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    read: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let available = read
            .fill_buf()
            .await
            .map_err(|_| local("IPC_DISCONNECTED"))?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(local("IPC_FRAME_INCOMPLETE"))
            };
        }
        let end = available.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let count = end.unwrap_or(available.len());
        if bytes.len() + count > limit {
            return Err(local("IPC_FRAME_TOO_LARGE"));
        }
        bytes.extend_from_slice(&available[..count]);
        read.consume(count);
        if end.is_some() {
            return Ok(Some(bytes));
        }
    }
}
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(write: &mut W, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| local("IPC_RESPONSE_INVALID"))?;
    if bytes.len() > MAX_WIRE_RESPONSE {
        return Err(local("IPC_RESPONSE_TOO_LARGE"));
    }
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(3), write.write_all(&bytes))
        .await
        .map_err(|_| local("IPC_WRITE_TIMEOUT"))?
        .map_err(|_| local("IPC_DISCONNECTED"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    format: String,
    key_id: String,
    client_nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedFrame {
    format: String,
    payload: String,
}
pub(crate) struct Authenticated {
    credential: String,
    method: String,
}
fn opaque_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
async fn accept_handshake<R: tokio::io::AsyncBufRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    runtime: &Runtime,
) -> Result<Authenticated> {
    let wire = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(read, 4096))
        .await
        .map_err(|_| local("IPC_HANDSHAKE_TIMEOUT"))??
        .ok_or_else(|| local("IPC_DISCONNECTED"))?;
    let hello: Hello = serde_json::from_value(
        peerwork_core::strict_json::parse_strict_json(&wire)
            .map_err(|_| local("IPC_UNAUTHORIZED"))?,
    )
    .map_err(|_| local("IPC_UNAUTHORIZED"))?;
    if hello.format != HELLO_FORMAT
        || !opaque_token(&hello.key_id)
        || !opaque_token(&hello.client_nonce)
    {
        return Err(local("IPC_UNAUTHORIZED"));
    }
    let credential = runtime
        .credential(&hello.key_id)
        .ok_or_else(|| local("IPC_UNAUTHORIZED"))?
        .to_string();
    let nonce = random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?;
    // The challenge is authenticated before the client sends private data.
    let proof = channel::response_bounded(
        &credential,
        HANDSHAKE_METHOD,
        &wire,
        &json!({"format":CHALLENGE_FORMAT,"client_nonce":hello.client_nonce,"server_nonce":nonce}),
        4096,
    )
    .map_err(|_| local("IPC_CHANNEL_INVALID"))?;
    write_frame(write, &json!({"format":CHALLENGE_FORMAT,"payload":proof})).await?;
    let confirmation = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(read, 16384))
        .await
        .map_err(|_| local("IPC_HANDSHAKE_TIMEOUT"))??
        .ok_or_else(|| local("IPC_DISCONNECTED"))?;
    let confirmation: SealedFrame = serde_json::from_value(
        peerwork_core::strict_json::parse_strict_json(&confirmation)
            .map_err(|_| local("IPC_UNAUTHORIZED"))?,
    )
    .map_err(|_| local("IPC_UNAUTHORIZED"))?;
    if confirmation.format != AUTH_FORMAT {
        return Err(local("IPC_UNAUTHORIZED"));
    }
    let proof = channel::open_request_bounded(
        &credential,
        &format!("PARTICIPANT_AUTH:{nonce}"),
        confirmation.payload.as_bytes(),
        4096,
    )
    .map_err(|_| local("IPC_UNAUTHORIZED"))?;
    if proof != json!({"format":AUTH_FORMAT,"client_nonce":hello.client_nonce,"server_nonce":nonce})
    {
        return Err(local("IPC_UNAUTHORIZED"));
    }
    Ok(Authenticated {
        credential,
        method: format!("PARTICIPANT_RPC:{nonce}"),
    })
}
pub(crate) async fn client_handshake(
    stream: &mut BufReader<TcpStream>,
    credential: &str,
) -> Result<Authenticated> {
    let nonce = random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?;
    let hello =
        json!({"format":HELLO_FORMAT,"key_id":channel::key_id(credential),"client_nonce":nonce});
    // Newline is part of the exact challenge transcript on both ends.
    let wire = serde_json::to_string(&hello).map_err(|_| local("IPC_FRAME_INVALID"))? + "\n";
    write_frame(stream.get_mut(), &hello).await?;
    let reply = tokio::time::timeout(CLIENT_HANDSHAKE_TIMEOUT, read_frame(stream, 16384))
        .await
        .map_err(|_| local("IPC_HANDSHAKE_TIMEOUT"))??
        .ok_or_else(|| local("IPC_DISCONNECTED"))?;
    let reply: SealedFrame = serde_json::from_value(
        peerwork_core::strict_json::parse_strict_json(&reply)
            .map_err(|_| local("IPC_PEER_UNVERIFIED"))?,
    )
    .map_err(|_| local("IPC_PEER_UNVERIFIED"))?;
    if reply.format != CHALLENGE_FORMAT {
        return Err(local("IPC_PEER_UNVERIFIED"));
    }
    let proof = channel::open_response_bounded(
        credential,
        HANDSHAKE_METHOD,
        wire.as_bytes(),
        reply.payload.as_bytes(),
        4096,
    )
    .map_err(|_| local("IPC_PEER_UNVERIFIED"))?;
    let server = proof["server_nonce"]
        .as_str()
        .filter(|n| opaque_token(n))
        .ok_or_else(|| local("IPC_PEER_UNVERIFIED"))?;
    if proof["format"] != CHALLENGE_FORMAT || proof["client_nonce"] != nonce {
        return Err(local("IPC_PEER_UNVERIFIED"));
    }
    let confirmation = channel::request_bounded(
        credential,
        &format!("PARTICIPANT_AUTH:{server}"),
        &json!({"format":AUTH_FORMAT,"client_nonce":nonce,"server_nonce":server}),
        4096,
    )
    .map_err(|_| local("IPC_CHANNEL_INVALID"))?;
    write_frame(
        stream.get_mut(),
        &json!({"format":AUTH_FORMAT,"payload":confirmation}),
    )
    .await?;
    Ok(Authenticated {
        credential: credential.into(),
        method: format!("PARTICIPANT_RPC:{server}"),
    })
}
pub(crate) fn encode_request(
    auth: &Authenticated,
    id: &str,
    request: Value,
) -> Result<(Value, String)> {
    let payload = channel::request_bounded(
        &auth.credential,
        &auth.method,
        &json!({"format":REQUEST_FORMAT,"request_id":id,"request":request}),
        MAX_REQUEST,
    )
    .map_err(|_| local("IPC_FRAME_TOO_LARGE"))?;
    Ok((json!({"format":SEALED_REQUEST,"payload":payload}), payload))
}
fn decode_request(auth: &Authenticated, wire: &[u8]) -> Result<(Frame, String)> {
    let outer: SealedFrame = serde_json::from_value(
        peerwork_core::strict_json::parse_strict_json(wire)
            .map_err(|_| local("IPC_FRAME_INVALID"))?,
    )
    .map_err(|_| local("IPC_FRAME_INVALID"))?;
    if outer.format != SEALED_REQUEST {
        return Err(local("IPC_UNAUTHORIZED"));
    }
    let value = channel::open_request_bounded(
        &auth.credential,
        &auth.method,
        outer.payload.as_bytes(),
        MAX_REQUEST,
    )
    .map_err(|_| local("IPC_UNAUTHORIZED"))?;
    let frame: Frame = serde_json::from_value(value).map_err(|_| local("IPC_FRAME_INVALID"))?;
    if frame.format != REQUEST_FORMAT || !identifier(&frame.request_id) {
        return Err(local("IPC_FRAME_INVALID"));
    }
    Ok((frame, outer.payload))
}
pub(crate) fn decode_response(
    auth: &Authenticated,
    id: &str,
    request: &str,
    wire: &[u8],
) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        format: String,
        request_id: String,
        payload: String,
    }
    let outer: Reply = serde_json::from_value(
        peerwork_core::strict_json::parse_strict_json(wire)
            .map_err(|_| local("IPC_RESPONSE_INVALID"))?,
    )
    .map_err(|_| local("IPC_RESPONSE_INVALID"))?;
    if outer.format != SEALED_RESPONSE || outer.request_id != id {
        return Err(local("IPC_RESPONSE_INVALID"));
    }
    let value = channel::open_response_bounded(
        &auth.credential,
        &auth.method,
        request.as_bytes(),
        outer.payload.as_bytes(),
        MAX_RESPONSE,
    )
    .map_err(|_| local("IPC_RESPONSE_INVALID"))?;
    if value["format"] != RESPONSE_FORMAT || value["request_id"] != id {
        return Err(local("IPC_RESPONSE_INVALID"));
    }
    Ok(value)
}
async fn connection(stream: TcpStream, runtime: Arc<Runtime>) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|_| local("IPC_DISCONNECTED"))?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let auth = accept_handshake(&mut read, &mut write, &runtime).await?;
    let mut calls: JoinSet<(String, String, Value)> = JoinSet::new();
    let mut seen = BTreeSet::new();
    let mut eof = false;
    let mut buffer = Vec::new();
    loop {
        tokio::select! {
            _=runtime.cancel.cancelled()=>break,
            completed=calls.join_next(),if !calls.is_empty()=>{
                match completed{
                    Some(Ok((id,request,out)))=>{
                        let stop=out["ok"]==true&&out["value"]["state"]=="STOPPING";
                        let payload=channel::response_bounded(&auth.credential,&auth.method,request.as_bytes(),&out,MAX_RESPONSE).map_err(|_|local("IPC_RESPONSE_TOO_LARGE"))?;
                        let result=write_frame(&mut write,&json!({"format":SEALED_RESPONSE,"request_id":id,"payload":payload})).await;
                        if stop{runtime.cancel.cancel();}result?;
                    },Some(Err(_))=>return Err(local("IPC_CALL_FAILED")),_=>{},
                }
            },
            part=read.fill_buf(),if !eof&&calls.len()<MAX_CALLS_PER_CONNECTION=>{
                let available=part.map_err(|_|local("IPC_DISCONNECTED"))?;
                if available.is_empty(){eof=true;if !buffer.is_empty(){return Err(local("IPC_FRAME_INCOMPLETE"));}}
                else{
                    let end=available.iter().position(|b|*b==b'\n').map(|n|n+1);let count=end.unwrap_or(available.len());
                    if buffer.len()+count>MAX_WIRE_REQUEST{return Err(local("IPC_FRAME_TOO_LARGE"));}
                    buffer.extend_from_slice(&available[..count]);read.consume(count);
                    if end.is_some(){
                        let(frame,request)=decode_request(&auth,&buffer)?;buffer.clear();
                        if seen.len()>=MAX_CONNECTION_REQUESTS||!seen.insert(frame.request_id.clone()){return Err(local("IPC_REQUEST_ID_CONFLICT"));}
                        let id=frame.request_id.clone();let handler=runtime.clone();let credential=auth.credential.clone();calls.spawn(async move{let out=handler.request(frame,&credential).await;(id,request,out)});
                    }
                }
            },
        }
        if eof && calls.is_empty() {
            break;
        }
    }
    calls.abort_all();
    while calls.join_next().await.is_some() {}
    Ok(())
}
fn endpoint(path: &Path, address: SocketAddr, token: &str, access: &str) -> Result<()> {
    if path.exists() {
        private_json(path, 4096).map_err(|_| local("ENDPOINT_NOT_PRIVATE"))?;
        std::fs::remove_file(path).map_err(|_| local("ENDPOINT_WRITE_FAILED"))?;
    }
    let wire = serde_json::to_vec(&Endpoint {
        format: ENDPOINT_FORMAT.into(),
        address,
        token: token.into(),
        access: access.into(),
    })
    .map_err(|_| local("ENDPOINT_WRITE_FAILED"))?;
    write_private(path, &wire).map_err(|_| local("ENDPOINT_WRITE_FAILED"))
}
/// Bounded IPC and participant engines. LOCAL_READY makes no delivery claim.
pub async fn serve(
    config: RuntimeConfig,
    cancel: KernelCancellationToken,
    ready: oneshot::Sender<Result<RuntimeReady>>,
) -> Result<()> {
    if config.format != "peerwork.participant-runtime.v1"
        || !config.state_directory.is_absolute()
        || config.engines.is_empty()
        || config.engines.len() > 8
        || config.clients.is_empty()
        || config.clients.len() > 32
    {
        return Err(local("RUNTIME_CONFIG_INVALID"));
    }
    create_private_state_directory(&config.state_directory)
        .map_err(|_| local("RUNTIME_STATE_NOT_PRIVATE"))?;
    let _lock = SecureStateStore::open(&config.state_directory.join("runtime.state"))
        .map_err(|_| local("RUNTIME_ALREADY_OWNED"))?;
    let mut owners = BTreeMap::new();
    let mut sessions = Vec::new();
    let mut names = BTreeSet::new();
    for engine in &config.engines {
        if !identifier(&engine.name) || !names.insert(engine.name.clone()) {
            return Err(local("ENGINE_NAME_INVALID"));
        }
    }
    let engines = names.clone();
    names.clear();
    for client in &config.clients {
        client.capability.validate()?;
        if !identifier(&client.name)
            || !names.insert(client.name.clone())
            || !engines.contains(&client.engine)
        {
            return Err(local("CLIENT_CONFIG_INVALID"));
        }
    }
    let initialized: Result<()> = async {
        for engine in &config.engines {
            owners.insert(
                engine.name.clone(),
                ParticipantClient::open(engine.participant_config()).await?,
            );
        }
        for client in &config.clients {
            let owner = owners
                .get(&client.engine)
                .ok_or_else(|| local("CLIENT_CONFIG_INVALID"))?;
            sessions.push(Session {
                watches: Default::default(),
                token: random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?,
                client: owner.restrict(&client.name, client.capability.clone())?,
            });
        }
        Ok(())
    }
    .await;
    if let Err(error) = initialized {
        for owner in owners.values() {
            let _ = owner.close().await;
        }
        return Err(error);
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| local("IPC_BIND_FAILED"))?;
    let address = listener
        .local_addr()
        .map_err(|_| local("IPC_BIND_FAILED"))?;
    let admin_token = random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?;
    let admin_endpoint = config.state_directory.join("admin.json");
    let mut paths = BTreeMap::new();
    let published: Result<()> = (|| {
        endpoint(&admin_endpoint, address, &admin_token, "ADMIN")?;
        for (client, session) in config.clients.iter().zip(&sessions) {
            let path = config
                .state_directory
                .join(format!("client-{}.json", client.name));
            endpoint(&path, address, &session.token, "CLIENT")?;
            paths.insert(client.name.clone(), path);
        }
        Ok(())
    })();
    if let Err(error) = published {
        for owner in owners.values() {
            let _ = owner.close().await;
        }
        return Err(error);
    }
    let clients = config
        .clients
        .iter()
        .zip(&sessions)
        .map(|(config, session)| (config.name.clone(), session.client.clone()))
        .collect();
    let host_jobs = match crate::participant_dispatch::start(
        &config.hosts,
        &clients,
        &config.state_directory,
        cancel.clone(),
    ) {
        Ok(jobs) => jobs,
        Err(error) => {
            for owner in owners.values() {
                let _ = owner.close().await;
            }
            for path in paths.values().chain(std::iter::once(&admin_endpoint)) {
                let _ = std::fs::remove_file(path);
            }
            return Err(error);
        }
    };
    let host_status = host_jobs.iter().map(|job| job.status.clone()).collect();
    let _ = ready.send(Ok(RuntimeReady {
        state: "LOCAL_READY".into(),
        admin_endpoint: admin_endpoint.clone(),
        client_endpoints: paths.clone(),
    }));
    let runtime = Arc::new(Runtime {
        owners,
        sessions,
        admin_token,
        host_status,
        cancel,
    });
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _=runtime.cancel.cancelled()=>break,
            _=connections.join_next(),if !connections.is_empty()=>{},
            incoming=listener.accept(),if connections.len()<MAX_CONNECTIONS=>{
                match incoming{Ok((stream,_))=>{let runtime=runtime.clone();connections.spawn(async move{let _=tokio::time::timeout(Duration::from_secs(300),connection(stream,runtime)).await;});},Err(_)=>{runtime.cancel.cancel();break;}}
            },
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    // A host call may already have reached the selected session. Finish its
    // evidence write while the owning engine remains available.
    for job in host_jobs {
        let _ = job.task.await;
    }
    let mut close_error = None;
    for owner in runtime.owners.values() {
        if let Err(error) = owner.close().await {
            close_error.get_or_insert(error);
        }
    }
    for path in paths.values().chain(std::iter::once(&admin_endpoint)) {
        let _ = std::fs::remove_file(path);
    }
    if let Some(error) = close_error {
        return Err(error);
    }
    Ok(())
}
/// Thin native local client. The daemon owns signing, recovery and remote pool.
/// Native frontends use RuntimeClient; the shared encrypted channel owns the
/// wire protocol rather than making each language reimplement its handshake.
fn load_endpoint(endpoint_path: &Path) -> Result<Endpoint> {
    let value = private_json(endpoint_path, 4096).map_err(|_| local("ENDPOINT_NOT_PRIVATE"))?;
    let endpoint: Endpoint =
        serde_json::from_value(value).map_err(|_| local("ENDPOINT_INVALID"))?;
    if endpoint.format != ENDPOINT_FORMAT
        || !endpoint.address.ip().is_loopback()
        || endpoint.token.len() != 43
    {
        return Err(local("ENDPOINT_INVALID"));
    }
    if !opaque_token(&endpoint.token) {
        return Err(local("ENDPOINT_INVALID"));
    }
    Ok(endpoint)
}
/// Low-level local RPC, including the separately authorized admin interface.
pub async fn call(endpoint_path: &Path, request: Value) -> Result<Value> {
    let endpoint = load_endpoint(endpoint_path)?;
    call_endpoint(&endpoint, request).await
}
async fn call_endpoint(endpoint: &Endpoint, request: Value) -> Result<Value> {
    let stream = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(endpoint.address))
        .await
        .map_err(|_| local("RUNTIME_UNAVAILABLE"))?
        .map_err(|_| local("RUNTIME_UNAVAILABLE"))?;
    let mut stream = BufReader::new(stream);
    let auth = client_handshake(&mut stream, &endpoint.token)
        .await
        .map_err(observation)?;
    let id = random_token().map_err(|_| local("ENTROPY_UNAVAILABLE"))?;
    let (value, request) = encode_request(&auth, &id, request).map_err(observation)?;
    write_frame(stream.get_mut(), &value)
        .await
        .map_err(observation)?;
    let wire = tokio::time::timeout(
        Duration::from_secs(35),
        read_frame(&mut stream, MAX_WIRE_RESPONSE),
    )
    .await
    .map_err(|_| observation(local("IPC_OBSERVATION_TIMEOUT")))?
    .map_err(observation)?
    .ok_or_else(|| observation(local("IPC_DISCONNECTED")))?;
    decode_response(&auth, &id, &request, &wire).map_err(observation)
}

pub fn cli(args: &[String]) -> Value {
    fn run(args: &[String]) -> Result<Value> {
        if let [verb,config,request]=args {
            if verb=="rebind-host" {
                return crate::participant_rebind::cli(Path::new(config),Path::new(request));
            }
        }
        if args.is_empty() || args == ["--help"] {
            return Ok(
                json!({"state":"HELP","availability":"UNRELEASED_CANDIDATE","runtime_dependencies":[],"usage":["peerwork runtime run CONFIG.json","peerwork runtime call CLIENT_ENDPOINT.json REQUEST.json","peerwork runtime admin ADMIN_ENDPOINT.json status|stop","peerwork runtime transfer-engine RUNTIME_CONFIG.json ENGINE_NAME NEW_STATE_DIRECTORY","peerwork runtime rebind-host RUNTIME_CONFIG.json REQUEST.json","peerwork runtime import-node-delivery SELECTION.json","peerwork runtime legacy-evidence SELECTION.json RECORD_KEY"],"authority":"Client endpoints pin identity and capability; no request profile/key selection.","readiness":"LOCAL_READY is not a network/host delivery proof."}),
            );
        }
        if let [verb,path]=args {
            if verb=="import-node-delivery" {
                return crate::participant_legacy_delivery::import_all(&crate::participant_legacy_delivery::load_selection(Path::new(path))?);
            }
        }
        if let [verb,path,key]=args {
            if verb=="legacy-evidence" {
                return crate::participant_legacy_delivery::read_evidence(&crate::participant_legacy_delivery::load_selection(Path::new(path))?,key);
            }
        }
        if let [verb, config, name, target] = args {
            if verb == "transfer-engine" {
                return crate::participant_transfer::transfer_engine(
                    Path::new(config),
                    name,
                    Path::new(target),
                );
            }
        }
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| local("EXECUTOR_FAILED"))?;
        match args {
            [verb, path] if verb == "run" => {
                let config = serde_json::from_value(
                    private_json(Path::new(path), 65536)
                        .map_err(|_| local("RUNTIME_CONFIG_NOT_PRIVATE"))?,
                )
                .map_err(|_| local("RUNTIME_CONFIG_INVALID"))?;
                let cancel = KernelCancellationToken::new();
                let _interrupt = crate::interrupts::InterruptMonitor::start(cancel.clone())
                    .map_err(|_| local("SIGNAL_FAILED"))?;
                executor.block_on(async{let(tx,rx)=oneshot::channel();let service=serve(config,cancel,tx);tokio::pin!(service);tokio::pin!(rx);tokio::select!{
                    result=&mut service=>{result?;},
                    ready=&mut rx=>{let ready=ready.map_err(|_|local("RUNTIME_START_FAILED"))??;println!("{}",serde_json::to_string(&ready).map_err(|_|local("IPC_RESPONSE_INVALID"))?);service.await?;}
                }Ok(json!({"state":"STOPPED"}))})
            }
            [verb, path, input] if verb == "call" => {
                let request = private_json(Path::new(input), MAX_REQUEST)
                    .map_err(|_| local("REQUEST_NOT_PRIVATE"))?;
                executor.block_on(call(Path::new(path), request))
            }
            [verb, path, method]
                if verb == "admin" && matches!(method.as_str(), "status" | "stop") =>
            {
                executor.block_on(call(Path::new(path), json!({"method":method})))
            }
            _ => Err(local("RUNTIME_ARGUMENT_INVALID")),
        }
    }
    run(args).unwrap_or_else(|error| json!({"state":"FAILED","error":error}))
}
