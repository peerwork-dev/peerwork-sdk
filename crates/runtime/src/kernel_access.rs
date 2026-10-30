//! Public, redacted kernel access boundary for language bindings. Each call
//! reopens protected local state. Embedded runtimes may explicitly retain a
//! verified session and HTTP pool; restart still rechecks durable continuity.

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
use std::sync::{Arc,Mutex};
use std::time::{Duration,Instant};

#[derive(Default)]
struct PersistentSession {
    refresh:tokio::sync::Mutex<()>,
    runtime:Mutex<Option<Arc<Runtime>>>,
    identity:Mutex<Option<KernelIdentity>>,
    seed:Mutex<Option<(crate::kernel_client::KernelClientSeed,Instant)>>,
}
impl std::fmt::Debug for PersistentSession {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("PersistentSession(<protected>)")}
}

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
#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelPublicError {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if="Option::is_none")]
    pub details:Option<serde_json::Value>,
}
impl KernelPublicError {
    pub fn envelope(self) -> serde_json::Value {
        serde_json::json!({"ok":false,"code":self.code,"message":self.message,"details":self.details})
    }
}
impl From<&'static str> for KernelPublicError {
    fn from(message: &'static str) -> Self {
        Self {
            code: "INPUT_INVALID",
            message,details:None,
        }
    }
}
impl From<KernelAccessError> for KernelPublicError {
    fn from(error: KernelAccessError) -> Self {
        use crate::kernel_client::KernelClientError as C;
        use crate::kernel_intents::JournalError as J;
        use crate::transport::TransportError as T;
        use KernelAccessError as A;
        if let A::Client(C::ArchiveMigration(code))=&error{return Self{code:*code,message:"archive migration could not proceed; preserve the original operation and inspect the selected source",details:Some(serde_json::json!({"phase":"MIGRATION_PREPARATION","effect_certainty":"NOT_SUBMITTED","retryable":false,"recovery":"INSPECT_SOURCE_AND_RESUME_OR_CORRECT_INPUT"}))};}
        if let A::Client(C::OperationRefused(refusal))=&error{return Self{code:"OPERATION_REJECTED",message:if refusal.phase=="LOCAL_PREPARATION"{"local migration preparation failed; inspect the original code and reuse the verified source capsule"}else{"the service confirmed refusal; inspect the phase, code and recovery details"},details:Some(serde_json::json!(refusal))};}
        if let A::Client(C::HistoryDeliveryBlocked{job_id,workspace_id,code,retryable})=&error{return Self{code:"HISTORY_KEY_DELIVERY_BLOCKED",message:"the selected Owner key-history job needs attention; other job results remain saved",details:Some(serde_json::json!({"phase":"HISTORY_KEY_DELIVERY","job_id":job_id,"workspace_id":workspace_id,"server_code":code,"retryable":retryable,"effect_certainty":"UNKNOWN","recovery":"CONTINUE_OWNER_KEY_WORKER"}))};}
        if let A::Client(C::CryptoPrerequisitePending{command_id,workspace_id,code,retryable})=&error{return Self{code:"CRYPTO_PREREQUISITE_PENDING",message:"the original Owner crypto prerequisite requires reconciliation",details:Some(serde_json::json!({"phase":"KEY_HEAD_ROTATION","command_id":command_id,"workspace_id":workspace_id,"server_code":code,"effect_certainty":"UNKNOWN","retryable":retryable,"recovery":"RESUME_ORIGINAL_PREREQUISITE"}))};}
        if let A::Client(C::PrerequisitePending{command_id,workspace_id})=&error{return Self{code:"PREREQUISITE_PENDING",message:"body-key initialization needs reconciliation of its saved command",details:Some(serde_json::json!({"phase":"KEY_HEAD_INITIALIZATION","command_id":command_id,"workspace_id":workspace_id,"effect_certainty":"UNKNOWN","retryable":true,"recovery":"RESUME_ORIGINAL_PREREQUISITE"}))};}
        if let A::Client(C::ServerResource(code))=&error{return Self{code:*code,message:"service reported resource pressure; preserve the original operation and recover after capacity is available",details:Some(serde_json::json!({"http_status":429,"server_code":code,"phase":"HTTP_REQUEST","diagnostic_trust":"UNVERIFIED_HTTP","effect_certainty":"UNKNOWN","retryable":false,"recovery":"RESUME_AFTER_CAPACITY_AVAILABLE"}))};}
        let details=if let A::Client(C::ServerRejected(status))=&error{Some(serde_json::json!({"http_status":status,"phase":"HTTP_REQUEST","effect_certainty":"UNKNOWN","retryable":*status>=500||*status==429,"recovery":"RECONCILE_ORIGINAL_INTENT"}))}else if matches!(&error,A::Client(C::InvalidDocumentTime)){Some(serde_json::json!({"phase":"VALIDATION","server_code":"DOCUMENT_TIME_INVALID","effect_certainty":"NOT_SUBMITTED","retryable":false,"recovery":"CORRECT_DOCUMENT_TIMES"}))}else{None};
        let (code, message) = match error {
            A::Client(C::ArchiveMigration(code)) => (code,"archive migration preparation failed"),
            A::Client(C::HistoryDeliveryBlocked{..}) => ("HISTORY_KEY_DELIVERY_BLOCKED", "inspect the selected historical key job"),
            A::Client(C::CryptoPrerequisitePending{..}) => ("CRYPTO_PREREQUISITE_PENDING", "reconcile the saved Owner crypto prerequisite"),
            A::Client(C::PrerequisitePending{..}) => ("PREREQUISITE_PENDING", "reconcile the saved body-key prerequisite command"),
            A::Client(C::Access(peerwork_core::structure_access::AccessError::Expired)) => ("ACCESS_REQUEST_EXPIRED", "request a fresh approval code from the device"),
            A::Client(C::Access(peerwork_core::structure_access::AccessError::Invalid)) => ("ACCESS_REQUEST_INVALID", "access request, workspace or recipient binding is invalid"),
            A::Client(C::Access(peerwork_core::structure_access::AccessError::Authentication)) => ("ACCESS_KEY_AUTHENTICATION_FAILED", "the selected key grant failed authentication"),
            A::Client(C::AccessState(_)) => ("ACCESS_STATE_INVALID", "protected recipient state is missing, invalid or belongs to another identity"),
            A::Client(C::LegacyModeRetired) => (crate::runtime_contract::RETIRED_CODE,crate::runtime_contract::RETIRED_MESSAGE),
            A::Client(C::ContentKey(crate::kernel_intents::ContentKeyError::Missing)) => (
                "CONTENT_KEY_MISSING", "the selected local identity has no body key for this workspace; obtain authorized key delivery",
            ),
            A::Client(C::ContentKey(crate::kernel_intents::ContentKeyError::HeadRollback)) => ("CONTENT_KEY_ROLLBACK", "canonical body-key epoch or Owner differs from protected local continuity; preserve state and inspect the selected service"),
            A::Client(C::ContentKey(crate::kernel_intents::ContentKeyError::RotationRequired)) => ("CONTENT_KEY_ROTATION_REQUIRED", "Owner must rotate the workspace body key before new encrypted bodies can be written"),
            A::Client(C::ContentKey(crate::kernel_intents::ContentKeyError::Conflict)) => (
                "CONTENT_KEY_CONFLICT", "the selected local body key changed; preserve and recover the original operation",
            ),
            A::Client(C::ContentKey(crate::kernel_intents::ContentKeyError::Content(peerwork_core::structure_content::StructureContentError::TooLarge))) => (
                "CONTENT_TOO_LARGE", "body or aggregate attachments exceed the supported 65536-byte limit",
            ),
            A::Client(C::ContentKey(crate::kernel_intents::ContentKeyError::Content(peerwork_core::structure_content::StructureContentError::Authentication))) => (
                "CONTENT_AUTHENTICATION_FAILED", "selected body failed authentication; preserve the original signed operation",
            ),
            A::Client(C::ContentKey(_)) => (
                "CONTENT_KEY_STATE", "selected protected body-key state or binding could not be verified",
            ),
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
            A::Client(C::Store(J::PendingIndexIncomplete)) => (
                "PENDING_INDEX_BUILD_REQUIRED", "run buildPendingIndex/build_pending_index; selected submit and resume remain available",
            ),
            A::Client(C::Store(J::PendingPageRequired)) => (
                "PENDING_PAGE_REQUIRED", "use pendingPage/pending_page to read more than 32 unconfirmed operations",
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
            A::Client(C::UnsupportedStructureProfile) => (
                "CAPABILITY_UNAVAILABLE",
                "selected service does not support backend structure intents",
            ),
            A::Client(C::OperationRefused(_))=>unreachable!("handled above"),
            A::Client(C::IntentNotFound) => ("NOT_FOUND", "saved kernel command was not found"),
            A::Client(C::ServerResource(_))=>unreachable!("handled above"),
            A::Client(C::ServerRejected(_)) => (
                "SERVICE_REJECTED",
                "kernel service rejected the saved command",
            ),
            A::Client(C::InvalidResult) => (
                "VERIFICATION_FAILED",
                "kernel result has an unsupported verified summary",
            ),
            A::Client(C::InvalidDocumentTime) => ("DOCUMENT_TIME_INVALID", "document_times requires1..8 unique output indexes and valid RFC3339 created_at or updated_at claims; correct the input locally"),
            A::Client(C::InvalidCommand) => (
                "COMMAND_INVALID",
                "kernel command does not match the selected discovery and identity",
            ),
        };
        Self { code, message, details }
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
    session: Option<Arc<PersistentSession>>,
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
            session: None,
        }
    }

    /// Use an explicitly configured authority digest. The default matches
    /// the TypeScript client's SHA-256 digest of this local actor ID.
    pub fn with_authority(mut self, authority: Option<String>) -> Self {
        self.authority_override = authority;
        if self.session.is_some() { self.session=Some(Arc::new(PersistentSession::default())); }
        self
    }

    pub fn with_transport_options(mut self, options: crate::transport::TransportOptions) -> Self {
        self.transport = options;
        if self.session.is_some() { self.session=Some(Arc::new(PersistentSession::default())); }
        self
    }

    /// Opt-in handle lifetime for embedded communication runtimes. Pins and
    /// secrets remain private to this exact access configuration and identity.
    pub fn with_persistent_session(mut self)->Self{
        self.session=Some(Arc::new(PersistentSession::default()));self
    }

    /// After all owned host/maintenance jobs stop, release a lazily created
    /// synchronous-bridge executor off the async owner thread.
    pub(crate) async fn close_session_executor_async(&self){
        let runtime=self.session.as_ref().and_then(|s|s.runtime.lock().ok()?.take());
        if let Some(runtime)=runtime{let _=tokio::task::spawn_blocking(move||drop(runtime)).await;}
    }

    fn runtime(&self) -> Result<Arc<Runtime>, KernelAccessError> {
        if let Some(session)=&self.session{
            let mut slot=session.runtime.lock().map_err(|_|KernelAccessError::Runtime)?;
            if let Some(runtime)=slot.as_ref(){return Ok(runtime.clone());}
            let runtime=Arc::new(Builder::new_multi_thread().worker_threads(1).enable_all().build().map_err(|_|KernelAccessError::Runtime)?);
            *slot=Some(runtime.clone());return Ok(runtime);
        }
        Builder::new_current_thread().enable_all().build().map(Arc::new).map_err(|_| KernelAccessError::Runtime)
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
        runtime.block_on(self.open_session_client(cancel))
    }

    async fn open_session_client(&self,cancel:&CancellationToken)->Result<KernelClient,KernelAccessError>{
        if cancel.is_cancelled(){return Err(KernelAccessError::Cancelled);}
        // Only expired/cold discovery participates in this single-flight.
        // Warm operations never wait for the background refresh owner.
        let _refresh=if let Some(session)=&self.session{
            let stale=session.seed.lock().map_err(|_|KernelAccessError::Runtime)?.as_ref().is_none_or(|(_,at)|at.elapsed()>=Duration::from_secs(60));
            if stale{Some(session.refresh.lock().await)}else{None}
        }else{None};
        let cached=if let Some(session)=&self.session{
            // Release the mutex before any network await. The seed owns no
            // SQLite connection; journals stay per operation.
            session.seed.lock().map_err(|_|KernelAccessError::Runtime)?.as_ref()
                .map(|(seed,at)|(seed.clone(),at.elapsed()))
        }else{None};
        let mut client=match cached{
            Some((seed,age)) if age<Duration::from_secs(60)=>KernelClient::from_session_seed(&seed,&self.journal_path)?,
            Some((seed,_))=>KernelClient::refresh_session_seed(&seed,&self.journal_path,&self.required_features,cancel).await?,
            None=>KernelClient::open(self.transport_config(),&self.journal_path,&self.required_features,cancel).await?,
        };
        if let Some(session)=&self.session{
            let mut slot=session.seed.lock().map_err(|_|KernelAccessError::Runtime)?;
            // Warm reuse must not extend the discovery refresh interval.
            if slot.as_ref().is_none_or(|(_,at)|at.elapsed()>=Duration::from_secs(60)){
                *slot=Some((client.session_seed(),Instant::now()));
            }
        }
        client.bind_content_key_path(self.content_key_path_for_origin(client.origin()));
        client.bind_access_recipient_path(self.access_recipient_path(client.origin()));
        Ok(client)
    }

    fn open_client_until(&self,runtime:&Runtime,cancel:&CancellationToken,deadline:tokio::time::Instant)->Result<KernelClient,KernelAccessError>{
        runtime.block_on(async{
            tokio::time::timeout_at(deadline,self.open_session_client(cancel)).await
                .map_err(|_|KernelAccessError::Client(KernelClientError::Transport(crate::transport::TransportError::Timeout)))?
        })
    }

    pub(crate) fn content_key_path_for_origin(&self,origin:&str)->PathBuf{
        self.identity_path.with_extension(format!("{}.content-keys.sqlite",sha256_hex(origin.as_bytes())))
    }
    pub(crate) fn communication_executor(&self)->Result<Arc<Runtime>,KernelAccessError>{self.runtime()}
    pub(crate) fn delivery_wakes(&self,token:&str,cancel:&CancellationToken,on_wake:impl Fn(bool))->Result<(),KernelAccessError>{
        let runtime=self.runtime()?;let client=self.open_client(&runtime,cancel)?;
        runtime.block_on(async{
            let mut response=client.transport().delivery_stream(token,cancel).await?;
            let mut buffer=Vec::new();
            loop{
                let chunk=tokio::select!{_=cancel.cancelled()=>return Ok(()),v=response.chunk()=>v.map_err(|_|crate::transport::TransportError::Network)?};
                let Some(chunk)=chunk else{return Ok(());};
                for byte in chunk{
                    buffer.push(byte);if buffer.len()>4096{return Err(crate::transport::TransportError::ResponseTooLarge);}
                    if buffer.ends_with(b"\n\n"){
                        if buffer.windows(12).any(|v|v==b"event: ready"){on_wake(true);}
                        else if buffer.windows(11).any(|v|v==b"event: wake"){on_wake(false);}
                        buffer.clear();
                    }
                }
            }
        }).map_err(|e|KernelAccessError::Client(KernelClientError::Transport(e)))
    }
    pub fn session_metrics(&self)->serde_json::Value{
        self.session.as_ref().and_then(|s|s.seed.lock().ok()?.as_ref().map(|(seed,_)|seed.metrics())).unwrap_or_else(||serde_json::json!({"scope":"SESSION_CUMULATIVE","http_requests_started":0}))
    }

    fn identity(&self) -> Result<KernelIdentity, KernelAccessError> {
        if let Some(session)=&self.session{
            let mut slot=session.identity.lock().map_err(|_|KernelAccessError::Runtime)?;
            if let Some(identity)=slot.as_ref(){return Ok(identity.clone());}
            let identity=KernelIdentity::open(&self.identity_path)?;*slot=Some(identity.clone());return Ok(identity);
        }
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

    /// Business intent in, verified result or recoverable operation out. The
    /// selected identity/authority and source remain explicit client settings.
    pub fn execute_structure_intent_with_cancel(
        &self,intent_wire:&[u8],cancel:&CancellationToken,
    )->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        self.runtime()?.block_on(self.execute_structure_intent_async(intent_wire,cancel))
    }

    /// Native async entry: safe inside an embedding application's executor.
    /// No nested Tokio runtime, shared SQLite transaction or network mutex.
    pub async fn execute_structure_intent_async(
        &self,intent_wire:&[u8],cancel:&CancellationToken,
    )->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        let deadline=tokio::time::Instant::now()+Duration::from_secs(30);
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let mut client=tokio::time::timeout_at(deadline,self.open_session_client(cancel)).await
            .map_err(|_|KernelClientError::Transport(crate::transport::TransportError::Timeout))??;
        let recipient=self.access_recipient_path(client.origin());
        let mut outcome=client.execute_structure_intent_until(&identity,&authority,intent_wire,cancel,deadline).await?;
        let _=tokio::time::timeout_at(deadline,async{
            client.complete_known_structure_outcome(&identity,&authority,&mut outcome,cancel).await;
            client.complete_structure_history_outcome(&identity,&authority,&mut outcome,cancel).await;
            client.populate_selected_body_keys(&identity,&authority,&recipient,&mut outcome,cancel).await;
        }).await;
        Ok(outcome)
    }

    /// Convenience producers share the resident native session and existing
    /// encrypted parent/packet journals. Never call a synchronous facade here.
    pub(crate) async fn execute_participant_async(
        &self, request: &crate::participant::Invoke, namespace: &str,
        actor: &str, origin: &str, durable: bool, cancel: &CancellationToken,
        sources:&[crate::participant::MigrationSource],
    )->Result<serde_json::Value,KernelAccessError>{
        use crate::participant_actions::{self,Selection};
        let wire=request.wire(namespace,actor,origin,durable);
        if !participant_actions::HELPERS.contains(&request.action.as_str()) {
            return self.execute_structure_intent_async(wire.to_string().as_bytes(),cancel).await
                .map(crate::participant_outcome::outcome);
        }
        let selected=participant_actions::selection(request,wire["idempotency_key"].as_str().unwrap_or(""))
            .map_err(|_|KernelClientError::InvalidCommand)?;
        if let Selection::Offline{operation,input}=&selected{
            let operation=operation.clone();let input=input.to_string();let stop=cancel.clone();
            // This worker is awaited by the counted engine request job, even
            // when its caller disconnects. It cannot outlive engine ownership.
            return tokio::task::spawn_blocking(move||{
                let result=crate::protocol_workbench::workbench_json(&operation,&input,&stop);
                let result:serde_json::Value=serde_json::from_str(&result).map_err(|_|KernelClientError::InvalidResult)?;
                Ok(serde_json::json!({"state":"OFFLINE_RESULT","authoritative":false,"simulated":true,"effect_certainty":"NOT_SUBMITTED","result":result}))
            }).await.map_err(|_|KernelAccessError::Runtime)?;
        }
        if let Selection::Sources(ws)=&selected{
            let selected=sources.iter().filter(|s|s.workspace_id()==ws).map(|s|s.public_info().map_err(|_|KernelClientError::InvalidCommand)).collect::<Result<Vec<_>,_>>()?;
            return Ok(serde_json::json!({"state":"LOCAL_CONFIGURATION","workspace_id":ws,"sources":selected,"remote_effect":"NONE"}));
        }
        if let Selection::Initialize(ws)=&selected{
            return Ok(serde_json::json!({"state":"LOCAL_KEY_READY","effect_certainty":"LOCAL_ONLY","remote_access":"NOT_GRANTED","key":self.ensure_local_content_key_with_cancel(ws,cancel)?}));
        }
        let deadline=tokio::time::Instant::now()+Duration::from_secs(if matches!(selected,Selection::Migrate{..}){180}else{30});
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let mut client=tokio::time::timeout_at(deadline,self.open_session_client(cancel)).await
            .map_err(|_|KernelClientError::Transport(crate::transport::TransportError::Timeout))??;
        let recipient=self.access_recipient_path(client.origin());
        if let Selection::Migrate{workspace,source_id,name}=&selected{
            let key=wire["idempotency_key"].as_str().ok_or(KernelClientError::InvalidCommand)?;
            if let Some(original)=client.resume_prepared_archive(&identity,&authority,workspace,key,cancel,deadline).await?{
                return Ok(crate::participant_outcome::outcome(original));
            }
            let source=crate::participant_migration::resolve(sources,workspace,source_id,key,name.clone())
                .map_err(|_|KernelClientError::ArchiveMigration("MIGRATION_SOURCE_NOT_CONFIGURED"))?;
            return client.migrate_archive_until(&identity,&authority,source,cancel,deadline).await.map(crate::participant_outcome::outcome).map_err(KernelAccessError::from);
        }
        let result=tokio::time::timeout_at(deadline,async{
            let mut out=match selected {
                Selection::Request(selection)=>return Ok(client.request_structure_access(&identity,&recipient,selection,cancel).await?),
                Selection::Accept(selection)=>return Ok(client.accept_structure_keys(&identity,&authority,&recipient,selection,cancel).await?),
                Selection::Initialize(_)=>return Err(KernelClientError::InvalidCommand.into()),
                Selection::Offline{..}|Selection::Sources(_)=>return Err(KernelClientError::InvalidCommand.into()),
                Selection::Migrate{..}=>return Err(KernelClientError::InvalidCommand.into()),
                Selection::Approve(selection)=>client.authorize_structure_access_until(&identity,&authority,selection,cancel,deadline).await?,
                Selection::Publish(selection)=>client.publish_selected_record_until(&identity,&authority,selection,cancel,deadline).await?,
                Selection::Rotate(selection)=>client.rotate_structure_content_key(&identity,&authority,selection,cancel).await?,
                Selection::Coordinate(ws)=>client.coordinate_structure_keys(&identity,&authority,&ws,cancel).await?,
            };
            let _=tokio::time::timeout_at(deadline,client.complete_structure_history_outcome(&identity,&authority,&mut out,cancel)).await;
            Ok::<_,KernelAccessError>(crate::participant_outcome::outcome(out))
        }).await.map_err(|_|KernelClientError::Transport(crate::transport::TransportError::Timeout))?;
        result
    }

    /// Explicit migration owns a counted blocking maintenance lane because
    /// legacy checkpoint validation/conversion performs bounded local CPU/IO.
    /// It reuses this access object's transport/session and native journals.
    pub(crate) fn execute_participant_migration(
        &self,request:&crate::participant::Invoke,namespace:&str,actor:&str,origin:&str,
        cancel:&CancellationToken,sources:&[crate::participant::MigrationSource],
    )->Result<serde_json::Value,KernelAccessError>{
        self.runtime()?.block_on(self.execute_participant_async(request,namespace,actor,origin,true,cancel,sources))
    }

    /// Historical selected result verification, including cached body opening.
    /// No discovery, authorization refresh or remote submission is performed.
    pub(crate) fn cached_participant_result(&self,command_id:&str,cancel:&CancellationToken)
        ->Result<Option<crate::kernel_client::KernelAcceptedResult>,KernelAccessError>{
        let identity=self.identity()?;
        let mut client=KernelClient::open_cached(self.transport_config(),&self.journal_path,&[],cancel)?;
        client.bind_content_key_path(self.content_key_path_for_origin(client.origin()));
        match client.status(command_id,identity.key_id())?{
            Some(crate::kernel_client::KernelOperationStatus::Accepted(result))=>Ok(Some(result)),
            _=>Ok(None),
        }
    }

    pub(crate) async fn refresh_mailbox_clock(&self,cancel:&CancellationToken)->Result<(),KernelAccessError>{
        let client=self.open_session_client(cancel).await?;
        client.transport().invalidate_context(client.discovery().receipt_public_key());
        client.refresh_authorization_context(cancel).await?;Ok(())
    }
    /// Selected retained-key checks, with no discovery or network work.
    pub(crate) fn cached_mail_keys(&self,workspace:&str,ids:&[String])->Result<std::collections::BTreeSet<String>,KernelAccessError>{
        if ids.len()>32{return Err(KernelClientError::InvalidCommand.into());}
        if ids.is_empty(){return Ok(Default::default());}
        let identity=self.identity()?;
        let path=self.content_key_path_for_origin(&self.origin);
        if !path.is_file(){return Ok(Default::default());}
        let keys=crate::kernel_intents::StructureContentKeys::open(&path,self.transport_config()).map_err(KernelClientError::from)?;
        ids.iter().filter_map(|id|match keys.contains_retained(identity.key_id(),workspace,id){Ok(true)=>Some(Ok(id.clone())),Ok(false)=>None,Err(e)=>Some(Err(KernelClientError::from(e).into()))}).collect()
    }
    pub(crate) async fn prepare_mailbox_keys(&self,workspace:&str,mailbox:&str,needed:&[String],cancel:&CancellationToken)->Result<serde_json::Value,KernelAccessError>{
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let mut client=self.open_session_client(cancel).await?;
        client.watch_structure_keys(&identity,&authority,workspace,mailbox,needed,cancel).await.map_err(KernelAccessError::from)
    }
    pub(crate) async fn mailbox_session(&self,cancel:&CancellationToken)->Result<crate::participant_watch::MailSession,KernelAccessError>{
        let client=self.open_session_client(cancel).await?;
        client.refresh_authorization_context(cancel).await?;
        let discovery=client.discovery();
        if !discovery.protocol_features().contains(&peerwork_core::communication::FEATURE.encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile.into());}
        Ok(crate::participant_watch::MailSession{transport:client.transport().clone(),audience:discovery.audience_utf16().to_vec(),service_key:discovery.receipt_public_key().into()})
    }
    pub(crate) fn open_cached_mail(&self,entry:&mut serde_json::Value,audience:&[u16]){
        use crate::kernel_intents::{ContentKeyError,StructureContentKeys};
        let Some(message)=entry.get("envelope").and_then(|v|v.get("message"))else{return;};
        let opened=(||->Result<serde_json::Value,KernelAccessError>{
            let identity=self.identity()?;
            let author=peerwork_core::prepared_command::verify_structure_author_intent(message["author_intent"].as_str().ok_or(KernelClientError::InvalidResult)?,audience).map_err(|_|KernelClientError::InvalidResult)?;
            let (_,content)=peerwork_core::communication::authored_message_content(&author).map_err(|_|KernelClientError::InvalidResult)?;
            let peerwork_core::communication::MessageContent::WorkspaceE2ee{body}=content else{return Ok(serde_json::json!({"state":"SOURCE_REFERENCE"}));};
            let path=self.content_key_path_for_origin(&self.origin);
            let plain=if path.is_file(){StructureContentKeys::open(&path,self.transport_config()).map_err(KernelClientError::from)?.open_message(identity.key_id(),&author)}else{Err(ContentKeyError::Missing)};
            let mut out=serde_json::json!({"message_id":message["message_id"],"key_id":body.key_id});
            match plain{
                Ok(bytes)=>match std::str::from_utf8(&bytes){Ok(text)=>{out["state"]=serde_json::json!("OPENED");out["text"]=serde_json::json!(text);out["assurance"]=serde_json::json!("AUTHOR_SIGNATURE_AND_AEAD");},Err(_)=>out["state"]=serde_json::json!("UNSUPPORTED_ENCODING")},
                Err(ContentKeyError::Missing)=>out["state"]=serde_json::json!("KEY_UNAVAILABLE"),
                Err(ContentKeyError::Content(peerwork_core::structure_content::StructureContentError::Authentication))=>out["state"]=serde_json::json!("AUTHENTICATION_FAILED"),
                Err(_)=>out["state"]=serde_json::json!("KEY_STATE_INVALID"),
            }Ok(out)
        })();
        entry["opened_message"]=opened.unwrap_or_else(|_|serde_json::json!({"state":"KEY_STATE_INVALID"}));
    }
    pub async fn open_async(&self,cancel:&CancellationToken)->Result<KernelOpenInfo,KernelAccessError>{
        let identity=self.identity()?;let client=self.open_session_client(cancel).await?;
        Ok(KernelOpenInfo{actor_id:identity.actor_id().into(),key_id:identity.key_id().into(),origin:client.origin().into()})
    }

    pub async fn resume_structure_intent_async(&self,command_id:&str,cancel:&CancellationToken)
        ->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        let deadline=tokio::time::Instant::now()+Duration::from_secs(30);
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let mut client=tokio::time::timeout_at(deadline,self.open_session_client(cancel)).await
            .map_err(|_|KernelClientError::Transport(crate::transport::TransportError::Timeout))??;
        let mut outcome=client.resume_structure_parent_until(&identity,&authority,command_id,None,cancel,deadline).await?;
        let _=tokio::time::timeout_at(deadline,async{
            client.complete_known_structure_outcome(&identity,&authority,&mut outcome,cancel).await;
            client.complete_structure_history_outcome(&identity,&authority,&mut outcome,cancel).await;
        }).await;
        Ok(outcome)
    }

    /// Refresh verified prerequisites using the same transport pool. Used by
    /// the state owner before expiry, never to extend an unverified anchor.
    pub async fn refresh_session_async(&self,cancel:&CancellationToken)->Result<(),KernelAccessError>{
        let mut client=self.open_session_client(cancel).await?;
        let _guard=if let Some(session)=&self.session{Some(session.refresh.lock().await)}else{None};
        let refresh=self.session.as_ref().and_then(|s|s.seed.lock().ok()?.as_ref().map(|(_,at)|at.elapsed()>=Duration::from_secs(35))).unwrap_or(true);
        if refresh{
            let seed=client.session_seed();
            client=KernelClient::refresh_session_seed(&seed,&self.journal_path,&self.required_features,cancel).await?;
            if let Some(session)=&self.session{*session.seed.lock().map_err(|_|KernelAccessError::Runtime)?=Some((client.session_seed(),Instant::now()));}
        }
        client.refresh_authorization_context(cancel).await?;Ok(())
    }

    pub fn migrate_archive_with_cancel(&self,wire:&[u8],cancel:&CancellationToken)->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(180);
        let identity=self.identity()?;let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let selection=serde_json::from_slice(wire).map_err(|_|KernelClientError::InvalidCommand)?;
        let runtime=self.runtime()?;let mut client=self.open_client_until(&runtime,cancel,deadline)?;
        Ok(runtime.block_on(client.migrate_archive_until(&identity,&authority,selection,cancel,deadline))?)
    }

    fn access_recipient_path(&self,origin:&str)->PathBuf{
        self.identity_path.with_extension(format!("{}.access-recipient",sha256_hex(origin.as_bytes())))
    }
    pub fn request_access_json(&self,wire:&str,cancel:&CancellationToken)->Result<serde_json::Value,KernelPublicError>{
        if wire.len()>4096{return Err("access request selection exceeds limit".into());}
        let selection=serde_json::from_str::<crate::kernel_client::StructureAccessRequest>(wire).map_err(|_|KernelPublicError::from("invalid device access request selection"))?;
        let identity=self.identity().map_err(KernelPublicError::from)?;let runtime=self.runtime().map_err(KernelPublicError::from)?;let client=self.open_client(&runtime,cancel).map_err(KernelPublicError::from)?;
        runtime.block_on(client.request_structure_access(&identity,&self.access_recipient_path(client.origin()),selection,cancel)).map_err(|e|KernelPublicError::from(KernelAccessError::from(e)))
    }
    pub fn publish_selected_record_with_cancel(&self,wire:&[u8],cancel:&CancellationToken)->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(30);
        peerwork_core::wire_json::parse_wire_json_bounded(wire,16,524288).map_err(|_|KernelClientError::InvalidCommand)?;
        let selection=serde_json::from_slice(wire).map_err(|_|KernelClientError::InvalidCommand)?;
        let identity=self.identity()?;let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));let runtime=self.runtime()?;let mut client=self.open_client_until(&runtime,cancel,deadline)?;
        Ok(runtime.block_on(client.publish_selected_record_until(&identity,&authority,selection,cancel,deadline))?)
    }
    pub fn authorize_access_with_cancel(&self,wire:&[u8],cancel:&CancellationToken)->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(30);
        if wire.len()>20000{return Err(KernelClientError::InvalidCommand.into());}
        peerwork_core::wire_json::parse_wire_json_bounded(wire,16,20000).map_err(|_|KernelClientError::InvalidCommand)?;
        let selection=serde_json::from_slice(wire).map_err(|_|KernelClientError::InvalidCommand)?;
        let identity=self.identity()?;let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));let runtime=self.runtime()?;let mut client=self.open_client_until(&runtime,cancel,deadline)?;
        Ok(runtime.block_on(async{
            let mut outcome=client.authorize_structure_access_until(&identity,&authority,selection,cancel,deadline).await?;
            let _=tokio::time::timeout_at(deadline,client.complete_structure_history_outcome(&identity,&authority,&mut outcome,cancel)).await;
            Ok::<_,KernelClientError>(outcome)
        })?)
    }
    pub fn coordinate_content_keys_json(&self,wire:&str,cancel:&CancellationToken)->Result<crate::kernel_client::StructureIntentOutcome,KernelPublicError>{
        #[derive(serde::Deserialize)]#[serde(deny_unknown_fields)]struct Selection{workspace_id:String}
        if wire.len()>4096{return Err("key coordination selection exceeds limit".into());}
        let s:Selection=serde_json::from_str(wire).map_err(|_|KernelPublicError::from("invalid key coordination selection"))?;
        let identity=self.identity().map_err(KernelPublicError::from)?;let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let runtime=self.runtime().map_err(KernelPublicError::from)?;let mut client=self.open_client(&runtime,cancel).map_err(KernelPublicError::from)?;
        runtime.block_on(client.coordinate_structure_keys(&identity,&authority,&s.workspace_id,cancel)).map_err(|e|KernelPublicError::from(KernelAccessError::from(e)))
    }
    pub fn rotate_content_key_json(&self,wire:&str,cancel:&CancellationToken)->Result<crate::kernel_client::StructureIntentOutcome,KernelPublicError>{
        if wire.len()>4096{return Err("body-key rotation selection exceeds limit".into());}
        let selection=serde_json::from_str::<crate::kernel_client::StructureContentKeyRotation>(wire).map_err(|_|KernelPublicError::from("invalid body-key rotation selection"))?;
        let identity=self.identity().map_err(KernelPublicError::from)?;let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let runtime=self.runtime().map_err(KernelPublicError::from)?;let mut client=self.open_client(&runtime,cancel).map_err(KernelPublicError::from)?;
        runtime.block_on(client.rotate_structure_content_key(&identity,&authority,selection,cancel)).map_err(|e|KernelPublicError::from(KernelAccessError::from(e)))
    }
    pub fn accept_content_keys_json(&self,wire:&str,cancel:&CancellationToken)->Result<serde_json::Value,KernelPublicError>{
        if wire.len()>4096{return Err("selected key import exceeds limit".into());}
        let selection=serde_json::from_str(wire).map_err(|_|KernelPublicError::from("invalid selected key import"))?;
        let identity=self.identity().map_err(KernelPublicError::from)?;let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));let runtime=self.runtime().map_err(KernelPublicError::from)?;let mut client=self.open_client(&runtime,cancel).map_err(KernelPublicError::from)?;
        let path=self.access_recipient_path(client.origin());runtime.block_on(client.accept_structure_keys(&identity,&authority,&path,selection,cancel)).map_err(|e|KernelPublicError::from(KernelAccessError::from(e)))
    }

    /// Local initialization only; does not grant access or deliver keys.
    pub fn ensure_local_content_key_with_cancel(&self,workspace:&str,cancel:&CancellationToken)
        ->Result<crate::kernel_intents::ContentKeyInfo,KernelAccessError>{
        if cancel.is_cancelled(){return Err(KernelAccessError::Cancelled);}
        let identity=self.identity()?;
        let transport=crate::transport::HttpTransport::new(self.transport_config()).map_err(KernelClientError::from)?;
        let mut keys=crate::kernel_intents::StructureContentKeys::open(&self.content_key_path_for_origin(transport.trusted_origin()),self.transport_config())
            .map_err(KernelClientError::from)?;
        Ok(keys.ensure_current(identity.key_id(),workspace).map_err(KernelClientError::from)?)
    }

    pub fn ensure_local_content_key_json(&self,request:&str,cancel:&CancellationToken)->Result<serde_json::Value,KernelPublicError>{
        #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Selection{workspace_id:String}
        if request.len()>512{return Err("body-key selection exceeds limit".into());}
        let s:Selection=serde_json::from_str(request).map_err(|_|KernelPublicError::from("workspace_id is required for local body-key selection"))?;
        Ok(serde_json::json!(self.ensure_local_content_key_with_cancel(&s.workspace_id,cancel).map_err(KernelPublicError::from)?))
    }

    pub(crate) fn follow_structure_operation_with_cancel(&self,selection_wire:&[u8],cancel:&CancellationToken)
        ->Result<crate::kernel_client::StructureIntentOutcome,KernelAccessError>{
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let runtime=self.runtime()?;let mut client=self.open_client(&runtime,cancel)?;
        Ok(runtime.block_on(client.follow_structure_operation(&identity,&authority,selection_wire,cancel))?)
    }

    pub fn resume_structure_intent_with_cancel(
        &self,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<crate::kernel_client::StructureIntentOutcome, KernelAccessError> {
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(30);
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let runtime=self.runtime()?;
        let mut client=self.open_client_until(&runtime,cancel,deadline)?;
        Ok(runtime.block_on(async{
            let mut outcome=client.resume_structure_parent_until(&identity,&authority,command_id,None,cancel,deadline).await?;
            let _=tokio::time::timeout_at(deadline,async{
                client.complete_known_structure_outcome(&identity,&authority,&mut outcome,cancel).await;
                client.complete_structure_history_outcome(&identity,&authority,&mut outcome,cancel).await;
            }).await;
            Ok::<_,KernelClientError>(outcome)
        })?)
    }

    pub(crate) fn resume_structure_intent_scoped_with_cancel(
        &self, command_id: &str, workspace: &str, cancel: &CancellationToken,
    ) -> Result<crate::kernel_client::StructureIntentOutcome, KernelAccessError> {
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(30);
        let identity=self.identity()?;
        let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
        let runtime=self.runtime()?;
        let mut client=self.open_client_until(&runtime,cancel,deadline)?;
        Ok(runtime.block_on(async{
            let mut outcome=client.resume_structure_parent_until(&identity,&authority,command_id,Some(workspace),cancel,deadline).await?;
            let _=tokio::time::timeout_at(deadline,async{
                client.complete_known_structure_outcome(&identity,&authority,&mut outcome,cancel).await;
                client.complete_structure_history_outcome(&identity,&authority,&mut outcome,cancel).await;
            }).await;
            Ok::<_,KernelClientError>(outcome)
        })?)
    }

    pub fn prepare_with_cancel(
        &self,
        command_wire: &[u8],
        upload_chunk: Option<&[u8]>,
        cancel: &CancellationToken,
    ) -> Result<PendingKernelIntent, KernelAccessError> {
        let parsed = parse_wire_json_bounded(command_wire, 40, 180_000)
            .map_err(|_| KernelClientError::InvalidCommand)?;
        if !crate::runtime_contract::supports_command(&parsed){return Err(KernelClientError::LegacyModeRetired.into());}
        let identity = self.identity()?;
        let expected_authority = self
            .authority_override
            .clone()
            .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
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
        let client = KernelClient::open_cached(self.transport_config(),&self.journal_path,&self.required_features,cancel)?;
        Ok(client.pending(identity.key_id())?)
    }

    pub fn pending_page_json_with_cancel(&self,request:&str,cancel:&CancellationToken)
        ->Result<serde_json::Value,KernelPublicError>{
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Page {after:Option<String>,preparations_after:Option<String>,limit:Option<usize>}
        if request.len()>2048{return Err("pending page request exceeds limit".into());}
        let options:Page=serde_json::from_str(request).map_err(|_|KernelPublicError::from("invalid pending page options"))?;
        if options.limit.is_some_and(|v|!(1..=32).contains(&v))||options.after.as_deref().into_iter().chain(options.preparations_after.as_deref()).any(|v|
            v.len()!=43||!v.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'))){
            return Err("pending page requires limit 1-32 and a command-ID cursor".into());
        }
        let result=(||->Result<_,KernelAccessError>{
            let identity=self.identity()?;
            let client=KernelClient::open_cached(self.transport_config(),&self.journal_path,&self.required_features,cancel)?;
            let authority=self.authority_override.clone().unwrap_or_else(||sha256_hex(identity.actor_id().as_bytes()));
            let mut page=serde_json::json!(client.pending_page(identity.key_id(),options.after.as_deref(),options.limit.unwrap_or(32))?);
            page["preparations"]=client.preparations_page(&identity,&authority,options.preparations_after.as_deref(),options.limit.unwrap_or(32))?;
            Ok(page)
        })().map_err(KernelPublicError::from)?;
        Ok(serde_json::json!(result))
    }

    /// SDK-owned bounded loop for an explicit legacy local locator rebuild.
    /// No network, identity migration, response acceptance or request replay.
    pub fn build_pending_index_with_cancel(&self,cancel:&CancellationToken)
        ->Result<crate::kernel_intents::PendingIndexProgress,KernelAccessError>{
        if cancel.is_cancelled(){return Err(KernelAccessError::Cancelled);}
        let _identity=self.identity()?;
        let mut journal=crate::kernel_intents::KernelIntentJournal::open(&self.journal_path).map_err(KernelClientError::from)?;
        let started=std::time::Instant::now();
        let mut scanned_rows=0;
        for _ in 0..64 {
            if cancel.is_cancelled(){return Err(KernelAccessError::Cancelled);}
            let step=journal.build_pending_index(32).map_err(KernelClientError::from)?;
            scanned_rows+=step.scanned_rows;
            if step.complete{return Ok(crate::kernel_intents::PendingIndexProgress{complete:true,scanned_rows});}
            if started.elapsed()>=std::time::Duration::from_secs(2){break;}
        }
        Ok(crate::kernel_intents::PendingIndexProgress{complete:false,scanned_rows})
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
    use crate::test_support::protected_test_dir;
    #[test]
    fn pending_page_and_index_maintenance_are_offline_and_errors_are_actionable(){
        let state=protected_test_dir();let identity=state.path().join("identity");
        KernelIdentity::create(&identity).unwrap();let path=state.path().join("journal");
        let mut journal=crate::kernel_intents::KernelIntentJournal::open(&path).unwrap();
        let wire=serde_json::to_vec(&serde_json::json!({"semantics":"peerwork.kernel.v1","audience":"offline-pending",
            "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
            "receipt_public_key":peerwork_core::crypto::key_id(&[22;32]),"limits":{"max":1}})).unwrap();
        let discovery=peerwork_core::discovery::parse_discovery_wire(&wire,wire.len()).unwrap();
        // Port 1 has no service. These public native entrypoints must require
        // no discovery fetch, Tokio runtime, workspace history or remote loop.
        journal.bind_discovery("http://127.0.0.1:1/",&discovery).unwrap();drop(journal);
        let access=KernelAccess::new("http://127.0.0.1:1",&path,&identity,&[],true);
        let cancel=CancellationToken::new();
        assert!(access.pending().unwrap().is_empty());
        let page=access.pending_page_json_with_cancel("{}",&cancel).unwrap();
        assert_eq!(page,serde_json::json!({"items":[],"next_after":null,"consistency":"LIVE_KEYSET","preparations":{"items":[],"next_after":null,"consistency":"LIVE_KEYSET"}}));
        assert!(access.build_pending_index_with_cancel(&cancel).unwrap().complete);
        assert_eq!(access.pending_page_json_with_cancel(r#"{"limit":true}"#,&cancel).unwrap_err().code,"INPUT_INVALID");
        assert_eq!(access.pending_page_json_with_cancel(r#"{"unknown":1}"#,&cancel).unwrap_err().code,"INPUT_INVALID");
        assert_eq!(KernelPublicError::from(KernelAccessError::from(C::Store(J::PendingIndexIncomplete))).code,"PENDING_INDEX_BUILD_REQUIRED");
        assert_eq!(KernelPublicError::from(KernelAccessError::from(C::Store(J::PendingPageRequired))).code,"PENDING_PAGE_REQUIRED");
        cancel.cancel();assert_eq!(KernelPublicError::from(access.build_pending_index_with_cancel(&cancel).unwrap_err()).code,"CANCELLED");
    }
    #[test]
    fn malformed_and_retired_commands_fail_without_creating_a_journal() {
        let state = protected_test_dir();
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
        assert_eq!(authority.code, "LEGACY_MODE_RETIRED");
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
            if code=="SERVICE_REJECTED" {
                assert_eq!(serde_json::from_str::<serde_json::Value>(&wire).unwrap()["details"]["http_status"],503);
            } else {assert!(!wire.contains("503"));}
        }
    }
}
