//! Native PRIVATE browser approval. Exact reference/request provenance, protected
//! preparation and receipt-gated code release; browser redemption is separate.
use crate::{
    kernel_client::{KernelClient, KernelClientError},
    kernel_identity::KernelIdentity,
    secure_lifecycle::SecureLifecycle,
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::{SecureStateError, SecureStateStore},
    transport::TransportConfig,
};
use peerwork_core::{
    browser_approval::{
        parse_browser_approval_reference, prepare_private_browser_approval, BrowserApprovalError,
        BrowserApprovalInput,
    },
    crypto::{base64url, decode_base64url, sha256_hex},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum BrowserApprovalRuntimeError {
    #[error("browser approval input is invalid")]
    Invalid,
    #[error("browser approval selected context changed")]
    Context,
    #[error("browser approval operation ID binds a different intent")]
    Conflict,
    #[error("browser approval operation was not found")]
    NotFound,
    #[error("browser approval state is unavailable")]
    State,
    #[error("browser approval state is busy")]
    Busy,
    #[error("browser approval operation cancelled")]
    Cancelled,
    #[error("browser request could not be read from the selected service")]
    Request,
    #[error("browser approval receipt verification failed")]
    Receipt,
    #[error("browser approval source verification failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error(transparent)]
    Core(#[from] BrowserApprovalError),
    #[error("browser approval command preparation failed")]
    Command,
}
impl BrowserApprovalRuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "BROWSER_APPROVAL_INVALID",
            Self::Context => "CONTEXT_MISMATCH",
            Self::Conflict => "OPERATION_CONFLICT",
            Self::NotFound => "OPERATION_NOT_FOUND",
            Self::State => "STATE_FAILED",
            Self::Busy => "STATE_BUSY",
            Self::Cancelled => "CANCELLED",
            Self::Request => "BROWSER_REQUEST_READ",
            Self::Receipt => "BROWSER_APPROVAL_RECEIPT",
            Self::Read(e) => e.code(),
            Self::Core(e) => e.code(),
            Self::Command => "BROWSER_APPROVAL_COMMAND",
        }
    }
    pub fn effect_certainty(&self) -> &'static str {
        match self {
            Self::Receipt
            | Self::State
            | Self::Busy
            | Self::Command
            | Self::Context
            | Self::Cancelled => "unknown",
            _ => "not_sent",
        }
    }
}
impl From<SecureStateError> for BrowserApprovalRuntimeError {
    fn from(e: SecureStateError) -> Self {
        match e {
            SecureStateError::Busy => Self::Busy,
            _ => Self::State,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    reference: String,
    approve_writes: bool,
    command_id: String,
    request_id: String,
    body: String,
    code: String,
    command: String,
    expires_at: u64,
    request_expires_at: u64,
    #[serde(default)]
    accepted_observed: bool,
}
impl Drop for Row {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    binding: String,
    rows: BTreeMap<String, Row>,
}
fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.contains('\0')
}
fn now() -> Result<u64, BrowserApprovalRuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(BrowserApprovalRuntimeError::Invalid)
}
fn binding(
    config: &SecureReadProfileConfig,
    fp: &str,
) -> Result<String, BrowserApprovalRuntimeError> {
    if !valid(fp) {
        return Err(BrowserApprovalRuntimeError::Invalid);
    }
    let identity = KernelIdentity::inspect_existing(&config.identity_path)
        .map_err(|_| BrowserApprovalRuntimeError::Context)?;
    Ok(sha256_hex(&serde_json::to_vec(&json!({"fp":fp,"origin":config.origin,"actor":identity.actor_id(),"key":identity.key_id(),"workspace":config.workspace_id,"owner":config.owner_actor_id,"owner_key":config.owner_key_id,"authority":config.authority})).map_err(|_|BrowserApprovalRuntimeError::Context)?))
}
fn exists(path: &Path) -> Result<bool, BrowserApprovalRuntimeError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(BrowserApprovalRuntimeError::State),
    }
}
fn load(
    config: &SecureReadProfileConfig,
    fp: &str,
    create: bool,
) -> Result<Option<(SecureStateStore, Document)>, BrowserApprovalRuntimeError> {
    let expected = binding(config, fp)?;
    let path = config.state_dir.join("browser-approvals.state");
    crate::secure_state::check_private_directory(&config.state_dir)?;
    if !create && !exists(&path)? {
        return Ok(None);
    }
    let store = SecureStateStore::open(&path)?;
    let document = match store.read_exact_secret()? {
        Some(bytes) => {
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(BrowserApprovalRuntimeError::State);
            }
            let doc: Document =
                serde_json::from_slice(&bytes).map_err(|_| BrowserApprovalRuntimeError::State)?;
            if doc.version != 1 || doc.binding != expected {
                return Err(BrowserApprovalRuntimeError::Context);
            }
            doc
        }
        None => Document {
            version: 1,
            binding: expected,
            rows: BTreeMap::new(),
        },
    };
    Ok(Some((store, document)))
}
fn persist(store: &SecureStateStore, doc: &Document) -> Result<(), BrowserApprovalRuntimeError> {
    let bytes =
        Zeroizing::new(serde_json::to_vec(doc).map_err(|_| BrowserApprovalRuntimeError::State)?);
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(BrowserApprovalRuntimeError::State);
    }
    store.write_exact(&bytes)?;
    Ok(())
}
fn runtime() -> Result<tokio::runtime::Runtime, BrowserApprovalRuntimeError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| BrowserApprovalRuntimeError::State)
}
fn client(
    config: &SecureReadProfileConfig,
    cancel: &CancellationToken,
) -> Result<KernelClient, KernelClientError> {
    let mut transport = TransportConfig::new(&config.origin).with_options(config.transport.clone());
    transport.allow_loopback_http = config.allow_loopback_http;
    let required = config
        .required_features
        .iter()
        .map(|s| s.encode_utf16().collect())
        .collect::<Vec<Vec<u16>>>();
    runtime()
        .map_err(|_| KernelClientError::InvalidCommand)?
        .block_on(KernelClient::open(
            transport,
            &config.state_dir.join("kernel.sqlite"),
            &required,
            cancel,
        ))
}
fn pending(operation_id: &str, row: &Row, workspace: &str, reason: &str) -> Value {
    json!({"kind":"browser.approve","operation_id":operation_id,"command_id":row.command_id,"workspace_id":workspace,"request_id":row.request_id,"status":"PENDING","verification":"pending","effect_certainty":"unknown","reason":reason,"browser_consumption":"pending","continuation":{"kind":"browser.approve","operation_id":operation_id,"command_id":row.command_id}})
}
fn finish(
    config: &SecureReadProfileConfig,
    operation_id: &str,
    row: &Row,
    cancel: &CancellationToken,
) -> Result<Value, BrowserApprovalRuntimeError> {
    if cancel.is_cancelled() {
        return Ok(pending(
            operation_id,
            row,
            &config.workspace_id,
            "CANCELLED",
        ));
    }
    let identity = KernelIdentity::inspect_existing(&config.identity_path)
        .map_err(|_| BrowserApprovalRuntimeError::Context)?;
    // The durable row is a private preparation record, never acceptance proof.
    let body: Value =
        serde_json::from_str(&row.body).map_err(|_| BrowserApprovalRuntimeError::State)?;
    let decoded = Zeroizing::new(
        decode_base64url(&row.code).map_err(|_| BrowserApprovalRuntimeError::State)?,
    );
    if decoded.len() != 32
        || body["code_hash"] != sha256_hex(&decoded)
        || body["request_id"] != row.request_id
    {
        return Err(BrowserApprovalRuntimeError::State);
    }
    let mut client = match client(config, cancel) {
        Ok(v) => v,
        Err(_) => {
            return Ok(pending(
                operation_id,
                row,
                &config.workspace_id,
                "DISCOVERY_UNAVAILABLE",
            ))
        }
    };
    // Deterministic signature over the stored command repairs a crash between
    // state persistence and journal preparation; never changes time/body/code.
    client
        .prepare_command(&identity, row.command.as_bytes(), None)
        .map_err(|_| BrowserApprovalRuntimeError::Command)?;
    let mut verified = client
        .verified_browser_approval_result(
            &row.command_id,
            identity.key_id(),
            &row.request_id,
            &config.workspace_id,
            &row.body,
        )
        .map_err(|_| BrowserApprovalRuntimeError::Receipt)?;
    if verified.is_none() {
        if now()? >= row.expires_at || now()? >= row.request_expires_at {
            return Ok(pending(
                operation_id,
                row,
                &config.workspace_id,
                "EXPIRED_UNRESOLVED",
            ));
        }
        // Server exact-command deduplication is the existing kernel recovery
        // contract. No new command is synthesized for an uncertain submission.
        if runtime()?
            .block_on(client.submit_saved(&row.command_id, identity.key_id(), cancel))
            .is_err()
        {
            return Ok(pending(
                operation_id,
                row,
                &config.workspace_id,
                "SUBMISSION_UNRESOLVED",
            ));
        }
        verified = client
            .verified_browser_approval_result(
                &row.command_id,
                identity.key_id(),
                &row.request_id,
                &config.workspace_id,
                &row.body,
            )
            .map_err(|_| BrowserApprovalRuntimeError::Receipt)?;
    }
    let result = verified.ok_or(BrowserApprovalRuntimeError::Receipt)?;
    let mut out = json!({"kind":"browser.approve","operation_id":operation_id,"command_id":row.command_id,"workspace_id":config.workspace_id,"request_id":row.request_id,"status":"ACCEPTED","verification":"verified","effect_certainty":"accepted","browser_consumption":"pending","receipt_result":serde_json::from_str::<Value>(&result).map_err(|_|BrowserApprovalRuntimeError::Receipt)?,"continuation":{"kind":"browser.approve","operation_id":operation_id,"command_id":row.command_id}});
    if now()? < row.request_expires_at {
        let owner = config
            .owner_key_id
            .as_deref()
            .ok_or(BrowserApprovalRuntimeError::Context)?;
        out["approval_code"] = json!(format!(
            "peerwork-secure-code:v1:{}:{}:{}:{}:{}",
            config.workspace_id,
            row.request_id,
            row.code,
            owner,
            identity.key_id()
        ));
    } else {
        out["code_status"] = json!("expired");
    }
    Ok(out)
}
pub fn approve(
    config: SecureReadProfileConfig,
    fp: &str,
    reference: &str,
    approve_writes: bool,
    operation_id: &str,
    cancel: &CancellationToken,
) -> Result<Value, BrowserApprovalRuntimeError> {
    if !valid(operation_id) || !valid(fp) {
        return Err(BrowserApprovalRuntimeError::Invalid);
    }
    let parsed = parse_browser_approval_reference(reference)?;
    if parsed.workspace_id != config.workspace_id {
        return Err(BrowserApprovalRuntimeError::Context);
    }
    if cancel.is_cancelled() {
        return Err(BrowserApprovalRuntimeError::Cancelled);
    }
    let (store, mut doc) = load(&config, fp, true)?.ok_or(BrowserApprovalRuntimeError::State)?;
    if let Some(row) = doc.rows.get(operation_id) {
        if row.reference != reference || row.approve_writes != approve_writes {
            return Err(BrowserApprovalRuntimeError::Conflict);
        }
        let result = finish(&config, operation_id, row, cancel)?;
        if result["status"] == "ACCEPTED" {
            doc.rows.get_mut(operation_id).unwrap().accepted_observed = true;
            persist(&store, &doc)?;
        }
        return Ok(result);
    }
    if doc.rows.len() >= 128 {
        return Err(BrowserApprovalRuntimeError::State);
    }
    let row=SecureReadProfile::new(config.clone()).with_latest_replay(cancel,|source| -> Result<Row,BrowserApprovalRuntimeError> {
        source.verified_read().map_err(|_|BrowserApprovalRuntimeError::Context)?;
        let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|BrowserApprovalRuntimeError::Context)?;
        if source.source_actor_id()!=identity.actor_id()||source.source_key_id()!=identity.key_id()||source.replay().workspace_id()!=config.workspace_id {return Err(BrowserApprovalRuntimeError::Context);}
        let client=client(&config,cancel).map_err(|_|BrowserApprovalRuntimeError::Request)?;
        if client.origin()!=source.origin(){return Err(BrowserApprovalRuntimeError::Context);}
        let path=format!("/api/workspace/v1/admin/workspaces/{}/browser-requests/{}",parsed.workspace_id,parsed.request_id);
        let proof=crate::secure_journal_read::sign_read_proof(&path,client.discovery(),&identity,source.authority()).map_err(|_|BrowserApprovalRuntimeError::Request)?;
        let response=runtime()?.block_on(client.transport().get_browser_approval_request(&parsed.workspace_id,&parsed.request_id,&proof,cancel)).map_err(|_|BrowserApprovalRuntimeError::Request)?;
        if response.status!=200 {return Err(BrowserApprovalRuntimeError::Request);}
        let lifecycle=SecureLifecycle::open(&config.state_dir.join("lifecycle.state"),source.origin(),identity.actor_id(),&config.workspace_id,source.replay().owner_actor_id(),source.replay().owner_signing_key()).map_err(|_|BrowserApprovalRuntimeError::Context)?;
        let ring=lifecycle.active_keyring_without_pending().ok_or(BrowserApprovalRuntimeError::Context)?;
        let ring_wire=Zeroizing::new(ring.canonical_wire().map_err(|_|BrowserApprovalRuntimeError::Context)?);
        // Reprove the same authenticated history using the exact locked active
        // ring being granted, avoiding a lifecycle replacement race.
        let replay=source.authenticated_prefix_replay(source.checkpoint_canonical_json().as_bytes(),Some(&ring_wire)).map_err(|_|BrowserApprovalRuntimeError::Context)?;
        let policy=source.signed_policy_by_hash(replay.policy_hash()).ok_or(BrowserApprovalRuntimeError::Context)?;
        let origin=reqwest::Url::parse(client.origin()).map_err(|_|BrowserApprovalRuntimeError::Context)?.origin().ascii_serialization();
        let audience=String::from_utf16(client.discovery().audience_utf16()).map_err(|_|BrowserApprovalRuntimeError::Context)?;
        let issued=now()?;
        let prepared=prepare_private_browser_approval(BrowserApprovalInput {request_wire:&response.wire,reference,control_origin:&origin,audience:&audience,replay:&replay,policy_wire:policy,keyring:ring,signing_key:identity.signing_key(),now:issued,approve_writes})?;
        let mut random=[0u8;32];OsRng.try_fill_bytes(&mut random).map_err(|_|BrowserApprovalRuntimeError::State)?;
        let command_id=base64url(&random);let expires=issued.checked_add(600_000).ok_or(BrowserApprovalRuntimeError::Invalid)?;
        let command=json!({"v":1,"audience":audience,"command_id":command_id,"actor_id":identity.actor_id(),"authority":source.authority(),"method":"POST","path":"/api/workspace/v1/commands","workspace_id":null,"instance_id":null,"protocol_digest":null,"action_id":"browser.session.approve","expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"body":serde_json::from_str::<Value>(&prepared.body_canonical_json).map_err(|_|BrowserApprovalRuntimeError::Invalid)?,"issued_at":issued,"expires_at":expires});
        Ok(Row {reference:reference.into(),approve_writes,command_id,request_id:prepared.request_id,body:prepared.body_canonical_json,code:prepared.code.to_string(),command:serde_json::to_string(&command).map_err(|_|BrowserApprovalRuntimeError::Invalid)?,expires_at:expires,request_expires_at:prepared.request_expires_at,accepted_observed:false})
    })?;
    doc.rows.insert(operation_id.into(), row);
    persist(&store, &doc)?;
    let result = finish(
        &config,
        operation_id,
        doc.rows.get(operation_id).unwrap(),
        cancel,
    )?;
    if result["status"] == "ACCEPTED" {
        doc.rows.get_mut(operation_id).unwrap().accepted_observed = true;
        persist(&store, &doc)?;
    }
    Ok(result)
}
fn selected<'a>(
    doc: &'a Document,
    operation_id: Option<&str>,
    command_id: Option<&str>,
) -> Result<Option<(&'a str, &'a Row)>, BrowserApprovalRuntimeError> {
    match (operation_id, command_id) {
        (Some(id), None) if valid(id) => Ok(doc
            .rows
            .get_key_value(id)
            .map(|(id, row)| (id.as_str(), row))),
        (None, Some(id)) if valid(id) => Ok(doc
            .rows
            .iter()
            .find(|(_, r)| r.command_id == id)
            .map(|(id, row)| (id.as_str(), row))),
        _ => Err(BrowserApprovalRuntimeError::Invalid),
    }
}
pub fn has_operation(
    config: SecureReadProfileConfig,
    fp: &str,
    operation_id: Option<&str>,
    command_id: Option<&str>,
) -> Result<bool, BrowserApprovalRuntimeError> {
    let Some((_store, doc)) = load(&config, fp, false)? else {
        return Ok(false);
    };
    Ok(selected(&doc, operation_id, command_id)?.is_some())
}
pub fn recover(
    config: SecureReadProfileConfig,
    fp: &str,
    operation_id: Option<&str>,
    command_id: Option<&str>,
    cancel: &CancellationToken,
) -> Result<Value, BrowserApprovalRuntimeError> {
    let Some((store, mut doc)) = load(&config, fp, false)? else {
        return Err(BrowserApprovalRuntimeError::NotFound);
    };
    let (id, row) =
        selected(&doc, operation_id, command_id)?.ok_or(BrowserApprovalRuntimeError::NotFound)?;
    let result = finish(&config, id, row, cancel)?;
    let id = id.to_owned();
    if result["status"] == "ACCEPTED" {
        doc.rows.get_mut(&id).unwrap().accepted_observed = true;
        persist(&store, &doc)?;
    }
    Ok(result)
}
pub fn operations(
    config: SecureReadProfileConfig,
    fp: &str,
) -> Result<Value, BrowserApprovalRuntimeError> {
    let Some((_store, doc)) = load(&config, fp, false)? else {
        return Ok(json!([]));
    };
    Ok(json!(doc.rows.iter().filter(|(_,r)|!r.accepted_observed).map(|(id,r)|json!({"kind":"browser.approve","operation_id":id,"command_id":r.command_id,"workspace_id":config.workspace_id,"request_id":r.request_id,"status":"SAVED","continuation":{"kind":"browser.approve","operation_id":id,"command_id":r.command_id}})).collect::<Vec<_>>()))
}
#[cfg(test)]
mod tests;
