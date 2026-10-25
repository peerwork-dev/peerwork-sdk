//! HTTPS discovery with exact schema and durable origin/authority continuity.
//! Kernel command submission remains internal until verified outcome recovery
//! is persisted; this type currently supports discovery and pending listing.

use crate::{
    kernel_identity::KernelIdentity,
    kernel_intents::{
        JournalError, KernelIntentJournal, KernelPath, PendingKernelIntent, VerifiedPendingCommand,
    },
    transport::{ExactHttpResponse, HttpTransport, TransportConfig, TransportError, MAX_DISCOVERY_BYTES},
};
use peerwork_core::discovery::{parse_discovery_wire, ParsedDiscovery};
use peerwork_core::prepared_command::prepare_signed_command_wire;
use peerwork_core::prepared_command::VerifiedPreparedCommand;
use peerwork_core::receipt_wire::{verify_http_response_for_prepared, VerifiedCommandResponse};
use peerwork_core::wire_json::{parse_wire_json_bounded, WireValue};
use serde::Serialize;
use std::path::{Path,PathBuf};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[path = "structure_access_client.rs"]
mod structure_access_client;
pub use structure_access_client::{StructureAccessRequest,StructureAccessApproval,StructureKeyAcceptance};
#[path = "structure_parent_client.rs"]
mod structure_parent_client;
#[path="archive_migration_client.rs"]
mod archive_migration_client;
pub use archive_migration_client::ArchiveMigrationSelection;
#[path = "structure_intent.rs"]
mod structure_intent;
pub use structure_intent::StructureIntentOutcome;
pub(crate) use structure_intent::keyed_command_id as structure_keyed_command_id;
pub(crate) fn validate_public_action(value:&serde_json::Value)->Result<(),KernelClientError>{
    let invalid=||KernelClientError::InvalidCommand;
    if value.as_object().map(|o|o.len())!=Some(3)||value["disclosure"]!="PUBLISH_ACTION_AND_SELECTED_RECORDS"||value["policy_revision"].as_u64().is_none_or(|v|v==0||v>9_007_199_254_740_991){return Err(invalid());}
    let entries=value["entries"].as_array().ok_or_else(invalid)?;if entries.is_empty()||entries.len()>8{return Err(invalid());}
    let mut indices=std::collections::BTreeSet::new();let mut total=0usize;
    for entry in entries{
        if entry.as_object().map(|o|o.len())!=Some(3)||entry["record_index"].as_u64().is_none_or(|n|n>=8||!indices.insert(n))||entry["title"].as_str().is_none_or(|s|s.is_empty()||s.encode_utf16().count()>240)||entry["body"].as_object().map(|o|o.len())!=Some(2){return Err(invalid());}
        total+=crate::publication_read::public_text(&entry["body"]).map_err(|_|invalid())?.len();if total>65536{return Err(invalid());}
    }Ok(())
}

#[path = "structure_body_read.rs"]
mod structure_body_read;
pub use structure_body_read::OpenedStructureBody;

/// Verify already-signed transport bytes during raw preparation or recovery;
/// never reinterpret them as unsigned caller selections or regenerate proofs.
pub(crate) fn validate_public_wire(command:&WireValue)->Result<(),KernelClientError>{
 let invalid=||KernelClientError::InvalidCommand;let body=command.get("body").ok_or_else(invalid)?;let publication=body.get("publication").ok_or_else(invalid)?;
 if command.get("action_id").and_then(WireValue::as_string).as_deref()!=Some("structure.action")||publication.object_len()!=Some(3)||publication.get("disclosure").and_then(WireValue::as_string).as_deref()!=Some("PUBLISH_ACTION_AND_SELECTED_RECORDS")||body.get("contents").is_some_and(|v|!matches!(v,WireValue::Array(items) if items.is_empty())){return Err(invalid());}
 let Some(WireValue::Array(entries))=publication.get("entries")else{return Err(invalid());};if entries.is_empty()||entries.len()>8{return Err(invalid());}let mut seen=std::collections::BTreeSet::new();let mut total=0;
 for entry in entries{let index=entry.get("record_index").and_then(WireValue::as_number).filter(|v|v.fract()==0.0&&(0.0..8.0).contains(v)).ok_or_else(invalid)? as u64;if entry.object_len()!=Some(2)||!seen.insert(index){return Err(invalid());}total+=peerwork_core::public_output::for_command(entry.get("statement").ok_or_else(invalid)?,command,index).map_err(|_|invalid())?.text.len();}if total>65536{return Err(invalid());}Ok(())
}

#[derive(Debug, Error)]
pub enum KernelClientError {
    #[error("{0}")]
    ArchiveMigration(&'static str),
    #[error("legacy execution is retired; use backend-structure-v1")]
    LegacyModeRetired,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Store(#[from] JournalError),
    #[error(transparent)]
    ContentKey(#[from] crate::kernel_intents::ContentKeyError),
    #[error(transparent)]
    Access(#[from] peerwork_core::structure_access::AccessError),
    #[error(transparent)]
    AccessState(#[from] crate::secure_recipient_state::RecipientStateError),
    #[error(transparent)]
    Migration(#[from] crate::ts_migration::TsMigrationError),
    #[error("service confirmed refusal of a preflight or selected read")]
    OperationRefused(Box<OperationRefusal>),
    #[error("discovery HTTP status is not successful")]
    DiscoveryStatus,
    #[error("discovery schema or required features are unsupported")]
    UnsupportedDiscovery,
    #[error("body-key initialization outcome is unknown; recover the saved prerequisite command")]
    PrerequisitePending{command_id:String,workspace_id:String},
    #[error("Owner crypto prerequisite has a saved incomplete outcome")]
    CryptoPrerequisitePending{command_id:String,workspace_id:String,code:&'static str,retryable:bool},
    #[error("a selected historical key delivery is incomplete")]
    HistoryDeliveryBlocked{job_id:String,workspace_id:String,code:&'static str,retryable:bool},
    #[error("backend structure execution is unavailable on the selected service")]
    UnsupportedStructureProfile,
    #[error("saved command id was not found")]
    IntentNotFound,
    #[error("server rejected the saved command with HTTP {0}")]
    ServerRejected(u16),
    #[error("verified result has an unsupported public summary shape")]
    InvalidResult,
    #[error("command does not match pinned discovery, local identity, or supported signed shape")]
    InvalidCommand,
    #[error("document_times requires1..8 unique record_index selections0..7 and at least one strict RFC3339 created_at or updated_at per selection")]
    InvalidDocumentTime,
}

#[derive(Debug,Clone,Serialize)]
pub struct OperationRefusal{pub command_id:String,pub server_code:String,pub phase:String,pub http_status:Option<u16>,pub retryable:bool,pub recovery:String,pub effect_certainty:&'static str}
impl OperationRefusal{
 pub fn from_verified(result:&KernelAcceptedResult)->Result<Self,KernelClientError>{
  if result.outcome_state()!="REJECTED"{return Err(KernelClientError::InvalidResult);}
  let value:serde_json::Value=serde_json::from_str(result.structure_result_json.as_deref().ok_or(KernelClientError::InvalidResult)?).map_err(|_|KernelClientError::InvalidResult)?;
  let error=&value["error"];Ok(Self{command_id:result.command_id.clone(),server_code:error["code"].as_str().ok_or(KernelClientError::InvalidResult)?.into(),phase:error["phase"].as_str().ok_or(KernelClientError::InvalidResult)?.into(),http_status:error["http_status"].as_u64().map(|n|n as u16),retryable:false,recovery:error["recovery"].as_str().ok_or(KernelClientError::InvalidResult)?.into(),effect_certainty:"NOT_APPLIED"})
 }
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
    /// Authorized structure-profile data with an explicit backend assurance.
    /// Includes readable structure and opaque ciphertext, never identity keys.
    pub structure_result_json: Option<String>,
    /// Local opening of selected original-author bodies; never part of the
    /// service receipt and never persisted in the transport journal.
    pub opened_contents: Option<Vec<OpenedStructureBody>>,
    pub key_history:Option<StructureKeyHistoryReadiness>,
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
    /// Non-secret out-of-band bootstrap commitment derived only from the
    /// verified original Owner result. It is not added to signed service data.
    pub fn browser_approval_reference(&self)->Option<String>{
        let result:serde_json::Value=serde_json::from_str(self.structure_result_json.as_deref()?).ok()?;
        if matches!(result["status"].as_str(),Some("REJECTED_NO_EFFECT"|"COMMITTED_RESULT_UNAVAILABLE")){return None;}
        let wire=result["author_intent"].as_str()?;
        let payload=wire.split('.').nth(1)?;
        let command:serde_json::Value=serde_json::from_slice(&peerwork_core::crypto::decode_base64url(payload).ok()?).ok()?;
        if command["action_id"]!="structure.access.authorize"||command["body"]["mode"]!="SESSION"||command["body"]["content_key_epoch"].as_u64().is_none(){return None;}
        let csr=command["body"]["request_jws"].as_str()?.split('.').nth(1)?;
        let request:serde_json::Value=serde_json::from_slice(&peerwork_core::crypto::decode_base64url(csr).ok()?).ok()?;
        if request["kind"]!="BROWSER"||request["workspace_id"]!=command["workspace_id"]||request["request_id"]!=result["request_id"]||request["actor_id"]!=result["member_actor_id"]{return None;}
        Some(format!("peerwork-browser-approval:v2:{}:{}:{}:{}:{}",command["workspace_id"].as_str()?,request["request_id"].as_str()?,command["actor_id"].as_str()?,command["command_id"].as_str()?,peerwork_core::crypto::sha256_hex(wire.as_bytes())))
    }

    /// Receipt verification is distinct from applying business effects.
    pub fn outcome_state(&self)->&'static str{
        match self.structure_result_json.as_deref().and_then(|wire|serde_json::from_str::<serde_json::Value>(wire).ok()).and_then(|v|v["status"].as_str().map(str::to_owned)).as_deref(){
            Some("REJECTED_NO_EFFECT")=>"REJECTED",Some("COMMITTED_RESULT_UNAVAILABLE")=>"COMMITTED",_=>"ACCEPTED",
        }
    }
    fn from_verified(
        proof: VerifiedCommandResponse,
        prepared: &VerifiedPreparedCommand,
        catalog_begin: Option<(u64, u64)>,
    ) -> Result<Self, KernelClientError> {
        let prepared_command = parse_wire_json_bounded(prepared.command_canonical_json().as_bytes(), 40, 180_000)
            .map_err(|_| KernelClientError::InvalidResult)?;
        let structured = peerwork_core::structure_execution::is_structure_action(&required_text(&prepared_command, "action_id")?);
        let result = parse_wire_json_bounded(
            proof.result_canonical_json().as_bytes(),
            if structured { 32 } else { 12 },
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
        let structure_result_json = if structured {
            require_equal(&required_text(&result, "profile")?, peerwork_core::structure_execution::PROFILE)?;
            require_equal(&required_text(&result, "assurance")?, "BACKEND_CURRENT_STATE")?;
            Some(proof.result_canonical_json().to_owned())
        } else { None };
        Ok(Self {
            command_id: proof.command_id().to_owned(),
            workspace_id: proof.workspace_id().map(str::to_owned),
            protocol_digest: proof.protocol_digest().map(str::to_owned),
            instance_id,
            event_sequence: proof.event_sequence(),
            revision,
            produced_record_ids,
            catalog,
            structure_result_json,
            opened_contents: None,
            key_history:None,
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
    content_keys_path:Option<PathBuf>,
    access_recipient_path:Option<PathBuf>,
}

impl KernelClient {
    pub(crate) fn bind_access_recipient_path(&mut self,path:PathBuf){self.access_recipient_path=Some(path);}
    pub(crate) fn bind_content_key_path(&mut self,path:PathBuf){self.content_keys_path=Some(path);}
    pub(crate) fn content_key_store_path(&self)->PathBuf{
        self.content_keys_path.clone().unwrap_or_else(||self.journal.content_key_store_path())
    }
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
        if !crate::runtime_contract::supports_command(&command){return Err(KernelClientError::LegacyModeRetired);}
        if let Some(times)=command.get("body").and_then(|body|body.get("document_times")){
            if !self.discovery.protocol_features().contains(&"signed-document-time-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            if command.get("action_id").and_then(WireValue::as_string).as_deref()!=Some("structure.action"){return Err(KernelClientError::InvalidCommand);}
            peerwork_core::document_time::at(Some(times),0).map_err(|_|KernelClientError::InvalidDocumentTime)?;
        }
        if let Some(time)=command.get("body").and_then(|b|b.get("source")).and_then(|s|s.get("document_time")){
            if !self.discovery.protocol_features().contains(&"signed-document-time-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            if command.get("action_id").and_then(WireValue::as_string).as_deref()!=Some("structure.publication.entry.set")||time.object_len()!=Some(2){return Err(KernelClientError::InvalidCommand);}
            peerwork_core::document_time::normalized(time).map_err(|_|KernelClientError::InvalidDocumentTime)?;
        }
        if command.get("action_id").and_then(WireValue::as_string).is_some_and(|a|a.starts_with("structure.content-key.history."))&&!self.discovery.protocol_features().contains(&"owner-retained-key-delivery-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if command.get("action_id").and_then(WireValue::as_string).is_some_and(|a|matches!(a.as_str(),"structure.content-key.set"|"structure.content-key.get")){self.require_content_key_epochs()?;}
        if matches!(command.get("action_id").and_then(WireValue::as_string).as_deref(),Some("structure.workspace.delete"|"structure.workspace.deletion.get"|"structure.workspace.deletions.read"))&&!self.discovery.protocol_features().contains(&"durable-workspace-deletion-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if command.get("action_id").and_then(WireValue::as_string).as_deref()==Some("structure.record.withdraw")&&!self.discovery.protocol_features().contains(&"selected-record-withdrawal-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if command.get("action_id").and_then(WireValue::as_string).is_some_and(|a|matches!(a.as_str(),"structure.publication.policy.set"|"structure.publication.policy.get"|"structure.publication.entry.withdraw"))||command.get("body").is_some_and(|body|body.get("publication").is_some()){
            if !self.discovery.protocol_features().contains(&"member-public-actions-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            if command.get("body").is_some_and(|body|body.get("publication").is_some()){validate_public_wire(&command)?;}
        }
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

    /// Persist a fresh authorization for an existing backend structure intent.
    /// Business fields are immutable and every prior signed attempt is retained.
    /// The high-level operation driver supplies trusted authorization time;
    /// this low-level API never changes CAS or repairs business input.
    pub fn renew_structure_authorization(
        &mut self,
        identity: &KernelIdentity,
        command_wire: &[u8],
    ) -> Result<PendingKernelIntent, KernelClientError> {
        let command=parse_wire_json_bounded(command_wire,40,180_000).map_err(|_|KernelClientError::InvalidCommand)?;
        let signed=prepare_signed_command_wire(&command,identity.signing_key(),&self.discovery,None)
            .map_err(|_|KernelClientError::InvalidCommand)?;
        self.journal.renew_structure_authorization(&signed,&self.discovery).map_err(KernelClientError::Store)
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

    pub(crate) fn migrate_ts_store_selected(
        &mut self,
        source_path: &Path,
        backup_path: &Path,
        owner_actor_id: &str,
        owner_key_id: &str,
        workspace_id: &str,
        selected_pending_ids: &[String],
    ) -> Result<crate::kernel_intents::SelectedKernelImport, KernelClientError> {
        Ok(self.journal.import_ts_backup_selected(
            source_path,
            backup_path,
            &self.discovery,
            owner_actor_id,
            owner_key_id,
            workspace_id,
            selected_pending_ids,
        )?)
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
            content_keys_path:None,access_recipient_path:None,
        })
    }

    /// Refresh discovery only after locating the existing protected service pin.
    pub(crate) async fn open_existing(transport_config: TransportConfig, journal_path: &Path,
        required_features: &[Vec<u16>], cancel: &CancellationToken) -> Result<Self, KernelClientError> {
        if !journal_path.is_file() { return Err(KernelClientError::InvalidResult); }
        let transport = HttpTransport::new(transport_config)?;
        let mut journal = KernelIntentJournal::open(journal_path)?;
        journal.require_discovery_pin(transport.trusted_origin())?;
        let response = transport.discovery(cancel).await?;
        if !(200..300).contains(&response.status) { return Err(KernelClientError::DiscoveryStatus); }
        let discovery = parse_discovery_wire(&response.wire, MAX_DISCOVERY_BYTES)
            .map_err(|_| KernelClientError::UnsupportedDiscovery)?;
        if !discovery.supports_required_features(required_features) { return Err(KernelClientError::UnsupportedDiscovery); }
        journal.bind_discovery(transport.trusted_origin(), &discovery)?;
        Ok(Self { transport, journal, discovery,content_keys_path:None,access_recipient_path:None })
    }

    /// Open an existing protected pin without discovery HTTP. Only cached
    /// historical read verification uses this; no freshness is established.
    pub(crate) fn open_cached(transport_config: TransportConfig, journal_path: &Path,
        required_features: &[Vec<u16>], cancel: &CancellationToken) -> Result<Self, KernelClientError> {
        if cancel.is_cancelled() { return Err(TransportError::Cancelled.into()); }
        if !journal_path.is_file() { return Err(KernelClientError::InvalidResult); }
        let transport = HttpTransport::new(transport_config)?;
        let journal = KernelIntentJournal::open(journal_path)?;
        let discovery = journal.pinned_discovery(transport.trusted_origin())?;
        if !discovery.supports_required_features(required_features) { return Err(KernelClientError::UnsupportedDiscovery); }
        Ok(Self { transport, journal, discovery,content_keys_path:None,access_recipient_path:None })
    }

    pub fn origin(&self) -> &str {
        self.transport.trusted_origin()
    }

    pub(crate) async fn read_public_workspace_snapshot(
        &self,
        identity: &KernelIdentity,
        authority: &str,
        workspace_id: &str,
        cancel: &CancellationToken,
    ) -> Result<ExactHttpResponse, KernelClientError> {
        let path = format!("/api/workspace/v1/admin/workspaces/{workspace_id}");
        let proof = crate::secure_journal_read::sign_read_proof(
            &path,
            &self.discovery,
            identity,
            authority,
        )
        .map_err(|_| KernelClientError::InvalidResult)?;
        Ok(self
            .transport
            .get_public_workspace_snapshot(workspace_id, &proof, cancel)
            .await?)
    }

    pub fn discovery(&self) -> &ParsedDiscovery {
        &self.discovery
    }

    /// Origin-bound transport for private secure read composition. Callers
    /// cannot supply an unrelated parsed discovery to this handle.
    pub(crate) fn transport(&self) -> &HttpTransport {
        &self.transport
    }

    pub fn pending(
        &self,
        local_key_id: &str,
    ) -> Result<Vec<PendingKernelIntent>, KernelClientError> {
        let page=self.pending_page(local_key_id,None,32)?;
        if page.next_after.is_some(){return Err(crate::kernel_intents::JournalError::PendingPageRequired.into());}
        Ok(page.items)
    }

    pub fn pending_page(&self,local_key_id:&str,after:Option<&str>,limit:usize)
        ->Result<crate::kernel_intents::PendingIntentPage,KernelClientError>{
        Ok(self.journal.pending_page(local_key_id,self.discovery.audience_utf16(),after,limit)?)
    }

    pub(crate) fn preparations_page(&self,identity:&KernelIdentity,authority:&str,after:Option<&str>,limit:usize)->Result<serde_json::Value,KernelClientError>{
        Ok(self.journal.preparations_page(identity,self.origin(),self.discovery.audience_utf16(),authority,after,limit)?)
    }

    /// Bounded explicit legacy locator construction, never on ordinary open.
    pub fn build_pending_index(&mut self,max_rows:usize)
        ->Result<crate::kernel_intents::PendingIndexProgress,KernelClientError>{
        Ok(self.journal.build_pending_index(max_rows)?)
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
        let ids=self.journal.catalog_begin_ids(local_key_id,&upload_id)?;
        if ids.len()!=1{return Err(KernelClientError::InvalidResult);}
        for id in ids {
            let candidate = self
                .journal
                .verified_pending(
                    &id,
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
            require_equal(&required_text(&candidate_command,"action_id")?,"catalog.upload.begin")?;
            let candidate_body = candidate_command
                .get("body")
                .ok_or(KernelClientError::InvalidResult)?;
            require_equal(&required_text(candidate_body,"upload_id")?,&upload_id)?;
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
        if !peerwork_core::structure_execution::is_structure_action(saved.proof.action_id()){return Err(KernelClientError::LegacyModeRetired);}
        match self
            .journal
            .accepted_response(&saved, self.discovery.receipt_public_key())?
        {
            Some(verified) => {
                let mut result=KernelAcceptedResult::from_verified(
                    verified,
                    &saved.proof,
                    self.catalog_begin_context(&saved, local_key_id)?,
                )?;
                self.open_selected_structure_bodies(&mut result,saved.proof.action_id(),local_key_id)?;
                Ok(Some(KernelOperationStatus::Accepted(result)))
            },
            None => Ok(Some(KernelOperationStatus::Pending)),
        }
    }

    /// Read the workspace CAS revision only from the signature-verified
    /// result of this exact saved `protocol.publish` command. The general
    /// result DTO keeps its existing public shape and instance revision
    /// semantics.
    pub fn verified_published_workspace_revision(
        &self,
        command_id: &str,
        local_key_id: &str,
    ) -> Result<Option<u64>, KernelClientError> {
        let Some(saved) = self.journal.verified_pending(
            command_id, local_key_id, self.discovery.audience_utf16(),
        )? else { return Ok(None); };
        let Some(verified) = self.journal.accepted_response(
            &saved, self.discovery.receipt_public_key(),
        )? else { return Ok(None); };
        let command = parse_wire_json_bounded(
            saved.proof.command_canonical_json().as_bytes(), 40, 180_000,
        ).map_err(|_| KernelClientError::InvalidResult)?;
        if required_text(&command, "action_id")? != "protocol.publish" {
            return Err(KernelClientError::InvalidResult);
        }
        let result = parse_wire_json_bounded(
            verified.result_canonical_json().as_bytes(), 12, 32 * 1024 * 1024,
        ).map_err(|_| KernelClientError::InvalidResult)?;
        match result.get("workspace_revision") {
            Some(WireValue::Number(value)) if value.is_finite() && *value >= 1.0
                && *value <= 9_007_199_254_740_991.0 && value.fract() == 0.0 => Ok(Some(*value as u64)),
            _ => Err(KernelClientError::InvalidResult),
        }
    }

    /// Browser producer may release its local code only after this exact
    /// saved command and result have passed the ordinary receipt verifier.
    pub(crate) fn verified_browser_approval_result(&self, command_id:&str, local_key_id:&str, request_id:&str, workspace_id:&str, expected_body:&str)->Result<Option<String>,KernelClientError> {
        let saved=self.journal.verified_pending(command_id,local_key_id,self.discovery.audience_utf16())?.ok_or(KernelClientError::IntentNotFound)?;
        let command=parse_wire_json_bounded(saved.proof.command_canonical_json().as_bytes(),40,180_000).map_err(|_|KernelClientError::InvalidResult)?;
        let body=command.get("body").ok_or(KernelClientError::InvalidResult)?;
        let expected=parse_wire_json_bounded(expected_body.as_bytes(),40,180_000).map_err(|_|KernelClientError::InvalidResult)?;
        if required_text(&command,"action_id")? != "browser.session.approve" || body != &expected || required_text(body,"request_id")? != request_id { return Err(KernelClientError::InvalidResult); }
        let Some(verified)=self.journal.accepted_response(&saved,self.discovery.receipt_public_key())? else { return Ok(None); };
        let result=parse_wire_json_bounded(verified.result_canonical_json().as_bytes(),16,262_144).map_err(|_|KernelClientError::InvalidResult)?;
        if required_text(&result,"request_id")? != request_id || required_text(&result,"workspace_id")? != workspace_id || required_text(&result,"status")? != "APPROVED" || result.get("device_session_id").is_some() || result.get("session_id").is_some() { return Err(KernelClientError::InvalidResult); }
        Ok(Some(verified.result_canonical_json().to_owned()))
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
        if !peerwork_core::structure_execution::is_structure_action(saved.proof.action_id()){return Err(KernelClientError::LegacyModeRetired);}
        let catalog_begin = self.catalog_begin_context(&saved, local_key_id)?;
        if let Some(verified) = self
            .journal
            .accepted_response(&saved, self.discovery.receipt_public_key())?
        {
            let mut result=KernelAcceptedResult::from_verified(verified, &saved.proof, catalog_begin)?;
            self.open_selected_structure_bodies(&mut result,saved.proof.action_id(),local_key_id)?;
            return Ok(result);
        }
        let response = self
            .transport
            .post_exact(saved.proof.path(), saved.body.clone(), cancel)
            .await?;
        let proof=verify_http_response_for_prepared(&response.wire,&saved.proof,self.discovery.receipt_public_key());
        // HTTP status alone never finalizes a durable operation. A refusal or
        // restricted-result acknowledgment must verify under the pinned key.
        if !(200..300).contains(&response.status)&&proof.is_err(){
            let has_receipt=parse_wire_json_bounded(&response.wire,33,1024*1024).is_ok_and(|v|v.get("receipt").is_some());
            if has_receipt{return Err(JournalError::InvalidReceipt.into());}
            return Err(KernelClientError::ServerRejected(response.status));
        }
        proof.map_err(|_|KernelClientError::Store(JournalError::InvalidReceipt))?;
        let proof=self.journal.record_verified_response(&saved,&response.wire,self.discovery.receipt_public_key())?;
        let mut public = KernelAcceptedResult::from_verified(proof, &saved.proof, catalog_begin)?;
        self.open_selected_structure_bodies(&mut public,saved.proof.action_id(),local_key_id)?;
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
    #[test]
    fn structure_result_survives_verified_journal_reopen_without_workspace_replay() {
        let state = crate::test_support::protected_test_dir();
        let path = state.path().join("structure-intents.sqlite");
        let signing = SigningKey::from_bytes(&[21;32]);
        let service = SigningKey::from_bytes(&[22;32]);
        let actor = actor_id(&signing.verifying_key().to_bytes());
        let kid = key_id(&signing.verifying_key().to_bytes());
        let receipt_key = key_id(&service.verifying_key().to_bytes());
        let discovery = parse_discovery_wire(&discovery_wire(&receipt_key,&[]),MAX_DISCOVERY_BYTES).unwrap();
        let command_id = key_id(&[23;32]);
        let command = json!({"v":1,"audience":"https://workspace.example","command_id":command_id,
            "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
            "path":"/api/workspace/v1/commands","workspace_id":key_id(&[24;32]),
            "instance_id":key_id(&[25;32]),"protocol_digest":"a".repeat(64),
            "action_id":"structure.instance.get","expected_workspace_revision":null,
            "expected_instance_revision":null,"exact_input_refs":[],
            "body":{"profile":"backend-structure-v1"},"issued_at":1,"expires_at":600001});
        let wire = serde_json::to_vec(&command).unwrap();
        let parsed = parse_wire_json_bounded(&wire,40,180_000).unwrap();
        let prepared = prepare_signed_command_wire(&parsed,&signing,&discovery,None).unwrap();
        let mut nested = json!({"leaf":"visible structural rules"});
        for _ in 0..17 {nested=json!({"nested":nested});}
        let result = json!({"profile":"backend-structure-v1","assurance":"BACKEND_CURRENT_STATE",
            "workspace_id":command["workspace_id"],"instance_id":command["instance_id"],
            "protocol_digest":command["protocol_digest"],"revision":3,"manifest":nested});
        let result_json = canonical(&result,CanonicalPath::STRUCTURED).unwrap();
        let receipt = sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":receipt_key}),
            &json!({"v":1,"audience":"https://workspace.example","actor_id":actor,
                "workspace_id":command["workspace_id"],"command_id":command_id,
                "intent_digest":prepared.proof().intent_digest(),"result_digest":sha256_hex(result_json.as_bytes()),
                "protocol_digest":command["protocol_digest"],"event_sequence":null,"instance_revision":3,"accepted_at":10}),&service).unwrap();
        let response = serde_json::to_vec(&json!({"command_id":command_id,"receipt":receipt,"result":result})).unwrap();
        let mut journal = KernelIntentJournal::open(&path).unwrap();
        journal.bind_discovery("https://workspace.example/",&discovery).unwrap();
        journal.prepare(&command_id,KernelPath::Command,prepared.jws(),prepared.http_body()).unwrap();
        let saved = journal.verified_pending(&command_id,&kid,discovery.audience_utf16()).unwrap().unwrap();
        journal.record_verified_response(&saved,&response,&receipt_key).unwrap();drop(journal);
        let journal = KernelIntentJournal::open(&path).unwrap();
        let saved = journal.verified_pending(&command_id,&kid,discovery.audience_utf16()).unwrap().unwrap();
        let proof = journal.accepted_response(&saved,&receipt_key).unwrap().unwrap();
        let accepted = KernelAcceptedResult::from_verified(proof,&saved.proof,None).unwrap();
        assert_eq!(accepted.structure_result_json.as_deref(),Some(result_json.as_str()));
        assert_eq!(accepted.revision,Some(3));assert!(accepted.catalog.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn restricted_commit_ack_can_upgrade_to_full_outcome_but_a_refusal_never_can(){
        let dir=crate::test_support::protected_test_dir();let signing=SigningKey::from_bytes(&[21;32]);let service=SigningKey::from_bytes(&[22;32]);let kid=key_id(&signing.verifying_key().to_bytes());let actor=actor_id(&signing.verifying_key().to_bytes());let receipt_key=key_id(&service.verifying_key().to_bytes());let discovery=parse_discovery_wire(&discovery_wire(&receipt_key,&[]),MAX_DISCOVERY_BYTES).unwrap();let id=key_id(&[23;32]);
        let command=json!({"v":1,"audience":"https://workspace.example","command_id":id,"actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST","path":"/api/workspace/v1/commands","workspace_id":key_id(&[24;32]),"instance_id":key_id(&[25;32]),"protocol_digest":"a".repeat(64),"action_id":"structure.action","expected_workspace_revision":null,"expected_instance_revision":1,"exact_input_refs":[],"body":{"profile":"backend-structure-v1","action_id":"post","structure":{}},"issued_at":1,"expires_at":600001});
        let prepared=prepare_signed_command_wire(&parse_wire_json_bounded(&serde_json::to_vec(&command).unwrap(),40,180000).unwrap(),&signing,&discovery,None).unwrap();
        let base=json!({"profile":"backend-structure-v1","assurance":"BACKEND_CURRENT_STATE","workspace_id":command["workspace_id"],"instance_id":command["instance_id"],"protocol_digest":command["protocol_digest"],"author_intent":prepared.jws()});
        let mut marker=base.clone();marker["status"]=json!("COMMITTED_RESULT_UNAVAILABLE");marker["effect_certainty"]=json!("COMMITTED");marker["error"]=json!({"phase":"RESULT_ACCESS","code":"OUTCOME_RECORDED_ACCESS_DENIED","http_status":403,"retryable":false,"recovery":"REQUEST_ACCESS_AND_READ_ORIGINAL_OUTCOME"});
        let mut full=base.clone();full["status"]=json!("APPLIED");full["revision"]=json!(2);
        let mut refused=base;refused["status"]=json!("REJECTED_NO_EFFECT");refused["effect_certainty"]=json!("NOT_APPLIED");refused["error"]=json!({"phase":"AUTHORIZATION","code":"FORBIDDEN","http_status":403,"retryable":false,"recovery":"NEW_INTENT_REQUIRED"});
        let reply=|result:&serde_json::Value|{
            let payload=json!({"v":1,"audience":"https://workspace.example","actor_id":actor,"workspace_id":command["workspace_id"],"command_id":id,"intent_digest":prepared.proof().intent_digest(),"result_digest":sha256_hex(canonical(result,CanonicalPath::STRUCTURED).unwrap().as_bytes()),"protocol_digest":command["protocol_digest"],"event_sequence":null,"instance_revision":result.get("revision").unwrap_or(&serde_json::Value::Null),"accepted_at":10});
            let receipt=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":receipt_key}),&payload,&service).unwrap();serde_json::to_vec(&json!({"command_id":id,"receipt":receipt,"result":result})).unwrap()
        };
        let mut journal=KernelIntentJournal::open(&dir.path().join("outcomes.sqlite")).unwrap();journal.bind_discovery("https://workspace.example/",&discovery).unwrap();journal.prepare(&id,KernelPath::Command,prepared.jws(),prepared.http_body()).unwrap();let saved=journal.verified_pending(&id,&kid,discovery.audience_utf16()).unwrap().unwrap();
        journal.record_verified_response(&saved,&reply(&marker),&receipt_key).unwrap();assert!(journal.pending_page(&kid,discovery.audience_utf16(),None,32).unwrap().items.is_empty());
        let proof=journal.record_verified_response(&saved,&reply(&full),&receipt_key).unwrap();assert_eq!(KernelAcceptedResult::from_verified(proof,&saved.proof,None).unwrap().outcome_state(),"ACCEPTED");
        let proof=journal.record_verified_response(&saved,&reply(&marker),&receipt_key).unwrap();assert_eq!(KernelAcceptedResult::from_verified(proof,&saved.proof,None).unwrap().outcome_state(),"ACCEPTED","a restricted concurrent reply must not replace the full receipt");
        assert!(matches!(journal.record_verified_response(&saved,&reply(&refused),&receipt_key),Err(JournalError::InvalidReceipt)),"a signed committed outcome and signed refusal cannot be reconciled as the same fact");
    }

    #[cfg(unix)]
    #[test]
    fn cached_open_uses_only_existing_origin_pin_and_refuses_missing_or_wrong_source() {
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("kernel.sqlite");
        let config=||TransportConfig::new("https://example.invalid");
        assert!(KernelClient::open_cached(config(),&path,&[],&CancellationToken::new()).is_err());
        assert!(!path.exists());
        let parsed=parse_discovery_wire(&discovery_wire(&key_id(&[7;32]),&["base"]),MAX_DISCOVERY_BYTES).unwrap();
        let mut journal=KernelIntentJournal::open(&path).unwrap();journal.bind_discovery("https://example.invalid/",&parsed).unwrap();drop(journal);
        let client=KernelClient::open_cached(config(),&path,&["base".encode_utf16().collect()],&CancellationToken::new()).unwrap();
        assert_eq!(client.discovery().receipt_public_key(),parsed.receipt_public_key());drop(client);
        assert!(KernelClient::open_cached(TransportConfig::new("https://another.invalid"),&path,&[],&CancellationToken::new()).is_err());
        assert!(KernelClient::open_cached(config(),&path,&["missing".encode_utf16().collect()],&CancellationToken::new()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn catalog_chunk_selects_one_verified_begin_without_scanning_retained_commands(){
        let state=crate::test_support::protected_test_dir();let path=state.path().join("kernel.sqlite");
        let signing=SigningKey::from_bytes(&[21;32]);let service=SigningKey::from_bytes(&[22;32]);
        let actor=actor_id(&signing.verifying_key().to_bytes());let kid=key_id(&signing.verifying_key().to_bytes());
        let receipt_key=key_id(&service.verifying_key().to_bytes());
        let discovery=parse_discovery_wire(&discovery_wire(&receipt_key,&[]),MAX_DISCOVERY_BYTES).unwrap();
        let upload=key_id(&[24;32]);let digest="a".repeat(64);
        let prepare=|id:&str,action:&str,body:serde_json::Value,chunk:Option<&[u8]>|{
            let c=json!({"v":1,"audience":"https://workspace.example","command_id":id,"actor_id":actor,
                "authority":sha256_hex(actor.as_bytes()),"method":"POST","path":if chunk.is_some(){"/api/workspace/v1/catalog/upload"}else{"/api/workspace/v1/commands"},
                "workspace_id":null,"instance_id":null,"protocol_digest":null,"action_id":action,
                "expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"body":body,"issued_at":1,"expires_at":600001});
            prepare_signed_command_wire(&parse_wire_json_bounded(&serde_json::to_vec(&c).unwrap(),40,180_000).unwrap(),&signing,&discovery,chunk).unwrap()
        };
        let begin=prepare(&key_id(&[25;32]),"catalog.upload.begin",json!({"upload_id":upload,"bundle_digest":digest,"total_bytes":1,"chunk_count":1}),None);
        let accept=|j:&mut KernelIntentJournal,c:&peerwork_core::prepared_command::SignedPreparedCommand|{
            j.prepare(c.proof().command_id(),KernelPath::Command,c.jws(),c.http_body()).unwrap();
            let result=json!({"upload_id":upload,"state":"STAGING","expires_at":600001});
            let receipt=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":receipt_key}),
                &json!({"v":1,"audience":"https://workspace.example","actor_id":actor,"workspace_id":null,
                    "command_id":c.proof().command_id(),"intent_digest":c.proof().intent_digest(),
                    "result_digest":sha256_hex(canonical(&result,CanonicalPath::KERNEL).unwrap().as_bytes()),
                    "protocol_digest":null,"event_sequence":null,"instance_revision":null,"accepted_at":10}),&service).unwrap();
            let saved=j.verified_pending(c.proof().command_id(),&kid,discovery.audience_utf16()).unwrap().unwrap();
            j.record_verified_response(&saved,&serde_json::to_vec(&json!({"command_id":c.proof().command_id(),"receipt":receipt,"result":result})).unwrap(),&receipt_key).unwrap();
        };
        let mut journal=KernelIntentJournal::open(&path).unwrap();journal.bind_discovery("https://example.invalid/",&discovery).unwrap();
        accept(&mut journal,&begin);
        let mut db=rusqlite::Connection::open(&path).unwrap();let tx=db.transaction().unwrap();
        for n in 0..10000 {
            let id=format!("X{n:042}");
            tx.execute("INSERT INTO kernel_intents VALUES(?1,'/api/workspace/v1/commands','malformed','bad',x'01','PENDING',0)",[&id]).unwrap();
            tx.execute("INSERT INTO accepted_responses VALUES(?1,x'01')",[&id]).unwrap();
        }
        tx.commit().unwrap();
        let chunk=prepare(&key_id(&[26;32]),"catalog.upload.chunk",json!({"upload_id":upload,"bundle_digest":digest,
            "byte_length":1,"chunk_digest":sha256_hex(b"x"),"index":0,"offset":0}),Some(b"x"));
        journal.prepare(chunk.proof().command_id(),KernelPath::CatalogUpload,chunk.jws(),chunk.http_body()).unwrap();
        let saved=journal.verified_pending(chunk.proof().command_id(),&kid,discovery.audience_utf16()).unwrap().unwrap();
        let mut client=KernelClient{transport:HttpTransport::new(TransportConfig::new("https://example.invalid")).unwrap(),journal,discovery:discovery.clone(),content_keys_path:None,access_recipient_path:None};
        assert_eq!(client.catalog_begin_context(&saved,&kid).unwrap(),Some((1,1)));
        db.execute("UPDATE accepted_responses SET response_wire=x'01' WHERE command_id=?1",[begin.proof().command_id()]).unwrap();
        assert!(matches!(client.catalog_begin_context(&saved,&kid),Err(KernelClientError::Store(JournalError::IncompatibleStore))));
        db.execute("DELETE FROM accepted_responses WHERE command_id=?1",[begin.proof().command_id()]).unwrap();accept(&mut client.journal,&begin);
        let duplicate=prepare(&key_id(&[27;32]),"catalog.upload.begin",json!({"upload_id":upload,"bundle_digest":digest,"total_bytes":1,"chunk_count":1}),None);
        accept(&mut client.journal,&duplicate);
        assert!(matches!(client.catalog_begin_context(&saved,&kid),Err(KernelClientError::InvalidResult)),"ambiguous signed sources must not be guessed");
        let plan:Vec<String>=db.prepare("EXPLAIN QUERY PLAN SELECT command_id FROM kernel_catalog_begins WHERE local_key_id=?1 AND upload_id=?2 ORDER BY command_id LIMIT 2").unwrap()
            .query_map(rusqlite::params![kid,upload],|r|r.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
        assert!(plan.iter().any(|s|s.contains("kernel_catalog_begin_lookup")&&s.contains("local_key_id=?")&&s.contains("upload_id=?")),"{plan:?}");
        assert!(!plan.iter().any(|s|s.contains("SCAN ")||s.contains("TEMP B-TREE")),"{plan:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a frozen PEERWORK_STRUCTURE_REFERENCE_MANIFEST and candidate service"]
    async fn structure_profile_real_service_roundtrip() {
        use std::io::{BufRead,BufReader};
        use std::process::{Command,Stdio};
        use std::time::{SystemTime,UNIX_EPOCH};
        struct Server(std::process::Child);
        impl Drop for Server {fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
        let state=crate::test_support::protected_test_dir();
        let mut server=Server(Command::new(std::env::var("PEERWORK_TEST_NODE").unwrap())
            .arg(concat!(env!("CARGO_MANIFEST_DIR"),"/../../tests/structure-profile-service.mjs"))
            .env("PEERWORK_TEST_STATE",state.path()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
        let mut line=String::new();BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let origin=serde_json::from_str::<serde_json::Value>(&line).expect("candidate fixture starts")["origin"].as_str().unwrap().to_owned();
        let mut config=TransportConfig::new(&origin);config.allow_loopback_http=true;
        let identity=KernelIdentity::create(&state.path().join("identity")).unwrap();
        let mut client=KernelClient::open(config,&state.path().join("intents.sqlite"),&[],&CancellationToken::new()).await.unwrap();
        let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let command=|id:u8,action:&str,body:serde_json::Value,workspace:Option<&str>,instance:Option<&str>,protocol:Option<&str>,revision:Option<u64>|serde_json::to_vec(&json!({
            "v":1,"audience":"structure-candidate","command_id":key_id(&[id;32]),"actor_id":identity.actor_id(),
            "authority":sha256_hex(identity.actor_id().as_bytes()),"method":"POST","path":"/api/workspace/v1/commands",
            "workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"action_id":action,
            "expected_workspace_revision":null,"expected_instance_revision":revision,"exact_input_refs":[],"body":body,
            "issued_at":now,"expires_at":now+600_000})).unwrap();
        let cancel=CancellationToken::new();
        let created=client.prepare_command(&identity,&command(81,"structure.workspace.create",json!({"profile":"backend-structure-v1","name":"Native private candidate"}),None,None,None,None),None).unwrap();
        let workspace=client.submit_saved(&created.command_id,identity.key_id(),&cancel).await.unwrap().workspace_id.unwrap();
        let selected=client.prepare_command(&identity,&command(87,"structure.workspace.get",json!({"profile":"backend-structure-v1"}),Some(&workspace),None,None,None),None).unwrap();
        let selected=client.submit_saved(&selected.command_id,identity.key_id(),&cancel).await.unwrap();
        let selected:serde_json::Value=serde_json::from_str(selected.structure_result_json.as_deref().unwrap()).unwrap();
        assert_eq!(selected["activation"]["actor_id"],identity.actor_id());assert_eq!(selected["activation"]["intent_digest"],created.intent_digest);assert_eq!(selected["visibility"],"PRIVATE");
        let manifest=json!({"name":"native-structural","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],
            "initial_state":{"count":0},"record_schemas":{"change":{"type":"object","fields":{"count":"integer"},"required":["count"],"max_bytes":256}},
            "actions":[{"id":"advance","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},
                "variants":[{"when":[{"op":"eq","left":{"from":"state","path":["count"]},"right":{"from":"literal","value":0}}],
                    "effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}},
                    {"op":"append","schema":"change","value":{"from":"literal","value":{"count":1}},"relations":[]}]}]}]});
        let adopted=client.prepare_command(&identity,&command(82,"structure.adopt",json!({"profile":"backend-structure-v1","manifest":manifest,"bootstrap_grant":{"actions":["advance"]}}),Some(&workspace),None,None,None),None).unwrap();
        let adopted=client.submit_saved(&adopted.command_id,identity.key_id(),&cancel).await.unwrap();
        let instance=adopted.instance_id.unwrap();let protocol=adopted.protocol_digest.unwrap();
        let action=client.prepare_command(&identity,&command(83,"structure.action",json!({"profile":"backend-structure-v1","action_id":"advance","structure":{}}),Some(&workspace),Some(&instance),Some(&protocol),Some(1)),None).unwrap();
        assert!(matches!(client.submit_saved(&action.command_id,identity.key_id(),&cancel).await,Err(KernelClientError::ServerRejected(503))));
        let mut renewed:serde_json::Value=serde_json::from_slice(&command(83,"structure.action",json!({"profile":"backend-structure-v1","action_id":"advance","structure":{}}),Some(&workspace),Some(&instance),Some(&protocol),Some(1))).unwrap();
        renewed["issued_at"]=json!(now+1);renewed["expires_at"]=json!(now+600_001);
        let renewed=client.renew_structure_authorization(&identity,&serde_json::to_vec(&renewed).unwrap()).unwrap();
        assert_eq!(renewed.command_id,action.command_id);assert_ne!(renewed.intent_digest,action.intent_digest);
        let applied=client.submit_saved(&action.command_id,identity.key_id(),&cancel).await.unwrap();
        let applied_json:serde_json::Value=serde_json::from_str(applied.structure_result_json.as_deref().unwrap()).unwrap();
        assert_eq!(applied_json["state"],json!({"count":1}));assert_eq!(applied_json["status"],"APPLIED");
        assert_eq!(sha256_hex(applied_json["author_intent"].as_str().unwrap().as_bytes()),action.intent_digest,"the result preserves the original committed authorization");
        let read=client.prepare_command(&identity,&command(84,"structure.instance.get",json!({"profile":"backend-structure-v1"}),Some(&workspace),Some(&instance),Some(&protocol),None),None).unwrap();
        let read=client.submit_saved(&read.command_id,identity.key_id(),&cancel).await.unwrap();
        let current:serde_json::Value=serde_json::from_str(read.structure_result_json.as_deref().unwrap()).unwrap();assert_eq!(current["state"],json!({"count":1}));
        let rejected=client.prepare_command(&identity,&command(85,"structure.action",json!({"profile":"backend-structure-v1","action_id":"advance","structure":{}}),Some(&workspace),Some(&instance),Some(&protocol),Some(2)),None).unwrap();
        let denied=client.submit_saved(&rejected.command_id,identity.key_id(),&cancel).await.unwrap();
        let denied:serde_json::Value=serde_json::from_str(denied.structure_result_json.as_deref().unwrap()).unwrap();assert_eq!(denied["status"],"REJECTED_NO_EFFECT");
        let lookup=client.prepare_command(&identity,&command(86,"structure.operation.get",json!({"profile":"backend-structure-v1","command_id":rejected.command_id,"intent_digest":rejected.intent_digest}),Some(&workspace),None,None,None),None).unwrap();
        let lookup=client.submit_saved(&lookup.command_id,identity.key_id(),&cancel).await.unwrap();
        let lookup:serde_json::Value=serde_json::from_str(lookup.structure_result_json.as_deref().unwrap()).unwrap();assert_eq!(lookup["status"],"REJECTED_NO_EFFECT");
        let counts:serde_json::Value=serde_json::from_slice(&reqwest::get(format!("{origin}__test/counts")).await.unwrap().bytes().await.unwrap()).unwrap();
        assert_eq!(counts,json!({"records":1,"dropped":1,"journal_reads":0}));
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
            "protocol_digest":null,"action_id":"structure.workspace.create",
            "expected_workspace_revision":null,"expected_instance_revision":null,
            "exact_input_refs":[],"body":{"profile":"backend-structure-v1","name":"Network recovery fixture"},"issued_at":1,"expires_at":600001
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
        let result = json!({"profile":"backend-structure-v1","assurance":"BACKEND_CURRENT_STATE","workspace_id":key_id(&[24;32]),"visibility":"PRIVATE"});
        let result_digest = sha256_hex(
            canonical(&result, CanonicalPath::KERNEL)
                .unwrap()
                .as_bytes(),
        );
        let receipt_header =
            json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid});
        let receipt_payload = json!({
            "v":1,"audience":"https://workspace.example","actor_id":actor,"workspace_id":result["workspace_id"],
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
        let mut mismatched_result=result.clone();mismatched_result["profile"]=json!("retired-profile");
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
            Err(KernelClientError::Store(JournalError::InvalidReceipt))
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
        assert!(reopened.pending(&kid).unwrap().is_empty(),"pending is a locator, not an implicit audit of completed history");
        assert!(matches!(
            reopened.status(&command_id,&kid),
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

#[path = "structure_content_head.rs"]
mod structure_content_head;
pub use structure_content_head::StructureContentKeyRotation;

#[path = "structure_key_fanout.rs"]
mod structure_key_fanout;

#[path = "structure_retained_key_client.rs"]
mod structure_retained_key_client;
pub use structure_retained_key_client::StructureKeyHistoryReadiness;

#[path = "structure_publication_snapshot.rs"]
mod structure_publication_snapshot;
pub use structure_publication_snapshot::{PublicationSnapshotSelection,PublicationSnapshotBody};

#[cfg(test)]mod public_action_input_tests{
 use super::*;use serde_json::json;
 fn publication(text:&str)->serde_json::Value{let encoded=peerwork_core::crypto::base64url(text.as_bytes());json!({"policy_revision":1,"disclosure":"PUBLISH_ACTION_AND_SELECTED_RECORDS","entries":[{"record_index":0,"title":"Public note","body":{"format":"PUBLIC_UTF8_BASE64","chunks":encoded.as_bytes().chunks(8192).map(|v|std::str::from_utf8(v).unwrap()).collect::<Vec<_>>()}}]})}
 #[test]fn public_action_preflight_is_explicit_bounded_and_has_unique_output_indices(){let good=publication(&"x".repeat(65536));assert!(validate_public_action(&good).is_ok());assert!(validate_public_action(&publication(&"x".repeat(65537))).is_err());let mut duplicate=good.clone();duplicate["entries"].as_array_mut().unwrap().push(good["entries"][0].clone());assert!(validate_public_action(&duplicate).is_err());let mut implicit=publication("text");implicit["disclosure"]=json!("IMPLICIT");assert!(validate_public_action(&implicit).is_err());}
}
