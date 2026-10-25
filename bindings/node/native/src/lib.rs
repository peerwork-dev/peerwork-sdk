use napi::{
    bindgen_prelude::{AsyncTask, Buffer, ClassInstance},
    Env, Result, Task,
};
use napi_derive::napi;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::secure_action_access::{PublicActionInput, SecurePrivateActionAccess, SecurePublicActionAccess};
use peerwork_runtime::secure_public_admission::{PublicOfferInput, SecurePublicAdmission};
use peerwork_runtime::secure_public_decision::{PublicDecisionConfig, SecurePublicDecision};
use peerwork_runtime::secure_identity_directory::{IdentityDirectoryConfig, SecureIdentityDirectory};
use peerwork_runtime::secure_public_install::{
    PublicPackageInstallInput, SecurePublicPackageInstall,
};
use peerwork_runtime::secure_private_install::{PrivateDirectInstallBeginInput, PrivatePackageInstallBeginInput, PrivatePackageStageInput};
use peerwork_runtime::secure_read_access::{SecureReadAccess, SecureReadConfig};
use peerwork_runtime::secure_read_profile::{SecureReadProfile, SecureReadProfileConfig};
use peerwork_runtime::secure_private_read_access::SecurePrivateReadAccess;
use peerwork_runtime::secure_owner_create::{
    import_legacy_owner_identity, SecureOwnerCreateConfig, SecureOwnerCreateInput,
    SecureOwnerWorkspaceCreate,
};
use peerwork_runtime::secure_owner_attach::{HistoricalOwnerAttachInput, SecureHistoricalOwnerAttach};
use peerwork_runtime::secure_owner_format_transition::OwnerFormatTransitionInput;
use peerwork_runtime::secure_owner_coordination::OwnerCoordinationEnableInput;
use peerwork_runtime::public_catalog::{PublicCatalog, PublicCatalogConfig};
use peerwork_runtime::secure_recipient_enrollment::{
    RecipientEnrollmentConfig, SecureRecipientEnrollment,
};
use peerwork_runtime::KernelCancellationToken;
use std::path::Path;

fn multipart_stage_request(wire: Option<&str>) -> Option<(HistoricalOwnerAttachInput, String)> {
    let value: serde_json::Value = serde_json::from_str(wire?).ok()?;
    let object = value.as_object()?;
    if object.len() != 2 { return None; }
    let input = serde_json::from_value(object.get("attachment_input")?.clone()).ok()?;
    let material = object.get("material_json")?.as_str()?.to_owned();
    if material.is_empty() { return None; }
    Some((input, material))
}

fn direct_install_request(wire: Option<&str>, selection_key: &str) -> Option<(HistoricalOwnerAttachInput, String, Option<String>, String, String)> {
    let value: serde_json::Value = serde_json::from_str(wire?).ok()?;
    let object = value.as_object()?;
    if object.len() != 5 { return None; }
    let input = serde_json::from_value(object.get("attachment_input")?.clone()).ok()?;
    let selected = object.get(selection_key)?.as_str()?.to_owned();
    let digest = match object.get("expected_ts_state_digest")? {
        serde_json::Value::Null => None,
        value => Some(value.as_str()?.to_owned()),
    };
    let options = object.get("options_json")?.as_str()?.to_owned();
    let material = object.get("material_json")?.as_str()?.to_owned();
    if selected.is_empty() || options.is_empty() || material.is_empty()
        || digest.as_deref().is_some_and(str::is_empty) { return None; }
    Some((input, selected, digest, options, material))
}

#[napi]
pub fn version() -> &'static str {
    peerwork_core::version()
}

#[napi]
pub fn capabilities_json() -> Result<String> {
    serde_json::to_string(&peerwork_core::capability_manifest())
        .map_err(|_| napi::Error::from_reason("manifest serialization failed"))
}

pub struct IdentityTask {
    path: String,
    create: bool,
    seed_file: Option<String>,
    pem_file: Option<String>,
}

impl Task for IdentityTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let identity = if let Some(pem_file) = self.pem_file.as_deref() {
            KernelIdentity::import_pkcs8_pem_file(Path::new(&self.path), Path::new(pem_file))
        } else if let Some(seed_file) = self.seed_file.as_deref() {
            KernelIdentity::import_seed_file(Path::new(&self.path), Path::new(seed_file))
        } else if self.create {
            KernelIdentity::create(Path::new(&self.path))
        } else {
            KernelIdentity::open(Path::new(&self.path))
        }
        .map_err(|error| {
            if !self.create && self.pem_file.is_none() && self.seed_file.is_none() {
                napi::Error::from_reason(format!(
                    "{}: {}",
                    error.code(),
                    error.actionable_message()
                ))
            } else {
                napi::Error::from_reason(error.to_string())
            }
        })?;
        Ok(format!(
            "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
            identity.actor_id(),
            identity.key_id()
        ))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct OwnerIdentityImportTask { config_file: String, pem_file: String }

impl Task for OwnerIdentityImportTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Err(napi::Error::from_reason("LEGACY_MODE_RETIRED: select an explicit identity seed or PKCS8 PEM file"))
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}

#[napi]
pub fn identity_import_owner_pem_json(config_file: String, pem_file: String) -> AsyncTask<OwnerIdentityImportTask> {
    AsyncTask::new(OwnerIdentityImportTask { config_file, pem_file })
}

pub struct ConfigTask { path: Option<String> }
impl Task for ConfigTask {
    type Output = String; type JsValue = String;
    fn compute(&mut self) -> Result<String> { Ok(peerwork_runtime::protected_config::load_config_json(self.path.as_deref().map(Path::new))) }
    fn resolve(&mut self, _env: Env, output: String) -> Result<String> { Ok(output) }
}
#[napi]
pub fn load_config_json(path: Option<String>) -> AsyncTask<ConfigTask> { AsyncTask::new(ConfigTask { path }) }

pub struct OwnerCheckpointTask {request:String}
impl Task for OwnerCheckpointTask {
    type Output=String;type JsValue=String;
    fn compute(&mut self)->Result<String>{Ok(peerwork_runtime::owner_checkpoint::prepare_owner_checkpoint_json(&self.request))}
    fn resolve(&mut self,_env:Env,output:String)->Result<String>{Ok(output)}
}
#[napi]
pub fn prepare_owner_checkpoint_json(request:String)->AsyncTask<OwnerCheckpointTask>{AsyncTask::new(OwnerCheckpointTask{request})}

pub struct OwnerCacheReviewTask {request:String}
impl Task for OwnerCacheReviewTask {
    type Output=String;type JsValue=String;
    fn compute(&mut self)->Result<String>{Ok(peerwork_runtime::owner_cache_review::inspect_owner_cache_json(&self.request))}
    fn resolve(&mut self,_env:Env,output:String)->Result<String>{Ok(output)}
}
#[napi]
pub fn inspect_owner_cache_json(request:String)->AsyncTask<OwnerCacheReviewTask>{AsyncTask::new(OwnerCacheReviewTask{request})}

pub struct CachedCheckpointTask{request:String,planning:bool}
impl Task for CachedCheckpointTask{
 type Output=String;type JsValue=String;
 fn compute(&mut self)->Result<String>{Ok(if self.planning{peerwork_runtime::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&self.request)}else{peerwork_runtime::owner_cache_checkpoint::prepare_owner_checkpoint_from_cache_json(&self.request)})}
 fn resolve(&mut self,_env:Env,output:String)->Result<String>{Ok(output)}
}
#[napi]
pub fn plan_owner_checkpoint_from_cache_json(request:String)->AsyncTask<CachedCheckpointTask>{AsyncTask::new(CachedCheckpointTask{request,planning:true})}
#[napi]
pub fn prepare_owner_checkpoint_from_cache_json(request:String)->AsyncTask<CachedCheckpointTask>{AsyncTask::new(CachedCheckpointTask{request,planning:false})}

#[napi]
pub fn identity_create_json(path: String) -> AsyncTask<IdentityTask> {
    AsyncTask::new(IdentityTask {
        path,
        create: true,
        seed_file: None,
        pem_file: None,
    })
}

#[napi]
pub fn identity_open_json(path: String) -> AsyncTask<IdentityTask> {
    AsyncTask::new(IdentityTask {
        path,
        create: false,
        seed_file: None,
        pem_file: None,
    })
}

#[napi]
pub fn identity_import_seed_json(path: String, seed_file: String) -> AsyncTask<IdentityTask> {
    AsyncTask::new(IdentityTask {
        path,
        create: false,
        seed_file: Some(seed_file),
        pem_file: None,
    })
}

#[napi]
pub fn identity_import_pkcs8_pem_json(path: String, pem_file: String) -> AsyncTask<IdentityTask> {
    AsyncTask::new(IdentityTask {
        path,
        create: false,
        seed_file: None,
        pem_file: Some(pem_file),
    })
}

fn accepted_json(result: KernelAcceptedResult) -> serde_json::Value {
    let browser_reference=result.browser_approval_reference();
    let mut value = serde_json::json!({
        "command_id": result.command_id,
        "workspace_id": result.workspace_id,
        "protocol_digest": result.protocol_digest,
        "instance_id": result.instance_id,
        "event_sequence": result.event_sequence,
        "revision": result.revision,
        "produced_record_ids": result.produced_record_ids,
        "catalog": result.catalog,
    });
    if let Some(reference)=browser_reference{value.as_object_mut().unwrap().insert("browser_approval_reference".into(),serde_json::json!(reference));}
    if let Some(history)=result.key_history {value.as_object_mut().unwrap().insert("key_history".into(),serde_json::json!(history));}
    if let Some(contents)=result.opened_contents {value.as_object_mut().unwrap().insert("opened_contents".into(),serde_json::json!(contents));}
    if let Some(structure) = result.structure_result_json {
        value.as_object_mut().unwrap().insert("structure_result_json".into(), serde_json::Value::String(structure));
    }
    value
}

#[napi]
pub struct KernelCancelHandle {
    token: KernelCancellationToken,
}

#[napi]
impl KernelCancelHandle {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            token: KernelCancellationToken::new(),
        }
    }

    #[napi]
    pub fn cancel(&self) {
        self.token.cancel();
    }
}

pub struct KernelTask {
    operation: String,
    origin: String,
    journal_path: String,
    identity_path: String,
    required_features: Vec<String>,
    allow_loopback_http: bool,
    authority: Option<String>,
    command_json: Option<String>,
    command_id: Option<String>,
    upload_chunk: Option<Vec<u8>>,
    migration_source: Option<String>,
    migration_backup: Option<String>,
    trusted_signer_key_ids: Option<Vec<String>>,
    transport_json: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for KernelTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        if !peerwork_runtime::runtime_contract::supports_kernel_operation(&self.operation){return Ok(peerwork_runtime::runtime_contract::retired_json());}
        let transport = self.transport_json.as_deref().map(serde_json::from_str::<peerwork_runtime::transport::TransportOptions>).transpose().map_err(|_| napi::Error::from_reason("invalid transport options"))?.unwrap_or_default();
        transport.validate().map_err(|_| napi::Error::from_reason("invalid transport options"))?;
        let access = KernelAccess::new(
            &self.origin,
            &self.journal_path,
            &self.identity_path,
            &self.required_features,
            self.allow_loopback_http,
        )
        .with_authority(self.authority.clone()).with_transport_options(transport);
        let result = (|| -> std::result::Result<serde_json::Value, peerwork_runtime::kernel_access::KernelPublicError> {
        let value = match self.operation.as_str() {
            "open" => {
                let info = access.open_with_cancel(&self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?;
                serde_json::json!({"actor_id": info.actor_id, "key_id": info.key_id, "origin": info.origin})
            }
            "prepare" => {
                let command = self.command_json.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command is required"))?;
                let pending = access.prepare_with_cancel(command.as_bytes(), self.upload_chunk.as_deref(), &self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?;
                serde_json::json!({"command_id": pending.command_id, "intent_digest": pending.intent_digest, "created_at_ms": pending.created_at_ms})
            }
            "pending" => serde_json::json!(access.pending_with_cancel(&self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?.into_iter().map(|row| {
                serde_json::json!({"command_id": row.command_id, "intent_digest": row.intent_digest, "created_at_ms": row.created_at_ms})
            }).collect::<Vec<_>>()),
            "pending_page" => access.pending_page_json_with_cancel(self.command_json.as_deref().unwrap_or("{}"),&self.cancel)?,
            "request_access" => access.request_access_json(self.command_json.as_deref().unwrap_or("{}"),&self.cancel)?,
            "accept_content_keys" => access.accept_content_keys_json(self.command_json.as_deref().unwrap_or("{}"),&self.cancel)?,
            "ensure_local_content_key" => access.ensure_local_content_key_json(self.command_json.as_deref().unwrap_or("{}"),&self.cancel)?,
            "build_pending_index" => serde_json::json!(access.build_pending_index_with_cancel(&self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?),
            "status" => {
                let id = self.command_id.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                match access.status_with_cancel(id, &self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)? {
                    None => serde_json::json!({"state": "NOT_FOUND"}),
                    Some(KernelOperationStatus::Pending) => serde_json::json!({"state": "PENDING"}),
                    Some(KernelOperationStatus::Accepted(accepted)) => serde_json::json!({"state":accepted.outcome_state(),"result":accepted_json(accepted)}),
                }
            }
            "execute_structure_intent" | "publish_selected_record" | "authorize_access" | "rotate_content_key" | "coordinate_content_keys" => {
                let intent = self.command_json.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("business intent is required"))?;
                match (if self.operation=="coordinate_content_keys"{access.coordinate_content_keys_json(intent,&self.cancel)}else if self.operation=="rotate_content_key"{access.rotate_content_key_json(intent,&self.cancel)}else{(if self.operation=="publish_selected_record"{access.publish_selected_record_with_cancel(intent.as_bytes(),&self.cancel)}else if self.operation=="authorize_access"{access.authorize_access_with_cancel(intent.as_bytes(),&self.cancel)}else{access.execute_structure_intent_with_cancel(intent.as_bytes(),&self.cancel)}).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)})? {
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Accepted(result) => serde_json::json!({"state":result.outcome_state(),"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Completed{command_id,result}=>serde_json::json!({"state":"COMPLETED","command_id":command_id,"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Pending {command_id,code,phase,retryable,recovery} =>
                        serde_json::json!({"state":"PENDING","command_id":command_id,"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"effect_certainty":if phase=="KEY_DELIVERY"{"COMMITTED"}else if phase=="PREPARATION"{"NOT_SUBMITTED"}else{"UNKNOWN"}}),
                }
            }
            "resume_structure_intent" => {
                let id=self.command_id.as_deref().ok_or_else(||peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                match access.resume_structure_intent_with_cancel(id,&self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)? {
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Accepted(result)=>serde_json::json!({"state":result.outcome_state(),"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Completed{command_id,result}=>serde_json::json!({"state":"COMPLETED","command_id":command_id,"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Pending{command_id,code,phase,retryable,recovery}=>
                        serde_json::json!({"state":"PENDING","command_id":command_id,"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"effect_certainty":if phase=="KEY_DELIVERY"{"COMMITTED"}else if phase=="PREPARATION"{"NOT_SUBMITTED"}else{"UNKNOWN"}}),
                }
            }
            "submit_saved" => {
                let id = self.command_id.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                accepted_json(access.submit_saved_with_cancel(id, &self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?)
            }
            "migrate_ts_store" => {
                let source = self.migration_source.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("legacy source path is required"))?;
                let backup = self.migration_backup.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("backup path is required"))?;
                let signers = self.trusted_signer_key_ids.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("trusted signer IDs are required"))?;
                let report = access.migrate_ts_store(Path::new(source), Path::new(backup), signers, &self.cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?;
                serde_json::json!({"pending_count": report.pending_count, "accepted_count": report.accepted_count})
            }
            _ => return Err(peerwork_runtime::kernel_access::KernelPublicError::from("unsupported kernel operation")),
        };
        Ok(value)
        })();
        Ok(match result { Ok(value) => value, Err(error) => error.envelope() }.to_string())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn kernel_json(
    operation: String,
    origin: String,
    journal_path: String,
    identity_path: String,
    required_features: Vec<String>,
    allow_loopback_http: bool,
    authority: Option<String>,
    command_json: Option<String>,
    command_id: Option<String>,
    upload_chunk: Option<Buffer>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
    migration_source: Option<String>,
    migration_backup: Option<String>,
    trusted_signer_key_ids: Option<Vec<String>>,
    transport_json: Option<String>,
) -> AsyncTask<KernelTask> {
    AsyncTask::new(KernelTask {
        operation,
        origin,
        journal_path,
        identity_path,
        required_features,
        allow_loopback_http,
        authority,
        command_json,
        command_id,
        upload_chunk: upload_chunk.map(|chunk| chunk.to_vec()),
        migration_source,
        migration_backup,
        trusted_signer_key_ids,
        transport_json,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

pub struct SecureReadTask {
    config_json: String,
    profile: bool,
    cancel: KernelCancellationToken,
}

impl Task for SecureReadTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_read_json(
    config_json: String,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureReadTask> {
    AsyncTask::new(SecureReadTask {
        config_json,
        profile: false,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

#[napi]
pub fn secure_read_profile_json(
    config_json: String,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureReadTask> {
    AsyncTask::new(SecureReadTask {
        config_json,
        profile: true,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

pub struct SecurePrivateReadTask {
    config_json: String,
    cancel: KernelCancellationToken,
}

impl Task for SecurePrivateReadTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_private_read_json(
    config_json: String,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecurePrivateReadTask> {
    AsyncTask::new(SecurePrivateReadTask {
        config_json,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

pub struct SecureActionTask {
    private: bool,
    operation_id: Option<String>,
    operation: String,
    config_json: String,
    input_json: Option<String>,
    command_id: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for SecureActionTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_public_action_json(
    operation: String,
    config_json: String,
    input_json: Option<String>,
    command_id: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureActionTask> {
    AsyncTask::new(SecureActionTask {
        private: false,
        operation_id: None,
        operation,
        config_json,
        input_json,
        command_id,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

#[napi]
pub fn secure_private_action_json(
    operation: String, config_json: String, input_json: Option<String>,
    command_id: Option<String>, operation_id: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureActionTask> {
    AsyncTask::new(SecureActionTask { private: true, operation_id, operation,
        config_json, input_json, command_id,
        cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default(),
    })
}

pub struct SecureInstallTask {
    operation: String,
    config_json: String,
    input_json: Option<String>,
    begin_command_id: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for SecureInstallTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_public_install_json(
    operation: String,
    config_json: String,
    input_json: Option<String>,
    begin_command_id: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureInstallTask> {
    AsyncTask::new(SecureInstallTask {
        operation,
        config_json,
        input_json,
        begin_command_id,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

pub struct SecureOwnerCreateTask {
    operation: String,
    config_json: String,
    input_json: Option<String>,
    command_id: Option<String>,
    workspace_id: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for SecureOwnerCreateTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}

#[napi]
pub fn secure_owner_create_json(
    operation: String,
    config_json: String,
    input_json: Option<String>,
    command_id: Option<String>,
    workspace_id: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureOwnerCreateTask> {
    AsyncTask::new(SecureOwnerCreateTask {
        operation, config_json, input_json, command_id, workspace_id,
        cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default(),
    })
}

pub struct SecureOwnerConsumerTask {
    kind: String,
    operation: String,
    config_json: String,
    workspace_id: String,
    input_json: Option<String>,
    command_id: Option<String>,
    operation_id: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for SecureOwnerConsumerTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}

pub struct PublicCatalogTask {
    operation: String,
    config_json: String,
    query: Option<String>,
    after: Option<String>,
    limit: Option<u8>,
    digest: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for PublicCatalogTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}

#[napi]
pub fn public_catalog_json(
    operation: String, config_json: String, query: Option<String>, after: Option<String>,
    limit: Option<u8>, digest: Option<String>, cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<PublicCatalogTask> {
    AsyncTask::new(PublicCatalogTask {
        operation, config_json, query, after, limit, digest,
        cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default(),
    })
}

#[napi]
pub fn secure_owner_consumer_json(
    kind: String, operation: String, config_json: String, workspace_id: String,
    input_json: Option<String>, command_id: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>, operation_id: Option<String>,
) -> AsyncTask<SecureOwnerConsumerTask> {
    AsyncTask::new(SecureOwnerConsumerTask {
        kind, operation, config_json, workspace_id, input_json, command_id, operation_id,
        cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default(),
    })
}

pub struct SecureEnrollmentTask {
    operation: String,
    origin: String,
    state_dir: String,
    allow_loopback_http: bool,
    mode: Option<String>,
    expected_certificate_hash: Option<String>,
    update_id: Option<String>,
    transport_json: Option<String>,
    input_json: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for SecureEnrollmentTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_recipient_enrollment_json(
    operation: String,
    origin: String,
    state_dir: String,
    allow_loopback_http: bool,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
    mode: Option<String>,
    expected_certificate_hash: Option<String>,
    update_id: Option<String>,
    transport_json: Option<String>,
    input_json: Option<String>,
) -> AsyncTask<SecureEnrollmentTask> {
    AsyncTask::new(SecureEnrollmentTask {
        operation,
        origin,
        state_dir,
        allow_loopback_http,
        mode,
        expected_certificate_hash,
        update_id,
        transport_json,
        input_json,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

pub struct SecureDirectoryTask {
    transport_json: Option<String>,
    origin: String,
    state_dir: String,
    identity_path: String,
    target_actor_id: String,
    target_signing_key_id: String,
    allow_loopback_http: bool,
    cancel: KernelCancellationToken,
}

impl Task for SecureDirectoryTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_identity_directory_json(
    origin: String,
    state_dir: String,
    identity_path: String,
    target_actor_id: String,
    target_signing_key_id: String,
    allow_loopback_http: bool,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
    transport_json: Option<String>,
) -> AsyncTask<SecureDirectoryTask> {
    AsyncTask::new(SecureDirectoryTask {
        transport_json,
        origin,
        state_dir,
        identity_path,
        target_actor_id,
        target_signing_key_id,
        allow_loopback_http,
        cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default(),
    })
}

pub struct SecureAdmissionTask {
    role: String,
    operation: String,
    config_json: String,
    input_json: Option<String>,
    invite_id: Option<String>,
    grant_id: Option<String>,
    decision: Option<String>,
    cancel: KernelCancellationToken,
}

impl Task for SecureAdmissionTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

#[napi]
pub fn secure_public_admission_json(
    role: String,
    operation: String,
    config_json: String,
    input_json: Option<String>,
    invite_id: Option<String>,
    grant_id: Option<String>,
    decision: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureAdmissionTask> {
    AsyncTask::new(SecureAdmissionTask {
        role,
        operation,
        config_json,
        input_json,
        invite_id,
        grant_id,
        decision,
        cancel: cancel_handle.map(|h| h.token.clone()).unwrap_or_default(),
    })
}

/// Local atomic work runs off the JavaScript event loop; no network/cancel handle.
pub struct AcquisitionObservationsTask {
    operation: String,
    config_json: String,
    input_json: Option<String>,
}
impl Task for AcquisitionObservationsTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<Self::Output> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}
    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}
#[napi]
pub fn acquisition_observations_json(operation: String, config_json: String,
    input_json: Option<String>) -> AsyncTask<AcquisitionObservationsTask> {
    AsyncTask::new(AcquisitionObservationsTask { operation, config_json, input_json })
}

// Shared context lifecycle; native worker owns all identity, state and network work.
pub struct AgentContextTask {
    operation: String, profile_path: String, expected_actor: String,
    expected_service: String, request_json: Option<String>, cancel: KernelCancellationToken,
}
impl Task for AgentContextTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        Ok(peerwork_runtime::agent_context::agent_context_json(
            &self.operation, Path::new(&self.profile_path), &self.expected_actor,
            &self.expected_service, self.request_json.as_deref(), &self.cancel))
    }
    fn resolve(&mut self, _env: Env, output: String) -> Result<String> { Ok(output) }
}
#[napi]
pub fn agent_context_json(
    operation: String, profile_path: String, expected_actor: String,
    expected_service: String, request_json: Option<String>,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<AgentContextTask> {
    AsyncTask::new(AgentContextTask { operation, profile_path, expected_actor,
        expected_service, request_json,
        cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default() })
}

// All URL rules and anonymous changelog transport/verification remain native-owned.
pub struct NavigationTask { operation:String,input:String,cancel:KernelCancellationToken }
impl Task for NavigationTask {
 type Output=String;type JsValue=String;
 fn compute(&mut self)->Result<String>{Ok(peerwork_runtime::changelog::navigation_json(&self.operation,&self.input,&self.cancel))}
 fn resolve(&mut self,_env:Env,value:String)->Result<String>{Ok(value)}
}
#[napi]
pub fn navigation_json(operation:String,input_json:String,cancel_handle:Option<ClassInstance<KernelCancelHandle>>)->AsyncTask<NavigationTask>{
 AsyncTask::new(NavigationTask{operation,input:input_json,cancel:cancel_handle.map(|h|h.token.clone()).unwrap_or_default()})
}

/// Opt-in current-state reads; proof checks and bounded transport are native-owned.
pub struct ReadViewTask { input: String, cancel: KernelCancellationToken }
impl Task for ReadViewTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}
    fn resolve(&mut self, _env: Env, value: String) -> Result<String> { Ok(value) }
}
#[napi]
pub fn read_view_json(input_json: String, cancel_handle: Option<ClassInstance<KernelCancelHandle>>) -> AsyncTask<ReadViewTask> {
    AsyncTask::new(ReadViewTask { input: input_json, cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default() })
}

/// Existing protected-profile keys and pins stay inside the runtime.
pub struct PrivateReadViewTask { input: String, cancel: KernelCancellationToken }
impl Task for PrivateReadViewTask {
    type Output = String; type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}
    fn resolve(&mut self, _env: Env, value: String) -> Result<String> { Ok(value) }
}
#[napi]
pub fn private_read_view_json(input_json: String, cancel_handle: Option<ClassInstance<KernelCancelHandle>>) -> AsyncTask<PrivateReadViewTask> {
    AsyncTask::new(PrivateReadViewTask { input: input_json, cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default() })
}

/// System structure selection; protected keys, signatures and transport remain native-owned.
pub struct CurrentPageTask { input: String, cancel: KernelCancellationToken }
impl Task for CurrentPageTask {
    type Output = String; type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}
    fn resolve(&mut self, _env: Env, value: String) -> Result<String> { Ok(value) }
}
#[napi]
pub fn current_page_json(input_json: String, cancel_handle: Option<ClassInstance<KernelCancelHandle>>) -> AsyncTask<CurrentPageTask> {
    AsyncTask::new(CurrentPageTask { input: input_json, cancel: cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default() })
}

pub struct OwnerGuardTimeTask {
    config: String,
    operation: String,
    input: String,
    cancel: KernelCancellationToken,
}
impl Task for OwnerGuardTimeTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}
    fn resolve(&mut self, _env: Env, value: String) -> Result<String> {
        Ok(value)
    }
}
#[napi]
pub fn owner_guard_time_json(
    config_json: String,
    operation: String,
    input_json: String,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<OwnerGuardTimeTask> {
    AsyncTask::new(OwnerGuardTimeTask {
        config: config_json,
        operation,
        input: input_json,
        cancel: cancel_handle.map(|h| h.token.clone()).unwrap_or_default(),
    })
}

pub struct ProtocolWorkbenchTask {operation:String,input:String,cancel:KernelCancellationToken}
impl Task for ProtocolWorkbenchTask {
    type Output=String;type JsValue=String;
    fn compute(&mut self)->Result<String>{Ok(peerwork_runtime::protocol_workbench::workbench_json(&self.operation,&self.input,&self.cancel))}
    fn resolve(&mut self,_env:Env,value:String)->Result<String>{Ok(value)}
}
#[napi]
pub fn protocol_workbench_json(operation:String,input_json:String,cancel_handle:Option<ClassInstance<KernelCancelHandle>>)->AsyncTask<ProtocolWorkbenchTask>{
    AsyncTask::new(ProtocolWorkbenchTask{operation,input:input_json,cancel:cancel_handle.map(|h|h.token.clone()).unwrap_or_default()})
}

pub struct OwnerMemberScopesTask {
    config: String,
    operation: String,
    input: String,
    cancel: KernelCancellationToken,
}
impl Task for OwnerMemberScopesTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> Result<String> {
        Ok(peerwork_runtime::runtime_contract::retired_json())
}
    fn resolve(&mut self, _env: Env, value: String) -> Result<String> {
        Ok(value)
    }
}
#[napi]
pub fn owner_member_scopes_json(
    config_json: String,
    operation: String,
    input_json: String,
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<OwnerMemberScopesTask> {
    AsyncTask::new(OwnerMemberScopesTask {
        config: config_json,
        operation,
        input: input_json,
        cancel: cancel_handle.map(|h| h.token.clone()).unwrap_or_default(),
    })
}
