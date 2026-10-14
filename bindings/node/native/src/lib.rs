use napi::{
    bindgen_prelude::{AsyncTask, Buffer, ClassInstance},
    Env, Result, Task,
};
use napi_derive::napi;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::secure_action_access::{PublicActionInput, SecurePublicActionAccess};
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
        .map_err(|error| napi::Error::from_reason(error.to_string()))?;
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
        let config_bytes = std::fs::read(&self.config_file)
            .map_err(|_| napi::Error::from_reason("Owner config could not be read"))?;
        let config: SecureOwnerCreateConfig = serde_json::from_slice(&config_bytes)
            .map_err(|_| napi::Error::from_reason("invalid Owner configuration"))?;
        let identity = import_legacy_owner_identity(&config, Path::new(&self.pem_file))
            .map_err(|error| napi::Error::from_reason(error.to_string()))?;
        Ok(format!(
            "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
            identity.actor_id(), identity.key_id()
        ))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> { Ok(output) }
}

#[napi]
pub fn identity_import_owner_pem_json(config_file: String, pem_file: String) -> AsyncTask<OwnerIdentityImportTask> {
    AsyncTask::new(OwnerIdentityImportTask { config_file, pem_file })
}

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
    serde_json::json!({
        "command_id": result.command_id,
        "workspace_id": result.workspace_id,
        "protocol_digest": result.protocol_digest,
        "instance_id": result.instance_id,
        "event_sequence": result.event_sequence,
        "revision": result.revision,
        "produced_record_ids": result.produced_record_ids,
        "catalog": result.catalog,
    })
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
    cancel: KernelCancellationToken,
}

impl Task for KernelTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let access = KernelAccess::new(
            &self.origin,
            &self.journal_path,
            &self.identity_path,
            &self.required_features,
            self.allow_loopback_http,
        )
        .with_authority(self.authority.clone());
        let value = match self.operation.as_str() {
            "open" => {
                let info = access.open_with_cancel(&self.cancel).map_err(|error| napi::Error::from_reason(error.to_string()))?;
                serde_json::json!({"actor_id": info.actor_id, "key_id": info.key_id, "origin": info.origin})
            }
            "prepare" => {
                let command = self.command_json.as_deref().ok_or_else(|| napi::Error::from_reason("command is required"))?;
                let pending = access.prepare_with_cancel(command.as_bytes(), self.upload_chunk.as_deref(), &self.cancel).map_err(|error| napi::Error::from_reason(error.to_string()))?;
                serde_json::json!({"command_id": pending.command_id, "intent_digest": pending.intent_digest, "created_at_ms": pending.created_at_ms})
            }
            "pending" => serde_json::json!(access.pending_with_cancel(&self.cancel).map_err(|error| napi::Error::from_reason(error.to_string()))?.into_iter().map(|row| {
                serde_json::json!({"command_id": row.command_id, "intent_digest": row.intent_digest, "created_at_ms": row.created_at_ms})
            }).collect::<Vec<_>>()),
            "status" => {
                let id = self.command_id.as_deref().ok_or_else(|| napi::Error::from_reason("command ID is required"))?;
                match access.status_with_cancel(id, &self.cancel).map_err(|error| napi::Error::from_reason(error.to_string()))? {
                    None => serde_json::json!({"state": "NOT_FOUND"}),
                    Some(KernelOperationStatus::Pending) => serde_json::json!({"state": "PENDING"}),
                    Some(KernelOperationStatus::Accepted(accepted)) => serde_json::json!({"state": "ACCEPTED", "result": accepted_json(accepted)}),
                }
            }
            "submit_saved" => {
                let id = self.command_id.as_deref().ok_or_else(|| napi::Error::from_reason("command ID is required"))?;
                accepted_json(access.submit_saved_with_cancel(id, &self.cancel).map_err(|error| napi::Error::from_reason(error.to_string()))?)
            }
            "migrate_ts_store" => {
                let source = self.migration_source.as_deref().ok_or_else(|| napi::Error::from_reason("legacy source path is required"))?;
                let backup = self.migration_backup.as_deref().ok_or_else(|| napi::Error::from_reason("backup path is required"))?;
                let signers = self.trusted_signer_key_ids.as_deref().ok_or_else(|| napi::Error::from_reason("trusted signer IDs are required"))?;
                let report = access.migrate_ts_store(Path::new(source), Path::new(backup), signers, &self.cancel).map_err(|error| napi::Error::from_reason(error.to_string()))?;
                serde_json::json!({"pending_count": report.pending_count, "accepted_count": report.accepted_count})
            }
            _ => return Err(napi::Error::from_reason("unsupported kernel operation")),
        };
        serde_json::to_string(&value)
            .map_err(|_| napi::Error::from_reason("public result encoding failed"))
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
        let read = if self.profile {
            let config: SecureReadProfileConfig =
                serde_json::from_str(&self.config_json).map_err(|_| {
                    napi::Error::from_reason("invalid secure read profile configuration")
                })?;
            SecureReadProfile::new(config).read_latest_json_with_cancel(&self.cancel)
        } else {
            let config: SecureReadConfig = serde_json::from_str(&self.config_json)
                .map_err(|_| napi::Error::from_reason("invalid secure read configuration"))?;
            SecureReadAccess::new(config).read_json_with_cancel(&self.cancel)
        };
        Ok(match read {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({
                "ok": false,
                "code": error.code(),
                "message": error.to_string(),
            })
            .to_string(),
        })
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
        let config: SecureReadProfileConfig = serde_json::from_str(&self.config_json)
            .map_err(|_| napi::Error::from_reason("invalid secure private read configuration"))?;
        Ok(match SecurePrivateReadAccess::new(config).activate_and_read_json_with_cancel(&self.cancel) {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({
                "ok": false,
                "code": error.code(),
                "message": error.to_string(),
            })
            .to_string(),
        })
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
        let config: SecureReadProfileConfig = serde_json::from_str(&self.config_json)
            .map_err(|_| napi::Error::from_reason("invalid secure action configuration"))?;
        let access = SecurePublicActionAccess::new(config);
        let result = match self.operation.as_str() {
            "submit" => {
                let input: PublicActionInput = serde_json::from_str(
                    self.input_json
                        .as_deref()
                        .ok_or_else(|| napi::Error::from_reason("action input is required"))?,
                )
                .map_err(|_| napi::Error::from_reason("invalid secure action input"))?;
                access.submit_new_json_with_cancel(input, &self.cancel)
            }
            "reconcile" => access.reconcile_json_with_cancel(
                self.command_id
                    .as_deref()
                    .ok_or_else(|| napi::Error::from_reason("command ID is required"))?,
                &self.cancel,
            ),
            "retry" => access.retry_saved_json_with_cancel(
                self.command_id
                    .as_deref()
                    .ok_or_else(|| napi::Error::from_reason("command ID is required"))?,
                &self.cancel,
            ),
            "pending" => access.list_pending_json_with_cancel(&self.cancel),
            _ => {
                return Err(napi::Error::from_reason(
                    "unsupported secure action operation",
                ))
            }
        };
        Ok(match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => {
                serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()})
                    .to_string()
            }
        })
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
        operation,
        config_json,
        input_json,
        command_id,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
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
        let config: SecureReadProfileConfig = serde_json::from_str(&self.config_json)
            .map_err(|_| napi::Error::from_reason("invalid PUBLIC install configuration"))?;
        let access = SecurePublicPackageInstall::new(config);
        let result = match self.operation.as_str() {
            "begin" => {
                let input: PublicPackageInstallInput = serde_json::from_str(
                    self.input_json
                        .as_deref()
                        .ok_or_else(|| napi::Error::from_reason("install input is required"))?,
                )
                .map_err(|_| napi::Error::from_reason("invalid PUBLIC install input"))?;
                access.submit_begin_json_with_cancel(input, &self.cancel)
            }
            "continue" => access.continue_install_json_with_cancel(
                self.begin_command_id
                    .as_deref()
                    .ok_or_else(|| napi::Error::from_reason("begin command ID is required"))?,
                &self.cancel,
            ),
            "pending" => access.list_pending_json_with_cancel(&self.cancel),
            _ => {
                return Err(napi::Error::from_reason(
                    "unsupported PUBLIC install operation",
                ))
            }
        };
        Ok(match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => {
                serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()})
                    .to_string()
            }
        })
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
        let config: SecureOwnerCreateConfig = match serde_json::from_str(&self.config_json) {
            Ok(value) => value,
            Err(_) => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner configuration"}).to_string()),
        };
        if matches!(self.operation.as_str(), "attach" | "resume_attachment" | "retain_pending_action" | "attachments" | "kernel_inspect" | "kernel_status" | "kernel_recover" | "stage_inspect" | "stage_multipart_inspect" | "stage_multipart_attach" | "stage_recover" | "orphan_inspect" | "orphan_multipart_inspect" | "orphan_multipart_attach" | "orphan_replan" | "direct_begin_inspect" | "direct_begin_attach" | "direct_begin_recover" | "direct_completed_inspect" | "direct_completed_attach") {
            let access = SecureHistoricalOwnerAttach::new(config);
            let result = match self.operation.as_str() {
                "attach" => {
                    let input: HistoricalOwnerAttachInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner attachment input"}).to_string()),
                    };
                    access.attach(input, &self.cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                }
                "resume_attachment" => match self.command_id.as_deref() {
                    Some(id) => access.resume_attachment(id, &self.cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment ID is required"}).to_string()),
                },
                "retain_pending_action" => match (self.workspace_id.as_deref(), self.command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.retain_pending_action(attach_id, id, &self.cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and pending action command IDs are required"}).to_string()),
                },
                "attachments" => access.attachments().map(|value| serde_json::to_string(&value).expect("attachment history serializes")),
                "kernel_inspect" => {
                    let input: HistoricalOwnerAttachInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid kernel inspection input"}).to_string()),
                    };
                    access.inspect_kernel_pending(&input, &self.cancel).map(|value| serde_json::to_string(&value).expect("kernel inventory serializes"))
                }
                "kernel_status" => match self.command_id.as_deref() {
                    Some(attach_id) => access.kernel_command_status(attach_id).map(|value| serde_json::to_string(&value).expect("kernel status serializes")),
                    None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment ID is required"}).to_string()),
                },
                "kernel_recover" => match (self.workspace_id.as_deref(), self.command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_kernel_command(attach_id, id, &self.cancel).map(|value| serde_json::to_string(&value).expect("kernel recovery status serializes")),
                    _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and kernel command IDs are required"}).to_string()),
                },
                "direct_begin_inspect" | "direct_begin_attach" | "direct_completed_inspect" | "direct_completed_attach" => {
                    let completed = self.operation.starts_with("direct_completed_");
                    let selection_key = if completed { "selected_instance_id" } else { "selected_command_id" };
                    let (input, selected, digest, options, material) = match direct_install_request(self.input_json.as_deref(), selection_key) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid direct install input"}).to_string()),
                    };
                    if self.operation.ends_with("_inspect") {
                        if digest.is_some() { return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"direct install inspection must not select a TS state digest"}).to_string()); }
                        if completed {
                            access.inspect_completed_direct_install(&input, &selected, &options, &material, &self.cancel)
                                .map(|value| serde_json::to_string(&value).expect("completed direct inventory serializes"))
                        } else {
                            access.inspect_pending_direct_install_begin(&input, &selected, &options, &material, &self.cancel)
                                .map(|value| serde_json::to_string(&value).expect("direct packet inventory serializes"))
                        }
                    } else {
                        let Some(digest) = digest else { return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"direct install attach requires inspected TS state digest"}).to_string()); };
                        if completed {
                            access.attach_completed_direct_install(input, &selected, &digest, &options, &material, &self.cancel)
                                .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                        } else {
                            access.attach_pending_direct_install_begin(input, &selected, &digest, &options, &material, &self.cancel)
                                .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                        }
                    }
                },
                "direct_begin_recover" => match (self.workspace_id.as_deref(), self.command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_pending_direct_install_begin(attach_id, id, &self.cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and selected direct packet IDs are required"}).to_string()),
                },
                "stage_inspect" => {
                    let input: HistoricalOwnerAttachInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid package stage inspection input"}).to_string()),
                    };
                    access.inspect_pending_package_stage(&input, &self.cancel).map(|value| serde_json::to_string(&value).expect("package stage inventory serializes"))
                },
                "stage_multipart_inspect" => {
                    let (input, material) = match multipart_stage_request(self.input_json.as_deref()) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart stage inspection input"}).to_string()),
                    };
                    access.inspect_pending_package_stage_with_material(&input, &material, &self.cancel)
                        .map(|value| serde_json::to_string(&value).expect("package stage inventory serializes"))
                },
                "stage_multipart_attach" => {
                    let (input, material) = match multipart_stage_request(self.input_json.as_deref()) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart stage attachment input"}).to_string()),
                    };
                    access.attach_pending_package_stage_with_material(input, &material, &self.cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                },
                "stage_recover" => match (self.workspace_id.as_deref(), self.command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_pending_package_stage(attach_id, id, &self.cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and package stage command IDs are required"}).to_string()),
                },
                "orphan_inspect" => {
                    let input: HistoricalOwnerAttachInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid orphan stage inspection input"}).to_string()),
                    };
                    access.inspect_orphan_package_stage(&input, &self.cancel).map(|value| serde_json::to_string(&value).expect("orphan stage inventory serializes"))
                },
                "orphan_multipart_inspect" => {
                    let (input, material) = match multipart_stage_request(self.input_json.as_deref()) {
                        Some((input, material)) if input.selected_pending_package_stage_command_id.is_none()
                            && input.selected_orphan_package_stage_command_id.is_none()
                            && input.expected_ts_state_digest.is_none() => (input, material),
                        _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart orphan inspection input"}).to_string()),
                    };
                    access.inspect_multipart_orphan_package_stage_with_material(&input, &material, &self.cancel)
                        .map(|value| serde_json::to_string(&value).expect("orphan stage inventory serializes"))
                },
                "orphan_multipart_attach" => {
                    let (input, material) = match multipart_stage_request(self.input_json.as_deref()) {
                        Some((input, material)) if input.selected_pending_package_stage_command_id.is_none()
                            && input.selected_orphan_package_stage_command_id.is_some()
                            && input.expected_ts_state_digest.is_some() => (input, material),
                        _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart orphan attachment input"}).to_string()),
                    };
                    access.attach_pending_package_stage_with_material(input, &material, &self.cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                },
                "orphan_replan" => match (self.workspace_id.as_deref(), self.command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => {
                        let material: Option<String> = match self.input_json.as_deref() {
                            Some(wire) => match serde_json::from_str::<String>(wire) {
                                Ok(value) if !value.is_empty() => Some(value),
                                _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid orphan replan material"}).to_string()),
                            },
                            None => None,
                        };
                        access.replan_orphan_package_stage(attach_id, id, material.as_deref(), &self.cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                    }
                    _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and original stage command IDs are required"}).to_string()),
                },
                _ => unreachable!(),
            };
            return Ok(match result {
                Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            });
        }
        if matches!(self.operation.as_str(), "format_submit" | "format_resume" | "format_history") {
            let input: Option<OwnerFormatTransitionInput> = if self.operation == "format_submit" {
                match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                    Some(value) => Some(value),
                    None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner format transition input"}).to_string()),
                }
            } else { None };
            let selected_workspace = input.as_ref().map(|value| value.workspace_id.as_str())
                .or(self.workspace_id.as_deref());
            let Some(selected_workspace) = selected_workspace else {
                return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"workspace ID is required"}).to_string());
            };
            let access = match SecureOwnerWorkspaceCreate::new(config)
                .format_transition_access(selected_workspace) {
                Ok(value) => value,
                Err(error) => return Ok(serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string()),
            };
            let result = match self.operation.as_str() {
                "format_submit" => access.submit_json_with_cancel(input.expect("submit input parsed"), &self.cancel),
                "format_resume" => match self.command_id.as_deref() {
                    Some(id) => access.resume_json_with_cancel(id, &self.cancel),
                    None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"transition command ID is required"}).to_string()),
                },
                "format_history" => access.history_json(),
                _ => unreachable!(),
            };
            return Ok(match result {
                Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            });
        }
        let access = SecureOwnerWorkspaceCreate::new(config);
        let result = match self.operation.as_str() {
            "prepare" | "create" => {
                let input: SecureOwnerCreateInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                    Some(value) => value,
                    None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner creation input"}).to_string()),
                };
                if self.operation == "prepare" { access.prepare(input, &self.cancel) } else { access.create(input, &self.cancel) }
                    .map(|value| serde_json::to_string(&value).expect("Owner result serializes"))
            }
            "resume" => match self.command_id.as_deref() {
                Some(id) => access.resume(id, &self.cancel).map(|value| serde_json::to_string(&value).expect("Owner result serializes")),
                None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"command ID is required"}).to_string()),
            },
            "operations" => access.operations().map(|value| serde_json::to_string(&value).expect("Owner result serializes")),
            "read" => match self.workspace_id.as_deref() {
                Some(id) => access.read_workspace_json(id, &self.cancel),
                None => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"workspace ID is required"}).to_string()),
            },
            _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"unsupported Owner operation"}).to_string()),
        };
        Ok(match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        })
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
    cancel: KernelCancellationToken,
}

impl Task for SecureOwnerConsumerTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let fail = |code: &str, message: &str| serde_json::json!({"ok":false,"code":code,"message":message}).to_string();
        let config: SecureOwnerCreateConfig = match serde_json::from_str(&self.config_json) {
            Ok(value) => value,
            Err(_) => return Ok(fail("INPUT_INVALID", "invalid Owner configuration")),
        };
        let owner = SecureOwnerWorkspaceCreate::new(config);
        let result = if self.kind == "public_action" {
            let access = match owner.public_action_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "submit" => {
                    let input: PublicActionInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("ACTION_INPUT_INVALID", "invalid Owner action input")),
                    };
                    access.submit_new_json_with_cancel(input, &self.cancel)
                }
                "reconcile" => match self.command_id.as_deref() {
                    Some(id) => access.reconcile_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("ACTION_INPUT_INVALID", "command ID is required")),
                },
                "retry" => match self.command_id.as_deref() {
                    Some(id) => access.retry_saved_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("ACTION_INPUT_INVALID", "command ID is required")),
                },
                "pending" => access.list_pending_json_with_cancel(&self.cancel),
                _ => return Ok(fail("ACTION_INPUT_INVALID", "unsupported Owner action operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if self.kind == "private_action" {
            let access = match owner.private_action_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "submit" => {
                    let input: PublicActionInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("ACTION_INPUT_INVALID", "invalid Owner action input")),
                    };
                    access.submit_new_json_with_cancel(input, &self.cancel)
                }
                "reconcile" => match self.command_id.as_deref() {
                    Some(id) => access.reconcile_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("ACTION_INPUT_INVALID", "command ID is required")),
                },
                "retry" => match self.command_id.as_deref() {
                    Some(id) => access.retry_saved_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("ACTION_INPUT_INVALID", "command ID is required")),
                },
                "pending" => access.list_pending_json_with_cancel(&self.cancel),
                _ => return Ok(fail("ACTION_INPUT_INVALID", "unsupported Owner action operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if self.kind == "public_install" {
            let access = match owner.public_install_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "begin" => {
                    let input: PublicPackageInstallInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("INSTALL_INPUT_INVALID", "invalid Owner package input")),
                    };
                    access.submit_begin_json_with_cancel(input, &self.cancel)
                }
                "continue" => match self.command_id.as_deref() {
                    Some(id) => access.continue_install_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("INSTALL_INPUT_INVALID", "begin command ID is required")),
                },
                "pending" => access.list_pending_json_with_cancel(&self.cancel),
                _ => return Ok(fail("INSTALL_INPUT_INVALID", "unsupported Owner install operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if self.kind == "private_stage" {
            let access = match owner.private_install_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "stage" => {
                    let input: PrivatePackageStageInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("INSTALL_INPUT_INVALID", "invalid PRIVATE stage input")),
                    };
                    access.stage_package_json_with_cancel(input, &self.cancel)
                }
                "continue" => match self.command_id.as_deref() {
                    Some(id) => access.continue_stage_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("INSTALL_INPUT_INVALID", "stage ID is required")),
                },
                "stages" => access.stages_json(),
                _ => return Ok(fail("INSTALL_INPUT_INVALID", "unsupported PRIVATE stage operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if self.kind == "private_install" {
            let access = match owner.private_install_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "begin" => {
                    let input: PrivatePackageInstallBeginInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("INSTALL_INPUT_INVALID", "invalid PRIVATE install input")),
                    };
                    access.submit_begin_json_with_cancel(input, &self.cancel)
                }
                "begin_direct" => {
                    let input: PrivateDirectInstallBeginInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("INSTALL_INPUT_INVALID", "invalid PRIVATE direct install input")),
                    };
                    access.submit_direct_begin_json_with_cancel(input, &self.cancel)
                }
                "continue" => match self.command_id.as_deref() {
                    Some(id) => access.continue_install_json_with_cancel(id, &self.cancel),
                    None => return Ok(fail("INSTALL_INPUT_INVALID", "begin command ID is required")),
                },
                "installs" => access.installs_json(),
                _ => return Ok(fail("INSTALL_INPUT_INVALID", "unsupported PRIVATE install operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if self.kind == "public_admission" {
            let access = match owner.public_admission_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "offer" => {
                    let input: PublicOfferInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("ADMISSION_INPUT_INVALID", "invalid Owner offer input")),
                    };
                    access.submit_offer_json_with_cancel(input, &self.cancel)
                }
                "retry_offer" => access.retry_offer_json_with_cancel(self.command_id.as_deref().unwrap_or(""), &self.cancel),
                "pending_offers" => access.pending_offers_json(),
                "deliver" => access.deliver_accepted_json_with_cancel(self.command_id.as_deref().unwrap_or(""), &self.cancel),
                "retry_delivery" => access.retry_delivery_json_with_cancel(self.command_id.as_deref().unwrap_or(""), &self.cancel),
                "pending_deliveries" => access.pending_deliveries_json(),
                _ => return Ok(fail("ADMISSION_INPUT_INVALID", "unsupported Owner admission operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if self.kind == "private_admission" {
            let access = match owner.private_admission_access(&self.workspace_id) {
                Ok(value) => value,
                Err(error) => return Ok(fail(error.code(), &error.to_string())),
            };
            match self.operation.as_str() {
                "offer" => {
                    let input: PublicOfferInput = match self.input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return Ok(fail("ADMISSION_INPUT_INVALID", "invalid Owner offer input")),
                    };
                    access.submit_offer_json_with_cancel(input, &self.cancel)
                }
                "retry_offer" => access.retry_offer_json_with_cancel(self.command_id.as_deref().unwrap_or(""), &self.cancel),
                "pending_offers" => access.pending_offers_json(),
                "deliver" => access.deliver_accepted_json_with_cancel(self.command_id.as_deref().unwrap_or(""), &self.cancel),
                "retry_delivery" => access.retry_delivery_json_with_cancel(self.command_id.as_deref().unwrap_or(""), &self.cancel),
                "pending_deliveries" => access.pending_deliveries_json(),
                _ => return Ok(fail("ADMISSION_INPUT_INVALID", "unsupported Owner admission operation")),
            }.map_err(|error| (error.code(), error.to_string()))
        } else {
            return Ok(fail("INPUT_INVALID", "unsupported Owner consumer"));
        };
        Ok(match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err((code, message)) => fail(code, &message),
        })
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
        let config: PublicCatalogConfig = match serde_json::from_str(&self.config_json) {
            Ok(value) => value,
            Err(_) => return Ok(serde_json::json!({"ok":false,"code":"CATALOG_INPUT_INVALID","message":"invalid catalog configuration"}).to_string()),
        };
        let catalog = PublicCatalog::new(config);
        let result = match self.operation.as_str() {
            "search" => catalog.search(self.query.as_deref().unwrap_or(""), self.after.as_deref(), self.limit.unwrap_or(20), &self.cancel)
                .map(|value| serde_json::to_string(&value).expect("catalog result serializes")),
            "inspect" => catalog.inspect_exact(self.digest.as_deref().unwrap_or(""), &self.cancel)
                .map(|value| serde_json::to_string(&value).expect("catalog result serializes")),
            _ => return Ok(serde_json::json!({"ok":false,"code":"CATALOG_INPUT_INVALID","message":"unsupported catalog operation"}).to_string()),
        };
        Ok(match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        })
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
    cancel_handle: Option<ClassInstance<KernelCancelHandle>>,
) -> AsyncTask<SecureOwnerConsumerTask> {
    AsyncTask::new(SecureOwnerConsumerTask {
        kind, operation, config_json, workspace_id, input_json, command_id,
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
    cancel: KernelCancellationToken,
}

impl Task for SecureEnrollmentTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut config = RecipientEnrollmentConfig::for_state_dir(
            self.origin.clone(),
            Path::new(&self.state_dir),
        );
        config.allow_loopback_http = self.allow_loopback_http;
        let access = SecureRecipientEnrollment::new(config);
        if self.operation == "certificate" {
            return Ok(match access.certificate_json() {
                Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                Err(error) => {
                    serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()})
                        .to_string()
                }
            });
        }
        if self.operation == "update_key" {
            return Ok(match (self.mode.as_deref(), self.expected_certificate_hash.as_deref()) {
                (Some(mode), Some(hash)) => match access.update_key_with_cancel(mode, hash, self.update_id.as_deref(), &self.cancel) {
                    Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                    Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
                },
                _ => serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"mode and expected certificate hash are required"}).to_string(),
            });
        }
        if self.operation == "retry_key_update" {
            return Ok(match self.update_id.as_deref() {
                Some(id) => match access.retry_key_update_with_cancel(id, &self.cancel) {
                    Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                    Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
                },
                None => serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"update ID is required"}).to_string(),
            });
        }
        if self.operation == "pending_key_updates" {
            return Ok(match access.pending_key_updates() {
                Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            });
        }
        if self.operation == "key_updates" {
            return Ok(match access.key_updates() {
                Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            });
        }
        let result = match self.operation.as_str() {
            "create_local" => access.create_local().map(Some),
            "publish" => access.publish_with_cancel(&self.cancel).map(Some),
            "pending" => access.pending(),
            _ => return Ok(serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"unsupported recipient enrollment operation"}).to_string()),
        };
        Ok(match result {
            Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
            Err(error) => {
                serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()})
                    .to_string()
            }
        })
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
) -> AsyncTask<SecureEnrollmentTask> {
    AsyncTask::new(SecureEnrollmentTask {
        operation,
        origin,
        state_dir,
        allow_loopback_http,
        mode,
        expected_certificate_hash,
        update_id,
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}

pub struct SecureDirectoryTask {
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
        let config = IdentityDirectoryConfig {
            origin: self.origin.clone(),
            identity_path: Path::new(&self.identity_path).to_path_buf(),
            kernel_journal_path: Path::new(&self.state_dir).join("kernel.sqlite"),
            pins_path: Path::new(&self.state_dir).join("identity-directory.state"),
            allow_loopback_http: self.allow_loopback_http,
        };
        Ok(match SecureIdentityDirectory::new(config).lookup_certificate_with_cancel(
            &self.target_actor_id, &self.target_signing_key_id, &self.cancel,
        ) {
            Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        })
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
) -> AsyncTask<SecureDirectoryTask> {
    AsyncTask::new(SecureDirectoryTask {
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
        let result = if self.role == "owner" {
            let config: SecureReadProfileConfig = serde_json::from_str(&self.config_json)
                .map_err(|_| napi::Error::from_reason("invalid PUBLIC admission configuration"))?;
            let access = SecurePublicAdmission::new(config);
            match self.operation.as_str() {
                "offer" => {
                    let input: PublicOfferInput = serde_json::from_str(
                        self.input_json
                            .as_deref()
                            .ok_or_else(|| napi::Error::from_reason("offer input required"))?,
                    )
                    .map_err(|_| napi::Error::from_reason("invalid PUBLIC offer input"))?;
                    access
                        .submit_offer_json_with_cancel(input, &self.cancel)
                        .map_err(|e| (e.code(), e.to_string()))
                }
                "retry_offer" => access
                    .retry_offer_json_with_cancel(
                        self.invite_id.as_deref().unwrap_or(""),
                        &self.cancel,
                    )
                    .map_err(|e| (e.code(), e.to_string())),
                "pending_offers" => access
                    .pending_offers_json()
                    .map_err(|e| (e.code(), e.to_string())),
                "deliver" => access
                    .deliver_accepted_json_with_cancel(
                        self.invite_id.as_deref().unwrap_or(""),
                        &self.cancel,
                    )
                    .map_err(|e| (e.code(), e.to_string())),
                "retry_delivery" => access
                    .retry_delivery_json_with_cancel(
                        self.grant_id.as_deref().unwrap_or(""),
                        &self.cancel,
                    )
                    .map_err(|e| (e.code(), e.to_string())),
                "pending_deliveries" => access
                    .pending_deliveries_json()
                    .map_err(|e| (e.code(), e.to_string())),
                _ => {
                    return Err(napi::Error::from_reason(
                        "unsupported PUBLIC admission operation",
                    ))
                }
            }
        } else if self.role == "recipient" {
            let config: PublicDecisionConfig = serde_json::from_str(&self.config_json)
                .map_err(|_| napi::Error::from_reason("invalid PUBLIC decision configuration"))?;
            let config = match config.resolve_default_authority() {
                Ok(value) => value,
                Err(error) => return Ok(
                    serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()})
                        .to_string(),
                ),
            };
            let access = SecurePublicDecision::new(config);
            match self.operation.as_str() {
                "decide" => access
                    .decide_json_with_cancel(
                        self.invite_id.as_deref().unwrap_or(""),
                        self.decision.as_deref().unwrap_or(""),
                        &self.cancel,
                    )
                    .map_err(|e| (e.code(), e.to_string())),
                "retry_decision" => access
                    .retry_json_with_cancel(self.invite_id.as_deref().unwrap_or(""), &self.cancel)
                    .map_err(|e| (e.code(), e.to_string())),
                "pending_decisions" => access.pending_json().map_err(|e| (e.code(), e.to_string())),
                "receive" => access
                    .receive_json_with_cancel(self.invite_id.as_deref().unwrap_or(""), &self.cancel)
                    .map_err(|e| (e.code(), e.to_string())),
                "retry_receive" => access
                    .retry_receive_json_with_cancel(
                        self.invite_id.as_deref().unwrap_or(""),
                        &self.cancel,
                    )
                    .map_err(|e| (e.code(), e.to_string())),
                "pending_receipts" => access
                    .pending_receipts_json()
                    .map_err(|e| (e.code(), e.to_string())),
                _ => {
                    return Err(napi::Error::from_reason(
                        "unsupported PUBLIC decision operation",
                    ))
                }
            }
        } else {
            return Err(napi::Error::from_reason(
                "unsupported PUBLIC admission role",
            ));
        };
        Ok(match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err((code, message)) => {
                serde_json::json!({"ok":false,"code":code,"message":message}).to_string()
            }
        })
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
