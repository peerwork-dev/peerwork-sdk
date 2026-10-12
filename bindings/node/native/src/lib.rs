use napi::{
    bindgen_prelude::{AsyncTask, Buffer, ClassInstance},
    Env, Result, Task,
};
use napi_derive::napi;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::secure_read_access::{SecureReadAccess, SecureReadConfig};
use peerwork_runtime::KernelCancellationToken;
use std::path::Path;

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
    cancel: KernelCancellationToken,
}

impl Task for SecureReadTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let config: SecureReadConfig = serde_json::from_str(&self.config_json)
            .map_err(|_| napi::Error::from_reason("invalid secure read configuration"))?;
        Ok(
            match SecureReadAccess::new(config).read_json_with_cancel(&self.cancel) {
                Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
                Err(error) => serde_json::json!({
                    "ok": false,
                    "code": error.code(),
                    "message": error.to_string(),
                })
                .to_string(),
            },
        )
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
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}
