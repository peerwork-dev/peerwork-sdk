use napi::{
    bindgen_prelude::{AsyncTask, Buffer, ClassInstance},
    Env, Result, Task,
};
use napi_derive::napi;
use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
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
}

impl Task for IdentityTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let identity = if self.create {
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
    AsyncTask::new(IdentityTask { path, create: true })
}

#[napi]
pub fn identity_open_json(path: String) -> AsyncTask<IdentityTask> {
    AsyncTask::new(IdentityTask {
        path,
        create: false,
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
        cancel: cancel_handle
            .map(|handle| handle.token.clone())
            .unwrap_or_default(),
    })
}
