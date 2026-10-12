use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::KernelCancellationToken;
use pyo3::prelude::*;
use std::path::Path;

#[pyfunction]
fn version() -> &'static str {
    peerwork_core::version()
}

#[pyfunction]
fn capabilities_json() -> PyResult<String> {
    serde_json::to_string(&peerwork_core::capability_manifest())
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("manifest serialization failed"))
}

#[pyfunction]
fn identity_create_json(path: &str) -> PyResult<String> {
    let identity = KernelIdentity::create(Path::new(path))
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(format!(
        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
        identity.actor_id(),
        identity.key_id()
    ))
}

#[pyfunction]
fn identity_open_json(path: &str) -> PyResult<String> {
    let identity = KernelIdentity::open(Path::new(path))
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(format!(
        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
        identity.actor_id(),
        identity.key_id()
    ))
}

#[pyfunction]
fn identity_import_seed_json(path: &str, seed_file: &str) -> PyResult<String> {
    let identity = KernelIdentity::import_seed_file(Path::new(path), Path::new(seed_file))
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(format!(
        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
        identity.actor_id(),
        identity.key_id()
    ))
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

#[pyclass]
struct KernelCancelHandle {
    token: KernelCancellationToken,
}

#[pymethods]
impl KernelCancelHandle {
    #[new]
    fn new() -> Self {
        Self {
            token: KernelCancellationToken::new(),
        }
    }

    fn cancel(&self) {
        self.token.cancel();
    }
}

#[pyfunction]
#[pyo3(signature = (operation, origin, journal_path, identity_path, required_features, allow_loopback_http, authority=None, command_json=None, command_id=None, upload_chunk=None, cancel_handle=None, migration_source=None, migration_backup=None, trusted_signer_key_ids=None))]
fn kernel_json(
    py: Python<'_>,
    operation: &str,
    origin: &str,
    journal_path: &str,
    identity_path: &str,
    required_features: Vec<String>,
    allow_loopback_http: bool,
    authority: Option<String>,
    command_json: Option<&str>,
    command_id: Option<&str>,
    upload_chunk: Option<Vec<u8>>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
    migration_source: Option<String>,
    migration_backup: Option<String>,
    trusted_signer_key_ids: Option<Vec<String>>,
) -> PyResult<String> {
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    let access = KernelAccess::new(
        origin,
        journal_path,
        identity_path,
        &required_features,
        allow_loopback_http,
    )
    .with_authority(authority);
    let operation = operation.to_owned();
    let command_json = command_json.map(str::to_owned);
    let command_id = command_id.map(str::to_owned);
    // Discovery, protected disk access and HTTP must not hold Python's GIL.
    let result = py.allow_threads(move || {
        let value = match operation.as_str() {
            "open" => {
                let info = access.open_with_cancel(&cancel).map_err(|error| error.to_string())?;
                serde_json::json!({"actor_id": info.actor_id, "key_id": info.key_id, "origin": info.origin})
            }
            "prepare" => {
                let command = command_json.as_deref().ok_or_else(|| "command is required".to_owned())?;
                let pending = access.prepare_with_cancel(command.as_bytes(), upload_chunk.as_deref(), &cancel).map_err(|error| error.to_string())?;
                serde_json::json!({"command_id": pending.command_id, "intent_digest": pending.intent_digest, "created_at_ms": pending.created_at_ms})
            }
            "pending" => serde_json::json!(access.pending_with_cancel(&cancel).map_err(|error| error.to_string())?.into_iter().map(|row| {
                serde_json::json!({"command_id": row.command_id, "intent_digest": row.intent_digest, "created_at_ms": row.created_at_ms})
            }).collect::<Vec<_>>()),
            "status" => {
                let id = command_id.as_deref().ok_or_else(|| "command ID is required".to_owned())?;
                match access.status_with_cancel(id, &cancel).map_err(|error| error.to_string())? {
                    None => serde_json::json!({"state": "NOT_FOUND"}),
                    Some(KernelOperationStatus::Pending) => serde_json::json!({"state": "PENDING"}),
                    Some(KernelOperationStatus::Accepted(accepted)) => serde_json::json!({"state": "ACCEPTED", "result": accepted_json(accepted)}),
                }
            }
            "submit_saved" => {
                let id = command_id.as_deref().ok_or_else(|| "command ID is required".to_owned())?;
                accepted_json(access.submit_saved_with_cancel(id, &cancel).map_err(|error| error.to_string())?)
            }
            "migrate_ts_store" => {
                let source = migration_source.as_deref().ok_or_else(|| "legacy source path is required".to_owned())?;
                let backup = migration_backup.as_deref().ok_or_else(|| "backup path is required".to_owned())?;
                let signers = trusted_signer_key_ids.as_deref().ok_or_else(|| "trusted signer IDs are required".to_owned())?;
                let report = access.migrate_ts_store(Path::new(source), Path::new(backup), signers, &cancel).map_err(|error| error.to_string())?;
                serde_json::json!({"pending_count": report.pending_count, "accepted_count": report.accepted_count})
            }
            _ => return Err("unsupported kernel operation".to_owned()),
        };
        serde_json::to_string(&value).map_err(|_| "public result encoding failed".to_owned())
    });
    result.map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

#[pymodule]
fn _peerwork_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(capabilities_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_create_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_open_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_seed_json, module)?)?;
    module.add_function(wrap_pyfunction!(kernel_json, module)?)?;
    module.add_class::<KernelCancelHandle>()?;
    Ok(())
}
