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
use peerwork_runtime::secure_read_access::{SecureReadAccess, SecureReadConfig};
use peerwork_runtime::secure_read_profile::{SecureReadProfile, SecureReadProfileConfig};
use peerwork_runtime::secure_recipient_enrollment::{
    RecipientEnrollmentConfig, SecureRecipientEnrollment,
};
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

#[pyfunction]
fn identity_import_pkcs8_pem_json(path: &str, pem_file: &str) -> PyResult<String> {
    let identity = KernelIdentity::import_pkcs8_pem_file(Path::new(path), Path::new(pem_file))
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

#[pyfunction]
#[pyo3(signature = (config_json, cancel_handle=None))]
fn secure_read_json(
    py: Python<'_>,
    config_json: &str,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: SecureReadConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid secure read configuration")
    })?;
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        match SecureReadAccess::new(config).read_json_with_cancel(&cancel) {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({
                "ok": false,
                "code": error.code(),
                "message": error.to_string(),
            })
            .to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (config_json, cancel_handle=None))]
fn secure_read_profile_json(
    py: Python<'_>,
    config_json: &str,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: SecureReadProfileConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid secure read profile configuration")
    })?;
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        match SecureReadProfile::new(config).read_latest_json_with_cancel(&cancel) {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({
                "ok": false,
                "code": error.code(),
                "message": error.to_string(),
            })
            .to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, input_json=None, command_id=None, cancel_handle=None))]
fn secure_public_action_json(
    py: Python<'_>,
    operation: &str,
    config_json: &str,
    input_json: Option<&str>,
    command_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: SecureReadProfileConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid secure action configuration")
    })?;
    let input: Option<PublicActionInput> = input_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid secure action input"))?;
    let operation = operation.to_owned();
    let command_id = command_id.map(str::to_owned);
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        let access = SecurePublicActionAccess::new(config);
        let result = match operation.as_str() {
            "submit" => match input {
                Some(value) => access.submit_new_json_with_cancel(value, &cancel),
                None => return serde_json::json!({"ok":false,"code":"ACTION_INPUT_INVALID","message":"action input is required"}).to_string(),
            },
            "reconcile" => match command_id.as_deref() {
                Some(id) => access.reconcile_json_with_cancel(id, &cancel),
                None => return serde_json::json!({"ok":false,"code":"ACTION_INPUT_INVALID","message":"command ID is required"}).to_string(),
            },
            "retry" => match command_id.as_deref() {
                Some(id) => access.retry_saved_json_with_cancel(id, &cancel),
                None => return serde_json::json!({"ok":false,"code":"ACTION_INPUT_INVALID","message":"command ID is required"}).to_string(),
            },
            "pending" => access.list_pending_json_with_cancel(&cancel),
            _ => return serde_json::json!({"ok":false,"code":"ACTION_INPUT_INVALID","message":"unsupported secure action operation"}).to_string(),
        };
        match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, input_json=None, begin_command_id=None, cancel_handle=None))]
fn secure_public_install_json(
    py: Python<'_>,
    operation: &str,
    config_json: &str,
    input_json: Option<&str>,
    begin_command_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: SecureReadProfileConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid PUBLIC install configuration")
    })?;
    let input: Option<PublicPackageInstallInput> = input_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid PUBLIC install input"))?;
    let operation = operation.to_owned();
    let begin_command_id = begin_command_id.map(str::to_owned);
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        let access = SecurePublicPackageInstall::new(config);
        let result = match operation.as_str() {
            "begin" => match input {
                Some(value) => access.submit_begin_json_with_cancel(value, &cancel),
                None => return serde_json::json!({"ok":false,"code":"INSTALL_INPUT_INVALID","message":"install input is required"}).to_string(),
            },
            "continue" => match begin_command_id.as_deref() {
                Some(id) => access.continue_install_json_with_cancel(id, &cancel),
                None => return serde_json::json!({"ok":false,"code":"INSTALL_INPUT_INVALID","message":"begin command ID is required"}).to_string(),
            },
            "pending" => access.list_pending_json_with_cancel(&cancel),
            _ => return serde_json::json!({"ok":false,"code":"INSTALL_INPUT_INVALID","message":"unsupported PUBLIC install operation"}).to_string(),
        };
        match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, origin, state_dir, allow_loopback_http=false, cancel_handle=None, mode=None, expected_certificate_hash=None, update_id=None))]
fn secure_recipient_enrollment_json(
    py: Python<'_>,
    operation: &str,
    origin: &str,
    state_dir: &str,
    allow_loopback_http: bool,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
    mode: Option<&str>,
    expected_certificate_hash: Option<&str>,
    update_id: Option<&str>,
) -> PyResult<String> {
    let mut config =
        RecipientEnrollmentConfig::for_state_dir(origin.to_owned(), Path::new(state_dir));
    config.allow_loopback_http = allow_loopback_http;
    let operation = operation.to_owned();
    let mode = mode.map(str::to_owned);
    let expected_certificate_hash = expected_certificate_hash.map(str::to_owned);
    let update_id = update_id.map(str::to_owned);
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        let access = SecureRecipientEnrollment::new(config);
        if operation == "certificate" {
            return match access.certificate_json() {
                Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
        }
        if operation == "update_key" {
            return match (mode.as_deref(), expected_certificate_hash.as_deref()) {
                (Some(mode), Some(hash)) => match access.update_key(mode, hash, update_id.as_deref()) {
                    Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                    Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
                },
                _ => serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"mode and expected certificate hash are required"}).to_string(),
            };
        }
        if operation == "retry_key_update" {
            return match update_id.as_deref() {
                Some(id) => match access.retry_key_update(id) {
                    Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                    Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
                },
                None => serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"update ID is required"}).to_string(),
            };
        }
        if operation == "pending_key_updates" {
            return match access.pending_key_updates() {
                Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
        }
        let result = match operation.as_str() {
            "create_local" => access.create_local().map(Some),
            "publish" => access.publish_with_cancel(&cancel).map(Some),
            "pending" => access.pending(),
            _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"unsupported recipient enrollment operation"}).to_string(),
        };
        match result {
            Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (origin, state_dir, identity_path, target_actor_id, target_signing_key_id, allow_loopback_http=false, cancel_handle=None))]
fn secure_identity_directory_json(
    py: Python<'_>,
    origin: &str,
    state_dir: &str,
    identity_path: &str,
    target_actor_id: &str,
    target_signing_key_id: &str,
    allow_loopback_http: bool,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config = IdentityDirectoryConfig {
        origin: origin.to_owned(),
        identity_path: Path::new(identity_path).to_path_buf(),
        kernel_journal_path: Path::new(state_dir).join("kernel.sqlite"),
        pins_path: Path::new(state_dir).join("identity-directory.state"),
        allow_loopback_http,
    };
    let target_actor_id = target_actor_id.to_owned();
    let target_signing_key_id = target_signing_key_id.to_owned();
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        match SecureIdentityDirectory::new(config).lookup_certificate_with_cancel(
            &target_actor_id, &target_signing_key_id, &cancel,
        ) {
            Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, input_json=None, invite_id=None, grant_id=None, cancel_handle=None))]
fn secure_public_admission_json(
    py: Python<'_>,
    operation: &str,
    config_json: &str,
    input_json: Option<&str>,
    invite_id: Option<&str>,
    grant_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: SecureReadProfileConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid PUBLIC admission configuration")
    })?;
    let input: Option<PublicOfferInput> = input_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid PUBLIC offer input"))?;
    let operation = operation.to_owned();
    let invite_id = invite_id.map(str::to_owned);
    let grant_id = grant_id.map(str::to_owned);
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        let access = SecurePublicAdmission::new(config);
        let result = match operation.as_str() {
            "offer" => match input { Some(value) => access.submit_offer_json_with_cancel(value, &cancel), None => return serde_json::json!({"ok":false,"code":"ADMISSION_INPUT_INVALID","message":"offer input is required"}).to_string() },
            "retry_offer" => match invite_id.as_deref() { Some(id) => access.retry_offer_json_with_cancel(id, &cancel), None => return serde_json::json!({"ok":false,"code":"ADMISSION_INPUT_INVALID","message":"invite ID is required"}).to_string() },
            "pending_offers" => access.pending_offers_json(),
            "deliver" => match invite_id.as_deref() { Some(id) => access.deliver_accepted_json_with_cancel(id, &cancel), None => return serde_json::json!({"ok":false,"code":"ADMISSION_INPUT_INVALID","message":"invite ID is required"}).to_string() },
            "retry_delivery" => match grant_id.as_deref() { Some(id) => access.retry_delivery_json_with_cancel(id, &cancel), None => return serde_json::json!({"ok":false,"code":"ADMISSION_INPUT_INVALID","message":"grant ID is required"}).to_string() },
            "pending_deliveries" => access.pending_deliveries_json(),
            _ => return serde_json::json!({"ok":false,"code":"ADMISSION_INPUT_INVALID","message":"unsupported PUBLIC admission operation"}).to_string(),
        };
        match result { Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"), Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string() }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, invite_id=None, decision=None, cancel_handle=None))]
fn secure_public_decision_json(
    py: Python<'_>,
    operation: &str,
    config_json: &str,
    invite_id: Option<&str>,
    decision: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: PublicDecisionConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid PUBLIC decision configuration")
    })?;
    let operation = operation.to_owned();
    let invite_id = invite_id.map(str::to_owned);
    let decision = decision.map(str::to_owned);
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        let config = match config.resolve_default_authority() {
            Ok(value) => value,
            Err(error) => return serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        };
        let access = SecurePublicDecision::new(config);
        let result = match operation.as_str() {
            "decide" => match (invite_id.as_deref(), decision.as_deref()) { (Some(id), Some(value)) => access.decide_json_with_cancel(id, value, &cancel), _ => return serde_json::json!({"ok":false,"code":"DECISION_INVALID","message":"invite ID and decision are required"}).to_string() },
            "retry_decision" => match invite_id.as_deref() { Some(id) => access.retry_json_with_cancel(id, &cancel), None => return serde_json::json!({"ok":false,"code":"DECISION_INVALID","message":"invite ID is required"}).to_string() },
            "pending_decisions" => access.pending_json(),
            "receive" => match invite_id.as_deref() { Some(id) => access.receive_json_with_cancel(id, &cancel), None => return serde_json::json!({"ok":false,"code":"DECISION_INVALID","message":"invite ID is required"}).to_string() },
            "retry_receive" => match invite_id.as_deref() { Some(id) => access.retry_receive_json_with_cancel(id, &cancel), None => return serde_json::json!({"ok":false,"code":"DECISION_INVALID","message":"invite ID is required"}).to_string() },
            "pending_receipts" => access.pending_receipts_json(),
            _ => return serde_json::json!({"ok":false,"code":"DECISION_INVALID","message":"unsupported PUBLIC decision operation"}).to_string(),
        };
        match result { Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"), Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string() }
    }))
}

#[pymodule]
fn _peerwork_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(capabilities_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_create_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_open_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_seed_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_pkcs8_pem_json, module)?)?;
    module.add_function(wrap_pyfunction!(kernel_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_read_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_read_profile_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_action_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_install_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_recipient_enrollment_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_identity_directory_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_admission_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_decision_json, module)?)?;
    module.add_class::<KernelCancelHandle>()?;
    Ok(())
}
