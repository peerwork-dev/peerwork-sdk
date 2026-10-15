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
use peerwork_runtime::secure_owner_coordination::OwnerCoordinationEnableInput;
use peerwork_runtime::public_catalog::{PublicCatalog, PublicCatalogConfig};
use peerwork_runtime::secure_recipient_enrollment::{
    RecipientEnrollmentConfig, SecureRecipientEnrollment,
};
use peerwork_runtime::KernelCancellationToken;
use pyo3::prelude::*;
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

#[pyfunction]
fn version() -> &'static str {
    peerwork_core::version()
}

#[pyfunction]
fn capabilities_json() -> PyResult<String> {
    serde_json::to_string(&peerwork_core::capability_manifest())
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("manifest serialization failed"))
}

#[pyfunction(signature = (path=None))]
fn load_config_json(path: Option<String>) -> String {
    peerwork_runtime::protected_config::load_config_json(path.as_deref().map(Path::new))
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
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(format!(
            "{}: {}",
            error.code(),
            error.actionable_message()
        )))?;
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

#[pyfunction]
fn identity_import_owner_pem_json(config_file: &str, pem_file: &str) -> PyResult<String> {
    let config_bytes = std::fs::read(config_file)
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Owner config could not be read"))?;
    let config: SecureOwnerCreateConfig = serde_json::from_slice(&config_bytes)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid Owner configuration"))?;
    let identity = import_legacy_owner_identity(&config, Path::new(pem_file))
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(format!(
        "{{\"actor_id\":\"{}\",\"key_id\":\"{}\"}}",
        identity.actor_id(), identity.key_id()
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
#[pyo3(signature = (operation, origin, journal_path, identity_path, required_features, allow_loopback_http, authority=None, command_json=None, command_id=None, upload_chunk=None, cancel_handle=None, migration_source=None, migration_backup=None, trusted_signer_key_ids=None, transport_json=None))]
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
    transport_json: Option<&str>,
) -> PyResult<String> {
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    let transport = transport_json.map(serde_json::from_str::<peerwork_runtime::transport::TransportOptions>).transpose().map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid transport options"))?.unwrap_or_default();
    transport.validate().map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid transport options"))?;
    let access = KernelAccess::new(
        origin,
        journal_path,
        identity_path,
        &required_features,
        allow_loopback_http,
    )
    .with_authority(authority).with_transport_options(transport);
    let operation = operation.to_owned();
    let command_json = command_json.map(str::to_owned);
    let command_id = command_id.map(str::to_owned);
    // Discovery, protected disk access and HTTP must not hold Python's GIL.
    let result = py.allow_threads(move || -> Result<serde_json::Value, peerwork_runtime::kernel_access::KernelPublicError> {
        let value = match operation.as_str() {
            "open" => {
                let info = access.open_with_cancel(&cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?;
                serde_json::json!({"actor_id": info.actor_id, "key_id": info.key_id, "origin": info.origin})
            }
            "prepare" => {
                let command = command_json.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command is required"))?;
                let pending = access.prepare_with_cancel(command.as_bytes(), upload_chunk.as_deref(), &cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?;
                serde_json::json!({"command_id": pending.command_id, "intent_digest": pending.intent_digest, "created_at_ms": pending.created_at_ms})
            }
            "pending" => serde_json::json!(access.pending_with_cancel(&cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?.into_iter().map(|row| {
                serde_json::json!({"command_id": row.command_id, "intent_digest": row.intent_digest, "created_at_ms": row.created_at_ms})
            }).collect::<Vec<_>>()),
            "status" => {
                let id = command_id.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                match access.status_with_cancel(id, &cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)? {
                    None => serde_json::json!({"state": "NOT_FOUND"}),
                    Some(KernelOperationStatus::Pending) => serde_json::json!({"state": "PENDING"}),
                    Some(KernelOperationStatus::Accepted(accepted)) => serde_json::json!({"state": "ACCEPTED", "result": accepted_json(accepted)}),
                }
            }
            "submit_saved" => {
                let id = command_id.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                accepted_json(access.submit_saved_with_cancel(id, &cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?)
            }
            "migrate_ts_store" => {
                let source = migration_source.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("legacy source path is required"))?;
                let backup = migration_backup.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("backup path is required"))?;
                let signers = trusted_signer_key_ids.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("trusted signer IDs are required"))?;
                let report = access.migrate_ts_store(Path::new(source), Path::new(backup), signers, &cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?;
                serde_json::json!({"pending_count": report.pending_count, "accepted_count": report.accepted_count})
            }
            _ => return Err(peerwork_runtime::kernel_access::KernelPublicError::from("unsupported kernel operation")),
        };
        Ok(value)
    });
    Ok(match result { Ok(value) => value, Err(error) => error.envelope() }.to_string())
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
#[pyo3(signature = (config_json, cancel_handle=None))]
fn secure_private_read_json(
    py: Python<'_>,
    config_json: &str,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: SecureReadProfileConfig = serde_json::from_str(config_json).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("invalid secure private read configuration")
    })?;
    let cancel = cancel_handle
        .map(|handle| handle.token.clone())
        .unwrap_or_default();
    Ok(py.allow_threads(move || {
        match SecurePrivateReadAccess::new(config).activate_and_read_json_with_cancel(&cancel) {
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
#[pyo3(signature = (operation, config_json, input_json=None, command_id=None, workspace_id=None, cancel_handle=None))]
fn secure_owner_create_json(
    py: Python<'_>,
    operation: &str,
    config_json: &str,
    input_json: Option<&str>,
    command_id: Option<&str>,
    workspace_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let operation = operation.to_owned();
    let config_json = config_json.to_owned();
    let input_json = input_json.map(str::to_owned);
    let command_id = command_id.map(str::to_owned);
    let workspace_id = workspace_id.map(str::to_owned);
    let cancel = cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default();
    Ok(py.allow_threads(move || {
        let config: SecureOwnerCreateConfig = match serde_json::from_str(&config_json) {
            Ok(value) => value,
            Err(_) => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner configuration"}).to_string(),
        };
        if matches!(operation.as_str(), "attach" | "resume_attachment" | "retain_pending_action" | "attachments" | "kernel_inspect" | "kernel_status" | "kernel_recover" | "stage_inspect" | "stage_multipart_inspect" | "stage_multipart_attach" | "stage_recover" | "orphan_inspect" | "orphan_multipart_inspect" | "orphan_multipart_attach" | "orphan_replan" | "direct_begin_inspect" | "direct_begin_attach" | "direct_begin_recover" | "direct_completed_inspect" | "direct_completed_attach" | "object_stage_inspect" | "object_stage_attach" | "object_stage_recover" | "object_intent_candidates" | "object_intent_inspect" | "object_intent_attach" | "object_intent_recover") {
            let access = SecureHistoricalOwnerAttach::new(config);
            let result = match operation.as_str() {
                "attach" => {
                    let input: HistoricalOwnerAttachInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner attachment input"}).to_string(),
                    };
                    access.attach(input, &cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                }
                "resume_attachment" => match command_id.as_deref() {
                    Some(id) => access.resume_attachment(id, &cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment ID is required"}).to_string(),
                },
                "retain_pending_action" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.retain_pending_action(attach_id, id, &cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and pending action command IDs are required"}).to_string(),
                },
                "attachments" => access.attachments().map(|value| serde_json::to_string(&value).expect("attachment history serializes")),
                "kernel_inspect" => {
                    let input: HistoricalOwnerAttachInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid kernel inspection input"}).to_string(),
                    };
                    access.inspect_kernel_pending(&input, &cancel).map(|value| serde_json::to_string(&value).expect("kernel inventory serializes"))
                }
                "kernel_status" => match command_id.as_deref() {
                    Some(attach_id) => access.kernel_command_status(attach_id).map(|value| serde_json::to_string(&value).expect("kernel status serializes")),
                    None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment ID is required"}).to_string(),
                },
                "kernel_recover" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_kernel_command(attach_id, id, &cancel).map(|value| serde_json::to_string(&value).expect("kernel recovery status serializes")),
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and kernel command IDs are required"}).to_string(),
                },
                "direct_begin_inspect" | "direct_begin_attach" | "direct_completed_inspect" | "direct_completed_attach" | "object_stage_inspect" | "object_stage_attach" | "object_intent_inspect" | "object_intent_attach" => {
                    let completed = operation.starts_with("direct_completed_");
                    let object_stage = operation.starts_with("object_stage_");
                    let marker_intent = operation.starts_with("object_intent_");
                    let selection_key = if marker_intent { "selected_marker_hash" } else if completed { "selected_instance_id" } else { "selected_command_id" };
                    let (input, selected, digest, options, material) = match direct_install_request(input_json.as_deref(), selection_key) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid direct install input"}).to_string(),
                    };
                    if operation.ends_with("_inspect") {
                        if digest.is_some() { return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"direct install inspection must not select a TS state digest"}).to_string(); }
                        if marker_intent {
                            access.inspect_object_stage_intent(&input, &selected, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("marker intent inventory serializes"))
                        } else if object_stage {
                            access.inspect_pending_object_stage(&input, &selected, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("object stage inventory serializes"))
                        } else if completed {
                            access.inspect_completed_direct_install(&input, &selected, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("completed direct inventory serializes"))
                        } else {
                            access.inspect_pending_direct_install_begin(&input, &selected, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("direct packet inventory serializes"))
                        }
                    } else {
                        let Some(digest) = digest else { return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"direct install attach requires inspected TS state digest"}).to_string(); };
                        if marker_intent {
                            access.attach_object_stage_intent(input, &selected, &digest, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                        } else if object_stage {
                            access.attach_pending_object_stage(input, &selected, &digest, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                        } else if completed {
                            access.attach_completed_direct_install(input, &selected, &digest, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                        } else {
                            access.attach_pending_direct_install_begin(input, &selected, &digest, &options, &material, &cancel)
                                .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                        }
                    }
                },
                "direct_begin_recover" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_pending_direct_install_begin(attach_id, id, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and selected direct packet IDs are required"}).to_string(),
                },
                "object_intent_candidates" => {
                    let input: HistoricalOwnerAttachInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid marker source input"}).to_string(),
                    };
                    if cancel.is_cancelled() { return serde_json::json!({"ok":false,"code":"CANCELLED","message":"cancelled"}).to_string(); }
                    access.object_stage_intent_candidates(&input).map(|value| serde_json::to_string(&value).expect("marker candidates serialize"))
                },
                "object_intent_recover" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(hash)) => access.recover_object_stage_intent(attach_id, hash, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment ID and selected marker hash are required"}).to_string(),
                },
                "object_stage_recover" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_pending_object_stage(attach_id, id, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and original object stage IDs are required"}).to_string(),
                },
                "stage_inspect" => {
                    let input: HistoricalOwnerAttachInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid package stage inspection input"}).to_string(),
                    };
                    access.inspect_pending_package_stage(&input, &cancel).map(|value| serde_json::to_string(&value).expect("package stage inventory serializes"))
                },
                "stage_multipart_inspect" => {
                    let (input, material) = match multipart_stage_request(input_json.as_deref()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart stage inspection input"}).to_string(),
                    };
                    access.inspect_pending_package_stage_with_material(&input, &material, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("package stage inventory serializes"))
                },
                "stage_multipart_attach" => {
                    let (input, material) = match multipart_stage_request(input_json.as_deref()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart stage attachment input"}).to_string(),
                    };
                    access.attach_pending_package_stage_with_material(input, &material, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                },
                "stage_recover" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => access.recover_pending_package_stage(attach_id, id, &cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes")),
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and package stage command IDs are required"}).to_string(),
                },
                "orphan_inspect" => {
                    let input: HistoricalOwnerAttachInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid orphan stage inspection input"}).to_string(),
                    };
                    access.inspect_orphan_package_stage(&input, &cancel).map(|value| serde_json::to_string(&value).expect("orphan stage inventory serializes"))
                },
                "orphan_multipart_inspect" => {
                    let (input, material) = match multipart_stage_request(input_json.as_deref()) {
                        Some((input, material)) if input.selected_pending_package_stage_command_id.is_none()
                            && input.selected_orphan_package_stage_command_id.is_none()
                            && input.expected_ts_state_digest.is_none() => (input, material),
                        _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart orphan inspection input"}).to_string(),
                    };
                    access.inspect_multipart_orphan_package_stage_with_material(&input, &material, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("orphan stage inventory serializes"))
                },
                "orphan_multipart_attach" => {
                    let (input, material) = match multipart_stage_request(input_json.as_deref()) {
                        Some((input, material)) if input.selected_pending_package_stage_command_id.is_none()
                            && input.selected_orphan_package_stage_command_id.is_some()
                            && input.expected_ts_state_digest.is_some() => (input, material),
                        _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid multipart orphan attachment input"}).to_string(),
                    };
                    access.attach_pending_package_stage_with_material(input, &material, &cancel)
                        .map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                },
                "orphan_replan" => match (workspace_id.as_deref(), command_id.as_deref()) {
                    (Some(attach_id), Some(id)) => {
                        let material: Option<String> = match input_json.as_deref() {
                            Some(wire) => match serde_json::from_str::<String>(wire) {
                                Ok(value) if !value.is_empty() => Some(value),
                                _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid orphan replan material"}).to_string(),
                            },
                            None => None,
                        };
                        access.replan_orphan_package_stage(attach_id, id, material.as_deref(), &cancel).map(|value| serde_json::to_string(&value).expect("attachment result serializes"))
                    }
                    _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"attachment and original stage command IDs are required"}).to_string(),
                },
                _ => unreachable!(),
            };
            return match result {
                Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
        }
        if matches!(operation.as_str(), "coordination_enable" | "coordination_resume" | "coordination_operations") {
            let input: Option<OwnerCoordinationEnableInput> = if operation == "coordination_enable" {
                match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                    Some(value) => Some(value),
                    None => { return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner coordination input"}).to_string(); },
                }
            } else { None };
            let Some(workspace) = workspace_id.as_deref() else {
                return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"workspace ID is required"}).to_string();
            };
            if operation == "coordination_resume" && command_id.is_none() {
                return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"original coordination BEGIN command ID is required"}).to_string();
            }
            let access = match SecureOwnerWorkspaceCreate::new(config).coordination_access(workspace) {
                Ok(value) => value,
                Err(error) => return serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
            let result = match operation.as_str() {
                "coordination_enable" => access.enable_json_with_cancel(input.expect("enable input parsed"), &cancel),
                "coordination_resume" => access.resume_json_with_cancel(command_id.as_deref().expect("BEGIN ID checked"), &cancel),
                "coordination_operations" => access.operations_json(),
                _ => unreachable!(),
            };
            return match result {
                Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
        }
        if matches!(operation.as_str(), "format_submit" | "format_resume" | "format_history") {
            let input: Option<OwnerFormatTransitionInput> = if operation == "format_submit" {
                match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                    Some(value) => Some(value),
                    None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner format transition input"}).to_string(),
                }
            } else { None };
            let selected_workspace = input.as_ref().map(|value| value.workspace_id.as_str())
                .or(workspace_id.as_deref());
            let Some(selected_workspace) = selected_workspace else {
                return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"workspace ID is required"}).to_string();
            };
            let access = match SecureOwnerWorkspaceCreate::new(config)
                .format_transition_access(selected_workspace) {
                Ok(value) => value,
                Err(error) => return serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
            let result = match operation.as_str() {
                "format_submit" => access.submit_json_with_cancel(input.expect("submit input parsed"), &cancel),
                "format_resume" => match command_id.as_deref() {
                    Some(id) => access.resume_json_with_cancel(id, &cancel),
                    None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"transition command ID is required"}).to_string(),
                },
                "format_history" => access.history_json(),
                _ => unreachable!(),
            };
            return match result {
                Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
                Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
            };
        }
        let access = SecureOwnerWorkspaceCreate::new(config);
        let result = match operation.as_str() {
            "prepare" | "create" => {
                let input: SecureOwnerCreateInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                    Some(value) => value,
                    None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"invalid Owner creation input"}).to_string(),
                };
                if operation == "prepare" { access.prepare(input, &cancel) } else { access.create(input, &cancel) }
                    .map(|value| serde_json::to_string(&value).expect("Owner result serializes"))
            }
            "resume" => match command_id.as_deref() {
                Some(id) => access.resume(id, &cancel).map(|value| serde_json::to_string(&value).expect("Owner result serializes")),
                None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"command ID is required"}).to_string(),
            },
            "operations" => access.operations().map(|value| serde_json::to_string(&value).expect("Owner result serializes")),
            "read" => match workspace_id.as_deref() {
                Some(id) => access.read_workspace_json(id, &cancel),
                None => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"workspace ID is required"}).to_string(),
            },
            _ => return serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"unsupported Owner operation"}).to_string(),
        };
        match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (kind, operation, config_json, workspace_id, input_json=None, command_id=None, cancel_handle=None))]
fn secure_owner_consumer_json(
    py: Python<'_>, kind: &str, operation: &str, config_json: &str,
    workspace_id: &str, input_json: Option<&str>, command_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let kind = kind.to_owned();
    let operation = operation.to_owned();
    let config_json = config_json.to_owned();
    let workspace_id = workspace_id.to_owned();
    let input_json = input_json.map(str::to_owned);
    let command_id = command_id.map(str::to_owned);
    let cancel = cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default();
    Ok(py.allow_threads(move || {
        let fail = |code: &str, message: &str| serde_json::json!({"ok":false,"code":code,"message":message}).to_string();
        let config: SecureOwnerCreateConfig = match serde_json::from_str(&config_json) {
            Ok(value) => value,
            Err(_) => return fail("INPUT_INVALID", "invalid Owner configuration"),
        };
        let owner = SecureOwnerWorkspaceCreate::new(config);
        let result = if kind == "public_action" {
            let access = match owner.public_action_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "submit" => {
                    let input: PublicActionInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("ACTION_INPUT_INVALID", "invalid Owner action input"),
                    };
                    access.submit_new_json_with_cancel(input, &cancel)
                }
                "reconcile" | "retry" => match command_id.as_deref() {
                    Some(id) if operation == "reconcile" => access.reconcile_json_with_cancel(id, &cancel),
                    Some(id) => access.retry_saved_json_with_cancel(id, &cancel),
                    None => return fail("ACTION_INPUT_INVALID", "command ID is required"),
                },
                "pending" => access.list_pending_json_with_cancel(&cancel),
                _ => return fail("ACTION_INPUT_INVALID", "unsupported Owner action operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if kind == "private_action" {
            let access = match owner.private_action_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "submit" => {
                    let input: PublicActionInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("ACTION_INPUT_INVALID", "invalid Owner action input"),
                    };
                    access.submit_new_json_with_cancel(input, &cancel)
                }
                "reconcile" | "retry" => match command_id.as_deref() {
                    Some(id) if operation == "reconcile" => access.reconcile_json_with_cancel(id, &cancel),
                    Some(id) => access.retry_saved_json_with_cancel(id, &cancel),
                    None => return fail("ACTION_INPUT_INVALID", "command ID is required"),
                },
                "pending" => access.list_pending_json_with_cancel(&cancel),
                _ => return fail("ACTION_INPUT_INVALID", "unsupported Owner action operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if kind == "public_install" {
            let access = match owner.public_install_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "begin" => {
                    let input: PublicPackageInstallInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("INSTALL_INPUT_INVALID", "invalid Owner package input"),
                    };
                    access.submit_begin_json_with_cancel(input, &cancel)
                }
                "continue" => match command_id.as_deref() {
                    Some(id) => access.continue_install_json_with_cancel(id, &cancel),
                    None => return fail("INSTALL_INPUT_INVALID", "begin command ID is required"),
                },
                "pending" => access.list_pending_json_with_cancel(&cancel),
                _ => return fail("INSTALL_INPUT_INVALID", "unsupported Owner install operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if kind == "private_stage" {
            let access = match owner.private_install_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "stage" => {
                    let input: PrivatePackageStageInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("INSTALL_INPUT_INVALID", "invalid PRIVATE stage input"),
                    };
                    access.stage_package_json_with_cancel(input, &cancel)
                }
                "continue" => match command_id.as_deref() {
                    Some(id) => access.continue_stage_json_with_cancel(id, &cancel),
                    None => return fail("INSTALL_INPUT_INVALID", "stage ID is required"),
                },
                "stages" => access.stages_json(),
                _ => return fail("INSTALL_INPUT_INVALID", "unsupported PRIVATE stage operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if kind == "private_install" {
            let access = match owner.private_install_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "begin" => {
                    let input: PrivatePackageInstallBeginInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("INSTALL_INPUT_INVALID", "invalid PRIVATE install input"),
                    };
                    access.submit_begin_json_with_cancel(input, &cancel)
                }
                "begin_direct" => {
                    let input: PrivateDirectInstallBeginInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("INSTALL_INPUT_INVALID", "invalid PRIVATE direct install input"),
                    };
                    access.submit_direct_begin_json_with_cancel(input, &cancel)
                }
                "continue" => match command_id.as_deref() {
                    Some(id) => access.continue_install_json_with_cancel(id, &cancel),
                    None => return fail("INSTALL_INPUT_INVALID", "begin command ID is required"),
                },
                "installs" => access.installs_json(),
                _ => return fail("INSTALL_INPUT_INVALID", "unsupported PRIVATE install operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if kind == "public_admission" {
            let access = match owner.public_admission_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "offer" => {
                    let input: PublicOfferInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("ADMISSION_INPUT_INVALID", "invalid Owner offer input"),
                    };
                    access.submit_offer_json_with_cancel(input, &cancel)
                }
                "retry_offer" => match command_id.as_deref() {
                    Some(id) => access.retry_offer_json_with_cancel(id, &cancel),
                    None => return fail("ADMISSION_INPUT_INVALID", "invite ID is required"),
                },
                "pending_offers" => access.pending_offers_json(),
                "deliver" => match command_id.as_deref() {
                    Some(id) => access.deliver_accepted_json_with_cancel(id, &cancel),
                    None => return fail("ADMISSION_INPUT_INVALID", "invite ID is required"),
                },
                "retry_delivery" => match command_id.as_deref() {
                    Some(id) => access.retry_delivery_json_with_cancel(id, &cancel),
                    None => return fail("ADMISSION_INPUT_INVALID", "grant ID is required"),
                },
                "pending_deliveries" => access.pending_deliveries_json(),
                _ => return fail("ADMISSION_INPUT_INVALID", "unsupported Owner admission operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else if kind == "private_admission" {
            let access = match owner.private_admission_access(&workspace_id) {
                Ok(value) => value,
                Err(error) => return fail(error.code(), &error.to_string()),
            };
            match operation.as_str() {
                "offer" => {
                    let input: PublicOfferInput = match input_json.as_deref().and_then(|wire| serde_json::from_str(wire).ok()) {
                        Some(value) => value,
                        None => return fail("ADMISSION_INPUT_INVALID", "invalid Owner offer input"),
                    };
                    access.submit_offer_json_with_cancel(input, &cancel)
                }
                "retry_offer" => match command_id.as_deref() {
                    Some(id) => access.retry_offer_json_with_cancel(id, &cancel),
                    None => return fail("ADMISSION_INPUT_INVALID", "invite ID is required"),
                },
                "pending_offers" => access.pending_offers_json(),
                "deliver" => match command_id.as_deref() {
                    Some(id) => access.deliver_accepted_json_with_cancel(id, &cancel),
                    None => return fail("ADMISSION_INPUT_INVALID", "invite ID is required"),
                },
                "retry_delivery" => match command_id.as_deref() {
                    Some(id) => access.retry_delivery_json_with_cancel(id, &cancel),
                    None => return fail("ADMISSION_INPUT_INVALID", "grant ID is required"),
                },
                "pending_deliveries" => access.pending_deliveries_json(),
                _ => return fail("ADMISSION_INPUT_INVALID", "unsupported Owner admission operation"),
            }.map_err(|error| (error.code(), error.to_string()))
        } else {
            return fail("INPUT_INVALID", "unsupported Owner consumer");
        };
        match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err((code, message)) => fail(code, &message),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, query=None, after=None, limit=None, digest=None, cancel_handle=None))]
fn public_catalog_json(
    py: Python<'_>, operation: &str, config_json: &str,
    query: Option<&str>, after: Option<&str>, limit: Option<u8>, digest: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    let config: PublicCatalogConfig = serde_json::from_str(config_json)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid catalog configuration"))?;
    let operation = operation.to_owned();
    let query = query.map(str::to_owned);
    let after = after.map(str::to_owned);
    let digest = digest.map(str::to_owned);
    let cancel = cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default();
    Ok(py.allow_threads(move || {
        let catalog = PublicCatalog::new(config);
        let result = match operation.as_str() {
            "search" => catalog.search(query.as_deref().unwrap_or(""), after.as_deref(), limit.unwrap_or(20), &cancel)
                .map(|value| serde_json::to_string(&value).expect("catalog result serializes")),
            "inspect" => catalog.inspect_exact(digest.as_deref().unwrap_or(""), &cancel)
                .map(|value| serde_json::to_string(&value).expect("catalog result serializes")),
            _ => return serde_json::json!({"ok":false,"code":"CATALOG_INPUT_INVALID","message":"unsupported catalog operation"}).to_string(),
        };
        match result {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
            Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
        }
    }))
}

#[pyfunction]
#[pyo3(signature = (operation, origin, state_dir, allow_loopback_http=false, cancel_handle=None, mode=None, expected_certificate_hash=None, update_id=None, transport_json=None))]
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
    transport_json: Option<&str>,
) -> PyResult<String> {
    let mut config =
        RecipientEnrollmentConfig::for_state_dir(origin.to_owned(), Path::new(state_dir));
    config.allow_loopback_http = allow_loopback_http;
    config.transport = transport_json.map(serde_json::from_str).transpose().map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid transport options"))?.unwrap_or_default();
    config.transport.validate().map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid transport options"))?;
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
                (Some(mode), Some(hash)) => match access.update_key_with_cancel(mode, hash, update_id.as_deref(), &cancel) {
                    Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
                    Err(error) => serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()}).to_string(),
                },
                _ => serde_json::json!({"ok":false,"code":"INPUT_INVALID","message":"mode and expected certificate hash are required"}).to_string(),
            };
        }
        if operation == "retry_key_update" {
            return match update_id.as_deref() {
                Some(id) => match access.retry_key_update_with_cancel(id, &cancel) {
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
        if operation == "key_updates" {
            return match access.key_updates() {
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
#[pyo3(signature = (origin, state_dir, identity_path, target_actor_id, target_signing_key_id, allow_loopback_http=false, cancel_handle=None, transport_json=None))]
fn secure_identity_directory_json(
    py: Python<'_>,
    origin: &str,
    state_dir: &str,
    identity_path: &str,
    target_actor_id: &str,
    target_signing_key_id: &str,
    allow_loopback_http: bool,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
    transport_json: Option<&str>,
) -> PyResult<String> {
    let config = IdentityDirectoryConfig {
            transport: transport_json.map(serde_json::from_str).transpose().map_err(|_| pyo3::exceptions::PyValueError::new_err("invalid transport options"))?.unwrap_or_default(),
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

#[pyfunction]
#[pyo3(signature = (operation, config_json, input_json=None))]
fn acquisition_observations_json(py: Python<'_>, operation: String, config_json: String,
    input_json: Option<String>) -> String {
    py.allow_threads(move || peerwork_runtime::acquisition::acquisition_json(
        &operation, &config_json, input_json.as_deref()))
}

#[pymodule]
fn _peerwork_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(acquisition_observations_json, module)?)?;
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(capabilities_json, module)?)?;
    module.add_function(wrap_pyfunction!(load_config_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_create_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_open_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_seed_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_pkcs8_pem_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_owner_pem_json, module)?)?;
    module.add_function(wrap_pyfunction!(kernel_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_read_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_read_profile_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_private_read_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_action_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_install_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_owner_create_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_owner_consumer_json, module)?)?;
    module.add_function(wrap_pyfunction!(public_catalog_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_recipient_enrollment_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_identity_directory_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_admission_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_decision_json, module)?)?;
    module.add_class::<KernelCancelHandle>()?;
    Ok(())
}
