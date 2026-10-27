use peerwork_runtime::kernel_access::KernelAccess;
use peerwork_runtime::kernel_client::{KernelAcceptedResult, KernelOperationStatus};
use peerwork_runtime::kernel_identity::KernelIdentity;
use peerwork_runtime::secure_action_access::{
    PublicActionInput, SecurePrivateActionAccess, SecurePublicActionAccess,
};
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
fn prepare_owner_checkpoint_json(py:Python<'_>,request:String)->String{
    py.allow_threads(move||peerwork_runtime::owner_checkpoint::prepare_owner_checkpoint_json(&request))
}

#[pyfunction]
fn inspect_owner_cache_json(py:Python<'_>,request:String)->String{
    py.allow_threads(move||peerwork_runtime::owner_cache_review::inspect_owner_cache_json(&request))
}

#[pyfunction]
fn plan_owner_checkpoint_from_cache_json(py:Python<'_>,request:String)->String{py.allow_threads(move||peerwork_runtime::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&request))}
#[pyfunction]
fn prepare_owner_checkpoint_from_cache_json(py:Python<'_>,request:String)->String{py.allow_threads(move||peerwork_runtime::owner_cache_checkpoint::prepare_owner_checkpoint_from_cache_json(&request))}

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
    Err(pyo3::exceptions::PyRuntimeError::new_err("LEGACY_MODE_RETIRED: select an explicit identity seed or PKCS8 PEM file"))
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
    if !peerwork_runtime::runtime_contract::supports_kernel_operation(operation){return Ok(peerwork_runtime::runtime_contract::retired_json());}
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
            "pending_page" => access.pending_page_json_with_cancel(command_json.as_deref().unwrap_or("{}"),&cancel)?,
            "request_access" => access.request_access_json(command_json.as_deref().unwrap_or("{}"),&cancel)?,
            "accept_content_keys" => access.accept_content_keys_json(command_json.as_deref().unwrap_or("{}"),&cancel)?,
            "ensure_local_content_key" => access.ensure_local_content_key_json(command_json.as_deref().unwrap_or("{}"),&cancel)?,
            "build_pending_index" => serde_json::json!(access.build_pending_index_with_cancel(&cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)?),
            "status" => {
                let id = command_id.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                match access.status_with_cancel(id, &cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)? {
                    None => serde_json::json!({"state": "NOT_FOUND"}),
                    Some(KernelOperationStatus::Pending) => serde_json::json!({"state": "PENDING"}),
                    Some(KernelOperationStatus::Accepted(accepted)) => serde_json::json!({"state":accepted.outcome_state(),"result":accepted_json(accepted)}),
                }
            }
            "execute_structure_intent" | "migrate_archive" | "publish_selected_record" | "authorize_access" | "rotate_content_key" | "coordinate_content_keys" => {
                let intent = command_json.as_deref().ok_or_else(|| peerwork_runtime::kernel_access::KernelPublicError::from("business intent is required"))?;
                match (if operation=="coordinate_content_keys"{access.coordinate_content_keys_json(intent,&cancel)}else if operation=="rotate_content_key"{access.rotate_content_key_json(intent,&cancel)}else{(if operation=="migrate_archive"{access.migrate_archive_with_cancel(intent.as_bytes(),&cancel)}else if operation=="publish_selected_record"{access.publish_selected_record_with_cancel(intent.as_bytes(),&cancel)}else if operation=="authorize_access"{access.authorize_access_with_cancel(intent.as_bytes(),&cancel)}else{access.execute_structure_intent_with_cancel(intent.as_bytes(),&cancel)}).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)})? {
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Accepted(result) => serde_json::json!({"state":result.outcome_state(),"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Completed{command_id,result}=>serde_json::json!({"state":"COMPLETED","command_id":command_id,"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Pending {command_id,code,phase,retryable,recovery} =>
                        serde_json::json!({"state":"PENDING","command_id":command_id,"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"effect_certainty":if phase=="KEY_DELIVERY"{"COMMITTED"}else if phase=="PREPARATION"{"NOT_SUBMITTED"}else{"UNKNOWN"}}),
                }
            }
            "resume_structure_intent" => {
                let id=command_id.as_deref().ok_or_else(||peerwork_runtime::kernel_access::KernelPublicError::from("command ID is required"))?;
                match access.resume_structure_intent_with_cancel(id,&cancel).map_err(peerwork_runtime::kernel_access::KernelPublicError::from)? {
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Accepted(result)=>serde_json::json!({"state":result.outcome_state(),"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Completed{command_id,result}=>serde_json::json!({"state":"COMPLETED","command_id":command_id,"result":accepted_json(result)}),
                    peerwork_runtime::kernel_client::StructureIntentOutcome::Pending{command_id,code,phase,retryable,recovery}=>
                        serde_json::json!({"state":"PENDING","command_id":command_id,"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"effect_certainty":if phase=="KEY_DELIVERY"{"COMMITTED"}else if phase=="PREPARATION"{"NOT_SUBMITTED"}else{"UNKNOWN"}}),
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (config_json, cancel_handle=None))]
fn secure_read_profile_json(
    py: Python<'_>,
    config_json: &str,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (config_json, cancel_handle=None))]
fn secure_private_read_json(
    py: Python<'_>,
    config_json: &str,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    Ok(peerwork_runtime::runtime_contract::retired_json())
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, input_json=None, command_id=None, operation_id=None, cancel_handle=None))]
fn secure_private_action_json(
    py: Python<'_>,
    operation: &str,
    config_json: &str,
    input_json: Option<&str>,
    command_id: Option<&str>,
    operation_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    Ok(peerwork_runtime::runtime_contract::retired_json())
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (kind, operation, config_json, workspace_id, input_json=None, command_id=None, cancel_handle=None, operation_id=None))]
fn secure_owner_consumer_json(
    py: Python<'_>, kind: &str, operation: &str, config_json: &str,
    workspace_id: &str, input_json: Option<&str>, command_id: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>, operation_id: Option<&str>,
) -> PyResult<String> {
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, query=None, after=None, limit=None, digest=None, cancel_handle=None))]
fn public_catalog_json(
    py: Python<'_>, operation: &str, config_json: &str,
    query: Option<&str>, after: Option<&str>, limit: Option<u8>, digest: Option<&str>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> PyResult<String> {
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (operation, origin, state_dir, allow_loopback_http=false, cancel_handle=None, mode=None, expected_certificate_hash=None, update_id=None, transport_json=None, input_json=None))]
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
    input_json: Option<&str>,
) -> PyResult<String> {
    Ok(peerwork_runtime::runtime_contract::retired_json())
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
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
    Ok(peerwork_runtime::runtime_contract::retired_json())
}

#[pyfunction]
#[pyo3(signature = (operation, config_json, input_json=None))]
fn acquisition_observations_json(py: Python<'_>, operation: String, config_json: String,
    input_json: Option<String>) -> String {
    peerwork_runtime::runtime_contract::retired_json()
}

#[pyfunction]
#[pyo3(signature = (operation, profile_path, expected_actor, expected_service, request_json=None, cancel_handle=None))]
fn agent_context_json(
    py: Python<'_>, operation: String, profile_path: String,
    expected_actor: String, expected_service: String, request_json: Option<String>,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> String {
    let cancel = cancel_handle.map(|handle| handle.token.clone()).unwrap_or_default();
    py.allow_threads(move || peerwork_runtime::agent_context::agent_context_json(
        &operation, Path::new(&profile_path), &expected_actor, &expected_service,
        request_json.as_deref(), &cancel))
}

#[pyfunction]
#[pyo3(signature = (operation, input_json, cancel_handle=None))]
fn navigation_json(py: Python<'_>, operation: String, input_json: String,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>) -> String {
    let cancel=cancel_handle.map(|h|h.token.clone()).unwrap_or_default();
    py.allow_threads(move || peerwork_runtime::changelog::navigation_json(&operation,&input_json,&cancel))
}

#[pyfunction]
#[pyo3(signature = (input_json, cancel_handle=None))]
fn read_view_json(py: Python<'_>, input_json: String,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>) -> String {
    peerwork_runtime::runtime_contract::retired_json()
}

#[pyfunction]
#[pyo3(signature = (input_json, cancel_handle=None))]
fn private_read_view_json(py: Python<'_>, input_json: String,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>) -> String {
    peerwork_runtime::runtime_contract::retired_json()
}

#[pyfunction]
#[pyo3(signature = (input_json, cancel_handle=None))]
fn current_page_json(py: Python<'_>, input_json: String,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>) -> String {
    peerwork_runtime::runtime_contract::retired_json()
}

#[pyfunction]
#[pyo3(signature = (config_json, operation, input_json, cancel_handle=None))]
fn owner_guard_time_json(
    py: Python<'_>,
    config_json: String,
    operation: String,
    input_json: String,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> String {
    peerwork_runtime::runtime_contract::retired_json()
}

#[pyfunction]
#[pyo3(signature = (config_json, operation, input_json, cancel_handle=None))]
fn owner_member_scopes_json(
    py: Python<'_>,
    config_json: String,
    operation: String,
    input_json: String,
    cancel_handle: Option<PyRef<'_, KernelCancelHandle>>,
) -> String {
    peerwork_runtime::runtime_contract::retired_json()
}

#[pymodule]
fn _peerwork_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(protocol_bundle_inspect_json, module)?)?;
    module.add_function(wrap_pyfunction!(protocol_workbench_json, module)?)?;
    module.add_function(wrap_pyfunction!(owner_guard_time_json, module)?)?;
    module.add_function(wrap_pyfunction!(owner_member_scopes_json, module)?)?;
    module.add_function(wrap_pyfunction!(current_page_json, module)?)?;
    module.add_function(wrap_pyfunction!(read_view_json, module)?)?;
    module.add_function(wrap_pyfunction!(private_read_view_json, module)?)?;
    module.add_function(wrap_pyfunction!(navigation_json, module)?)?;
    module.add_function(wrap_pyfunction!(acquisition_observations_json, module)?)?;
    module.add_function(wrap_pyfunction!(agent_context_json, module)?)?;
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(capabilities_json, module)?)?;
    module.add_function(wrap_pyfunction!(load_config_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_create_json, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_owner_checkpoint_json, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_owner_cache_json, module)?)?;
    module.add_function(wrap_pyfunction!(plan_owner_checkpoint_from_cache_json, module)?)?;
    module.add_function(wrap_pyfunction!(prepare_owner_checkpoint_from_cache_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_open_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_seed_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_pkcs8_pem_json, module)?)?;
    module.add_function(wrap_pyfunction!(identity_import_owner_pem_json, module)?)?;
    module.add_function(wrap_pyfunction!(kernel_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_read_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_read_profile_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_private_read_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_public_action_json, module)?)?;
    module.add_function(wrap_pyfunction!(secure_private_action_json, module)?)?;
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

#[pyfunction]
#[pyo3(signature = (operation, input_json, cancel_handle=None))]
fn protocol_workbench_json(py:Python<'_>,operation:String,input_json:String,
    cancel_handle:Option<PyRef<'_,KernelCancelHandle>>)->String {
    let cancel=cancel_handle.map(|h|h.token.clone()).unwrap_or_default();
    py.allow_threads(move||peerwork_runtime::protocol_workbench::workbench_json(&operation,&input_json,&cancel))
}

#[pyfunction]
fn protocol_bundle_inspect_json(input_json:String)->String{
 let result=peerwork_core::strict_json::parse_strict_json(input_json.as_bytes()).ok().and_then(|v|peerwork_core::protocol_bundle::inspect(&v).ok());
 match result{Some(value)=>serde_json::json!({"ok":true,"value":value}),None=>serde_json::json!({"ok":false,"code":"PROTOCOL_BUNDLE_INVALID","message":"invalid or oversized protocol bundle"})}.to_string()
}
