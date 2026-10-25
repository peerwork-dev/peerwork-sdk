//! Existing-profile adapter. Opening is offline and never creates state or locks.
//! This is a scoped PRIVATE facade, not admission, approval, or a polling runtime.
use crate::{
    secure_action_access::{PublicActionInput, SecurePrivateActionAccess},
    secure_intents::SecureIntentJournal,
    secure_private_read_access::SecurePrivateReadAccess,
    secure_read_profile::SecureReadProfileConfig,
    secure_state::{check_private_directory, read_private_file_bounded},
};
use peerwork_core::crypto::sha256_hex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
#[path = "agent_structure_context.rs"]
mod structure;
const MAGIC: &[u8] = b"PEERWORK-NATIVE-SECURE-STATE\n1\n";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    service_id: String,
    origin: String,
    identity_path: PathBuf,
    #[serde(default)]
    allow_loopback_http: bool,
    workspaces: BTreeMap<String, Workspace>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workspace {
    profile_path: PathBuf,
    #[serde(default = "private")]
    visibility: String,
}
fn private() -> String {
    "PRIVATE".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    expected_fingerprint: Option<String>,
    workspace_id: String,
    operation_id: Option<String>,
    command_id: Option<String>,
    intent: Option<Value>,
    recovery: Option<RecoveryOptions>,
    workbench_input: Option<String>,
    query: Option<crate::agent_discovery::DiscoveryQuery>,
    consumer_id: Option<String>,
    filter_version: Option<String>,
    lease_ms: Option<u64>,
    wait_ms: Option<u64>,
    ack_token: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryOptions {
    mode: String,
    #[serde(default)] max_submissions: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    kind: String,
    instance_id: String,
    action_id: String,
    values: Value,
    refs: Option<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserIntent {
    kind: String,
    reference: String,
    #[serde(default)]
    approve_writes: bool,
}
struct Context {
    descriptor: Value,
    actor: String,
    profiles: BTreeMap<String, SecureReadProfileConfig>,
}
#[derive(Debug)]
struct Error {
    code: String,
    message: String,
    layer: &'static str,
    certainty: &'static str,
}
type Result<T> = std::result::Result<T, Error>;
fn error(code: &str, message: &str) -> Error {
    Error {
        code: code.into(),
        message: message.into(),
        layer: "context",
        certainty: "not_sent",
    }
}
fn runtime_error(code: &str, message: String) -> Error {
    Error {
        code: code.into(),
        message,
        layer: "runtime",
        certainty: "unknown",
    }
}
fn path(path: &Path, base: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(error("CONTEXT_PATH", "empty reference"));
    }
    let joined = if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                return Err(error("CONTEXT_PATH", "parent traversal is forbidden"))
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    if !out.is_absolute() {
        return Err(error("CONTEXT_PATH", "absolute reference required"));
    }
    Ok(out)
}
fn origin(value: &str, allow_loopback_http: bool) -> Result<String> {
    let u = reqwest::Url::parse(value)
        .map_err(|_| error("CONTEXT_ORIGIN", "invalid service origin"))?;
    let local_http = allow_loopback_http
        && u.scheme() == "http"
        && matches!(
            u.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
    if (u.scheme() != "https" && !local_http)
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(error("CONTEXT_ORIGIN", "HTTPS origin required"));
    }
    Ok(u.to_string())
}
fn raw(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    read_private_file_bounded(path, max)
        .map_err(|_| error("CONTEXT_STATE", "missing or unsafe protected reference"))
}
fn state(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = raw(path, max + MAGIC.len())?;
    Ok(Zeroizing::new(
        bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| error("CONTEXT_STATE", "unsupported native state format"))?
            .to_vec(),
    ))
}
// Shared decoder preserves native identity compatibility without creating locks.
fn identity(path: &Path) -> Result<(String, String)> {
    let identity = crate::kernel_identity::KernelIdentity::inspect_existing(path).map_err(|e| {
        error(
            e.code(),
            "existing native identity is missing, unsafe or invalid",
        )
    })?;
    Ok((identity.actor_id().to_owned(), identity.key_id().to_owned()))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| error("CONTEXT_BINDING", "missing saved binding"))
}
fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if b.len() < n {
        return Err(error("CONTEXT_STATE", "truncated key history"));
    }
    let (a, r) = b.split_at(n);
    *b = r;
    Ok(a)
}
fn validate_lifecycle(config: &SecureReadProfileConfig, actor: &str) -> Result<()> {
    let bytes = state(&config.state_dir.join("lifecycle.state"), 300_000)?;
    let mut b = bytes
        .strip_prefix(b"PEERWORK-SECURE-KEYRING\n1\n")
        .ok_or_else(|| error("CONTEXT_STATE", "invalid key history"))?;
    let canonical_origin=reqwest::Url::parse(&config.origin).map_err(|_|error("CONTEXT_BINDING","invalid saved origin"))?;
    for expected in [
        canonical_origin.as_str(),
        actor,
        config.workspace_id.as_str(),
        config.owner_actor_id.as_deref().unwrap_or(""),
        config.owner_key_id.as_deref().unwrap_or(""),
    ] {
        let n = u16::from_be_bytes(take(&mut b, 2)?.try_into().unwrap()) as usize;
        if take(&mut b, n)? != expected.as_bytes() {
            return Err(error(
                "CONTEXT_BINDING",
                "key history belongs to another context",
            ));
        }
    }
    for _ in 0..2 {
        match take(&mut b, 1)?[0] {
            0 => {}
            1 => {
                let n = u32::from_be_bytes(take(&mut b, 4)?.try_into().unwrap()) as usize;
                let ring =
                    peerwork_core::secure_keyring::SecretKeyring::parse_wire(take(&mut b, n)?)
                        .map_err(|_| error("CONTEXT_STATE", "invalid key history"))?;
                if ring.workspace_id() != config.workspace_id {
                    return Err(error("CONTEXT_BINDING", "key history workspace mismatch"));
                }
            }
            _ => return Err(error("CONTEXT_STATE", "invalid key history")),
        }
    }
    if !b.is_empty() {
        return Err(error("CONTEXT_STATE", "trailing key history"));
    }
    Ok(())
}
fn load(profile_path: &Path, expected_actor: &str, expected_service: &str) -> Result<Context> {
    let cwd = std::env::current_dir()
        .map_err(|_| error("CONTEXT_PATH", "current directory unavailable"))?;
    let selected = path(profile_path, &cwd)?;
    let cfg: Config = serde_json::from_slice(&raw(&selected, 64 * 1024)?)
        .map_err(|_| error("CONTEXT_CONFIG", "invalid context schema"))?;
    validate_config(&selected, cfg, expected_actor, expected_service)
}
fn validate_config(
    selected: &Path,
    cfg: Config,
    expected_actor: &str,
    expected_service: &str,
) -> Result<Context> {
    let parent = selected
        .parent()
        .ok_or_else(|| error("CONTEXT_PATH", "profile parent missing"))?;
    if cfg.schema != "peerwork.agent-context.v1" || cfg.service_id.is_empty() {
        return Err(error("CONTEXT_CONFIG", "unsupported context schema"));
    }
    if expected_service.is_empty() || expected_service != cfg.service_id {
        return Err(error(
            "CONTEXT_SERVICE",
            "selected service differs from expected service",
        ));
    }
    let canonical_origin = origin(&cfg.origin, cfg.allow_loopback_http)?;
    let identity_path = path(&cfg.identity_path, parent)?;
    let (actor, key) = identity(&identity_path)?;
    if expected_actor.is_empty() || expected_actor != actor {
        return Err(error(
            "CONTEXT_ACTOR",
            "selected identity differs from expected actor",
        ));
    }
    let mut profiles = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    for (workspace, reference) in cfg.workspaces {
        if reference.visibility != "PRIVATE" {
            return Err(error(
                "UNSUPPORTED_VISIBILITY",
                "only PRIVATE existing profiles are supported",
            ));
        }
        let file = path(&reference.profile_path, parent)?;
        let mut c: SecureReadProfileConfig = serde_json::from_slice(&raw(&file, 64 * 1024)?)
            .map_err(|_| error("CONTEXT_CONFIG", "invalid workspace profile"))?;
        let base = file.parent().unwrap();
        c.identity_path = path(&c.identity_path, base)?;
        c.state_dir = path(&c.state_dir, base)?;
        if c.identity_path != identity_path
            || identity(&c.identity_path)?.0 != actor
            || c.workspace_id != workspace
            || origin(&c.origin, c.allow_loopback_http)? != canonical_origin
            || c.allow_loopback_http != cfg.allow_loopback_http
        {
            return Err(error(
                "CONTEXT_BINDING",
                "workspace identity, service or workspace differs",
            ));
        }
        check_private_directory(&c.state_dir).map_err(|_| {
            error(
                "CONTEXT_STATE",
                "workspace state must already exist and be protected",
            )
        })?;
        c.transport
            .validate()
            .map_err(|_| error("CONTEXT_CONFIG", "invalid transport configuration"))?;
        for ca in &mut c.transport.additional_root_pem_files {
            *ca = path(ca, base)?;
        }
        let saved: Value =
            serde_json::from_slice(&state(&c.state_dir.join("read.profile"), 16 * 1024)?)
                .map_err(|_| error("CONTEXT_STATE", "invalid saved profile"))?;
        if saved["version"] != 1
            || text(&saved, "origin")? != c.origin
            || Path::new(text(&saved, "identity_path")?) != c.identity_path
            || text(&saved, "workspace_id")? != workspace
            || saved["required_features"] != json!(c.required_features)
            || saved["allow_loopback_http"] != json!(c.allow_loopback_http)
        {
            return Err(error(
                "CONTEXT_BINDING",
                "saved profile differs from selected context",
            ));
        }
        for (name, pin) in [
            ("owner_actor_id", &mut c.owner_actor_id),
            ("owner_key_id", &mut c.owner_key_id),
            ("authority", &mut c.authority),
        ] {
            let saved_pin = text(&saved, name)?;
            if pin.as_deref().is_some_and(|v| v != saved_pin) {
                return Err(error("CONTEXT_BINDING", "saved owner or authority differs"));
            }
            *pin = Some(saved_pin.into());
        }
        validate_lifecycle(&c, &actor)?;
        bindings.insert(workspace.clone(),json!({"profile_path":file,"identity_path":c.identity_path,"state_dir":c.state_dir,"origin":c.origin,"owner_actor_id":c.owner_actor_id,"owner_key_id":c.owner_key_id,"authority":c.authority,"required_features":c.required_features,"allow_loopback_http":c.allow_loopback_http,"transport":c.transport}));
        profiles.insert(workspace, c);
    }
    let mut descriptor = json!({"schema":"peerwork.agent-context.v1","service_id":cfg.service_id,"origin":canonical_origin,"allow_loopback_http":cfg.allow_loopback_http,"actor_id":actor,"key_id":key,"workspaces":profiles.keys().collect::<Vec<_>>(),"trust":"existing-profile-pins","events":{"source":"action_receipts_only","sync":"full_history_replay","incremental":false,"delivery":"at_least_once","task_completion":false}});
    // Stable selectors only: journal cursors and key-history rotations must not
    // invalidate a handle. Hash paths privately; never return them in the DTO.
    let fingerprint_input = json!({"descriptor":descriptor,"context_path":selected,"identity_path":identity_path,"bindings":bindings});
    descriptor["fingerprint"] = json!(sha256_hex(canonical(&fingerprint_input).as_bytes()));
    // Add evolving capability descriptions after hashing the frozen v1
    // binding projection: upgrading producers must preserve pending recovery.
    descriptor["discovery"] = json!({"schema":"peerwork.agent-discovery.v1","operations":["discover","describe"],"verification":"authenticated_full_replay","execution":"not_evaluated"});
    descriptor["producers"] = json!(["protocol.action", "browser.approve"]);
    // Capability metadata must not alter the frozen context binding.
    descriptor["events"]["platform_supported"] = json!(cfg!(unix));
    Ok(Context {
        descriptor,
        actor,
        profiles,
    })
}
fn canonical(value: &Value) -> String {
    // explicit recursive key ordering, independent of serde map features
    match value {
        Value::Object(m) => {
            let ordered: BTreeMap<_, _> = m.iter().collect();
            format!(
                "{{{}}}",
                ordered
                    .into_iter()
                    .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => value.to_string(),
    }
}
fn input(intent: Intent) -> Result<PublicActionInput> {
    if intent.kind != "protocol.action" {
        return Err(error(
            "UNSUPPORTED_PRODUCER",
            "only protocol.action is supported",
        ));
    }
    if intent.instance_id.is_empty()
        || intent.action_id.is_empty()
        || !intent.values.is_object()
        || intent.refs.as_ref().is_some_and(|v| !v.is_array())
    {
        return Err(error(
            "ACTION_INPUT_INVALID",
            "object values and array refs are required",
        ));
    }
    Ok(PublicActionInput {
        action_id: intent.action_id,
        instance_id: intent.instance_id,
        body_json: canonical(&intent.values),
        exact_input_refs_json: Some(canonical(&intent.refs.unwrap_or(json!([])))),
        allocations_json: None,
        command_id: None,
        issued_at_ms: None,
    })
}
fn decode(wire: String) -> Result<Value> {
    serde_json::from_str(&wire)
        .map_err(|_| runtime_error("RESULT_ENCODING", "invalid native result".into()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindRequest {
    workspace_profiles: Vec<PathBuf>,
}
fn bind(
    target: &Path,
    actor: &str,
    service: &str,
    request: Option<&str>,
    cancel: &CancellationToken,
) -> Result<Value> {
    let wire = request
        .filter(|v| v.len() <= 64 * 1024)
        .ok_or_else(|| error("REQUEST_INVALID", "bounded bind request required"))?;
    let request: BindRequest = serde_json::from_str(wire)
        .map_err(|_| error("REQUEST_INVALID", "workspace_profiles array required"))?;
    if request.workspace_profiles.is_empty() || request.workspace_profiles.len() > 128 {
        return Err(error(
            "REQUEST_INVALID",
            "bind requires 1 to 128 existing profiles",
        ));
    }
    let cwd = std::env::current_dir()
        .map_err(|_| error("CONTEXT_PATH", "current directory unavailable"))?;
    let target = path(target, &cwd)?;
    let parent = target
        .parent()
        .ok_or_else(|| error("CONTEXT_PATH", "target parent missing"))?;
    check_private_directory(parent)
        .map_err(|_| error("CONTEXT_STATE", "target parent must already be protected"))?;
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(error(
            "CONTEXT_EXISTS",
            "context already exists; reopen it explicitly",
        ));
    }
    let mut workspaces = serde_json::Map::new();
    let mut first = None;
    for reference in request.workspace_profiles {
        let file = path(&reference, parent)?;
        let config: SecureReadProfileConfig = serde_json::from_slice(&raw(&file, 64 * 1024)?)
            .map_err(|_| error("CONTEXT_CONFIG", "invalid workspace profile"))?;
        let identity = path(&config.identity_path, file.parent().unwrap())?;
        if workspaces
            .insert(
                config.workspace_id.clone(),
                json!({"profile_path":file,"visibility":"PRIVATE"}),
            )
            .is_some()
        {
            return Err(error("CONTEXT_CONFIG", "duplicate workspace profile"));
        }
        if first.is_none() {
            first = Some((config.origin, identity, config.allow_loopback_http));
        }
    }
    let (origin, identity, allow_loopback_http) = first.unwrap();
    let value = json!({"schema":"peerwork.agent-context.v1","service_id":service,"origin":origin,"identity_path":identity,"allow_loopback_http":allow_loopback_http,"workspaces":workspaces});
    let cfg: Config = serde_json::from_value(value.clone())
        .map_err(|_| error("CONTEXT_CONFIG", "invalid context references"))?;
    // Entire existing context is checked before even a temporary file exists.
    let context = validate_config(&target, cfg, actor, service)?;
    persist_context(&target, parent, value.to_string().as_bytes(), cancel)?;
    Ok(json!({"schema":"peerwork.agent-result.v1","context":context.descriptor,"status":"bound","local_only":true}))
}
fn persist_context(target: &Path, parent: &Path, wire: &[u8], cancel: &CancellationToken) -> Result<()> {
    use std::io::Write;
    if cancel.is_cancelled() {
        return Err(error("CANCELLED", "binding cancelled before persistence"));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| error("CONTEXT_STATE", "cannot prepare protected context file"))?;
    #[cfg(windows)]
    crate::windows_fs::create_or_check_file(temporary.path())
        .map_err(|_| error("CONTEXT_STATE", "cannot protect context file"))?;
    temporary
        .write_all(wire)
        .map_err(|_| error("CONTEXT_STATE", "cannot write context references"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| error("CONTEXT_STATE", "cannot sync context references"))?;
    temporary.persist_noclobber(&target).map_err(|_| {
        error(
            "CONTEXT_EXISTS",
            "context target appeared or could not be committed",
        )
    })?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| {
            error(
                "CONTEXT_DURABILITY_UNKNOWN",
                "context file was committed; reopen this target explicitly before retrying binding",
            )
        })?;
    Ok(())
}
fn event_error(e: crate::agent_events::AgentEventsError) -> Error {
    Error {
        code: e.code().into(),
        message: e.to_string(),
        layer: "events",
        certainty: "not_sent",
    }
}
fn consumer_params(r: &Request) -> Result<(&str, &str)> {
    let consumer = r
        .consumer_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("REQUEST_INVALID", "consumer_id required"))?;
    let filter = r
        .filter_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("REQUEST_INVALID", "filter_version required"))?;
    Ok((consumer, filter))
}
fn browser_error(e: crate::agent_browser_approval::BrowserApprovalRuntimeError) -> Error {
    Error {
        code: e.code().into(),
        message: e.to_string(),
        layer: "browser",
        certainty: e.effect_certainty(),
    }
}
fn admission_error(e: crate::agent_admission::AdmissionOperationError) -> Error {
    let detail=e.detail();
    Error { code:e.code().into(), message:detail.to_string(), layer:"admission", certainty:"unknown" }
}
fn action_error(e: crate::secure_action_access::PublicActionError) -> Error {
    if let crate::secure_action_access::PublicActionError::Intent(crate::secure_intents::SecureIntentError::Rejected(detail))=&e {
        return runtime_error(e.code(), detail.envelope().to_string());
    }
    runtime_error(e.code(), e.to_string())
}
fn pending_operations(
    config: &SecureReadProfileConfig,
    access: &SecurePrivateActionAccess,
    fp: &str,
    cancel: &CancellationToken,
) -> Result<Value> {
    let mut rows = decode(
        access
            .list_pending_json_with_cancel(cancel)
            .map_err(|e| runtime_error(e.code(), e.to_string()))?,
    )?;
    let browser =
        crate::agent_browser_approval::operations(config.clone(), fp).map_err(browser_error)?;
    rows.as_array_mut()
        .ok_or_else(|| runtime_error("RESULT_ENCODING", "invalid pending operation list".into()))?
        .extend(
            browser
                .as_array()
                .ok_or_else(|| {
                    runtime_error("RESULT_ENCODING", "invalid browser operation list".into())
                })?
                .iter()
                .cloned(),
        );
    let admission=crate::agent_admission::operations(config,fp).map_err(admission_error)?;
    rows.as_array_mut().ok_or_else(|| error("RESULT_ENCODING", "pending operation array required"))?
        .extend(admission.as_array().ok_or_else(|| error("RESULT_ENCODING", "admission operation array required"))?.iter().cloned());
    let plans=crate::protocol_workbench::pending_plans(config).map_err(|e|runtime_error(e.code(),e.envelope().to_string()))?;
    rows.as_array_mut().ok_or_else(||error("RESULT_ENCODING","pending operation array required"))?
        .extend(plans.as_array().ok_or_else(||error("RESULT_ENCODING","plan operation array required"))?.iter().cloned());
    Ok(rows)
}
fn legacy_action_operation(
    config: &SecureReadProfileConfig,
    actor: &str,
    id: &str,
) -> Result<bool> {
    let path = config.state_dir.join("action-intents.state");
    if crate::secure_state::missing_in_private_parent(&path) {
        return Ok(false);
    }
    let journal = SecureIntentJournal::open(&path, &config.origin, actor)
        .map_err(|e| runtime_error("INTENT_STATE", e.to_string()))?;
    Ok(journal
        .action_operation(id)
        .map_err(|e| runtime_error("INTENT_STATE", e.to_string()))?
        .is_some())
}
fn execute(
    operation: &str,
    profile_path: &Path,
    actor: &str,
    service: &str,
    request: Option<&str>,
    cancel: &CancellationToken,
) -> Result<Value> {
    if cancel.is_cancelled() {
        return Err(error("CANCELLED", "operation cancelled"));
    }
    if operation == "bind" {
        return Err(error(crate::runtime_contract::RETIRED_CODE,crate::runtime_contract::RETIRED_MESSAGE));
    }
    if operation == "bind.structure" {
        return structure::bind(profile_path, actor, service, request, cancel);
    }
    // The explicit v2 boundary selects backend execution. Never reinterpret a
    // v1 encrypted-history profile or require its replay to open a new space.
    let cwd = std::env::current_dir().map_err(|_| error("CONTEXT_PATH", "current directory unavailable"))?;
    let selected = path(profile_path, &cwd)?;
    let config_wire = raw(&selected, 64 * 1024)?;
    #[derive(Deserialize)]
    struct Version { schema: String }
    let version: Version = serde_json::from_slice(&config_wire)
        .map_err(|_| error("CONTEXT_CONFIG", "invalid context schema"))?;
    if version.schema == "peerwork.agent-context.v2" {
        return structure::execute(operation, &selected, &config_wire, actor, service, request, cancel);
    }
    Err(error(crate::runtime_contract::RETIRED_CODE,crate::runtime_contract::RETIRED_MESSAGE))
}
/// Thin bindings must preserve this versioned success/error envelope.
pub fn agent_context_json(
    operation: &str,
    profile_path: &Path,
    expected_actor: &str,
    expected_service: &str,
    request_json: Option<&str>,
    cancel: &CancellationToken,
) -> String {
    match execute(operation,profile_path,expected_actor,expected_service,request_json,cancel) {
        Ok(value)=>json!({"ok":true,"value":value}),
        Err(e)=>{
            let request=request_json.and_then(|v|serde_json::from_str::<Value>(v).ok()).unwrap_or(Value::Null);
            let continuation=if operation=="follow.operation" {
                structure::follow_error_continuation(&request)
            }else if operation.starts_with("events.") {
                json!({"operation":operation,"workspace_id":request["workspace_id"],"consumer_id":request["consumer_id"],"filter_version":request["filter_version"]})
            } else if request["operation_id"].is_string() {
                json!({"operation":"recover","workspace_id":request["workspace_id"],"operation_id":request["operation_id"]})
            } else {json!({"operation":"recover","workspace_id":request["workspace_id"],"command_id":request["command_id"]})};
            let detail=serde_json::from_str::<Value>(&e.message).ok().filter(|v|v.is_object());
            let mut envelope=json!({"ok":false,"schema":"peerwork.operation-error.v1","code":e.code,
                "message":e.message,"layer":e.layer,"effect_certainty":e.certainty,
                "stage":if e.certainty=="not_sent"{"inspect"}else{"reconcile"},
                "operation_id":request["operation_id"],"constraint":Value::Null,
                "retryability":if e.certainty=="not_sent"{"correct_input"}else{"reconcile_only"},
                "recovery_hints":[{"action":"recover","precondition":"same_saved_operation"}],"continuation":continuation});
            if let Some(detail)=detail {
                for key in ["stage","server_code","constraint","retryability","effect_certainty","recovery_hints","http_status","response_digest","completed_steps","results","dependency_diff","continuation"] {
                    if let Some(value)=detail.get(key){envelope[key]=value.clone();}
                }
            }
            envelope
        }
    }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kernel_identity::KernelIdentity, test_support::protected_test_dir};
    fn write(path: &Path, value: &Value) {
        #[cfg(windows)]
        crate::windows_fs::create_or_check_file(path).unwrap();
        std::fs::write(path, value.to_string()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn fixture() -> (crate::test_support::ProtectedTestDir, PathBuf, String) {
        let root = protected_test_dir();
        let id = root.path().join("identity.state");
        let actor = KernelIdentity::create(&id).unwrap().actor_id().to_owned();
        let p = root.path().join("context.json");
        write(
            &p,
            &json!({"schema":"peerwork.agent-context.v2","execution_profile":"backend-structure-v1","service_id":"test","origin":"https://example.invalid","identity_path":"identity.state","kernel_journal_path":"operations.sqlite","workspaces":["space"]}),
        );
        (root, p, actor)
    }
    fn call(p: &Path, actor: &str, service: &str) -> Value {
        serde_json::from_str(&agent_context_json(
            "open",
            p,
            actor,
            service,
            None,
            &CancellationToken::new(),
        ))
        .unwrap()
    }
    #[test]
    fn open_is_offline_noncreating_and_redacted() {
        let (root, p, actor) = fixture();
        let before = std::fs::read_dir(root.path()).unwrap().count();
        let identity_before = std::fs::read(root.path().join("identity.state")).unwrap();
        let first = call(&p, &actor, "test");
        assert_eq!(first["ok"], true);
        assert_eq!(first, call(&p, &actor, "test"));
        assert_eq!(
            first["value"]["context"]["origin"],
            "https://example.invalid/"
        );
        assert!(!first.to_string().contains("seed"));
        assert!(!first.to_string().contains(root.path().to_str().unwrap()));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), before);
        assert_eq!(
            std::fs::read(root.path().join("identity.state")).unwrap(),
            identity_before
        );
    }
    #[test]
    fn pinned_context_rejects_changed_service_binding_before_effects() {
        let (root, p, actor) = fixture();
        let first = call(&p, &actor, "test");
        let fingerprint = first["value"]["context"]["fingerprint"].as_str().unwrap();
        write(
            &p,
            &json!({"schema":"peerwork.agent-context.v2","execution_profile":"backend-structure-v1","service_id":"test","origin":"https://changed.invalid/","identity_path":"identity.state","kernel_journal_path":"operations.sqlite","workspaces":["space"]}),
        );
        let before = std::fs::read_dir(root.path()).unwrap().count();
        let request =
            json!({"workspace_id":"space","expected_fingerprint":fingerprint}).to_string();
        let result: Value = serde_json::from_str(&agent_context_json(
            "inspect",
            &p,
            &actor,
            "test",
            Some(&request),
            &CancellationToken::new(),
        ))
        .unwrap();
        assert_eq!(result["code"], "CONTEXT_CHANGED");
        assert_eq!(result["effect_certainty"], "not_sent");
        assert_eq!(before, std::fs::read_dir(root.path()).unwrap().count());
        assert_ne!(
            fingerprint,
            call(&p, &actor, "test")["value"]["context"]["fingerprint"]
                .as_str()
                .unwrap()
        );
    }
    #[test]
    fn bind_refuses_missing_references_and_never_overwrites() {
        let (root, existing, actor) = fixture();
        let target = root.path().join("bound.json");
        let request = json!({"schema":"peerwork.agent-context.v2","execution_profile":"backend-structure-v1","service_id":"test","origin":"https://example.invalid/","identity_path":"missing-identity.state","kernel_journal_path":"operations.sqlite","workspaces":[]}).to_string();
        let before = std::fs::read_dir(root.path()).unwrap().count();
        let failure: Value = serde_json::from_str(&agent_context_json(
            "bind.structure",
            &target,
            &actor,
            "test",
            Some(&request),
            &CancellationToken::new(),
        ))
        .unwrap();
        assert_eq!(failure["ok"], false);
        assert!(!target.exists());
        assert_eq!(before, std::fs::read_dir(root.path()).unwrap().count());
        let original = std::fs::read(&existing).unwrap();
        let failure: Value = serde_json::from_str(&agent_context_json(
            "bind.structure",
            &existing,
            &actor,
            "test",
            Some(&request),
            &CancellationToken::new(),
        ))
        .unwrap();
        assert_eq!(failure["code"], "CONTEXT_EXISTS");
        assert_eq!(std::fs::read(existing).unwrap(), original);
    }
    #[test]
    fn events_require_explicit_consumer_and_version() {
        let missing: Request = serde_json::from_value(json!({"workspace_id":"space"})).unwrap();
        assert!(consumer_params(&missing).is_err());
        let explicit:Request=serde_json::from_value(json!({"workspace_id":"space","consumer_id":"worker","filter_version":"v1","lease_ms":1000,"wait_ms":0})).unwrap();
        assert_eq!(consumer_params(&explicit).unwrap(), ("worker", "v1"));
    }
    #[test]
    fn wrong_selection_and_missing_profile_have_no_effects() {
        let (root, p, actor) = fixture();
        let before = std::fs::read_dir(root.path()).unwrap().count();
        assert_eq!(call(&p, "wrong", "test")["code"], "CONTEXT_ACTOR");
        assert_eq!(call(&p, &actor, "wrong")["code"], "CONTEXT_SERVICE");
        assert_eq!(
            call(&root.path().join("missing"), &actor, "test")["ok"],
            false
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), before);
    }
    #[test]
    fn retired_workspace_profile_is_not_reinterpreted_or_imported() {
        let (root, p, actor) = fixture();
        let other = root.path().join("other.state");
        KernelIdentity::create(&other).unwrap();
        write(
            &root.path().join("workspace.json"),
            &json!({"origin":"https://example.invalid/","state_dir":"must-not-create","identity_path":"other.state","workspace_id":"space","owner_actor_id":null,"owner_key_id":null,"authority":null}),
        );
        write(
            &p,
            &json!({"schema":"peerwork.agent-context.v1","service_id":"test","origin":"https://example.invalid/","identity_path":"identity.state","workspaces":{"space":{"profile_path":"workspace.json"}}}),
        );
        assert_eq!(call(&p, &actor, "test")["code"], "LEGACY_MODE_RETIRED");
        assert!(!root.path().join("must-not-create").exists());
    }
    #[test]
    fn typed_intent_is_canonical_and_unknown_producer_is_refused() {
        let a: Value = serde_json::from_str(r#"{"z":1,"a":{"y":2,"x":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":3,"y":2},"z":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
        let invalid = Intent {
            kind: "platform.browser.approve".into(),
            instance_id: "i".into(),
            action_id: "a".into(),
            values: a.clone(),
            refs: None,
        };
        assert_eq!(input(invalid).err().unwrap().code, "UNSUPPORTED_PRODUCER");
        let valid = Intent {
            kind: "protocol.action".into(),
            instance_id: "i".into(),
            action_id: "a".into(),
            values: a,
            refs: None,
        };
        let action = input(valid).unwrap();
        assert_eq!(action.body_json, canonical(&b));
        assert_eq!(action.exact_input_refs_json.as_deref(), Some("[]"));
        assert!(action.command_id.is_none());
    }
    #[cfg(unix)]
    #[test]
    fn traversal_and_symlink_are_refused() {
        let (root, p, actor) = fixture();
        let link = root.path().join("linked.json");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(call(&link, &actor, "test")["ok"], false);
        assert!(path(Path::new("../identity.state"), root.path()).is_err());
    }
}
