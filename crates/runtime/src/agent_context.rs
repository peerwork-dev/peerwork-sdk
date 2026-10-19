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
    query: Option<crate::agent_discovery::DiscoveryQuery>,
    consumer_id: Option<String>,
    filter_version: Option<String>,
    lease_ms: Option<u64>,
    wait_ms: Option<u64>,
    ack_token: Option<String>,
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
    for expected in [
        config.origin.as_str(),
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
    use std::io::Write;
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
    if cancel.is_cancelled() {
        return Err(error("CANCELLED", "binding cancelled before persistence"));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| error("CONTEXT_STATE", "cannot prepare protected context file"))?;
    #[cfg(windows)]
    crate::windows_fs::create_or_check_file(temporary.path())
        .map_err(|_| error("CONTEXT_STATE", "cannot protect context file"))?;
    temporary
        .write_all(value.to_string().as_bytes())
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
    Ok(
        json!({"schema":"peerwork.agent-result.v1","context":context.descriptor,"status":"bound","local_only":true}),
    )
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
        return bind(profile_path, actor, service, request, cancel);
    }
    if !matches!(
        operation,
        "open"
            | "inspect"
            | "discover"
            | "describe"
            | "operate"
            | "recover"
            | "operations"
            | "events.sync"
            | "events.receive"
            | "events.ack"
            | "events.status"
    ) {
        return Err(error(
            "UNSUPPORTED_PRODUCER",
            "unsupported context operation",
        ));
    }
    let context = load(profile_path, actor, service)?;
    let mut out =
        json!({"schema":"peerwork.agent-result.v1","context":context.descriptor,"status":"ready"});
    if operation == "open" {
        return Ok(out);
    }
    if request.is_some_and(|r| r.len() > 1024 * 1024) {
        return Err(error("REQUEST_LIMIT", "request exceeds one MiB"));
    }
    let r: Request = serde_json::from_str(
        request.ok_or_else(|| error("REQUEST_INVALID", "workspace request required"))?,
    )
    .map_err(|_| error("REQUEST_INVALID", "invalid structured request"))?;
    if r.expected_fingerprint
        .as_deref()
        .is_some_and(|expected| out["context"]["fingerprint"].as_str() != Some(expected))
    {
        return Err(error(
            "CONTEXT_CHANGED",
            "selected context bindings changed; explicitly reopen before proceeding",
        ));
    }
    let config = context
        .profiles
        .get(&r.workspace_id)
        .ok_or_else(|| error("CONTEXT_WORKSPACE", "workspace is not selected"))?
        .clone();
    let access = SecurePrivateActionAccess::new(config.clone());
    out["workspace_id"] = json!(r.workspace_id);
    out["operation_id"] = json!(r.operation_id);
    let result = match operation {
        "inspect" => {
            let state = decode(
                SecurePrivateReadAccess::new(config.clone())
                    .activate_and_read_json_with_cancel(cancel)
                    .map_err(|e| runtime_error(e.code(), e.to_string()))?,
            )?;
            let pending = pending_operations(
                &config,
                &access,
                out["context"]["fingerprint"].as_str().unwrap(),
                cancel,
            )?;
            json!({"state":state,"pending":pending})
        }
        "operations" => pending_operations(
            &config,
            &access,
            out["context"]["fingerprint"].as_str().unwrap(),
            cancel,
        )?,
        "operate" => {
            let id = r
                .operation_id
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| error("REQUEST_INVALID", "stable operation_id required"))?;
            let mut intent = r
                .intent
                .ok_or_else(|| error("REQUEST_INVALID", "intent required"))?;
            match intent.get("kind").and_then(Value::as_str) {
                Some("protocol.action") => {
                    let action = input(serde_json::from_value(intent.clone()).map_err(|_| {
                        error("ACTION_INPUT_INVALID", "invalid protocol.action intent")
                    })?)?;
                    if intent.get("refs").is_none_or(Value::is_null) {
                        intent["refs"] = json!([]);
                    }
                    if crate::agent_browser_approval::has_operation(
                        config.clone(),
                        out["context"]["fingerprint"].as_str().unwrap(),
                        Some(id),
                        None,
                    )
                    .map_err(browser_error)?
                    {
                        return Err(error(
                            "INTENT_CONFLICT",
                            "operation id already belongs to browser.approve",
                        ));
                    }
                    // Legacy rows predate the common index. Their original
                    // digest must reject an edited retry before any backfill.
                    let indexed = crate::agent_operations::kind(&config, &context.actor, id)
                        .map_err(|e| error(e.code(), &e.to_string()))?;
                    if indexed.is_some() || !legacy_action_operation(&config, &context.actor, id)? {
                        crate::agent_operations::bind(
                            &config,
                            &context.actor,
                            id,
                            "protocol.action",
                            &intent,
                        )
                        .map_err(|e| error(e.code(), &e.to_string()))?;
                    }
                    decode(
                        access
                            .submit_new_json_with_operation_id(action, id, cancel)
                            .map_err(|e| runtime_error(e.code(), e.to_string()))?,
                    )?
                }
                Some("browser.approve") => {
                    let intent: BrowserIntent = serde_json::from_value(intent).map_err(|_| {
                        error("ACTION_INPUT_INVALID", "invalid browser.approve intent")
                    })?;
                    if intent.reference.is_empty() || intent.reference.len() > 300 {
                        return Err(error(
                            "ACTION_INPUT_INVALID",
                            "bounded browser approval reference required",
                        ));
                    }
                    if legacy_action_operation(&config, &context.actor, id)? {
                        return Err(error(
                            "INTENT_CONFLICT",
                            "operation id already belongs to protocol.action",
                        ));
                    }
                    let normalized = json!({"kind":intent.kind,"reference":intent.reference,"approve_writes":intent.approve_writes});
                    crate::agent_operations::bind(
                        &config,
                        &context.actor,
                        id,
                        "browser.approve",
                        &normalized,
                    )
                    .map_err(|e| error(e.code(), &e.to_string()))?;
                    crate::agent_browser_approval::approve(
                        config,
                        out["context"]["fingerprint"].as_str().unwrap(),
                        &intent.reference,
                        intent.approve_writes,
                        id,
                        cancel,
                    )
                    .map_err(browser_error)?
                }
                _ => {
                    return Err(error(
                        "UNSUPPORTED_PRODUCER",
                        "supported producers: protocol.action, browser.approve",
                    ))
                }
            }
        }
        "recover" => {
            if r.operation_id.is_some() == r.command_id.is_some() {
                return Err(error(
                    "REQUEST_INVALID",
                    "select exactly one operation_id or command_id",
                ));
            }
            let indexed_kind = r
                .operation_id
                .as_deref()
                .map(|id| crate::agent_operations::kind(&config, &context.actor, id))
                .transpose()
                .map_err(|e| error(e.code(), &e.to_string()))?
                .flatten();
            if indexed_kind.as_deref() == Some("browser.approve")
                || crate::agent_browser_approval::has_operation(
                    config.clone(),
                    out["context"]["fingerprint"].as_str().unwrap(),
                    r.operation_id.as_deref(),
                    r.command_id.as_deref(),
                )
                .map_err(browser_error)?
            {
                crate::agent_browser_approval::recover(
                    config,
                    out["context"]["fingerprint"].as_str().unwrap(),
                    r.operation_id.as_deref(),
                    r.command_id.as_deref(),
                    cancel,
                )
                .map_err(browser_error)?
            } else {
                let command = if let Some(id) = r.command_id {
                    id
                } else {
                    let journal = SecureIntentJournal::open(
                        &config.state_dir.join("action-intents.state"),
                        &config.origin,
                        &context.actor,
                    )
                    .map_err(|e| runtime_error("INTENT_STATE", e.to_string()))?;
                    journal
                        .action_operation(r.operation_id.as_deref().unwrap())
                        .map_err(|e| runtime_error("INTENT_STATE", e.to_string()))?
                        .ok_or_else(|| error("INTENT_NOT_FOUND", "operation has no saved command"))?
                        .0
                };
                decode(
                    access
                        .reconcile_json_with_cancel(&command, cancel)
                        .map_err(|e| runtime_error(e.code(), e.to_string()))?,
                )?
            }
        }
        "discover" | "describe" => crate::agent_discovery::discover(
            config,
            r.query.unwrap_or_default(),
            operation == "describe",
            cancel,
        )
        .map_err(|e| Error {
            code: e.code().into(),
            message: e.to_string(),
            layer: "discovery",
            certainty: "not_sent",
        })?,
        "events.sync" => crate::agent_events::sync(
            config,
            out["context"]["fingerprint"].as_str().unwrap(),
            cancel,
        )
        .map_err(event_error)?,
        "events.status" => {
            crate::agent_events::status(config, out["context"]["fingerprint"].as_str().unwrap())
                .map_err(event_error)?
        }
        "events.receive" => {
            let (consumer, filter) = consumer_params(&r)?;
            let lease = r
                .lease_ms
                .ok_or_else(|| error("REQUEST_INVALID", "lease_ms required"))?;
            let wait = r
                .wait_ms
                .ok_or_else(|| error("REQUEST_INVALID", "wait_ms required"))?;
            crate::agent_events::receive(
                config,
                out["context"]["fingerprint"].as_str().unwrap(),
                consumer,
                filter,
                lease,
                wait,
                cancel,
            )
            .map_err(event_error)?
        }
        "events.ack" => {
            let (consumer, filter) = consumer_params(&r)?;
            let token = r
                .ack_token
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| error("REQUEST_INVALID", "ack_token required"))?;
            crate::agent_events::ack(
                config,
                out["context"]["fingerprint"].as_str().unwrap(),
                consumer,
                filter,
                token,
            )
            .map_err(event_error)?
        }
        _ => unreachable!(),
    };
    if operation.starts_with("events.") {
        if let Some(status) = result.get("status").and_then(Value::as_str) {
            out["status"] = json!(status);
        }
        out["continuation"] = json!({"operation":operation,"workspace_id":r.workspace_id,"consumer_id":r.consumer_id,"filter_version":r.filter_version});
    }
    if matches!(operation, "operate" | "recover") {
        if result["workspace_id"].as_str() != Some(r.workspace_id.as_str()) {
            return Err(runtime_error(
                "CONTEXT_BINDING",
                "saved operation belongs to a different workspace".into(),
            ));
        }
        let browser = result["kind"] == "browser.approve";
        let accepted =
            result["status"] == "ACCEPTED" && (!browser || result["verification"] == "verified");
        out["status"] = json!(if accepted { "verified" } else { "pending" });
        out["evidence"] = json!({"acceptance":if accepted{"accepted"}else{"unknown"},"verification":if accepted{"verified"}else{"pending"},"sequence":result["sequence"],"commit_hash":result["commit_hash"]});
        if accepted && browser {
            out["refs"] = json!([]);
        } else if accepted {
            let receipt: Value =
                serde_json::from_str(result["receipt_canonical_json"].as_str().ok_or_else(
                    || runtime_error("RESULT_ENCODING", "verified receipt missing".into()),
                )?)
                .map_err(|_| runtime_error("RESULT_ENCODING", "invalid verified receipt".into()))?;
            out["refs"] = receipt["effects"].clone();
            out["receipt"] = receipt;
        }
        out["continuation"] = json!({"operation":"recover","workspace_id":r.workspace_id,"command_id":result["command_id"]});
    }
    out["result"] = result;
    Ok(out)
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
    match execute(operation,profile_path,expected_actor,expected_service,request_json,cancel){Ok(value)=>json!({"ok":true,"value":value}),Err(e)=>{let continuation=request_json.and_then(|v|serde_json::from_str::<Value>(v).ok()).map(|v|if operation.starts_with("events."){json!({"operation":operation,"workspace_id":v["workspace_id"],"consumer_id":v["consumer_id"],"filter_version":v["filter_version"]})}else{json!({"operation":"recover","workspace_id":v["workspace_id"],"operation_id":v["operation_id"],"command_id":v["command_id"]})});json!({"ok":false,"code":e.code,"message":e.message,"layer":e.layer,"effect_certainty":e.certainty,"continuation":continuation})}}.to_string()
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
            &json!({"schema":"peerwork.agent-context.v1","service_id":"test","origin":"https://example.invalid","identity_path":"identity.state","workspaces":{}}),
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
            &json!({"schema":"peerwork.agent-context.v1","service_id":"test","origin":"https://changed.invalid/","identity_path":"identity.state","workspaces":{}}),
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
        let request = json!({"workspace_profiles":["missing-read-profile.json"]}).to_string();
        let before = std::fs::read_dir(root.path()).unwrap().count();
        let failure: Value = serde_json::from_str(&agent_context_json(
            "bind",
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
            "bind",
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
    fn workspace_identity_mismatch_fails_before_state_creation() {
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
        assert_eq!(call(&p, &actor, "test")["code"], "CONTEXT_BINDING");
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
