//! Explicit offline preparation of an Owner-attested execution-model change.
//! Reads a protected, decrypted current-state export in bounded JSONL records;
//! selects only mapped business fields and re-encrypts the selected body.
//! It never opens a transport, replays history or changes the source identity.
use rusqlite::OptionalExtension;
use crate::{
    kernel_identity::KernelIdentity, kernel_intents::StructureContentKeys,
    transport::TransportConfig,
};
use ed25519_dalek::Signer;
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, sha256, sha256_hex},
    prepared_command::verify_structure_author_intent,
    protocol_simulation::build_fixture_json,
    structure_content::StructureContentContext,
    wire_json::{canonical_wire_value, parse_wire_json_bounded},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(not(unix))]
use std::time::UNIX_EPOCH;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

const PROFILE: &str = "backend-structure-v1";
const COMMAND_TYPE: &str = "peerwork.kernel-command.v1+jws";
const MAX_LINE: usize = 250000;
type R<T> = Result<T, CheckpointError>;
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CheckpointError(pub &'static str, pub Option<Value>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareCheckpointRequest {
    pub identity_path: PathBuf,
    pub expected_actor: String,
    pub origin: String,
    pub audience: String,
    pub source_path: PathBuf,
    pub plan_path: PathBuf,
    pub output_path: PathBuf,
    #[serde(default)]
    pub content_keys_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_loopback_http: bool,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Source {
    #[serde(default,skip_serializing_if="Option::is_none")]
    kind:Option<String>,
    snapshot_sha256: String,
    workspace_id: String,
    owner_id: String,
    owner_kid: String,
    authority: String,
    sequence: u64,
    head: String,
    policy_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    #[serde(default="executable_mode")]
    migration_mode:String,
    source: Source,
    name: String,
    workspace_alias: Option<String>,
    instances: BTreeMap<String, InstanceMap>,
    schemas: BTreeMap<String, RecordMap>,
}
fn executable_mode()->String{"EXECUTABLE".into()}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceMap {
    manifest: Value,
    state_fields: BTreeMap<String, Vec<String>>,
    bootstrap_grant: GrantMap,
    #[serde(default)]
    record_mappings: BTreeMap<String, RecordMap>,
    #[serde(default)]
    role_history: Option<RoleHistory>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoleHistory {
    complete: bool,
    claims: Vec<RoleClaim>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RoleClaim {
    actor_id: String,
    roles: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantMap {
    actions: Vec<String>,
    #[serde(default)]
    protocol_roles: Vec<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordMap {
    target_schema: String,
    structure_fields: BTreeMap<String, Vec<String>>,
    body_field: Option<Vec<String>>,
    #[serde(default)]
    body_fields: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    strict_body_separation: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceInput {
    kind: String,
    instance_id: String,
    state: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordInput {
    kind: String,
    instance_id: String,
    record_id: String,
    entity_id: String,
    revision: u64,
    is_head: bool,
    schema: String,
    fields: Value,
    legacy_source: LegacySource,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationInput {kind:String,record_id:String,relation_kind:String,target_record:String,target_revision:u64}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacySource {
    sequence: u64,
    commit_hash: String,
    record_id: String,
    revision: u64,
    actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
}
fn token(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn error(code: &'static str) -> CheckpointError {
    CheckpointError(code, None)
}
fn wire(value: &Value, path: CanonicalPath) -> R<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| error("CHECKPOINT_INPUT_INVALID"))?;
    let parsed = parse_wire_json_bounded(&bytes, 40, 2 * 1024 * 1024)
        .map_err(|_| error("CHECKPOINT_INPUT_INVALID"))?;
    canonical_wire_value(&parsed, path).map_err(|_| error("CHECKPOINT_INPUT_INVALID"))
}
fn hashed(value: &Value) -> R<String> {
    Ok(sha256_hex(
        wire(value, CanonicalPath::STRUCTURED)?.as_bytes(),
    ))
}
fn plan_digest(value: &Value) -> R<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| error("CHECKPOINT_PLAN_INVALID"))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(error("CHECKPOINT_PLAN_LIMIT"));
    }
    let parsed = parse_wire_json_bounded(&bytes, 64, 2 * 1024 * 1024)
        .map_err(|_| error("CHECKPOINT_PLAN_INVALID"))?;
    // A mapping contains many independently bounded programs. Applying one
    // program's node budget to the entire mapping rejects valid workspaces.
    let canonical = canonical_wire_value(&parsed, CanonicalPath::SecureArtifact)
        .map_err(|_| error("CHECKPOINT_PLAN_INVALID"))?;
    Ok(sha256_hex(canonical.as_bytes()))
}
fn strict_plan(bytes: &[u8]) -> R<Value> {
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(error("CHECKPOINT_PLAN_LIMIT"));
    }
    let parsed = parse_wire_json_bounded(bytes, 64, 2 * 1024 * 1024)
        .map_err(|_| error("CHECKPOINT_PLAN_INVALID"))?;
    let canonical = canonical_wire_value(&parsed, CanonicalPath::SecureArtifact)
        .map_err(|_| error("CHECKPOINT_PLAN_INVALID"))?;
    serde_json::from_str(&canonical).map_err(|_| error("CHECKPOINT_PLAN_INVALID"))
}
fn strict(bytes: &[u8]) -> R<Value> {
    let w = parse_wire_json_bounded(bytes, 40, 2 * 1024 * 1024)
        .map_err(|_| error("CHECKPOINT_INPUT_INVALID"))?;
    serde_json::from_str(
        &canonical_wire_value(&w, CanonicalPath::COMMAND)
            .map_err(|_| error("CHECKPOINT_INPUT_INVALID"))?,
    )
    .map_err(|_| error("CHECKPOINT_INPUT_INVALID"))
}
fn protected(path: &Path) -> R<File> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| error("CHECKPOINT_FILE_MISSING"))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(error("CHECKPOINT_FILE_PROTECTION_INVALID"));
    }
    crate::kernel_intents::ensure_private_parent(path)
        .map_err(|_| error("CHECKPOINT_FILE_PROTECTION_INVALID"))?;
    crate::kernel_intents::create_or_check_private_file(path)
        .map_err(|_| error("CHECKPOINT_FILE_PROTECTION_INVALID"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| error("CHECKPOINT_FILE_PROTECTION_INVALID"))
}
fn fingerprint(file: &File) -> R<Value> {
    let m = file
        .metadata()
        .map_err(|_| error("CHECKPOINT_FILE_MISSING"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(json!([
            m.dev().to_string(),
            m.ino().to_string(),
            m.len().to_string(),
            m.mtime().to_string(),
            m.mtime_nsec().to_string(),
            m.ctime().to_string(),
            m.ctime_nsec().to_string()
        ]))
    }
    #[cfg(not(unix))]
    {
        Ok(json!([
            m.len().to_string(),
            m.modified()
                .map_err(|_| error("CHECKPOINT_FILE_MISSING"))?
                .duration_since(UNIX_EPOCH)
                .map_err(|_| error("CHECKPOINT_FILE_MISSING"))?
                .as_nanos()
                .to_string()
        ]))
    }
}
fn line(reader: &mut impl BufRead) -> R<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let read = reader
        .take((MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| error("CHECKPOINT_SOURCE_READ_FAILED"))?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_LINE || bytes.last() != Some(&b'\n') {
        return Err(error("CHECKPOINT_LINE_LIMIT_OR_TRUNCATED"));
    }
    Ok(Some(bytes))
}
fn selected(value: &Value, path: &[String]) -> R<Value> {
    if path.is_empty() || path.len() > 12 {
        return Err(error("CHECKPOINT_MAPPING_INVALID"));
    }
    let mut at = value;
    for key in path {
        if key.is_empty()
            || matches!(
                key.as_str(),
                "__proto__" | "prototype" | "constructor" | "sealed_content" | "$content"
            )
        {
            return Err(error("CHECKPOINT_MAPPING_INVALID"));
        }
        at = at.as_object().and_then(|map| map.get(key)).ok_or_else(|| {
            CheckpointError(
                "CHECKPOINT_MAPPING_PATH_MISSING",
                Some(json!({"mapping_path":path})),
            )
        })?;
    }
    Ok(at.clone())
}
fn readable(value: &Value) -> R<()> {
    if let Some(object) = value.as_object() {
        for (key, child) in object {
            if matches!(key.as_str(), "sealed_content" | "$content") {
                return Err(error("CHECKPOINT_PRIVATE_RULE_FIELD"));
            }
            readable(child)?;
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            readable(child)?;
        }
    }
    Ok(())
}
fn map_fields(fields: &BTreeMap<String, Vec<String>>, source: &Value) -> R<Value> {
    let mut out = serde_json::Map::new();
    for (key, path) in fields {
        if key.is_empty()
            || matches!(
                key.as_str(),
                "__proto__" | "prototype" | "constructor" | "sealed_content" | "$content"
            )
        {
            return Err(error("CHECKPOINT_MAPPING_INVALID"));
        }
        out.insert(key.clone(), selected(source, path)?);
    }
    let value = Value::Object(out);
    readable(&value)?;
    wire(&value, CanonicalPath::KERNEL)?;
    Ok(value)
}
fn normalize(manifest: &Value, state: &Value, role_history_complete: bool) -> R<(Value, String)> {
    if !role_history_complete
        && manifest["historical_role_conflicts"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    {
        return Err(error("CHECKPOINT_HISTORICAL_ROLE_MAPPING_REQUIRED"));
    }
    let fixture=build_fixture_json(&json!({"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"checkpoint","manifest":manifest,"state":state}]}).to_string()).map_err(|_|error("CHECKPOINT_PROTOCOL_INVALID"))?;
    let fixture: Value =
        serde_json::from_str(&fixture).map_err(|_| error("CHECKPOINT_PROTOCOL_INVALID"))?;
    let row = fixture["objects"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["kind"] == "protocols"))
        .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?;
    let normalized = row["value"]["resolved_manifest"].clone();
    let hash = row["id"]
        .as_str()
        .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?
        .to_owned();
    if normalized["dependencies"]
        .as_array()
        .is_none_or(|a| !a.is_empty())
        || normalized["constraints"]
            .as_object()
            .is_none_or(|o| !o.is_empty())
    {
        return Err(CheckpointError("CHECKPOINT_PROTOCOL_UNSUPPORTED",Some(json!({"feature":"UNRESOLVED_DEPENDENCIES_OR_CONSTRAINTS"}))));
    }
    for schema in normalized["record_schemas"]
        .as_object()
        .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?
        .values()
    {
        if schema["workflow"].get("dependencies").is_some() {
            return Err(CheckpointError("CHECKPOINT_PROTOCOL_UNSUPPORTED",Some(json!({"feature":"WORKFLOW_DEPENDENCIES"}))));
        }
        if schema["workflow"]["deadline"].get("reminder").is_some() {
            return Err(CheckpointError("CHECKPOINT_PROTOCOL_UNSUPPORTED",Some(json!({"feature":"WORKFLOW_REMINDERS"}))));
        }
        if let Some(fields) = schema["protection"]["fields"].as_object() {
            if fields
                .values()
                .any(|v| v["protection"] != "server_readable")
            {
                return Err(error("CHECKPOINT_PRIVATE_RULE_FIELD"));
            }
        }
    }
    readable(&normalized)?;
    if !role_history_complete
        && normalized["historical_role_conflicts"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    {
        return Err(error("CHECKPOINT_HISTORICAL_ROLE_MAPPING_REQUIRED"));
    }
    Ok((normalized, hash))
}

/// Reject a known incompatible target before replaying or refreshing its
/// source. This is a compatibility check only; it grants no role-history or
/// source authority, both of which are still verified during preparation.
pub(crate) fn preflight_checkpoint_target(plan:&Value)->R<()> {
    let instances=plan["instances"].as_object().ok_or_else(||error("CHECKPOINT_PLAN_INVALID"))?;
    if instances.is_empty()||instances.len()>32{return Err(error("CHECKPOINT_PLAN_INVALID"));}
    for (instance,mapping) in instances {
        normalize(&mapping["manifest"],&mapping["manifest"]["initial_state"],true).map_err(|mut e|{
            let details=e.1.get_or_insert_with(||json!({}));details["instance_id"]=json!(instance);details["phase"]=json!("TARGET_PROTOCOL_PREFLIGHT");e
        })?;
    }
    Ok(())
}
fn validate_record(manifest: &Value, schema: &str, value: &Value) -> R<()> {
    let schema = manifest["record_schemas"]
        .get(schema)
        .ok_or_else(|| error("CHECKPOINT_RECORD_SCHEMA_INVALID"))?;
    let fields = schema["fields"]
        .as_object()
        .ok_or_else(|| error("CHECKPOINT_RECORD_SCHEMA_INVALID"))?;
    let v = value
        .as_object()
        .ok_or_else(|| error("CHECKPOINT_RECORD_SCHEMA_INVALID"))?;
    if v.keys().any(|key| !fields.contains_key(key))
        || schema["required"].as_array().is_none_or(|r| {
            r.iter()
                .any(|k| k.as_str().is_none_or(|k| !v.contains_key(k)))
        })
    {
        return Err(error("CHECKPOINT_RECORD_SCHEMA_INVALID"));
    }
    for (key, current) in v {
        let valid = match fields[key].as_str() {
            Some("string") => current.is_string(),
            Some("integer") => current
                .as_i64()
                .is_some_and(|n| n.unsigned_abs() <= 9007199254740991),
            Some("boolean") => current.is_boolean(),
            Some("null") => current.is_null(),
            Some("json") => true,
            Some("source_text") => {
                current.is_null() || current.as_str().is_some_and(|text| text.len() <= 8192)
            }
            Some("source_timestamp") => {
                current.is_null()
                    || current
                        .as_str()
                        .is_some_and(peerwork_core::source_provenance::valid_source_timestamp_str)
            }
            Some("source_sha256") => current.is_null() || current.as_str().is_some_and(digest),
            _ => false,
        };
        if !valid {
            return Err(error("CHECKPOINT_RECORD_TYPE_UNSUPPORTED"));
        }
    }
    if wire(value, CanonicalPath::KERNEL)?.len()
        > schema["max_bytes"].as_u64().unwrap_or(0) as usize
    {
        return Err(error("CHECKPOINT_RECORD_LIMIT"));
    }
    Ok(())
}
fn validate_grant(manifest: &Value, grant: &GrantMap) -> R<()> {
    for (selected, field, limit) in [
        (&grant.actions, "actions", 64),
        (&grant.protocol_roles, "protocol_roles", 32),
        (&grant.capabilities, "capabilities", 64),
    ] {
        let unique: BTreeSet<_> = selected.iter().collect();
        if unique.len() != selected.len() || selected.len() > limit {
            return Err(error("CHECKPOINT_BOOTSTRAP_GRANT_INVALID"));
        }
        let declared: BTreeSet<_> = manifest[field]
            .as_array()
            .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?
            .iter()
            .filter_map(|v| {
                if field == "actions" {
                    v["id"].as_str()
                } else {
                    v.as_str()
                }
            })
            .collect();
        if selected.iter().any(|s| !declared.contains(s.as_str())) {
            return Err(error("CHECKPOINT_BOOTSTRAP_GRANT_INVALID"));
        }
    }
    for field in ["role_conflicts", "historical_role_conflicts"] {
        for pair in manifest[field]
            .as_array()
            .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?
        {
            if pair.as_array().is_some_and(|pair| {
                pair.len() == 2
                    && pair.iter().all(|role| {
                        role.as_str().is_some_and(|r| {
                            grant.protocol_roles.iter().any(|selected| selected == r)
                        })
                    })
            }) {
                return Err(error("CHECKPOINT_BOOTSTRAP_ROLE_CONFLICT"));
            }
        }
    }
    Ok(())
}
struct Builder<'a> {
    identity: &'a KernelIdentity,
    keys: Option<StructureContentKeys>,
    content_keys_path: PathBuf,
    origin: String,
    allow_loopback_http: bool,
    plan: &'a Plan,
    audience: &'a str,
    conversion: String,
    time: u64,
    head: String,
    pages: u64,
    records: u64,
    output: File,
}
impl Builder<'_> {
    fn command_id(&self, index: u64) -> String {
        base64url(&sha256(
            format!("peerwork.owner-checkpoint.v1\0{}\0{index}", self.conversion).as_bytes(),
        ))
    }
    fn sign(
        &self,
        action: &str,
        command_id: &str,
        instance: Option<&str>,
        protocol: Option<&str>,
        body: Value,
    ) -> R<String> {
        let command = json!({"v":1,"audience":self.audience,"command_id":command_id,"actor_id":self.identity.actor_id(),"authority":self.plan.source.authority,"method":"POST","path":"/api/workspace/v1/commands","workspace_id":self.plan.source.workspace_id,"instance_id":instance,"protocol_digest":protocol,"action_id":action,"expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"body":body,"issued_at":self.time,"expires_at":self.time+1});
        let header = base64url(
            wire(
                &json!({"alg":"EdDSA","typ":COMMAND_TYPE,"kid":self.identity.key_id()}),
                CanonicalPath::KERNEL,
            )?
            .as_bytes(),
        );
        let payload = base64url(
            wire(
                &command,
                if action == "structure.checkpoint.instance" {
                    CanonicalPath::Structure { max_depth: 40 }
                } else {
                    CanonicalPath::COMMAND
                },
            )?
            .as_bytes(),
        );
        let signing = format!("{header}.{payload}");
        let jws = format!(
            "{signing}.{}",
            base64url(
                &self
                    .identity
                    .signing_key()
                    .sign(signing.as_bytes())
                    .to_bytes()
            )
        );
        if jws.len() > MAX_LINE - 32 {
            return Err(error("CHECKPOINT_PACKET_LIMIT"));
        }
        verify_structure_author_intent(&jws, &self.audience.encode_utf16().collect::<Vec<_>>())
            .map_err(|_| error("CHECKPOINT_SIGNATURE_INVALID"))?;
        Ok(jws)
    }
    fn page(&mut self, action: &str, instance: Option<&str>, protocol: Option<&str>, mut body: Value) -> R<()> {
        body["profile"] = json!(PROFILE);
        body["conversion_id"] = json!(self.conversion);
        body["page_index"] = json!(self.pages);
        body["previous_digest"] = json!(self.head);
        let jws = self.sign(
            action,
            &self.command_id(self.pages),
            instance,
            protocol,
            body,
        )?;
        writeln!(self.output, "{}", json!({"jws":jws}))
            .map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
        self.head = hashed(&json!([self.head, self.pages, sha256_hex(jws.as_bytes())]))?;
        self.pages += 1;
        if self.pages > 65536 {
            return Err(error("CHECKPOINT_PAGE_LIMIT"));
        }
        Ok(())
    }
    fn records(
        &mut self,
        instance: &str,
        protocol: &str,
        batch: &mut Vec<(Value, Option<String>)>,
    ) -> R<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let id = self.command_id(self.pages);
        let mut contents = Vec::new();
        for (index, (_, body)) in batch.iter().enumerate() {
            if let Some(body) = body {
                if self.keys.is_none() {
                    let mut config = TransportConfig::new(&self.origin);
                    config.allow_loopback_http = self.allow_loopback_http;
                    let mut keys = StructureContentKeys::open(&self.content_keys_path, config)
                        .map_err(|_| error("CHECKPOINT_KEY_STATE_INVALID"))?;
                    keys.ensure_current(self.identity.key_id(), &self.plan.source.workspace_id)
                        .map_err(|_| error("CHECKPOINT_KEY_STATE_INVALID"))?;
                    self.keys = Some(keys);
                }
                let context = StructureContentContext {
                    workspace_id: self.plan.source.workspace_id.clone(),
                    instance_id: instance.into(),
                    protocol_digest: protocol.into(),
                    actor_id: self.identity.actor_id().into(),
                    command_id: id.clone(),
                    action_id: "checkpoint.import".into(),
                    record_index: index as u8,
                };
                let sealed = self
                    .keys
                    .as_ref()
                    .ok_or_else(|| error("CHECKPOINT_KEY_STATE_INVALID"))?
                    .seal(self.identity.key_id(), body.as_bytes(), &context)
                    .map_err(|_| error("CHECKPOINT_BODY_ENCRYPTION_FAILED"))?;
                contents.push(json!({"record_index":index,"body":sealed}));
            }
        }
        let records: Vec<_> = batch.iter().map(|(record, _)| record.clone()).collect();
        self.records += records.len() as u64;
        self.page(
            "structure.checkpoint.records",
            Some(instance),
            Some(protocol),
            json!({"action_id":"checkpoint.import","records":records,"contents":contents}),
        )?;
        batch.clear();
        Ok(())
    }
}

pub fn prepare_owner_checkpoint(request: &PrepareCheckpointRequest) -> R<Value> {
    prepare_with_source(request, None, None)
}
/// A separately authenticated Owner cache can feed the same bounded encoder
/// without ever materializing decrypted source rows or a plan on disk.
pub(crate) fn prepare_verified_owner_checkpoint(
    request: &PrepareCheckpointRequest,
    source: &[u8],
    plan: &Value,
) -> R<Value> {
    if source.len() > 64 * 1024 * 1024 {
        return Err(error("CHECKPOINT_SOURCE_LIMIT"));
    }
    prepare_with_source(request, Some(source), Some(plan))
}
fn prepare_with_source(
    request: &PrepareCheckpointRequest,
    source_bytes: Option<&[u8]>,
    memory_plan: Option<&Value>,
) -> R<Value> {
    let identity = KernelIdentity::open(&request.identity_path)
        .map_err(|_| error("CHECKPOINT_IDENTITY_INVALID"))?;
    if identity.actor_id() != request.expected_actor
        || request.audience.is_empty()
        || request.audience.len() > 200
    {
        return Err(error("CHECKPOINT_ACTOR_OR_AUDIENCE_MISMATCH"));
    }
    let source_file = if source_bytes.is_none() {
        Some(protected(&request.source_path)?)
    } else {
        None
    };
    let mut plan_file = if memory_plan.is_none() {
        Some(protected(&request.plan_path)?)
    } else {
        None
    };
    let source_binding = if let Some(file) = &source_file {
        fingerprint(file)?
    } else {
        json!([
            "VERIFIED_OWNER_CACHE_MEMORY",
            sha256_hex(source_bytes.unwrap())
        ])
    };
    let plan_binding = if let Some(file) = &plan_file {
        fingerprint(file)?
    } else {
        json!([
            "VERIFIED_OWNER_CACHE_MAPPING",
            plan_digest(memory_plan.unwrap())?
        ])
    };
    let mut source: Box<dyn Read + '_> = if let Some(file) = &source_file {
        Box::new(file)
    } else {
        Box::new(std::io::Cursor::new(source_bytes.unwrap()))
    };
    let plan_value = if let Some(plan) = memory_plan {
        plan.clone()
    } else {
        let file = plan_file.as_mut().unwrap();
        if file
            .metadata()
            .map_err(|_| error("CHECKPOINT_FILE_MISSING"))?
            .len()
            > 2 * 1024 * 1024
        {
            return Err(error("CHECKPOINT_PLAN_LIMIT"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| error("CHECKPOINT_SOURCE_READ_FAILED"))?;
        strict_plan(&bytes)?
    };
    let plan: Plan =
        serde_json::from_value(plan_value.clone()).map_err(|_| error("CHECKPOINT_PLAN_INVALID"))?;
    if plan.schema != "peerwork.owner-conversion-map.v1"
        || !matches!(plan.migration_mode.as_str(),"EXECUTABLE"|"READ_ONLY_SNAPSHOT")
        || plan.source.owner_id != identity.actor_id()
        || plan.source.owner_kid != identity.key_id()
        || !token(&plan.source.workspace_id)
        || (plan.source.kind.as_deref()!=Some("PLAIN_PUBLIC")&&plan.source.sequence==0)
        || (plan.source.kind.is_some()&&plan.source.kind.as_deref()!=Some("PLAIN_PUBLIC"))
        || !digest(&plan.source.snapshot_sha256)
        || !digest(&plan.source.authority)
        || !digest(&plan.source.head)
        || !digest(&plan.source.policy_hash)
        || plan.instances.is_empty()
        || plan.instances.len() > 32
        || plan.name.is_empty()
        || plan.name.chars().count() > 120
    {
        return Err(error("CHECKPOINT_PLAN_INVALID"));
    }
    let mapping_digest = plan_digest(&plan_value)?;
    let mut config = TransportConfig::new(&request.origin);
    config.allow_loopback_http = request.allow_loopback_http;
    let origin = crate::transport::HttpTransport::new(config)
        .map_err(|_| error("CHECKPOINT_ORIGIN_INVALID"))?
        .trusted_origin()
        .to_owned();
    let preparation = hashed(&json!([
        "peerwork.owner-checkpoint-preparation.v1",
        request.expected_actor,
        origin,
        request.audience,
        source_binding,
        plan_binding,
        mapping_digest
    ]))?;
    let content_keys_path = request.content_keys_path.clone().unwrap_or_else(|| {
        request.identity_path.with_extension(format!(
            "{}.content-keys.sqlite",
            sha256_hex(origin.as_bytes())
        ))
    });
    crate::kernel_intents::ensure_private_parent(&request.output_path)
        .map_err(|_| error("CHECKPOINT_OUTPUT_PROTECTION_INVALID"))?;
    if request.output_path.exists() {
        return inspect_prepared(
            &request.output_path,
            &identity,
            &request.audience,
            &preparation,
            &content_keys_path,
            &origin,
            request.allow_loopback_http,
        );
    }
    let parent = request
        .output_path
        .parent()
        .ok_or_else(|| error("CHECKPOINT_OUTPUT_PROTECTION_INVALID"))?;
    let pages =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    // These packets are offline evidence only. A constant historical interval
    // avoids depending on client time; snapshot/Owner/digest pins and the
    // operator's isolated target provide the import/replay boundary.
    let conversion = base64url(&sha256(preparation.as_bytes()));
    let time = 0;
    let seed = hashed(&json!([
        "peerwork.owner-checkpoint.v1",
        plan.source,
        mapping_digest,
        conversion
    ]))?;
    let mut builder = Builder {
        identity: &identity,
        keys: None,
        content_keys_path,
        origin,
        allow_loopback_http: request.allow_loopback_http,
        plan: &plan,
        audience: &request.audience,
        conversion: conversion.clone(),
        time,
        head: seed,
        pages: 0,
        records: 0,
        output: pages
            .reopen()
            .map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?,
    };
    let uniqueness_file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    let unique = rusqlite::Connection::open(uniqueness_file.path())
        .map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    unique.execute_batch("CREATE TABLE records(id TEXT PRIMARY KEY,entity TEXT,revision INTEGER,head INTEGER,UNIQUE(entity,revision));CREATE UNIQUE INDEX heads ON records(entity) WHERE head=1;CREATE TABLE relations(source TEXT,kind TEXT,target TEXT,revision INTEGER,PRIMARY KEY(source,kind,target,revision));").map_err(|_|error("CHECKPOINT_OUTPUT_FAILED"))?;
    let mut reader = BufReader::new(&mut source);
    let mut instances = BTreeMap::<String, (Value, String)>::new();
    let mut batch = Vec::new();
    let mut active = String::new();
    let mut batch_bytes = 0;
    let mut record_phase = false;
    let mut relation_phase=false;let mut relation_count=0u64;let mut relation_batch=Vec::new();
    let mut source_row = 0;
    let mapped = (|| -> R<()> {
        while let Some(bytes) = line(&mut reader)? {
            source_row += 1;
            let value = strict(&bytes)?;
            match value["kind"].as_str() {
                Some("instance") => {
                    if record_phase {
                        return Err(error("CHECKPOINT_INSTANCE_ORDER_INVALID"));
                    }
                    let row: InstanceInput = serde_json::from_value(value)
                        .map_err(|_| error("CHECKPOINT_SOURCE_INVALID"))?;
                    let mapping = plan
                        .instances
                        .get(&row.instance_id)
                        .ok_or_else(|| error("CHECKPOINT_INSTANCE_UNMAPPED"))?;
                    if row.kind != "instance"
                        || !token(&row.instance_id)
                        || instances.contains_key(&row.instance_id)
                    {
                        return Err(error("CHECKPOINT_INSTANCE_INVALID"));
                    }
                    let mut state = mapping.manifest["initial_state"].clone();
                    if !state.is_object() {
                        return Err(error("CHECKPOINT_PROTOCOL_INVALID"));
                    }
                    for (key, value) in map_fields(&mapping.state_fields, &row.state)?
                        .as_object()
                        .ok_or_else(|| error("CHECKPOINT_MAPPING_INVALID"))?
                    {
                        state[key] = value.clone();
                    }
                    readable(&state)?;
                    wire(&state, CanonicalPath::KERNEL)?;
                    let (manifest, digest) = normalize(
                        &mapping.manifest,
                        &state,
                        mapping.role_history.as_ref().is_some_and(|h| h.complete),
                    )?;
                    let actions: BTreeSet<_> = manifest["actions"]
                        .as_array()
                        .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?
                        .iter()
                        .filter_map(|a| a["id"].as_str())
                        .collect();
                    if mapping
                        .bootstrap_grant
                        .actions
                        .iter()
                        .any(|a| !actions.contains(a.as_str()))
                    {
                        return Err(error("CHECKPOINT_BOOTSTRAP_ACTION_INVALID"));
                    }
                    validate_grant(&manifest, &mapping.bootstrap_grant)?;
                    let mut page = json!({"instance_id":row.instance_id,"manifest":manifest,"state":state,"bootstrap_grant":mapping.bootstrap_grant});
                    if let Some(history) = &mapping.role_history {
                        if !history.complete
                            || history.claims.len() > 32
                            || history.claims.iter().map(|c| c.roles.len()).sum::<usize>() > 256
                        {
                            return Err(error("CHECKPOINT_ROLE_HISTORY_PAGE_REQUIRED"));
                        }
                        let declared: BTreeSet<_> = manifest["protocol_roles"]
                            .as_array()
                            .ok_or_else(|| error("CHECKPOINT_PROTOCOL_INVALID"))?
                            .iter()
                            .filter_map(Value::as_str)
                            .collect();
                        let mut actors = BTreeSet::new();
                        for claim in &history.claims {
                            if !token(&claim.actor_id)
                                || !actors.insert(&claim.actor_id)
                                || claim.roles.len() > 32
                                || claim.roles.iter().collect::<BTreeSet<_>>().len()
                                    != claim.roles.len()
                                || claim
                                    .roles
                                    .iter()
                                    .any(|role| !declared.contains(role.as_str()))
                            {
                                return Err(error("CHECKPOINT_ROLE_HISTORY_INVALID"));
                            }
                        }
                        page["role_history"] = serde_json::to_value(history)
                            .map_err(|_| error("CHECKPOINT_ROLE_HISTORY_INVALID"))?;
                    }
                    builder.page(
                        "structure.checkpoint.instance",
                        Some(&row.instance_id),
                        Some(&digest),
                        page,
                    )?;
                    instances.insert(row.instance_id, (manifest, digest));
                }
                Some("record") => {
                    if relation_phase{return Err(error("CHECKPOINT_RELATION_ORDER_INVALID"))}
                    record_phase = true;
                    if instances.len() != plan.instances.len() {
                        return Err(error("CHECKPOINT_INSTANCE_MISSING"));
                    }
                    let row: RecordInput = serde_json::from_value(value)
                        .map_err(|_| error("CHECKPOINT_SOURCE_INVALID"))?;
                    let (manifest, _protocol) = instances
                        .get(&row.instance_id)
                        .ok_or_else(|| error("CHECKPOINT_INSTANCE_UNMAPPED"))?;
                    let mapping = plan
                        .instances
                        .get(&row.instance_id)
                        .and_then(|mapping| mapping.record_mappings.get(&row.schema))
                        .or_else(|| plan.schemas.get(&row.schema))
                        .ok_or_else(|| error("CHECKPOINT_SCHEMA_UNMAPPED"))?;
                    if row.kind != "record"
                        || ![&row.record_id, &row.entity_id, &row.legacy_source.actor_id]
                            .into_iter()
                            .all(|s| token(s))
                        || row.revision == 0
                        || row.revision > 9007199254740991
                        || (row.legacy_source.sequence==0&&plan.source.kind.as_deref()!=Some("PLAIN_PUBLIC"))
                        || row.legacy_source.sequence > plan.source.sequence
                        || !digest(&row.legacy_source.commit_hash)
                        || row
                            .legacy_source
                            .record_actor_id
                            .as_ref()
                            .is_some_and(|actor| !token(actor))
                        || row
                            .legacy_source
                            .created_at
                            .is_some_and(|time| time > 9007199254740991)
                    {
                        return Err(error("CHECKPOINT_RECORD_INVALID"));
                    }
                    unique
                        .execute(
                            "INSERT INTO records VALUES(?1,?2,?3,?4)",
                            rusqlite::params![
                                row.record_id,
                                row.entity_id,
                                row.revision,
                                row.is_head as i64
                            ],
                        )
                        .map_err(|_| error("CHECKPOINT_DUPLICATE_RECORD_OR_HEAD"))?;
                    let structure = map_fields(&mapping.structure_fields, &row.fields)?;
                    if mapping.strict_body_separation
                        && crate::owner_cache_plan::has_narrative_fields(&structure)
                    {
                        return Err(error("CHECKPOINT_MIXED_CONTENT_FIELD_REQUIRES_MAPPING"));
                    }
                    validate_record(manifest, &mapping.target_schema, &structure)?;
                    if mapping.body_field.is_some() && !mapping.body_fields.is_empty() {
                        return Err(error("CHECKPOINT_BODY_MAPPING_CONFLICT"));
                    }
                    let body = if !mapping.body_fields.is_empty() {
                        let mut body = serde_json::Map::new();
                        for (name, path) in &mapping.body_fields {
                            let item = selected(&row.fields, path)?;
                            if !item.is_string() {
                                return Err(error("CHECKPOINT_BODY_MUST_BE_TEXT"));
                            }
                            body.insert(name.clone(), item);
                        }
                        Some(
                            serde_json::to_string(&Value::Object(body))
                                .map_err(|_| error("CHECKPOINT_BODY_MUST_BE_TEXT"))?,
                        )
                    } else {
                        match &mapping.body_field {
                            None => None,
                            Some(path) => {
                                let selected = selected(&row.fields, path)?;
                                Some(
                                    selected
                                        .as_str()
                                        .ok_or_else(|| error("CHECKPOINT_BODY_MUST_BE_TEXT"))?
                                        .to_owned(),
                                )
                            }
                        }
                    };
                    if body
                        .as_ref()
                        .is_some_and(|s| s.len() > peerwork_core::structure_content::MAX_BODY_BYTES)
                    {
                        return Err(error("CHECKPOINT_BODY_LIMIT"));
                    }
                    let record = json!({"record_id":row.record_id,"entity_id":row.entity_id,"revision":row.revision,"is_head":row.is_head,"schema":mapping.target_schema,"structure":structure,"legacy_source":row.legacy_source});
                    let size = serde_json::to_vec(&record)
                        .map_err(|_| error("CHECKPOINT_RECORD_INVALID"))?
                        .len()
                        + body.as_ref().map(|s| s.len() * 4 / 3 + 1024).unwrap_or(0);
                    if !batch.is_empty()
                        && (batch.len() == 8
                            || active != row.instance_id
                            || batch_bytes + size > 60000)
                    {
                        let previous = &instances[&active].1;
                        builder.records(&active, previous, &mut batch)?;
                        batch_bytes = 0;
                    }
                    active = row.instance_id;
                    batch.push((record, body));
                    batch_bytes += size;
                }
                Some("relation")=>{
                    record_phase=true;relation_phase=true;
                    if !batch.is_empty(){builder.records(&active,&instances[&active].1,&mut batch)?;batch_bytes=0;}
                    let row:RelationInput=serde_json::from_value(value).map_err(|_|error("CHECKPOINT_RELATION_INVALID"))?;
                    if row.kind!="relation"||!token(&row.record_id)||!token(&row.target_record)||row.relation_kind.is_empty()||row.relation_kind.encode_utf16().count()>120||row.target_revision==0||row.target_revision>9_007_199_254_740_991{return Err(error("CHECKPOINT_RELATION_INVALID"))}
                    let source:Option<u64>=unique.query_row("SELECT revision FROM records WHERE id=?1",[&row.record_id],|r|r.get(0)).optional().map_err(|_|error("CHECKPOINT_OUTPUT_FAILED"))?;
                    let target:Option<u64>=unique.query_row("SELECT revision FROM records WHERE id=?1",[&row.target_record],|r|r.get(0)).optional().map_err(|_|error("CHECKPOINT_OUTPUT_FAILED"))?;
                    if source.is_none()||target!=Some(row.target_revision){return Err(error("CHECKPOINT_RELATION_REFERENCE_INVALID"))}
                    unique.execute("INSERT INTO relations VALUES(?1,?2,?3,?4)",rusqlite::params![row.record_id,row.relation_kind,row.target_record,row.target_revision]).map_err(|_|error("CHECKPOINT_RELATION_DUPLICATE"))?;
                    relation_count+=1;if relation_count>50_000{return Err(error("CHECKPOINT_RELATION_LIMIT"))}
                    relation_batch.push(json!({"record_id":row.record_id,"kind":row.relation_kind,"target_record":row.target_record,"target_revision":row.target_revision}));
                    if relation_batch.len()==32{builder.page("structure.checkpoint.relations",None,None,json!({"relations":std::mem::take(&mut relation_batch)}))?;}
                },
                _ => return Err(error("CHECKPOINT_SOURCE_INVALID")),
            }
        }
        Ok(())
    })();
    mapped.map_err(|mut error| {
        let mut details = error.1.take().unwrap_or_else(|| json!({}));
        details["source_row"] = json!(source_row);
        error.1 = Some(details);
        error
    })?;
    if instances.len() != plan.instances.len() {
        return Err(error("CHECKPOINT_INSTANCE_MISSING"));
    }
    if !batch.is_empty() {
        builder.records(&active, &instances[&active].1, &mut batch)?;
    }
    if !relation_batch.is_empty(){builder.page("structure.checkpoint.relations",None,None,json!({"relations":relation_batch}))?;}
    if source_file
        .as_ref()
        .map(fingerprint)
        .transpose()?
        .is_some_and(|v| v != source_binding)
        || plan_file
            .as_ref()
            .map(fingerprint)
            .transpose()?
            .is_some_and(|v| v != plan_binding)
    {
        return Err(error("CHECKPOINT_SOURCE_CHANGED"));
    }
    builder
        .output
        .sync_all()
        .map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    let mut begin_body=json!({"profile":PROFILE,"conversion_id":conversion,"source_binding":"WORKSPACE_FRONTIER","source":plan.source,"mapping_digest":mapping_digest,"preparation_digest":preparation,"name":plan.name,"workspace_alias":plan.workspace_alias,"page_count":builder.pages,"instance_count":instances.len(),"record_count":builder.records,"final_digest":builder.head});
    if plan.migration_mode=="READ_ONLY_SNAPSHOT"{begin_body["migration_mode"]=json!(plan.migration_mode);}
    if relation_count>0{begin_body["relation_count"]=json!(relation_count);}
    let begin=builder.sign("structure.checkpoint.begin",&conversion,None,None,begin_body)?;
    let mut final_file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    writeln!(final_file, "{}", json!({"jws":begin}))
        .map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    let mut input = File::open(pages.path()).map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    std::io::copy(&mut input, &mut final_file).map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    final_file
        .as_file()
        .sync_all()
        .map_err(|_| error("CHECKPOINT_OUTPUT_FAILED"))?;
    final_file
        .persist_noclobber(&request.output_path)
        .map_err(|_| error("CHECKPOINT_OUTPUT_EXISTS"))?;
    Ok(
        json!({"status":"PREPARED_OFFLINE","assurance":"OWNER_ATTESTED_CONVERSION","workspace_id":plan.source.workspace_id,"conversion_id":conversion,"pages":builder.pages,"records":builder.records,"relations":relation_count,"mapping_digest":mapping_digest,"preparation_digest":preparation,"output_path":request.output_path,"network_requests":0,"body_key_status":if builder.keys.is_some(){"AVAILABLE"}else{"NOT_REQUIRED"}}),
    )
}
fn inspect_prepared(
    path: &Path,
    identity: &KernelIdentity,
    audience: &str,
    preparation: &str,
    content_keys_path: &Path,
    origin: &str,
    allow_loopback_http: bool,
) -> R<Value> {
    let mut reader = BufReader::new(protected(path)?);
    let first = line(&mut reader)?.ok_or_else(|| error("CHECKPOINT_OUTPUT_INVALID"))?;
    let envelope = strict(&first)?;
    let jws = envelope["jws"]
        .as_str()
        .ok_or_else(|| error("CHECKPOINT_OUTPUT_INVALID"))?;
    let owner = verify_structure_author_intent(jws, &audience.encode_utf16().collect::<Vec<_>>())
        .map_err(|_| error("CHECKPOINT_OUTPUT_INVALID"))?;
    let command: Value = serde_json::from_str(&wire_value(owner.command())?)
        .map_err(|_| error("CHECKPOINT_OUTPUT_INVALID"))?;
    let b = &command["body"];
    if owner.actor_id() != identity.actor_id()
        || owner.action_id() != "structure.checkpoint.begin"
        || b["source_binding"] != "WORKSPACE_FRONTIER"
        || b["preparation_digest"] != preparation
    {
        return Err(error("CHECKPOINT_OUTPUT_CONFLICT"));
    }
    let mut head = hashed(&json!([
        "peerwork.owner-checkpoint.v1",
        b["source"],
        b["mapping_digest"],
        b["conversion_id"]
    ]))?;
    let mut pages = 0;
    let mut keys: Option<StructureContentKeys> = None;
    let mut keys_checked = false;
    let mut body_key_status = "NOT_REQUIRED";
    let mut relation_count=0u64;
    while let Some(line) = line(&mut reader)? {
        let v = strict(&line)?;
        let jws = v["jws"]
            .as_str()
            .ok_or_else(|| error("CHECKPOINT_OUTPUT_INVALID"))?;
        let page =
            verify_structure_author_intent(jws, &audience.encode_utf16().collect::<Vec<_>>())
                .map_err(|_| error("CHECKPOINT_OUTPUT_INVALID"))?;
        let c: Value = serde_json::from_str(&wire_value(page.command())?)
            .map_err(|_| error("CHECKPOINT_OUTPUT_INVALID"))?;
        if page.actor_id() != owner.actor_id()
            || page.workspace_id() != owner.workspace_id()
            || c["body"]["conversion_id"] != b["conversion_id"]
            || c["body"]["page_index"] != pages
            || c["body"]["previous_digest"] != head
        {
            return Err(error("CHECKPOINT_OUTPUT_INVALID"));
        }
        head = hashed(&json!([head, pages, sha256_hex(jws.as_bytes())]))?;
        pages += 1;
        if page.action_id()=="structure.checkpoint.relations" {
            let relations=c["body"]["relations"].as_array().filter(|r|!r.is_empty()&&r.len()<=32).ok_or_else(||error("CHECKPOINT_OUTPUT_INVALID"))?;
            if !c["instance_id"].is_null()||!c["protocol_digest"].is_null(){return Err(error("CHECKPOINT_OUTPUT_INVALID"))}relation_count+=relations.len() as u64;
        }
        if page.action_id() == "structure.checkpoint.records" {
            for content in c["body"]["contents"]
                .as_array()
                .ok_or_else(|| error("CHECKPOINT_OUTPUT_INVALID"))?
            {
                let index = content["record_index"]
                    .as_u64()
                    .filter(|n| *n < 8)
                    .ok_or_else(|| error("CHECKPOINT_OUTPUT_INVALID"))?;
                if !keys_checked {
                    keys_checked = true;
                    if content_keys_path.is_file() {
                        let mut config = TransportConfig::new(origin);
                        config.allow_loopback_http = allow_loopback_http;
                        match StructureContentKeys::open(content_keys_path, config) {
                            Ok(value) => {
                                keys = Some(value);
                                body_key_status = "AVAILABLE";
                            }
                            Err(_) => body_key_status = "INTEGRITY_FAILED",
                        }
                    } else {
                        body_key_status = "UNAVAILABLE";
                    }
                }
                if let Some(keys) = &keys {
                    if let Err(error) =
                        keys.open_authored_body(identity.key_id(), &page, index as u8)
                    {
                        if matches!(error, crate::kernel_intents::ContentKeyError::Missing) {
                            if body_key_status != "INTEGRITY_FAILED" {
                                body_key_status = "UNAVAILABLE";
                            }
                        } else {
                            body_key_status = "INTEGRITY_FAILED";
                        }
                    }
                }
            }
        }
    }
    if pages != b["page_count"].as_u64().unwrap_or(u64::MAX) || head != b["final_digest"] || relation_count!=b.get("relation_count").and_then(Value::as_u64).unwrap_or(0) {
        return Err(error("CHECKPOINT_OUTPUT_INVALID"));
    }
    Ok(
        json!({"status":"PREPARED_OFFLINE","reused":true,"workspace_id":owner.workspace_id(),"conversion_id":b["conversion_id"],"pages":pages,"records":b["record_count"],"relations":relation_count,"mapping_digest":b["mapping_digest"],"preparation_digest":preparation,"output_path":path,"network_requests":0,"body_key_status":body_key_status,"body_key_recovery_needed":matches!(body_key_status,"UNAVAILABLE"|"INTEGRITY_FAILED")}),
    )
}
fn wire_value(value: &peerwork_core::wire_json::WireValue) -> R<String> {
    canonical_wire_value(
        value,
        peerwork_core::prepared_command::command_canonical_path(value),
    )
    .map_err(|_| error("CHECKPOINT_OUTPUT_INVALID"))
}
pub fn prepare_owner_checkpoint_json(request: &str) -> String {
    let result = (|| {
        if request.len() > 65536 {
            return Err(error("CHECKPOINT_REQUEST_LIMIT"));
        }
        let value = strict(request.as_bytes())?;
        let request: PrepareCheckpointRequest =
            serde_json::from_value(value).map_err(|_| error("CHECKPOINT_REQUEST_INVALID"))?;
        prepare_owner_checkpoint(&request)
    })();
    match result{Ok(value)=>json!({"ok":true,"value":value}).to_string(),Err(error)=>json!({"ok":false,"code":error.0,"stage":"OFFLINE_CONVERSION_PREPARATION","effect_certainty":"NOT_SUBMITTED","recovery":"CORRECT_INPUT_OR_REOPEN_SAME_OUTPUT","diagnostic":error.1}).to_string()}
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn save(path: &Path, value: &str) {
        std::fs::write(path, value).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fixture_request(directory: &Path, count: usize) -> PrepareCheckpointRequest {
        let identity = KernelIdentity::create(&directory.join("identity.state")).unwrap();
        let workspace = "W".repeat(43);
        let instance = "I".repeat(43);
        let manifest = json!({"name":"checkpoint-test","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{"holder":null},"record_schemas":{"note":{"type":"object","fields":{"status":"string"},"required":["status"],"max_bytes":256}},"actions":[{"id":"claim","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":[]}]}]});
        let plan = json!({"schema":"peerwork.owner-conversion-map.v1","source":{"snapshot_sha256":"a".repeat(64),"workspace_id":workspace,"owner_id":identity.actor_id(),"owner_kid":identity.key_id(),"authority":sha256_hex(identity.actor_id().as_bytes()),"sequence":1,"head":"b".repeat(64),"policy_hash":"c".repeat(64)},"name":"converted","workspace_alias":null,"instances":{(instance.clone()):{"manifest":manifest,"state_fields":{"holder":["lease","holder"]},"bootstrap_grant":{"actions":["claim"],"protocol_roles":[],"capabilities":[]}}},"schemas":{"old-note":{"target_schema":"note","structure_fields":{"status":["status"]},"body_field":["private_body"]}}});
        let mut source = format!(
            "{}\n",
            json!({"kind":"instance","instance_id":instance,"state":{"lease":{"holder":null},"unmapped_secret":"DO NOT DISCLOSE"}})
        );
        for i in 0..count {
            let id = base64url(&sha256(format!("record-{i}").as_bytes()));
            source.push_str(&format!("{}\n",json!({"kind":"record","instance_id":instance,"record_id":id,"entity_id":id,"revision":1,"is_head":true,"schema":"old-note","fields":{"status":"open","private_body":"PRIVATE BODY ONLY","unmapped_secret":"DO NOT DISCLOSE"},"legacy_source":{"sequence":1,"commit_hash":"b".repeat(64),"record_id":id,"revision":1,"actor_id":identity.actor_id()}})));
        }
        save(&directory.join("plan.json"), &plan.to_string());
        save(&directory.join("source.jsonl"), &source);
        PrepareCheckpointRequest {
            identity_path: directory.join("identity.state"),
            expected_actor: identity.actor_id().into(),
            origin: "https://example.invalid".into(),
            audience: "checkpoint-test".into(),
            source_path: directory.join("source.jsonl"),
            plan_path: directory.join("plan.json"),
            output_path: directory.join("checkpoint.jsonl"),
            content_keys_path: Some(directory.join("body-keys.sqlite")),
            allow_loopback_http: false,
        }
    }
    #[test]
    fn incompatible_target_is_rejected_before_owner_cache_or_network_work() {
        let dir=crate::test_support::protected_test_dir();
        let request=fixture_request(dir.path(),0);
        let mut plan:Value=serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        let instance="I".repeat(43);
        plan["instances"][&instance]["manifest"]["constraints"]=json!({"retained_constraint":[{"op":"eq","left":{"from":"literal","value":1},"right":{"from":"literal","value":1}}]});
        save(&request.plan_path,&plan.to_string());
        std::fs::remove_file(&request.identity_path).unwrap();
        std::fs::remove_file(&request.source_path).unwrap();
        let value:Value=serde_json::from_str(&crate::owner_cache_checkpoint::prepare_owner_checkpoint_from_cache_json(&json!({"state_dir":dir.path(),"workspace_id":plan["source"]["workspace_id"],"expected_actor":request.expected_actor,"plan_path":request.plan_path,"output_path":request.output_path,"origin":"https://example.invalid","audience":"checkpoint-test","refresh_source":true}).to_string())).unwrap();
        assert_eq!(value["code"],"CHECKPOINT_PROTOCOL_UNSUPPORTED");
        assert_eq!(value["diagnostic"]["phase"],"TARGET_PROTOCOL_PREFLIGHT");
        assert_eq!(value["diagnostic"]["instance_id"],instance);
        assert!(!request.identity_path.exists());assert!(!request.output_path.exists());
        assert!(!request.content_keys_path.unwrap().exists());
    }
    #[test]
    fn signing_large_valid_programs_uses_the_program_budget_and_keeps_actions_small() {
        let dir = crate::test_support::protected_test_dir();
        let request = fixture_request(dir.path(), 0);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        let manifest = &mut plan["instances"]["I".repeat(43)]["manifest"];
        let action = manifest["actions"][0].clone();
        manifest["actions"]=json!((0..32).map(|i|{let mut row=action.clone();row["id"]=json!(if i==0{"claim".into()}else{format!("claim.{i}")});row["variants"][0]["when"]=json!((0..8).map(|_|json!({"op":"eq","left":{"from":"literal","value":1},"right":{"from":"literal","value":1}})).collect::<Vec<_>>());row}).collect::<Vec<_>>());
        assert!(wire(manifest, CanonicalPath::COMMAND).is_err());
        let source = zeroize::Zeroizing::new(std::fs::read(&request.source_path).unwrap());
        let prepared = prepare_verified_owner_checkpoint(&request, &source, &plan).unwrap();
        assert_eq!(prepared["pages"], 1);
        assert_eq!(
            prepare_verified_owner_checkpoint(&request, &source, &plan).unwrap()["reused"],
            true
        );
    }
    #[test]
    fn workspace_mapping_does_not_share_a_single_program_node_budget() {
        let dir = crate::test_support::protected_test_dir();
        let request = fixture_request(dir.path(), 0);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        let mut mapping = plan["instances"]["I".repeat(43)].clone();
        let action = mapping["manifest"]["actions"][0].clone();
        mapping["manifest"]["actions"] = json!((0..32)
            .map(|i| {
                let mut a = action.clone();
                a["id"] = json!(if i == 0 {
                    "claim".into()
                } else {
                    format!("claim.{i}")
                });
                a
            })
            .collect::<Vec<_>>());
        let mut instances = serde_json::Map::new();
        let mut source = String::new();
        for i in 0..24 {
            let id = base64url(&sha256(format!("instance-{i}").as_bytes()));
            instances.insert(id.clone(), mapping.clone());
            source.push_str(&format!(
                "{}\n",
                json!({"kind":"instance","instance_id":id,"state":{"lease":{"holder":null}}})
            ));
        }
        plan["instances"] = Value::Object(instances);
        let bytes = zeroize::Zeroizing::new(source.into_bytes());
        assert!(wire(&plan, CanonicalPath::STRUCTURED).is_err());
        assert_eq!(
            prepare_verified_owner_checkpoint(&request, &bytes, &plan).unwrap()["pages"],
            24
        );
    }
    #[test]
    fn readable_primitive_declarations_preserve_the_original_business_type() {
        let dir = crate::test_support::protected_test_dir();
        let request = fixture_request(dir.path(), 1);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        plan["instances"]["I".repeat(43)]["manifest"]["record_schemas"]["note"]["protection"] =
            json!({"v":1,"fields":{"status":{"protection":"server_readable","type":"string"}}});
        save(&request.plan_path, &plan.to_string());
        assert_eq!(prepare_owner_checkpoint(&request).unwrap()["records"], 1);
    }
    #[test]
    fn record_mapping_is_selected_in_its_instance_scope() {
        let dir = crate::test_support::protected_test_dir();
        let request = fixture_request(dir.path(), 2);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        let mappings = plan["schemas"].take();
        plan["schemas"] = json!({"old-note":{"target_schema":"wrong-global-schema","structure_fields":{},"body_field":null}});
        plan["instances"]["I".repeat(43)]["record_mappings"] = mappings;
        save(&request.plan_path, &plan.to_string());
        assert_eq!(prepare_owner_checkpoint(&request).unwrap()["records"], 2);
    }
    #[test]
    fn authenticated_memory_source_needs_no_plaintext_files_and_reuses_exact_output() {
        let dir = crate::test_support::protected_test_dir();
        let request = fixture_request(dir.path(), 17);
        let rows = zeroize::Zeroizing::new(std::fs::read(&request.source_path).unwrap());
        let plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        std::fs::remove_file(&request.source_path).unwrap();
        std::fs::remove_file(&request.plan_path).unwrap();
        let result = prepare_verified_owner_checkpoint(&request, &rows, &plan).unwrap();
        assert_eq!(result["pages"], 4);
        assert_eq!(result["records"], 17);
        let bytes = std::fs::read(&request.output_path).unwrap();
        let again = prepare_verified_owner_checkpoint(&request, &rows, &plan).unwrap();
        assert_eq!(again["reused"], true);
        assert_eq!(std::fs::read(&request.output_path).unwrap(), bytes);
        assert!(!request.source_path.exists());
        assert!(!request.plan_path.exists());
        for line in std::str::from_utf8(&bytes).unwrap().lines() {
            let envelope: Value = serde_json::from_str(line).unwrap();
            let proof = verify_structure_author_intent(
                envelope["jws"].as_str().unwrap(),
                &request.audience.encode_utf16().collect::<Vec<_>>(),
            )
            .unwrap();
            let command = wire_value(proof.command()).unwrap();
            assert!(!command.contains("PRIVATE BODY ONLY"));
            assert!(!command.contains("DO NOT DISCLOSE"));
        }
    }
    #[test]
    fn offline_checkpoint_automatically_splits_encrypts_and_reuses_signed_artifact() {
        let directory = crate::test_support::protected_test_dir();
        let mut request = fixture_request(directory.path(), 40);
        let before = std::fs::read(&request.identity_path).unwrap();
        let result = prepare_owner_checkpoint(&request).unwrap();
        assert_eq!(result["pages"], 6);
        assert_eq!(result["records"], 40);
        assert_eq!(result["network_requests"], 0);
        let saved = std::fs::read(&request.output_path).unwrap();
        let text = String::from_utf8(saved.clone()).unwrap();
        for line in text.lines() {
            let envelope: Value = serde_json::from_str(line).unwrap();
            let author = verify_structure_author_intent(
                envelope["jws"].as_str().unwrap(),
                &request.audience.encode_utf16().collect::<Vec<_>>(),
            )
            .unwrap();
            let command = wire_value(author.command()).unwrap();
            assert!(!command.contains("PRIVATE BODY ONLY"));
            assert!(!command.contains("DO NOT DISCLOSE"));
        }
        request.origin.push('/'); // Canonically equivalent service root.
        let again = prepare_owner_checkpoint(&request).unwrap();
        assert_eq!(again["reused"], true);
        assert_eq!(std::fs::read(&request.output_path).unwrap(), saved);
        assert_eq!(std::fs::read(&request.identity_path).unwrap(), before);
    }
    #[test]
    fn missing_mapping_fails_locally_without_leaving_an_import_artifact() {
        let directory = crate::test_support::protected_test_dir();
        let request = fixture_request(directory.path(), 1);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        plan["schemas"] = json!({});
        save(&request.plan_path, &plan.to_string());
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap_err().0,
            "CHECKPOINT_SCHEMA_UNMAPPED"
        );
        assert!(!request.output_path.exists());
    }
    #[test]
    fn wrong_actor_and_unprotected_source_are_rejected_before_preparation() {
        let directory = crate::test_support::protected_test_dir();
        let mut request = fixture_request(directory.path(), 1);
        let actor = request.expected_actor.clone();
        request.expected_actor = "A".repeat(43);
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap_err().0,
            "CHECKPOINT_ACTOR_OR_AUDIENCE_MISMATCH"
        );
        request.expected_actor = actor;
        std::fs::set_permissions(&request.source_path, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap_err().0,
            "CHECKPOINT_FILE_PROTECTION_INVALID"
        );
    }
    #[test]
    fn duplicate_current_heads_and_corrupted_saved_outputs_fail_locally() {
        let directory = crate::test_support::protected_test_dir();
        let request = fixture_request(directory.path(), 1);
        let mut source = std::fs::read_to_string(&request.source_path).unwrap();
        let duplicate = source.lines().nth(1).unwrap().to_owned();
        source.push_str(&duplicate);
        source.push('\n');
        save(&request.source_path, &source);
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap_err().0,
            "CHECKPOINT_DUPLICATE_RECORD_OR_HEAD"
        );
        let directory = crate::test_support::protected_test_dir();
        let request = fixture_request(directory.path(), 1);
        prepare_owner_checkpoint(&request).unwrap();
        let original = std::fs::read_to_string(&request.output_path).unwrap();
        save(
            &request.output_path,
            &format!("{}\n", original.lines().next().unwrap()),
        );
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap_err().0,
            "CHECKPOINT_OUTPUT_INVALID"
        );
    }
    #[test]
    fn reopening_a_prepared_conversion_never_replaces_a_missing_body_key() {
        let directory = crate::test_support::protected_test_dir();
        let request = fixture_request(directory.path(), 1);
        prepare_owner_checkpoint(&request).unwrap();
        let path = request.content_keys_path.as_ref().unwrap();
        std::fs::rename(path, directory.path().join("saved-body-keys.sqlite")).unwrap();
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap()["body_key_status"],
            "UNAVAILABLE"
        );
        assert!(!path.exists());
    }
    #[test]
    fn structural_conversion_never_requires_or_creates_body_key_state() {
        let directory = crate::test_support::protected_test_dir();
        let request = fixture_request(directory.path(), 1);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        plan["schemas"]["old-note"]["body_field"] = Value::Null;
        save(&request.plan_path, &plan.to_string());
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap()["body_key_status"],
            "NOT_REQUIRED"
        );
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap()["body_key_status"],
            "NOT_REQUIRED"
        );
        assert!(!request.content_keys_path.unwrap().exists());
    }
    #[test]
    fn historical_separation_of_duties_cannot_be_silently_reset_by_conversion() {
        let directory = crate::test_support::protected_test_dir();
        let request = fixture_request(directory.path(), 0);
        let mut plan: Value =
            serde_json::from_slice(&std::fs::read(&request.plan_path).unwrap()).unwrap();
        let manifest = &mut plan["instances"]["I".repeat(43)]["manifest"];
        manifest["protocol_roles"] = json!(["AUTHOR", "REVIEWER"]);
        manifest["historical_role_conflicts"] = json!([["AUTHOR", "REVIEWER"]]);
        save(&request.plan_path, &plan.to_string());
        assert_eq!(
            prepare_owner_checkpoint(&request).unwrap_err().0,
            "CHECKPOINT_HISTORICAL_ROLE_MAPPING_REQUIRED"
        );
        assert!(!request.output_path.exists());
    }
    #[test]
    fn relations_preserve_cycles_in_signed_bounded_pages_and_reopen_exactly(){
        let dir=crate::test_support::protected_test_dir();let request=fixture_request(dir.path(),2);let first=base64url(&sha256(b"record-0"));let second=base64url(&sha256(b"record-1"));let mut rows=std::fs::read_to_string(&request.source_path).unwrap();
        for i in 0..65{let (source,target)=if i%2==0{(&first,&second)}else{(&second,&first)};rows.push_str(&format!("{}\n",json!({"kind":"relation","record_id":source,"relation_kind":format!("ref-{i}"),"target_record":target,"target_revision":1})));}save(&request.source_path,&rows);
        let result=prepare_owner_checkpoint(&request).unwrap();assert_eq!(result["relations"],65);assert_eq!(result["pages"],5);let signed=std::fs::read(&request.output_path).unwrap();let mut relation_pages=0;let mut links=0;
        for line in std::str::from_utf8(&signed).unwrap().lines(){let line:Value=serde_json::from_str(line).unwrap();let body=peerwork_core::crypto::decode_base64url(line["jws"].as_str().unwrap().split('.').nth(1).unwrap()).unwrap();let command:Value=serde_json::from_slice(&body).unwrap();if command["action_id"]=="structure.checkpoint.begin"{assert_eq!(command["body"]["relation_count"],65);}if command["action_id"]=="structure.checkpoint.relations"{assert!(command["instance_id"].is_null());let page=command["body"]["relations"].as_array().unwrap();assert!(page.len()<=32);relation_pages+=1;links+=page.len();}}
        assert_eq!(relation_pages,3);assert_eq!(links,65);assert_eq!(prepare_owner_checkpoint(&request).unwrap()["relations"],65);assert_eq!(std::fs::read(&request.output_path).unwrap(),signed);
    }
    #[test]
    fn missing_duplicate_or_wrong_revision_relations_fail_without_an_output(){
        for mode in ["MISSING","REVISION","DUPLICATE"]{let dir=crate::test_support::protected_test_dir();let request=fixture_request(dir.path(),2);let mut rows=std::fs::read_to_string(&request.source_path).unwrap();let link=json!({"kind":"relation","record_id":base64url(&sha256(b"record-0")),"relation_kind":"ref","target_record":if mode=="MISSING"{"M".repeat(43)}else{base64url(&sha256(b"record-1"))},"target_revision":if mode=="REVISION"{2}else{1}});rows.push_str(&format!("{link}\n"));if mode=="DUPLICATE"{rows.push_str(&format!("{link}\n"));}save(&request.source_path,&rows);assert_eq!(prepare_owner_checkpoint(&request).unwrap_err().0,if mode=="DUPLICATE"{"CHECKPOINT_RELATION_DUPLICATE"}else{"CHECKPOINT_RELATION_REFERENCE_INVALID"});assert!(!request.output_path.exists());}
    }

}
