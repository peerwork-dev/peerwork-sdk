//! Owner-local field review, never an online legacy reader. Run only after
//! pausing the Owner watcher and confirming no other Owner operation is active.
//! The identity is never copied. Active encrypted cache/keyring copies remain
//! in a private temporary directory next to the Owner's report and are removed.
use crate::{
    kernel_identity::KernelIdentity, secure_read_access::SecureReadAccessError,
    secure_read_profile::SecureReadProfile,
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    wire_json::{canonical_wire_value, WireValue},
};
use serde::{Deserialize,Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    state_dir: PathBuf,
    workspace_id: String,
    report_path: PathBuf,
    expected_actor: Option<String>,
    #[serde(default)] cache_selection:OwnerCacheSelection,
    #[serde(default)] refresh_source:bool,
}
/// Select only named local caches. All selections still prove the saved
/// ACTIVE floor, complete transport, signatures and decryption. Selection is
/// exclusively for an Owner-signed offline conversion, never legacy activation.
#[derive(Clone,Copy,Debug,Default,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub(crate) enum OwnerCacheSelection {#[default] Active, Recovery, Install}
impl OwnerCacheSelection {
 fn prefix(self,slot:u8)->String{match self{Self::Active=>format!("read-{slot}.state"),Self::Recovery=>"private-recovery-read.state".into(),Self::Install=>"private-install-read.state".into()}}
}
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct Error(pub(crate) &'static str, pub(crate) Option<Value>);
type R<T> = Result<T, Error>;
impl From<SecureReadAccessError> for Error {
    fn from(error: SecureReadAccessError) -> Self {
        let mut diagnostic=json!({"source_code":error.code()});
        if let SecureReadAccessError::ReadDetail{stage,class,http_status}=&error{diagnostic["source_phase"]=json!(stage);diagnostic["source_class"]=json!(class);diagnostic["http_status"]=json!(http_status);}
        Self("OWNER_CACHE_REVIEW_FAILED",Some(diagnostic))
    }
}
fn private_file(path: &Path) -> R<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| Error("OWNER_CACHE_FILE_MISSING", None))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error("OWNER_CACHE_PROTECTION_INVALID", None));
    }
    crate::kernel_intents::ensure_private_parent(path)
        .map_err(|_| Error("OWNER_CACHE_PROTECTION_INVALID", None))?;
    crate::kernel_intents::create_or_check_private_file(path)
        .map_err(|_| Error("OWNER_CACHE_PROTECTION_INVALID", None))
}
fn stamp(path: &Path) -> R<Value> {
    let m = fs::symlink_metadata(path).map_err(|_| Error("OWNER_CACHE_FILE_MISSING", None))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(json!([
            m.len(),
            m.ino(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ]))
    }
    #[cfg(not(unix))]
    {
        Ok(json!([
            m.len(),
            m.modified()
                .map_err(|_| Error("OWNER_CACHE_FILE_MISSING", None))?
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error("OWNER_CACHE_FILE_MISSING", None))?
                .as_nanos()
                .to_string()
        ]))
    }
}
fn value(source: &WireValue) -> R<Value> {
    serde_json::from_str(
        &canonical_wire_value(source, CanonicalPath::SecureArtifact)
            .map_err(|_| Error("OWNER_CACHE_OBJECT_INVALID", None))?,
    )
    .map_err(|_| Error("OWNER_CACHE_OBJECT_INVALID", None))
}
fn decoded(mut source: Value) -> Value {
    if let Some(text) = source.as_str() {
        if text.len() <= 65536 {
            if let Ok(parsed) = serde_json::from_str(text) {
                source = parsed;
            }
        }
    }
    source
}
fn fields(source: &Value, path: Vec<String>, out: &mut Vec<Value>, remaining: &mut usize) {
    if *remaining == 0 {
        return;
    }
    *remaining -= 1;
    let kind = match source {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    out.push(json!({"path":path,"type":kind}));
    if path.len() >= 6 {
        return;
    }
    if let Some(map) = source.as_object() {
        for (key, child) in map {
            let mut next = path.clone();
            next.push(key.clone());
            fields(child, next, out, remaining);
        }
    }
}
fn current_objects(objects: &[WireValue]) -> R<Vec<&WireValue>> {
    let mut latest = BTreeMap::<(String, String), &WireValue>::new();
    for object in objects {
        let kind = object
            .get("kind")
            .and_then(WireValue::as_string)
            .ok_or(Error("OWNER_CACHE_OBJECT_INVALID", None))?;
        let id = object
            .get("id")
            .and_then(WireValue::as_string)
            .ok_or(Error("OWNER_CACHE_OBJECT_INVALID", None))?;
        let revision = object
            .get("revision")
            .and_then(WireValue::as_number)
            .unwrap_or(1.0);
        let key = (kind, id);
        if latest.get(&key).is_none_or(|old| {
            old.get("revision")
                .and_then(WireValue::as_number)
                .unwrap_or(1.0)
                < revision
        }) {
            latest.insert(key, object);
        }
    }
    Ok(latest.into_values().collect())
}
fn report(objects: &[WireValue]) -> R<Value> {
    let mut protocols = Vec::new();
    let mut instances = Vec::new();
    let mut records = 0;
    let mut relations = 0;
    let mut record_schemas = BTreeMap::<String, usize>::new();
    let mut remaining = 4096;
    let current = current_objects(objects)?;
    for object in &current {
        let kind = object
            .get("kind")
            .and_then(WireValue::as_string)
            .unwrap_or_default();
        match kind.as_str() {
            "protocols" => {
                let row = value(object)?;
                let item = decoded(row["value"].clone());
                let manifest = decoded(
                    item.get("resolved_manifest")
                        .or_else(|| item.get("manifest"))
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                protocols.push(json!({"protocol_digest":row["id"],"name":manifest["name"],"display_version":manifest["display_version"],"record_schemas":manifest["record_schemas"],"state_reads":manifest["actions"].as_array().map(|rows|rows.iter().map(|a|json!({"action_id":a["id"],"reads":a["reads"],"writes":a["writes"]})).collect::<Vec<_>>()),"historical_role_mapping_required":manifest["historical_role_conflicts"].as_array().is_some_and(|rows|!rows.is_empty())}));
            }
            "instances" => {
                let row = value(object)?;
                let item = decoded(row["value"].clone());
                let state = decoded(item["state"].clone());
                let mut paths = Vec::new();
                fields(&state, Vec::new(), &mut paths, &mut remaining);
                instances.push(json!({"instance_id":row["id"],"protocol_digest":item["protocol_digest"],"state_fields":paths}));
            }
            "records" => {
                records += 1;
                let item = object.get("value");
                let schema = item
                    .and_then(|v| v.get("schema_ref"))
                    .and_then(WireValue::as_string)
                    .unwrap_or_else(|| "<encoded-or-unknown>".into());
                *record_schemas.entry(schema).or_default() += 1;
            }
            "record_relations" => relations += 1,
            _ => {}
        }
    }
    Ok(
        json!({"schema":"peerwork.owner-field-review.v1","mapping_confirmed":false,"field_values_included":false,"source_object_revision_count":objects.len(),"current_object_count":current.len(),"protocols":protocols,"instances":instances,"record_count":records,"record_schema_counts":record_schemas,"relation_object_count":relations,"relation_adapter_required":relations>0,"state_field_tree_truncated":remaining==0,"disclosure":"No conversion or field disclosure has been submitted. Owner must confirm the selected structure/body mapping locally."}),
    )
}
fn protected_output(path: &Path, root: &Path, selected: &Path) -> R<()> {
    let parent = path
        .parent()
        .ok_or(Error("OWNER_CACHE_REPORT_PROTECTION_INVALID", None))?;
    if parent != root && parent != selected {
        return Err(Error("OWNER_CACHE_REPORT_MUST_STAY_WITH_OWNER", None));
    }
    crate::kernel_intents::ensure_private_parent(path)
        .map_err(|_| Error("OWNER_CACHE_REPORT_PROTECTION_INVALID", None))?;
    if path.exists() {
        return Err(Error("OWNER_CACHE_REPORT_EXISTS", None));
    }
    Ok(())
}
pub(crate) fn with_owner_snapshot<T, F>(
    state_dir: &Path,
    workspace_id: &str,
    working_dir: &Path,
    expected_actor: Option<&str>,
    cache_selection:OwnerCacheSelection,
    refresh_source:bool,
    consume: F,
) -> R<T>
where
    F: FnOnce(&crate::secure_verified_read::TransportReplayedJournal) -> R<T>,
{
    let q = Request {
        state_dir: state_dir.into(),
        workspace_id: workspace_id.into(),
        report_path: working_dir.join(".owner-cache-working-selector"),
        expected_actor: expected_actor.map(str::to_owned),cache_selection,refresh_source,
    };
    if q.workspace_id.len() != 43
        || !q
            .workspace_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Error("OWNER_CACHE_SELECTION_INVALID", None));
    }
    let identity_path = q.state_dir.join("identity.state");
    let selected = q.state_dir.join("workspaces").join(&q.workspace_id);
    private_file(&identity_path)?;
    let (config, slot) =
        SecureReadProfile::cached_export_config(&selected, &identity_path, &q.workspace_id)?;
    let identity = KernelIdentity::open(&identity_path)
        .map_err(|_| Error("OWNER_CACHE_IDENTITY_INVALID", None))?;
    if q.expected_actor
        .as_deref()
        .is_some_and(|actor| actor != identity.actor_id())
        || config.owner_actor_id.as_deref() != Some(identity.actor_id())
    {
        return Err(Error("OWNER_CACHE_OWNER_MISMATCH", None));
    }
    crate::kernel_intents::ensure_private_parent(&q.report_path)
        .map_err(|_| Error("OWNER_CACHE_REPORT_PROTECTION_INVALID", None))?;
    let parent = q
        .report_path
        .parent()
        .ok_or(Error("OWNER_CACHE_REPORT_PROTECTION_INVALID", None))?;
    if parent != q.state_dir && parent != selected {
        return Err(Error("OWNER_CACHE_REPORT_MUST_STAY_WITH_OWNER", None));
    }
    let copy = tempfile::TempDir::new_in(parent)
        .map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(copy.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
    }
    let prefix = cache_selection.prefix(slot);
    let mut source_files = vec![
        identity_path.clone(),
        selected.join("read.profile"),
        selected.join("kernel.sqlite"),
        selected.join("lifecycle.state"),
        selected.join(&prefix),
    ];
    for entry in fs::read_dir(&selected).map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))? {
        let entry = entry.map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&format!("{prefix}.page.")) && name.ends_with(".state") {
            source_files.push(entry.path());
        }
    }
    let before = source_files
        .iter()
        .map(|p| {
            private_file(p)?;
            Ok((p.clone(), stamp(p)?))
        })
        .collect::<R<Vec<_>>>()?;
    for source in &source_files {
        if source == &identity_path {
            continue;
        }
        let name = source
            .file_name()
            .ok_or(Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
        let target = copy.path().join(name);
        if name == "kernel.sqlite" {
            let db = rusqlite::Connection::open_with_flags(
                source,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
            db.backup(rusqlite::DatabaseName::Main, &target, None)
                .map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
        } else {
            fs::copy(source, &target).map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .map_err(|_| Error("OWNER_CACHE_SNAPSHOT_FAILED", None))?;
        }
    }
    let mut config = config;
    config.state_dir = copy.path().into();
    let profile = SecureReadProfile::new(config);
    let result=if cache_selection==OwnerCacheSelection::Active&&!refresh_source {
        profile.with_pinned_replay(&crate::KernelCancellationToken::new(),consume)?
    }else{
        let (mut selected_config,floor)=profile.local_active_view_config()?;
        selected_config.read_state_path=copy.path().join(&prefix);
        let access=crate::secure_read_access::SecureReadAccess::new(selected_config);
        let replayed=if refresh_source{access.refresh_owner_conversion_source(&crate::KernelCancellationToken::new(),&floor)}
            else{access.replay_cached_owner_conversion(&crate::KernelCancellationToken::new(),&floor)}
            .map_err(|error|Error::from(error.verification_stage("owner.conversion-source")))?;
        consume(&replayed)?
    };
    for (path, old) in before {
        if stamp(&path)? != old {
            return Err(Error("OWNER_CACHE_CHANGED_DURING_REVIEW", None));
        }
    }
    Ok(result)
}
fn inspect(q: Request) -> R<Value> {
    let selected = q.state_dir.join("workspaces").join(&q.workspace_id);
    protected_output(&q.report_path, &q.state_dir, &selected)?;
    let parent = q
        .report_path
        .parent()
        .ok_or(Error("OWNER_CACHE_REPORT_PROTECTION_INVALID", None))?;
    let mut result: Value = with_owner_snapshot(
        &q.state_dir,
        &q.workspace_id,
        parent,
        q.expected_actor.as_deref(),
        q.cache_selection,
        q.refresh_source,
        |source| {
            let mut result = report(source.replay().objects())?;
            result["workspace_id"] = json!(source.replay().workspace_id());
            result["legacy_structure_status"]=json!(format!("{:?}",source.replay().structure_status()));
            result["source_frontier"] = json!({"sequence":source.replay().sequence(),"head":source.replay().head(),"policy_hash":source.replay().policy_hash()});
            Ok(result)
        },
    )?;
    result["cache_selection"] = json!(q.cache_selection);
    result["source_refresh_requested"]=json!(q.refresh_source);
    result["network_requests"]=if q.refresh_source{Value::Null}else{json!(0)};
    result["identity_copied"] = json!(false);
    result["original_cache_unchanged"] = json!(true);
    let bytes =
        serde_json::to_vec_pretty(&result).map_err(|_| Error("OWNER_CACHE_REPORT_FAILED", None))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(Error("OWNER_CACHE_REPORT_LIMIT", None));
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| Error("OWNER_CACHE_REPORT_FAILED", None))?;
    file.write_all(&bytes)
        .map_err(|_| Error("OWNER_CACHE_REPORT_FAILED", None))?;
    file.as_file()
        .sync_all()
        .map_err(|_| Error("OWNER_CACHE_REPORT_FAILED", None))?;
    file.persist_noclobber(&q.report_path)
        .map_err(|_| Error("OWNER_CACHE_REPORT_EXISTS", None))?;
    Ok(
        json!({"status":"LOCAL_REVIEW_READY","cache_selection":q.cache_selection,"mapping_confirmed":false,"source_refresh_requested":q.refresh_source,"network_requests":result["network_requests"],"identity_copied":false,"original_cache_unchanged":true,"protocol_count":result["protocols"].as_array().map(Vec::len),"instance_count":result["instances"].as_array().map(Vec::len),"record_count":result["record_count"],"source_frontier":result["source_frontier"],"report_path":q.report_path,"report_sha256":sha256_hex(&bytes)}),
    )
}
pub fn inspect_owner_cache_json(input: &str) -> String {
    let result = (|| {
        if input.len() > 65536 {
            return Err(Error("OWNER_CACHE_REQUEST_LIMIT", None));
        }
        let q: Request =
            serde_json::from_str(input).map_err(|_| Error("OWNER_CACHE_REQUEST_INVALID", None))?;
        inspect(q)
    })();
    match result{Ok(value)=>json!({"ok":true,"value":value}).to_string(),Err(error)=>json!({"ok":false,"code":error.0,"diagnostic":error.1,"stage":"OFFLINE_OWNER_CACHE_REVIEW","effect_certainty":"NOT_SUBMITTED"}).to_string()}
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn field_report_contains_types_and_paths_but_no_state_values() {
        let objects = serde_json::json!([{"kind":"instances","id":"I","value":{"protocol_digest":"D","state":{"holder":"PRIVATE VALUE MUST NOT APPEAR","count":123456789}}},{"kind":"records","id":"R","value":{"schema_ref":"note","payload":"PRIVATE BODY MUST NOT APPEAR"}},{"kind":"record_relations","id":"E","value":{}}]);
        let objects: Vec<_> = objects
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                peerwork_core::wire_json::parse_wire_json_bounded(
                    v.to_string().as_bytes(),
                    16,
                    65536,
                )
                .unwrap()
            })
            .collect();
        let result = report(&objects).unwrap();
        let encoded = result.to_string();
        assert!(!encoded.contains("PRIVATE VALUE"));
        assert!(!encoded.contains("123456789"));
        assert!(!encoded.contains("PRIVATE BODY"));
        assert_eq!(result["record_count"], 1);
        assert_eq!(result["relation_adapter_required"], true);
    }
    #[test]
    fn latest_instance_revision_is_reported_once() {
        let rows = json!([{"kind":"instances","id":"I","revision":1,"value":{"protocol_digest":"D","state":{"old_field":1}}},{"kind":"instances","id":"I","revision":2,"value":{"protocol_digest":"D","state":{"new_field":true}}}]);
        let rows: Vec<_> = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                peerwork_core::wire_json::parse_wire_json_bounded(
                    v.to_string().as_bytes(),
                    16,
                    65536,
                )
                .unwrap()
            })
            .collect();
        let result = report(&rows).unwrap();
        assert_eq!(result["instances"].as_array().unwrap().len(), 1);
        assert_eq!(result["source_object_revision_count"], 2);
        assert!(result.to_string().contains("new_field"));
        assert!(!result.to_string().contains("old_field"));
    }
    #[test]
    fn auxiliary_selection_is_explicit_and_unknown_paths_fail_before_source_access() {
        let dir=crate::test_support::protected_test_dir();
        for selection in ["../private-recovery-read.state","read-0.state","LATEST","RECOVERY/../ACTIVE"] {
            let request=json!({"state_dir":dir.path(),"workspace_id":"W".repeat(43),"report_path":dir.path().join("report.json"),"cache_selection":selection});
            let result:Value=serde_json::from_str(&inspect_owner_cache_json(&request.to_string())).unwrap();
            assert_eq!(result["code"],"OWNER_CACHE_REQUEST_INVALID");assert!(!dir.path().join("identity.state").exists());assert!(!dir.path().join("report.json").exists());
        }
        for selection in [OwnerCacheSelection::Recovery,OwnerCacheSelection::Install] {
            let request=json!({"state_dir":dir.path(),"workspace_id":"W".repeat(43),"report_path":dir.path().join("report.json"),"cache_selection":selection});
            let result:Value=serde_json::from_str(&inspect_owner_cache_json(&request.to_string())).unwrap();assert_eq!(result["ok"],false);assert_eq!(result["code"],"OWNER_CACHE_FILE_MISSING");assert!(!dir.path().join("identity.state").exists());
        }
    }
    #[test]
    fn missing_cache_fails_without_creating_a_profile_or_identity() {
        let dir = crate::test_support::protected_test_dir();
        let out=inspect_owner_cache_json(&json!({"state_dir":dir.path(),"workspace_id":"W".repeat(43),"report_path":dir.path().join("report.json")}).to_string());
        let result: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(result["ok"], false);
        assert!(!dir.path().join("identity.state").exists());
        assert!(!dir.path().join("workspaces").exists());
    }
}
