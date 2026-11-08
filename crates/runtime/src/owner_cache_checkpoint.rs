//! Explicit offline Owner conversion from an authenticated local cache.
//! Decrypted rows are zeroized memory input, never a new plaintext source file.
use crate::{
    owner_cache_review::{Error,OwnerCacheSelection},
    owner_checkpoint::{prepare_verified_owner_checkpoint, PrepareCheckpointRequest},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    wire_json::{canonical_wire_value, WireValue},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    state_dir: PathBuf,
    #[serde(default)] capsule_path:Option<PathBuf>,
    #[serde(default)] cache_selection:OwnerCacheSelection,
    #[serde(default)] refresh_source:bool,
    workspace_id: String,
    expected_actor: String,
    plan_path: PathBuf,
    output_path: PathBuf,
    origin: String,
    audience: String,
    #[serde(default)]
    allow_loopback_http: bool,
}
type R<T> = Result<T, Error>;
fn bad(code: &'static str) -> Error {
    Error(code, None)
}
fn value(wire: &WireValue) -> R<Value> {
    serde_json::from_str(
        &canonical_wire_value(wire, CanonicalPath::SecureArtifact)
            .map_err(|_| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?,
    )
    .map_err(|_| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))
}
fn decode(mut row: Value) -> R<Value> {
    if let Some(text) = row.as_str() {
        row = serde_json::from_str(text).map_err(|_| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?;
    }
    Ok(row)
}
fn key(row: &Value) -> String {
    json!([row["kind"], row["id"], row["revision"]]).to_string()
}
fn selected_rows(objects: &[WireValue]) -> R<BTreeMap<(String, String), Value>> {
    let mut latest = BTreeMap::<(String, String), Value>::new();
    for object in objects {
        let row = value(object)?;
        let kind = row["kind"]
            .as_str()
            .ok_or_else(|| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?
            .to_owned();
        let id = row["id"]
            .as_str()
            .ok_or_else(|| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?
            .to_owned();
        let revision = row["revision"]
            .as_u64()
            .ok_or_else(|| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?;
        if latest
            .get(&(kind.clone(), id.clone()))
            .is_none_or(|old| old["revision"].as_u64().unwrap_or(0) < revision)
        {
            latest.insert((kind, id), row);
        }
    }
    Ok(latest)
}
fn source_rows(
    source: &crate::legacy_migration::MigrationSource,
    plan: &Value,
) -> R<Zeroizing<Vec<u8>>> {
    let selected = selected_rows(source.replay().objects())?;
    let wanted = plan["instances"]
        .as_object()
        .ok_or_else(|| bad("CHECKPOINT_PLAN_INVALID"))?;
    if selected.keys().filter(|(kind,_)|kind=="instances").count()!=wanted.len(){return Err(bad("CHECKPOINT_INSTANCE_SCOPE_INCOMPLETE"));}
    if selected.keys().any(|(kind,_)|kind.contains("withdraw")){return Err(bad("LEGACY_VISIBILITY_MAPPING_REQUIRED"));}
    let sources: BTreeMap<_, _> = source
        .replay()
        .object_sources()
        .iter()
        .map(|wire| {
            let row = value(wire)?;
            Ok((key(&row), row))
        })
        .collect::<R<_>>()?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut write = |row: Value| -> R<()> {
        serde_json::to_writer(&mut *bytes, &row)
            .map_err(|_| bad("CHECKPOINT_CACHE_ENCODING_FAILED"))?;
        bytes.push(b'\n');
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(bad("CHECKPOINT_CACHE_SOURCE_LIMIT"));
        }
        Ok(())
    };
    for id in wanted.keys() {
        let row = selected
            .get(&("instances".into(), id.clone()))
            .ok_or_else(|| bad("CHECKPOINT_CACHE_INSTANCE_MISSING"))?;
        let row = decode(row["value"].clone())?;
        write(json!({"kind":"instance","instance_id":id,"state":decode(row["state"].clone())?}))?;
    }
    let mut heads = BTreeMap::<String, (String, u64)>::new();
    for ((kind, _), row) in &selected {
        if kind == "entity_heads" {
            let item = decode(row["value"].clone())?;
            if let (Some(entity), Some(record), Some(revision)) = (
                item["entity_id"].as_str(),
                item["record_id"].as_str(),
                item["revision"].as_u64(),
            ) {
                heads.insert(entity.into(), (record.into(), revision));
            } else {
                return Err(bad("CHECKPOINT_CACHE_HEAD_INVALID"));
            }
        }
    }
    let explicit: BTreeSet<_> = heads.keys().cloned().collect();
    let mut records = Vec::new();
    for ((kind, _), row) in &selected {
        if kind != "records" {
            continue;
        }
        let item = decode(row["value"].clone())?;
        let instance = item["instance_id"]
            .as_str()
            .ok_or_else(|| bad("CHECKPOINT_CACHE_RECORD_INVALID"))?;
        if !wanted.contains_key(instance) {
            continue;
        }
        let id = row["id"]
            .as_str()
            .ok_or_else(|| bad("CHECKPOINT_CACHE_RECORD_INVALID"))?;
        let entity = item["entity_id"].as_str().unwrap_or(id);
        if item["actor_id"].as_str().is_none() || item["created"].as_u64().is_none() {
            return Err(bad("CHECKPOINT_CACHE_RECORD_PROVENANCE_MISSING"));
        }
        let revision = item["revision"]
            .as_u64()
            .ok_or_else(|| bad("CHECKPOINT_CACHE_RECORD_INVALID"))?;
        if !explicit.contains(entity) && heads.get(entity).is_none_or(|(_, old)| *old < revision) {
            heads.insert(entity.into(), (id.into(), revision));
        }
        let origin = sources
            .get(&key(row))
            .ok_or_else(|| bad("CHECKPOINT_CACHE_PROVENANCE_UNAVAILABLE"))?;
        let wire = peerwork_core::wire_json::parse_wire_json_bounded(
            row.to_string().as_bytes(),
            64,
            2 * 1024 * 1024,
        )
        .map_err(|_| bad("CHECKPOINT_CACHE_RECORD_INVALID"))?;
        if origin["object_digest"]
            != sha256_hex(
                canonical_wire_value(&wire, CanonicalPath::SecureArtifact)
                    .map_err(|_| bad("CHECKPOINT_CACHE_RECORD_INVALID"))?
                    .as_bytes(),
            )
        {
            return Err(bad("CHECKPOINT_CACHE_PROVENANCE_UNAVAILABLE"));
        }
        records.push((instance.to_owned(),entity.to_owned(),revision,json!({"kind":"record","instance_id":instance,"record_id":id,"entity_id":entity,"revision":revision,"is_head":false,"schema":item["schema_ref"],"fields":decode(item["payload"].clone())?,"legacy_source":{"sequence":origin["sequence"],"commit_hash":origin["commit_hash"],"record_id":id,"revision":revision,"actor_id":origin["actor_id"],"record_actor_id":item["actor_id"],"created_at":item["created"]}})));
    }
    records.sort_by(|a, b| (&a.0, &a.1, a.2).cmp(&(&b.0, &b.1, b.2)));
    let record_ids:BTreeSet<String>=records.iter().filter_map(|(_,_,_,row)|row["record_id"].as_str().map(str::to_owned)).collect();
    for (_, entity, revision, mut row) in records {
        row["is_head"] =
            json!(heads
                .get(&entity)
                .is_some_and(
                    |(record, rev)| Some(record.as_str()) == row["record_id"].as_str()
                        && *rev == revision
                ));
        write(row)?;
    }
    // Relations are structure too. Emit them only after all record rows so
    // forward references and cycles can be checked without losing links.
    for ((kind,_),row) in &selected {
        if kind!="record_relations" {continue;}
        let relation=decode(row["value"].clone())?;
        let source=relation["record_id"].as_str().ok_or_else(||bad("CHECKPOINT_CACHE_RELATION_INVALID"))?;
        if !record_ids.contains(source){return Err(bad("CHECKPOINT_CACHE_RELATION_SOURCE_MISSING"))}
        let target=relation["target_record"].as_str().ok_or_else(||bad("CHECKPOINT_CACHE_RELATION_INVALID"))?;
        if !record_ids.contains(target){return Err(bad("CHECKPOINT_CACHE_RELATION_TARGET_MISSING"))}
        write(json!({"kind":"relation","record_id":source,"relation_kind":relation["kind"],"target_record":target,"target_revision":relation["target_revision"]}))?;
    }
    Ok(bytes)
}
fn protected_plan(path: &Path) -> R<Value> {
    crate::kernel_intents::ensure_private_parent(path)
        .map_err(|_| bad("CHECKPOINT_PLAN_PROTECTION_INVALID"))?;
    let stat = fs::symlink_metadata(path).map_err(|_| bad("CHECKPOINT_PLAN_MISSING"))?;
    if !stat.is_file() || stat.file_type().is_symlink() || stat.len() > 2 * 1024 * 1024 {
        return Err(bad("CHECKPOINT_PLAN_PROTECTION_INVALID"));
    }
    crate::kernel_intents::create_or_check_private_file(path)
        .map_err(|_| bad("CHECKPOINT_PLAN_PROTECTION_INVALID"))?;
    let bytes = fs::read(path).map_err(|_| bad("CHECKPOINT_PLAN_MISSING"))?;
    peerwork_core::wire_json::parse_wire_json_bounded(&bytes, 64, 2 * 1024 * 1024)
        .map_err(|_| bad("CHECKPOINT_PLAN_INVALID"))?;
    serde_json::from_slice(&bytes).map_err(|_| bad("CHECKPOINT_PLAN_INVALID"))
}
fn private_staging(parent: &Path) -> R<tempfile::TempDir> {
    let stage = tempfile::TempDir::new_in(parent).map_err(|_| bad("CHECKPOINT_OUTPUT_FAILED"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| bad("CHECKPOINT_OUTPUT_PROTECTION_INVALID"))?;
    }
    Ok(stage)
}
fn prepare(q: Request) -> R<Value> {
    let parent = q
        .output_path
        .parent()
        .ok_or_else(|| bad("CHECKPOINT_OUTPUT_PROTECTION_INVALID"))?;
    if parent != q.state_dir && parent != q.state_dir.join("workspaces").join(&q.workspace_id) {
        return Err(bad("CHECKPOINT_OUTPUT_MUST_STAY_WITH_OWNER"));
    }
    let plan = protected_plan(&q.plan_path)?;
    crate::owner_checkpoint::preflight_checkpoint_target(&plan).map_err(|e|Error(e.0,e.1))?;
    let staged = private_staging(parent)?;
    let exists = q.output_path.exists();
    let prepared_path = if exists {
        q.output_path.clone()
    } else {
        staged.path().join("checkpoint.jsonl")
    };
    let mut completed = crate::legacy_migration::with_migration_source(
        &q.state_dir,
        &q.workspace_id,
        parent,
        Some(&q.expected_actor),
        q.cache_selection,
        q.refresh_source,
        q.capsule_path.as_deref(),
        plan["source"]["snapshot_sha256"].as_str().ok_or_else(||bad("CHECKPOINT_PLAN_INVALID"))?,
        |source| {
            if plan["migration_mode"]!="READ_ONLY_SNAPSHOT"&&(source.pin["kind"]=="PLAIN_PUBLIC"||source.structure_status()=="Seeding"){return Err(bad("LEGACY_SOURCE_REQUIRES_READ_ONLY_SNAPSHOT"));}
            let pin = &plan["source"];
            if pin["workspace_id"] != source.replay().workspace_id()
                || pin["owner_id"] != source.replay().owner_actor_id()
                || pin["owner_kid"] != source.replay().owner_signing_key()
                || pin["authority"] != source.authority()
                || pin["sequence"] != source.replay().sequence()
                || pin["head"].as_str() != source.replay().head()
                || pin["policy_hash"] != source.replay().policy_hash()
            {
                return Err(bad("CHECKPOINT_CACHE_FRONTIER_MISMATCH"));
            }
            let mut plan = plan.clone();
            let selected = selected_rows(source.replay().objects())?;
            for (id, mapping) in plan["instances"]
                .as_object_mut()
                .ok_or_else(|| bad("CHECKPOINT_PLAN_INVALID"))?
            {
                let instance = selected
                    .get(&("instances".into(), id.clone()))
                    .ok_or_else(|| bad("CHECKPOINT_CACHE_INSTANCE_MISSING"))?;
                let instance = decode(instance["value"].clone())?;
                let mut claims = Vec::new();
                for wire in source.replay().historical_role_claims() {
                    let row = value(wire)?;
                    if row["instance_id"] == id.as_str()
                        && row["protocol_digest"] == instance["protocol_digest"]
                    {
                        claims.push(json!({"actor_id":row["actor_id"],"roles":row["roles"]}));
                    }
                }
                if source.pin["kind"]!="PLAIN_PUBLIC"{mapping["role_history"] = json!({"complete":true,"claims":claims});}else{mapping.as_object_mut().ok_or_else(||bad("CHECKPOINT_PLAN_INVALID"))?.remove("role_history");}
                if let Some(schemas) = mapping["record_mappings"].as_object_mut() {
                    for record in schemas.values_mut() {
                        record["strict_body_separation"] = json!(true);
                    }
                }
            }
            let rows = source_rows(source, &plan)?;
            let request = PrepareCheckpointRequest {
                identity_path: q.state_dir.join("identity.state"),
                expected_actor: q.expected_actor.clone(),
                origin: q.origin.clone(),
                audience: q.audience.clone(),
                source_path: q.plan_path.clone(),
                plan_path: q.plan_path.clone(),
                output_path: prepared_path.clone(),
                content_keys_path: None,
                allow_loopback_http: q.allow_loopback_http,
            };
            let mut result = prepare_verified_owner_checkpoint(&request, &rows, &plan)
                .map_err(|e| Error(e.0, e.1))?;
            result["source_refresh_requested"]=json!(q.refresh_source);
            result["network_requests"]=if q.refresh_source{Value::Null}else{json!(0)};
            result["cache_selection"]=if q.capsule_path.is_some(){Value::Null}else{json!(q.cache_selection)};
            result["source_mode"] = json!(if q.capsule_path.is_some(){"VERIFIED_OWNER_CAPSULE_MEMORY"}else{"VERIFIED_OWNER_CACHE_MEMORY"});
            result["plaintext_source_persisted"] = json!(false);
            result["identity_copied"] = json!(false);
            result["context_binding"] = json!({"execution_profile":"backend-structure-v1","expected_actor":source.replay().owner_actor_id(),"authority":source.authority(),"audience":q.audience,"workspace_ids":[q.workspace_id]});
            Ok(result)
        },
    )?;
    if !exists {
        let mut input =
            fs::File::open(&prepared_path).map_err(|_| bad("CHECKPOINT_OUTPUT_FAILED"))?;
        let mut file =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| bad("CHECKPOINT_OUTPUT_FAILED"))?;
        std::io::copy(&mut input, &mut file).map_err(|_| bad("CHECKPOINT_OUTPUT_FAILED"))?;
        file.as_file()
            .sync_all()
            .map_err(|_| bad("CHECKPOINT_OUTPUT_FAILED"))?;
        file.persist_noclobber(&q.output_path)
            .map_err(|_| bad("CHECKPOINT_OUTPUT_EXISTS"))?;
    }
    completed["output_path"] = json!(q.output_path);
    Ok(completed)
}
pub fn prepare_owner_checkpoint_from_cache_json(input: &str) -> String {
    let result = (|| {
        if input.len() > 65536 {
            return Err(bad("CHECKPOINT_REQUEST_LIMIT"));
        }
        let q: Request =
            serde_json::from_str(input).map_err(|_| bad("CHECKPOINT_REQUEST_INVALID"))?;
        prepare(q)
    })();
    match result{Ok(value)=>json!({"ok":true,"value":value}).to_string(),Err(error)=>json!({"ok":false,"code":error.0,"diagnostic":error.1,"stage":"OFFLINE_OWNER_CACHE_CONVERSION","effect_certainty":"NOT_SUBMITTED"}).to_string()}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_obeys_the_native_protected_output_contract() {
        let root = crate::test_support::protected_test_dir();
        let stage = private_staging(root.path()).unwrap();
        crate::kernel_intents::ensure_private_parent(&stage.path().join("artifact.jsonl")).unwrap();
        crate::kernel_intents::create_or_check_private_file(&stage.path().join("artifact.jsonl"))
            .unwrap();
    }
    #[test]
    fn instance_selection_never_rewinds_to_a_historical_revision() {
        let rows = json!([{"kind":"instances","id":"I","revision":2,"value":{"state":{"latest":true}}},{"kind":"instances","id":"I","revision":1,"value":{"state":{"latest":false}}}]);
        let rows: Vec<_> = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                peerwork_core::wire_json::parse_wire_json_bounded(
                    row.to_string().as_bytes(),
                    16,
                    65536,
                )
                .unwrap()
            })
            .collect();
        let selected = selected_rows(&rows).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[&("instances".into(), "I".into())]["revision"], 2);
    }
}
