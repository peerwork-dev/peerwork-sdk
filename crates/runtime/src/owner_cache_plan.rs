//! Policy-based conversion mapping. Only explicitly classified narrative fields
//! become encrypted bodies; all other business structure remains readable.
use crate::owner_cache_review::{Error,OwnerCacheSelection};
use crate::legacy_migration::with_migration_source;
use peerwork_core::{
    canonical::Path as CanonicalPath,
    wire_json::{canonical_wire_value, WireValue},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
};
type R<T> = Result<T, Error>;
fn bad(code: &'static str) -> Error {
    Error(code, None)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    state_dir: PathBuf,
    #[serde(default)] cache_selection:OwnerCacheSelection,
    #[serde(default)] refresh_source:bool,
    workspace_id: String,
    expected_actor: String,
    snapshot_sha256: String,
    name: String,
    plan_path: PathBuf,
    #[serde(default)] read_only_snapshot:bool,
    #[serde(default)] capsule_path:Option<PathBuf>,
}
fn snapshot_manifest(mut manifest:Value)->R<Value>{
    manifest["name"]=json!(format!("Historical snapshot: {}",manifest["name"].as_str().unwrap_or("workspace")).chars().take(120).collect::<String>());
    manifest["display_version"]=json!("snapshot-1");manifest["dependencies"]=json!([]);manifest["constraints"]=json!({});
    manifest.as_object_mut().ok_or_else(||bad("CHECKPOINT_PROTOCOL_INVALID"))?.remove("execution_requirements");
    manifest["actions"]=json!([{"id":"snapshot.readonly","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[{"op":"eq","left":{"from":"literal","value":false},"right":{"from":"literal","value":true}}],"effects":[]}]}]);
    for schema in manifest["record_schemas"].as_object_mut().ok_or_else(||bad("CHECKPOINT_PROTOCOL_INVALID"))?.values_mut(){schema.as_object_mut().ok_or_else(||bad("CHECKPOINT_PROTOCOL_INVALID"))?.remove("workflow");}
    Ok(manifest)
}
fn value(row: &WireValue) -> R<Value> {
    serde_json::from_str(
        &canonical_wire_value(row, CanonicalPath::SecureArtifact)
            .map_err(|_| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?,
    )
    .map_err(|_| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))
}
fn decoded(mut row: Value) -> R<Value> {
    if let Some(text) = row.as_str() {
        row = serde_json::from_str(text).map_err(|_| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?;
    }
    Ok(row)
}
fn bodies(schema: &str, fields: &serde_json::Map<String, Value>) -> BTreeSet<String> {
    let selected: &[&str] = match schema {
        "discussion.message" => &["message"],
        "wiki.revision" => &["body"],
        "task.revision" => &["description", "note"],
        "task.report"
        | "service.delivery"
        | "service.note"
        | "service.external_report"
        | "outputs.selection" => &["summary"],
        "service.message" => &["text"],
        "service.scope" => &["scope"],
        _ => &[
            "body",
            "content",
            "message",
            "text",
            "description",
            "note",
            "summary",
        ],
    };
    selected
        .iter()
        .filter(|field| {
            matches!(
                fields.get(**field).and_then(Value::as_str),
                Some("string" | "source_text")
            )
        })
        .map(|field| (*field).into())
        .collect()
}
fn input_fields(node: &Value, selected: &mut BTreeSet<String>) {
    if node.get("from").and_then(Value::as_str) == Some("literal") {
        return;
    }
    if matches!(
        node.get("from").and_then(Value::as_str),
        Some("input" | "body")
    ) {
        if let Some(name) = node
            .get("path")
            .and_then(Value::as_array)
            .and_then(|p| p.first())
            .and_then(Value::as_str)
        {
            selected.insert(name.into());
        }
    }
    match node {
        Value::Object(fields) => fields
            .values()
            .for_each(|child| input_fields(child, selected)),
        Value::Array(rows) => rows.iter().for_each(|child| input_fields(child, selected)),
        _ => {}
    }
}
fn remove_output_fields(
    expression: &mut Value,
    removed: &BTreeSet<String>,
    inputs: &mut BTreeSet<String>,
) -> R<()> {
    match expression["from"].as_str() {
        Some("object") => {
            let fields = expression["fields"]
                .as_object_mut()
                .ok_or_else(|| bad("CHECKPOINT_BODY_OUTPUT_ADAPTER_REQUIRED"))?;
            for field in removed {
                if let Some(value) = fields.remove(field) {
                    input_fields(&value, inputs);
                }
            }
        }
        Some("literal") => {
            let fields = expression["value"]
                .as_object_mut()
                .ok_or_else(|| bad("CHECKPOINT_BODY_OUTPUT_ADAPTER_REQUIRED"))?;
            for field in removed {
                fields.remove(field);
            }
        }
        _ => return Err(bad("CHECKPOINT_BODY_OUTPUT_ADAPTER_REQUIRED")),
    }
    Ok(())
}
fn rewrite_effects(actions: &mut Value, body_fields: &BTreeMap<String, BTreeSet<String>>) -> R<()> {
    for action in actions
        .as_array_mut()
        .ok_or_else(|| bad("CHECKPOINT_PROTOCOL_INVALID"))?
    {
        let mut removed_inputs = BTreeSet::new();
        for variant in action["variants"]
            .as_array_mut()
            .ok_or_else(|| bad("CHECKPOINT_PROTOCOL_INVALID"))?
        {
            for effect in variant["effects"]
                .as_array_mut()
                .ok_or_else(|| bad("CHECKPOINT_PROTOCOL_INVALID"))?
            {
                if effect["op"] == "append" {
                    if let Some(fields) = effect["schema"]
                        .as_str()
                        .and_then(|name| body_fields.get(name))
                    {
                        if !fields.is_empty() {
                            remove_output_fields(
                                &mut effect["value"],
                                fields,
                                &mut removed_inputs,
                            )?;
                        }
                    }
                }
            }
        }
        let mut used_inputs = BTreeSet::new();
        input_fields(&action["variants"], &mut used_inputs);
        if !removed_inputs.is_disjoint(&used_inputs) {
            return Err(bad("CHECKPOINT_BUSINESS_RULE_REQUIRES_BODY"));
        }
        if let Some(inputs) = action.get_mut("inputs") {
            if let Some(fields) = inputs.get_mut("fields").and_then(Value::as_object_mut) {
                for field in &removed_inputs {
                    fields.remove(field);
                }
            }
            if let Some(required) = inputs.get_mut("required").and_then(Value::as_array_mut) {
                required.retain(|field| {
                    !field
                        .as_str()
                        .is_some_and(|field| removed_inputs.contains(field))
                });
            }
        }
    }
    Ok(())
}
pub(crate) fn has_narrative_fields(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(name, child)| {
            matches!(
                name.as_str(),
                "body" | "content" | "message" | "text" | "description" | "note" | "summary"
            ) && (child.is_string() || child.is_array() || child.is_object())
                || has_narrative_fields(child)
        }),
        Value::Array(items) => items.iter().any(has_narrative_fields),
        _ => false,
    }
}
fn literal_narrative(node: &Value) -> bool {
    if node.get("from").and_then(Value::as_str) == Some("literal") {
        return node.get("value").is_some_and(has_narrative_fields);
    }
    match node {
        Value::Object(fields) => fields.values().any(literal_narrative),
        Value::Array(rows) => rows.iter().any(literal_narrative),
        _ => false,
    }
}
fn body_rule(node: &Value, removed: &BTreeSet<String>) -> bool {
    if node.get("from").and_then(Value::as_str) == Some("literal") {
        return false;
    }
    if let Some(path) = node.get("path").and_then(Value::as_array) {
        if node.get("from").is_some()
            && path
                .iter()
                .any(|p| p.as_str().is_some_and(|p| removed.contains(p)))
        {
            return true;
        }
    }
    match node {
        Value::Array(rows) => rows.iter().any(|n| body_rule(n, removed)),
        Value::Object(fields) => fields.values().any(|n| body_rule(n, removed)),
        _ => false,
    }
}
fn transform(mut manifest: Value) -> R<(Value, BTreeMap<String, Value>, Vec<&'static str>)> {
    let mut mappings = BTreeMap::new();
    let mut body_fields = BTreeMap::new();
    for (name, schema) in manifest["record_schemas"]
        .as_object_mut()
        .ok_or_else(|| bad("CHECKPOINT_PROTOCOL_INVALID"))?
    {
        let fields = schema["fields"]
            .as_object()
            .ok_or_else(|| bad("CHECKPOINT_PROTOCOL_INVALID"))?;
        let removed = bodies(name, fields);
        let structure_fields: serde_json::Map<_, _> = fields
            .keys()
            .filter(|field| !removed.contains(*field))
            .map(|field| (field.clone(), json!([field])))
            .collect();
        let mut mapping = json!({"target_schema":name,"structure_fields":structure_fields,"body_field":null,"strict_body_separation":true});
        if removed.len() == 1 {
            mapping["body_field"] = json!([removed.first().unwrap()]);
        } else if !removed.is_empty() {
            mapping["body_fields"] = json!(removed
                .iter()
                .map(|field| (field.clone(), vec![field.clone()]))
                .collect::<BTreeMap<_, _>>());
        }
        mappings.insert(name.clone(), mapping);
        body_fields.insert(name.clone(), removed.clone());
        for field in &removed {
            schema["fields"].as_object_mut().unwrap().remove(field);
        }
        if let Some(required) = schema["required"].as_array_mut() {
            required.retain(|field| field.as_str().is_some_and(|field| !removed.contains(field)));
        }
        if schema.get("workflow").is_none() {
            schema.as_object_mut().unwrap().remove("protection");
        } else if let Some(protection) = schema["protection"]["fields"].as_object_mut() {
            for field in &removed {
                protection.remove(field);
            }
            for rule in protection.values_mut() {
                if rule["protection"] == "e2ee" {
                    rule["protection"] = json!("server_readable");
                }
            }
        }
    }
    rewrite_effects(&mut manifest["actions"], &body_fields)?;
    let removed: BTreeSet<_> = body_fields
        .values()
        .flat_map(|set| set.iter().cloned())
        .collect();
    if body_rule(&manifest["actions"], &removed) || body_rule(&manifest["constraints"], &removed) {
        return Err(bad("CHECKPOINT_BUSINESS_RULE_REQUIRES_BODY"));
    }
    // This input is the already-verified resolved manifest, whose composed
    // schemas/actions/state are complete. A new target source has no imports.
    if literal_narrative(&manifest["actions"]) || has_narrative_fields(&manifest["initial_state"]) {
        return Err(bad("CHECKPOINT_LITERAL_BODY_REQUIRES_MAPPING"));
    }
    manifest["dependencies"] = json!([]);
    let mut required = Vec::new();
    if manifest["historical_role_conflicts"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty())
    {
        required.push("HISTORICAL_ROLE_CHECKPOINT");
    }
    if manifest["constraints"]
        .as_object()
        .is_some_and(|fields| !fields.is_empty())
    {
        required.push("STRUCTURAL_CONSTRAINTS");
    }
    if manifest["record_schemas"]
        .as_object()
        .unwrap()
        .values()
        .any(|s| s.get("workflow").is_some())
    {
        required.push("BOUNDED_WORKFLOW_TRANSITIONS");
    }
    Ok((manifest, mappings, required))
}
fn write_plan(q: Request) -> R<Value> {
    if q.snapshot_sha256.len() != 64
        || !q
            .snapshot_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(bad("CHECKPOINT_SNAPSHOT_INVALID"));
    }
    let parent = q
        .plan_path
        .parent()
        .ok_or_else(|| bad("CHECKPOINT_PLAN_PROTECTION_INVALID"))?;
    if parent != q.state_dir && parent != q.state_dir.join("workspaces").join(&q.workspace_id) {
        return Err(bad("CHECKPOINT_PLAN_MUST_STAY_WITH_OWNER"));
    }
    crate::kernel_intents::ensure_private_parent(&q.plan_path)
        .map_err(|_| bad("CHECKPOINT_PLAN_PROTECTION_INVALID"))?;
    if q.plan_path.exists() {
        return Err(bad("CHECKPOINT_PLAN_EXISTS"));
    }
    let (mut plan, mut summary) = with_migration_source(
        &q.state_dir,
        &q.workspace_id,
        parent,
        Some(&q.expected_actor),
        q.cache_selection,
        q.refresh_source,
        q.capsule_path.as_deref(),
        &q.snapshot_sha256,
        |source| {
            if !q.read_only_snapshot&&(source.pin["kind"]=="PLAIN_PUBLIC"||source.structure_status()=="Seeding"){return Err(bad("LEGACY_SOURCE_REQUIRES_READ_ONLY_SNAPSHOT"));}
            let mut selected = BTreeMap::<(String, String), Value>::new();
            for wire in source.replay().objects() {
                let row = value(wire)?;
                let key = (
                    row["kind"]
                        .as_str()
                        .ok_or_else(|| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?
                        .into(),
                    row["id"]
                        .as_str()
                        .ok_or_else(|| bad("CHECKPOINT_CACHE_OBJECT_INVALID"))?
                        .into(),
                );
                if selected.get(&key).is_none_or(|old| {
                    old["revision"].as_u64().unwrap_or(0) < row["revision"].as_u64().unwrap_or(0)
                }) {
                    selected.insert(key, row);
                }
            }
            let mut instances = serde_json::Map::new();
            let mut schemas = BTreeMap::new();
            let mut requirements = BTreeSet::new();
            let mut encrypted_fields = 0;
            for ((kind, id), row) in &selected {
                if kind != "instances" {
                    continue;
                }
                let instance = decoded(row["value"].clone())?;
                let digest = instance["protocol_digest"]
                    .as_str()
                    .ok_or_else(|| bad("CHECKPOINT_CACHE_INSTANCE_INVALID"))?;
                let protocol = selected
                    .get(&("protocols".into(), digest.into()))
                    .ok_or_else(|| bad("CHECKPOINT_CACHE_PROTOCOL_MISSING"))?;
                let protocol = decoded(protocol["value"].clone())?;
                let original = decoded(
                    protocol
                        .get("resolved_manifest")
                        .cloned()
                        .ok_or_else(|| bad("CHECKPOINT_RESOLVED_MANIFEST_REQUIRED"))?,
                )?;
                let mut target=if q.read_only_snapshot{snapshot_manifest(original)?}else{original};if source.pin["kind"]=="PLAIN_PUBLIC"{target["historical_role_conflicts"]=json!([]);}
                let (manifest,mapped,needed)=transform(target)?;
                for need in needed {
                    requirements.insert(need);
                }
                for (name, mapping) in &mapped {
                    let unique = format!("{digest}:{name}");
                    if !schemas.contains_key(&unique) {
                        encrypted_fields += mapping["body_fields"]
                            .as_object()
                            .map_or(usize::from(!mapping["body_field"].is_null()), |m| m.len());
                        schemas.insert(unique, mapping.clone());
                    }
                }
                let state = decoded(instance["state"].clone())?;
                if has_narrative_fields(&state) {
                    return Err(bad("CHECKPOINT_STATE_BODY_REQUIRES_EXPLICIT_MAPPING"));
                }
                let state_fields: serde_json::Map<_, _> = state
                    .as_object()
                    .ok_or_else(|| bad("CHECKPOINT_CACHE_STATE_INVALID"))?
                    .keys()
                    .map(|field| (field.clone(), json!([field])))
                    .collect();
                // Grant no application authority implicitly during conversion. Subsequent
                // grants are selected explicitly and checked against retained role history.
                instances.insert(id.clone(),json!({"manifest":manifest,"state_fields":state_fields,"record_mappings":mapped,"bootstrap_grant":{"actions":[],"protocol_roles":[],"capabilities":[]}}));
            }
            let pin=source.pin.clone();
            let summary = json!({"instance_count":instances.len(),"schema_count":schemas.len(),"encrypted_body_field_count":encrypted_fields,"required_backend_features":requirements,"legacy_structure_status":source.replay().structure_status(),"relation_object_count":selected.keys().filter(|(kind,_)|kind=="record_relations").count()});
            Ok((
                json!({"schema":"peerwork.owner-conversion-map.v1","source":pin,"name":q.name,"workspace_alias":null,"instances":instances,"schemas":{}}),
                summary,
            ))
        },
    )?;
    if q.read_only_snapshot{plan["migration_mode"]=json!("READ_ONLY_SNAPSHOT");summary["migration_mode"]=json!("READ_ONLY_SNAPSHOT");summary["original_business_semantics_restored"]=json!(false);}
    let bytes = serde_json::to_vec_pretty(&plan).map_err(|_| bad("CHECKPOINT_PLAN_INVALID"))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(bad("CHECKPOINT_PLAN_LIMIT"));
    }
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| bad("CHECKPOINT_PLAN_WRITE_FAILED"))?;
    file.write_all(&bytes)
        .map_err(|_| bad("CHECKPOINT_PLAN_WRITE_FAILED"))?;
    file.as_file()
        .sync_all()
        .map_err(|_| bad("CHECKPOINT_PLAN_WRITE_FAILED"))?;
    file.persist_noclobber(&q.plan_path)
        .map_err(|_| bad("CHECKPOINT_PLAN_EXISTS"))?;
    summary["cache_selection"]=if q.capsule_path.is_some(){Value::Null}else{json!(q.cache_selection)};
    summary["source_mode"]=json!(if q.capsule_path.is_some(){"VERIFIED_OWNER_CAPSULE_MEMORY"}else{"VERIFIED_OWNER_CACHE_MEMORY"});
    summary["status"] = json!("POLICY_MAPPING_READY");
    summary["policy"] = json!("BODY_ENCRYPTED_STRUCTURE_READABLE");
    summary["plan_path"] = json!(q.plan_path);
    summary["plaintext_body_persisted"] = json!(false);
    summary["source_refresh_requested"]=json!(q.refresh_source);
    summary["network_requests"]=if q.refresh_source{Value::Null}else{json!(0)};
    summary["source_frontier"] = plan["source"].take();
    Ok(summary)
}
pub fn plan_owner_checkpoint_from_cache_json(input: &str) -> String {
    let result = (|| {
        if input.len() > 65536 {
            return Err(bad("CHECKPOINT_REQUEST_LIMIT"));
        }
        write_plan(serde_json::from_str(input).map_err(|_| bad("CHECKPOINT_REQUEST_INVALID"))?)
    })();
    match result{Ok(value)=>json!({"ok":true,"value":value}).to_string(),Err(error)=>json!({"ok":false,"code":error.0,"diagnostic":error.1,"stage":"OFFLINE_OWNER_POLICY_MAPPING","effect_certainty":"NOT_SUBMITTED"}).to_string()}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn narrative_fields_are_removed_from_structure_and_rule_outputs() {
        let original = json!({"dependencies":[],"record_schemas":{"task.revision":{"fields":{"title":"string","description":"string","note":"string","status":"string"},"required":["title","description","note","status"]}},"actions":[{"id":"create","variants":[{"when":[],"effects":[{"op":"append","schema":"task.revision","value":{"from":"object","fields":{"title":{"from":"input","path":["title"]},"description":{"from":"input","path":["description"]},"note":{"from":"literal","value":"PRIVATE LITERAL BODY"},"status":{"from":"literal","value":"OPEN"}}}}]}]}]});
        let (manifest, map, _) = transform(original).unwrap();
        assert!(!manifest.to_string().contains("PRIVATE LITERAL BODY"));
        assert!(manifest["actions"][0].get("inputs").is_none());
        assert!(manifest["record_schemas"]["task.revision"]["fields"]
            .get("description")
            .is_none());
        assert_eq!(
            map["task.revision"]["body_fields"]["description"],
            json!(["description"])
        );
    }
    #[test]
    fn literal_business_data_is_not_executed_or_rewritten_as_protocol_ast() {
        let data = json!({"op":"append","schema":"wiki.revision","value":{"from":"literal","value":{"body":42}},"from":"body","path":["body"]});
        let source = json!({"record_schemas":{"wiki.revision":{"fields":{"body":"string","metadata":"json"},"required":["body","metadata"]}},"actions":[{"variants":[{"when":[],"effects":[{"op":"append","schema":"wiki.revision","value":{"from":"object","fields":{"body":{"from":"literal","value":"secret narrative"},"metadata":{"from":"literal","value":data.clone()}}}}]}]}]});
        let (manifest, _, _) = transform(source).unwrap();
        assert_eq!(
            manifest["actions"][0]["variants"][0]["effects"][0]["value"]["fields"]["metadata"]
                ["value"],
            data
        );
        assert!(!manifest.to_string().contains("secret narrative"));
    }
    #[test]
    fn mixed_narrative_inside_structural_json_is_diagnosed_instead_of_disclosed() {
        assert!(has_narrative_fields(
            &json!({"metadata":{"body":"private text"}})
        ));
        assert!(!has_narrative_fields(
            &json!({"metadata":{"record_id":"R","revision":1,"path":["body"]}})
        ));
    }
    #[test]
    fn body_dependent_rules_cannot_be_silently_reinterpreted() {
        let manifest = json!({"record_schemas":{"wiki.revision":{"fields":{"body":"string"},"required":["body"]}},"actions":[{"variants":[{"when":[{"op":"eq","left":{"from":"input","path":["body"]},"right":{"from":"literal","value":"private"}}],"effects":[]}]}]});
        assert_eq!(
            transform(manifest).unwrap_err().0,
            "CHECKPOINT_BUSINESS_RULE_REQUIRES_BODY"
        );
    }
    #[test]
    fn converted_actions_never_require_plaintext_narrative_inputs() {
        let original = json!({"record_schemas":{"custom.entry":{"fields":{"text":"string","body":"integer","status":"string"},"required":["text","body","status"]}},"actions":[{"inputs":{"fields":{"draft":{"type":"string"},"status":{"type":"string"}},"required":["draft","status"],"additionalProperties":false},"variants":[{"when":[],"effects":[{"op":"append","schema":"custom.entry","value":{"from":"object","fields":{"text":{"from":"input","path":["draft"]},"body":{"from":"literal","value":42},"status":{"from":"input","path":["status"]}}}}]}]}]});
        let (manifest, mappings, _) = transform(original.clone()).unwrap();
        assert_eq!(mappings["custom.entry"]["body_field"], json!(["text"]));
        assert!(manifest["actions"][0]["inputs"]["fields"]
            .get("draft")
            .is_none());
        assert_eq!(
            manifest["actions"][0]["inputs"]["required"],
            json!(["status"])
        );
        assert_eq!(
            manifest["record_schemas"]["custom.entry"]["fields"]["body"],
            "integer"
        );
        let mut guarded = original;
        guarded["actions"][0]["variants"][0]["when"] = json!([{"op":"eq","left":{"from":"input","path":["draft"]},"right":{"from":"literal","value":"private"}}]);
        assert_eq!(
            transform(guarded).unwrap_err().0,
            "CHECKPOINT_BUSINESS_RULE_REQUIRES_BODY"
        );
    }
}

#[cfg(test)]mod snapshot_tests{
 use super::*;
 #[test]fn explicit_snapshot_preserves_data_mapping_but_does_not_claim_original_workflow_execution(){
  let original=json!({"name":"old","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"constraints":{},"initial_state":{},"record_schemas":{"task.revision":{"type":"object","fields":{"status":"string","description":"string"},"required":["status","description"],"max_bytes":4096,"workflow":{"dependencies":{"field":"deps"},"deadline":{"reminder":{"lead_ms":1}}}}},"actions":[{"id":"old.task","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":[]}]}]});
  let (target,mapping,_)=transform(snapshot_manifest(original.clone()).unwrap()).unwrap();
  assert!(original["record_schemas"]["task.revision"].get("workflow").is_some());assert!(target["record_schemas"]["task.revision"].get("workflow").is_none());
  assert_eq!(mapping["task.revision"]["body_field"],json!(["description"]));assert_eq!(mapping["task.revision"]["structure_fields"]["status"],json!(["status"]));
  assert_eq!(target["actions"][0]["id"],"snapshot.readonly");assert_eq!(target["actions"][0]["variants"][0]["when"][0]["left"]["value"],false);crate::owner_checkpoint::preflight_checkpoint_target(&json!({"instances":{"I":{"manifest":target}}})).unwrap();
 }
}
