//! Object-derived structured policy binding. This is a replay prerequisite,
//! not an authority proof: legacy migration and DELTA state authorization are
//! separate checks.

use crate::{
    canonical::Path,
    full_manifest::validate_full_manifest,
    wire_json::{
        canonical_wire_value, parse_js_json_string_bounded, parse_wire_json_js_bounded, WireValue,
    },
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidStructureBinding;
type Result<T> = std::result::Result<T, InvalidStructureBinding>;

fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue> {
    value.get(name).ok_or(InvalidStructureBinding)
}
fn text(value: &WireValue) -> Result<String> {
    value.as_string().ok_or(InvalidStructureBinding)
}
fn array(value: &WireValue) -> Result<&[WireValue]> {
    if let WireValue::Array(items) = value {
        Ok(items)
    } else {
        Err(InvalidStructureBinding)
    }
}
fn entries(value: &WireValue) -> Result<&[(Vec<u16>, WireValue)]> {
    if let WireValue::Object(items) = value {
        Ok(items)
    } else {
        Err(InvalidStructureBinding)
    }
}
fn obj(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.encode_utf16().collect(), value))
            .collect(),
    )
}
fn string(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn same(a: &WireValue, b: &WireValue) -> Result<bool> {
    Ok(
        canonical_wire_value(a, Path::SecureArtifact).map_err(|_| InvalidStructureBinding)?
            == canonical_wire_value(b, Path::SecureArtifact)
                .map_err(|_| InvalidStructureBinding)?,
    )
}
fn decode(value: &WireValue) -> Result<WireValue> {
    match value {
        WireValue::String(units) => {
            parse_js_json_string_bounded(units, 32, 65_536).map_err(|_| InvalidStructureBinding)
        }
        value => Ok(value.clone()),
    }
}
fn normalized_manifest(value: &WireValue) -> Result<WireValue> {
    let decoded = decode(value)?;
    let normalized = validate_full_manifest(&decoded).map_err(|_| InvalidStructureBinding)?;
    let wrapped = parse_wire_json_js_bounded(normalized.as_bytes(), 32, 65_536)
        .map_err(|_| InvalidStructureBinding)?;
    Ok(field(&wrapped, "manifest")?.clone())
}
fn latest<'a>(objects: &'a [WireValue], kind: &str) -> Result<Vec<&'a WireValue>> {
    let mut rows: Vec<&WireValue> = Vec::new();
    let mut positions: HashMap<Vec<u16>, usize> = HashMap::new();
    for row in objects {
        if row.get("kind").and_then(WireValue::as_string).as_deref() != Some(kind) {
            continue;
        }
        let id = field(row, "id")?
            .as_utf16()
            .ok_or(InvalidStructureBinding)?
            .to_vec();
        let revision = field(row, "revision")?
            .as_number()
            .ok_or(InvalidStructureBinding)?;
        if let Some(index) = positions.get(&id) {
            let old = field(rows[*index], "revision")?
                .as_number()
                .ok_or(InvalidStructureBinding)?;
            if old < revision {
                rows[*index] = row;
            }
        } else {
            positions.insert(id, rows.len());
            rows.push(row);
        }
    }
    Ok(rows)
}

const READABLE: &[(&str, &[(&str, &str)])] = &[
    (
        "coordination.request",
        &[
            ("request_id", "opaque"),
            ("recipients", "tokens"),
            ("source_ref", "optional_workspace_reference"),
            ("author", "actor"),
        ],
    ),
    (
        "coordination.ack",
        &[
            ("item_id", "item_key"),
            ("source_ref", "workspace_reference"),
            ("source_hash", "digest"),
            ("author", "actor"),
        ],
    ),
    (
        "coordination.disposition",
        &[
            ("item_id", "item_key"),
            ("source_ref", "workspace_reference"),
            ("source_hash", "digest"),
            ("author", "actor"),
            ("expected_version", "counter"),
            ("state", "work_status"),
            ("defer_until", "timestamp"),
            ("result_ref", "optional_workspace_reference"),
        ],
    ),
    (
        "coordination.cancel",
        &[
            ("item_id", "item_key"),
            ("source_ref", "workspace_reference"),
            ("source_hash", "digest"),
            ("author", "actor"),
        ],
    ),
    (
        "coordination.remind",
        &[
            ("item_id", "item_key"),
            ("source_ref", "workspace_reference"),
            ("source_hash", "digest"),
            ("author", "actor"),
        ],
    ),
    (
        "discussion.message",
        &[("author", "actor"), ("reply_to", "optional_reference")],
    ),
    (
        "wiki.revision",
        &[("author", "actor"), ("parent", "optional_reference")],
    ),
    (
        "task.revision",
        &[
            ("status", "task_status"),
            ("assignee", "optional_actor"),
            ("author", "actor"),
            ("parent", "optional_reference"),
        ],
    ),
    (
        "task.report",
        &[("task_ref", "reference"), ("author", "actor")],
    ),
];
fn readable(schema: &str, field: &str) -> Option<&'static str> {
    READABLE
        .iter()
        .find(|(s, _)| *s == schema)
        .and_then(|(_, fields)| fields.iter().find(|(f, _)| *f == field).map(|(_, t)| *t))
}
fn transition(schemas: &WireValue, action: &str) -> Option<WireValue> {
    let fields = schemas.get("task.revision")?.get("fields")?;
    let status = fields.get("status")?;
    let parent = fields.get("parent")?;
    if status.get("protection")?.as_string()?.as_str() != "server_readable"
        || status.get("type")?.as_string()?.as_str() != "task_status"
        || parent.get("protection")?.as_string()?.as_str() != "server_readable"
        || parent.get("type")?.as_string()?.as_str() != "optional_reference"
    {
        return None;
    }
    let pair = |from: Option<&str>, to: &str| {
        obj(vec![
            ("from", from.map(string).unwrap_or(WireValue::Null)),
            ("to", string(to)),
        ])
    };
    match action {
        "task.create" => Some(WireValue::Array(vec![pair(None, "OPEN")])),
        "task.update" => Some(WireValue::Array(vec![
            pair(Some("OPEN"), "IN_PROGRESS"),
            pair(Some("IN_PROGRESS"), "DONE"),
            pair(Some("OPEN"), "CANCELED"),
            pair(Some("IN_PROGRESS"), "CANCELED"),
        ])),
        _ => None,
    }
}
fn common_guards(variants: &[WireValue], op: &str, key: &str) -> Result<Vec<WireValue>> {
    let Some(first) = variants.first() else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for predicate in array(field(first, "when")?)? {
        if field(predicate, "op")?.as_string().as_deref() != Some(op) {
            continue;
        }
        let value = field(predicate, key)?;
        if variants.iter().all(|variant| {
            variant
                .get("when")
                .and_then(|v| array(v).ok())
                .is_some_and(|guards| {
                    guards.iter().any(|guard| {
                        guard.get("op").and_then(WireValue::as_string).as_deref() == Some(op)
                            && guard.get(key) == Some(value)
                    })
                })
        }) {
            out.push(value.clone());
        }
    }
    Ok(out)
}
fn protocol_from_manifest(
    id: &str,
    manifest: &WireValue,
    declared: &WireValue,
) -> Result<WireValue> {
    let mut schemas = Vec::new();
    let mut any_declaration = false;
    let declared_schemas = field(declared, "schemas")?;
    for (schema_units, definition) in entries(field(manifest, "record_schemas")?)? {
        let schema = String::from_utf16(schema_units).map_err(|_| InvalidStructureBinding)?;
        let mut fields = Vec::new();
        let protection = definition.get("protection");
        if protection.is_some() {
            any_declaration = true;
        }
        for (name_units, kind) in entries(field(definition, "fields")?)? {
            let name = String::from_utf16(name_units).map_err(|_| InvalidStructureBinding)?;
            let encrypted = declared_schemas
                .get(&schema)
                .and_then(|v| v.get("fields"))
                .and_then(|v| v.get(&name))
                .and_then(|v| v.get("protection"))
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("e2ee");
            let rule = if encrypted {
                obj(vec![("protection", string("e2ee")), ("type", kind.clone())])
            } else if let Some(rule) = protection
                .and_then(|p| p.get("fields"))
                .and_then(|f| f.get(&name))
            {
                rule.clone()
            } else if let Some(kind) = readable(&schema, &name) {
                obj(vec![
                    ("protection", string("server_readable")),
                    ("type", string(kind)),
                ])
            } else {
                obj(vec![("protection", string("e2ee")), ("type", kind.clone())])
            };
            fields.push((name_units.clone(), rule));
        }
        let mut schema_fields = vec![
            ("fields", WireValue::Object(fields)),
            ("required", field(definition, "required")?.clone()),
        ];
        if let Some(workflow) = definition.get("workflow") {
            schema_fields.push(("workflow", workflow.clone()));
        }
        schemas.push((schema_units.clone(), obj(schema_fields)));
    }
    let schemas = WireValue::Object(schemas);
    let mut actions = Vec::new();
    for action in array(field(manifest, "actions")?)? {
        let action_id = text(field(action, "id")?)?;
        let variants = array(field(action, "variants")?)?;
        let mut produced = Vec::new();
        let mut seen = HashSet::new();
        let mut select = false;
        let mut append_head = false;
        for variant in variants {
            for effect in array(field(variant, "effects")?)? {
                match field(effect, "op")?
                    .as_string()
                    .ok_or(InvalidStructureBinding)?
                    .as_str()
                {
                    "append" => {
                        let schema = text(field(effect, "schema")?)?;
                        if seen.insert(schema.clone()) {
                            produced.push(string(&schema));
                        }
                        append_head |= effect
                            .get("selectHead")
                            .and_then(|v| {
                                if let WireValue::Bool(b) = v {
                                    Some(*b)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(false);
                    }
                    "select_head" => select = true,
                    _ => {}
                }
            }
        }
        let roles = common_guards(variants, "has_protocol_role", "role")?;
        let capabilities = common_guards(variants, "has_capability", "capability")?;
        let mut unique_caps = Vec::new();
        for cap in capabilities {
            if !unique_caps.contains(&cap) {
                unique_caps.push(cap);
            }
        }
        let head = if select {
            "SELECT"
        } else if append_head {
            "APPEND"
        } else {
            "NONE"
        };
        let mut rule = vec![
            ("schemas", WireValue::Array(produced)),
            ("roles", WireValue::Array(roles)),
            ("capabilities", WireValue::Array(unique_caps)),
            ("heads", string(head)),
        ];
        if let Some(transitions) = transition(&schemas, &action_id) {
            rule.push(("task_transition", transitions));
        }
        actions.push((action_id.encode_utf16().collect(), obj(rule)));
    }
    let mut protocol = vec![
        ("v", WireValue::Number(1.0)),
        ("protocol_digest", string(id)),
        ("schemas", schemas),
        ("actions", WireValue::Object(actions)),
    ];
    if any_declaration {
        protocol.push(("field_declarations", WireValue::Number(1.0)));
    }
    Ok(obj(protocol))
}

#[cfg(test)]
pub(crate) fn protocol_with_default_choices_for_test(id: &str, raw: &WireValue) -> WireValue {
    protocol_from_manifest(
        id,
        &normalized_manifest(raw).unwrap(),
        &obj(vec![("schemas", obj(vec![]))]),
    )
    .unwrap()
}

pub(crate) fn validate_object_bindings(policy: &WireValue, objects: &[WireValue]) -> Result<()> {
    crate::structure_policy::validate_structure_policy(policy)
        .map_err(|_| InvalidStructureBinding)?;
    let mut derived = Vec::new();
    for object in latest(objects, "protocols")? {
        // Legacy rows require their separate canonical envelope and composition
        // verification before this object-derived declaration can be trusted.
        if field(object, "provenance")?.as_string().as_deref() != Some("AUTHOR_SIGNED") {
            return Err(InvalidStructureBinding);
        }
        let id = text(field(object, "id")?)?;
        let value = field(object, "value")?;
        let manifest = normalized_manifest(
            value
                .get("resolved_manifest")
                .unwrap_or(field(value, "manifest")?),
        )?;
        let declared = array(field(policy, "protocols")?)?.iter().find(|p| {
            p.get("protocol_digest")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(&id)
        });
        // A protocol absent from the signed policy must not acquire a structure declaration.
        let declared = declared.ok_or(InvalidStructureBinding)?;
        derived.push(protocol_from_manifest(&id, &manifest, declared)?);
    }
    let declared = array(field(policy, "protocols")?)?;
    if declared.len() != derived.len() {
        return Err(InvalidStructureBinding);
    }
    for protocol in declared {
        let id = text(field(protocol, "protocol_digest")?)?;
        let actual = derived
            .iter()
            .find(|p| {
                p.get("protocol_digest")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&id)
            })
            .ok_or(InvalidStructureBinding)?;
        if !same(protocol, actual)? {
            return Err(InvalidStructureBinding);
        }
    }
    let instances = latest(objects, "instances")?
        .into_iter()
        .map(|row| {
            Ok(obj(vec![
                ("instance_id", field(row, "id")?.clone()),
                (
                    "protocol_digest",
                    field(field(row, "value")?, "protocol_digest")?.clone(),
                ),
            ]))
        })
        .collect::<Result<Vec<_>>>()?;
    if !same(field(policy, "instances")?, &WireValue::Array(instances))? {
        return Err(InvalidStructureBinding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_typescript_object_derived_bindings() {
        let cases = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/structure-binding-vectors.json"),
            64,
            1_000_000,
        )
        .unwrap();
        for case in array(&cases).unwrap() {
            let name = field(case, "name").unwrap().as_string().unwrap();
            if name == "official_proposal_declaration" {
                let manifest = field(case, "manifest").unwrap();
                let id = text(field(case, "digest").unwrap()).unwrap();
                let expected = field(case, "expected_protocol").unwrap();
                let actual = protocol_with_default_choices_for_test(&id, manifest);
                assert!(same(&actual, expected).unwrap(), "{name}");
                continue;
            }
            let policy = field(case, "policy").unwrap();
            let objects = array(field(case, "objects").unwrap()).unwrap();
            let expected = field(case, "ok").unwrap() == &WireValue::Bool(true);
            assert_eq!(
                validate_object_bindings(policy, objects).is_ok(),
                expected,
                "{name}"
            );
        }
    }
}
