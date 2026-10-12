//! Deterministic genesis structure declaration from signed BOOTSTRAP objects.
//! This constructs a proposed policy; it grants no authority or replay result.

use crate::{
    canonical::Path,
    structure_bindings::{derive_genesis_protocol, validate_object_bindings},
    structure_policy::validate_structure_policy,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GenesisStructureError {
    #[error("genesis objects cannot form the requested structure policy")]
    Invalid,
}

fn key(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}
fn text(name: &str) -> WireValue {
    WireValue::String(key(name))
}
fn obj(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(fields.into_iter().map(|(k, v)| (key(k), v)).collect())
}

struct Choice {
    schema: String,
    fields: Vec<String>,
    protocol_digest: Option<String>,
}
fn name(value: &str) -> bool {
    value.len() <= 80
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value.as_bytes()[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'.' | b'-'))
}
fn choices(wire: &[u8]) -> Result<Vec<Choice>, GenesisStructureError> {
    let bad = || GenesisStructureError::Invalid;
    let parsed = parse_wire_json_bounded(wire, 32, 65_536).map_err(|_| bad())?;
    let WireValue::Array(items) = parsed else {
        return Err(bad());
    };
    if items.len() > 256 {
        return Err(bad());
    }
    items
        .iter()
        .map(|item| {
            let count = item.object_len().ok_or_else(bad)?;
            if count != 2 && count != 3 {
                return Err(bad());
            }
            let schema = item
                .get("schema")
                .and_then(WireValue::as_string)
                .ok_or_else(bad)?;
            if !name(&schema) {
                return Err(bad());
            }
            let protocol_digest = item
                .get("protocol_digest")
                .map(|v| v.as_string().ok_or_else(bad))
                .transpose()?;
            if count != 2 + usize::from(protocol_digest.is_some()) {
                return Err(bad());
            }
            if protocol_digest.as_ref().is_some_and(|d| {
                d.len() != 64
                    || !d
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }) {
                return Err(bad());
            }
            let Some(WireValue::Array(raw_fields)) = item.get("fields") else {
                return Err(bad());
            };
            if raw_fields.is_empty() || raw_fields.len() > 64 {
                return Err(bad());
            }
            let mut seen = HashSet::new();
            let mut fields = Vec::new();
            for field in raw_fields {
                let value = field.as_string().ok_or_else(bad)?;
                if !name(&value) || !seen.insert(value.clone()) {
                    return Err(bad());
                }
                fields.push(value);
            }
            Ok(Choice {
                schema,
                fields,
                protocol_digest,
            })
        })
        .collect()
}

/// Mirrors `structurePolicyFromObjects(objects,{})` for a genesis set with no
/// `keep_encrypted` overrides. The caller must bind these objects into its
/// separately signed operation and policy before transport.
pub fn derive_genesis_structure_policy(
    objects_wire: &[u8],
) -> Result<String, GenesisStructureError> {
    derive_genesis_structure_policy_with_keep_encrypted(objects_wire, b"[]")
}

pub fn derive_genesis_structure_policy_with_keep_encrypted(
    objects_wire: &[u8],
    keep_encrypted_wire: &[u8],
) -> Result<String, GenesisStructureError> {
    let bad = || GenesisStructureError::Invalid;
    let choices = choices(keep_encrypted_wire)?;
    let mut matched = vec![false; choices.len()];
    let parsed = parse_wire_json_bounded(objects_wire, 64, 2_000_000).map_err(|_| bad())?;
    let WireValue::Array(objects) = parsed else {
        return Err(bad());
    };
    if objects.len() > 128 {
        return Err(bad());
    }
    let mut protocols = Vec::new();
    let mut disclosure = Vec::new();
    let mut instances = Vec::new();
    let mut protocol_ids = HashSet::new();
    let mut instance_ids = HashSet::new();
    for row in &objects {
        let kind = row
            .get("kind")
            .and_then(WireValue::as_string)
            .ok_or_else(bad)?;
        if kind == "protocols" {
            let id = row
                .get("id")
                .and_then(WireValue::as_string)
                .ok_or_else(bad)?;
            if !protocol_ids.insert(id.clone()) {
                return Err(bad());
            }
            let value = row.get("value").ok_or_else(bad)?;
            let manifest = value
                .get("resolved_manifest")
                .or_else(|| value.get("manifest"))
                .ok_or_else(bad)?;
            let default =
                derive_genesis_protocol(&id, manifest, &obj(vec![("schemas", obj(vec![]))]))
                    .map_err(|_| bad())?;
            let mut declared: BTreeMap<String, BTreeMap<String, WireValue>> = BTreeMap::new();
            let mut selected = HashSet::new();
            for (i, choice) in choices.iter().enumerate() {
                if choice.protocol_digest.as_deref().is_some_and(|d| d != id)
                    || default
                        .get("schemas")
                        .and_then(|v| v.get(&choice.schema))
                        .is_none()
                {
                    continue;
                }
                matched[i] = true;
                for field in &choice.fields {
                    if default
                        .get("schemas")
                        .and_then(|v| v.get(&choice.schema))
                        .and_then(|v| v.get("fields"))
                        .and_then(|v| v.get(field))
                        .is_none()
                        || !selected.insert((choice.schema.clone(), field.clone()))
                    {
                        return Err(bad());
                    }
                    declared
                        .entry(choice.schema.clone())
                        .or_default()
                        .insert(field.clone(), obj(vec![("protection", text("e2ee"))]));
                }
            }
            let declared = WireValue::Object(
                declared
                    .into_iter()
                    .map(|(schema, fields)| {
                        (
                            key(&schema),
                            obj(vec![(
                                "fields",
                                WireValue::Object(
                                    fields
                                        .into_iter()
                                        .map(|(field, rule)| (key(&field), rule))
                                        .collect(),
                                ),
                            )]),
                        )
                    })
                    .collect(),
            );
            let protocol =
                derive_genesis_protocol(&id, manifest, &obj(vec![("schemas", declared)]))
                    .map_err(|_| bad())?;
            let WireValue::Object(schemas) = manifest.get("record_schemas").ok_or_else(bad)? else {
                return Err(bad());
            };
            for (schema_units, schema) in schemas {
                let schema_name = WireValue::String(schema_units.clone());
                let schema_id = schema_name.as_string().ok_or_else(bad)?;
                let WireValue::Object(fields) = schema.get("fields").ok_or_else(bad)? else {
                    return Err(bad());
                };
                let readable = fields
                    .iter()
                    .filter_map(|(field, _)| {
                        let field_id = WireValue::String(field.clone()).as_string()?;
                        let rule = protocol
                            .get("schemas")?
                            .get(&schema_id)?
                            .get("fields")?
                            .get(&field_id)?;
                        (rule
                            .get("protection")
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some("server_readable"))
                        .then(|| WireValue::String(field.clone()))
                    })
                    .collect();
                disclosure.push(obj(vec![
                    ("protocol_digest", text(&id)),
                    ("schema", schema_name),
                    ("fields", WireValue::Array(readable)),
                ]));
            }
            protocols.push(protocol);
        } else if kind == "instances" {
            let id = row
                .get("id")
                .and_then(WireValue::as_string)
                .ok_or_else(bad)?;
            if !instance_ids.insert(id.clone()) {
                return Err(bad());
            }
            let digest = row
                .get("value")
                .and_then(|v| v.get("protocol_digest"))
                .and_then(WireValue::as_string)
                .ok_or_else(bad)?;
            instances.push(obj(vec![
                ("instance_id", text(&id)),
                ("protocol_digest", text(&digest)),
            ]));
        }
    }
    if matched.iter().any(|value| !value) {
        return Err(bad());
    }
    let policy = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("protocols", WireValue::Array(protocols)),
        ("disclosure", WireValue::Array(disclosure)),
        ("instances", WireValue::Array(instances)),
    ]);
    validate_structure_policy(&policy).map_err(|_| bad())?;
    validate_object_bindings(&policy, &objects).map_err(|_| bad())?;
    canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| bad())
}

/// Attach the tracked default coordination policy to an object-derived
/// genesis declaration. The owner is the initial coordinator; version 2
/// selects result-aware routing. Signed policy authority is still separate.
pub fn derive_genesis_structure_policy_with_coordination(
    objects_wire: &[u8],
    instance_id: &str,
    protocol_digest: &str,
    owner_actor: &str,
    version: u8,
) -> Result<String, GenesisStructureError> {
    derive_genesis_structure_policy_with_coordination_and_keep_encrypted(
        objects_wire,
        b"[]",
        instance_id,
        protocol_digest,
        owner_actor,
        version,
    )
}

pub fn derive_genesis_structure_policy_with_coordination_and_keep_encrypted(
    objects_wire: &[u8],
    keep_encrypted_wire: &[u8],
    instance_id: &str,
    protocol_digest: &str,
    owner_actor: &str,
    version: u8,
) -> Result<String, GenesisStructureError> {
    let bad = || GenesisStructureError::Invalid;
    if !matches!(version, 1 | 2) {
        return Err(bad());
    }
    let base =
        derive_genesis_structure_policy_with_keep_encrypted(objects_wire, keep_encrypted_wire)?;
    let mut policy = parse_wire_json_bounded(base.as_bytes(), 64, 2_000_000).map_err(|_| bad())?;
    let WireValue::Object(fields) = &mut policy else {
        return Err(bad());
    };
    fields.push((
        key("coordination"),
        obj(vec![
            ("v", WireValue::Number(version as f64)),
            ("instance_id", text(instance_id)),
            ("protocol_digest", text(protocol_digest)),
            ("coordinator", text(owner_actor)),
            ("initial_delay_ms", WireValue::Number(60_000.0)),
            ("max_delay_ms", WireValue::Number(3_600_000.0)),
            ("escalate_after", WireValue::Number(5.0)),
            ("window_ms", WireValue::Number(60_000.0)),
            ("workspace_limit", WireValue::Number(60.0)),
            ("sender_limit", WireValue::Number(10.0)),
            ("recipient_limit", WireValue::Number(10.0)),
        ]),
    ));
    validate_structure_policy(&policy).map_err(|_| bad())?;
    let objects = parse_wire_json_bounded(objects_wire, 64, 2_000_000).map_err(|_| bad())?;
    let WireValue::Array(objects) = objects else {
        return Err(bad());
    };
    validate_object_bindings(&policy, &objects).map_err(|_| bad())?;
    canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bootstrap_objects::owner_bootstrap_objects, crypto::base64url};
    #[test]
    fn six_preset_genesis_has_valid_object_derived_structure() {
        let workspace = base64url(&[7; 32]);
        let owner = base64url(&[8; 32]);
        let ids = std::array::from_fn(|i| base64url(&[i as u8 + 20; 32]));
        let built = owner_bootstrap_objects("Structured", &workspace, &owner, 100, &ids).unwrap();
        let objects = serde_json::to_vec(&built.operation()["objects"]).unwrap();
        let policy = derive_genesis_structure_policy(&objects).unwrap();
        let json: serde_json::Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(json["protocols"].as_array().unwrap().len(), 6);
        assert_eq!(json["instances"].as_array().unwrap().len(), 6);
        assert!(json["disclosure"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn exact_tracked_typescript_default_and_custom_declarations() {
        fn difference(a: &serde_json::Value, b: &serde_json::Value, path: &str) -> Option<String> {
            match (a, b) {
                (serde_json::Value::Array(a), serde_json::Value::Array(b)) => {
                    if a.len() != b.len() {
                        return Some(format!("{path}: lengths {} vs {}", a.len(), b.len()));
                    }
                    for (i, (a, b)) in a.iter().zip(b).enumerate() {
                        if let Some(found) = difference(a, b, &format!("{path}/{i}")) {
                            return Some(found);
                        }
                    }
                    None
                }
                (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
                    for key in a.keys().chain(b.keys()) {
                        if let Some(found) = difference(&a[key], &b[key], &format!("{path}/{key}"))
                        {
                            return Some(found);
                        }
                    }
                    None
                }
                _ if a != b => Some(format!("{path}: {a} vs {b}")),
                _ => None,
            }
        }
        let fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/genesis-structure-vectors.json"),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = fixture else {
            panic!("fixture cases");
        };
        assert_eq!(cases.len(), 3);
        for case in cases {
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let objects = case
                .get("objects_wire")
                .and_then(WireValue::as_string)
                .unwrap();
            let expected =
                canonical_wire_value(case.get("policy").unwrap(), Path::SecureArtifact).unwrap();
            let choices = case
                .get("choices_wire")
                .and_then(WireValue::as_string)
                .unwrap();
            let actual = derive_genesis_structure_policy_with_keep_encrypted(
                objects.as_bytes(),
                choices.as_bytes(),
            )
            .unwrap();
            let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();
            let actual: serde_json::Value = serde_json::from_str(&actual).unwrap();
            assert!(
                difference(&actual, &expected, "").is_none(),
                "{name}: {:?}",
                difference(&actual, &expected, "")
            );
        }
    }
}
