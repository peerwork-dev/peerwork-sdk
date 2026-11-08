//! Lossless shape validation for a signed structured policy. This is one
//! prerequisite of object-derived bindings and DELTA authorization, not a
//! journal authority proof.

use crate::wire_json::WireValue;
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidStructurePolicy;
type Result<T> = std::result::Result<T, InvalidStructurePolicy>;

fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue> {
    value.get(name).ok_or(InvalidStructurePolicy)
}
fn array(value: &WireValue, max: usize) -> Result<&[WireValue]> {
    match value {
        WireValue::Array(items) if items.len() <= max => Ok(items),
        _ => Err(InvalidStructurePolicy),
    }
}
fn object(value: &WireValue, max: usize) -> Result<&[(Vec<u16>, WireValue)]> {
    match value {
        WireValue::Object(items) if items.len() <= max => Ok(items),
        _ => Err(InvalidStructurePolicy),
    }
}
fn shape(value: &WireValue, required: &[&str], optional: &[&str]) -> Result<()> {
    let fields = object(value, required.len() + optional.len())?;
    if required.iter().any(|name| value.get(name).is_none())
        || fields.iter().any(|(name, _)| {
            !required
                .iter()
                .chain(optional)
                .any(|allowed| name == &allowed.encode_utf16().collect::<Vec<_>>())
        })
    {
        return Err(InvalidStructurePolicy);
    }
    Ok(())
}
fn text(value: &WireValue) -> Result<String> {
    value.as_string().ok_or(InvalidStructurePolicy)
}
fn integer(value: &WireValue) -> Result<u64> {
    let n = value.as_number().ok_or(InvalidStructurePolicy)?;
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(InvalidStructurePolicy);
    }
    Ok(n as u64)
}
fn ascii_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 80
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}
fn state_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 40
        && bytes[0].is_ascii_uppercase()
        && bytes[1..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
}
fn unique_text(values: &WireValue, max: usize, check: fn(&str) -> bool) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in array(values, max)? {
        let value = text(item)?;
        if !check(&value) || !seen.insert(value.clone()) {
            return Err(InvalidStructurePolicy);
        }
        out.push(value);
    }
    Ok(out)
}
fn protected_rule(value: &WireValue) -> Result<()> {
    shape(value, &["protection", "type"], &["values"])?;
    let mode = text(field(value, "protection")?)?;
    let kind = text(field(value, "type")?)?;
    match mode.as_str() {
        "e2ee"
            if value.get("values").is_none()
                && matches!(
                    kind.as_str(),
                    "string" | "integer" | "boolean" | "null" | "json"
                ) =>
        {
            Ok(())
        }
        "server_readable" if kind == "enum" => {
            shape(value, &["protection", "type", "values"], &[])?;
            let values = unique_text(field(value, "values")?, 32, state_name)?;
            if values.is_empty() {
                Err(InvalidStructurePolicy)
            } else {
                Ok(())
            }
        }
        "server_readable"
            if value.get("values").is_none()
                && matches!(
                    kind.as_str(),
                    "actor"
                        | "optional_actor"
                        | "reference"
                        | "optional_reference"
                        | "references"
                        | "timestamp"
                        | "tokens"
                        | "task_status"
                        | "opaque"
                        | "item_key"
                        | "digest"
                        | "counter"
                        | "work_status"
                        | "workspace_reference"
                        | "optional_workspace_reference"
                ) =>
        {
            Ok(())
        }
        _ => Err(InvalidStructurePolicy),
    }
}
fn truthy(value: &WireValue) -> bool {
    match value {
        WireValue::Null | WireValue::Bool(false) => false,
        WireValue::Number(number) if *number == 0.0 => false,
        WireValue::String(units) if units.is_empty() => false,
        _ => true,
    }
}

fn workflow(value: &WireValue, fields: &WireValue, required: &[WireValue]) -> Result<()> {
    crate::full_manifest::validate_structure_workflow(value, fields, required)
        .map_err(|_| InvalidStructurePolicy)
}

fn coordination(value: &WireValue) -> Result<(String, String)> {
    shape(
        value,
        &[
            "v",
            "instance_id",
            "protocol_digest",
            "coordinator",
            "initial_delay_ms",
            "max_delay_ms",
            "escalate_after",
            "window_ms",
            "workspace_limit",
            "sender_limit",
            "recipient_limit",
        ],
        &[],
    )?;
    if !matches!(integer(field(value, "v")?)?, 1 | 2) {
        return Err(InvalidStructurePolicy);
    }
    let instance = text(field(value, "instance_id")?)?;
    let coordinator = text(field(value, "coordinator")?)?;
    let protocol = text(field(value, "protocol_digest")?)?;
    if !token(&instance) || !token(&coordinator) || !digest(&protocol) {
        return Err(InvalidStructurePolicy);
    }
    let initial = integer(field(value, "initial_delay_ms")?)?;
    let max = integer(field(value, "max_delay_ms")?)?;
    let escalate = integer(field(value, "escalate_after")?)?;
    let window = integer(field(value, "window_ms")?)?;
    let workspace_limit = integer(field(value, "workspace_limit")?)?;
    let sender = integer(field(value, "sender_limit")?)?;
    let recipient = integer(field(value, "recipient_limit")?)?;
    if initial < 1000
        || max < initial
        || max > 86_400_000
        || escalate == 0
        || escalate > 100
        || window < 1000
        || window > 3_600_000
        || workspace_limit == 0
        || workspace_limit > 1000
        || sender == 0
        || sender > workspace_limit
        || recipient == 0
        || recipient > workspace_limit
    {
        return Err(InvalidStructurePolicy);
    }
    Ok((instance, protocol))
}

pub(crate) fn validate_structure_policy(value: &WireValue) -> Result<()> {
    shape(
        value,
        &["v", "protocols", "disclosure", "instances"],
        &["coordination"],
    )?;
    if integer(field(value, "v")?)? != 1 {
        return Err(InvalidStructurePolicy);
    }
    let mut protocols = HashMap::<String, &WireValue>::new();
    for protocol in array(field(value, "protocols")?, 64)? {
        shape(
            protocol,
            &["v", "protocol_digest", "schemas", "actions"],
            &["field_declarations"],
        )?;
        let id = text(field(protocol, "protocol_digest")?)?;
        if integer(field(protocol, "v")?)? != 1
            || !digest(&id)
            || protocol
                .get("field_declarations")
                .is_some_and(|v| integer(v) != Ok(1))
            || protocols.insert(id, protocol).is_some()
        {
            return Err(InvalidStructurePolicy);
        }
        let schemas = field(protocol, "schemas")?;
        for (schema_name, definition) in object(schemas, 64)? {
            let name = String::from_utf16(schema_name).map_err(|_| InvalidStructurePolicy)?;
            if !ascii_name(&name) {
                return Err(InvalidStructurePolicy);
            }
            shape(definition, &["fields", "required"], &["workflow"])?;
            let fields = field(definition, "fields")?;
            for (field_name, rule) in object(fields, 64)? {
                let name = String::from_utf16(field_name).map_err(|_| InvalidStructurePolicy)?;
                if !ascii_name(&name) {
                    return Err(InvalidStructurePolicy);
                }
                protected_rule(rule)?;
            }
            let required = array(field(definition, "required")?, 64)?;
            let mut seen = HashSet::new();
            for item in required {
                let name = text(item)?;
                if fields.get(&name).is_none() || !seen.insert(name) {
                    return Err(InvalidStructurePolicy);
                }
            }
            if let Some(rule) = definition.get("workflow").filter(|value| truthy(value)) {
                workflow(rule, fields, required)?;
            }
        }
        for (action_name, rule) in object(field(protocol, "actions")?, 64)? {
            let action = String::from_utf16(action_name).map_err(|_| InvalidStructurePolicy)?;
            if !ascii_name(&action) {
                return Err(InvalidStructurePolicy);
            }
            shape(
                rule,
                &["schemas", "roles", "capabilities", "heads"],
                &["task_transition"],
            )?;
            if !matches!(
                text(field(rule, "heads")?)?.as_str(),
                "NONE" | "APPEND" | "SELECT"
            ) {
                return Err(InvalidStructurePolicy);
            }
            unique_text(field(rule, "schemas")?, 64, ascii_name)?
                .iter()
                .try_for_each(|name| {
                    if schemas.get(name).is_some() {
                        Ok(())
                    } else {
                        Err(InvalidStructurePolicy)
                    }
                })?;
            unique_text(field(rule, "roles")?, 64, ascii_name)?;
            unique_text(field(rule, "capabilities")?, 64, ascii_name)?;
            if let Some(transitions) = rule.get("task_transition").filter(|value| truthy(value)) {
                let task = schemas.get("task.revision").ok_or(InvalidStructurePolicy)?;
                let fields = field(task, "fields")?;
                let status = field(fields, "status")?;
                let parent = field(fields, "parent")?;
                if text(field(status, "protection")?)? != "server_readable"
                    || text(field(status, "type")?)? != "task_status"
                    || text(field(parent, "protection")?)? != "server_readable"
                    || text(field(parent, "type")?)? != "optional_reference"
                    || !array(field(rule, "schemas")?, 64)?
                        .iter()
                        .any(|v| v.as_string().as_deref() == Some("task.revision"))
                {
                    return Err(InvalidStructurePolicy);
                }
                let items = array(transitions, 16)?;
                if items.is_empty() {
                    return Err(InvalidStructurePolicy);
                }
                for item in items {
                    shape(item, &["from", "to"], &[])?;
                    let valid = |v: &WireValue| {
                        v.as_string().is_some_and(|s| {
                            matches!(s.as_str(), "OPEN" | "IN_PROGRESS" | "DONE" | "CANCELED")
                        })
                    };
                    if !matches!(field(item, "from")?, WireValue::Null)
                        && !valid(field(item, "from")?)
                        || !valid(field(item, "to")?)
                    {
                        return Err(InvalidStructurePolicy);
                    }
                }
            }
        }
    }
    let mut grants = HashSet::new();
    for grant in array(field(value, "disclosure")?, 256)? {
        shape(grant, &["protocol_digest", "schema", "fields"], &[])?;
        let digest = text(field(grant, "protocol_digest")?)?;
        let schema = text(field(grant, "schema")?)?;
        let definition = protocols
            .get(&digest)
            .and_then(|p| p.get("schemas"))
            .and_then(|s| s.get(&schema))
            .ok_or(InvalidStructurePolicy)?;
        if !grants.insert((digest.clone(), schema.clone())) {
            return Err(InvalidStructurePolicy);
        }
        let fields = field(definition, "fields")?;
        for name in unique_text(field(grant, "fields")?, 64, ascii_name)? {
            let rule = fields.get(&name).ok_or(InvalidStructurePolicy)?;
            if text(field(rule, "protection")?)? != "server_readable" {
                return Err(InvalidStructurePolicy);
            }
        }
    }
    for (digest, protocol) in &protocols {
        for (schema_name, definition) in object(field(protocol, "schemas")?, 64)? {
            let schema = String::from_utf16(schema_name).map_err(|_| InvalidStructurePolicy)?;
            let approved = array(field(value, "disclosure")?, 256)?.iter().find(|g| {
                g.get("protocol_digest")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(digest)
                    && g.get("schema").and_then(WireValue::as_string).as_deref() == Some(&schema)
            });
            for (name, rule) in object(field(definition, "fields")?, 64)? {
                if text(field(rule, "protection")?)? == "server_readable"
                    && !approved
                        .and_then(|g| g.get("fields"))
                        .and_then(|v| array(v, 64).ok())
                        .is_some_and(|items| items.iter().any(|v| v.as_utf16() == Some(name)))
                {
                    return Err(InvalidStructurePolicy);
                }
            }
        }
    }
    let mut instances = HashSet::new();
    for instance in array(field(value, "instances")?, 128)? {
        shape(instance, &["instance_id", "protocol_digest"], &[])?;
        let id = text(field(instance, "instance_id")?)?;
        let protocol = text(field(instance, "protocol_digest")?)?;
        if !token(&id)
            || !protocols.contains_key(&protocol)
            || !instances.insert((id.clone(), protocol))
            || instances.iter().filter(|(saved, _)| saved == &id).count() != 1
        {
            return Err(InvalidStructurePolicy);
        }
    }
    if let Some(coord) = value.get("coordination").filter(|value| truthy(value)) {
        let (instance, protocol) = coordination(coord)?;
        if !instances.contains(&(instance, protocol.clone())) {
            return Err(InvalidStructurePolicy);
        }
        let p = protocols.get(&protocol).ok_or(InvalidStructurePolicy)?;
        for schema in [
            "coordination.request",
            "coordination.ack",
            "coordination.disposition",
            "coordination.cancel",
            "coordination.remind",
        ] {
            if p.get("schemas").and_then(|v| v.get(schema)).is_none() {
                return Err(InvalidStructurePolicy);
            }
        }
        let routing = [
            (
                "coordination.request",
                &[
                    ("request_id", "opaque"),
                    ("recipients", "tokens"),
                    ("source_ref", "optional_workspace_reference"),
                    ("author", "actor"),
                ][..],
            ),
            (
                "coordination.ack",
                &[
                    ("item_id", "item_key"),
                    ("source_ref", "workspace_reference"),
                    ("source_hash", "digest"),
                    ("author", "actor"),
                ][..],
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
                ][..],
            ),
            (
                "coordination.cancel",
                &[
                    ("item_id", "item_key"),
                    ("source_ref", "workspace_reference"),
                    ("source_hash", "digest"),
                    ("author", "actor"),
                ][..],
            ),
            (
                "coordination.remind",
                &[
                    ("item_id", "item_key"),
                    ("source_ref", "workspace_reference"),
                    ("source_hash", "digest"),
                    ("author", "actor"),
                ][..],
            ),
        ];
        for (schema, fields) in routing {
            let declared = p
                .get("schemas")
                .and_then(|v| v.get(schema))
                .and_then(|v| v.get("fields"))
                .ok_or(InvalidStructurePolicy)?;
            for (name, kind) in fields {
                if schema == "coordination.disposition"
                    && *name == "result_ref"
                    && integer(field(coord, "v")?)? != 2
                {
                    continue;
                }
                let rule = declared.get(name).ok_or(InvalidStructurePolicy)?;
                if text(field(rule, "protection")?)? != "server_readable"
                    || text(field(rule, "type")?)? != *kind
                {
                    return Err(InvalidStructurePolicy);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::parse_wire_json_js_bounded;
    #[test]
    fn empty_policy_shape_and_disclosure_gate() {
        let parse = |wire: &[u8]| parse_wire_json_js_bounded(wire, 32, 16_384).unwrap();
        assert_eq!(
            validate_structure_policy(&parse(
                br#"{"v":1,"protocols":[],"disclosure":[],"instances":[]}"#
            )),
            Ok(())
        );
        assert_eq!(
            validate_structure_policy(&parse(
                br#"{"v":1,"protocols":[],"disclosure":[],"instances":[],"unknown":1}"#
            )),
            Err(InvalidStructurePolicy)
        );
    }

    #[test]
    fn pinned_typescript_structure_policy_cases() {
        let cases = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/structure-policy-vectors.json"),
            64,
            256_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("cases")
        };
        for case in cases {
            let expected = matches!(case.get("ok"), Some(WireValue::Bool(true)));
            let actual = validate_structure_policy(case.get("input").unwrap()).is_ok();
            assert_eq!(
                actual,
                expected,
                "{}",
                case.get("name").and_then(WireValue::as_string).unwrap()
            );
        }
    }
}
