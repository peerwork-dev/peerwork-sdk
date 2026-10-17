//! Private full-protocol manifest gate. It is not an authority boundary until
//! execution requirements and replay integration
//! pass their source differentials.

use crate::{
    canonical::Path,
    interpreter::{validate_guard, validate_manifest},
    wire_json::{canonical_wire_value, WireValue},
};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ManifestError {
    Invalid,
    Resource,
    Unsupported,
}

pub(crate) fn validate_full_manifest(value: &WireValue) -> Result<String, ManifestError> {
    shape(
        value,
        &[
            "name",
            "display_version",
            "semantics",
            "dependencies",
            "record_schemas",
            "initial_state",
            "actions",
        ],
        &[
            "format_version",
            "protocol_roles",
            "capabilities",
            "role_conflicts",
            "historical_role_conflicts",
            "constraints",
            "state_array_types",
            "state_exports",
            "execution_requirements",
        ],
    )?;
    string_len(field(value, "name")?, 1, 120)?;
    string_len(field(value, "display_version")?, 1, 40)?;
    if field(value, "semantics")?.as_string().as_deref() != Some("peerwork.kernel.v1") {
        return Err(ManifestError::Invalid);
    }
    let format = value.get("format_version").map(integer).transpose()?;
    if format.is_some_and(|format| format != 2) {
        return Err(ManifestError::Invalid);
    }
    let deps = list(field(value, "dependencies")?, 16)?;
    let mut dep_set = HashSet::new();
    for dependency in deps {
        let value = dependency.as_utf16().ok_or(ManifestError::Invalid)?;
        if !hex_digest(value) || !dep_set.insert(value.to_vec()) {
            return Err(ManifestError::Invalid);
        }
    }
    let roles = bindings(value.get("protocol_roles"), 32)?;
    let capabilities = bindings(value.get("capabilities"), 64)?;
    validate_conflicts(value.get("role_conflicts"), &roles)?;
    validate_conflicts(value.get("historical_role_conflicts"), &roles)?;
    let initial = field(value, "initial_state")?;
    canonical_wire_value(initial, Path::KERNEL).map_err(|_| ManifestError::Invalid)?;
    let schemas = field(value, "record_schemas")?;
    validate_schemas(schemas)?;
    let actions = field(value, "actions")?.clone();
    validate_manifest(&object(vec![("actions", actions.clone())]))
        .map_err(|_| ManifestError::Invalid)?;
    let constraints = value
        .get("constraints")
        .cloned()
        .unwrap_or_else(|| object(vec![]));
    validate_constraints(&constraints)?;
    if let WireValue::Array(actions) = &actions {
        for action in actions {
            if let Some(WireValue::Array(variants)) = action.get("variants") {
                for variant in variants {
                    if let Some(WireValue::Array(effects)) = variant.get("effects") {
                        for effect in effects {
                            if effect.get("op").and_then(WireValue::as_string).as_deref()
                                == Some("withdraw")
                                && !capabilities
                                    .iter()
                                    .any(|value| value == &"publication.withdraw".encode_utf16().collect::<Vec<_>>())
                            {
                                return Err(ManifestError::Invalid);
                            }
                            if effect.get("op").and_then(WireValue::as_string).as_deref()
                                == Some("append")
                            {
                                let schema = effect
                                    .get("schema")
                                    .and_then(WireValue::as_string)
                                    .ok_or(ManifestError::Invalid)?;
                                if schemas.get(&schema).is_none() {
                                    return Err(ManifestError::Invalid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let arrays = value.get("state_array_types");
    if format.is_some() != arrays.is_some() {
        return Err(ManifestError::Invalid);
    }
    if let Some(arrays) = arrays {
        validate_state_array_types(arrays, initial, &actions, &constraints)?;
    }
    if let Some(exports) = value.get("state_exports") {
        validate_exports(exports, initial)?;
    }
    if let Some(requirements) = value.get("execution_requirements") {
        validate_requirements(requirements)?;
    }

    let mut normalized = value.clone();
    for (name, default) in [
        ("protocol_roles", WireValue::Array(vec![])),
        ("capabilities", WireValue::Array(vec![])),
        ("role_conflicts", WireValue::Array(vec![])),
        ("historical_role_conflicts", WireValue::Array(vec![])),
        ("constraints", object(vec![])),
    ] {
        if normalized.get(name).is_none() {
            put(&mut normalized, name, default)?;
        }
    }
    let wrapped = object(vec![
        ("semantics", string("peerwork.kernel.v1")),
        ("manifest", normalized),
    ]);
    let encoded =
        canonical_wire_value(&wrapped, Path::STRUCTURED).map_err(|_| ManifestError::Invalid)?;
    if encoded.len() > 65_536 {
        return Err(ManifestError::Resource);
    }
    let _ = capabilities;
    Ok(encoded)
}

fn validate_schemas(value: &WireValue) -> Result<(), ManifestError> {
    let WireValue::Object(schemas) = value else {
        return Err(ManifestError::Invalid);
    };
    for (name, schema) in schemas {
        if name.is_empty() || name.len() > 80 {
            return Err(ManifestError::Invalid);
        }
        shape(
            schema,
            &["type", "fields", "required", "max_bytes"],
            &["protection", "workflow"],
        )?;
        if field(schema, "type")?.as_string().as_deref() != Some("object") {
            return Err(ManifestError::Invalid);
        }
        let WireValue::Object(fields) = field(schema, "fields")? else {
            return Err(ManifestError::Invalid);
        };
        for (name, kind) in fields {
            if name.is_empty()
                || name.len() > 80
                || !matches!(
                    kind.as_string().as_deref(),
                    Some("string" | "integer" | "boolean" | "null" | "json" | "source_text" | "source_timestamp" | "source_sha256")
                )
            {
                return Err(ManifestError::Invalid);
            }
        }
        let required = list(field(schema, "required")?, 64)?;
        for required_name in required {
            let required_name = required_name.as_utf16().ok_or(ManifestError::Invalid)?;
            if required_name.is_empty()
                || required_name.len() > 80
                || !fields.iter().any(|(name, _)| name == required_name)
            {
                return Err(ManifestError::Invalid);
            }
        }
        let max = integer(field(schema, "max_bytes")?)?;
        if max == 0 || max > 16_384 {
            return Err(ManifestError::Invalid);
        }
        let protection = schema
            .get("protection")
            .map(|value| validate_protection(value, fields))
            .transpose()?;
        if let Some(workflow) = schema.get("workflow") {
            validate_workflow(workflow, protection.as_ref(), required)?;
        }
    }
    Ok(())
}

fn validate_protection<'a>(
    value: &'a WireValue,
    fields: &[(Vec<u16>, WireValue)],
) -> Result<&'a WireValue, ManifestError> {
    shape(value, &["v", "fields"], &[])?;
    if integer(field(value, "v")?)? != 1 {
        return Err(ManifestError::Invalid);
    }
    let protected = field(value, "fields")?;
    let WireValue::Object(entries) = protected else {
        return Err(ManifestError::Invalid);
    };
    if entries.len() != fields.len() {
        return Err(ManifestError::Invalid);
    }
    for (name, rule) in entries {
        if name.is_empty() || name.len() > 80 {
            return Err(ManifestError::Invalid);
        }
        let stored = fields
            .iter()
            .find(|(key, _)| key == name)
            .ok_or(ManifestError::Invalid)?
            .1
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        shape(rule, &["protection", "type"], &["values"])?;
        let mode = field(rule, "protection")?
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        let kind = field(rule, "type")?
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        let compatible = match mode.as_str() {
            "e2ee" => {
                if rule.get("values").is_some()
                    || !matches!(
                        kind.as_str(),
                        "string" | "integer" | "boolean" | "null" | "json" | "source_text" | "source_timestamp" | "source_sha256"
                    )
                {
                    return Err(ManifestError::Invalid);
                }
                stored == kind
            }
            "server_readable" => {
                match kind.as_str() {
                    "enum" => {
                        let values = list(field(rule, "values")?, 32)?;
                        if values.is_empty() {
                            return Err(ManifestError::Invalid);
                        }
                        let mut seen = HashSet::new();
                        for value in values {
                            let value = value.as_utf16().ok_or(ManifestError::Invalid)?;
                            if !state_name(value) || !seen.insert(value.to_vec()) {
                                return Err(ManifestError::Invalid);
                            }
                        }
                    }
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
                    | "optional_workspace_reference" => {
                        if rule.get("values").is_some() {
                            return Err(ManifestError::Invalid);
                        }
                    }
                    _ => return Err(ManifestError::Invalid),
                }
                stored == "json"
                    || matches!(
                        kind.as_str(),
                        "actor"
                            | "opaque"
                            | "item_key"
                            | "digest"
                            | "task_status"
                            | "work_status"
                            | "enum"
                    ) && stored == "string"
                    || kind == "optional_actor" && matches!(stored.as_str(), "string" | "null")
                    || kind == "timestamp" && matches!(stored.as_str(), "integer" | "null")
                    || kind == "counter" && stored == "integer"
            }
            _ => return Err(ManifestError::Invalid),
        };
        if !compatible {
            return Err(ManifestError::Invalid);
        }
    }
    Ok(protected)
}

fn validate_workflow(
    value: &WireValue,
    protection: Option<&&WireValue>,
    required: &[WireValue],
) -> Result<(), ManifestError> {
    shape(
        value,
        &["v", "status_field", "parent_field", "states", "transitions"],
        &["assignee_field", "dependencies", "deadline"],
    )?;
    if integer(field(value, "v")?)? != 1 {
        return Err(ManifestError::Invalid);
    }
    let mut fields = Vec::new();
    for name in ["status_field", "parent_field"] {
        let field_name = field(value, name)?
            .as_utf16()
            .ok_or(ManifestError::Invalid)?;
        if !binding(field_name) {
            return Err(ManifestError::Invalid);
        }
        fields.push(field_name.to_vec());
    }
    let assignee = value
        .get("assignee_field")
        .map(|v| v.as_utf16().ok_or(ManifestError::Invalid))
        .transpose()?;
    if let Some(name) = assignee {
        if !binding(name) {
            return Err(ManifestError::Invalid);
        }
        fields.push(name.to_vec());
    }
    let states = list(field(value, "states")?, 32)?;
    if states.is_empty() {
        return Err(ManifestError::Invalid);
    }
    let mut state_set = HashSet::new();
    for state in states {
        let state = state.as_utf16().ok_or(ManifestError::Invalid)?;
        if !state_name(state) || !state_set.insert(state.to_vec()) {
            return Err(ManifestError::Invalid);
        }
    }
    let transitions = list(field(value, "transitions")?, 64)?;
    if transitions.is_empty() {
        return Err(ManifestError::Invalid);
    }
    let mut seen = HashSet::new();
    for transition in transitions {
        shape(transition, &["action", "from", "to"], &[])?;
        let action = field(transition, "action")?
            .as_utf16()
            .ok_or(ManifestError::Invalid)?;
        if !binding(action) {
            return Err(ManifestError::Invalid);
        }
        let from = field(transition, "from")?;
        let from = if matches!(from, WireValue::Null) {
            None
        } else {
            Some(from.as_utf16().ok_or(ManifestError::Invalid)?)
        };
        if let Some(from) = from {
            if !state_name(from) || !state_set.contains(from) {
                return Err(ManifestError::Invalid);
            }
        }
        let to = field(transition, "to")?
            .as_utf16()
            .ok_or(ManifestError::Invalid)?;
        if !state_name(to) || !state_set.contains(to) {
            return Err(ManifestError::Invalid);
        }
        // Zod parses strict transition objects into schema field order before its
        // JSON.stringify duplicate check.
        if !seen.insert((action.to_vec(), from.map(|v| v.to_vec()), to.to_vec())) {
            return Err(ManifestError::Invalid);
        }
    }
    let dependencies = value.get("dependencies");
    if let Some(deps) = dependencies {
        shape(deps, &["field", "satisfied_states", "gated_states"], &[])?;
        let name = field(deps, "field")?
            .as_utf16()
            .ok_or(ManifestError::Invalid)?;
        if !binding(name) {
            return Err(ManifestError::Invalid);
        }
        fields.push(name.to_vec());
        for key in ["satisfied_states", "gated_states"] {
            let list = list(field(deps, key)?, 32)?;
            if list.is_empty() {
                return Err(ManifestError::Invalid);
            }
            let mut set = HashSet::new();
            for item in list {
                let item = item.as_utf16().ok_or(ManifestError::Invalid)?;
                if !state_name(item) || !state_set.contains(item) || !set.insert(item.to_vec()) {
                    return Err(ManifestError::Invalid);
                }
            }
        }
    }
    let deadline = value.get("deadline");
    if let Some(deadline) = deadline {
        shape(deadline, &["field"], &["reminder"])?;
        let name = field(deadline, "field")?
            .as_utf16()
            .ok_or(ManifestError::Invalid)?;
        if !binding(name) {
            return Err(ManifestError::Invalid);
        }
        fields.push(name.to_vec());
        if let Some(reminder) = deadline.get("reminder") {
            shape(reminder, &["lead_ms", "active_states"], &[])?;
            if assignee.is_none() || integer(field(reminder, "lead_ms")?)? > 30 * 86_400_000 {
                return Err(ManifestError::Invalid);
            }
            let active = list(field(reminder, "active_states")?, 32)?;
            if active.is_empty() {
                return Err(ManifestError::Invalid);
            }
            let mut set = HashSet::new();
            for item in active {
                let item = item.as_utf16().ok_or(ManifestError::Invalid)?;
                if !state_name(item) || !state_set.contains(item) || !set.insert(item.to_vec()) {
                    return Err(ManifestError::Invalid);
                }
            }
        }
    }
    let mut distinct = HashSet::new();
    if fields.iter().any(|field| !distinct.insert(field)) {
        return Err(ManifestError::Invalid);
    }
    let Some(protection) = protection else {
        return Err(ManifestError::Invalid);
    };
    let mut readable = 0;
    for (index, name) in fields.iter().enumerate() {
        let rule = protection
            .get(&String::from_utf16(name).map_err(|_| ManifestError::Invalid)?)
            .ok_or(ManifestError::Invalid)?;
        if !required.iter().any(|entry| entry.as_utf16() == Some(name)) {
            return Err(ManifestError::Invalid);
        }
        let mode = field(rule, "protection")?
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        let kind = field(rule, "type")?
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        let valid = match index {
            0 => {
                if mode == "e2ee" {
                    kind == "string"
                } else {
                    kind == "enum"
                }
            }
            1 => {
                if mode == "e2ee" {
                    kind == "json"
                } else {
                    kind == "optional_reference"
                }
            }
            _ => {
                let assignee_name = assignee.map(|v| v == name).unwrap_or(false);
                let dependency_name = dependencies
                    .and_then(|v| v.get("field"))
                    .and_then(WireValue::as_utf16)
                    .is_some_and(|v| v == name);
                if assignee_name {
                    if mode == "e2ee" {
                        matches!(kind.as_str(), "json" | "string" | "null")
                    } else {
                        kind == "optional_actor"
                    }
                } else if dependency_name {
                    if mode == "e2ee" {
                        kind == "json"
                    } else {
                        kind == "references"
                    }
                } else {
                    if mode == "e2ee" {
                        matches!(kind.as_str(), "json" | "integer" | "null")
                    } else {
                        kind == "timestamp"
                    }
                }
            }
        };
        if !valid {
            return Err(ManifestError::Invalid);
        }
        if mode == "server_readable"
            && (index < 2
                || dependencies
                    .and_then(|v| v.get("field"))
                    .and_then(WireValue::as_utf16)
                    .is_some_and(|v| v == name))
        {
            readable += 1
        }
    }
    let critical = 2 + usize::from(dependencies.is_some());
    if readable != 0 && readable != critical {
        return Err(ManifestError::Invalid);
    }
    if field(
        protection,
        &String::from_utf16(&fields[0]).map_err(|_| ManifestError::Invalid)?,
    )?
    .get("type")
    .and_then(WireValue::as_string)
    .as_deref()
        == Some("enum")
    {
        let rules = field(
            protection,
            &String::from_utf16(&fields[0]).map_err(|_| ManifestError::Invalid)?,
        )?;
        if rules.get("values") != Some(field(value, "states")?) {
            return Err(ManifestError::Invalid);
        }
    }
    Ok(())
}

pub(crate) fn validate_structure_workflow(
    value: &WireValue,
    fields: &WireValue,
    required: &[WireValue],
) -> Result<(), ManifestError> {
    validate_workflow(value, Some(&fields), required)
}

fn state_name(value: &[u16]) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && matches!(value[0], 65..=90)
        && value[1..].iter().all(|ch| matches!(*ch,65..=90|48..=57|95))
}

fn validate_requirements(value: &WireValue) -> Result<(), ManifestError> {
    shape(value, &["format", "closure_complete", "ports"], &[])?;
    if field(value, "format")?.as_string().as_deref()
        != Some("peerwork.protocol-execution-requirements.v1")
    {
        return Err(ManifestError::Invalid);
    }
    boolean(field(value, "closure_complete")?)?;
    for port in list(field(value, "ports")?, 512)? {
        shape(
            port,
            &[
                "import_path",
                "action_id",
                "variant",
                "input_name",
                "type",
                "required",
                "bound",
            ],
            &[],
        )?;
        for part in list(field(port, "import_path")?, 16)? {
            let name = part.as_utf16().ok_or(ManifestError::Invalid)?;
            if !binding(name) {
                return Err(ManifestError::Invalid);
            }
        }
        string_len(field(port, "action_id")?, 1, 120)?;
        if integer(field(port, "variant")?)? > 31 {
            return Err(ManifestError::Invalid);
        }
        if !binding(
            field(port, "input_name")?
                .as_utf16()
                .ok_or(ManifestError::Invalid)?,
        ) {
            return Err(ManifestError::Invalid);
        }
        if !matches!(
            field(port, "type")?.as_string().as_deref(),
            Some("exact_ref" | "actor_id")
        ) {
            return Err(ManifestError::Invalid);
        }
        boolean(field(port, "required")?)?;
        boolean(field(port, "bound")?)?;
    }
    Ok(())
}

fn validate_constraints(value: &WireValue) -> Result<(), ManifestError> {
    let WireValue::Object(constraints) = value else {
        return Err(ManifestError::Invalid);
    };
    for (name, rules) in constraints {
        if name.is_empty() || name.len() > 120 {
            return Err(ManifestError::Invalid);
        }
        let rules = list(rules, 32)?;
        if rules.is_empty() {
            return Err(ManifestError::Invalid);
        }
        for rule in rules {
            validate_guard(rule, 0, &[]).map_err(|_| ManifestError::Invalid)?;
        }
    }
    Ok(())
}

fn validate_state_array_types(
    value: &WireValue,
    initial: &WireValue,
    actions: &WireValue,
    constraints: &WireValue,
) -> Result<(), ManifestError> {
    let arrays = list(value, 64)?;
    if arrays.is_empty() {
        return Err(ManifestError::Invalid);
    }
    if !matches!(initial, WireValue::Object(_)) {
        return Err(ManifestError::Invalid);
    }
    let mut previous: Vec<u16> = Vec::new();
    let mut json_paths = HashSet::new();
    for entry in arrays {
        shape(entry, &["path", "kind"], &[])?;
        let path = segments(field(entry, "path")?, 1, 12)?;
        let encoded = canonical_wire_value(field(entry, "path")?, Path::KERNEL)
            .map_err(|_| ManifestError::Invalid)?;
        let js_order: Vec<u16> = encoded.encode_utf16().collect();
        if !previous.is_empty() && js_order <= previous {
            return Err(ManifestError::Invalid);
        }
        previous = js_order;
        let kind = field(entry, "kind")?
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        if !matches!(kind.as_str(), "json" | "exact_ref_list") {
            return Err(ManifestError::Invalid);
        }
        if kind == "json" {
            json_paths.insert(encoded);
        }
        let target = at(initial, &path).ok_or(ManifestError::Invalid)?;
        let WireValue::Array(items) = target else {
            return Err(ManifestError::Invalid);
        };
        if kind == "exact_ref_list" && items.iter().any(|item| !exact_ref(item)) {
            return Err(ManifestError::Invalid);
        }
        if kind == "json" && items.iter().any(nested_ref_or_produced) {
            return Err(ManifestError::Invalid);
        }
    }
    if let WireValue::Array(actions) = actions {
        for action in actions {
            if let Some(WireValue::Array(variants)) = action.get("variants") {
                for variant in variants {
                    if let Some(WireValue::Array(guards)) = variant.get("when") {
                        for guard in guards {
                            guard_array_kind(guard, &json_paths)?;
                        }
                    }
                }
            }
        }
    }
    if let WireValue::Object(entries) = constraints {
        for (_, rules) in entries {
            if let WireValue::Array(rules) = rules {
                for rule in rules {
                    guard_array_kind(rule, &json_paths)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_state_array_state(
    manifest: &WireValue,
    state: &WireValue,
) -> Result<(), ManifestError> {
    let Some(declarations) = manifest.get("state_array_types") else {
        return Ok(());
    };
    canonical_wire_value(state, Path::KERNEL).map_err(|_| ManifestError::Invalid)?;
    if !matches!(state, WireValue::Object(_)) {
        return Err(ManifestError::Invalid);
    }
    for entry in list(declarations, 64)? {
        let path = segments(field(entry, "path")?, 1, 12)?;
        let kind = field(entry, "kind")?
            .as_string()
            .ok_or(ManifestError::Invalid)?;
        let Some(WireValue::Array(items)) = at(state, &path) else {
            return Err(ManifestError::Invalid);
        };
        if kind == "exact_ref_list" && items.iter().any(|item| !exact_ref(item))
            || kind == "json" && nested_ref_or_produced(&WireValue::Array(items.to_vec()))
            || !matches!(kind.as_str(), "exact_ref_list" | "json")
        {
            return Err(ManifestError::Invalid);
        }
    }
    Ok(())
}

fn guard_array_kind(guard: &WireValue, json_paths: &HashSet<String>) -> Result<(), ManifestError> {
    match guard.get("op").and_then(WireValue::as_string).as_deref() {
        Some("exact_ref_list")
            if guard
                .get("source")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("state") =>
        {
            let encoded = canonical_wire_value(field(guard, "path")?, Path::KERNEL)
                .map_err(|_| ManifestError::Invalid)?;
            if json_paths.contains(&encoded) {
                return Err(ManifestError::Invalid);
            }
        }
        Some("and" | "or") => {
            if let WireValue::Array(rules) = field(guard, "rules")? {
                for rule in rules {
                    guard_array_kind(rule, json_paths)?;
                }
            }
        }
        Some("not") => guard_array_kind(field(guard, "rule")?, json_paths)?,
        _ => {}
    }
    Ok(())
}

fn validate_exports(value: &WireValue, initial: &WireValue) -> Result<(), ManifestError> {
    let exports = list(value, 64)?;
    let mut seen = HashSet::new();
    for entry in exports {
        shape(entry, &["path", "read", "write"], &[])?;
        let path = segments(field(entry, "path")?, 1, 12)?;
        let read = boolean(field(entry, "read")?)?;
        let write = boolean(field(entry, "write")?)?;
        if !read && !write || at(initial, &path).is_none() {
            return Err(ManifestError::Invalid);
        }
        if !seen.insert(path) {
            return Err(ManifestError::Invalid);
        }
    }
    Ok(())
}

fn nested_ref_or_produced(value: &WireValue) -> bool {
    if exact_ref(value) {
        return true;
    }
    match value {
        WireValue::Array(items) => items.iter().any(nested_ref_or_produced),
        WireValue::Object(fields) => fields.iter().any(|(key, value)| {
            key.iter().copied().eq("$produced".encode_utf16()) || nested_ref_or_produced(value)
        }),
        _ => false,
    }
}
fn exact_ref(value: &WireValue) -> bool {
    let WireValue::Object(fields) = value else {
        return false;
    };
    fields.len() == 2
        && value
            .get("record_id")
            .and_then(WireValue::as_utf16)
            .is_some_and(token)
        && value
            .get("revision")
            .and_then(WireValue::as_number)
            .is_some_and(|n| {
                n.is_finite() && n > 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_991.0
            })
}
fn at<'a>(value: &'a WireValue, path: &[Vec<u16>]) -> Option<&'a WireValue> {
    let mut current = value;
    for segment in path {
        let WireValue::Object(fields) = current else {
            return None;
        };
        current = fields
            .iter()
            .find(|(name, _)| name == segment)
            .map(|(_, value)| value)?;
    }
    Some(current)
}
fn segments(value: &WireValue, min: usize, max: usize) -> Result<Vec<Vec<u16>>, ManifestError> {
    let values = list(value, max)?;
    if values.len() < min {
        return Err(ManifestError::Invalid);
    }
    let mut out = Vec::new();
    for value in values {
        let text = value.as_utf16().ok_or(ManifestError::Invalid)?;
        if text.is_empty()
            || text.len() > 80
            || ["__proto__", "prototype", "constructor"]
                .iter()
                .any(|bad| text.iter().copied().eq(bad.encode_utf16()))
        {
            return Err(ManifestError::Invalid);
        }
        out.push(text.to_vec());
    }
    Ok(out)
}
fn bindings(value: Option<&WireValue>, max: usize) -> Result<Vec<Vec<u16>>, ManifestError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = list(value, max)?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        let text = item.as_utf16().ok_or(ManifestError::Invalid)?;
        if !binding(text) || !seen.insert(text.to_vec()) {
            return Err(ManifestError::Invalid);
        }
        out.push(text.to_vec());
    }
    Ok(out)
}
fn validate_conflicts(value: Option<&WireValue>, roles: &[Vec<u16>]) -> Result<(), ManifestError> {
    let Some(value) = value else { return Ok(()) };
    let pairs = list(value, 32)?;
    let mut seen = HashSet::new();
    for pair in pairs {
        let pair = list(pair, 2)?;
        if pair.len() != 2 {
            return Err(ManifestError::Invalid);
        }
        let a = pair[0].as_utf16().ok_or(ManifestError::Invalid)?;
        let b = pair[1].as_utf16().ok_or(ManifestError::Invalid)?;
        if !binding(a)
            || !binding(b)
            || a == b
            || !roles.iter().any(|role| role == a)
            || !roles.iter().any(|role| role == b)
        {
            return Err(ManifestError::Invalid);
        }
        let mut key = [a.to_vec(), b.to_vec()];
        key.sort();
        if !seen.insert(key) {
            return Err(ManifestError::Invalid);
        }
    }
    Ok(())
}
fn binding(value: &[u16]) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value[0] <= 127
        && (value[0] as u8).is_ascii_alphabetic()
        && value[1..].iter().all(|ch| {
            *ch <= 127 && ((*ch as u8).is_ascii_alphanumeric() || matches!(*ch, 46 | 95 | 45))
        })
}
fn hex_digest(value: &[u16]) -> bool {
    value.len() == 64 && value.iter().all(|ch| matches!(*ch,48..=57|97..=102))
}
fn token(value: &[u16]) -> bool {
    value.len() == 43
        && value
            .iter()
            .all(|ch| matches!(*ch,65..=90|97..=122|48..=57|95|45))
}
fn string_len(value: &WireValue, min: usize, max: usize) -> Result<(), ManifestError> {
    let value = value.as_utf16().ok_or(ManifestError::Invalid)?;
    if value.len() < min || value.len() > max {
        Err(ManifestError::Invalid)
    } else {
        Ok(())
    }
}
fn integer(value: &WireValue) -> Result<u64, ManifestError> {
    let number = value.as_number().ok_or(ManifestError::Invalid)?;
    if !number.is_finite()
        || number < 0.0
        || number.fract() != 0.0
        || number > 9_007_199_254_740_991.0
    {
        Err(ManifestError::Invalid)
    } else {
        Ok(number as u64)
    }
}
fn boolean(value: &WireValue) -> Result<bool, ManifestError> {
    if let WireValue::Bool(value) = value {
        Ok(*value)
    } else {
        Err(ManifestError::Invalid)
    }
}
fn list(value: &WireValue, max: usize) -> Result<&[WireValue], ManifestError> {
    if let WireValue::Array(values) = value {
        if values.len() <= max {
            Ok(values)
        } else {
            Err(ManifestError::Invalid)
        }
    } else {
        Err(ManifestError::Invalid)
    }
}
fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue, ManifestError> {
    value.get(name).ok_or(ManifestError::Invalid)
}
fn shape(value: &WireValue, required: &[&str], optional: &[&str]) -> Result<(), ManifestError> {
    let WireValue::Object(fields) = value else {
        return Err(ManifestError::Invalid);
    };
    if required.iter().any(|name| value.get(name).is_none())
        || fields.iter().any(|(key, _)| {
            !required
                .iter()
                .chain(optional)
                .any(|name| key.iter().copied().eq(name.encode_utf16()))
        })
    {
        Err(ManifestError::Invalid)
    } else {
        Ok(())
    }
}
fn string(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.encode_utf16().collect(), value))
            .collect(),
    )
}
fn put(value: &mut WireValue, name: &str, item: WireValue) -> Result<(), ManifestError> {
    let WireValue::Object(fields) = value else {
        return Err(ManifestError::Invalid);
    };
    fields.push((name.encode_utf16().collect(), item));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::parse_wire_json_js_bounded;
    #[test]
    fn pinned_typescript_manifest_cases() {
        let fixture = parse_wire_json_js_bounded(
            include_str!("../../../conformance/manifest-vectors.json").as_bytes(),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = fixture else {
            panic!("array")
        };
        for case in cases {
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let result = validate_full_manifest(case.get("manifest").unwrap());
            if case.get("error").is_some() {
                assert_eq!(result, Err(ManifestError::Invalid), "{name}");
            } else {
                assert_eq!(
                    result,
                    Ok(case.get("result").and_then(WireValue::as_string).unwrap()),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn provenance_scalar_fields_and_withdraw_capability_are_strictly_gated() {
        let base = br#"{"name":"peerwork.wiki.provenance.v1","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{"wiki.document.v2":{"type":"object","fields":{"source_text":"source_text","source_timestamp":"source_timestamp","source_sha256":"source_sha256"},"required":[],"max_bytes":16384}},"initial_state":{},"actions":[{"id":"wiki.withdraw","reads":[],"writes":[],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"withdraw","target":{"from":"ref","source":"body","path":["target"],"scope":"INSTANCE","schema":"wiki.document.v2"},"expected_max":{"from":"body","path":["expected_max"]},"expected_head":{"from":"body","path":["expected_head"]}}]}]}]}"#;
        let without_capability = parse_wire_json_js_bounded(base, 64, 32_768).unwrap();
        assert_eq!(validate_full_manifest(&without_capability), Err(ManifestError::Invalid));

        let with_capability = parse_wire_json_js_bounded(
            br#"{"name":"peerwork.wiki.provenance.v1","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"capabilities":["publication.withdraw"],"record_schemas":{"wiki.document.v2":{"type":"object","fields":{"source_text":"source_text","source_timestamp":"source_timestamp","source_sha256":"source_sha256"},"required":[],"max_bytes":16384,"protection":{"v":1,"fields":{"source_text":{"protection":"e2ee","type":"source_text"},"source_timestamp":{"protection":"e2ee","type":"source_timestamp"},"source_sha256":{"protection":"e2ee","type":"source_sha256"}}}}},"initial_state":{},"actions":[{"id":"wiki.withdraw","reads":[],"writes":[],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"withdraw","target":{"from":"ref","source":"body","path":["target"],"scope":"INSTANCE","schema":"wiki.document.v2"},"expected_max":{"from":"body","path":["expected_max"]},"expected_head":{"from":"body","path":["expected_head"]}}]}]}]}"#,
            64,
            32_768,
        ).unwrap();
        assert!(validate_full_manifest(&with_capability).is_ok());
    }

    #[test]
    fn typescript_provenance_preset_validates_and_evaluates_import_create() {
        use crate::interpreter::{evaluate_action, InterpreterAuth};
        let fixture = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/provenance-wiki-v2-ts.json"),
            64,
            65_536,
        )
        .unwrap();
        let manifest = field(&fixture, "manifest").unwrap();
        assert!(validate_full_manifest(manifest).is_ok());

        let actor = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let auth = InterpreterAuth {
            actor_id: actor.into(),
            workspace_roles: vec![],
            protocol_roles: vec!["EDITOR".encode_utf16().collect()],
            capabilities: vec!["IMPORT".encode_utf16().collect()],
        };
        let body = parse_wire_json_js_bounded(
            br#"{"title":"Imported source","body":"Source body","source_ref":"archive:manual/42","source_author":"Source author","source_created_at":"1998-06-01T00:00:00Z","source_updated_at":null,"source_revision_at":"1998-06-07T08:09:10.123456789-04:30","source_revision_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#,
            64,
            32_768,
        )
        .unwrap();
        let result = evaluate_action(
            &WireValue::Object(vec![(
                "actions".encode_utf16().collect(),
                field(manifest, "actions").unwrap().clone(),
            )]),
            &"wiki.import_create".encode_utf16().collect::<Vec<_>>(),
            &WireValue::Object(vec![]),
            &body,
            &auth,
            &[],
            None,
        )
        .unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(
            result.records[0].get("schema").and_then(WireValue::as_string).as_deref(),
            Some("wiki.document.v2")
        );
        let payload = result.records[0].get("payload").unwrap();
        assert_eq!(payload.get("source_ref").and_then(WireValue::as_string).as_deref(), Some("archive:manual/42"));
        assert_eq!(payload.get("source_updated_at"), Some(&WireValue::Null));
        assert_eq!(payload.get("source_revision_at").and_then(WireValue::as_string).as_deref(), Some("1998-06-07T08:09:10.123456789-04:30"));
        assert_eq!(payload.get("source_revision_sha256").and_then(WireValue::as_string).as_deref(), Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
        assert_eq!(payload.get("author").and_then(WireValue::as_string).as_deref(), Some(actor));
    }
}
