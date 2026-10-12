//! Private package-compiler namespace transform, following protocol-compiler.ts.
//! Complete v2 interfaces, symbol mappings and fixture propagation are still
//! compiler prerequisites before this can participate in authority decisions.
use crate::wire_json::WireValue;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NamespaceError {
    Invalid,
    Resource,
}

fn text(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn field_mut<'a>(
    value: &'a mut WireValue,
    name: &str,
) -> Result<&'a mut WireValue, NamespaceError> {
    let WireValue::Object(fields) = value else {
        return Err(NamespaceError::Invalid);
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.iter().copied().eq(name.encode_utf16()))
        .map(|(_, value)| value)
        .ok_or(NamespaceError::Invalid)
}
fn set(value: &mut WireValue, name: &str, next: WireValue) -> Result<(), NamespaceError> {
    *field_mut(value, name)? = next;
    Ok(())
}
fn string(value: &WireValue) -> Result<String, NamespaceError> {
    value.as_string().ok_or(NamespaceError::Invalid)
}
fn qualify(namespace: &str, value: &str, max: usize) -> Result<WireValue, NamespaceError> {
    let joined = format!("{namespace}.{value}");
    if joined.encode_utf16().count() > max {
        return Err(NamespaceError::Resource);
    }
    Ok(text(&joined))
}
fn prepend(path: &WireValue, namespace: &str) -> Result<WireValue, NamespaceError> {
    let WireValue::Array(segments) = path else {
        return Err(NamespaceError::Invalid);
    };
    let mut next = Vec::with_capacity(segments.len() + 1);
    next.push(text(namespace));
    next.extend(segments.iter().cloned());
    Ok(WireValue::Array(next))
}
fn map_string_array(
    value: &mut WireValue,
    namespace: &str,
    max: usize,
) -> Result<(), NamespaceError> {
    let WireValue::Array(items) = value else {
        return Err(NamespaceError::Invalid);
    };
    for item in items {
        *item = qualify(namespace, &string(item)?, max)?;
    }
    Ok(())
}
fn map_path_array(value: &mut WireValue, namespace: &str) -> Result<(), NamespaceError> {
    let WireValue::Array(items) = value else {
        return Err(NamespaceError::Invalid);
    };
    for item in items {
        *item = prepend(item, namespace)?;
    }
    Ok(())
}
fn transform(value: &mut WireValue, namespace: &str, depth: usize) -> Result<(), NamespaceError> {
    if depth > 32 {
        return Err(NamespaceError::Resource);
    }
    match value {
        WireValue::Array(values) => {
            for child in values {
                transform(child, namespace, depth + 1)?;
            }
        }
        WireValue::Object(fields) => {
            for (_, child) in fields.iter_mut() {
                transform(child, namespace, depth + 1)?;
            }
            let from = value.get("from").and_then(WireValue::as_string);
            let op = value.get("op").and_then(WireValue::as_string);
            if from.as_deref() == Some("state") && value.get("path").is_some() {
                let path = prepend(value.get("path").ok_or(NamespaceError::Invalid)?, namespace)?;
                set(value, "path", path)?;
            }
            if from.as_deref() == Some("ref") {
                if value
                    .get("source")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some("state")
                    && value.get("path").is_some()
                {
                    let path =
                        prepend(value.get("path").ok_or(NamespaceError::Invalid)?, namespace)?;
                    set(value, "path", path)?;
                }
                if let Some(schema) = value.get("schema").and_then(WireValue::as_string) {
                    set(value, "schema", qualify(namespace, &schema, 80)?)?;
                }
            }
            if op.as_deref() == Some("exact_ref_list") {
                if value
                    .get("source")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some("state")
                    && value.get("path").is_some()
                {
                    let path =
                        prepend(value.get("path").ok_or(NamespaceError::Invalid)?, namespace)?;
                    set(value, "path", path)?;
                }
                if let Some(schema) = value.get("schema").and_then(WireValue::as_string) {
                    set(value, "schema", qualify(namespace, &schema, 80)?)?;
                }
            }
            if op.as_deref() == Some("has_protocol_role") {
                let role = string(value.get("role").ok_or(NamespaceError::Invalid)?)?;
                set(value, "role", qualify(namespace, &role, 120)?)?;
            }
            if op.as_deref() == Some("has_capability") {
                let capability = string(value.get("capability").ok_or(NamespaceError::Invalid)?)?;
                set(value, "capability", qualify(namespace, &capability, 120)?)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn namespace_manifest(
    input: &WireValue,
    namespace: &str,
) -> Result<WireValue, NamespaceError> {
    let mut value = input.clone();
    set(&mut value, "dependencies", WireValue::Array(vec![]))?;
    let state = value
        .get("initial_state")
        .ok_or(NamespaceError::Invalid)?
        .clone();
    set(
        &mut value,
        "initial_state",
        WireValue::Object(vec![(namespace.encode_utf16().collect(), state)]),
    )?;
    for key in ["state_array_types", "state_exports"] {
        if let Some(WireValue::Array(rows)) = value.get(key) {
            let mut next = rows.clone();
            for row in &mut next {
                let path = prepend(row.get("path").ok_or(NamespaceError::Invalid)?, namespace)?;
                set(row, "path", path)?;
            }
            set(&mut value, key, WireValue::Array(next))?;
        }
    }
    for (key, max) in [("protocol_roles", 120), ("capabilities", 120)] {
        map_string_array(field_mut(&mut value, key)?, namespace, max)?;
    }
    for key in ["role_conflicts", "historical_role_conflicts"] {
        let WireValue::Array(pairs) = field_mut(&mut value, key)? else {
            return Err(NamespaceError::Invalid);
        };
        for pair in pairs {
            map_string_array(pair, namespace, 120)?;
        }
    }
    if let Some(WireValue::Object(_)) = value.get("execution_requirements") {
        let requirements = field_mut(&mut value, "execution_requirements")?;
        let WireValue::Array(ports) = field_mut(requirements, "ports")? else {
            return Err(NamespaceError::Invalid);
        };
        for port in ports {
            let action = string(port.get("action_id").ok_or(NamespaceError::Invalid)?)?;
            set(port, "action_id", qualify(namespace, &action, 120)?)?;
            let WireValue::Array(path) = field_mut(port, "import_path")? else {
                return Err(NamespaceError::Invalid);
            };
            path.insert(0, text(namespace));
        }
    }
    let WireValue::Array(actions) = field_mut(&mut value, "actions")? else {
        return Err(NamespaceError::Invalid);
    };
    for action in actions {
        let id = string(action.get("id").ok_or(NamespaceError::Invalid)?)?;
        set(action, "id", qualify(namespace, &id, 120)?)?;
        for key in ["reads", "writes"] {
            map_path_array(field_mut(action, key)?, namespace)?;
        }
        if let Some(inputs) = action.get("inputs") {
            let mut inputs = inputs.clone();
            let fields = field_mut(&mut inputs, "fields")?;
            let WireValue::Object(rows) = fields else {
                return Err(NamespaceError::Invalid);
            };
            for (_, field) in rows {
                if field.get("type").and_then(WireValue::as_string).as_deref() == Some("exact_ref")
                {
                    let schema = string(field.get("schema").ok_or(NamespaceError::Invalid)?)?;
                    if schema != "*" {
                        set(field, "schema", qualify(namespace, &schema, 80)?)?;
                    }
                }
            }
            set(action, "inputs", inputs)?;
        }
        let WireValue::Array(variants) = field_mut(action, "variants")? else {
            return Err(NamespaceError::Invalid);
        };
        for variant in variants {
            transform(field_mut(variant, "when")?, namespace, 0)?;
            let WireValue::Array(effects) = field_mut(variant, "effects")? else {
                return Err(NamespaceError::Invalid);
            };
            for effect in effects {
                transform(effect, namespace, 0)?;
                match effect.get("op").and_then(WireValue::as_string).as_deref() {
                    Some("set") => {
                        let path = prepend(
                            effect.get("path").ok_or(NamespaceError::Invalid)?,
                            namespace,
                        )?;
                        set(effect, "path", path)?;
                    }
                    Some("append") => {
                        let schema = string(effect.get("schema").ok_or(NamespaceError::Invalid)?)?;
                        set(effect, "schema", qualify(namespace, &schema, 80)?)?;
                        if let Some(WireValue::Array(relations)) = effect.get("relations") {
                            let mut relations = relations.clone();
                            for relation in &mut relations {
                                let kind =
                                    string(relation.get("kind").ok_or(NamespaceError::Invalid)?)?;
                                set(relation, "kind", qualify(namespace, &kind, 80)?)?;
                            }
                            set(effect, "relations", WireValue::Array(relations))?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let schemas = value
        .get("record_schemas")
        .ok_or(NamespaceError::Invalid)?
        .clone();
    let WireValue::Object(schemas) = schemas else {
        return Err(NamespaceError::Invalid);
    };
    let mut mapped = Vec::new();
    for (name, schema) in schemas {
        let name = String::from_utf16(&name).map_err(|_| NamespaceError::Invalid)?;
        let WireValue::String(name) = qualify(namespace, &name, 80)? else {
            unreachable!()
        };
        mapped.push((name, schema));
    }
    set(&mut value, "record_schemas", WireValue::Object(mapped))?;
    if let Some(WireValue::Object(constraints)) = value.get("constraints") {
        let mut mapped = Vec::new();
        for (name, rules) in constraints {
            let name = String::from_utf16(name).map_err(|_| NamespaceError::Invalid)?;
            let WireValue::String(name) = qualify(namespace, &name, 120)? else {
                unreachable!()
            };
            let mut rules = rules.clone();
            transform(&mut rules, namespace, 0)?;
            mapped.push((name, rules));
        }
        set(&mut value, "constraints", WireValue::Object(mapped))?;
    }
    crate::full_manifest::validate_full_manifest(&value).map_err(|_| NamespaceError::Invalid)?;
    Ok(value)
}

fn replace_symbol(value: &mut WireValue, symbols: &HashMap<Vec<u16>, Vec<u16>>) {
    if let WireValue::String(name) = value {
        if let Some(mapped) = symbols.get(name) {
            *name = mapped.clone();
        }
    }
}
fn map_guard_symbols(
    value: &mut WireValue,
    roles: &HashMap<Vec<u16>, Vec<u16>>,
    capabilities: &HashMap<Vec<u16>, Vec<u16>>,
) {
    match value {
        WireValue::Array(rows) => {
            for row in rows {
                map_guard_symbols(row, roles, capabilities);
            }
        }
        WireValue::Object(fields) => {
            let op = fields
                .iter()
                .find(|(key, _)| key.iter().copied().eq("op".encode_utf16()))
                .and_then(|(_, value)| value.as_string());
            for (key, child) in fields {
                if op.as_deref() == Some("has_protocol_role")
                    && key.iter().copied().eq("role".encode_utf16())
                {
                    replace_symbol(child, roles);
                } else if op.as_deref() == Some("has_capability")
                    && key.iter().copied().eq("capability".encode_utf16())
                {
                    replace_symbol(child, capabilities);
                } else {
                    map_guard_symbols(child, roles, capabilities);
                }
            }
        }
        _ => {}
    }
}
/// Apply v2 parent symbol mappings to an already namespaced dependency.
pub(crate) fn map_namespaced_symbols(
    mut value: WireValue,
    roles: &HashMap<Vec<u16>, Vec<u16>>,
    capabilities: &HashMap<Vec<u16>, Vec<u16>>,
) -> Result<WireValue, NamespaceError> {
    for (key, mappings) in [("protocol_roles", roles), ("capabilities", capabilities)] {
        let WireValue::Array(items) = field_mut(&mut value, key)? else {
            return Err(NamespaceError::Invalid);
        };
        for item in items {
            replace_symbol(item, mappings);
        }
    }
    for key in ["role_conflicts", "historical_role_conflicts"] {
        let WireValue::Array(pairs) = field_mut(&mut value, key)? else {
            return Err(NamespaceError::Invalid);
        };
        for pair in pairs {
            let WireValue::Array(items) = pair else {
                return Err(NamespaceError::Invalid);
            };
            for role in items.iter_mut() {
                replace_symbol(role, roles);
            }
            if items.len() == 2 && items[0] == items[1] {
                return Err(NamespaceError::Invalid);
            }
        }
    }
    if let Some(constraints) = value.get("constraints") {
        let mut constraints = constraints.clone();
        map_guard_symbols(&mut constraints, roles, capabilities);
        set(&mut value, "constraints", constraints)?;
    }
    let WireValue::Array(actions) = field_mut(&mut value, "actions")? else {
        return Err(NamespaceError::Invalid);
    };
    for action in actions {
        let WireValue::Array(variants) = field_mut(action, "variants")? else {
            return Err(NamespaceError::Invalid);
        };
        for variant in variants {
            map_guard_symbols(field_mut(variant, "when")?, roles, capabilities);
            map_guard_symbols(field_mut(variant, "effects")?, roles, capabilities);
        }
    }
    crate::full_manifest::validate_full_manifest(&value).map_err(|_| NamespaceError::Invalid)?;
    Ok(value)
}
