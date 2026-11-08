//! Lossless private protocol-composition candidate. Not an authority proof.
use crate::{
    canonical::Path,
    crypto::sha256_hex,
    full_manifest::validate_full_manifest,
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompositionError {
    Invalid,
    Missing,
    Cycle,
    Conflict,
    Resource,
}

fn string(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}
fn array(value: &WireValue) -> Result<&[WireValue], CompositionError> {
    if let WireValue::Array(items) = value {
        Ok(items)
    } else {
        Err(CompositionError::Invalid)
    }
}
fn fields(value: &WireValue) -> Result<&[(Vec<u16>, WireValue)], CompositionError> {
    if let WireValue::Object(items) = value {
        Ok(items)
    } else {
        Err(CompositionError::Invalid)
    }
}
fn field<'a>(value: &'a WireValue, key: &str) -> Result<&'a WireValue, CompositionError> {
    value.get(key).ok_or(CompositionError::Invalid)
}
fn utf16(value: &WireValue) -> Result<Vec<u16>, CompositionError> {
    value
        .as_utf16()
        .map(<[u16]>::to_vec)
        .ok_or(CompositionError::Invalid)
}
fn canonical(value: &WireValue) -> Result<String, CompositionError> {
    canonical_wire_value(value, Path::SecureArtifact).map_err(|_| CompositionError::Invalid)
}
fn same(a: &WireValue, b: &WireValue) -> Result<bool, CompositionError> {
    Ok(canonical(a)? == canonical(b)?)
}
fn normalized(value: &WireValue) -> Result<(WireValue, String), CompositionError> {
    let text = validate_full_manifest(value).map_err(|_| CompositionError::Invalid)?;
    let wrapped = parse_wire_json_js_bounded(text.as_bytes(), 32, 65_536)
        .map_err(|_| CompositionError::Invalid)?;
    Ok((field(&wrapped, "manifest")?.clone(), text))
}
fn digest(value: &WireValue) -> Result<String, CompositionError> {
    Ok(sha256_hex(normalized(value)?.1.as_bytes()))
}
pub(crate) fn verify_composition(
    proof: &WireValue,
    stored_manifest: &WireValue,
    stored_resolved: &WireValue,
    stored_digest: &str,
    format_ceiling: u64,
) -> Result<(), CompositionError> {
    if proof.object_len() != Some(4) || proof.get("v") != Some(&WireValue::Number(1.0)) {
        return Err(CompositionError::Invalid);
    }
    let source = field(proof, "source_manifest")?;
    let source_normalized = normalized(source)?.0;
    let source_digest = digest(source)?;
    if !same(source, &source_normalized)?
        || field(proof, "source_digest")?.as_string().as_deref() != Some(source_digest.as_str())
    {
        return Err(CompositionError::Invalid);
    }
    let entries = array(field(proof, "dependencies")?)?;
    if entries.len() > 16 {
        return Err(CompositionError::Resource);
    }
    let mut nodes = HashMap::new();
    let mut original_order = Vec::new();
    for entry in entries {
        if entry.object_len() != Some(2) {
            return Err(CompositionError::Invalid);
        }
        let key = utf16(field(entry, "digest")?)?;
        let manifest = field(entry, "manifest")?.clone();
        if manifest.get("format_version").is_some() && format_ceiling != 2
            || !same(&manifest, &normalized(&manifest)?.0)?
            || nodes.insert(key.clone(), manifest).is_some()
        {
            return Err(CompositionError::Invalid);
        }
        original_order.push(key);
    }
    if source.get("format_version").is_some() && format_ceiling != 2 {
        return Err(CompositionError::Invalid);
    }
    let (resolved, closure) = resolve_protocol(source, &nodes)?;
    if closure != original_order
        || !same(&resolved, stored_manifest)?
        || !same(&resolved, stored_resolved)?
        || digest(&resolved)? != stored_digest
    {
        return Err(CompositionError::Invalid);
    }
    Ok(())
}
fn put(value: &mut WireValue, key: &str, replacement: WireValue) -> Result<(), CompositionError> {
    let WireValue::Object(items) = value else {
        return Err(CompositionError::Invalid);
    };
    let name: Vec<u16> = key.encode_utf16().collect();
    if let Some((_, current)) = items.iter_mut().find(|(name0, _)| *name0 == name) {
        *current = replacement;
    } else {
        items.push((name, replacement));
    }
    Ok(())
}
fn uses_state(value: &WireValue) -> bool {
    match value {
        WireValue::Array(items) => items.iter().any(uses_state),
        WireValue::Object(items) => {
            let is_literal =
                value.get("from").and_then(WireValue::as_string).as_deref() == Some("literal");
            if value.get("from").and_then(WireValue::as_string).as_deref() == Some("state")
                || value
                    .get("source")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some("state")
                || value.get("op").and_then(WireValue::as_string).as_deref() == Some("set")
            {
                return true;
            }
            items.iter().any(|(key, child)| {
                !(is_literal && key.iter().copied().eq("value".encode_utf16())) && uses_state(child)
            })
        }
        _ => false,
    }
}
fn stateless(manifest: &WireValue) -> Result<bool, CompositionError> {
    let actions = array(field(manifest, "actions")?)?;
    let constraints = fields(field(manifest, "constraints")?)?;
    Ok(actions.iter().all(|action| {
        action
            .get("reads")
            .and_then(|v| array(v).ok())
            .is_some_and(|v| v.is_empty())
            && action
                .get("writes")
                .and_then(|v| array(v).ok())
                .is_some_and(|v| v.is_empty())
            && !uses_state(action)
    }) && constraints.iter().all(|(_, rules)| !uses_state(rules)))
}

pub(crate) fn resolve_protocol(
    root_raw: &WireValue,
    nodes: &HashMap<Vec<u16>, WireValue>,
) -> Result<(WireValue, Vec<Vec<u16>>), CompositionError> {
    let root = normalized(root_raw)?.0;
    let mut ordered = Vec::<WireValue>::new();
    let mut closure = Vec::<Vec<u16>>::new();
    let mut active = HashSet::<Vec<u16>>::new();
    let mut done = HashSet::<Vec<u16>>::new();
    fn visit(
        key: Vec<u16>,
        depth: usize,
        nodes: &HashMap<Vec<u16>, WireValue>,
        active: &mut HashSet<Vec<u16>>,
        done: &mut HashSet<Vec<u16>>,
        ordered: &mut Vec<WireValue>,
        closure: &mut Vec<Vec<u16>>,
    ) -> Result<(), CompositionError> {
        if active.contains(&key) {
            return Err(CompositionError::Cycle);
        }
        if done.contains(&key) {
            return Ok(());
        }
        if depth > 16 || active.len() + done.len() >= 16 {
            return Err(CompositionError::Resource);
        }
        let raw = nodes.get(&key).ok_or(CompositionError::Missing)?;
        if digest(raw)?.encode_utf16().collect::<Vec<_>>() != key {
            return Err(CompositionError::Invalid);
        }
        let manifest = normalized(raw)?.0;
        active.insert(key.clone());
        let mut children = array(field(&manifest, "dependencies")?)?
            .iter()
            .map(utf16)
            .collect::<Result<Vec<_>, _>>()?;
        children.sort();
        for child in children {
            visit(child, depth + 1, nodes, active, done, ordered, closure)?;
        }
        active.remove(&key);
        done.insert(key.clone());
        closure.push(key);
        ordered.push(manifest);
        Ok(())
    }
    let mut roots = array(field(&root, "dependencies")?)?
        .iter()
        .map(utf16)
        .collect::<Result<Vec<_>, _>>()?;
    roots.sort();
    for key in roots {
        visit(
            key,
            1,
            nodes,
            &mut active,
            &mut done,
            &mut ordered,
            &mut closure,
        )?;
    }
    ordered.push(root.clone());
    let standalone = closure.is_empty();
    let root_initial = field(&root, "initial_state")?;
    let non_object_root = !matches!(root_initial, WireValue::Object(_));
    if non_object_root
        && !standalone
        && (ordered[..ordered.len() - 1]
            .iter()
            .any(|module| module.get("initial_state").and_then(WireValue::object_len) != Some(0))
            || ordered.iter().any(|module| stateless(module) != Ok(true)))
    {
        return Err(CompositionError::Conflict);
    }
    let mut schemas = BTreeMap::<Vec<u16>, WireValue>::new();
    let mut actions = BTreeMap::<Vec<u16>, WireValue>::new();
    let mut roles = BTreeSet::<Vec<u16>>::new();
    let mut capabilities = BTreeSet::<Vec<u16>>::new();
    let mut conflicts = BTreeMap::<Vec<u16>, WireValue>::new();
    let mut historical_conflicts = BTreeMap::<Vec<u16>, WireValue>::new();
    let mut state = if standalone || non_object_root {
        root_initial.clone()
    } else {
        WireValue::Object(vec![])
    };
    let mut state_owners = HashMap::<Vec<u16>, Vec<WireValue>>::new();
    let mut array_types = BTreeMap::<Vec<u16>, WireValue>::new();
    let mut constraints = BTreeMap::<Vec<u16>, Vec<WireValue>>::new();
    for manifest in &ordered {
        for (name, schema) in fields(field(manifest, "record_schemas")?)? {
            if schemas
                .get(name)
                .is_some_and(|prior| same(prior, schema) != Ok(true))
            {
                return Err(CompositionError::Conflict);
            }
            schemas.insert(name.clone(), schema.clone());
        }
        for action in array(field(manifest, "actions")?)? {
            let id = utf16(field(action, "id")?)?;
            if actions.insert(id, action.clone()).is_some() {
                return Err(CompositionError::Conflict);
            }
        }
        for role in array(field(manifest, "protocol_roles")?)? {
            roles.insert(utf16(role)?);
        }
        for capability in array(field(manifest, "capabilities")?)? {
            capabilities.insert(utf16(capability)?);
        }
        for (name, target) in [
            ("role_conflicts", &mut conflicts),
            ("historical_role_conflicts", &mut historical_conflicts),
        ] {
            for pair in array(field(manifest, name)?)? {
                let mut roles = array(pair)?
                    .iter()
                    .map(utf16)
                    .collect::<Result<Vec<_>, _>>()?;
                if roles.len() != 2 {
                    return Err(CompositionError::Invalid);
                }
                roles.sort();
                let mut key = roles[0].clone();
                key.push(',' as u16);
                key.extend(&roles[1]);
                target.insert(
                    key,
                    WireValue::Array(roles.into_iter().map(WireValue::String).collect()),
                );
            }
        }
        if !standalone && !non_object_root {
            for (key, value) in fields(field(manifest, "initial_state")?)? {
                let declarations = manifest
                    .get("state_array_types")
                    .map(array)
                    .transpose()?
                    .unwrap_or(&[])
                    .iter()
                    .filter(|entry| {
                        entry
                            .get("path")
                            .and_then(|v| array(v).ok())
                            .is_some_and(|path| {
                                path.first().and_then(WireValue::as_utf16) == Some(key.as_slice())
                            })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let prior_state = if let WireValue::Object(fields) = &state {
                    fields
                        .iter()
                        .find(|(candidate, _)| candidate == key)
                        .map(|(_, value)| value)
                } else {
                    None
                };
                if prior_state.is_some_and(|prior| {
                    same(prior, value) != Ok(true)
                        || state_owners.get(key).is_some_and(|prior_declarations| {
                            same(
                                &WireValue::Array(prior_declarations.clone()),
                                &WireValue::Array(declarations.clone()),
                            ) != Ok(true)
                        })
                }) {
                    return Err(CompositionError::Conflict);
                }
                if prior_state.is_none() {
                    if let WireValue::Object(fields) = &mut state {
                        fields.push((key.clone(), value.clone()));
                    }
                }
                state_owners.insert(key.clone(), declarations);
            }
        }
        if let Some(array_declarations) = manifest.get("state_array_types") {
            for declaration in array(array_declarations)? {
                let path = field(declaration, "path")?;
                let key = canonical(path)?.encode_utf16().collect::<Vec<_>>();
                if array_types
                    .get(&key)
                    .is_some_and(|prior| same(prior, declaration) != Ok(true))
                {
                    return Err(CompositionError::Conflict);
                }
                array_types.insert(key, declaration.clone());
            }
        }
        for (id, rules) in fields(field(manifest, "constraints")?)? {
            constraints
                .entry(id.clone())
                .or_default()
                .extend(array(rules)?.iter().cloned());
        }
    }
    if !actions.is_empty() && constraints.keys().any(|id| !actions.contains_key(id)) {
        return Err(CompositionError::Conflict);
    }
    let mut resolved_actions = Vec::new();
    for (id, mut action) in actions {
        if let Some(extra) = constraints.remove(&id) {
            let mut variants = array(field(&action, "variants")?)?.to_vec();
            for variant in &mut variants {
                let mut when = extra.clone();
                when.extend(array(field(variant, "when")?)?.iter().cloned());
                put(variant, "when", WireValue::Array(when))?;
            }
            put(&mut action, "variants", WireValue::Array(variants))?;
        }
        resolved_actions.push(action);
    }
    let mut merged = object(vec![
        ("name", field(&root, "name")?.clone()),
        ("display_version", field(&root, "display_version")?.clone()),
        ("semantics", field(&root, "semantics")?.clone()),
        (
            "dependencies",
            WireValue::Array(closure.iter().cloned().map(WireValue::String).collect()),
        ),
        (
            "protocol_roles",
            WireValue::Array(roles.into_iter().map(WireValue::String).collect()),
        ),
        (
            "capabilities",
            WireValue::Array(capabilities.into_iter().map(WireValue::String).collect()),
        ),
        (
            "role_conflicts",
            WireValue::Array(conflicts.into_values().collect()),
        ),
        (
            "historical_role_conflicts",
            WireValue::Array(historical_conflicts.into_values().collect()),
        ),
        (
            "constraints",
            WireValue::Object(
                constraints
                    .into_iter()
                    .map(|(key, rules)| (key, WireValue::Array(rules)))
                    .collect(),
            ),
        ),
        (
            "record_schemas",
            WireValue::Object(schemas.into_iter().collect()),
        ),
        ("initial_state", state),
        ("actions", WireValue::Array(resolved_actions)),
    ]);
    if !array_types.is_empty() {
        put(&mut merged, "format_version", WireValue::Number(2.0))?;
        put(
            &mut merged,
            "state_array_types",
            WireValue::Array(array_types.into_values().collect()),
        )?;
    }
    if let Some(exports) = root.get("state_exports") {
        put(&mut merged, "state_exports", exports.clone())?;
    }
    let mut requirement_sources = ordered
        .iter()
        .filter_map(|module| module.get("execution_requirements"))
        .collect::<Vec<_>>();
    if let Some(root_requirements) = root.get("execution_requirements") {
        requirement_sources.push(root_requirements);
    }
    if let Some(root_requirements) = root.get("execution_requirements") {
        if root_requirements.get("closure_complete") == Some(&WireValue::Bool(true)) {
            put(
                &mut merged,
                "execution_requirements",
                root_requirements.clone(),
            )?;
        } else if !requirement_sources.is_empty() {
            let ports = requirement_sources
                .iter()
                .flat_map(|item| {
                    item.get("ports")
                        .and_then(|v| array(v).ok())
                        .unwrap_or(&[])
                        .iter()
                        .cloned()
                })
                .collect();
            put(
                &mut merged,
                "execution_requirements",
                object(vec![
                    (
                        "format",
                        string("peerwork.protocol-execution-requirements.v1"),
                    ),
                    ("closure_complete", WireValue::Bool(true)),
                    ("ports", WireValue::Array(ports)),
                ]),
            )?;
        }
    } else if !requirement_sources.is_empty() {
        let ports = requirement_sources
            .iter()
            .flat_map(|item| {
                item.get("ports")
                    .and_then(|v| array(v).ok())
                    .unwrap_or(&[])
                    .iter()
                    .cloned()
            })
            .collect();
        put(
            &mut merged,
            "execution_requirements",
            object(vec![
                (
                    "format",
                    string("peerwork.protocol-execution-requirements.v1"),
                ),
                ("closure_complete", WireValue::Bool(true)),
                ("ports", WireValue::Array(ports)),
            ]),
        )?;
    }
    let result = normalized(&merged)?.0;
    if let Some(requirements) = result.get("execution_requirements") {
        for port in array(field(requirements, "ports")?)? {
            let action_id = utf16(field(port, "action_id")?)?;
            let index = field(port, "variant")?
                .as_number()
                .ok_or(CompositionError::Invalid)? as usize;
            let action = array(field(&result, "actions")?)?.iter().find(|action| {
                action.get("id").and_then(WireValue::as_utf16) == Some(action_id.as_slice())
            });
            if !action.is_some_and(|action| {
                action
                    .get("variants")
                    .and_then(|value| array(value).ok())
                    .is_some_and(|variants| variants.get(index).is_some())
            }) {
                return Err(CompositionError::Conflict);
            }
        }
    }
    Ok((result, closure))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_typescript_protocol_composition() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/protocol-composition-vectors.json").as_bytes(),
            64,
            1_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("vector array")
        };
        for case in cases {
            let name = field(&case, "name").unwrap().as_string().unwrap();
            let nodes = array(field(&case, "nodes").unwrap())
                .unwrap()
                .iter()
                .map(|node| {
                    (
                        utf16(field(node, "digest").unwrap()).unwrap(),
                        field(node, "manifest").unwrap().clone(),
                    )
                })
                .collect::<HashMap<_, _>>();
            let actual = resolve_protocol(field(&case, "root").unwrap(), &nodes);
            match case.get("result") {
                Some(expected) => {
                    let (manifest, closure) =
                        actual.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                    assert_eq!(
                        canonical(&manifest).unwrap(),
                        canonical(field(expected, "manifest").unwrap()).unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        WireValue::Array(closure.into_iter().map(WireValue::String).collect()),
                        field(expected, "closure").unwrap().clone(),
                        "{name}"
                    );
                    assert_eq!(
                        digest(&manifest).unwrap(),
                        field(expected, "digest").unwrap().as_string().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        verify_composition(
                            field(expected, "composition").unwrap(),
                            field(expected, "manifest").unwrap(),
                            field(expected, "manifest").unwrap(),
                            &field(expected, "digest").unwrap().as_string().unwrap(),
                            if name == "format2_array_dependency" {
                                2
                            } else {
                                1
                            },
                        ),
                        Ok(()),
                        "{name}"
                    );
                }
                None => {
                    assert!(actual.is_err(), "{name}");
                    if name.starts_with("merged_port_missing_") {
                        let root = field(&case, "root").unwrap();
                        let proof = object(vec![
                            ("v", WireValue::Number(1.0)),
                            ("source_digest", string(&digest(root).unwrap())),
                            ("source_manifest", normalized(root).unwrap().0),
                            (
                                "dependencies",
                                WireValue::Array(
                                    array(field(&case, "nodes").unwrap())
                                        .unwrap()
                                        .iter()
                                        .map(|node| {
                                            object(vec![
                                                ("digest", field(node, "digest").unwrap().clone()),
                                                (
                                                    "manifest",
                                                    normalized(field(node, "manifest").unwrap())
                                                        .unwrap()
                                                        .0,
                                                ),
                                            ])
                                        })
                                        .collect(),
                                ),
                            ),
                        ]);
                        assert_eq!(
                            verify_composition(
                                &proof,
                                &WireValue::Null,
                                &WireValue::Null,
                                "unused",
                                1
                            ),
                            Err(CompositionError::Conflict),
                            "{name} proof consumer",
                        );
                    }
                }
            }
        }
    }
}
