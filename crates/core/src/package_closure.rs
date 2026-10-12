//! Private exact-byte package closure scanner. Full package schema and compiler
//! validation must run before these bytes can authorize protocol installation.
use crate::{
    canonical::Path,
    crypto::{decode_base64url, sha256_hex},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClosureError {
    Invalid,
    Resource,
    Missing,
    Mismatch,
    Cycle,
}
fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue, ClosureError> {
    value.get(name).ok_or(ClosureError::Invalid)
}
fn exact(value: &WireValue, keys: &[&str]) -> bool {
    let WireValue::Object(fields) = value else {
        return false;
    };
    fields.len() == keys.len() && keys.iter().all(|key| value.get(key).is_some())
}
fn scalar(value: &WireValue) -> Result<String, ClosureError> {
    value.as_string().ok_or(ClosureError::Invalid)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn canonical(value: &WireValue) -> Result<String, ClosureError> {
    canonical_wire_value(value, Path::SecureArtifact).map_err(|_| ClosureError::Invalid)
}
fn safe_path(path: &str) -> bool {
    path.len() <= 200
        && !path.is_empty()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
        && path.split('/').count() <= 8
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !matches!(part, "__proto__" | "prototype" | "constructor")
        })
}
fn file(files: &WireValue, path: &str) -> Result<String, ClosureError> {
    // Callers parse file strings with the lossless JSON parser. Package text
    // itself must be Unicode scalar text: TS TextEncoder/TextDecoder roundtrip
    // rejects raw unpaired UTF-16 in a bundle file.
    let value = field(files, path)?;
    let WireValue::String(units) = value else {
        return Err(ClosureError::Invalid);
    };
    let text = String::from_utf16(units).map_err(|_| ClosureError::Invalid)?;
    if text.len() > 256 * 1024 {
        return Err(ClosureError::Resource);
    }
    Ok(text)
}
fn json_file(files: &WireValue, path: &str) -> Result<WireValue, ClosureError> {
    let text = file(files, path)?;
    let value = parse_wire_json_bounded(text.as_bytes(), 32, 256 * 1024)
        .map_err(|_| ClosureError::Invalid)?;
    let mut nodes = 0usize;
    fn safe(value: &WireValue, depth: usize, nodes: &mut usize) -> Result<(), ClosureError> {
        *nodes += 1;
        if *nodes > 8192 || depth > 32 {
            return Err(ClosureError::Resource);
        }
        match value {
            WireValue::Object(fields) => {
                for (name, child) in fields {
                    if ["__proto__", "prototype", "constructor"]
                        .iter()
                        .any(|bad| name.iter().copied().eq(bad.encode_utf16()))
                    {
                        return Err(ClosureError::Invalid);
                    }
                    safe(child, depth + 1, nodes)?;
                }
            }
            WireValue::Array(values) => {
                for child in values {
                    safe(child, depth + 1, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    safe(&value, 0, &mut nodes)?;
    Ok(value)
}
fn validate_bundle_basics(bundle: &WireValue) -> Result<(), ClosureError> {
    let files = field(bundle, "files")?;
    let WireValue::Object(entries) = files else {
        return Err(ClosureError::Invalid);
    };
    for (path, text) in entries {
        let path = String::from_utf16(path).map_err(|_| ClosureError::Invalid)?;
        if !safe_path(&path) {
            return Err(ClosureError::Invalid);
        }
        let text = text.as_string().ok_or(ClosureError::Invalid)?;
        if text.len() > 256 * 1024 {
            return Err(ClosureError::Resource);
        }
    }
    for required in [
        "package.json",
        "protocol.source.json",
        "release.lock.json",
        "README.md",
        "LICENSE",
    ] {
        file(files, required)?;
    }
    let metadata = json_file(files, "package.json")?;
    if !exact(
        &metadata,
        &[
            "format",
            "package_id",
            "version",
            "name",
            "description",
            "license",
            "license_file",
            "source_maintainers",
        ],
    ) || metadata
        .get("format")
        .and_then(WireValue::as_string)
        .as_deref()
        != Some("peerwork.protocol-package-metadata.v1")
    {
        return Err(ClosureError::Invalid);
    }
    let package_id = scalar(field(&metadata, "package_id")?)?;
    if package_id.is_empty()
        || package_id.len() > 80
        || package_id.split('-').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
    {
        return Err(ClosureError::Invalid);
    }
    let license_file = scalar(field(&metadata, "license_file")?)?;
    if !safe_path(&license_file) || files.get(&license_file).is_none() {
        return Err(ClosureError::Invalid);
    }
    let source = json_file(files, "protocol.source.json")?;
    let WireValue::Object(source_fields) = &source else {
        return Err(ClosureError::Invalid);
    };
    const SOURCE_KEYS: &[&str] = &[
        "format",
        "semantics",
        "manifest",
        "imports",
        "parameters",
        "exports",
        "bindings",
        "derive",
        "interfaces",
        "connections",
        "role_mappings",
        "capability_mappings",
        "fixture_dispositions",
    ];
    if source_fields.iter().any(|(name, _)| {
        !SOURCE_KEYS
            .iter()
            .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
    }) {
        return Err(ClosureError::Invalid);
    }
    if let Some(WireValue::Array(parameters)) = source.get("parameters") {
        let mut names = HashSet::new();
        for parameter in parameters {
            let name = scalar(field(parameter, "name")?)?;
            if !names.insert(name) {
                return Err(ClosureError::Invalid);
            }
            let kind = scalar(field(parameter, "type")?)?;
            if kind == "enum"
                && !matches!(parameter.get("values"), Some(WireValue::Array(values)) if !values.is_empty())
                || kind != "enum" && parameter.get("values").is_some()
            {
                return Err(ClosureError::Invalid);
            }
        }
    }
    if let Some(interfaces) = source.get("interfaces") {
        for collection in ["inputs", "action_bodies"] {
            let WireValue::Array(rows) = field(interfaces, collection)? else {
                return Err(ClosureError::Invalid);
            };
            for row in rows {
                let body = if collection == "inputs" {
                    field(row, "action_body")?
                } else {
                    field(row, "body")?
                };
                let fields = field(body, "fields")?;
                let WireValue::Array(required) = field(body, "required")? else {
                    return Err(ClosureError::Invalid);
                };
                if required.iter().any(|name| name.as_utf16().is_none_or(|name| !matches!(fields, WireValue::Object(fields) if fields.iter().any(|(key, _)| key == name)))) { return Err(ClosureError::Invalid); }
            }
        }
    }
    let lock = json_file(files, "release.lock.json")?;
    let source_format = field(&source, "format")?
        .as_string()
        .ok_or(ClosureError::Invalid)?;
    if !matches!(
        source_format.as_str(),
        "peerwork.protocol-source.v1" | "peerwork.protocol-source.v2"
    ) || field(&source, "semantics")?.as_string().as_deref() != Some("peerwork.kernel.v1")
        || field(&lock, "semantics")?.as_string().as_deref() != Some("peerwork.kernel.v1")
        || field(&lock, "format")?.as_string().as_deref() != Some("peerwork.protocol-lock.v1")
    {
        return Err(ClosureError::Invalid);
    }
    let source_manifest = field(&source, "manifest")?;
    crate::full_manifest::validate_full_manifest(source_manifest)
        .map_err(|_| ClosureError::Invalid)?;
    if !matches!(source_manifest.get("dependencies"), Some(WireValue::Array(deps)) if deps.is_empty())
        || source_manifest.get("execution_requirements").is_some()
        || source_format == "peerwork.protocol-source.v1"
            && [
                "interfaces",
                "connections",
                "role_mappings",
                "capability_mappings",
                "fixture_dispositions",
            ]
            .iter()
            .any(|key| source.get(key).is_some())
        || source_format == "peerwork.protocol-source.v2" && source.get("interfaces").is_none()
    {
        return Err(ClosureError::Invalid);
    }
    let WireValue::Array(imports) = field(&source, "imports")? else {
        return Err(ClosureError::Invalid);
    };
    let WireValue::Array(locked) = field(&lock, "dependencies")? else {
        return Err(ClosureError::Invalid);
    };
    if imports.len() > 16 || imports.len() != locked.len() {
        return Err(ClosureError::Invalid);
    }
    for source_import in imports {
        let alias = scalar(field(source_import, "alias")?)?;
        let package_digest = scalar(field(source_import, "package_digest")?)?;
        let namespace = scalar(field(source_import, "namespace")?)?;
        if !locked.iter().any(|entry| {
            entry.get("alias").and_then(WireValue::as_string).as_deref() == Some(&alias)
                && entry
                    .get("package_digest")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&package_digest)
                && entry
                    .get("namespace")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&namespace)
        }) {
            return Err(ClosureError::Invalid);
        }
    }
    let mut fixture_ids = HashSet::new();
    let mut fixture_count = 0usize;
    for (path, _) in entries {
        let path = String::from_utf16(path).map_err(|_| ClosureError::Invalid)?;
        if path.starts_with("fixtures/") && path.ends_with(".json") {
            fixture_count += 1;
            let fixture = json_file(files, &path)?;
            let id = scalar(field(&fixture, "id")?)?;
            if !fixture_ids.insert(id) {
                return Err(ClosureError::Invalid);
            }
        }
    }
    if !(1..=64).contains(&fixture_count) {
        return Err(ClosureError::Invalid);
    }
    Ok(())
}
fn js_array_index(key: &[u16]) -> Option<u32> {
    let text = String::from_utf16(key).ok()?;
    if text.is_empty()
        || text.len() > 10
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let n = text.parse::<u64>().ok()?;
    (n <= 4_294_967_294).then_some(n as u32)
}
fn bundle_bytes(bundle: &WireValue) -> Result<Vec<u8>, ClosureError> {
    if !exact(bundle, &["format", "files"])
        || scalar(field(bundle, "format")?)? != "peerwork.protocol-package.v1"
    {
        return Err(ClosureError::Invalid);
    }
    let WireValue::Object(files) = field(bundle, "files")? else {
        return Err(ClosureError::Invalid);
    };
    if files.len() > 64 {
        return Err(ClosureError::Resource);
    }
    validate_bundle_basics(bundle)?;
    let mut files = files.iter().collect::<Vec<_>>();
    files.sort_by(
        |(left, _), (right, _)| match (js_array_index(left), js_array_index(right)) {
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left.cmp(right),
        },
    );
    let mut result = String::from("{\"format\":\"peerwork.protocol-package.v1\",\"files\":{");
    for (index, (name, value)) in files.iter().enumerate() {
        if index > 0 {
            result.push(',')
        }
        result.push_str(&canonical(&WireValue::String((*name).clone()))?);
        result.push(':');
        result.push_str(&canonical(value)?);
    }
    result.push_str("}}");
    if result.len() > 1024 * 1024 {
        return Err(ClosureError::Resource);
    }
    Ok(result.into_bytes())
}
/// First compiler slice: no imports, parameters, derivations or interfaces.
/// A caller must never turn this subset into a general publishability proof.
pub(crate) struct SimpleCompilation {
    pub manifest: WireValue,
    pub source_digest: String,
    pub protocol_digest: String,
    pub compilation_lock: WireValue,
}
fn safe_integer(value: &WireValue) -> Result<u64, ClosureError> {
    let number = value.as_number().ok_or(ClosureError::Invalid)?;
    if !number.is_finite()
        || number < 0.0
        || number > 9_007_199_254_740_991.0
        || number.fract() != 0.0
    {
        return Err(ClosureError::Invalid);
    }
    Ok(number as u64)
}
fn merged_state(initial: &WireValue, provided: &WireValue) -> WireValue {
    let (WireValue::Object(initial), WireValue::Object(provided)) = (initial, provided) else {
        return provided.clone();
    };
    let mut result = initial.clone();
    for (key, value) in provided {
        if let Some((_, original)) = result.iter_mut().find(|(name, _)| name == key) {
            *original = merged_state(original, value);
        } else {
            result.push((key.clone(), value.clone()));
        }
    }
    WireValue::Object(result)
}
fn fixture_matches(manifest: &WireValue, fixture: &WireValue) -> Result<bool, ClosureError> {
    if fixture.get("kind").is_some() {
        return Err(ClosureError::Invalid);
    }
    let auth = field(fixture, "auth")?;
    let roles = |key| -> Result<Vec<Vec<u16>>, ClosureError> {
        match auth.get(key) {
            Some(WireValue::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_utf16()
                        .map(<[u16]>::to_vec)
                        .ok_or(ClosureError::Invalid)
                })
                .collect(),
            None => Ok(vec![]),
            _ => Err(ClosureError::Invalid),
        }
    };
    let auth = crate::interpreter::InterpreterAuth {
        actor_id: scalar(field(auth, "actorId")?)?,
        workspace_roles: roles("workspaceRoles")?,
        protocol_roles: roles("protocolRoles")?,
        capabilities: roles("capabilities")?,
    };
    let exact_inputs = match fixture.get("exact_inputs") {
        Some(WireValue::Array(inputs)) => inputs.as_slice(),
        None => &[],
        _ => return Err(ClosureError::Invalid),
    };
    let mut resolved_inputs = Vec::new();
    for input in exact_inputs {
        resolved_inputs.push(crate::interpreter::ResolvedInput {
            record_id: scalar(field(input, "recordId")?)?,
            revision: safe_integer(field(input, "revision")?)?,
            schema: field(input, "schema")?
                .as_utf16()
                .ok_or(ClosureError::Invalid)?
                .to_vec(),
            payload: field(input, "payload")?.clone(),
            scope: scalar(field(input, "scope")?)?,
            entity_id: input.get("entityId").map(scalar).transpose()?,
        });
    }
    let state = merged_state(field(manifest, "initial_state")?, field(fixture, "state")?);
    crate::full_manifest::validate_state_array_state(manifest, &state)
        .map_err(|_| ClosureError::Invalid)?;
    let action_manifest = WireValue::Object(vec![(
        "actions".encode_utf16().collect(),
        field(manifest, "actions")?.clone(),
    )]);
    let observed = crate::interpreter::evaluate_action(
        &action_manifest,
        field(fixture, "action_id")?
            .as_utf16()
            .ok_or(ClosureError::Invalid)?,
        &state,
        field(fixture, "body")?,
        &auth,
        &resolved_inputs,
        fixture.get("time_ms").map(safe_integer).transpose()?,
    );
    let expected = field(fixture, "expected")?;
    match expected.get("accepted") {
        Some(WireValue::Bool(false)) => {
            if !exact(expected, &["accepted", "code"]) {
                return Err(ClosureError::Invalid);
            }
            Ok(observed.err().map(|error| error.to_string())
                == expected.get("code").and_then(WireValue::as_string))
        }
        Some(WireValue::Bool(true)) => {
            let WireValue::Object(fields) = expected else {
                return Err(ClosureError::Invalid);
            };
            if fields
                .iter()
                .any(|(name, _)| !name.iter().copied().eq("accepted".encode_utf16()))
            {
                // Additional expected result fields will be supported by the
                // complete fixture runner, not silently ignored here.
                return Err(ClosureError::Invalid);
            }
            Ok(observed.is_ok())
        }
        _ => Err(ClosureError::Invalid),
    }
}
fn field_mut<'a>(value: &'a mut WireValue, key: &str) -> Result<&'a mut WireValue, ClosureError> {
    let WireValue::Object(fields) = value else {
        return Err(ClosureError::Invalid);
    };
    fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(key.encode_utf16()))
        .map(|(_, value)| value)
        .ok_or(ClosureError::Invalid)
}
fn insert_field(value: &mut WireValue, key: &str, next: WireValue) -> Result<(), ClosureError> {
    let WireValue::Object(fields) = value else {
        return Err(ClosureError::Invalid);
    };
    if let Some((_, old)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(key.encode_utf16()))
    {
        *old = next;
    } else {
        fields.push((key.encode_utf16().collect(), next));
    }
    Ok(())
}
fn remove_field(value: &mut WireValue, key: &str) -> Result<(), ClosureError> {
    let WireValue::Object(fields) = value else {
        return Err(ClosureError::Invalid);
    };
    fields.retain(|(name, _)| !name.iter().copied().eq(key.encode_utf16()));
    Ok(())
}
fn apply_interface_inputs(
    source: &WireValue,
    mut manifest: WireValue,
) -> Result<(WireValue, Vec<WireValue>), ClosureError> {
    if field(source, "format")?.as_string().as_deref() != Some("peerwork.protocol-source.v2") {
        return Ok((manifest, vec![]));
    }
    let interfaces = field(source, "interfaces")?;
    let WireValue::Array(outputs) = field(interfaces, "outputs")? else {
        return Err(ClosureError::Invalid);
    };
    // Output forwarding requires a checked import context and is handled by
    // the later connected-interface compiler layer.
    if !outputs.is_empty() {
        return Err(ClosureError::Invalid);
    }
    let WireValue::Array(contracts) = field(interfaces, "action_bodies")? else {
        return Err(ClosureError::Invalid);
    };
    let WireValue::Array(inputs) = field(interfaces, "inputs")? else {
        return Err(ClosureError::Invalid);
    };
    let mut assigned = HashMap::<String, String>::new();
    for contract in contracts {
        let action_id = scalar(field(contract, "action")?)?;
        let body = field(contract, "body")?.clone();
        let canonical_body = canonical(&body)?;
        if assigned.insert(action_id.clone(), canonical_body).is_some() {
            return Err(ClosureError::Invalid);
        }
        let WireValue::Array(actions) = field_mut(&mut manifest, "actions")? else {
            return Err(ClosureError::Invalid);
        };
        let action = actions
            .iter_mut()
            .find(|action| {
                action.get("id").and_then(WireValue::as_string).as_deref() == Some(&action_id)
            })
            .ok_or(ClosureError::Invalid)?;
        insert_field(action, "inputs", body)?;
    }
    let mut ports = Vec::new();
    for input in inputs {
        let action_id = scalar(field(input, "action")?)?;
        let variant = safe_integer(field(input, "variant")?)?;
        let name = scalar(field(input, "name")?)?;
        let kind = scalar(field(input, "type")?)?;
        let required = matches!(field(input, "required")?, WireValue::Bool(true));
        let WireValue::Array(body_path) = field(input, "body_path")? else {
            return Err(ClosureError::Invalid);
        };
        if body_path.len() != 1 {
            return Err(ClosureError::Invalid);
        }
        let path = scalar(&body_path[0])?;
        let body = field(input, "action_body")?;
        let body_field = field(field(body, "fields")?, &path)?;
        if body_field
            .get("type")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(&kind)
            || body_field
                .get("input")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(&name)
            || kind == "exact_ref" && body_field.get("scope") != input.get("scope")
        {
            return Err(ClosureError::Invalid);
        }
        let WireValue::Array(body_required) = field(body, "required")? else {
            return Err(ClosureError::Invalid);
        };
        if required
            != body_required
                .iter()
                .any(|value| value.as_string().as_deref() == Some(&path))
        {
            return Err(ClosureError::Invalid);
        }
        let mut runtime_body = body.clone();
        let WireValue::Object(fields) = field_mut(&mut runtime_body, "fields")? else {
            return Err(ClosureError::Invalid);
        };
        for (_, spec) in fields {
            match spec.get("type").and_then(WireValue::as_string).as_deref() {
                Some("exact_ref") if spec.get("input").is_some() => {
                    remove_field(spec, "input")?;
                    insert_field(
                        spec,
                        "schema",
                        WireValue::String("*".encode_utf16().collect()),
                    )?;
                }
                Some("actor_id") if spec.get("input").is_some() => {
                    remove_field(spec, "input")?;
                }
                _ => {}
            }
        }
        let canonical_body = canonical(&runtime_body)?;
        if assigned
            .get(&action_id)
            .is_some_and(|prior| prior != &canonical_body)
        {
            return Err(ClosureError::Mismatch);
        }
        assigned.insert(action_id.clone(), canonical_body);
        let WireValue::Array(actions) = field_mut(&mut manifest, "actions")? else {
            return Err(ClosureError::Invalid);
        };
        let action = actions
            .iter_mut()
            .find(|action| {
                action.get("id").and_then(WireValue::as_string).as_deref() == Some(&action_id)
            })
            .ok_or(ClosureError::Invalid)?;
        let WireValue::Array(variants) = field(action, "variants")? else {
            return Err(ClosureError::Invalid);
        };
        if variants.get(variant as usize).is_none() {
            return Err(ClosureError::Invalid);
        }
        insert_field(action, "inputs", runtime_body)?;
        let scope = input.get("scope").cloned();
        if !matches!(kind.as_str(), "exact_ref" | "actor_id")
            || kind == "exact_ref" && scope.is_none()
        {
            return Err(ClosureError::Invalid);
        }
        ports.push(WireValue::Object(vec![
            (
                "import_path".encode_utf16().collect(),
                WireValue::Array(vec![]),
            ),
            (
                "action_id".encode_utf16().collect(),
                WireValue::String(action_id.encode_utf16().collect()),
            ),
            (
                "variant".encode_utf16().collect(),
                WireValue::Number(variant as f64),
            ),
            (
                "input_name".encode_utf16().collect(),
                WireValue::String(name.encode_utf16().collect()),
            ),
            (
                "type".encode_utf16().collect(),
                WireValue::String(kind.encode_utf16().collect()),
            ),
            (
                "required".encode_utf16().collect(),
                WireValue::Bool(required),
            ),
            ("bound".encode_utf16().collect(), WireValue::Bool(false)),
        ]));
    }
    Ok((manifest, ports))
}
fn parameter_values(source: &WireValue, supplied: &WireValue) -> Result<WireValue, ClosureError> {
    let WireValue::Object(given) = supplied else {
        return Err(ClosureError::Invalid);
    };
    let WireValue::Array(parameters) = field(source, "parameters")? else {
        return Err(ClosureError::Invalid);
    };
    if given.len() > parameters.len() {
        return Err(ClosureError::Invalid);
    }
    let mut values = Vec::new();
    for parameter in parameters {
        let name = scalar(field(parameter, "name")?)?;
        let kind = scalar(field(parameter, "type")?)?;
        let value = supplied
            .get(&name)
            .or_else(|| parameter.get("default"))
            .ok_or(ClosureError::Invalid)?;
        let valid = match kind.as_str() {
            "enum" => {
                matches!(parameter.get("values"), Some(WireValue::Array(options)) if options.iter().any(|option| option == value))
            }
            "string" => value
                .as_utf16()
                .is_some_and(|text| String::from_utf16_lossy(text).len() <= 8192),
            "integer" => {
                let number = safe_integer(value)? as f64;
                parameter
                    .get("minimum")
                    .and_then(WireValue::as_number)
                    .is_none_or(|min| number >= min)
                    && parameter
                        .get("maximum")
                        .and_then(WireValue::as_number)
                        .is_none_or(|max| number <= max)
            }
            "boolean" => matches!(value, WireValue::Bool(_)),
            _ => false,
        };
        if !valid {
            return Err(ClosureError::Invalid);
        }
        values.push((name.encode_utf16().collect(), value.clone()));
    }
    if given
        .iter()
        .any(|(name, _)| !values.iter().any(|(known, _)| known == name))
    {
        return Err(ClosureError::Invalid);
    }
    Ok(WireValue::Object(values))
}
fn apply_parameter_bindings(
    source: &WireValue,
    values: &WireValue,
) -> Result<WireValue, ClosureError> {
    let mut manifest = field(source, "manifest")?.clone();
    let WireValue::Array(parameters) = field(source, "parameters")? else {
        return Err(ClosureError::Invalid);
    };
    for parameter in parameters {
        let Some(binding) = parameter.get("binding") else {
            continue;
        };
        if field(binding, "kind")?.as_string().as_deref() != Some("protocol_role_guard") {
            return Err(ClosureError::Invalid);
        }
        let name = scalar(field(parameter, "name")?)?;
        let chosen = scalar(field(values, &name)?)?;
        let declared = match manifest.get("protocol_roles") {
            Some(WireValue::Array(values)) => values,
            _ => return Err(ClosureError::Invalid),
        };
        if !declared
            .iter()
            .any(|role| role.as_string().as_deref() == Some(&chosen))
        {
            return Err(ClosureError::Invalid);
        }
        let target_action = scalar(field(binding, "action_id")?)?;
        let variant = safe_integer(field(binding, "variant_index")?)? as usize;
        let guard = safe_integer(field(binding, "guard_index")?)? as usize;
        let WireValue::Array(actions) = field_mut(&mut manifest, "actions")? else {
            return Err(ClosureError::Invalid);
        };
        let action = actions
            .iter_mut()
            .find(|action| {
                action.get("id").and_then(WireValue::as_string).as_deref() == Some(&target_action)
            })
            .ok_or(ClosureError::Invalid)?;
        let WireValue::Array(variants) = field_mut(action, "variants")? else {
            return Err(ClosureError::Invalid);
        };
        let target = variants.get_mut(variant).ok_or(ClosureError::Invalid)?;
        let WireValue::Array(guards) = field_mut(target, "when")? else {
            return Err(ClosureError::Invalid);
        };
        let guard = guards.get_mut(guard).ok_or(ClosureError::Invalid)?;
        if guard.get("op").and_then(WireValue::as_string).as_deref() != Some("has_protocol_role") {
            return Err(ClosureError::Invalid);
        }
        *field_mut(guard, "role")? = WireValue::String(chosen.encode_utf16().collect());
        if let Some(conflict) = binding.get("conflict_role") {
            let conflict = scalar(conflict)?;
            for key in ["role_conflicts", "historical_role_conflicts"] {
                let WireValue::Array(pairs) = field_mut(&mut manifest, key)? else {
                    return Err(ClosureError::Invalid);
                };
                let mut found = false;
                for pair in pairs {
                    let WireValue::Array(roles) = pair else {
                        return Err(ClosureError::Invalid);
                    };
                    if roles
                        .iter()
                        .any(|role| role.as_string().as_deref() == Some(&conflict))
                    {
                        found = true;
                        if roles.iter().any(|role| {
                            role.as_string().as_deref() == Some(&chosen) && chosen != conflict
                        }) {
                            return Err(ClosureError::Invalid);
                        }
                        for role in roles {
                            if role.as_string().as_deref() == Some(&conflict) {
                                *role = WireValue::String(chosen.encode_utf16().collect());
                            }
                        }
                    }
                }
                if !found {
                    return Err(ClosureError::Invalid);
                }
            }
        }
    }
    Ok(manifest)
}
fn check_derivation_guard_symbols(
    guard: &WireValue,
    roles: &HashSet<Vec<u16>>,
    capabilities: &HashSet<Vec<u16>>,
) -> Result<(), ClosureError> {
    let kind = field(guard, "op")?
        .as_string()
        .ok_or(ClosureError::Invalid)?;
    match kind.as_str() {
        "has_protocol_role" => {
            let role = field(guard, "role")?
                .as_utf16()
                .ok_or(ClosureError::Invalid)?;
            if !roles.contains(role) {
                return Err(ClosureError::Invalid);
            }
        }
        "has_capability" => {
            let capability = field(guard, "capability")?
                .as_utf16()
                .ok_or(ClosureError::Invalid)?;
            if !capabilities.contains(capability) {
                return Err(ClosureError::Invalid);
            }
        }
        "and" | "or" => {
            let WireValue::Array(rules) = field(guard, "rules")? else {
                return Err(ClosureError::Invalid);
            };
            for rule in rules {
                check_derivation_guard_symbols(rule, roles, capabilities)?;
            }
        }
        "not" => check_derivation_guard_symbols(field(guard, "rule")?, roles, capabilities)?,
        _ => {}
    }
    Ok(())
}
fn apply_derivations(
    source: &WireValue,
    root: &mut WireValue,
    dependencies: &HashMap<Vec<u16>, WireValue>,
) -> Result<(), ClosureError> {
    let WireValue::Array(derivations) = field(source, "derive")? else {
        return Err(ClosureError::Invalid);
    };
    let mut actions = HashSet::new();
    let mut roles = HashSet::new();
    let mut capabilities = HashSet::new();
    for manifest in std::iter::once(&*root).chain(dependencies.values()) {
        let WireValue::Array(list) = field(manifest, "actions")? else {
            return Err(ClosureError::Invalid);
        };
        for action in list {
            actions.insert(
                field(action, "id")?
                    .as_utf16()
                    .ok_or(ClosureError::Invalid)?
                    .to_vec(),
            );
        }
        for (key, target) in [
            ("protocol_roles", &mut roles),
            ("capabilities", &mut capabilities),
        ] {
            let WireValue::Array(list) = field(manifest, key)? else {
                return Err(ClosureError::Invalid);
            };
            for symbol in list {
                target.insert(symbol.as_utf16().ok_or(ClosureError::Invalid)?.to_vec());
            }
        }
    }
    let mut additions = field(root, "constraints")?.clone();
    for derivation in derivations {
        if field(derivation, "op")?.as_string().as_deref() != Some("add_constraint") {
            return Err(ClosureError::Invalid);
        }
        let action = field(derivation, "action_id")?
            .as_utf16()
            .ok_or(ClosureError::Invalid)?;
        if !actions.contains(action) {
            return Err(ClosureError::Invalid);
        }
        let guard = field(derivation, "guard")?;
        check_derivation_guard_symbols(guard, &roles, &capabilities)?;
        let WireValue::Object(fields) = &mut additions else {
            return Err(ClosureError::Invalid);
        };
        if !fields.iter().any(|(name, _)| name == action) {
            fields.push((action.to_vec(), WireValue::Array(vec![])));
        }
        let WireValue::Array(rules) = &mut fields
            .iter_mut()
            .find(|(name, _)| name == action)
            .ok_or(ClosureError::Invalid)?
            .1
        else {
            return Err(ClosureError::Invalid);
        };
        rules.push(guard.clone());
    }
    insert_field(root, "constraints", additions)?;
    Ok(())
}
pub(crate) fn compile_simple_baseline(
    closure: &ScannedPackageClosure,
) -> Result<SimpleCompilation, ClosureError> {
    compile_at(closure, &closure.root, None, true, 0, &mut 0)
}
fn mapped_import_values(
    source: &WireValue,
    values: &WireValue,
    alias: &str,
    dependency_source: &WireValue,
) -> Result<WireValue, ClosureError> {
    let WireValue::Array(bindings) = field(source, "bindings")? else {
        return Err(ClosureError::Invalid);
    };
    let WireValue::Array(exports) = field(dependency_source, "exports")? else {
        return Err(ClosureError::Invalid);
    };
    let mut mapped: Vec<(Vec<u16>, WireValue)> = Vec::new();
    for binding in bindings {
        if field(binding, "import_alias")?.as_string().as_deref() != Some(alias) {
            continue;
        }
        let slot = scalar(field(binding, "slot")?)?;
        let export = exports
            .iter()
            .find(|row| row.get("slot").and_then(WireValue::as_string).as_deref() == Some(&slot))
            .ok_or(ClosureError::Invalid)?;
        let child_parameter = scalar(field(export, "parameter")?)?;
        let parent_parameter = scalar(field(binding, "parameter")?)?;
        let chosen = field(values, &parent_parameter)?.clone();
        if mapped
            .iter()
            .any(|(name, _)| name.iter().copied().eq(child_parameter.encode_utf16()))
        {
            return Err(ClosureError::Invalid);
        }
        mapped.push((child_parameter.encode_utf16().collect(), chosen));
    }
    Ok(WireValue::Object(mapped))
}
fn compile_at(
    closure: &ScannedPackageClosure,
    package_digest: &str,
    supplied: Option<&WireValue>,
    enforce_lock: bool,
    depth: usize,
    steps: &mut usize,
) -> Result<SimpleCompilation, ClosureError> {
    *steps += 1;
    if depth > 16 || *steps > 128 {
        return Err(ClosureError::Resource);
    }
    let bundle = closure
        .packages
        .get(package_digest)
        .ok_or(ClosureError::Missing)?;
    let files = field(bundle, "files")?;
    let source = json_file(files, "protocol.source.json")?;
    let release = json_file(files, "release.lock.json")?;
    let source_format = scalar(field(&source, "format")?)?;
    let compiler_version = scalar(field(&release, "compiler_version")?)?;
    let v1 = source_format == "peerwork.protocol-source.v1"
        && compiler_version == "peerwork.protocol-compiler.v1";
    let v2 = source_format == "peerwork.protocol-source.v2"
        && compiler_version == "peerwork.protocol-compiler.v3";
    if !(v1 || v2)
        || v1
            && !exact(
                &source,
                &[
                    "format",
                    "semantics",
                    "manifest",
                    "imports",
                    "parameters",
                    "exports",
                    "bindings",
                    "derive",
                ],
            )
        || v2
            && (!matches!(source.get("interfaces"), Some(interfaces)
                if exact(interfaces, &["outputs", "inputs", "action_bodies"])
                    && ["outputs", "inputs", "action_bodies"].iter().all(|key| matches!(interfaces.get(key), Some(WireValue::Array(_)))))
                || [
                    "connections",
                    "role_mappings",
                    "capability_mappings",
                    "fixture_dispositions",
                ]
                .iter()
                .any(|key| {
                    source.get(key).is_some_and(
                        |value| !matches!(value, WireValue::Array(rows) if rows.is_empty()),
                    )
                }))
        || !matches!(source.get("bindings"), Some(WireValue::Array(_)))
        || !exact(
            &release,
            &[
                "format",
                "compiler_version",
                "semantics",
                "dependencies",
                "baseline_bindings",
                "output_protocol_digest",
            ],
        )
        || release.get("dependencies").and_then(|value| match value {
            WireValue::Array(rows) => Some(rows.len()),
            _ => None,
        }) != source.get("imports").and_then(|value| match value {
            WireValue::Array(rows) => Some(rows.len()),
            _ => None,
        })
    {
        return Err(ClosureError::Invalid);
    }
    let values = parameter_values(
        &source,
        supplied.unwrap_or(field(&release, "baseline_bindings")?),
    )?;
    let raw_manifest = apply_parameter_bindings(&source, &values)?;
    let (raw_manifest, own_ports) = apply_interface_inputs(&source, raw_manifest)?;
    let canonical_source = crate::full_manifest::validate_full_manifest(&raw_manifest)
        .map_err(|_| ClosureError::Invalid)?;
    let source_digest = sha256_hex(canonical_source.as_bytes());
    let WireValue::Array(imports) = field(&source, "imports")? else {
        return Err(ClosureError::Invalid);
    };
    let mut nodes = HashMap::new();
    let mut dependency_ids = Vec::new();
    for imported in imports {
        let digest = scalar(field(imported, "package_digest")?)?;
        let alias = scalar(field(imported, "alias")?)?;
        let namespace = scalar(field(imported, "namespace")?)?;
        let dependency_bundle = closure.packages.get(&digest).ok_or(ClosureError::Missing)?;
        let dependency_source =
            json_file(field(dependency_bundle, "files")?, "protocol.source.json")?;
        let baseline = compile_at(closure, &digest, None, true, depth + 1, steps)?;
        let mapped = mapped_import_values(&source, &values, &alias, &dependency_source)?;
        let compiled = if matches!(&mapped, WireValue::Object(fields) if fields.is_empty()) {
            baseline
        } else {
            compile_at(closure, &digest, Some(&mapped), false, depth + 1, steps)?
        };
        let namespaced =
            crate::package_namespace::namespace_manifest(&compiled.manifest, &namespace)
                .map_err(|_| ClosureError::Invalid)?;
        let checked = crate::full_manifest::validate_full_manifest(&namespaced)
            .map_err(|_| ClosureError::Invalid)?;
        let digest = sha256_hex(checked.as_bytes());
        if nodes
            .insert(digest.encode_utf16().collect(), namespaced)
            .is_some()
        {
            return Err(ClosureError::Mismatch);
        }
        dependency_ids.push(WireValue::String(digest.encode_utf16().collect()));
    }
    let mut root = raw_manifest;
    *field_mut(&mut root, "dependencies")? = WireValue::Array(dependency_ids);
    apply_derivations(&source, &mut root, &nodes)?;
    if v2 {
        insert_field(
            &mut root,
            "execution_requirements",
            WireValue::Object(vec![
                (
                    "format".encode_utf16().collect(),
                    WireValue::String(
                        "peerwork.protocol-execution-requirements.v1"
                            .encode_utf16()
                            .collect(),
                    ),
                ),
                (
                    "closure_complete".encode_utf16().collect(),
                    WireValue::Bool(true),
                ),
                (
                    "ports".encode_utf16().collect(),
                    WireValue::Array(own_ports),
                ),
            ]),
        )?;
    }
    let (manifest, _dependency_closure) =
        crate::protocol_composition::resolve_protocol(&root, &nodes)
            .map_err(|_| ClosureError::Invalid)?;
    let canonical_manifest = crate::full_manifest::validate_full_manifest(&manifest)
        .map_err(|_| ClosureError::Invalid)?;
    let protocol_digest = sha256_hex(canonical_manifest.as_bytes());
    if enforce_lock
        && field(&release, "output_protocol_digest")?
            .as_string()
            .as_deref()
            != Some(&protocol_digest)
    {
        return Err(ClosureError::Mismatch);
    }
    let WireValue::Object(entries) = files else {
        return Err(ClosureError::Invalid);
    };
    for (path, _) in entries {
        let path = String::from_utf16(path).map_err(|_| ClosureError::Invalid)?;
        if !(path.starts_with("fixtures/") && path.ends_with(".json")) {
            continue;
        }
        let fixture = json_file(files, &path)?;
        if !fixture_matches(&manifest, &fixture)? {
            return Err(ClosureError::Mismatch);
        }
    }
    let compilation_lock = WireValue::Object(vec![
        (
            "format".encode_utf16().collect(),
            WireValue::String("peerwork.compilation-lock.v1".encode_utf16().collect()),
        ),
        (
            "compiler_version".encode_utf16().collect(),
            WireValue::String(compiler_version.encode_utf16().collect()),
        ),
        (
            "semantics".encode_utf16().collect(),
            WireValue::String("peerwork.kernel.v1".encode_utf16().collect()),
        ),
        (
            "root_package_digest".encode_utf16().collect(),
            WireValue::String(package_digest.encode_utf16().collect()),
        ),
        (
            "dependencies".encode_utf16().collect(),
            field(&source, "imports")?.clone(),
        ),
        ("bindings".encode_utf16().collect(), values),
        (
            "source_digest".encode_utf16().collect(),
            WireValue::String(source_digest.encode_utf16().collect()),
        ),
        (
            "protocol_digest".encode_utf16().collect(),
            WireValue::String(protocol_digest.encode_utf16().collect()),
        ),
    ]);
    Ok(SimpleCompilation {
        manifest,
        source_digest,
        protocol_digest,
        compilation_lock,
    })
}
fn package_imports(bundle: &WireValue) -> Result<Vec<String>, ClosureError> {
    let WireValue::Object(files) = field(bundle, "files")? else {
        return Err(ClosureError::Invalid);
    };
    let source = files
        .iter()
        .find(|(key, _)| {
            key.iter()
                .copied()
                .eq("protocol.source.json".encode_utf16())
        })
        .map(|(_, value)| value)
        .ok_or(ClosureError::Invalid)?;
    let source = scalar(source)?;
    if source.len() > 256 * 1024 {
        return Err(ClosureError::Resource);
    }
    let parsed = parse_wire_json_bounded(source.as_bytes(), 32, 256 * 1024)
        .map_err(|_| ClosureError::Invalid)?;
    let imports = match parsed.get("imports") {
        Some(WireValue::Array(imports)) => imports.as_slice(),
        None => &[],
        _ => return Err(ClosureError::Invalid),
    };
    if imports.len() > 16 {
        return Err(ClosureError::Resource);
    }
    imports
        .iter()
        .map(|row| {
            let hash = scalar(field(row, "package_digest")?)?;
            if !digest(&hash) {
                return Err(ClosureError::Invalid);
            }
            Ok(hash)
        })
        .collect()
}

pub(crate) struct ScannedPackageClosure {
    pub packages: HashMap<String, WireValue>,
    pub root: String,
    pub canonical_bytes: Vec<u8>,
}
pub(crate) fn scan_package_closure(
    value: &WireValue,
) -> Result<ScannedPackageClosure, ClosureError> {
    if !exact(value, &["format", "packages", "root_package_digest"])
        || scalar(field(value, "format")?)? != "peerwork.protocol-package-closure.v1"
    {
        return Err(ClosureError::Invalid);
    }
    let root = scalar(field(value, "root_package_digest")?)?;
    if !digest(&root) {
        return Err(ClosureError::Invalid);
    }
    let WireValue::Object(encoded) = field(value, "packages")? else {
        return Err(ClosureError::Invalid);
    };
    if encoded.is_empty() || encoded.len() > 16 {
        return Err(ClosureError::Resource);
    }
    let mut packages = HashMap::new();
    let mut raw_total = 0usize;
    for (name, text) in encoded {
        let name = String::from_utf16(name).map_err(|_| ClosureError::Invalid)?;
        if !digest(&name) {
            return Err(ClosureError::Invalid);
        }
        let bytes = decode_base64url(&scalar(text)?).map_err(|_| ClosureError::Invalid)?;
        raw_total = raw_total
            .checked_add(bytes.len())
            .filter(|value| *value <= 4 * 1024 * 1024)
            .ok_or(ClosureError::Resource)?;
        if bytes.len() > 1024 * 1024 {
            return Err(ClosureError::Resource);
        }
        let bundle =
            parse_wire_json_bounded(&bytes, 32, 1024 * 1024).map_err(|_| ClosureError::Invalid)?;
        if bundle_bytes(&bundle)? != bytes || sha256_hex(&bytes) != name {
            return Err(ClosureError::Mismatch);
        }
        packages.insert(name, bundle);
    }
    if !packages.contains_key(&root) {
        return Err(ClosureError::Missing);
    }
    let mut active = HashSet::new();
    let mut visited = HashSet::new();
    let mut steps = 0usize;
    fn visit(
        key: &str,
        depth: usize,
        packages: &HashMap<String, WireValue>,
        active: &mut HashSet<String>,
        visited: &mut HashSet<String>,
        steps: &mut usize,
    ) -> Result<(), ClosureError> {
        if depth > 16 {
            return Err(ClosureError::Resource);
        }
        if active.contains(key) {
            return Err(ClosureError::Cycle);
        }
        if visited.contains(key) {
            return Ok(());
        }
        *steps += 1;
        if *steps > 128 {
            return Err(ClosureError::Resource);
        }
        let bundle = packages.get(key).ok_or(ClosureError::Missing)?;
        active.insert(key.to_owned());
        for dependency in package_imports(bundle)? {
            visit(&dependency, depth + 1, packages, active, visited, steps)?
        }
        active.remove(key);
        visited.insert(key.to_owned());
        Ok(())
    }
    visit(&root, 0, &packages, &mut active, &mut visited, &mut steps)?;
    if visited.len() != packages.len() {
        return Err(ClosureError::Mismatch);
    }
    let bytes = canonical(value)?.into_bytes();
    if bytes.len() > 6 * 1024 * 1024 {
        return Err(ClosureError::Resource);
    }
    Ok(ScannedPackageClosure {
        packages,
        root,
        canonical_bytes: bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracked_package_closure_bytes_and_tamper() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/protocol-package-vectors.json"
        ))
        .unwrap();
        for case in cases.as_array().unwrap() {
            let closure_wire = serde_json::to_vec(&case["closure"]).unwrap();
            let closure = parse_wire_json_bounded(&closure_wire, 32, 6 * 1024 * 1024).unwrap();
            if case["result"] == "ok" {
                let scanned = scan_package_closure(&closure).unwrap();
                assert_eq!(scanned.root, case["package_digest"].as_str().unwrap());
                assert_eq!(
                    scanned.packages.len(),
                    case["package_count"].as_u64().unwrap() as usize
                );
                assert_eq!(
                    scanned.canonical_bytes,
                    decode_base64url(case["canonical_closure_base64"].as_str().unwrap()).unwrap()
                );
                assert_eq!(
                    bundle_bytes(scanned.packages.get(&scanned.root).unwrap()).unwrap(),
                    decode_base64url(case["canonical_package_base64"].as_str().unwrap()).unwrap()
                );
                {
                    let compiled = compile_simple_baseline(&scanned).unwrap();
                    assert_eq!(
                        compiled.protocol_digest,
                        case["protocol_digest"].as_str().unwrap()
                    );
                    assert_eq!(
                        compiled.source_digest,
                        case["source_digest"].as_str().unwrap()
                    );
                    let expected_manifest = serde_json::to_vec(&case["compiled_manifest"]).unwrap();
                    let expected_manifest =
                        parse_wire_json_bounded(&expected_manifest, 32, 65_536).unwrap();
                    assert_eq!(
                        canonical(&compiled.manifest).unwrap(),
                        canonical(&expected_manifest).unwrap()
                    );
                    assert_eq!(
                        canonical(&compiled.compilation_lock).unwrap(),
                        canonical(
                            &parse_wire_json_bounded(
                                serde_json::to_string(&case["compilation_lock"])
                                    .unwrap()
                                    .as_bytes(),
                                16,
                                2048,
                            )
                            .unwrap()
                        )
                        .unwrap()
                    );
                    assert_eq!(
                        compiled
                            .manifest
                            .get("name")
                            .and_then(WireValue::as_string)
                            .as_deref(),
                        Some("demo")
                    );
                }
            } else if case.get("compile_result").is_some() {
                let scanned = scan_package_closure(&closure).unwrap();
                assert!(compile_simple_baseline(&scanned).is_err());
            } else {
                assert!(scan_package_closure(&closure).is_err());
            }
        }
    }

    #[test]
    fn tracked_public_proposal_adoption_compilation() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let closure_wire = serde_json::to_vec(&vector["closure"]).unwrap();
        let closure = parse_wire_json_bounded(&closure_wire, 32, 6 * 1024 * 1024).unwrap();
        let scanned = scan_package_closure(&closure).unwrap();
        assert_eq!(scanned.root, vector["package_digest"].as_str().unwrap());
        let compiled = compile_simple_baseline(&scanned).unwrap();
        assert_eq!(
            compiled.source_digest,
            vector["source_digest"].as_str().unwrap()
        );
        let expected_wire = serde_json::to_vec(&vector["compiled_manifest"]).unwrap();
        let expected = parse_wire_json_bounded(&expected_wire, 32, 65_536).unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let lock = serde_json::to_vec(&vector["compilation_lock"]).unwrap();
        let lock = parse_wire_json_bounded(&lock, 16, 2048).unwrap();
        assert_eq!(
            canonical(&compiled.compilation_lock).unwrap(),
            canonical(&lock).unwrap()
        );
        assert_eq!(
            compiled
                .manifest
                .get("name")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("peerwork.proposal-adoption.v1")
        );
    }

    #[test]
    fn tracked_public_proposal_adoption_v2_input_compilation() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-v2-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        assert_eq!(vector["interfaces_complete"], false);
        let closure_wire = serde_json::to_vec(&vector["closure"]).unwrap();
        let closure = parse_wire_json_bounded(&closure_wire, 32, 6 * 1024 * 1024).unwrap();
        let scanned = scan_package_closure(&closure).unwrap();
        assert_eq!(scanned.root, vector["package_digest"].as_str().unwrap());
        let compiled = compile_simple_baseline(&scanned).unwrap();
        assert_eq!(
            compiled.source_digest,
            vector["source_digest"].as_str().unwrap()
        );
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected_wire = serde_json::to_vec(&vector["compiled_manifest"]).unwrap();
        let expected = parse_wire_json_bounded(&expected_wire, 32, 65_536).unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
        let lock_wire = serde_json::to_vec(&vector["compilation_lock"]).unwrap();
        let lock = parse_wire_json_bounded(&lock_wire, 16, 2048).unwrap();
        assert_eq!(
            canonical(&compiled.compilation_lock).unwrap(),
            canonical(&lock).unwrap()
        );
    }

    #[test]
    fn tracked_public_proposal_adoption_derived_guard_compilation() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-derived-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        let closure_wire = serde_json::to_vec(&vector["closure"]).unwrap();
        let closure = parse_wire_json_bounded(&closure_wire, 32, 6 * 1024 * 1024).unwrap();
        let scanned = scan_package_closure(&closure).unwrap();
        let compiled = compile_simple_baseline(&scanned).unwrap();
        assert_eq!(
            compiled.source_digest,
            vector["source_digest"].as_str().unwrap()
        );
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected_wire = serde_json::to_vec(&vector["compiled_manifest"]).unwrap();
        let expected = parse_wire_json_bounded(&expected_wire, 32, 65_536).unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
        let lock_wire = serde_json::to_vec(&vector["compilation_lock"]).unwrap();
        let lock = parse_wire_json_bounded(&lock_wire, 16, 2048).unwrap();
        assert_eq!(
            canonical(&compiled.compilation_lock).unwrap(),
            canonical(&lock).unwrap()
        );
    }

    #[test]
    fn tracked_exported_parent_binding_compilation() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-binding-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        let closure_wire = serde_json::to_vec(&vector["closure"]).unwrap();
        let closure = parse_wire_json_bounded(&closure_wire, 32, 6 * 1024 * 1024).unwrap();
        let scanned = scan_package_closure(&closure).unwrap();
        let compiled = compile_simple_baseline(&scanned).unwrap();
        assert_eq!(
            compiled.source_digest,
            vector["source_digest"].as_str().unwrap()
        );
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected_wire = serde_json::to_vec(&vector["compiled_manifest"]).unwrap();
        let expected = parse_wire_json_bounded(&expected_wire, 32, 65_536).unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
        let lock_wire = serde_json::to_vec(&vector["compilation_lock"]).unwrap();
        let lock = parse_wire_json_bounded(&lock_wire, 16, 2048).unwrap();
        assert_eq!(
            canonical(&compiled.compilation_lock).unwrap(),
            canonical(&lock).unwrap()
        );
    }
}
