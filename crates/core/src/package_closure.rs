//! Private exact-byte package closure scanner. Full package schema and compiler
//! validation must run before these bytes can authorize protocol installation.
use crate::{
    canonical::Path,
    crypto::{base64url, decode_base64url, sha256, sha256_hex},
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
fn schema_error(error: crate::package_schema::PackageSchemaError) -> ClosureError {
    match error {
        crate::package_schema::PackageSchemaError::Invalid => ClosureError::Invalid,
        crate::package_schema::PackageSchemaError::Resource => ClosureError::Resource,
    }
}
fn source_file(files: &WireValue) -> Result<WireValue, ClosureError> {
    crate::package_schema::normalize_and_validate_source(&json_file(files, "protocol.source.json")?)
        .map_err(schema_error)
}
fn lock_file(files: &WireValue) -> Result<WireValue, ClosureError> {
    crate::package_schema::normalize_and_validate_lock(&json_file(files, "release.lock.json")?)
        .map_err(schema_error)
}
fn fixture_file(files: &WireValue, path: &str) -> Result<WireValue, ClosureError> {
    crate::package_schema::normalize_and_validate_fixture(&json_file(files, path)?)
        .map_err(schema_error)
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
    let metadata = crate::package_schema::validate_metadata(&json_file(files, "package.json")?)
        .map_err(schema_error)?;
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
    let source = source_file(files)?;
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
    let lock = lock_file(files)?;
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
            let fixture = fixture_file(files, &path)?;
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

pub(crate) fn inspect_exact_public_bundle(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<(WireValue, WireValue), ClosureError> {
    if !digest(expected_digest) {
        return Err(ClosureError::Invalid);
    }
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(ClosureError::Resource);
    }
    let bundle =
        parse_wire_json_bounded(bytes, 32, 1024 * 1024).map_err(|_| ClosureError::Invalid)?;
    if bundle_bytes(&bundle)? != bytes || sha256_hex(bytes) != expected_digest {
        return Err(ClosureError::Mismatch);
    }
    let files = field(&bundle, "files")?;
    let metadata = json_file(files, "package.json")?;
    let source = source_file(files)?;
    let imports = field(&source, "imports")?.clone();
    let fixture_ids = match files {
        WireValue::Object(entries) => entries
            .iter()
            .filter_map(|(name, _)| {
                let path = String::from_utf16(name).ok()?;
                (path.starts_with("fixtures/") && path.ends_with(".json")).then_some(path)
            })
            .map(|path| {
                let fixture = fixture_file(files, &path)?;
                Ok(field(&fixture, "id")?.clone())
            })
            .collect::<Result<Vec<_>, ClosureError>>()?,
        _ => return Err(ClosureError::Invalid),
    };
    let summary = WireValue::Object(vec![
        (
            "bundle_digest".encode_utf16().collect(),
            WireValue::String(expected_digest.encode_utf16().collect()),
        ),
        ("metadata".encode_utf16().collect(), metadata),
        ("imports".encode_utf16().collect(), imports),
        (
            "fixture_ids".encode_utf16().collect(),
            WireValue::Array(fixture_ids),
        ),
    ]);
    Ok((bundle, summary))
}
/// First compiler slice: no imports, parameters, derivations or interfaces.
/// A caller must never turn this subset into a general publishability proof.
pub(crate) struct SimpleCompilation {
    pub manifest: WireValue,
    // TS compiler enumeration is separate from canonical digest ordering.
    pub schema_order: Vec<Vec<u16>>,
    pub source_digest: String,
    pub protocol_digest: String,
    /// Exact normalized manifest closure for a dependency-bearing secure
    /// protocol object. This is compiler output, not an install authority.
    pub composition: Option<WireValue>,
    pub compilation_lock: WireValue,
    scenarios: Vec<FixtureScenario>,
    dispositions: Vec<FixtureDisposition>,
}
#[derive(Clone)]
struct FixtureScenario {
    id: String,
    fixture: WireValue,
    origin_package_digest: String,
    import_path: Vec<String>,
}
#[derive(Clone)]
struct FixtureDisposition {
    origin_package_digest: String,
    import_path: Vec<String>,
    fixture_id: String,
    expected_rejection: String,
    replacement_id: String,
}
struct ImportedUnit {
    package_digest: String,
    namespace: String,
    source: WireValue,
    values: WireValue,
    manifest: WireValue,
    schema_order: Vec<Vec<u16>>,
    roles: HashMap<Vec<u16>, Vec<u16>>,
    capabilities: HashMap<Vec<u16>, Vec<u16>>,
}
struct ResolvedOutput {
    kind: String,
    path: Vec<WireValue>,
    schema: Option<String>,
    scope: Option<String>,
    available: WireValue,
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
fn accepted_result_matches(
    expected: &WireValue,
    observed: crate::interpreter::EvalResult,
    state: WireValue,
) -> Result<bool, ClosureError> {
    let WireValue::Object(fields) = expected else {
        return Err(ClosureError::Invalid);
    };
    let mut actual = WireValue::Object(vec![
        ("accepted".encode_utf16().collect(), WireValue::Bool(true)),
        ("state".encode_utf16().collect(), state),
        (
            "records".encode_utf16().collect(),
            WireValue::Array(observed.records),
        ),
        (
            "headSelections".encode_utf16().collect(),
            WireValue::Array(observed.head_selections),
        ),
        (
            "revisionEffects".encode_utf16().collect(),
            WireValue::Object(vec![
                (
                    "control".encode_utf16().collect(),
                    WireValue::Bool(observed.control_revision),
                ),
                (
                    "contentEntities".encode_utf16().collect(),
                    WireValue::Array(
                        observed
                            .content_entities
                            .into_iter()
                            .map(WireValue::String)
                            .collect(),
                    ),
                ),
            ]),
        ),
    ]);
    if let Some(time) = observed.evaluated_at {
        insert_field(&mut actual, "evaluated_at", WireValue::Number(time as f64))?;
    }
    for (name, wanted) in fields {
        let name = String::from_utf16(name).map_err(|_| ClosureError::Invalid)?;
        if ![
            "accepted",
            "state",
            "records",
            "headSelections",
            "revisionEffects",
            "evaluated_at",
        ]
        .contains(&name.as_str())
        {
            return Err(ClosureError::Invalid);
        }
        let Some(value) = actual.get(&name) else {
            return Ok(false);
        };
        if canonical(value)? != canonical(wanted)? {
            return Ok(false);
        }
    }
    Ok(true)
}
struct FixtureCheck {
    passed: bool,
    rejections: Vec<String>,
}
fn fixture_matches(
    manifest: &WireValue,
    fixture: &WireValue,
    id: &str,
) -> Result<FixtureCheck, ClosureError> {
    if fixture.get("kind").is_some() {
        return sequence_fixture_matches(manifest, fixture, id);
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
    let rejections = observed
        .as_ref()
        .err()
        .map(|error| vec![error.to_string()])
        .unwrap_or_default();
    match expected.get("accepted") {
        Some(WireValue::Bool(false)) => {
            if !exact(expected, &["accepted", "code"]) {
                return Err(ClosureError::Invalid);
            }
            Ok(FixtureCheck {
                passed: rejections.first().map(String::as_str)
                    == expected
                        .get("code")
                        .and_then(WireValue::as_string)
                        .as_deref(),
                rejections,
            })
        }
        Some(WireValue::Bool(true)) => {
            let Ok(observed) = observed else {
                return Ok(FixtureCheck {
                    passed: false,
                    rejections,
                });
            };
            let state = observed.next_state.clone();
            Ok(FixtureCheck {
                passed: accepted_result_matches(expected, observed, state)?,
                rejections,
            })
        }
        _ => Err(ClosureError::Invalid),
    }
}
fn replace_fixture_refs(
    value: &WireValue,
    refs: &HashMap<String, crate::interpreter::ResolvedInput>,
    expected: bool,
) -> Result<WireValue, ClosureError> {
    match value {
        WireValue::Array(values) => Ok(WireValue::Array(
            values
                .iter()
                .map(|value| replace_fixture_refs(value, refs, expected))
                .collect::<Result<_, _>>()?,
        )),
        WireValue::Object(fields) if fields.len() == 1 && value.get("$fixture_ref").is_some() => {
            let name = scalar(field(value, "$fixture_ref")?)?;
            let reference = refs.get(&name).ok_or(ClosureError::Invalid)?;
            Ok(WireValue::Object(vec![
                (
                    (if expected { "recordId" } else { "record_id" })
                        .encode_utf16()
                        .collect(),
                    WireValue::String(reference.record_id.encode_utf16().collect()),
                ),
                (
                    "revision".encode_utf16().collect(),
                    WireValue::Number(reference.revision as f64),
                ),
            ]))
        }
        WireValue::Object(fields) => Ok(WireValue::Object(
            fields
                .iter()
                .map(|(name, value)| {
                    Ok((name.clone(), replace_fixture_refs(value, refs, expected)?))
                })
                .collect::<Result<_, ClosureError>>()?,
        )),
        _ => Ok(value.clone()),
    }
}
fn replace_produced_record(
    value: &WireValue,
    slot: &[u16],
    record_id: &str,
    revision: u64,
) -> WireValue {
    match value {
        WireValue::Array(values) => WireValue::Array(
            values
                .iter()
                .map(|value| replace_produced_record(value, slot, record_id, revision))
                .collect(),
        ),
        WireValue::Object(_)
            if value
                .get("$produced")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("record")
                && value.get("slot").and_then(WireValue::as_utf16) == Some(slot) =>
        {
            WireValue::Object(vec![
                (
                    "record_id".encode_utf16().collect(),
                    WireValue::String(record_id.encode_utf16().collect()),
                ),
                (
                    "revision".encode_utf16().collect(),
                    WireValue::Number(revision as f64),
                ),
            ])
        }
        WireValue::Object(fields) => WireValue::Object(
            fields
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        replace_produced_record(value, slot, record_id, revision),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}
fn replace_produced_entity(value: &WireValue, slot: &[u16], entity_id: &str) -> WireValue {
    match value {
        WireValue::Array(values) => WireValue::Array(
            values
                .iter()
                .map(|value| replace_produced_entity(value, slot, entity_id))
                .collect(),
        ),
        WireValue::Object(_)
            if value
                .get("$produced")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("entity")
                && value.get("slot").and_then(WireValue::as_utf16) == Some(slot) =>
        {
            WireValue::String(entity_id.encode_utf16().collect())
        }
        WireValue::Object(fields) => WireValue::Object(
            fields
                .iter()
                .map(|(name, child)| {
                    (
                        name.clone(),
                        replace_produced_entity(child, slot, entity_id),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}
fn resolve_sequence_output_state(
    manifest: &WireValue,
    records: &[WireValue],
    id: &str,
    mut state: WireValue,
) -> Result<WireValue, ClosureError> {
    // The tracked fixture runner resolves all emitted markers when signed
    // state-array declarations are present, whether or not bind_refs names a
    // record for a later sequence step.
    if manifest.get("state_array_types").is_none() {
        return Ok(state);
    }
    for record in records {
        if let Some(slot) = record.get("recordSlot").and_then(WireValue::as_utf16) {
            let hash_input = format!("{id}:record:{}", String::from_utf16_lossy(slot));
            let record_id = base64url(&sha256(hash_input.as_bytes()));
            state = replace_produced_record(&state, slot, &record_id, 1);
        }
        let slot = record
            .get("entity")
            .and_then(|entity| entity.get("slot"))
            .or_else(|| record.get("entitySlot"))
            .and_then(WireValue::as_utf16);
        if let Some(slot) = slot {
            let hash_input = format!("{id}:entity:{}", String::from_utf16_lossy(slot));
            let entity_id = base64url(&sha256(hash_input.as_bytes()));
            state = replace_produced_entity(&state, slot, &entity_id);
        }
    }
    Ok(state)
}
fn fixture_auth(value: &WireValue) -> Result<crate::interpreter::InterpreterAuth, ClosureError> {
    let roles = |name| -> Result<Vec<Vec<u16>>, ClosureError> {
        let WireValue::Array(values) = field(value, name)? else {
            return Err(ClosureError::Invalid);
        };
        values
            .iter()
            .map(|value| {
                value
                    .as_utf16()
                    .map(<[u16]>::to_vec)
                    .ok_or(ClosureError::Invalid)
            })
            .collect()
    };
    Ok(crate::interpreter::InterpreterAuth {
        actor_id: scalar(field(value, "actorId")?)?,
        workspace_roles: roles("workspaceRoles")?,
        protocol_roles: roles("protocolRoles")?,
        capabilities: roles("capabilities")?,
    })
}
fn sequence_fixture_matches(
    manifest: &WireValue,
    fixture: &WireValue,
    id: &str,
) -> Result<FixtureCheck, ClosureError> {
    if field(fixture, "kind")?.as_string().as_deref() != Some("sequence") {
        return Err(ClosureError::Invalid);
    }
    let WireValue::Array(steps) = field(fixture, "steps")? else {
        return Err(ClosureError::Invalid);
    };
    if steps.is_empty() || steps.len() > 32 {
        return Err(ClosureError::Invalid);
    }
    let mut state = merged_state(field(manifest, "initial_state")?, field(fixture, "state")?);
    let mut refs: HashMap<String, crate::interpreter::ResolvedInput> = HashMap::new();
    let mut rejections = Vec::new();
    let action_manifest = WireValue::Object(vec![(
        "actions".encode_utf16().collect(),
        field(manifest, "actions")?.clone(),
    )]);
    for (index, step) in steps.iter().enumerate() {
        let body = replace_fixture_refs(field(step, "body")?, &refs, false)?;
        let WireValue::Array(input_names) = field(step, "exact_inputs")? else {
            return Err(ClosureError::Invalid);
        };
        let exact_inputs = input_names
            .iter()
            .map(|name| {
                refs.get(&scalar(name)?)
                    .cloned()
                    .ok_or(ClosureError::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let auth = fixture_auth(field(step, "auth")?)?;
        crate::full_manifest::validate_state_array_state(manifest, &state)
            .map_err(|_| ClosureError::Invalid)?;
        let result = crate::interpreter::evaluate_action(
            &action_manifest,
            field(step, "action_id")?
                .as_utf16()
                .ok_or(ClosureError::Invalid)?,
            &state,
            &body,
            &auth,
            &exact_inputs,
            step.get("time_ms").map(safe_integer).transpose()?,
        );
        let expected = field(step, "expected")?;
        match result {
            Err(error) => {
                rejections.push(error.to_string());
                if !exact(expected, &["accepted", "code"])
                    || !matches!(expected.get("accepted"), Some(WireValue::Bool(false)))
                    || expected
                        .get("code")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        != Some(&error.to_string())
                {
                    return Ok(FixtureCheck {
                        passed: false,
                        rejections,
                    });
                }
            }
            Ok(observed) => {
                let mut next_refs = refs.clone();
                let mut next_state = observed.next_state.clone();
                let WireValue::Array(bindings) = field(step, "bind_refs")? else {
                    return Err(ClosureError::Invalid);
                };
                for binding in bindings {
                    let name = scalar(field(binding, "name")?)?;
                    if next_refs.contains_key(&name) {
                        return Err(ClosureError::Invalid);
                    }
                    let slot = scalar(field(binding, "record_slot")?)?;
                    let record = observed
                        .records
                        .iter()
                        .find(|record| {
                            record
                                .get("recordSlot")
                                .and_then(WireValue::as_string)
                                .as_deref()
                                == Some(&slot)
                        })
                        .ok_or(ClosureError::Invalid)?;
                    let record_id = base64url(&sha256(format!("{id}:{index}:{name}").as_bytes()));
                    let mut revision = 1;
                    let mut entity_id = None;
                    if let Some(entity) = record.get("entity") {
                        match field(entity, "mode")?.as_string().as_deref() {
                            Some("new") => {
                                let entity_slot = scalar(field(entity, "slot")?)?;
                                entity_id = Some(base64url(&sha256(
                                    format!("{id}:{index}:{entity_slot}").as_bytes(),
                                )));
                            }
                            Some("revise") => {
                                let parent = field(entity, "parent")?;
                                let parent_id = scalar(field(parent, "recordId")?)?;
                                let parent_rev = safe_integer(field(parent, "revision")?)?;
                                let parent_input = next_refs
                                    .values()
                                    .find(|reference| {
                                        reference.record_id == parent_id
                                            && reference.revision == parent_rev
                                    })
                                    .ok_or(ClosureError::Invalid)?;
                                entity_id = Some(
                                    parent_input
                                        .entity_id
                                        .clone()
                                        .ok_or(ClosureError::Invalid)?,
                                );
                                revision = parent_rev
                                    .checked_add(1)
                                    .filter(|value| *value <= 9_007_199_254_740_991)
                                    .ok_or(ClosureError::Invalid)?;
                            }
                            _ => return Err(ClosureError::Invalid),
                        }
                    }
                    next_refs.insert(
                        name.clone(),
                        crate::interpreter::ResolvedInput {
                            record_id: record_id.clone(),
                            revision,
                            schema: field(record, "schema")?
                                .as_utf16()
                                .ok_or(ClosureError::Invalid)?
                                .to_vec(),
                            payload: field(record, "payload")?.clone(),
                            scope: "INSTANCE".to_owned(),
                            entity_id,
                        },
                    );
                    next_state = replace_produced_record(
                        &next_state,
                        &slot.encode_utf16().collect::<Vec<_>>(),
                        &record_id,
                        revision,
                    );
                }
                next_state = resolve_sequence_output_state(
                    manifest,
                    &observed.records,
                    &format!("{id}:{index}"),
                    next_state,
                )?;
                crate::full_manifest::validate_state_array_state(manifest, &next_state)
                    .map_err(|_| ClosureError::Invalid)?;
                refs = next_refs;
                state = next_state.clone();
                let expected = replace_fixture_refs(expected, &refs, true)?;
                if !accepted_result_matches(&expected, observed, next_state)? {
                    return Ok(FixtureCheck {
                        passed: false,
                        rejections,
                    });
                }
            }
        }
    }
    Ok(FixtureCheck {
        passed: true,
        rejections,
    })
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
    let mut output_names = HashSet::new();
    for output in outputs {
        let name = scalar(field(output, "name")?)?;
        if !output_names.insert(name) {
            return Err(ClosureError::Invalid);
        }
        let output_type = scalar(field(output, "type")?)?;
        if output_type != "exact_ref" && output_type != "actor_id" {
            return Err(ClosureError::Invalid);
        }
        crate::interpreter::validate_guard(field(output, "available_when")?, 0, &[])
            .map_err(|_| ClosureError::Invalid)?;
        let selector = field(output, "selector")?;
        match scalar(field(selector, "from")?)?.as_str() {
            "state" => {
                let WireValue::Array(path) = field(selector, "path")? else {
                    return Err(ClosureError::Invalid);
                };
                if path.is_empty() || path.len() > 12 {
                    return Err(ClosureError::Invalid);
                }
                let mut selected = field(&manifest, "initial_state")?;
                for segment in path {
                    selected = field(selected, &scalar(segment)?)?;
                }
                let _ = selected;
                if output_type == "exact_ref" {
                    let schema = scalar(field(output, "schema")?)?;
                    field(field(&manifest, "record_schemas")?, &schema)?;
                    let scope = scalar(field(output, "scope")?)?;
                    if scope != "INSTANCE" && scope != "WORKSPACE" {
                        return Err(ClosureError::Invalid);
                    }
                }
            }
            "import" => {
                let alias = scalar(field(selector, "alias")?)?;
                let WireValue::Array(imports) = field(source, "imports")? else {
                    return Err(ClosureError::Invalid);
                };
                if !imports.iter().any(|import| {
                    import
                        .get("alias")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some(&alias)
                }) {
                    return Err(ClosureError::Invalid);
                }
                scalar(field(selector, "output")?)?;
            }
            _ => return Err(ClosureError::Invalid),
        }
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
pub(crate) fn compile_package_material(
    closure: &ScannedPackageClosure,
    bindings: &WireValue,
) -> Result<SimpleCompilation, ClosureError> {
    // The exact release lock is independently checked at its baseline before
    // any caller-supplied binding is allowed to produce a retained protocol.
    compile_simple_baseline(closure)?;
    let compiled = compile_at(closure, &closure.root, Some(bindings), false, 0, &mut 0)?;
    if let Some(requirements) = compiled.manifest.get("execution_requirements") {
        let WireValue::Array(ports) = field(requirements, "ports")? else {
            return Err(ClosureError::Invalid);
        };
        if ports.iter().any(|port| {
            port.get("required") == Some(&WireValue::Bool(true))
                && port.get("bound") != Some(&WireValue::Bool(true))
        }) {
            return Err(ClosureError::Mismatch);
        }
    }
    Ok(compiled)
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
fn import_symbol_mappings(
    source: &WireValue,
    alias: &str,
    namespace: &str,
    dependency: &WireValue,
) -> Result<(HashMap<Vec<u16>, Vec<u16>>, HashMap<Vec<u16>, Vec<u16>>), ClosureError> {
    let mut roles = HashMap::new();
    let mut capabilities = HashMap::new();
    for (source_key, manifest_key, member_key, output) in [
        ("role_mappings", "protocol_roles", "role", &mut roles),
        (
            "capability_mappings",
            "capabilities",
            "capability",
            &mut capabilities,
        ),
    ] {
        let Some(WireValue::Array(rows)) = source.get(source_key) else {
            continue;
        };
        let WireValue::Array(declared) = field(dependency, manifest_key)? else {
            return Err(ClosureError::Invalid);
        };
        let WireValue::Array(parent_declared) = field(field(source, "manifest")?, manifest_key)?
        else {
            return Err(ClosureError::Invalid);
        };
        for row in rows {
            if field(field(row, "from")?, "import")?.as_string().as_deref() != Some(alias) {
                continue;
            }
            let original = field(field(row, "from")?, member_key)?
                .as_utf16()
                .ok_or(ClosureError::Invalid)?;
            let target = field(row, "to")?.as_utf16().ok_or(ClosureError::Invalid)?;
            if !declared
                .iter()
                .any(|candidate| candidate.as_utf16() == Some(original))
                || !parent_declared
                    .iter()
                    .any(|candidate| candidate.as_utf16() == Some(target))
            {
                return Err(ClosureError::Invalid);
            }
            let mut qualified = namespace.encode_utf16().collect::<Vec<_>>();
            qualified.push('.' as u16);
            qualified.extend_from_slice(original);
            if output.insert(qualified, target.to_vec()).is_some() {
                return Err(ClosureError::Invalid);
            }
        }
    }
    Ok((roles, capabilities))
}
fn qualified_fixture_text(
    value: &WireValue,
    namespace: &str,
    max: usize,
) -> Result<WireValue, ClosureError> {
    let original = value.as_utf16().ok_or(ClosureError::Invalid)?;
    let mut joined = namespace.encode_utf16().collect::<Vec<_>>();
    joined.push('.' as u16);
    joined.extend_from_slice(original);
    if joined.len() > max {
        return Err(ClosureError::Resource);
    }
    Ok(WireValue::String(joined))
}
fn mapped_fixture_symbol(
    value: &WireValue,
    namespace: &str,
    mappings: &HashMap<Vec<u16>, Vec<u16>>,
) -> Result<WireValue, ClosureError> {
    let qualified = qualified_fixture_text(value, namespace, 120)?;
    if let WireValue::String(units) = &qualified {
        if let Some(mapped) = mappings.get(units) {
            return Ok(WireValue::String(mapped.clone()));
        }
    }
    Ok(qualified)
}
fn transform_fixture_auth(
    auth: &mut WireValue,
    namespace: &str,
    roles: &HashMap<Vec<u16>, Vec<u16>>,
    capabilities: &HashMap<Vec<u16>, Vec<u16>>,
) -> Result<(), ClosureError> {
    for (key, mappings) in [("protocolRoles", roles), ("capabilities", capabilities)] {
        let WireValue::Array(values) = field_mut(auth, key)? else {
            return Err(ClosureError::Invalid);
        };
        for value in values {
            *value = mapped_fixture_symbol(value, namespace, mappings)?;
        }
    }
    Ok(())
}
fn transform_fixture_expected(
    expected: &mut WireValue,
    namespace: &str,
) -> Result<(), ClosureError> {
    if let Some(WireValue::Object(_)) = expected.get("state") {
        let state = field(expected, "state")?.clone();
        insert_field(
            expected,
            "state",
            WireValue::Object(vec![(namespace.encode_utf16().collect(), state)]),
        )?;
    }
    if let Some(WireValue::Array(records)) = expected.get("records") {
        let mut records = records.clone();
        for record in &mut records {
            let schema = qualified_fixture_text(field(record, "schema")?, namespace, 80)?;
            insert_field(record, "schema", schema)?;
            if let Some(WireValue::Array(relations)) = record.get("relations") {
                let mut relations = relations.clone();
                for relation in &mut relations {
                    let kind = qualified_fixture_text(field(relation, "kind")?, namespace, 80)?;
                    insert_field(relation, "kind", kind)?;
                }
                insert_field(record, "relations", WireValue::Array(relations))?;
            }
        }
        insert_field(expected, "records", WireValue::Array(records))?;
    }
    if let Some(effects) = expected.get("revisionEffects") {
        let mut effects = effects.clone();
        let WireValue::Array(entities) = field_mut(&mut effects, "contentEntities")? else {
            return Err(ClosureError::Invalid);
        };
        for entity in entities {
            *entity = qualified_fixture_text(entity, namespace, 120)?;
        }
        insert_field(expected, "revisionEffects", effects)?;
    }
    Ok(())
}
fn transform_inherited_fixture(
    mut scenario: FixtureScenario,
    alias: &str,
    namespace: &str,
    roles: &HashMap<Vec<u16>, Vec<u16>>,
    capabilities: &HashMap<Vec<u16>, Vec<u16>>,
) -> Result<FixtureScenario, ClosureError> {
    scenario.id = format!("{alias}/{}", scenario.id);
    scenario.import_path.insert(0, alias.to_owned());
    let fixture = &mut scenario.fixture;
    if let Some(WireValue::Object(_)) = fixture.get("state") {
        let state = field(fixture, "state")?.clone();
        insert_field(
            fixture,
            "state",
            WireValue::Object(vec![(namespace.encode_utf16().collect(), state)]),
        )?;
    }
    if fixture.get("kind").is_some() {
        let WireValue::Array(steps) = field_mut(fixture, "steps")? else {
            return Err(ClosureError::Invalid);
        };
        for step in steps {
            let action = qualified_fixture_text(field(step, "action_id")?, namespace, 120)?;
            insert_field(step, "action_id", action)?;
            transform_fixture_auth(field_mut(step, "auth")?, namespace, roles, capabilities)?;
            transform_fixture_expected(field_mut(step, "expected")?, namespace)?;
        }
    } else {
        let action = qualified_fixture_text(field(fixture, "action_id")?, namespace, 120)?;
        insert_field(fixture, "action_id", action)?;
        transform_fixture_auth(field_mut(fixture, "auth")?, namespace, roles, capabilities)?;
        let WireValue::Array(inputs) = field_mut(fixture, "exact_inputs")? else {
            return Err(ClosureError::Invalid);
        };
        for input in inputs {
            let schema = qualified_fixture_text(field(input, "schema")?, namespace, 80)?;
            insert_field(input, "schema", schema)?;
        }
        transform_fixture_expected(field_mut(fixture, "expected")?, namespace)?;
    }
    Ok(scenario)
}
fn parse_local_dispositions(source: &WireValue) -> Result<Vec<FixtureDisposition>, ClosureError> {
    let Some(WireValue::Array(rows)) = source.get("fixture_dispositions") else {
        return Ok(vec![]);
    };
    let mut parsed = Vec::new();
    let mut origins = HashSet::new();
    for row in rows {
        let origin = field(row, "origin")?;
        let origin_package_digest = scalar(field(origin, "package_digest")?)?;
        let WireValue::Array(path) = field(origin, "import_path")? else {
            return Err(ClosureError::Invalid);
        };
        let import_path = path.iter().map(scalar).collect::<Result<Vec<_>, _>>()?;
        let fixture_id = scalar(field(origin, "fixture_id")?)?;
        if !origins.insert((
            origin_package_digest.clone(),
            import_path.clone(),
            fixture_id.clone(),
        )) {
            return Err(ClosureError::Invalid);
        }
        parsed.push(FixtureDisposition {
            origin_package_digest,
            import_path,
            fixture_id,
            expected_rejection: scalar(field(row, "expected_rejection")?)?,
            replacement_id: scalar(field(row, "replacement_scenario_id")?)?,
        });
    }
    Ok(parsed)
}
fn check_fixture_dispositions(
    scenarios: &[FixtureScenario],
    checks: &mut [FixtureCheck],
    dispositions: &[FixtureDisposition],
) -> Result<(), ClosureError> {
    let mut used = HashSet::new();
    for disposition in dispositions {
        let matches = scenarios
            .iter()
            .enumerate()
            .filter(|(_, scenario)| {
                scenario.origin_package_digest == disposition.origin_package_digest
                    && scenario.import_path == disposition.import_path
                    && scenario
                        .fixture
                        .get("id")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some(&disposition.fixture_id)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(ClosureError::Invalid);
        }
        let index = matches[0];
        if !used.insert(index)
            || checks[index].passed
            || !checks[index]
                .rejections
                .contains(&disposition.expected_rejection)
        {
            return Err(ClosureError::Mismatch);
        }
        let replacement = scenarios
            .iter()
            .enumerate()
            .find(|(_, scenario)| scenario.id == disposition.replacement_id)
            .map(|(index, _)| index)
            .ok_or(ClosureError::Mismatch)?;
        if replacement == index || !checks[replacement].passed {
            return Err(ClosureError::Mismatch);
        }
        checks[index].passed = true;
    }
    if checks.iter().any(|check| !check.passed) {
        return Err(ClosureError::Mismatch);
    }
    Ok(())
}
fn resolve_source_output(
    closure: &ScannedPackageClosure,
    package_digest: &str,
    source: &WireValue,
    values: &WireValue,
    name: &str,
    seen: &mut HashSet<(String, String)>,
    depth: usize,
) -> Result<ResolvedOutput, ClosureError> {
    if depth > 16 || !seen.insert((package_digest.to_owned(), name.to_owned())) {
        return Err(ClosureError::Cycle);
    }
    let WireValue::Array(outputs) = field(field(source, "interfaces")?, "outputs")? else {
        return Err(ClosureError::Invalid);
    };
    let output = outputs
        .iter()
        .find(|row| row.get("name").and_then(WireValue::as_string).as_deref() == Some(name))
        .ok_or(ClosureError::Invalid)?;
    let kind = scalar(field(output, "type")?)?;
    let selector = field(output, "selector")?;
    match field(selector, "from")?.as_string().as_deref() {
        Some("state") => {
            let WireValue::Array(path) = field(selector, "path")? else {
                return Err(ClosureError::Invalid);
            };
            Ok(ResolvedOutput {
                kind,
                path: path.clone(),
                schema: output.get("schema").map(scalar).transpose()?,
                scope: output.get("scope").map(scalar).transpose()?,
                available: field(output, "available_when")?.clone(),
            })
        }
        Some("import") => {
            let alias = scalar(field(selector, "alias")?)?;
            let forwarded_name = scalar(field(selector, "output")?)?;
            let WireValue::Array(imports) = field(source, "imports")? else {
                return Err(ClosureError::Invalid);
            };
            let imported = imports
                .iter()
                .find(|row| {
                    row.get("alias").and_then(WireValue::as_string).as_deref() == Some(&alias)
                })
                .ok_or(ClosureError::Missing)?;
            let digest = scalar(field(imported, "package_digest")?)?;
            let namespace = scalar(field(imported, "namespace")?)?;
            let bundle = closure.packages.get(&digest).ok_or(ClosureError::Missing)?;
            let files = field(bundle, "files")?;
            let child_source = source_file(files)?;
            let child_lock = lock_file(files)?;
            let supplied = mapped_import_values(source, values, &alias, &child_source)?;
            let baseline = matches!(&supplied, WireValue::Object(fields) if fields.is_empty());
            let chosen = if baseline {
                field(&child_lock, "baseline_bindings")?
            } else {
                &supplied
            };
            let child_values = parameter_values(&child_source, chosen)?;
            let mut compile_steps = 0usize;
            let compiled = compile_at(
                closure,
                &digest,
                if baseline { None } else { Some(&supplied) },
                baseline,
                depth + 1,
                &mut compile_steps,
            )?;
            let inner = resolve_source_output(
                closure,
                &digest,
                &child_source,
                &child_values,
                &forwarded_name,
                seen,
                depth + 1,
            )?;
            if inner.kind != kind {
                return Err(ClosureError::Mismatch);
            }
            let schema = inner.schema.map(|schema| format!("{namespace}.{schema}"));
            if kind == "exact_ref"
                && (output.get("scope").map(scalar).transpose()? != inner.scope
                    || output.get("schema").map(scalar).transpose()? != schema)
            {
                return Err(ClosureError::Mismatch);
            }
            let (roles, capabilities) =
                import_symbol_mappings(source, &alias, &namespace, &compiled.manifest)?;
            let nested_available = crate::package_namespace::namespace_guard(
                &inner.available,
                &namespace,
                &roles,
                &capabilities,
            )
            .map_err(|_| ClosureError::Invalid)?;
            Ok(ResolvedOutput {
                kind,
                path: std::iter::once(WireValue::String(namespace.encode_utf16().collect()))
                    .chain(inner.path)
                    .collect(),
                schema,
                scope: inner.scope,
                available: WireValue::Object(vec![
                    (
                        "op".encode_utf16().collect(),
                        WireValue::String("and".encode_utf16().collect()),
                    ),
                    (
                        "rules".encode_utf16().collect(),
                        WireValue::Array(vec![
                            field(output, "available_when")?.clone(),
                            nested_available,
                        ]),
                    ),
                ]),
            })
        }
        _ => Err(ClosureError::Invalid),
    }
}
fn apply_connections(
    closure: &ScannedPackageClosure,
    source: &WireValue,
    units: &mut HashMap<String, ImportedUnit>,
) -> Result<(), ClosureError> {
    let Some(WireValue::Array(rows)) = source.get("connections") else {
        return Ok(());
    };
    fn text(value: &str) -> WireValue {
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
    fn state_paths(value: &WireValue, paths: &mut Vec<WireValue>) {
        match value {
            WireValue::Array(rows) => {
                for row in rows {
                    state_paths(row, paths);
                }
            }
            WireValue::Object(fields) => {
                let is_state = value.get("from").and_then(WireValue::as_string).as_deref()
                    == Some("state")
                    || value.get("from").and_then(WireValue::as_string).as_deref() == Some("ref")
                        && value
                            .get("source")
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some("state")
                    || value.get("op").and_then(WireValue::as_string).as_deref()
                        == Some("exact_ref_list")
                        && value
                            .get("source")
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some("state");
                if is_state {
                    if let Some(path) = value.get("path") {
                        paths.push(path.clone());
                    }
                }
                for (_, child) in fields {
                    state_paths(child, paths);
                }
            }
            _ => {}
        }
    }
    let mut target_ports = HashSet::new();
    for connection in rows {
        let from = field(connection, "from")?;
        let to = field(connection, "to")?;
        let from_alias = scalar(field(from, "import")?)?;
        let to_alias = scalar(field(to, "import")?)?;
        let output_name = scalar(field(from, "output")?)?;
        let action_name = scalar(field(to, "action")?)?;
        let variant_index = safe_integer(field(to, "variant")?)? as usize;
        let input_name = scalar(field(to, "input")?)?;
        if !target_ports.insert((
            to_alias.clone(),
            action_name.clone(),
            variant_index,
            input_name.clone(),
        )) {
            return Err(ClosureError::Invalid);
        }
        let provider = units.get(&from_alias).ok_or(ClosureError::Missing)?;
        let WireValue::Array(outputs) = field(field(&provider.source, "interfaces")?, "outputs")?
        else {
            return Err(ClosureError::Invalid);
        };
        let output = outputs
            .iter()
            .find(|row| {
                row.get("name").and_then(WireValue::as_string).as_deref() == Some(&output_name)
            })
            .ok_or(ClosureError::Invalid)?;
        let declared_type = scalar(field(output, "type")?)?;
        let resolved = resolve_source_output(
            closure,
            &provider.package_digest,
            &provider.source,
            &provider.values,
            &output_name,
            &mut HashSet::new(),
            0,
        )?;
        if declared_type != resolved.kind {
            return Err(ClosureError::Mismatch);
        }
        let output_type = resolved.kind;
        let output_scope = resolved.scope;
        let output_schema = resolved.schema;
        let output_path = WireValue::Array(
            std::iter::once(text(&provider.namespace))
                .chain(resolved.path)
                .collect(),
        );
        let output_schema =
            output_schema.map(|schema| format!("{}.{}", provider.namespace, schema));
        let available = crate::package_namespace::namespace_guard(
            &resolved.available,
            &provider.namespace,
            &provider.roles,
            &provider.capabilities,
        )
        .map_err(|_| ClosureError::Invalid)?;
        let consumer = units.get_mut(&to_alias).ok_or(ClosureError::Missing)?;
        let WireValue::Array(inputs) = field(field(&consumer.source, "interfaces")?, "inputs")?
        else {
            return Err(ClosureError::Invalid);
        };
        let input = inputs
            .iter()
            .find(|row| {
                row.get("action").and_then(WireValue::as_string).as_deref() == Some(&action_name)
                    && row.get("name").and_then(WireValue::as_string).as_deref()
                        == Some(&input_name)
                    && row.get("variant").and_then(WireValue::as_number)
                        == Some(variant_index as f64)
            })
            .ok_or(ClosureError::Invalid)?;
        let input_type = scalar(field(input, "type")?)?;
        if input_type != output_type {
            return Err(ClosureError::Mismatch);
        }
        let WireValue::Array(body_path) = field(input, "body_path")? else {
            return Err(ClosureError::Invalid);
        };
        if body_path.len() != 1 {
            return Err(ClosureError::Invalid);
        }
        let body_field = scalar(&body_path[0])?;
        let action_id = format!("{}.{}", consumer.namespace, action_name);
        let WireValue::Array(actions) = field_mut(&mut consumer.manifest, "actions")? else {
            return Err(ClosureError::Invalid);
        };
        let action = actions
            .iter_mut()
            .find(|row| row.get("id").and_then(WireValue::as_string).as_deref() == Some(&action_id))
            .ok_or(ClosureError::Invalid)?;
        let mut guards = Vec::new();
        if input_type == "exact_ref" {
            let scope = output_scope.clone().ok_or(ClosureError::Invalid)?;
            let schema = output_schema.clone().ok_or(ClosureError::Invalid)?;
            let runtime_field = field_mut(
                field_mut(field_mut(action, "inputs")?, "fields")?,
                &body_field,
            )?;
            if field(input, "scope")?.as_string().as_deref() != Some(&scope)
                || field(runtime_field, "type")?.as_string().as_deref() != Some("exact_ref")
                || field(runtime_field, "schema")?.as_string().as_deref() != Some("*")
            {
                return Err(ClosureError::Mismatch);
            }
            insert_field(runtime_field, "schema", text(&schema))?;
            let body_ref = object(vec![
                ("from", text("ref")),
                ("source", text("body")),
                ("path", WireValue::Array(body_path.clone())),
                ("scope", text(&scope)),
                ("schema", text(&schema)),
            ]);
            let state_ref = object(vec![
                ("from", text("ref")),
                ("source", text("state")),
                ("path", output_path.clone()),
                ("scope", text(&scope)),
                ("schema", text(&schema)),
            ]);
            guards.push(object(vec![
                ("op", text("exact_ref")),
                ("ref", body_ref.clone()),
            ]));
            guards.push(object(vec![
                ("op", text("eq")),
                ("left", body_ref),
                ("right", state_ref),
            ]));
        } else if input_type == "actor_id" {
            let runtime_field = field_mut(
                field_mut(field_mut(action, "inputs")?, "fields")?,
                &body_field,
            )?;
            if field(runtime_field, "type")?.as_string().as_deref() != Some("actor_id") {
                return Err(ClosureError::Mismatch);
            }
            let body_actor = object(vec![
                ("from", text("body")),
                ("path", WireValue::Array(body_path.clone())),
            ]);
            let state_actor = object(vec![("from", text("state")), ("path", output_path.clone())]);
            let auth_actor = object(vec![("from", text("auth")), ("field", text("actorId"))]);
            guards.push(object(vec![
                ("op", text("eq")),
                ("left", body_actor.clone()),
                ("right", state_actor),
            ]));
            let relation = scalar(field(input, "relation")?)?;
            let same = object(vec![
                ("op", text("eq")),
                ("left", body_actor),
                ("right", auth_actor),
            ]);
            guards.push(if relation == "same_actor" {
                same
            } else if relation == "different_actor" {
                object(vec![("op", text("not")), ("rule", same)])
            } else {
                return Err(ClosureError::Invalid);
            });
        } else {
            return Err(ClosureError::Invalid);
        }
        guards.push(object(vec![
            ("op", text("and")),
            ("rules", WireValue::Array(vec![available.clone()])),
        ]));
        let WireValue::Array(variants) = field_mut(action, "variants")? else {
            return Err(ClosureError::Invalid);
        };
        let variant = variants
            .get_mut(variant_index)
            .ok_or(ClosureError::Invalid)?;
        let WireValue::Array(when) = field_mut(variant, "when")? else {
            return Err(ClosureError::Invalid);
        };
        when.extend(guards);
        if let Some(hook) = input.get("provenance_hook") {
            if input_type != "exact_ref" {
                return Err(ClosureError::Invalid);
            }
            let slot = scalar(field(hook, "record_slot")?)?;
            let schema = format!(
                "{}.{}",
                consumer.namespace,
                scalar(field(hook, "record_schema")?)?
            );
            let kind = format!(
                "{}.{}",
                consumer.namespace,
                scalar(field(hook, "relation_kind")?)?
            );
            let WireValue::Array(effects) = field_mut(variant, "effects")? else {
                return Err(ClosureError::Invalid);
            };
            let matching = effects
                .iter()
                .enumerate()
                .filter(|(_, effect)| {
                    effect.get("op").and_then(WireValue::as_string).as_deref() == Some("append")
                        && effect
                            .get("recordSlot")
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some(&slot)
                        && effect
                            .get("schema")
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some(&schema)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(ClosureError::Mismatch);
            }
            let append = effects.get_mut(matching[0]).ok_or(ClosureError::Invalid)?;
            let WireValue::Array(relations) = field_mut(append, "relations")? else {
                return Err(ClosureError::Invalid);
            };
            if relations.iter().any(|relation| {
                relation
                    .get("kind")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&kind)
            }) {
                return Err(ClosureError::Mismatch);
            }
            relations.push(object(vec![
                ("kind", text(&kind)),
                (
                    "target",
                    object(vec![
                        ("from", text("ref")),
                        ("source", text("body")),
                        ("path", WireValue::Array(body_path.clone())),
                        (
                            "scope",
                            text(output_scope.as_deref().ok_or(ClosureError::Invalid)?),
                        ),
                        (
                            "schema",
                            text(output_schema.as_deref().ok_or(ClosureError::Invalid)?),
                        ),
                    ]),
                ),
            ]));
        }
        let WireValue::Array(reads) = field_mut(action, "reads")? else {
            return Err(ClosureError::Invalid);
        };
        let mut extra = vec![output_path];
        state_paths(&available, &mut extra);
        for path in extra {
            if !reads.contains(&path) {
                reads.push(path);
            }
        }
    }
    Ok(())
}
// ECMAScript OwnPropertyKeys: integer indices first; other strings retain insertion.
fn schema_enumeration(manifest: &WireValue) -> Result<Vec<Vec<u16>>, ClosureError> {
    let WireValue::Object(fields) = field(manifest, "record_schemas")? else { return Err(ClosureError::Invalid); };
    let index = |name: &[u16]| -> Option<u32> {
        let text = String::from_utf16(name).ok()?;
        let value = text.parse::<u32>().ok()?;
        (value != u32::MAX && value.to_string() == text).then_some(value)
    };
    let mut names = fields.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>();
    names.sort_by(|a,b| match (index(a), index(b)) {
        (Some(a), Some(b)) => a.cmp(&b), (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater, (None, None) => std::cmp::Ordering::Equal,
    });
    Ok(names)
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
    let source = source_file(files)?;
    let release = lock_file(files)?;
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
                    && ["outputs", "inputs", "action_bodies"].iter().all(|key| matches!(interfaces.get(key), Some(WireValue::Array(_))))))
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
    let mut schema_orders = std::collections::BTreeMap::new();
    let own_schema_order = schema_enumeration(&raw_manifest)?;
    let mut dependency_ids = Vec::new();
    let mut inherited_ports = Vec::new();
    let mut imported_units = HashMap::<String, ImportedUnit>::new();
    let mut scenarios = Vec::new();
    let mut inherited_dispositions = Vec::new();
    for imported in imports {
        let digest = scalar(field(imported, "package_digest")?)?;
        let alias = scalar(field(imported, "alias")?)?;
        let namespace = scalar(field(imported, "namespace")?)?;
        let dependency_bundle = closure.packages.get(&digest).ok_or(ClosureError::Missing)?;
        let dependency_source = source_file(field(dependency_bundle, "files")?)?;
        let baseline = compile_at(closure, &digest, None, true, depth + 1, steps)?;
        let mapped = mapped_import_values(&source, &values, &alias, &dependency_source)?;
        let dependency_lock = lock_file(field(dependency_bundle, "files")?)?;
        let baseline_values = if matches!(&mapped, WireValue::Object(fields) if fields.is_empty()) {
            field(&dependency_lock, "baseline_bindings")?
        } else {
            &mapped
        };
        let dependency_values = parameter_values(&dependency_source, baseline_values)?;
        let compiled = if matches!(&mapped, WireValue::Object(fields) if fields.is_empty()) {
            baseline
        } else {
            compile_at(closure, &digest, Some(&mapped), false, depth + 1, steps)?
        };
        let namespaced =
            crate::package_namespace::namespace_manifest(&compiled.manifest, &namespace, &alias)
                .map_err(|_| ClosureError::Invalid)?;
        let (roles, capabilities) =
            import_symbol_mappings(&source, &alias, &namespace, &compiled.manifest)?;
        let namespaced =
            crate::package_namespace::map_namespaced_symbols(namespaced, &roles, &capabilities)
                .map_err(|_| ClosureError::Invalid)?;
        for scenario in compiled.scenarios.iter().cloned() {
            scenarios.push(transform_inherited_fixture(
                scenario,
                &alias,
                &namespace,
                &roles,
                &capabilities,
            )?);
        }
        for mut disposition in compiled.dispositions.iter().cloned() {
            disposition.import_path.insert(0, alias.clone());
            disposition.replacement_id = format!("{alias}/{}", disposition.replacement_id);
            inherited_dispositions.push(disposition);
        }
        if imported_units
            .insert(
                alias,
                ImportedUnit {
                    package_digest: digest,
                    namespace: namespace.clone(),
                    source: dependency_source,
                    values: dependency_values,
                    manifest: namespaced,
                    schema_order: compiled.schema_order.iter().map(|name| {
                        let mut qualified = namespace.encode_utf16().collect::<Vec<_>>();
                        qualified.push(u16::from(b'.')); qualified.extend(name); qualified
                    }).collect(),
                    roles,
                    capabilities,
                },
            )
            .is_some()
        {
            return Err(ClosureError::Mismatch);
        }
    }
    apply_connections(closure, &source, &mut imported_units)?;
    for imported in imports {
        let alias = scalar(field(imported, "alias")?)?;
        let unit = imported_units.get(&alias).ok_or(ClosureError::Invalid)?;
        if let Some(requirements) = unit.manifest.get("execution_requirements") {
            let WireValue::Array(ports) = field(requirements, "ports")? else {
                return Err(ClosureError::Invalid);
            };
            for port in ports {
                let mut inherited = port.clone();
                if let Some(WireValue::Array(connections)) = source.get("connections") {
                    let direct = matches!(port.get("import_path"), Some(WireValue::Array(path)) if path.len()==1 && path[0].as_string().as_deref()==Some(&alias));
                    if direct
                        && connections.iter().any(|row| {
                            let Some(to) = row.get("to") else {
                                return false;
                            };
                            to.get("import").and_then(WireValue::as_string).as_deref()
                                == Some(&alias)
                                && to
                                    .get("action")
                                    .and_then(WireValue::as_string)
                                    .map(|action| format!("{}.{}", unit.namespace, action))
                                    == port.get("action_id").and_then(WireValue::as_string)
                                && to.get("variant") == port.get("variant")
                                && to.get("input") == port.get("input_name")
                        })
                    {
                        insert_field(&mut inherited, "bound", WireValue::Bool(true))?;
                    }
                }
                inherited_ports.push(inherited);
            }
        }
        let checked = crate::full_manifest::validate_full_manifest(&unit.manifest)
            .map_err(|_| ClosureError::Invalid)?;
        let digest = sha256_hex(checked.as_bytes());
        if nodes
            .insert(digest.encode_utf16().collect(), unit.manifest.clone())
            .is_some()
        {
            return Err(ClosureError::Mismatch);
        }
        schema_orders.insert(digest.encode_utf16().collect::<Vec<_>>(), unit.schema_order.clone());
        dependency_ids.push(WireValue::String(digest.encode_utf16().collect()));
    }
    let mut root = raw_manifest;
    *field_mut(&mut root, "dependencies")? = WireValue::Array(dependency_ids);
    apply_derivations(&source, &mut root, &nodes)?;
    if v2 {
        inherited_ports.extend(own_ports);
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
                    WireValue::Array(inherited_ports),
                ),
            ]),
        )?;
    }
    let (manifest, dependency_closure) =
        crate::protocol_composition::resolve_protocol(&root, &nodes)
            .map_err(|_| ClosureError::Invalid)?;
    let composition = if dependency_closure.is_empty() {
        None
    } else {
        let source_canonical = crate::full_manifest::validate_full_manifest(&root)
            .map_err(|_| ClosureError::Invalid)?;
        let source_wrapped = parse_wire_json_bounded(source_canonical.as_bytes(), 64, 2_000_000)
            .map_err(|_| ClosureError::Invalid)?;
        let source_manifest = field(&source_wrapped, "manifest")?.clone();
        let mut dependencies = Vec::with_capacity(dependency_closure.len());
        for id in dependency_closure {
            let manifest = nodes.get(&id).ok_or(ClosureError::Missing)?.clone();
            dependencies.push(WireValue::Object(vec![
                ("digest".encode_utf16().collect(), WireValue::String(id)),
                ("manifest".encode_utf16().collect(), manifest),
            ]));
        }
        Some(WireValue::Object(vec![
            ("v".encode_utf16().collect(), WireValue::Number(1.0)),
            (
                "source_digest".encode_utf16().collect(),
                WireValue::String(
                    sha256_hex(source_canonical.as_bytes())
                        .encode_utf16()
                        .collect(),
                ),
            ),
            ("source_manifest".encode_utf16().collect(), source_manifest),
            (
                "dependencies".encode_utf16().collect(),
                WireValue::Array(dependencies),
            ),
        ]))
    };
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
        let fixture = fixture_file(files, &path)?;
        let id = scalar(field(&fixture, "id")?)?;
        scenarios.push(FixtureScenario {
            id,
            fixture,
            origin_package_digest: package_digest.to_owned(),
            import_path: vec![],
        });
    }
    let mut checks = scenarios
        .iter()
        .map(|scenario| fixture_matches(&manifest, &scenario.fixture, &scenario.id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut dispositions = parse_local_dispositions(&source)?;
    dispositions.extend(inherited_dispositions);
    check_fixture_dispositions(&scenarios, &mut checks, &dispositions)?;
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
    let mut seen_schemas = HashSet::new();
    let schema_order = schema_orders.into_values().flatten().chain(own_schema_order)
        .filter(|name| seen_schemas.insert(name.clone())).collect();
    Ok(SimpleCompilation {
        manifest,
        schema_order,
        source_digest,
        protocol_digest,
        composition,
        compilation_lock,
        scenarios,
        dispositions,
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
    fn inherited_v2_requirement_uses_import_alias_path() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-inherited-port-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        assert_eq!(vector["interfaces_complete"], false);
        let closure = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["closure"]).unwrap(),
            32,
            6 * 1024 * 1024,
        )
        .unwrap();
        let compiled = compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["compiled_manifest"]).unwrap(),
            32,
            65_536,
        )
        .unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
        let ports = compiled
            .manifest
            .get("execution_requirements")
            .unwrap()
            .get("ports")
            .unwrap();
        let WireValue::Array(ports) = ports else {
            panic!("expected ports")
        };
        assert_eq!(ports.len(), 1);
        let WireValue::Array(path) = ports[0].get("import_path").unwrap() else {
            panic!("expected import path")
        };
        assert_eq!(path[0].as_string().as_deref(), Some("dep"));
    }

    #[test]
    fn v2_state_output_declaration_matches_reference_compiler() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-output-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        let closure = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["closure"]).unwrap(),
            32,
            6 * 1024 * 1024,
        )
        .unwrap();
        let compiled = compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
        assert_eq!(
            compiled.source_digest,
            vector["source_digest"].as_str().unwrap()
        );
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["compiled_manifest"]).unwrap(),
            32,
            65_536,
        )
        .unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
    }

    #[test]
    fn sequence_resolves_unbound_record_and_entity_state_outputs() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-unbound-output-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        assert_eq!(vector["fixture"]["passed"], true);
        let closure = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["closure"]).unwrap(),
            32,
            6 * 1024 * 1024,
        )
        .unwrap();
        let compiled = compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
    }

    #[test]
    fn v2_exact_ref_connection_mutates_signed_dependency_and_binds_port() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-connection-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        assert_eq!(vector["interfaces_complete"], true);
        let closure = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["closure"]).unwrap(),
            32,
            6 * 1024 * 1024,
        )
        .unwrap();
        let compiled = compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["compiled_manifest"]).unwrap(),
            32,
            65_536,
        )
        .unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
    }

    #[test]
    fn v2_actor_connection_binds_state_and_authenticated_actor() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-actor-connection-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        assert_eq!(vector["interfaces_complete"], true);
        let closure = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["closure"]).unwrap(),
            32,
            6 * 1024 * 1024,
        )
        .unwrap();
        let compiled = compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["compiled_manifest"]).unwrap(),
            32,
            65_536,
        )
        .unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
    }

    #[test]
    fn v2_provenance_hook_adds_exact_reference_relation() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-provenance-hook-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["passed"], true);
        let closure = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["closure"]).unwrap(),
            32,
            6 * 1024 * 1024,
        )
        .unwrap();
        let compiled = compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
        assert_eq!(
            compiled.protocol_digest,
            vector["protocol_digest"].as_str().unwrap()
        );
        let expected = parse_wire_json_bounded(
            &serde_json::to_vec(&vector["compiled_manifest"]).unwrap(),
            32,
            65_536,
        )
        .unwrap();
        assert_eq!(
            canonical(&compiled.manifest).unwrap(),
            canonical(&expected).unwrap()
        );
    }

    #[test]
    fn v2_forwarded_output_traverses_nested_package_context() {
        for raw in [
            include_str!("../../../conformance/public-package-forwarded-output-vectors.json"),
            include_str!("../../../conformance/public-package-forwarded-actor-vectors.json"),
        ] {
            let vector: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert_eq!(vector["passed"], true);
            let closure = parse_wire_json_bounded(
                &serde_json::to_vec(&vector["closure"]).unwrap(),
                32,
                6 * 1024 * 1024,
            )
            .unwrap();
            let compiled =
                compile_simple_baseline(&scan_package_closure(&closure).unwrap()).unwrap();
            assert_eq!(
                compiled.protocol_digest,
                vector["protocol_digest"].as_str().unwrap()
            );
            let expected = parse_wire_json_bounded(
                &serde_json::to_vec(&vector["compiled_manifest"]).unwrap(),
                32,
                65_536,
            )
            .unwrap();
            assert_eq!(
                canonical(&compiled.manifest).unwrap(),
                canonical(&expected).unwrap()
            );
        }
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

    #[test]
    fn tracked_v2_parent_symbol_mapping_compilation() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-mapping-vectors.json"
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
    fn tracked_single_fixture_exact_outputs_and_wrong_state() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-exact-fixture-vectors.json"
        ))
        .unwrap();
        for (name, should_pass) in [("valid", true), ("wrong", false)] {
            let wire = serde_json::to_vec(&vector[name]["closure"]).unwrap();
            let closure = parse_wire_json_bounded(&wire, 32, 6 * 1024 * 1024).unwrap();
            let scanned = scan_package_closure(&closure).unwrap();
            assert_eq!(
                scanned.root,
                vector[name]["package_digest"].as_str().unwrap()
            );
            let compiled = compile_simple_baseline(&scanned);
            if should_pass {
                assert_eq!(
                    compiled.unwrap().protocol_digest,
                    vector[name]["protocol_digest"].as_str().unwrap()
                );
            } else {
                assert_eq!(vector[name]["result"], "EXAMPLE_FAILED");
                assert_eq!(compiled.err(), Some(ClosureError::Mismatch));
            }
        }
    }

    #[test]
    fn tracked_sequence_fixture_binds_exact_ref_and_rejects_missing_slot() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-sequence-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["valid"]["fixture"]["passed"], true);
        assert_eq!(vector["valid"]["fixture"]["executedSteps"], 3);
        for (name, should_pass) in [("valid", true), ("wrong", false)] {
            let wire = serde_json::to_vec(&vector[name]["closure"]).unwrap();
            let closure = parse_wire_json_bounded(&wire, 32, 6 * 1024 * 1024).unwrap();
            let scanned = scan_package_closure(&closure).unwrap();
            assert_eq!(
                scanned.root,
                vector[name]["package_digest"].as_str().unwrap()
            );
            let compiled = compile_simple_baseline(&scanned);
            if should_pass {
                assert_eq!(
                    compiled.unwrap().protocol_digest,
                    vector[name]["protocol_digest"].as_str().unwrap()
                );
            } else {
                assert_eq!(vector[name]["result"], "INVALID_PAYLOAD");
                assert_eq!(compiled.err(), Some(ClosureError::Invalid));
            }
        }
    }

    #[test]
    fn tracked_inherited_sequence_replays_in_parent_namespace() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-inherited-sequence-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["valid"]["fixture"]["passed"], true);
        assert_eq!(vector["valid"]["fixture"]["id"], "dep/adoption-sequence");
        for (name, should_pass) in [("valid", true), ("blocked", false)] {
            let wire = serde_json::to_vec(&vector[name]["closure"]).unwrap();
            let closure = parse_wire_json_bounded(&wire, 32, 6 * 1024 * 1024).unwrap();
            let scanned = scan_package_closure(&closure).unwrap();
            assert_eq!(
                scanned.root,
                vector[name]["package_digest"].as_str().unwrap()
            );
            let compiled = compile_simple_baseline(&scanned);
            if should_pass {
                assert_eq!(
                    compiled.unwrap().protocol_digest,
                    vector[name]["protocol_digest"].as_str().unwrap()
                );
            } else {
                assert_eq!(vector[name]["result"], "EXAMPLE_FAILED");
                assert_eq!(compiled.err(), Some(ClosureError::Mismatch));
            }
        }
    }

    #[test]
    fn tracked_inherited_fixture_disposition_binds_origin_code_and_replacement() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-disposition-vectors.json"
        ))
        .unwrap();
        assert_eq!(vector["valid"]["fixture"]["passed"], true);
        assert_eq!(
            vector["valid"]["fixture"]["disposition"]["expectedRejection"],
            "CONSTRAINT_FAILED"
        );
        assert_eq!(
            vector["nested"]["fixture"]["disposition"]["origin"]["import_path"],
            serde_json::json!(["outer", "dep"])
        );
        for (name, expected) in [
            ("valid", None),
            ("nested", None),
            ("wrong_code", Some(ClosureError::Mismatch)),
            ("wrong_origin", Some(ClosureError::Invalid)),
            ("wrong_replacement", Some(ClosureError::Mismatch)),
        ] {
            let wire = serde_json::to_vec(&vector[name]["closure"]).unwrap();
            let closure = parse_wire_json_bounded(&wire, 32, 6 * 1024 * 1024).unwrap();
            let scanned = scan_package_closure(&closure).unwrap();
            let compiled = compile_simple_baseline(&scanned);
            match expected {
                None => assert_eq!(
                    compiled.unwrap().protocol_digest,
                    vector[name]["protocol_digest"].as_str().unwrap()
                ),
                Some(error) => assert_eq!(compiled.err(), Some(error)),
            }
        }
        assert_eq!(vector["wrong_code"]["result"], "EXAMPLE_FAILED");
        assert_eq!(vector["wrong_origin"]["result"], "INVALID_PAYLOAD");
        assert_eq!(vector["wrong_replacement"]["result"], "EXAMPLE_FAILED");
    }
}

#[cfg(test)]
mod schema_order_regression {
    use super::*;
    #[test]
    fn own_schemas_follow_js_integer_index_enumeration() {
        let manifest = parse_wire_json_bounded(br#"{"record_schemas":{"10":{},"2":{},"01":{},"4294967295":{},"z":{}}}"#, 8, 1024).unwrap();
        let names = schema_enumeration(&manifest).unwrap().iter().map(|name| String::from_utf16(name).unwrap()).collect::<Vec<_>>();
        assert_eq!(names, ["2", "10", "01", "4294967295", "z"]);
    }
}
