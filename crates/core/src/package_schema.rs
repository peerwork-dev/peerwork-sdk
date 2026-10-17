//! Lossless validation and Zod-compatible normalization for package metadata,
//! sources, locks, and fixture files. Package bytes are hashed before this
//! normalized compiler input is used.

use crate::{
    full_manifest::{ManifestError, validate_full_manifest},
    interpreter::validate_guard,
    wire_json::{WireValue, parse_wire_json_bounded},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageSchemaError {
    Invalid,
    Resource,
}
use PackageSchemaError::{Invalid, Resource};

const SOURCE_V1: &str = "peerwork.protocol-source.v1";
const SOURCE_V2: &str = "peerwork.protocol-source.v2";
const META_V1: &str = "peerwork.protocol-package-metadata.v1";
const LOCK_V1: &str = "peerwork.protocol-lock.v1";
const SEMANTICS: &str = "peerwork.kernel.v1";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn string(value: &str) -> WireValue {
    WireValue::String(units(value))
}
fn array(values: Vec<WireValue>) -> WireValue {
    WireValue::Array(values)
}
fn get<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue, PackageSchemaError> {
    value.get(name).ok_or(Invalid)
}
fn get_units<'a>(value: &'a WireValue, name: &[u16]) -> Option<&'a WireValue> {
    let WireValue::Object(fields) = value else {
        return None;
    };
    fields
        .iter()
        .find(|(key, _)| key.as_slice() == name)
        .map(|(_, value)| value)
}
fn as_str(value: &WireValue) -> Result<&[u16], PackageSchemaError> {
    value.as_utf16().ok_or(Invalid)
}
fn string_len(value: &WireValue, min: usize, max: usize) -> Result<(), PackageSchemaError> {
    let units = as_str(value)?;
    if units.len() < min || units.len() > max {
        return Err(Invalid);
    }
    Ok(())
}
fn ascii(value: &WireValue, min: usize, max: usize) -> Result<String, PackageSchemaError> {
    let s = value.as_string().ok_or(Invalid)?;
    if s.encode_utf16().count() < min || s.encode_utf16().count() > max {
        return Err(Invalid);
    }
    Ok(s)
}
fn regex(
    value: &WireValue,
    min: usize,
    max: usize,
    pred: impl Fn(&str) -> bool,
) -> Result<String, PackageSchemaError> {
    let s = ascii(value, min, max)?;
    if !pred(&s) {
        return Err(Invalid);
    }
    Ok(s)
}
fn safe_int(value: &WireValue) -> Result<f64, PackageSchemaError> {
    let n = value.as_number().ok_or(Invalid)?;
    // Zod 4's z.number().int() rejects values outside the IEEE-754 safe range.
    if !n.is_finite() || n.fract() != 0.0 || n.abs() > MAX_SAFE {
        return Err(Invalid);
    }
    Ok(n)
}
fn bounded_int(value: &WireValue, min: f64, max: f64) -> Result<f64, PackageSchemaError> {
    let n = safe_int(value)?;
    if n < min || n > max {
        return Err(Invalid);
    }
    Ok(n)
}
fn arr(value: &WireValue, max: usize, min: usize) -> Result<&[WireValue], PackageSchemaError> {
    let WireValue::Array(items) = value else {
        return Err(Invalid);
    };
    if items.len() < min || items.len() > max {
        return Err(Invalid);
    }
    Ok(items)
}
fn object_fields(value: &WireValue) -> Result<&[(Vec<u16>, WireValue)], PackageSchemaError> {
    if let WireValue::Object(fields) = value {
        Ok(fields)
    } else {
        Err(Invalid)
    }
}
fn shape(
    value: &WireValue,
    required: &[&str],
    optional: &[&str],
) -> Result<(), PackageSchemaError> {
    let fields = object_fields(value)?;
    for key in required {
        if value.get(key).is_none() {
            return Err(Invalid);
        }
    }
    for (key, _) in fields {
        let key = String::from_utf16(key).map_err(|_| Invalid)?;
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(Invalid);
        }
    }
    Ok(())
}
fn put(value: &mut WireValue, key: &str, next: WireValue) -> Result<(), PackageSchemaError> {
    let WireValue::Object(fields) = value else {
        return Err(Invalid);
    };
    if let Some((_, v)) = fields
        .iter_mut()
        .find(|(k, _)| k.iter().copied().eq(key.encode_utf16()))
    {
        *v = next;
    } else {
        fields.push((units(key), next));
    }
    Ok(())
}
fn name(value: &WireValue, max: usize) -> Result<String, PackageSchemaError> {
    regex(value, 1, max, |s| {
        let mut cs = s.chars();
        matches!(cs.next(), Some('A'..='Z' | 'a'..='z'))
            && cs.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    })
}
fn digest(value: &WireValue) -> Result<(), PackageSchemaError> {
    regex(value, 64, 64, |s| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    })
    .map(|_| ())
}
fn id_pattern(
    value: &WireValue,
    max: usize,
    allowed_dot: bool,
) -> Result<String, PackageSchemaError> {
    regex(value, 1, max, |s| {
        s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || allowed_dot && b == b'.'
        })
    })
}

fn validate_path(value: &WireValue) -> Result<(), PackageSchemaError> {
    let s = regex(value, 1, 200, |s| {
        s.is_ascii()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
    })?;
    if s.starts_with('/')
        || s.contains('\\')
        || s.contains('\0')
        || s.as_bytes().get(1) == Some(&b':')
    {
        return Err(Invalid);
    }
    let parts: Vec<_> = s.split('/').collect();
    if parts.len() > 8
        || parts.iter().any(|p| {
            p.is_empty()
                || *p == "."
                || *p == ".."
                || p.trim() != *p
                || matches!(*p, "__proto__" | "prototype" | "constructor")
        })
    {
        return Err(Invalid);
    }
    Ok(())
}

fn validate_maintainer(value: &WireValue) -> Result<(), PackageSchemaError> {
    shape(value, &["name"], &["origin"])?;
    string_len(get(value, "name")?, 1, 120)?;
    if let Some(v) = value.get("origin") {
        string_len(v, 1, 240)?;
    }
    Ok(())
}
pub(crate) fn validate_metadata(value: &WireValue) -> Result<WireValue, PackageSchemaError> {
    shape(
        value,
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
        &[],
    )?;
    if ascii(get(value, "format")?, 1, 64)? != META_V1 {
        return Err(Invalid);
    }
    regex(get(value, "package_id")?, 1, 80, |s| {
        let mut prev_dash = true;
        let mut seen_alnum = false;
        for b in s.bytes() {
            if b == b'-' {
                if prev_dash {
                    return false;
                }
                prev_dash = true;
            } else if b.is_ascii_lowercase() || b.is_ascii_digit() {
                prev_dash = false;
                seen_alnum = true
            } else {
                return false;
            }
        }
        seen_alnum && !prev_dash
    })?;
    regex(get(value, "version")?, 1, 80, |s| {
        let (base, build) = s.split_once('+').map_or((s, None), |(a, b)| (a, Some(b)));
        if build.is_some_and(|b| {
            b.is_empty()
                || !b
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        }) {
            return false;
        }
        let (core, pre) = base
            .split_once('-')
            .map_or((base, None), |(a, b)| (a, Some(b)));
        if pre.is_some_and(|p| {
            p.is_empty()
                || !p
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        }) {
            return false;
        }
        let mut p = core.split('.');
        p.clone().count() == 3 && p.all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
    })?;
    string_len(get(value, "name")?, 1, 120)?;
    string_len(get(value, "description")?, 1, 4000)?;
    regex(get(value, "license")?, 1, 100, |s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    })?;
    validate_path(get(value, "license_file")?)?;
    let maintainers = arr(get(value, "source_maintainers")?, 16, 1)?;
    for item in maintainers {
        validate_maintainer(item)?;
    }
    Ok(value.clone())
}

fn validate_guard_value(v: &WireValue) -> Result<(), PackageSchemaError> {
    validate_guard(v, 0, &[]).map_err(|_| Invalid)
}
fn validate_selector(v: &WireValue, outputs: bool) -> Result<(), PackageSchemaError> {
    if outputs {
        let from = ascii(get(v, "from")?, 1, 8)?;
        match from.as_str() {
            "state" => {
                shape(v, &["from", "path"], &[])?;
                for x in arr(get(v, "path")?, 12, 1)? {
                    string_len(x, 1, 80)?;
                }
            }
            "import" => {
                shape(v, &["from", "alias", "output"], &[])?;
                string_len(get(v, "alias")?, 1, 40)?;
                string_len(get(v, "output")?, 1, 120)?;
            }
            _ => return Err(Invalid),
        }
    } else {
        return Err(Invalid);
    }
    Ok(())
}
fn validate_input_field(v: &WireValue) -> Result<(), PackageSchemaError> {
    let ty = ascii(get(v, "type")?, 1, 20)?;
    match ty.as_str() {
        "string" => {
            shape(v, &["type"], &["maxBytes", "nullable"])?;
            if let Some(x) = v.get("maxBytes") {
                bounded_int(x, 1.0, 8192.0)?;
            }
            if let Some(x) = v.get("nullable") {
                if !matches!(x, WireValue::Bool(_)) {
                    return Err(Invalid);
                }
            }
        }
        "integer" => {
            shape(v, &["type"], &["minimum", "maximum", "nullable"])?;
            for k in ["minimum", "maximum"] {
                if let Some(x) = v.get(k) {
                    safe_int(x)?;
                }
            }
            if let Some(x) = v.get("nullable") {
                if !matches!(x, WireValue::Bool(_)) {
                    return Err(Invalid);
                }
            }
        }
        "boolean" => {
            shape(v, &["type"], &["nullable"])?;
            if let Some(x) = v.get("nullable") {
                if !matches!(x, WireValue::Bool(_)) {
                    return Err(Invalid);
                }
            }
        }
        "enum" => {
            shape(v, &["type", "values"], &["nullable"])?;
            for x in arr(get(v, "values")?, 64, 1)? {
                string_len(x, 1, 8192)?;
            }
            if let Some(x) = v.get("nullable") {
                if !matches!(x, WireValue::Bool(_)) {
                    return Err(Invalid);
                }
            }
        }
        "actor_id" => {
            shape(v, &["type", "input"], &[])?;
            string_len(get(v, "input")?, 1, 120)?;
        }
        "exact_ref" => {
            if v.get("input").is_some() {
                shape(v, &["type", "input", "scope"], &[])?;
                string_len(get(v, "input")?, 1, 120)?;
                scope(get(v, "scope")?)?;
            } else {
                shape(v, &["type", "schema", "scope"], &[])?;
                string_len(get(v, "schema")?, 1, 80)?;
                scope(get(v, "scope")?)?;
            }
        }
        _ => return Err(Invalid),
    }
    Ok(())
}
fn scope(v: &WireValue) -> Result<(), PackageSchemaError> {
    if matches!(v.as_string().as_deref(), Some("INSTANCE" | "WORKSPACE")) {
        Ok(())
    } else {
        Err(Invalid)
    }
}
fn validate_body(v: &WireValue) -> Result<(), PackageSchemaError> {
    shape(v, &["fields", "required", "additionalProperties"], &[])?;
    let fields = object_fields(get(v, "fields")?)?;
    for (k, item) in fields {
        if k.is_empty() || k.len() > 80 {
            return Err(Invalid);
        }
        validate_input_field(item)?;
    }
    let req = arr(get(v, "required")?, 32, 0)?;
    for x in req {
        string_len(x, 1, 80)?;
    }
    if !matches!(get(v, "additionalProperties")?, WireValue::Bool(_)) {
        return Err(Invalid);
    }
    Ok(())
}
fn validate_interface_input(v: &WireValue) -> Result<(), PackageSchemaError> {
    let ty = ascii(get(v, "type")?, 1, 20)?;
    match ty.as_str() {
        "exact_ref" => {
            shape(
                v,
                &[
                    "action",
                    "variant",
                    "name",
                    "type",
                    "scope",
                    "body_path",
                    "required",
                    "action_body",
                ],
                &["provenance_hook"],
            )?;
            string_len(get(v, "action")?, 1, 120)?;
            bounded_int(get(v, "variant")?, 0.0, 31.0)?;
            name(get(v, "name")?, 120)?;
            scope(get(v, "scope")?)?;
            let p = arr(get(v, "body_path")?, 1, 1)?;
            string_len(&p[0], 1, 80)?;
            if !matches!(get(v, "required")?, WireValue::Bool(_)) {
                return Err(Invalid);
            }
            validate_body(get(v, "action_body")?)?;
            if let Some(h) = v.get("provenance_hook") {
                shape(
                    h,
                    &[
                        "record_slot",
                        "record_schema",
                        "relation_kind",
                        "target_input",
                    ],
                    &[],
                )?;
                for k in [
                    "record_slot",
                    "record_schema",
                    "relation_kind",
                    "target_input",
                ] {
                    string_len(get(h, k)?, 1, if k == "target_input" { 120 } else { 80 })?;
                }
            }
        }
        "actor_id" => {
            shape(
                v,
                &[
                    "action",
                    "variant",
                    "name",
                    "type",
                    "relation",
                    "body_path",
                    "required",
                    "action_body",
                ],
                &[],
            )?;
            string_len(get(v, "action")?, 1, 120)?;
            bounded_int(get(v, "variant")?, 0.0, 31.0)?;
            name(get(v, "name")?, 120)?;
            if !matches!(
                get(v, "relation")?.as_string().as_deref(),
                Some("same_actor" | "different_actor")
            ) {
                return Err(Invalid);
            }
            let p = arr(get(v, "body_path")?, 1, 1)?;
            string_len(&p[0], 1, 80)?;
            if !matches!(get(v, "required")?, WireValue::Bool(_)) {
                return Err(Invalid);
            }
            validate_body(get(v, "action_body")?)?;
        }
        _ => return Err(Invalid),
    }
    Ok(())
}
fn validate_interface_output(v: &WireValue) -> Result<(), PackageSchemaError> {
    let ty = ascii(get(v, "type")?, 1, 20)?;
    let sel = get(v, "selector")?;
    validate_selector(sel, true)?;
    validate_guard_value(get(v, "available_when")?)?;
    match ty.as_str() {
        "exact_ref" => {
            shape(
                v,
                &[
                    "name",
                    "type",
                    "schema",
                    "scope",
                    "selector",
                    "available_when",
                ],
                &[],
            )?;
            name(get(v, "name")?, 120)?;
            string_len(get(v, "schema")?, 1, 80)?;
            scope(get(v, "scope")?)?
        }
        "actor_id" => {
            shape(v, &["name", "type", "selector", "available_when"], &[])?;
            name(get(v, "name")?, 120)?;
        }
        _ => return Err(Invalid),
    }
    Ok(())
}

fn validate_source_inner(source: &WireValue) -> Result<WireValue, PackageSchemaError> {
    let required = ["format", "semantics", "manifest"];
    let optional = [
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
    shape(source, &required, &optional)?;
    let format = ascii(get(source, "format")?, 1, 64)?;
    let v1 = format == SOURCE_V1;
    let v2 = format == SOURCE_V2;
    if !v1 && !v2 || ascii(get(source, "semantics")?, 1, 80)? != SEMANTICS {
        return Err(Invalid);
    }
    // Match the append defaults inserted by the TypeScript manifest schema.
    // Normalize only action effects; literal business data stays opaque.
    let mut source_manifest = get(source, "manifest")?.clone();
    let WireValue::Array(mut actions) = get(&source_manifest, "actions")?.clone() else { return Err(Invalid); };
    for action in &mut actions {
        let WireValue::Array(mut variants) = get(action, "variants")?.clone() else { return Err(Invalid); };
        for variant in &mut variants {
            let WireValue::Array(mut effects) = get(variant, "effects")?.clone() else { return Err(Invalid); };
            for effect in &mut effects {
                if effect.get("op").and_then(WireValue::as_string).as_deref() == Some("append") {
                    if effect.get("selectHead").is_none() { put(effect, "selectHead", WireValue::Bool(false))?; }
                    if effect.get("relations").is_none() { put(effect, "relations", array(vec![]))?; }
                }
            }
            put(variant, "effects", array(effects))?;
        }
        put(action, "variants", array(variants))?;
    }
    put(&mut source_manifest, "actions", array(actions))?;
    let manifest_canonical =
        validate_full_manifest(&source_manifest).map_err(|e| match e {
            ManifestError::Resource => Resource,
            _ => Invalid,
        })?;
    let normalized_manifest = parse_wire_json_bounded(manifest_canonical.as_bytes(), 32, 65_536)
        .map_err(|_| Invalid)?
        .get("manifest")
        .cloned()
        .ok_or(Invalid)?;
    let mut out = source.clone();
    put(&mut out, "manifest", normalized_manifest.clone())?;
    let manifest = &normalized_manifest;
    if !matches!(get(manifest,"dependencies")?,WireValue::Array(a) if a.is_empty())
        || manifest.get("execution_requirements").is_some()
    {
        return Err(Invalid);
    }
    let imports = source
        .get("imports")
        .cloned()
        .unwrap_or_else(|| array(vec![]));
    let import_items = arr(&imports, 16, 0)?;
    let mut aliases = Vec::<String>::new();
    for x in import_items {
        shape(x, &["alias", "package_digest", "namespace"], &[])?;
        let a = regex(get(x, "alias")?, 1, 40, |s| {
            s.as_bytes()[0].is_ascii_lowercase()
                && s.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
        })?;
        if aliases.contains(&a) {
            return Err(Invalid);
        }
        aliases.push(a);
        digest(get(x, "package_digest")?)?;
        regex(get(x, "namespace")?, 1, 32, |s| {
            s.as_bytes()[0].is_ascii_alphabetic()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })?;
    }
    put(&mut out, "imports", imports)?;
    let params = source
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| array(vec![]));
    let ps = arr(&params, 32, 0)?;
    let mut pnames = Vec::<String>::new();
    let mut locally_bound_params = Vec::<String>::new();
    for p in ps {
        shape(
            p,
            &["name", "type"],
            &[
                "values", "minimum", "maximum", "default", "required", "binding",
            ],
        )?;
        let n = regex(get(p, "name")?, 1, 80, |s| {
            let mut c = s.chars();
            matches!(c.next(), Some('A'..='Z' | 'a'..='z'))
                && c.all(|x| x.is_ascii_alphanumeric() || matches!(x, '.' | '_' | '-'))
        })?;
        if pnames.contains(&n) {
            return Err(Invalid);
        }
        pnames.push(n);
        if p.get("binding").is_some() {
            locally_bound_params.push(pnames.last().unwrap().clone());
        }
        let t = ascii(get(p, "type")?, 1, 16)?;
        if !matches!(t.as_str(), "string" | "enum" | "integer" | "boolean") {
            return Err(Invalid);
        }
        if t == "enum" {
            for x in arr(get(p, "values")?, 32, 1)? {
                string_len(x, 1, 120)?;
            }
        } else if p.get("values").is_some() {
            return Err(Invalid);
        }
        if t == "integer" {
            let lo = p.get("minimum").map(safe_int).transpose()?;
            let hi = p.get("maximum").map(safe_int).transpose()?;
            if lo.zip(hi).is_some_and(|(a, b)| a > b) {
                return Err(Invalid);
            }
        } else if p.get("minimum").is_some() || p.get("maximum").is_some() {
            return Err(Invalid);
        }
        if let Some(r) = p.get("required") {
            if !matches!(r, WireValue::Bool(_)) {
                return Err(Invalid);
            }
        }
        if let Some(b) = p.get("binding") {
            shape(
                b,
                &["kind", "action_id", "variant_index", "guard_index"],
                &["conflict_role"],
            )?;
            if ascii(get(b, "kind")?, 1, 40)? != "protocol_role_guard" {
                return Err(Invalid);
            }
            string_len(get(b, "action_id")?, 1, 120)?;
            bounded_int(get(b, "variant_index")?, 0.0, 31.0)?;
            bounded_int(get(b, "guard_index")?, 0.0, 31.0)?;
            if let Some(x) = b.get("conflict_role") {
                string_len(x, 1, 80)?;
            }
        }
    }
    // Field defaults in the source schemas are applied by Zod parse.
    let mut normalized_params = params;
    if let WireValue::Array(items) = &mut normalized_params {
        for p in items {
            if p.get("required").is_none() {
                put(p, "required", WireValue::Bool(false))?;
            }
        }
    }
    put(&mut out, "parameters", normalized_params)?;
    let exports = source
        .get("exports")
        .cloned()
        .unwrap_or_else(|| array(vec![]));
    let mut slots = Vec::new();
    let mut exported_parameters = Vec::new();
    for x in arr(&exports, 32, 0)? {
        shape(x, &["slot", "parameter"], &[])?;
        let slot = name(get(x, "slot")?, 120)?;
        let parameter = ascii(get(x, "parameter")?, 1, 80)?;
        if slots.contains(&slot) || !pnames.contains(&parameter) {
            return Err(Invalid);
        }
        slots.push(slot);
        exported_parameters.push(parameter);
    }
    put(&mut out, "exports", exports)?;
    let bindings = source
        .get("bindings")
        .cloned()
        .unwrap_or_else(|| array(vec![]));
    let mut targets = Vec::<(String, Vec<u16>)>::new();
    for x in arr(&bindings, 32, 0)? {
        shape(x, &["parameter", "import_alias", "slot"], &[])?;
        let p = ascii(get(x, "parameter")?, 1, 80)?;
        let a = ascii(get(x, "import_alias")?, 1, 40)?;
        let s = as_str(get(x, "slot")?)?.to_vec();
        string_len(get(x, "slot")?, 1, 120)?;
        if !pnames.contains(&p)
            || !aliases.contains(&a)
            || targets.contains(&(a.clone(), s.clone()))
        {
            return Err(Invalid);
        }
        targets.push((a, s));
    }
    for parameter in &pnames {
        if !locally_bound_params.contains(parameter)
            && !exported_parameters.contains(parameter)
        {
            return Err(Invalid);
        }
    }
    put(&mut out, "bindings", bindings)?;
    let derive = source
        .get("derive")
        .cloned()
        .unwrap_or_else(|| array(vec![]));
    for x in arr(&derive, 32, 0)? {
        shape(x, &["op", "action_id", "guard"], &[])?;
        if ascii(get(x, "op")?, 1, 40)? != "add_constraint" {
            return Err(Invalid);
        }
        let action_id = get(x, "action_id")?;
        string_len(action_id, 1, 120)?;
        let a = as_str(action_id)?;
        if ["__proto__", "prototype", "constructor"]
            .iter()
            .any(|unsafe_name| a == unsafe_name.encode_utf16().collect::<Vec<_>>())
        {
            return Err(Invalid);
        }
        validate_guard_value(get(x, "guard")?)?;
    }
    put(&mut out, "derive", derive)?;
    if v2 && source.get("interfaces").is_none() {
        return Err(Invalid);
    }
    if let Some(ifaces) = source.get("interfaces") {
        if !v2 {
            return Err(Invalid);
        }
        shape(ifaces, &[], &["outputs", "inputs", "action_bodies", "input_exports"])?;
        let mut ni = ifaces.clone();
        let mut outputs = Vec::new();
        let mut inputs = Vec::new();
        let mut body_actions: Vec<Vec<u16>> = Vec::new();
        for (field, max) in [("outputs", 32usize), ("inputs", 32), ("action_bodies", 64)] {
            let value = ifaces.get(field).cloned().unwrap_or_else(|| array(vec![]));
            for x in arr(&value, max, 0)? {
                match field {
                    "outputs" => {
                        validate_interface_output(x)?;
                        let n =
                            String::from_utf16(as_str(get(x, "name")?)?).map_err(|_| Invalid)?;
                        if outputs.contains(&n) {
                            return Err(Invalid);
                        }
                        outputs.push(n);
                    }
                    "inputs" => {
                        validate_interface_input(x)?;
                        let n =
                            String::from_utf16(as_str(get(x, "name")?)?).map_err(|_| Invalid)?;
                        if inputs.contains(&n) {
                            return Err(Invalid);
                        }
                        inputs.push(n);
                    }
                    _ => {
                        shape(x, &["action", "body"], &[])?;
                        let action_units = as_str(get(x, "action")?)?;
                        string_len(get(x, "action")?, 1, 120)?;
                        let actions = manifest.get("actions").and_then(|v| {
                            if let WireValue::Array(a) = v {
                                Some(a)
                            } else {
                                None
                            }
                        });
                        if body_actions.iter().any(|existing| existing == action_units)
                            || !actions.is_some_and(|a| {
                                a.iter().any(|a| {
                                    get_units(a, &units("id")) == Some(get(x, "action").unwrap())
                                })
                            })
                        {
                            return Err(Invalid);
                        }
                        body_actions.push(action_units.to_vec());
                        let body = get(x, "body")?;
                        validate_body(body)?;
                        for r in arr(get(body, "required")?, 32, 0)? {
                            if get_units(get(body, "fields")?, as_str(r)?).is_none() {
                                return Err(Invalid);
                            }
                        }
                    }
                }
            }
            put(&mut ni, field, value)?;
        }
        if let Some(exports) = ifaces.get("input_exports") {
            let mut targets = Vec::new();
            for export in arr(exports, 512, 0)? {
                shape(export, &["name", "from"], &[])?;
                let exported_name = name(get(export, "name")?, 120)?;
                if inputs.contains(&exported_name) { return Err(Invalid); }
                inputs.push(exported_name);
                let from = get(export, "from")?;
                shape(from, &["import", "input"], &[])?;
                let alias = ascii(get(from, "import")?, 1, 40)?;
                let input = ascii(get(from, "input")?, 1, 120)?;
                if !aliases.contains(&alias) || targets.contains(&(alias.clone(), input.clone())) {
                    return Err(Invalid);
                }
                targets.push((alias, input));
            }
            if inputs.len() > 512 { return Err(Invalid); }
        }
        // Cross-field checks are applied to the normalized interface shape.
        for input in arr(ni.get("inputs").unwrap(), 32, 0)? {
            let action = get(input, "action")?;
            string_len(action, 1, 120)?;
            let variant = bounded_int(get(input, "variant")?, 0.0, 31.0)? as usize;
            let action_obj = manifest
                .get("actions")
                .and_then(|v| {
                    if let WireValue::Array(a) = v {
                        a.iter()
                            .find(|x| get_units(x, &units("id")) == Some(action))
                    } else {
                        None
                    }
                })
                .ok_or(Invalid)?;
            let variants = arr(get(action_obj, "variants")?, 64, 0)?;
            if variants.get(variant).is_none() {
                return Err(Invalid);
            }
            let body = get(input, "action_body")?;
            let path = arr(get(input, "body_path")?, 1, 1)?;
            let field_name = as_str(&path[0])?;
            let body_field = get_units(get(body, "fields")?, field_name).ok_or(Invalid)?;
            let required = arr(get(body, "required")?, 32, 0)?
                .iter()
                .any(|r| r.as_utf16() == Some(field_name));
            if !matches!((get(input,"required")?,required),(WireValue::Bool(a),b) if *a==b) {
                return Err(Invalid);
            }
            if ascii(get(input, "type")?, 1, 20)? == "exact_ref" {
                if body_field
                    .get("type")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some("exact_ref")
                    || body_field
                        .get("input")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        != Some(
                            input
                                .get("name")
                                .and_then(WireValue::as_string)
                                .as_deref()
                                .ok_or(Invalid)?,
                        )
                {
                    return Err(Invalid);
                }
                if body_field.get("scope") != input.get("scope") {
                    return Err(Invalid);
                }
                if let Some(h) = input.get("provenance_hook") {
                    if h.get("target_input") != input.get("name") {
                        return Err(Invalid);
                    }
                }
            } else if body_field
                .get("type")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some("actor_id")
                || body_field.get("input") != input.get("name")
            {
                return Err(Invalid);
            }
        }
        for output in arr(ni.get("outputs").unwrap(), 32, 0)? {
            let selector = get(output, "selector")?;
            if ascii(get(selector, "from")?, 1, 8)? == "state" {
                let mut at = manifest.get("initial_state");
                for part in arr(get(selector, "path")?, 12, 1)? {
                    at = at.and_then(|v| get_units(v, as_str(part).ok()?));
                    if at.is_none() {
                        return Err(Invalid);
                    }
                }
                if ascii(get(output, "type")?, 1, 20)? == "exact_ref" {
                    let schemas = object_fields(get(manifest, "record_schemas")?)?;
                    let schema = as_str(get(output, "schema")?)?;
                    if !schemas.iter().any(|(k, _)| k.as_slice() == schema) {
                        return Err(Invalid);
                    }
                }
            } else if !aliases.iter().any(|a| {
                selector
                    .get("alias")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(a)
            }) {
                return Err(Invalid);
            }
        }
        put(&mut out, "interfaces", ni)?;
    }
    for (key, max) in [
        ("connections", 64usize),
        ("role_mappings", 64),
        ("capability_mappings", 64),
    ] {
        if let Some(items) = source.get(key) {
            if !v2 {
                return Err(Invalid);
            }
            let mut ports = Vec::new();
            for x in arr(items, max, 0)? {
                match key {
                    "connections" => {
                        shape(x, &["from", "to"], &[])?;
                        let from = get(x, "from")?;
                        let to = get(x, "to")?;
                        shape(from, &["import", "output"], &[])?;
                        let full = to.get("action").is_some() || to.get("variant").is_some();
                        if full { shape(to, &["import", "action", "variant", "input"], &[])?; }
                        else { shape(to, &["import", "input"], &[])?; }
                        let fa = ascii(get(from, "import")?, 1, 40)?;
                        string_len(get(from, "output")?, 1, 120)?;
                        let ta = ascii(get(to, "import")?, 1, 40)?;
                        if full {
                            string_len(get(to, "action")?, 1, 120)?;
                            bounded_int(get(to, "variant")?, 0.0, 31.0)?;
                        }
                        let input = as_str(get(to, "input")?)?.to_vec();
                        string_len(get(to, "input")?, 1, 120)?;
                        if !aliases.contains(&fa) || !aliases.contains(&ta) {
                            return Err(Invalid);
                        }
                        let port = (ta, input);
                        if ports.contains(&port) {
                            return Err(Invalid);
                        }
                        ports.push(port);
                    }
                    "role_mappings" => {
                        shape(x, &["from", "to"], &[])?;
                        let from = get(x, "from")?;
                        shape(from, &["import", "role"], &[])?;
                        let a = ascii(get(from, "import")?, 1, 40)?;
                        string_len(get(from, "role")?, 1, 80)?;
                        string_len(get(x, "to")?, 1, 80)?;
                        if !aliases.contains(&a) {
                            return Err(Invalid);
                        }
                    }
                    _ => {
                        shape(x, &["from", "to"], &[])?;
                        let from = get(x, "from")?;
                        shape(from, &["import", "capability"], &[])?;
                        let a = ascii(get(from, "import")?, 1, 40)?;
                        string_len(get(from, "capability")?, 1, 120)?;
                        string_len(get(x, "to")?, 1, 120)?;
                        if !aliases.contains(&a) {
                            return Err(Invalid);
                        }
                    }
                }
            }
        }
    }
    if let Some(ds) = source.get("fixture_dispositions") {
        if !v2 {
            return Err(Invalid);
        }
        let mut origins = Vec::new();
        for d in arr(ds, 64, 0)? {
            shape(
                d,
                &[
                    "origin",
                    "expected_rejection",
                    "rationale",
                    "replacement_scenario_id",
                ],
                &[],
            )?;
            let o = get(d, "origin")?;
            shape(o, &["package_digest", "import_path", "fixture_id"], &[])?;
            digest(get(o, "package_digest")?)?;
            let mut path = Vec::new();
            for a in arr(get(o, "import_path")?, 16, 0)? {
                let a = regex(a, 1, 40, |s| {
                    s.as_bytes()[0].is_ascii_lowercase()
                        && s.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                        })
                })?;
                path.push(a)
            }
            let f = id_pattern(get(o, "fixture_id")?, 80, true)?;
            let key = (ascii(get(o, "package_digest")?, 64, 64)?, path.join("/"), f);
            if origins.contains(&key) {
                return Err(Invalid);
            }
            origins.push(key);
            string_len(get(d, "expected_rejection")?, 1, 80)?;
            string_len(get(d, "rationale")?, 1, 1000)?;
            string_len(get(d, "replacement_scenario_id")?, 1, 120)?;
        }
    }
    Ok(out)
}

pub(crate) fn normalize_and_validate_source(
    value: &WireValue,
) -> Result<WireValue, PackageSchemaError> {
    validate_source_inner(value)
}

pub(crate) fn normalize_and_validate_lock(
    value: &WireValue,
) -> Result<WireValue, PackageSchemaError> {
    shape(
        value,
        &[
            "format",
            "compiler_version",
            "semantics",
            "dependencies",
            "baseline_bindings",
            "output_protocol_digest",
        ],
        &[],
    )?;
    if ascii(get(value, "format")?, 1, 64)? != LOCK_V1
        || ascii(get(value, "semantics")?, 1, 80)? != SEMANTICS
    {
        return Err(Invalid);
    }
    string_len(get(value, "compiler_version")?, 1, 80)?;
    digest(get(value, "output_protocol_digest")?)?;
    for x in arr(get(value, "dependencies")?, 16, 0)? {
        shape(x, &["alias", "package_digest", "namespace"], &[])?;
        string_len(get(x, "alias")?, 1, 40)?;
        digest(get(x, "package_digest")?)?;
        string_len(get(x, "namespace")?, 1, 32)?;
    }
    for (key, _) in object_fields(get(value, "baseline_bindings")?)? {
        if key.is_empty() || key.len() > 80 {
            return Err(Invalid);
        }
    }
    Ok(value.clone())
}

fn fixture_auth(v: &WireValue) -> Result<WireValue, PackageSchemaError> {
    shape(
        v,
        &["actorId"],
        &["workspaceRoles", "protocolRoles", "capabilities"],
    )?;
    regex(get(v, "actorId")?, 43, 43, |s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    })?;
    let mut out = v.clone();
    for k in ["workspaceRoles", "protocolRoles", "capabilities"] {
        let list = v.get(k).cloned().unwrap_or_else(|| array(vec![]));
        for role in arr(&list, 64, 0)? {
            if !matches!(role, WireValue::String(_)) {
                return Err(Invalid);
            }
        }
        put(&mut out, k, list)?;
    }
    Ok(out)
}
fn fixture_input(v: &WireValue) -> Result<(), PackageSchemaError> {
    shape(
        v,
        &["recordId", "revision", "schema", "payload", "scope"],
        &["entityId"],
    )?;
    regex(get(v, "recordId")?, 43, 43, |s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    })?;
    bounded_int(get(v, "revision")?, 1.0, MAX_SAFE)?;
    string_len(get(v, "schema")?, 1, 80)?;
    scope(get(v, "scope")?)?;
    if let Some(x) = v.get("entityId") {
        regex(x, 43, 43, |s| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })?;
    }
    Ok(())
}
fn expected(v: &WireValue) -> Result<(), PackageSchemaError> {
    let accepted = matches!(v.get("accepted"), Some(WireValue::Bool(true)));
    if accepted {
        shape(
            v,
            &["accepted"],
            &[
                "state",
                "records",
                "headSelections",
                "revisionEffects",
                "evaluated_at",
                "withdrawals",
            ],
        )?;
        if let Some(x) = v.get("evaluated_at") {
            bounded_int(x, 0.0, MAX_SAFE)?;
        }
        if let Some(WireValue::Array(withdrawals)) = v.get("withdrawals") {
            // Empty optional collections are omitted from the canonical TS
            // result; reject them rather than introducing another wire form.
            if withdrawals.is_empty() || withdrawals.len() > 1 { return Err(Invalid); }
            for withdrawal in withdrawals {
                shape(withdrawal, &["target", "expectedMax", "expectedHead"], &[])?;
                validate_exact_ref(get(withdrawal, "target")?)?;
                bounded_int(get(withdrawal, "expectedMax")?, 1.0, MAX_SAFE)?;
                if !matches!(get(withdrawal, "expectedHead")?, WireValue::Null) {
                    validate_exact_ref(get(withdrawal, "expectedHead")?)?;
                }
            }
        } else if v.get("withdrawals").is_some() {
            return Err(Invalid);
        }
    } else {
        shape(v, &["accepted", "code"], &[])?;
        if !matches!(v.get("accepted"), Some(WireValue::Bool(false))) {
            return Err(Invalid);
        }
        string_len(get(v, "code")?, 1, 80)?;
    }
    Ok(())
}
fn validate_exact_ref(v: &WireValue) -> Result<(), PackageSchemaError> {
    shape(v, &["recordId", "revision"], &[])?;
    regex(get(v, "recordId")?, 43, 43, |s| {
        s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    })?;
    bounded_int(get(v, "revision")?, 1.0, MAX_SAFE)?;
    Ok(())
}
fn normalize_fixture(value: &WireValue) -> Result<WireValue, PackageSchemaError> {
    let is_sequence = matches!(
        value.get("kind").and_then(WireValue::as_string).as_deref(),
        Some("sequence")
    );
    if is_sequence {
        shape(value, &["kind", "id", "state", "steps"], &[])?;
        id_pattern(get(value, "id")?, 80, true)?;
        let steps = arr(get(value, "steps")?, 32, 1)?;
        let mut out = value.clone();
        let mut names = Vec::<String>::new();
        let mut norm_steps = Vec::new();
        for step in steps {
            shape(
                step,
                &["action_id", "body", "auth", "expected"],
                &["exact_inputs", "bind_refs", "time_ms"],
            )?;
            string_len(get(step, "action_id")?, 1, 120)?;
            let mut s = step.clone();
            let inputs = step
                .get("exact_inputs")
                .cloned()
                .unwrap_or_else(|| array(vec![]));
            for x in arr(&inputs, 32, 0)? {
                let n = regex(x, 1, 80, |s| {
                    let mut c = s.chars();
                    matches!(c.next(), Some('A'..='Z' | 'a'..='z'))
                        && c.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                })?;
                if !names.contains(&n) {
                    return Err(Invalid);
                }
            }
            put(&mut s, "exact_inputs", inputs)?;
            let bindings = step
                .get("bind_refs")
                .cloned()
                .unwrap_or_else(|| array(vec![]));
            for b in arr(&bindings, 32, 0)? {
                shape(b, &["name", "record_slot"], &[])?;
                let n = name(get(b, "name")?, 80)?;
                if names.contains(&n) {
                    return Err(Invalid);
                }
                names.push(n);
                string_len(get(b, "record_slot")?, 1, 80)?;
            }
            put(&mut s, "bind_refs", bindings)?;
            put(&mut s, "auth", fixture_auth(get(step, "auth")?)?)?;
            expected(get(step, "expected")?)?;
            if let Some(t) = step.get("time_ms") {
                bounded_int(t, 0.0, MAX_SAFE)?;
            }
            norm_steps.push(s);
        }
        put(&mut out, "steps", array(norm_steps))?;
        Ok(out)
    } else {
        shape(
            value,
            &["id", "action_id", "state", "body", "auth", "expected"],
            &["exact_inputs", "time_ms"],
        )?;
        id_pattern(get(value, "id")?, 80, true)?;
        string_len(get(value, "action_id")?, 1, 120)?;
        let mut out = value.clone();
        let inputs = value
            .get("exact_inputs")
            .cloned()
            .unwrap_or_else(|| array(vec![]));
        for x in arr(&inputs, 32, 0)? {
            fixture_input(x)?;
        }
        put(&mut out, "exact_inputs", inputs)?;
        put(&mut out, "auth", fixture_auth(get(value, "auth")?)?)?;
        expected(get(value, "expected")?)?;
        if let Some(t) = value.get("time_ms") {
            bounded_int(t, 0.0, MAX_SAFE)?;
        }
        Ok(out)
    }
}
pub(crate) fn normalize_and_validate_fixture(
    value: &WireValue,
) -> Result<WireValue, PackageSchemaError> {
    normalize_fixture(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Path;
    use crate::wire_json::canonical_wire_value;
    fn parse(s: &str) -> WireValue {
        parse_wire_json_bounded(s.as_bytes(), 64, 1024 * 1024).unwrap()
    }

    #[test]
    fn direct_pinned_typescript_schema_vectors_match() {
        let vectors = parse(include_str!(
            "../../../conformance/package-schema-vectors.json"
        ));
        let WireValue::Array(cases) = vectors.get("cases").unwrap() else {
            panic!("cases")
        };
        for case in cases {
            let input = case.get("input").unwrap();
            let kind = case.get("kind").and_then(WireValue::as_string).unwrap();
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let result = match kind.as_str() {
                "source" => normalize_and_validate_source(&input),
                "metadata" => validate_metadata(&input),
                "lock" => normalize_and_validate_lock(&input),
                "fixture" => normalize_and_validate_fixture(&input),
                kind => panic!("unknown package schema vector kind: {kind}"),
            };
            if matches!(case.get("valid"), Some(WireValue::Bool(true))) {
                let actual =
                    result.unwrap_or_else(|error| panic!("{name} rejected by Rust: {error:?}"));
                let expected = case.get("normalized").unwrap();
                assert_eq!(
                    canonical_wire_value(&actual, Path::SecureArtifact).unwrap(),
                    canonical_wire_value(&expected, Path::SecureArtifact).unwrap(),
                    "{} normalization differs",
                    name
                );
            } else {
                assert!(result.is_err(), "{} accepted by Rust", name);
            }
        }
    }

    #[test]
    fn defaults_and_safe_integer_match_zod() {
        let source = parse(
            r#"{"format":"peerwork.protocol-source.v1","semantics":"peerwork.kernel.v1","manifest":{"name":"x","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{},"actions":[]}}"#,
        );
        let normalized = normalize_and_validate_source(&source).unwrap();
        assert_eq!(
            normalized.get("parameters").unwrap(),
            &WireValue::Array(vec![])
        );
        let fixture = parse(
            r#"{"id":"a","action_id":"a","state":{},"body":{},"auth":{"actorId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"expected":{"accepted":false,"code":"X"}}"#,
        );
        let normalized = normalize_and_validate_fixture(&fixture).unwrap();
        assert!(
            normalized
                .get("auth")
                .unwrap()
                .get("capabilities")
                .is_some()
        );
        assert!(normalize_and_validate_fixture(&parse(r#"{"id":"a","action_id":"a","state":{},"body":{},"auth":{"actorId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"time_ms":9007199254740992,"expected":{"accepted":false,"code":"X"}}"#)).is_err());
    }

    #[test]
    fn exact_ref_input_body_field_requires_and_accepts_scope() {
        assert!(
            validate_input_field(&parse(
                r#"{"type":"exact_ref","input":"candidate","scope":"WORKSPACE"}"#
            ))
            .is_ok()
        );
        assert!(
            validate_input_field(&parse(r#"{"type":"exact_ref","input":"candidate"}"#)).is_err()
        );
    }

    #[test]
    fn expected_withdrawal_result_is_nonempty_exact_and_typed() {
        let valid = parse(r#"{"accepted":true,"withdrawals":[{"target":{"recordId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","revision":2},"expectedMax":3,"expectedHead":null}]}"#);
        assert!(expected(&valid).is_ok());
        let empty = parse(r#"{"accepted":true,"withdrawals":[]}"#);
        assert!(expected(&empty).is_err());
        let malformed = parse(r#"{"accepted":true,"withdrawals":[{"target":{"recordId":"bad","revision":2},"expectedMax":3,"expectedHead":null}]}"#);
        assert!(expected(&malformed).is_err());
    }

    #[test]
    fn combined_public_inputs_share_the_512_port_bound() {
        let make_source = |count: usize| {
            let exports = (0..count)
                .map(|index| format!(r#"{{"name":"public{index}","from":{{"import":"leaf","input":"input{index}"}}}}"#))
                .collect::<Vec<_>>()
                .join(",");
            format!(r#"{{"format":"peerwork.protocol-source.v2","semantics":"peerwork.kernel.v1","manifest":{{"name":"bounded","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{{}},"initial_state":{{}},"actions":[{{"id":"action0","reads":[],"writes":[],"revisionEffects":{{"control":false,"contentEntities":[]}},"variants":[{{"when":[],"effects":[]}}]}}]}},"imports":[{{"alias":"leaf","package_digest":"{}","namespace":"leaf"}}],"parameters":[],"exports":[],"bindings":[],"derive":[],"interfaces":{{"outputs":[],"inputs":[{{"action":"action0","variant":0,"name":"local","type":"actor_id","relation":"same_actor","body_path":["actor"],"required":true,"action_body":{{"fields":{{"actor":{{"type":"actor_id","input":"local"}}}},"required":["actor"],"additionalProperties":false}}}}],"action_bodies":[],"input_exports":[{}]}},"connections":[]}}"#, "a".repeat(64), exports)
        };
        assert!(normalize_and_validate_source(&parse(&make_source(511))).is_ok());
        assert!(normalize_and_validate_source(&parse(&make_source(512))).is_err());
    }
}
