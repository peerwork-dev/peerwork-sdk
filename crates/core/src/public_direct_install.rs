//! Source-matched object proposal for a direct PUBLIC protocol install.
//! The caller must bind this proposal to complete authenticated replay,
//! owner policy, signed ADMIN snapshot, and exact saved transport bytes.

use crate::{
    canonical::Path,
    crypto::sha256_hex,
    full_manifest::validate_full_manifest,
    genesis_structure_policy::derive_genesis_structure_policy_with_keep_encrypted,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectInstallError {
    Invalid,
    Resource,
}

pub(crate) struct DirectInstallObjects {
    pub added: Vec<WireValue>,
    pub manifest: WireValue,
}
pub(crate) struct EmptySnapshotBegin {
    pub operation: WireValue,
    pub structure: WireValue,
}

fn entries(value: &WireValue) -> Result<&[(Vec<u16>, WireValue)], DirectInstallError> {
    if let WireValue::Object(fields) = value {
        Ok(fields)
    } else {
        Err(DirectInstallError::Invalid)
    }
}
fn array(value: &WireValue) -> Result<&[WireValue], DirectInstallError> {
    if let WireValue::Array(items) = value {
        Ok(items)
    } else {
        Err(DirectInstallError::Invalid)
    }
}
fn name(units: &[u16]) -> Result<String, DirectInstallError> {
    String::from_utf16(units).map_err(|_| DirectInstallError::Invalid)
}
fn required<'a>(value: &'a WireValue, field: &str) -> Result<&'a WireValue, DirectInstallError> {
    value.get(field).ok_or(DirectInstallError::Invalid)
}
fn put(
    value: &mut WireValue,
    field: &str,
    replacement: WireValue,
) -> Result<(), DirectInstallError> {
    let WireValue::Object(fields) = value else {
        return Err(DirectInstallError::Invalid);
    };
    if let Some((_, slot)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(field.encode_utf16()))
    {
        *slot = replacement;
    } else {
        fields.push((key(field), replacement));
    }
    Ok(())
}
fn safe_int(value: &WireValue) -> Result<u64, DirectInstallError> {
    let number = value.as_number().ok_or(DirectInstallError::Invalid)?;
    if number.fract() != 0.0 || number < 0.0 || number > 9_007_199_254_740_991.0 {
        return Err(DirectInstallError::Invalid);
    }
    Ok(number as u64)
}
fn ordered_json(
    value: &WireValue,
    depth: usize,
    out: &mut String,
) -> Result<(), DirectInstallError> {
    if depth > 64 || out.len() > 2_000_000 {
        return Err(DirectInstallError::Resource);
    }
    match value {
        WireValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                ordered_json(item, depth + 1, out)?;
            }
            out.push(']');
        }
        WireValue::Object(fields) => {
            out.push('{');
            for (index, (name, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(
                    &canonical_wire_value(&WireValue::String(name.clone()), Path::SecureArtifact)
                        .map_err(|_| DirectInstallError::Invalid)?,
                );
                out.push(':');
                ordered_json(item, depth + 1, out)?;
            }
            out.push('}');
        }
        _ => out.push_str(
            &canonical_wire_value(value, Path::SecureArtifact)
                .map_err(|_| DirectInstallError::Invalid)?,
        ),
    }
    if out.len() > 2_000_000 {
        return Err(DirectInstallError::Resource);
    }
    Ok(())
}

fn key(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn text(value: &str) -> WireValue {
    WireValue::String(key(value))
}
fn obj(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (key(name), value))
            .collect(),
    )
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn entrypoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "coordination"
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

pub(crate) fn build_direct_install_objects(
    manifest_wire: &[u8],
    expected_digest: &str,
    workspace_id: &str,
    instance_id: &str,
    origin_entrypoint: &str,
    issued_at: u64,
) -> Result<DirectInstallObjects, DirectInstallError> {
    let bad = || DirectInstallError::Invalid;
    if manifest_wire.is_empty() || manifest_wire.len() > 2_000_000 {
        return Err(DirectInstallError::Resource);
    }
    if !token(workspace_id)
        || !token(instance_id)
        || !entrypoint(origin_entrypoint)
        || expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || issued_at > 9_007_199_254_740_991
    {
        return Err(bad());
    }
    let raw = parse_wire_json_bounded(manifest_wire, 64, 2_000_000).map_err(|_| bad())?;
    let wrapped = validate_full_manifest(&raw).map_err(|_| bad())?;
    let parsed = parse_wire_json_bounded(wrapped.as_bytes(), 64, 2_000_000).map_err(|_| bad())?;
    let manifest = parsed.get("manifest").ok_or_else(bad)?.clone();
    // PUBLIC direct install carries a resolved executable manifest. Package
    // closure provenance stays local; dependencies require the separate
    // source-matched composition path and are refused by this builder.
    if manifest.get("format_version") == Some(&WireValue::Number(2.0))
        || manifest.get("dependencies") != Some(&WireValue::Array(vec![]))
        || manifest.get("constraints") != Some(&obj(vec![]))
    {
        return Err(bad());
    }
    if sha256_hex(wrapped.as_bytes()) != expected_digest {
        return Err(bad());
    }
    let protocol = obj(vec![
        ("kind", text("protocols")),
        ("id", text(expected_digest)),
        ("revision", WireValue::Number(1.0)),
        ("provenance", text("AUTHOR_SIGNED")),
        (
            "value",
            obj(vec![
                ("workspace_id", text(workspace_id)),
                ("digest", text(expected_digest)),
                ("manifest", manifest.clone()),
                ("resolved_manifest", manifest.clone()),
            ]),
        ),
    ]);
    let instance = obj(vec![
        ("kind", text("instances")),
        ("id", text(instance_id)),
        ("revision", WireValue::Number(1.0)),
        ("provenance", text("AUTHOR_SIGNED")),
        (
            "value",
            obj(vec![
                ("id", text(instance_id)),
                ("workspace_id", text(workspace_id)),
                ("protocol_digest", text(expected_digest)),
                ("origin_entrypoint", text(origin_entrypoint)),
                ("semantics", text("peerwork.kernel.v1")),
                (
                    "state",
                    manifest.get("initial_state").ok_or_else(bad)?.clone(),
                ),
                ("revision", WireValue::Number(0.0)),
                ("event_revision", WireValue::Number(0.0)),
                ("created", WireValue::Number(issued_at as f64)),
            ]),
        ),
    ]);
    canonical_wire_value(
        &WireValue::Array(vec![protocol.clone(), instance.clone()]),
        Path::SecureArtifact,
    )
    .map_err(|_| bad())?;
    Ok(DirectInstallObjects {
        added: vec![protocol, instance],
        manifest,
    })
}

/// Match the PUBLIC planner's `keep_encrypted`: retain every old E2EE field,
/// then make each field of the newly installed protocol E2EE by default.
pub(crate) fn derive_direct_install_structure(
    prior_structure: &WireValue,
    prior_objects: &[WireValue],
    added: &[WireValue],
    protocol_digest: &str,
    manifest: &WireValue,
) -> Result<WireValue, DirectInstallError> {
    let mut choices = Vec::new();
    for protocol in array(required(prior_structure, "protocols")?)? {
        let digest = required(protocol, "protocol_digest")?
            .as_string()
            .ok_or(DirectInstallError::Invalid)?;
        for (schema, definition) in entries(required(protocol, "schemas")?)? {
            let mut fields = Vec::new();
            for (field, details) in entries(required(definition, "fields")?)? {
                if required(details, "protection")?.as_string().as_deref() == Some("e2ee") {
                    fields.push(WireValue::String(field.clone()));
                }
            }
            if !fields.is_empty() {
                choices.push(obj(vec![
                    ("protocol_digest", text(&digest)),
                    ("schema", text(&name(schema)?)),
                    ("fields", WireValue::Array(fields)),
                ]));
            }
        }
    }
    for (schema, definition) in entries(required(manifest, "record_schemas")?)? {
        let fields = entries(required(definition, "fields")?)?
            .iter()
            .map(|(field, _)| WireValue::String(field.clone()))
            .collect::<Vec<_>>();
        if !fields.is_empty() {
            choices.push(obj(vec![
                ("protocol_digest", text(protocol_digest)),
                ("schema", text(&name(schema)?)),
                ("fields", WireValue::Array(fields)),
            ]));
        }
    }
    let all = WireValue::Array(prior_objects.iter().chain(added).cloned().collect());
    let mut all_wire = String::new();
    ordered_json(&all, 0, &mut all_wire)?;
    let mut choice_wire = String::new();
    ordered_json(&WireValue::Array(choices), 0, &mut choice_wire)?;
    let projected = derive_genesis_structure_policy_with_keep_encrypted(
        all_wire.as_bytes(),
        choice_wire.as_bytes(),
    )
    .map_err(|_| DirectInstallError::Invalid)?;
    let mut structure = parse_wire_json_bounded(projected.as_bytes(), 64, 2_000_000)
        .map_err(|_| DirectInstallError::Invalid)?;
    if let Some(coordination) = prior_structure.get("coordination") {
        let WireValue::Object(fields) = &mut structure else {
            return Err(DirectInstallError::Invalid);
        };
        fields.push((key("coordination"), coordination.clone()));
    }
    Ok(structure)
}

/// Build the next PUBLIC signed-policy payload for a direct standalone
/// install. `prior_signed_policy` and checkpoint must be authenticated by the
/// runtime before this proposal can be signed or submitted.
pub(crate) fn derive_direct_install_policy_payload(
    prior_signed_policy: &WireValue,
    checkpoint_sequence: u64,
    structure: &WireValue,
    grants: &[WireValue],
    manifest: &WireValue,
    instance_id: &str,
    issued_at: u64,
) -> Result<WireValue, DirectInstallError> {
    let invalid = || DirectInstallError::Invalid;
    if !token(instance_id)
        || checkpoint_sequence == 0
        || checkpoint_sequence >= 9_007_199_254_740_991
        || issued_at > 9_007_199_254_740_991
        || grants.len() > 128
    {
        return Err(invalid());
    }
    let old = required(prior_signed_policy, "payload")?;
    if required(old, "v")? != &WireValue::Number(3.0)
        || required(old, "visibility")?.as_string().as_deref() != Some("PUBLIC")
        || required(old, "structure_mode")?.as_string().as_deref() != Some("STRUCTURED")
        || required(old, "protocol_format_ceiling")? != &WireValue::Number(1.0)
        || required(old, "structure")?.object_len().is_none()
        || prior_signed_policy
            .get("signature")
            .and_then(WireValue::as_string)
            .is_none()
    {
        return Err(invalid());
    }
    let version = safe_int(required(old, "version")?)?
        .checked_add(1)
        .ok_or_else(invalid)?;
    let signed_wire =
        canonical_wire_value(prior_signed_policy, Path::SecureArtifact).map_err(|_| invalid())?;
    let previous = sha256_hex(signed_wire.as_bytes());
    let mut members = array(required(old, "members")?)?.to_vec();
    let mut seen = HashSet::new();
    for grant in grants {
        let actor = required(grant, "actor_id")?
            .as_string()
            .ok_or_else(invalid)?;
        if !token(&actor) || !seen.insert(actor.clone()) {
            return Err(invalid());
        }
        let member = members
            .iter_mut()
            .find(|member| {
                member
                    .get("actor_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&actor)
            })
            .ok_or_else(invalid)?;
        let WireValue::Object(grant_fields) = grant else {
            return Err(invalid());
        };
        if grant_fields.iter().any(|(name, _)| {
            ![
                "actor_id",
                "actions",
                "protocol_roles",
                "capabilities",
                "expires_at",
            ]
            .iter()
            .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
        }) {
            return Err(invalid());
        }
        for (scope_key, manifest_key) in [
            ("actions", "actions"),
            ("protocol_roles", "protocol_roles"),
            ("capabilities", "capabilities"),
        ] {
            let values = array(required(grant, scope_key)?)?;
            let declared = array(required(manifest, manifest_key)?)?;
            for value in values {
                if value.as_utf16().is_none()
                    || !declared.iter().any(|item| {
                        if manifest_key == "actions" {
                            item.get("id") == Some(value)
                        } else {
                            item == value
                        }
                    })
                {
                    return Err(invalid());
                }
            }
        }
        let mut scope = WireValue::Object(
            grant_fields
                .iter()
                .filter(|(name, _)| !name.iter().copied().eq("actor_id".encode_utf16()))
                .cloned()
                .collect(),
        );
        put(&mut scope, "instance_id", text(instance_id))?;
        let mut scopes = array(required(member, "scopes")?)?.to_vec();
        scopes.push(scope);
        put(member, "scopes", WireValue::Array(scopes))?;
    }
    let mut payload = old.clone();
    put(&mut payload, "structure", structure.clone())?;
    put(&mut payload, "members", WireValue::Array(members))?;
    put(&mut payload, "version", WireValue::Number(version as f64))?;
    put(&mut payload, "previous_policy", text(&previous))?;
    put(
        &mut payload,
        "effective_sequence",
        WireValue::Number((checkpoint_sequence + 1) as f64),
    )?;
    put(
        &mut payload,
        "issued_at",
        WireValue::Number(issued_at as f64),
    )?;
    canonical_wire_value(&payload, Path::SecureArtifact).map_err(|_| invalid())?;
    Ok(payload)
}

/// First-install narrow snapshot: only when authenticated prior structure has
/// no records or heads. Other histories need projected snapshot paging.
pub(crate) fn build_empty_direct_install_begin(
    checkpoint: &WireValue,
    added: &[WireValue],
    instance_id: &str,
    protocol_digest: &str,
    entrypoint_name: &str,
) -> Result<EmptySnapshotBegin, DirectInstallError> {
    if !token(instance_id)
        || !entrypoint(entrypoint_name)
        || protocol_digest.len() != 64
        || !protocol_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(DirectInstallError::Invalid);
    }
    let empty_data = obj(vec![
        ("records", WireValue::Array(vec![])),
        ("heads", WireValue::Array(vec![])),
    ]);
    let root = sha256_hex(
        canonical_wire_value(&empty_data, Path::SecureArtifact)
            .map_err(|_| DirectInstallError::Invalid)?
            .as_bytes(),
    );
    let snapshot = obj(vec![
        ("source", checkpoint.clone()),
        ("root", text(&root)),
        ("records", WireValue::Number(0.0)),
        ("heads", WireValue::Number(0.0)),
        ("offset", WireValue::Number(0.0)),
    ]);
    let structure = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("mode", text("SNAPSHOT_BEGIN")),
        ("records", WireValue::Array(vec![])),
        ("heads", WireValue::Array(vec![])),
        ("snapshot", snapshot),
    ]);
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", text("ADMIN")),
        (
            "input",
            obj(vec![(
                "install",
                obj(vec![
                    ("instance_id", text(instance_id)),
                    ("protocol_digest", text(protocol_digest)),
                    ("entrypoint", text(entrypoint_name)),
                ]),
            )]),
        ),
        ("objects", WireValue::Array(added.to_vec())),
    ]);
    Ok(EmptySnapshotBegin {
        operation,
        structure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_public_direct_objects_match_pinned_planner() {
        let fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-direct-install-vectors.json"),
            64,
            500_000,
        )
        .unwrap();
        let expected = fixture.get("added").unwrap();
        let manifest = fixture.get("options").unwrap().get("manifest").unwrap();
        let manifest_wire = canonical_wire_value(manifest, Path::SecureArtifact).unwrap();
        let result = build_direct_install_objects(
            manifest_wire.as_bytes(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &fixture.get("workspace_id").unwrap().as_string().unwrap(),
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(
                &WireValue::Array(result.added.clone()),
                Path::SecureArtifact
            )
            .unwrap(),
            canonical_wire_value(expected, Path::SecureArtifact).unwrap()
        );
        assert_eq!(
            canonical_wire_value(&result.manifest, Path::SecureArtifact).unwrap(),
            canonical_wire_value(manifest, Path::SecureArtifact).unwrap()
        );
        let WireValue::Array(prior) = fixture.get("prior_objects").unwrap() else {
            panic!("prior objects")
        };
        let structure = derive_direct_install_structure(
            fixture
                .get("prior_policy")
                .unwrap()
                .get("payload")
                .unwrap()
                .get("structure")
                .unwrap(),
            prior,
            &result.added,
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &result.manifest,
        )
        .unwrap();
        let actual = canonical_wire_value(&structure, Path::SecureArtifact).unwrap();
        let expected =
            canonical_wire_value(fixture.get("structure").unwrap(), Path::SecureArtifact).unwrap();
        if actual != expected {
            let index = actual
                .bytes()
                .zip(expected.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(actual.len().min(expected.len()));
            panic!(
                "structure mismatch at {index}: actual {:?}, expected {:?}",
                &actual[index.saturating_sub(60)..(index + 100).min(actual.len())],
                &expected[index.saturating_sub(60)..(index + 100).min(expected.len())]
            );
        }
        let policy = derive_direct_install_policy_payload(
            fixture.get("prior_policy").unwrap(),
            1,
            &structure,
            match fixture.get("options").unwrap().get("grants").unwrap() {
                WireValue::Array(items) => items,
                _ => panic!("grants"),
            },
            &result.manifest,
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(&policy, Path::SecureArtifact).unwrap(),
            canonical_wire_value(fixture.get("policy_payload").unwrap(), Path::SecureArtifact)
                .unwrap()
        );
        let begin = build_empty_direct_install_begin(
            fixture.get("checkpoint").unwrap(),
            &result.added,
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(&begin.operation, Path::SecureArtifact).unwrap(),
            canonical_wire_value(
                fixture.get("begin_operation").unwrap(),
                Path::SecureArtifact
            )
            .unwrap()
        );
        assert_eq!(
            canonical_wire_value(&begin.structure, Path::SecureArtifact).unwrap(),
            canonical_wire_value(
                fixture.get("begin_structure").unwrap(),
                Path::SecureArtifact
            )
            .unwrap()
        );
        assert!(matches!(
            build_direct_install_objects(
                manifest_wire.as_bytes(),
                &"0".repeat(64),
                "w".repeat(43).as_str(),
                "z".repeat(43).as_str(),
                "proposalAdoption",
                2
            ),
            Err(DirectInstallError::Invalid)
        ));
    }
}
