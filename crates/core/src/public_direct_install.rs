//! Source-matched object proposal for a direct PUBLIC protocol install.
//! The caller must bind this proposal to complete authenticated replay,
//! owner policy, signed ADMIN snapshot, and exact saved transport bytes.

use crate::{
    canonical::Path,
    crypto::sha256_hex,
    full_manifest::validate_full_manifest,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DirectInstallError {
    Invalid,
    Resource,
}

pub(crate) struct DirectInstallObjects {
    pub added: Vec<WireValue>,
    pub manifest: WireValue,
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
