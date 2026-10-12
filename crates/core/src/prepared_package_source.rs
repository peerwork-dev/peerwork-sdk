//! Exact package material/part construction from a caller-provided checkpoint.
//! Compilation and byte integrity are checked, but the checkpoint is not
//! authenticated here. This result cannot authorize a stage POST or install.

use crate::{
    canonical::Path,
    crypto::sha256_hex,
    package_closure::{compile_package_material, scan_package_closure},
    protocol_package_source::{
        package_part_id, package_source_id, validate_package_checkpoint, validate_package_part,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};

const MAX_SOURCE_BYTES: usize = 8192;
const MAX_MATERIAL_BYTES: usize = 8 * 1024 * 1024;
const SOURCE_MATERIAL_LIMIT: usize = 6 * 1024 * 1024 + 32 * 6 * 8192 + 64 * 1024;
const PART_BYTES: usize = 64 * 1024;
const PARTS: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreparePackageSourceError {
    Invalid,
    Resource,
}

pub(crate) struct PreparedPackageSource {
    pub proof: WireValue,
    pub parts: Vec<WireValue>,
    pub canonical_material: String,
}

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
fn scalar(value: &WireValue) -> Result<String, PreparePackageSourceError> {
    value.as_string().ok_or(PreparePackageSourceError::Invalid)
}
fn canonical(value: &WireValue) -> Result<String, PreparePackageSourceError> {
    canonical_wire_value(value, Path::SecureArtifact)
        .map_err(|_| PreparePackageSourceError::Invalid)
}

pub(crate) fn prepare_package_source_wire(
    material_wire: &[u8],
    source_wire: &[u8],
) -> Result<PreparedPackageSource, PreparePackageSourceError> {
    use PreparePackageSourceError::{Invalid, Resource};
    if material_wire.is_empty()
        || material_wire.len() > MAX_MATERIAL_BYTES
        || source_wire.is_empty()
        || source_wire.len() > MAX_SOURCE_BYTES
    {
        return Err(Resource);
    }
    let source = parse_wire_json_bounded(source_wire, 32, MAX_SOURCE_BYTES).map_err(|_| Invalid)?;
    validate_package_checkpoint(&source).map_err(|_| Invalid)?;
    let material =
        parse_wire_json_bounded(material_wire, 64, MAX_MATERIAL_BYTES).map_err(|_| Invalid)?;
    if material.object_len() != Some(3) || material.get("v") != Some(&WireValue::Number(1.0)) {
        return Err(Invalid);
    }
    let closure = material.get("closure").ok_or(Invalid)?;
    let bindings = material.get("bindings").ok_or(Invalid)?;
    if bindings.object_len().is_none() {
        return Err(Invalid);
    }
    let scanned = scan_package_closure(closure).map_err(|_| Invalid)?;
    let normalized_closure = parse_wire_json_bounded(&scanned.canonical_bytes, 32, 6 * 1024 * 1024)
        .map_err(|_| Invalid)?;
    let normalized_bindings_wire = canonical(bindings)?;
    let normalized_bindings =
        parse_wire_json_bounded(normalized_bindings_wire.as_bytes(), 32, MAX_MATERIAL_BYTES)
            .map_err(|_| Invalid)?;
    let compiled = compile_package_material(&scanned, &normalized_bindings).map_err(|_| Invalid)?;
    let material = object(vec![
        ("v", WireValue::Number(1.0)),
        ("closure", normalized_closure),
        ("bindings", normalized_bindings),
    ]);
    let canonical_material = canonical(&material)?;
    if canonical_material.len() > SOURCE_MATERIAL_LIMIT {
        return Err(Resource);
    }
    let source_sha256 = sha256_hex(canonical_material.as_bytes());
    let source_id = package_source_id(&source, &source_sha256).map_err(|_| Invalid)?;
    let workspace_id = scalar(source.get("workspace_id").ok_or(Invalid)?)?;
    let units: Vec<u16> = canonical_material.encode_utf16().collect();
    let mut offset = 0usize;
    let mut parts = Vec::new();
    let mut descriptors = Vec::new();
    while offset < units.len() {
        if parts.len() >= PARTS {
            return Err(Resource);
        }
        let index = parts.len();
        let id = package_part_id(&source, &source_id, index).map_err(|_| Invalid)?;
        let mut low = offset + 1;
        let mut high = units.len().min(offset + PART_BYTES);
        let mut chosen: Option<(usize, WireValue, usize, String)> = None;
        while low <= high {
            let middle = low + (high - low) / 2;
            let mut boundary = middle;
            if boundary < units.len()
                && boundary > offset
                && (0xd800..=0xdbff).contains(&units[boundary - 1])
                && (0xdc00..=0xdfff).contains(&units[boundary])
            {
                boundary -= 1;
            }
            if boundary <= offset {
                low = middle + 1;
                continue;
            }
            let piece = String::from_utf16(&units[offset..boundary]).map_err(|_| Invalid)?;
            let bytes = piece.len();
            let digest = sha256_hex(piece.as_bytes());
            let part = object(vec![
                ("kind", text("protocol_package_part")),
                ("id", text(&id)),
                ("revision", WireValue::Number(1.0)),
                ("provenance", text("AUTHOR_SIGNED")),
                (
                    "value",
                    object(vec![
                        ("v", WireValue::Number(1.0)),
                        ("workspace_id", text(&workspace_id)),
                        ("source_id", text(&source_id)),
                        ("index", WireValue::Number(index as f64)),
                        ("bytes", WireValue::Number(bytes as f64)),
                        ("sha256", text(&digest)),
                        ("text", text(&piece)),
                    ]),
                ),
            ]);
            if bytes <= PART_BYTES && canonical(&part)?.len() <= 98_304 {
                chosen = Some((boundary, part, bytes, digest));
                low = middle + 1;
            } else {
                if middle == 0 {
                    break;
                }
                high = middle - 1;
            }
        }
        let (next, part, bytes, digest) = chosen.ok_or(Resource)?;
        validate_package_part(&part).map_err(|_| Invalid)?;
        descriptors.push(object(vec![
            ("id", text(&id)),
            ("index", WireValue::Number(index as f64)),
            ("sha256", text(&digest)),
            ("bytes", WireValue::Number(bytes as f64)),
        ]));
        parts.push(part);
        offset = next;
    }
    let closure_digest = sha256_hex(&scanned.canonical_bytes);
    let compilation_lock_sha256 = sha256_hex(canonical(&compiled.compilation_lock)?.as_bytes());
    let proof = object(vec![
        ("v", WireValue::Number(1.0)),
        ("workspace_id", text(&workspace_id)),
        ("source", source),
        ("source_id", text(&source_id)),
        ("source_sha256", text(&source_sha256)),
        ("bytes", WireValue::Number(canonical_material.len() as f64)),
        ("parts", WireValue::Array(descriptors)),
        ("root_package_digest", text(&scanned.root)),
        ("closure_digest", text(&closure_digest)),
        ("compilation_lock_sha256", text(&compilation_lock_sha256)),
        ("protocol_digest", text(&compiled.protocol_digest)),
    ]);
    Ok(PreparedPackageSource {
        proof,
        parts,
        canonical_material,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_package_source::verify_protocol_package_source;

    #[test]
    fn exact_official_package_matches_pinned_typescript_source_and_parts() {
        let cases = parse_wire_json_bounded(
            include_bytes!("../../../conformance/protocol-package-source-vectors.json"),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("cases")
        };
        let valid = &cases[0];
        let expected_proof = valid.get("proof").unwrap();
        let expected_parts = valid.get("parts").unwrap();
        let public = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-package-vectors.json"),
            64,
            2_000_000,
        )
        .unwrap();
        let material = object(vec![
            ("v", WireValue::Number(1.0)),
            ("closure", public.get("closure").unwrap().clone()),
            ("bindings", object(vec![])),
        ]);
        let result = prepare_package_source_wire(
            canonical(&material).unwrap().as_bytes(),
            canonical(expected_proof.get("source").unwrap())
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            canonical(&result.proof).unwrap(),
            canonical(expected_proof).unwrap()
        );
        assert_eq!(
            canonical(&WireValue::Array(result.parts.clone())).unwrap(),
            canonical(expected_parts).unwrap()
        );
        assert_eq!(
            sha256_hex(result.canonical_material.as_bytes()),
            scalar(expected_proof.get("source_sha256").unwrap()).unwrap()
        );
        let verified = verify_protocol_package_source(&result.proof, &result.parts).unwrap();
        assert_eq!(
            verified.protocol_digest,
            scalar(expected_proof.get("protocol_digest").unwrap()).unwrap()
        );
    }
}
