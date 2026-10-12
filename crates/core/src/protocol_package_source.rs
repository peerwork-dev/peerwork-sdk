//! Private retained package-source verification. A successful result is input
//! to journal replay, never an authority proof by itself.

use crate::{
    canonical::Path,
    crypto::sha256_hex,
    package_closure::{compile_package_material, scan_package_closure},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};

const PART_BYTES: usize = 64 * 1024;
const MAX_PARTS: usize = 128;
const MATERIAL_BYTES: usize = 6 * 1024 * 1024 + 32 * 6 * 8192 + 64 * 1024;
const OBJECT_BYTES: usize = 98_304;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PackageSourceError {
    Invalid,
    Resource,
    Missing,
    Mismatch,
}
use PackageSourceError::{Invalid, Mismatch, Missing, Resource};

pub(crate) struct VerifiedPackageMaterial {
    pub manifest: WireValue,
    pub protocol_digest: String,
    pub source: WireValue,
    pub part_count: usize,
}

fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue, PackageSourceError> {
    value.get(name).ok_or(Invalid)
}
fn scalar(value: &WireValue) -> Result<String, PackageSourceError> {
    value.as_string().ok_or(Invalid)
}
fn exact(value: &WireValue, keys: &[&str]) -> bool {
    let WireValue::Object(fields) = value else {
        return false;
    };
    fields.len() == keys.len() && keys.iter().all(|key| value.get(key).is_some())
}
fn integer(value: &WireValue) -> Result<u64, PackageSourceError> {
    let n = value.as_number().ok_or(Invalid)?;
    if !n.is_finite() || n < 0.0 || n > MAX_SAFE || n.fract() != 0.0 {
        return Err(Invalid);
    }
    Ok(n as u64)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn canonical(value: &WireValue) -> Result<String, PackageSourceError> {
    canonical_wire_value(value, Path::SecureArtifact).map_err(|_| Invalid)
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
pub(crate) fn validate_package_checkpoint(value: &WireValue) -> Result<(), PackageSourceError> {
    if !exact(
        value,
        &[
            "v",
            "workspace_id",
            "owner_id",
            "owner_key",
            "sequence",
            "head",
            "policy_hash",
        ],
    ) || integer(field(value, "v")?)? != 1
        || integer(field(value, "sequence")?)? < 1
    {
        return Err(Invalid);
    }
    for key in ["workspace_id", "owner_id", "owner_key"] {
        if !token(&scalar(field(value, key)?)?) {
            return Err(Invalid);
        }
    }
    for key in ["head", "policy_hash"] {
        if !digest(&scalar(field(value, key)?)?) {
            return Err(Invalid);
        }
    }
    Ok(())
}
pub(crate) fn package_source_id(
    source: &WireValue,
    hash: &str,
) -> Result<String, PackageSourceError> {
    let value = object(vec![
        ("source", source.clone()),
        ("source_sha256", string(hash)),
    ]);
    Ok(sha256_hex(
        format!(
            "peerwork.protocol-package-source.v1\0{}",
            canonical(&value)?
        )
        .as_bytes(),
    ))
}
pub(crate) fn package_part_id(
    source: &WireValue,
    id: &str,
    index: usize,
) -> Result<String, PackageSourceError> {
    let value = object(vec![
        ("source", source.clone()),
        ("source_id", string(id)),
        ("index", WireValue::Number(index as f64)),
    ]);
    Ok(sha256_hex(
        format!("peerwork.protocol-package-part.v1\0{}", canonical(&value)?).as_bytes(),
    ))
}
pub(crate) fn validate_package_part(part: &WireValue) -> Result<(), PackageSourceError> {
    if !exact(part, &["kind", "id", "revision", "provenance", "value"])
        || scalar(field(part, "kind")?)? != "protocol_package_part"
        || !digest(&scalar(field(part, "id")?)?)
        || integer(field(part, "revision")?)? != 1
        || scalar(field(part, "provenance")?)? != "AUTHOR_SIGNED"
    {
        return Err(Invalid);
    }
    let value = field(part, "value")?;
    if !exact(
        value,
        &[
            "v",
            "workspace_id",
            "source_id",
            "index",
            "bytes",
            "sha256",
            "text",
        ],
    ) || integer(field(value, "v")?)? != 1
        || !token(&scalar(field(value, "workspace_id")?)?)
        || !digest(&scalar(field(value, "source_id")?)?)
        || integer(field(value, "index")?)? >= MAX_PARTS as u64
        || !digest(&scalar(field(value, "sha256")?)?)
    {
        return Err(Invalid);
    }
    let text = scalar(field(value, "text")?)?;
    if text.is_empty()
        || text.len() > PART_BYTES
        || integer(field(value, "bytes")?)? != text.len() as u64
        || sha256_hex(text.as_bytes()) != scalar(field(value, "sha256")?)?
        || canonical(part)?.len() > OBJECT_BYTES
    {
        return Err(Resource);
    }
    Ok(())
}

pub(crate) fn verify_protocol_package_source(
    proof: &WireValue,
    objects: &[WireValue],
) -> Result<VerifiedPackageMaterial, PackageSourceError> {
    if !exact(
        proof,
        &[
            "v",
            "workspace_id",
            "source",
            "source_id",
            "source_sha256",
            "bytes",
            "parts",
            "root_package_digest",
            "closure_digest",
            "compilation_lock_sha256",
            "protocol_digest",
        ],
    ) || integer(field(proof, "v")?)? != 1
    {
        return Err(Invalid);
    }
    let source = field(proof, "source")?;
    validate_package_checkpoint(source)?;
    let workspace = scalar(field(proof, "workspace_id")?)?;
    let source_hash = scalar(field(proof, "source_sha256")?)?;
    let id = scalar(field(proof, "source_id")?)?;
    let total = integer(field(proof, "bytes")?)? as usize;
    if workspace != scalar(field(source, "workspace_id")?)?
        || !digest(&source_hash)
        || !digest(&id)
        || id != package_source_id(source, &source_hash)?
        || !(1..=MATERIAL_BYTES).contains(&total)
    {
        return Err(Invalid);
    }
    for name in [
        "root_package_digest",
        "closure_digest",
        "compilation_lock_sha256",
        "protocol_digest",
    ] {
        if !digest(&scalar(field(proof, name)?)?) {
            return Err(Invalid);
        }
    }
    let WireValue::Array(descriptors) = field(proof, "parts")? else {
        return Err(Invalid);
    };
    if descriptors.is_empty() || descriptors.len() > MAX_PARTS {
        return Err(Resource);
    }
    let related = objects
        .iter()
        .filter(|row| {
            row.get("kind").and_then(WireValue::as_string).as_deref()
                == Some("protocol_package_part")
                && row
                    .get("value")
                    .and_then(|value| value.get("source_id"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&id)
        })
        .collect::<Vec<_>>();
    if related.len() != descriptors.len() {
        return Err(Missing);
    }
    let mut bytes = Vec::with_capacity(total);
    let mut sum = 0usize;
    for (index, descriptor) in descriptors.iter().enumerate() {
        if !exact(descriptor, &["id", "index", "sha256", "bytes"])
            || integer(field(descriptor, "index")?)? != index as u64
        {
            return Err(Invalid);
        }
        let expected_id = package_part_id(source, &id, index)?;
        let hash = scalar(field(descriptor, "sha256")?)?;
        let length = integer(field(descriptor, "bytes")?)? as usize;
        if scalar(field(descriptor, "id")?)? != expected_id
            || !digest(&hash)
            || !(1..=PART_BYTES).contains(&length)
        {
            return Err(Invalid);
        }
        sum = sum
            .checked_add(length)
            .filter(|n| *n <= MATERIAL_BYTES)
            .ok_or(Resource)?;
        let matching = related
            .iter()
            .filter(|row| {
                row.get("id").and_then(WireValue::as_string).as_deref() == Some(&expected_id)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(Missing);
        }
        let row = matching[0];
        validate_package_part(row)?;
        let value = field(row, "value")?;
        if scalar(field(value, "workspace_id")?)? != workspace
            || scalar(field(value, "source_id")?)? != id
            || integer(field(value, "index")?)? != index as u64
            || integer(field(value, "bytes")?)? as usize != length
            || scalar(field(value, "sha256")?)? != hash
        {
            return Err(Mismatch);
        }
        bytes.extend_from_slice(scalar(field(value, "text")?)?.as_bytes());
    }
    if sum != total || bytes.len() != total || sha256_hex(&bytes) != source_hash {
        return Err(Mismatch);
    }
    let material = parse_wire_json_bounded(&bytes, 64, MATERIAL_BYTES).map_err(|_| Invalid)?;
    if !exact(&material, &["v", "closure", "bindings"])
        || integer(field(&material, "v")?)? != 1
        || field(&material, "bindings")?.object_len().is_none()
        || canonical_wire_value(field(&material, "bindings")?, Path::STRUCTURED).is_err()
        || canonical(&material)?.as_bytes() != bytes
    {
        return Err(Mismatch);
    }
    let closure = field(&material, "closure")?;
    let scanned = scan_package_closure(closure).map_err(|_| Invalid)?;
    if scanned.root != scalar(field(proof, "root_package_digest")?)?
        || sha256_hex(&scanned.canonical_bytes) != scalar(field(proof, "closure_digest")?)?
    {
        return Err(Mismatch);
    }
    let compiled =
        compile_package_material(&scanned, field(&material, "bindings")?).map_err(|_| Invalid)?;
    if compiled.protocol_digest != scalar(field(proof, "protocol_digest")?)?
        || sha256_hex(canonical(&compiled.compilation_lock)?.as_bytes())
            != scalar(field(proof, "compilation_lock_sha256")?)?
    {
        return Err(Mismatch);
    }
    Ok(VerifiedPackageMaterial {
        manifest: compiled.manifest,
        protocol_digest: compiled.protocol_digest,
        source: source.clone(),
        part_count: descriptors.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_typescript_retained_package_source_proof() {
        let vectors = parse_wire_json_bounded(
            include_str!("../../../conformance/protocol-package-source-vectors.json").as_bytes(),
            96,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = vectors else {
            panic!("expected vector array")
        };
        for case in cases {
            let name = field(&case, "name").unwrap().as_string().unwrap();
            let WireValue::Array(parts) = field(&case, "parts").unwrap() else {
                panic!("expected part array")
            };
            let result = verify_protocol_package_source(field(&case, "proof").unwrap(), parts);
            if let Some(expected) = case.get("result") {
                let valid = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(
                    valid.protocol_digest,
                    scalar(field(expected, "protocol_digest").unwrap()).unwrap(),
                    "{name}"
                );
                assert_eq!(
                    canonical(&valid.manifest).unwrap(),
                    canonical(field(expected, "manifest").unwrap()).unwrap(),
                    "{name}"
                );
                assert_eq!(valid.part_count, parts.len(), "{name}");
            } else {
                assert!(result.is_err(), "{name}");
            }
        }
    }
}
