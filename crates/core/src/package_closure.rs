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
                assert_eq!(scanned.packages.len(), 1);
                assert_eq!(
                    scanned.canonical_bytes,
                    decode_base64url(case["canonical_closure_base64"].as_str().unwrap()).unwrap()
                );
                assert_eq!(
                    bundle_bytes(scanned.packages.get(&scanned.root).unwrap()).unwrap(),
                    decode_base64url(case["canonical_package_base64"].as_str().unwrap()).unwrap()
                );
            } else {
                assert!(scan_package_closure(&closure).is_err());
            }
        }
    }
}
