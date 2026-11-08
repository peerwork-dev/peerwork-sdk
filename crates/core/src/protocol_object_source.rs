//! Private retained protocol-object source proof. Does not authorize a journal.
use crate::{
    canonical::Path,
    crypto::sha256_hex,
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};

const VALUE_BYTES: usize = 32 * 1024 * 1024;
const PART_BYTES: usize = 64 * 1024;
const PARTS: usize = 2048;
pub(crate) const OBJECT_BYTES: usize = 98_304;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ObjectSourceError {
    Invalid,
    Resource,
    Missing,
    Mismatch,
}
fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue, ObjectSourceError> {
    value.get(name).ok_or(ObjectSourceError::Invalid)
}
fn exact(value: &WireValue, required: &[&str]) -> bool {
    let WireValue::Object(fields) = value else {
        return false;
    };
    fields.len() == required.len() && required.iter().all(|name| value.get(name).is_some())
}
fn scalar(value: &WireValue) -> Result<String, ObjectSourceError> {
    value.as_string().ok_or(ObjectSourceError::Invalid)
}
fn integer(value: &WireValue) -> Result<u64, ObjectSourceError> {
    let n = value.as_number().ok_or(ObjectSourceError::Invalid)?;
    if !n.is_finite() || n < 0.0 || n > 9_007_199_254_740_991.0 || n.fract() != 0.0 {
        return Err(ObjectSourceError::Invalid);
    }
    Ok(n as u64)
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, b'a'..=b'f'))
}
fn canonical(value: &WireValue) -> Result<String, ObjectSourceError> {
    canonical_wire_value(value, Path::SecureArtifact).map_err(|_| ObjectSourceError::Invalid)
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
fn checkpoint(value: &WireValue) -> Result<(), ObjectSourceError> {
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
        || integer(field(value, "sequence")?)? == 0
    {
        return Err(ObjectSourceError::Invalid);
    }
    for key in ["workspace_id", "owner_id", "owner_key"] {
        if !token(&scalar(field(value, key)?)?) {
            return Err(ObjectSourceError::Invalid);
        }
    }
    for key in ["head", "policy_hash"] {
        if !digest(&scalar(field(value, key)?)?) {
            return Err(ObjectSourceError::Invalid);
        }
    }
    Ok(())
}
fn value_shape(
    value: &WireValue,
    workspace: &str,
    protocol: &str,
) -> Result<(), ObjectSourceError> {
    let WireValue::Object(fields) = value else {
        return Err(ObjectSourceError::Invalid);
    };
    let optional = ["composition", "package_source"];
    if fields.len() < 4
        || fields.len() > 6
        || ["workspace_id", "digest", "manifest", "resolved_manifest"]
            .iter()
            .any(|key| value.get(key).is_none())
        || fields.iter().any(|(name, _)| {
            !["workspace_id", "digest", "manifest", "resolved_manifest"]
                .iter()
                .chain(optional.iter())
                .any(|key| name.iter().copied().eq(key.encode_utf16()))
        })
        || scalar(field(value, "workspace_id")?)? != workspace
        || scalar(field(value, "digest")?)? != protocol
    {
        return Err(ObjectSourceError::Invalid);
    }
    Ok(())
}
fn source_id(
    source: &WireValue,
    protocol: &str,
    value_hash: &str,
) -> Result<String, ObjectSourceError> {
    let envelope = object(vec![
        ("source", source.clone()),
        ("protocol_digest", string(protocol)),
        ("value_sha256", string(value_hash)),
    ]);
    Ok(sha256_hex(
        format!(
            "peerwork.protocol-object-source.v1\0{}",
            canonical(&envelope)?
        )
        .as_bytes(),
    ))
}
pub(crate) fn object_part_id(
    source: &WireValue,
    source_id: &str,
    index: usize,
) -> Result<String, ObjectSourceError> {
    let envelope = object(vec![
        ("source", source.clone()),
        ("source_id", string(source_id)),
        ("index", WireValue::Number(index as f64)),
    ]);
    Ok(sha256_hex(
        format!(
            "peerwork.protocol-object-part.v1\0{}",
            canonical(&envelope)?
        )
        .as_bytes(),
    ))
}
pub(crate) fn validate_object_part(part: &WireValue) -> Result<(), ObjectSourceError> {
    if !exact(part, &["kind", "id", "revision", "provenance", "value"])
        || scalar(field(part, "kind")?)? != "protocol_object_part"
        || !digest(&scalar(field(part, "id")?)?)
        || integer(field(part, "revision")?)? != 1
        || scalar(field(part, "provenance")?)? != "AUTHOR_SIGNED"
    {
        return Err(ObjectSourceError::Invalid);
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
        || integer(field(value, "index")?)? >= PARTS as u64
        || !digest(&scalar(field(value, "sha256")?)?)
    {
        return Err(ObjectSourceError::Invalid);
    }
    let text = scalar(field(value, "text")?)?;
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > PART_BYTES
        || integer(field(value, "bytes")?)? != bytes.len() as u64
        || sha256_hex(bytes) != scalar(field(value, "sha256")?)?
        || canonical(part)?.len() > OBJECT_BYTES
    {
        return Err(ObjectSourceError::Resource);
    }
    Ok(())
}

pub(crate) fn validate_object_source_proof(proof: &WireValue) -> Result<(), ObjectSourceError> {
    if !exact(
        proof,
        &[
            "v",
            "workspace_id",
            "source",
            "source_id",
            "protocol_digest",
            "value_sha256",
            "bytes",
            "parts",
        ],
    ) || integer(field(proof, "v")?)? != 1
    {
        return Err(ObjectSourceError::Invalid);
    }
    let source = field(proof, "source")?;
    checkpoint(source)?;
    let workspace = scalar(field(proof, "workspace_id")?)?;
    let protocol = scalar(field(proof, "protocol_digest")?)?;
    let value_hash = scalar(field(proof, "value_sha256")?)?;
    let source_hash = scalar(field(proof, "source_id")?)?;
    let total = integer(field(proof, "bytes")?)? as usize;
    if workspace != scalar(field(source, "workspace_id")?)?
        || !digest(&protocol)
        || !digest(&value_hash)
        || !digest(&source_hash)
        || source_hash != source_id(source, &protocol, &value_hash)?
        || !(1..=VALUE_BYTES).contains(&total)
    {
        return Err(ObjectSourceError::Invalid);
    }
    let WireValue::Array(descriptors) = field(proof, "parts")? else {
        return Err(ObjectSourceError::Invalid);
    };
    if descriptors.is_empty() || descriptors.len() > PARTS {
        return Err(ObjectSourceError::Resource);
    }
    let mut sum = 0usize;
    for (index, descriptor) in descriptors.iter().enumerate() {
        let length = integer(field(descriptor, "bytes")?)? as usize;
        if !exact(descriptor, &["id", "index", "sha256", "bytes"])
            || integer(field(descriptor, "index")?)? != index as u64
            || scalar(field(descriptor, "id")?)? != object_part_id(source, &source_hash, index)?
            || !digest(&scalar(field(descriptor, "sha256")?)?)
            || !(1..=PART_BYTES).contains(&length)
        {
            return Err(ObjectSourceError::Invalid);
        }
        sum = sum
            .checked_add(length)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or(ObjectSourceError::Resource)?;
    }
    if sum != total {
        return Err(ObjectSourceError::Invalid);
    }
    Ok(())
}

/// Pure bounded source construction. Signed ancestry and Owner authority must
/// be established by the caller before authoring any staging packet.
pub(crate) fn prepare_protocol_object_source(
    value: &WireValue, source: &WireValue,
) -> Result<(WireValue, Vec<WireValue>), ObjectSourceError> {
    checkpoint(source)?;
    let workspace = scalar(field(source, "workspace_id")?)?;
    let protocol = scalar(field(value, "digest")?)?;
    if !digest(&protocol) { return Err(ObjectSourceError::Invalid); }
    value_shape(value, &workspace, &protocol)?;
    let text = canonical(value)?;
    if text.is_empty() || text.len() > VALUE_BYTES { return Err(ObjectSourceError::Resource); }
    let value_hash = sha256_hex(text.as_bytes());
    let id = source_id(source, &protocol, &value_hash)?;
    let mut parts = Vec::new();
    let mut descriptors = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        if parts.len() >= PARTS { return Err(ObjectSourceError::Resource); }
        let index = parts.len();
        let part_id = object_part_id(source, &id, index)?;
        let mut low = offset + 1;
        let mut high = (offset + PART_BYTES).min(text.len());
        let mut chosen = None;
        while low <= high {
            let middle = low + (high - low) / 2;
            let mut end = middle;
            while end > offset && !text.is_char_boundary(end) { end -= 1; }
            let piece = &text[offset..end];
            let part = object(vec![
                ("kind", string("protocol_object_part")), ("id", string(&part_id)),
                ("revision", WireValue::Number(1.0)), ("provenance", string("AUTHOR_SIGNED")),
                ("value", object(vec![
                    ("v", WireValue::Number(1.0)), ("workspace_id", string(&workspace)),
                    ("source_id", string(&id)), ("index", WireValue::Number(index as f64)),
                    ("bytes", WireValue::Number(piece.len() as f64)),
                    ("sha256", string(&sha256_hex(piece.as_bytes()))), ("text", string(piece)),
                ])),
            ]);
            if end > offset && canonical(&part)?.len() <= OBJECT_BYTES {
                chosen = Some((end, part)); low = middle + 1;
            } else { high = middle - 1; }
        }
        let (end, part) = chosen.ok_or(ObjectSourceError::Resource)?;
        validate_object_part(&part)?;
        let v = field(&part, "value")?;
        descriptors.push(object(vec![
            ("id", string(&part_id)), ("index", WireValue::Number(index as f64)),
            ("sha256", field(v, "sha256")?.clone()), ("bytes", field(v, "bytes")?.clone()),
        ]));
        parts.push(part); offset = end;
    }
    let proof = object(vec![
        ("v", WireValue::Number(1.0)), ("workspace_id", string(&workspace)),
        ("source", source.clone()), ("source_id", string(&id)),
        ("protocol_digest", string(&protocol)), ("value_sha256", string(&value_hash)),
        ("bytes", WireValue::Number(text.len() as f64)), ("parts", WireValue::Array(descriptors)),
    ]);
    validate_object_source_proof(&proof)?;
    if canonical(&read_protocol_object_source(&proof, &parts)?)? != text { return Err(ObjectSourceError::Mismatch); }
    Ok((proof, parts))
}

pub(crate) fn read_protocol_object_source(
    proof: &WireValue,
    objects: &[WireValue],
) -> Result<WireValue, ObjectSourceError> {
    validate_object_source_proof(proof)?;
    if !exact(
        proof,
        &[
            "v",
            "workspace_id",
            "source",
            "source_id",
            "protocol_digest",
            "value_sha256",
            "bytes",
            "parts",
        ],
    ) || integer(field(proof, "v")?)? != 1
    {
        return Err(ObjectSourceError::Invalid);
    }
    let source = field(proof, "source")?;
    checkpoint(source)?;
    let workspace = scalar(field(proof, "workspace_id")?)?;
    let protocol = scalar(field(proof, "protocol_digest")?)?;
    let value_hash = scalar(field(proof, "value_sha256")?)?;
    let source_hash = scalar(field(proof, "source_id")?)?;
    let total = integer(field(proof, "bytes")?)? as usize;
    if workspace != scalar(field(source, "workspace_id")?)?
        || !digest(&protocol)
        || !digest(&value_hash)
        || !digest(&source_hash)
        || source_hash != source_id(source, &protocol, &value_hash)?
        || total == 0
        || total > VALUE_BYTES
    {
        return Err(ObjectSourceError::Invalid);
    }
    let WireValue::Array(descriptors) = field(proof, "parts")? else {
        return Err(ObjectSourceError::Invalid);
    };
    if descriptors.is_empty() || descriptors.len() > PARTS {
        return Err(ObjectSourceError::Resource);
    }
    let related = objects
        .iter()
        .filter(|part| {
            part.get("kind").and_then(WireValue::as_string).as_deref()
                == Some("protocol_object_part")
                && part
                    .get("value")
                    .and_then(|value| value.get("source_id"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(source_hash.as_str())
        })
        .collect::<Vec<_>>();
    if related.len() != descriptors.len() {
        return Err(ObjectSourceError::Missing);
    }
    let mut bytes = Vec::with_capacity(total);
    let mut sum = 0usize;
    for (index, descriptor) in descriptors.iter().enumerate() {
        if !exact(descriptor, &["id", "index", "sha256", "bytes"])
            || integer(field(descriptor, "index")?)? != index as u64
        {
            return Err(ObjectSourceError::Invalid);
        }
        let id = scalar(field(descriptor, "id")?)?;
        let hash = scalar(field(descriptor, "sha256")?)?;
        let length = integer(field(descriptor, "bytes")?)? as usize;
        if id != object_part_id(source, &source_hash, index)?
            || !digest(&hash)
            || length == 0
            || length > PART_BYTES
        {
            return Err(ObjectSourceError::Invalid);
        }
        sum = sum
            .checked_add(length)
            .filter(|value| *value <= VALUE_BYTES)
            .ok_or(ObjectSourceError::Resource)?;
        let matching = related
            .iter()
            .filter(|part| {
                part.get("id").and_then(WireValue::as_string).as_deref() == Some(id.as_str())
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(ObjectSourceError::Missing);
        }
        let part = matching[0];
        validate_object_part(part)?;
        let row = field(part, "value")?;
        if scalar(field(row, "workspace_id")?)? != workspace
            || scalar(field(row, "source_id")?)? != source_hash
            || integer(field(row, "index")?)? != index as u64
            || integer(field(row, "bytes")?)? as usize != length
            || scalar(field(row, "sha256")?)? != hash
        {
            return Err(ObjectSourceError::Mismatch);
        }
        bytes.extend_from_slice(scalar(field(row, "text")?)?.as_bytes());
    }
    if sum != total || bytes.len() != total || sha256_hex(&bytes) != value_hash {
        return Err(ObjectSourceError::Mismatch);
    }
    let value = parse_wire_json_js_bounded(&bytes, 64, VALUE_BYTES)
        .map_err(|_| ObjectSourceError::Invalid)?;
    if canonical(&value)?.as_bytes() != bytes {
        return Err(ObjectSourceError::Mismatch);
    }
    value_shape(&value, &workspace, &protocol)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_typescript_protocol_object_source_parts_and_proof() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/protocol-object-source-vectors.json").as_bytes(),
            64,
            1_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("vector array")
        };
        for case in cases {
            let name = field(&case, "name").unwrap().as_string().unwrap();
            let WireValue::Array(parts) = field(&case, "parts").unwrap() else {
                panic!("parts")
            };
            let result = read_protocol_object_source(field(&case, "proof").unwrap(), parts);
            match case.get("result") {
                Some(expected) => assert_eq!(
                    canonical(&result.unwrap()).unwrap(),
                    canonical(expected).unwrap(),
                    "{name}"
                ),
                None => assert!(result.is_err(), "{name}"),
            }
        }
    }
}
