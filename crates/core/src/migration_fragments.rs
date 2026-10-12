//! Migration fragment inflation. These bytes remain private to replay until the
//! signed descriptor root and the entire migration batch have been checked.

use crate::{
    canonical::Path,
    crypto::{decode_base64url, sha256_hex},
    wire_json::{
        canonical_wire_value, parse_js_json_string_bounded, parse_wire_json_js_bounded, WireValue,
    },
};
use std::collections::HashMap;
use thiserror::Error;

const PART_BYTES: usize = 16 * 1024;
const TOTAL_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum FragmentError {
    #[error("invalid migration fragment")]
    Invalid,
}

struct Group {
    kind: Vec<u16>,
    id: Vec<u16>,
    revision: u64,
    provenance: Vec<u16>,
    parts: Vec<Option<Vec<u8>>>,
}

fn integer(value: &WireValue) -> Option<u64> {
    let number = value.as_number()?;
    (number.is_finite()
        && number.fract() == 0.0
        && (0.0..=9_007_199_254_740_991.0).contains(&number))
    .then_some(number as u64)
}

fn text<'a>(value: &'a WireValue, name: &str) -> Result<&'a [u16], FragmentError> {
    value
        .get(name)
        .and_then(WireValue::as_utf16)
        .ok_or(FragmentError::Invalid)
}

fn is_kind(value: &WireValue, expected: &str) -> bool {
    value
        .get("kind")
        .and_then(WireValue::as_utf16)
        .is_some_and(|units| units.iter().copied().eq(expected.encode_utf16()))
}

fn canonical(value: &WireValue) -> Result<String, FragmentError> {
    canonical_wire_value(value, Path::SecureArtifact).map_err(|_| FragmentError::Invalid)
}

/// The root is over the complete descriptor collection, sorted by JavaScript
/// string comparison of each canonical descriptor text, not the object key.
pub(crate) fn validate_descriptor_root(
    items: &[WireValue],
    expected_root: &str,
) -> Result<(), FragmentError> {
    let mut sorted: Vec<(Vec<u16>, WireValue)> = items
        .iter()
        .map(|item| {
            let text = canonical(item)?;
            Ok((text.encode_utf16().collect(), item.clone()))
        })
        .collect::<Result<_, FragmentError>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(FragmentError::Invalid);
    }
    let root = sha256_hex(
        canonical(&WireValue::Array(
            sorted.into_iter().map(|(_, item)| item).collect(),
        ))?
        .as_bytes(),
    );
    if root != expected_root {
        return Err(FragmentError::Invalid);
    }
    Ok(())
}

pub(crate) struct MigrationBatch {
    root: String,
    source: WireValue,
    format: u64,
    descriptors: Vec<WireValue>,
    objects: Vec<WireValue>,
}

impl MigrationBatch {
    pub(crate) fn new(root: String, source: WireValue, format: u64) -> Result<Self, FragmentError> {
        if root.len() != 64
            || !root
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !matches!(format, 1..=3)
        {
            return Err(FragmentError::Invalid);
        }
        Ok(Self {
            root,
            source,
            format,
            descriptors: Vec::new(),
            objects: Vec::new(),
        })
    }

    pub(crate) fn source(&self) -> &WireValue {
        &self.source
    }
    pub(crate) fn format(&self) -> u64 {
        self.format
    }
    pub(crate) fn root(&self) -> &str {
        &self.root
    }

    pub(crate) fn add_page(
        &mut self,
        descriptors: &[WireValue],
        objects: &[WireValue],
    ) -> Result<(), FragmentError> {
        let derived: Vec<WireValue> = objects
            .iter()
            .map(|object| {
                Ok(descriptor(
                    text(object, "kind")?,
                    text(object, "id")?,
                    integer(object.get("revision").ok_or(FragmentError::Invalid)?)
                        .ok_or(FragmentError::Invalid)?,
                ))
            })
            .collect::<Result<_, FragmentError>>()?;
        if canonical(&WireValue::Array(derived))?
            != canonical(&WireValue::Array(descriptors.to_vec()))?
        {
            return Err(FragmentError::Invalid);
        }
        self.descriptors.extend_from_slice(descriptors);
        self.objects.extend_from_slice(objects);
        Ok(())
    }

    pub(crate) fn finish(self, prior: &[WireValue]) -> Result<Vec<WireValue>, FragmentError> {
        validate_descriptor_root(&self.descriptors, &self.root)?;
        let inflated = inflate_fragments(&self.objects)?;
        let mut protocol_ids = Vec::<Vec<u16>>::new();
        for object in &inflated {
            if text(object, "kind")? == "protocols".encode_utf16().collect::<Vec<_>>() {
                let id = text(object, "id")?.to_vec();
                if protocol_ids.contains(&id) {
                    return Err(FragmentError::Invalid);
                }
                protocol_ids.push(id);
            }
        }
        let mut candidate = prior.to_vec();
        let mut keys = HashMap::<String, usize>::new();
        for (index, object) in candidate.iter().enumerate() {
            keys.insert(object_key(object)?, index);
        }
        for object in inflated {
            let key = object_key(&object)?;
            if let Some(index) = keys.get(&key) {
                if canonical(&candidate[*index])? != canonical(&object)? {
                    return Err(FragmentError::Invalid);
                }
            } else {
                keys.insert(key, candidate.len());
                candidate.push(object);
            }
        }
        candidate.retain(|object| {
            text(object, "kind").ok()
                != Some(&"secure_fragment".encode_utf16().collect::<Vec<_>>()[..])
        });
        Ok(candidate)
    }
}

fn object_key(object: &WireValue) -> Result<String, FragmentError> {
    canonical(&WireValue::Array(vec![
        WireValue::String(text(object, "kind")?.to_vec()),
        WireValue::String(text(object, "id")?.to_vec()),
        WireValue::Number(
            integer(object.get("revision").ok_or(FragmentError::Invalid)?)
                .ok_or(FragmentError::Invalid)? as f64,
        ),
    ]))
}

fn descriptor(kind: &[u16], id: &[u16], revision: u64) -> WireValue {
    WireValue::Object(vec![
        (
            "kind".encode_utf16().collect(),
            WireValue::String(kind.to_vec()),
        ),
        (
            "id".encode_utf16().collect(),
            WireValue::String(id.to_vec()),
        ),
        (
            "revision".encode_utf16().collect(),
            WireValue::Number(revision as f64),
        ),
    ])
}

fn row(
    kind: Vec<u16>,
    id: Vec<u16>,
    revision: u64,
    provenance: Vec<u16>,
    value: WireValue,
) -> WireValue {
    WireValue::Object(vec![
        ("kind".encode_utf16().collect(), WireValue::String(kind)),
        ("id".encode_utf16().collect(), WireValue::String(id)),
        (
            "revision".encode_utf16().collect(),
            WireValue::Number(revision as f64),
        ),
        (
            "provenance".encode_utf16().collect(),
            WireValue::String(provenance),
        ),
        ("value".encode_utf16().collect(), value),
    ])
}

pub(crate) fn inflate_fragments(objects: &[WireValue]) -> Result<Vec<WireValue>, FragmentError> {
    let mut normal: Vec<WireValue> = objects
        .iter()
        .filter(|object| !is_kind(object, "secure_fragment"))
        .cloned()
        .collect();
    let mut groups = Vec::<Group>::new();
    let mut by_key = HashMap::<String, usize>::new();
    let mut total = 0_usize;
    for object in objects {
        if !is_kind(object, "secure_fragment") {
            continue;
        }
        let value = object.get("value").ok_or(FragmentError::Invalid)?;
        let fragment = value.get("fragment").ok_or(FragmentError::Invalid)?;
        let kind = text(fragment, "kind")?;
        let id = text(fragment, "id")?;
        let revision = integer(fragment.get("revision").ok_or(FragmentError::Invalid)?)
            .ok_or(FragmentError::Invalid)?;
        let count = integer(fragment.get("count").ok_or(FragmentError::Invalid)?)
            .ok_or(FragmentError::Invalid)?;
        let index = integer(fragment.get("index").ok_or(FragmentError::Invalid)?)
            .ok_or(FragmentError::Invalid)?;
        let provenance = text(fragment, "provenance")?;
        if kind.is_empty()
            || kind == "secure_fragment".encode_utf16().collect::<Vec<_>>()
            || id.is_empty()
            || revision == 0
            || count == 0
            || count > 2048
            || index >= count
            || !matches!(
                String::from_utf16(provenance).ok().as_deref(),
                Some("AUTHOR_SIGNED" | "LEGACY_OWNER_ATTESTED")
            )
            || integer(object.get("revision").ok_or(FragmentError::Invalid)?) != Some(1)
        {
            return Err(FragmentError::Invalid);
        }
        let key = sha256_hex(canonical(&descriptor(kind, id, revision))?.as_bytes());
        if text(object, "id")? != format!("{key}-{index}").encode_utf16().collect::<Vec<_>>() {
            return Err(FragmentError::Invalid);
        }
        let encoded = value
            .get("data")
            .and_then(WireValue::as_string)
            .ok_or(FragmentError::Invalid)?;
        let part = decode_base64url(&encoded).map_err(|_| FragmentError::Invalid)?;
        total = total
            .checked_add(part.len())
            .ok_or(FragmentError::Invalid)?;
        if part.is_empty() || part.len() > PART_BYTES || total > TOTAL_BYTES {
            return Err(FragmentError::Invalid);
        }
        let group_index = if let Some(group_index) = by_key.get(&key) {
            *group_index
        } else {
            let group_index = groups.len();
            by_key.insert(key, group_index);
            groups.push(Group {
                kind: kind.to_vec(),
                id: id.to_vec(),
                revision,
                provenance: provenance.to_vec(),
                parts: vec![None; count as usize],
            });
            group_index
        };
        let group = &mut groups[group_index];
        if group.parts.len() != count as usize
            || group.provenance != provenance
            || group.parts[index as usize].is_some()
        {
            return Err(FragmentError::Invalid);
        }
        group.parts[index as usize] = Some(part);
    }
    for group in groups {
        let mut bytes = Vec::new();
        for (index, part) in group.parts.iter().enumerate() {
            let part = part.as_ref().ok_or(FragmentError::Invalid)?;
            if index + 1 < group.parts.len() && part.len() != PART_BYTES {
                return Err(FragmentError::Invalid);
            }
            bytes.extend_from_slice(part);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| FragmentError::Invalid)?;
        let value = parse_wire_json_js_bounded(&bytes, 2048, TOTAL_BYTES)
            .map_err(|_| FragmentError::Invalid)?;
        if canonical(&value)? != text
            || normal.iter().any(|other| {
                text_field_equal(other, "kind", &group.kind)
                    && text_field_equal(other, "id", &group.id)
                    && other.get("revision").and_then(integer) == Some(group.revision)
            })
        {
            return Err(FragmentError::Invalid);
        }
        normal.push(row(
            group.kind,
            group.id,
            group.revision,
            group.provenance,
            value,
        ));
    }
    Ok(normal)
}

fn text_field_equal(value: &WireValue, name: &str, expected: &[u16]) -> bool {
    value.get(name).and_then(WireValue::as_utf16) == Some(expected)
}

fn decoded_object(value: &WireValue) -> Result<WireValue, FragmentError> {
    let parsed = if let Some(units) = value.as_utf16() {
        parse_js_json_string_bounded(units, 2048, TOTAL_BYTES)
            .map_err(|_| FragmentError::Invalid)?
    } else {
        value.clone()
    };
    parsed.object_len().ok_or(FragmentError::Invalid)?;
    Ok(parsed)
}

fn collect_archived(
    objects: &[WireValue],
    budget: &mut usize,
    depth: usize,
) -> Result<Vec<WireValue>, FragmentError> {
    if depth > 8 {
        return Err(FragmentError::Invalid);
    }
    let mut result = Vec::new();
    for object in objects {
        *budget = budget.checked_add(1).ok_or(FragmentError::Invalid)?;
        if *budget > 65_536 || object.object_len().is_none() {
            return Err(FragmentError::Invalid);
        }
        if is_kind(object, "secure_commits") {
            let value = object.get("value").ok_or(FragmentError::Invalid)?;
            value.object_len().ok_or(FragmentError::Invalid)?;
            let artifact = if let Some(units) = value.get("artifact").and_then(WireValue::as_utf16)
            {
                parse_js_json_string_bounded(units, 2048, TOTAL_BYTES)
                    .map_err(|_| FragmentError::Invalid)?
            } else {
                value.clone()
            };
            let payload = artifact.get("payload").ok_or(FragmentError::Invalid)?;
            if text(payload, "mode")? != "PUBLIC".encode_utf16().collect::<Vec<_>>() {
                return Err(FragmentError::Invalid);
            }
            let WireValue::Array(nested) = payload
                .get("body")
                .and_then(|body| body.get("objects"))
                .ok_or(FragmentError::Invalid)?
            else {
                return Err(FragmentError::Invalid);
            };
            result.extend(collect_archived(nested, budget, depth + 1)?);
        } else {
            result.push(object.clone());
        }
    }
    Ok(result)
}

fn format_within(value: &WireValue, ceiling: u64) -> Result<(), FragmentError> {
    let decoded = decoded_object(value)?;
    if let Some(version) = decoded.get("format_version") {
        if ceiling != 2 || integer(version) != Some(2) {
            return Err(FragmentError::Invalid);
        }
    }
    Ok(())
}

fn check_protocol_format(object: &WireValue, ceiling: u64) -> Result<(), FragmentError> {
    let value = object.get("value").ok_or(FragmentError::Invalid)?;
    let provenance = text(object, "provenance")?;
    if provenance == "AUTHOR_SIGNED".encode_utf16().collect::<Vec<_>>() {
        format_within(
            value.get("manifest").ok_or(FragmentError::Invalid)?,
            ceiling,
        )?;
        format_within(
            value
                .get("resolved_manifest")
                .ok_or(FragmentError::Invalid)?,
            ceiling,
        )?;
        if let Some(composition) = value.get("composition") {
            format_within(
                composition
                    .get("source_manifest")
                    .ok_or(FragmentError::Invalid)?,
                ceiling,
            )?;
            let WireValue::Array(nodes) = composition
                .get("dependencies")
                .ok_or(FragmentError::Invalid)?
            else {
                return Err(FragmentError::Invalid);
            };
            for node in nodes {
                format_within(node.get("manifest").ok_or(FragmentError::Invalid)?, ceiling)?;
            }
        }
    } else if provenance == "LEGACY_OWNER_ATTESTED".encode_utf16().collect::<Vec<_>>() {
        let envelope = decoded_object(value.get("manifest").ok_or(FragmentError::Invalid)?)?;
        format_within(
            envelope.get("manifest").ok_or(FragmentError::Invalid)?,
            ceiling,
        )?;
        format_within(
            value
                .get("resolved_manifest")
                .ok_or(FragmentError::Invalid)?,
            ceiling,
        )?;
    } else {
        return Err(FragmentError::Invalid);
    }
    Ok(())
}

/// Match the nested v3 decrypted-content format gate. This is a private
/// prerequisite; it does not validate a protocol manifest or authorize reads.
pub(crate) fn assert_protocol_format_ceiling(
    objects: &[WireValue],
    ceiling: u64,
) -> Result<(), FragmentError> {
    if !matches!(ceiling, 1 | 2) {
        return Err(FragmentError::Invalid);
    }
    let mut budget = 0;
    let mut candidate = collect_archived(objects, &mut budget, 0)?;
    let mut fragment_bytes = 0_usize;
    for _ in 0..8 {
        if !candidate
            .iter()
            .any(|object| is_kind(object, "secure_fragment"))
        {
            break;
        }
        for object in &candidate {
            if is_kind(object, "secure_fragment") {
                let data = text(object.get("value").ok_or(FragmentError::Invalid)?, "data")?;
                fragment_bytes = fragment_bytes
                    .checked_add((data.len() * 3).div_ceil(4))
                    .ok_or(FragmentError::Invalid)?;
                if fragment_bytes > TOTAL_BYTES {
                    return Err(FragmentError::Invalid);
                }
            }
        }
        candidate = collect_archived(&inflate_fragments(&candidate)?, &mut budget, 0)?;
    }
    if candidate
        .iter()
        .any(|object| is_kind(object, "secure_fragment"))
    {
        return Err(FragmentError::Invalid);
    }
    for object in candidate {
        if is_kind(&object, "protocols") {
            check_protocol_format(&object, ceiling)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::base64url;

    fn field(name: &str, value: WireValue) -> (Vec<u16>, WireValue) {
        (name.encode_utf16().collect(), value)
    }
    fn str_value(value: &str) -> WireValue {
        WireValue::String(value.encode_utf16().collect())
    }
    fn fragment(index: u64, count: u64, data: &[u8]) -> WireValue {
        let kind = "protocols".encode_utf16().collect::<Vec<_>>();
        let id = "proto".encode_utf16().collect::<Vec<_>>();
        let key = sha256_hex(canonical(&descriptor(&kind, &id, 1)).unwrap().as_bytes());
        row(
            "secure_fragment".encode_utf16().collect(),
            format!("{key}-{index}").encode_utf16().collect(),
            1,
            "AUTHOR_SIGNED".encode_utf16().collect(),
            WireValue::Object(vec![
                field(
                    "fragment",
                    WireValue::Object(vec![
                        field("kind", str_value("protocols")),
                        field("id", str_value("proto")),
                        field("revision", WireValue::Number(1.0)),
                        field("index", WireValue::Number(index as f64)),
                        field("count", WireValue::Number(count as f64)),
                        field("provenance", str_value("AUTHOR_SIGNED")),
                    ]),
                ),
                field("data", str_value(&base64url(data))),
            ]),
        )
    }

    #[test]
    fn complete_canonical_fragments_only_and_normal_collision() {
        let one = fragment(0, 1, b"{\"example\":1}");
        let inflated = inflate_fragments(&[one.clone()]).unwrap();
        assert_eq!(inflated.len(), 1);
        assert_eq!(
            inflated[0]
                .get("kind")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("protocols")
        );
        assert!(inflate_fragments(&[one.clone(), one]).is_err());
        assert!(inflate_fragments(&[fragment(0, 2, b"{\"example\":1}")]).is_err());
        assert!(inflate_fragments(&[fragment(0, 1, b"{ \"example\":1}")]).is_err());
        assert!(inflate_fragments(&[fragment(0, 1, b"not json")]).is_err());
        let normal = row(
            "protocols".encode_utf16().collect(),
            "proto".encode_utf16().collect(),
            1,
            "AUTHOR_SIGNED".encode_utf16().collect(),
            WireValue::Null,
        );
        assert!(inflate_fragments(&[normal, fragment(0, 1, b"{}")]).is_err());
    }

    #[test]
    fn direct_pinned_typescript_fragment_outcomes() {
        let vectors = parse_wire_json_js_bounded(
            include_str!("../../../conformance/migration-fragment-vectors.json").as_bytes(),
            64,
            1024 * 1024,
        )
        .unwrap();
        let WireValue::Array(cases) = vectors else {
            panic!("vector array")
        };
        for case in cases {
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let WireValue::Array(objects) = case.get("objects").unwrap() else {
                panic!("objects")
            };
            let expected = case.get("ok") == Some(&WireValue::Bool(true));
            let actual = inflate_fragments(objects);
            assert_eq!(actual.is_ok(), expected, "{name}");
            if let Ok(inflated) = actual {
                assert_eq!(
                    canonical(&WireValue::Array(inflated)).unwrap(),
                    canonical(case.get("inflated").unwrap()).unwrap(),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn descriptor_root_requires_complete_unique_sorted_set() {
        let a = descriptor(
            &"protocols".encode_utf16().collect::<Vec<_>>(),
            &"a".encode_utf16().collect::<Vec<_>>(),
            1,
        );
        let b = descriptor(
            &"protocols".encode_utf16().collect::<Vec<_>>(),
            &"b".encode_utf16().collect::<Vec<_>>(),
            1,
        );
        let root = sha256_hex(
            canonical(&WireValue::Array(vec![a.clone(), b.clone()]))
                .unwrap()
                .as_bytes(),
        );
        assert!(validate_descriptor_root(&[b.clone(), a.clone()], &root).is_ok());
        assert!(validate_descriptor_root(&[a.clone()], &root).is_err());
        assert!(validate_descriptor_root(&[a.clone(), a], &root).is_err());
    }

    #[test]
    fn batch_is_atomic_and_rejects_conflicting_imported_history() {
        let imported = fragment(0, 1, b"{\"example\":1}");
        let item_descriptor = descriptor(
            text(&imported, "kind").unwrap(),
            text(&imported, "id").unwrap(),
            1,
        );
        let root = sha256_hex(
            canonical(&WireValue::Array(vec![item_descriptor.clone()]))
                .unwrap()
                .as_bytes(),
        );
        let mut batch = MigrationBatch::new(root.clone(), WireValue::Null, 1).unwrap();
        assert!(batch.add_page(&[item_descriptor], &[imported]).is_ok());
        let candidate = batch.finish(&[]).unwrap();
        assert_eq!(candidate.len(), 1);
        assert_eq!(
            candidate[0]
                .get("kind")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("protocols")
        );
        let missing = MigrationBatch::new(root.clone(), WireValue::Null, 1).unwrap();
        assert!(missing.finish(&[]).is_err());
        let mut missing = MigrationBatch::new(root, WireValue::Null, 1).unwrap();
        let wrong_descriptor = descriptor(
            &"protocols".encode_utf16().collect::<Vec<_>>(),
            &"other".encode_utf16().collect::<Vec<_>>(),
            1,
        );
        assert!(missing
            .add_page(&[wrong_descriptor], &[fragment(0, 1, b"{}")])
            .is_err());
    }

    #[test]
    fn direct_pinned_typescript_nested_format_ceiling() {
        let vectors = parse_wire_json_js_bounded(
            include_str!("../../../conformance/migration-format-vectors.json").as_bytes(),
            64,
            1024 * 1024,
        )
        .unwrap();
        let WireValue::Array(cases) = vectors else {
            panic!("vector array")
        };
        for case in cases {
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let WireValue::Array(objects) = case.get("objects").unwrap() else {
                panic!("objects")
            };
            let ceiling = integer(case.get("ceiling").unwrap()).unwrap();
            let expected = case.get("ok") == Some(&WireValue::Bool(true));
            assert_eq!(
                assert_protocol_format_ceiling(objects, ceiling).is_ok(),
                expected,
                "{name}"
            );
        }
    }
}
