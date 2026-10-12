//! Source-matched ACTION relation target substitution and object construction.
//! The caller must supply authenticated prior objects and independently
//! assigned record/slot facts. This module does not prove a journal or action.

use crate::{
    canonical::Path,
    wire_json::{canonical_wire_value, WireValue},
};
use std::collections::HashMap;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

pub(crate) struct PendingRelation {
    pub position: usize,
    pub source_id: Vec<u16>,
    pub relation: WireValue,
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
fn safe_integer(value: &WireValue) -> Option<u64> {
    let n = value.as_number()?;
    (n.is_finite() && n >= 0.0 && n <= MAX_SAFE && n.fract() == 0.0).then_some(n as u64)
}
fn substitute(
    value: &WireValue,
    record_slots: &HashMap<Vec<u16>, WireValue>,
    entity_slots: &HashMap<Vec<u16>, WireValue>,
    depth: usize,
) -> Result<WireValue, &'static str> {
    if depth > 12 {
        return Err("INVALID_PROTOCOL_TRANSITION");
    }
    match value {
        WireValue::Array(values) => Ok(WireValue::Array(
            values
                .iter()
                .map(|value| substitute(value, record_slots, entity_slots, depth + 1))
                .collect::<Result<_, _>>()?,
        )),
        WireValue::Object(fields) => {
            if let Some(kind) = value.get("$produced").and_then(WireValue::as_string) {
                let slot = value
                    .get("slot")
                    .and_then(WireValue::as_utf16)
                    .ok_or("INVALID_PROTOCOL_TRANSITION")?;
                if kind == "record" {
                    return record_slots
                        .get(slot)
                        .cloned()
                        .ok_or("INVALID_PROTOCOL_TRANSITION");
                }
                if kind == "entity" {
                    return entity_slots
                        .get(slot)
                        .cloned()
                        .ok_or("INVALID_PROTOCOL_TRANSITION");
                }
            }
            Ok(WireValue::Object(
                fields
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            key.clone(),
                            substitute(value, record_slots, entity_slots, depth + 1)?,
                        ))
                    })
                    .collect::<Result<_, &'static str>>()?,
            ))
        }
        value => Ok(value.clone()),
    }
}

pub(crate) fn resolve_relation_objects(
    pending: &[PendingRelation],
    authenticated_prior_objects: &[WireValue],
    assigned_records: &HashMap<Vec<u16>, u64>,
    record_slots: &HashMap<Vec<u16>, WireValue>,
    entity_slots: &HashMap<Vec<u16>, WireValue>,
) -> Result<Vec<(usize, WireValue)>, &'static str> {
    let mut output = Vec::with_capacity(pending.len());
    for item in pending {
        let kind = item
            .relation
            .get("kind")
            .and_then(WireValue::as_utf16)
            .ok_or("RELATION_TARGET_INVALID")?;
        let target = substitute(
            item.relation
                .get("target")
                .ok_or("RELATION_TARGET_INVALID")?,
            record_slots,
            entity_slots,
            0,
        )?;
        let target_id = target
            .get("recordId")
            .filter(|value| !matches!(value, WireValue::Null))
            .or_else(|| target.get("record_id"))
            .and_then(WireValue::as_utf16)
            .ok_or("RELATION_TARGET_INVALID")?;
        let revision = target
            .get("revision")
            .and_then(safe_integer)
            .ok_or("RELATION_TARGET_INVALID")?;
        let exists = authenticated_prior_objects.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                && object.get("id").and_then(WireValue::as_utf16) == Some(target_id)
                && object
                    .get("value")
                    .and_then(|value| value.get("revision"))
                    .and_then(safe_integer)
                    == Some(revision)
        }) || assigned_records.get(target_id) == Some(&revision);
        if !exists {
            return Err("RELATION_TARGET_INVALID");
        }
        // The tracked writer uses JSON.stringify on this four-element array.
        // Its valid input domains here are token IDs, a bounded segment kind,
        // and a safe positive integer; secure array canonicalization is equal.
        let id = canonical_wire_value(
            &WireValue::Array(vec![
                WireValue::String(item.source_id.clone()),
                WireValue::String(kind.to_vec()),
                WireValue::String(target_id.to_vec()),
                WireValue::Number(revision as f64),
            ]),
            Path::SecureArtifact,
        )
        .map_err(|_| "RELATION_TARGET_INVALID")?;
        let prior_revision = authenticated_prior_objects
            .iter()
            .filter(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref()
                    == Some("record_relations")
                    && object.get("id").and_then(WireValue::as_string).as_deref()
                        == Some(id.as_str())
            })
            .filter_map(|object| object.get("revision").and_then(safe_integer))
            .max()
            .unwrap_or(0);
        let outer_revision = prior_revision
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE as u64)
            .ok_or("PROTOCOL_OUTPUT_MISMATCH")?;
        output.push((
            item.position,
            object(vec![
                ("kind", text("record_relations")),
                ("id", text(&id)),
                ("revision", WireValue::Number(outer_revision as f64)),
                (
                    "value",
                    object(vec![
                        ("record_id", WireValue::String(item.source_id.clone())),
                        ("kind", WireValue::String(kind.to_vec())),
                        ("target_record", WireValue::String(target_id.to_vec())),
                        ("target_revision", WireValue::Number(revision as f64)),
                    ]),
                ),
                ("provenance", text("AUTHOR_SIGNED")),
            ]),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::parse_wire_json_js_bounded;

    #[test]
    fn direct_typescript_relation_objects() {
        let cases = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/action-relation-vectors.json"),
            64,
            2 * 1024 * 1024,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("cases")
        };
        for case in cases {
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let WireValue::Array(prior) = case.get("prior_objects").unwrap() else {
                panic!("prior")
            };
            let WireValue::Array(rows) = case.get("pending").unwrap() else {
                panic!("pending")
            };
            let pending = rows
                .iter()
                .map(|row| PendingRelation {
                    position: row.get("position").and_then(safe_integer).unwrap() as usize,
                    source_id: row
                        .get("source_id")
                        .and_then(WireValue::as_utf16)
                        .unwrap()
                        .to_vec(),
                    relation: row.get("relation").unwrap().clone(),
                })
                .collect::<Vec<_>>();
            fn map(value: &WireValue) -> HashMap<Vec<u16>, WireValue> {
                let WireValue::Object(rows) = value else {
                    panic!("map")
                };
                rows.iter().cloned().collect()
            }
            let records = map(case.get("assigned_records").unwrap())
                .into_iter()
                .map(|(id, value)| (id, safe_integer(&value).unwrap()))
                .collect();
            let actual = resolve_relation_objects(
                &pending,
                prior,
                &records,
                &map(case.get("record_slots").unwrap()),
                &map(case.get("entity_slots").unwrap()),
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            let WireValue::Array(expected) = case.get("expected").unwrap() else {
                panic!("expected")
            };
            assert_eq!(actual.len(), expected.len(), "{name}");
            for ((index, object), expected) in actual.iter().zip(expected) {
                assert_eq!(
                    *index,
                    expected.get("position").and_then(safe_integer).unwrap() as usize,
                    "{name}"
                );
                assert_eq!(
                    canonical_wire_value(object, Path::SecureArtifact).unwrap(),
                    canonical_wire_value(expected.get("object").unwrap(), Path::SecureArtifact)
                        .unwrap(),
                    "{name}"
                );
            }
        }
    }
}
