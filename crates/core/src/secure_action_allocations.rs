//! ACTION record-allocation phase from the pinned secure-engine writer.
//! Inputs are caller-supplied here; signed replay must authenticate them and
//! independently validate schema, heads, effects, and the resulting operation.

use crate::{
    crypto::{base64url, sha256},
    interpreter::ResolvedInput,
    wire_json::WireValue,
};
use std::collections::{HashMap, HashSet};

const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub(crate) struct AssignedRecord {
    pub id: Vec<u16>,
    pub entity_id: Vec<u16>,
    pub revision: u64,
    pub parent: Option<WireValue>,
    pub record: WireValue,
}

#[derive(Debug)]
pub(crate) struct AllocationPlan {
    pub assigned: Vec<AssignedRecord>,
    pub record_slots: HashMap<Vec<u16>, WireValue>,
    pub entity_slots: HashMap<Vec<u16>, WireValue>,
    pub assigned_records: HashMap<Vec<u16>, u64>,
}

fn integer(value: &WireValue) -> Option<u64> {
    let n = value.as_number()?;
    (n.is_finite() && n >= 0.0 && n <= MAX_SAFE as f64 && n.fract() == 0.0).then_some(n as u64)
}
fn token(value: &[u16]) -> bool {
    value.len() == 43
        && value.iter().all(|unit| {
            u8::try_from(*unit).is_ok_and(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}
fn row<'a>(object: &'a WireValue, kind: &str) -> Option<&'a WireValue> {
    (object.get("kind").and_then(WireValue::as_string).as_deref() == Some(kind))
        .then(|| object.get("value"))
        .flatten()
}
fn revision(row: &WireValue) -> Option<u64> {
    row.get("revision").and_then(integer)
}

/// Exact assignment phase only. The caller must supply interpreter output,
/// immutable allocations, exact refs, and authenticated prior objects.
pub(crate) fn resolve_record_allocations(
    records: &[WireValue],
    allocations: &[WireValue],
    authenticated_prior: &[WireValue],
    exact_refs: &[ResolvedInput],
    context: &WireValue,
    instance_id: &WireValue,
    protocol_digest: &WireValue,
) -> Result<AllocationPlan, &'static str> {
    if records.len() != allocations.len() {
        return Err("ALLOCATION_INVALID");
    }
    let instance = instance_id.as_utf16().ok_or("INVALID_PAYLOAD")?;
    let workspace = context.get("workspace_id").ok_or("INVALID_PAYLOAD")?;
    let mut seen_ids = HashSet::new();
    for allocation in allocations {
        let id = allocation
            .get("record_id")
            .and_then(WireValue::as_utf16)
            .ok_or("ALLOCATION_INVALID")?;
        let entity = allocation
            .get("entity_id")
            .and_then(WireValue::as_utf16)
            .ok_or("ALLOCATION_INVALID")?;
        if !token(id) || !token(entity) || !seen_ids.insert(id.to_vec()) {
            return Err("ALLOCATION_INVALID");
        }
    }
    if allocations.iter().any(|allocation| {
        let id = allocation.get("record_id").and_then(WireValue::as_utf16);
        authenticated_prior.iter().any(|object| {
            row(object, "records").is_some() && object.get("id").and_then(WireValue::as_utf16) == id
        })
    }) {
        return Err("RECORD_ALREADY_EXISTS");
    }
    let all_records = authenticated_prior
        .iter()
        .filter_map(|object| row(object, "records"))
        .collect::<Vec<_>>();
    let mut plan = AllocationPlan {
        assigned: Vec::with_capacity(records.len()),
        record_slots: HashMap::new(),
        entity_slots: HashMap::new(),
        assigned_records: HashMap::new(),
    };
    let mut entity_max = HashMap::<Vec<u16>, u64>::new();
    for (record, allocation) in records.iter().zip(allocations) {
        let id = allocation
            .get("record_id")
            .and_then(WireValue::as_utf16)
            .unwrap()
            .to_vec();
        let mut entity_id = allocation
            .get("entity_id")
            .and_then(WireValue::as_utf16)
            .unwrap()
            .to_vec();
        let mut assigned_revision = 1_u64;
        let mut parent = None;
        let entity = record.get("entity");
        if let Some(slot) = record.get("entitySlot").and_then(WireValue::as_utf16) {
            // TextEncoder replaces lone UTF-16 surrogates before SHA-256.
            let text = format!(
                "{}\0{}",
                String::from_utf16_lossy(instance),
                String::from_utf16_lossy(slot)
            );
            entity_id = base64url(&sha256(text.as_bytes())).encode_utf16().collect();
            let old = all_records
                .iter()
                .copied()
                .filter(|row| {
                    row.get("entity_id").and_then(WireValue::as_utf16) == Some(&entity_id)
                })
                .max_by_key(|row| revision(row).unwrap_or(0));
            if let Some(old) = old {
                let old_id = old
                    .get("id")
                    .and_then(WireValue::as_string)
                    .ok_or("STALE_REVISION")?;
                let old_rev = revision(old).ok_or("STALE_REVISION")?;
                if !exact_refs
                    .iter()
                    .any(|reference| reference.record_id == old_id && reference.revision == old_rev)
                {
                    return Err("STALE_REVISION");
                }
                assigned_revision = entity_max
                    .get(&entity_id)
                    .copied()
                    .unwrap_or(old_rev)
                    .checked_add(1)
                    .filter(|revision| *revision <= MAX_SAFE)
                    .ok_or("PROTOCOL_OUTPUT_MISMATCH")?;
            }
            plan.entity_slots
                .insert(slot.to_vec(), WireValue::String(entity_id.clone()));
        } else if entity
            .and_then(|value| value.get("mode"))
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("new")
        {
            if all_records
                .iter()
                .any(|row| row.get("entity_id").and_then(WireValue::as_utf16) == Some(&entity_id))
                || plan.assigned.iter().any(|row| row.entity_id == entity_id)
            {
                return Err("ENTITY_ALREADY_EXISTS");
            }
            let slot = entity
                .and_then(|value| value.get("slot"))
                .and_then(WireValue::as_utf16)
                .ok_or("INVALID_PROTOCOL_TRANSITION")?;
            plan.entity_slots
                .insert(slot.to_vec(), WireValue::String(entity_id.clone()));
        } else if let Some(entity) = entity {
            if entity.get("mode").and_then(WireValue::as_string).as_deref() != Some("revise") {
                return Err("INVALID_PROTOCOL_TRANSITION");
            }
            let requested_parent = entity.get("parent").ok_or("ENTITY_PARENT_INVALID")?;
            let parent_id = requested_parent
                .get("recordId")
                .and_then(WireValue::as_utf16)
                .ok_or("ENTITY_PARENT_INVALID")?;
            let parent_revision = requested_parent
                .get("revision")
                .and_then(integer)
                .ok_or("ENTITY_PARENT_INVALID")?;
            let old = all_records
                .iter()
                .copied()
                .find(|row| {
                    row.get("id").and_then(WireValue::as_utf16) == Some(parent_id)
                        && revision(row) == Some(parent_revision)
                })
                .ok_or("ENTITY_PARENT_INVALID")?;
            if old.get("workspace_id") != Some(workspace)
                || old.get("instance_id") != Some(instance_id)
                || old.get("protocol_digest") != Some(protocol_digest)
            {
                return Err("ENTITY_PARENT_INVALID");
            }
            entity_id = old
                .get("entity_id")
                .and_then(WireValue::as_utf16)
                .ok_or("ENTITY_PARENT_INVALID")?
                .to_vec();
            let max = all_records
                .iter()
                .copied()
                .filter(|row| {
                    row.get("entity_id").and_then(WireValue::as_utf16) == Some(&entity_id)
                })
                .filter_map(revision)
                .max()
                .ok_or("ENTITY_PARENT_INVALID")?;
            assigned_revision = entity_max
                .get(&entity_id)
                .copied()
                .unwrap_or(max)
                .checked_add(1)
                .filter(|revision| *revision <= MAX_SAFE)
                .ok_or("PROTOCOL_OUTPUT_MISMATCH")?;
            parent = Some(requested_parent.clone());
            let slot = entity
                .get("slot")
                .and_then(WireValue::as_utf16)
                .ok_or("INVALID_PROTOCOL_TRANSITION")?;
            plan.entity_slots
                .insert(slot.to_vec(), WireValue::String(entity_id.clone()));
            if matches!(record.get("selectHead"), Some(WireValue::Bool(true))) {
                let head = authenticated_prior
                    .iter()
                    .filter(|object| {
                        row(object, "entity_heads").is_some()
                            && object.get("id").and_then(WireValue::as_utf16) == Some(&entity_id)
                    })
                    .max_by_key(|object| object.get("revision").and_then(integer).unwrap_or(0))
                    .and_then(|object| object.get("value"))
                    .ok_or("STALE_REVISION")?;
                if head.get("record_id").and_then(WireValue::as_utf16) != Some(parent_id)
                    || revision(head) != Some(parent_revision)
                {
                    return Err("STALE_REVISION");
                }
            }
        } else if all_records
            .iter()
            .any(|row| row.get("entity_id").and_then(WireValue::as_utf16) == Some(&entity_id))
            || plan.assigned.iter().any(|row| row.entity_id == entity_id)
        {
            return Err("ENTITY_ALREADY_EXISTS");
        }
        entity_max.insert(entity_id.clone(), assigned_revision);
        if let Some(slot) = record.get("recordSlot").and_then(WireValue::as_utf16) {
            if plan
                .record_slots
                .insert(
                    slot.to_vec(),
                    object(vec![
                        ("record_id", WireValue::String(id.clone())),
                        ("revision", WireValue::Number(assigned_revision as f64)),
                    ]),
                )
                .is_some()
            {
                return Err("INVALID_PROTOCOL_TRANSITION");
            }
        }
        plan.assigned_records.insert(id.clone(), assigned_revision);
        plan.assigned.push(AssignedRecord {
            id,
            entity_id,
            revision: assigned_revision,
            parent,
            record: record.clone(),
        });
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::Path,
        wire_json::{canonical_wire_value, parse_wire_json_js_bounded},
    };

    fn same(a: &WireValue, b: &WireValue) -> bool {
        canonical_wire_value(a, Path::SecureArtifact).unwrap()
            == canonical_wire_value(b, Path::SecureArtifact).unwrap()
    }
    fn map(value: &WireValue) -> HashMap<Vec<u16>, WireValue> {
        let WireValue::Object(fields) = value else {
            panic!("map")
        };
        fields.iter().cloned().collect()
    }
    #[test]
    fn direct_typescript_assignment_phase() {
        let vectors = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/action-allocation-vectors.json"),
            64,
            3 * 1024 * 1024,
        )
        .unwrap();
        let WireValue::Array(cases) = vectors else {
            panic!("cases")
        };
        for case in cases {
            let name = case.get("name").and_then(WireValue::as_string).unwrap();
            let WireValue::Array(records) = case.get("records").unwrap() else {
                panic!("records")
            };
            let WireValue::Array(allocations) = case.get("allocations").unwrap() else {
                panic!("allocations")
            };
            let WireValue::Array(prior) = case.get("prior_objects").unwrap() else {
                panic!("prior")
            };
            let WireValue::Array(refs) = case.get("exact_refs").unwrap() else {
                panic!("refs")
            };
            let exact_refs = refs
                .iter()
                .map(|reference| ResolvedInput {
                    record_id: reference
                        .get("recordId")
                        .and_then(WireValue::as_string)
                        .unwrap(),
                    revision: reference.get("revision").and_then(integer).unwrap(),
                    schema: reference
                        .get("schema")
                        .and_then(WireValue::as_utf16)
                        .unwrap()
                        .to_vec(),
                    payload: reference.get("payload").unwrap().clone(),
                    entity_id: reference.get("entityId").and_then(WireValue::as_string),
                    scope: reference
                        .get("scope")
                        .and_then(WireValue::as_string)
                        .unwrap(),
                })
                .collect::<Vec<_>>();
            let actual = resolve_record_allocations(
                records,
                allocations,
                prior,
                &exact_refs,
                case.get("context").unwrap(),
                case.get("instance_id").unwrap(),
                case.get("protocol_digest").unwrap(),
            );
            if let Some(error) = case.get("error").and_then(WireValue::as_string) {
                assert_eq!(actual.unwrap_err(), error, "{name}");
                continue;
            }
            let actual = actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            let expected = case.get("result").unwrap();
            let WireValue::Array(assigned) = expected.get("assigned").unwrap() else {
                panic!("assigned")
            };
            assert_eq!(actual.assigned.len(), assigned.len(), "{name}");
            for (row, expected) in actual.assigned.iter().zip(assigned) {
                assert_eq!(
                    row.id,
                    expected.get("id").and_then(WireValue::as_utf16).unwrap(),
                    "{name}"
                );
                assert_eq!(
                    row.entity_id,
                    expected
                        .get("entity_id")
                        .and_then(WireValue::as_utf16)
                        .unwrap(),
                    "{name}"
                );
                assert_eq!(
                    row.revision,
                    expected.get("revision").and_then(integer).unwrap(),
                    "{name}"
                );
            }
            for (actual_map, expected_key) in [
                (&actual.record_slots, "record_slots"),
                (&actual.entity_slots, "entity_slots"),
            ] {
                let expected_map = map(expected.get(expected_key).unwrap());
                assert_eq!(
                    actual_map.len(),
                    expected_map.len(),
                    "{name}: {expected_key}"
                );
                for (key, value) in actual_map {
                    assert!(
                        same(value, expected_map.get(key).unwrap()),
                        "{name}: {expected_key}"
                    );
                }
            }
            let expected_records = map(expected.get("assigned_records").unwrap());
            assert_eq!(
                actual.assigned_records.len(),
                expected_records.len(),
                "{name}"
            );
            for (key, value) in &actual.assigned_records {
                assert_eq!(
                    Some(*value),
                    expected_records.get(key).and_then(integer),
                    "{name}"
                );
            }
        }
    }
}
