//! Exact ACTION input-reference resolution over caller-supplied prior objects.
//! The caller must provide the authenticated prior journal projection and
//! signed context pins. Resolved rows alone authorize no action or effect.

use crate::{
    interpreter::ResolvedInput,
    wire_json::{parse_js_json_string_bounded, WireValue},
};
use std::collections::HashSet;

const MAX_REFS: usize = 32;
const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn safe_number(value: &WireValue) -> Option<u64> {
    let n = value.as_number()?;
    (n.is_finite() && n >= 0.0 && n <= MAX_SAFE && n.fract() == 0.0).then_some(n as u64)
}

pub(crate) fn resolve_exact_inputs(
    refs: &WireValue,
    authenticated_prior_objects: &[WireValue],
    workspace_id: &WireValue,
    instance_id: &WireValue,
    protocol_digest: &WireValue,
) -> Result<Vec<ResolvedInput>, &'static str> {
    let WireValue::Array(refs) = refs else {
        return Err("REFERENCE_INVALID");
    };
    if refs.len() > MAX_REFS {
        return Err("REFERENCE_INVALID");
    }
    let mut seen = HashSet::new();
    let mut output = Vec::with_capacity(refs.len());
    for reference in refs {
        let id = reference
            .get("record_id")
            .and_then(WireValue::as_utf16)
            .ok_or("REFERENCE_INVALID")?;
        let revision = reference
            .get("revision")
            .and_then(safe_number)
            .ok_or("REFERENCE_INVALID")?;
        if !seen.insert((id.to_vec(), revision)) {
            return Err("REFERENCE_INVALID");
        }
        let record = authenticated_prior_objects
            .iter()
            .find(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                    && object.get("id").and_then(WireValue::as_utf16) == Some(id)
                    && object
                        .get("value")
                        .and_then(|value| value.get("revision"))
                        .and_then(safe_number)
                        == Some(revision)
            })
            .ok_or("REFERENCE_NOT_FOUND")?;
        let row = record.get("value").ok_or("REFERENCE_NOT_FOUND")?;
        if row.get("workspace_id") != Some(workspace_id)
            || row
                .get("schema_ref")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("participation.request")
        {
            return Err("REFERENCE_SCOPE_MISMATCH");
        }
        let schema = row
            .get("schema_ref")
            .and_then(WireValue::as_utf16)
            .ok_or("REFERENCE_SCOPE_MISMATCH")?;
        let raw_payload = row.get("payload").ok_or("REFERENCE_INVALID")?;
        let payload = match raw_payload {
            WireValue::String(units) => {
                parse_js_json_string_bounded(units, 2048, MAX_CONTENT_BYTES)
                    .map_err(|_| "REFERENCE_INVALID")?
            }
            value => value.clone(),
        };
        let scope = if row.get("instance_id") == Some(instance_id)
            && row.get("protocol_digest") == Some(protocol_digest)
        {
            "INSTANCE"
        } else {
            "WORKSPACE"
        };
        output.push(ResolvedInput {
            record_id: String::from_utf16(id).map_err(|_| "REFERENCE_INVALID")?,
            revision,
            schema: schema.to_vec(),
            payload,
            scope: scope.into(),
            entity_id: row.get("entity_id").and_then(WireValue::as_string),
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::Path,
        wire_json::{canonical_wire_value, parse_wire_json_js_bounded},
    };

    #[test]
    fn direct_typescript_exact_input_cases() {
        let vectors = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/action-input-vectors.json"),
            64,
            2 * 1024 * 1024,
        )
        .unwrap();
        let WireValue::Array(rows) = vectors else {
            panic!("vectors")
        };
        for row in rows {
            let name = row.get("name").and_then(WireValue::as_string).unwrap();
            let WireValue::Array(prior) = row.get("prior_objects").unwrap() else {
                panic!("prior")
            };
            let result = resolve_exact_inputs(
                row.get("refs").unwrap(),
                prior,
                row.get("workspace_id").unwrap(),
                row.get("instance_id").unwrap(),
                row.get("protocol_digest").unwrap(),
            );
            if let Some(WireValue::Array(expected)) = row.get("result") {
                let actual = result.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(actual.len(), expected.len(), "{name}");
                for (resolved, expected) in actual.iter().zip(expected) {
                    assert_eq!(
                        resolved.record_id,
                        expected
                            .get("record_id")
                            .and_then(WireValue::as_string)
                            .unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        resolved.revision,
                        expected.get("revision").and_then(safe_number).unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        resolved.schema,
                        expected
                            .get("schema")
                            .and_then(WireValue::as_utf16)
                            .unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        resolved.scope,
                        expected
                            .get("scope")
                            .and_then(WireValue::as_string)
                            .unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        resolved.entity_id,
                        expected.get("entity_id").and_then(WireValue::as_string),
                        "{name}"
                    );
                    assert_eq!(
                        canonical_wire_value(&resolved.payload, Path::SecureArtifact).unwrap(),
                        canonical_wire_value(
                            expected.get("payload").unwrap(),
                            Path::SecureArtifact
                        )
                        .unwrap(),
                        "{name}",
                    );
                }
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    row.get("error").and_then(WireValue::as_string).unwrap(),
                    "{name}"
                );
            }
        }
    }
}
