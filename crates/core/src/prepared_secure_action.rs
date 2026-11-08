//! Low-level ACTION evaluator proof over caller-supplied prior state. Runtime
//! must source the policy and objects from complete authenticated replay.
//! This type alone does not prove transport provenance or journal acceptance.

use crate::{
    canonical::Path,
    crypto::{base64url, sha256_hex},
    secure_replay::{
        compute_action_objects_with_default_allocations, project_structure_data,
        validate_action_state_slice,
    },
    structure_delta::validate_projection_page,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};

const MAX_WIRE: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum PreparedActionError {
    Invalid,
    Unsupported,
    Entropy,
}

/// Private-constructor exact operation candidate checked against the selected
/// policy, prior objects and context. The producing caller must authenticate
/// all three inputs before treating this as an authoring plan.
pub struct ValidatedPreparedAction {
    canonical_operation: Vec<u8>,
    context_sha256: String,
    policy_sha256: String,
}

/// A native ACTION plan with the exact context needed for its generated
/// structure projection. The caller still must authenticate prior state and
/// the selected policy before signing or submitting the packet.
pub struct BuiltPreparedAction {
    context_wire: Vec<u8>,
    action: ValidatedPreparedAction,
}

impl BuiltPreparedAction {
    pub fn context_wire(&self) -> &[u8] {
        &self.context_wire
    }

    pub fn action(&self) -> &ValidatedPreparedAction {
        &self.action
    }
}

impl ValidatedPreparedAction {
    pub fn operation_wire(&self) -> &[u8] {
        &self.canonical_operation
    }

    pub fn matches_context_and_policy(&self, context_wire: &[u8], policy_wire: &[u8]) -> bool {
        canonical_hash(context_wire) == Some(self.context_sha256.clone())
            && canonical_hash(policy_wire) == Some(self.policy_sha256.clone())
    }
}

fn canonical_hash(wire: &[u8]) -> Option<String> {
    let value = parse_wire_json_bounded(wire, 64, MAX_WIRE).ok()?;
    Some(sha256_hex(
        canonical_wire_value(&value, Path::SecureArtifact)
            .ok()?
            .as_bytes(),
    ))
}

fn same(left: &WireValue, right: &WireValue) -> Result<bool, PreparedActionError> {
    Ok(canonical_wire_value(left, Path::SecureArtifact)
        .map_err(|_| PreparedActionError::Invalid)?
        == canonical_wire_value(right, Path::SecureArtifact)
            .map_err(|_| PreparedActionError::Invalid)?)
}

/// Produce the exact ACTION operation from an action input and authenticated
/// context. An allocation array is honored exactly; `allocations:null`
/// generates OS-random defaults for the interpreter's produced records.
pub fn build_prepared_action_operation(
    action_input_wire: &[u8],
    context_wire: &[u8],
    signed_policy_wire: &[u8],
    authenticated_prior_objects: &[WireValue],
) -> Result<ValidatedPreparedAction, PreparedActionError> {
    let (operation, context, policy) = compute_operation(
        action_input_wire,
        context_wire,
        signed_policy_wire,
        authenticated_prior_objects,
    )?;
    if policy.get("payload").and_then(|payload| payload.get("guard_time")).is_some() {
        // This API returns no context for the caller to bind as AAD. Guarded
        // actions must use the context-returning builder below.
        let _ = context;
        return Err(PreparedActionError::Unsupported);
    }
    let operation_wire = canonical_wire_value(&operation, Path::SecureArtifact)
        .map_err(|_| PreparedActionError::Invalid)?;
    validate_prepared_action_operation(
        operation_wire.as_bytes(),
        context_wire,
        signed_policy_wire,
        authenticated_prior_objects,
    )
}

/// Build from action values and derive the exact signed DELTA for a selected
/// structured policy. The same produced objects supply both the ACTION body
/// and its server-readable structure projection, so they cannot diverge.
pub fn build_prepared_action_with_context(
    action_input_wire: &[u8],
    context_wire: &[u8],
    signed_policy_wire: &[u8],
    authenticated_prior_objects: &[WireValue],
) -> Result<BuiltPreparedAction, PreparedActionError> {
    let (operation, mut context, policy) = compute_operation(
        action_input_wire,
        context_wire,
        signed_policy_wire,
        authenticated_prior_objects,
    )?;
    let payload = policy.get("payload").ok_or(PreparedActionError::Invalid)?;
    let structured = payload.get("v").and_then(WireValue::as_number) == Some(2.0)
        || payload.get("v").and_then(WireValue::as_number) == Some(3.0)
            && payload
                .get("structure_mode")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("STRUCTURED");
    if structured {
        if context.get("structure").is_some() {
            return Err(PreparedActionError::Invalid);
        }
        let contract = payload
            .get("structure")
            .ok_or(PreparedActionError::Invalid)?;
        let WireValue::Array(objects) = operation
            .get("objects")
            .ok_or(PreparedActionError::Invalid)?
        else {
            return Err(PreparedActionError::Invalid);
        };
        let (records, heads) =
            project_structure_data(objects, contract).map_err(|_| PreparedActionError::Invalid)?;
        let WireValue::Object(fields) = &mut context else {
            return Err(PreparedActionError::Invalid);
        };
        fields.push((
            "structure".encode_utf16().collect(),
            WireValue::Object(vec![
                ("v".encode_utf16().collect(), WireValue::Number(1.0)),
                (
                    "mode".encode_utf16().collect(),
                    WireValue::String("DELTA".encode_utf16().collect()),
                ),
                (
                    "records".encode_utf16().collect(),
                    WireValue::Array(records),
                ),
                ("heads".encode_utf16().collect(), WireValue::Array(heads)),
            ]),
        ));
    } else if context.get("structure").is_some() {
        return Err(PreparedActionError::Invalid);
    }
    let context_wire = canonical_wire_value(&context, Path::SecureArtifact)
        .map_err(|_| PreparedActionError::Invalid)?
        .into_bytes();
    let operation_wire = canonical_wire_value(&operation, Path::SecureArtifact)
        .map_err(|_| PreparedActionError::Invalid)?;
    let action = validate_prepared_action_operation(
        operation_wire.as_bytes(),
        &context_wire,
        signed_policy_wire,
        authenticated_prior_objects,
    )?;
    Ok(BuiltPreparedAction {
        context_wire,
        action,
    })
}

fn compute_operation(
    action_input_wire: &[u8],
    context_wire: &[u8],
    signed_policy_wire: &[u8],
    authenticated_prior_objects: &[WireValue],
) -> Result<(WireValue, WireValue, WireValue), PreparedActionError> {
    let parse = |wire: &[u8]| {
        parse_wire_json_bounded(wire, 64, MAX_WIRE).map_err(|_| PreparedActionError::Invalid)
    };
    let mut input = parse(action_input_wire)?;
    let mut context = parse(context_wire)?;
    let policy = parse(signed_policy_wire)?;
    let mut candidates = Vec::new();
    if matches!(input.get("allocations"), Some(WireValue::Null)) {
        for _ in 0..8 {
            let mut record = [0u8; 32];
            let mut entity = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut record)
                .map_err(|_| PreparedActionError::Entropy)?;
            OsRng
                .try_fill_bytes(&mut entity)
                .map_err(|_| PreparedActionError::Entropy)?;
            candidates.push(WireValue::Object(vec![
                (
                    "record_id".encode_utf16().collect(),
                    WireValue::String(base64url(&record).encode_utf16().collect()),
                ),
                (
                    "entity_id".encode_utf16().collect(),
                    WireValue::String(base64url(&entity).encode_utf16().collect()),
                ),
            ]));
        }
    }
    let objects = compute_action_objects_with_default_allocations(
        &mut input,
        &mut context,
        &policy,
        authenticated_prior_objects,
        &candidates,
    )
    .map_err(|code| {
        if code == "UNSUPPORTED" {
            PreparedActionError::Unsupported
        } else {
            PreparedActionError::Invalid
        }
    })?;
    let operation = WireValue::Object(vec![
        ("v".encode_utf16().collect(), WireValue::Number(1.0)),
        (
            "kind".encode_utf16().collect(),
            WireValue::String("ACTION".encode_utf16().collect()),
        ),
        ("input".encode_utf16().collect(), input),
        ("objects".encode_utf16().collect(), objects),
    ]);
    Ok((operation, context, policy))
}

pub fn validate_prepared_action_operation(
    operation_wire: &[u8],
    context_wire: &[u8],
    signed_policy_wire: &[u8],
    authenticated_prior_objects: &[WireValue],
) -> Result<ValidatedPreparedAction, PreparedActionError> {
    let parse = |wire: &[u8]| {
        parse_wire_json_bounded(wire, 64, MAX_WIRE).map_err(|_| PreparedActionError::Invalid)
    };
    let operation = parse(operation_wire)?;
    let context = parse(context_wire)?;
    let policy = parse(signed_policy_wire)?;
    if operation.get("v").and_then(WireValue::as_number) != Some(1.0)
        || operation
            .get("kind")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some("ACTION")
    {
        return Err(PreparedActionError::Invalid);
    }
    validate_action_state_slice(&operation, &context, &policy, authenticated_prior_objects)
        .map_err(|code| {
            if code == "UNSUPPORTED" {
                PreparedActionError::Unsupported
            } else {
                PreparedActionError::Invalid
            }
        })?;
    let payload = policy.get("payload").ok_or(PreparedActionError::Invalid)?;
    let version = payload
        .get("v")
        .and_then(WireValue::as_number)
        .ok_or(PreparedActionError::Invalid)?;
    let structured = version == 2.0
        || version == 3.0
            && payload
                .get("structure_mode")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("STRUCTURED");
    if structured {
        let contract = payload
            .get("structure")
            .ok_or(PreparedActionError::Invalid)?;
        let envelope = context
            .get("structure")
            .ok_or(PreparedActionError::Invalid)?;
        let WireValue::Object(fields) = envelope else {
            return Err(PreparedActionError::Invalid);
        };
        if fields.len() != 4
            || envelope.get("v").and_then(WireValue::as_number) != Some(1.0)
            || envelope
                .get("mode")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some("DELTA")
        {
            return Err(PreparedActionError::Invalid);
        }
        let WireValue::Array(records) = envelope
            .get("records")
            .ok_or(PreparedActionError::Invalid)?
        else {
            return Err(PreparedActionError::Invalid);
        };
        let WireValue::Array(heads) = envelope.get("heads").ok_or(PreparedActionError::Invalid)?
        else {
            return Err(PreparedActionError::Invalid);
        };
        validate_projection_page(records, heads, contract)
            .map_err(|_| PreparedActionError::Invalid)?;
        let WireValue::Array(objects) = operation
            .get("objects")
            .ok_or(PreparedActionError::Invalid)?
        else {
            return Err(PreparedActionError::Invalid);
        };
        let (expected_records, expected_heads) =
            project_structure_data(objects, contract).map_err(|_| PreparedActionError::Invalid)?;
        if !same(
            &WireValue::Array(expected_records),
            &WireValue::Array(records.to_vec()),
        )? || !same(
            &WireValue::Array(expected_heads),
            &WireValue::Array(heads.to_vec()),
        )? {
            return Err(PreparedActionError::Invalid);
        }
    } else if context.get("structure").is_some() {
        return Err(PreparedActionError::Invalid);
    }
    let canonical_operation = canonical_wire_value(&operation, Path::SecureArtifact)
        .map_err(|_| PreparedActionError::Invalid)?
        .into_bytes();
    Ok(ValidatedPreparedAction {
        canonical_operation,
        context_sha256: canonical_hash(context_wire).ok_or(PreparedActionError::Invalid)?,
        policy_sha256: canonical_hash(signed_policy_wire).ok_or(PreparedActionError::Invalid)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn check_case(
        policy: &Value,
        commits: &Value,
        operations: &Value,
    ) -> Result<ValidatedPreparedAction, PreparedActionError> {
        let mut context = commits[1]["payload"].clone();
        context.as_object_mut().unwrap().remove("mode");
        context.as_object_mut().unwrap().remove("body");
        let prior_wire = serde_json::to_vec(&operations[0]["objects"]).unwrap();
        let WireValue::Array(prior) = parse_wire_json_bounded(&prior_wire, 64, MAX_WIRE).unwrap()
        else {
            panic!("prior objects must be an array")
        };
        let proof = validate_prepared_action_operation(
            &serde_json::to_vec(&operations[1]).unwrap(),
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(policy).unwrap(),
            &prior,
        )?;
        let produced = build_prepared_action_operation(
            &serde_json::to_vec(&operations[1]["input"]).unwrap(),
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(policy).unwrap(),
            &prior,
        )?;
        assert_eq!(produced.operation_wire(), proof.operation_wire());
        Ok(proof)
    }

    #[test]
    fn writer_generated_many_effect_and_delegated_action_validate_before_authoring() {
        let many: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/signed-many-action-vectors.json"
        ))
        .unwrap();
        let proof =
            check_case(&many["policies"][0], &many["commits"], &many["operations"]).unwrap();
        assert!(!proof.operation_wire().is_empty());
        let mut altered = many["operations"].clone();
        altered[1]["objects"][0]["value"]["entity_id"] = json!("x".repeat(43));
        assert!(check_case(&many["policies"][0], &many["commits"], &altered).is_err());

        let cases: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/signed-recovery-vectors.json"
        ))
        .unwrap();
        let delegated = cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "signed_delegated_wiki_action_corrected")
            .unwrap();
        let proof = check_case(
            &delegated["policy"],
            &delegated["commits"],
            &delegated["operations"],
        )
        .unwrap();
        assert!(!proof.operation_wire().is_empty());
        let mut expected_context = delegated["commits"][1]["payload"].clone();
        expected_context.as_object_mut().unwrap().remove("mode");
        expected_context.as_object_mut().unwrap().remove("body");
        let mut input_context = expected_context.clone();
        input_context.as_object_mut().unwrap().remove("structure");
        let WireValue::Array(prior) = parse_wire_json_bounded(
            &serde_json::to_vec(&delegated["operations"][0]["objects"]).unwrap(),
            64,
            MAX_WIRE,
        )
        .unwrap() else {
            panic!("prior objects must be an array")
        };
        let built = build_prepared_action_with_context(
            &serde_json::to_vec(&delegated["operations"][1]["input"]).unwrap(),
            &serde_json::to_vec(&input_context).unwrap(),
            &serde_json::to_vec(&delegated["policy"]).unwrap(),
            &prior,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(built.context_wire()).unwrap(),
            expected_context
        );
        assert_eq!(built.action().operation_wire(), proof.operation_wire());
        let mut wrong_structure = delegated["commits"].clone();
        wrong_structure[1]["payload"]["structure"]["heads"] = json!([]);
        assert!(check_case(
            &delegated["policy"],
            &wrong_structure,
            &delegated["operations"]
        )
        .is_err());
    }
}
