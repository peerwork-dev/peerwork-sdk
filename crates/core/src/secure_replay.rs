//! Internal content decoding and basic object-history checks. These facts do
//! not authorize reads: protocol evaluation, structure, recovery, migration,
//! and role policies must all pass before a verified journal may be returned.

use crate::{
    canonical::Path,
    crypto::{decode_base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{open_content_wire, SealedContent},
    interpreter::{evaluate_action, EvalResult, InterpreterAuth},
    legacy_protocol_bindings::validate_legacy_protocol_bindings,
    migration_fragments::{assert_protocol_format_ceiling, inflate_fragments, MigrationBatch},
    protocol_object_source::{
        object_part_id, read_protocol_object_source, validate_object_part,
        validate_object_source_proof,
    },
    protocol_package_source::{
        package_part_id, validate_package_checkpoint, validate_package_part,
        verify_protocol_package_source,
    },
    secure_chain::{
        scan_signed_chain_headers_with_limit, DEFAULT_MAX_COMMITS, ChainError, CheckpointPin, HeaderChainFacts, OwnerPin,
    },
    secure_recovery::preflight_recovery,
    wire_json::{
        canonical_wire_value, parse_js_json_string_bounded, parse_wire_json_js_bounded, WireValue,
    },
};
#[cfg(test)]
use crate::secure_chain::scan_signed_chain_headers;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 98_304;
type RoleHistory = HashMap<(Vec<u16>, Vec<u16>, Vec<u16>), HashSet<Vec<u16>>>;

fn ensure_secure_effects_supported(interpreted: &EvalResult) -> Result<(), &'static str> {
    if interpreted.withdrawals.is_empty() {
        Ok(())
    } else {
        Err("PUBLICATION_WITHDRAWAL_UNSUPPORTED")
    }
}

#[derive(Debug, Error)]
pub(crate) enum ReplayError {
    #[error("signed replay exceeds configured commit budget")]
    ResourceLimit,
    #[error("signed chain did not validate: {0}")]
    Chain(#[from] ChainError),
    #[error("content or object history is invalid")]
    Invalid,
    #[error("signed content failed at sequence {sequence} during {check}")]
    Content { sequence: u64, check: &'static str },
}

fn same_wire(left: &WireValue, right: &WireValue) -> Result<bool, ReplayError> {
    Ok(
        canonical_wire_value(left, Path::SecureArtifact).map_err(|_| ReplayError::Invalid)?
            == canonical_wire_value(right, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?,
    )
}

fn exact_fields(value: &WireValue, names: &[&str]) -> bool {
    value.object_len() == Some(names.len()) && names.iter().all(|name| value.get(name).is_some())
}

fn validate_signed_object_stage(
    operation: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior: &[WireValue],
    commit_wires: &[&[u8]],
    chain: &HeaderChainFacts,
) -> Result<(), ReplayError> {
    let p = policy.get("payload").ok_or(ReplayError::Invalid)?;
    let input = operation.get("input").ok_or(ReplayError::Invalid)?;
    let stage = input
        .get("protocol_object_stage")
        .ok_or(ReplayError::Invalid)?;
    let proof = stage.get("proof").ok_or(ReplayError::Invalid)?;
    validate_object_source_proof(proof).map_err(|_| ReplayError::Invalid)?;
    let source = proof.get("source").ok_or(ReplayError::Invalid)?;
    let WireValue::Array(descriptors) = proof.get("parts").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let index = integer(stage, "part_index")? as usize;
    let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    if !exact_fields(operation, &["v", "kind", "input", "objects"])
        || !exact_fields(input, &["protocol_object_stage"])
        || !exact_fields(stage, &["proof", "part_index"])
        || integer(context, "v")? != 3
        || integer(p, "v")? != 3
        || string(p, "visibility")? != "PRIVATE"
        || string(context, "workspace_id")? != string(p, "workspace_id")?
        || string(context, "actor_id")? != string(p, "owner_id")?
        || string(context, "signing_key")? != string(p, "signing_key")?
        || !matches!(context.get("delegation"), Some(WireValue::Null))
        || !matches!(context.get("instance_id"), Some(WireValue::Null))
        || context.get("recovery").is_some()
        || context.get("migration").is_some()
        || context.get("conversion_excluded_members").is_some()
        || objects.len() != 1
        || index >= descriptors.len()
    {
        return Err(ReplayError::Invalid);
    }
    match string(p, "structure_mode")?.as_str() {
        "STRUCTURED" => {
            let structure = context.get("structure").ok_or(ReplayError::Invalid)?;
            if p.get("structure").is_none()
                || !exact_fields(structure, &["v", "mode", "records", "heads"])
                || integer(structure, "v")? != 1
                || string(structure, "mode")? != "DELTA"
                || !matches!(structure.get("records"), Some(WireValue::Array(items)) if items.is_empty())
                || !matches!(structure.get("heads"), Some(WireValue::Array(items)) if items.is_empty())
            {
                return Err(ReplayError::Invalid);
            }
        }
        "NONE" if context.get("structure").is_none() && p.get("structure").is_none() => {}
        _ => return Err(ReplayError::Invalid),
    }
    let base = integer(source, "sequence")?;
    let id = string(proof, "source_id")?;
    let descriptor = &descriptors[index];
    let part = &objects[0];
    validate_object_part(part).map_err(|_| ReplayError::Invalid)?;
    let value = part.get("value").ok_or(ReplayError::Invalid)?;
    if !same_wire(source, &signed_checkpoint_at(base, chain, commit_wires)?)?
        || string(source, "workspace_id")? != string(context, "workspace_id")?
        || string(source, "owner_id")? != string(context, "actor_id")?
        || string(source, "owner_key")? != string(context, "signing_key")?
        || string(source, "policy_hash")? != string(context, "policy_hash")?
        || integer(p, "effective_sequence")? > base
        || integer(context, "sequence")? != base + index as u64 + 1
        || string(part, "id")? != string(descriptor, "id")?
        || string(value, "workspace_id")? != string(source, "workspace_id")?
        || string(value, "source_id")? != id
        || integer(value, "index")? != index as u64
        || integer(value, "bytes")? != integer(descriptor, "bytes")?
        || string(value, "sha256")? != string(descriptor, "sha256")?
        || prior.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref()
                == Some("protocol_object_part")
                && object.get("id").and_then(WireValue::as_string).as_deref()
                    == Some(&string(part, "id").unwrap_or_default())
        })
    {
        return Err(ReplayError::Invalid);
    }
    if index == 0 {
        if string(context, "previous")? != string(source, "head")? {
            return Err(ReplayError::Invalid);
        }
    } else {
        let previous_id =
            object_part_id(source, &id, index - 1).map_err(|_| ReplayError::Invalid)?;
        let previous = prior
            .iter()
            .filter(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref()
                    == Some("protocol_object_part")
                    && object.get("id").and_then(WireValue::as_string).as_deref()
                        == Some(&previous_id)
            })
            .collect::<Vec<_>>();
        if previous.len() != 1 {
            return Err(ReplayError::Invalid);
        }
        validate_object_part(previous[0]).map_err(|_| ReplayError::Invalid)?;
        let row = previous[0].get("value").ok_or(ReplayError::Invalid)?;
        let expected = &descriptors[index - 1];
        if string(row, "source_id")? != id
            || string(row, "workspace_id")? != string(source, "workspace_id")?
            || integer(row, "index")? != (index - 1) as u64
            || integer(row, "bytes")? != integer(expected, "bytes")?
            || string(row, "sha256")? != string(expected, "sha256")?
        {
            return Err(ReplayError::Invalid);
        }
    }
    Ok(())
}

struct HydratedProtocolObject {
    reference_index: usize,
    proof: WireValue,
}

fn validate_replayed_object_size(
    object: &WireValue, index: usize, source: Option<&HydratedProtocolObject>,
) -> Result<(), ReplayError> {
    let object_bytes = canonical_wire_value(object, Path::SecureArtifact).map_err(|_| ReplayError::Invalid)?.len();
    if object_bytes <= MAX_OBJECT_BYTES { return Ok(()); }
    // Only the exact reference slot hydrated earlier in this iteration can
    // exceed the wire-object bound; an unrelated/inline object cannot inherit it.
    let source = source.filter(|source| source.reference_index == index).ok_or(ReplayError::Invalid)?;
    validate_object_source_proof(&source.proof).map_err(|_| ReplayError::Invalid)?;
    let value = canonical_wire_value(object.get("value").ok_or(ReplayError::Invalid)?, Path::SecureArtifact)
        .map_err(|_| ReplayError::Invalid)?;
    let declared = usize::try_from(integer(&source.proof, "bytes")?).map_err(|_| ReplayError::Invalid)?;
    if string(object, "kind")? != "protocols" || object.get("id") != source.proof.get("protocol_digest")
        || value.len() != declared || sha256_hex(value.as_bytes()) != string(&source.proof, "value_sha256")?
        || object_bytes > declared.checked_add(MAX_OBJECT_BYTES).ok_or(ReplayError::Invalid)? {
        return Err(ReplayError::Invalid);
    }
    Ok(())
}

fn hydrate_signed_protocol_install(
    operation: WireValue,
    context: &WireValue,
    prior_objects: &[WireValue],
    prior_operations: &[WireValue],
    chain: &HeaderChainFacts,
    commit_wires: &[&[u8]],
) -> Result<(WireValue, Option<HydratedProtocolObject>), ReplayError> {
    let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let references = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
                && object
                    .get("value")
                    .and_then(|value| value.get("object_source"))
                    .is_some()
        })
        .collect::<Vec<_>>();
    if references.is_empty() {
        return Ok((operation, None));
    }
    if references.len() != 1
        || objects.len() != 2
        || integer(context, "v")? != 3
        || string(context, "action_id")? != "secure.structure.begin"
        || !matches!(context.get("instance_id"), Some(WireValue::Null))
        || !matches!(context.get("delegation"), Some(WireValue::Null))
        || context.get("recovery").is_some()
        || context.get("migration").is_some()
        || string(
            context.get("structure").ok_or(ReplayError::Invalid)?,
            "mode",
        )? != "SNAPSHOT_BEGIN"
        || string(&operation, "kind")? != "ADMIN"
    {
        return Err(ReplayError::Invalid);
    }
    let (reference_index, reference) = references[0];
    let reference_value = reference.get("value").ok_or(ReplayError::Invalid)?;
    if !exact_fields(
        reference_value,
        &["workspace_id", "digest", "object_source"],
    ) || integer(reference, "revision")? != 1
        || string(reference, "provenance")? != "AUTHOR_SIGNED"
        || canonical_wire_value(reference, Path::SecureArtifact)
            .map_err(|_| ReplayError::Invalid)?
            .len()
            > MAX_OBJECT_BYTES
    {
        return Err(ReplayError::Invalid);
    }
    let proof = reference_value
        .get("object_source")
        .ok_or(ReplayError::Invalid)?;
    validate_object_source_proof(proof).map_err(|_| ReplayError::Invalid)?;
    let source = proof.get("source").ok_or(ReplayError::Invalid)?;
    let snapshot_source = context
        .get("structure")
        .and_then(|s| s.get("snapshot"))
        .and_then(|s| s.get("source"))
        .ok_or(ReplayError::Invalid)?;
    let input_digest = operation
        .get("input")
        .and_then(|input| input.get("install"))
        .and_then(|install| install.get("protocol_digest"))
        .ok_or(ReplayError::Invalid)?;
    let WireValue::Array(descriptors) = proof.get("parts").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let base = integer(source, "sequence")?;
    let end = base + descriptors.len() as u64;
    let digest = string(reference, "id")?;
    if string(reference_value, "workspace_id")? != string(context, "workspace_id")?
        || string(reference_value, "digest")? != digest
        || string(proof, "protocol_digest")? != digest
        || string(proof, "workspace_id")? != string(context, "workspace_id")?
        || !same_wire(source, &signed_checkpoint_at(base, chain, commit_wires)?)?
        || !same_wire(
            snapshot_source,
            &signed_checkpoint_at(end, chain, commit_wires)?,
        )?
        || string(source, "owner_id")? != string(context, "actor_id")?
        || string(source, "owner_key")? != string(context, "signing_key")?
        || string(source, "policy_hash")? != string(snapshot_source, "policy_hash")?
        || integer(context, "sequence")? != end + 1
        || string(context, "previous")? != string(snapshot_source, "head")?
        || input_digest != reference.get("id").ok_or(ReplayError::Invalid)?
        || prior_objects.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
                && object.get("id") == reference.get("id")
        })
        || prior_operations.len() < descriptors.len()
    {
        return Err(ReplayError::Invalid);
    }
    for (index, (earlier, descriptor)) in prior_operations
        .iter()
        .rev()
        .take(descriptors.len())
        .rev()
        .zip(descriptors)
        .enumerate()
    {
        let stage = earlier
            .get("input")
            .and_then(|input| input.get("protocol_object_stage"))
            .ok_or(ReplayError::Invalid)?;
        let WireValue::Array(parts) = earlier.get("objects").ok_or(ReplayError::Invalid)? else {
            return Err(ReplayError::Invalid);
        };
        if !exact_fields(earlier, &["v", "kind", "input", "objects"])
            || string(earlier, "kind")? != "ADMIN"
            || !exact_fields(
                earlier.get("input").ok_or(ReplayError::Invalid)?,
                &["protocol_object_stage"],
            )
            || !exact_fields(stage, &["proof", "part_index"])
            || !same_wire(stage.get("proof").ok_or(ReplayError::Invalid)?, proof)?
            || integer(stage, "part_index")? != index as u64
            || parts.len() != 1
            || string(&parts[0], "id")? != string(descriptor, "id")?
        {
            return Err(ReplayError::Invalid);
        }
    }
    let logical_value =
        read_protocol_object_source(proof, prior_objects).map_err(|_| ReplayError::Invalid)?;
    let saved_proof = proof.clone();
    let mut hydrated = operation;
    let WireValue::Object(fields) = &mut hydrated else {
        return Err(ReplayError::Invalid);
    };
    let (_, WireValue::Array(objects)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq("objects".encode_utf16()))
        .ok_or(ReplayError::Invalid)?
    else {
        return Err(ReplayError::Invalid);
    };
    let WireValue::Object(reference_fields) = &mut objects[reference_index] else {
        return Err(ReplayError::Invalid);
    };
    let (_, value) = reference_fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq("value".encode_utf16()))
        .ok_or(ReplayError::Invalid)?;
    *value = logical_value;
    Ok((hydrated, Some(HydratedProtocolObject { reference_index, proof: saved_proof })))
}

fn signed_checkpoint_at(
    sequence: u64,
    chain: &HeaderChainFacts,
    commit_wires: &[&[u8]],
) -> Result<WireValue, ReplayError> {
    let index = usize::try_from(sequence.checked_sub(1).ok_or(ReplayError::Invalid)?)
        .map_err(|_| ReplayError::Invalid)?;
    let head = chain.commit_hashes.get(index).ok_or(ReplayError::Invalid)?;
    let commit = parse_wire_json_js_bounded(
        commit_wires.get(index).ok_or(ReplayError::Invalid)?,
        64,
        196_608,
    )
    .map_err(|_| ReplayError::Invalid)?;
    let payload = commit.get("payload").ok_or(ReplayError::Invalid)?;
    Ok(fields_object(vec![
        ("v", WireValue::Number(1.0)),
        ("workspace_id", string_value(&chain.workspace_id)),
        ("owner_id", string_value(&chain.owner_id)),
        ("owner_key", string_value(&chain.owner_key)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("head", string_value(head)),
        (
            "policy_hash",
            string_value(&string(payload, "policy_hash")?),
        ),
    ]))
}

fn normalized_structure_field(
    rule: &WireValue,
    value: &WireValue,
) -> Result<WireValue, ReplayError> {
    validate_readable_field(rule, value).map_err(|_| ReplayError::Invalid)?;
    let kind = string(rule, "type")?;
    if matches!(
        kind.as_str(),
        "reference" | "workspace_reference" | "optional_reference" | "optional_workspace_reference"
    ) {
        if matches!(value, WireValue::Null) {
            return Ok(WireValue::Null);
        }
        return normalized_structure_reference(value);
    }
    if kind == "references" {
        let WireValue::Array(values) = value else {
            return Err(ReplayError::Invalid);
        };
        return Ok(WireValue::Array(
            values
                .iter()
                .map(normalized_structure_reference)
                .collect::<Result<Vec<_>, _>>()?,
        ));
    }
    Ok(value.clone())
}

fn normalized_structure_reference(value: &WireValue) -> Result<WireValue, ReplayError> {
    let id = value
        .get("recordId")
        .or_else(|| value.get("record_id"))
        .ok_or(ReplayError::Invalid)?;
    Ok(fields_object(vec![
        ("record_id", id.clone()),
        (
            "revision",
            value.get("revision").ok_or(ReplayError::Invalid)?.clone(),
        ),
    ]))
}

pub(crate) fn project_structure_data(
    objects: &[WireValue],
    contract: &WireValue,
) -> Result<(Vec<WireValue>, Vec<WireValue>), ReplayError> {
    let WireValue::Array(protocols) = contract.get("protocols").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let mut records = Vec::new();
    let mut heads = Vec::<(Vec<u16>, u64, WireValue)>::new();
    for object in objects {
        let kind = string(object, "kind")?;
        if kind == "records" {
            let value = object.get("value").ok_or(ReplayError::Invalid)?;
            let protocol_digest = string(value, "protocol_digest")?;
            let schema_name = string(value, "schema_ref")?;
            let protocol = protocols
                .iter()
                .find(|p| {
                    p.get("protocol_digest")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some(&protocol_digest)
                })
                .ok_or(ReplayError::Invalid)?;
            let schema = protocol
                .get("schemas")
                .and_then(|schemas| schemas.get(&schema_name))
                .ok_or(ReplayError::Invalid)?;
            let definitions = schema.get("fields").ok_or(ReplayError::Invalid)?;
            let payload = decoded_value(value.get("payload").ok_or(ReplayError::Invalid)?)
                .map_err(|_| ReplayError::Invalid)?;
            let WireValue::Object(payload_fields) = &payload else {
                return Err(ReplayError::Invalid);
            };
            let WireValue::Array(required) = schema.get("required").ok_or(ReplayError::Invalid)?
            else {
                return Err(ReplayError::Invalid);
            };
            if required.iter().any(|name| {
                name.as_string()
                    .is_none_or(|name| payload.get(&name).is_none())
            }) {
                return Err(ReplayError::Invalid);
            }
            let mut readable = Vec::new();
            for (name, item) in payload_fields {
                let key = String::from_utf16(name).map_err(|_| ReplayError::Invalid)?;
                let rule = definitions.get(&key).ok_or(ReplayError::Invalid)?;
                if string(rule, "protection")? == "server_readable" {
                    readable.push((name.clone(), normalized_structure_field(rule, item)?));
                }
            }
            records.push(fields_object(vec![
                (
                    "record_id",
                    value.get("id").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "entity_id",
                    value.get("entity_id").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "revision",
                    value.get("revision").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "instance_id",
                    value
                        .get("instance_id")
                        .ok_or(ReplayError::Invalid)?
                        .clone(),
                ),
                (
                    "protocol_digest",
                    value
                        .get("protocol_digest")
                        .ok_or(ReplayError::Invalid)?
                        .clone(),
                ),
                (
                    "schema_ref",
                    value.get("schema_ref").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "actor_id",
                    value.get("actor_id").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "created",
                    value.get("created").ok_or(ReplayError::Invalid)?.clone(),
                ),
                ("fields", WireValue::Object(readable)),
            ]));
        } else if kind == "entity_heads" {
            let value = object.get("value").ok_or(ReplayError::Invalid)?;
            let id = utf16(object, "id")?.to_vec();
            let revision = integer(object, "revision")?;
            let projected = fields_object(vec![
                (
                    "entity_id",
                    value.get("entity_id").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "record_id",
                    value.get("record_id").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "revision",
                    value.get("revision").ok_or(ReplayError::Invalid)?.clone(),
                ),
                (
                    "instance_id",
                    value
                        .get("instance_id")
                        .ok_or(ReplayError::Invalid)?
                        .clone(),
                ),
            ]);
            if let Some((_, prior_revision, prior_head)) =
                heads.iter_mut().find(|(prior_id, _, _)| *prior_id == id)
            {
                if revision > *prior_revision {
                    *prior_revision = revision;
                    *prior_head = projected;
                }
            } else {
                heads.push((id, revision, projected));
            }
        }
    }
    let heads = heads
        .into_iter()
        .map(|(_, _, head)| head)
        .collect::<Vec<_>>();
    Ok((records, heads))
}

fn sort_structure_snapshot(records: &mut [WireValue], heads: &mut [WireValue]) {
    records.sort_by(|left, right| {
        left.get("record_id")
            .and_then(WireValue::as_utf16)
            .cmp(&right.get("record_id").and_then(WireValue::as_utf16))
    });
    heads.sort_by(|left, right| {
        left.get("entity_id")
            .and_then(WireValue::as_utf16)
            .cmp(&right.get("entity_id").and_then(WireValue::as_utf16))
    });
}

struct StructureSnapshotProgress {
    source: WireValue,
    root: String,
    record_count: usize,
    head_count: usize,
    offset: usize,
    expected_records: Vec<WireValue>,
    expected_heads: Vec<WireValue>,
}

fn validate_signed_structure_slice(
    operation: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior_objects: &[WireValue],
    chain: &HeaderChainFacts,
    commit_wires: &[&[u8]],
    progress: &mut Option<StructureSnapshotProgress>,
) -> Result<(), ReplayError> {
    let p = policy.get("payload").ok_or(ReplayError::Invalid)?;
    let structured = integer(p, "v")? == 2
        || integer(p, "v")? == 3 && string(p, "structure_mode")? == "STRUCTURED";
    let recovery = context.get("recovery");
    if !structured {
        return if context.get("structure").is_none() && progress.is_none() {
            Ok(())
        } else {
            Err(ReplayError::Invalid)
        };
    }
    let contract = p.get("structure").ok_or(ReplayError::Invalid)?;
    crate::structure_policy::validate_structure_policy(contract)
        .map_err(|_| ReplayError::Invalid)?;
    let envelope = context.get("structure").ok_or(ReplayError::Invalid)?;
    let mode = string(envelope, "mode")?;
    if recovery.is_some() {
        if mode != "SNAPSHOT_BEGIN" {
            return Err(ReplayError::Invalid);
        }
        // The signed recovery disposition discards a partial snapshot and
        // restarts from the independently replayed base objects.
        *progress = None;
    }
    let WireValue::Array(records) = envelope.get("records").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let WireValue::Array(heads) = envelope.get("heads").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    if integer(envelope, "v")? != 1 || records.len() > 128 || heads.len() > 128 {
        return Err(ReplayError::Invalid);
    }
    crate::structure_delta::validate_projection_page(records, heads, contract)
        .map_err(|_| ReplayError::Invalid)?;
    if mode == "DELTA" {
        if !exact_fields(envelope, &["v", "mode", "records", "heads"]) {
            return Err(ReplayError::Invalid);
        }
        let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)?
        else {
            return Err(ReplayError::Invalid);
        };
        let (expected_records, expected_heads) = project_structure_data(objects, contract)?;
        if progress.is_some()
            && (string(operation, "kind")? != "ADMIN"
                || !objects.is_empty()
                || string(context, "action_id")? != "secure.rotate"
                || string(context, "actor_id")? != string(p, "owner_id")?
                || string(context, "signing_key")? != string(p, "signing_key")?
                || !matches!(context.get("delegation"), Some(WireValue::Null))
                || !matches!(context.get("instance_id"), Some(WireValue::Null))
                || integer(p, "effective_sequence")? != integer(context, "sequence")?)
        {
            return Err(ReplayError::Invalid);
        }
        return if same_wire(
            &WireValue::Array(records.clone()),
            &WireValue::Array(expected_records),
        )? && same_wire(
            &WireValue::Array(heads.clone()),
            &WireValue::Array(expected_heads),
        )? {
            if progress.is_none() {
                let (prior_records, prior_heads) = project_structure_data(prior_objects, contract)?;
                crate::structure_delta::apply_delta(
                    records,
                    heads,
                    contract,
                    &prior_records,
                    &prior_heads,
                    context,
                    policy,
                )
                .map_err(|_| ReplayError::Invalid)?;
            }
            Ok(())
        } else {
            Err(ReplayError::Invalid)
        };
    }
    if !matches!(
        mode.as_str(),
        "SNAPSHOT_BEGIN" | "SNAPSHOT_PAGE" | "SNAPSHOT_END"
    ) || !exact_fields(envelope, &["v", "mode", "records", "heads", "snapshot"])
        || string(operation, "kind")? != "ADMIN"
        || string(context, "actor_id")? != string(p, "owner_id")?
        || string(context, "signing_key")? != string(p, "signing_key")?
        || !matches!(context.get("delegation"), Some(WireValue::Null))
        || !matches!(context.get("instance_id"), Some(WireValue::Null))
    {
        return Err(ReplayError::Invalid);
    }
    let snapshot = envelope.get("snapshot").ok_or(ReplayError::Invalid)?;
    let action = string(context, "action_id")?;
    let expected_action = match mode.as_str() {
        "SNAPSHOT_BEGIN" => "secure.structure.begin",
        "SNAPSHOT_PAGE" => "secure.structure.page",
        "SNAPSHOT_END" => "secure.structure.end",
        _ => unreachable!(),
    };
    if action != expected_action
        && !(mode == "SNAPSHOT_BEGIN"
            && (action == "secure.fields.begin"
                || recovery.is_some() && action == "secure.recover"))
        || !exact_fields(snapshot, &["source", "root", "records", "heads", "offset"])
    {
        return Err(ReplayError::Invalid);
    }
    let record_count =
        usize::try_from(integer(snapshot, "records")?).map_err(|_| ReplayError::Invalid)?;
    let head_count =
        usize::try_from(integer(snapshot, "heads")?).map_err(|_| ReplayError::Invalid)?;
    let total = record_count
        .checked_add(head_count)
        .filter(|n| *n <= 100_000)
        .ok_or(ReplayError::Invalid)?;
    let offset = usize::try_from(integer(snapshot, "offset")?).map_err(|_| ReplayError::Invalid)?;
    if offset > total {
        return Err(ReplayError::Invalid);
    }
    let root = string(snapshot, "root")?;
    if root.len() != 64
        || !root
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ReplayError::Invalid);
    }
    let source = snapshot.get("source").ok_or(ReplayError::Invalid)?;
    if mode != "SNAPSHOT_BEGIN" {
        let state = progress.as_mut().ok_or(ReplayError::Invalid)?;
        if !same_wire(source, &state.source)?
            || root != state.root
            || record_count != state.record_count
            || head_count != state.head_count
            || offset != state.offset
        {
            return Err(ReplayError::Invalid);
        }
        if mode == "SNAPSHOT_END" {
            if !records.is_empty() || !heads.is_empty() || offset != total {
                return Err(ReplayError::Invalid);
            }
            crate::structure_delta::validate_snapshot_graph(
                contract,
                &state.expected_records,
                &state.expected_heads,
            )
            .map_err(|_| ReplayError::Invalid)?;
            *progress = None;
            return Ok(());
        }
        let count = records
            .len()
            .checked_add(heads.len())
            .ok_or(ReplayError::Invalid)?;
        if count == 0
            || offset.checked_add(count).is_none_or(|end| end > total)
            || offset < record_count && !heads.is_empty()
            || offset >= record_count && !records.is_empty()
            || offset < record_count && offset + records.len() > record_count
        {
            return Err(ReplayError::Invalid);
        }
        let expected_records = if offset < record_count {
            &state.expected_records[offset..offset + records.len()]
        } else {
            &[]
        };
        let expected_heads = if offset >= record_count {
            let start = offset - record_count;
            &state.expected_heads[start..start + heads.len()]
        } else {
            &[]
        };
        if !same_wire(
            &WireValue::Array(records.clone()),
            &WireValue::Array(expected_records.to_vec()),
        )? || !same_wire(
            &WireValue::Array(heads.clone()),
            &WireValue::Array(expected_heads.to_vec()),
        )? {
            return Err(ReplayError::Invalid);
        }
        state.offset += count;
        return Ok(());
    }
    if progress.is_some() || !records.is_empty() || !heads.is_empty() || offset != 0 {
        return Err(ReplayError::Invalid);
    }
    let prior_sequence = integer(context, "sequence")?
        .checked_sub(1)
        .ok_or(ReplayError::Invalid)?;
    let prior_checkpoint = if let Some(recovery) = recovery {
        recovery.get("base").ok_or(ReplayError::Invalid)?.clone()
    } else if prior_sequence == 0 {
        fields_object(vec![
            ("v", WireValue::Number(1.0)),
            ("workspace_id", string_value(&chain.workspace_id)),
            ("owner_id", string_value(&chain.owner_id)),
            ("owner_key", string_value(&chain.owner_key)),
            ("sequence", WireValue::Number(0.0)),
            ("head", WireValue::Null),
            (
                "policy_hash",
                string_value(&string(context, "policy_hash")?),
            ),
        ])
    } else {
        signed_checkpoint_at(prior_sequence, chain, commit_wires)?
    };
    if !same_wire(
        snapshot.get("source").ok_or(ReplayError::Invalid)?,
        &prior_checkpoint,
    )? {
        return Err(ReplayError::Invalid);
    }
    let (mut expected_records, mut expected_heads) =
        project_structure_data(prior_objects, contract)?;
    sort_structure_snapshot(&mut expected_records, &mut expected_heads);
    let projected = fields_object(vec![
        ("records", WireValue::Array(expected_records.clone())),
        ("heads", WireValue::Array(expected_heads.clone())),
    ]);
    let root = sha256_hex(
        canonical_wire_value(&projected, Path::SecureArtifact)
            .map_err(|_| ReplayError::Invalid)?
            .as_bytes(),
    );
    if record_count != expected_records.len()
        || head_count != expected_heads.len()
        || string(snapshot, "root")? != root
    {
        return Err(ReplayError::Invalid);
    }
    *progress = Some(StructureSnapshotProgress {
        source: source.clone(),
        root,
        record_count,
        head_count,
        offset: 0,
        expected_records,
        expected_heads,
    });
    Ok(())
}

fn validate_signed_package_stage(
    operation: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior: &[WireValue],
    commit_wires: &[&[u8]],
    chain: &HeaderChainFacts,
) -> Result<(), ReplayError> {
    let p = policy.get("payload").ok_or(ReplayError::Invalid)?;
    let v = integer(context, "v")?;
    let structure = context.get("structure").ok_or(ReplayError::Invalid)?;
    let records = structure.get("records").ok_or(ReplayError::Invalid)?;
    let heads = structure.get("heads").ok_or(ReplayError::Invalid)?;
    let input = operation.get("input").ok_or(ReplayError::Invalid)?;
    let stage = input.get("package_stage").ok_or(ReplayError::Invalid)?;
    let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    if !exact_fields(operation, &["v", "kind", "input", "objects"])
        || !exact_fields(input, &["package_stage"])
        || !exact_fields(stage, &["part_index", "source", "source_id"])
        || !exact_fields(structure, &["v", "mode", "records", "heads"])
        || integer(structure, "v")? != 1
        || string(structure, "mode")? != "DELTA"
        || !matches!(records, WireValue::Array(values) if values.is_empty())
        || !matches!(heads, WireValue::Array(values) if values.is_empty())
        || objects.len() != 1
        || string(p, "visibility")? != "PRIVATE"
        || !(v == 2 || v == 3 && string(p, "structure_mode")? == "STRUCTURED")
        || integer(p, "v")? != v
        || p.get("structure").is_none()
        || string(context, "actor_id")? != string(p, "owner_id")?
        || string(context, "signing_key")? != string(p, "signing_key")?
        || !matches!(context.get("delegation"), Some(WireValue::Null))
        || !matches!(context.get("instance_id"), Some(WireValue::Null))
        || context.get("recovery").is_some()
        || context.get("migration").is_some()
        || context.get("conversion_excluded_members").is_some()
    {
        return Err(ReplayError::Invalid);
    }
    let source = stage.get("source").ok_or(ReplayError::Invalid)?;
    validate_package_checkpoint(source).map_err(|_| ReplayError::Invalid)?;
    let base = integer(source, "sequence")?;
    let index = integer(stage, "part_index")?;
    let sequence = integer(context, "sequence")?;
    let id = string(stage, "source_id")?;
    let part = &objects[0];
    validate_package_part(part).map_err(|_| ReplayError::Invalid)?;
    let value = part.get("value").ok_or(ReplayError::Invalid)?;
    if !same_wire(source, &signed_checkpoint_at(base, chain, commit_wires)?)?
        || sequence
            != base
                .checked_add(index)
                .and_then(|n| n.checked_add(1))
                .ok_or(ReplayError::Invalid)?
        || integer(p, "effective_sequence")? > base
        || string(source, "workspace_id")? != string(context, "workspace_id")?
        || string(source, "owner_id")? != string(context, "actor_id")?
        || string(source, "owner_key")? != string(context, "signing_key")?
        || string(source, "policy_hash")? != string(context, "policy_hash")?
        || string(value, "workspace_id")? != string(context, "workspace_id")?
        || string(value, "source_id")? != id
        || integer(value, "index")? != index
        || string(part, "id")?
            != package_part_id(source, &id, index as usize).map_err(|_| ReplayError::Invalid)?
    {
        return Err(ReplayError::Invalid);
    }
    if index == 0 {
        if string(context, "previous")? != string(source, "head")? {
            return Err(ReplayError::Invalid);
        }
    } else {
        let previous_id =
            package_part_id(source, &id, (index - 1) as usize).map_err(|_| ReplayError::Invalid)?;
        let previous = prior
            .iter()
            .filter(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref()
                    == Some("protocol_package_part")
                    && object.get("id").and_then(WireValue::as_string).as_deref()
                        == Some(&previous_id)
            })
            .collect::<Vec<_>>();
        if previous.len() != 1 {
            return Err(ReplayError::Invalid);
        }
        validate_package_part(previous[0]).map_err(|_| ReplayError::Invalid)?;
        let last = previous[0].get("value").ok_or(ReplayError::Invalid)?;
        if string(last, "source_id")? != id
            || string(last, "workspace_id")? != string(source, "workspace_id")?
            || integer(last, "index")? != index - 1
        {
            return Err(ReplayError::Invalid);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_signed_package_install(
    operation: &WireValue,
    context: &WireValue,
    prior_objects: &[WireValue],
    prior_operations: &[WireValue],
    chain: &HeaderChainFacts,
    commit_wires: &[&[u8]],
    workspace_id: &str,
    object_source: Option<&WireValue>,
) -> Result<(), ReplayError> {
    let input = operation.get("input").ok_or(ReplayError::Invalid)?;
    let install = input.get("install").ok_or(ReplayError::Invalid)?;
    let structure = context.get("structure").ok_or(ReplayError::Invalid)?;
    let snapshot = structure.get("snapshot").ok_or(ReplayError::Invalid)?;
    let snapshot_source = snapshot.get("source").ok_or(ReplayError::Invalid)?;
    let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    if !exact_fields(operation, &["v", "kind", "input", "objects"])
        || !exact_fields(input, &["install"])
        || !exact_fields(install, &["entrypoint", "instance_id", "protocol_digest"])
        || string(context, "action_id")? != "secure.structure.begin"
        || string(structure, "mode")? != "SNAPSHOT_BEGIN"
        || !matches!(context.get("instance_id"), Some(WireValue::Null))
        || !matches!(context.get("delegation"), Some(WireValue::Null))
        || !objects.iter().all(|object| {
            matches!(
                object.get("kind").and_then(WireValue::as_string).as_deref(),
                Some("protocols" | "instances")
            )
        })
    {
        return Err(ReplayError::Invalid);
    }
    let instance_id = string(install, "instance_id")?;
    let digest = string(install, "protocol_digest")?;
    let entrypoint = string(install, "entrypoint")?;
    if !token_utf16(&instance_id.encode_utf16().collect::<Vec<_>>())
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || entrypoint.is_empty()
        || entrypoint.len() > 64
        || !entrypoint.as_bytes()[0].is_ascii_alphabetic()
        || !entrypoint
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || prior_objects.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && object.get("id").and_then(WireValue::as_string).as_deref() == Some(&instance_id)
        })
    {
        return Err(ReplayError::Invalid);
    }
    let instances = objects
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
        })
        .collect::<Vec<_>>();
    let added = objects
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
        })
        .collect::<Vec<_>>();
    let prior = prior_objects.iter().find(|object| {
        object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
            && object.get("id").and_then(WireValue::as_string).as_deref() == Some(&digest)
    });
    if instances.len() != 1
        || added.len() != usize::from(prior.is_none())
        || objects.len() != 1 + added.len()
    {
        return Err(ReplayError::Invalid);
    }
    let instance = instances[0];
    let protocol = if let Some(prior) = prior {
        prior
    } else {
        added[0]
    };
    let value = protocol.get("value").ok_or(ReplayError::Invalid)?;
    let instance_value = instance.get("value").ok_or(ReplayError::Invalid)?;
    // Direct and composed installs have no package_source on the instance.
    // They still require the same exact install shape and initial instance
    // value as a staged package-source install. The source-specific proof
    // below only applies when that field is actually present.
    if instance_value.get("package_source").is_none() {
        if value.get("package_source").is_some() {
            return Err(ReplayError::Invalid);
        }
        let format_ceiling = if integer(context, "v")? == 3 {
            integer(context, "protocol_format_ceiling")?
        } else {
            1
        };
        validate_authored_protocol_in_history(
            protocol,
            workspace_id,
            format_ceiling,
            prior_objects,
        )?;
        let expected_fields = if value.get("composition").is_some() {
            vec![
                "composition",
                "digest",
                "manifest",
                "resolved_manifest",
                "workspace_id",
            ]
        } else {
            vec!["digest", "manifest", "resolved_manifest", "workspace_id"]
        };
        if added.len() == 1 && !exact_fields(value, &expected_fields) {
            return Err(ReplayError::Invalid);
        }
        let manifest = decoded_value(value.get("manifest").ok_or(ReplayError::Invalid)?)
            .map_err(|_| ReplayError::Invalid)?;
        let expected_instance = fields_object(vec![
            ("id", string_value(&instance_id)),
            ("workspace_id", string_value(workspace_id)),
            ("protocol_digest", string_value(&digest)),
            ("origin_entrypoint", string_value(&entrypoint)),
            ("semantics", string_value("peerwork.kernel.v1")),
            (
                "state",
                manifest
                    .get("initial_state")
                    .ok_or(ReplayError::Invalid)?
                    .clone(),
            ),
            ("revision", WireValue::Number(0.0)),
            ("event_revision", WireValue::Number(0.0)),
            (
                "created",
                context
                    .get("issued_at")
                    .ok_or(ReplayError::Invalid)?
                    .clone(),
            ),
        ]);
        if string(instance, "id")? != instance_id
            || integer(instance, "revision")? != 1
            || string(instance, "provenance")? != "AUTHOR_SIGNED"
            || !same_wire(instance_value, &expected_instance)?
        {
            return Err(ReplayError::Invalid);
        }
        return Ok(());
    }
    let proof = instance_value
        .get("package_source")
        .ok_or(ReplayError::Invalid)?;
    let verified =
        verify_protocol_package_source(proof, prior_objects).map_err(|_| ReplayError::Invalid)?;
    let source = &verified.source;
    let base = integer(source, "sequence")?;
    let end = base
        .checked_add(verified.part_count as u64)
        .ok_or(ReplayError::Invalid)?;
    let package_stage_head = object_source
        .and_then(|proof| proof.get("source"))
        .unwrap_or(snapshot_source);
    let object_parts = object_source
        .and_then(|proof| proof.get("parts"))
        .and_then(|parts| match parts {
            WireValue::Array(parts) => Some(parts.len()),
            _ => None,
        })
        .unwrap_or(0);
    if string(proof, "workspace_id")? != workspace_id
        || string(source, "owner_id")? != string(context, "actor_id")?
        || string(source, "owner_key")? != string(context, "signing_key")?
        || string(source, "policy_hash")? != string(snapshot_source, "policy_hash")?
        || end != integer(package_stage_head, "sequence")?
        || !same_wire(
            package_stage_head,
            &signed_checkpoint_at(end, chain, commit_wires)?,
        )?
        || integer(snapshot_source, "sequence")? != end + object_parts as u64
        || !same_wire(
            snapshot_source,
            &signed_checkpoint_at(end + object_parts as u64, chain, commit_wires)?,
        )?
        || !same_wire(source, &signed_checkpoint_at(base, chain, commit_wires)?)?
        || integer(context, "sequence")? != end + object_parts as u64 + 1
        || string(context, "previous")? != string(snapshot_source, "head")?
        || verified.protocol_digest != digest
        || string(protocol, "id")? != digest
        || string(value, "digest")? != digest
        || string(value, "workspace_id")? != workspace_id
        || !same_wire(
            value.get("manifest").ok_or(ReplayError::Invalid)?,
            value.get("resolved_manifest").ok_or(ReplayError::Invalid)?,
        )?
    {
        return Err(ReplayError::Invalid);
    }
    let manifest = decoded_value(value.get("manifest").ok_or(ReplayError::Invalid)?)
        .map_err(|_| ReplayError::Invalid)?;
    if let Some(original) = value.get("package_source") {
        let original_verified = verify_protocol_package_source(original, prior_objects)
            .map_err(|_| ReplayError::Invalid)?;
        if value.get("composition").is_some()
            || original_verified.protocol_digest != digest
            || !same_wire(&original_verified.manifest, &manifest)?
        {
            return Err(ReplayError::Invalid);
        }
    }
    if manifest.get("format_version").is_some()
        && (integer(context, "v")? != 3 || integer(context, "protocol_format_ceiling")? != 2)
    {
        return Err(ReplayError::Invalid);
    }
    if !same_wire(&manifest, &verified.manifest)?
        || sha256_hex(
            canonical_wire_value(
                &fields_object(vec![
                    ("semantics", string_value("peerwork.kernel.v1")),
                    ("manifest", manifest.clone()),
                ]),
                Path::SecureArtifact,
            )
            .map_err(|_| ReplayError::Invalid)?
            .as_bytes(),
        ) != digest
    {
        return Err(ReplayError::Invalid);
    }
    // The reviewed source must correspond to the exact signed contiguous
    // stage operations. Retained part bytes alone do not authenticate order.
    let WireValue::Array(descriptors) = proof.get("parts").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let stage_start = prior_operations
        .len()
        .checked_sub(object_parts)
        .and_then(|end| end.checked_sub(descriptors.len()))
        .ok_or(ReplayError::Invalid)?;
    for (offset, descriptor) in descriptors.iter().enumerate() {
        // Journal.operations can omit earlier recovered commits. Sequence
        // numbers authenticate the stage range above; this tail position is
        // relative to the decoded operation list, as in the tracked verifier.
        let operation = prior_operations
            .get(stage_start + offset)
            .ok_or(ReplayError::Invalid)?;
        let stage = operation
            .get("input")
            .and_then(|input| input.get("package_stage"))
            .ok_or(ReplayError::Invalid)?;
        let WireValue::Array(parts) = operation.get("objects").ok_or(ReplayError::Invalid)? else {
            return Err(ReplayError::Invalid);
        };
        if parts.len() != 1
            || !same_wire(stage.get("source").ok_or(ReplayError::Invalid)?, source)?
            || string(stage, "source_id")? != string(proof, "source_id")?
            || integer(stage, "part_index")? != offset as u64
            || string(&parts[0], "id")? != string(descriptor, "id")?
        {
            return Err(ReplayError::Invalid);
        }
    }
    if added.len() == 1 {
        if value.get("composition").is_some()
            || !same_wire(
                value.get("package_source").ok_or(ReplayError::Invalid)?,
                proof,
            )?
            || !exact_fields(
                value,
                &[
                    "digest",
                    "workspace_id",
                    "manifest",
                    "resolved_manifest",
                    "package_source",
                ],
            )
            || integer(protocol, "revision")? != 1
            || string(protocol, "provenance")? != "AUTHOR_SIGNED"
        {
            return Err(ReplayError::Invalid);
        }
    }
    let expected_instance = fields_object(vec![
        ("id", string_value(&instance_id)),
        ("workspace_id", string_value(workspace_id)),
        ("protocol_digest", string_value(&digest)),
        ("origin_entrypoint", string_value(&entrypoint)),
        ("semantics", string_value("peerwork.kernel.v1")),
        (
            "state",
            manifest
                .get("initial_state")
                .ok_or(ReplayError::Invalid)?
                .clone(),
        ),
        ("revision", WireValue::Number(0.0)),
        ("event_revision", WireValue::Number(0.0)),
        (
            "created",
            context
                .get("issued_at")
                .ok_or(ReplayError::Invalid)?
                .clone(),
        ),
        ("package_source", proof.clone()),
    ]);
    if string(instance, "id")? != instance_id
        || integer(instance, "revision")? != 1
        || string(instance, "provenance")? != "AUTHOR_SIGNED"
        || !same_wire(instance_value, &expected_instance)?
    {
        return Err(ReplayError::Invalid);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayFacts {
    pub chain: HeaderChainFacts,
    pub operations: Vec<WireValue>,
    pub objects: Vec<WireValue>,
    pub object_count: usize,
    pub legacy: bool,
    pub recoveries: Vec<WireValue>,
    pub action_receipts: Vec<WireValue>,
    pub structure_state: Option<&'static str>,
    pub structure_snapshot: Option<WireValue>,
}

/// Reconstruct a signed PUBLIC prefix exported into the first PRIVATE
/// migration pages. The regular header scanner authenticates the complete
/// concatenated history after this function returns; nothing here is a proof.
#[cfg(test)]
fn restore_archived_public_history(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    workspace_id: &str,
    keyring_wire: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, ReplayError> {
    restore_archived_public_history_with_limit(policy_wires, commit_wires, workspace_id, keyring_wire, DEFAULT_MAX_COMMITS)
}

fn restore_archived_public_history_with_limit(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    workspace_id: &str,
    keyring_wire: Option<&[u8]>,
    max_commits: usize,
) -> Result<Vec<Vec<u8>>, ReplayError> {
    if max_commits == 0 || commit_wires.len() > max_commits { return Err(ReplayError::ResourceLimit); }
    let Some(first_wire) = commit_wires.first() else {
        return Ok(Vec::new());
    };
    let first =
        parse_wire_json_js_bounded(first_wire, 64, 196_608).map_err(|_| ReplayError::Invalid)?;
    let first_payload = first.get("payload").ok_or(ReplayError::Invalid)?;
    if integer(first_payload, "sequence")? == 1 {
        return Ok(commit_wires.iter().map(|wire| wire.to_vec()).collect());
    }
    let source = first_payload
        .get("migration")
        .and_then(|migration| migration.get("source_checkpoint"))
        .ok_or(ReplayError::Invalid)?;
    let source_sequence = integer(source, "sequence")?;
    if source_sequence == 0
        || string(source, "workspace_id")? != workspace_id
        || source_sequence.checked_add(1) != Some(integer(first_payload, "sequence")?)
        || source.get("head") != first_payload.get("previous")
    {
        return Err(ReplayError::Invalid);
    }
    let restored_count = usize::try_from(source_sequence).ok().and_then(|n| n.checked_add(commit_wires.len())).ok_or(ReplayError::ResourceLimit)?;
    if restored_count > max_commits { return Err(ReplayError::ResourceLimit); }
    let genesis_wire = policy_wires.first().ok_or(ReplayError::Invalid)?;
    let genesis = parse_wire_json_js_bounded(genesis_wire, 64, 32 * 1024 * 1024)
        .map_err(|_| ReplayError::Invalid)?;
    let genesis_payload = genesis.get("payload").ok_or(ReplayError::Invalid)?;
    let owner = string(genesis_payload, "owner_id")?;
    let owner_key = string(genesis_payload, "signing_key")?;
    if string(source, "owner_id")? != owner || string(source, "owner_key")? != owner_key {
        return Err(ReplayError::Invalid);
    }
    let mut policies = HashMap::new();
    let mut source_policy: Option<(u64, String)> = None;
    for wire in policy_wires {
        let policy = parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024)
            .map_err(|_| ReplayError::Invalid)?;
        let hash = sha256_hex(
            canonical_wire_value(&policy, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?
                .as_bytes(),
        );
        let effective = integer(
            policy.get("payload").ok_or(ReplayError::Invalid)?,
            "effective_sequence",
        )?;
        if effective <= source_sequence
            && source_policy
                .as_ref()
                .is_none_or(|(prior, _)| effective >= *prior)
        {
            source_policy = Some((effective, hash.clone()));
        }
        policies.insert(hash, policy);
    }
    if source_policy.as_ref().map(|(_, hash)| hash.as_str())
        != Some(string(source, "policy_hash")?.as_str())
    {
        return Err(ReplayError::Invalid);
    }
    let mut prior = string(source, "head")?;
    let mut sequence = source_sequence;
    let mut archive_objects = Vec::new();
    for wire in commit_wires {
        let commit =
            parse_wire_json_js_bounded(wire, 64, 196_608).map_err(|_| ReplayError::Invalid)?;
        let payload = commit.get("payload").ok_or(ReplayError::Invalid)?;
        let Some(migration) = payload.get("migration") else {
            break;
        };
        let policy_hash = string(payload, "policy_hash")?;
        let policy = policies.get(&policy_hash).ok_or(ReplayError::Invalid)?;
        let policy_payload = policy.get("payload").ok_or(ReplayError::Invalid)?;
        if string(payload, "workspace_id")? != workspace_id
            || string(payload, "mode")? != "PRIVATE"
            || integer(payload, "sequence")? != sequence + 1
            || string(payload, "previous")? != prior
            || string(payload, "actor_id")? != owner
            || string(payload, "signing_key")? != owner_key
            || payload.get("delegation") != Some(&WireValue::Null)
            || integer(payload, "epoch")? != integer(policy_payload, "epoch")?
            || !same_wire(
                migration
                    .get("source_checkpoint")
                    .ok_or(ReplayError::Invalid)?,
                source,
            )?
        {
            return Err(ReplayError::Invalid);
        }
        if !verify_secure_signed_wire(wire, "peerwork.secure.commit.v1", &owner_key)
            .map_err(|_| ReplayError::Invalid)?
        {
            return Err(ReplayError::Invalid);
        }
        let key = zeroize::Zeroizing::new(epoch_key(
            keyring_wire.ok_or(ReplayError::Invalid)?,
            workspace_id,
            integer(payload, "epoch")?,
        )?);
        let sealed = sealed_content(payload.get("body").ok_or(ReplayError::Invalid)?)?;
        let context = commit_context(payload)?;
        let context_text = canonical_wire_value(&context, Path::SecureArtifact)
            .map_err(|_| ReplayError::Invalid)?;
        let plaintext = zeroize::Zeroizing::new(
            open_content_wire(&key, &sealed, context_text.as_bytes())
                .map_err(|_| ReplayError::Invalid)?,
        );
        let operation = parse_wire_json_js_bounded(&plaintext, 2048, MAX_CONTENT_BYTES)
            .map_err(|_| ReplayError::Invalid)?;
        if string(&operation, "kind")? != "MIGRATE"
            || canonical_wire_value(&operation, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?
                .as_bytes()
                != plaintext.as_slice()
        {
            return Err(ReplayError::Invalid);
        }
        let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)?
        else {
            return Err(ReplayError::Invalid);
        };
        archive_objects.extend_from_slice(objects);
        sequence += 1;
        prior = sha256_hex(
            canonical_wire_value(&commit, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?
                .as_bytes(),
        );
    }
    let inflated = inflate_fragments(&archive_objects).map_err(|_| ReplayError::Invalid)?;
    let mut originals = HashMap::<u64, Vec<u8>>::new();
    for object in inflated {
        if string(&object, "kind")? != "secure_commits" {
            continue;
        }
        let value = object.get("value").ok_or(ReplayError::Invalid)?;
        let original = if let Some(units) = value.get("artifact").and_then(WireValue::as_utf16) {
            parse_js_json_string_bounded(units, 64, 196_608).map_err(|_| ReplayError::Invalid)?
        } else {
            value.clone()
        };
        let payload = original.get("payload").ok_or(ReplayError::Invalid)?;
        let n = integer(payload, "sequence")?;
        if n == 0
            || n > source_sequence
            || string(payload, "workspace_id")? != workspace_id
            || string(payload, "mode")? != "PUBLIC"
            || originals.contains_key(&n)
        {
            return Err(ReplayError::Invalid);
        }
        originals.insert(
            n,
            canonical_wire_value(&original, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?
                .into_bytes(),
        );
    }
    if u64::try_from(originals.len()).map_err(|_| ReplayError::Invalid)? != source_sequence {
        return Err(ReplayError::Invalid);
    }
    let mut restored = Vec::with_capacity(restored_count);
    for sequence in 1..=source_sequence {
        restored.push(originals.remove(&sequence).ok_or(ReplayError::Invalid)?);
    }
    restored.extend(commit_wires.iter().map(|wire| wire.to_vec()));
    Ok(restored)
}

fn index_candidate_objects(
    candidate: &[WireValue],
) -> Result<(HashSet<String>, HashMap<String, u64>), ReplayError> {
    let mut seen = HashSet::new();
    let mut latest = HashMap::<String, u64>::new();
    for object in candidate {
        let kind = utf16(object, "kind")?;
        let id = utf16(object, "id")?;
        let revision = integer(object, "revision")?;
        let key = canonical_wire_value(
            &WireValue::Array(vec![
                WireValue::String(kind.to_vec()),
                WireValue::String(id.to_vec()),
                WireValue::Number(revision as f64),
            ]),
            Path::SecureArtifact,
        )
        .map_err(|_| ReplayError::Invalid)?;
        if !seen.insert(key) {
            return Err(ReplayError::Invalid);
        }
        let pair = canonical_wire_value(
            &WireValue::Array(vec![
                WireValue::String(kind.to_vec()),
                WireValue::String(id.to_vec()),
            ]),
            Path::SecureArtifact,
        )
        .map_err(|_| ReplayError::Invalid)?;
        latest
            .entry(pair)
            .and_modify(|prior| *prior = (*prior).max(revision))
            .or_insert(revision);
    }
    Ok((seen, latest))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_basic_content(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    checkpoint_wire: &[u8],
    workspace_id: &str,
    trusted_owner: Option<&OwnerPin<'_>>,
    pinned: Option<&CheckpointPin<'_>>,
    keyring_wire: Option<&[u8]>,
) -> Result<ReplayFacts, ReplayError> {
    replay_basic_content_with_limit(policy_wires, commit_wires, checkpoint_wire, workspace_id, trusted_owner, pinned, keyring_wire, DEFAULT_MAX_COMMITS)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_basic_content_with_limit(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    checkpoint_wire: &[u8],
    workspace_id: &str,
    trusted_owner: Option<&OwnerPin<'_>>,
    pinned: Option<&CheckpointPin<'_>>,
    keyring_wire: Option<&[u8]>,
    max_commits: usize,
) -> Result<ReplayFacts, ReplayError> {
    replay_basic_content_with_guard_times(
        policy_wires, commit_wires, checkpoint_wire, workspace_id, trusted_owner, pinned,
        keyring_wire, max_commits, None,
    )
}

pub(crate) fn replay_basic_content_with_guard_times(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    checkpoint_wire: &[u8],
    workspace_id: &str,
    trusted_owner: Option<&OwnerPin<'_>>,
    pinned: Option<&CheckpointPin<'_>>,
    keyring_wire: Option<&[u8]>,
    max_commits: usize,
    guard_times: Option<&HashMap<String, Vec<u8>>>,
) -> Result<ReplayFacts, ReplayError> {
    replay_basic_content_depth(
        policy_wires,
        commit_wires,
        checkpoint_wire,
        workspace_id,
        trusted_owner,
        pinned,
        keyring_wire,
        guard_times,
        0,
        max_commits,
    )
}

#[allow(clippy::too_many_arguments)]
fn replay_basic_content_depth(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    checkpoint_wire: &[u8],
    workspace_id: &str,
    trusted_owner: Option<&OwnerPin<'_>>,
    pinned: Option<&CheckpointPin<'_>>,
    keyring_wire: Option<&[u8]>,
    guard_times: Option<&HashMap<String, Vec<u8>>>,
    depth: usize,
    max_commits: usize,
) -> Result<ReplayFacts, ReplayError> {
    if depth > 32 {
        return Err(ReplayError::Invalid);
    }
    let restored =
        restore_archived_public_history_with_limit(policy_wires, commit_wires, workspace_id, keyring_wire, max_commits)?;
    let restored_refs = restored.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let commit_wires = restored_refs.as_slice();
    let chain = scan_signed_chain_headers_with_limit(
        policy_wires,
        commit_wires,
        checkpoint_wire,
        workspace_id,
        trusted_owner,
        pinned,
        max_commits,
    )?;
    // The legacy replay API carries no service proof collection. It must fail
    // closed before decrypting or evaluating opted-in journal content.
    if chain.guard_time_enabled && guard_times.is_none() {
        return Err(ReplayError::Invalid);
    }
    let recovery_segments =
        preflight_recovery(policy_wires, commit_wires, &chain).map_err(|_| ReplayError::Invalid)?;
    let mut policies = HashMap::new();
    for (hash, wire) in chain.policy_hashes.iter().zip(policy_wires) {
        let policy = parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024)
            .map_err(|_| ReplayError::Invalid)?;
        policies.insert(hash.as_str(), policy);
    }
    let mut seen_objects = HashSet::new();
    let mut latest_revisions: HashMap<String, u64> = HashMap::new();
    let mut prior_objects = Vec::new();
    let mut role_history = RoleHistory::new();
    let mut structure_progress = None;
    let mut previous_policy_hash: Option<String> = None;
    let mut operations = Vec::with_capacity(commit_wires.len());
    let mut recoveries = Vec::new();
    let mut action_receipts = Vec::new();
    let mut legacy = false;
    let mut migration_batch: Option<MigrationBatch> = None;
    let mut migration_base: Option<Vec<WireValue>> = None;
    let mut prior_mode: Option<String> = None;
    let mut verified_guard_proofs = HashSet::new();
    for (commit_index, wire) in commit_wires.iter().enumerate() {
        let mut staged_revisions: HashMap<String, u64> = HashMap::new();
        let commit =
            parse_wire_json_js_bounded(wire, 64, 196_608).map_err(|_| ReplayError::Invalid)?;
        let payload = commit.get("payload").ok_or(ReplayError::Invalid)?;
        let sequence = integer(payload, "sequence")?;
        let commit_policy_hash = string(payload, "policy_hash")?;
        let commit_policy = policies.get(commit_policy_hash.as_str()).ok_or(ReplayError::Invalid)?;
        let commit_policy_payload = commit_policy.get("payload").ok_or(ReplayError::Invalid)?;
        let admitted_at_ms = if chain.guard_time_enabled && commit_policy_payload.get("guard_time").is_some() {
            let guard_policy = crate::guard_time::parse_guard_time_policy(
                commit_policy_payload.get("guard_time").ok_or(ReplayError::Invalid)?,
            )
            .map_err(|_| ReplayError::Invalid)?;
            let source = signed_checkpoint_at(sequence.checked_sub(1).ok_or(ReplayError::Invalid)?, &chain, commit_wires)?;
            let result = signed_checkpoint_at(sequence, &chain, commit_wires)?;
            let commit_hash = chain.commit_hashes.get(commit_index).ok_or(ReplayError::Invalid)?;
            let proof_wire = guard_times
                .and_then(|proofs| proofs.get(commit_hash))
                .ok_or(ReplayError::Invalid)?;
            let proof_envelope = parse_wire_json_js_bounded(proof_wire, 32, crate::guard_time::GUARD_TIME_ATTESTATION_MAX_BYTES)
                .map_err(|_| ReplayError::Invalid)?;
            let proof_payload = proof_envelope.get("payload").ok_or(ReplayError::Invalid)?;
            let expected = fields_object(vec![
                ("v", WireValue::Number(1.0)),
                ("audience", string_value(&guard_policy.audience)),
                ("service_key", string_value(&guard_policy.service_key)),
                ("workspace_id", string_value(workspace_id)),
                ("command_id", payload.get("command_id").ok_or(ReplayError::Invalid)?.clone()),
                ("actor_id", payload.get("actor_id").ok_or(ReplayError::Invalid)?.clone()),
                ("signing_key", payload.get("signing_key").ok_or(ReplayError::Invalid)?.clone()),
                ("action_id", payload.get("action_id").ok_or(ReplayError::Invalid)?.clone()),
                ("instance_id", payload.get("instance_id").ok_or(ReplayError::Invalid)?.clone()),
                ("epoch", payload.get("epoch").ok_or(ReplayError::Invalid)?.clone()),
                ("policy_hash", payload.get("policy_hash").ok_or(ReplayError::Invalid)?.clone()),
                ("source", source),
                ("result", result),
                ("commit_hash", string_value(commit_hash)),
                ("context", payload.get("guard_time").ok_or(ReplayError::Invalid)?.clone()),
                ("admitted_at_ms", proof_payload.get("admitted_at_ms").ok_or(ReplayError::Invalid)?.clone()),
            ]);
            let proof = crate::guard_time::verify_guard_time_attestation(proof_wire, &guard_policy, &expected)
                .map_err(|_| ReplayError::Invalid)?;
            if !verified_guard_proofs.insert(commit_hash.clone()) {
                return Err(ReplayError::Invalid);
            }
            Some(proof.payload.get("admitted_at_ms").and_then(WireValue::as_number)
                .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
                .map(|value| value as u64).ok_or(ReplayError::Invalid)?)
        } else {
            None
        };
        if let Some(admitted_at) = admitted_at_ms {
            let mut auth_context = commit_context(payload)?;
            replace_field(
                &mut auth_context,
                "issued_at",
                WireValue::Number(admitted_at as f64),
            )
            .map_err(|_| ReplayError::Invalid)?;
            let policy = commit_policy.get("payload").ok_or(ReplayError::Invalid)?;
            let delegation_wire = match auth_context.get("delegation") {
                Some(WireValue::Null) => None,
                Some(value) => Some(
                    canonical_wire_value(value, Path::SecureArtifact)
                        .map_err(|_| ReplayError::Invalid)?,
                ),
                None => return Err(ReplayError::Invalid),
            };
            let checked = crate::secure_action_delegation::resolve_action_scope(
                &auth_context,
                policy,
                delegation_wire.as_deref().map(str::as_bytes),
            )
            .map_err(|_| ReplayError::Invalid)?;
            crate::secure_action_delegation::verify_member_certificate_at(
                policy,
                &checked.actor_id,
                admitted_at,
            )
            .map_err(|_| ReplayError::Invalid)?;
            let instance_at_t = payload.get("instance_id").and_then(WireValue::as_utf16);
            let mut admission_history = RoleHistory::new();
            validate_role_policies_with_history(
                policy,
                &prior_objects,
                admitted_at,
                instance_at_t,
                &mut admission_history,
            )
            .map_err(|_| ReplayError::Invalid)?;
            let owner_admin_context = string(payload, "actor_id")? == chain.owner_id
                && matches!(payload.get("instance_id"), Some(WireValue::Null))
                && matches!(payload.get("delegation"), Some(WireValue::Null));
            if !owner_admin_context && !checked.permits_action() {
                return Err(ReplayError::Invalid);
            }
        }
        let old_policy_payload = previous_policy_hash
            .as_deref()
            .and_then(|old_hash| policies.get(old_hash))
            .and_then(|old| old.get("payload"));
        let enabling_guard_time = old_policy_payload
            .is_some_and(|old| old.get("guard_time").is_none())
            && commit_policy_payload.get("guard_time").is_some();
        if enabling_guard_time {
            if string(payload, "action_id")? != "secure.guard-time.enable"
                || string(payload, "actor_id")? != chain.owner_id
                || !matches!(payload.get("instance_id"), Some(WireValue::Null))
                || !matches!(payload.get("delegation"), Some(WireValue::Null))
                || commit_policy_payload.get("visibility").and_then(WireValue::as_string).as_deref() != Some("PRIVATE")
                || crate::guard_time::parse_guard_time_context(
                    payload.get("guard_time").ok_or(ReplayError::Invalid)?,
                )
                .map_err(|_| ReplayError::Invalid)?
                    != crate::guard_time::GuardTimeContextV1::universal()
            {
                return Err(ReplayError::Invalid);
            }
            let old = old_policy_payload.ok_or(ReplayError::Invalid)?;
            for field in ["epoch", "members", "structure_mode", "protocol_format_ceiling"] {
                if !same_wire(
                    old.get(field).ok_or(ReplayError::Invalid)?,
                    commit_policy_payload.get(field).ok_or(ReplayError::Invalid)?,
                )? {
                    return Err(ReplayError::Invalid);
                }
            }
            if match (old.get("structure"), commit_policy_payload.get("structure")) {
                (Some(old), Some(new)) => !same_wire(old, new)?,
                (None, None) => false,
                _ => true,
            } {
                return Err(ReplayError::Invalid);
            }
        } else if string(payload, "action_id")? == "secure.guard-time.enable" {
            return Err(ReplayError::Invalid);
        }
        let excluded = recovery_segments
            .iter()
            .find(|segment| sequence > segment.base && sequence <= segment.through);
        if let Some(segment) = excluded {
            if enabling_guard_time {
                return Err(ReplayError::Invalid);
            }
            let policy_hash = string(payload, "policy_hash")?;
            let policy = policies
                .get(policy_hash.as_str())
                .ok_or(ReplayError::Invalid)?;
            if integer(payload, "v")? == 3 {
                // A decryptable v3 BOOTSTRAP or MIGRATE body cannot be hidden
                // inside a recovery range under an ordinary action header.
                let decoded = (|| -> Result<WireValue, ReplayError> {
                    let key = epoch_key(
                        keyring_wire.ok_or(ReplayError::Invalid)?,
                        workspace_id,
                        integer(payload, "epoch")?,
                    )?;
                    let sealed = sealed_content(payload.get("body").ok_or(ReplayError::Invalid)?)?;
                    let context = commit_context(payload)?;
                    let context_text = canonical_wire_value(&context, Path::SecureArtifact)
                        .map_err(|_| ReplayError::Invalid)?;
                    let plaintext = open_content_wire(&key, &sealed, context_text.as_bytes())
                        .map_err(|_| ReplayError::Invalid)?;
                    parse_wire_json_js_bounded(&plaintext, 2048, MAX_CONTENT_BYTES)
                        .map_err(|_| ReplayError::Invalid)
                })();
                if let Ok(operation) = decoded {
                    if let Some(kind) = operation.get("kind") {
                        if !matches!(kind.as_string().as_deref(), Some("ACTION" | "ADMIN")) {
                            return Err(ReplayError::Invalid);
                        }
                    }
                }
            }
            if sequence == segment.base + 1 {
                let base_checkpoint = signed_checkpoint_at(segment.base, &chain, commit_wires)?;
                let marker_index =
                    usize::try_from(segment.marker - 1).map_err(|_| ReplayError::Invalid)?;
                let marker_wire = commit_wires.get(marker_index).ok_or(ReplayError::Invalid)?;
                let marker = parse_wire_json_js_bounded(marker_wire, 64, 196_608)
                    .map_err(|_| ReplayError::Invalid)?;
                let recovery = marker
                    .get("payload")
                    .and_then(|payload| payload.get("recovery"))
                    .ok_or(ReplayError::Invalid)?;
                if !same_wire(
                    recovery.get("base").ok_or(ReplayError::Invalid)?,
                    &base_checkpoint,
                )? {
                    return Err(ReplayError::Invalid);
                }
                // The signed range alone never authorizes a skip. Replaying
                // through its first commit must fail, after the base prefix
                // has independently completed. Missing key material is not
                // a recoverable content failure.
                let keyring = keyring_wire.ok_or(ReplayError::Invalid)?;
                let _ = epoch_key(keyring, workspace_id, integer(payload, "epoch")?)?;
                let prefix_policy_count = policy_wires
                    .iter()
                    .take_while(|wire| {
                        parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024)
                            .ok()
                            .and_then(|policy| policy.get("payload").cloned())
                            .and_then(|payload| integer(&payload, "effective_sequence").ok())
                            .is_some_and(|effective| effective <= sequence)
                    })
                    .count();
                if prefix_policy_count == 0 {
                    return Err(ReplayError::Invalid);
                }
                let prefix_policies = &policy_wires[..prefix_policy_count];
                // The invalid BEGIN may itself introduce a policy. Its policy
                // belongs to the failure probe, not to the older base replay.
                // The complete outer header scan still verifies every policy.
                let base_policy_count = prefix_policies
                    .iter()
                    .take_while(|wire| {
                        parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024)
                            .ok()
                            .and_then(|policy| policy.get("payload").cloned())
                            .and_then(|payload| integer(&payload, "effective_sequence").ok())
                            .is_some_and(|effective| effective <= segment.base)
                    })
                    .count();
                if base_policy_count == 0 {
                    return Err(ReplayError::Invalid);
                }
                let base_checkpoint_wire =
                    canonical_wire_value(&base_checkpoint, Path::SecureArtifact)
                        .map_err(|_| ReplayError::Invalid)?;
                replay_basic_content_depth(
                    &prefix_policies[..base_policy_count],
                    &commit_wires[..commit_index],
                    base_checkpoint_wire.as_bytes(),
                    workspace_id,
                    trusted_owner,
                    pinned.filter(|pin| pin.sequence <= segment.base),
                    keyring_wire,
                    guard_times,
                    depth + 1,
                    max_commits,
                )?;
                let failed_checkpoint = signed_checkpoint_at(sequence, &chain, commit_wires)?;
                let failed_checkpoint_wire =
                    canonical_wire_value(&failed_checkpoint, Path::SecureArtifact)
                        .map_err(|_| ReplayError::Invalid)?;
                match replay_basic_content_depth(
                    prefix_policies,
                    &commit_wires[..=commit_index],
                    failed_checkpoint_wire.as_bytes(),
                    workspace_id,
                    trusted_owner,
                    pinned.filter(|pin| pin.sequence <= sequence),
                    keyring_wire,
                    guard_times,
                    depth + 1,
                    max_commits,
                ) {
                    Err(ReplayError::Content { sequence: failed, .. }) if failed == sequence => {}
                    _ => return Err(ReplayError::Invalid),
                }
            }
            validate_role_policies_with_history(
                policy.get("payload").ok_or(ReplayError::Invalid)?,
                &prior_objects,
                integer(payload, "issued_at")?,
                None,
                &mut role_history,
            )
            .map_err(|_| ReplayError::Invalid)?;
            previous_policy_hash = Some(policy_hash);
            continue;
        }
        let mode = string(payload, "mode")?;
        if mode == "PRIVATE" {
            // Source imports epoch material before entering the recoverable
            // content block. Its absence must never become a skip reason.
            let _ = epoch_key(
                keyring_wire.ok_or(ReplayError::Invalid)?,
                workspace_id,
                integer(payload, "epoch")?,
            )?;
        }
        let mut check = "content.decrypt";
        let step = (|| -> Result<(), ReplayError> {
            let operation = if mode == "PRIVATE" {
                let epoch = integer(payload, "epoch")?;
                let key = epoch_key(
                    keyring_wire.ok_or(ReplayError::Invalid)?,
                    workspace_id,
                    epoch,
                )?;
                let sealed_wire = payload.get("body").ok_or(ReplayError::Invalid)?;
                let sealed = sealed_content(sealed_wire)?;
                let context = commit_context(payload)?;
                let context_text = canonical_wire_value(&context, Path::SecureArtifact)
                    .map_err(|_| ReplayError::Invalid)?;
                let plaintext = open_content_wire(&key, &sealed, context_text.as_bytes())
                    .map_err(|_| ReplayError::Invalid)?;
                let operation = parse_wire_json_js_bounded(&plaintext, 2048, MAX_CONTENT_BYTES)
                    .map_err(|_| ReplayError::Invalid)?;
                if canonical_wire_value(&operation, Path::SecureArtifact)
                    .map_err(|_| ReplayError::Invalid)?
                    .as_bytes()
                    != plaintext
                {
                    return Err(ReplayError::Invalid);
                }
                operation
            } else if mode == "PUBLIC" {
                payload.get("body").ok_or(ReplayError::Invalid)?.clone()
            } else {
                return Err(ReplayError::Invalid);
            };
            if integer(&operation, "v")? != 1 {
                return Err(ReplayError::Invalid);
            }
            let kind = string(&operation, "kind")?;
            if !matches!(kind.as_str(), "BOOTSTRAP" | "MIGRATE" | "ACTION" | "ADMIN") {
                return Err(ReplayError::Invalid);
            }
            if commit_policy_payload.get("guard_time").is_some() && kind != "ACTION" {
                let context = crate::guard_time::parse_guard_time_context(
                    payload.get("guard_time").ok_or(ReplayError::Invalid)?,
                )
                .map_err(|_| ReplayError::Invalid)?;
                if context != crate::guard_time::GuardTimeContextV1::universal() {
                    return Err(ReplayError::Invalid);
                }
            }
            let marker = recovery_segments
                .iter()
                .find(|segment| segment.marker == sequence);
            if let Some(segment) = marker {
                if string(payload, "action_id")? != "secure.recover"
                    || kind != "ADMIN"
                    || !exact_fields(&operation, &["v", "kind", "input", "objects"])
                    || operation.get("input").and_then(WireValue::object_len) != Some(0)
                    || !matches!(operation.get("objects"), Some(WireValue::Array(items)) if items.is_empty())
                {
                    return Err(ReplayError::Invalid);
                }
                let WireValue::Object(fields) =
                    payload.get("recovery").ok_or(ReplayError::Invalid)?
                else {
                    return Err(ReplayError::Invalid);
                };
                let mut notice = fields.clone();
                notice.push((
                    "marker_sequence".encode_utf16().collect(),
                    WireValue::Number(sequence as f64),
                ));
                notice.push((
                    "excluded_count".encode_utf16().collect(),
                    WireValue::Number((segment.through - segment.base) as f64),
                ));
                recoveries.push(WireValue::Object(notice));
            } else if payload
                .get("recovery")
                .is_some_and(crate::secure_recovery::js_truthy)
                || string(payload, "action_id")? == "secure.recover"
            {
                return Err(ReplayError::Invalid);
            }
            let signed_operation = operation.clone();
            check = "install.hydration";
            let (operation, object_source) = hydrate_signed_protocol_install(
                operation,
                payload,
                &prior_objects,
                &operations,
                &chain,
                commit_wires,
            )?;
            let policy_hash = string(payload, "policy_hash")?;
            let policy = policies
                .get(policy_hash.as_str())
                .ok_or(ReplayError::Invalid)?;
            if enabling_guard_time {
                if kind != "ADMIN"
                    || mode != "PRIVATE"
                    || string(payload, "action_id")? != "secure.guard-time.enable"
                    || string(payload, "actor_id")? != chain.owner_id
                    || !matches!(payload.get("instance_id"), Some(WireValue::Null))
                    || !matches!(payload.get("delegation"), Some(WireValue::Null))
                    || !exact_fields(&operation, &["v", "kind", "input", "objects"])
                    || operation.get("input").and_then(WireValue::object_len) != Some(0)
                    || !matches!(operation.get("objects"), Some(WireValue::Array(items)) if items.is_empty())
                    || policy.get("payload").and_then(|p| p.get("visibility")).and_then(WireValue::as_string).as_deref() != Some("PRIVATE")
                {
                    return Err(ReplayError::Invalid);
                }
            } else if string(payload, "action_id")? == "secure.guard-time.enable" {
                return Err(ReplayError::Invalid);
            }
            if let Some(old_hash) = previous_policy_hash.as_deref() {
                let old_policy = policies.get(old_hash).ok_or(ReplayError::Invalid)?;
                let old_structure = old_policy.get("payload").and_then(|p| p.get("structure"));
                let new_structure = policy.get("payload").and_then(|p| p.get("structure"));
                if old_structure.is_some() && new_structure.is_none() {
                    return Err(ReplayError::Invalid);
                }
                let changed = match (old_structure, new_structure) {
                    (Some(old), Some(new)) => !same_wire(old, new)?,
                    (None, Some(_)) | (Some(_), None) => true,
                    (None, None) => false,
                };
                if changed {
                    let envelope = payload.get("structure").ok_or(ReplayError::Invalid)?;
                    let action = string(payload, "action_id")?;
                    if string(envelope, "mode")? != "SNAPSHOT_BEGIN"
                        || !(matches!(action.as_str(), "secure.structure.begin" | "secure.fields.begin")
                            || action == "secure.recover" && payload.get("recovery").is_some())
                    {
                        return Err(ReplayError::Invalid);
                    }
                }
            }
            check = "structure.snapshot";
            validate_signed_structure_slice(
                &operation,
                payload,
                policy,
                &prior_objects,
                &chain,
                commit_wires,
                &mut structure_progress,
            )?;
            if kind != "MIGRATE" && migration_batch.is_some() {
                let batch = migration_batch.take().ok_or(ReplayError::Invalid)?;
                let format = batch.format();
                let candidate = batch
                    .finish(migration_base.as_deref().ok_or(ReplayError::Invalid)?)
                    .map_err(|_| ReplayError::Invalid)?;
                if format == 3 {
                    assert_protocol_format_ceiling(&candidate, 1)
                        .map_err(|_| ReplayError::Invalid)?;
                }
                validate_historical_authored_protocols(&candidate, workspace_id, format)?;
                validate_legacy_protocol_bindings(&candidate, workspace_id)
                    .map_err(|_| ReplayError::Invalid)?;
                (seen_objects, latest_revisions) = index_candidate_objects(&candidate)?;
                legacy |= candidate.iter().any(|object| {
                    object
                        .get("provenance")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        == Some("LEGACY_OWNER_ATTESTED")
                });
                prior_objects = candidate;
                migration_base = None;
            }
            // These are only local preconditions. Full operation evaluation still
            // happens before any trusted journal result may be constructed.
            check = "operation.shape";
            let input = operation.get("input").ok_or(ReplayError::Invalid)?;
            match kind.as_str() {
                "BOOTSTRAP" if !operations.is_empty() => return Err(ReplayError::Invalid),
                "MIGRATE" if payload.get("migration").is_none() => {
                    return Err(ReplayError::Invalid)
                }
                "ACTION" => {
                    if string(input, "action_id")? != string(payload, "action_id")?
                        || input.get("instance_id") != payload.get("instance_id")
                        || integer(input, "expected_instance_revision").is_err()
                        || !matches!(input.get("exact_input_refs"), Some(WireValue::Array(_)))
                        || !matches!(input.get("allocations"), Some(WireValue::Array(_)))
                    {
                        return Err(ReplayError::Invalid);
                    }
                }
                _ => {}
            }
            let WireValue::Array(objects) = operation.get("objects").ok_or(ReplayError::Invalid)?
            else {
                return Err(ReplayError::Invalid);
            };
            if objects.len() > 128 {
                return Err(ReplayError::Invalid);
            }
            if string(payload,"action_id")? == "secure.member.scopes" {
                let old=old_policy_payload.ok_or(ReplayError::Invalid)?;
                let old_hash=previous_policy_hash.as_deref().ok_or(ReplayError::Invalid)?;
                crate::member_scopes::validate_transition(old,commit_policy_payload,payload,&operation,old_hash,&prior_objects).map_err(|_|ReplayError::Invalid)?;
                let at=integer(payload,"issued_at")?;
                for object in prior_objects.iter().filter(|o|o.get("kind").and_then(WireValue::as_string).as_deref()==Some("instances")) {
                    let instance=object.get("id").and_then(WireValue::as_utf16).ok_or(ReplayError::Invalid)?;
                    validate_role_policies_with_history(commit_policy_payload,&prior_objects,at,Some(instance),&mut role_history).map_err(|_|ReplayError::Invalid)?;
                }
            }
            check = "admin.preflight";
            let object_stage =
                kind == "ADMIN" && string(payload, "action_id")? == "secure.protocol-object.stage";
            let package_stage =
                kind == "ADMIN" && string(payload, "action_id")? == "secure.protocol-package.stage";
            if object_stage {
                validate_signed_object_stage(
                    &operation,
                    payload,
                    policies
                        .get(string(payload, "policy_hash")?.as_str())
                        .ok_or(ReplayError::Invalid)?,
                    &prior_objects,
                    commit_wires,
                    &chain,
                )?;
            } else if package_stage {
                validate_signed_package_stage(
                    &operation,
                    payload,
                    policies
                        .get(string(payload, "policy_hash")?.as_str())
                        .ok_or(ReplayError::Invalid)?,
                    &prior_objects,
                    commit_wires,
                    &chain,
                )?;
            } else if kind == "ADMIN" {
                validate_admin_preflight(&operation, payload, &latest_revisions)
                    .map_err(|error| ReplayError::Content { sequence, check: error.check() })?;
            } else if kind == "ACTION" {
                let hash = string(payload, "policy_hash")?;
                let policy = policies.get(hash.as_str()).ok_or(ReplayError::Invalid)?;
                if let Some(admitted_at) = admitted_at_ms {
                    let mut auth_context = commit_context(payload)?;
                    replace_field(
                        &mut auth_context,
                        "issued_at",
                        WireValue::Number(admitted_at as f64),
                    )
                    .map_err(|_| ReplayError::Invalid)?;
                    let delegation_wire = match auth_context.get("delegation") {
                        Some(WireValue::Null) => None,
                        Some(value) => Some(
                            canonical_wire_value(value, Path::SecureArtifact)
                                .map_err(|_| ReplayError::Invalid)?,
                        ),
                        None => return Err(ReplayError::Invalid),
                    };
                    let checked_at_t = crate::secure_action_delegation::resolve_action_scope(
                        &auth_context,
                        policy.get("payload").ok_or(ReplayError::Invalid)?,
                        delegation_wire.as_deref().map(str::as_bytes),
                    )
                    .map_err(|_| ReplayError::Invalid)?;
                    if !checked_at_t.permits_action() {
                        return Err(ReplayError::Invalid);
                    }
                }
                let context = commit_context(payload)?;
                validate_action_state_slice_at_time(&operation, &context, policy, &prior_objects, admitted_at_ms)
                    .map_err(|_| ReplayError::Invalid)?;
            } else if kind == "BOOTSTRAP" {
                if integer(payload, "sequence")? != 1 || !prior_objects.is_empty() {
                    return Err(ReplayError::Invalid);
                }
                validate_admin_preflight(&operation, payload, &latest_revisions)
                    .map_err(|_| ReplayError::Invalid)?;
            } else if kind == "MIGRATE" {
                let migration = payload.get("migration").ok_or(ReplayError::Invalid)?;
                let root = string(migration, "source_root")?;
                let source = migration
                    .get("source_checkpoint")
                    .ok_or(ReplayError::Invalid)?;
                let version = integer(payload, "v")?;
                if let Some(batch) = &migration_batch {
                    if batch.root() != root
                        || batch.format() != version
                        || !same_wire(batch.source(), source)?
                    {
                        return Err(ReplayError::Invalid);
                    }
                } else {
                    let sequence = integer(payload, "sequence")?;
                    if sequence == 1 {
                        if source != &WireValue::Null {
                            return Err(ReplayError::Invalid);
                        }
                    } else if prior_mode.as_deref() == Some("PUBLIC") && mode == "PRIVATE" {
                        let expected = fields_object(vec![
                            ("v", WireValue::Number(1.0)),
                            ("workspace_id", string_value(workspace_id)),
                            ("owner_id", string_value(&chain.owner_id)),
                            ("owner_key", string_value(&chain.owner_key)),
                            ("sequence", WireValue::Number((sequence - 1) as f64)),
                            (
                                "head",
                                payload.get("previous").ok_or(ReplayError::Invalid)?.clone(),
                            ),
                            (
                                "policy_hash",
                                string_value(
                                    previous_policy_hash
                                        .as_deref()
                                        .ok_or(ReplayError::Invalid)?,
                                ),
                            ),
                        ]);
                        if !same_wire(source, &expected)? {
                            return Err(ReplayError::Invalid);
                        }
                    } else {
                        return Err(ReplayError::Invalid);
                    }
                    migration_base = Some(prior_objects.clone());
                    migration_batch = Some(
                        MigrationBatch::new(root, source.clone(), version)
                            .map_err(|_| ReplayError::Invalid)?,
                    );
                }
                let source_items = payload
                    .get("migration")
                    .and_then(|migration| migration.get("source_items"))
                    .ok_or(ReplayError::Invalid)?;
                let WireValue::Array(items) = source_items else {
                    return Err(ReplayError::Invalid);
                };
                let WireValue::Array(objects) =
                    operation.get("objects").ok_or(ReplayError::Invalid)?
                else {
                    return Err(ReplayError::Invalid);
                };
                let descriptors = WireValue::Array(
                    objects
                        .iter()
                        .map(|object| {
                            fields_object(vec![
                                (
                                    "kind",
                                    object.get("kind").cloned().unwrap_or(WireValue::Null),
                                ),
                                ("id", object.get("id").cloned().unwrap_or(WireValue::Null)),
                                (
                                    "revision",
                                    object.get("revision").cloned().unwrap_or(WireValue::Null),
                                ),
                            ])
                        })
                        .collect(),
                );
                if canonical_wire_value(&descriptors, Path::SecureArtifact)
                    .map_err(|_| ReplayError::Invalid)?
                    != canonical_wire_value(&WireValue::Array(items.clone()), Path::SecureArtifact)
                        .map_err(|_| ReplayError::Invalid)?
                {
                    return Err(ReplayError::Invalid);
                }
                migration_batch
                    .as_mut()
                    .ok_or(ReplayError::Invalid)?
                    .add_page(items, objects)
                    .map_err(|_| ReplayError::Invalid)?;
            }
            let mut batch = HashSet::new();
            for (object_index, object) in objects.iter().enumerate() {
                check = "object.size";
                validate_replayed_object_size(object, object_index, object_source.as_ref())?;
                check = "object.shape";
                let object_kind = utf16(object, "kind")?;
                let id = utf16(object, "id")?;
                let revision = integer(object, "revision")?;
                let provenance = string(object, "provenance")?;
                if object_kind.is_empty()
                    || object_kind.len() > 80
                    || id.is_empty()
                    || id.len() > 512
                    || revision == 0
                    || object.get("value").is_none()
                    || !matches!(
                        provenance.as_str(),
                        "AUTHOR_SIGNED" | "LEGACY_OWNER_ATTESTED"
                    )
                    || provenance == "LEGACY_OWNER_ATTESTED" && kind != "MIGRATE"
                {
                    return Err(ReplayError::Invalid);
                }
                legacy |= provenance == "LEGACY_OWNER_ATTESTED";
                let object_key = WireValue::Array(vec![
                    WireValue::String(object_kind.to_vec()),
                    WireValue::String(id.to_vec()),
                    WireValue::Number(revision as f64),
                ]);
                let object_key = canonical_wire_value(&object_key, Path::SecureArtifact)
                    .map_err(|_| ReplayError::Invalid)?;
                if !batch.insert(object_key.clone()) || !seen_objects.insert(object_key) {
                    return Err(ReplayError::Invalid);
                }
                let pair_key = canonical_wire_value(
                    &WireValue::Array(vec![
                        WireValue::String(object_kind.to_vec()),
                        WireValue::String(id.to_vec()),
                    ]),
                    Path::SecureArtifact,
                )
                .map_err(|_| ReplayError::Invalid)?;
                staged_revisions
                    .entry(pair_key)
                    .and_modify(|prior| *prior = (*prior).max(revision))
                    .or_insert(revision);
                if kind != "MIGRATE"
                    && object_kind.iter().copied().eq("protocols".encode_utf16())
                    && !package_stage
                    && !object_stage
                {
                    check = "protocol.manifest";
                    let format_ceiling = if integer(payload, "v")? == 3 {
                        integer(payload, "protocol_format_ceiling")?
                    } else {
                        1
                    };
                    if object
                        .get("value")
                        .and_then(|value| value.get("package_source"))
                        .is_none()
                    {
                        validate_authored_protocol_simple(object, workspace_id, format_ceiling)?;
                    }
                }
            }
            // Ordinary ADMIN/DELTA updates can retain installed provenance.
            // A nonempty snapshot, a claimed BEGIN, or an install input must
            // still reprove the exact install even when other fields are malformed.
            let structure_mode = payload
                .get("structure")
                .and_then(|structure| structure.get("mode"))
                .and_then(WireValue::as_string);
            let install_input = operation
                .get("input")
                .and_then(|input| input.get("install"))
                .is_some();
            let begin_action = payload
                .get("action_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("secure.structure.begin");
            if kind == "ADMIN"
                && (install_input
                    || !objects.is_empty()
                        && (begin_action
                            || matches!(
                                structure_mode.as_deref(),
                                Some("SNAPSHOT_BEGIN" | "SNAPSHOT_PAGE" | "SNAPSHOT_END")
                            )))
            {
                check = "install.provenance";
                validate_signed_package_install(
                    &operation,
                    payload,
                    &prior_objects,
                    &operations,
                    &chain,
                    commit_wires,
                    workspace_id,
                    object_source.as_ref().map(|source| &source.proof),
                )?;
            }
            let policy_payload = policy.get("payload").ok_or(ReplayError::Invalid)?;
            let structured = integer(policy_payload, "v")? == 2
                || integer(policy_payload, "v")? == 3
                    && string(policy_payload, "structure_mode")? == "STRUCTURED";
            if structured {
                let contract = policy_payload
                    .get("structure")
                    .ok_or(ReplayError::Invalid)?;
                let mut candidate = prior_objects.clone();
                candidate.extend(objects.iter().cloned());
                check = "structure.object_bindings";
                crate::structure_bindings::validate_object_bindings(contract, &candidate)
                    .map_err(|_| ReplayError::Invalid)?;
            }
            for (key, revision) in staged_revisions {
                latest_revisions
                    .entry(key)
                    .and_modify(|prior| *prior = (*prior).max(revision))
                    .or_insert(revision);
            }
            check = "roles.policy";
            prior_objects.extend(objects.iter().cloned());
            let hash = string(payload, "policy_hash")?;
            let policy = policies.get(hash.as_str()).ok_or(ReplayError::Invalid)?;
            let instance = if kind == "ACTION" {
                payload.get("instance_id").and_then(WireValue::as_utf16)
            } else {
                None
            };
            // The TS replay validates roles only after finishMigration has
            // inflated and authenticated the complete migration batch. A prefix
            // can contain only part of an instance/protocol/grant history.
            if kind != "MIGRATE" {
                validate_role_policies_with_history(
                    policy.get("payload").ok_or(ReplayError::Invalid)?,
                    &prior_objects,
                    integer(payload, "issued_at")?,
                    instance,
                    &mut role_history,
                )
                .map_err(|_| ReplayError::Invalid)?;
            }
            if kind == "ACTION" {
                // The signed device is the receipt actor. The authenticated
                // delegation principal is the actor in writer-produced record
                // effects, as also required by structured DELTA application.
                let effect_actor = match payload.get("delegation") {
                    Some(WireValue::Null) => payload.get("actor_id"),
                    Some(delegation) => delegation
                        .get("payload")
                        .and_then(|grant| grant.get("actor_id")),
                    None => None,
                }
                .ok_or(ReplayError::Invalid)?;
                let mut effects = Vec::new();
                for object in objects {
                    if string(object, "kind")? != "records" {
                        continue;
                    }
                    let value = object.get("value").ok_or(ReplayError::Invalid)?;
                    if value.get("id") != object.get("id")
                        || !integer(value, "revision").is_ok_and(|revision| revision >= 1)
                        || value
                            .get("schema_ref")
                            .and_then(WireValue::as_utf16)
                            .is_none()
                        || value.get("actor_id") != Some(effect_actor)
                        || value.get("instance_id") != payload.get("instance_id")
                    {
                        return Err(ReplayError::Invalid);
                    }
                    effects.push(fields_object(vec![
                        (
                            "record_id",
                            object.get("id").ok_or(ReplayError::Invalid)?.clone(),
                        ),
                        (
                            "revision",
                            value.get("revision").ok_or(ReplayError::Invalid)?.clone(),
                        ),
                        (
                            "schema_ref",
                            value.get("schema_ref").ok_or(ReplayError::Invalid)?.clone(),
                        ),
                        (
                            "entity_id",
                            value
                                .get("entity_id")
                                .filter(|v| v.as_utf16().is_some())
                                .cloned()
                                .unwrap_or(WireValue::Null),
                        ),
                    ]));
                }
                let hash = chain
                    .commit_hashes
                    .get(usize::try_from(sequence - 1).map_err(|_| ReplayError::Invalid)?)
                    .ok_or(ReplayError::Invalid)?;
                action_receipts.push(fields_object(vec![
                    (
                        "command_id",
                        payload
                            .get("command_id")
                            .ok_or(ReplayError::Invalid)?
                            .clone(),
                    ),
                    ("commit_hash", string_value(hash)),
                    ("sequence", WireValue::Number(sequence as f64)),
                    (
                        "actor_id",
                        payload.get("actor_id").ok_or(ReplayError::Invalid)?.clone(),
                    ),
                    (
                        "instance_id",
                        payload
                            .get("instance_id")
                            .ok_or(ReplayError::Invalid)?
                            .clone(),
                    ),
                    (
                        "action_id",
                        payload
                            .get("action_id")
                            .ok_or(ReplayError::Invalid)?
                            .clone(),
                    ),
                    ("effects", WireValue::Array(effects)),
                ]));
            }
            operations.push(signed_operation);
            previous_policy_hash = Some(policy_hash);
            prior_mode = Some(mode);
            Ok(())
        })();
        step.map_err(|error| match error {
            ReplayError::Chain(_) | ReplayError::Content { .. } | ReplayError::ResourceLimit => error,
            ReplayError::Invalid => ReplayError::Content { sequence, check },
        })?;
    }
    if let Some(batch) = migration_batch {
        let format = batch.format();
        let candidate = batch
            .finish(migration_base.as_deref().ok_or(ReplayError::Invalid)?)
            .map_err(|_| ReplayError::Invalid)?;
        if format == 3 {
            assert_protocol_format_ceiling(&candidate, 1).map_err(|_| ReplayError::Invalid)?;
        }
        validate_historical_authored_protocols(&candidate, workspace_id, format)?;
        validate_legacy_protocol_bindings(&candidate, workspace_id)
            .map_err(|_| ReplayError::Invalid)?;
        seen_objects = index_candidate_objects(&candidate)?.0;
        legacy |= candidate.iter().any(|object| {
            object
                .get("provenance")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("LEGACY_OWNER_ATTESTED")
        });
        prior_objects = candidate;
    }
    if depth == 0 && guard_times.is_some_and(|proofs| proofs.len() != verified_guard_proofs.len()) {
        return Err(ReplayError::Invalid);
    }
    let final_policy = policies
        .get(chain.policy_hash.as_str())
        .ok_or(ReplayError::Invalid)?;
    validate_role_policies_with_history(
        final_policy.get("payload").ok_or(ReplayError::Invalid)?,
        &prior_objects,
        integer(
            final_policy.get("payload").ok_or(ReplayError::Invalid)?,
            "issued_at",
        )?,
        None,
        &mut role_history,
    )
    .map_err(|_| ReplayError::Invalid)?;
    let final_payload = final_policy.get("payload").ok_or(ReplayError::Invalid)?;
    let structured = integer(final_payload, "v")? == 2
        || integer(final_payload, "v")? == 3
            && string(final_payload, "structure_mode")? == "STRUCTURED";
    Ok(ReplayFacts {
        chain,
        operations,
        objects: prior_objects,
        object_count: seen_objects.len(),
        legacy,
        recoveries,
        action_receipts,
        structure_state: if structured {
            Some(if structure_progress.is_some() {
                "SEEDING"
            } else {
                "ACTIVE"
            })
        } else {
            None
        },
        structure_snapshot: structure_progress.as_ref().map(|snapshot| {
            fields_object(vec![
                ("source", snapshot.source.clone()),
                ("root", string_value(&snapshot.root)),
                ("records", WireValue::Number(snapshot.record_count as f64)),
                ("heads", WireValue::Number(snapshot.head_count as f64)),
                ("offset", WireValue::Number(snapshot.offset as f64)),
            ])
        }),
    })
}

/// Private authored protocol identity and composition binding. Package-source
/// compilation and migrated legacy rows need separate proofs before release.
fn validate_authored_protocol_simple(
    object: &WireValue,
    workspace_id: &str,
    format_ceiling: u64,
) -> Result<(), ReplayError> {
    validate_authored_protocol_in_history(object, workspace_id, format_ceiling, &[])
}

fn validate_authored_protocol_in_history(
    object: &WireValue,
    workspace_id: &str,
    format_ceiling: u64,
    history: &[WireValue],
) -> Result<(), ReplayError> {
    if string(object, "provenance")? != "AUTHOR_SIGNED" || integer(object, "revision")? != 1 {
        return Err(ReplayError::Invalid);
    }
    let id = string(object, "id")?;
    let value = object.get("value").ok_or(ReplayError::Invalid)?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        || string(value, "digest")? != id
        || string(value, "workspace_id")? != workspace_id
    {
        return Err(ReplayError::Invalid);
    }
    let source = decoded_value(value.get("manifest").ok_or(ReplayError::Invalid)?)
        .map_err(|_| ReplayError::Invalid)?;
    let resolved = decoded_value(value.get("resolved_manifest").ok_or(ReplayError::Invalid)?)
        .map_err(|_| ReplayError::Invalid)?;
    let checked_source =
        crate::full_manifest::validate_full_manifest(&source).map_err(|_| ReplayError::Invalid)?;
    let checked_resolved = crate::full_manifest::validate_full_manifest(&resolved)
        .map_err(|_| ReplayError::Invalid)?;
    let format_two =
        source.get("format_version").is_some() || resolved.get("format_version").is_some();
    if format_two && format_ceiling != 2 {
        return Err(ReplayError::Invalid);
    }
    if format_two {
        // Format two's signed value must already be schema-normalized.
        for (raw, normalized) in [(&source, &checked_source), (&resolved, &checked_resolved)] {
            let wrapped = parse_wire_json_js_bounded(normalized.as_bytes(), 32, 65_536)
                .map_err(|_| ReplayError::Invalid)?;
            let parsed = wrapped.get("manifest").ok_or(ReplayError::Invalid)?;
            if canonical_wire_value(raw, Path::SecureArtifact).map_err(|_| ReplayError::Invalid)?
                != canonical_wire_value(parsed, Path::SecureArtifact)
                    .map_err(|_| ReplayError::Invalid)?
            {
                return Err(ReplayError::Invalid);
            }
        }
    }
    let source_envelope = fields_object(vec![
        ("semantics", string_value("peerwork.kernel.v1")),
        ("manifest", source.clone()),
    ]);
    let digest = sha256_hex(
        canonical_wire_value(&source_envelope, Path::SecureArtifact)
            .map_err(|_| ReplayError::Invalid)?
            .as_bytes(),
    );
    if digest != id {
        return Err(ReplayError::Invalid);
    }
    if let Some(proof) = value.get("package_source") {
        if value.get("composition").is_some() {
            return Err(ReplayError::Invalid);
        }
        let material =
            verify_protocol_package_source(proof, history).map_err(|_| ReplayError::Invalid)?;
        if material.protocol_digest != id
            || !same_wire(&material.manifest, &source)?
            || !same_wire(&source, &resolved)?
        {
            return Err(ReplayError::Invalid);
        }
    } else if let Some(proof) = value.get("composition") {
        crate::protocol_composition::verify_composition(
            proof,
            &source,
            &resolved,
            &id,
            format_ceiling,
        )
        .map_err(|_| ReplayError::Invalid)?;
    } else if source.get("dependencies") != Some(&WireValue::Array(vec![]))
        || source
            .get("constraints")
            .is_some_and(|value| value.object_len() != Some(0))
        || canonical_wire_value(&source, Path::SecureArtifact).map_err(|_| ReplayError::Invalid)?
            != canonical_wire_value(&resolved, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?
    {
        return Err(ReplayError::Invalid);
    }
    Ok(())
}

fn validate_historical_authored_protocols(
    candidate: &[WireValue],
    workspace_id: &str,
    format: u64,
) -> Result<(), ReplayError> {
    let ceiling = if format == 3 { 1 } else { format };
    let mut latest = HashMap::<Vec<u16>, &WireValue>::new();
    for object in candidate {
        if object.get("kind").and_then(WireValue::as_utf16)
            != Some(&"protocols".encode_utf16().collect::<Vec<_>>()[..])
        {
            continue;
        }
        let id = utf16(object, "id")?.to_vec();
        let revision = integer(object, "revision")?;
        if latest
            .get(&id)
            .is_none_or(|prior| integer(prior, "revision").is_ok_and(|old| old < revision))
        {
            latest.insert(id, object);
        }
    }
    for object in latest.values() {
        if string(object, "provenance")? == "AUTHOR_SIGNED" {
            validate_authored_protocol_in_history(object, workspace_id, ceiling, candidate)?;
        }
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
enum AdminPreflightError {
    #[error("ADMIN_CONTENT_KIND_DENIED")]
    Kind,
    #[error("INVALID_PROTOCOL_TRANSITION")]
    Value,
    #[error("OBJECT_WORKSPACE_MISMATCH")]
    Workspace,
    #[error("OBJECT_REVISION_INVALID")]
    Revision,
}

impl AdminPreflightError {
    fn check(&self) -> &'static str {
        match self {
            Self::Kind => "admin.kind",
            Self::Value => "admin.value",
            Self::Workspace => "admin.workspace",
            Self::Revision => "admin.revision",
        }
    }
}

/// Source-matched generic ADMIN preflight. Protocol object manifest, role,
/// structure, and workflow checks are deliberately handled by later layers.
fn validate_admin_preflight(
    operation: &WireValue,
    context: &WireValue,
    prior: &HashMap<String, u64>,
) -> Result<(), AdminPreflightError> {
    let workspace = context
        .get("workspace_id")
        .and_then(WireValue::as_utf16)
        .ok_or(AdminPreflightError::Value)?;
    let objects = operation.get("objects").ok_or(AdminPreflightError::Value)?;
    let WireValue::Array(objects) = objects else {
        return Err(AdminPreflightError::Value);
    };
    for object in objects {
        let kind = object
            .get("kind")
            .and_then(WireValue::as_string)
            .ok_or(AdminPreflightError::Kind)?;
        if !matches!(
            kind.as_str(),
            "workspaces"
                | "protocols"
                | "instances"
                | "workspace_config"
                | "entrypoints"
                | "protocol_status"
                | "protocol_drafts"
                | "protocol_draft_revisions"
                | "protocol_validations"
                | "instance_links"
        ) {
            return Err(AdminPreflightError::Kind);
        }
        let value = object.get("value").ok_or(AdminPreflightError::Value)?;
        if !matches!(value, WireValue::Object(_)) {
            return Err(AdminPreflightError::Value);
        }
        if value
            .get("workspace_id")
            .is_some_and(|id| id.as_utf16() != Some(workspace))
        {
            return Err(AdminPreflightError::Workspace);
        }
        let id = object
            .get("id")
            .and_then(WireValue::as_utf16)
            .ok_or(AdminPreflightError::Value)?;
        if kind == "workspaces"
            && (id != workspace || value.get("id").and_then(WireValue::as_utf16) != Some(workspace))
        {
            return Err(AdminPreflightError::Workspace);
        }
        let revision = integer(object, "revision").map_err(|_| AdminPreflightError::Revision)?;
        let pair = canonical_wire_value(
            &WireValue::Array(vec![
                WireValue::String(kind.encode_utf16().collect()),
                WireValue::String(id.to_vec()),
            ]),
            Path::SecureArtifact,
        )
        .map_err(|_| AdminPreflightError::Value)?;
        if revision != prior.get(&pair).copied().unwrap_or(0) + 1 {
            return Err(AdminPreflightError::Revision);
        }
        if kind == "protocols" {
            let raw = value
                .get("resolved_manifest")
                .or_else(|| value.get("manifest"))
                .ok_or(AdminPreflightError::Value)?;
            let manifest = decoded_value(raw).map_err(|_| AdminPreflightError::Value)?;
            let actions = manifest.get("actions").ok_or(AdminPreflightError::Value)?;
            crate::interpreter::validate_manifest(&fields_object(vec![(
                "actions",
                actions.clone(),
            )]))
            .map_err(|_| AdminPreflightError::Value)?;
        }
    }
    Ok(())
}

/// Private ACTION evaluator covering state, record, head, relation, protected
/// field, and workflow effects. Other histories still return `UNSUPPORTED`;
/// this never yields a verified journal or receipt.
pub(crate) fn validate_action_state_slice(
    operation: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior: &[WireValue],
) -> Result<(), &'static str> {
    validate_action_state_slice_at_time(operation, context, policy, prior, None)
}

fn validate_action_state_slice_at_time(
    operation: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior: &[WireValue],
    execution_time_ms: Option<u64>,
) -> Result<(), &'static str> {
    if !exact_fields(operation, &["v", "kind", "input", "objects"]) {
        return Err("PROTOCOL_OUTPUT_MISMATCH");
    }
    let input = operation.get("input").ok_or("ACTION_CONTEXT_MISMATCH")?;
    let mut context = context.clone();
    let expected = compute_action_objects_inner(
        &mut input.clone(),
        &mut context,
        policy,
        prior,
        None,
        execution_time_ms,
    )?;
    let actual = operation.get("objects").ok_or("PROTOCOL_OUTPUT_MISMATCH")?;
    if canonical_wire_value(&expected, Path::SecureArtifact)
        .map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?
        != canonical_wire_value(actual, Path::SecureArtifact)
            .map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?
    {
        return Err("PROTOCOL_OUTPUT_MISMATCH");
    }
    Ok(())
}

pub(crate) fn compute_action_objects(
    input: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior: &[WireValue],
) -> Result<WireValue, &'static str> {
    let mut context = context.clone();
    compute_action_objects_inner(&mut input.clone(), &mut context, policy, prior, None, None)
}

pub(crate) fn compute_action_objects_with_default_allocations(
    input: &mut WireValue,
    context: &mut WireValue,
    policy: &WireValue,
    prior: &[WireValue],
    candidates: &[WireValue],
) -> Result<WireValue, &'static str> {
    compute_action_objects_inner(input, context, policy, prior, Some(candidates), None)
}

/// Fixture-only adapter: simulated time is not admission evidence. Production
/// preparation continues to use its existing entry points above.
pub(crate) fn simulate_action_objects(
    input: &mut WireValue,
    context: &mut WireValue,
    policy: &WireValue,
    prior: &[WireValue],
    candidates: &[WireValue],
    time_ms: u64,
) -> Result<WireValue, &'static str> {
    compute_action_objects_inner(input, context, policy, prior, Some(candidates), Some(time_ms))
}

fn compute_action_objects_inner(
    input: &mut WireValue,
    context: &mut WireValue,
    policy: &WireValue,
    prior: &[WireValue],
    default_allocations: Option<&[WireValue]>,
    execution_time_override: Option<u64>,
) -> Result<WireValue, &'static str> {
    if !exact_fields(
        input,
        &[
            "instance_id",
            "expected_instance_revision",
            "action_id",
            "body",
            "exact_input_refs",
            "allocations",
        ],
    ) {
        return Err("PROTOCOL_OUTPUT_MISMATCH");
    }
    let action_id = context
        .get("action_id")
        .and_then(WireValue::as_utf16)
        .ok_or("ACTION_CONTEXT_MISMATCH")?
        .to_vec();
    let instance_id = context
        .get("instance_id")
        .and_then(WireValue::as_utf16)
        .ok_or("ACTION_CONTEXT_MISMATCH")?
        .to_vec();
    if input.get("action_id").and_then(WireValue::as_utf16) != Some(action_id.as_slice())
        || input.get("instance_id").and_then(WireValue::as_utf16) != Some(instance_id.as_slice())
    {
        return Err("ACTION_CONTEXT_MISMATCH");
    }
    let refs_wire = input.get("exact_input_refs").ok_or("REFERENCE_INVALID")?;
    let instance = prior
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && object.get("id").and_then(WireValue::as_utf16) == Some(instance_id.as_slice())
        })
        .max_by_key(|object| integer(object, "revision").unwrap_or(0))
        .ok_or("INSTANCE_NOT_FOUND")?;
    let instance_value = instance.get("value").ok_or("INSTANCE_NOT_FOUND")?;
    if instance_value.get("id").and_then(WireValue::as_utf16) != Some(instance_id.as_slice())
        || instance_value.get("workspace_id") != context.get("workspace_id")
    {
        return Err("INSTANCE_SCOPE_MISMATCH");
    }
    let old_revision = integer(instance_value, "revision").map_err(|_| "STALE_REVISION")?;
    if integer(input, "expected_instance_revision").map_err(|_| "STALE_REVISION")? != old_revision {
        return Err("STALE_REVISION");
    }
    let digest = instance_value
        .get("protocol_digest")
        .and_then(WireValue::as_utf16)
        .ok_or("PROTOCOL_NOT_FOUND")?;
    if let Some(status) = prior
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocol_status")
                && object
                    .get("value")
                    .and_then(|value| value.get("digest"))
                    .and_then(WireValue::as_utf16)
                    == Some(digest)
        })
        .max_by_key(|object| integer(object, "revision").unwrap_or(0))
    {
        if status
            .get("value")
            .and_then(|value| value.get("state"))
            .and_then(WireValue::as_string)
            .as_deref()
            != Some("ACTIVE")
        {
            return Err("PROTOCOL_SUSPENDED");
        }
    }
    let protocol = prior
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
                && object
                    .get("value")
                    .and_then(|value| value.get("digest"))
                    .and_then(WireValue::as_utf16)
                    == Some(digest)
        })
        .max_by_key(|object| integer(object, "revision").unwrap_or(0))
        .ok_or("PROTOCOL_NOT_FOUND")?;
    let manifest_raw = protocol
        .get("value")
        .and_then(|value| {
            value
                .get("resolved_manifest")
                .or_else(|| value.get("manifest"))
        })
        .ok_or("PROTOCOL_NOT_FOUND")?;
    let manifest = decoded_value(manifest_raw).map_err(|_| "INVALID_PAYLOAD")?;
    let exact_inputs = crate::secure_action_inputs::resolve_exact_inputs(
        refs_wire,
        prior,
        context
            .get("workspace_id")
            .ok_or("REFERENCE_SCOPE_MISMATCH")?,
        context
            .get("instance_id")
            .ok_or("REFERENCE_SCOPE_MISMATCH")?,
        instance_value
            .get("protocol_digest")
            .ok_or("REFERENCE_SCOPE_MISMATCH")?,
    )?;
    let policy_payload = policy.get("payload").ok_or("AUTHOR_NOT_MEMBER")?;
    let delegation_wire = match context.get("delegation") {
        Some(WireValue::Null) => None,
        Some(delegation) => Some(
            canonical_wire_value(delegation, Path::SecureArtifact)
                .map_err(|_| "AUTHOR_SCOPE_DENIED")?,
        ),
        None => return Err("AUTHOR_SCOPE_DENIED"),
    };
    let checked = crate::secure_action_delegation::resolve_action_scope(
        context,
        policy_payload,
        delegation_wire.as_deref().map(str::as_bytes),
    )
    .map_err(|error| error.code())?;
    if !checked.permits_action() {
        return Err("AUTHOR_SCOPE_DENIED");
    }
    let actor = checked.actor_id.encode_utf16().collect::<Vec<_>>();
    let issued = integer(context, "issued_at").map_err(|_| "AUTHOR_SCOPE_DENIED")?;
    let applicable: Vec<_> = checked
        .scopes
        .iter()
        .filter(|scope| {
            (matches!(scope.get("instance_id"), Some(WireValue::Null))
                || scope.get("instance_id").and_then(WireValue::as_utf16) == Some(instance_id.as_slice()))
                && scope.get("expires_at").map_or(true, |at| {
                    matches!(at, WireValue::Null)
                        || at.as_number().is_some_and(|at| at > issued as f64)
                })
        })
        .collect();
    validate_role_policies(policy_payload, prior, issued, &instance_id)?;
    let mut roles = applicable
        .iter()
        .flat_map(|scope| {
            scope
                .get("protocol_roles")
                .and_then(|value| {
                    if let WireValue::Array(items) = value {
                        Some(items)
                    } else {
                        None
                    }
                })
                .into_iter()
                .flatten()
        })
        .filter_map(WireValue::as_utf16)
        .map(|value| value.to_vec())
        .collect::<Vec<_>>();
    let mut capabilities = applicable
        .iter()
        .flat_map(|scope| {
            scope
                .get("capabilities")
                .and_then(|value| {
                    if let WireValue::Array(items) = value {
                        Some(items)
                    } else {
                        None
                    }
                })
                .into_iter()
                .flatten()
        })
        .filter_map(WireValue::as_utf16)
        .map(|value| value.to_vec())
        .collect::<Vec<_>>();
    let mut role_seen = HashSet::new();
    roles.retain(|role| role_seen.insert(role.clone()));
    let mut capability_seen = HashSet::new();
    capabilities.retain(|capability| capability_seen.insert(capability.clone()));
    let auth = InterpreterAuth {
        actor_id: checked.actor_id.clone(),
        workspace_roles: vec![checked.role.encode_utf16().collect()],
        protocol_roles: roles,
        capabilities,
    };
    let source_state = decoded_value(instance_value.get("state").ok_or("INVALID_PAYLOAD")?)
        .map_err(|_| "INVALID_PAYLOAD")?;
    crate::full_manifest::validate_state_array_state(&manifest, &source_state)
        .map_err(|_| "STATE_ARRAY_TYPE_INVALID")?;
    let eval_manifest = WireValue::Object(vec![(
        "actions".encode_utf16().collect(),
        manifest.get("actions").ok_or("INVALID_PAYLOAD")?.clone(),
    )]);
    let execution_time_ms = if let Some(guard_policy_wire) = policy_payload.get("guard_time") {
        let _guard_policy = crate::guard_time::parse_guard_time_policy(guard_policy_wire)
            .map_err(|_| "GUARD_TIME_POLICY_INVALID")?;
        let window = crate::guard_time::derive_private_guard_time_window(
            &eval_manifest,
            &action_id,
            &source_state,
            input.get("body").ok_or("INVALID_PAYLOAD")?,
            &auth,
            &exact_inputs,
        )
        .map_err(|error| match error {
            crate::guard_time::GuardTimeError::Unsupported => "PRIVATE_GUARD_TIME_UNSUPPORTED",
            crate::guard_time::GuardTimeError::Empty => "CONSTRAINT_FAILED",
            crate::guard_time::GuardTimeError::Invalid => "INVALID_PAYLOAD",
        })?;
        if let Some(supplied) = context.get("guard_time") {
            let supplied = crate::guard_time::parse_guard_time_context(supplied)
                .map_err(|_| "GUARD_TIME_CONTEXT_INVALID")?;
            if supplied != window {
                return Err("GUARD_TIME_CONTEXT_INVALID");
            }
        } else {
            replace_field(context, "guard_time", window.to_wire()).map_err(|_| "INVALID_PAYLOAD")?;
        }
        Some(execution_time_override.unwrap_or(window.lower_ms))
    } else {
        if context.get("guard_time").is_some() {
            return Err("GUARD_TIME_CONTEXT_INVALID");
        }
        None
    };
    let interpreted = evaluate_action(
        &eval_manifest,
        &action_id,
        &source_state,
        input.get("body").ok_or("INVALID_PAYLOAD")?,
        &auth,
        &exact_inputs,
        execution_time_ms,
    )
    .map_err(|_| "INVALID_PAYLOAD")?;
    // The generic interpreter can reproduce the signed effect contract, but
    // native secure replay does not yet implement the publication lifecycle.
    // Never accept a commit while silently dropping this effect.
    ensure_secure_effects_supported(&interpreted)?;
    if matches!(input.get("allocations"), Some(WireValue::Null)) {
        let candidates = default_allocations.ok_or("ALLOCATION_INVALID")?;
        let count = interpreted.records.len();
        if count > candidates.len() {
            return Err("ALLOCATION_INVALID");
        }
        replace_field(
            input,
            "allocations",
            WireValue::Array(candidates[..count].to_vec()),
        )
        .map_err(|_| "ALLOCATION_INVALID")?;
    }
    let allocations = match input.get("allocations") {
        Some(WireValue::Array(values)) => values,
        _ => return Err("ACTION_CONTEXT_MISMATCH"),
    };
    let crate::secure_action_allocations::AllocationPlan {
        assigned,
        record_slots,
        entity_slots,
        assigned_records,
    } = crate::secure_action_allocations::resolve_record_allocations(
        &interpreted.records,
        allocations,
        prior,
        &exact_inputs,
        context,
        context.get("instance_id").ok_or("INVALID_PAYLOAD")?,
        instance_value
            .get("protocol_digest")
            .ok_or("INVALID_PAYLOAD")?,
    )?;
    let mut expected_objects = Vec::new();
    let mut head_changes = Vec::new();
    let mut head_ids = HashSet::new();
    let mut pending_relations = Vec::<crate::secure_action_relations::PendingRelation>::new();
    for assigned_record in &assigned {
        let record = &assigned_record.record;
        let entity = record.get("entity");
        let record_id = &assigned_record.id;
        let assigned_entity = assigned_record.entity_id.clone();
        let assigned_revision = assigned_record.revision;
        let schema = record
            .get("schema")
            .and_then(WireValue::as_utf16)
            .ok_or("RECORD_SCHEMA_INVALID")?;
        let schema_key = String::from_utf16(schema).map_err(|_| "RECORD_SCHEMA_INVALID")?;
        let _definition = manifest
            .get("record_schemas")
            .and_then(|schemas| schemas.get(&schema_key))
            .ok_or("RECORD_SCHEMA_INVALID")?;
        let payload = record.get("payload").ok_or("RECORD_SCHEMA_INVALID")?;
        let value = fields_object(vec![
            ("id", WireValue::String(record_id.to_vec())),
            (
                "workspace_id",
                context
                    .get("workspace_id")
                    .ok_or("PROTOCOL_OUTPUT_MISMATCH")?
                    .clone(),
            ),
            ("instance_id", WireValue::String(instance_id.to_vec())),
            ("protocol_digest", WireValue::String(digest.to_vec())),
            ("entity_id", WireValue::String(assigned_entity.clone())),
            ("schema_ref", WireValue::String(schema.to_vec())),
            ("payload", payload.clone()),
            ("actor_id", WireValue::String(actor.to_vec())),
            ("revision", WireValue::Number(assigned_revision as f64)),
            ("created", WireValue::Number(issued as f64)),
        ]);
        expected_objects.push(fields_object(vec![
            ("kind", string_value("records")),
            ("id", WireValue::String(record_id.to_vec())),
            ("revision", WireValue::Number(1.0)),
            ("value", value),
            ("provenance", string_value("AUTHOR_SIGNED")),
        ]));
        let Some(WireValue::Array(relations)) = record.get("relations") else {
            return Err("UNSUPPORTED");
        };
        for relation in relations {
            pending_relations.push(crate::secure_action_relations::PendingRelation {
                position: expected_objects.len(),
                source_id: record_id.to_vec(),
                relation: relation.clone(),
            });
            expected_objects.push(WireValue::Null);
        }
        if entity.is_some()
            && record
                .get("selectHead")
                .is_some_and(|value| matches!(value, WireValue::Bool(true)))
        {
            if !head_ids.insert(assigned_entity.clone()) {
                return Err("HEAD_CONFLICT");
            }
            let head_value = fields_object(vec![
                ("entity_id", WireValue::String(assigned_entity.clone())),
                (
                    "workspace_id",
                    context
                        .get("workspace_id")
                        .ok_or("PROTOCOL_OUTPUT_MISMATCH")?
                        .clone(),
                ),
                ("instance_id", WireValue::String(instance_id.to_vec())),
                ("record_id", WireValue::String(record_id.to_vec())),
                ("revision", WireValue::Number(assigned_revision as f64)),
                ("updated", WireValue::Number(issued as f64)),
            ]);
            let head_revision = safe_add(
                prior
                    .iter()
                    .filter(|object| {
                        object.get("kind").and_then(WireValue::as_string).as_deref()
                            == Some("entity_heads")
                            && object.get("id").and_then(WireValue::as_utf16)
                                == head_value.get("entity_id").and_then(WireValue::as_utf16)
                    })
                    .filter_map(|object| integer(object, "revision").ok())
                    .max()
                    .unwrap_or(0),
                1,
            )?;
            head_changes.push(fields_object(vec![
                ("kind", string_value("entity_heads")),
                ("id", WireValue::String(assigned_entity)),
                ("revision", WireValue::Number(head_revision as f64)),
                ("value", head_value),
                ("provenance", string_value("AUTHOR_SIGNED")),
            ]));
        }
    }
    for object in &mut expected_objects {
        if object.get("kind").and_then(WireValue::as_string).as_deref() != Some("records") {
            continue;
        }
        let row = object.get("value").ok_or("RECORD_SCHEMA_INVALID")?;
        let schema = row
            .get("schema_ref")
            .and_then(WireValue::as_string)
            .ok_or("RECORD_SCHEMA_INVALID")?;
        let definition = manifest
            .get("record_schemas")
            .and_then(|schemas| schemas.get(&schema))
            .ok_or("RECORD_SCHEMA_INVALID")?;
        let payload = substitute_produced(
            row.get("payload").ok_or("RECORD_SCHEMA_INVALID")?,
            &record_slots,
            &entity_slots,
            0,
        )?;
        validate_simple_record_schema(&payload, definition)?;
        let mut value = row.clone();
        replace_field(&mut value, "payload", payload).map_err(|_| "RECORD_SCHEMA_INVALID")?;
        replace_field(object, "value", value).map_err(|_| "RECORD_SCHEMA_INVALID")?;
    }
    for (position, relation) in crate::secure_action_relations::resolve_relation_objects(
        &pending_relations,
        prior,
        &assigned_records,
        &record_slots,
        &entity_slots,
    )? {
        expected_objects[position] = relation;
    }
    for selection in &interpreted.head_selections {
        let expected = selection.get("expected").ok_or("HEAD_SELECTION_INVALID")?;
        let target = selection.get("target").ok_or("HEAD_SELECTION_INVALID")?;
        let expected_id = expected
            .get("recordId")
            .and_then(WireValue::as_utf16)
            .ok_or("HEAD_SELECTION_INVALID")?;
        let target_id = target
            .get("recordId")
            .and_then(WireValue::as_utf16)
            .ok_or("HEAD_SELECTION_INVALID")?;
        let expected_revision =
            integer(expected, "revision").map_err(|_| "HEAD_SELECTION_INVALID")?;
        let target_revision = integer(target, "revision").map_err(|_| "HEAD_SELECTION_INVALID")?;
        let find_record = |id: &[u16], revision: u64| {
            prior.iter().find(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                    && object.get("id").and_then(WireValue::as_utf16) == Some(id)
                    && object
                        .get("value")
                        .and_then(|value| integer(value, "revision").ok())
                        == Some(revision)
            })
        };
        let old = find_record(expected_id, expected_revision).ok_or("HEAD_SELECTION_INVALID")?;
        let next = find_record(target_id, target_revision).ok_or("HEAD_SELECTION_INVALID")?;
        let entity = old
            .get("value")
            .and_then(|value| value.get("entity_id"))
            .and_then(WireValue::as_utf16)
            .ok_or("HEAD_SELECTION_INVALID")?;
        if next
            .get("value")
            .and_then(|value| value.get("entity_id"))
            .and_then(WireValue::as_utf16)
            != Some(entity)
        {
            return Err("HEAD_SELECTION_INVALID");
        }
        let head = prior
            .iter()
            .filter(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref() == Some("entity_heads")
                    && object.get("id").and_then(WireValue::as_utf16) == Some(entity)
            })
            .max_by_key(|object| integer(object, "revision").unwrap_or(0))
            .ok_or("STALE_REVISION")?;
        let head_value = head.get("value").ok_or("STALE_REVISION")?;
        if head_value.get("record_id").and_then(WireValue::as_utf16) != Some(expected_id)
            || integer(head_value, "revision").map_err(|_| "STALE_REVISION")? != expected_revision
            || !head_ids.insert(entity.to_vec())
        {
            return Err("STALE_REVISION");
        }
        let mut head_value = head_value.clone();
        replace_field(
            &mut head_value,
            "record_id",
            WireValue::String(target_id.to_vec()),
        )
        .map_err(|_| "HEAD_SELECTION_INVALID")?;
        replace_field(
            &mut head_value,
            "revision",
            WireValue::Number(target_revision as f64),
        )
        .map_err(|_| "HEAD_SELECTION_INVALID")?;
        replace_field(&mut head_value, "updated", WireValue::Number(issued as f64))
            .map_err(|_| "HEAD_SELECTION_INVALID")?;
        head_changes.push(fields_object(vec![
            ("kind", string_value("entity_heads")),
            ("id", WireValue::String(entity.to_vec())),
            (
                "revision",
                WireValue::Number(safe_add(
                    integer(head, "revision").map_err(|_| "STALE_REVISION")?,
                    1,
                )? as f64),
            ),
            ("value", head_value),
            ("provenance", string_value("AUTHOR_SIGNED")),
        ]));
    }
    expected_objects.extend(head_changes);
    validate_action_workflows(
        &manifest,
        &instance_id,
        digest,
        &action_id,
        prior,
        &expected_objects,
        policy,
    )?;
    let mut next = instance_value.clone();
    let next_state = substitute_produced(&interpreted.next_state, &record_slots, &entity_slots, 0)?;
    crate::full_manifest::validate_state_array_state(&manifest, &next_state)
        .map_err(|_| "STATE_ARRAY_TYPE_INVALID")?;
    replace_field(&mut next, "state", next_state).map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?;
    replace_field(
        &mut next,
        "revision",
        WireValue::Number(safe_add(old_revision, u64::from(interpreted.control_revision))? as f64),
    )
    .map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?;
    replace_field(
        &mut next,
        "event_revision",
        WireValue::Number(
            safe_add(integer(instance_value, "event_revision").unwrap_or(0), 1)? as f64,
        ),
    )
    .map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?;
    expected_objects.push(WireValue::Object(vec![
        (
            "kind".encode_utf16().collect(),
            WireValue::String("instances".encode_utf16().collect()),
        ),
        (
            "id".encode_utf16().collect(),
            WireValue::String(instance_id.to_vec()),
        ),
        (
            "revision".encode_utf16().collect(),
            WireValue::Number(safe_add(
                integer(instance, "revision").map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?,
                1,
            )? as f64),
        ),
        ("value".encode_utf16().collect(), next),
        (
            "provenance".encode_utf16().collect(),
            WireValue::String("AUTHOR_SIGNED".encode_utf16().collect()),
        ),
    ]));
    Ok(WireValue::Array(expected_objects))
}
#[derive(Clone)]
struct WorkflowValues {
    status: String,
    parent: Option<(String, u64)>,
    assignee: Option<String>,
    dependencies: Vec<(String, u64)>,
}

fn wire_array(value: &WireValue) -> Option<&[WireValue]> {
    if let WireValue::Array(items) = value {
        Some(items)
    } else {
        None
    }
}

fn workflow_reference(value: &WireValue) -> Result<(String, u64), &'static str> {
    let WireValue::Object(fields) = value else {
        return Err("WORKFLOW_REFERENCE_INVALID");
    };
    let id = value
        .get("record_id")
        .and_then(WireValue::as_string)
        .ok_or("WORKFLOW_REFERENCE_INVALID")?;
    let revision = integer(value, "revision").map_err(|_| "WORKFLOW_REFERENCE_INVALID")?;
    if fields.len() != 2 || !token_utf16(&id.encode_utf16().collect::<Vec<_>>()) || revision == 0 {
        return Err("WORKFLOW_REFERENCE_INVALID");
    }
    Ok((id, revision))
}

fn workflow_values(rule: &WireValue, record: &WireValue) -> Result<WorkflowValues, &'static str> {
    let payload = record.get("payload").ok_or("WORKFLOW_STATUS_INVALID")?;
    let decoded;
    let fields = if let WireValue::String(raw) = payload {
        decoded = parse_js_json_string_bounded(raw, 32, MAX_OBJECT_BYTES)
            .map_err(|_| "WORKFLOW_STATUS_INVALID")?;
        &decoded
    } else {
        payload
    };
    let field_name = |name| -> Result<String, &'static str> {
        rule.get(name)
            .and_then(WireValue::as_string)
            .ok_or("WORKFLOW_STATUS_INVALID")
    };
    let status = fields
        .get(&field_name("status_field")?)
        .and_then(WireValue::as_string)
        .ok_or("WORKFLOW_STATUS_INVALID")?;
    let declared = rule
        .get("states")
        .and_then(wire_array)
        .ok_or("WORKFLOW_STATUS_INVALID")?;
    if !declared
        .iter()
        .any(|value| value.as_string().as_deref() == Some(&status))
    {
        return Err("WORKFLOW_STATUS_INVALID");
    }
    let parent = match fields.get(&field_name("parent_field")?) {
        Some(WireValue::Null) => None,
        Some(value) => Some(workflow_reference(value)?),
        None => return Err("WORKFLOW_REFERENCE_INVALID"),
    };
    if let Some(deadline) = rule.get("deadline") {
        let name = deadline
            .get("field")
            .and_then(WireValue::as_string)
            .ok_or("WORKFLOW_DEADLINE_INVALID")?;
        let value = fields.get(&name).ok_or("WORKFLOW_DEADLINE_INVALID")?;
        if !matches!(value, WireValue::Null)
            && !value.as_number().is_some_and(|n| {
                n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_991.0
            })
        {
            return Err("WORKFLOW_DEADLINE_INVALID");
        }
    }
    let assignee = if let Some(name) = rule.get("assignee_field").and_then(WireValue::as_string) {
        match fields.get(&name) {
            Some(WireValue::Null) => None,
            None => return Err("WORKFLOW_ASSIGNEE_INVALID"),
            Some(value) => {
                let id = value.as_string().ok_or("WORKFLOW_ASSIGNEE_INVALID")?;
                if !token_utf16(&id.encode_utf16().collect::<Vec<_>>()) {
                    return Err("WORKFLOW_ASSIGNEE_INVALID");
                }
                Some(id)
            }
        }
    } else {
        None
    };
    let dependencies = if let Some(config) = rule.get("dependencies") {
        let name = config
            .get("field")
            .and_then(WireValue::as_string)
            .ok_or("WORKFLOW_DEPENDENCIES_INVALID")?;
        let items = fields
            .get(&name)
            .and_then(wire_array)
            .ok_or("WORKFLOW_DEPENDENCIES_INVALID")?;
        if items.len() > 32 {
            return Err("WORKFLOW_DEPENDENCIES_INVALID");
        }
        items
            .iter()
            .map(workflow_reference)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    Ok(WorkflowValues {
        status,
        parent,
        assignee,
        dependencies,
    })
}

fn workflow_matches(record: &WireValue, schema: &str, instance: &[u16], protocol: &[u16]) -> bool {
    record
        .get("schema_ref")
        .and_then(WireValue::as_string)
        .as_deref()
        == Some(schema)
        && record.get("instance_id").and_then(WireValue::as_utf16) == Some(instance)
        && record.get("protocol_digest").and_then(WireValue::as_utf16) == Some(protocol)
}

fn workflow_rows(objects: &[WireValue]) -> HashMap<String, WireValue> {
    objects
        .iter()
        .filter(|o| o.get("kind").and_then(WireValue::as_string).as_deref() == Some("records"))
        .filter_map(|o| Some((o.get("id")?.as_string()?, o.get("value")?.clone())))
        .collect()
}

fn workflow_heads(objects: &[WireValue]) -> HashMap<String, WireValue> {
    let mut rows = HashMap::<String, (u64, WireValue)>::new();
    for object in objects
        .iter()
        .filter(|o| o.get("kind").and_then(WireValue::as_string).as_deref() == Some("entity_heads"))
    {
        let (Some(id), Some(value), Ok(revision)) = (
            object.get("id").and_then(WireValue::as_string),
            object.get("value"),
            integer(object, "revision"),
        ) else {
            continue;
        };
        if rows.get(&id).is_none_or(|(latest, _)| revision >= *latest) {
            rows.insert(id, (revision, value.clone()));
        }
    }
    rows.into_iter()
        .map(|(id, (_, value))| (id, value))
        .collect()
}

fn validate_action_workflows(
    manifest: &WireValue,
    instance: &[u16],
    protocol: &[u16],
    action: &[u16],
    prior: &[WireValue],
    produced: &[WireValue],
    policy: &WireValue,
) -> Result<(), &'static str> {
    let Some(WireValue::Object(schemas)) = manifest.get("record_schemas") else {
        return Ok(());
    };
    if !schemas
        .iter()
        .any(|(_, schema)| schema.get("workflow").is_some())
    {
        return Ok(());
    }
    let before = workflow_rows(prior);
    let changed = workflow_rows(produced);
    let mut after = before.clone();
    after.extend(changed.clone());
    let before_heads = workflow_heads(prior);
    let mut all = prior.to_vec();
    all.extend_from_slice(produced);
    let after_heads = workflow_heads(&all);
    let members: HashSet<String> = policy
        .get("payload")
        .and_then(|p| p.get("members"))
        .and_then(wire_array)
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("actor_id").and_then(WireValue::as_string))
        .collect();
    let action = String::from_utf16(action).map_err(|_| "WORKFLOW_TRANSITION_INVALID")?;
    for (schema_units, definition) in schemas {
        let Some(rule) = definition.get("workflow") else {
            continue;
        };
        let schema = String::from_utf16(schema_units).map_err(|_| "WORKFLOW_STATUS_INVALID")?;
        for old_head in before_heads.values() {
            let Some(old_id) = old_head.get("record_id").and_then(WireValue::as_string) else {
                continue;
            };
            let Some(old) = before.get(&old_id) else {
                continue;
            };
            if !workflow_matches(old, &schema, instance, protocol) {
                continue;
            }
            let entity = old_head
                .get("entity_id")
                .and_then(WireValue::as_string)
                .ok_or("WORKFLOW_ENTITY_SCHEMA_CHANGED")?;
            let next = after_heads
                .get(&entity)
                .and_then(|h| h.get("record_id"))
                .and_then(WireValue::as_string)
                .and_then(|id| after.get(&id))
                .ok_or("WORKFLOW_ENTITY_SCHEMA_CHANGED")?;
            if !workflow_matches(next, &schema, instance, protocol)
                || next.get("entity_id") != old.get("entity_id")
                || changed.values().any(|r| {
                    r.get("entity_id") == old.get("entity_id")
                        && !workflow_matches(r, &schema, instance, protocol)
                })
            {
                return Err("WORKFLOW_ENTITY_SCHEMA_CHANGED");
            }
        }
        for record in changed
            .values()
            .filter(|r| workflow_matches(r, &schema, instance, protocol))
        {
            let own = workflow_values(rule, record)?;
            if own
                .assignee
                .as_ref()
                .is_some_and(|id| !members.contains(id))
            {
                return Err("WORKFLOW_ASSIGNEE_NOT_MEMBER");
            }
            let entity = record
                .get("entity_id")
                .and_then(WireValue::as_string)
                .ok_or("WORKFLOW_PARENT_INVALID")?;
            let revision = integer(record, "revision").map_err(|_| "WORKFLOW_PARENT_INVALID")?;
            let previous = if let Some((id, expected)) = &own.parent {
                let parent = before.get(id).ok_or("WORKFLOW_PARENT_INVALID")?;
                let old_head = before_heads.get(&entity).ok_or("WORKFLOW_PARENT_INVALID")?;
                if integer(parent, "revision").ok() != Some(*expected)
                    || parent.get("entity_id") != record.get("entity_id")
                    || !workflow_matches(parent, &schema, instance, protocol)
                    || old_head
                        .get("record_id")
                        .and_then(WireValue::as_string)
                        .as_deref()
                        != Some(id)
                    || revision != expected.checked_add(1).ok_or("WORKFLOW_PARENT_INVALID")?
                {
                    return Err("WORKFLOW_PARENT_INVALID");
                }
                Some(workflow_values(rule, parent)?.status)
            } else {
                if revision != 1 || before_heads.contains_key(&entity) {
                    return Err("WORKFLOW_PARENT_INVALID");
                }
                None
            };
            let transitions = rule
                .get("transitions")
                .and_then(wire_array)
                .ok_or("WORKFLOW_TRANSITION_INVALID")?;
            if !transitions.iter().any(|t| {
                t.get("action").and_then(WireValue::as_string).as_deref() == Some(&action)
                    && t.get("from").and_then(WireValue::as_string) == previous
                    && t.get("to").and_then(WireValue::as_string).as_deref() == Some(&own.status)
            }) {
                return Err("WORKFLOW_TRANSITION_INVALID");
            }
            if after_heads.get(&entity).and_then(|h| h.get("record_id")) != record.get("id") {
                return Err("WORKFLOW_REVISION_MUST_BE_HEAD");
            }
        }
        for (entity, head) in &after_heads {
            let Some(record_id) = head.get("record_id").and_then(WireValue::as_string) else {
                continue;
            };
            let Some(record) = after.get(&record_id) else {
                continue;
            };
            if workflow_matches(record, &schema, instance, protocol)
                && before_heads.get(entity).and_then(|h| h.get("record_id"))
                    != head.get("record_id")
                && !changed.contains_key(&record_id)
            {
                return Err("WORKFLOW_HEAD_SELECTION_DENIED");
            }
        }
        validate_workflow_graph(rule, &schema, instance, protocol, &after, &after_heads)?;
    }
    Ok(())
}

fn validate_workflow_graph(
    rule: &WireValue,
    schema: &str,
    instance: &[u16],
    protocol: &[u16],
    records: &HashMap<String, WireValue>,
    heads: &HashMap<String, WireValue>,
) -> Result<(), &'static str> {
    let mut selected = HashMap::<String, WireValue>::new();
    for head in heads.values() {
        let Some(id) = head.get("record_id").and_then(WireValue::as_string) else {
            continue;
        };
        let Some(record) = records.get(&id) else {
            continue;
        };
        if !workflow_matches(record, schema, instance, protocol) {
            continue;
        }
        let entity = record
            .get("entity_id")
            .and_then(WireValue::as_string)
            .ok_or("WORKFLOW_HEAD_INVALID")?;
        if head.get("entity_id") != record.get("entity_id")
            || integer(head, "revision").ok() != integer(record, "revision").ok()
            || head.get("instance_id").and_then(WireValue::as_utf16) != Some(instance)
        {
            return Err("WORKFLOW_HEAD_INVALID");
        }
        selected.insert(entity, record.clone());
    }
    let mut edges = HashMap::<String, Vec<String>>::new();
    for (entity, record) in &selected {
        let own = workflow_values(rule, record)?;
        let mut dependencies = Vec::new();
        for (id, revision) in own.dependencies {
            let anchor = records.get(&id).ok_or("WORKFLOW_DEPENDENCY_SCOPE")?;
            if integer(anchor, "revision").ok() != Some(revision)
                || !workflow_matches(anchor, schema, instance, protocol)
            {
                return Err("WORKFLOW_DEPENDENCY_SCOPE");
            }
            let target_entity = anchor
                .get("entity_id")
                .and_then(WireValue::as_string)
                .ok_or("WORKFLOW_DEPENDENCY_SCOPE")?;
            if &target_entity == entity || dependencies.contains(&target_entity) {
                return Err("WORKFLOW_DEPENDENCY_DUPLICATE_OR_SELF");
            }
            let target = selected
                .get(&target_entity)
                .ok_or("WORKFLOW_DEPENDENCY_HEAD_REQUIRED")?;
            let status = workflow_values(rule, target)?.status;
            let config = rule
                .get("dependencies")
                .ok_or("WORKFLOW_DEPENDENCIES_INVALID")?;
            let gated = config
                .get("gated_states")
                .and_then(wire_array)
                .ok_or("WORKFLOW_DEPENDENCIES_INVALID")?;
            let satisfied = config
                .get("satisfied_states")
                .and_then(wire_array)
                .ok_or("WORKFLOW_DEPENDENCIES_INVALID")?;
            if gated
                .iter()
                .any(|v| v.as_string().as_deref() == Some(&own.status))
                && !satisfied
                    .iter()
                    .any(|v| v.as_string().as_deref() == Some(&status))
            {
                return Err("WORKFLOW_DEPENDENCY_NOT_SATISFIED");
            }
            dependencies.push(target_entity);
        }
        edges.insert(entity.clone(), dependencies);
    }
    let mut done = HashSet::new();
    let mut active = HashSet::new();
    for start in edges.keys() {
        if done.contains(start) {
            continue;
        }
        let mut stack = vec![(start.clone(), 0_usize)];
        active.insert(start.clone());
        while let Some((id, index)) = stack.last_mut() {
            let next = edges.get(id).and_then(|v| v.get(*index)).cloned();
            *index += 1;
            if let Some(next) = next {
                if active.contains(&next) {
                    return Err("WORKFLOW_DEPENDENCY_CYCLE");
                }
                if !done.contains(&next) {
                    active.insert(next.clone());
                    stack.push((next, 0));
                }
            } else {
                let id = id.clone();
                stack.pop();
                active.remove(&id);
                done.insert(id);
            }
        }
    }
    Ok(())
}

fn substitute_produced(
    value: &WireValue,
    record_slots: &HashMap<Vec<u16>, WireValue>,
    entity_slots: &HashMap<Vec<u16>, WireValue>,
    depth: usize,
) -> Result<WireValue, &'static str> {
    if depth > 12 {
        return Err("INVALID_PROTOCOL_TRANSITION");
    }
    match value {
        WireValue::Array(items) => Ok(WireValue::Array(
            items
                .iter()
                .map(|item| substitute_produced(item, record_slots, entity_slots, depth + 1))
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
                    .map(|(key, item)| {
                        Ok((
                            key.clone(),
                            substitute_produced(item, record_slots, entity_slots, depth + 1)?,
                        ))
                    })
                    .collect::<Result<_, &'static str>>()?,
            ))
        }
        _ => Ok(value.clone()),
    }
}

fn safe_add(value: u64, delta: u64) -> Result<u64, &'static str> {
    value
        .checked_add(delta)
        .filter(|result| *result <= 9_007_199_254_740_991)
        .ok_or("PROTOCOL_OUTPUT_MISMATCH")
}
fn decoded_value(value: &WireValue) -> Result<WireValue, &'static str> {
    match value {
        WireValue::String(units) => parse_js_json_string_bounded(units, 2048, MAX_CONTENT_BYTES)
            .map_err(|_| "INVALID_PAYLOAD"),
        value => Ok(value.clone()),
    }
}

fn validate_role_policies(
    policy: &WireValue,
    prior: &[WireValue],
    at: u64,
    validate_instance: &[u16],
) -> Result<(), &'static str> {
    let mut history = RoleHistory::new();
    validate_role_policies_with_history(policy, prior, at, Some(validate_instance), &mut history)
}

fn validate_role_policies_with_history(
    policy: &WireValue,
    prior: &[WireValue],
    at: u64,
    validate_instance: Option<&[u16]>,
    history: &mut RoleHistory,
) -> Result<(), &'static str> {
    let mut latest = Vec::new();
    let mut positions = HashMap::new();
    for object in prior {
        let (Some(kind), Some(id)) = (
            object.get("kind").and_then(WireValue::as_utf16),
            object.get("id").and_then(WireValue::as_utf16),
        ) else {
            continue;
        };
        let key = (kind.to_vec(), id.to_vec());
        if let Some(&index) = positions.get(&key) {
            if integer(latest[index], "revision").unwrap_or(0)
                < integer(object, "revision").unwrap_or(0)
            {
                latest[index] = object;
            }
        } else {
            positions.insert(key, latest.len());
            latest.push(object);
        }
    }
    let members = match policy.get("members") {
        Some(WireValue::Array(members)) => members,
        _ => return Err("PROTOCOL_ROLE_POLICY_INVALID"),
    };
    for object in latest.iter().filter(|object| {
        object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
    }) {
        let Some(instance) = object.get("value") else {
            continue;
        };
        let Some(protocol_digest) = instance
            .get("protocol_digest")
            .and_then(WireValue::as_utf16)
        else {
            continue;
        };
        let Some(protocol) = latest.iter().find(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
                && object
                    .get("value")
                    .and_then(|value| value.get("digest"))
                    .and_then(WireValue::as_utf16)
                    == Some(protocol_digest)
        }) else {
            continue;
        };
        let Some(manifest_raw) = protocol.get("value").and_then(|value| {
            value
                .get("resolved_manifest")
                .or_else(|| value.get("manifest"))
        }) else {
            continue;
        };
        let manifest = decoded_value(manifest_raw).map_err(|_| "PROTOCOL_ROLE_POLICY_INVALID")?;
        let (Some(WireValue::Array(active)), Some(WireValue::Array(historical))) = (
            manifest.get("role_conflicts"),
            manifest.get("historical_role_conflicts"),
        ) else {
            return Err("PROTOCOL_ROLE_POLICY_INVALID");
        };
        let Some(instance_id) = object.get("id").and_then(WireValue::as_utf16) else {
            continue;
        };
        // Legacy grants contribute history for their actors even when those
        // actors are absent from this policy's current member list.
        for grant in latest.iter().filter(|grant| {
            grant.get("kind").and_then(WireValue::as_string).as_deref() == Some("grants")
        }) {
            let Some(row) = grant.get("value") else {
                continue;
            };
            if row.get("instance_id").and_then(WireValue::as_utf16) != Some(instance_id)
                || row.get("protocol_digest").and_then(WireValue::as_utf16) != Some(protocol_digest)
            {
                continue;
            }
            let actor = row
                .get("actor_id")
                .and_then(WireValue::as_utf16)
                .ok_or("LEGACY_GRANT_INVALID")?;
            let roles = decoded_value(row.get("protocol_roles").ok_or("LEGACY_GRANT_INVALID")?)
                .map_err(|_| "LEGACY_GRANT_INVALID")?;
            let WireValue::Array(roles) = roles else {
                return Err("LEGACY_GRANT_INVALID");
            };
            let past = history
                .entry((
                    instance_id.to_vec(),
                    protocol_digest.to_vec(),
                    actor.to_vec(),
                ))
                .or_default();
            for role in roles {
                past.insert(role.as_utf16().ok_or("LEGACY_GRANT_INVALID")?.to_vec());
            }
        }
        for member in members {
            let Some(actor) = member.get("actor_id").and_then(WireValue::as_utf16) else {
                continue;
            };
            let key = (
                instance_id.to_vec(),
                protocol_digest.to_vec(),
                actor.to_vec(),
            );
            let mut past = history.get(&key).cloned().unwrap_or_default();
            let mut roles = HashSet::<Vec<u16>>::new();
            if let Some(WireValue::Array(scopes)) = member.get("scopes") {
                for scope in scopes {
                    let active_at = scope.get("expires_at").is_none_or(|expiry| {
                        matches!(expiry, WireValue::Null)
                            || expiry.as_number().is_some_and(|value| value > at as f64)
                    });
                    let targets = matches!(scope.get("instance_id"), Some(WireValue::Null))
                        || scope.get("instance_id").and_then(WireValue::as_utf16)
                            == Some(instance_id);
                    if active_at && targets {
                        if let Some(WireValue::Array(entries)) = scope.get("protocol_roles") {
                            for role in entries {
                                if let Some(role) = role.as_utf16() {
                                    roles.insert(role.to_vec());
                                }
                            }
                        }
                    }
                }
            }
            past.extend(roles.iter().cloned());
            if validate_instance == Some(instance_id) {
                for pair in active {
                    if conflict_pair(pair, &roles) {
                        return Err("ACTIVE_ROLE_CONFLICT");
                    }
                }
                for pair in historical {
                    if conflict_pair(pair, &past) {
                        return Err("HISTORICAL_ROLE_CONFLICT");
                    }
                }
            }
            history.insert(key, past);
        }
    }
    Ok(())
}

pub(crate) fn validate_member_scope_roles(policies:&[WireValue],candidate:&WireValue,objects:&[WireValue])->Result<(),&'static str>{
    let mut history=RoleHistory::new();
    for policy in policies {
        validate_role_policies_with_history(policy,objects,integer(policy,"issued_at").map_err(|_|"MEMBER_SCOPES_INVALID")?,None,&mut history)?;
    }
    let at=integer(candidate,"issued_at").map_err(|_|"MEMBER_SCOPES_INVALID")?;
    for object in objects.iter().filter(|o|o.get("kind").and_then(WireValue::as_string).as_deref()==Some("instances")) {
        let id=object.get("id").and_then(WireValue::as_utf16).ok_or("MEMBER_SCOPES_INVALID")?;
        validate_role_policies_with_history(candidate,objects,at,Some(id),&mut history)?;
    }
    Ok(())
}

fn conflict_pair(pair: &WireValue, roles: &HashSet<Vec<u16>>) -> bool {
    let WireValue::Array(pair) = pair else {
        return false;
    };
    pair.len() == 2
        && pair[0].as_utf16().is_some_and(|role| roles.contains(role))
        && pair[1].as_utf16().is_some_and(|role| roles.contains(role))
}
fn token_utf16(value: &[u16]) -> bool {
    value.len() == 43
        && value.iter().all(|ch| {
            (*ch >= 65 && *ch <= 90)
                || (*ch >= 97 && *ch <= 122)
                || (*ch >= 48 && *ch <= 57)
                || *ch == 95
                || *ch == 45
        })
}

fn string_value(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn fields_object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}

pub(crate) fn validate_simple_record_schema(
    payload: &WireValue,
    definition: &WireValue,
) -> Result<(), &'static str> {
    if definition
        .get("type")
        .and_then(WireValue::as_string)
        .as_deref()
        != Some("object")
    {
        return Err("RECORD_SCHEMA_INVALID");
    }
    let WireValue::Object(values) = payload else {
        return Err("RECORD_SCHEMA_INVALID");
    };
    let Some(WireValue::Object(fields)) = definition.get("fields") else {
        return Err("RECORD_SCHEMA_INVALID");
    };
    let Some(WireValue::Array(required)) = definition.get("required") else {
        return Err("RECORD_SCHEMA_INVALID");
    };
    if required.iter().any(|name| {
        name.as_utf16()
            .is_none_or(|name| !values.iter().any(|(key, _)| key == name))
    }) {
        return Err("RECORD_SCHEMA_INVALID");
    }
    for (name, value) in values {
        let Some((_, kind)) = fields.iter().find(|(key, _)| key == name) else {
            return Err("RECORD_SCHEMA_INVALID");
        };
        let Some(kind) = kind.as_string() else {
            return Err("RECORD_SCHEMA_INVALID");
        };
        let valid = match kind.as_str() {
            "string" => matches!(value, WireValue::String(_)),
            "source_text" => matches!(value, WireValue::Null) || crate::source_provenance::valid_source_text(value),
            "source_timestamp" => matches!(value, WireValue::Null) || crate::source_provenance::valid_source_timestamp(value),
            "source_sha256" => matches!(value, WireValue::Null) || crate::source_provenance::valid_source_sha256(value),
            "integer" => value.as_number().is_some_and(|value| {
                value.is_finite() && value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0
            }),
            "boolean" => matches!(value, WireValue::Bool(_)),
            "null" => matches!(value, WireValue::Null),
            "json" => true,
            _ => false,
        };
        if !valid {
            return Err("RECORD_SCHEMA_INVALID");
        }
        if let Some(declaration) = definition
            .get("protection")
            .and_then(|protection| protection.get("fields"))
            .and_then(|declarations| {
                let WireValue::Object(declarations) = declarations else {
                    return None;
                };
                declarations
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value)
            })
        {
            if declaration
                .get("protection")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some("server_readable")
            {
                validate_readable_field(declaration, value)?;
            }
        }
    }
    let max = integer(definition, "max_bytes").map_err(|_| "RECORD_SCHEMA_INVALID")? as usize;
    if canonical_wire_value(payload, Path::SecureArtifact)
        .map_err(|_| "RECORD_SCHEMA_INVALID")?
        .len()
        > max
    {
        return Err("RECORD_TOO_LARGE");
    }
    Ok(())
}

fn validate_readable_reference(value: &WireValue, optional: bool) -> Result<(), &'static str> {
    if optional && matches!(value, WireValue::Null) {
        return Ok(());
    }
    let WireValue::Object(fields) = value else {
        return Err("STRUCTURE_REFERENCE_INVALID");
    };
    let id = if value.get("recordId").is_some() {
        "recordId"
    } else {
        "record_id"
    };
    if fields.len() != 2
        || !value
            .get(id)
            .and_then(WireValue::as_utf16)
            .is_some_and(token_utf16)
        || integer(value, "revision").unwrap_or(0) == 0
        || fields.iter().any(|(key, _)| {
            key.as_slice() != id.encode_utf16().collect::<Vec<_>>().as_slice()
                && key.as_slice() != "revision".encode_utf16().collect::<Vec<_>>().as_slice()
        })
    {
        return Err("STRUCTURE_REFERENCE_INVALID");
    }
    Ok(())
}

pub(crate) fn validate_readable_field(
    rule: &WireValue,
    value: &WireValue,
) -> Result<(), &'static str> {
    let kind = rule
        .get("type")
        .and_then(WireValue::as_string)
        .ok_or("RECORD_SCHEMA_INVALID")?;
    let token = value.as_utf16().is_some_and(token_utf16);
    match kind.as_str() {
        "opaque" | "actor" => {
            if !token {
                return Err("STRUCTURE_ACTOR_INVALID");
            }
        }
        "optional_actor" => {
            if !matches!(value, WireValue::Null) && !token {
                return Err("STRUCTURE_ACTOR_INVALID");
            }
        }
        "workspace_reference" | "reference" => validate_readable_reference(value, false)?,
        "optional_workspace_reference" | "optional_reference" => {
            validate_readable_reference(value, true)?
        }
        "item_key" => {
            let Some(s) = value.as_string() else {
                return Err("STRUCTURE_ITEM_KEY_INVALID");
            };
            let parts: Vec<_> = s.split('.').collect();
            if !(parts.len() == 3 || parts.len() == 4 && parts[3] == "deadline")
                || parts[..3].iter().any(|part| {
                    part.len() != 43
                        || !part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
            {
                return Err("STRUCTURE_ITEM_KEY_INVALID");
            }
        }
        "digest" => {
            if !value.as_string().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }) {
                return Err("STRUCTURE_DIGEST_INVALID");
            }
        }
        "enum" => {
            let Some(WireValue::Array(allowed)) = rule.get("values") else {
                return Err("STRUCTURE_ENUM_INVALID");
            };
            if !allowed.contains(value) {
                return Err("STRUCTURE_ENUM_INVALID");
            }
        }
        "counter" => {
            if !value.as_number().is_some_and(|n| {
                n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_991.0
            }) {
                return Err("STRUCTURE_COUNTER_INVALID");
            }
        }
        "work_status" => {
            if !matches!(
                value.as_string().as_deref(),
                Some("IN_PROGRESS" | "WAITING_FOR_INPUT" | "DEFERRED" | "HANDLED" | "DECLINED")
            ) {
                return Err("STRUCTURE_WORK_STATUS_INVALID");
            }
        }
        "references" => {
            let WireValue::Array(items) = value else {
                return Err("STRUCTURE_REFERENCE_INVALID");
            };
            if items.len() > 32 {
                return Err("STRUCTURE_REFERENCE_INVALID");
            }
            for item in items {
                validate_readable_reference(item, false)?;
            }
        }
        "task_status" => {
            if !matches!(
                value.as_string().as_deref(),
                Some("OPEN" | "IN_PROGRESS" | "DONE" | "CANCELED")
            ) {
                return Err("STRUCTURE_TASK_STATUS_INVALID");
            }
        }
        "timestamp" => {
            if !matches!(value, WireValue::Null)
                && !value.as_number().is_some_and(|n| {
                    n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_991.0
                })
            {
                return Err("STRUCTURE_TIMESTAMP_INVALID");
            }
        }
        "tokens" => {
            let WireValue::Array(items) = value else {
                return Err("STRUCTURE_LIST_INVALID");
            };
            let mut seen = HashSet::new();
            if items.len() > 32
                || items.iter().any(|item| {
                    !item.as_utf16().is_some_and(token_utf16)
                        || !seen.insert(item.as_utf16().unwrap().to_vec())
                })
            {
                return Err("STRUCTURE_LIST_INVALID");
            }
        }
        _ => return Err("RECORD_SCHEMA_INVALID"),
    }
    Ok(())
}

fn replace_field(object: &mut WireValue, name: &str, value: WireValue) -> Result<(), ()> {
    let WireValue::Object(fields) = object else {
        return Err(());
    };
    if let Some((_, found)) = fields
        .iter_mut()
        .find(|(key, _)| key.iter().copied().eq(name.encode_utf16()))
    {
        *found = value;
    } else {
        fields.push((name.encode_utf16().collect(), value));
    }
    Ok(())
}

fn sealed_content(value: &WireValue) -> Result<SealedContent, ReplayError> {
    let WireValue::Array(chunks) = value.get("chunks").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    Ok(SealedContent {
        v: integer(value, "v")?
            .try_into()
            .map_err(|_| ReplayError::Invalid)?,
        alg: string(value, "alg")?,
        nonce: string(value, "nonce")?,
        chunks: chunks
            .iter()
            .map(|chunk| chunk.as_string().ok_or(ReplayError::Invalid))
            .collect::<Result<_, _>>()?,
    })
}

fn commit_context(payload: &WireValue) -> Result<WireValue, ReplayError> {
    let WireValue::Object(fields) = payload else {
        return Err(ReplayError::Invalid);
    };
    Ok(WireValue::Object(
        fields
            .iter()
            .filter(|(name, _)| {
                !name.iter().copied().eq("mode".encode_utf16())
                    && !name.iter().copied().eq("body".encode_utf16())
            })
            .cloned()
            .collect(),
    ))
}

fn epoch_key(wire: &[u8], workspace_id: &str, epoch: u64) -> Result<[u8; 32], ReplayError> {
    let keyring = parse_wire_json_js_bounded(wire, 2048, 512 * 1024 * 1024)
        .map_err(|_| ReplayError::Invalid)?;
    if integer(&keyring, "v")? != 1 || string(&keyring, "workspace_id")? != workspace_id {
        return Err(ReplayError::Invalid);
    }
    let WireValue::Array(keys) = keyring.get("keys").ok_or(ReplayError::Invalid)? else {
        return Err(ReplayError::Invalid);
    };
    let key = keys
        .iter()
        .find(|key| integer(key, "epoch").is_ok_and(|candidate| candidate == epoch))
        .ok_or(ReplayError::Invalid)?;
    decode_base64url(&string(key, "key")?)
        .map_err(|_| ReplayError::Invalid)?
        .try_into()
        .map_err(|_| ReplayError::Invalid)
}

fn integer(value: &WireValue, name: &str) -> Result<u64, ReplayError> {
    let number = value
        .get(name)
        .and_then(WireValue::as_number)
        .ok_or(ReplayError::Invalid)?;
    if number.is_finite()
        && number >= 0.0
        && number.fract() == 0.0
        && number <= 9_007_199_254_740_991.0
    {
        Ok(number as u64)
    } else {
        Err(ReplayError::Invalid)
    }
}

fn string(value: &WireValue, name: &str) -> Result<String, ReplayError> {
    value
        .get(name)
        .and_then(WireValue::as_string)
        .ok_or(ReplayError::Invalid)
}

fn utf16<'a>(value: &'a WireValue, name: &str) -> Result<&'a [u16], ReplayError> {
    value
        .get(name)
        .and_then(WireValue::as_utf16)
        .ok_or(ReplayError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_replay_rejects_unimplemented_publication_withdrawal() {
        let interpreted = EvalResult {
            next_state: WireValue::Object(vec![]),
            records: vec![],
            head_selections: vec![],
            withdrawals: vec![WireValue::Null],
            control_revision: true,
            content_entities: vec![],
            evaluated_at: None,
        };
        assert_eq!(
            ensure_secure_effects_supported(&interpreted),
            Err("PUBLICATION_WITHDRAWAL_UNSUPPORTED")
        );
        let ordinary = EvalResult { withdrawals: vec![], ..interpreted };
        assert_eq!(ensure_secure_effects_supported(&ordinary), Ok(()));
    }

    #[test]
    fn provenance_record_scalars_accept_null_and_validate_claims() {
        let definition = crate::wire_json::parse_wire_json_bounded(
            br#"{"type":"object","fields":{"source_text":"source_text","source_timestamp":"source_timestamp","source_sha256":"source_sha256"},"required":["source_text","source_timestamp","source_sha256"],"max_bytes":16384}"#,
            64,
            32_768,
        ).unwrap();
        let nulls = crate::wire_json::parse_wire_json_bounded(
            br#"{"source_text":null,"source_timestamp":null,"source_sha256":null}"#,
            64,
            32_768,
        ).unwrap();
        assert!(validate_simple_record_schema(&nulls, &definition).is_ok());
        let valid = crate::wire_json::parse_wire_json_bounded(
            br#"{"source_text":"source note","source_timestamp":"1500-02-28T23:59:59.123456789-04:30","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            64,
            32_768,
        ).unwrap();
        assert!(validate_simple_record_schema(&valid, &definition).is_ok());
        let invalid = crate::wire_json::parse_wire_json_bounded(
            br#"{"source_text":"source note","source_timestamp":"1900-02-29T00:00:00Z","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            64,
            32_768,
        ).unwrap();
        assert_eq!(validate_simple_record_schema(&invalid, &definition), Err("RECORD_SCHEMA_INVALID"));
    }

    #[test]
    fn hydrated_protocol_source_size_limit_is_reference_specific() {
        let text = |value: &str| WireValue::String(value.encode_utf16().collect());
        let Ok(directory) = std::env::var("PEERWORK_OBJECT_REPLAY_FIXTURE") else { return; };
        let path = std::path::Path::new(&directory).join("direct-object-end-applied-loss/agent.state");
        let before = std::fs::read(&path).unwrap();
        let state = crate::wire_json::parse_wire_json_bounded(&before, 64, 8 * 1024 * 1024).unwrap();
        let WireValue::Object(markers) = state.get("protocol_object_stage_intents").unwrap() else { panic!("marker map"); };
        assert_eq!(markers.len(), 1);
        let marker = &markers[0].1;
        let proof = marker.get("proof").unwrap().clone();
        let WireValue::Array(parts) = marker.get("parts").unwrap() else { panic!("parts"); };
        let value = read_protocol_object_source(&proof, parts).unwrap();
        let object = fields_object(vec![("kind", text("protocols")),
            ("id", proof.get("protocol_digest").unwrap().clone()),
            ("revision", WireValue::Number(1.0)), ("provenance", text("AUTHOR_SIGNED")), ("value", value)]);
        let source = HydratedProtocolObject { reference_index: 0, proof };
        assert_eq!(canonical_wire_value(&object, Path::SecureArtifact).unwrap().len(), 121_506);
        // This unit isolates the size rule using genuine value/proof bytes.
        // Signed source authority is exercised by the separate replay gates.
        assert!(validate_replayed_object_size(&object, 0, Some(&source)).is_ok());
        assert!(validate_replayed_object_size(&object, 0, None).is_err(), "inline oversized object");
        assert!(validate_replayed_object_size(&object, 1, Some(&source)).is_err(), "unrelated slot");
        let mut wrong_kind = object.clone();
        let WireValue::Object(fields) = &mut wrong_kind else { unreachable!() };
        fields.iter_mut().find(|(key, _)| key.iter().copied().eq("kind".encode_utf16())).unwrap().1 = text("instances");
        assert!(validate_replayed_object_size(&wrong_kind, 0, Some(&source)).is_err(), "unrelated kind");
        let mut changed = source;
        let WireValue::Object(fields) = &mut changed.proof else { unreachable!() };
        fields.iter_mut().find(|(key, _)| key.iter().copied().eq("value_sha256".encode_utf16())).unwrap().1 = text(&"0".repeat(64));
        assert!(validate_replayed_object_size(&object, 0, Some(&changed)).is_err(), "value proof mismatch");
        assert_eq!(std::fs::read(path).unwrap(), before);
        eprintln!("OBJECT_SIZE_BOUNDARY selected_slot=true inline_refused=true unrelated_slot_refused=true unrelated_kind_refused=true changed_hash_refused=true bytes=121506 wire_limit=98304");
    }
    use crate::{
        canonical::canonical,
        crypto::{actor_id, base64url, key_id, sha256, sha256_hex, sign_canonical},
        e2ee::{seal_content_bytes, seal_content_wire},
    };
    use ed25519_dalek::SigningKey;
    use hpke::{kem::DhP256HkdfSha256, Kem, Serializable};
    use serde_json::{json, Value};

    fn signed(payload: Value, domain: &str, key: &SigningKey) -> Vec<u8> {
        let signature = sign_canonical(domain, &payload, key).unwrap();
        serde_json::to_vec(&json!({"payload":payload,"signature":signature})).unwrap()
    }
    fn hash(wire: &[u8]) -> String {
        let parsed = parse_wire_json_js_bounded(wire, 64, 196_608).unwrap();
        sha256_hex(
            canonical_wire_value(&parsed, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        )
    }

    #[test]
    fn signed_typescript_migration_journals_match_private_replay() {
        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/signed-migration-vectors.json"
        ))
        .unwrap();
        for case in vectors.as_array().unwrap() {
            let policy_values = case["policies"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![case["policy"].clone()]);
            let policies = policy_values
                .iter()
                .map(|policy| serde_json::to_vec(policy).unwrap())
                .collect::<Vec<_>>();
            let policy_refs = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let commits = case["commits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|commit| serde_json::to_vec(commit).unwrap())
                .collect::<Vec<_>>();
            let commit_refs = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let checkpoint = serde_json::to_vec(&case["checkpoint"]).unwrap();
            let workspace = case["workspace_id"].as_str().unwrap();
            let owner = OwnerPin {
                actor_id: case["owner"]["actor_id"].as_str().unwrap(),
                signing_key: case["owner"]["key"].as_str().unwrap(),
            };
            let keyring = case
                .get("keyring")
                .map(|value| serde_json::to_vec(value).unwrap());
            let actual = replay_basic_content(
                &policy_refs,
                &commit_refs,
                &checkpoint,
                workspace,
                Some(&owner),
                None,
                keyring.as_deref(),
            );
            assert_eq!(
                actual.is_ok(),
                case["ok"].as_bool().unwrap(),
                "{}: {actual:?}",
                case["name"]
            );
            if let Ok(facts) = actual {
                assert_eq!(
                    facts.legacy,
                    case["legacy"].as_bool().unwrap(),
                    "{}: legacy provenance",
                    case["name"]
                );
                let expected_operations = parse_wire_json_js_bounded(
                    &serde_json::to_vec(&case["operations"]).unwrap(),
                    48,
                    32 * 1024 * 1024,
                )
                .unwrap();
                assert_eq!(
                    canonical_wire_value(&WireValue::Array(facts.operations), Path::SecureArtifact)
                        .unwrap(),
                    canonical_wire_value(&expected_operations, Path::SecureArtifact).unwrap(),
                    "{}: replayed operation content/order",
                    case["name"]
                );
                assert_eq!(
                    facts.object_count,
                    case["objects"].as_array().unwrap().len(),
                    "{}: migrated object projection",
                    case["name"]
                );
                let expected = parse_wire_json_js_bounded(
                    &serde_json::to_vec(&case["objects"]).unwrap(),
                    48,
                    32 * 1024 * 1024,
                )
                .unwrap();
                assert_eq!(
                    canonical_wire_value(&WireValue::Array(facts.objects), Path::SecureArtifact)
                        .unwrap(),
                    canonical_wire_value(&expected, Path::SecureArtifact).unwrap(),
                    "{}: migrated exact object content/order",
                    case["name"]
                );
            }
        }
    }

    #[test]
    fn signed_typescript_recovery_requires_first_failed_content() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/signed-recovery-vectors.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let policies = case["policies"].as_array().map_or_else(
                || vec![serde_json::to_vec(&case["policy"]).unwrap()],
                |values| {
                    values
                        .iter()
                        .map(|value| serde_json::to_vec(value).unwrap())
                        .collect()
                },
            );
            let policy_refs = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let commits = case["commits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| serde_json::to_vec(value).unwrap())
                .collect::<Vec<_>>();
            let commit_refs = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let checkpoint = serde_json::to_vec(&case["checkpoint"]).unwrap();
            let keyring = serde_json::to_vec(&case["keyring"]).unwrap();
            let owner = OwnerPin {
                actor_id: case["owner"]["actor_id"].as_str().unwrap(),
                signing_key: case["owner"]["key"].as_str().unwrap(),
            };
            let actual = replay_basic_content(
                &policy_refs,
                &commit_refs,
                &checkpoint,
                case["workspace_id"].as_str().unwrap(),
                Some(&owner),
                None,
                Some(&keyring),
            );
            assert_eq!(
                actual.is_ok(),
                case["ok"].as_bool().unwrap(),
                "{}: {actual:?}",
                case["name"]
            );
            if let Ok(facts) = actual {
                if !case["structure_records"].is_null() {
                    let policy =
                        parse_wire_json_js_bounded(&policies[0], 64, 32 * 1024 * 1024).unwrap();
                    let contract = policy.get("payload").unwrap().get("structure").unwrap();
                    let (mut records, mut heads) =
                        project_structure_data(&facts.objects, contract).unwrap();
                    sort_structure_snapshot(&mut records, &mut heads);
                    for (field, actual) in
                        [("structure_records", records), ("structure_heads", heads)]
                    {
                        let expected = parse_wire_json_js_bounded(
                            &serde_json::to_vec(&case[field]).unwrap(),
                            64,
                            32 * 1024 * 1024,
                        )
                        .unwrap();
                        assert_eq!(
                            canonical_wire_value(&WireValue::Array(actual), Path::SecureArtifact)
                                .unwrap(),
                            canonical_wire_value(&expected, Path::SecureArtifact).unwrap(),
                            "{}: {field}",
                            case["name"]
                        );
                    }
                }
                for (field, native) in [
                    ("objects", facts.objects),
                    ("operations", facts.operations),
                    ("recoveries", facts.recoveries),
                ] {
                    let expected = parse_wire_json_js_bounded(
                        &serde_json::to_vec(&case[field]).unwrap(),
                        64,
                        32 * 1024 * 1024,
                    )
                    .unwrap();
                    assert_eq!(
                        canonical_wire_value(&WireValue::Array(native), Path::SecureArtifact)
                            .unwrap(),
                        canonical_wire_value(&expected, Path::SecureArtifact).unwrap(),
                        "{}: {field}",
                        case["name"]
                    );
                }
                if case["action_receipts"].is_array() {
                    let expected = parse_wire_json_js_bounded(
                        &serde_json::to_vec(&case["action_receipts"]).unwrap(),
                        64,
                        32 * 1024 * 1024,
                    )
                    .unwrap();
                    assert_eq!(
                        canonical_wire_value(
                            &WireValue::Array(facts.action_receipts),
                            Path::SecureArtifact,
                        )
                        .unwrap(),
                        canonical_wire_value(&expected, Path::SecureArtifact).unwrap(),
                        "{}: action receipts",
                        case["name"]
                    );
                }
                assert_eq!(
                    facts.legacy,
                    case["legacy"].as_bool().unwrap(),
                    "{}: legacy",
                    case["name"]
                );
                assert_eq!(
                    facts.structure_state,
                    case["structure_state"].as_str(),
                    "{}: structure status",
                    case["name"]
                );
            }
        }
    }

    #[test]
    fn archived_public_prefix_is_restored_before_signed_header_scan() {
        let key = SigningKey::from_bytes(&[116; 32]);
        let owner_key = key_id(&key.verifying_key().to_bytes());
        let owner = actor_id(&key.verifying_key().to_bytes());
        let workspace = base64url(&[117; 32]);
        let (_, encryption_public) = DhP256HkdfSha256::gen_keypair();
        let point = encryption_public.to_bytes();
        let encryption = json!({"kty":"EC","crv":"P-256","x":base64url(&point[1..33]),"y":base64url(&point[33..65])});
        let encryption_id = base64url(&sha256(
            canonical(&encryption, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        ));
        let certificate: Value = serde_json::from_slice(&signed(
            json!({"v":1,"actor_id":owner,"signing_key":owner_key,"encryption_key":encryption,
                "encryption_key_id":encryption_id,"issued_at":0,"expires_at":1000}),
            "peerwork.secure.key-certificate.v1",
            &key,
        ))
        .unwrap();
        let members =
            json!([{"actor_id":owner,"certificate":certificate,"role":"OWNER","scopes":[]}]);
        let policy1 = signed(
            json!({"v":1,"workspace_id":workspace,"owner_id":owner,"signing_key":owner_key,
            "version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PUBLIC","epoch":0,
            "members":members,"issued_at":1}),
            "peerwork.secure.policy.v1",
            &key,
        );
        let policy2 = signed(
            json!({"v":1,"workspace_id":workspace,"owner_id":owner,"signing_key":owner_key,
            "version":2,"previous_policy":hash(&policy1),"effective_sequence":2,"visibility":"PRIVATE","epoch":1,
            "members":members,"issued_at":2}),
            "peerwork.secure.policy.v1",
            &key,
        );
        let public = signed(
            json!({"v":1,"workspace_id":workspace,"sequence":1,"previous":null,
            "policy_hash":hash(&policy1),"epoch":0,"actor_id":owner,"signing_key":owner_key,
            "command_id":base64url(&[118;32]),"action_id":"test.bootstrap","instance_id":null,
            "issued_at":1,"delegation":null,"mode":"PUBLIC",
            "body":{"v":1,"kind":"BOOTSTRAP","input":{},"objects":[]}}),
            "peerwork.secure.commit.v1",
            &key,
        );
        let source = json!({"v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&public),"policy_hash":hash(&policy1)});
        let artifact = canonical(
            &serde_json::from_slice::<Value>(&public).unwrap(),
            Path::SecureArtifact,
        )
        .unwrap();
        let archived = json!({"kind":"secure_commits","id":base64url(&[119;32]),"revision":1,
            "provenance":"LEGACY_OWNER_ATTESTED","value":{"artifact":artifact}});
        let descriptors = json!([{"kind":"secure_commits","id":archived["id"],"revision":1}]);
        let source_root = sha256_hex(
            canonical(&descriptors, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        );
        let context = json!({"v":1,"workspace_id":workspace,"sequence":2,"previous":hash(&public),
            "policy_hash":hash(&policy2),"epoch":1,"actor_id":owner,"signing_key":owner_key,
            "command_id":base64url(&[120;32]),"action_id":"secure.migrate","instance_id":null,
            "issued_at":2,"delegation":null,
            "migration":{"source_checkpoint":source,"source_root":source_root,"source_items":descriptors}});
        let operation = json!({"v":1,"kind":"MIGRATE","input":{},"objects":[archived]});
        let epoch_key = [121_u8; 32];
        let plaintext = canonical(&operation, Path::SecureArtifact).unwrap();
        let sealed = seal_content_wire(
            &epoch_key,
            plaintext.as_bytes(),
            canonical(&context, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let mut payload = context;
        payload["mode"] = json!("PRIVATE");
        payload["body"] = serde_json::to_value(sealed).unwrap();
        let migration = signed(payload, "peerwork.secure.commit.v1", &key);
        let keyring = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
            "keys":[{"epoch":1,"key":base64url(&epoch_key)}]}))
        .unwrap();
        let restored = restore_archived_public_history(
            &[&policy1, &policy2],
            &[&migration],
            &workspace,
            Some(&keyring),
        )
        .unwrap();
        assert!(matches!(restore_archived_public_history_with_limit(
            &[&policy1, &policy2], &[&migration], &workspace, Some(&keyring), 1
        ), Err(ReplayError::ResourceLimit)));
        let selected = restore_archived_public_history_with_limit(
            &[&policy1, &policy2], &[&migration], &workspace, Some(&keyring), 2
        ).unwrap();
        assert_eq!(selected, restored);
        assert_eq!(restored.len(), 2);
        assert_eq!(hash(&restored[0]), hash(&public));
        let checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,"owner_id":owner,
            "owner_key":owner_key,"sequence":2,"head":hash(&migration),"policy_hash":hash(&policy2)})).unwrap();
        let refs = restored.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(scan_signed_chain_headers(
            &[&policy1, &policy2],
            &refs,
            &checkpoint,
            &workspace,
            Some(&OwnerPin {
                actor_id: &owner,
                signing_key: &owner_key
            }),
            None
        )
        .is_ok());
        let replayed = replay_basic_content(
            &[&policy1, &policy2],
            &[&migration],
            &checkpoint,
            &workspace,
            Some(&OwnerPin {
                actor_id: &owner,
                signing_key: &owner_key,
            }),
            None,
            Some(&keyring),
        )
        .unwrap();
        assert_eq!(replayed.object_count, 1);
        assert!(replayed.legacy);
        let sealed = crate::replayed_secure_journal::replay_secure_journal_exact(
            crate::replayed_secure_journal::JournalReplayInput {
                policy_wires: &[&policy1, &policy2],
                commit_wires: &[&migration],
                checkpoint_wire: &checkpoint,
                workspace_id: &workspace,
                owner_actor_id: &owner,
                owner_signing_key: &owner_key,
                final_sequence: 2,
                final_head: Some(&hash(&migration)),
                final_policy_hash: &hash(&policy2),
                keyring_wire: Some(&keyring),
            },
        )
        .unwrap();
        assert_eq!(sealed.sequence(), 2);
        assert_eq!(sealed.operations().len(), 2);
        assert!(restore_archived_public_history(
            &[&policy1, &policy2],
            &[&migration],
            &workspace,
            None
        )
        .is_err());
        let mut tampered: Value = serde_json::from_slice(&migration).unwrap();
        tampered["signature"] = json!(base64url(&[0; 64]));
        assert!(restore_archived_public_history(
            &[&policy1, &policy2],
            &[&serde_json::to_vec(&tampered).unwrap()],
            &workspace,
            Some(&keyring),
        )
        .is_err());
    }

    #[test]
    fn pinned_typescript_structure_delta_and_snapshot_order_differ() {
        let vector = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/structure-order-vectors.json"),
            32,
            16_384,
        )
        .unwrap();
        let WireValue::Array(objects) = vector.get("objects").unwrap() else {
            panic!("objects array")
        };
        let contract = fields_object(vec![("protocols", WireValue::Array(Vec::new()))]);
        let (mut records, mut heads) = project_structure_data(objects, &contract).unwrap();
        let delta = vector.get("delta").unwrap();
        assert!(same_wire(
            &WireValue::Array(records.clone()),
            delta.get("records").unwrap()
        )
        .unwrap());
        assert!(same_wire(
            &WireValue::Array(heads.clone()),
            delta.get("heads").unwrap()
        )
        .unwrap());
        sort_structure_snapshot(&mut records, &mut heads);
        let snapshot = vector.get("snapshot").unwrap();
        assert!(same_wire(&WireValue::Array(records), snapshot.get("records").unwrap()).unwrap());
        assert!(same_wire(&WireValue::Array(heads), snapshot.get("heads").unwrap()).unwrap());
    }

    #[test]
    fn structure_snapshot_pages_follow_projected_order_and_root() {
        let parse = |value: Value| {
            parse_wire_json_js_bounded(&serde_json::to_vec(&value).unwrap(), 32, 16_384).unwrap()
        };
        let vector: Value = serde_json::from_str(include_str!(
            "../../../conformance/structure-order-vectors.json"
        ))
        .unwrap();
        let objects = parse(vector["objects"].clone());
        let WireValue::Array(prior) = objects else {
            panic!("objects")
        };
        let snapshot_data = parse(vector["snapshot"].clone());
        let root = sha256_hex(
            canonical_wire_value(&snapshot_data, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        );
        let owner = "o".repeat(43);
        let key = "k".repeat(43);
        let workspace = "w".repeat(43);
        let policy_hash = "b".repeat(64);
        let source = json!({"v":1,"workspace_id":workspace,"owner_id":owner,
            "owner_key":key,"sequence":0,"head":null,"policy_hash":policy_hash});
        let snapshot = json!({"source":source,"root":root,"records":0,"heads":2,"offset":0});
        let policy = parse(json!({"payload":{"v":2,"owner_id":owner,"signing_key":key,
            "structure":{"v":1,"protocols":[],"disclosure":[],"instances":[]}}}));
        let operation = parse(json!({"v":1,"kind":"ADMIN","input":{},"objects":[]}));
        let chain = HeaderChainFacts {
            workspace_id: workspace.clone(),
            owner_id: owner.clone(),
            owner_key: key.clone(),
            sequence: 0,
            head: None,
            policy_hash: policy_hash.clone(),
            policy_hashes: Vec::new(),
            policy_effective_sequences: Vec::new(),
            commit_hashes: Vec::new(),
            guard_time_enabled: false,
        };
        let make_context = |sequence: u64, action: &str, mode: &str, offset: u64, heads: Value| {
            let mut page = snapshot.clone();
            page["offset"] = json!(offset);
            parse(json!({"v":2,"sequence":sequence,"action_id":action,
                "actor_id":owner,"signing_key":key,"policy_hash":policy_hash,
                "instance_id":null,"delegation":null,
                "structure":{"v":1,"mode":mode,"records":[],"heads":heads,"snapshot":page}}))
        };
        let mut progress = None;
        let begin = make_context(1, "secure.structure.begin", "SNAPSHOT_BEGIN", 0, json!([]));
        let mut recovery_begin = begin.clone();
        let WireValue::Object(fields) = &mut recovery_begin else {
            panic!("context")
        };
        fields.push((
            "recovery".encode_utf16().collect(),
            WireValue::Object(Vec::new()),
        ));
        assert!(validate_signed_structure_slice(
            &operation,
            &recovery_begin,
            &policy,
            &prior,
            &chain,
            &[],
            &mut progress
        )
        .is_err());
        validate_signed_structure_slice(
            &operation,
            &begin,
            &policy,
            &prior,
            &chain,
            &[],
            &mut progress,
        )
        .unwrap();
        let expected = vector["snapshot"]["heads"].as_array().unwrap();
        let wrong = make_context(
            2,
            "secure.structure.page",
            "SNAPSHOT_PAGE",
            0,
            json!([expected[1].clone()]),
        );
        assert!(validate_signed_structure_slice(
            &operation,
            &wrong,
            &policy,
            &prior,
            &chain,
            &[],
            &mut progress
        )
        .is_err());
        for (index, head) in expected.iter().enumerate() {
            let page = make_context(
                index as u64 + 2,
                "secure.structure.page",
                "SNAPSHOT_PAGE",
                index as u64,
                json!([head]),
            );
            validate_signed_structure_slice(
                &operation,
                &page,
                &policy,
                &prior,
                &chain,
                &[],
                &mut progress,
            )
            .unwrap();
        }
        let end = make_context(4, "secure.structure.end", "SNAPSHOT_END", 2, json!([]));
        // The ordering oracle deliberately has synthetic heads with no
        // corresponding records. PAGE matching succeeds, but a completed
        // structure snapshot must reject those dangling targets.
        assert!(validate_signed_structure_slice(
            &operation,
            &end,
            &policy,
            &prior,
            &chain,
            &[],
            &mut progress,
        )
        .is_err());
        assert!(progress.is_some());
    }

    #[test]
    fn signed_package_stages_bind_compiled_install_to_history() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../conformance/protocol-package-source-vectors.json"
        ))
        .unwrap();
        let case = &vector[0];
        let signer = SigningKey::from_bytes(&[92; 32]);
        let owner_key = key_id(&signer.verifying_key().to_bytes());
        let owner_id = actor_id(&signer.verifying_key().to_bytes());
        let workspace = base64url(&[93; 32]);
        let (_, encryption_public) = DhP256HkdfSha256::gen_keypair();
        let point = encryption_public.to_bytes();
        let encryption = json!({"kty":"EC","crv":"P-256","x":base64url(&point[1..33]),"y":base64url(&point[33..65])});
        let encryption_id = base64url(&sha256(
            canonical(&encryption, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        ));
        let certificate: Value = serde_json::from_slice(&signed(
            json!({"v":1,"actor_id":owner_id,"signing_key":owner_key,"encryption_key":encryption,
                "encryption_key_id":encryption_id,"issued_at":0,"expires_at":1000}),
            "peerwork.secure.key-certificate.v1",
            &signer,
        ))
        .unwrap();
        let policy = signed(
            json!({"v":2,"workspace_id":workspace,"owner_id":owner_id,
            "signing_key":owner_key,"version":1,"previous_policy":null,"effective_sequence":1,
            "visibility":"PRIVATE","epoch":1,"members":[{"actor_id":owner_id,
            "certificate":certificate,"role":"OWNER","scopes":[]}],"issued_at":1,
            "structure":{"v":1,"protocols":[],"disclosure":[],"instances":[]}}),
            "peerwork.secure.policy.v2",
            &signer,
        );
        let policy_hash = hash(&policy);
        let epoch_key = [19u8; 32];
        let keyring = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
            "keys":[{"epoch":1,"key":base64url(&epoch_key)}]}))
        .unwrap();
        let delta = json!({"v":1,"mode":"DELTA","records":[],"heads":[]});
        let make_commit = |sequence: u64,
                           previous: Option<&str>,
                           action: &str,
                           structure: Value,
                           operation: Value,
                           selected_policy_hash: &str| {
            let context = json!({"v":2,"workspace_id":workspace,"sequence":sequence,
                "previous":previous,"policy_hash":selected_policy_hash,"epoch":1,"actor_id":owner_id,
                "signing_key":owner_key,"command_id":base64url(&[sequence as u8;32]),
                "action_id":action,"instance_id":null,"issued_at":sequence,"delegation":null,
                "structure":structure});
            let plaintext = canonical(&operation, Path::SecureArtifact).unwrap();
            let sealed = seal_content_wire(
                &epoch_key,
                plaintext.as_bytes(),
                &serde_json::to_vec(&context).unwrap(),
            )
            .unwrap();
            let mut payload = context;
            payload["mode"] = json!("PRIVATE");
            payload["body"] = serde_json::to_value(sealed).unwrap();
            signed(payload, "peerwork.secure.commit.v2", &signer)
        };
        let bootstrap = make_commit(
            1,
            None,
            "secure.bootstrap",
            delta.clone(),
            json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":[]}),
            &policy_hash,
        );
        let source = json!({"v":1,"workspace_id":workspace,"owner_id":owner_id,
            "owner_key":owner_key,"sequence":1,"head":hash(&bootstrap),"policy_hash":policy_hash});
        let mut proof = case["proof"].clone();
        proof["workspace_id"] = json!(workspace);
        proof["source"] = source.clone();
        let source_id = sha256_hex(
            format!(
                "peerwork.protocol-package-source.v1\0{}",
                canonical(
                    &json!({"source":source,"source_sha256":proof["source_sha256"]}),
                    Path::SecureArtifact
                )
                .unwrap()
            )
            .as_bytes(),
        );
        proof["source_id"] = json!(source_id);
        let part_id = sha256_hex(
            format!(
                "peerwork.protocol-package-part.v1\0{}",
                canonical(
                    &json!({"source":source,"source_id":source_id,"index":0}),
                    Path::SecureArtifact
                )
                .unwrap()
            )
            .as_bytes(),
        );
        proof["parts"][0]["id"] = json!(part_id);
        let mut part = case["parts"][0].clone();
        part["id"] = json!(part_id);
        part["value"]["workspace_id"] = json!(workspace);
        part["value"]["source_id"] = json!(source_id);
        let stage_operation = json!({"v":1,"kind":"ADMIN","input":{"package_stage":{
            "source":source,"source_id":source_id,"part_index":0}},"objects":[part]});
        let stage = make_commit(
            2,
            Some(&hash(&bootstrap)),
            "secure.protocol-package.stage",
            delta,
            stage_operation.clone(),
            &policy_hash,
        );
        let stage_checkpoint = json!({"v":1,"workspace_id":workspace,"owner_id":owner_id,
            "owner_key":owner_key,"sequence":2,"head":hash(&stage),"policy_hash":policy_hash});
        let digest = proof["protocol_digest"].as_str().unwrap().to_owned();
        let manifest = case["result"]["manifest"].clone();
        let protocol = json!({"kind":"protocols","id":digest,"revision":1,
            "provenance":"AUTHOR_SIGNED","value":{"digest":digest,"workspace_id":workspace,
            "manifest":manifest,"resolved_manifest":manifest,"package_source":proof}});
        let instance_id = base64url(&[31; 32]);
        let instance = json!({"kind":"instances","id":instance_id,"revision":1,
            "provenance":"AUTHOR_SIGNED","value":{"id":instance_id,"workspace_id":workspace,
            "protocol_digest":digest,"origin_entrypoint":"proposal","semantics":"peerwork.kernel.v1",
            "state":manifest["initial_state"],"revision":0,"event_revision":0,"created":3,
            "package_source":proof}});
        let manifest_wire =
            parse_wire_json_js_bounded(&serde_json::to_vec(&manifest).unwrap(), 32, 65_536)
                .unwrap();
        let declaration = crate::structure_bindings::protocol_with_default_choices_for_test(
            &digest,
            &manifest_wire,
        );
        let declaration: Value = serde_json::from_str(
            &canonical_wire_value(&declaration, Path::SecureArtifact).unwrap(),
        )
        .unwrap();
        let disclosure: Vec<Value> = declaration["schemas"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(schema, definition)| {
                let fields: Vec<String> = definition["fields"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(_, rule)| rule["protection"] == "server_readable")
                    .map(|(name, _)| name.clone())
                    .collect();
                json!({"protocol_digest":digest,"schema":schema,"fields":fields})
            })
            .collect();
        let structure2 = json!({"v":1,"protocols":[declaration],"disclosure":disclosure,
            "instances":[{"instance_id":instance_id,"protocol_digest":digest}]});
        let mut policy2_payload: Value =
            serde_json::from_slice::<Value>(&policy).unwrap()["payload"].clone();
        policy2_payload["version"] = json!(2);
        policy2_payload["previous_policy"] = json!(policy_hash);
        policy2_payload["effective_sequence"] = json!(3);
        policy2_payload["issued_at"] = json!(3);
        policy2_payload["structure"] = structure2;
        let policy2 = signed(policy2_payload, "peerwork.secure.policy.v2", &signer);
        let policy2_hash = hash(&policy2);
        let install_operation = json!({"v":1,"kind":"ADMIN","input":{"install":{
            "instance_id":instance_id,"protocol_digest":digest,"entrypoint":"proposal"}},
            "objects":[protocol,instance]});
        let empty_structure_root = sha256_hex(
            canonical(&json!({"records":[],"heads":[]}), Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        );
        let snapshot = json!({"v":1,"mode":"SNAPSHOT_BEGIN","records":[],"heads":[],
            "snapshot":{"source":stage_checkpoint,"root":empty_structure_root,
                "records":0,"heads":0,"offset":0}});
        let install = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            snapshot.clone(),
            install_operation.clone(),
            &policy2_hash,
        );
        let owner_pin = OwnerPin {
            actor_id: &owner_id,
            signing_key: &owner_key,
        };
        let empty_checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
            "owner_id":owner_id,"owner_key":owner_key,"sequence":0,"head":null,
            "policy_hash":policy_hash}))
        .unwrap();
        assert!(
            scan_signed_chain_headers(
                &[&policy],
                &[],
                &empty_checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .is_ok(),
            "policy alone"
        );
        for (sequence, commits) in [
            vec![&bootstrap],
            vec![&bootstrap, &stage],
            vec![&bootstrap, &stage, &install],
        ]
        .into_iter()
        .enumerate()
        {
            let policies: Vec<&[u8]> = if sequence == 2 {
                vec![&policy, &policy2]
            } else {
                vec![&policy]
            };
            let checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
                "owner_id":owner_id,"owner_key":owner_key,"sequence":sequence+1,
                "head":hash(commits[sequence]),"policy_hash":if sequence == 2 { &policy2_hash } else { &policy_hash }}))
            .unwrap();
            assert!(
                scan_signed_chain_headers(
                    &policies,
                    &commits
                        .iter()
                        .map(|wire| wire.as_slice())
                        .collect::<Vec<_>>(),
                    &checkpoint,
                    &workspace,
                    Some(&owner_pin),
                    None
                )
                .is_ok(),
                "chain prefix {}",
                sequence + 1
            );
        }
        let check_with_policy =
            |second_policy: &[u8], bootstrap: &[u8], stage: &[u8], install: &[u8]| {
                let checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
                "owner_id":owner_id,"owner_key":owner_key,"sequence":3,"head":hash(install),
                "policy_hash":hash(second_policy)}))
                .unwrap();
                replay_basic_content(
                    &[&policy, second_policy],
                    &[bootstrap, stage, install],
                    &checkpoint,
                    &workspace,
                    Some(&owner_pin),
                    None,
                    Some(&keyring),
                )
            };
        let check = |bootstrap: &[u8], stage: &[u8], install: &[u8]| {
            check_with_policy(&policy2, bootstrap, stage, install)
        };
        assert_eq!(check(&bootstrap, &stage, &install).unwrap().object_count, 3);
        // A direct install omits package_source entirely. It must still
        // reprove the exact initial instance, including fields that generic
        // object/structure binding does not constrain.
        let mut direct_operation = install_operation.clone();
        direct_operation["objects"][0]["value"]
            .as_object_mut()
            .unwrap()
            .remove("package_source");
        direct_operation["objects"][1]["value"]
            .as_object_mut()
            .unwrap()
            .remove("package_source");
        let direct_install = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            snapshot.clone(),
            direct_operation.clone(),
            &policy2_hash,
        );
        assert_eq!(
            check(&bootstrap, &stage, &direct_install)
                .unwrap()
                .object_count,
            3
        );
        for field in ["state", "origin_entrypoint", "created"] {
            let mut altered = direct_operation.clone();
            altered["objects"][1]["value"][field] = match field {
                "state" => json!({"tampered":true}),
                "origin_entrypoint" => json!("other"),
                _ => json!(999),
            };
            let signed_altered = make_commit(
                3,
                Some(&hash(&stage)),
                "secure.structure.begin",
                snapshot.clone(),
                altered,
                &policy2_hash,
            );
            assert!(
                check(&bootstrap, &stage, &signed_altered).is_err(),
                "{field}"
            );
        }
        let missing_upgrade_snapshot = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            json!({"v":1,"mode":"DELTA","records":[],"heads":[]}),
            install_operation.clone(),
            &policy2_hash,
        );
        assert!(check(&bootstrap, &stage, &missing_upgrade_snapshot).is_err());
        let mut wrong_policy_payload: Value =
            serde_json::from_slice::<Value>(&policy2).unwrap()["payload"].clone();
        wrong_policy_payload["structure"]["instances"] = json!([]);
        let wrong_policy = signed(wrong_policy_payload, "peerwork.secure.policy.v2", &signer);
        let wrong_policy_hash = hash(&wrong_policy);
        let wrong_policy_install = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            snapshot.clone(),
            install_operation.clone(),
            &wrong_policy_hash,
        );
        assert!(
            check_with_policy(&wrong_policy, &bootstrap, &stage, &wrong_policy_install).is_err()
        );
        let mut end_envelope = snapshot.clone();
        end_envelope["mode"] = json!("SNAPSHOT_END");
        let end_operation = json!({"v":1,"kind":"ADMIN","input":{},"objects":[]});
        let end = make_commit(
            4,
            Some(&hash(&install)),
            "secure.structure.end",
            end_envelope.clone(),
            end_operation.clone(),
            &policy2_hash,
        );
        let end_checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
            "owner_id":owner_id,"owner_key":owner_key,"sequence":4,"head":hash(&end),
            "policy_hash":policy2_hash}))
        .unwrap();
        assert_eq!(
            replay_basic_content(
                &[&policy, &policy2],
                &[&bootstrap, &stage, &install, &end],
                &end_checkpoint,
                &workspace,
                Some(&owner_pin),
                None,
                Some(&keyring),
            )
            .unwrap()
            .object_count,
            3,
        );
        // A later snapshot ADMIN cannot carry a package-sourced instance
        // revision as if it were a fresh install. The strict BEGIN validator
        // must still run for a nonempty snapshot operation.
        let mut carried_instance = install_operation["objects"][1].clone();
        carried_instance["revision"] = json!(2);
        carried_instance["value"]["revision"] = json!(1);
        let wrong_end_with_object = make_commit(
            4,
            Some(&hash(&install)),
            "secure.structure.end",
            end_envelope.clone(),
            json!({"v":1,"kind":"ADMIN","input":{},"objects":[carried_instance]}),
            &policy2_hash,
        );
        let wrong_end_with_object_checkpoint = serde_json::to_vec(&json!({"v":1,
            "workspace_id":workspace,"owner_id":owner_id,"owner_key":owner_key,
            "sequence":4,"head":hash(&wrong_end_with_object),"policy_hash":policy2_hash}))
        .unwrap();
        assert!(replay_basic_content(
            &[&policy, &policy2],
            &[&bootstrap, &stage, &install, &wrong_end_with_object],
            &wrong_end_with_object_checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&keyring),
        )
        .is_err());
        end_envelope["snapshot"]["offset"] = json!(1);
        let wrong_end = make_commit(
            4,
            Some(&hash(&install)),
            "secure.structure.end",
            end_envelope,
            end_operation,
            &policy2_hash,
        );
        let wrong_end_checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
            "owner_id":owner_id,"owner_key":owner_key,"sequence":4,"head":hash(&wrong_end),
            "policy_hash":policy2_hash}))
        .unwrap();
        assert!(replay_basic_content(
            &[&policy, &policy2],
            &[&bootstrap, &stage, &install, &wrong_end],
            &wrong_end_checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&keyring),
        )
        .is_err());
        let final_checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
            "owner_id":owner_id,"owner_key":owner_key,"sequence":3,"head":hash(&install),
            "policy_hash":policy2_hash}))
        .unwrap();
        let chain = scan_signed_chain_headers(
            &[&policy, &policy2],
            &[&bootstrap, &stage, &install],
            &final_checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
        )
        .unwrap();
        let signed_stage =
            parse_wire_json_js_bounded(&serde_json::to_vec(&stage_operation).unwrap(), 64, 196_608)
                .unwrap();
        let signed_install = parse_wire_json_js_bounded(
            &serde_json::to_vec(&install_operation).unwrap(),
            64,
            196_608,
        )
        .unwrap();
        let install_commit = parse_wire_json_js_bounded(&install, 64, 196_608).unwrap();
        let prior_part = signed_stage.get("objects").unwrap();
        let WireValue::Array(prior_parts) = prior_part else {
            panic!("stage part array")
        };
        // A recovered earlier commit is omitted from journal.operations, but
        // the signed sequence/checkpoint and contiguous stage suffix remain.
        assert!(validate_signed_package_install(
            &signed_install,
            install_commit.get("payload").unwrap(),
            prior_parts,
            &[signed_stage.clone()],
            &chain,
            &[&bootstrap, &stage, &install],
            &workspace,
            None,
        )
        .is_ok());
        let composition_vectors: Value = serde_json::from_str(include_str!(
            "../../../conformance/protocol-composition-vectors.json"
        ))
        .unwrap();
        let composed = composition_vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "action_dependency")
            .unwrap();
        let mut composed_operation = install_operation.clone();
        let composed_digest = composed["result"]["digest"].clone();
        let composed_manifest = composed["result"]["manifest"].clone();
        composed_operation["input"]["install"]["protocol_digest"] = composed_digest.clone();
        composed_operation["objects"][0]["id"] = composed_digest.clone();
        composed_operation["objects"][0]["value"]["digest"] = composed_digest.clone();
        composed_operation["objects"][0]["value"]["manifest"] = composed_manifest.clone();
        composed_operation["objects"][0]["value"]["resolved_manifest"] = composed_manifest.clone();
        composed_operation["objects"][0]["value"]["composition"] =
            composed["result"]["composition"].clone();
        composed_operation["objects"][0]["value"]
            .as_object_mut()
            .unwrap()
            .remove("package_source");
        composed_operation["objects"][1]["value"]["protocol_digest"] = composed_digest;
        composed_operation["objects"][1]["value"]["state"] =
            composed_manifest["initial_state"].clone();
        composed_operation["objects"][1]["value"]
            .as_object_mut()
            .unwrap()
            .remove("package_source");
        let check_composed = |operation: &Value| {
            let wire =
                parse_wire_json_js_bounded(&serde_json::to_vec(operation).unwrap(), 64, 196_608)
                    .unwrap();
            validate_signed_package_install(
                &wire,
                install_commit.get("payload").unwrap(),
                prior_parts,
                &[signed_stage.clone()],
                &chain,
                &[&bootstrap, &stage, &install],
                &workspace,
                None,
            )
        };
        assert!(check_composed(&composed_operation).is_ok());
        for field in ["state", "origin_entrypoint", "created"] {
            let mut altered = composed_operation.clone();
            altered["objects"][1]["value"][field] = match field {
                "state" => json!({"tampered":true}),
                "origin_entrypoint" => json!("other"),
                _ => json!(999),
            };
            assert!(check_composed(&altered).is_err(), "composed {field}");
        }
        let mut wrong_snapshot = snapshot.clone();
        wrong_snapshot["snapshot"]["root"] = json!("a".repeat(64));
        let wrong_install = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            wrong_snapshot,
            install_operation.clone(),
            &policy2_hash,
        );
        assert!(check(&bootstrap, &stage, &wrong_install).is_err());
        // In v3 the complete logical protocol value can be staged after the
        // package and the install commit signs only its source reference.
        let mut policy3_payload: Value =
            serde_json::from_slice::<Value>(&policy).unwrap()["payload"].clone();
        policy3_payload["v"] = json!(3);
        policy3_payload["structure_mode"] = json!("STRUCTURED");
        policy3_payload["protocol_format_ceiling"] = json!(1);
        let policy3 = signed(policy3_payload, "peerwork.secure.policy.v3", &signer);
        let policy3_hash = hash(&policy3);
        let make_v3 = |sequence: u64,
                       previous: Option<&str>,
                       action: &str,
                       structure: Value,
                       operation: Value,
                       selected_policy_hash: &str| {
            let context = json!({"v":3,"workspace_id":workspace,"sequence":sequence,
                "previous":previous,"policy_hash":selected_policy_hash,"epoch":1,"actor_id":owner_id,
                "signing_key":owner_key,"command_id":base64url(&[sequence as u8 + 50;32]),
                "action_id":action,"instance_id":null,"issued_at":sequence,"delegation":null,
                "protocol_format_ceiling":1,"structure":structure});
            let plaintext = canonical(&operation, Path::SecureArtifact).unwrap();
            let sealed = seal_content_wire(
                &epoch_key,
                plaintext.as_bytes(),
                &serde_json::to_vec(&context).unwrap(),
            )
            .unwrap();
            let mut payload = context;
            payload["mode"] = json!("PRIVATE");
            payload["body"] = serde_json::to_value(sealed).unwrap();
            signed(payload, "peerwork.secure.commit.v3", &signer)
        };
        let delta3 = json!({"v":1,"mode":"DELTA","records":[],"heads":[]});
        let bootstrap3 = make_v3(
            1,
            None,
            "secure.bootstrap",
            delta3.clone(),
            json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":[]}),
            &policy3_hash,
        );
        let source3 = json!({"v":1,"workspace_id":workspace,"owner_id":owner_id,
            "owner_key":owner_key,"sequence":1,"head":hash(&bootstrap3),"policy_hash":policy3_hash});
        let mut proof3 = case["proof"].clone();
        proof3["workspace_id"] = json!(workspace);
        proof3["source"] = source3.clone();
        let package_id3 = sha256_hex(
            format!(
                "peerwork.protocol-package-source.v1\0{}",
                canonical(
                    &json!({"source":source3,"source_sha256":proof3["source_sha256"]}),
                    Path::SecureArtifact
                )
                .unwrap()
            )
            .as_bytes(),
        );
        proof3["source_id"] = json!(package_id3);
        let package_part_id3 = sha256_hex(
            format!(
                "peerwork.protocol-package-part.v1\0{}",
                canonical(
                    &json!({"source":source3,"source_id":package_id3,"index":0}),
                    Path::SecureArtifact
                )
                .unwrap()
            )
            .as_bytes(),
        );
        proof3["parts"][0]["id"] = json!(package_part_id3);
        let mut package_part3 = case["parts"][0].clone();
        package_part3["id"] = json!(package_part_id3);
        package_part3["value"]["workspace_id"] = json!(workspace);
        package_part3["value"]["source_id"] = json!(package_id3);
        let stage3 = make_v3(
            2,
            Some(&hash(&bootstrap3)),
            "secure.protocol-package.stage",
            delta3.clone(),
            json!({"v":1,"kind":"ADMIN","input":{"package_stage":{
                "source":source3,"source_id":package_id3,"part_index":0}},"objects":[package_part3]}),
            &policy3_hash,
        );
        let object_source = json!({"v":1,"workspace_id":workspace,"owner_id":owner_id,
            "owner_key":owner_key,"sequence":2,"head":hash(&stage3),"policy_hash":policy3_hash});
        let mut logical_value = install_operation["objects"][0]["value"].clone();
        logical_value["package_source"] = proof3.clone();
        let value_text = canonical(&logical_value, Path::SecureArtifact).unwrap();
        let value_sha = sha256_hex(value_text.as_bytes());
        let object_source_id = sha256_hex(format!("peerwork.protocol-object-source.v1\0{}",
            canonical(&json!({"source":object_source,"protocol_digest":digest,"value_sha256":value_sha}),
                Path::SecureArtifact).unwrap()).as_bytes());
        let object_part_id = sha256_hex(
            format!(
                "peerwork.protocol-object-part.v1\0{}",
                canonical(
                    &json!({"source":object_source,"source_id":object_source_id,"index":0}),
                    Path::SecureArtifact
                )
                .unwrap()
            )
            .as_bytes(),
        );
        let object_proof = json!({"v":1,"workspace_id":workspace,"source":object_source,
            "source_id":object_source_id,"protocol_digest":digest,"value_sha256":value_sha,
            "bytes":value_text.len(),"parts":[{"id":object_part_id,"index":0,"sha256":value_sha,"bytes":value_text.len()}]});
        let object_part = json!({"kind":"protocol_object_part","id":object_part_id,"revision":1,
            "provenance":"AUTHOR_SIGNED","value":{"v":1,"workspace_id":workspace,
                "source_id":object_source_id,"index":0,"bytes":value_text.len(),
                "sha256":value_sha,"text":value_text}});
        let object_stage_operation = json!({"v":1,"kind":"ADMIN","input":{
            "protocol_object_stage":{"proof":object_proof,"part_index":0}},"objects":[object_part]});
        let object_stage = make_v3(
            3,
            Some(&hash(&stage3)),
            "secure.protocol-object.stage",
            delta3,
            object_stage_operation,
            &policy3_hash,
        );
        let object_checkpoint = json!({"v":1,"workspace_id":workspace,"owner_id":owner_id,
            "owner_key":owner_key,"sequence":3,"head":hash(&object_stage),"policy_hash":policy3_hash});
        let mut instance3 = install_operation["objects"][1].clone();
        instance3["value"]["package_source"] = proof3;
        instance3["value"]["created"] = json!(4);
        let reference = json!({"kind":"protocols","id":digest,"revision":1,
            "provenance":"AUTHOR_SIGNED","value":{"workspace_id":workspace,"digest":digest,
                "object_source":object_proof}});
        let reference_install = json!({"v":1,"kind":"ADMIN","input":{"install":{
            "instance_id":instance_id,"protocol_digest":digest,"entrypoint":"proposal"}},
            "objects":[reference,instance3]});
        let mut policy3b_payload: Value =
            serde_json::from_slice::<Value>(&policy3).unwrap()["payload"].clone();
        policy3b_payload["version"] = json!(2);
        policy3b_payload["previous_policy"] = json!(policy3_hash);
        policy3b_payload["effective_sequence"] = json!(4);
        policy3b_payload["issued_at"] = json!(4);
        policy3b_payload["structure"] =
            serde_json::from_slice::<Value>(&policy2).unwrap()["payload"]["structure"].clone();
        let policy3b = signed(policy3b_payload, "peerwork.secure.policy.v3", &signer);
        let policy3b_hash = hash(&policy3b);
        let snapshot3 = json!({"v":1,"mode":"SNAPSHOT_BEGIN","records":[],"heads":[],
            "snapshot":{"source":object_checkpoint,
                "root":empty_structure_root,
                "records":0,"heads":0,"offset":0}});
        let install3 = make_v3(
            4,
            Some(&hash(&object_stage)),
            "secure.structure.begin",
            snapshot3.clone(),
            reference_install.clone(),
            &policy3b_hash,
        );
        let check_v3 = |object_stage: &[u8], install: &[u8]| {
            let checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,
                "owner_id":owner_id,"owner_key":owner_key,"sequence":4,"head":hash(install),
                "policy_hash":policy3b_hash}))
            .unwrap();
            replay_basic_content(
                &[&policy3, &policy3b],
                &[&bootstrap3, &stage3, object_stage, install],
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None,
                Some(&keyring),
            )
        };
        assert_eq!(check_v3(&object_stage, &install3).unwrap().object_count, 4);
        let mut wrong_reference = reference_install;
        wrong_reference["objects"][0]["value"]["object_source"]["value_sha256"] =
            json!("0".repeat(64));
        let wrong_install = make_v3(
            4,
            Some(&hash(&object_stage)),
            "secure.structure.begin",
            snapshot3,
            wrong_reference,
            &policy3b_hash,
        );
        assert!(check_v3(&object_stage, &wrong_install).is_err());
        let mut changed = install_operation.clone();
        changed["objects"][1]["value"]["package_source"]["protocol_digest"] = json!("0".repeat(64));
        let changed_install = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            snapshot.clone(),
            changed,
            &policy2_hash,
        );
        assert!(check(&bootstrap, &stage, &changed_install).is_err());
        let mut missing_instance_proof = install_operation.clone();
        missing_instance_proof["objects"][1]["value"]
            .as_object_mut()
            .unwrap()
            .remove("package_source");
        let changed_install = make_commit(
            3,
            Some(&hash(&stage)),
            "secure.structure.begin",
            snapshot.clone(),
            missing_instance_proof,
            &policy2_hash,
        );
        assert!(check(&bootstrap, &stage, &changed_install).is_err());
        let mut changed_part = stage_operation.clone();
        changed_part["objects"][0]["value"]["text"] = json!("not the retained package");
        let changed_stage = make_commit(
            2,
            Some(&hash(&bootstrap)),
            "secure.protocol-package.stage",
            json!({"v":1,"mode":"DELTA","records":[],"heads":[]}),
            changed_part,
            &policy_hash,
        );
        let changed_install = make_commit(
            3,
            Some(&hash(&changed_stage)),
            "secure.structure.begin",
            snapshot.clone(),
            install_operation.clone(),
            &policy2_hash,
        );
        assert!(check(&bootstrap, &changed_stage, &changed_install).is_err());
        let mut changed_stage = stage_operation;
        changed_stage["input"]["package_stage"]["source"]["head"] = json!("0".repeat(64));
        let changed_stage = make_commit(
            2,
            Some(&hash(&bootstrap)),
            "secure.protocol-package.stage",
            json!({"v":1,"mode":"DELTA","records":[],"heads":[]}),
            changed_stage,
            &policy_hash,
        );
        let changed_install = make_commit(
            3,
            Some(&hash(&changed_stage)),
            "secure.structure.begin",
            snapshot,
            install_operation,
            &policy2_hash,
        );
        assert!(check(&bootstrap, &changed_stage, &changed_install).is_err());
    }

    #[test]
    fn legacy_grant_history_survives_absent_member_and_superseded_grant() {
        let wire = |value: Value| {
            parse_wire_json_js_bounded(&serde_json::to_vec(&value).unwrap(), 32, 64_000).unwrap()
        };
        let protocol = wire(json!({
            "kind":"protocols","id":"p","revision":1,
            "value":{"digest":"p","manifest":{
                "role_conflicts":[],"historical_role_conflicts":[["reviewer","approver"]]
            }}
        }));
        let instance = wire(json!({
            "kind":"instances","id":"i","revision":1,
            "value":{"protocol_digest":"p"}
        }));
        let grant = wire(json!({
            "kind":"grants","id":"g","revision":1,
            "value":{"instance_id":"i","protocol_digest":"p",
                "actor_id":"a","protocol_roles":["reviewer"]}
        }));
        let empty_members = wire(json!({"members":[]}));
        let mut history = RoleHistory::new();
        validate_role_policies_with_history(
            &empty_members,
            &[protocol.clone(), instance.clone(), grant],
            1,
            None,
            &mut history,
        )
        .unwrap();
        assert!(history
            .get(&(vec![105], vec![112], vec![97]))
            .is_some_and(|roles| roles.contains(&"reviewer".encode_utf16().collect::<Vec<_>>())));

        let superseding_grant = wire(json!({
            "kind":"grants","id":"g","revision":2,
            "value":{"instance_id":"i","protocol_digest":"p",
                "actor_id":"a","protocol_roles":[]}
        }));
        let readmitted = wire(json!({"members":[{
            "actor_id":"a","scopes":[{"instance_id":"i","protocol_roles":["approver"]}]
        }]}));
        assert_eq!(
            validate_role_policies_with_history(
                &readmitted,
                &[protocol, instance, superseding_grant],
                2,
                Some(&[105]),
                &mut history,
            ),
            Err("HISTORICAL_ROLE_CONFLICT")
        );
    }

    #[test]
    fn historical_format_two_source_requires_ceiling_and_normalized_signed_value() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../conformance/manifest-vectors.json"))
                .unwrap();
        let source = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "state_array_utf16_sort_valid")
            .unwrap()["manifest"]
            .clone();
        let digest = sha256_hex(
            canonical(
                &json!({"semantics":"peerwork.kernel.v1","manifest":source}),
                Path::SecureArtifact,
            )
            .unwrap()
            .as_bytes(),
        );
        let make_object = |manifest: Value| {
            let value = json!({
                "kind":"protocols","id":digest,"revision":1,
                "provenance":"AUTHOR_SIGNED",
                "value":{"digest":digest,"workspace_id":"workspace",
                    "manifest":manifest,"resolved_manifest":manifest}
            });
            parse_wire_json_js_bounded(&serde_json::to_vec(&value).unwrap(), 32, 128_000).unwrap()
        };
        let valid = make_object(source.clone());
        assert!(validate_authored_protocol_simple(&valid, "workspace", 2).is_ok());
        assert!(validate_authored_protocol_simple(&valid, "workspace", 1).is_err());
        let mut omitted_default = source;
        omitted_default
            .as_object_mut()
            .unwrap()
            .remove("capabilities");
        assert!(
            validate_authored_protocol_simple(&make_object(omitted_default), "workspace", 2,)
                .is_err()
        );
    }

    #[test]
    fn pinned_typescript_historical_protocol_source_encodings() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/historical-protocol-vectors.json").as_bytes(),
            64,
            1_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("vector array")
        };
        for case in cases {
            let name = string(&case, "name").unwrap();
            let result = validate_authored_protocol_simple(
                case.get("object").unwrap(),
                &string(&case, "workspace_id").unwrap(),
                integer(&case, "format").unwrap(),
            );
            assert_eq!(result.is_ok(), case.get("result").is_some(), "{name}");
        }
    }

    #[test]
    fn pinned_typescript_secure_engine_admin_preflight() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/secure-engine-vectors.json").as_bytes(),
            64,
            1_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("vector array")
        };
        for case in cases {
            let name = string(&case, "name").unwrap();
            if name.starts_with("action_") {
                continue;
            }
            let mut prior = HashMap::new();
            if let Some(WireValue::Array(objects)) = case.get("prior") {
                for object in objects {
                    let kind = utf16(object, "kind").unwrap();
                    let id = utf16(object, "id").unwrap();
                    let pair = canonical_wire_value(
                        &WireValue::Array(vec![
                            WireValue::String(kind.to_vec()),
                            WireValue::String(id.to_vec()),
                        ]),
                        Path::SecureArtifact,
                    )
                    .unwrap();
                    prior.insert(pair, integer(object, "revision").unwrap());
                }
            }
            let result = validate_admin_preflight(
                case.get("operation").unwrap(),
                case.get("context").unwrap(),
                &prior,
            );
            if let Some(error) = case.get("error") {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    error.as_string().unwrap(),
                    "{name}"
                );
            } else {
                assert_eq!(result, Ok(()), "{name}");
            }
        }
    }

    #[test]
    fn pinned_typescript_secure_engine_action_state_slice() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/secure-engine-vectors.json").as_bytes(),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else {
            panic!("vector array")
        };
        for case in cases {
            let name = string(&case, "name").unwrap();
            if !name.starts_with("action_") {
                continue;
            }
            let prior = match case.get("prior") {
                Some(WireValue::Array(values)) => values,
                _ => panic!("prior"),
            };
            let result = validate_action_state_slice(
                case.get("operation").unwrap(),
                case.get("context").unwrap(),
                case.get("policy").unwrap(),
                prior,
            );
            if let Some(error) = case.get("error") {
                assert_eq!(result.unwrap_err(), error.as_string().unwrap(), "{name}");
            } else {
                assert_eq!(result, Ok(()), "{name}");
            }
        }
    }

    #[test]
    fn guarded_action_replay_uses_proof_time_without_rewriting_signed_issued_at() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/secure-engine-vectors.json").as_bytes(),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = cases else { panic!("vector array") };
        let case = cases.iter().find(|case| {
            case.get("name").and_then(WireValue::as_string).as_deref()
                == Some("action_control_revision")
        }).unwrap();
        let to_json = |value: &WireValue| -> Value {
            serde_json::from_str(&canonical_wire_value(value, Path::SecureArtifact).unwrap()).unwrap()
        };
        let operation = to_json(case.get("operation").unwrap());
        let mut context = to_json(case.get("context").unwrap());
        let mut policy = to_json(case.get("policy").unwrap());
        let mut prior = to_json(case.get("prior").unwrap());
        let guards = &mut prior[0]["value"]["resolved_manifest"]["actions"][0]["variants"][0]["when"];
        guards.as_array_mut().unwrap().push(json!({"op":"gte","left":{"from":"time"},"right":{"from":"literal","value":5}}));
        guards.as_array_mut().unwrap().push(json!({"op":"lte","left":{"from":"time"},"right":{"from":"literal","value":9}}));
        policy["payload"]["guard_time"] = json!({"v":1,"mode":"ALL_COMMITS","audience":"test.example","service_key":"S".repeat(43),"disclosure":"GUARD_WINDOW"});
        context["guard_time"] = json!({"v":1,"lower_ms":5,"upper_ms":9});
        let parse = |value: &Value| parse_wire_json_js_bounded(&serde_json::to_vec(value).unwrap(), 64, 2_000_000).unwrap();
        let operation = parse(&operation);
        let context = parse(&context);
        let policy = parse(&policy);
        let prior = match parse(&prior) { WireValue::Array(items) => items, _ => panic!("prior objects") };
        let before_issued_at = context.get("issued_at").unwrap().clone();
        assert_eq!(validate_action_state_slice_at_time(&operation, &context, &policy, &prior, Some(7)), Ok(()));
        assert_eq!(context.get("issued_at"), Some(&before_issued_at));
        assert!(validate_action_state_slice_at_time(&operation, &context, &policy, &prior, Some(4)).is_err());

        let mut expiring_policy = to_json(&policy);
        expiring_policy["payload"]["members"][0]["scopes"][0]["expires_at"] = json!(6);
        let mut at_t_context = to_json(&context);
        at_t_context["issued_at"] = json!(7);
        let expiring_policy = parse(&expiring_policy);
        let at_t_context = parse(&at_t_context);
        let checked_at_t = crate::secure_action_delegation::resolve_action_scope(
            &at_t_context,
            expiring_policy.get("payload").unwrap(),
            None,
        )
        .unwrap();
        assert!(!checked_at_t.permits_action(), "a scope that expired before T cannot authorize replay");

        let mut widened = to_json(&context);
        widened["guard_time"] = json!({"v":1,"lower_ms":0,"upper_ms":9});
        assert!(validate_action_state_slice_at_time(&operation, &parse(&widened), &policy, &prior, Some(7)).is_err());
        let mut tampered = to_json(&operation);
        tampered["objects"][0]["value"]["state"]["count"] = json!(99);
        assert!(validate_action_state_slice_at_time(&parse(&tampered), &context, &policy, &prior, Some(7)).is_err());

        let delegated_vectors = parse_wire_json_js_bounded(
            include_str!("../../../conformance/action-delegation-vectors.json").as_bytes(),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(delegated_vectors) = delegated_vectors else { panic!("delegation vectors") };
        let delegated = delegated_vectors.iter().find(|item| {
            item.get("name").and_then(WireValue::as_string).as_deref() == Some("valid_delegated")
        }).unwrap();
        let mut delegated_context = to_json(delegated.get("context").unwrap());
        let mut delegated_policy = to_json(delegated.get("policy_payload").unwrap());
        let mut delegated_operation = to_json(case.get("operation").unwrap());
        let mut delegated_prior = to_json(case.get("prior").unwrap());
        delegated_context["action_id"] = json!("alpha");
        delegated_context["guard_time"] = json!({"v":1,"lower_ms":0,"upper_ms":9_007_199_254_740_991u64});
        delegated_policy["guard_time"] = json!({"v":1,"mode":"ALL_COMMITS","audience":"test.example","service_key":"S".repeat(43),"disclosure":"GUARD_WINDOW"});
        delegated_operation["input"]["action_id"] = json!("alpha");
        delegated_prior[0]["value"]["resolved_manifest"]["actions"][0]["id"] = json!("alpha");
        let delegated_context = parse(&delegated_context);
        let delegated_policy = parse(&json!({"payload":delegated_policy}));
        let delegated_operation = parse(&delegated_operation);
        let delegated_prior = match parse(&delegated_prior) { WireValue::Array(items) => items, _ => panic!("prior") };
        assert_eq!(integer(&delegated_context, "issued_at").unwrap(), 30);
        assert_eq!(validate_action_state_slice_at_time(&delegated_operation, &delegated_context, &delegated_policy, &delegated_prior, None), Ok(()), "R=0 preparation must retain a valid delegated issued_at=30");
    }

    #[test]
    fn signed_encrypted_action_replay_binds_policy_source_and_effects() {
        let vectors = parse_wire_json_js_bounded(
            include_str!("../../../conformance/secure-engine-vectors.json").as_bytes(),
            64,
            2_000_000,
        )
        .unwrap();
        let WireValue::Array(cases) = vectors else {
            panic!("vector array")
        };
        let case = cases
            .iter()
            .find(|case| {
                case.get("name").and_then(WireValue::as_string).as_deref()
                    == Some("action_control_revision")
            })
            .unwrap();
        let to_json = |value: &WireValue| -> Value {
            serde_json::from_str(&canonical_wire_value(value, Path::SecureArtifact).unwrap())
                .unwrap()
        };
        let mut base_prior = to_json(case.get("prior").unwrap());
        let mut base_action = to_json(case.get("operation").unwrap());
        let owner_keypair = SigningKey::from_bytes(&[92; 32]);
        let owner_key = key_id(&owner_keypair.verifying_key().to_bytes());
        let owner = actor_id(&owner_keypair.verifying_key().to_bytes());
        let workspace = base_prior[1]["value"]["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let instance = base_prior[1]["id"].as_str().unwrap().to_owned();
        let manifest = &mut base_prior[0]["value"]["resolved_manifest"];
        manifest["name"] = json!("test");
        manifest["display_version"] = json!("1");
        manifest["semantics"] = json!("peerwork.kernel.v1");
        manifest["dependencies"] = json!([]);
        manifest["initial_state"] = json!({"count":0});
        let raw_manifest = manifest.clone();
        let protocol_digest = sha256_hex(
            canonical(
                &json!({"semantics":"peerwork.kernel.v1","manifest":raw_manifest}),
                Path::SecureArtifact,
            )
            .unwrap()
            .as_bytes(),
        );
        base_prior[0]["id"] = json!(protocol_digest);
        base_prior[0]["value"]["digest"] = json!(protocol_digest);
        base_prior[0]["value"]["workspace_id"] = json!(workspace);
        base_prior[0]["value"]["manifest"] = raw_manifest;
        base_prior[1]["value"]["protocol_digest"] = json!(protocol_digest);
        base_action["objects"][0]["value"]["protocol_digest"] = json!(protocol_digest);
        let (_, encryption_public) = DhP256HkdfSha256::gen_keypair();
        let point = encryption_public.to_bytes();
        let encryption = json!({"kty":"EC","crv":"P-256","x":base64url(&point[1..33]),"y":base64url(&point[33..65])});
        let encryption_id = base64url(&sha256(
            canonical(&encryption, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        ));
        let certificate: Value = serde_json::from_slice(&signed(
            json!({"v":1,"actor_id":owner,"signing_key":owner_key,"encryption_key":encryption,"encryption_key_id":encryption_id,"issued_at":0,"expires_at":1000}),
            "peerwork.secure.key-certificate.v1", &owner_keypair,
        )).unwrap();
        let epoch_key = [19u8; 32];
        let keyring = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,"keys":[{"epoch":1,"key":base64url(&epoch_key)}]})).unwrap();
        let run = |label: &str,
                   prior: Value,
                   action: Value,
                   allowed: bool,
                   role_change: bool|
         -> Result<ReplayFacts, ReplayError> {
            let scopes = if allowed {
                json!([{"instance_id":null,"actions":["test.set"],"protocol_roles":if role_change {vec!["reviewer"]} else {vec![]},"capabilities":[]}])
            } else {
                json!([{"instance_id":null,"actions":["other.action"],"protocol_roles":[],"capabilities":[]}])
            };
            let policy = signed(
                json!({"v":1,"workspace_id":workspace,"owner_id":owner,"signing_key":owner_key,"version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PRIVATE","epoch":1,"members":[{"actor_id":owner,"certificate":certificate,"role":"OWNER","scopes":scopes}],"issued_at":1}),
                "peerwork.secure.policy.v1",
                &owner_keypair,
            );
            let rotated = role_change.then(|| signed(
                json!({"v":1,"workspace_id":workspace,"owner_id":owner,"signing_key":owner_key,"version":2,"previous_policy":hash(&policy),"effective_sequence":2,"visibility":"PRIVATE","epoch":1,"members":[{"actor_id":owner,"certificate":certificate,"role":"OWNER","scopes":[{"instance_id":null,"actions":["test.set"],"protocol_roles":["approver"],"capabilities":[]}]}],"issued_at":2}),
                "peerwork.secure.policy.v1", &owner_keypair,
            ));
            let action_policy = rotated.as_ref().unwrap_or(&policy);
            let mut policy_wires: Vec<&[u8]> = vec![&policy];
            if let Some(rotated) = &rotated {
                policy_wires.push(rotated);
            }
            let context1 = json!({"v":1,"workspace_id":workspace,"sequence":1,"previous":null,"policy_hash":hash(&policy),"epoch":1,"actor_id":owner,"signing_key":owner_key,"command_id":base64url(&[21;32]),"action_id":"test.admin","instance_id":null,"issued_at":1,"delegation":null});
            let admin = json!({"v":1,"kind":"ADMIN","input":{},"objects":prior});
            let plaintext1 = canonical(&admin, Path::SecureArtifact).unwrap();
            let sealed1 = seal_content_wire(
                &epoch_key,
                plaintext1.as_bytes(),
                &serde_json::to_vec(&context1).unwrap(),
            )
            .unwrap();
            let mut payload1 = context1;
            payload1["mode"] = json!("PRIVATE");
            payload1["body"] = serde_json::to_value(sealed1).unwrap();
            let commit1 = signed(payload1, "peerwork.secure.commit.v1", &owner_keypair);
            let context2 = json!({"v":1,"workspace_id":workspace,"sequence":2,"previous":hash(&commit1),"policy_hash":hash(action_policy),"epoch":1,"actor_id":owner,"signing_key":owner_key,"command_id":base64url(&[22;32]),"action_id":"test.set","instance_id":instance,"issued_at":2,"delegation":null});
            let action_context = context2.clone();
            let plaintext2 = canonical(&action, Path::SecureArtifact).unwrap();
            let sealed2 = seal_content_wire(
                &epoch_key,
                plaintext2.as_bytes(),
                &serde_json::to_vec(&context2).unwrap(),
            )
            .unwrap();
            let mut payload2 = context2;
            payload2["mode"] = json!("PRIVATE");
            payload2["body"] = serde_json::to_value(sealed2).unwrap();
            let commit2 = signed(payload2, "peerwork.secure.commit.v1", &owner_keypair);
            let checkpoint = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,"sequence":2,"head":hash(&commit2),"policy_hash":hash(action_policy)})).unwrap();
            let headers = scan_signed_chain_headers(
                &policy_wires,
                &[&commit1, &commit2],
                &checkpoint,
                &workspace,
                Some(&OwnerPin {
                    actor_id: &owner,
                    signing_key: &owner_key,
                }),
                None,
            );
            assert_eq!(headers.is_ok(), label != "policy", "{label} header result");
            if role_change {
                let op = parse_wire_json_js_bounded(plaintext2.as_bytes(), 64, MAX_CONTENT_BYTES)
                    .unwrap();
                let context = parse_wire_json_js_bounded(
                    &serde_json::to_vec(&action_context).unwrap(),
                    64,
                    196_608,
                )
                .unwrap();
                let policy =
                    parse_wire_json_js_bounded(action_policy, 64, 32 * 1024 * 1024).unwrap();
                let prior = parse_wire_json_js_bounded(
                    &serde_json::to_vec(&admin["objects"]).unwrap(),
                    64,
                    MAX_CONTENT_BYTES,
                )
                .unwrap();
                let WireValue::Array(prior) = prior else {
                    panic!("prior objects")
                };
                assert_eq!(
                    validate_action_state_slice(&op, &context, &policy, &prior),
                    Ok(()),
                    "current policy alone must not explain the historical conflict"
                );
            }
            replay_basic_content(
                &policy_wires,
                &[&commit1, &commit2],
                &checkpoint,
                &workspace,
                Some(&OwnerPin {
                    actor_id: &owner,
                    signing_key: &owner_key,
                }),
                None,
                Some(&keyring),
            )
        };
        assert_eq!(
            run(
                "valid",
                base_prior.clone(),
                base_action.clone(),
                true,
                false
            )
            .unwrap()
            .operations
            .len(),
            2
        );
        let composition_vectors: Value = serde_json::from_str(include_str!(
            "../../../conformance/protocol-composition-vectors.json"
        ))
        .unwrap();
        let composed = composition_vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "action_dependency")
            .unwrap();
        let composed_digest = composed["result"]["digest"].as_str().unwrap();
        let mut composed_prior = base_prior.clone();
        composed_prior[0]["id"] = json!(composed_digest);
        composed_prior[0]["value"]["digest"] = json!(composed_digest);
        composed_prior[0]["value"]["manifest"] = composed["result"]["manifest"].clone();
        composed_prior[0]["value"]["resolved_manifest"] = composed["result"]["manifest"].clone();
        composed_prior[0]["value"]["composition"] = composed["result"]["composition"].clone();
        composed_prior[1]["value"]["protocol_digest"] = json!(composed_digest);
        let mut composed_action = base_action.clone();
        composed_action["objects"][0]["value"]["protocol_digest"] = json!(composed_digest);
        assert_eq!(
            run(
                "composed",
                composed_prior.clone(),
                composed_action.clone(),
                true,
                false
            )
            .unwrap()
            .operations
            .len(),
            2
        );
        composed_prior[0]["value"]["composition"]["dependencies"][0]["manifest"]["name"] =
            json!("tampered");
        assert!(run(
            "composition_tamper",
            composed_prior,
            composed_action,
            true,
            false
        )
        .is_err());
        let mut tampered = base_action.clone();
        tampered["objects"][0]["value"]["state"]["count"] = json!(99);
        assert!(run("output", base_prior.clone(), tampered, true, false).is_err());
        assert!(run(
            "policy",
            base_prior.clone(),
            base_action.clone(),
            false,
            false
        )
        .is_err());
        let mut changed_source = base_prior.clone();
        changed_source[1]["value"]["state"]["count"] = json!(1);
        assert!(run("source", changed_source, base_action.clone(), true, false).is_err());
        let mut invalid_manifest = base_prior.clone();
        invalid_manifest[0]["value"]["resolved_manifest"]["actions"][0]["id"] = json!("!");
        assert!(run(
            "manifest",
            invalid_manifest,
            base_action.clone(),
            true,
            false
        )
        .is_err());
        let mut changed_raw_manifest = base_prior.clone();
        changed_raw_manifest[0]["value"]["manifest"]["name"] = json!("changed");
        assert!(run(
            "manifest_digest",
            changed_raw_manifest,
            base_action.clone(),
            true,
            false,
        )
        .is_err());
        let mut historical = base_prior;
        historical[0]["value"]["resolved_manifest"]["historical_role_conflicts"] =
            json!([["reviewer", "approver"]]);
        assert!(run("history", historical, base_action, true, true).is_err());
    }

    #[test]
    fn private_commit_aad_and_canonical_utf16_plaintext_are_required() {
        let owner_keypair = SigningKey::from_bytes(&[92; 32]);
        let owner_key = key_id(&owner_keypair.verifying_key().to_bytes());
        let owner = actor_id(&owner_keypair.verifying_key().to_bytes());
        let workspace = base64url(&[93; 32]);
        let (_, encryption_public) = DhP256HkdfSha256::gen_keypair();
        let point = encryption_public.to_bytes();
        let encryption = json!({"kty":"EC","crv":"P-256","x":base64url(&point[1..33]),"y":base64url(&point[33..65])});
        let encryption_id = base64url(&sha256(
            canonical(&encryption, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        ));
        let certificate: Value = serde_json::from_slice(&signed(
            json!({"v":1,"actor_id":owner,"signing_key":owner_key,"encryption_key":encryption,"encryption_key_id":encryption_id,"issued_at":0,"expires_at":1000}),
            "peerwork.secure.key-certificate.v1",
            &owner_keypair,
        ))
        .unwrap();
        let policy = signed(
            json!({"v":1,"workspace_id":workspace,"owner_id":owner,"signing_key":owner_key,"version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PRIVATE","epoch":1,"members":[{"actor_id":owner,"certificate":certificate,"role":"OWNER","scopes":[]}],"issued_at":1}),
            "peerwork.secure.policy.v1",
            &owner_keypair,
        );
        let epoch_key = [19u8; 32];
        let context = json!({
            "v":1,"workspace_id":workspace,"sequence":1,"previous":null,"policy_hash":hash(&policy),
            "epoch":1,"actor_id":owner,"signing_key":owner_key,"command_id":base64url(&[21;32]),
            "action_id":"test.admin","instance_id":null,"issued_at":1,"delegation":null
        });
        let plaintext = br#"{"input":{"body":"\ud800"},"kind":"ADMIN","objects":[],"v":1}"#;
        let sealed = seal_content_wire(
            &epoch_key,
            plaintext,
            &serde_json::to_vec(&context).unwrap(),
        )
        .unwrap();
        let mut commit_payload = context.clone();
        commit_payload["mode"] = json!("PRIVATE");
        commit_payload["body"] = serde_json::to_value(sealed).unwrap();
        let commit = signed(
            commit_payload.clone(),
            "peerwork.secure.commit.v1",
            &owner_keypair,
        );
        let checkpoint = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&commit),"policy_hash":hash(&policy)
        }))
        .unwrap();
        let keyring = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,"keys":[{"epoch":1,"key":base64url(&epoch_key)}]})).unwrap();
        let owner_pin = OwnerPin {
            actor_id: &owner,
            signing_key: &owner_key,
        };
        let facts = replay_basic_content(
            &[&policy],
            &[&commit],
            &checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&keyring),
        )
        .unwrap();
        assert_eq!(facts.operations.len(), 1);
        assert_eq!(facts.object_count, 0);
        assert!(!facts.legacy);
        assert_eq!(
            facts.operations[0]
                .get("input")
                .unwrap()
                .get("body")
                .unwrap()
                .as_utf16(),
            Some([0xd800_u16].as_slice())
        );
        let mut v1_extra_body = commit_payload.clone();
        v1_extra_body["body"]["extra"] = json!(true);
        let v1_extra = signed(v1_extra_body, "peerwork.secure.commit.v1", &owner_keypair);
        let v1_extra_checkpoint = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&v1_extra),"policy_hash":hash(&policy)
        }))
        .unwrap();
        assert!(replay_basic_content(
            &[&policy],
            &[&v1_extra],
            &v1_extra_checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&keyring),
        )
        .is_ok());
        let mut changed_context = commit_payload.clone();
        changed_context["action_id"] = json!("test.other");
        let changed_context = signed(changed_context, "peerwork.secure.commit.v1", &owner_keypair);
        let changed_checkpoint = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&changed_context),"policy_hash":hash(&policy)
        }))
        .unwrap();
        assert!(replay_basic_content(
            &[&policy],
            &[&changed_context],
            &changed_checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&keyring),
        )
        .is_err());
        let wrong_keyring = serde_json::to_vec(&json!({"v":1,"workspace_id":workspace,"keys":[{"epoch":1,"key":base64url(&[20u8;32])}]})).unwrap();
        assert!(replay_basic_content(
            &[&policy],
            &[&commit],
            &checkpoint,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&wrong_keyring),
        )
        .is_err());
        let noncanonical = br#"{"v":1,"kind":"ADMIN","input":{},"objects":[]}"#;
        let sealed_bad = seal_content_bytes(&epoch_key, noncanonical, &context).unwrap();
        commit_payload["body"] = serde_json::to_value(sealed_bad).unwrap();
        let commit_bad = signed(commit_payload, "peerwork.secure.commit.v1", &owner_keypair);
        let checkpoint_bad = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&commit_bad),"policy_hash":hash(&policy)
        }))
        .unwrap();
        assert!(replay_basic_content(
            &[&policy],
            &[&commit_bad],
            &checkpoint_bad,
            &workspace,
            Some(&owner_pin),
            None,
            Some(&keyring),
        )
        .is_err());

        // Authenticated, canonical plaintext can still be semantically invalid.
        // The private scanner rejects these local context/content mismatches;
        // a later full validator must still evaluate policy and protocol effects.
        let invalid_operations = [
            json!({"v":1,"kind":"ADMIN","input":{},"objects":[{"kind":"records","id":"x","revision":1,"value":{},"provenance":"AUTHOR_SIGNED"}]}),
            json!({"v":1,"kind":"ACTION","input":{"action_id":"other","instance_id":null,"expected_instance_revision":1,"exact_input_refs":[],"allocations":[]},"objects":[]}),
        ];
        for operation in invalid_operations {
            let plaintext = canonical(&operation, Path::SecureArtifact).unwrap();
            let sealed = seal_content_wire(
                &epoch_key,
                plaintext.as_bytes(),
                &serde_json::to_vec(&context).unwrap(),
            )
            .unwrap();
            let mut payload = context.clone();
            payload["mode"] = json!("PRIVATE");
            payload["body"] = serde_json::to_value(sealed).unwrap();
            let candidate = signed(payload, "peerwork.secure.commit.v1", &owner_keypair);
            let checkpoint = serde_json::to_vec(&json!({
                "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
                "sequence":1,"head":hash(&candidate),"policy_hash":hash(&policy)
            }))
            .unwrap();
            assert!(replay_basic_content(
                &[&policy],
                &[&candidate],
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None,
                Some(&keyring)
            )
            .is_err());
        }
    }
}
