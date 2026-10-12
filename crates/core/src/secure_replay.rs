//! Internal content decoding and basic object-history checks. These facts do
//! not authorize reads: protocol evaluation, structure, recovery, migration,
//! and role policies must all pass before a verified journal may be returned.

use crate::{
    canonical::Path,
    crypto::{actor_id, decode_base64url},
    e2ee::{open_content_wire, SealedContent},
    interpreter::{evaluate_action, InterpreterAuth, ResolvedInput},
    secure_chain::{scan_signed_chain_headers, ChainError, CheckpointPin, OwnerPin},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 98_304;

#[derive(Debug, Error)]
pub(crate) enum ReplayError {
    #[error("signed chain did not validate: {0}")]
    Chain(#[from] ChainError),
    #[error("content or object history is invalid")]
    Invalid,
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayFacts {
    pub operations: Vec<WireValue>,
    pub object_count: usize,
    pub legacy: bool,
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
    scan_signed_chain_headers(
        policy_wires,
        commit_wires,
        checkpoint_wire,
        workspace_id,
        trusted_owner,
        pinned,
    )?;
    let mut seen_objects = HashSet::new();
    let mut latest_revisions: HashMap<String, u64> = HashMap::new();
    let mut operations = Vec::with_capacity(commit_wires.len());
    let mut legacy = false;
    for wire in commit_wires {
        let mut staged_revisions: HashMap<String, u64> = HashMap::new();
        let commit =
            parse_wire_json_js_bounded(wire, 64, 196_608).map_err(|_| ReplayError::Invalid)?;
        let payload = commit.get("payload").ok_or(ReplayError::Invalid)?;
        let mode = string(payload, "mode")?;
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
        // These are only local preconditions. Full operation evaluation still
        // happens before any trusted journal result may be constructed.
        let input = operation.get("input").ok_or(ReplayError::Invalid)?;
        match kind.as_str() {
            "BOOTSTRAP" if !operations.is_empty() => return Err(ReplayError::Invalid),
            "MIGRATE" if payload.get("migration").is_none() => return Err(ReplayError::Invalid),
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
        if kind == "ADMIN" {
            validate_admin_preflight(&operation, payload, &latest_revisions)
                .map_err(|_| ReplayError::Invalid)?;
        }
        let mut batch = HashSet::new();
        for object in objects {
            let object_text = canonical_wire_value(object, Path::SecureArtifact)
                .map_err(|_| ReplayError::Invalid)?;
            if object_text.len() > MAX_OBJECT_BYTES {
                return Err(ReplayError::Invalid);
            }
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
        }
        for (key, revision) in staged_revisions {
            latest_revisions
                .entry(key)
                .and_modify(|prior| *prior = (*prior).max(revision))
                .or_insert(revision);
        }
        operations.push(operation);
    }
    Ok(ReplayFacts {
        operations,
        object_count: seen_objects.len(),
        legacy,
    })
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
    }
    Ok(())
}

/// First ACTION replay slice: direct-member, no-record state transition.
/// Other ACTION shapes return `UNSUPPORTED` while the full validator is ported;
/// this function is private and never yields a verified journal or receipt.
fn validate_action_state_slice(
    operation: &WireValue,
    context: &WireValue,
    policy: &WireValue,
    prior: &[WireValue],
) -> Result<(), &'static str> {
    let input = operation.get("input").ok_or("ACTION_CONTEXT_MISMATCH")?;
    let action_id = context
        .get("action_id")
        .and_then(WireValue::as_utf16)
        .ok_or("ACTION_CONTEXT_MISMATCH")?;
    let instance_id = context
        .get("instance_id")
        .and_then(WireValue::as_utf16)
        .ok_or("ACTION_CONTEXT_MISMATCH")?;
    if input.get("action_id").and_then(WireValue::as_utf16) != Some(action_id)
        || input.get("instance_id").and_then(WireValue::as_utf16) != Some(instance_id)
    {
        return Err("ACTION_CONTEXT_MISMATCH");
    }
    let refs = match input.get("exact_input_refs") {
        Some(WireValue::Array(values)) => values,
        _ => return Err("ACTION_CONTEXT_MISMATCH"),
    };
    let allocations = match input.get("allocations") {
        Some(WireValue::Array(values)) => values,
        _ => return Err("ACTION_CONTEXT_MISMATCH"),
    };
    if !matches!(context.get("delegation"), Some(WireValue::Null)) {
        return Err("UNSUPPORTED");
    }
    let instance = prior
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && object.get("id").and_then(WireValue::as_utf16) == Some(instance_id)
        })
        .max_by_key(|object| integer(object, "revision").unwrap_or(0))
        .ok_or("INSTANCE_NOT_FOUND")?;
    let instance_value = instance.get("value").ok_or("INSTANCE_NOT_FOUND")?;
    if instance_value.get("id").and_then(WireValue::as_utf16) != Some(instance_id)
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
    let manifest = protocol
        .get("value")
        .and_then(|value| {
            value
                .get("resolved_manifest")
                .or_else(|| value.get("manifest"))
        })
        .ok_or("PROTOCOL_NOT_FOUND")?;
    if refs.len() > 32 {
        return Err("REFERENCE_INVALID");
    }
    let mut seen_refs = HashSet::new();
    let mut exact_inputs = Vec::with_capacity(refs.len());
    for reference in refs {
        let record_id = reference
            .get("record_id")
            .and_then(WireValue::as_utf16)
            .ok_or("REFERENCE_INVALID")?;
        let revision = integer(reference, "revision").map_err(|_| "REFERENCE_INVALID")?;
        if !seen_refs.insert((record_id.to_vec(), revision)) {
            return Err("REFERENCE_INVALID");
        }
        let found = prior
            .iter()
            .find(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                    && object.get("id").and_then(WireValue::as_utf16) == Some(record_id)
                    && object.get("value").is_some_and(|value| {
                        integer(value, "revision").is_ok_and(|value| value == revision)
                    })
            })
            .ok_or("REFERENCE_NOT_FOUND")?;
        let row = found.get("value").ok_or("REFERENCE_NOT_FOUND")?;
        if row.get("workspace_id") != context.get("workspace_id")
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
        let payload = match row.get("payload").ok_or("REFERENCE_INVALID")? {
            WireValue::String(value) => parse_wire_json_js_bounded(
                String::from_utf16(value)
                    .map_err(|_| "UNSUPPORTED")?
                    .as_bytes(),
                2048,
                MAX_CONTENT_BYTES,
            )
            .map_err(|_| "REFERENCE_INVALID")?,
            value => value.clone(),
        };
        let scope = if row.get("instance_id").and_then(WireValue::as_utf16) == Some(instance_id)
            && row.get("protocol_digest").and_then(WireValue::as_utf16) == Some(digest)
        {
            "INSTANCE"
        } else {
            "WORKSPACE"
        };
        exact_inputs.push(ResolvedInput {
            record_id: String::from_utf16(record_id).map_err(|_| "REFERENCE_INVALID")?,
            revision,
            schema: schema.to_vec(),
            payload,
            scope: scope.into(),
            entity_id: row.get("entity_id").and_then(WireValue::as_string),
        });
    }
    let policy_payload = policy.get("payload").ok_or("AUTHOR_NOT_MEMBER")?;
    let actor = context
        .get("actor_id")
        .and_then(WireValue::as_utf16)
        .ok_or("AUTHOR_NOT_MEMBER")?;
    let key = context
        .get("signing_key")
        .and_then(WireValue::as_utf16)
        .ok_or("AUTHOR_NOT_MEMBER")?;
    let key_text = String::from_utf16(key).map_err(|_| "AUTHOR_KEY_MISMATCH")?;
    let public_key: [u8; 32] = decode_base64url(&key_text)
        .map_err(|_| "AUTHOR_KEY_MISMATCH")?
        .try_into()
        .map_err(|_| "AUTHOR_KEY_MISMATCH")?;
    if actor_id(&public_key).encode_utf16().collect::<Vec<_>>() != actor {
        return Err("AUTHOR_KEY_MISMATCH");
    }
    let members = match policy_payload.get("members") {
        Some(WireValue::Array(values)) => values,
        _ => return Err("AUTHOR_NOT_MEMBER"),
    };
    let member = members
        .iter()
        .find(|member| {
            member.get("actor_id").and_then(WireValue::as_utf16) == Some(actor)
                && member
                    .get("certificate")
                    .and_then(|certificate| certificate.get("payload"))
                    .and_then(|payload| payload.get("signing_key"))
                    .and_then(WireValue::as_utf16)
                    == Some(key)
        })
        .ok_or("AUTHOR_NOT_MEMBER")?;
    let scopes = match member.get("scopes") {
        Some(WireValue::Array(values)) => values,
        _ => return Err("AUTHOR_SCOPE_DENIED"),
    };
    let issued = integer(context, "issued_at").map_err(|_| "AUTHOR_SCOPE_DENIED")?;
    let applicable: Vec<_> = scopes
        .iter()
        .filter(|scope| {
            (matches!(scope.get("instance_id"), Some(WireValue::Null))
                || scope.get("instance_id").and_then(WireValue::as_utf16) == Some(instance_id))
                && scope.get("expires_at").map_or(true, |at| {
                    matches!(at, WireValue::Null)
                        || at.as_number().is_some_and(|at| at > issued as f64)
                })
        })
        .collect();
    if !applicable.iter().any(|scope| {
        scope
            .get("actions")
            .and_then(|value| {
                if let WireValue::Array(items) = value {
                    Some(items)
                } else {
                    None
                }
            })
            .is_some_and(|actions| {
                actions
                    .iter()
                    .any(|value| value.as_utf16() == Some(action_id))
            })
    }) {
        return Err("AUTHOR_SCOPE_DENIED");
    }
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
        actor_id: String::from_utf16(actor).map_err(|_| "AUTHOR_NOT_MEMBER")?,
        workspace_roles: vec![member
            .get("role")
            .and_then(WireValue::as_utf16)
            .ok_or("AUTHOR_NOT_MEMBER")?
            .to_vec()],
        protocol_roles: roles,
        capabilities,
    };
    if manifest.get("state_array_types").is_some() {
        return Err("UNSUPPORTED");
    }
    let interpreted = evaluate_action(
        &WireValue::Object(vec![(
            "actions".encode_utf16().collect(),
            manifest.get("actions").ok_or("INVALID_PAYLOAD")?.clone(),
        )]),
        action_id,
        instance_value.get("state").ok_or("INVALID_PAYLOAD")?,
        input.get("body").ok_or("INVALID_PAYLOAD")?,
        &auth,
        &exact_inputs,
        None,
    )
    .map_err(|_| "INVALID_PAYLOAD")?;
    if !interpreted.head_selections.is_empty() || !interpreted.content_entities.is_empty() {
        return Err("UNSUPPORTED");
    }
    if allocations.len() != interpreted.records.len() {
        return Err("ALLOCATION_INVALID");
    }
    let mut expected_objects = Vec::new();
    let mut allocated_ids = HashSet::new();
    let mut allocated_entities = HashSet::new();
    for (record, allocation) in interpreted.records.iter().zip(allocations) {
        if record.get("entity").is_some()
            || record.get("entitySlot").is_some()
            || record
                .get("selectHead")
                .is_some_and(|value| matches!(value, WireValue::Bool(true)))
            || !matches!(record.get("relations"),Some(WireValue::Array(values)) if values.is_empty())
        {
            return Err("UNSUPPORTED");
        }
        let record_id = allocation
            .get("record_id")
            .and_then(WireValue::as_utf16)
            .ok_or("ALLOCATION_INVALID")?;
        let entity_id = allocation
            .get("entity_id")
            .and_then(WireValue::as_utf16)
            .ok_or("ALLOCATION_INVALID")?;
        if !token_utf16(record_id)
            || !token_utf16(entity_id)
            || !allocated_ids.insert(record_id.to_vec())
        {
            return Err("ALLOCATION_INVALID");
        }
        if prior.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                && object.get("id").and_then(WireValue::as_utf16) == Some(record_id)
        }) {
            return Err("RECORD_ALREADY_EXISTS");
        }
        if !allocated_entities.insert(entity_id.to_vec())
            || prior.iter().any(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                    && object
                        .get("value")
                        .and_then(|value| value.get("entity_id"))
                        .and_then(WireValue::as_utf16)
                        == Some(entity_id)
            })
        {
            return Err("ENTITY_ALREADY_EXISTS");
        }
        let schema = record
            .get("schema")
            .and_then(WireValue::as_utf16)
            .ok_or("RECORD_SCHEMA_INVALID")?;
        let schema_key = String::from_utf16(schema).map_err(|_| "RECORD_SCHEMA_INVALID")?;
        let definition = manifest
            .get("record_schemas")
            .and_then(|schemas| schemas.get(&schema_key))
            .ok_or("RECORD_SCHEMA_INVALID")?;
        if definition.get("protection").is_some() || definition.get("workflow").is_some() {
            return Err("UNSUPPORTED");
        }
        let payload = record.get("payload").ok_or("RECORD_SCHEMA_INVALID")?;
        validate_simple_record_schema(payload, definition)?;
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
            ("entity_id", WireValue::String(entity_id.to_vec())),
            ("schema_ref", WireValue::String(schema.to_vec())),
            ("payload", payload.clone()),
            ("actor_id", WireValue::String(actor.to_vec())),
            ("revision", WireValue::Number(1.0)),
            ("created", WireValue::Number(issued as f64)),
        ]);
        expected_objects.push(fields_object(vec![
            ("kind", string_value("records")),
            ("id", WireValue::String(record_id.to_vec())),
            ("revision", WireValue::Number(1.0)),
            ("value", value),
            ("provenance", string_value("AUTHOR_SIGNED")),
        ]));
    }
    let mut next = instance_value.clone();
    replace_field(&mut next, "state", interpreted.next_state)
        .map_err(|_| "PROTOCOL_OUTPUT_MISMATCH")?;
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
    let expected = WireValue::Array(expected_objects);
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
fn safe_add(value: u64, delta: u64) -> Result<u64, &'static str> {
    value
        .checked_add(delta)
        .filter(|result| *result <= 9_007_199_254_740_991)
        .ok_or("PROTOCOL_OUTPUT_MISMATCH")
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

fn validate_simple_record_schema(
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
