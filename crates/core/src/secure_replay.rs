//! Internal content decoding and basic object-history checks. These facts do
//! not authorize reads: protocol evaluation, structure, recovery, migration,
//! and role policies must all pass before a verified journal may be returned.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, decode_base64url, sha256},
    e2ee::{open_content_wire, SealedContent},
    interpreter::{evaluate_action, InterpreterAuth, ResolvedInput},
    secure_chain::{scan_signed_chain_headers, ChainError, CheckpointPin, OwnerPin},
    wire_json::{
        canonical_wire_value, parse_js_json_string_bounded, parse_wire_json_js_bounded, WireValue,
    },
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
        let payload = decoded_value(row.get("payload").ok_or("REFERENCE_INVALID")?)
            .map_err(|_| "REFERENCE_INVALID")?;
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
    validate_role_policies(policy_payload, prior, issued, instance_id)?;
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
    let source_state = decoded_value(instance_value.get("state").ok_or("INVALID_PAYLOAD")?)
        .map_err(|_| "INVALID_PAYLOAD")?;
    crate::full_manifest::validate_state_array_state(&manifest, &source_state)
        .map_err(|_| "STATE_ARRAY_TYPE_INVALID")?;
    let interpreted = evaluate_action(
        &WireValue::Object(vec![(
            "actions".encode_utf16().collect(),
            manifest.get("actions").ok_or("INVALID_PAYLOAD")?.clone(),
        )]),
        action_id,
        &source_state,
        input.get("body").ok_or("INVALID_PAYLOAD")?,
        &auth,
        &exact_inputs,
        None,
    )
    .map_err(|_| "INVALID_PAYLOAD")?;
    if allocations.len() != interpreted.records.len() {
        return Err("ALLOCATION_INVALID");
    }
    let mut expected_objects = Vec::new();
    let mut allocated_ids = HashSet::new();
    let mut allocated_entities = HashSet::new();
    let mut entity_max = HashMap::<Vec<u16>, u64>::new();
    let mut head_changes = Vec::new();
    let mut head_ids = HashSet::new();
    let mut record_slots = HashMap::<Vec<u16>, WireValue>::new();
    let mut entity_slots = HashMap::<Vec<u16>, WireValue>::new();
    let mut assigned_records = HashMap::<Vec<u16>, u64>::new();
    let mut pending_relations = Vec::<(usize, Vec<u16>, WireValue)>::new();
    for (record, allocation) in interpreted.records.iter().zip(allocations) {
        let entity = record.get("entity");
        if entity.is_some_and(|entity| {
            !matches!(
                entity.get("mode").and_then(WireValue::as_string).as_deref(),
                Some("new" | "revise")
            )
        }) || entity.is_none()
            && record
                .get("selectHead")
                .is_some_and(|value| matches!(value, WireValue::Bool(true)))
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
        let mut assigned_entity = entity_id.to_vec();
        let mut assigned_revision = 1_u64;
        if let Some(slot) = record.get("entitySlot").and_then(WireValue::as_string) {
            let instance = String::from_utf16(instance_id).map_err(|_| "INVALID_PAYLOAD")?;
            assigned_entity = base64url(&sha256(format!("{instance}\0{slot}").as_bytes()))
                .encode_utf16()
                .collect();
            let existing = prior
                .iter()
                .filter(|object| {
                    object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                        && object
                            .get("value")
                            .and_then(|value| value.get("entity_id"))
                            .and_then(WireValue::as_utf16)
                            == Some(&assigned_entity)
                })
                .max_by_key(|object| {
                    object
                        .get("value")
                        .and_then(|value| integer(value, "revision").ok())
                        .unwrap_or(0)
                });
            if let Some(existing) = existing {
                let row = existing.get("value").ok_or("STALE_REVISION")?;
                let old_revision = integer(row, "revision").map_err(|_| "STALE_REVISION")?;
                let old_id = existing
                    .get("id")
                    .and_then(WireValue::as_utf16)
                    .ok_or("STALE_REVISION")?;
                if !seen_refs.contains(&(old_id.to_vec(), old_revision)) {
                    return Err("STALE_REVISION");
                }
                assigned_revision = safe_add(
                    entity_max
                        .get(&assigned_entity)
                        .copied()
                        .unwrap_or(old_revision),
                    1,
                )?;
            }
            entity_max.insert(assigned_entity.clone(), assigned_revision);
        } else if entity.is_some_and(|entity| {
            entity.get("mode").and_then(WireValue::as_string).as_deref() == Some("revise")
        }) {
            let parent = entity
                .and_then(|value| value.get("parent"))
                .ok_or("ENTITY_PARENT_INVALID")?;
            let parent_id = parent
                .get("recordId")
                .and_then(WireValue::as_utf16)
                .ok_or("ENTITY_PARENT_INVALID")?;
            let parent_revision =
                integer(parent, "revision").map_err(|_| "ENTITY_PARENT_INVALID")?;
            let old = prior
                .iter()
                .find(|object| {
                    object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                        && object.get("id").and_then(WireValue::as_utf16) == Some(parent_id)
                        && object
                            .get("value")
                            .and_then(|value| integer(value, "revision").ok())
                            == Some(parent_revision)
                })
                .ok_or("ENTITY_PARENT_INVALID")?;
            let old_row = old.get("value").ok_or("ENTITY_PARENT_INVALID")?;
            if old_row.get("workspace_id") != context.get("workspace_id")
                || old_row.get("instance_id").and_then(WireValue::as_utf16) != Some(instance_id)
                || old_row.get("protocol_digest").and_then(WireValue::as_utf16) != Some(digest)
            {
                return Err("ENTITY_PARENT_INVALID");
            }
            assigned_entity = old_row
                .get("entity_id")
                .and_then(WireValue::as_utf16)
                .ok_or("ENTITY_PARENT_INVALID")?
                .to_vec();
            let max_revision = prior
                .iter()
                .filter(|object| {
                    object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                        && object
                            .get("value")
                            .and_then(|value| value.get("entity_id"))
                            .and_then(WireValue::as_utf16)
                            == Some(&assigned_entity)
                })
                .filter_map(|object| {
                    object
                        .get("value")
                        .and_then(|value| integer(value, "revision").ok())
                })
                .max()
                .ok_or("ENTITY_PARENT_INVALID")?;
            assigned_revision = safe_add(
                entity_max
                    .get(&assigned_entity)
                    .copied()
                    .unwrap_or(max_revision),
                1,
            )?;
            entity_max.insert(assigned_entity.clone(), assigned_revision);
            if record
                .get("selectHead")
                .is_some_and(|value| matches!(value, WireValue::Bool(true)))
            {
                let current_head = prior
                    .iter()
                    .filter(|object| {
                        object.get("kind").and_then(WireValue::as_string).as_deref()
                            == Some("entity_heads")
                            && object.get("id").and_then(WireValue::as_utf16)
                                == Some(&assigned_entity)
                    })
                    .max_by_key(|object| integer(object, "revision").unwrap_or(0))
                    .ok_or("STALE_REVISION")?;
                let current = current_head.get("value").ok_or("STALE_REVISION")?;
                if current.get("record_id").and_then(WireValue::as_utf16) != Some(parent_id)
                    || integer(current, "revision").map_err(|_| "STALE_REVISION")?
                        != parent_revision
                {
                    return Err("STALE_REVISION");
                }
            }
        } else if !allocated_entities.insert(assigned_entity.clone())
            || prior.iter().any(|object| {
                object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                    && object
                        .get("value")
                        .and_then(|value| value.get("entity_id"))
                        .and_then(WireValue::as_utf16)
                        == Some(&assigned_entity)
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
        if let Some(slot) = record.get("recordSlot").and_then(WireValue::as_utf16) {
            if record_slots
                .insert(
                    slot.to_vec(),
                    fields_object(vec![
                        ("record_id", WireValue::String(record_id.to_vec())),
                        ("revision", WireValue::Number(assigned_revision as f64)),
                    ]),
                )
                .is_some()
            {
                return Err("INVALID_PROTOCOL_TRANSITION");
            }
        }
        if let Some(slot) = record
            .get("entitySlot")
            .or_else(|| entity.and_then(|value| value.get("slot")))
            .and_then(WireValue::as_utf16)
        {
            entity_slots.insert(slot.to_vec(), WireValue::String(assigned_entity.clone()));
        }
        assigned_records.insert(record_id.to_vec(), assigned_revision);
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
            pending_relations.push((expected_objects.len(), record_id.to_vec(), relation.clone()));
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
    for (index, source_id, relation) in pending_relations {
        let kind = relation
            .get("kind")
            .and_then(WireValue::as_utf16)
            .ok_or("RELATION_TARGET_INVALID")?;
        let target = substitute_produced(
            relation.get("target").ok_or("RELATION_TARGET_INVALID")?,
            &record_slots,
            &entity_slots,
            0,
        )?;
        let target_id = target
            .get("recordId")
            .or_else(|| target.get("record_id"))
            .and_then(WireValue::as_utf16)
            .ok_or("RELATION_TARGET_INVALID")?;
        let target_revision =
            integer(&target, "revision").map_err(|_| "RELATION_TARGET_INVALID")?;
        let exists = prior.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                && object.get("id").and_then(WireValue::as_utf16) == Some(target_id)
                && object
                    .get("value")
                    .and_then(|value| integer(value, "revision").ok())
                    == Some(target_revision)
        }) || assigned_records.get(target_id) == Some(&target_revision);
        if !exists {
            return Err("RELATION_TARGET_INVALID");
        }
        let id = canonical_wire_value(
            &WireValue::Array(vec![
                WireValue::String(source_id.clone()),
                WireValue::String(kind.to_vec()),
                WireValue::String(target_id.to_vec()),
                WireValue::Number(target_revision as f64),
            ]),
            Path::SecureArtifact,
        )
        .map_err(|_| "RELATION_TARGET_INVALID")?;
        let relation_value = fields_object(vec![
            ("record_id", WireValue::String(source_id)),
            ("kind", WireValue::String(kind.to_vec())),
            ("target_record", WireValue::String(target_id.to_vec())),
            ("target_revision", WireValue::Number(target_revision as f64)),
        ]);
        let outer_revision = safe_add(
            prior
                .iter()
                .filter(|object| {
                    object.get("kind").and_then(WireValue::as_string).as_deref()
                        == Some("record_relations")
                        && object.get("id").and_then(WireValue::as_string).as_deref() == Some(&id)
                })
                .filter_map(|object| integer(object, "revision").ok())
                .max()
                .unwrap_or(0),
            1,
        )?;
        expected_objects[index] = fields_object(vec![
            ("kind", string_value("record_relations")),
            ("id", string_value(&id)),
            ("revision", WireValue::Number(outer_revision as f64)),
            ("value", relation_value),
            ("provenance", string_value("AUTHOR_SIGNED")),
        ]);
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
        for member in members {
            let Some(actor) = member.get("actor_id").and_then(WireValue::as_utf16) else {
                continue;
            };
            let mut past = HashSet::<Vec<u16>>::new();
            for grant in latest.iter().filter(|grant| {
                grant.get("kind").and_then(WireValue::as_string).as_deref() == Some("grants")
            }) {
                let Some(row) = grant.get("value") else {
                    continue;
                };
                if row.get("instance_id").and_then(WireValue::as_utf16) != Some(instance_id)
                    || row.get("protocol_digest").and_then(WireValue::as_utf16)
                        != Some(protocol_digest)
                    || row.get("actor_id").and_then(WireValue::as_utf16) != Some(actor)
                {
                    continue;
                }
                let roles = decoded_value(row.get("protocol_roles").ok_or("LEGACY_GRANT_INVALID")?)
                    .map_err(|_| "LEGACY_GRANT_INVALID")?;
                let WireValue::Array(roles) = roles else {
                    return Err("LEGACY_GRANT_INVALID");
                };
                for role in roles {
                    past.insert(role.as_utf16().ok_or("LEGACY_GRANT_INVALID")?.to_vec());
                }
            }
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
            if instance_id == validate_instance {
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
        }
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
