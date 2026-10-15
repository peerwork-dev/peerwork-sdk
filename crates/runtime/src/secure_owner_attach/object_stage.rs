//! Selected saved object-stage handoff, including the first part. Original source provenance and the
//! separately authorized native BEGIN are retained as distinct durable facts.
use super::*;
use peerwork_core::prepared_private_install::{
    prepare_private_direct_install_begin_with_object_source, prepare_private_protocol_object_stage,
    verify_private_protocol_object_stage_material, verify_protocol_object_source_prefix,
    verify_saved_private_protocol_object_stage,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalObjectStagePendingInventory {
    pub ts_state_digest: String,
    pub command_id: String,
    pub instance_id: String,
    pub source_id: String,
    pub protocol_digest: String,
    pub part_index: usize,
    pub part_count: usize,
    pub original_commit_hash: String,
    pub original_options_hash: String,
    pub status: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedObjectStage {
    pub(super) plan_id: String,
    pub(super) command_id: String,
    pub(super) instance_id: String,
    pub(super) stage_accepted: bool,
    pub(super) native_begin_command_id: Option<String>,
    pub(super) complete: bool,
}

pub(super) struct LegacyPendingObjectStage {
    command_id: String,
    instance_id: String,
    path: String,
    request: Zeroizing<Vec<u8>>,
    marker: LegacyCompletedObjectStage,
    marker_floor: Option<u64>,
    orphan_command: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ObjectStagePlan {
    version: u8,
    origin: String,
    plan_id: String,
    attach_id: String,
    workspace_id: String,
    owner_actor_id: String,
    owner_key_id: String,
    command_id: String,
    instance_id: String,
    original_commit_hash: String,
    source_epoch: u64,
    ts_state_sha256: String,
    owner_pem_sha256: String,
    ts_intent_sha256: String,
    options_sha256: String,
    material_sha256: String,
}
struct LoadedObjectStagePlan {
    manifest: ObjectStagePlan,
    source: LegacySource,
    pem: Zeroizing<Vec<u8>>,
    options: Zeroizing<Vec<u8>>,
    material: Zeroizing<Vec<u8>>,
}
/// This packet is native-authored, never represented as a TS saved BEGIN.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeObjectBegin {
    version: u8,
    plan_id: String,
    command_id: String,
    commit_hash: String,
    request_b64: String,
}
/// One native-authored remaining part; never labeled as an original TS packet.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeObjectRemainder {
    version: u8,
    plan_id: String,
    packets: Vec<NativeObjectStagePacket>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeObjectStagePacket {
    part_index: usize,
    command_id: String,
    commit_hash: String,
    request_b64: String,
}
#[cfg(test)]
pub(super) static TEST_STOP_AFTER_OBJECT_REMAINDER_ROW: AtomicBool = AtomicBool::new(false);

struct VerifiedObjectStage {
    marker_only: bool,
    applied: bool,
    source_complete: bool,
    accepted_parts: usize,
    commit_hash: String,
    part_index: usize,
    part_count: usize,
    stage_end: u64,
    root_digest: String,
    closure: Zeroizing<String>,
    bindings: Zeroizing<String>,
    entrypoint: String,
    resolved: ResolvedLegacyDirectOptions,
}
fn invalid() -> HistoricalOwnerAttachError {
    HistoricalOwnerAttachError::SourceUnresolved
}
fn local() -> HistoricalOwnerAttachError {
    HistoricalOwnerAttachError::Local
}
fn scalar(value: &WireValue, name: &str) -> Result<String, HistoricalOwnerAttachError> {
    value
        .get(name)
        .and_then(WireValue::as_string)
        .ok_or_else(invalid)
}
fn canonical(value: &WireValue) -> Result<String, HistoricalOwnerAttachError> {
    canonical_wire_value(value, CanonicalPath::SecureArtifact).map_err(|_| invalid())
}
fn object_attach_id(plan_id: &str) -> String {
    base64url(&sha256(
        format!("peerwork.owner.object-stage-attach.v1:{plan_id}").as_bytes(),
    ))
}
fn object_plan_id(
    origin: &str,
    input: &HistoricalOwnerAttachInput,
    state: &str,
    command: &str,
    options: &str,
    material: &str,
) -> Result<String, HistoricalOwnerAttachError> {
    let bytes = serde_json::to_vec(&(
        "peerwork.owner.object-stage-plan.v1",
        origin,
        &input.workspace_id,
        state,
        command,
        options,
        material,
    ))
    .map_err(|_| local())?;
    Ok(base64url(&sha256(&bytes)))
}

pub(super) fn parse_pending_object_stage(
    value: &WireValue,
    input: &HistoricalOwnerAttachInput,
    command: &str,
    instance: &str,
) -> Result<LegacyPendingObjectStage, HistoricalOwnerAttachError> {
    if valid_digest(command) {
        return parse_marker_object_stage(value, input, command, instance);
    }
    if !valid_token(command)
        || !valid_token(instance)
        || !empty_optional_map(value.get("protocol_install_intents"))
    {
        return Err(invalid());
    }
    let Some(WireValue::Object(markers)) = value.get("protocol_object_stage_intents") else {
        return Err(invalid());
    };
    let key = format!("{}.{}", input.workspace_id, instance)
        .encode_utf16()
        .collect::<Vec<_>>();
    if markers.len() != 1 || markers[0].0 != key {
        return Err(invalid());
    }
    let marker = &markers[0].1;
    if marker.object_len() != Some(4) || scalar(marker, "command_id")? != command {
        return Err(invalid());
    }
    let request_hash = scalar(marker, "request_hash")?;
    if !valid_digest(&request_hash) {
        return Err(invalid());
    }
    let proof = normalize_protocol_object_source_proof(marker.get("proof").ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let source = proof.get("source").ok_or_else(invalid)?;
    if scalar(&proof, "workspace_id")? != input.workspace_id
        || scalar(source, "owner_id")? != input.expected_owner_actor_id
        || scalar(source, "owner_key")? != input.expected_owner_key_id
    {
        return Err(invalid());
    }
    let Some(WireValue::Array(parts)) = marker.get("parts") else {
        return Err(invalid());
    };
    let mut logical = read_complete_protocol_object_source(&proof, parts).map_err(|_| invalid())?;
    scrub(&mut logical);
    let Some(WireValue::Object(packets)) = value.get("pending") else {
        return Err(invalid());
    };
    if packets.len() != 1
        || String::from_utf16(&packets[0].0).ok().as_deref() != Some(command)
        || packets[0].1.object_len() != Some(2)
    {
        return Err(invalid());
    }
    let row = &packets[0].1;
    let path = scalar(row, "path")?;
    let body = row.get("body").ok_or_else(invalid)?;
    let payload = body
        .get("commit")
        .and_then(|commit| commit.get("payload"))
        .ok_or_else(invalid)?;
    if path
        != format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            input.workspace_id
        )
        || body.object_len() != Some(1)
        || scalar(payload, "command_id")? != command
        || scalar(payload, "action_id")? != "secure.protocol-object.stage"
    {
        return Err(invalid());
    }
    Ok(LegacyPendingObjectStage {
        command_id: command.into(),
        instance_id: instance.into(),
        path,
        request: Zeroizing::new(canonical(body)?.into_bytes()),
        marker_floor: None,
        orphan_command: None,
        marker: LegacyCompletedObjectStage {
            request_hash,
            proof,
            parts_wire: Zeroizing::new(
                canonical(marker.get("parts").ok_or_else(invalid)?)?.into_bytes(),
            ),
        },
    })
}

// A marker selection has no original saved packet. Its SHA256 is a selection
// identity, never a command ID or a claim about a missing signature/nonce.
fn parse_marker_object_stage(
    value: &WireValue,
    input: &HistoricalOwnerAttachInput,
    hash: &str,
    instance: &str,
) -> Result<LegacyPendingObjectStage, HistoricalOwnerAttachError> {
    if !valid_token(instance)
        || !empty_optional_map(value.get("pending"))
        || !empty_optional_map(value.get("protocol_install_intents"))
    {
        return Err(invalid());
    }
    let Some(WireValue::Object(markers)) = value.get("protocol_object_stage_intents") else {
        return Err(invalid());
    };
    let key = format!("{}.{}", input.workspace_id, instance)
        .encode_utf16()
        .collect::<Vec<_>>();
    if markers.len() != 1 || markers[0].0 != key {
        return Err(invalid());
    }
    let marker = &markers[0].1;
    let orphan = marker
        .get("command_id")
        .map(|_| scalar(marker, "command_id"))
        .transpose()?;
    if marker.object_len() != Some(3 + usize::from(orphan.is_some()))
        || orphan.as_ref().is_some_and(|id| !valid_token(id))
        || sha256_hex(canonical(marker)?.as_bytes()) != hash
    {
        return Err(invalid());
    }
    let request_hash = scalar(marker, "request_hash")?;
    let proof = normalize_protocol_object_source_proof(marker.get("proof").ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let source = proof.get("source").ok_or_else(invalid)?;
    if !valid_digest(&request_hash)
        || scalar(&proof, "workspace_id")? != input.workspace_id
        || scalar(source, "owner_id")? != input.expected_owner_actor_id
        || scalar(source, "owner_key")? != input.expected_owner_key_id
    {
        return Err(invalid());
    }
    let Some(WireValue::Array(parts)) = marker.get("parts") else {
        return Err(invalid());
    };
    let mut logical = read_complete_protocol_object_source(&proof, parts).map_err(|_| invalid())?;
    scrub(&mut logical);
    let floor = value
        .get("workspaces")
        .and_then(|v| v.get(&input.workspace_id))
        .and_then(|v| v.get("checkpoint"))
        .and_then(|v| exact_u64(v.get("sequence")))
        .ok_or_else(invalid)?;
    Ok(LegacyPendingObjectStage {
        command_id: hash.into(),
        instance_id: instance.into(),
        path: format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            input.workspace_id
        ),
        request: Zeroizing::new(vec![]),
        marker_floor: Some(floor),
        orphan_command: orphan,
        marker: LegacyCompletedObjectStage {
            request_hash,
            proof,
            parts_wire: Zeroizing::new(
                canonical(marker.get("parts").ok_or_else(invalid)?)?.into_bytes(),
            ),
        },
    })
}

fn check_current_owner(
    replayed: &TransportReplayedJournal,
    ring: &SecretKeyring,
    owner: &KernelIdentity,
    input: &HistoricalOwnerAttachInput,
) -> Result<(), HistoricalOwnerAttachError> {
    let wire = replayed
        .signed_policy_by_hash(replayed.replay().policy_hash())
        .ok_or_else(invalid)?;
    let policy = parse_wire_json_bounded(wire, 64, 196_608).map_err(|_| invalid())?;
    let policy = policy.get("payload").ok_or_else(invalid)?;
    let member = matches!(policy.get("members"), Some(WireValue::Array(members)) if members.iter().any(|row|
        row.get("actor_id").and_then(WireValue::as_string).as_deref() == Some(owner.actor_id())
        && row.get("role").and_then(WireValue::as_string).as_deref() == Some("OWNER")
        && row.get("certificate").and_then(|c| c.get("payload")).and_then(|p| p.get("signing_key"))
            .and_then(WireValue::as_string).as_deref() == Some(owner.key_id())));
    if owner.actor_id() != input.expected_owner_actor_id
        || owner.key_id() != input.expected_owner_key_id
        || replayed.replay().owner_actor_id() != owner.actor_id()
        || replayed.replay().owner_signing_key() != owner.key_id()
        || scalar(policy, "visibility")? != "PRIVATE"
        || !member
        || exact_u64(policy.get("epoch")) != ring.epochs().last()
    {
        return Err(invalid());
    }
    Ok(())
}

fn verify_object_stage(
    pending: &LegacyPendingObjectStage,
    options: &[u8],
    material: &[u8],
    ring: &SecretKeyring,
    replayed: &TransportReplayedJournal,
    owner: &KernelIdentity,
    input: &HistoricalOwnerAttachInput,
    native_begin_exists: bool,
    remaining: Option<&NativeObjectRemainder>,
) -> Result<VerifiedObjectStage, HistoricalOwnerAttachError> {
    check_current_owner(replayed, ring, owner, input)?;
    let proof = &pending.marker.proof;
    let source = proof.get("source").ok_or_else(invalid)?;
    let base = exact_u64(source.get("sequence")).ok_or_else(invalid)?;
    let Some(WireValue::Array(descriptors)) = proof.get("parts") else {
        return Err(invalid());
    };
    let part_count = descriptors.len();
    let stage_end = base.checked_add(part_count as u64).ok_or_else(invalid)?;
    let parts = parse_wire_json_bounded(&pending.marker.parts_wire, 64, MAX_SOURCE)
        .map_err(|_| invalid())?;
    let WireValue::Array(parts) = parts else {
        return Err(invalid());
    };
    let policy_hash = scalar(source, "policy_hash")?;
    let policy = replayed
        .signed_policy_by_hash(&policy_hash)
        .ok_or_else(invalid)?;
    let epoch = ring.epochs().last().ok_or_else(invalid)?;
    let (applied, commit_hash, part_index, mut accepted_parts, tail_start) = if let Some(floor) =
        pending.marker_floor
    {
        if floor < base || floor > stage_end {
            return Err(invalid());
        }
        let (prefix, _) = replay_install_step_predecessor(replayed, ring, input, floor)?;
        verify_protocol_object_source_prefix(proof, &prefix).map_err(|_| invalid())?;
        if prefix.structure_status() != StructureStatus::Active {
            return Err(invalid());
        }
        let mut initial = floor;
        if let Some(orphan) = pending.orphan_command.as_ref() {
            let mut found = None;
            for (i, signed) in replayed.signed_commit_wires().iter().enumerate() {
                let wire = parse_wire_json_bounded(signed, 64, 220_000).map_err(|_| invalid())?;
                if wire
                    .get("payload")
                    .and_then(|p| p.get("command_id"))
                    .and_then(WireValue::as_string)
                    .as_ref()
                    == Some(orphan)
                {
                    if found.replace(i as u64 + 1).is_some() {
                        return Err(invalid());
                    }
                }
            }
            if let Some(sequence) = found {
                if sequence <= base
                    || sequence > stage_end
                    || !(sequence == floor || sequence == floor + 1)
                {
                    return Err(invalid());
                }
                initial = initial.max(sequence);
            }
        }
        let (prefix, _) = replay_install_step_predecessor(replayed, ring, input, initial)?;
        verify_protocol_object_source_prefix(proof, &prefix).map_err(|_| invalid())?;
        if prefix.structure_status() != StructureStatus::Active {
            return Err(invalid());
        }
        let count = usize::try_from(initial - base).map_err(|_| invalid())?;
        (true, pending.command_id.clone(), count, count, count)
    } else {
        let request =
            parse_wire_json_bounded(&pending.request, 64, 220_000).map_err(|_| invalid())?;
        let payload = request
            .get("commit")
            .and_then(|v| v.get("payload"))
            .ok_or_else(invalid)?;
        let sequence = exact_u64(payload.get("sequence")).ok_or_else(invalid)?;
        let index = usize::try_from(
            sequence
                .checked_sub(base)
                .and_then(|n| n.checked_sub(1))
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        if index >= part_count {
            return Err(invalid());
        }
        let (prior, checkpoint) =
            replay_install_step_predecessor(replayed, ring, input, sequence - 1)?;
        verify_protocol_object_source_prefix(proof, &prior).map_err(|_| invalid())?;
        if prior.structure_status() != StructureStatus::Active {
            return Err(invalid());
        }
        let hash = verify_saved_private_protocol_object_stage(
            &pending.request,
            proof,
            parts.get(index).ok_or_else(invalid)?,
            index,
            &checkpoint,
            policy,
            &pending.command_id,
            owner.signing_key(),
            ring.key_at(exact_u64(payload.get("epoch")).ok_or_else(invalid)?)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let applied =
            if let Some(signed) = replayed.signed_commit_wires().get((sequence - 1) as usize) {
                if sha256_hex(signed) != hash {
                    return Err(invalid());
                }
                true
            } else if replayed.replay().sequence() == sequence - 1
                && replayed.replay().head() == prior.head()
                && replayed.replay().policy_hash() == prior.policy_hash()
            {
                false
            } else {
                return Err(invalid());
            };
        (
            applied,
            hash,
            index,
            index + usize::from(applied),
            index + 1,
        )
    };
    if let Some(remaining) = remaining {
        if (!applied && pending.marker_floor.is_none())
            || remaining.packets.is_empty()
            || remaining.packets.len() > part_count - tail_start
        {
            return Err(invalid());
        }
        let mut ids = std::collections::HashSet::new();
        for (offset, packet) in remaining.packets.iter().enumerate() {
            let index = tail_start + offset;
            if packet.part_index != index
                || packet.command_id == pending.command_id
                || !valid_token(&packet.command_id)
                || !valid_digest(&packet.commit_hash)
                || !ids.insert(&packet.command_id)
            {
                return Err(invalid());
            }
            let (prefix, checkpoint) =
                replay_install_step_predecessor(replayed, ring, input, base + index as u64)?;
            verify_protocol_object_source_prefix(proof, &prefix).map_err(|_| invalid())?;
            if prefix.structure_status() != StructureStatus::Active {
                return Err(invalid());
            }
            let request = peerwork_core::crypto::decode_base64url(&packet.request_b64)
                .map_err(|_| invalid())?;
            let hash = verify_saved_private_protocol_object_stage(
                &request,
                proof,
                parts.get(index).ok_or_else(invalid)?,
                index,
                &checkpoint,
                policy,
                &packet.command_id,
                owner.signing_key(),
                ring.key_at(epoch).ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            if hash != packet.commit_hash {
                return Err(invalid());
            }
            if let Some(signed) = replayed.signed_commit_wires().get(base as usize + index) {
                if sha256_hex(signed) != hash {
                    return Err(invalid());
                }
                accepted_parts += 1;
            } else if offset + 1 != remaining.packets.len()
                || replayed.replay().sequence() != base + index as u64
                || replayed.replay().head() != prefix.head()
                || replayed.replay().policy_hash() != prefix.policy_hash()
            {
                return Err(invalid());
            }
        }
    }
    let source_complete = accepted_parts == part_count;
    if (!native_begin_exists
        && (replayed.replay().sequence() != base + accepted_parts as u64
            || replayed.replay().structure_status() != StructureStatus::Active))
        || (native_begin_exists && (!source_complete || replayed.replay().sequence() < stage_end))
    {
        return Err(invalid());
    }
    let options = parse_wire_json_bounded(options, 64, 2 * 1024 * 1024).map_err(|_| invalid())?;
    if scalar(&options, "instance_id")? != pending.instance_id
        || sha256_hex(canonical(&options)?.as_bytes()) != pending.marker.request_hash
        || options
            .get("expected_checkpoint")
            .is_some_and(|cp| canonical(cp).ok() != canonical(source).ok())
    {
        return Err(invalid());
    }
    let (original, _) = replay_install_step_predecessor(replayed, ring, input, base)?;
    let resolved = resolve_legacy_direct_options_from_prior(&options, original.objects())?;
    if resolved.package_source.is_some()
        || resolved.protocol_digest != scalar(proof, "protocol_digest")?
    {
        return Err(invalid());
    }
    let material = parse_wire_json_bounded(material, 64, 8 * 1024 * 1024).map_err(|_| invalid())?;
    if material.object_len() != Some(3) || exact_u64(material.get("v")) != Some(1) {
        return Err(invalid());
    }
    let root_digest = scalar(
        material.get("closure").ok_or_else(invalid)?,
        "root_package_digest",
    )?;
    let closure = Zeroizing::new(canonical(material.get("closure").ok_or_else(invalid)?)?);
    let bindings = Zeroizing::new(canonical(material.get("bindings").ok_or_else(invalid)?)?);
    let entrypoint = scalar(&options, "entrypoint")?;
    let compiled = verify_private_protocol_object_stage_material(
        closure.as_bytes(),
        bindings.as_bytes(),
        &root_digest,
        &resolved.protocol_digest,
        proof,
        &parts,
        policy,
        original.objects(),
        &pending.instance_id,
        &entrypoint,
        resolved.grants_json.as_bytes(),
        resolved.disclose_json.as_deref().unwrap_or("[]").as_bytes(),
        owner.signing_key(),
    )
    .map_err(|_| invalid())?;
    if match (compiled.as_ref(), resolved.composition.as_ref()) {
        (None, None) => false,
        (Some(a), Some(b)) => canonical(a)? != canonical(b)?,
        _ => true,
    } {
        return Err(invalid());
    }
    // Authenticate all accepted original part bytes, not merely descriptors.
    for (index, expected) in parts.iter().enumerate().take(accepted_parts) {
        let operation = replayed
            .replay()
            .operations()
            .get(base as usize + index)
            .ok_or_else(invalid)?;
        let Some(WireValue::Array(actual)) = operation.get("objects") else {
            return Err(invalid());
        };
        if actual.len() != 1 || canonical(&actual[0])? != canonical(expected)? {
            return Err(invalid());
        }
    }
    if source_complete {
        let (complete, _) = replay_install_step_predecessor(replayed, ring, input, stage_end)?;
        let mut logical =
            verify_completed_protocol_object_source(proof, &complete).map_err(|_| invalid())?;
        scrub(&mut logical);
    }
    Ok(VerifiedObjectStage {
        marker_only: pending.marker_floor.is_some(),
        applied: if pending.marker_floor.is_some() {
            accepted_parts > 0
        } else {
            applied
        },
        source_complete,
        accepted_parts,
        commit_hash,
        part_index,
        part_count,
        stage_end,
        root_digest,
        closure,
        bindings,
        entrypoint,
        resolved,
    })
}

fn selection_input(
    input: &HistoricalOwnerAttachInput,
    command: &str,
    options: &str,
    material: &str,
) -> Result<String, HistoricalOwnerAttachError> {
    validate_input(input)?;
    if material.is_empty() {
        return Err(HistoricalOwnerAttachError::ObjectMaterialRequired);
    }
    if !(valid_token(command) || valid_digest(command))
        || options.is_empty()
        || options.len() > 2 * 1024 * 1024
        || material.len() > 8 * 1024 * 1024
        || input.recover_pending_action
        || input.retain_pending_action_command_id.is_some()
        || input.selected_pending_package_stage_command_id.is_some()
        || input.selected_orphan_package_stage_command_id.is_some()
        || !input.kernel_pending_command_ids.is_empty()
    {
        return Err(HistoricalOwnerAttachError::Input);
    }
    direct_install_options_instance(options.as_bytes())
}

impl SecureHistoricalOwnerAttach {
    fn inspect_object_stage_sources(
        &self,
        input: &HistoricalOwnerAttachInput,
        command: &str,
        instance: &str,
    ) -> Result<(LegacySource, String, String, String), HistoricalOwnerAttachError> {
        let pem = read_private_file_bounded(&input.protected_owner_pkcs8_path, 2048)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        let owner = KernelIdentity::inspect_pkcs8_pem_file(&input.protected_owner_pkcs8_path)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        if owner.actor_id() != input.expected_owner_actor_id
            || owner.key_id() != input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        let state = read_private_file_bounded(&input.protected_ts_state_path, MAX_SOURCE)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        let source = parse_legacy_source_selected_install_inner(
            &state,
            input,
            None,
            None,
            None,
            Some((command, instance)),
        )?;
        if source.visibility != "PRIVATE" || source.ring.is_none() {
            return Err(invalid());
        }
        let digest = crate::ts_migration::source_snapshot_digest_allow_pending(
            &input.protected_ts_intent_db_path,
        )
        .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        Ok((source, sha256_hex(&state), sha256_hex(&pem), digest))
    }

    /// Inspect one original selected object-stage packet with full caller
    /// options/material. This authors no packet and creates no attachment row.
    fn inspect_selected_object_stage(
        &self,
        input: &HistoricalOwnerAttachInput,
        command: &str,
        options: &str,
        material: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalObjectStagePendingInventory, HistoricalOwnerAttachError> {
        if !valid_history_config(&self.config) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        let instance = selection_input(input, command, options, material)?;
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        let (source, digest, pem_digest, intent_digest) =
            self.inspect_object_stage_sources(input, command, &instance)?;
        let pending = source.pending_object_stage.as_ref().ok_or_else(invalid)?;
        let ring = source.ring.as_ref().ok_or_else(invalid)?;
        ensure_dir(&self.config.state_dir)?;
        let _lock =
            SecureStateStore::open(&self.config.state_dir.join("owner-attach-recovery.state"))
                .map_err(|_| local())?;
        let verified = self.with_preflight_replay(input, &source, cancel, |replayed, owner| {
            verify_object_stage(
                pending,
                options.as_bytes(),
                material.as_bytes(),
                ring,
                replayed,
                owner,
                input,
                false,
                None,
            )
        })?;
        let (_, after, pem_after, intent_after) =
            self.inspect_object_stage_sources(input, command, &instance)?;
        if (after, pem_after, intent_after) != (digest.clone(), pem_digest, intent_digest) {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        Ok(HistoricalObjectStagePendingInventory {
            ts_state_digest: digest,
            command_id: command.into(),
            instance_id: instance,
            source_id: scalar(&pending.marker.proof, "source_id")?,
            protocol_digest: verified.resolved.protocol_digest,
            part_index: verified.part_index,
            part_count: verified.part_count,
            original_commit_hash: verified.commit_hash,
            original_options_hash: pending.marker.request_hash.clone(),
            status: if verified.applied {
                "APPLIED_IN_SIGNED_REPLAY"
            } else {
                "PENDING_UNRESOLVED"
            }
            .into(),
        })
    }

    fn attach_selected_object_stage(
        &self,
        input: HistoricalOwnerAttachInput,
        command: &str,
        expected_digest: &str,
        options: &str,
        material: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_history_config(&self.config) || !valid_digest(expected_digest) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        let instance = selection_input(&input, command, options, material)?;
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        let (source, digest, pem_digest, intent_digest) =
            self.inspect_object_stage_sources(&input, command, &instance)?;
        if expected_digest != digest
            || input
                .expected_kernel_intent_db_digest
                .as_deref()
                .is_some_and(|hash| hash != intent_digest)
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        ensure_dir(&self.config.state_dir)?;
        match KernelIdentity::open(&self.identity_path()) {
            Ok(owner)
                if owner.actor_id() == input.expected_owner_actor_id
                    && owner.key_id() == input.expected_owner_key_id =>
            {
                ()
            }
            Err(KernelIdentityError::NotFound) => (),
            _ => return Err(HistoricalOwnerAttachError::Identity),
        }
        let source_owner =
            KernelIdentity::inspect_pkcs8_pem_file(&input.protected_owner_pkcs8_path)
                .map_err(|_| HistoricalOwnerAttachError::Identity)?;
        if SecureOwnerWorkspaceCreate::new(self.config.clone())
            .has_saved_workspace_for_attach(&input.workspace_id, &source_owner)
            .map_err(|_| HistoricalOwnerAttachError::Conflict)?
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        self.preflight_kernel_source(&input, cancel, Some(&[]))?;
        let lock =
            SecureStateStore::open(&self.config.state_dir.join("owner-attach-recovery.state"))
                .map_err(|_| local())?;
        let pending = source.pending_object_stage.as_ref().ok_or_else(invalid)?;
        let ring = source.ring.as_ref().ok_or_else(invalid)?;
        let verified = self.with_preflight_replay(&input, &source, cancel, |replayed, owner| {
            verify_object_stage(
                pending,
                options.as_bytes(),
                material.as_bytes(),
                ring,
                replayed,
                owner,
                &input,
                false,
                None,
            )
        })?;
        let options_value = parse_wire_json_bounded(options.as_bytes(), 64, 2 * 1024 * 1024)
            .map_err(|_| invalid())?;
        let material_value = parse_wire_json_bounded(material.as_bytes(), 64, 8 * 1024 * 1024)
            .map_err(|_| invalid())?;
        let options_wire = Zeroizing::new(canonical(&options_value)?);
        let material_wire = Zeroizing::new(canonical(&material_value)?);
        let plan_id = object_plan_id(
            &self.config.origin,
            &input,
            &digest,
            command,
            &sha256_hex(options_wire.as_bytes()),
            &sha256_hex(material_wire.as_bytes()),
        )?;
        let attach_id = object_attach_id(&plan_id);
        let store = SecureStateStore::open(&self.history_path()).map_err(|_| local())?;
        let mut history = read_history(&store, &self.config.origin)?;
        if let Some((id, old)) = history
            .rows
            .iter()
            .find(|(_, row)| row.input.workspace_id == input.workspace_id)
        {
            if id != &attach_id
                || old.input != input
                || old.pending_object_stage.as_ref().is_none_or(|old| {
                    old.plan_id != plan_id
                        || old.command_id != command
                        || old.instance_id != instance
                })
                || old.ts_state_sha256 != digest
                || old.owner_pem_sha256 != pem_digest
                || old.ts_intent_sha256 != intent_digest
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            drop(history);
            drop(store);
            drop(lock);
            return self.resume_attachment(&attach_id, cancel);
        }
        if history.rows.len() >= MAX_HISTORY {
            return Err(local());
        }
        let manifest = ObjectStagePlan {
            version: if valid_digest(command) { 2 } else { 1 },
            origin: self.config.origin.clone(),
            plan_id: plan_id.clone(),
            attach_id: attach_id.clone(),
            workspace_id: input.workspace_id.clone(),
            owner_actor_id: input.expected_owner_actor_id.clone(),
            owner_key_id: input.expected_owner_key_id.clone(),
            command_id: command.into(),
            instance_id: instance.clone(),
            original_commit_hash: verified.commit_hash,
            source_epoch: ring.epochs().last().ok_or_else(invalid)?,
            ts_state_sha256: digest.clone(),
            owner_pem_sha256: pem_digest.clone(),
            ts_intent_sha256: intent_digest.clone(),
            options_sha256: sha256_hex(options_wire.as_bytes()),
            material_sha256: sha256_hex(material_wire.as_bytes()),
        };
        self.save_object_stage_plan(&input, &manifest, &options_wire, &material_wire)?;
        let row = SavedAttach {
            input,
            visibility: source.visibility,
            ts_state_sha256: digest,
            owner_pem_sha256: pem_digest,
            ts_intent_sha256: intent_digest,
            source_sequence: source.sequence,
            source_head: source.head,
            source_policy_hash: source.policy_hash,
            attached_sequence: None,
            attached_head: None,
            kernel_import: None,
            retained_action_commit_hash: None,
            retained_action_command_id: None,
            retained_upgrade_accepted: false,
            retained_action_accepted: false,
            pending_package_stage: None,
            pending_multipart_plan_id: None,
            orphan_multipart_plan_id: None,
            orphan_package_stage: None,
            pending_direct_install_plan_id: None,
            pending_direct_install_command_id: None,
            pending_direct_install_instance_id: None,
            pending_direct_install_begin_accepted: false,
            pending_direct_install_complete: false,
            pending_object_stage: Some(SavedObjectStage {
                plan_id,
                command_id: command.into(),
                instance_id: instance,
                stage_accepted: false,
                native_begin_command_id: None,
                complete: false,
            }),
        };
        history.rows.insert(attach_id.clone(), row);
        save_history(&store, &history)?;
        drop(history);
        drop(store);
        drop(lock);
        #[cfg(test)]
        if TEST_STOP_AFTER_ATTACH_ROW.swap(false, Ordering::SeqCst) {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        self.resume_attachment(&attach_id, cancel)
    }

    pub(super) fn object_stage_plan_directory(&self, plan_id: &str) -> PathBuf {
        self.config
            .state_dir
            .join("owner-object-stage-plans")
            .join(plan_id)
    }

    fn save_object_stage_plan(
        &self,
        input: &HistoricalOwnerAttachInput,
        manifest: &ObjectStagePlan,
        options: &str,
        material: &str,
    ) -> Result<(), HistoricalOwnerAttachError> {
        let root = self.config.state_dir.join("owner-object-stage-plans");
        ensure_dir(&root)?;
        let final_directory = self.object_stage_plan_directory(&manifest.plan_id);
        if final_directory.exists() {
            // An inert prior plan can only be reused byte-for-byte.
            let bytes = SecureStateStore::open(&final_directory.join("plan-manifest.state"))
                .map_err(|_| local())?
                .read_exact_secret()
                .map_err(|_| local())?
                .ok_or_else(local)?;
            let existing: ObjectStagePlan = serde_json::from_slice(&bytes).map_err(|_| local())?;
            if &existing != manifest {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            for (name, hash, bound) in [
                ("source-state.state", &manifest.ts_state_sha256, MAX_SOURCE),
                ("owner-pem.state", &manifest.owner_pem_sha256, 2048),
                ("options.state", &manifest.options_sha256, 2 * 1024 * 1024),
                ("material.state", &manifest.material_sha256, 8 * 1024 * 1024),
            ] {
                let bytes = SecureStateStore::open(&final_directory.join(name))
                    .map_err(|_| local())?
                    .read_exact_secret()
                    .map_err(|_| local())?
                    .ok_or_else(local)?;
                if bytes.len() > bound || sha256_hex(&bytes) != *hash {
                    return Err(HistoricalOwnerAttachError::Conflict);
                }
            }
            if crate::ts_migration::source_snapshot_digest_allow_pending(
                &final_directory.join("source-intents.sqlite"),
            )
            .map_err(|_| local())?
                != manifest.ts_intent_sha256
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            let (_, state_after, pem_after, intents_after) = self.inspect_object_stage_sources(
                input,
                &manifest.command_id,
                &manifest.instance_id,
            )?;
            if state_after != manifest.ts_state_sha256
                || pem_after != manifest.owner_pem_sha256
                || intents_after != manifest.ts_intent_sha256
            {
                return Err(HistoricalOwnerAttachError::SourceChanged);
            }
            return Ok(());
        }
        let staging = new_direct_install_plan_staging(&root)?;
        let directory = staging.path();
        let state = read_private_file_bounded(&input.protected_ts_state_path, MAX_SOURCE)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        let pem = read_private_file_bounded(&input.protected_owner_pkcs8_path, 2048)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        if sha256_hex(&state) != manifest.ts_state_sha256
            || sha256_hex(&pem) != manifest.owner_pem_sha256
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        for (name, bytes) in [
            ("source-state.state", state.as_slice()),
            ("owner-pem.state", pem.as_slice()),
            ("options.state", options.as_bytes()),
            ("material.state", material.as_bytes()),
        ] {
            SecureStateStore::open(&directory.join(name))
                .map_err(|_| local())?
                .write_exact(bytes)
                .map_err(|_| local())?;
        }
        let backup = directory.join("source-intents.sqlite");
        let backup_digest = crate::ts_migration::checked_backup_snapshot_allow_pending(
            &input.protected_ts_intent_db_path,
            &backup,
        )
        .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        if backup_digest != manifest.ts_intent_sha256
            || std::fs::metadata(&backup).map_err(|_| local())?.len() > 256 * 1024 * 1024
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        let (_, state_after, pem_after, intents_after) =
            self.inspect_object_stage_sources(input, &manifest.command_id, &manifest.instance_id)?;
        if state_after != manifest.ts_state_sha256
            || pem_after != manifest.owner_pem_sha256
            || intents_after != manifest.ts_intent_sha256
        {
            return Err(HistoricalOwnerAttachError::SourceChanged);
        }
        SecureStateStore::open(&directory.join("plan-manifest.state"))
            .map_err(|_| local())?
            .write_exact(&serde_json::to_vec(manifest).map_err(|_| local())?)
            .map_err(|_| local())?;
        publish_orphan_plan_staging(&staging, &final_directory, &root)
    }

    fn load_object_stage_plan(
        &self,
        attach_id: &str,
        row: &SavedAttach,
    ) -> Result<LoadedObjectStagePlan, HistoricalOwnerAttachError> {
        let saved = row.pending_object_stage.as_ref().ok_or_else(invalid)?;
        if !valid_token(&saved.plan_id)
            || !(valid_token(&saved.command_id) || valid_digest(&saved.command_id))
            || !valid_token(&saved.instance_id)
            || row.pending_direct_install_plan_id.is_some()
            || row.pending_multipart_plan_id.is_some()
            || row.orphan_multipart_plan_id.is_some()
            || row.pending_package_stage.is_some()
            || row.orphan_package_stage.is_some()
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let directory = self.object_stage_plan_directory(&saved.plan_id);
        let load =
            |name: &str, max: usize| -> Result<Zeroizing<Vec<u8>>, HistoricalOwnerAttachError> {
                let bytes = SecureStateStore::open(&directory.join(name))
                    .map_err(|_| local())?
                    .read_exact_secret()
                    .map_err(|_| local())?
                    .ok_or_else(local)?;
                if bytes.len() > max {
                    return Err(local());
                }
                Ok(bytes)
            };
        let manifest_bytes = load("plan-manifest.state", 32_768)?;
        let manifest: ObjectStagePlan =
            serde_json::from_slice(&manifest_bytes).map_err(|_| local())?;
        if manifest.version
            != if valid_digest(&manifest.command_id) {
                2
            } else {
                1
            }
            || manifest.origin != self.config.origin
            || manifest.plan_id != saved.plan_id
            || manifest.attach_id != attach_id
            || object_attach_id(&manifest.plan_id) != attach_id
            || manifest.command_id != saved.command_id
            || manifest.instance_id != saved.instance_id
            || manifest.workspace_id != row.input.workspace_id
            || manifest.owner_actor_id != row.input.expected_owner_actor_id
            || manifest.owner_key_id != row.input.expected_owner_key_id
            || manifest.ts_state_sha256 != row.ts_state_sha256
            || manifest.owner_pem_sha256 != row.owner_pem_sha256
            || manifest.ts_intent_sha256 != row.ts_intent_sha256
            || !valid_digest(&manifest.original_commit_hash)
            || !valid_digest(&manifest.options_sha256)
            || !valid_digest(&manifest.material_sha256)
            || object_plan_id(
                &manifest.origin,
                &row.input,
                &manifest.ts_state_sha256,
                &manifest.command_id,
                &manifest.options_sha256,
                &manifest.material_sha256,
            )? != manifest.plan_id
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let state = load("source-state.state", MAX_SOURCE)?;
        let pem = load("owner-pem.state", 2048)?;
        let options = load("options.state", 2 * 1024 * 1024)?;
        let material = load("material.state", 8 * 1024 * 1024)?;
        if sha256_hex(&state) != manifest.ts_state_sha256
            || sha256_hex(&pem) != manifest.owner_pem_sha256
            || sha256_hex(&options) != manifest.options_sha256
            || sha256_hex(&material) != manifest.material_sha256
            || direct_install_options_instance(&options)? != manifest.instance_id
            || crate::ts_migration::source_snapshot_digest_allow_pending(
                &directory.join("source-intents.sqlite"),
            )
            .map_err(|_| local())?
                != manifest.ts_intent_sha256
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let source = parse_legacy_source_selected_install_inner(
            &state,
            &row.input,
            None,
            None,
            None,
            Some((&manifest.command_id, &manifest.instance_id)),
        )?;
        if source.visibility != "PRIVATE"
            || source.sequence != row.source_sequence
            || source.head != row.source_head
            || source.policy_hash != row.source_policy_hash
            || source.ring.as_ref().and_then(|ring| ring.epochs().last())
                != Some(manifest.source_epoch)
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        Ok(LoadedObjectStagePlan {
            manifest,
            source,
            pem,
            options,
            material,
        })
    }
}

impl SecureHistoricalOwnerAttach {
    pub(super) fn inspect_object_stage_saved_sources(
        &self,
        row: &SavedAttach,
    ) -> Result<
        (
            LegacySource,
            Option<Zeroizing<Vec<u8>>>,
            Option<Zeroizing<Vec<u8>>>,
            PathBuf,
        ),
        HistoricalOwnerAttachError,
    > {
        let saved = row.pending_object_stage.as_ref().ok_or_else(invalid)?;
        let loaded = self.load_object_stage_plan(&object_attach_id(&saved.plan_id), row)?;
        let intents = self
            .object_stage_plan_directory(&saved.plan_id)
            .join("source-intents.sqlite");
        Ok((loaded.source, Some(loaded.pem), None, intents))
    }

    fn load_native_object_remainder(
        &self,
        plan: &LoadedObjectStagePlan,
    ) -> Result<Option<NativeObjectRemainder>, HistoricalOwnerAttachError> {
        let store = SecureStateStore::open(
            &self
                .object_stage_plan_directory(&plan.manifest.plan_id)
                .join("native-remainder.state"),
        )
        .map_err(|_| local())?;
        let Some(bytes) = store.read_exact_secret().map_err(|_| local())? else {
            return Ok(None);
        };
        if bytes.len() > MAX_SOURCE {
            return Err(local());
        }
        let packet: NativeObjectRemainder =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if packet.version != 1
            || packet.plan_id != plan.manifest.plan_id
            || packet.packets.is_empty()
            || packet.packets.len()
                > plan
                    .source
                    .pending_object_stage
                    .as_ref()
                    .ok_or_else(invalid)?
                    .marker
                    .proof
                    .get("parts")
                    .and_then(|v| {
                        if let WireValue::Array(a) = v {
                            Some(a.len())
                        } else {
                            None
                        }
                    })
                    .ok_or_else(invalid)?
            || packet.packets.iter().any(|part| {
                !valid_token(&part.command_id)
                    || part.command_id == plan.manifest.command_id
                    || !valid_digest(&part.commit_hash)
            })
        {
            return Err(invalid());
        }
        Ok(Some(packet))
    }

    fn load_native_object_begin(
        &self,
        plan: &LoadedObjectStagePlan,
        row: &SavedAttach,
    ) -> Result<Option<NativeObjectBegin>, HistoricalOwnerAttachError> {
        let store = SecureStateStore::open(
            &self
                .object_stage_plan_directory(&plan.manifest.plan_id)
                .join("native-begin.state"),
        )
        .map_err(|_| local())?;
        let bytes = store.read_exact_secret().map_err(|_| local())?;
        let saved = row.pending_object_stage.as_ref().ok_or_else(invalid)?;
        let Some(bytes) = bytes else {
            if saved.native_begin_command_id.is_some() || saved.complete {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            return Ok(None);
        };
        if bytes.len() > 350_000 {
            return Err(local());
        }
        let native: NativeObjectBegin = serde_json::from_slice(&bytes).map_err(|_| local())?;
        if native.version != 1
            || native.plan_id != plan.manifest.plan_id
            || !valid_token(&native.command_id)
            || native.command_id == plan.manifest.command_id
            || !valid_digest(&native.commit_hash)
            || saved
                .native_begin_command_id
                .as_ref()
                .is_some_and(|old| old != &native.command_id)
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        Ok(Some(native))
    }

    fn verify_native_object_begin(
        &self,
        attach_id: &str,
        row: &SavedAttach,
        plan: &LoadedObjectStagePlan,
        native: &NativeObjectBegin,
        original: &VerifiedObjectStage,
        replayed: &TransportReplayedJournal,
        owner: &KernelIdentity,
    ) -> Result<VerifiedLegacyDirectBegin, HistoricalOwnerAttachError> {
        let stage = plan
            .source
            .pending_object_stage
            .as_ref()
            .ok_or_else(invalid)?;
        let ring = plan.source.ring.as_ref().ok_or_else(invalid)?;
        let request =
            peerwork_core::crypto::decode_base64url(&native.request_b64).map_err(|_| invalid())?;
        // This is an explicit native-authored packet from the protected plan.
        // No TS state, pending map, or historical BEGIN is synthesized.
        let candidate = LegacyPendingInstallBegin {
            command_id: native.command_id.clone(),
            instance_id: plan.manifest.instance_id.clone(),
            intent_hash: original.resolved.intent_hash.clone(),
            path: stage.path.clone(),
            request: Zeroizing::new(request),
            retained_installed_instances: vec![],
            object_stage: Some(stage.marker.clone()),
        };
        let mut verified = verify_exact_direct_install_begin(
            &candidate,
            &plan.options,
            &plan.material,
            ring,
            replayed,
            owner,
            &row.input,
        )?;
        if verified.commit_hash != native.commit_hash
            || verified.imported.command_id != native.command_id
            || verified.imported.instance_id != plan.manifest.instance_id
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        verified.imported.attach_id = attach_id.into();
        Ok(verified)
    }

    fn write_object_stage_history(
        &self,
        attach_id: &str,
        row: &SavedAttach,
        applied: bool,
        native: Option<&str>,
        completed: bool,
        replayed: &TransportReplayedJournal,
        kernel: Option<SavedKernelImport>,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        let store = SecureStateStore::open(&self.history_path()).map_err(|_| local())?;
        let mut history = read_history(&store, &self.config.origin)?;
        let saved = history
            .rows
            .get_mut(attach_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)?;
        if saved.input != row.input
            || saved
                .pending_object_stage
                .as_ref()
                .map(|stage| (&stage.plan_id, &stage.command_id, &stage.instance_id))
                != row
                    .pending_object_stage
                    .as_ref()
                    .map(|stage| (&stage.plan_id, &stage.command_id, &stage.instance_id))
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let stage = saved.pending_object_stage.as_mut().ok_or_else(invalid)?;
        if stage.complete && !applied
            || stage
                .native_begin_command_id
                .as_deref()
                .is_some_and(|old| Some(old) != native)
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        stage.stage_accepted |= applied;
        if let Some(native) = native {
            stage.native_begin_command_id = Some(native.into());
        }
        stage.complete |= completed;
        if let Some(kernel) = kernel {
            if saved
                .kernel_import
                .as_ref()
                .is_some_and(|old| old != &kernel)
            {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            saved.kernel_import = Some(kernel);
        }
        saved.attached_sequence = Some(replayed.replay().sequence());
        saved.attached_head = replayed.replay().head().map(str::to_owned);
        let result = saved.clone();
        save_history(&store, &history)?;
        Ok(summary(attach_id, &result))
    }

    /// Root recovery lock is held. Importing this generation never posts or
    /// authors a packet; both original stage and any saved native BEGIN are
    /// re-proved before key activation/imported InstallRow creation.
    pub(super) fn resume_object_stage_attachment(
        &self,
        attach_id: &str,
        row: &SavedAttach,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        let plan = self.load_object_stage_plan(attach_id, row)?;
        let ring = plan.source.ring.as_ref().ok_or_else(invalid)?;
        let stage = plan
            .source
            .pending_object_stage
            .as_ref()
            .ok_or_else(invalid)?;
        let native = self.load_native_object_begin(&plan, row)?;
        let remaining = self.load_native_object_remainder(&plan)?;
        let owner = match KernelIdentity::open(&self.identity_path()) {
            Ok(owner) => owner,
            Err(KernelIdentityError::NotFound) => {
                KernelIdentity::import_pkcs8_pem_bytes(&self.identity_path(), &plan.pem)
                    .map_err(|_| HistoricalOwnerAttachError::Identity)?
            }
            Err(_) => return Err(HistoricalOwnerAttachError::Identity),
        };
        if owner.actor_id() != row.input.expected_owner_actor_id
            || owner.key_id() != row.input.expected_owner_key_id
        {
            return Err(HistoricalOwnerAttachError::Identity);
        }
        let directory = self.workspace_dir(&row.input.workspace_id);
        ensure_dir(&directory)?;
        let mut lifecycle = SecureLifecycle::open(
            &directory.join("lifecycle.state"),
            &crate::transport::canonical_lifecycle_origin(&self.config.origin, self.config.allow_loopback_http).map_err(|_| HistoricalOwnerAttachError::Input)?,
            owner.actor_id(),
            &row.input.workspace_id,
            owner.actor_id(),
            owner.key_id(),
        )
        .map_err(|_| local())?;
        lifecycle
            .stage_historical_owner_ring(ring)
            .map_err(|_| HistoricalOwnerAttachError::Conflict)?;
        drop(lifecycle);
        let replayed = SecureReadAccess::new(self.attach_read_config(&row.input))
            .replay_checked_attach_generation(cancel)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        if !replayed.replay().contains_checkpoint(
            row.source_sequence,
            row.source_head.as_deref(),
            &row.source_policy_hash,
        ) {
            return Err(HistoricalOwnerAttachError::Verification);
        }
        let original = verify_object_stage(
            stage,
            &plan.options,
            &plan.material,
            ring,
            &replayed,
            &owner,
            &row.input,
            native.is_some(),
            remaining.as_ref(),
        )?;
        if original.commit_hash != plan.manifest.original_commit_hash {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let verified = native
            .as_ref()
            .map(|native| {
                self.verify_native_object_begin(
                    attach_id, row, &plan, native, &original, &replayed, &owner,
                )
            })
            .transpose()?;
        let kernel = self.import_selected_kernel_source(row, &owner, cancel)?;
        let mut lifecycle = SecureLifecycle::open(
            &directory.join("lifecycle.state"),
            &crate::transport::canonical_lifecycle_origin(&self.config.origin, self.config.allow_loopback_http).map_err(|_| HistoricalOwnerAttachError::Input)?,
            owner.actor_id(),
            &row.input.workspace_id,
            owner.actor_id(),
            owner.key_id(),
        )
        .map_err(|_| local())?;
        let (base_sequence, base_head, base_policy) = if native.is_some() {
            let (_, cp) =
                replay_install_step_predecessor(&replayed, ring, &row.input, original.stage_end)?;
            let cp = parse_wire_json_bounded(&cp, 32, 8192).map_err(|_| invalid())?;
            (
                original.stage_end,
                Some(scalar(&cp, "head")?),
                scalar(&cp, "policy_hash")?,
            )
        } else {
            (
                row.source_sequence,
                row.source_head.clone(),
                row.source_policy_hash.clone(),
            )
        };
        if let Some(verified) = verified {
            if replayed.replay().structure_status() == StructureStatus::Seeding {
                if !verified.applied {
                    return Err(invalid());
                }
                lifecycle
                    .activate_verified_historical_owner_pending_begin(
                        ring,
                        &replayed,
                        base_sequence,
                        base_head.as_deref(),
                        &base_policy,
                        &verified.imported.commit_hash,
                        &verified.imported.policy_hash,
                    )
                    .map_err(|_| HistoricalOwnerAttachError::Verification)?;
            } else {
                lifecycle
                    .activate_verified_historical_owner(
                        ring,
                        &replayed,
                        base_sequence,
                        base_head.as_deref(),
                        &base_policy,
                    )
                    .map_err(|_| HistoricalOwnerAttachError::Verification)?;
            }
            drop(lifecycle);
            SecurePrivatePackageInstall::new(self.profile_config(&row.input))
                .save_native_object_begin_row_for_attach(verified.imported, &plan.manifest.plan_id)
                .map_err(|_| HistoricalOwnerAttachError::Conflict)?;
        } else {
            lifecycle
                .activate_verified_historical_owner(
                    ring,
                    &replayed,
                    base_sequence,
                    base_head.as_deref(),
                    &base_policy,
                )
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
            drop(lifecycle);
        }
        if replayed.replay().structure_status() == StructureStatus::Active {
            SecureReadProfile::new(self.profile_config(&row.input))
                .read_latest_json_with_cancel(cancel)
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        }
        self.write_object_stage_history(
            attach_id,
            row,
            original.applied,
            native.as_ref().map(|native| native.command_id.as_str()),
            false,
            &replayed,
            Some(kernel),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn continue_object_stage_remainder(
        &self,
        attach_id: &str,
        row: &SavedAttach,
        plan: &LoadedObjectStagePlan,
        owner: &KernelIdentity,
        replayed: &TransportReplayedJournal,
        access: &SecureReadAccess,
        original: &VerifiedObjectStage,
        remaining: Option<NativeObjectRemainder>,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if (!original.applied && !original.marker_only)
            || original.source_complete
            || original.accepted_parts >= original.part_count
        {
            return Err(invalid());
        }
        let stage = plan
            .source
            .pending_object_stage
            .as_ref()
            .ok_or_else(invalid)?;
        let ring = plan.source.ring.as_ref().ok_or_else(invalid)?;
        let mut remaining = remaining.unwrap_or(NativeObjectRemainder {
            version: 1,
            plan_id: plan.manifest.plan_id.clone(),
            packets: vec![],
        });
        let author_next = remaining
            .packets
            .last()
            .is_none_or(|p| p.part_index < original.accepted_parts);
        if author_next {
            let index = original.accepted_parts;
            let proof = &stage.marker.proof;
            verify_protocol_object_source_prefix(proof, replayed.replay())
                .map_err(|_| invalid())?;
            let parts = parse_wire_json_bounded(&stage.marker.parts_wire, 64, MAX_SOURCE)
                .map_err(|_| invalid())?;
            let WireValue::Array(parts) = parts else {
                return Err(invalid());
            };
            let policy = replayed
                .signed_policy_by_hash(replayed.replay().policy_hash())
                .ok_or_else(invalid)?;
            let mut random = [0u8; 32];
            OsRng.try_fill_bytes(&mut random).map_err(|_| local())?;
            let command = base64url(&random);
            if command == plan.manifest.command_id
                || remaining.packets.iter().any(|p| p.command_id == command)
            {
                return Err(local());
            }
            let issued = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| local())?
                    .as_millis(),
            )
            .map_err(|_| local())?;
            let prepared = prepare_private_protocol_object_stage(
                proof,
                parts.get(index).ok_or_else(invalid)?,
                index,
                replayed.checkpoint_canonical_json().as_bytes(),
                policy,
                &command,
                issued,
                owner.signing_key(),
                ring.key_at(plan.manifest.source_epoch)
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            let previous = if remaining.packets.is_empty() {
                None
            } else {
                Some(serde_json::to_vec(&remaining).map_err(|_| local())?)
            };
            remaining.packets.push(NativeObjectStagePacket {
                part_index: index,
                command_id: command,
                commit_hash: prepared.commit_hash().into(),
                request_b64: base64url(prepared.request_wire()),
            });
            let store = SecureStateStore::open(
                &self
                    .object_stage_plan_directory(&plan.manifest.plan_id)
                    .join("native-remainder.state"),
            )
            .map_err(|_| local())?;
            let saved = store.read_exact_secret().map_err(|_| local())?;
            if saved.as_deref().map(Vec::as_slice) != previous.as_deref() {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            let bytes = serde_json::to_vec(&remaining).map_err(|_| local())?;
            if bytes.len() > MAX_SOURCE {
                return Err(local());
            }
            store.write_exact(&bytes).map_err(|_| local())?;
            #[cfg(test)]
            if TEST_STOP_AFTER_OBJECT_REMAINDER_ROW.swap(false, Ordering::SeqCst) {
                return Err(HistoricalOwnerAttachError::Cancelled);
            }
        }
        let packet = remaining.packets.last().ok_or_else(invalid)?;
        let checked = verify_object_stage(
            stage,
            &plan.options,
            &plan.material,
            ring,
            replayed,
            owner,
            &row.input,
            false,
            Some(&remaining),
        )?;
        if checked.source_complete {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let request =
            peerwork_core::crypto::decode_base64url(&packet.request_b64).map_err(|_| invalid())?;
        let mut journal = SecureIntentJournal::open(
            &self
                .workspace_dir(&row.input.workspace_id)
                .join("private-object-stage-intents.state"),
            &self.config.origin,
            owner.actor_id(),
        )
        .map_err(|_| local())?;
        journal
            .prepare(SecurePacketInput {
                intent_id: &packet.command_id,
                path: &stage.path,
                action_id: "secure.protocol-object.stage",
                workspace_id: Some(&row.input.workspace_id),
                trusted_owner_key: Some(owner.key_id()),
                intent_digest: &packet.commit_hash,
                exact_request: &request,
            })
            .map_err(|_| HistoricalOwnerAttachError::Conflict)?;
        if journal
            .exact_request(&packet.command_id)
            .map_err(|_| invalid())?
            != request
        {
            return Err(invalid());
        }
        let mut config = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        config.allow_loopback_http = self.config.allow_loopback_http;
        let transport =
            HttpTransport::new(config).map_err(|_| HistoricalOwnerAttachError::Verification)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| local())?;
        let response = runtime
            .block_on(transport.post_exact(&stage.path, request, cancel))
            .map_err(|_| HistoricalOwnerAttachError::PendingObjectStageUnresolved)?;
        if !response.wire.is_empty() {
            journal
                .observe_response(&packet.command_id, &response.wire)
                .map_err(|_| local())?;
        }
        drop(journal);
        let after = access
            .replay_checked_attach_generation(cancel)
            .map_err(|_| HistoricalOwnerAttachError::PendingObjectStageUnresolved)?;
        let checked = verify_object_stage(
            stage,
            &plan.options,
            &plan.material,
            ring,
            &after,
            owner,
            &row.input,
            false,
            Some(&remaining),
        )?;
        if checked.accepted_parts != packet.part_index + 1 {
            return Err(HistoricalOwnerAttachError::PendingObjectStageUnresolved);
        }
        self.write_object_stage_history(attach_id, row, true, None, false, &after, None)
    }

    /// Reconcile the original final stage packet, then explicitly authorize a
    /// distinct durable native BEGIN and ordinary attach-owned continuation.
    fn recover_selected_object_stage(
        &self,
        attach_id: &str,
        expected_command: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_history_config(&self.config)
            || !valid_token(attach_id)
            || !(valid_token(expected_command) || valid_digest(expected_command))
        {
            return Err(HistoricalOwnerAttachError::Input);
        }
        if cancel.is_cancelled() {
            return Err(HistoricalOwnerAttachError::Cancelled);
        }
        let _lock =
            SecureStateStore::open(&self.config.state_dir.join("owner-attach-recovery.state"))
                .map_err(|_| local())?;
        let store = SecureStateStore::open(&self.history_path()).map_err(|_| local())?;
        let history = read_history(&store, &self.config.origin)?;
        let row = history
            .rows
            .get(attach_id)
            .ok_or(HistoricalOwnerAttachError::NotFound)?
            .clone();
        drop(history);
        drop(store);
        let saved = row
            .pending_object_stage
            .as_ref()
            .ok_or(HistoricalOwnerAttachError::NotFound)?;
        if row.attached_sequence.is_none()
            || row.kernel_import.is_none()
            || saved.command_id != expected_command
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let plan = self.load_object_stage_plan(attach_id, &row)?;
        let owner = KernelIdentity::open(&self.identity_path())
            .map_err(|_| HistoricalOwnerAttachError::Identity)?;
        let pending = plan
            .source
            .pending_object_stage
            .as_ref()
            .ok_or_else(invalid)?;
        let ring = plan.source.ring.as_ref().ok_or_else(invalid)?;
        let access = SecureReadAccess::new(self.attach_read_config(&row.input));
        let replayed = access
            .replay_checked_attach_generation(cancel)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        let mut native = self.load_native_object_begin(&plan, &row)?;
        let mut remaining = self.load_native_object_remainder(&plan)?;
        let verified = verify_object_stage(
            pending,
            &plan.options,
            &plan.material,
            ring,
            &replayed,
            &owner,
            &row.input,
            native.is_some(),
            remaining.as_ref(),
        )?;
        if verified.commit_hash != plan.manifest.original_commit_hash {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        if !verified.marker_only && !verified.applied {
            let mut journal = SecureIntentJournal::open(
                &self
                    .workspace_dir(&row.input.workspace_id)
                    .join("private-object-stage-intents.state"),
                &self.config.origin,
                owner.actor_id(),
            )
            .map_err(|_| local())?;
            journal
                .prepare(SecurePacketInput {
                    intent_id: expected_command,
                    path: &pending.path,
                    action_id: "secure.protocol-object.stage",
                    workspace_id: Some(&row.input.workspace_id),
                    trusted_owner_key: Some(owner.key_id()),
                    intent_digest: &verified.commit_hash,
                    exact_request: &pending.request,
                })
                .map_err(|_| HistoricalOwnerAttachError::Conflict)?;
            let mut config = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
            config.allow_loopback_http = self.config.allow_loopback_http;
            let transport =
                HttpTransport::new(config).map_err(|_| HistoricalOwnerAttachError::Verification)?;
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| local())?;
            let response = runtime
                .block_on(transport.post_exact(&pending.path, pending.request.to_vec(), cancel))
                .map_err(|_| HistoricalOwnerAttachError::PendingObjectStageUnresolved)?;
            if !response.wire.is_empty() {
                journal
                    .observe_response(expected_command, &response.wire)
                    .map_err(|_| local())?;
            }
            drop(journal);
            let after = access
                .replay_checked_attach_generation(cancel)
                .map_err(|_| HistoricalOwnerAttachError::PendingObjectStageUnresolved)?;
            let accepted = verify_object_stage(
                pending,
                &plan.options,
                &plan.material,
                ring,
                &after,
                &owner,
                &row.input,
                false,
                remaining.as_ref(),
            )?;
            if !accepted.applied {
                return Err(HistoricalOwnerAttachError::PendingObjectStageUnresolved);
            }
            return self
                .write_object_stage_history(attach_id, &row, true, None, false, &after, None);
        }
        if !verified.source_complete {
            return self.continue_object_stage_remainder(
                attach_id,
                &row,
                &plan,
                &owner,
                &replayed,
                &access,
                &verified,
                remaining.take(),
                cancel,
            );
        }
        if native.is_none() {
            // Stage ancestry and complete compiler value are authenticated at
            // this exact head. Allocate/sign once, then save before any POST.
            let mut random = [0u8; 32];
            OsRng.try_fill_bytes(&mut random).map_err(|_| local())?;
            let command = base64url(&random);
            if command == expected_command
                || remaining
                    .as_ref()
                    .is_some_and(|r| r.packets.iter().any(|p| p.command_id == command))
            {
                return Err(local());
            }
            let issued = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| local())?
                .as_millis();
            let issued = u64::try_from(issued).map_err(|_| local())?;
            let (prefix, checkpoint) =
                replay_install_step_predecessor(&replayed, ring, &row.input, verified.stage_end)?;
            let policy = replayed
                .signed_policy_by_hash(prefix.policy_hash())
                .ok_or_else(invalid)?;
            let prepared = prepare_private_direct_install_begin_with_object_source(
                verified.closure.as_bytes(),
                verified.bindings.as_bytes(),
                &verified.root_digest,
                &verified.resolved.protocol_digest,
                &checkpoint,
                policy,
                prefix.objects(),
                verified.resolved.grants_json.as_bytes(),
                verified
                    .resolved
                    .disclose_json
                    .as_deref()
                    .unwrap_or("[]")
                    .as_bytes(),
                &pending.instance_id,
                &verified.entrypoint,
                &command,
                issued,
                owner.signing_key(),
                ring.key_at(plan.manifest.source_epoch)
                    .ok_or_else(invalid)?,
                &pending.marker.proof,
            )
            .map_err(|_| invalid())?;
            let packet = NativeObjectBegin {
                version: 1,
                plan_id: plan.manifest.plan_id.clone(),
                command_id: command,
                commit_hash: prepared.commit_hash().into(),
                request_b64: base64url(prepared.request_wire()),
            };
            let store = SecureStateStore::open(
                &self
                    .object_stage_plan_directory(&plan.manifest.plan_id)
                    .join("native-begin.state"),
            )
            .map_err(|_| local())?;
            if store.read_exact_secret().map_err(|_| local())?.is_some() {
                return Err(HistoricalOwnerAttachError::Conflict);
            }
            store
                .write_exact(&serde_json::to_vec(&packet).map_err(|_| local())?)
                .map_err(|_| local())?;
            native = Some(packet);
        }
        let native = native.as_ref().ok_or_else(invalid)?;
        // This revalidates both the original stage source and new BEGIN,
        // durably binds its ID to history, and creates only an attach-owned row.
        self.resume_object_stage_attachment(attach_id, &row, cancel)?;
        let progress = SecurePrivatePackageInstall::new(self.profile_config(&row.input))
            .continue_imported_install_json_with_cancel(&native.command_id, attach_id, cancel)
            .map_err(|_| HistoricalOwnerAttachError::PendingObjectStageUnresolved)?;
        let progress: serde_json::Value = serde_json::from_str(&progress).map_err(|_| local())?;
        if progress["begin_command_id"].as_str() != Some(native.command_id.as_str())
            || progress["instance_id"].as_str() != Some(plan.manifest.instance_id.as_str())
        {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let accepted = progress["status"].as_str() == Some("ACCEPTED");
        if !accepted && progress["status"].as_str() != Some("PENDING") {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        let after = access
            .replay_checked_attach_generation(cancel)
            .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        let original = verify_object_stage(
            pending,
            &plan.options,
            &plan.material,
            ring,
            &after,
            &owner,
            &row.input,
            true,
            remaining.as_ref(),
        )?;
        self.verify_native_object_begin(attach_id, &row, &plan, native, &original, &after, &owner)?;
        if accepted {
            if after.replay().structure_status() != StructureStatus::Active {
                return Err(HistoricalOwnerAttachError::Verification);
            }
            after
                .verified_read()
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
            SecureReadProfile::new(self.profile_config(&row.input))
                .read_latest_json_with_cancel(cancel)
                .map_err(|_| HistoricalOwnerAttachError::Verification)?;
        }
        self.write_object_stage_history(
            attach_id,
            &row,
            true,
            Some(&native.command_id),
            accepted,
            &after,
            None,
        )
    }
}

impl SecureHistoricalOwnerAttach {
    pub fn inspect_pending_object_stage(
        &self,
        input: &HistoricalOwnerAttachInput,
        command: &str,
        options: &str,
        material: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalObjectStagePendingInventory, HistoricalOwnerAttachError> {
        if !valid_token(command) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        self.inspect_selected_object_stage(input, command, options, material, cancel)
    }
    pub fn attach_pending_object_stage(
        &self,
        input: HistoricalOwnerAttachInput,
        command: &str,
        digest: &str,
        options: &str,
        material: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_token(command) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        self.attach_selected_object_stage(input, command, digest, options, material, cancel)
    }
    pub fn recover_pending_object_stage(
        &self,
        id: &str,
        command: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_token(command) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        self.recover_selected_object_stage(id, command, cancel)
    }
    /// Explicit marker SHA256 selection. No original packet is claimed or reconstructed.
    pub fn inspect_object_stage_intent(
        &self,
        input: &HistoricalOwnerAttachInput,
        marker_hash: &str,
        options: &str,
        material: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalObjectStageIntentInventory, HistoricalOwnerAttachError> {
        if !valid_digest(marker_hash) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        let i =
            self.inspect_selected_object_stage(input, marker_hash, options, material, cancel)?;
        Ok(HistoricalObjectStageIntentInventory {
            ts_state_digest: i.ts_state_digest,
            marker_hash: marker_hash.into(),
            instance_id: i.instance_id,
            source_id: i.source_id,
            protocol_digest: i.protocol_digest,
            accepted_parts: i.part_index,
            part_count: i.part_count,
        })
    }
    pub fn attach_object_stage_intent(
        &self,
        input: HistoricalOwnerAttachInput,
        marker_hash: &str,
        digest: &str,
        options: &str,
        material: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_digest(marker_hash) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        self.attach_selected_object_stage(input, marker_hash, digest, options, material, cancel)
    }
    pub fn recover_object_stage_intent(
        &self,
        id: &str,
        marker_hash: &str,
        cancel: &CancellationToken,
    ) -> Result<HistoricalOwnerAttachResult, HistoricalOwnerAttachError> {
        if !valid_digest(marker_hash) {
            return Err(HistoricalOwnerAttachError::Input);
        }
        self.recover_selected_object_stage(id, marker_hash, cancel)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalObjectStageIntentInventory {
    pub ts_state_digest: String,
    pub marker_hash: String,
    pub instance_id: String,
    pub source_id: String,
    pub protocol_digest: String,
    pub accepted_parts: usize,
    pub part_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalObjectStageIntentCandidate {
    pub workspace_id: String,
    pub instance_id: String,
    pub marker_hash: String,
    pub original_command_id: Option<String>,
    pub original_options_hash: String,
    pub protocol_digest: String,
    pub part_count: usize,
}
impl SecureHistoricalOwnerAttach {
    /// Protected source candidates only. Caller-selected full options/material
    /// and authenticated signed replay are required by inspect/attach.
    pub fn object_stage_intent_candidates(
        &self,
        input: &HistoricalOwnerAttachInput,
    ) -> Result<Vec<HistoricalObjectStageIntentCandidate>, HistoricalOwnerAttachError> {
        validate_input(input)?;
        let bytes = read_private_file_bounded(&input.protected_ts_state_path, MAX_SOURCE)
            .map_err(|_| HistoricalOwnerAttachError::SourceChanged)?;
        let value = parse_wire_json_bounded(&bytes, 64, MAX_SOURCE).map_err(|_| invalid())?;
        let Some(WireValue::Object(markers)) = value.get("protocol_object_stage_intents") else {
            return Err(invalid());
        };
        if markers.len() != 1 {
            return Err(invalid());
        }
        let key = String::from_utf16(&markers[0].0).map_err(|_| invalid())?;
        let instance = key
            .strip_prefix(&format!("{}.", input.workspace_id))
            .ok_or_else(invalid)?;
        let hash = sha256_hex(canonical(&markers[0].1)?.as_bytes());
        let (source, _, _, _) = self.inspect_object_stage_sources(input, &hash, instance)?;
        let marker = source.pending_object_stage.as_ref().ok_or_else(invalid)?;
        let Some(WireValue::Array(parts)) = marker.marker.proof.get("parts") else {
            return Err(invalid());
        };
        Ok(vec![HistoricalObjectStageIntentCandidate {
            workspace_id: input.workspace_id.clone(),
            instance_id: instance.into(),
            marker_hash: hash,
            original_command_id: marker.orphan_command.clone(),
            original_options_hash: marker.marker.request_hash.clone(),
            protocol_digest: scalar(&marker.marker.proof, "protocol_digest")?,
            part_count: parts.len(),
        }])
    }
}
