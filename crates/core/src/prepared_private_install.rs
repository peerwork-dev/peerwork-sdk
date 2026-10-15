//! PRIVATE Owner package staging. The caller must obtain both checkpoints and
//! the selected policy from complete authenticated replay. This low-level
//! author is not an installation receipt or a transport authority by itself.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{open_content_wire, SealedContent},
    prepared_package_source::prepare_package_source_wire,
    prepared_secure_author::sign_private_commit,
    protocol_package_source::{package_source_id, verify_protocol_package_source},
    public_direct_install::{
        build_direct_install_begin, build_direct_install_objects_with_composition_at_ceiling,
        compile_package_closure_with_bindings_at_ceiling,
        derive_direct_install_structure_with_options, plan_public_install_snapshot,
        PublicInstallSnapshotPlan,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
/// The source compiler and verifier both limit one material to 128 parts.
pub const MAX_PACKAGE_SOURCE_PARTS: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivateInstallError {
    #[error("package material or signed staging context is invalid")]
    Invalid,
    #[error("package material exceeds the supported resource budget")]
    Resource,
    #[error("OS entropy or encrypted packet authoring failed")]
    Author,
}

/// Validate candidate proof bytes only; signed stage ancestry remains mandatory.
pub fn normalize_package_source_proof(proof: &WireValue) -> Result<WireValue, PrivateInstallError> {
    crate::protocol_package_source::validate_package_source_proof(proof)
        .map_err(|_| PrivateInstallError::Invalid)?;
    Ok(proof.clone())
}

/// Candidate shape/content only; complete authenticated staging is separate.
pub fn normalize_protocol_object_source_proof(proof: &WireValue) -> Result<WireValue, PrivateInstallError> {
    crate::protocol_object_source::validate_object_source_proof(proof).map_err(|_| PrivateInstallError::Invalid)?;
    Ok(proof.clone())
}

pub fn read_complete_protocol_object_source(proof: &WireValue, parts: &[WireValue]) -> Result<WireValue, PrivateInstallError> {
    crate::protocol_object_source::read_protocol_object_source(proof, parts).map_err(|_| PrivateInstallError::Invalid)
}

/// Verify exactly the authenticated consecutive staging prefix. An empty
/// prefix at the signed source is valid; this does not claim completion.
pub fn verify_protocol_object_source_prefix(
    proof: &WireValue, prior: &crate::replayed_secure_journal::ReplayedSecureJournal,
) -> Result<(), PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    normalize_protocol_object_source_proof(proof)?;
    let source = proof.get("source").ok_or_else(bad)?;
    let Some(WireValue::Array(parts)) = proof.get("parts") else { return Err(bad()); };
    let base = number(source, "sequence")?;
    let count = usize::try_from(prior.sequence().checked_sub(base).ok_or_else(bad)?).map_err(|_| bad())?;
    if string(source, "workspace_id")? != prior.workspace_id()
        || string(source, "owner_id")? != prior.owner_actor_id()
        || string(source, "owner_key")? != prior.owner_signing_key()
        || count > parts.len() || string(source, "policy_hash")? != prior.policy_hash()
        || !prior.contains_checkpoint(base, Some(&string(source, "head")?), prior.policy_hash()) {
        return Err(bad());
    }
    let start = usize::try_from(base).map_err(|_| bad())?;
    let operations = prior.operations().get(start..).ok_or_else(bad)?;
    if operations.len() != count { return Err(bad()); }
    for (index, (operation, descriptor)) in operations.iter().zip(parts).enumerate() {
        let input = operation.get("input").ok_or_else(bad)?;
        let stage = input.get("protocol_object_stage").ok_or_else(bad)?;
        let Some(WireValue::Array(objects)) = operation.get("objects") else { return Err(bad()); };
        if operation.object_len() != Some(4) || number(operation, "v")? != 1
            || string(operation, "kind")? != "ADMIN" || input.object_len() != Some(1)
            || stage.object_len() != Some(2) || number(stage, "part_index")? != index as u64
            || canonical_wire_value(stage.get("proof").ok_or_else(bad)?, Path::SecureArtifact).map_err(|_| bad())?
                != canonical_wire_value(proof, Path::SecureArtifact).map_err(|_| bad())?
            || objects.len() != 1 || objects[0].get("id") != descriptor.get("id") {
            return Err(bad());
        }
    }
    Ok(())
}

/// The caller supplies the exact authenticated original BEGIN predecessor.
/// Keep this wrapper strict: a valid partial prefix is not a complete source.
pub fn verify_completed_protocol_object_source(
    proof: &WireValue, prior: &crate::replayed_secure_journal::ReplayedSecureJournal,
) -> Result<WireValue, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    verify_protocol_object_source_prefix(proof, prior)?;
    let Some(WireValue::Array(parts)) = proof.get("parts") else { return Err(bad()); };
    if number(proof.get("source").ok_or_else(bad)?, "sequence")?.checked_add(parts.len() as u64)
        != Some(prior.sequence()) { return Err(bad()); }
    read_complete_protocol_object_source(proof, prior.objects())
}

/// Compile the explicit caller's original author material and compare the full
/// retained logical object. Signed prefix/current authority remain runtime
/// obligations; the marker hash alone is never historical install authority.
#[allow(clippy::too_many_arguments)]
pub fn verify_private_protocol_object_stage_material(
    closure_wire: &[u8], bindings_wire: &[u8], expected_root: &str,
    expected_protocol: &str, proof: &WireValue, parts: &[WireValue],
    signed_policy_wire: &[u8], prior_objects: &[WireValue], instance_id: &str,
    entrypoint: &str, grants_wire: &[u8], disclose_wire: &[u8], signing_key: &SigningKey,
) -> Result<Option<WireValue>, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    let logical = read_complete_protocol_object_source(proof, parts)?;
    let source = proof.get("source").ok_or_else(bad)?;
    let signed = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let policy = signed.get("payload").ok_or_else(bad)?;
    let key_id = base64url(&signing_key.verifying_key().to_bytes());
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let policy_wire = canonical_wire_value(&signed, Path::SecureArtifact).map_err(|_| bad())?;
    if number(policy, "v")? != 3 || string(policy, "visibility")? != "PRIVATE"
        || string(policy, "structure_mode")? != "STRUCTURED"
        || string(policy, "owner_id")? != actor || string(policy, "signing_key")? != key_id
        || string(source, "owner_id")? != actor || string(source, "owner_key")? != key_id
        || string(policy, "workspace_id")? != string(source, "workspace_id")?
        || string(source, "policy_hash")? != sha256_hex(policy_wire.as_bytes())
        || number(policy, "effective_sequence")? > number(source, "sequence")?
        || !verify_secure_signed_wire(policy_wire.as_bytes(), "peerwork.secure.policy.v1", &key_id).map_err(|_| bad())?
        || prior_objects.iter().any(|object| object.get("kind") == Some(&s("protocols")) && object.get("id") == Some(&s(expected_protocol))
            || object.get("kind") == Some(&s("instances")) && object.get("id") == Some(&s(instance_id))) {
        return Err(bad());
    }
    let ceiling = number(policy, "protocol_format_ceiling")?;
    let bindings = parse_wire_json_bounded(bindings_wire, 32, 65_536).map_err(|_| bad())?;
    let compiled = compile_package_closure_with_bindings_at_ceiling(closure_wire, &bindings, ceiling).map_err(|_| bad())?;
    if compiled.package_digest() != expected_root || compiled.protocol_digest() != expected_protocol {
        return Err(bad());
    }
    let built = build_direct_install_objects_with_composition_at_ceiling(compiled.manifest_wire(),
        compiled.composition(), expected_protocol, &string(source, "workspace_id")?, instance_id,
        entrypoint, number(policy, "issued_at")?, ceiling).map_err(|_| bad())?;
    if canonical_wire_value(&logical, Path::SecureArtifact).map_err(|_| bad())?
        != canonical_wire_value(built.added[0].get("value").ok_or_else(bad)?, Path::SecureArtifact).map_err(|_| bad())? {
        return Err(bad());
    }
    let disclose = parse_wire_json_bounded(disclose_wire, 32, 65_536).map_err(|_| bad())?;
    let WireValue::Array(disclose) = disclose else { return Err(bad()); };
    derive_direct_install_structure_with_options(policy.get("structure"), prior_objects, &built.added,
        expected_protocol, &built.manifest, false, &disclose).map_err(|_| bad())?;
    let mut selected_policy = policy.clone();
    apply_install_grants(&mut selected_policy, grants_wire, &built.manifest, instance_id)?;
    Ok(compiled.composition().cloned())
}

/// Verify a saved, encrypted object-stage request against its exact signed
/// predecessor and deterministic part. This never re-signs or submits it.
#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_protocol_object_stage(
    request_wire: &[u8], proof: &WireValue, part: &WireValue, part_index: usize,
    current_checkpoint_wire: &[u8], signed_policy_wire: &[u8], command_id: &str,
    signing_key: &SigningKey, epoch_key: &[u8; 32],
) -> Result<String, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    normalize_protocol_object_source_proof(proof)?;
    if !token(command_id) || request_wire.is_empty() || request_wire.len() > 220_000 { return Err(bad()); }
    let current = parse_wire_json_bounded(current_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let source = proof.get("source").ok_or_else(bad)?;
    let Some(WireValue::Array(descriptors)) = proof.get("parts") else { return Err(bad()); };
    let descriptor = descriptors.get(part_index).ok_or_else(bad)?;
    crate::protocol_object_source::validate_object_part(part).map_err(|_| bad())?;
    let signed = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let policy = signed.get("payload").ok_or_else(bad)?;
    let key_id = base64url(&signing_key.verifying_key().to_bytes());
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let policy_wire = canonical_wire_value(&signed, Path::SecureArtifact).map_err(|_| bad())?;
    let policy_hash = sha256_hex(policy_wire.as_bytes());
    if number(policy, "v")? != 3 || string(policy, "visibility")? != "PRIVATE"
        || string(policy, "structure_mode")? != "STRUCTURED" || number(policy, "epoch")? == 0
        || !matches!(number(policy, "protocol_format_ceiling")?, 1 | 2)
        || string(policy, "owner_id")? != actor || string(policy, "signing_key")? != key_id
        || string(policy, "workspace_id")? != string(source, "workspace_id")?
        || string(source, "owner_id")? != actor || string(source, "owner_key")? != key_id
        || string(&current, "owner_id")? != actor || string(&current, "owner_key")? != key_id
        || string(&current, "workspace_id")? != string(source, "workspace_id")?
        || string(&current, "policy_hash")? != policy_hash || string(source, "policy_hash")? != policy_hash
        || number(policy, "effective_sequence")? > number(source, "sequence")?
        || number(source, "sequence")?.checked_add(part_index as u64) != Some(number(&current, "sequence")?)
        || !verify_secure_signed_wire(policy_wire.as_bytes(), "peerwork.secure.policy.v1", &key_id).map_err(|_| bad())?
        || part.get("id") != descriptor.get("id") { return Err(bad()); }
    let value = part.get("value").ok_or_else(bad)?;
    if value.get("source_id") != proof.get("source_id") || value.get("workspace_id") != proof.get("workspace_id")
        || number(value, "index")? != part_index as u64 || value.get("bytes") != descriptor.get("bytes")
        || value.get("sha256") != descriptor.get("sha256") { return Err(bad()); }
    let request = parse_wire_json_bounded(request_wire, 64, 220_000).map_err(|_| bad())?;
    let commit = request.get("commit").ok_or_else(bad)?;
    let commit_wire = canonical_wire_value(commit, Path::SecureArtifact).map_err(|_| bad())?;
    if request.object_len() != Some(1) || commit.object_len() != Some(2)
        || request_wire != format!("{{\"commit\":{commit_wire}}}").as_bytes()
        || !verify_secure_signed_wire(commit_wire.as_bytes(), "peerwork.secure.commit.v1", &key_id).map_err(|_| bad())? { return Err(bad()); }
    let payload = commit.get("payload").ok_or_else(bad)?;
    let issued_at = number(payload, "issued_at")?;
    if number(policy, "issued_at")? > issued_at { return Err(bad()); }
    let expected = obj(vec![("v", WireValue::Number(3.0)), ("workspace_id", s(&string(source, "workspace_id")?)),
        ("sequence", WireValue::Number((number(&current, "sequence")? + 1) as f64)),
        ("previous", s(&string(&current, "head")?)), ("policy_hash", s(&policy_hash)),
        ("epoch", WireValue::Number(number(policy, "epoch")? as f64)), ("actor_id", s(&actor)),
        ("signing_key", s(&key_id)), ("command_id", s(command_id)), ("action_id", s("secure.protocol-object.stage")),
        ("instance_id", WireValue::Null), ("issued_at", WireValue::Number(issued_at as f64)), ("delegation", WireValue::Null),
        ("protocol_format_ceiling", WireValue::Number(number(policy, "protocol_format_ceiling")? as f64)),
        ("structure", obj(vec![("v", WireValue::Number(1.0)), ("mode", s("DELTA")),
            ("records", WireValue::Array(vec![])), ("heads", WireValue::Array(vec![]))]))]);
    let WireValue::Object(fields) = payload else { return Err(bad()); };
    let context = WireValue::Object(fields.iter().filter(|(key, _)| !["body", "mode"].iter()
        .any(|name| key.iter().copied().eq(name.encode_utf16()))).cloned().collect());
    if payload.get("mode") != Some(&s("PRIVATE"))
        || canonical_wire_value(&context, Path::SecureArtifact).map_err(|_| bad())?
            != canonical_wire_value(&expected, Path::SecureArtifact).map_err(|_| bad())? { return Err(bad()); }
    let sealed_wire = canonical_wire_value(payload.get("body").ok_or_else(bad)?, Path::SecureArtifact).map_err(|_| bad())?;
    let sealed: SealedContent = serde_json::from_str(&sealed_wire).map_err(|_| bad())?;
    let context_wire = canonical_wire_value(&context, Path::SecureArtifact).map_err(|_| bad())?;
    let plaintext = Zeroizing::new(open_content_wire(epoch_key, &sealed, context_wire.as_bytes()).map_err(|_| bad())?);
    let operation = obj(vec![("v", WireValue::Number(1.0)), ("kind", s("ADMIN")),
        ("input", obj(vec![("protocol_object_stage", obj(vec![("proof", proof.clone()),
            ("part_index", WireValue::Number(part_index as f64))]))])), ("objects", WireValue::Array(vec![part.clone()]))]);
    if canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| bad())?.as_bytes() != plaintext.as_slice() { return Err(bad()); }
    Ok(sha256_hex(commit_wire.as_bytes()))
}

/// Author one retained original object-source part after the caller proves its
/// exact authenticated prefix. Persist this packet before POST; never replace
/// it with newly encrypted bytes on an uncertain retry.
#[allow(clippy::too_many_arguments)]
pub fn prepare_private_protocol_object_stage(
    proof: &WireValue,
    part: &WireValue,
    part_index: usize,
    checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallStep, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if issued_at > MAX_SAFE || !token(command_id) {
        return Err(bad());
    }
    let signed = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let policy = signed.get("payload").ok_or_else(bad)?;
    let checkpoint = parse_wire_json_bounded(checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let policy_hash = sha256_hex(
        canonical_wire_value(&signed, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes(),
    );
    let key = base64url(&signing_key.verifying_key().to_bytes());
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let workspace = string(policy, "workspace_id")?;
    let previous = string(&checkpoint, "head")?;
    let sequence = number(&checkpoint, "sequence")?
        .checked_add(1)
        .ok_or_else(bad)?;
    let epoch = number(policy, "epoch")?;
    let ceiling = number(policy, "protocol_format_ceiling")?;
    let context = obj(vec![
        ("v", WireValue::Number(3.0)),
        ("workspace_id", s(&workspace)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&previous)),
        ("policy_hash", s(&policy_hash)),
        ("epoch", WireValue::Number(epoch as f64)),
        ("actor_id", s(&actor)),
        ("signing_key", s(&key)),
        ("command_id", s(command_id)),
        ("action_id", s("secure.protocol-object.stage")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("protocol_format_ceiling", WireValue::Number(ceiling as f64)),
        (
            "structure",
            obj(vec![
                ("v", WireValue::Number(1.0)),
                ("mode", s("DELTA")),
                ("records", WireValue::Array(vec![])),
                ("heads", WireValue::Array(vec![])),
            ]),
        ),
    ]);
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", s("ADMIN")),
        (
            "input",
            obj(vec![(
                "protocol_object_stage",
                obj(vec![
                    ("proof", proof.clone()),
                    ("part_index", WireValue::Number(part_index as f64)),
                ]),
            )]),
        ),
        ("objects", WireValue::Array(vec![part.clone()])),
    ]);
    let operation = canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| bad())?;
    let commit = sign_private_commit(
        &context,
        operation.as_bytes(),
        epoch_key,
        signing_key,
        &crate::prepared_secure_request::SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key,
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence,
            previous: Some(&previous),
            epoch,
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(ceiling),
        },
    )
    .map_err(|_| PrivateInstallError::Author)?;
    let request_wire = format!("{{\"commit\":{commit}}}").into_bytes();
    // The same exact verifier binds proof/descriptor/text/policy/Owner/context
    // and decrypts the produced bytes before any caller can retain them.
    let commit_hash = verify_saved_private_protocol_object_stage(
        &request_wire,
        proof,
        part,
        part_index,
        checkpoint_wire,
        signed_policy_wire,
        command_id,
        signing_key,
        epoch_key,
    )?;
    Ok(PreparedPrivatePackageInstallStep {
        request_wire,
        commit_hash,
        action_id: "secure.protocol-object.stage",
    })
}

/// Reconstruct a complete package source from consecutive authenticated
/// signed parts. The caller separately binds every part to an origin-bound
/// replayed stage commit and the source checkpoint to that replay.
pub fn verify_complete_package_source(
    signed_parts: &[WireValue],
    source_checkpoint: &WireValue,
) -> Result<WireValue, PrivateInstallError> {
    if signed_parts.is_empty() || signed_parts.len() > MAX_PACKAGE_SOURCE_PARTS {
        return Err(PrivateInstallError::Invalid);
    }
    let mut text = String::new();
    for part in signed_parts {
        let piece = part
            .get("value")
            .and_then(|value| value.get("text"))
            .and_then(WireValue::as_string)
            .ok_or(PrivateInstallError::Invalid)?;
        if text.len().checked_add(piece.len()).is_none_or(|size| size > 8 * 1024 * 1024) {
            return Err(PrivateInstallError::Resource);
        }
        text.push_str(&piece);
    }
    let source_wire = canonical_wire_value(source_checkpoint, Path::SecureArtifact)
        .map_err(|_| PrivateInstallError::Invalid)?;
    let prepared = prepare_package_source_wire(text.as_bytes(), source_wire.as_bytes())
        .map_err(|_| PrivateInstallError::Invalid)?;
    if prepared.parts.len() != signed_parts.len() {
        return Err(PrivateInstallError::Invalid);
    }
    for (expected, signed) in prepared.parts.iter().zip(signed_parts) {
        if canonical_wire_value(expected, Path::SecureArtifact)
            .map_err(|_| PrivateInstallError::Invalid)?
            != canonical_wire_value(signed, Path::SecureArtifact)
                .map_err(|_| PrivateInstallError::Invalid)?
        {
            return Err(PrivateInstallError::Invalid);
        }
    }
    verify_protocol_package_source(&prepared.proof, signed_parts)
        .map_err(|_| PrivateInstallError::Invalid)?;
    Ok(prepared.proof)
}

/// Preserve the former one-part API for its existing callers.
pub fn verify_single_part_package_source(
    signed_part: &WireValue,
    source_checkpoint: &WireValue,
) -> Result<WireValue, PrivateInstallError> {
    verify_complete_package_source(std::slice::from_ref(signed_part), source_checkpoint)
}

/// Check a local retained stage marker's source identity before creating any
/// durable attach row. This is only a consistency check; signed replay must
/// still prove the stage command and material before attachment.
pub fn package_source_identity_matches(
    source: &WireValue,
    source_id: &str,
    source_sha256: &str,
) -> bool {
    package_source_id(source, source_sha256).is_ok_and(|expected| expected == source_id)
}

/// Compile caller-supplied material at an authenticated source checkpoint and
/// bind the complete one-part proof to a retained marker. This does not sign
/// or submit a replacement for the marker's missing original packet.
pub fn prepare_orphan_package_stage_material(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    expected_source_id: &str,
    expected_source_sha256: &str,
) -> Result<(String, String, String), PrivateInstallError> {
    let prepared = prepare_package_source_wire(material_wire, source_checkpoint_wire)
        .map_err(|_| PrivateInstallError::Invalid)?;
    if prepared.parts.len() != 1
        || prepared.proof.get("source_id").and_then(WireValue::as_string).as_deref()
            != Some(expected_source_id)
        || prepared.proof.get("source_sha256").and_then(WireValue::as_string).as_deref()
            != Some(expected_source_sha256)
    {
        return Err(PrivateInstallError::Invalid);
    }
    verify_protocol_package_source(&prepared.proof, &prepared.parts)
        .map_err(|_| PrivateInstallError::Invalid)?;
    let root = prepared.proof.get("root_package_digest").and_then(WireValue::as_string)
        .ok_or(PrivateInstallError::Invalid)?;
    let protocol = prepared.proof.get("protocol_digest").and_then(WireValue::as_string)
        .ok_or(PrivateInstallError::Invalid)?;
    let proof_wire = canonical_wire_value(&prepared.proof, Path::SecureArtifact)
        .map_err(|_| PrivateInstallError::Invalid)?;
    Ok((root, protocol, sha256_hex(proof_wire.as_bytes())))
}

/// Normalize caller material with the same bounded package-source compiler
/// used when an Owner stage was selected. A retry may use different JSON
/// whitespace or key order, but still has to compile to the selected source.
pub fn canonical_package_source_material(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
) -> Result<Zeroizing<String>, PrivateInstallError> {
    let prepared = prepare_package_source_wire(material_wire, source_checkpoint_wire)
        .map_err(|_| PrivateInstallError::Invalid)?;
    verify_protocol_package_source(&prepared.proof, &prepared.parts)
        .map_err(|_| PrivateInstallError::Invalid)?;
    Ok(Zeroizing::new(prepared.canonical_material))
}

/// Compile all caller-supplied material for a marker whose original packet
/// was never saved. `signed_prefix` must already have been selected from a
/// complete authenticated replay by the runtime; this helper compares every
/// whole part, without granting signer or transport authority.
pub struct VerifiedMultipartOrphanMaterial {
    pub canonical_material: Zeroizing<String>,
    pub part_count: usize,
    pub selected_part: WireValue,
    pub root_package_digest: String,
    pub protocol_digest: String,
    pub proof_sha256: String,
}

pub fn prepare_multipart_orphan_package_stage_material(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    expected_source_id: &str,
    expected_source_sha256: &str,
    marker_part_index: usize,
    signed_prefix: &[WireValue],
) -> Result<VerifiedMultipartOrphanMaterial, PrivateInstallError> {
    let prepared = prepare_package_source_wire(material_wire, source_checkpoint_wire)
        .map_err(|_| PrivateInstallError::Invalid)?;
    if marker_part_index == 0
        || marker_part_index >= prepared.parts.len()
        || prepared.parts.len() > MAX_PACKAGE_SOURCE_PARTS
        || signed_prefix.len() != marker_part_index
        || prepared.proof.get("source_id").and_then(WireValue::as_string).as_deref()
            != Some(expected_source_id)
        || prepared.proof.get("source_sha256").and_then(WireValue::as_string).as_deref()
            != Some(expected_source_sha256)
    {
        return Err(PrivateInstallError::Invalid);
    }
    for (expected, signed) in prepared.parts.iter().zip(signed_prefix) {
        if canonical_wire_value(expected, Path::SecureArtifact)
            .map_err(|_| PrivateInstallError::Invalid)?
            != canonical_wire_value(signed, Path::SecureArtifact)
                .map_err(|_| PrivateInstallError::Invalid)?
        {
            return Err(PrivateInstallError::Invalid);
        }
    }
    verify_protocol_package_source(&prepared.proof, &prepared.parts)
        .map_err(|_| PrivateInstallError::Invalid)?;
    let root_package_digest = prepared.proof.get("root_package_digest")
        .and_then(WireValue::as_string).ok_or(PrivateInstallError::Invalid)?;
    let protocol_digest = prepared.proof.get("protocol_digest")
        .and_then(WireValue::as_string).ok_or(PrivateInstallError::Invalid)?;
    let proof_wire = canonical_wire_value(&prepared.proof, Path::SecureArtifact)
        .map_err(|_| PrivateInstallError::Invalid)?;
    Ok(VerifiedMultipartOrphanMaterial {
        canonical_material: Zeroizing::new(prepared.canonical_material),
        part_count: prepared.parts.len(),
        selected_part: prepared.parts[marker_part_index].clone(),
        root_package_digest,
        protocol_digest,
        proof_sha256: sha256_hex(proof_wire.as_bytes()),
    })
}

/// Exact encrypted packet plus the source-derived material proof. Persist the
/// packet and chosen source before POST; never re-encrypt an uncertain step.
pub struct PreparedPrivatePackageStage {
    request_wire: Vec<u8>,
    commit_hash: String,
    source_id: String,
    protocol_digest: String,
    root_package_digest: String,
    part_count: usize,
    part_index: usize,
}

/// Signed policy update and encrypted BEGIN packet for an already staged
/// package. The runtime must prove the complete staged source range before
/// calling this author and persist the exact packet before POST.
pub struct PreparedPrivatePackageInstallBegin {
    request_wire: Vec<u8>,
    commit_hash: String,
    policy_hash: String,
    snapshot: WireValue,
    direct_composition: Option<WireValue>,
    protocol_digest: String,
    instance_id: String,
}
pub struct PreparedPrivatePackageInstallStep {
    request_wire: Vec<u8>,
    commit_hash: String,
    action_id: &'static str,
}
impl PreparedPrivatePackageInstallStep {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    pub fn action_id(&self) -> &'static str {
        self.action_id
    }
}
impl PreparedPrivatePackageInstallBegin {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn snapshot(&self) -> &WireValue {
        &self.snapshot
    }
    /// Exact composition independently compiled under the authenticated source policy.
    pub fn direct_composition(&self) -> Option<&WireValue> {
        self.direct_composition.as_ref()
    }
    pub fn protocol_digest(&self) -> &str {
        &self.protocol_digest
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

struct StagePlan {
    context: WireValue,
    operation: WireValue,
    source_id: String,
    protocol_digest: String,
    root_package_digest: String,
    part_count: usize,
}

impl PreparedPrivatePackageStage {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn protocol_digest(&self) -> &str {
        &self.protocol_digest
    }
    pub fn root_package_digest(&self) -> &str {
        &self.root_package_digest
    }
    pub fn part_count(&self) -> usize {
        self.part_count
    }
    pub fn part_index(&self) -> usize {
        self.part_index
    }
}

fn s(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn obj(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}
fn string(value: &WireValue, field: &str) -> Result<String, PrivateInstallError> {
    value
        .get(field)
        .and_then(WireValue::as_string)
        .ok_or(PrivateInstallError::Invalid)
}
fn number(value: &WireValue, field: &str) -> Result<u64, PrivateInstallError> {
    let n = value
        .get(field)
        .and_then(WireValue::as_number)
        .ok_or(PrivateInstallError::Invalid)?;
    if !n.is_finite() || n < 0.0 || n > MAX_SAFE as f64 || n.fract() != 0.0 {
        return Err(PrivateInstallError::Invalid);
    }
    Ok(n as u64)
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Derive an exact source part without allocating a nonce or signing a packet.
/// Source ancestry beyond the first part remains a caller/replay obligation.
#[allow(clippy::too_many_arguments)]
fn plan_stage(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    part_index: usize,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
) -> Result<StagePlan, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if !token(command_id) || issued_at > MAX_SAFE {
        return Err(bad());
    }
    let prepared =
        prepare_package_source_wire(material_wire, source_checkpoint_wire).map_err(|error| {
            match error {
                crate::prepared_package_source::PreparePackageSourceError::Resource => {
                    PrivateInstallError::Resource
                }
                _ => bad(),
            }
        })?;
    let part = prepared.parts.get(part_index).ok_or_else(bad)?.clone();
    let source = parse_wire_json_bounded(source_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let current = parse_wire_json_bounded(current_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let signed_policy =
        parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let policy = signed_policy.get("payload").ok_or_else(bad)?;
    let key_id = base64url(&signing_key.verifying_key().to_bytes());
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let source_sequence = number(&source, "sequence")?;
    let current_sequence = number(&current, "sequence")?;
    let sequence = current_sequence.checked_add(1).ok_or_else(bad)?;
    let expected_sequence = source_sequence
        .checked_add(part_index as u64)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(bad)?;
    let version = number(policy, "v")?;
    let epoch = number(policy, "epoch")?;
    let policy_wire =
        canonical_wire_value(&signed_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let policy_hash = sha256_hex(policy_wire.as_bytes());
    let source_id = string(&prepared.proof, "source_id")?;
    let protocol_digest = string(&prepared.proof, "protocol_digest")?;
    let root_package_digest = string(&prepared.proof, "root_package_digest")?;
    if !matches!(version, 2 | 3)
        || epoch == 0
        || policy.get("structure").is_none()
        || version == 3 && string(policy, "structure_mode")? != "STRUCTURED"
        || version == 3 && !matches!(number(policy, "protocol_format_ceiling")?, 1 | 2)
        || string(policy, "visibility")? != "PRIVATE"
        || string(policy, "owner_id")? != actor
        || string(policy, "signing_key")? != key_id
        || string(policy, "workspace_id")? != string(&current, "workspace_id")?
        || string(&source, "workspace_id")? != string(&current, "workspace_id")?
        || string(&source, "owner_id")? != actor
        || string(&source, "owner_key")? != key_id
        || string(&current, "owner_id")? != actor
        || string(&current, "owner_key")? != key_id
        || string(&current, "policy_hash")? != policy_hash
        || string(&source, "policy_hash")? != policy_hash
        || number(policy, "effective_sequence")? > source_sequence
        || sequence != expected_sequence
        || part_index == 0 && string(&source, "head")? != string(&current, "head")?
        || !verify_secure_signed_wire(policy_wire.as_bytes(), "peerwork.secure.policy.v1", &key_id)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let structure = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("mode", s("DELTA")),
        ("records", WireValue::Array(Vec::new())),
        ("heads", WireValue::Array(Vec::new())),
    ]);
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", s("ADMIN")),
        (
            "input",
            obj(vec![(
                "package_stage",
                obj(vec![
                    ("source", source),
                    ("source_id", s(&source_id)),
                    ("part_index", WireValue::Number(part_index as f64)),
                ]),
            )]),
        ),
        ("objects", WireValue::Array(vec![part])),
    ]);
    let mut fields = vec![
        ("v", WireValue::Number(version as f64)),
        ("workspace_id", s(&string(&current, "workspace_id")?)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&string(&current, "head")?)),
        ("policy_hash", s(&policy_hash)),
        ("epoch", WireValue::Number(epoch as f64)),
        ("actor_id", s(&actor)),
        ("signing_key", s(&key_id)),
        ("command_id", s(command_id)),
        ("action_id", s("secure.protocol-package.stage")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("structure", structure),
    ];
    if version == 3 {
        fields.push((
            "protocol_format_ceiling",
            WireValue::Number(number(policy, "protocol_format_ceiling")? as f64),
        ));
    }
    Ok(StagePlan {
        context: obj(fields),
        operation,
        source_id,
        protocol_digest,
        root_package_digest,
        part_count: prepared.parts.len(),
    })
}

/// Sign one exact source part at `source.sequence + part_index + 1`. The
/// runtime must establish source ancestry and current policy from complete
/// replay before invoking this function, and reprove the saved packet before
/// submitting it or moving to the next part.
#[allow(clippy::too_many_arguments)]
pub fn prepare_private_package_stage(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    part_index: usize,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageStage, PrivateInstallError> {
    let plan = plan_stage(
        material_wire,
        source_checkpoint_wire,
        current_checkpoint_wire,
        signed_policy_wire,
        part_index,
        command_id,
        issued_at,
        signing_key,
    )?;
    let context = &plan.context;
    let operation_wire = canonical_wire_value(&plan.operation, Path::SecureArtifact)
        .map_err(|_| PrivateInstallError::Invalid)?;
    let actor = string(context, "actor_id")?;
    let key_id = string(context, "signing_key")?;
    let workspace = string(context, "workspace_id")?;
    let policy_hash = string(context, "policy_hash")?;
    let previous = string(context, "previous")?;
    let sequence = number(context, "sequence")?;
    let epoch = number(context, "epoch")?;
    let version = number(context, "v")?;
    let commit = sign_private_commit(
        &context,
        operation_wire.as_bytes(),
        epoch_key,
        signing_key,
        &crate::prepared_secure_request::SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key_id,
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence,
            previous: Some(&previous),
            epoch,
            mode: "PRIVATE",
            version,
            protocol_format_ceiling: if version == 3 {
                Some(number(context, "protocol_format_ceiling")?)
            } else {
                None
            },
        },
    )
    .map_err(|_| PrivateInstallError::Author)?;
    let request_wire = format!("{{\"commit\":{commit}}}").into_bytes();
    if request_wire.len() > 220_000 {
        return Err(PrivateInstallError::Resource);
    }
    Ok(PreparedPrivatePackageStage {
        request_wire,
        commit_hash: sha256_hex(commit.as_bytes()),
        source_id: plan.source_id,
        protocol_digest: plan.protocol_digest,
        root_package_digest: plan.root_package_digest,
        part_count: plan.part_count,
        part_index,
    })
}

/// Reprove one protected exact packet before transport or recovery. The
/// ciphertext must decrypt to the compiler-derived part and the signed
/// context must equal the source/checkpoint/policy plan byte-for-byte.
/// This still requires runtime to authenticate both checkpoints and prove
/// staged-prefix ancestry from its complete replay.
#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_package_stage(
    request_wire: &[u8],
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    part_index: usize,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageStage, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if request_wire.is_empty() || request_wire.len() > 220_000 {
        return Err(bad());
    }
    let plan = plan_stage(
        material_wire,
        source_checkpoint_wire,
        current_checkpoint_wire,
        signed_policy_wire,
        part_index,
        command_id,
        issued_at,
        signing_key,
    )?;
    let request = parse_wire_json_bounded(request_wire, 64, 220_000).map_err(|_| bad())?;
    if request.object_len() != Some(1) {
        return Err(bad());
    }
    let commit = request.get("commit").ok_or_else(bad)?;
    if commit.object_len() != Some(2) {
        return Err(bad());
    }
    let commit_wire = canonical_wire_value(commit, Path::SecureArtifact).map_err(|_| bad())?;
    if request_wire != format!("{{\"commit\":{commit_wire}}}").as_bytes()
        || !verify_secure_signed_wire(
            commit_wire.as_bytes(),
            "peerwork.secure.commit.v1",
            &base64url(&signing_key.verifying_key().to_bytes()),
        )
        .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let payload = commit.get("payload").ok_or_else(bad)?;
    let WireValue::Object(fields) = payload else {
        return Err(bad());
    };
    if payload.get("mode") != Some(&s("PRIVATE")) || payload.get("body").is_none() {
        return Err(bad());
    }
    let context = WireValue::Object(
        fields
            .iter()
            .filter(|(name, _)| {
                !name.iter().copied().eq("mode".encode_utf16())
                    && !name.iter().copied().eq("body".encode_utf16())
            })
            .cloned()
            .collect(),
    );
    if canonical_wire_value(&context, Path::SecureArtifact).map_err(|_| bad())?
        != canonical_wire_value(&plan.context, Path::SecureArtifact).map_err(|_| bad())?
    {
        return Err(bad());
    }
    let sealed_wire =
        canonical_wire_value(payload.get("body").ok_or_else(bad)?, Path::SecureArtifact)
            .map_err(|_| bad())?;
    let sealed: SealedContent = serde_json::from_str(&sealed_wire).map_err(|_| bad())?;
    let context_wire = canonical_wire_value(&context, Path::SecureArtifact).map_err(|_| bad())?;
    let plaintext =
        open_content_wire(epoch_key, &sealed, context_wire.as_bytes()).map_err(|_| bad())?;
    let operation = parse_wire_json_bounded(&plaintext, 64, 16 * 1024 * 1024).map_err(|_| bad())?;
    if canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| bad())?
        != canonical_wire_value(&plan.operation, Path::SecureArtifact).map_err(|_| bad())?
    {
        return Err(bad());
    }
    Ok(PreparedPrivatePackageStage {
        request_wire: request_wire.to_vec(),
        commit_hash: sha256_hex(commit_wire.as_bytes()),
        source_id: plan.source_id,
        protocol_digest: plan.protocol_digest,
        root_package_digest: plan.root_package_digest,
        part_count: plan.part_count,
        part_index,
    })
}

/// Reprove one old-client saved, encrypted ADMIN stage without re-signing it.
/// The caller must supply the source checkpoint and policy from complete,
/// origin-bound replay, and the imported Owner signing/epoch keys. The old
/// client persisted a body object, so `request_wire` is the canonical native
/// retry envelope; its signed commit and ciphertext are the original values.
/// This helper is limited to a sole part at the supplied source checkpoint.
pub fn verify_imported_private_package_stage(
    request_wire: &[u8],
    source_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    command_id: &str,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageStage, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if request_wire.is_empty() || request_wire.len() > 220_000 {
        return Err(bad());
    }
    let request = parse_wire_json_bounded(request_wire, 64, 220_000).map_err(|_| bad())?;
    if request.object_len() != Some(1) {
        return Err(bad());
    }
    let commit = request.get("commit").ok_or_else(bad)?;
    if commit.object_len() != Some(2) {
        return Err(bad());
    }
    let commit_wire = canonical_wire_value(commit, Path::SecureArtifact).map_err(|_| bad())?;
    if request_wire != format!("{{\"commit\":{commit_wire}}}").as_bytes()
        || !verify_secure_signed_wire(
            commit_wire.as_bytes(),
            "peerwork.secure.commit.v1",
            &base64url(&signing_key.verifying_key().to_bytes()),
        )
        .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let payload = commit.get("payload").ok_or_else(bad)?;
    let WireValue::Object(fields) = payload else {
        return Err(bad());
    };
    let context = WireValue::Object(
        fields
            .iter()
            .filter(|(name, _)| {
                !name.iter().copied().eq("mode".encode_utf16())
                    && !name.iter().copied().eq("body".encode_utf16())
            })
            .cloned()
            .collect(),
    );
    let context_wire = canonical_wire_value(&context, Path::SecureArtifact).map_err(|_| bad())?;
    let sealed_wire = canonical_wire_value(payload.get("body").ok_or_else(bad)?, Path::SecureArtifact)
        .map_err(|_| bad())?;
    let sealed: SealedContent = serde_json::from_str(&sealed_wire).map_err(|_| bad())?;
    let plaintext = Zeroizing::new(
        open_content_wire(epoch_key, &sealed, context_wire.as_bytes()).map_err(|_| bad())?,
    );
    let operation = parse_wire_json_bounded(&plaintext, 64, 16 * 1024 * 1024)
        .map_err(|_| bad())?;
    let WireValue::Array(objects) = operation.get("objects").ok_or_else(bad)? else {
        return Err(bad());
    };
    if objects.len() != 1 {
        return Err(bad());
    }
    let material = objects[0]
        .get("value")
        .and_then(|value| value.get("text"))
        .and_then(WireValue::as_string)
        .ok_or_else(bad)?;
    verify_saved_private_package_stage(
        request_wire,
        material.as_bytes(),
        source_checkpoint_wire,
        source_checkpoint_wire,
        signed_policy_wire,
        0,
        command_id,
        number(payload, "issued_at")?,
        signing_key,
        epoch_key,
    )
}

/// Reprove a multipart old-client packet against caller-supplied complete
/// material. The material is required because one decrypted part cannot prove
/// the full source. This does not authorize a POST: the caller must separately
/// authenticate source/current checkpoints, every earlier signed part, Owner
/// authority, and current replay ancestry before persisting a selection.
pub struct VerifiedImportedMultipartStage {
    prepared: PreparedPrivatePackageStage,
    proof: WireValue,
    parts: Vec<WireValue>,
    canonical_material: String,
}

impl VerifiedImportedMultipartStage {
    pub fn prepared(&self) -> &PreparedPrivatePackageStage { &self.prepared }
    pub fn proof(&self) -> &WireValue { &self.proof }
    pub fn part(&self, index: usize) -> Option<&WireValue> { self.parts.get(index) }
    pub fn part_count(&self) -> usize { self.parts.len() }
    pub fn canonical_material(&self) -> &str { &self.canonical_material }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_imported_private_package_stage_with_material(
    request_wire: &[u8],
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    part_index: usize,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<VerifiedImportedMultipartStage, PrivateInstallError> {
    if part_index == 0 || part_index >= MAX_PACKAGE_SOURCE_PARTS {
        return Err(PrivateInstallError::Invalid);
    }
    let source = prepare_package_source_wire(material_wire, source_checkpoint_wire)
        .map_err(|_| PrivateInstallError::Invalid)?;
    if part_index >= source.parts.len() {
        return Err(PrivateInstallError::Invalid);
    }
    let prepared = verify_saved_private_package_stage(
        request_wire, source.canonical_material.as_bytes(),
        source_checkpoint_wire, current_checkpoint_wire, signed_policy_wire,
        part_index, command_id, issued_at, signing_key, epoch_key,
    )?;
    if prepared.part_count() != source.parts.len()
        || source.proof.get("source_id").and_then(WireValue::as_string).as_deref()
            != Some(prepared.source_id())
    {
        return Err(PrivateInstallError::Invalid);
    }
    Ok(VerifiedImportedMultipartStage {
        prepared, proof: source.proof, parts: source.parts,
        canonical_material: source.canonical_material,
    })
}

fn replace(value: &mut WireValue, field: &str, item: WireValue) -> Result<(), PrivateInstallError> {
    let WireValue::Object(fields) = value else {
        return Err(PrivateInstallError::Invalid);
    };
    let Some((_, slot)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(field.encode_utf16()))
    else {
        return Err(PrivateInstallError::Invalid);
    };
    *slot = item;
    Ok(())
}

fn upsert(value: &mut WireValue, field: &str, item: WireValue) -> Result<(), PrivateInstallError> {
    let WireValue::Object(fields) = value else {
        return Err(PrivateInstallError::Invalid);
    };
    if let Some((_, slot)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(field.encode_utf16()))
    {
        *slot = item;
    } else {
        fields.push((field.encode_utf16().collect(), item));
    }
    Ok(())
}

fn apply_install_grants(
    policy: &mut WireValue,
    grants_wire: &[u8],
    manifest: &WireValue,
    instance_id: &str,
) -> Result<(), PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    let grants = parse_wire_json_bounded(grants_wire, 32, 65_536).map_err(|_| bad())?;
    let WireValue::Array(grants) = grants else {
        return Err(bad());
    };
    if grants.len() > 128 {
        return Err(PrivateInstallError::Resource);
    }
    let mut members = match policy.get("members").ok_or_else(bad)? {
        WireValue::Array(rows) => rows.clone(),
        _ => return Err(bad()),
    };
    let mut seen = std::collections::HashSet::new();
    for grant in grants {
        let WireValue::Object(fields) = &grant else {
            return Err(bad());
        };
        if fields.iter().any(|(name, _)| {
            String::from_utf16(name).map_or(true, |name| {
                !matches!(
                    name.as_str(),
                    "actor_id" | "actions" | "protocol_roles" | "capabilities" | "expires_at"
                )
            })
        }) {
            return Err(bad());
        }
        let actor = string(&grant, "actor_id")?;
        if !token(&actor)
            || !seen.insert(actor.clone())
            || grant.object_len().is_none_or(|n| n < 4 || n > 5)
        {
            return Err(bad());
        }
        let member = members
            .iter_mut()
            .find(|m| m.get("actor_id") == Some(&s(&actor)))
            .ok_or_else(bad)?;
        let mut scope_fields = Vec::new();
        for (field, manifest_field) in [
            ("actions", "actions"),
            ("protocol_roles", "protocol_roles"),
            ("capabilities", "capabilities"),
        ] {
            let values = match grant.get(field).ok_or_else(bad)? {
                WireValue::Array(values) => values,
                _ => return Err(bad()),
            };
            let declared = match manifest.get(manifest_field).ok_or_else(bad)? {
                WireValue::Array(values) => values,
                _ => return Err(bad()),
            };
            if values.len() > 64 {
                return Err(PrivateInstallError::Resource);
            }
            let mut unique = std::collections::HashSet::new();
            for value in values {
                let name = value.as_string().ok_or_else(bad)?;
                if name.is_empty()
                    || name.len() > 120
                    || !unique.insert(name)
                    || !declared.iter().any(|item| {
                        if field == "actions" {
                            item.get("id") == Some(value)
                        } else {
                            item == value
                        }
                    })
                {
                    return Err(bad());
                }
            }
            scope_fields.push((field, WireValue::Array(values.clone())));
        }
        if let Some(expires) = grant.get("expires_at") {
            if !matches!(expires, WireValue::Null)
                && !expires.as_number().is_some_and(|at| {
                    at.fract() == 0.0 && at >= 1.0 && at <= 9_007_199_254_740_991.0
                })
            {
                return Err(bad());
            }
            scope_fields.push(("expires_at", expires.clone()));
        }
        scope_fields.push(("instance_id", s(instance_id)));
        let mut scopes = match member.get("scopes").ok_or_else(bad)? {
            WireValue::Array(rows) => rows.clone(),
            _ => return Err(bad()),
        };
        scopes.push(obj(scope_fields));
        replace(member, "scopes", WireValue::Array(scopes))?;
    }
    replace(policy, "members", WireValue::Array(members))?;
    Ok(())
}

/// Build the first encrypted install command from an authenticated stage-end
/// checkpoint and its complete prior objects. This only authors the packet:
/// runtime must bind `prior_objects` and stage operations to signed replay.
#[allow(clippy::too_many_arguments)]
pub fn prepare_private_package_install_begin(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    stage_end_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    prepare_private_package_install_begin_with_disclosure(
        material_wire, source_checkpoint_wire, stage_end_checkpoint_wire,
        signed_policy_wire, prior_objects, grants_wire, b"[]", instance_id,
        entrypoint, command_id, issued_at, signing_key, epoch_key,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_private_package_install_begin_with_disclosure(
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    stage_end_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    disclose_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if !token(instance_id)
        || !token(command_id)
        || issued_at > MAX_SAFE
        || entrypoint.is_empty()
        || entrypoint.len() > 64
        || !entrypoint.as_bytes()[0].is_ascii_alphabetic()
        || !entrypoint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || entrypoint == "coordination"
    {
        return Err(bad());
    }
    let source = parse_wire_json_bounded(source_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let end = parse_wire_json_bounded(stage_end_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let signed_policy =
        parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let policy = signed_policy.get("payload").ok_or_else(bad)?;
    let version = number(policy, "v")?;
    let epoch = number(policy, "epoch")?;
    let signer_key = base64url(&signing_key.verifying_key().to_bytes());
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let policy_wire =
        canonical_wire_value(&signed_policy, Path::SecureArtifact).map_err(|_| bad())?;
    if !matches!(version, 2 | 3)
        || epoch == 0
        || string(policy, "visibility")? != "PRIVATE"
        || string(policy, "owner_id")? != actor
        || string(policy, "signing_key")? != signer_key
        || string(&source, "owner_id")? != actor
        || string(&source, "owner_key")? != signer_key
        || string(&end, "owner_id")? != actor
        || string(&end, "owner_key")? != signer_key
        || string(policy, "workspace_id")? != string(&end, "workspace_id")?
        || string(&source, "workspace_id")? != string(&end, "workspace_id")?
        || string(&source, "policy_hash")? != string(&end, "policy_hash")?
        || string(&end, "policy_hash")? != sha256_hex(policy_wire.as_bytes())
        || !verify_secure_signed_wire(
            policy_wire.as_bytes(),
            "peerwork.secure.policy.v1",
            &signer_key,
        )
        .map_err(|_| bad())?
        || number(policy, "issued_at")? > issued_at
        || policy.get("structure").is_none()
        || (version == 3 && string(policy, "structure_mode")? != "STRUCTURED")
    {
        return Err(bad());
    }
    let prepared =
        prepare_package_source_wire(material_wire, source_checkpoint_wire).map_err(|error| {
            match error {
                crate::prepared_package_source::PreparePackageSourceError::Resource => {
                    PrivateInstallError::Resource
                }
                _ => bad(),
            }
        })?;
    let stage_count = prepared.parts.len() as u64;
    if number(&source, "sequence")?.checked_add(stage_count) != Some(number(&end, "sequence")?)
        || prior_objects.iter().any(|o| {
            o.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && o.get("id") == Some(&s(instance_id))
        })
    {
        return Err(bad());
    }
    let verified =
        verify_protocol_package_source(&prepared.proof, prior_objects).map_err(|_| bad())?;
    let digest = verified.protocol_digest;
    if verified.part_count != prepared.parts.len()
        || (verified.manifest.get("format_version").is_some()
            && (version != 3 || number(policy, "protocol_format_ceiling")? != 2))
    {
        return Err(bad());
    }
    let workspace = string(&end, "workspace_id")?;
    let protocol_exists = prior_objects.iter().any(|o| {
        o.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
            && o.get("id") == Some(&s(&digest))
    });
    let protocol = obj(vec![
        ("kind", s("protocols")),
        ("id", s(&digest)),
        ("revision", WireValue::Number(1.0)),
        ("provenance", s("AUTHOR_SIGNED")),
        (
            "value",
            obj(vec![
                ("workspace_id", s(&workspace)),
                ("digest", s(&digest)),
                ("manifest", verified.manifest.clone()),
                ("resolved_manifest", verified.manifest.clone()),
                ("package_source", prepared.proof.clone()),
            ]),
        ),
    ]);
    let instance = obj(vec![
        ("kind", s("instances")),
        ("id", s(instance_id)),
        ("revision", WireValue::Number(1.0)),
        ("provenance", s("AUTHOR_SIGNED")),
        (
            "value",
            obj(vec![
                ("id", s(instance_id)),
                ("workspace_id", s(&workspace)),
                ("protocol_digest", s(&digest)),
                ("origin_entrypoint", s(entrypoint)),
                ("semantics", s("peerwork.kernel.v1")),
                (
                    "state",
                    verified
                        .manifest
                        .get("initial_state")
                        .ok_or_else(bad)?
                        .clone(),
                ),
                ("revision", WireValue::Number(0.0)),
                ("event_revision", WireValue::Number(0.0)),
                ("created", WireValue::Number(issued_at as f64)),
                ("package_source", prepared.proof.clone()),
            ]),
        ),
    ]);
    let added = if protocol_exists {
        vec![instance]
    } else {
        vec![protocol, instance]
    };
    let old_structure = policy.get("structure").ok_or_else(bad)?;
    let disclose = parse_wire_json_bounded(disclose_wire, 32, 65_536).map_err(|_| bad())?;
    let WireValue::Array(disclose) = disclose else { return Err(bad()); };
    let structure = derive_direct_install_structure_with_options(
        Some(old_structure),
        prior_objects,
        &added,
        &digest,
        &verified.manifest,
        false,
        &disclose,
    )
    .map_err(|_| bad())?;
    let snapshot = plan_public_install_snapshot(prior_objects, &structure, &end)
        .map_err(|_| bad())?
        .snapshot()
        .clone();
    let begin =
        build_direct_install_begin(&end, &added, instance_id, &digest, entrypoint, &snapshot)
            .map_err(|_| bad())?;
    let mut next_policy = policy.clone();
    replace(&mut next_policy, "structure", structure)?;
    apply_install_grants(
        &mut next_policy,
        grants_wire,
        &verified.manifest,
        instance_id,
    )?;
    replace(
        &mut next_policy,
        "version",
        WireValue::Number((number(policy, "version")?.checked_add(1).ok_or_else(bad)?) as f64),
    )?;
    replace(
        &mut next_policy,
        "previous_policy",
        s(&sha256_hex(policy_wire.as_bytes())),
    )?;
    replace(
        &mut next_policy,
        "effective_sequence",
        WireValue::Number((number(&end, "sequence")?.checked_add(1).ok_or_else(bad)?) as f64),
    )?;
    replace(
        &mut next_policy,
        "issued_at",
        WireValue::Number(issued_at as f64),
    )?;
    let payload_wire =
        canonical_wire_value(&next_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let domain = format!("peerwork.secure.policy.v{version}");
    let mut message = Vec::with_capacity(domain.len() + 1 + payload_wire.len());
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(payload_wire.as_bytes());
    let signed_new_policy = obj(vec![
        ("payload", next_policy),
        (
            "signature",
            s(&base64url(&signing_key.sign(&message).to_bytes())),
        ),
    ]);
    let signed_new_policy_wire =
        canonical_wire_value(&signed_new_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let new_policy_hash = sha256_hex(signed_new_policy_wire.as_bytes());
    let sequence = number(&end, "sequence")?.checked_add(1).ok_or_else(bad)?;
    let mut context_fields = vec![
        ("v", WireValue::Number(version as f64)),
        ("workspace_id", s(&workspace)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&string(&end, "head")?)),
        ("policy_hash", s(&new_policy_hash)),
        ("epoch", WireValue::Number(epoch as f64)),
        ("actor_id", s(&actor)),
        ("signing_key", s(&signer_key)),
        ("command_id", s(command_id)),
        ("action_id", s("secure.structure.begin")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("structure", begin.structure),
    ];
    let ceiling = if version == 3 {
        let n = number(policy, "protocol_format_ceiling")?;
        context_fields.push(("protocol_format_ceiling", WireValue::Number(n as f64)));
        Some(n)
    } else {
        None
    };
    let context = obj(context_fields);
    let operation_wire =
        canonical_wire_value(&begin.operation, Path::SecureArtifact).map_err(|_| bad())?;
    let commit = sign_private_commit(
        &context,
        operation_wire.as_bytes(),
        epoch_key,
        signing_key,
        &crate::prepared_secure_request::SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &signer_key,
            workspace_id: &workspace,
            policy_hash: &new_policy_hash,
            sequence,
            previous: Some(&string(&end, "head")?),
            epoch,
            mode: "PRIVATE",
            version,
            protocol_format_ceiling: ceiling,
        },
    )
    .map_err(|_| PrivateInstallError::Author)?;
    let commit_hash = sha256_hex(commit.as_bytes());
    let request_wire =
        format!("{{\"commit\":{commit},\"policy_update\":{signed_new_policy_wire}}}").into_bytes();
    if request_wire.len() > 220_000 {
        return Err(PrivateInstallError::Resource);
    }
    Ok(PreparedPrivatePackageInstallBegin {
        request_wire,
        commit_hash,
        policy_hash: new_policy_hash,
        snapshot,
        direct_composition: None,
        protocol_digest: digest,
        instance_id: instance_id.to_owned(),
    })
}

/// Author a PRIVATE direct install from locally selected package material.
/// There is no stage source: the signed prior checkpoint is both the source
/// and BEGIN parent. The runtime must authenticate its full replay and retain
/// this material and exact encrypted packet before any POST.
#[allow(clippy::too_many_arguments)]
pub fn prepare_private_direct_install_begin(
    material_wire: &[u8],
    expected_root_package_digest: &str,
    expected_protocol_digest: &str,
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    prepare_private_direct_install_begin_with_options(
        material_wire, b"{}", expected_root_package_digest,
        expected_protocol_digest, current_checkpoint_wire, signed_policy_wire,
        prior_objects, grants_wire, b"[]", instance_id, entrypoint, command_id,
        issued_at, signing_key, epoch_key,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_private_direct_install_begin_with_options(
    material_wire: &[u8],
    bindings_wire: &[u8],
    expected_root_package_digest: &str,
    expected_protocol_digest: &str,
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    disclose_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    prepare_private_direct_install_begin_with_source(material_wire, bindings_wire, expected_root_package_digest, expected_protocol_digest,
        current_checkpoint_wire, signed_policy_wire, prior_objects, grants_wire, disclose_wire,
        instance_id, entrypoint, command_id, issued_at, signing_key, epoch_key, None)
}

/// Author a new native BEGIN only after the caller authenticates the complete
/// object source and exact stage-end predecessor. This is not an old packet.
#[allow(clippy::too_many_arguments)]
pub fn prepare_private_direct_install_begin_with_object_source(
    material_wire: &[u8], bindings_wire: &[u8], expected_root: &str, expected_protocol: &str,
    current_checkpoint_wire: &[u8], signed_policy_wire: &[u8], prior_objects: &[WireValue],
    grants_wire: &[u8], disclose_wire: &[u8], instance_id: &str, entrypoint: &str,
    command_id: &str, issued_at: u64, signing_key: &SigningKey, epoch_key: &[u8; 32], proof: &WireValue,
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    prepare_private_direct_install_begin_with_source(material_wire, bindings_wire, expected_root, expected_protocol,
        current_checkpoint_wire, signed_policy_wire, prior_objects, grants_wire, disclose_wire,
        instance_id, entrypoint, command_id, issued_at, signing_key, epoch_key, Some(proof))
}

#[allow(clippy::too_many_arguments)]
fn prepare_private_direct_install_begin_with_source(
    material_wire: &[u8],
    bindings_wire: &[u8],
    expected_root_package_digest: &str,
    expected_protocol_digest: &str,
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    disclose_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
    object_source: Option<&WireValue>,
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if !token(instance_id)
        || !token(command_id)
        || issued_at > MAX_SAFE
        || entrypoint.is_empty()
        || entrypoint.len() > 64
        || !entrypoint.as_bytes()[0].is_ascii_alphabetic()
        || !entrypoint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || entrypoint == "coordination"
    {
        return Err(bad());
    }
    let current = parse_wire_json_bounded(current_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let signed_policy =
        parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let policy = signed_policy.get("payload").ok_or_else(bad)?;
    let version = number(policy, "v")?;
    let epoch = number(policy, "epoch")?;
    let signer_key = base64url(&signing_key.verifying_key().to_bytes());
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let policy_wire =
        canonical_wire_value(&signed_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let workspace = string(&current, "workspace_id")?;
    let structure_mode = if version == 3 {
        Some(string(policy, "structure_mode")?)
    } else {
        None
    };
    if !matches!(version, 1 | 2 | 3)
        || epoch == 0
        || string(policy, "visibility")? != "PRIVATE"
        || string(policy, "workspace_id")? != workspace
        || string(policy, "owner_id")? != actor
        || string(policy, "signing_key")? != signer_key
        || string(&current, "owner_id")? != actor
        || string(&current, "owner_key")? != signer_key
        || string(&current, "policy_hash")? != sha256_hex(policy_wire.as_bytes())
        || !verify_secure_signed_wire(
            policy_wire.as_bytes(),
            "peerwork.secure.policy.v1",
            &signer_key,
        )
        .map_err(|_| bad())?
        || number(policy, "issued_at")? > issued_at
        || (version == 3 && !matches!(structure_mode.as_deref(), Some("NONE" | "STRUCTURED")))
        || (version == 3
            && structure_mode.as_deref() == Some("STRUCTURED")
            && policy.get("structure").is_none())
    {
        return Err(bad());
    }
    // Only a signed, authenticated PRIVATE-v3 structured policy with its
    // format ceiling raised to two may select format-two package material.
    let direct_format_ceiling = if version == 3
        && structure_mode.as_deref() == Some("STRUCTURED")
        && number(policy, "protocol_format_ceiling")? == 2
    {
        2
    } else {
        1
    };
    let bindings = parse_wire_json_bounded(bindings_wire, 32, 65_536).map_err(|_| bad())?;
    let compiled = compile_package_closure_with_bindings_at_ceiling(material_wire, &bindings, direct_format_ceiling)
        .map_err(|_| bad())?;
    if compiled.package_digest() != expected_root_package_digest
        || compiled.protocol_digest() != expected_protocol_digest
        || prior_objects.iter().any(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && object.get("id") == Some(&s(instance_id))
        })
    {
        return Err(bad());
    }
    let built = build_direct_install_objects_with_composition_at_ceiling(
        compiled.manifest_wire(),
        compiled.composition(),
        expected_protocol_digest,
        &workspace,
        instance_id,
        entrypoint,
        issued_at,
        direct_format_ceiling,
    )
    .map_err(|_| bad())?;
    let mut added = built.added;
    let prior_protocol = prior_objects.iter().find(|object| {
        object.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
            && object.get("id") == Some(&s(expected_protocol_digest))
    });
    if let Some(existing) = prior_protocol {
        // A matching previously authored direct protocol can be reused for a
        // distinct instance. The old protocol object and its provenance never
        // change as a side effect of this install.
        let old_value = existing.get("value").ok_or_else(bad)?;
        let compiled_value = added[0].get("value").ok_or_else(bad)?;
        if canonical_wire_value(old_value, Path::SecureArtifact).map_err(|_| bad())?
            != canonical_wire_value(compiled_value, Path::SecureArtifact).map_err(|_| bad())?
        {
            return Err(bad());
        }
        added.remove(0);
    }
    let undisclosed = version == 1 || (version == 3 && structure_mode.as_deref() == Some("NONE"));
    let disclose = parse_wire_json_bounded(disclose_wire, 32, 65_536).map_err(|_| bad())?;
    let WireValue::Array(disclose) = disclose else { return Err(bad()); };
    let structure = derive_direct_install_structure_with_options(
        policy.get("structure"),
        prior_objects,
        &added,
        expected_protocol_digest,
        &built.manifest,
        undisclosed,
        &disclose,
    )
    .map_err(|_| bad())?;
    let snapshot = plan_public_install_snapshot(prior_objects, &structure, &current)
        .map_err(|_| bad())?
        .snapshot()
        .clone();
    let mut wire_added = added.clone();
    if let Some(proof) = object_source {
        normalize_protocol_object_source_proof(proof)?;
        if version != 3 || prior_protocol.is_some() { return Err(bad()); }
        let source = proof.get("source").ok_or_else(bad)?;
        let Some(WireValue::Array(parts)) = proof.get("parts") else { return Err(bad()); };
        if string(source, "workspace_id")? != workspace || string(source, "owner_id")? != actor
            || string(source, "owner_key")? != signer_key || string(source, "policy_hash")? != string(&current, "policy_hash")?
            || number(source, "sequence")?.checked_add(parts.len() as u64) != Some(number(&current, "sequence")?)
            || string(proof, "protocol_digest")? != expected_protocol_digest { return Err(bad()); }
        let logical = read_complete_protocol_object_source(proof, prior_objects)?;
        if canonical_wire_value(&logical, Path::SecureArtifact).map_err(|_| bad())?
            != canonical_wire_value(added[0].get("value").ok_or_else(bad)?, Path::SecureArtifact).map_err(|_| bad())? {
            return Err(bad());
        }
        replace(&mut wire_added[0], "value", obj(vec![("workspace_id", s(&workspace)),
            ("digest", s(expected_protocol_digest)), ("object_source", proof.clone())]))?;
        if canonical_wire_value(&wire_added[0], Path::SecureArtifact).map_err(|_| bad())?.len()
            > crate::protocol_object_source::OBJECT_BYTES { return Err(PrivateInstallError::Resource); }
    }
    let begin = build_direct_install_begin(
        &current,
        &wire_added,
        instance_id,
        expected_protocol_digest,
        entrypoint,
        &snapshot,
    )
    .map_err(|_| bad())?;
    let next_version = if version == 1 { 2 } else { version };
    let mut next_policy = policy.clone();
    replace(
        &mut next_policy,
        "v",
        WireValue::Number(next_version as f64),
    )?;
    upsert(&mut next_policy, "structure", structure)?;
    if next_version == 3 {
        replace(&mut next_policy, "structure_mode", s("STRUCTURED"))?;
    }
    apply_install_grants(&mut next_policy, grants_wire, &built.manifest, instance_id)?;
    replace(
        &mut next_policy,
        "version",
        WireValue::Number((number(policy, "version")?.checked_add(1).ok_or_else(bad)?) as f64),
    )?;
    replace(
        &mut next_policy,
        "previous_policy",
        s(&sha256_hex(policy_wire.as_bytes())),
    )?;
    replace(
        &mut next_policy,
        "effective_sequence",
        WireValue::Number(
            (number(&current, "sequence")?
                .checked_add(1)
                .ok_or_else(bad)?) as f64,
        ),
    )?;
    replace(
        &mut next_policy,
        "issued_at",
        WireValue::Number(issued_at as f64),
    )?;
    let payload_wire =
        canonical_wire_value(&next_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let domain = format!("peerwork.secure.policy.v{next_version}");
    let mut message = Vec::with_capacity(domain.len() + 1 + payload_wire.len());
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(payload_wire.as_bytes());
    let signed_new_policy = obj(vec![
        ("payload", next_policy),
        (
            "signature",
            s(&base64url(&signing_key.sign(&message).to_bytes())),
        ),
    ]);
    let signed_new_policy_wire =
        canonical_wire_value(&signed_new_policy, Path::SecureArtifact).map_err(|_| bad())?;
    let new_policy_hash = sha256_hex(signed_new_policy_wire.as_bytes());
    let sequence = number(&current, "sequence")?
        .checked_add(1)
        .ok_or_else(bad)?;
    let mut context_fields = vec![
        ("v", WireValue::Number(next_version as f64)),
        ("workspace_id", s(&workspace)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&string(&current, "head")?)),
        ("policy_hash", s(&new_policy_hash)),
        ("epoch", WireValue::Number(epoch as f64)),
        ("actor_id", s(&actor)),
        ("signing_key", s(&signer_key)),
        ("command_id", s(command_id)),
        ("action_id", s("secure.structure.begin")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("structure", begin.structure),
    ];
    let ceiling = if next_version == 3 {
        let ceiling = number(policy, "protocol_format_ceiling")?;
        context_fields.push(("protocol_format_ceiling", WireValue::Number(ceiling as f64)));
        Some(ceiling)
    } else {
        None
    };
    let operation_wire =
        canonical_wire_value(&begin.operation, Path::SecureArtifact).map_err(|_| bad())?;
    let commit = sign_private_commit(
        &obj(context_fields),
        operation_wire.as_bytes(),
        epoch_key,
        signing_key,
        &crate::prepared_secure_request::SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &signer_key,
            workspace_id: &workspace,
            policy_hash: &new_policy_hash,
            sequence,
            previous: Some(&string(&current, "head")?),
            epoch,
            mode: "PRIVATE",
            version: next_version,
            protocol_format_ceiling: ceiling,
        },
    )
    .map_err(|_| PrivateInstallError::Author)?;
    let commit_hash = sha256_hex(commit.as_bytes());
    let request_wire =
        format!("{{\"commit\":{commit},\"policy_update\":{signed_new_policy_wire}}}").into_bytes();
    if request_wire.len() > 220_000 {
        return Err(PrivateInstallError::Resource);
    }
    Ok(PreparedPrivatePackageInstallBegin {
        request_wire,
        commit_hash,
        policy_hash: new_policy_hash,
        snapshot,
        direct_composition: compiled.composition().cloned(),
        protocol_digest: expected_protocol_digest.to_owned(),
        instance_id: instance_id.to_owned(),
    })
}

/// Reconstruct every deterministic BEGIN field and decrypt the saved packet
/// before uncertain-reply retry. The nonce and ciphertext themselves remain
/// the original protected bytes; this function never returns a new packet.
#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_package_install_begin(
    saved_request_wire: &[u8],
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    stage_end_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    verify_saved_private_package_install_begin_with_disclosure(
        saved_request_wire, material_wire, source_checkpoint_wire,
        stage_end_checkpoint_wire, signed_policy_wire, prior_objects,
        grants_wire, b"[]", instance_id, entrypoint, command_id, issued_at,
        signing_key, epoch_key,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_package_install_begin_with_disclosure(
    saved_request_wire: &[u8],
    material_wire: &[u8],
    source_checkpoint_wire: &[u8],
    stage_end_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    disclose_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if saved_request_wire.is_empty() || saved_request_wire.len() > 220_000 {
        return Err(bad());
    }
    let expected = prepare_private_package_install_begin_with_disclosure(
        material_wire,
        source_checkpoint_wire,
        stage_end_checkpoint_wire,
        signed_policy_wire,
        prior_objects,
        grants_wire,
        disclose_wire,
        instance_id,
        entrypoint,
        command_id,
        issued_at,
        signing_key,
        epoch_key,
    )?;
    verify_saved_private_install_begin_against(saved_request_wire, expected, signing_key, epoch_key)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_direct_install_begin(
    saved_request_wire: &[u8],
    material_wire: &[u8],
    expected_root_package_digest: &str,
    expected_protocol_digest: &str,
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    verify_saved_private_direct_install_begin_with_options(
        saved_request_wire, material_wire, b"{}", expected_root_package_digest,
        expected_protocol_digest, current_checkpoint_wire, signed_policy_wire,
        prior_objects, grants_wire, b"[]", instance_id, entrypoint, command_id,
        issued_at, signing_key, epoch_key,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_direct_install_begin_with_options(
    saved_request_wire: &[u8],
    material_wire: &[u8],
    bindings_wire: &[u8],
    expected_root_package_digest: &str,
    expected_protocol_digest: &str,
    current_checkpoint_wire: &[u8],
    signed_policy_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    disclose_wire: &[u8],
    instance_id: &str,
    entrypoint: &str,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    let expected = prepare_private_direct_install_begin_with_options(
        material_wire,
        bindings_wire,
        expected_root_package_digest,
        expected_protocol_digest,
        current_checkpoint_wire,
        signed_policy_wire,
        prior_objects,
        grants_wire,
        disclose_wire,
        instance_id,
        entrypoint,
        command_id,
        issued_at,
        signing_key,
        epoch_key,
    )?;
    verify_saved_private_install_begin_against(saved_request_wire, expected, signing_key, epoch_key)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_direct_install_begin_with_object_source(
    saved_request_wire: &[u8], material_wire: &[u8], bindings_wire: &[u8],
    expected_root_package_digest: &str, expected_protocol_digest: &str,
    current_checkpoint_wire: &[u8], signed_policy_wire: &[u8], prior_objects: &[WireValue],
    grants_wire: &[u8], disclose_wire: &[u8], instance_id: &str, entrypoint: &str,
    command_id: &str, issued_at: u64, signing_key: &SigningKey, epoch_key: &[u8; 32],
    proof: &WireValue,
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    let expected = prepare_private_direct_install_begin_with_source(material_wire, bindings_wire,
        expected_root_package_digest, expected_protocol_digest, current_checkpoint_wire,
        signed_policy_wire, prior_objects, grants_wire, disclose_wire, instance_id, entrypoint,
        command_id, issued_at, signing_key, epoch_key, Some(proof))?;
    verify_saved_private_install_begin_against(saved_request_wire, expected, signing_key, epoch_key)
}

fn verify_saved_private_install_begin_against(
    saved_request_wire: &[u8],
    expected: PreparedPrivatePackageInstallBegin,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallBegin, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if saved_request_wire.is_empty() || saved_request_wire.len() > 220_000 {
        return Err(bad());
    }
    let saved = parse_wire_json_bounded(saved_request_wire, 64, 220_000).map_err(|_| bad())?;
    let fresh = parse_wire_json_bounded(expected.request_wire(), 64, 220_000).map_err(|_| bad())?;
    if saved.object_len() != Some(2)
        || canonical_wire_value(
            saved.get("policy_update").ok_or_else(bad)?,
            Path::SecureArtifact,
        )
        .map_err(|_| bad())?
            != canonical_wire_value(
                fresh.get("policy_update").ok_or_else(bad)?,
                Path::SecureArtifact,
            )
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let saved_commit = saved.get("commit").ok_or_else(bad)?;
    let fresh_commit = fresh.get("commit").ok_or_else(bad)?;
    let saved_commit_wire =
        canonical_wire_value(saved_commit, Path::SecureArtifact).map_err(|_| bad())?;
    let key_id = base64url(&signing_key.verifying_key().to_bytes());
    if !verify_secure_signed_wire(
        saved_commit_wire.as_bytes(),
        "peerwork.secure.commit.v1",
        &key_id,
    )
    .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let saved_payload = saved_commit.get("payload").ok_or_else(bad)?;
    let fresh_payload = fresh_commit.get("payload").ok_or_else(bad)?;
    fn context(value: &WireValue) -> Result<WireValue, PrivateInstallError> {
        let WireValue::Object(fields) = value else {
            return Err(PrivateInstallError::Invalid);
        };
        Ok(WireValue::Object(
            fields
                .iter()
                .filter(|(name, _)| {
                    !name.iter().copied().eq("body".encode_utf16())
                        && !name.iter().copied().eq("mode".encode_utf16())
                })
                .cloned()
                .collect(),
        ))
    }
    if saved_payload.get("mode") != Some(&s("PRIVATE"))
        || saved_payload.get("body").is_none()
        || canonical_wire_value(&context(saved_payload)?, Path::SecureArtifact)
            .map_err(|_| bad())?
            != canonical_wire_value(&context(fresh_payload)?, Path::SecureArtifact)
                .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let saved_body = canonical_wire_value(
        saved_payload.get("body").ok_or_else(bad)?,
        Path::SecureArtifact,
    )
    .map_err(|_| bad())?;
    let fresh_body = canonical_wire_value(
        fresh_payload.get("body").ok_or_else(bad)?,
        Path::SecureArtifact,
    )
    .map_err(|_| bad())?;
    let saved_sealed: SealedContent = serde_json::from_str(&saved_body).map_err(|_| bad())?;
    let fresh_sealed: SealedContent = serde_json::from_str(&fresh_body).map_err(|_| bad())?;
    let context_wire =
        canonical_wire_value(&context(saved_payload)?, Path::SecureArtifact).map_err(|_| bad())?;
    let saved_plain =
        open_content_wire(epoch_key, &saved_sealed, context_wire.as_bytes()).map_err(|_| bad())?;
    let fresh_plain =
        open_content_wire(epoch_key, &fresh_sealed, context_wire.as_bytes()).map_err(|_| bad())?;
    if saved_plain != fresh_plain
        || canonical_wire_value(&saved, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes()
            != saved_request_wire
    {
        return Err(bad());
    }
    Ok(PreparedPrivatePackageInstallBegin {
        request_wire: saved_request_wire.to_vec(),
        commit_hash: sha256_hex(saved_commit_wire.as_bytes()),
        policy_hash: expected.policy_hash,
        snapshot: expected.snapshot,
        direct_composition: expected.direct_composition,
        protocol_digest: expected.protocol_digest,
        instance_id: expected.instance_id,
    })
}

/// Author one encrypted PAGE or END from a signed SEEDING snapshot. Runtime
/// must derive `plan` from the authenticated source objects and BEGIN policy,
/// then persist/reprove these exact bytes before network submission.
#[allow(clippy::too_many_arguments)]
pub fn prepare_private_package_install_step(
    signed_policy_wire: &[u8],
    current_checkpoint_wire: &[u8],
    signed_snapshot: &WireValue,
    plan: &PublicInstallSnapshotPlan,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallStep, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if !token(command_id) || issued_at > MAX_SAFE {
        return Err(bad());
    }
    let policy = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| bad())?;
    let payload = policy.get("payload").ok_or_else(bad)?;
    let checkpoint =
        parse_wire_json_bounded(current_checkpoint_wire, 32, 8192).map_err(|_| bad())?;
    let policy_wire = canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| bad())?;
    let version = number(payload, "v")?;
    let epoch = number(payload, "epoch")?;
    let actor = actor_id(&signing_key.verifying_key().to_bytes());
    let key_id = base64url(&signing_key.verifying_key().to_bytes());
    if !matches!(version, 2 | 3)
        || epoch == 0
        || string(payload, "visibility")? != "PRIVATE"
        || string(payload, "owner_id")? != actor
        || string(payload, "signing_key")? != key_id
        || string(&checkpoint, "owner_id")? != actor
        || string(&checkpoint, "owner_key")? != key_id
        || string(payload, "workspace_id")? != string(&checkpoint, "workspace_id")?
        || string(&checkpoint, "policy_hash")? != sha256_hex(policy_wire.as_bytes())
        || number(payload, "issued_at")? > issued_at
        || !verify_secure_signed_wire(policy_wire.as_bytes(), "peerwork.secure.policy.v1", &key_id)
            .map_err(|_| bad())?
        || (version == 3 && string(payload, "structure_mode")? != "STRUCTURED")
    {
        return Err(bad());
    }
    for field in ["source", "root", "records", "heads"] {
        if signed_snapshot.get(field) != plan.snapshot().get(field) {
            return Err(bad());
        }
    }
    let offset = usize::try_from(number(signed_snapshot, "offset")?).map_err(|_| bad())?;
    let records = plan.records();
    let heads = plan.heads();
    let total = records.len().checked_add(heads.len()).ok_or_else(bad)?;
    if offset > total {
        return Err(bad());
    }
    let done = offset == total;
    let (action_id, mode, page_records, page_heads) = if done {
        (
            "secure.structure.end",
            "SNAPSHOT_END",
            Vec::new(),
            Vec::new(),
        )
    } else if offset < records.len() {
        let end = offset.saturating_add(50).min(records.len());
        (
            "secure.structure.page",
            "SNAPSHOT_PAGE",
            records[offset..end].to_vec(),
            Vec::new(),
        )
    } else {
        let start = offset - records.len();
        let end = start.saturating_add(50).min(heads.len());
        (
            "secure.structure.page",
            "SNAPSHOT_PAGE",
            Vec::new(),
            heads[start..end].to_vec(),
        )
    };
    let structure = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("mode", s(mode)),
        ("snapshot", signed_snapshot.clone()),
        ("records", WireValue::Array(page_records)),
        ("heads", WireValue::Array(page_heads)),
    ]);
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", s("ADMIN")),
        ("input", obj(vec![])),
        ("objects", WireValue::Array(vec![])),
    ]);
    let sequence = number(&checkpoint, "sequence")?
        .checked_add(1)
        .ok_or_else(bad)?;
    let workspace = string(&checkpoint, "workspace_id")?;
    let previous = string(&checkpoint, "head")?;
    let policy_hash = string(&checkpoint, "policy_hash")?;
    let mut fields = vec![
        ("v", WireValue::Number(version as f64)),
        ("workspace_id", s(&workspace)),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", s(&previous)),
        ("policy_hash", s(&policy_hash)),
        ("epoch", WireValue::Number(epoch as f64)),
        ("actor_id", s(&actor)),
        ("signing_key", s(&key_id)),
        ("command_id", s(command_id)),
        ("action_id", s(action_id)),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("structure", structure),
    ];
    let ceiling = if version == 3 {
        let n = number(payload, "protocol_format_ceiling")?;
        fields.push(("protocol_format_ceiling", WireValue::Number(n as f64)));
        Some(n)
    } else {
        None
    };
    let context = obj(fields);
    let operation_wire =
        canonical_wire_value(&operation, Path::SecureArtifact).map_err(|_| bad())?;
    let commit = sign_private_commit(
        &context,
        operation_wire.as_bytes(),
        epoch_key,
        signing_key,
        &crate::prepared_secure_request::SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key_id,
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence,
            previous: Some(&previous),
            epoch,
            mode: "PRIVATE",
            version,
            protocol_format_ceiling: ceiling,
        },
    )
    .map_err(|_| PrivateInstallError::Author)?;
    let request_wire = format!("{{\"commit\":{commit}}}").into_bytes();
    if request_wire.len() > 220_000 {
        return Err(PrivateInstallError::Resource);
    }
    Ok(PreparedPrivatePackageInstallStep {
        request_wire,
        commit_hash: sha256_hex(commit.as_bytes()),
        action_id,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_saved_private_package_install_step(
    saved_request_wire: &[u8],
    signed_policy_wire: &[u8],
    current_checkpoint_wire: &[u8],
    signed_snapshot: &WireValue,
    plan: &PublicInstallSnapshotPlan,
    command_id: &str,
    issued_at: u64,
    signing_key: &SigningKey,
    epoch_key: &[u8; 32],
) -> Result<PreparedPrivatePackageInstallStep, PrivateInstallError> {
    let bad = || PrivateInstallError::Invalid;
    if saved_request_wire.is_empty() || saved_request_wire.len() > 220_000 {
        return Err(bad());
    }
    let expected = prepare_private_package_install_step(
        signed_policy_wire,
        current_checkpoint_wire,
        signed_snapshot,
        plan,
        command_id,
        issued_at,
        signing_key,
        epoch_key,
    )?;
    let saved = parse_wire_json_bounded(saved_request_wire, 64, 220_000).map_err(|_| bad())?;
    let fresh = parse_wire_json_bounded(expected.request_wire(), 64, 220_000).map_err(|_| bad())?;
    if saved.object_len() != Some(1) {
        return Err(bad());
    }
    let saved_commit = saved.get("commit").ok_or_else(bad)?;
    let fresh_commit = fresh.get("commit").ok_or_else(bad)?;
    let saved_commit_wire =
        canonical_wire_value(saved_commit, Path::SecureArtifact).map_err(|_| bad())?;
    if !verify_secure_signed_wire(
        saved_commit_wire.as_bytes(),
        "peerwork.secure.commit.v1",
        &base64url(&signing_key.verifying_key().to_bytes()),
    )
    .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let saved_payload = saved_commit.get("payload").ok_or_else(bad)?;
    let fresh_payload = fresh_commit.get("payload").ok_or_else(bad)?;
    let context = |value: &WireValue| -> Result<WireValue, PrivateInstallError> {
        let WireValue::Object(fields) = value else {
            return Err(bad());
        };
        Ok(WireValue::Object(
            fields
                .iter()
                .filter(|(name, _)| {
                    !name.iter().copied().eq("body".encode_utf16())
                        && !name.iter().copied().eq("mode".encode_utf16())
                })
                .cloned()
                .collect(),
        ))
    };
    let saved_context = context(saved_payload)?;
    if saved_payload.get("mode") != Some(&s("PRIVATE"))
        || canonical_wire_value(&saved_context, Path::SecureArtifact).map_err(|_| bad())?
            != canonical_wire_value(&context(fresh_payload)?, Path::SecureArtifact)
                .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let open = |payload: &WireValue| -> Result<Vec<u8>, PrivateInstallError> {
        let body = canonical_wire_value(payload.get("body").ok_or_else(bad)?, Path::SecureArtifact)
            .map_err(|_| bad())?;
        let sealed: SealedContent = serde_json::from_str(&body).map_err(|_| bad())?;
        let context_wire =
            canonical_wire_value(&saved_context, Path::SecureArtifact).map_err(|_| bad())?;
        open_content_wire(epoch_key, &sealed, context_wire.as_bytes()).map_err(|_| bad())
    };
    if open(saved_payload)? != open(fresh_payload)?
        || canonical_wire_value(&saved, Path::SecureArtifact)
            .map_err(|_| bad())?
            .as_bytes()
            != saved_request_wire
    {
        return Err(bad());
    }
    Ok(PreparedPrivatePackageInstallStep {
        request_wire: saved_request_wire.to_vec(),
        commit_hash: sha256_hex(saved_commit_wire.as_bytes()),
        action_id: expected.action_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        e2ee::{open_content_wire, SealedContent},
        wire_json::parse_wire_json_bounded,
    };
    use ed25519_dalek::Signer;

    fn signed(payload: &WireValue, signer: &SigningKey) -> Vec<u8> {
        let canonical = canonical_wire_value(payload, Path::SecureArtifact).unwrap();
        let mut message = b"peerwork.secure.policy.v2\0".to_vec();
        message.extend_from_slice(canonical.as_bytes());
        canonical_wire_value(
            &obj(vec![
                ("payload", payload.clone()),
                (
                    "signature",
                    s(&base64url(&signer.sign(&message).to_bytes())),
                ),
            ]),
            Path::SecureArtifact,
        )
        .unwrap()
        .into_bytes()
    }

    #[test]
    fn encrypted_stage_uses_compiler_part_and_exact_owner_checkpoint() {
        let signer = SigningKey::from_bytes(&[92; 32]);
        let workspace = base64url(&[93; 32]);
        let owner_key = base64url(&signer.verifying_key().to_bytes());
        let owner = actor_id(&signer.verifying_key().to_bytes());
        let policy = signed(
            &obj(vec![
                ("v", WireValue::Number(2.0)),
                ("workspace_id", s(&workspace)),
                ("owner_id", s(&owner)),
                ("signing_key", s(&owner_key)),
                ("visibility", s("PRIVATE")),
                ("epoch", WireValue::Number(1.0)),
                ("effective_sequence", WireValue::Number(1.0)),
                (
                    "structure",
                    obj(vec![
                        ("v", WireValue::Number(1.0)),
                        ("protocols", WireValue::Array(vec![])),
                        ("disclosure", WireValue::Array(vec![])),
                        ("instances", WireValue::Array(vec![])),
                    ]),
                ),
            ]),
            &signer,
        );
        let policy_hash = sha256_hex(&policy);
        let checkpoint = obj(vec![
            ("v", WireValue::Number(1.0)),
            ("workspace_id", s(&workspace)),
            ("owner_id", s(&owner)),
            ("owner_key", s(&owner_key)),
            ("sequence", WireValue::Number(1.0)),
            ("head", s(&"a".repeat(64))),
            ("policy_hash", s(&policy_hash)),
        ]);
        let source_wire = canonical_wire_value(&checkpoint, Path::SecureArtifact).unwrap();
        let public = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-package-vectors.json"),
            64,
            2_000_000,
        )
        .unwrap();
        let material = obj(vec![
            ("v", WireValue::Number(1.0)),
            ("closure", public.get("closure").unwrap().clone()),
            ("bindings", obj(vec![])),
        ]);
        let material_wire = canonical_wire_value(&material, Path::SecureArtifact).unwrap();
        let result = prepare_private_package_stage(
            material_wire.as_bytes(),
            source_wire.as_bytes(),
            source_wire.as_bytes(),
            &policy,
            0,
            &base64url(&[21; 32]),
            2,
            &signer,
            &[19; 32],
        )
        .unwrap();
        let saved = verify_saved_private_package_stage(
            result.request_wire(),
            material_wire.as_bytes(),
            source_wire.as_bytes(),
            source_wire.as_bytes(),
            &policy,
            0,
            &base64url(&[21; 32]),
            2,
            &signer,
            &[19; 32],
        )
        .unwrap();
        assert_eq!(saved.commit_hash(), result.commit_hash());
        let imported = verify_imported_private_package_stage(
            result.request_wire(),
            source_wire.as_bytes(),
            &policy,
            &base64url(&[21; 32]),
            &signer,
            &[19; 32],
        )
        .unwrap();
        assert_eq!(imported.commit_hash(), result.commit_hash());
        assert_eq!(imported.request_wire(), result.request_wire());
        assert!(verify_imported_private_package_stage(
            result.request_wire(),
            source_wire.as_bytes(),
            &policy,
            &base64url(&[21; 32]),
            &signer,
            &[20; 32],
        )
        .is_err());
        assert!(verify_saved_private_package_stage(
            result.request_wire(),
            material_wire.as_bytes(),
            source_wire.as_bytes(),
            source_wire.as_bytes(),
            &policy,
            0,
            &base64url(&[22; 32]),
            2,
            &signer,
            &[19; 32],
        )
        .is_err());
        assert!(verify_saved_private_package_stage(
            result.request_wire(),
            material_wire.as_bytes(),
            source_wire.as_bytes(),
            source_wire.as_bytes(),
            &policy,
            0,
            &base64url(&[21; 32]),
            2,
            &signer,
            &[18; 32],
        )
        .is_err());
        assert_eq!(result.part_index(), 0);
        assert!(result.part_count() >= 1);
        let request = parse_wire_json_bounded(result.request_wire(), 64, 220_000).unwrap();
        let commit = request.get("commit").unwrap();
        let commit_wire = canonical_wire_value(commit, Path::SecureArtifact).unwrap();
        assert_eq!(result.commit_hash(), sha256_hex(commit_wire.as_bytes()));
        assert!(verify_secure_signed_wire(
            commit_wire.as_bytes(),
            "peerwork.secure.commit.v1",
            &owner_key
        )
        .unwrap());
        let payload = commit.get("payload").unwrap();
        let WireValue::Object(fields) = payload else {
            panic!("payload")
        };
        let context = WireValue::Object(
            fields
                .iter()
                .filter(|(name, _)| {
                    !name.iter().copied().eq("mode".encode_utf16())
                        && !name.iter().copied().eq("body".encode_utf16())
                })
                .cloned()
                .collect(),
        );
        let context_wire = canonical_wire_value(&context, Path::SecureArtifact).unwrap();
        let sealed_wire =
            canonical_wire_value(payload.get("body").unwrap(), Path::SecureArtifact).unwrap();
        let sealed: SealedContent = serde_json::from_str(&sealed_wire).unwrap();
        let plain = open_content_wire(&[19; 32], &sealed, context_wire.as_bytes()).unwrap();
        let op = parse_wire_json_bounded(&plain, 64, 220_000).unwrap();
        assert_eq!(
            op.get("kind").and_then(WireValue::as_string).as_deref(),
            Some("ADMIN")
        );
        assert_eq!(
            op.get("input")
                .unwrap()
                .get("package_stage")
                .unwrap()
                .get("source_id")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some(result.source_id())
        );
        let mut wrong = checkpoint.clone();
        if let WireValue::Object(fields) = &mut wrong {
            fields
                .iter_mut()
                .find(|(key, _)| key.iter().copied().eq("head".encode_utf16()))
                .unwrap()
                .1 = s(&"b".repeat(64));
        }
        let wrong_wire = canonical_wire_value(&wrong, Path::SecureArtifact).unwrap();
        assert!(prepare_private_package_stage(
            material_wire.as_bytes(),
            source_wire.as_bytes(),
            wrong_wire.as_bytes(),
            &policy,
            0,
            &base64url(&[21; 32]),
            2,
            &signer,
            &[19; 32]
        )
        .is_err());
    }

    #[test]
    fn selected_material_normalization_preserves_compiled_identity() {
        let cases = parse_wire_json_bounded(
            include_bytes!("../../../conformance/protocol-package-source-vectors.json"),
            64,
            2_000_000,
        ).unwrap();
        let WireValue::Array(cases) = cases else { panic!("source cases") };
        let source = cases[0].get("proof").unwrap().get("source").unwrap();
        let source_wire = canonical_wire_value(source, Path::SecureArtifact).unwrap();
        let public = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-package-vectors.json"),
            64,
            2_000_000,
        ).unwrap();
        let material = obj(vec![
            ("v", WireValue::Number(1.0)),
            ("closure", public.get("closure").unwrap().clone()),
            ("bindings", obj(vec![])),
        ]);
        let selected = canonical_wire_value(&material, Path::SecureArtifact).unwrap();
        let formatted = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&selected).unwrap(),
        ).unwrap();
        assert_ne!(sha256_hex(selected.as_bytes()), sha256_hex(formatted.as_bytes()));
        let canonical = canonical_package_source_material(
            selected.as_bytes(), source_wire.as_bytes(),
        ).unwrap();
        let equivalent = canonical_package_source_material(
            formatted.as_bytes(), source_wire.as_bytes(),
        ).unwrap();
        assert_eq!(canonical, equivalent);
        let mut changed = serde_json::from_str::<serde_json::Value>(&selected).unwrap();
        changed["v"] = serde_json::json!(2);
        assert!(canonical_package_source_material(
            serde_json::to_string(&changed).unwrap().as_bytes(), source_wire.as_bytes(),
        ).is_err());
    }
}
