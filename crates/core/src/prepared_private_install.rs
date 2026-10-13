//! PRIVATE Owner package staging. The caller must obtain both checkpoints and
//! the selected policy from complete authenticated replay. This low-level
//! author is not an installation receipt or a transport authority by itself.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{open_content_wire, SealedContent},
    prepared_package_source::prepare_package_source_wire,
    prepared_secure_author::sign_private_commit,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::SigningKey;
use thiserror::Error;

const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivateInstallError {
    #[error("package material or signed staging context is invalid")]
    Invalid,
    #[error("package material exceeds the supported resource budget")]
    Resource,
    #[error("OS entropy or encrypted packet authoring failed")]
    Author,
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
}
