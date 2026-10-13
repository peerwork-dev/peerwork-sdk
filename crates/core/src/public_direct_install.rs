//! Source-matched object proposal for a direct PUBLIC protocol install.
//! The caller must bind this proposal to complete authenticated replay,
//! owner policy, signed ADMIN snapshot, and exact saved transport bytes.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, sha256_hex, verify_secure_signed_wire},
    full_manifest::validate_full_manifest,
    genesis_structure_policy::derive_install_structure_policy_with_keep_encrypted,
    package_closure::{compile_package_material, scan_package_closure},
    secure_replay::project_structure_data,
    structure_bindings::validate_object_bindings,
    structure_policy::validate_structure_policy,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub enum DirectInstallError {
    Invalid,
    Resource,
}
pub struct PublicPackageCompilation {
    package_digest: String,
    package_id: String,
    package_version: String,
    protocol_digest: String,
    manifest_wire: Vec<u8>,
}
impl PublicPackageCompilation {
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }
    pub fn package_id(&self) -> &str {
        &self.package_id
    }
    pub fn package_version(&self) -> &str {
        &self.package_version
    }
    pub fn protocol_digest(&self) -> &str {
        &self.protocol_digest
    }
    pub fn manifest_wire(&self) -> &[u8] {
        &self.manifest_wire
    }
}
pub struct PreparedPublicPackageInstallBegin {
    package_digest: String,
    package_id: String,
    package_version: String,
    signed: SignedPublicInstallBegin,
}
impl PreparedPublicPackageInstallBegin {
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }
    pub fn package_id(&self) -> &str {
        &self.package_id
    }
    pub fn package_version(&self) -> &str {
        &self.package_version
    }
    pub fn protocol_digest(&self) -> &str {
        self.signed.protocol_digest()
    }
    pub fn instance_id(&self) -> &str {
        self.signed.instance_id()
    }
    pub fn policy_hash(&self) -> &str {
        self.signed.policy_hash()
    }
    pub fn commit_hash(&self) -> &str {
        self.signed.commit_hash()
    }
    pub fn request_wire(&self) -> &[u8] {
        self.signed.request_wire()
    }
}

/// Verify the exact locally selected package closure before PUBLIC direct
/// install. The signed PUBLIC wire later carries only the resolved manifest;
/// this package digest therefore remains protected local selection evidence.
pub fn compile_public_package_closure(
    closure_wire: &[u8],
) -> Result<PublicPackageCompilation, DirectInstallError> {
    if closure_wire.is_empty() || closure_wire.len() > 6 * 1024 * 1024 {
        return Err(DirectInstallError::Resource);
    }
    let closure = parse_wire_json_bounded(closure_wire, 64, 6 * 1024 * 1024)
        .map_err(|_| DirectInstallError::Invalid)?;
    let scanned = scan_package_closure(&closure).map_err(|_| DirectInstallError::Invalid)?;
    let root_bundle = scanned
        .packages
        .get(&scanned.root)
        .ok_or(DirectInstallError::Invalid)?;
    let metadata_text = root_bundle
        .get("files")
        .and_then(|files| files.get("package.json"))
        .and_then(WireValue::as_string)
        .ok_or(DirectInstallError::Invalid)?;
    let metadata = parse_wire_json_bounded(metadata_text.as_bytes(), 16, 16 * 1024)
        .map_err(|_| DirectInstallError::Invalid)?;
    let package_id = metadata
        .get("package_id")
        .and_then(WireValue::as_string)
        .ok_or(DirectInstallError::Invalid)?;
    let package_version = metadata
        .get("version")
        .and_then(WireValue::as_string)
        .ok_or(DirectInstallError::Invalid)?;
    let compiled = compile_package_material(&scanned, &obj(vec![]))
        .map_err(|_| DirectInstallError::Invalid)?;
    let manifest_wire = canonical_wire_value(&compiled.manifest, Path::SecureArtifact)
        .map_err(|_| DirectInstallError::Invalid)?
        .into_bytes();
    if compiled.manifest.get("format_version") == Some(&WireValue::Number(2.0))
        || compiled.manifest.get("dependencies") != Some(&WireValue::Array(vec![]))
        || compiled.manifest.get("constraints") != Some(&obj(vec![]))
    {
        return Err(DirectInstallError::Invalid);
    }
    Ok(PublicPackageCompilation {
        package_digest: scanned.root,
        package_id,
        package_version,
        protocol_digest: compiled.protocol_digest,
        manifest_wire,
    })
}

/// Keep the locally selected package digest adjacent to the signed packet;
/// PUBLIC service wire has no package_source field. Runtime must obtain prior
/// artifacts from HTTPS-bound complete replay before it may submit this.
#[allow(clippy::too_many_arguments)]
pub fn prepare_public_package_install_begin(
    closure_wire: &[u8],
    expected_package_digest: &str,
    expected_protocol_digest: &str,
    prior_signed_policy_wire: &[u8],
    prior_checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    instance_id: &str,
    entrypoint_name: &str,
    command_id: &str,
    issued_at: u64,
    signer: &SigningKey,
) -> Result<PreparedPublicPackageInstallBegin, DirectInstallError> {
    let compiled = compile_public_package_closure(closure_wire)?;
    if compiled.package_digest() != expected_package_digest
        || compiled.protocol_digest() != expected_protocol_digest
    {
        return Err(DirectInstallError::Invalid);
    }
    let signed = prepare_public_direct_install_begin(
        compiled.manifest_wire(),
        expected_protocol_digest,
        prior_signed_policy_wire,
        prior_checkpoint_wire,
        prior_objects,
        grants_wire,
        instance_id,
        entrypoint_name,
        command_id,
        issued_at,
        signer,
    )?;
    Ok(PreparedPublicPackageInstallBegin {
        package_digest: compiled.package_digest,
        package_id: compiled.package_id,
        package_version: compiled.package_version,
        signed,
    })
}

/// Compose a PUBLIC direct-install BEGIN into one exact signed
/// pre-submit packet. This verifies the prior policy signature and checkpoint
/// consistency, but only the runtime can prove HTTPS origin, complete replay,
/// local package selection, active structure and prior-object provenance.
#[allow(clippy::too_many_arguments)]
pub fn prepare_public_direct_install_begin(
    manifest_wire: &[u8],
    expected_protocol_digest: &str,
    prior_signed_policy_wire: &[u8],
    prior_checkpoint_wire: &[u8],
    prior_objects: &[WireValue],
    grants_wire: &[u8],
    instance_id: &str,
    entrypoint_name: &str,
    command_id: &str,
    issued_at: u64,
    signer: &SigningKey,
) -> Result<SignedPublicInstallBegin, DirectInstallError> {
    let invalid = || DirectInstallError::Invalid;
    let prior_policy =
        parse_wire_json_bounded(prior_signed_policy_wire, 64, 196_608).map_err(|_| invalid())?;
    let checkpoint =
        parse_wire_json_bounded(prior_checkpoint_wire, 32, 8192).map_err(|_| invalid())?;
    let grants = parse_wire_json_bounded(grants_wire, 32, 65_536).map_err(|_| invalid())?;
    let objects = prior_objects;
    let grant_rows = array(&grants)?;
    let key_id = base64url(&signer.verifying_key().to_bytes());
    let actor = actor_id(&signer.verifying_key().to_bytes());
    let policy_wire =
        canonical_wire_value(&prior_policy, Path::SecureArtifact).map_err(|_| invalid())?;
    if !verify_secure_signed_wire(policy_wire.as_bytes(), "peerwork.secure.policy.v3", &key_id)
        .map_err(|_| invalid())?
        || required(&checkpoint, "policy_hash")?.as_string().as_deref()
            != Some(&sha256_hex(policy_wire.as_bytes()))
        || required(&checkpoint, "owner_id")?.as_string().as_deref() != Some(&actor)
        || required(&checkpoint, "owner_key")?.as_string().as_deref() != Some(&key_id)
        || required(required(&prior_policy, "payload")?, "workspace_id")?
            != required(&checkpoint, "workspace_id")?
        || objects.iter().any(|object| {
            object.get("id").and_then(WireValue::as_string).as_deref() == Some(instance_id)
        })
    {
        return Err(invalid());
    }
    let prior_payload = required(&prior_policy, "payload")?;
    let prior_structure = if let Some(structure) = prior_payload.get("structure") {
        structure.clone()
    } else if required(prior_payload, "structure_mode")?
        .as_string()
        .as_deref()
        == Some("NONE")
    {
        let mut prior_wire = String::new();
        ordered_json(
            &WireValue::Array(adoption_objects(objects)?),
            0,
            &mut prior_wire,
        )?;
        let derived =
            derive_install_structure_policy_with_keep_encrypted(prior_wire.as_bytes(), b"[]")
                .map_err(|_| invalid())?;
        parse_wire_json_bounded(derived.as_bytes(), 64, 2_000_000).map_err(|_| invalid())?
    } else {
        return Err(invalid());
    };
    validate_object_bindings(&prior_structure, objects).map_err(|_| invalid())?;
    let workspace_id = required(&checkpoint, "workspace_id")?
        .as_string()
        .ok_or_else(invalid)?;
    let built = build_direct_install_objects(
        manifest_wire,
        expected_protocol_digest,
        &workspace_id,
        instance_id,
        entrypoint_name,
        issued_at,
    )?;
    if objects.iter().any(|object| {
        object.get("id").and_then(WireValue::as_string).as_deref() == Some(expected_protocol_digest)
    }) {
        return Err(invalid());
    }
    let structure = derive_direct_install_structure(
        &prior_structure,
        objects,
        &built.added,
        expected_protocol_digest,
        &built.manifest,
    )?;
    let sequence = safe_int(required(&checkpoint, "sequence")?)?;
    let payload = derive_direct_install_policy_payload(
        &prior_policy,
        sequence,
        &structure,
        grant_rows,
        &built.manifest,
        instance_id,
        issued_at,
    )?;
    let snapshot = plan_public_install_snapshot(objects, &structure, &checkpoint)?;
    let begin = build_direct_install_begin(
        &checkpoint,
        &built.added,
        instance_id,
        expected_protocol_digest,
        entrypoint_name,
        snapshot.snapshot(),
    )?;
    sign_public_direct_install_begin(&payload, &checkpoint, &begin, command_id, issued_at, signer)
}

pub(crate) struct DirectInstallObjects {
    pub added: Vec<WireValue>,
    pub manifest: WireValue,
}
pub(crate) struct EmptySnapshotBegin {
    pub operation: WireValue,
    pub structure: WireValue,
}

/// Exact sorted projection that the signed BEGIN commits to. The same plan
/// yields bounded PAGE slices during authenticated continuation.
pub struct PublicInstallSnapshotPlan {
    snapshot: WireValue,
    records: Vec<WireValue>,
    heads: Vec<WireValue>,
}

impl PublicInstallSnapshotPlan {
    pub fn snapshot(&self) -> &WireValue {
        &self.snapshot
    }
    pub fn records(&self) -> &[WireValue] {
        &self.records
    }
    pub fn heads(&self) -> &[WireValue] {
        &self.heads
    }
}

pub fn plan_public_install_snapshot(
    prior_objects: &[WireValue],
    contract: &WireValue,
    source_checkpoint: &WireValue,
) -> Result<PublicInstallSnapshotPlan, DirectInstallError> {
    validate_structure_policy(contract).map_err(|_| DirectInstallError::Invalid)?;
    let (mut records, mut heads) =
        project_structure_data(prior_objects, contract).map_err(|_| DirectInstallError::Invalid)?;
    if records
        .len()
        .checked_add(heads.len())
        .is_none_or(|total| total > 100_000)
    {
        return Err(DirectInstallError::Resource);
    }
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
    let data = obj(vec![
        ("records", WireValue::Array(records.clone())),
        ("heads", WireValue::Array(heads.clone())),
    ]);
    let canonical = canonical_wire_value(&data, Path::SecureArtifact)
        .map_err(|_| DirectInstallError::Invalid)?;
    let snapshot = obj(vec![
        ("source", source_checkpoint.clone()),
        ("root", text(&sha256_hex(canonical.as_bytes()))),
        ("records", WireValue::Number(records.len() as f64)),
        ("heads", WireValue::Number(heads.len() as f64)),
        ("offset", WireValue::Number(0.0)),
    ]);
    Ok(PublicInstallSnapshotPlan {
        snapshot,
        records,
        heads,
    })
}
pub struct SignedPublicInstallBegin {
    request_wire: Vec<u8>,
    policy_hash: String,
    commit_hash: String,
    protocol_digest: String,
    instance_id: String,
}
impl SignedPublicInstallBegin {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    pub fn protocol_digest(&self) -> &str {
        &self.protocol_digest
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

pub struct SignedPublicInstallEnd {
    request_wire: Vec<u8>,
    commit_hash: String,
    policy_hash: String,
    action_id: &'static str,
}
impl SignedPublicInstallEnd {
    pub fn request_wire(&self) -> &[u8] {
        &self.request_wire
    }
    pub fn commit_hash(&self) -> &str {
        &self.commit_hash
    }
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
    pub fn action_id(&self) -> &'static str {
        self.action_id
    }
}

/// Low-level PAGE/END signer. Runtime must derive `plan` from authenticated
/// prior objects and the signed BEGIN policy, and obtain `snapshot` and
/// `checkpoint` from a complete signed SEEDING replay before transport.
pub fn sign_public_install_step(
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    snapshot: &WireValue,
    plan: &PublicInstallSnapshotPlan,
    command_id: &str,
    issued_at: u64,
    signer: &SigningKey,
) -> Result<SignedPublicInstallEnd, DirectInstallError> {
    let invalid = || DirectInstallError::Invalid;
    if !token(command_id) || issued_at > 9_007_199_254_740_991 {
        return Err(invalid());
    }
    let policy = parse_wire_json_bounded(signed_policy_wire, 64, 196_608).map_err(|_| invalid())?;
    let checkpoint = parse_wire_json_bounded(checkpoint_wire, 32, 8192).map_err(|_| invalid())?;
    let key_id = base64url(&signer.verifying_key().to_bytes());
    let actor = actor_id(&signer.verifying_key().to_bytes());
    let policy_canonical =
        canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| invalid())?;
    if !verify_secure_signed_wire(
        policy_canonical.as_bytes(),
        "peerwork.secure.policy.v3",
        &key_id,
    )
    .map_err(|_| invalid())?
        || required(&checkpoint, "policy_hash")?.as_string().as_deref()
            != Some(&sha256_hex(policy_canonical.as_bytes()))
        || required(&checkpoint, "owner_id")?.as_string().as_deref() != Some(&actor)
        || required(&checkpoint, "owner_key")?.as_string().as_deref() != Some(&key_id)
    {
        return Err(invalid());
    }
    let p = required(&policy, "payload")?;
    if required(p, "v")? != &WireValue::Number(3.0)
        || required(p, "visibility")?.as_string().as_deref() != Some("PUBLIC")
        || required(p, "structure_mode")?.as_string().as_deref() != Some("STRUCTURED")
        || required(p, "protocol_format_ceiling")? != &WireValue::Number(1.0)
        || required(p, "owner_id")?.as_string().as_deref() != Some(&actor)
        || required(p, "signing_key")?.as_string().as_deref() != Some(&key_id)
        || required(p, "workspace_id")? != required(&checkpoint, "workspace_id")?
        || safe_int(required(p, "issued_at")?)? > issued_at
        || !matches!(required(&checkpoint, "head")?, WireValue::String(_))
    {
        return Err(invalid());
    }
    for field in ["source", "root", "records", "heads"] {
        if required(snapshot, field)? != required(plan.snapshot(), field)? {
            return Err(invalid());
        }
    }
    let offset =
        usize::try_from(safe_int(required(snapshot, "offset")?)?).map_err(|_| invalid())?;
    let record_count = plan.records().len();
    let total = record_count
        .checked_add(plan.heads().len())
        .ok_or_else(invalid)?;
    if offset > total {
        return Err(invalid());
    }
    let done = offset == total;
    let (action_id, mode, page_records, page_heads) = if done {
        (
            "secure.structure.end",
            "SNAPSHOT_END",
            Vec::new(),
            Vec::new(),
        )
    } else if offset < record_count {
        let end = offset.saturating_add(50).min(record_count);
        (
            "secure.structure.page",
            "SNAPSHOT_PAGE",
            plan.records()[offset..end].to_vec(),
            Vec::new(),
        )
    } else {
        let start = offset - record_count;
        let end = start.saturating_add(50).min(plan.heads().len());
        (
            "secure.structure.page",
            "SNAPSHOT_PAGE",
            Vec::new(),
            plan.heads()[start..end].to_vec(),
        )
    };
    let sequence = safe_int(required(&checkpoint, "sequence")?)?
        .checked_add(1)
        .ok_or_else(invalid)?;
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", text("ADMIN")),
        ("input", obj(vec![])),
        ("objects", WireValue::Array(vec![])),
    ]);
    let structure = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("mode", text(mode)),
        ("snapshot", snapshot.clone()),
        ("records", WireValue::Array(page_records)),
        ("heads", WireValue::Array(page_heads)),
    ]);
    let payload = obj(vec![
        ("v", WireValue::Number(3.0)),
        (
            "workspace_id",
            required(&checkpoint, "workspace_id")?.clone(),
        ),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", required(&checkpoint, "head")?.clone()),
        ("policy_hash", required(&checkpoint, "policy_hash")?.clone()),
        ("epoch", WireValue::Number(0.0)),
        ("actor_id", text(&actor)),
        ("signing_key", text(&key_id)),
        ("command_id", text(command_id)),
        ("action_id", text(action_id)),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("protocol_format_ceiling", WireValue::Number(1.0)),
        ("structure", structure),
        ("mode", text("PUBLIC")),
        ("body", operation),
    ]);
    let commit = sign_envelope(payload, "peerwork.secure.commit.v3", signer)?;
    let commit_wire = canonical_wire_value(&commit, Path::SecureArtifact).map_err(|_| invalid())?;
    if !verify_secure_signed_wire(commit_wire.as_bytes(), "peerwork.secure.commit.v3", &key_id)
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let request_wire = canonical_wire_value(&obj(vec![("commit", commit)]), Path::SecureArtifact)
        .map_err(|_| invalid())?
        .into_bytes();
    Ok(SignedPublicInstallEnd {
        request_wire,
        commit_hash: sha256_hex(commit_wire.as_bytes()),
        policy_hash: required(&checkpoint, "policy_hash")?
            .as_string()
            .ok_or_else(invalid)?,
        action_id,
    })
}

/// Compatibility signer for the already supported empty snapshot. It remains
/// strict while generic PAGE continuation is integrated by the runtime.
pub fn sign_public_empty_install_end(
    signed_policy_wire: &[u8],
    checkpoint_wire: &[u8],
    snapshot: &WireValue,
    command_id: &str,
    issued_at: u64,
    signer: &SigningKey,
) -> Result<SignedPublicInstallEnd, DirectInstallError> {
    if required(snapshot, "records")? != &WireValue::Number(0.0)
        || required(snapshot, "heads")? != &WireValue::Number(0.0)
        || required(snapshot, "offset")? != &WireValue::Number(0.0)
        || required(snapshot, "root")?.as_string().as_deref()
            != Some("5df677702279081de975c0b78651baa9fd6d5987ab205898154fd9ed3bafc9ff")
    {
        return Err(DirectInstallError::Invalid);
    }
    let plan = PublicInstallSnapshotPlan {
        snapshot: snapshot.clone(),
        records: vec![],
        heads: vec![],
    };
    sign_public_install_step(
        signed_policy_wire,
        checkpoint_wire,
        snapshot,
        &plan,
        command_id,
        issued_at,
        signer,
    )
}

fn entries(value: &WireValue) -> Result<&[(Vec<u16>, WireValue)], DirectInstallError> {
    if let WireValue::Object(fields) = value {
        Ok(fields)
    } else {
        Err(DirectInstallError::Invalid)
    }
}
fn array(value: &WireValue) -> Result<&[WireValue], DirectInstallError> {
    if let WireValue::Array(items) = value {
        Ok(items)
    } else {
        Err(DirectInstallError::Invalid)
    }
}
fn name(units: &[u16]) -> Result<String, DirectInstallError> {
    String::from_utf16(units).map_err(|_| DirectInstallError::Invalid)
}
fn required<'a>(value: &'a WireValue, field: &str) -> Result<&'a WireValue, DirectInstallError> {
    value.get(field).ok_or(DirectInstallError::Invalid)
}
fn put(
    value: &mut WireValue,
    field: &str,
    replacement: WireValue,
) -> Result<(), DirectInstallError> {
    let WireValue::Object(fields) = value else {
        return Err(DirectInstallError::Invalid);
    };
    if let Some((_, slot)) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(field.encode_utf16()))
    {
        *slot = replacement;
    } else {
        fields.push((key(field), replacement));
    }
    Ok(())
}
fn safe_int(value: &WireValue) -> Result<u64, DirectInstallError> {
    let number = value.as_number().ok_or(DirectInstallError::Invalid)?;
    if number.fract() != 0.0 || number < 0.0 || number > 9_007_199_254_740_991.0 {
        return Err(DirectInstallError::Invalid);
    }
    Ok(number as u64)
}
fn ordered_json(
    value: &WireValue,
    depth: usize,
    out: &mut String,
) -> Result<(), DirectInstallError> {
    if depth > 64 || out.len() > 2_000_000 {
        return Err(DirectInstallError::Resource);
    }
    match value {
        WireValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                ordered_json(item, depth + 1, out)?;
            }
            out.push(']');
        }
        WireValue::Object(fields) => {
            out.push('{');
            for (index, (name, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(
                    &canonical_wire_value(&WireValue::String(name.clone()), Path::SecureArtifact)
                        .map_err(|_| DirectInstallError::Invalid)?,
                );
                out.push(':');
                ordered_json(item, depth + 1, out)?;
            }
            out.push('}');
        }
        _ => out.push_str(
            &canonical_wire_value(value, Path::SecureArtifact)
                .map_err(|_| DirectInstallError::Invalid)?,
        ),
    }
    if out.len() > 2_000_000 {
        return Err(DirectInstallError::Resource);
    }
    Ok(())
}

/// `structurePolicyFromObjects` selects latest protocol and instance rows;
/// historical records/heads are projected into the snapshot separately.
fn adoption_objects(objects: &[WireValue]) -> Result<Vec<WireValue>, DirectInstallError> {
    let mut selected: Vec<WireValue> = Vec::new();
    for object in objects {
        let kind = required(object, "kind")?
            .as_string()
            .ok_or(DirectInstallError::Invalid)?;
        if kind != "protocols" && kind != "instances" {
            continue;
        }
        let id = required(object, "id")?;
        let revision = safe_int(required(object, "revision")?)?;
        if let Some(old) = selected
            .iter_mut()
            .find(|old| old.get("kind") == object.get("kind") && old.get("id") == Some(id))
        {
            if safe_int(required(old, "revision")?)? < revision {
                *old = object.clone();
            }
        } else {
            selected.push(object.clone());
        }
    }
    Ok(selected)
}

fn key(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn text(value: &str) -> WireValue {
    WireValue::String(key(value))
}
fn obj(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (key(name), value))
            .collect(),
    )
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn entrypoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "coordination"
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

pub(crate) fn build_direct_install_objects(
    manifest_wire: &[u8],
    expected_digest: &str,
    workspace_id: &str,
    instance_id: &str,
    origin_entrypoint: &str,
    issued_at: u64,
) -> Result<DirectInstallObjects, DirectInstallError> {
    let bad = || DirectInstallError::Invalid;
    if manifest_wire.is_empty() || manifest_wire.len() > 2_000_000 {
        return Err(DirectInstallError::Resource);
    }
    if !token(workspace_id)
        || !token(instance_id)
        || !entrypoint(origin_entrypoint)
        || expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || issued_at > 9_007_199_254_740_991
    {
        return Err(bad());
    }
    let raw = parse_wire_json_bounded(manifest_wire, 64, 2_000_000).map_err(|_| bad())?;
    let wrapped = validate_full_manifest(&raw).map_err(|_| bad())?;
    let parsed = parse_wire_json_bounded(wrapped.as_bytes(), 64, 2_000_000).map_err(|_| bad())?;
    let manifest = parsed.get("manifest").ok_or_else(bad)?.clone();
    // PUBLIC direct install carries a resolved executable manifest. Package
    // closure provenance stays local; dependencies require the separate
    // source-matched composition path and are refused by this builder.
    if manifest.get("format_version") == Some(&WireValue::Number(2.0))
        || manifest.get("dependencies") != Some(&WireValue::Array(vec![]))
        || manifest.get("constraints") != Some(&obj(vec![]))
    {
        return Err(bad());
    }
    if sha256_hex(wrapped.as_bytes()) != expected_digest {
        return Err(bad());
    }
    let protocol = obj(vec![
        ("kind", text("protocols")),
        ("id", text(expected_digest)),
        ("revision", WireValue::Number(1.0)),
        ("provenance", text("AUTHOR_SIGNED")),
        (
            "value",
            obj(vec![
                ("workspace_id", text(workspace_id)),
                ("digest", text(expected_digest)),
                ("manifest", manifest.clone()),
                ("resolved_manifest", manifest.clone()),
            ]),
        ),
    ]);
    let instance = obj(vec![
        ("kind", text("instances")),
        ("id", text(instance_id)),
        ("revision", WireValue::Number(1.0)),
        ("provenance", text("AUTHOR_SIGNED")),
        (
            "value",
            obj(vec![
                ("id", text(instance_id)),
                ("workspace_id", text(workspace_id)),
                ("protocol_digest", text(expected_digest)),
                ("origin_entrypoint", text(origin_entrypoint)),
                ("semantics", text("peerwork.kernel.v1")),
                (
                    "state",
                    manifest.get("initial_state").ok_or_else(bad)?.clone(),
                ),
                ("revision", WireValue::Number(0.0)),
                ("event_revision", WireValue::Number(0.0)),
                ("created", WireValue::Number(issued_at as f64)),
            ]),
        ),
    ]);
    canonical_wire_value(
        &WireValue::Array(vec![protocol.clone(), instance.clone()]),
        Path::SecureArtifact,
    )
    .map_err(|_| bad())?;
    Ok(DirectInstallObjects {
        added: vec![protocol, instance],
        manifest,
    })
}

/// Match the PUBLIC planner's `keep_encrypted`: retain every old E2EE field,
/// then make each field of the newly installed protocol E2EE by default.
pub(crate) fn derive_direct_install_structure(
    prior_structure: &WireValue,
    prior_objects: &[WireValue],
    added: &[WireValue],
    protocol_digest: &str,
    manifest: &WireValue,
) -> Result<WireValue, DirectInstallError> {
    let mut choices = Vec::new();
    for protocol in array(required(prior_structure, "protocols")?)? {
        let digest = required(protocol, "protocol_digest")?
            .as_string()
            .ok_or(DirectInstallError::Invalid)?;
        for (schema, definition) in entries(required(protocol, "schemas")?)? {
            let mut fields = Vec::new();
            for (field, details) in entries(required(definition, "fields")?)? {
                if required(details, "protection")?.as_string().as_deref() == Some("e2ee") {
                    fields.push(WireValue::String(field.clone()));
                }
            }
            if !fields.is_empty() {
                choices.push(obj(vec![
                    ("protocol_digest", text(&digest)),
                    ("schema", text(&name(schema)?)),
                    ("fields", WireValue::Array(fields)),
                ]));
            }
        }
    }
    for (schema, definition) in entries(required(manifest, "record_schemas")?)? {
        let fields = entries(required(definition, "fields")?)?
            .iter()
            .map(|(field, _)| WireValue::String(field.clone()))
            .collect::<Vec<_>>();
        if !fields.is_empty() {
            choices.push(obj(vec![
                ("protocol_digest", text(protocol_digest)),
                ("schema", text(&name(schema)?)),
                ("fields", WireValue::Array(fields)),
            ]));
        }
    }
    let all = WireValue::Array(adoption_objects(
        &prior_objects
            .iter()
            .chain(added)
            .cloned()
            .collect::<Vec<_>>(),
    )?);
    let mut all_wire = String::new();
    ordered_json(&all, 0, &mut all_wire)?;
    let mut choice_wire = String::new();
    ordered_json(&WireValue::Array(choices), 0, &mut choice_wire)?;
    let projected = derive_install_structure_policy_with_keep_encrypted(
        all_wire.as_bytes(),
        choice_wire.as_bytes(),
    )
    .map_err(|_| DirectInstallError::Invalid)?;
    let mut structure = parse_wire_json_bounded(projected.as_bytes(), 64, 2_000_000)
        .map_err(|_| DirectInstallError::Invalid)?;
    if let Some(coordination) = prior_structure.get("coordination") {
        let WireValue::Object(fields) = &mut structure else {
            return Err(DirectInstallError::Invalid);
        };
        fields.push((key("coordination"), coordination.clone()));
    }
    Ok(structure)
}

/// Build the next PUBLIC signed-policy payload for a direct standalone
/// install. `prior_signed_policy` and checkpoint must be authenticated by the
/// runtime before this proposal can be signed or submitted.
pub(crate) fn derive_direct_install_policy_payload(
    prior_signed_policy: &WireValue,
    checkpoint_sequence: u64,
    structure: &WireValue,
    grants: &[WireValue],
    manifest: &WireValue,
    instance_id: &str,
    issued_at: u64,
) -> Result<WireValue, DirectInstallError> {
    let invalid = || DirectInstallError::Invalid;
    if !token(instance_id)
        || checkpoint_sequence == 0
        || checkpoint_sequence >= 9_007_199_254_740_991
        || issued_at > 9_007_199_254_740_991
        || grants.len() > 128
    {
        return Err(invalid());
    }
    let old = required(prior_signed_policy, "payload")?;
    if required(old, "v")? != &WireValue::Number(3.0)
        || required(old, "visibility")?.as_string().as_deref() != Some("PUBLIC")
        || !matches!(
            required(old, "structure_mode")?.as_string().as_deref(),
            Some("STRUCTURED" | "NONE")
        )
        || required(old, "protocol_format_ceiling")? != &WireValue::Number(1.0)
        || old
            .get("structure")
            .is_some_and(|value| value.object_len().is_none())
        || prior_signed_policy
            .get("signature")
            .and_then(WireValue::as_string)
            .is_none()
    {
        return Err(invalid());
    }
    let version = safe_int(required(old, "version")?)?
        .checked_add(1)
        .ok_or_else(invalid)?;
    let signed_wire =
        canonical_wire_value(prior_signed_policy, Path::SecureArtifact).map_err(|_| invalid())?;
    let previous = sha256_hex(signed_wire.as_bytes());
    let mut members = array(required(old, "members")?)?.to_vec();
    let mut seen = HashSet::new();
    for grant in grants {
        let actor = required(grant, "actor_id")?
            .as_string()
            .ok_or_else(invalid)?;
        if !token(&actor) || !seen.insert(actor.clone()) {
            return Err(invalid());
        }
        let member = members
            .iter_mut()
            .find(|member| {
                member
                    .get("actor_id")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&actor)
            })
            .ok_or_else(invalid)?;
        let WireValue::Object(grant_fields) = grant else {
            return Err(invalid());
        };
        if grant_fields.iter().any(|(name, _)| {
            ![
                "actor_id",
                "actions",
                "protocol_roles",
                "capabilities",
                "expires_at",
            ]
            .iter()
            .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
        }) {
            return Err(invalid());
        }
        for (scope_key, manifest_key) in [
            ("actions", "actions"),
            ("protocol_roles", "protocol_roles"),
            ("capabilities", "capabilities"),
        ] {
            let values = array(required(grant, scope_key)?)?;
            let declared = array(required(manifest, manifest_key)?)?;
            for value in values {
                if value.as_utf16().is_none()
                    || !declared.iter().any(|item| {
                        if manifest_key == "actions" {
                            item.get("id") == Some(value)
                        } else {
                            item == value
                        }
                    })
                {
                    return Err(invalid());
                }
            }
        }
        let mut scope = WireValue::Object(
            grant_fields
                .iter()
                .filter(|(name, _)| !name.iter().copied().eq("actor_id".encode_utf16()))
                .cloned()
                .collect(),
        );
        put(&mut scope, "instance_id", text(instance_id))?;
        let mut scopes = array(required(member, "scopes")?)?.to_vec();
        scopes.push(scope);
        put(member, "scopes", WireValue::Array(scopes))?;
    }
    let mut payload = old.clone();
    put(&mut payload, "structure", structure.clone())?;
    put(&mut payload, "structure_mode", text("STRUCTURED"))?;
    put(&mut payload, "members", WireValue::Array(members))?;
    put(&mut payload, "version", WireValue::Number(version as f64))?;
    put(&mut payload, "previous_policy", text(&previous))?;
    put(
        &mut payload,
        "effective_sequence",
        WireValue::Number((checkpoint_sequence + 1) as f64),
    )?;
    put(
        &mut payload,
        "issued_at",
        WireValue::Number(issued_at as f64),
    )?;
    canonical_wire_value(&payload, Path::SecureArtifact).map_err(|_| invalid())?;
    Ok(payload)
}

pub(crate) fn build_direct_install_begin(
    checkpoint: &WireValue,
    added: &[WireValue],
    instance_id: &str,
    protocol_digest: &str,
    entrypoint_name: &str,
    snapshot: &WireValue,
) -> Result<EmptySnapshotBegin, DirectInstallError> {
    if !token(instance_id)
        || !entrypoint(entrypoint_name)
        || protocol_digest.len() != 64
        || !protocol_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(DirectInstallError::Invalid);
    }
    if required(snapshot, "source")? != checkpoint || safe_int(required(snapshot, "offset")?)? != 0
    {
        return Err(DirectInstallError::Invalid);
    }
    let structure = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("mode", text("SNAPSHOT_BEGIN")),
        ("records", WireValue::Array(vec![])),
        ("heads", WireValue::Array(vec![])),
        ("snapshot", snapshot.clone()),
    ]);
    let operation = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("kind", text("ADMIN")),
        (
            "input",
            obj(vec![(
                "install",
                obj(vec![
                    ("instance_id", text(instance_id)),
                    ("protocol_digest", text(protocol_digest)),
                    ("entrypoint", text(entrypoint_name)),
                ]),
            )]),
        ),
        ("objects", WireValue::Array(added.to_vec())),
    ]);
    Ok(EmptySnapshotBegin {
        operation,
        structure,
    })
}

#[cfg(test)]
pub(crate) fn build_empty_direct_install_begin(
    checkpoint: &WireValue,
    added: &[WireValue],
    instance_id: &str,
    protocol_digest: &str,
    entrypoint_name: &str,
) -> Result<EmptySnapshotBegin, DirectInstallError> {
    let empty_contract = obj(vec![
        ("v", WireValue::Number(1.0)),
        ("protocols", WireValue::Array(vec![])),
        ("disclosure", WireValue::Array(vec![])),
        ("instances", WireValue::Array(vec![])),
    ]);
    let snapshot = plan_public_install_snapshot(&[], &empty_contract, checkpoint)?;
    build_direct_install_begin(
        checkpoint,
        added,
        instance_id,
        protocol_digest,
        entrypoint_name,
        snapshot.snapshot(),
    )
}

fn sign_envelope(
    payload: WireValue,
    domain: &str,
    signer: &SigningKey,
) -> Result<WireValue, DirectInstallError> {
    let canonical = canonical_wire_value(&payload, Path::SecureArtifact)
        .map_err(|_| DirectInstallError::Invalid)?;
    let mut message = Vec::with_capacity(domain.len() + 1 + canonical.len());
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical.as_bytes());
    let signature = base64url(&signer.sign(&message).to_bytes());
    Ok(obj(vec![
        ("payload", payload),
        ("signature", text(&signature)),
    ]))
}

/// Sign the already-derived PUBLIC BEGIN packet. This low-level builder does
/// not authenticate `prior_checkpoint` or the source of prior objects; runtime
/// must derive both from complete HTTPS-bound replay and persist these exact
/// request bytes before POST.
pub(crate) fn sign_public_direct_install_begin(
    policy_payload: &WireValue,
    prior_checkpoint: &WireValue,
    begin: &EmptySnapshotBegin,
    command_id: &str,
    issued_at: u64,
    signer: &SigningKey,
) -> Result<SignedPublicInstallBegin, DirectInstallError> {
    let invalid = || DirectInstallError::Invalid;
    if !token(command_id) || issued_at > 9_007_199_254_740_991 {
        return Err(invalid());
    }
    let key_id = base64url(&signer.verifying_key().to_bytes());
    let actor = actor_id(&signer.verifying_key().to_bytes());
    if required(policy_payload, "v")? != &WireValue::Number(3.0)
        || required(policy_payload, "visibility")?
            .as_string()
            .as_deref()
            != Some("PUBLIC")
        || required(policy_payload, "structure_mode")?
            .as_string()
            .as_deref()
            != Some("STRUCTURED")
        || required(policy_payload, "protocol_format_ceiling")? != &WireValue::Number(1.0)
        || required(policy_payload, "owner_id")?.as_string().as_deref() != Some(&actor)
        || required(policy_payload, "signing_key")?
            .as_string()
            .as_deref()
            != Some(&key_id)
        || required(policy_payload, "issued_at")? != &WireValue::Number(issued_at as f64)
        || required(prior_checkpoint, "owner_id")?
            .as_string()
            .as_deref()
            != Some(&actor)
        || required(prior_checkpoint, "owner_key")?
            .as_string()
            .as_deref()
            != Some(&key_id)
        || required(prior_checkpoint, "workspace_id")? != required(policy_payload, "workspace_id")?
    {
        return Err(invalid());
    }
    let sequence = safe_int(required(prior_checkpoint, "sequence")?)?
        .checked_add(1)
        .ok_or_else(invalid)?;
    if required(policy_payload, "effective_sequence")? != &WireValue::Number(sequence as f64) {
        return Err(invalid());
    }
    if canonical_wire_value(
        required(required(&begin.structure, "snapshot")?, "source")?,
        Path::SecureArtifact,
    )
    .map_err(|_| invalid())?
        != canonical_wire_value(prior_checkpoint, Path::SecureArtifact).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let policy = sign_envelope(policy_payload.clone(), "peerwork.secure.policy.v3", signer)?;
    let policy_wire = canonical_wire_value(&policy, Path::SecureArtifact).map_err(|_| invalid())?;
    if !verify_secure_signed_wire(policy_wire.as_bytes(), "peerwork.secure.policy.v3", &key_id)
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let policy_hash = sha256_hex(policy_wire.as_bytes());
    let payload = obj(vec![
        ("v", WireValue::Number(3.0)),
        (
            "workspace_id",
            required(policy_payload, "workspace_id")?.clone(),
        ),
        ("sequence", WireValue::Number(sequence as f64)),
        ("previous", required(prior_checkpoint, "head")?.clone()),
        ("policy_hash", text(&policy_hash)),
        ("epoch", WireValue::Number(0.0)),
        ("actor_id", text(&actor)),
        ("signing_key", text(&key_id)),
        ("command_id", text(command_id)),
        ("action_id", text("secure.structure.begin")),
        ("instance_id", WireValue::Null),
        ("issued_at", WireValue::Number(issued_at as f64)),
        ("delegation", WireValue::Null),
        ("protocol_format_ceiling", WireValue::Number(1.0)),
        ("structure", begin.structure.clone()),
        ("mode", text("PUBLIC")),
        ("body", begin.operation.clone()),
    ]);
    let commit = sign_envelope(payload, "peerwork.secure.commit.v3", signer)?;
    let commit_wire = canonical_wire_value(&commit, Path::SecureArtifact).map_err(|_| invalid())?;
    if !verify_secure_signed_wire(commit_wire.as_bytes(), "peerwork.secure.commit.v3", &key_id)
        .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let commit_hash = sha256_hex(commit_wire.as_bytes());
    let request = obj(vec![("commit", commit), ("policy_update", policy)]);
    let request_wire = canonical_wire_value(&request, Path::SecureArtifact)
        .map_err(|_| invalid())?
        .into_bytes();
    if request_wire.len() > 220_000 {
        return Err(DirectInstallError::Resource);
    }
    let install = required(required(&begin.operation, "input")?, "install")?;
    let protocol_digest = required(install, "protocol_digest")?
        .as_string()
        .ok_or_else(invalid)?;
    let instance_id = required(install, "instance_id")?
        .as_string()
        .ok_or_else(invalid)?;
    Ok(SignedPublicInstallBegin {
        request_wire,
        policy_hash,
        commit_hash,
        protocol_digest,
        instance_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonempty_prior_snapshot_matches_pinned_install_planner() {
        let fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-direct-install-nonempty-vectors.json"),
            64,
            700_000,
        )
        .unwrap();
        let WireValue::Array(prior) = fixture.get("prior_objects").unwrap() else {
            panic!("prior objects")
        };
        let plan = plan_public_install_snapshot(
            prior,
            fixture.get("structure").unwrap(),
            fixture.get("checkpoint").unwrap(),
        )
        .unwrap();
        let same = |actual: &WireValue, expected: &WireValue| {
            canonical_wire_value(actual, Path::SecureArtifact).unwrap()
                == canonical_wire_value(expected, Path::SecureArtifact).unwrap()
        };
        assert!(same(plan.snapshot(), fixture.get("snapshot").unwrap()));
        assert!(same(
            &WireValue::Array(plan.records().to_vec()),
            fixture.get("projected").unwrap().get("records").unwrap()
        ));
        assert!(same(
            &WireValue::Array(plan.heads().to_vec()),
            fixture.get("projected").unwrap().get("heads").unwrap()
        ));
        let WireValue::Array(added) = fixture.get("added").unwrap() else {
            panic!("added")
        };
        let begin = build_direct_install_begin(
            fixture.get("checkpoint").unwrap(),
            added,
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
            plan.snapshot(),
        )
        .unwrap();
        assert!(same(
            begin.structure.get("snapshot").unwrap(),
            fixture.get("snapshot").unwrap()
        ));
    }

    #[test]
    fn official_public_direct_objects_match_pinned_planner() {
        let fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-direct-install-vectors.json"),
            64,
            500_000,
        )
        .unwrap();
        let expected = fixture.get("added").unwrap();
        let manifest = fixture.get("options").unwrap().get("manifest").unwrap();
        let manifest_wire = canonical_wire_value(manifest, Path::SecureArtifact).unwrap();
        let package_fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-package-vectors.json"),
            64,
            2_000_000,
        )
        .unwrap();
        let closure_wire = canonical_wire_value(
            package_fixture.get("closure").unwrap(),
            Path::SecureArtifact,
        )
        .unwrap();
        let compiled = compile_public_package_closure(closure_wire.as_bytes()).unwrap();
        assert_eq!(
            compiled.package_digest(),
            fixture.get("package_digest").unwrap().as_string().unwrap()
        );
        assert_eq!(
            compiled.protocol_digest(),
            fixture.get("protocol_digest").unwrap().as_string().unwrap()
        );
        assert_eq!(compiled.manifest_wire(), manifest_wire.as_bytes());
        let result = build_direct_install_objects(
            manifest_wire.as_bytes(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &fixture.get("workspace_id").unwrap().as_string().unwrap(),
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(
                &WireValue::Array(result.added.clone()),
                Path::SecureArtifact
            )
            .unwrap(),
            canonical_wire_value(expected, Path::SecureArtifact).unwrap()
        );
        assert_eq!(
            canonical_wire_value(&result.manifest, Path::SecureArtifact).unwrap(),
            canonical_wire_value(manifest, Path::SecureArtifact).unwrap()
        );
        let WireValue::Array(prior) = fixture.get("prior_objects").unwrap() else {
            panic!("prior objects")
        };
        let structure = derive_direct_install_structure(
            fixture
                .get("prior_policy")
                .unwrap()
                .get("payload")
                .unwrap()
                .get("structure")
                .unwrap(),
            prior,
            &result.added,
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &result.manifest,
        )
        .unwrap();
        let actual = canonical_wire_value(&structure, Path::SecureArtifact).unwrap();
        let expected =
            canonical_wire_value(fixture.get("structure").unwrap(), Path::SecureArtifact).unwrap();
        if actual != expected {
            let index = actual
                .bytes()
                .zip(expected.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(actual.len().min(expected.len()));
            panic!(
                "structure mismatch at {index}: actual {:?}, expected {:?}",
                &actual[index.saturating_sub(60)..(index + 100).min(actual.len())],
                &expected[index.saturating_sub(60)..(index + 100).min(expected.len())]
            );
        }
        let policy = derive_direct_install_policy_payload(
            fixture.get("prior_policy").unwrap(),
            1,
            &structure,
            match fixture.get("options").unwrap().get("grants").unwrap() {
                WireValue::Array(items) => items,
                _ => panic!("grants"),
            },
            &result.manifest,
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(&policy, Path::SecureArtifact).unwrap(),
            canonical_wire_value(fixture.get("policy_payload").unwrap(), Path::SecureArtifact)
                .unwrap()
        );
        let begin = build_empty_direct_install_begin(
            fixture.get("checkpoint").unwrap(),
            &result.added,
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
        )
        .unwrap();
        assert_eq!(
            canonical_wire_value(&begin.operation, Path::SecureArtifact).unwrap(),
            canonical_wire_value(
                fixture.get("begin_operation").unwrap(),
                Path::SecureArtifact
            )
            .unwrap()
        );
        assert_eq!(
            canonical_wire_value(&begin.structure, Path::SecureArtifact).unwrap(),
            canonical_wire_value(
                fixture.get("begin_structure").unwrap(),
                Path::SecureArtifact
            )
            .unwrap()
        );
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let actor = actor_id(&signer.verifying_key().to_bytes());
        let key_id = base64url(&signer.verifying_key().to_bytes());
        let mut signing_policy = policy.clone();
        put(&mut signing_policy, "owner_id", text(&actor)).unwrap();
        put(&mut signing_policy, "signing_key", text(&key_id)).unwrap();
        let mut signing_checkpoint = fixture.get("checkpoint").unwrap().clone();
        put(&mut signing_checkpoint, "owner_id", text(&actor)).unwrap();
        put(&mut signing_checkpoint, "owner_key", text(&key_id)).unwrap();
        let signed_begin = build_empty_direct_install_begin(
            &signing_checkpoint,
            &result.added,
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
        )
        .unwrap();
        let authored = sign_public_direct_install_begin(
            &signing_policy,
            &signing_checkpoint,
            &signed_begin,
            &"c".repeat(43),
            2,
            &signer,
        )
        .unwrap();
        let request = parse_wire_json_bounded(&authored.request_wire, 64, 220_000).unwrap();
        assert_eq!(
            sha256_hex(
                canonical_wire_value(request.get("commit").unwrap(), Path::SecureArtifact)
                    .unwrap()
                    .as_bytes()
            ),
            authored.commit_hash
        );
        assert_eq!(
            sha256_hex(
                canonical_wire_value(request.get("policy_update").unwrap(), Path::SecureArtifact)
                    .unwrap()
                    .as_bytes()
            ),
            authored.policy_hash
        );
        assert!(matches!(
            build_direct_install_objects(
                manifest_wire.as_bytes(),
                &"0".repeat(64),
                "w".repeat(43).as_str(),
                "z".repeat(43).as_str(),
                "proposalAdoption",
                2
            ),
            Err(DirectInstallError::Invalid)
        ));
    }

    #[test]
    fn signed_begin_requires_exact_prior_owner_policy_and_checkpoint() {
        let fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-direct-install-vectors.json"),
            64,
            500_000,
        )
        .unwrap();
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let actor = actor_id(&signer.verifying_key().to_bytes());
        let key_id = base64url(&signer.verifying_key().to_bytes());
        let mut payload = fixture
            .get("prior_policy")
            .unwrap()
            .get("payload")
            .unwrap()
            .clone();
        put(&mut payload, "owner_id", text(&actor)).unwrap();
        put(&mut payload, "signing_key", text(&key_id)).unwrap();
        let WireValue::Array(members) = required(&payload, "members").unwrap().clone() else {
            panic!("members")
        };
        let mut members = members;
        put(&mut members[0], "actor_id", text(&actor)).unwrap();
        put(&mut payload, "members", WireValue::Array(members)).unwrap();
        let old = sign_envelope(payload, "peerwork.secure.policy.v3", &signer).unwrap();
        let old_wire = canonical_wire_value(&old, Path::SecureArtifact).unwrap();
        let mut checkpoint = fixture.get("checkpoint").unwrap().clone();
        put(&mut checkpoint, "owner_id", text(&actor)).unwrap();
        put(&mut checkpoint, "owner_key", text(&key_id)).unwrap();
        put(
            &mut checkpoint,
            "policy_hash",
            text(&sha256_hex(old_wire.as_bytes())),
        )
        .unwrap();
        let checkpoint_wire = canonical_wire_value(&checkpoint, Path::SecureArtifact).unwrap();
        let WireValue::Array(prior_objects) = fixture.get("prior_objects").unwrap() else {
            panic!("prior objects")
        };
        let mut grants = fixture
            .get("options")
            .unwrap()
            .get("grants")
            .unwrap()
            .clone();
        let WireValue::Array(rows) = &mut grants else {
            panic!("grants")
        };
        put(&mut rows[0], "actor_id", text(&actor)).unwrap();
        let grants_wire = ordered_json_for_test(&grants);
        let manifest_wire =
            ordered_json_for_test(fixture.get("options").unwrap().get("manifest").unwrap());
        let args = || {
            prepare_public_direct_install_begin(
                manifest_wire.as_bytes(),
                &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
                old_wire.as_bytes(),
                checkpoint_wire.as_bytes(),
                prior_objects,
                grants_wire.as_bytes(),
                &fixture.get("instance_id").unwrap().as_string().unwrap(),
                &fixture.get("entrypoint").unwrap().as_string().unwrap(),
                &"c".repeat(43),
                2,
                &signer,
            )
        };
        let prepared = args().unwrap();
        let package_fixture = parse_wire_json_bounded(
            include_bytes!("../../../conformance/public-package-vectors.json"),
            64,
            2_000_000,
        )
        .unwrap();
        let closure_wire = canonical_wire_value(
            package_fixture.get("closure").unwrap(),
            Path::SecureArtifact,
        )
        .unwrap();
        let package_prepared = prepare_public_package_install_begin(
            closure_wire.as_bytes(),
            &fixture.get("package_digest").unwrap().as_string().unwrap(),
            &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
            old_wire.as_bytes(),
            checkpoint_wire.as_bytes(),
            prior_objects,
            grants_wire.as_bytes(),
            &fixture.get("instance_id").unwrap().as_string().unwrap(),
            &fixture.get("entrypoint").unwrap().as_string().unwrap(),
            &"c".repeat(43),
            2,
            &signer,
        )
        .unwrap();
        assert_eq!(
            package_prepared.package_digest(),
            fixture.get("package_digest").unwrap().as_string().unwrap()
        );
        assert_eq!(package_prepared.request_wire(), prepared.request_wire());
        assert_eq!(
            prepared.protocol_digest(),
            fixture.get("protocol_digest").unwrap().as_string().unwrap()
        );
        assert_eq!(
            prepared.instance_id(),
            fixture.get("instance_id").unwrap().as_string().unwrap()
        );
        let request = parse_wire_json_bounded(prepared.request_wire(), 64, 220_000).unwrap();
        assert!(request.get("policy_update").is_some());
        assert!(request.get("commit").is_some());
        let mut bad_checkpoint = checkpoint.clone();
        put(&mut bad_checkpoint, "policy_hash", text(&"0".repeat(64))).unwrap();
        let bad_wire = canonical_wire_value(&bad_checkpoint, Path::SecureArtifact).unwrap();
        assert!(matches!(
            prepare_public_direct_install_begin(
                manifest_wire.as_bytes(),
                &fixture.get("protocol_digest").unwrap().as_string().unwrap(),
                old_wire.as_bytes(),
                bad_wire.as_bytes(),
                prior_objects,
                grants_wire.as_bytes(),
                &fixture.get("instance_id").unwrap().as_string().unwrap(),
                &fixture.get("entrypoint").unwrap().as_string().unwrap(),
                &"c".repeat(43),
                2,
                &signer
            ),
            Err(DirectInstallError::Invalid)
        ));
    }
    fn ordered_json_for_test(value: &WireValue) -> String {
        let mut out = String::new();
        ordered_json(value, 0, &mut out).unwrap();
        out
    }
}
