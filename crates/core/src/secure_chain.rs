//! Internal signed-link scanner. Its facts carry no read/action authority:
//! member certificates, scope, format shapes, recovery, and operation replay
//! are checked by later layers before any verified journal can be returned.

use crate::{
    canonical::Path,
    crypto::{
        actor_id, base64url, decode_base64url, sha256, sha256_hex, verify_secure_signed_wire,
    },
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use hpke::{kem::DhP256HkdfSha256, Deserializable, Kem};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const POLICY_MAX: usize = 1024;
pub(crate) const DEFAULT_MAX_COMMITS: usize = 102_400;
const COMMIT_BYTES: usize = 196_608;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ChainError {
    #[error("signed history has invalid shape, signature, or link")]
    Invalid,
    #[error("signed history rolls back or forks from the pinned checkpoint")]
    Rollback,
}

#[derive(Debug, Clone)]
pub(crate) struct OwnerPin<'a> {
    pub actor_id: &'a str,
    pub signing_key: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckpointPin<'a> {
    pub sequence: u64,
    pub head: Option<&'a str>,
    pub policy_hash: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct HeaderChainFacts {
    pub workspace_id: String,
    pub owner_id: String,
    pub owner_key: String,
    pub sequence: u64,
    pub head: Option<String>,
    pub policy_hash: String,
    pub policy_hashes: Vec<String>,
    pub policy_effective_sequences: Vec<u64>,
    pub commit_hashes: Vec<String>,
}

struct PolicyHeader {
    hash: String,
    wire_version: u64,
    version: u64,
    effective_sequence: u64,
    epoch: u64,
    issued_at: u64,
    visibility: String,
    owner_id: String,
    owner_key: String,
    members: HashMap<String, MemberHeader>,
    structured: bool,
    format_ceiling: Option<u64>,
    format_raise_guard: Option<String>,
}

struct MemberHeader {
    signing_key: String,
    encryption_key: String,
    role: String,
    scopes: Vec<ScopeHeader>,
}

struct ScopeHeader {
    instance_id: Option<String>,
    actions: Vec<Vec<u16>>,
    expires_at: Option<u64>,
}

struct CertificateHeader {
    actor_id: String,
    signing_key: String,
    encryption_key: String,
}

pub(crate) fn scan_signed_chain_headers(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    checkpoint_wire: &[u8],
    workspace_id: &str,
    trusted_owner: Option<&OwnerPin<'_>>,
    pinned: Option<&CheckpointPin<'_>>,
) -> Result<HeaderChainFacts, ChainError> {
    scan_signed_chain_headers_with_limit(policy_wires, commit_wires, checkpoint_wire, workspace_id, trusted_owner, pinned, DEFAULT_MAX_COMMITS)
}

pub(crate) fn scan_signed_chain_headers_with_limit(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    checkpoint_wire: &[u8],
    workspace_id: &str,
    trusted_owner: Option<&OwnerPin<'_>>,
    pinned: Option<&CheckpointPin<'_>>,
    max_commits: usize,
) -> Result<HeaderChainFacts, ChainError> {
    if !token(workspace_id)
        || policy_wires.is_empty()
        || policy_wires.len() > POLICY_MAX
        || max_commits == 0
        || commit_wires.len() > max_commits
    {
        return Err(ChainError::Invalid);
    }
    let mut policies = Vec::with_capacity(policy_wires.len());
    let mut hashes = HashSet::new();
    for wire in policy_wires {
        let artifact = parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024)
            .map_err(|_| ChainError::Invalid)?;
        let payload = envelope_payload(&artifact)?;
        let wire_version = version(payload)?;
        let owner_key = field(payload, "signing_key")?;
        let owner_id = field(payload, "owner_id")?;
        let key_bytes: [u8; 32] = decode_base64url(&owner_key)
            .map_err(|_| ChainError::Invalid)?
            .try_into()
            .map_err(|_| ChainError::Invalid)?;
        if !token(&owner_key)
            || !token(&owner_id)
            || owner_id != actor_id(&key_bytes)
            || field(payload, "workspace_id")? != workspace_id
            || !verify_secure_signed_wire(wire, "peerwork.secure.policy.v1", &owner_key)
                .map_err(|_| ChainError::Invalid)?
        {
            return Err(ChainError::Invalid);
        }
        let previous = policies.last();
        let prior_hash = previous.map(|p: &PolicyHeader| p.hash.as_str());
        let version = unsigned(payload, "version")?;
        let effective_sequence = unsigned(payload, "effective_sequence")?;
        let epoch = unsigned(payload, "epoch")?;
        let issued_at = unsigned(payload, "issued_at")?;
        let visibility = field(payload, "visibility")?;
        let (structured, format_ceiling) = validate_policy_shape(payload, wire_version)?;
        let format_raise_guard = if wire_version == 3 {
            Some(format_raise_guard(payload)?)
        } else {
            None
        };
        let members = validate_members(payload, issued_at, &owner_id, &owner_key, wire_version)?;
        if version != previous.map_or(1, |p: &PolicyHeader| p.version + 1)
            || effective_sequence == 0
            || nullable_field(payload, "previous_policy")?.as_deref() != prior_hash
            || !matches!(visibility.as_str(), "PUBLIC" | "PRIVATE")
            || (visibility == "PRIVATE" && epoch == 0)
            || (visibility == "PUBLIC" && epoch != 0)
        {
            return Err(ChainError::Invalid);
        }
        if let Some(prior) = previous {
            if prior.owner_id != owner_id
                || prior.owner_key != owner_key
                || effective_sequence <= prior.effective_sequence
                || issued_at < prior.issued_at
                || epoch < prior.epoch
                || (prior.visibility == "PRIVATE" && visibility == "PUBLIC")
                || (prior.wire_version == 3 && wire_version != 3)
                || (prior.structured && !structured)
            {
                return Err(ChainError::Invalid);
            }
            if wire_version == 3
                && (prior.wire_version != 3 && format_ceiling != Some(1)
                    || prior.wire_version == 3
                        && format_ceiling != prior.format_ceiling
                        && !(prior.format_ceiling == Some(1)
                            && format_ceiling == Some(2)
                            && prior.visibility == "PRIVATE"
                            && visibility == "PRIVATE"
                            && prior.format_raise_guard == format_raise_guard))
            {
                return Err(ChainError::Invalid);
            }
            let removed_or_rotated = prior.members.iter().any(|(actor, old)| {
                members
                    .get(actor)
                    .is_none_or(|new| new.encryption_key != old.encryption_key)
            });
            if visibility == "PRIVATE"
                && (removed_or_rotated || prior.visibility == "PUBLIC")
                && epoch <= prior.epoch
            {
                return Err(ChainError::Invalid);
            }
        } else if effective_sequence != 1 {
            return Err(ChainError::Invalid);
        } else if wire_version == 3 && format_ceiling != Some(1) {
            return Err(ChainError::Invalid);
        }
        let hash = secure_hash(&artifact)?;
        if !hashes.insert(hash.clone()) {
            return Err(ChainError::Invalid);
        }
        policies.push(PolicyHeader {
            hash,
            wire_version,
            version,
            effective_sequence,
            epoch,
            issued_at,
            visibility,
            owner_id,
            owner_key,
            members,
            structured,
            format_ceiling,
            format_raise_guard,
        });
    }
    let genesis = &policies[0];
    if trusted_owner
        .is_some_and(|pin| pin.actor_id != genesis.owner_id || pin.signing_key != genesis.owner_key)
    {
        return Err(ChainError::Rollback);
    }
    let by_hash: HashMap<&str, &PolicyHeader> =
        policies.iter().map(|p| (p.hash.as_str(), p)).collect();
    let mut head: Option<String> = None;
    let mut commit_hashes = Vec::with_capacity(commit_wires.len());
    let mut command_ids = HashSet::new();
    for (index, wire) in commit_wires.iter().enumerate() {
        let artifact =
            parse_wire_json_js_bounded(wire, 64, COMMIT_BYTES).map_err(|_| ChainError::Invalid)?;
        let canonical = canonical_wire_value(&artifact, Path::SecureArtifact)
            .map_err(|_| ChainError::Invalid)?;
        if canonical.len() > COMMIT_BYTES {
            return Err(ChainError::Invalid);
        }
        let payload = envelope_payload(&artifact)?;
        let sequence = (index as u64) + 1;
        let policy_hash = field(payload, "policy_hash")?;
        let policy = by_hash
            .get(policy_hash.as_str())
            .ok_or(ChainError::Invalid)?;
        let active = policies
            .iter()
            .rev()
            .find(|p| p.effective_sequence <= sequence)
            .ok_or(ChainError::Invalid)?;
        let signing_key = field(payload, "signing_key")?;
        let actor = field(payload, "actor_id")?;
        let command_id = field(payload, "command_id")?;
        let action_id = payload
            .get("action_id")
            .and_then(WireValue::as_utf16)
            .ok_or(ChainError::Invalid)?;
        let issued_at = unsigned(payload, "issued_at")?;
        let instance_id = nullable_field(payload, "instance_id")?;
        let authorized = resolve_author(
            policy,
            payload,
            workspace_id,
            &actor,
            &signing_key,
            issued_at,
            instance_id.as_deref(),
            action_id,
        )?;
        validate_commit_shape(payload, policy)?;
        if field(payload, "workspace_id")? != workspace_id
            || unsigned(payload, "sequence")? != sequence
            || nullable_field(payload, "previous")?.as_deref() != head.as_deref()
            || !authorized
            || !token(&actor)
            || !token(&signing_key)
            || !token(&command_id)
            || action_id.is_empty()
            || action_id.len() > 120
            || !nullable_token(payload, "instance_id")?
            || !command_ids.insert(command_id.clone())
            || policy.hash != active.hash
            || unsigned(payload, "epoch")? != policy.epoch
            || version(payload)? != policy.wire_version
            || field(payload, "mode")? != policy.visibility
            || !verify_secure_signed_wire(wire, "peerwork.secure.commit.v1", &signing_key)
                .map_err(|_| ChainError::Invalid)?
        {
            return Err(ChainError::Invalid);
        }
        head = Some(sha256_hex(canonical.as_bytes()));
        commit_hashes.push(head.clone().unwrap());
    }
    let latest = policies.last().ok_or(ChainError::Invalid)?;
    if latest.effective_sequence > commit_hashes.len().max(1) as u64 {
        return Err(ChainError::Invalid);
    }
    let checkpoint =
        parse_wire_json_js_bounded(checkpoint_wire, 8, 8192).map_err(|_| ChainError::Invalid)?;
    if checkpoint.object_len() != Some(7)
        || unsigned(&checkpoint, "v")? != 1
        || field(&checkpoint, "workspace_id")? != workspace_id
        || field(&checkpoint, "owner_id")? != genesis.owner_id
        || field(&checkpoint, "owner_key")? != genesis.owner_key
        || unsigned(&checkpoint, "sequence")? != commit_hashes.len() as u64
        || nullable_field(&checkpoint, "head")?.as_deref() != head.as_deref()
        || field(&checkpoint, "policy_hash")? != latest.hash
    {
        return Err(ChainError::Invalid);
    }
    if let Some(pin) = pinned {
        let at = pin.sequence.max(1);
        let policy = policies
            .iter()
            .rev()
            .find(|p| p.effective_sequence <= at)
            .ok_or(ChainError::Rollback)?;
        if pin.sequence > commit_hashes.len() as u64
            || (pin.sequence == 0 && pin.head.is_some())
            || (pin.sequence > 0
                && commit_hashes[(pin.sequence - 1) as usize].as_str() != pin.head.unwrap_or(""))
            || pin.policy_hash != policy.hash
        {
            return Err(ChainError::Rollback);
        }
    }
    Ok(HeaderChainFacts {
        workspace_id: workspace_id.into(),
        owner_id: genesis.owner_id.clone(),
        owner_key: genesis.owner_key.clone(),
        sequence: commit_hashes.len() as u64,
        head,
        policy_hash: latest.hash.clone(),
        policy_effective_sequences: policies.iter().map(|p| p.effective_sequence).collect(),
        policy_hashes: policies.into_iter().map(|p| p.hash).collect(),
        commit_hashes,
    })
}

fn envelope_payload(value: &WireValue) -> Result<&WireValue, ChainError> {
    if value.object_len() != Some(2)
        || value
            .get("signature")
            .and_then(WireValue::as_string)
            .is_none()
    {
        return Err(ChainError::Invalid);
    }
    value.get("payload").ok_or(ChainError::Invalid)
}

fn validate_certificate(certificate: &WireValue, at: u64) -> Result<CertificateHeader, ChainError> {
    let cert = envelope_payload(certificate)?;
    let signing_key = field(cert, "signing_key")?;
    let actor = field(cert, "actor_id")?;
    let key_bytes: [u8; 32] = decode_base64url(&signing_key)
        .map_err(|_| ChainError::Invalid)?
        .try_into()
        .map_err(|_| ChainError::Invalid)?;
    let issued = unsigned(cert, "issued_at")?;
    let expires = unsigned(cert, "expires_at")?;
    if unsigned(cert, "v")? != 1
        || !token(&signing_key)
        || !token(&actor)
        || actor_id(&key_bytes) != actor
        || expires <= issued
        || expires - issued > 366 * 86_400_000
        || at < issued
        || at >= expires
    {
        return Err(ChainError::Invalid);
    }
    let cert_wire =
        canonical_wire_value(certificate, Path::SecureArtifact).map_err(|_| ChainError::Invalid)?;
    if !verify_secure_signed_wire(
        cert_wire.as_bytes(),
        "peerwork.secure.key-certificate.v1",
        &signing_key,
    )
    .map_err(|_| ChainError::Invalid)?
    {
        return Err(ChainError::Invalid);
    }
    let encryption = cert.get("encryption_key").ok_or(ChainError::Invalid)?;
    if encryption.object_len() != Some(4)
        || field(encryption, "kty")? != "EC"
        || field(encryption, "crv")? != "P-256"
    {
        return Err(ChainError::Invalid);
    }
    let x = field(encryption, "x")?;
    let y = field(encryption, "y")?;
    if !token(&x) || !token(&y) {
        return Err(ChainError::Invalid);
    }
    let x: [u8; 32] = decode_base64url(&x)
        .map_err(|_| ChainError::Invalid)?
        .try_into()
        .map_err(|_| ChainError::Invalid)?;
    let y: [u8; 32] = decode_base64url(&y)
        .map_err(|_| ChainError::Invalid)?
        .try_into()
        .map_err(|_| ChainError::Invalid)?;
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..65].copy_from_slice(&y);
    <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(&point).map_err(|_| ChainError::Invalid)?;
    let encryption_key =
        canonical_wire_value(encryption, Path::SecureArtifact).map_err(|_| ChainError::Invalid)?;
    if field(cert, "encryption_key_id")? != base64url(&sha256(encryption_key.as_bytes())) {
        return Err(ChainError::Invalid);
    }
    Ok(CertificateHeader {
        actor_id: actor,
        signing_key,
        encryption_key,
    })
}

fn exact_keys(value: &WireValue, required: &[&str], optional: &[&str]) -> Result<(), ChainError> {
    let WireValue::Object(fields) = value else {
        return Err(ChainError::Invalid);
    };
    if required.iter().any(|key| value.get(key).is_none())
        || fields.iter().any(|(name, _)| {
            !required
                .iter()
                .chain(optional)
                .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
        })
    {
        return Err(ChainError::Invalid);
    }
    Ok(())
}

fn validate_policy_shape(
    payload: &WireValue,
    version: u64,
) -> Result<(bool, Option<u64>), ChainError> {
    let base = [
        "v",
        "workspace_id",
        "owner_id",
        "signing_key",
        "version",
        "previous_policy",
        "effective_sequence",
        "visibility",
        "epoch",
        "members",
        "issued_at",
    ];
    match version {
        1 => {
            if !matches!(payload.get("structure"), None | Some(WireValue::Null)) {
                return Err(ChainError::Invalid);
            }
            Ok((false, None))
        }
        2 => {
            let mut required = base.to_vec();
            required.push("structure");
            exact_keys(payload, &required, &[])?;
            if matches!(payload.get("structure"), None | Some(WireValue::Null)) {
                return Err(ChainError::Invalid);
            }
            Ok((true, None))
        }
        3 => {
            let mut required = base.to_vec();
            required.extend(["protocol_format_ceiling", "structure_mode"]);
            let mode = field(payload, "structure_mode")?;
            let structured = match mode.as_str() {
                "STRUCTURED" => true,
                "NONE" => false,
                _ => return Err(ChainError::Invalid),
            };
            exact_keys(
                payload,
                &required,
                if structured { &["structure"] } else { &[] },
            )?;
            if structured != payload.get("structure").is_some() {
                return Err(ChainError::Invalid);
            }
            let ceiling = unsigned(payload, "protocol_format_ceiling")?;
            if ceiling != 1 && !(ceiling == 2 && field(payload, "visibility")? == "PRIVATE") {
                return Err(ChainError::Invalid);
            }
            Ok((structured, Some(ceiling)))
        }
        _ => Err(ChainError::Invalid),
    }
}

fn format_raise_guard(payload: &WireValue) -> Result<String, ChainError> {
    let WireValue::Object(fields) = payload else {
        return Err(ChainError::Invalid);
    };
    let unchanged = WireValue::Object(
        fields
            .iter()
            .filter(|(name, _)| {
                ![
                    "protocol_format_ceiling",
                    "version",
                    "previous_policy",
                    "effective_sequence",
                    "issued_at",
                ]
                .iter()
                .any(|mutable| name.iter().copied().eq(mutable.encode_utf16()))
            })
            .cloned()
            .collect(),
    );
    Ok(sha256_hex(
        canonical_wire_value(&unchanged, Path::SecureArtifact)
            .map_err(|_| ChainError::Invalid)?
            .as_bytes(),
    ))
}

fn validate_commit_shape(payload: &WireValue, policy: &PolicyHeader) -> Result<(), ChainError> {
    if policy.wire_version == 1 {
        return Ok(());
    }
    let mut required = vec![
        "v",
        "workspace_id",
        "sequence",
        "previous",
        "policy_hash",
        "epoch",
        "actor_id",
        "signing_key",
        "command_id",
        "action_id",
        "instance_id",
        "issued_at",
        "delegation",
        "mode",
        "body",
    ];
    if policy.wire_version == 2 || policy.structured {
        required.push("structure");
    }
    if policy.wire_version == 3 {
        required.push("protocol_format_ceiling");
        if unsigned(payload, "protocol_format_ceiling")? != policy.format_ceiling.unwrap_or(0) {
            return Err(ChainError::Invalid);
        }
    }
    exact_keys(
        payload,
        &required,
        &["migration", "conversion_excluded_members", "recovery"],
    )?;
    if policy.wire_version == 3 && !policy.structured && payload.get("structure").is_some() {
        return Err(ChainError::Invalid);
    }
    if policy.visibility == "PRIVATE" {
        exact_keys(
            payload.get("body").ok_or(ChainError::Invalid)?,
            &["v", "alg", "nonce", "chunks"],
            &[],
        )?;
    }
    Ok(())
}

fn validate_members(
    policy: &WireValue,
    issued_at: u64,
    owner_id: &str,
    owner_key: &str,
    wire_version: u64,
) -> Result<HashMap<String, MemberHeader>, ChainError> {
    let WireValue::Array(members) = policy.get("members").ok_or(ChainError::Invalid)? else {
        return Err(ChainError::Invalid);
    };
    if members.is_empty() || members.len() > 128 {
        return Err(ChainError::Invalid);
    }
    let mut result = HashMap::new();
    let mut owners = 0;
    for member in members {
        if wire_version >= 2 {
            exact_keys(member, &["actor_id", "certificate", "role", "scopes"], &[])?;
            let certificate = member.get("certificate").ok_or(ChainError::Invalid)?;
            exact_keys(certificate, &["payload", "signature"], &[])?;
            let cert = envelope_payload(certificate)?;
            exact_keys(
                cert,
                &[
                    "v",
                    "actor_id",
                    "signing_key",
                    "encryption_key",
                    "encryption_key_id",
                    "issued_at",
                    "expires_at",
                ],
                &[],
            )?;
        }
        let actor = field(member, "actor_id")?;
        let role = field(member, "role")?;
        if !token(&actor) || !matches!(role.as_str(), "OWNER" | "MEMBER") {
            return Err(ChainError::Invalid);
        }
        if role == "OWNER" {
            owners += 1;
        }
        let certificate = member.get("certificate").ok_or(ChainError::Invalid)?;
        let certificate = validate_certificate(certificate, issued_at)?;
        if certificate.actor_id != actor {
            return Err(ChainError::Invalid);
        }
        let scope_headers = validate_scopes(member.get("scopes").ok_or(ChainError::Invalid)?)?;
        if result
            .insert(
                actor,
                MemberHeader {
                    signing_key: certificate.signing_key,
                    encryption_key: certificate.encryption_key,
                    role,
                    scopes: scope_headers,
                },
            )
            .is_some()
        {
            return Err(ChainError::Invalid);
        }
    }
    if owners != 1
        || result
            .get(owner_id)
            .is_none_or(|owner| owner.role != "OWNER" || owner.signing_key != owner_key)
    {
        return Err(ChainError::Invalid);
    }
    Ok(result)
}

fn validate_scopes(value: &WireValue) -> Result<Vec<ScopeHeader>, ChainError> {
    let WireValue::Array(scopes) = value else {
        return Err(ChainError::Invalid);
    };
    if scopes.len() > 128 {
        return Err(ChainError::Invalid);
    }
    let mut result = Vec::with_capacity(scopes.len());
    for scope in scopes {
        let WireValue::Object(fields) = scope else {
            return Err(ChainError::Invalid);
        };
        if fields.iter().any(|(name, _)| {
            ![
                "instance_id",
                "actions",
                "protocol_roles",
                "capabilities",
                "expires_at",
            ]
            .iter()
            .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
        }) {
            return Err(ChainError::Invalid);
        }
        let instance_id = nullable_field(scope, "instance_id")?;
        if instance_id.as_ref().is_some_and(|id| !token(id)) {
            return Err(ChainError::Invalid);
        }
        let actions = scope_strings(scope, "actions")?;
        scope_strings(scope, "protocol_roles")?;
        scope_strings(scope, "capabilities")?;
        let expires_at = match scope.get("expires_at") {
            None | Some(WireValue::Null) => None,
            Some(_) => {
                let expiry = unsigned(scope, "expires_at")?;
                if expiry == 0 {
                    return Err(ChainError::Invalid);
                }
                Some(expiry)
            }
        };
        result.push(ScopeHeader {
            instance_id,
            actions,
            expires_at,
        });
    }
    Ok(result)
}

fn permits(
    scopes: &[ScopeHeader],
    action_id: &[u16],
    instance_id: Option<&str>,
    issued_at: u64,
) -> bool {
    scopes.iter().any(|scope| {
        (scope.instance_id.is_none() || scope.instance_id.as_deref() == instance_id)
            && scope.expires_at.is_none_or(|expiry| expiry > issued_at)
            && scope
                .actions
                .iter()
                .any(|action| action.as_slice() == action_id)
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_author(
    policy: &PolicyHeader,
    payload: &WireValue,
    workspace_id: &str,
    actor: &str,
    signing_key: &str,
    issued_at: u64,
    instance_id: Option<&str>,
    action_id: &[u16],
) -> Result<bool, ChainError> {
    let key_bytes: [u8; 32] = decode_base64url(signing_key)
        .map_err(|_| ChainError::Invalid)?
        .try_into()
        .map_err(|_| ChainError::Invalid)?;
    if actor_id(&key_bytes) != actor {
        return Ok(false);
    }
    match payload.get("delegation").ok_or(ChainError::Invalid)? {
        WireValue::Null => Ok(policy.members.get(actor).is_some_and(|member| {
            member.signing_key == signing_key
                && ((member.role == "OWNER" && instance_id.is_none())
                    || permits(&member.scopes, action_id, instance_id, issued_at))
        })),
        delegation => {
            let grant = envelope_payload(delegation)?;
            let grant_issued = unsigned(grant, "issued_at")?;
            let grant_expires = unsigned(grant, "expires_at")?;
            if unsigned(grant, "v")? != 1
                || field(grant, "workspace_id")? != workspace_id
                || grant_expires == 0
                || issued_at < grant_issued
                || issued_at >= grant_expires
            {
                return Ok(false);
            }
            let device =
                validate_certificate(grant.get("device").ok_or(ChainError::Invalid)?, issued_at)?;
            if device.actor_id != actor || device.signing_key != signing_key {
                return Ok(false);
            }
            let principal_id = field(grant, "actor_id")?;
            let principal_key = field(grant, "signing_key")?;
            let Some(principal) = policy.members.get(&principal_id) else {
                return Ok(false);
            };
            if principal.signing_key != principal_key {
                return Ok(false);
            }
            let grant_wire = canonical_wire_value(delegation, Path::SecureArtifact)
                .map_err(|_| ChainError::Invalid)?;
            if !verify_secure_signed_wire(
                grant_wire.as_bytes(),
                "peerwork.secure.device-delegation.v1",
                &principal_key,
            )
            .map_err(|_| ChainError::Invalid)?
            {
                return Ok(false);
            }
            let scopes = validate_scopes(grant.get("scope").ok_or(ChainError::Invalid)?)?;
            Ok(permits(&scopes, action_id, instance_id, issued_at)
                && permits(&principal.scopes, action_id, instance_id, issued_at))
        }
    }
}

fn scope_strings(scope: &WireValue, name: &str) -> Result<Vec<Vec<u16>>, ChainError> {
    let WireValue::Array(values) = scope.get(name).ok_or(ChainError::Invalid)? else {
        return Err(ChainError::Invalid);
    };
    if values.len() > 64 {
        return Err(ChainError::Invalid);
    }
    let mut unique = HashSet::new();
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let units = value.as_utf16().ok_or(ChainError::Invalid)?;
        if units.is_empty() || units.len() > 120 || !unique.insert(units.to_vec()) {
            return Err(ChainError::Invalid);
        }
        result.push(units.to_vec());
    }
    Ok(result)
}
fn field(value: &WireValue, name: &str) -> Result<String, ChainError> {
    let WireValue::String(units) = value.get(name).ok_or(ChainError::Invalid)? else {
        return Err(ChainError::Invalid);
    };
    // Header identity and hash fields are ASCII; other SecureJson remains UTF-16 lossless.
    if units.iter().any(|unit| *unit > 0x7f) {
        return Err(ChainError::Invalid);
    }
    let bytes: Vec<u8> = units.iter().map(|unit| *unit as u8).collect();
    String::from_utf8(bytes).map_err(|_| ChainError::Invalid)
}

fn unsigned(value: &WireValue, name: &str) -> Result<u64, ChainError> {
    let number = value
        .get(name)
        .and_then(WireValue::as_number)
        .ok_or(ChainError::Invalid)?;
    if number.is_finite() && number >= 0.0 && number.fract() == 0.0 && number <= MAX_SAFE {
        Ok(number as u64)
    } else {
        Err(ChainError::Invalid)
    }
}
fn version(value: &WireValue) -> Result<u64, ChainError> {
    let version = unsigned(value, "v")?;
    if (1..=3).contains(&version) {
        Ok(version)
    } else {
        Err(ChainError::Invalid)
    }
}
fn nullable_field(value: &WireValue, name: &str) -> Result<Option<String>, ChainError> {
    match value.get(name).ok_or(ChainError::Invalid)? {
        WireValue::Null => Ok(None),
        _ => field(value, name).map(Some),
    }
}
fn nullable_token(value: &WireValue, name: &str) -> Result<bool, ChainError> {
    match nullable_field(value, name)? {
        None => Ok(true),
        Some(value) => Ok(token(&value)),
    }
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn secure_hash(value: &WireValue) -> Result<String, ChainError> {
    let canonical =
        canonical_wire_value(value, Path::SecureArtifact).map_err(|_| ChainError::Invalid)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{base64url, key_id, sign_canonical};
    use ed25519_dalek::SigningKey;
    use hpke::Serializable;
    use serde_json::{json, Value};

    fn signed(payload: Value, domain: &str, key: &SigningKey) -> Vec<u8> {
        let signature = sign_canonical(domain, &payload, key).unwrap();
        serde_json::to_vec(&json!({"payload":payload,"signature":signature})).unwrap()
    }
    fn hash(wire: &[u8]) -> String {
        secure_hash(&parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024).unwrap()).unwrap()
    }
    #[test]
    fn signed_policy_commit_links_and_checkpoint_pin_scan_all_wire_versions() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let owner_key = key_id(&key.verifying_key().to_bytes());
        let owner = actor_id(&key.verifying_key().to_bytes());
        let workspace = base64url(&[43; 32]);
        let (_, encryption_public) = DhP256HkdfSha256::gen_keypair();
        let point = encryption_public.to_bytes();
        let encryption_key = json!({"kty":"EC","crv":"P-256","x":base64url(&point[1..33]),"y":base64url(&point[33..65])});
        let encryption_key_id = base64url(&sha256(
            crate::canonical::canonical(&encryption_key, Path::SecureArtifact)
                .unwrap()
                .as_bytes(),
        ));
        let certificate: Value = serde_json::from_slice(&signed(
            json!({"v":1,"actor_id":owner,"signing_key":owner_key,"encryption_key":encryption_key,"encryption_key_id":encryption_key_id,"issued_at":0,"expires_at":1000}),
            "peerwork.secure.key-certificate.v1",
            &key,
        ))
        .unwrap();
        let delegated_instance = base64url(&[77; 32]);
        let member_scope = json!({"instance_id":delegated_instance,"actions":["test.action"],"protocol_roles":[],"capabilities":[]});
        let members = json!([{"actor_id":owner,"certificate":certificate,"role":"OWNER","scopes":[member_scope]}]);
        let mut policies = Vec::new();
        let mut commits = Vec::new();
        let mut prior_policy: Option<String> = None;
        let mut prior_commit: Option<String> = None;
        for version in 1..=3 {
            let mut policy_payload = json!({
                "v":version,"workspace_id":workspace,"owner_id":owner,"signing_key":owner_key,
                "version":version,"previous_policy":prior_policy,"effective_sequence":version,
                "visibility":"PUBLIC","epoch":0,"members":members,"issued_at":version
            });
            if version >= 2 {
                policy_payload["structure"] =
                    json!({"v":1,"protocols":[],"disclosure":[],"instances":[]});
            }
            if version == 3 {
                policy_payload["protocol_format_ceiling"] = json!(1);
                policy_payload["structure_mode"] = json!("STRUCTURED");
            }
            let policy = signed(
                policy_payload,
                &format!("peerwork.secure.policy.v{version}"),
                &key,
            );
            let policy_hash = hash(&policy);
            policies.push(policy);
            let mut commit_payload = json!({
                "v":version,"workspace_id":workspace,"sequence":version,"previous":prior_commit,
                "policy_hash":policy_hash,"epoch":0,"actor_id":owner,"signing_key":owner_key,
                "command_id":base64url(&[version as u8;32]),"action_id":"test.action",
                "instance_id":null,"issued_at":version,"delegation":null,"mode":"PUBLIC",
                "body":{"v":1,"kind":"ADMIN","input":{},"objects":[]}
            });
            if version >= 2 {
                commit_payload["structure"] = json!({"v":1,"mode":"DELTA","records":[],"heads":[]});
            }
            if version == 3 {
                commit_payload["protocol_format_ceiling"] = json!(1);
            }
            let commit = signed(
                commit_payload,
                &format!("peerwork.secure.commit.v{version}"),
                &key,
            );
            prior_commit = Some(hash(&commit));
            commits.push(commit);
            prior_policy = Some(policy_hash);
        }
        let checkpoint = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":3,"head":prior_commit,"policy_hash":prior_policy
        }))
        .unwrap();
        let policy_refs: Vec<_> = policies.iter().map(Vec::as_slice).collect();
        let commit_refs: Vec<_> = commits.iter().map(Vec::as_slice).collect();
        let owner_pin = OwnerPin {
            actor_id: &owner,
            signing_key: &owner_key,
        };
        let pin = CheckpointPin {
            sequence: 2,
            head: Some(&hash(&commits[1])),
            policy_hash: &hash(&policies[1]),
        };
        let facts = scan_signed_chain_headers(
            &policy_refs,
            &commit_refs,
            &checkpoint,
            &workspace,
            Some(&owner_pin),
            Some(&pin),
        )
        .unwrap();
        assert_eq!(facts.sequence, 3);
        assert_eq!(facts.head.as_deref(), prior_commit.as_deref());
        assert_eq!(facts.policy_hashes.len(), 3);
        assert_eq!(facts.commit_hashes.len(), 3);

        let device_key = SigningKey::from_bytes(&[88; 32]);
        let device_signing_key = key_id(&device_key.verifying_key().to_bytes());
        let device_actor = actor_id(&device_key.verifying_key().to_bytes());
        let device_certificate: Value = serde_json::from_slice(&signed(
            json!({"v":1,"actor_id":device_actor,"signing_key":device_signing_key,"encryption_key":encryption_key,"encryption_key_id":encryption_key_id,"issued_at":0,"expires_at":1000}),
            "peerwork.secure.key-certificate.v1",
            &device_key,
        ))
        .unwrap();
        let delegation: Value = serde_json::from_slice(&signed(
            json!({"v":1,"workspace_id":workspace,"actor_id":owner,"signing_key":owner_key,"device":device_certificate,"request_id":base64url(&[66; 32]),"scope":[member_scope],"read":false,"origin":"https://example.test","audience":"example","issued_at":0,"expires_at":1000}),
            "peerwork.secure.device-delegation.v1",
            &key,
        ))
        .unwrap();
        let mut delegated_payload: Value = serde_json::from_slice(&commits[0]).unwrap();
        delegated_payload["payload"]["actor_id"] = json!(device_actor);
        delegated_payload["payload"]["signing_key"] = json!(device_signing_key);
        delegated_payload["payload"]["instance_id"] = json!(delegated_instance);
        delegated_payload["payload"]["delegation"] = delegation.clone();
        let delegated = signed(
            delegated_payload["payload"].clone(),
            "peerwork.secure.commit.v1",
            &device_key,
        );
        let delegated_checkpoint = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&delegated),"policy_hash":hash(&policies[0])
        }))
        .unwrap();
        assert_eq!(
            scan_signed_chain_headers(
                &[policies[0].as_slice()],
                &[delegated.as_slice()],
                &delegated_checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap()
            .sequence,
            1
        );
        // The old synthetic test signed and verified this same wrong domain.
        // Re-sign the whole commit so its only defect is the delegation domain.
        let wrong_domain_delegation: Value = serde_json::from_slice(&signed(
            delegation["payload"].clone(),
            "peerwork.secure.delegation.v1",
            &key,
        ))
        .unwrap();
        delegated_payload["payload"]["delegation"] = wrong_domain_delegation;
        let wrong_domain_commit = signed(
            delegated_payload["payload"].clone(),
            "peerwork.secure.commit.v1",
            &device_key,
        );
        let wrong_domain_checkpoint = serde_json::to_vec(&json!({
            "v":1,"workspace_id":workspace,"owner_id":owner,"owner_key":owner_key,
            "sequence":1,"head":hash(&wrong_domain_commit),"policy_hash":hash(&policies[0])
        }))
        .unwrap();
        assert_eq!(
            scan_signed_chain_headers(
                &[policies[0].as_slice()],
                &[wrong_domain_commit.as_slice()],
                &wrong_domain_checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );
        delegated_payload["payload"]["delegation"] = delegation.clone();
        delegated_payload["payload"]["delegation"]["payload"]["workspace_id"] =
            json!(base64url(&[11; 32]));
        let invalid_delegation = signed(
            delegated_payload["payload"].clone(),
            "peerwork.secure.commit.v1",
            &device_key,
        );
        assert_eq!(
            scan_signed_chain_headers(
                &[policies[0].as_slice()],
                &[invalid_delegation.as_slice()],
                &delegated_checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );
        let forked = CheckpointPin {
            sequence: 2,
            head: Some("0"),
            policy_hash: pin.policy_hash,
        };
        assert_eq!(
            scan_signed_chain_headers(
                &policy_refs,
                &commit_refs,
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                Some(&forked)
            )
            .unwrap_err(),
            ChainError::Rollback
        );
        let wrong_owner = OwnerPin {
            actor_id: &workspace,
            signing_key: &owner_key,
        };
        assert_eq!(
            scan_signed_chain_headers(
                &policy_refs,
                &commit_refs,
                &checkpoint,
                &workspace,
                Some(&wrong_owner),
                None
            )
            .unwrap_err(),
            ChainError::Rollback
        );
        let mut tampered: Value = serde_json::from_slice(&commits[1]).unwrap();
        tampered["payload"]["previous"] = json!("wrong");
        let bad = serde_json::to_vec(&tampered).unwrap();
        let bad_refs = [commits[0].as_slice(), bad.as_slice(), commits[2].as_slice()];
        assert_eq!(
            scan_signed_chain_headers(
                &policy_refs,
                &bad_refs,
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );

        let mut unauthorized: Value = serde_json::from_slice(&commits[0]).unwrap();
        unauthorized["payload"]["instance_id"] = json!(base64url(&[55; 32]));
        let unauthorized = signed(
            unauthorized["payload"].clone(),
            "peerwork.secure.commit.v1",
            &key,
        );
        let unauthorized_refs = [
            unauthorized.as_slice(),
            commits[1].as_slice(),
            commits[2].as_slice(),
        ];
        assert_eq!(
            scan_signed_chain_headers(
                &policy_refs,
                &unauthorized_refs,
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );

        let mut invalid_certificate: Value = serde_json::from_slice(&policies[0]).unwrap();
        invalid_certificate["payload"]["members"][0]["certificate"]["payload"]
            ["encryption_key_id"] = json!(base64url(&[99; 32]));
        let invalid_certificate = signed(
            invalid_certificate["payload"].clone(),
            "peerwork.secure.policy.v1",
            &key,
        );
        let invalid_policy_refs = [
            invalid_certificate.as_slice(),
            policies[1].as_slice(),
            policies[2].as_slice(),
        ];
        assert_eq!(
            scan_signed_chain_headers(
                &invalid_policy_refs,
                &commit_refs,
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );

        let mut invalid_v3_policy: Value = serde_json::from_slice(&policies[2]).unwrap();
        invalid_v3_policy["payload"]["surplus"] = json!(true);
        let invalid_v3_policy = signed(
            invalid_v3_policy["payload"].clone(),
            "peerwork.secure.policy.v3",
            &key,
        );
        assert_eq!(
            scan_signed_chain_headers(
                &[
                    policies[0].as_slice(),
                    policies[1].as_slice(),
                    invalid_v3_policy.as_slice()
                ],
                &commit_refs,
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );
        let mut invalid_v3_commit: Value = serde_json::from_slice(&commits[2]).unwrap();
        invalid_v3_commit["payload"]
            .as_object_mut()
            .unwrap()
            .remove("protocol_format_ceiling");
        let invalid_v3_commit = signed(
            invalid_v3_commit["payload"].clone(),
            "peerwork.secure.commit.v3",
            &key,
        );
        assert_eq!(
            scan_signed_chain_headers(
                &policy_refs,
                &[
                    commits[0].as_slice(),
                    commits[1].as_slice(),
                    invalid_v3_commit.as_slice()
                ],
                &checkpoint,
                &workspace,
                Some(&owner_pin),
                None
            )
            .unwrap_err(),
            ChainError::Invalid
        );
    }
}
