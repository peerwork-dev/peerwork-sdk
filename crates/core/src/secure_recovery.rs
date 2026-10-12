//! Signed recovery marker preflight over an already authenticated header chain.
//! These facts cannot authorize a skip until replay reproduces the first
//! excluded content failure and validates the marker operation.

use crate::{
    canonical::Path,
    crypto::sha256_hex,
    secure_chain::HeaderChainFacts,
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoverySegment {
    pub base: u64,
    pub through: u64,
    pub marker: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidRecovery;
type Result<T> = std::result::Result<T, InvalidRecovery>;

fn field<'a>(value: &'a WireValue, key: &str) -> Result<&'a WireValue> {
    value.get(key).ok_or(InvalidRecovery)
}
fn text(value: &WireValue, key: &str) -> Result<String> {
    field(value, key)?.as_string().ok_or(InvalidRecovery)
}
fn number(value: &WireValue, key: &str) -> Result<u64> {
    let n = field(value, key)?.as_number().ok_or(InvalidRecovery)?;
    if !n.is_finite() || n < 0.0 || n > 9_007_199_254_740_991.0 || n.fract() != 0.0 {
        return Err(InvalidRecovery);
    }
    Ok(n as u64)
}
fn exact(value: &WireValue, keys: &[&str]) -> Result<()> {
    if value.object_len() != Some(keys.len()) || keys.iter().any(|key| value.get(key).is_none()) {
        return Err(InvalidRecovery);
    }
    Ok(())
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn checkpoint(value: &WireValue) -> Result<u64> {
    exact(
        value,
        &[
            "v",
            "workspace_id",
            "owner_id",
            "owner_key",
            "sequence",
            "head",
            "policy_hash",
        ],
    )?;
    let sequence = number(value, "sequence")?;
    if number(value, "v")? != 1
        || sequence == 0
        || !token(&text(value, "workspace_id")?)
        || !token(&text(value, "owner_id")?)
        || !token(&text(value, "owner_key")?)
        || !digest(&text(value, "head")?)
        || !digest(&text(value, "policy_hash")?)
    {
        return Err(InvalidRecovery);
    }
    Ok(sequence)
}

pub(crate) fn preflight_recovery(
    policy_wires: &[&[u8]],
    commit_wires: &[&[u8]],
    chain: &HeaderChainFacts,
) -> Result<Vec<RecoverySegment>> {
    let mut policies = HashMap::new();
    for (hash, wire) in chain.policy_hashes.iter().zip(policy_wires) {
        let artifact =
            parse_wire_json_js_bounded(wire, 64, 32 * 1024 * 1024).map_err(|_| InvalidRecovery)?;
        policies.insert(hash.as_str(), artifact);
    }
    let mut commits = Vec::with_capacity(commit_wires.len());
    for wire in commit_wires {
        let artifact =
            parse_wire_json_js_bounded(wire, 64, 196_608).map_err(|_| InvalidRecovery)?;
        commits.push(field(&artifact, "payload")?.clone());
    }
    if commits.len() != chain.commit_hashes.len() {
        return Err(InvalidRecovery);
    }
    let mut selected = Vec::<usize>::new();
    for index in (0..commits.len()).rev() {
        let p = &commits[index];
        let n = number(p, "sequence")?;
        if selected.iter().any(|later| {
            let r = commits[*later].get("recovery").unwrap();
            field(r, "base")
                .and_then(checkpoint)
                .is_ok_and(|base| n > base)
                && field(r, "through")
                    .and_then(checkpoint)
                    .is_ok_and(|through| n <= through)
        }) {
            continue;
        }
        if p.get("recovery").is_some() {
            selected.push(index);
        }
    }
    selected.reverse();
    let mut segments = Vec::with_capacity(selected.len());
    for index in selected {
        let p = &commits[index];
        let marker = number(p, "sequence")?;
        let r = field(p, "recovery")?;
        exact(r, &["v", "reason", "base", "through", "excluded_root"])?;
        let base_cp = field(r, "base")?;
        let through_cp = field(r, "through")?;
        let base = checkpoint(base_cp)?;
        let through = checkpoint(through_cp)?;
        let policy_hash = text(p, "policy_hash")?;
        let policy = policies.get(policy_hash.as_str()).ok_or(InvalidRecovery)?;
        let policy = field(policy, "payload")?;
        if number(r, "v")? != 1
            || text(r, "reason")? != "INVALID_ENCRYPTED_OPERATION"
            || !digest(&text(r, "excluded_root")?)
            || base >= through
            || through.checked_add(1) != Some(marker)
            || field(through_cp, "head")? != field(p, "previous")?
            || text(p, "action_id")? != "secure.recover"
            || text(p, "mode")? != "PRIVATE"
            || text(policy, "visibility")? != "PRIVATE"
            || field(p, "instance_id")? != &WireValue::Null
            || field(p, "delegation")? != &WireValue::Null
            || text(p, "actor_id")? != text(policy, "owner_id")?
            || text(p, "signing_key")? != text(policy, "signing_key")?
            || p.get("migration").is_some()
            || p.get("conversion_excluded_members").is_some()
            || text(base_cp, "workspace_id")? != chain.workspace_id
            || text(through_cp, "workspace_id")? != chain.workspace_id
            || text(base_cp, "owner_id")? != chain.owner_id
            || text(through_cp, "owner_id")? != chain.owner_id
            || text(base_cp, "owner_key")? != chain.owner_key
            || text(through_cp, "owner_key")? != chain.owner_key
        {
            return Err(InvalidRecovery);
        }
        let base_index = usize::try_from(base - 1).map_err(|_| InvalidRecovery)?;
        let through_index = usize::try_from(through - 1).map_err(|_| InvalidRecovery)?;
        if base_index >= commits.len()
            || through_index >= commits.len()
            || text(base_cp, "head")? != chain.commit_hashes[base_index]
            || text(through_cp, "head")? != chain.commit_hashes[through_index]
            || text(base_cp, "policy_hash")? != text(&commits[base_index], "policy_hash")?
            || text(through_cp, "policy_hash")? != text(&commits[through_index], "policy_hash")?
        {
            return Err(InvalidRecovery);
        }
        let mut excluded = Vec::new();
        for n in (base + 1)..=through {
            let i = usize::try_from(n - 1).map_err(|_| InvalidRecovery)?;
            let commit = commits.get(i).ok_or(InvalidRecovery)?;
            if number(commit, "sequence")? != n || text(commit, "mode")? != "PRIVATE" {
                return Err(InvalidRecovery);
            }
            excluded.push(WireValue::Object(vec![
                (
                    "sequence".encode_utf16().collect(),
                    WireValue::Number(n as f64),
                ),
                (
                    "hash".encode_utf16().collect(),
                    WireValue::String(chain.commit_hashes[i].encode_utf16().collect()),
                ),
            ]));
        }
        let root = sha256_hex(
            canonical_wire_value(&WireValue::Array(excluded), Path::SecureArtifact)
                .map_err(|_| InvalidRecovery)?
                .as_bytes(),
        );
        if root != text(r, "excluded_root")? {
            return Err(InvalidRecovery);
        }
        // V3 has stricter origin/range and operation exclusions. Its complete
        // source-equivalent gate must run before this segment is usable.
        if number(p, "v")? == 3 {
            return Err(InvalidRecovery);
        }
        segments.push(RecoverySegment {
            base,
            through,
            marker,
        });
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_chain::{scan_signed_chain_headers, OwnerPin};

    #[test]
    fn signed_typescript_recovery_range_is_authenticated() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/signed-recovery-vectors.json"
        ))
        .unwrap();
        for case in oracle["cases"].as_array().unwrap() {
            let policies = vec![serde_json::to_vec(&case["policy"]).unwrap()];
            let commits = case["commits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|commit| serde_json::to_vec(commit).unwrap())
                .collect::<Vec<_>>();
            let policy_refs = policies.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let commit_refs = commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let checkpoint = serde_json::to_vec(&case["checkpoint"]).unwrap();
            let chain = scan_signed_chain_headers(
                &policy_refs,
                &commit_refs,
                &checkpoint,
                case["workspace_id"].as_str().unwrap(),
                Some(&OwnerPin {
                    actor_id: case["owner"]["actor_id"].as_str().unwrap(),
                    signing_key: case["owner"]["key"].as_str().unwrap(),
                }),
                None,
            )
            .unwrap();
            let preflight = preflight_recovery(&policy_refs, &commit_refs, &chain);
            if case["name"] == "signed_wrong_excluded_root" {
                assert!(preflight.is_err());
            } else if case["name"] == "recovered_invalid_encrypted_commit"
                || case["name"] == "invented_failure_over_valid_content"
            {
                assert_eq!(
                    preflight.unwrap(),
                    vec![RecoverySegment {
                        base: 1,
                        through: 2,
                        marker: 3
                    }]
                );
            } else {
                assert!(preflight.unwrap().is_empty());
            }
        }
    }
}
