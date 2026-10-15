//! Dedicated pinned coordination installation. Callers must supply an authenticated
//! exact source replay, persist packets before POST, and require signed ACTIVE END.
use crate::{
    canonical::{canonical, Path},
    crypto::{actor_id, base64url, sha256_hex, sign_canonical, verify_secure_signed},
    e2ee::{open_content_wire, SealedContent},
    genesis_structure_policy::derive_install_structure_policy_with_keep_encrypted,
    prepared_secure_author::sign_private_commit,
    prepared_secure_request::SecureCommitRequestPins,
    public_direct_install::{plan_public_install_snapshot, PublicInstallSnapshotPlan},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoordinationPrepareError {
    #[error("coordination input or authenticated source is invalid")]
    Invalid,
    #[error("coordination configuration or participants conflict")]
    Conflict,
    #[error("coordination participant is not a signed member")]
    ParticipantNotMember,
}
type Result<T> = std::result::Result<T, CoordinationPrepareError>;
fn bad() -> CoordinationPrepareError {
    CoordinationPrepareError::Invalid
}
pub fn token(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn wire(v: &Value) -> Result<WireValue> {
    parse_wire_json_bounded(
        &serde_json::to_vec(v).map_err(|_| bad())?,
        64,
        8 * 1024 * 1024,
    )
    .map_err(|_| bad())
}
pub fn value(v: &WireValue) -> Result<Value> {
    serde_json::from_str(&canonical_wire_value(v, Path::SecureArtifact).map_err(|_| bad())?)
        .map_err(|_| bad())
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(canonical(v, Path::SecureArtifact)
        .map_err(|_| bad())?
        .into_bytes())
}
fn hash(v: &Value) -> Result<String> {
    Ok(sha256_hex(&bytes(v)?))
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or_else(bad)
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(bad)
}
fn signed(payload: Value, domain: &str, signer: &SigningKey) -> Result<Value> {
    let signature = sign_canonical(
        &format!("{domain}.v{}", n(&payload, "v")?),
        &payload,
        signer,
    )
    .map_err(|_| bad())?;
    Ok(json!({"payload":payload,"signature":signature}))
}

pub fn preset(version: u8) -> Result<(Value, String)> {
    if !matches!(version, 1 | 2) {
        return Err(bad());
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../conformance/coordination-presets.json"
    ))
    .map_err(|_| bad())?;
    if fixture["source_sha256"]
        != "2e85ed64b4ff63737cfe5fc2fd47f270dc8bb488533a5a287a0270d5702223bd"
    {
        return Err(bad());
    }
    let entry = fixture["entries"]
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .find(|e| e["version"] == version)
        .ok_or_else(bad)?;
    let manifest = entry["manifest"].clone();
    let digest = sha256_hex(
        crate::full_manifest::validate_full_manifest(&wire(&manifest)?)
            .map_err(|_| bad())?
            .as_bytes(),
    );
    if entry["digest"] != digest {
        return Err(bad());
    }
    Ok((manifest, digest))
}

// Structure declarations bind the latest protocol/instance revisions; all data
// revisions remain in the independently projected snapshot.
fn adoption_objects(objects: &[WireValue]) -> Result<Vec<WireValue>> {
    let mut selected: Vec<WireValue> = vec![];
    for object in objects {
        if !matches!(
            object.get("kind").and_then(WireValue::as_string).as_deref(),
            Some("protocols" | "instances")
        ) {
            continue;
        }
        let id = object.get("id").ok_or_else(bad)?;
        let revision = object
            .get("revision")
            .and_then(WireValue::as_number)
            .ok_or_else(bad)?;
        if let Some(old) = selected
            .iter_mut()
            .find(|old| old.get("kind") == object.get("kind") && old.get("id") == Some(id))
        {
            if old
                .get("revision")
                .and_then(WireValue::as_number)
                .ok_or_else(bad)?
                < revision
            {
                *old = object.clone();
            }
        } else {
            selected.push(object.clone());
        }
    }
    Ok(selected)
}

pub struct CoordinationPlan {
    pub instance_id: String,
    pub protocol_digest: String,
    pub version: u8,
    pub already_enabled: bool,
    pub signed_policy: Value,
    pub operation: Value,
    pub snapshot: PublicInstallSnapshotPlan,
}

/// Participants None and Some([]) deliberately have different idempotence semantics.
#[allow(clippy::too_many_arguments)]
pub fn plan(
    signed_policy: &[u8],
    checkpoint: &[u8],
    objects: &[WireValue],
    version: u8,
    participants: Option<&[String]>,
    instance: &str,
    issued: u64,
    signer: &SigningKey,
) -> Result<CoordinationPlan> {
    let signed_old: Value = serde_json::from_slice(signed_policy).map_err(|_| bad())?;
    let old = &signed_old["payload"];
    let cp: Value = serde_json::from_slice(checkpoint).map_err(|_| bad())?;
    let actor = actor_id(&signer.verifying_key().to_bytes());
    let key = base64url(&signer.verifying_key().to_bytes());
    if !token(instance)
        || issued > 9_007_199_254_740_991
        || issued < n(old, "issued_at")?
        || !matches!(n(old, "v")?, 1 | 2 | 3)
        || !matches!(s(old, "visibility")?, "PUBLIC" | "PRIVATE")
        || old["owner_id"] != actor
        || old["signing_key"] != key
        || cp["owner_id"] != actor
        || cp["owner_key"] != key
        || old["workspace_id"] != cp["workspace_id"]
        || cp["policy_hash"] != hash(&signed_old)?
        || !verify_secure_signed(&signed_old, "peerwork.secure.policy.v1", &key)
            .map_err(|_| bad())?
    {
        return Err(bad());
    }
    let (manifest, digest) = preset(version)?;
    let requested = participants
        .map(|p| {
            let mut all = p.to_vec();
            if p.iter().any(|id| !token(id))
                || p.iter().collect::<std::collections::HashSet<_>>().len() != p.len()
            {
                return Err(bad());
            }
            all.push(actor.clone());
            all.sort();
            all.dedup();
            Ok(all)
        })
        .transpose()?;
    let members = old["members"].as_array().ok_or_else(bad)?;
    let previous = &old["structure"]["coordination"];
    if !previous.is_null() && previous["protocol_digest"] != digest {
        if version != 2 || previous["v"] != 1 || previous["protocol_digest"] != preset(1)?.1 {
            return Err(CoordinationPrepareError::Conflict);
        }
    }
    let already = previous["protocol_digest"] == digest;
    let selected = if already {
        s(previous, "instance_id")?.to_owned()
    } else {
        instance.to_owned()
    };
    let actions: Vec<Value> = manifest["actions"]
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|a| a["id"].clone())
        .collect();
    if already {
        if let Some(requested) = &requested {
            for id in requested {
                let valid = members
                    .iter()
                    .find(|m| m["actor_id"] == *id)
                    .and_then(|m| m["scopes"].as_array())
                    .is_some_and(|scopes| {
                        scopes.iter().any(|scope| {
                            scope["instance_id"] == selected
                                && actions.iter().all(|a| {
                                    scope["actions"]
                                        .as_array()
                                        .is_some_and(|items| items.contains(a))
                                })
                                && scope["protocol_roles"]
                                    .as_array()
                                    .is_some_and(|r| r.contains(&json!("COLLABORATOR")))
                                && scope["capabilities"]
                                    .as_array()
                                    .is_some_and(|r| r.contains(&json!("COORDINATE")))
                        })
                    });
                if !valid {
                    return Err(CoordinationPrepareError::Conflict);
                }
            }
        }
    }
    let mut next = old.clone();
    let mut added = vec![];
    if !already {
        let requested = requested.unwrap_or_else(|| vec![actor.clone()]);
        if requested
            .iter()
            .any(|id| !members.iter().any(|m| m["actor_id"] == *id))
        {
            return Err(CoordinationPrepareError::ParticipantNotMember);
        }
        if objects
            .iter()
            .any(|o| o.get("id").and_then(WireValue::as_string).as_deref() == Some(instance))
        {
            return Err(bad());
        }
        if !objects.iter().any(|o| {
            o.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
                && o.get("id").and_then(WireValue::as_string).as_deref() == Some(&digest)
        }) {
            added.push(json!({"kind":"protocols","id":digest,"revision":1,"provenance":"AUTHOR_SIGNED","value":{"workspace_id":cp["workspace_id"],"digest":digest,"manifest":manifest,"resolved_manifest":manifest}}));
        }
        added.push(json!({"kind":"instances","id":instance,"revision":1,"provenance":"AUTHOR_SIGNED","value":{"id":instance,"workspace_id":cp["workspace_id"],"protocol_digest":digest,"origin_entrypoint":"coordination","semantics":"peerwork.kernel.v1","state":manifest["initial_state"],"revision":0,"event_revision":0,"created":issued}}));
        let old_objects = WireValue::Array(adoption_objects(objects)?);
        let old_wire =
            canonical_wire_value(&old_objects, Path::SecureArtifact).map_err(|_| bad())?;
        let before = if old["structure"].is_object() {
            old["structure"].clone()
        } else {
            serde_json::from_str(
                &derive_install_structure_policy_with_keep_encrypted(old_wire.as_bytes(), b"[]")
                    .map_err(|_| bad())?,
            )
            .map_err(|_| bad())?
        };
        let undisclosed = old["v"] == 1
            || (old["v"] == 3 && old["structure_mode"] == "NONE" && old["visibility"] == "PRIVATE");
        let mut keep = vec![];
        for p in before["protocols"].as_array().ok_or_else(bad)? {
            for (schema, def) in p["schemas"].as_object().ok_or_else(bad)? {
                let fields: Vec<_> = def["fields"]
                    .as_object()
                    .ok_or_else(bad)?
                    .iter()
                    .filter(|(_, f)| undisclosed || f["protection"] == "e2ee")
                    .map(|(name, _)| name.clone())
                    .collect();
                if !fields.is_empty() {
                    keep.push(json!({"protocol_digest":p["protocol_digest"],"schema":schema,"fields":fields}));
                }
            }
        }
        let mut all = adoption_objects(objects)?;
        for o in &added {
            all.push(wire(o)?);
        }
        let mut structure: Value = serde_json::from_str(
            &derive_install_structure_policy_with_keep_encrypted(
                canonical_wire_value(&WireValue::Array(all), Path::SecureArtifact)
                    .map_err(|_| bad())?
                    .as_bytes(),
                &bytes(&json!(keep))?,
            )
            .map_err(|_| bad())?,
        )
        .map_err(|_| bad())?;
        let mut config = if previous.is_object() {
            previous.clone()
        } else {
            json!({"v":version,"instance_id":instance,"protocol_digest":digest,"coordinator":actor,"initial_delay_ms":60000,"max_delay_ms":3600000,"escalate_after":5,"window_ms":60000,"workspace_limit":60,"sender_limit":10,"recipient_limit":10})
        };
        config["v"] = json!(version);
        config["instance_id"] = json!(instance);
        config["protocol_digest"] = json!(digest);
        structure["coordination"] = config;
        let mut next_members = members.clone();
        for member in &mut next_members {
            if requested.iter().any(|id| member["actor_id"] == *id) {
                member["scopes"].as_array_mut().ok_or_else(bad)?.push(json!({"instance_id":instance,"actions":actions,"protocol_roles":["COLLABORATOR"],"capabilities":["COORDINATE"]}));
            }
        }
        next["v"] = json!(if old["v"] == 3 { 3 } else { 2 });
        if old["v"] == 3 {
            next["structure_mode"] = json!("STRUCTURED");
        }
        next["structure"] = structure;
        next["members"] = json!(next_members);
        next["version"] = json!(n(old, "version")?.checked_add(1).ok_or_else(bad)?);
        next["previous_policy"] = json!(hash(&signed_old)?);
        next["effective_sequence"] = json!(n(&cp, "sequence")?.checked_add(1).ok_or_else(bad)?);
        next["issued_at"] = json!(issued);
    }
    let snapshot = plan_public_install_snapshot(objects, &wire(&next["structure"])?, &wire(&cp)?)
        .map_err(|_| bad())?;
    let signed_policy = if already {
        signed_old
    } else {
        signed(next, "peerwork.secure.policy", signer)?
    };
    Ok(CoordinationPlan {
        instance_id: selected,
        protocol_digest: digest,
        version,
        already_enabled: already,
        signed_policy,
        operation: json!({"v":1,"kind":"ADMIN","input":{"install":{"instance_id":instance,"protocol_digest":preset(version)?.1,"entrypoint":"coordination"}},"objects":added}),
        snapshot,
    })
}

pub struct CoordinationPacket {
    pub request: Vec<u8>,
    pub commit_hash: String,
    pub policy_hash: String,
    pub action_id: String,
}
#[allow(clippy::too_many_arguments)]
pub fn packet(
    plan: &CoordinationPlan,
    checkpoint: &[u8],
    snapshot: Option<&WireValue>,
    command: &str,
    issued: u64,
    signer: &SigningKey,
    epoch_key: Option<&[u8; 32]>,
    saved: Option<&[u8]>,
) -> Result<CoordinationPacket> {
    let cp: Value = serde_json::from_slice(checkpoint).map_err(|_| bad())?;
    let policy = &plan.signed_policy["payload"];
    let policy_hash = hash(&plan.signed_policy)?;
    let actor = actor_id(&signer.verifying_key().to_bytes());
    let key = base64url(&signer.verifying_key().to_bytes());
    let begin = snapshot.is_none();
    if plan.already_enabled
        || !token(command)
        || issued > 9_007_199_254_740_991
        || issued < n(policy, "issued_at")?
        || cp["workspace_id"] != policy["workspace_id"]
        || cp["owner_id"] != actor
        || cp["owner_key"] != key
    {
        return Err(bad());
    }
    if !begin && cp["policy_hash"] != policy_hash {
        return Err(bad());
    }
    let (action, structure, operation) = if let Some(snapshot) = snapshot {
        for f in ["source", "root", "records", "heads"] {
            if snapshot.get(f) != plan.snapshot.snapshot().get(f) {
                return Err(bad());
            }
        }
        let snap = value(snapshot)?;
        let offset = usize::try_from(n(&snap, "offset")?).map_err(|_| bad())?;
        let records = plan.snapshot.records();
        let heads = plan.snapshot.heads();
        let total = records.len() + heads.len();
        if offset > total {
            return Err(bad());
        }
        let (action, mode, rs, hs) = if offset == total {
            ("secure.structure.end", "SNAPSHOT_END", vec![], vec![])
        } else if offset < records.len() {
            (
                "secure.structure.page",
                "SNAPSHOT_PAGE",
                records[offset..(offset + 50).min(records.len())].to_vec(),
                vec![],
            )
        } else {
            let start = offset - records.len();
            (
                "secure.structure.page",
                "SNAPSHOT_PAGE",
                vec![],
                heads[start..(start + 50).min(heads.len())].to_vec(),
            )
        };
        (
            action,
            json!({"v":1,"mode":mode,"snapshot":snap,"records":value(&WireValue::Array(rs))?,"heads":value(&WireValue::Array(hs))?}),
            json!({"v":1,"kind":"ADMIN","input":{},"objects":[]}),
        )
    } else {
        (
            "secure.structure.begin",
            json!({"v":1,"mode":"SNAPSHOT_BEGIN","snapshot":value(plan.snapshot.snapshot())?,"records":[],"heads":[]}),
            plan.operation.clone(),
        )
    };
    let mut context = json!({"v":policy["v"],"workspace_id":policy["workspace_id"],"sequence":n(&cp,"sequence")?.checked_add(1).ok_or_else(bad)?,"previous":cp["head"],"policy_hash":policy_hash,"epoch":policy["epoch"],"actor_id":actor,"signing_key":key,"command_id":command,"action_id":action,"instance_id":null,"issued_at":issued,"delegation":null,"structure":structure});
    if policy["v"] == 3 {
        context["protocol_format_ceiling"] = policy["protocol_format_ceiling"].clone();
    }
    let commit = if let Some(saved) = saved {
        let request: Value = serde_json::from_slice(saved).map_err(|_| bad())?;
        if bytes(&request)? != saved
            || request.as_object().ok_or_else(bad)?.len() != if begin { 2 } else { 1 }
            || (begin && request["policy_update"] != plan.signed_policy)
        {
            return Err(bad());
        }
        let commit = request["commit"].clone();
        if !verify_secure_signed(&commit, "peerwork.secure.commit.v1", &key).map_err(|_| bad())? {
            return Err(bad());
        }
        let mut actual = commit["payload"].clone();
        let mode = actual
            .as_object_mut()
            .ok_or_else(bad)?
            .remove("mode")
            .ok_or_else(bad)?;
        let body = actual
            .as_object_mut()
            .ok_or_else(bad)?
            .remove("body")
            .ok_or_else(bad)?;
        if actual != context || mode != policy["visibility"] {
            return Err(bad());
        }
        let plain = if mode == "PRIVATE" {
            let sealed: SealedContent = serde_json::from_value(body).map_err(|_| bad())?;
            let opened = open_content_wire(epoch_key.ok_or_else(bad)?, &sealed, &bytes(&context)?)
                .map_err(|_| bad())?;
            opened.to_vec()
        } else {
            bytes(&body)?
        };
        if plain != bytes(&operation)? {
            return Err(bad());
        }
        commit
    } else if policy["visibility"] == "PRIVATE" {
        let pins = SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &key,
            workspace_id: s(policy, "workspace_id")?,
            policy_hash: &policy_hash,
            sequence: n(&context, "sequence")?,
            previous: cp["head"].as_str(),
            epoch: n(policy, "epoch")?,
            mode: "PRIVATE",
            version: n(policy, "v")?,
            protocol_format_ceiling: if policy["v"] == 3 {
                Some(n(policy, "protocol_format_ceiling")?)
            } else {
                None
            },
        };
        let commit = sign_private_commit(
            &wire(&context)?,
            &bytes(&operation)?,
            epoch_key.ok_or_else(bad)?,
            signer,
            &pins,
        )
        .map_err(|_| bad())?;
        serde_json::from_str(&commit).map_err(|_| bad())?
    } else {
        context["mode"] = json!("PUBLIC");
        context["body"] = operation;
        signed(context, "peerwork.secure.commit", signer)?
    };
    let commit_hash = hash(&commit)?;
    let mut request = json!({"commit":commit});
    if begin {
        request["policy_update"] = plan.signed_policy.clone();
    }
    let request = bytes(&request)?;
    if request.len() > 220_000 {
        return Err(bad());
    }
    Ok(CoordinationPacket {
        request,
        commit_hash,
        policy_hash,
        action_id: action.into(),
    })
}
