//! Bounded generic discovery from authenticated full replay. Metadata never
//! executes protocol content or claims that dynamic action predicates passed.
use crate::{
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_verified_read::TransportReplayedJournal,
};
use peerwork_core::{
    canonical::Path,
    crypto::sha256_hex,
    replayed_secure_journal::ReplayedSecureJournal,
    wire_json::{
        canonical_wire_value, parse_js_json_string_bounded, parse_wire_json_bounded, WireValue,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("verified source read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("discovery selector is invalid")]
    Invalid,
    #[error("exact verified source or reference was not found")]
    NotFound,
    #[error("verified source cannot be represented by this discovery schema")]
    Source,
    #[error("discovery result exceeds its bounded output; select a narrower source")]
    Limit,
}
impl DiscoveryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(e) => e.code(),
            Self::Invalid => "DISCOVERY_QUERY_INVALID",
            Self::NotFound => "DISCOVERY_NOT_FOUND",
            Self::Source => "DISCOVERY_SOURCE",
            Self::Limit => "DISCOVERY_LIMIT",
        }
    }
}
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryQuery {
    pub instance_id: Option<String>,
    pub action_id: Option<String>,
    pub record_id: Option<String>,
    pub revision: Option<u64>,
    pub object_ref: Option<ObjectRef>,
    pub after: Option<String>,
    pub limit: Option<usize>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub kind: String,
    pub id: String,
    pub revision: u64,
}
fn validate_query(q: &DiscoveryQuery, describe: bool) -> Result<(), DiscoveryError> {
    let valid = |s: &str| !s.is_empty() && s.len() <= 4096 && !s.contains('\0');
    for s in [&q.instance_id, &q.action_id, &q.record_id, &q.after]
        .into_iter()
        .flatten()
    {
        if !valid(s) {
            return Err(DiscoveryError::Invalid);
        }
    }
    if q.revision.is_some_and(|r| r > 9_007_199_254_740_991) {
        return Err(DiscoveryError::Invalid);
    }
    if let Some(r) = &q.object_ref {
        if !valid(&r.kind) || !valid(&r.id) || r.revision > 9_007_199_254_740_991 {
            return Err(DiscoveryError::Invalid);
        }
    }
    let good = if describe {
        q.after.is_none()
            && q.limit.is_none()
            && match (&q.instance_id, &q.record_id, &q.object_ref) {
                (Some(_), None, None) => q.revision.is_none(),
                (None, Some(_), None) => q.revision.is_some() && q.action_id.is_none(),
                (None, None, Some(_)) => q.revision.is_none() && q.action_id.is_none(),
                _ => false,
            }
    } else {
        q.instance_id.is_none()
            && q.action_id.is_none()
            && q.record_id.is_none()
            && q.revision.is_none()
            && q.object_ref.is_none()
            && (1..=128).contains(&q.limit.unwrap_or(64))
    };
    if good {
        Ok(())
    } else {
        Err(DiscoveryError::Invalid)
    }
}
fn string(v: &WireValue, k: &str) -> Result<String, DiscoveryError> {
    v.get(k)
        .and_then(WireValue::as_string)
        .ok_or(DiscoveryError::Source)
}
fn number(v: &WireValue, k: &str) -> Result<u64, DiscoveryError> {
    v.get(k)
        .and_then(WireValue::as_number)
        .filter(|n| n.is_finite() && *n >= 0.0 && *n <= 9_007_199_254_740_991.0 && n.fract() == 0.0)
        .map(|n| n as u64)
        .ok_or(DiscoveryError::Source)
}
fn value(v: &WireValue) -> Result<Value, DiscoveryError> {
    let canonical =
        canonical_wire_value(v, Path::SecureArtifact).map_err(|_| DiscoveryError::Source)?;
    serde_json::from_str(&canonical).map_err(|_| DiscoveryError::Source)
}
fn decoded(v: &WireValue) -> Result<WireValue, DiscoveryError> {
    match v {
        WireValue::String(units) => parse_js_json_string_bounded(units, 2048, 16 * 1024 * 1024)
            .map_err(|_| DiscoveryError::Source),
        _ => Ok(v.clone()),
    }
}
fn latest<'a>(
    objects: &'a [WireValue],
    kind: &str,
) -> Result<BTreeMap<String, &'a WireValue>, DiscoveryError> {
    let mut rows: BTreeMap<String, &'a WireValue> = BTreeMap::new();
    for object in objects {
        if object.get("kind").and_then(WireValue::as_string).as_deref() != Some(kind) {
            continue;
        }
        let id = string(object, "id")?;
        let revision = number(object, "revision")?;
        if rows
            .get(&id)
            .map(|prior| number(prior, "revision").unwrap_or(0) < revision)
            .unwrap_or(true)
        {
            rows.insert(id, object);
        }
    }
    Ok(rows)
}
fn joined<'a>(
    replay: &'a ReplayedSecureJournal,
    instance: &'a WireValue,
) -> Result<(&'a WireValue, WireValue), DiscoveryError> {
    let iv = instance.get("value").ok_or(DiscoveryError::Source)?;
    let digest = string(iv, "protocol_digest")?;
    if string(iv, "workspace_id")? != replay.workspace_id() {
        return Err(DiscoveryError::Source);
    }
    let protocol = replay
        .objects()
        .iter()
        .filter(|o| {
            o.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocols")
                && o.get("value")
                    .and_then(|v| v.get("digest"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(&digest)
        })
        .max_by_key(|o| number(o, "revision").unwrap_or(0))
        .ok_or(DiscoveryError::NotFound)?;
    let pv = protocol.get("value").ok_or(DiscoveryError::Source)?;
    if string(pv, "workspace_id")? != replay.workspace_id() {
        return Err(DiscoveryError::Source);
    }
    let manifest = decoded(
        pv.get("resolved_manifest")
            .or_else(|| pv.get("manifest"))
            .ok_or(DiscoveryError::Source)?,
    )?;
    Ok((protocol, manifest))
}
fn status(replay: &ReplayedSecureJournal, digest: &str) -> Result<Value, DiscoveryError> {
    let row = replay
        .objects()
        .iter()
        .filter(|o| {
            o.get("kind").and_then(WireValue::as_string).as_deref() == Some("protocol_status")
                && o.get("value")
                    .and_then(|v| v.get("digest"))
                    .and_then(WireValue::as_string)
                    .as_deref()
                    == Some(digest)
        })
        .max_by_key(|o| number(o, "revision").unwrap_or(0));
    match row {
        Some(r) => Ok(
            json!({"state":string(r.get("value").ok_or(DiscoveryError::Source)?,"state")?,"ref":object_ref(replay,r)?}),
        ),
        None => Ok(json!({"state":"ACTIVE","basis":"no_suspension_record"})),
    }
}
fn authority(
    policy: &Value,
    actor: &str,
    key: &str,
    instance: &str,
    action: Option<&str>,
    at: u64,
) -> Value {
    let member = policy["payload"]["members"].as_array().and_then(|rows| {
        rows.iter()
            .find(|m| m["actor_id"] == actor && m["certificate"]["payload"]["signing_key"] == key)
    });
    let certificate_current = member.is_some_and(|m| {
        m["certificate"]["payload"]["issued_at"]
            .as_u64()
            .is_some_and(|t| t <= at)
            && m["certificate"]["payload"]["expires_at"]
                .as_u64()
                .is_some_and(|t| t > at)
    });
    let scopes: Vec<Value> = member
        .and_then(|m| m["scopes"].as_array())
        .into_iter()
        .flatten()
        .filter(|g| {
            (g["instance_id"].is_null() || g["instance_id"] == instance)
                && (g["expires_at"].is_null() || g["expires_at"].as_u64().is_some_and(|t| t > at))
        })
        .cloned()
        .collect();
    let permitted = action.map(|a| {
        certificate_current
            && scopes.iter().any(|s| {
                s["actions"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().any(|v| v == a))
            })
    });
    json!({"member":member.is_some(),"certificate_current":certificate_current,"observed_at_ms":at,"scope_permitted":permitted,"applicable_scopes":scopes,"execution":"not_evaluated","dynamic_guards":"not_evaluated"})
}
fn object_ref(replay: &ReplayedSecureJournal, object: &WireValue) -> Result<Value, DiscoveryError> {
    let wire =
        canonical_wire_value(object, Path::SecureArtifact).map_err(|_| DiscoveryError::Source)?;
    Ok(
        json!({"workspace_id":replay.workspace_id(),"kind":string(object,"kind")?,"id":string(object,"id")?,"revision":number(object,"revision")?,"object_sha256":sha256_hex(wire.as_bytes())}),
    )
}
fn project(
    replay: &ReplayedSecureJournal,
    policy: &Value,
    actor: &str,
    key: &str,
    at: u64,
    describe: bool,
    q: &DiscoveryQuery,
) -> Result<Value, DiscoveryError> {
    validate_query(q, describe)?;
    let mut out = json!({"schema":"peerwork.agent-discovery.v1","actor_id":actor,"checkpoint":{"sequence":replay.sequence(),"head":replay.head(),"policy_hash":replay.policy_hash()},"verification":"verified","execution":"not_evaluated"});
    if describe && (q.record_id.is_some() || q.object_ref.is_some()) {
        if q.instance_id.is_some()
            || q.action_id.is_some()
            || q.after.is_some()
            || q.limit.is_some()
            || q.record_id.is_some() == q.object_ref.is_some()
        {
            return Err(DiscoveryError::Invalid);
        }
        let object = if let Some(id) = &q.record_id {
            let revision = q.revision.ok_or(DiscoveryError::Invalid)?;
            replay.objects().iter().find(|o| {
                o.get("kind").and_then(WireValue::as_string).as_deref() == Some("records")
                    && o.get("id").and_then(WireValue::as_string).as_deref() == Some(id)
                    && o.get("value").and_then(|v| number(v, "revision").ok()) == Some(revision)
            })
        } else {
            if q.revision.is_some() {
                return Err(DiscoveryError::Invalid);
            }
            let r = q.object_ref.as_ref().unwrap();
            replay.objects().iter().find(|o| {
                o.get("kind").and_then(WireValue::as_string).as_deref() == Some(&r.kind)
                    && o.get("id").and_then(WireValue::as_string).as_deref() == Some(&r.id)
                    && number(o, "revision").ok() == Some(r.revision)
            })
        }
        .ok_or(DiscoveryError::NotFound)?;
        out["object"] = value(object)?;
        out["refs"] = object_ref(replay, object)?;
        if let Some(id) = &q.record_id {
            out["refs"]["record_id"] = json!(id);
            out["refs"]["record_revision"] = json!(q.revision);
        }
        return Ok(out);
    }
    let instances = latest(replay.objects(), "instances")?;
    if describe {
        if q.record_id.is_some()
            || q.revision.is_some()
            || q.object_ref.is_some()
            || q.after.is_some()
            || q.limit.is_some()
        {
            return Err(DiscoveryError::Invalid);
        }
        let id = q
            .instance_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or(DiscoveryError::Invalid)?;
        let instance = *instances.get(id).ok_or(DiscoveryError::NotFound)?;
        let (protocol, manifest) = joined(replay, instance)?;
        let iv = instance.get("value").ok_or(DiscoveryError::Source)?;
        let pv = protocol.get("value").ok_or(DiscoveryError::Source)?;
        let digest = string(iv, "protocol_digest")?;
        let manifest_json = value(&manifest)?;
        let action = match q.action_id.as_deref() {
            Some(id) => manifest_json["actions"]
                .as_array()
                .and_then(|a| a.iter().find(|a| a["id"] == id))
                .cloned()
                .ok_or(DiscoveryError::NotFound)?,
            None => Value::Null,
        };
        out["instance"] = value(instance)?;
        out["protocol"] = json!({"ref":object_ref(replay,protocol)?,"manifest":value(&decoded(pv.get("manifest").ok_or(DiscoveryError::Source)?)?)?,"resolved_manifest":manifest_json,"composition":pv.get("composition").map(value).transpose()?,"package_source":pv.get("package_source").map(value).transpose()?,"status":status(replay,&digest)?});
        out["action"] = action;
        out["schemas"] = out["protocol"]["resolved_manifest"]["record_schemas"].clone();
        out["authority"] = authority(policy, actor, key, id, q.action_id.as_deref(), at);
        out["refs"] = json!({"workspace_id":replay.workspace_id(),"instance_id":id,"instance_revision":number(iv,"revision")?,"instance_object":object_ref(replay,instance)?,"protocol_digest":digest,"protocol_object":object_ref(replay,protocol)?});
        return Ok(out);
    }
    if q.instance_id.is_some()
        || q.action_id.is_some()
        || q.record_id.is_some()
        || q.revision.is_some()
        || q.object_ref.is_some()
    {
        return Err(DiscoveryError::Invalid);
    }
    let limit = q.limit.unwrap_or(64);
    if !(1..=128).contains(&limit) {
        return Err(DiscoveryError::Invalid);
    }
    let candidates: Vec<_> = instances
        .into_iter()
        .filter(|(id, _)| q.after.as_ref().is_none_or(|after| id > after))
        .collect();
    let mut rows = Vec::new();
    for (id, instance) in candidates.iter().take(limit) {
        let (protocol, manifest) = joined(replay, instance)?;
        let iv = instance.get("value").ok_or(DiscoveryError::Source)?;
        let digest = string(iv, "protocol_digest")?;
        let m = value(&manifest)?;
        let actions=m["actions"].as_array().ok_or(DiscoveryError::Source)?.iter().map(|a|{let action=a["id"].as_str().ok_or(DiscoveryError::Source)?;Ok(json!({"action_id":action,"scope_permitted":authority(policy,actor,key,id,Some(action),at)["scope_permitted"],"execution":"not_evaluated"}))}).collect::<Result<Vec<_>,DiscoveryError>>()?;
        rows.push(json!({"instance_id":id,"instance_revision":number(iv,"revision")?,"protocol_digest":digest,"origin_entrypoint":iv.get("origin_entrypoint").map(value).transpose()?,"protocol_ref":object_ref(replay,protocol)?,"protocol_status":status(replay,&digest)?,"actions":actions}));
    }
    let workspace = latest(replay.objects(), "workspaces")?
        .get(replay.workspace_id())
        .copied()
        .ok_or(DiscoveryError::NotFound)?;
    out["workspace"] = value(workspace.get("value").ok_or(DiscoveryError::Source)?)?;
    out["workspace_ref"] = object_ref(replay, workspace)?;
    out["entry"] = json!({"status":"not_declared","workspace_entry_protocol":null,"note":"No universal entry selector is declared by this verified workspace schema; origin_entrypoint records installation origin, not a selected entry workflow."});
    out["structure"] = json!({"status":format!("{:?}",replay.structure_status()),"declared":policy["payload"].get("structure").is_some(),"policy_hash":replay.policy_hash()});
    out["continuation"] = if candidates.len() > limit {
        json!({"after":rows.last().unwrap()["instance_id"],"limit":limit})
    } else {
        Value::Null
    };
    out["instances"] = json!(rows);
    Ok(out)
}
/// Query only selected exact verified sources. Full replay remains the reader;
/// this projection reduces caller inspection, not network/replay complexity.
pub fn discover(
    config: SecureReadProfileConfig,
    query: DiscoveryQuery,
    describe: bool,
    cancel: &CancellationToken,
) -> Result<Value, DiscoveryError> {
    validate_query(&query, describe)?;
    SecureReadProfile::new(config).with_latest_replay(
        cancel,
        |source: &TransportReplayedJournal| {
            source.verified_read().map_err(|_| DiscoveryError::Source)?;
            let policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(DiscoveryError::Source)?;
            let policy = parse_wire_json_bounded(policy, 64, 16 * 1024 * 1024)
                .map_err(|_| DiscoveryError::Source)?;
            let policy = value(&policy)?;
            let at = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| DiscoveryError::Source)?
                    .as_millis(),
            )
            .map_err(|_| DiscoveryError::Source)?;
            let result = project(
                source.replay(),
                &policy,
                source.source_actor_id(),
                source.source_key_id(),
                at,
                describe,
                &query,
            )?;
            if serde_json::to_vec(&result)
                .map_err(|_| DiscoveryError::Source)?
                .len()
                > 2 * 1024 * 1024
            {
                return Err(DiscoveryError::Limit);
            }
            Ok(result)
        },
    )
}
#[cfg(test)]
mod tests;
