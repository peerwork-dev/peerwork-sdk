//! Exact member-only policy replacement and decrypted permission catalog.
use crate::{
    canonical::Path,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue as V},
};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
#[derive(Debug, Error)]
#[error("{0}")]
pub struct MemberScopeError(pub &'static str);
type R<T> = Result<T, MemberScopeError>;
fn bad() -> MemberScopeError {
    MemberScopeError("MEMBER_SCOPES_INVALID")
}
fn array(v: &V) -> R<&[V]> {
    if let V::Array(a) = v {
        Ok(a)
    } else {
        Err(bad())
    }
}
fn field<'a>(v: &'a V, k: &str) -> R<&'a V> {
    v.get(k).ok_or_else(bad)
}
fn string(v: &V, k: &str) -> R<String> {
    field(v, k)?.as_string().ok_or_else(bad)
}
fn number(v: &V, k: &str) -> R<u64> {
    let n = field(v, k)?.as_number().ok_or_else(bad)?;
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > 9007199254740991.0 {
        return Err(bad());
    }
    Ok(n as u64)
}
fn same(a: &V, b: &V) -> R<bool> {
    Ok(
        canonical_wire_value(a, Path::SecureArtifact).map_err(|_| bad())?
            == canonical_wire_value(b, Path::SecureArtifact).map_err(|_| bad())?,
    )
}
fn set(v: &mut V, k: &str, value: V) -> R<()> {
    let V::Object(fields) = v else {
        return Err(bad());
    };
    let (_, slot) = fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(k.encode_utf16()))
        .ok_or_else(bad)?;
    *slot = value;
    Ok(())
}
fn text(s: &str) -> V {
    V::String(s.encode_utf16().collect())
}
fn object(fields: Vec<(&str, V)>) -> V {
    V::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.encode_utf16().collect(), v))
            .collect(),
    )
}
fn token(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn validate_scopes(scopes: &V) -> R<()> {
    let scopes = array(scopes)?;
    if scopes.len() > 128 {
        return Err(bad());
    }
    for scope in scopes {
        let V::Object(fields) = scope else {
            return Err(bad());
        };
        if fields.iter().any(|(k, _)| {
            ![
                "instance_id",
                "actions",
                "protocol_roles",
                "capabilities",
                "expires_at",
            ]
            .iter()
            .any(|s| k.iter().copied().eq(s.encode_utf16()))
        }) {
            return Err(bad());
        }
        let instance = field(scope, "instance_id")?;
        if !matches!(instance, V::Null) && !instance.as_string().is_some_and(|s| token(&s)) {
            return Err(bad());
        }
        for k in ["actions", "protocol_roles", "capabilities"] {
            let list = array(field(scope, k)?)?;
            let mut seen = HashSet::new();
            if list.len() > 64
                || list.iter().any(|v| {
                    v.as_utf16()
                        .is_none_or(|s| s.is_empty() || s.len() > 120 || !seen.insert(s))
                })
            {
                return Err(bad());
            }
        }
        if scope
            .get("expires_at")
            .is_some_and(|v| !matches!(v, V::Null))
            && number(scope, "expires_at")? == 0
        {
            return Err(bad());
        }
    }
    Ok(())
}

/// Catalog comes only from the caller's complete authenticated object replay.
pub fn catalog(objects: &[V]) -> R<V> {
    let mut latest = BTreeMap::new();
    for o in objects {
        let key = (string(o, "kind")?, string(o, "id")?);
        if latest.get(&key).is_none_or(|p: &&V| {
            number(p, "revision").unwrap_or(0) < number(o, "revision").unwrap_or(0)
        }) {
            latest.insert(key, o);
        }
    }
    let mut result = Vec::new();
    for ((kind, id), o) in &latest {
        if kind != "instances" {
            continue;
        }
        let instance = field(o, "value")?;
        let digest = string(instance, "protocol_digest")?;
        let protocol = latest
            .get(&("protocols".to_owned(), digest.clone()))
            .ok_or(MemberScopeError("MEMBER_SCOPE_PROTOCOL_NOT_FOUND"))?;
        let value = field(protocol, "value")?;
        let manifest = value
            .get("resolved_manifest")
            .or_else(|| value.get("manifest"))
            .ok_or_else(bad)?;
        let decoded;
        let manifest = if let Some(s) = manifest.as_string() {
            decoded =
                parse_wire_json_bounded(s.as_bytes(), 64, 2 * 1024 * 1024).map_err(|_| bad())?;
            &decoded
        } else {
            manifest
        };
        let actions = array(field(manifest, "actions")?)?
            .iter()
            .map(|a| field(a, "id").cloned())
            .collect::<R<Vec<_>>>()?;
        result.push(object(vec![
            ("instance_id", text(id)),
            ("protocol_digest", text(&digest)),
            (
                "entrypoint",
                instance
                    .get("origin_entrypoint")
                    .cloned()
                    .unwrap_or(V::Null),
            ),
            ("actions", V::Array(actions)),
            ("protocol_roles", field(manifest, "protocol_roles")?.clone()),
            ("capabilities", field(manifest, "capabilities")?.clone()),
            ("role_conflicts", field(manifest, "role_conflicts")?.clone()),
            (
                "historical_role_conflicts",
                field(manifest, "historical_role_conflicts")?.clone(),
            ),
        ]));
    }
    Ok(V::Array(result))
}
pub fn validate_permissions(scopes: &V, objects: &[V]) -> R<()> {
    validate_scopes(scopes)?;
    let entries = catalog(objects)?;
    for scope in array(scopes)? {
        let selected = array(&entries)?
            .iter()
            .filter(|e| {
                scope.get("instance_id") == Some(&V::Null)
                    || scope.get("instance_id") == e.get("instance_id")
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(MemberScopeError("MEMBER_SCOPE_INSTANCE_NOT_FOUND"));
        }
        for k in ["actions", "protocol_roles", "capabilities"] {
            let mut allowed = HashSet::new();
            for entry in &selected {
                for v in array(field(entry, k)?)? {
                    allowed.insert(v.as_utf16().ok_or_else(bad)?);
                }
            }
            if array(field(scope, k)?)?
                .iter()
                .any(|v| v.as_utf16().is_none_or(|s| !allowed.contains(s)))
            {
                return Err(MemberScopeError("MEMBER_SCOPE_UNDECLARED_PERMISSION"));
            }
        }
    }
    Ok(())
}

/// Validate every field, not merely the target scopes or policy version.
pub fn validate_transition(
    before: &V,
    after: &V,
    context: &V,
    operation: &V,
    old_hash: &str,
    objects: &[V],
) -> R<String> {
    if string(context, "action_id")? != "secure.member.scopes"
        || context.get("actor_id") != before.get("owner_id")
        || context.get("signing_key") != before.get("signing_key")
        || context.get("delegation") != Some(&V::Null)
        || context.get("instance_id") != Some(&V::Null)
        || number(after, "version")? != number(before, "version")?.checked_add(1).ok_or_else(bad)?
        || after.get("effective_sequence") != context.get("sequence")
        || after.get("issued_at") != context.get("issued_at")
        || string(after, "previous_policy")? != old_hash
    {
        return Err(bad());
    }
    let old = array(field(before, "members")?)?;
    let new = array(field(after, "members")?)?;
    if old.len() != new.len() {
        return Err(bad());
    }
    let mut changed = None;
    for (a, b) in old.iter().zip(new) {
        let mut expected = a.clone();
        set(&mut expected, "scopes", field(b, "scopes")?.clone())?;
        if !same(&expected, b)? {
            return Err(bad());
        }
        if !same(field(a, "scopes")?, field(b, "scopes")?)? {
            if changed.is_some() {
                return Err(bad());
            }
            changed = Some(b);
        }
    }
    let target = changed.ok_or_else(bad)?;
    let actor = string(target, "actor_id")?;
    let mut expected = before.clone();
    for key in [
        "members",
        "version",
        "previous_policy",
        "effective_sequence",
        "issued_at",
    ] {
        set(&mut expected, key, field(after, key)?.clone())?;
    }
    if !same(&expected, after)? {
        return Err(bad());
    }
    let expected = object(vec![
        ("v", V::Number(1.0)),
        ("kind", text("ADMIN")),
        (
            "input",
            object(vec![
                ("member_id", text(&actor)),
                ("expected_policy_hash", text(old_hash)),
            ]),
        ),
        ("objects", V::Array(vec![])),
    ]);
    if !same(&expected, operation)? {
        return Err(bad());
    }
    if let Some(structure) = context.get("structure") {
        let expected = object(vec![
            ("v", V::Number(1.0)),
            ("mode", text("DELTA")),
            ("records", V::Array(vec![])),
            ("heads", V::Array(vec![])),
        ]);
        if !same(structure, &expected)? {
            return Err(bad());
        }
    }
    validate_permissions(field(target, "scopes")?, objects)?;
    Ok(actor)
}

/// Source policies must be the verified, chronological history ending at the
/// selected source. History cannot be omitted when granting conflicting roles.
pub fn validate_candidate_roles(policies: &[V], candidate: &V, objects: &[V]) -> R<()> {
    crate::secure_replay::validate_member_scope_roles(policies, candidate, objects)
        .map_err(MemberScopeError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn wire(v: serde_json::Value) -> V {
        parse_wire_json_bounded(v.to_string().as_bytes(), 64, 100000).unwrap()
    }
    fn source() -> Vec<V> {
        vec![
            wire(
                json!({"kind":"protocols","id":"d","revision":1,"value":{"digest":"d","manifest":{"actions":[{"id":"post"}],"protocol_roles":["writer","reviewer"],"capabilities":["write"],"role_conflicts":[["writer","reviewer"]],"historical_role_conflicts":[["writer","reviewer"]]}}}),
            ),
            wire(
                json!({"kind":"instances","id":"I".repeat(43),"revision":1,"value":{"protocol_digest":"d","origin_entrypoint":"test"}}),
            ),
        ]
    }
    fn scope() -> serde_json::Value {
        json!({"instance_id":"I".repeat(43),"actions":["post"],"protocol_roles":["writer"],"capabilities":["write"]})
    }
    #[test]
    fn permission_validation_and_latest_instance_catalog() {
        let objects = source();
        validate_permissions(&wire(json!([scope()])), &objects).unwrap();
        assert_eq!(array(&catalog(&objects).unwrap()).unwrap().len(), 1);
        for key in ["actions", "protocol_roles", "capabilities"] {
            let mut s = scope();
            s[key] = json!(["missing"]);
            assert_eq!(
                validate_permissions(&wire(json!([s])), &objects)
                    .unwrap_err()
                    .0,
                "MEMBER_SCOPE_UNDECLARED_PERMISSION"
            );
        }
        let mut s = scope();
        s["instance_id"] = json!("J".repeat(43));
        assert_eq!(
            validate_permissions(&wire(json!([s])), &objects)
                .unwrap_err()
                .0,
            "MEMBER_SCOPE_INSTANCE_NOT_FOUND"
        );
        for expiry in [json!(0), json!(-1), json!(1.5), json!(9007199254740992u64)] {
            let mut s = scope();
            s["expires_at"] = expiry;
            assert!(validate_scopes(&wire(json!([s]))).is_err());
        }
        let mut s = scope();
        s["actions"] = json!(["post", "post"]);
        assert!(validate_scopes(&wire(json!([s]))).is_err());
        let mut s = scope();
        s["extra"] = json!(true);
        assert!(validate_scopes(&wire(json!([s]))).is_err());
        validate_permissions(&wire(json!([])), &objects).unwrap();
    }
    #[test]
    fn exact_target_only_transition_and_all_unchanged_fields() {
        let before = json!({"version":1,"previous_policy":null,"effective_sequence":1,"issued_at":1,"owner_id":"owner","signing_key":"key","epoch":1,"members":[{"actor_id":"member","certificate":{"x":1},"role":"MEMBER","scopes":[scope()]}]});
        let mut after = before.clone();
        after["version"] = json!(2);
        after["previous_policy"] = json!("hash");
        after["effective_sequence"] = json!(2);
        after["issued_at"] = json!(2);
        after["members"][0]["scopes"] = json!([]);
        let context = json!({"action_id":"secure.member.scopes","actor_id":"owner","signing_key":"key","delegation":null,"instance_id":null,"sequence":2,"issued_at":2});
        let operation = json!({"v":1,"kind":"ADMIN","input":{"member_id":"member","expected_policy_hash":"hash"},"objects":[]});
        let check = |a: serde_json::Value, c: serde_json::Value, o: serde_json::Value| {
            validate_transition(
                &wire(before.clone()),
                &wire(a),
                &wire(c),
                &wire(o),
                "hash",
                &source(),
            )
        };
        assert_eq!(
            check(after.clone(), context.clone(), operation.clone()).unwrap(),
            "member"
        );
        for field in ["owner_id", "signing_key", "epoch"] {
            let mut a = after.clone();
            a[field] = json!("changed");
            assert!(check(a, context.clone(), operation.clone()).is_err());
        }
        let mut a = after.clone();
        a["members"][0]["certificate"] = json!({"x":2});
        assert!(check(a, context.clone(), operation.clone()).is_err());
        let mut c = context.clone();
        c["actor_id"] = json!("member");
        assert!(check(after.clone(), c, operation.clone()).is_err());
        let mut o = operation.clone();
        o["objects"] = json!([{"kind":"records"}]);
        assert!(check(after.clone(), context.clone(), o).is_err());
        let mut a = after.clone();
        a["members"][0]["scopes"] = before["members"][0]["scopes"].clone();
        assert!(check(a, context.clone(), operation.clone()).is_err());
    }
    #[test]
    fn active_and_historical_role_conflicts_are_preflighted() {
        let mut old = json!({"issued_at":1,"members":[{"actor_id":"member","scopes":[scope()]}]});
        let mut next = old.clone();
        next["issued_at"] = json!(2);
        next["members"][0]["scopes"][0]["protocol_roles"] = json!(["reviewer"]);
        assert_eq!(
            validate_candidate_roles(&[wire(old.clone())], &wire(next.clone()), &source())
                .unwrap_err()
                .0,
            "HISTORICAL_ROLE_CONFLICT"
        );
        old["members"][0]["scopes"] = json!([]);
        next["members"][0]["scopes"][0]["protocol_roles"] = json!(["writer", "reviewer"]);
        assert_eq!(
            validate_candidate_roles(&[wire(old)], &wire(next), &source())
                .unwrap_err()
                .0,
            "ACTIVE_ROLE_CONFLICT"
        );
    }
}
