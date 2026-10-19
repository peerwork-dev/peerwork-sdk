//! System-maintained structure selection with independently authenticated original content.
//! Service selection/completeness is explicit; this is neither full replay nor Owner state attestation.
use crate::{
    read_view::{
        self, actor, arr, check, digest, equivalent, g, n, number, obj, payload, s, signed, size,
        string, ReadViewError, ReadViewPin,
    },
    secure_keyring::SecretKeyring,
    selected_author::verify_original_operation,
    wire_json::WireValue as W,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
pub const RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const DOMAIN: &str = "peerwork.current-page.v1";
type R<T> = Result<T, ReadViewError>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CurrentPageQuery {
    #[serde(rename = "get")]
    Get { object_kind: String, id: String },
    #[serde(rename = "instances")]
    Instances {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<serde_json::Value>,
    },
    #[serde(rename = "records")]
    Records {
        instance_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<serde_json::Value>,
    },
}
impl CurrentPageQuery {
    pub fn validate(&self) -> R<()> {
        match self {
            Self::Get { object_kind, id } => check(
                ["workspaces", "instances", "protocols", "records"].contains(&object_kind.as_str())
                    && !id.is_empty()
                    && id.encode_utf16().count() <= 512,
                "CURRENT_PAGE_QUERY_INVALID",
            ),
            Self::Instances { limit, .. } => check(
                (1..=20).contains(&limit.unwrap_or(20)),
                "CURRENT_PAGE_QUERY_INVALID",
            ),
            Self::Records {
                instance_id,
                schema,
                limit,
                ..
            } => check(
                read_view::token(instance_id)
                    && schema.as_ref().is_none_or(|s| {
                        !s.is_empty()
                            && s.len() <= 80
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                    })
                    && (1..=20).contains(&limit.unwrap_or(20)),
                "CURRENT_PAGE_QUERY_INVALID",
            ),
        }
    }
    pub fn wire(&self) -> R<W> {
        read_view::parse(
            &serde_json::to_vec(self).map_err(|_| ReadViewError("CURRENT_PAGE_QUERY_INVALID"))?,
            4096,
        )
    }
}
pub struct VerifiedCurrentPage {
    value: W,
    observed: u64,
    expires: u64,
}
impl VerifiedCurrentPage {
    pub fn check_elapsed(&self, millis: u64) -> R<()> {
        check(
            self.observed
                .checked_add(millis)
                .is_some_and(|n| n < self.expires),
            "CURRENT_PAGE_EXPIRED",
        )
    }
    pub fn value(&self) -> &W {
        &self.value
    }
    pub fn into_value(self) -> W {
        self.value
    }
}
pub fn verify_current_page(
    response: &W,
    pin: &ReadViewPin,
    nonce: &str,
    query: &CurrentPageQuery,
    ring: Option<&SecretKeyring>,
    floor: Option<&W>,
    mut active: impl FnMut() -> R<()>,
) -> R<VerifiedCurrentPage> {
    active()?;
    query.validate()?;
    size(response, RESPONSE_BYTES)?;
    check(read_view::token(nonce), "CURRENT_PAGE_NONCE_INVALID")?;
    let page = g(response, "page")?;
    let p = payload(page)?;
    signed(page, DOMAIN, &pin.service_key)?;
    let cp = g(p, "checkpoint")?;
    let policy = g(response, "policy")?;
    let q = payload(policy)?;
    size(policy, 2 * 1024 * 1024)?;
    let observed = n(p, "observed_at")?;
    let expires = n(p, "expires_at")?;
    check(
        n(p, "v")? == 1
            && s(p, "workspace_id")? == pin.workspace_id
            && s(p, "origin")? == pin.origin
            && s(p, "audience")? == pin.audience
            && s(p, "service_key")? == pin.service_key
            && s(p, "nonce")? == nonce
            && observed < expires
            && expires - observed <= 60000
            && equivalent(g(p, "query")?, &query.wire()?)?,
        "CURRENT_PAGE_SOURCE_INVALID",
    )?;
    check(
        actor(&pin.owner_key_id)? == pin.owner_actor_id
            && s(q, "workspace_id")? == pin.workspace_id
            && s(q, "owner_id")? == pin.owner_actor_id
            && s(q, "signing_key")? == pin.owner_key_id
            && read_view::hash(policy)? == s(p, "policy_hash")?
            && n(q, "epoch")? == n(p, "epoch")?
            && s(q, "visibility")? == "PRIVATE",
        "CURRENT_PAGE_POLICY_INVALID",
    )?;
    signed(policy, "peerwork.secure.policy.v1", &pin.owner_key_id)?;
    check(
        (n(q, "v")? == 2 || n(q, "v")? == 3 && s(q, "structure_mode")? == "STRUCTURED")
            && q.get("structure").is_some(),
        "CURRENT_PAGE_STRUCTURE_REQUIRED",
    )?;
    check(
        n(cp, "v")? == 1
            && s(cp, "workspace_id")? == pin.workspace_id
            && s(cp, "owner_id")? == pin.owner_actor_id
            && s(cp, "owner_key")? == pin.owner_key_id
            && n(cp, "sequence")? > 0
            && digest(&s(cp, "head")?)
            && s(cp, "policy_hash")? == s(p, "policy_hash")?,
        "CURRENT_PAGE_CHECKPOINT_INVALID",
    )?;
    if let Some(f) = floor {
        check(
            n(cp, "sequence")? >= n(f, "sequence")?,
            "CURRENT_PAGE_ROLLBACK",
        )?;
        if n(cp, "sequence")? == n(f, "sequence")? {
            check(
                s(cp, "head")? == s(f, "head")? && s(cp, "policy_hash")? == s(f, "policy_hash")?,
                "CURRENT_PAGE_FORK",
            )?
        }
    }
    let query_wire = query.wire()?;
    let mut hash_query = query_wire.clone();
    if let W::Object(fields) = &mut hash_query {
        fields.retain(|(k, _)| !k.iter().copied().eq("cursor".encode_utf16()));
    }
    let query_hash = read_view::hash(&hash_query)?;
    let cursor = query_wire.get("cursor").filter(|v| *v != &W::Null);
    if let Some(c) = cursor {
        check(
            n(c, "v")? == 1
                && n(c, "sequence")? == n(cp, "sequence")?
                && s(c, "head")? == s(cp, "head")?
                && s(c, "query_hash")? == query_hash,
            "CURRENT_PAGE_RESET_REQUIRED",
        )?;
    }
    let limit = match query {
        CurrentPageQuery::Get { .. } => 1,
        CurrentPageQuery::Instances { limit, .. } | CurrentPageQuery::Records { limit, .. } => {
            limit.unwrap_or(20)
        }
    };
    let selections = arr(g(p, "selections")?)?;
    check(selections.len() <= limit, "CURRENT_PAGE_RESOURCE_LIMIT")?;
    let evidence = arr(g(response, "evidence")?)?;
    check(evidence.len() <= 24, "CURRENT_PAGE_RESOURCE_LIMIT")?;
    let mut by_hash = HashMap::new();
    for ev in evidence {
        let c = g(ev, "commit")?;
        size(c, read_view::COMMIT_BYTES)?;
        size(g(ev, "policy")?, read_view::EVIDENCE_BYTES)?;
        let h = read_view::hash(c)?;
        check(
            by_hash.insert(h, ev).is_none(),
            "CURRENT_PAGE_EVIDENCE_DUPLICATE",
        )?;
    }
    let mut operations = HashMap::<String, W>::new();
    let mut objects = vec![];
    let mut seen = HashSet::new();
    let mut previous = cursor.map(|c| s(c, "after")).transpose()?;
    for selection in selections {
        active()?;
        let kind = s(selection, "kind")?;
        let id = s(selection, "id")?;
        check(
            seen.insert((kind.clone(), id.clone())),
            "CURRENT_PAGE_SELECTION_INVALID",
        )?;
        if !matches!(query, CurrentPageQuery::Get { .. }) {
            check(
                read_view::token(&id) && previous.as_ref().is_none_or(|p| &id > p),
                "CURRENT_PAGE_SELECTION_INVALID",
            )?;
            previous = Some(id.clone());
        }
        match query {
            CurrentPageQuery::Get {
                object_kind,
                id: requested,
            } => check(
                &kind == object_kind && &id == requested,
                "CURRENT_PAGE_SELECTION_INVALID",
            )?,
            CurrentPageQuery::Instances { .. } => {
                check(kind == "instances", "CURRENT_PAGE_SELECTION_INVALID")?
            }
            CurrentPageQuery::Records { .. } => {
                check(kind == "records", "CURRENT_PAGE_SELECTION_INVALID")?
            }
        };
        let hashes = arr(g(selection, "commit_hashes")?)?;
        check(
            !hashes.is_empty() && hashes.len() <= 4,
            "CURRENT_PAGE_EVIDENCE_REQUIRED",
        )?;
        let mut found: Option<(W, u64, String)> = None;
        for h in hashes {
            let hash = h
                .as_string()
                .ok_or(ReadViewError("CURRENT_PAGE_EVIDENCE_INVALID"))?;
            check(digest(&hash), "CURRENT_PAGE_EVIDENCE_INVALID")?;
            let ev = by_hash
                .get(&hash)
                .ok_or(ReadViewError("CURRENT_PAGE_EVIDENCE_REQUIRED"))?;
            let commit = payload(g(ev, "commit")?)?;
            let seq = n(commit, "sequence")?;
            check(
                seq > 0 && seq <= n(cp, "sequence")?,
                "CURRENT_PAGE_EVIDENCE_INVALID",
            )?;
            if !operations.contains_key(&hash) {
                let op =
                    verify_original_operation(ev, &hash, seq, pin, &s(q, "visibility")?, ring)?;
                operations.insert(hash.clone(), op);
            }
            let op = operations
                .get(&hash)
                .ok_or(ReadViewError("CURRENT_PAGE_EVIDENCE_INVALID"))?;
            for item in arr(g(op, "objects")?)? {
                if s(item, "kind").ok() != Some(kind.clone())
                    || s(item, "id").ok() != Some(id.clone())
                {
                    continue;
                }
                size(item, 98304)?;
                let rev = if kind == "records" {
                    n(g(item, "value")?, "revision")?
                } else {
                    n(item, "revision")?
                };
                if selection.get("revision").is_some() && rev != n(selection, "revision")? {
                    continue;
                }
                if let Some((prior, previous, _)) = &found {
                    if rev < *previous {
                        continue;
                    }
                    if rev == *previous {
                        check(equivalent(prior, item)?, "CURRENT_PAGE_AMBIGUOUS_OBJECT")?;
                        continue;
                    }
                }
                found = Some((item.clone(), rev, hash.clone()));
            }
        }
        let (found, _, source_hash) =
            found.ok_or(ReadViewError("CURRENT_PAGE_OBJECT_UNAVAILABLE"))?;
        check(
            s(&found, "provenance")? == "AUTHOR_SIGNED",
            "CURRENT_PAGE_SOURCE_UNAVAILABLE",
        )?;
        if kind == "instances" {
            let value = g(&found, "value")?;
            check(
                s(value, "workspace_id")? == pin.workspace_id
                    && arr(g(g(q, "structure")?, "instances")?)?
                        .iter()
                        .any(|instance| {
                            s(instance, "instance_id").ok().as_ref() == Some(&id)
                                && instance.get("protocol_digest") == value.get("protocol_digest")
                        }),
                "CURRENT_PAGE_SELECTION_INVALID",
            )?;
        }
        if kind == "records" {
            let value = g(&found, "value")?;
            check(
                s(value, "workspace_id")? == pin.workspace_id && s(value, "id")? == id,
                "CURRENT_PAGE_RECORD_INVALID",
            )?;
            if let CurrentPageQuery::Records {
                instance_id,
                schema,
                ..
            } = query
            {
                check(
                    s(value, "instance_id")? == *instance_id
                        && schema.as_ref().is_none_or(|expected| {
                            s(value, "schema_ref").ok().as_ref() == Some(expected)
                        }),
                    "CURRENT_PAGE_SELECTION_INVALID",
                )?;
            }
            if let Some(structure) = selection.get("structure") {
                verify_structure(
                    structure,
                    &found,
                    payload(g(by_hash[&source_hash], "commit")?)?,
                    payload(g(by_hash[&source_hash], "policy")?)?,
                )?;
            } else {
                return Err(ReadViewError("CURRENT_PAGE_STRUCTURE_PROOF_REQUIRED"));
            }
        }
        objects.push(found);
    }
    let next = g(p, "next")?.clone();
    if next != W::Null {
        check(
            n(&next, "v")? == 1
                && n(&next, "sequence")? == n(cp, "sequence")?
                && s(&next, "head")? == s(cp, "head")?
                && s(&next, "query_hash")? == query_hash
                && read_view::token(&s(&next, "after")?)
                && !matches!(query, CurrentPageQuery::Get { .. })
                && previous.as_ref() == Some(&s(&next, "after")?),
            "CURRENT_PAGE_CURSOR_INVALID",
        )?;
    }
    active()?;
    let floor = obj(vec![
        ("sequence", g(cp, "sequence")?.clone()),
        ("head", g(cp, "head")?.clone()),
        ("policy_hash", g(cp, "policy_hash")?.clone()),
    ]);
    let mut value = obj(vec![
        ("assurance", string("SERVICE_STRUCTURE_SELECTION")),
        ("checkpoint", cp.clone()),
        ("policy", policy.clone()),
        ("objects", W::Array(objects.clone())),
        ("next", next),
        ("floor", floor),
        (
            "metrics",
            obj(vec![
                (
                    "response_bytes",
                    number(size(response, RESPONSE_BYTES)? as u64),
                ),
                ("evidence_commits", number(evidence.len() as u64)),
                ("verified_commits", number(operations.len() as u64)),
            ]),
        ),
    ]);
    if matches!(query, CurrentPageQuery::Get { .. }) {
        if let W::Object(fields) = &mut value {
            fields.push((
                "object".encode_utf16().collect(),
                objects.into_iter().next().unwrap_or(W::Null),
            ));
        }
    }
    Ok(VerifiedCurrentPage {
        value,
        observed,
        expires,
    })
}
fn verify_structure(structure: &W, object: &W, commit: &W, policy: &W) -> R<()> {
    let value = g(object, "value")?;
    for (selected, original) in [
        ("record_id", "id"),
        ("entity_id", "entity_id"),
        ("revision", "revision"),
        ("instance_id", "instance_id"),
        ("protocol_digest", "protocol_digest"),
        ("schema_ref", "schema_ref"),
        ("actor_id", "actor_id"),
        ("created", "created"),
    ] {
        check(
            equivalent(g(structure, selected)?, g(value, original)?)?,
            "CURRENT_PAGE_STRUCTURE_MISMATCH",
        )?;
    }
    let header = g(commit, "structure")?;
    check(
        s(header, "mode")? == "DELTA",
        "CURRENT_PAGE_STRUCTURE_SOURCE_UNAVAILABLE",
    )?;
    let records = arr(g(header, "records")?)?;
    check(
        records
            .iter()
            .any(|r| equivalent(r, structure).unwrap_or(false)),
        "CURRENT_PAGE_STRUCTURE_MISMATCH",
    )?;
    let contract = g(policy, "structure")?;
    crate::structure_policy::validate_structure_policy(contract)
        .map_err(|_| ReadViewError("CURRENT_PAGE_STRUCTURE_MISMATCH"))?;
    let (projected, _) = crate::secure_replay::project_structure_data(&[object.clone()], contract)
        .map_err(|_| ReadViewError("CURRENT_PAGE_STRUCTURE_MISMATCH"))?;
    check(
        projected.len() == 1 && equivalent(&projected[0], structure)?,
        "CURRENT_PAGE_STRUCTURE_MISMATCH",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> W {
        read_view::parse(
            include_bytes!("../tests/fixtures/private-current-page-v1.json"),
            RESPONSE_BYTES,
        )
        .unwrap()
    }
    fn pin(v: &W) -> ReadViewPin {
        let p = g(v, "pin").unwrap();
        ReadViewPin {
            origin: s(p, "origin").unwrap(),
            workspace_id: s(p, "workspace").unwrap(),
            owner_actor_id: s(p, "ownerId").unwrap(),
            owner_key_id: s(p, "ownerKey").unwrap(),
            audience: s(p, "audience").unwrap(),
            service_key: s(p, "serviceKey").unwrap(),
        }
    }
    fn query(v: &W) -> CurrentPageQuery {
        serde_json::from_str(&read_view::wire(g(v, "query").unwrap()).unwrap()).unwrap()
    }
    fn ring(v: &W) -> SecretKeyring {
        SecretKeyring::parse_wire(
            read_view::wire(g(v, "keyring").unwrap())
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
    }
    fn set(v: &mut W, k: &str, value: W) {
        if let W::Object(fields) = v {
            let key = k.encode_utf16().collect::<Vec<_>>();
            if let Some((_, v)) = fields.iter_mut().find(|(k, _)| k == &key) {
                *v = value;
            } else {
                fields.push((key, value));
            }
        } else {
            panic!()
        }
    }
    #[test]
    fn current_page_ts_private_original_author_and_structure() {
        let v = fixture();
        let ring = ring(&v);
        let pin = pin(&v);
        let query = query(&v);
        let result = verify_current_page(
            g(&v, "response").unwrap(),
            &pin,
            &s(&v, "nonce").unwrap(),
            &query,
            Some(&ring),
            None,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            s(result.value(), "assurance").unwrap(),
            "SERVICE_STRUCTURE_SELECTION"
        );
        assert_eq!(arr(g(result.value(), "objects").unwrap()).unwrap().len(), 2);
        assert!(result.check_elapsed(0).is_ok());
        assert!(result.check_elapsed(60000).is_err());
        let floor = g(result.value(), "floor").unwrap();
        assert!(verify_current_page(
            g(&v, "response").unwrap(),
            &pin,
            &s(&v, "nonce").unwrap(),
            &query,
            Some(&ring),
            Some(floor),
            || Ok(())
        )
        .is_ok());
    }
    #[test]
    fn current_page_nonce_query_floor_and_key_fail_closed() {
        let v = fixture();
        let ring = ring(&v);
        let pin = pin(&v);
        let query = query(&v);
        let response = g(&v, "response").unwrap();
        let nonce = s(&v, "nonce").unwrap();
        assert!(verify_current_page(
            response,
            &pin,
            &"a".repeat(43),
            &query,
            Some(&ring),
            None,
            || Ok(())
        )
        .is_err());
        let wrong = CurrentPageQuery::Get {
            object_kind: "records".into(),
            id: "b".repeat(43),
        };
        assert!(
            verify_current_page(response, &pin, &nonce, &wrong, Some(&ring), None, || Ok(()))
                .is_err()
        );
        assert!(
            verify_current_page(response, &pin, &nonce, &query, None, None, || Ok(())).is_err()
        );
        let floor = obj(vec![
            ("sequence", number(900000)),
            ("head", string(&"a".repeat(64))),
            ("policy_hash", string(&"a".repeat(64))),
        ]);
        assert!(verify_current_page(
            response,
            &pin,
            &nonce,
            &query,
            Some(&ring),
            Some(&floor),
            || Ok(())
        )
        .is_err());
        assert_eq!(
            verify_current_page(response, &pin, &nonce, &query, Some(&ring), None, || Err(
                ReadViewError("CANCELLED")
            ))
            .err()
            .unwrap()
            .0,
            "CANCELLED"
        );
    }
    #[test]
    fn current_page_tampered_service_and_original_evidence() {
        let v = fixture();
        let ring = ring(&v);
        let pin = pin(&v);
        let query = query(&v);
        let nonce = s(&v, "nonce").unwrap();
        for target in ["page", "commit", "policy"] {
            let mut response = g(&v, "response").unwrap().clone();
            if target == "page" {
                let mut page = g(&response, "page").unwrap().clone();
                set(&mut page, "signature", string(&"a".repeat(86)));
                set(&mut response, "page", page);
            } else {
                let mut evidence = arr(g(&response, "evidence").unwrap()).unwrap().to_vec();
                let mut artifact = g(&evidence[0], target).unwrap().clone();
                set(&mut artifact, "signature", string(&"a".repeat(86)));
                set(&mut evidence[0], target, artifact);
                set(&mut response, "evidence", W::Array(evidence));
            }
            assert!(
                verify_current_page(
                    &response,
                    &pin,
                    &nonce,
                    &query,
                    Some(&ring),
                    None,
                    || Ok(())
                )
                .is_err(),
                "{target}"
            );
        }
    }
    fn sign_page(response: &mut W, pin: &mut ReadViewPin) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        pin.service_key = crate::crypto::key_id(&key.verifying_key().to_bytes());
        let mut page = g(response, "page").unwrap().clone();
        let mut p = payload(&page).unwrap().clone();
        set(&mut p, "service_key", string(&pin.service_key));
        let json: serde_json::Value = serde_json::from_str(&read_view::wire(&p).unwrap()).unwrap();
        set(
            &mut page,
            "signature",
            string(&crate::crypto::sign_canonical(DOMAIN, &json, &key).unwrap()),
        );
        set(&mut page, "payload", p);
        set(response, "page", page);
    }
    #[test]
    fn current_page_historical_epoch_is_selected_from_active_ring() {
        let v = fixture();
        let mut material = g(&v, "keyring").unwrap().clone();
        let old = arr(g(&material, "keys").unwrap()).unwrap()[0].clone();
        let newer = obj(vec![
            ("epoch", number(n(&old, "epoch").unwrap() + 1)),
            ("key", string(&crate::crypto::base64url(&[99; 32]))),
        ]);
        set(&mut material, "keys", W::Array(vec![old, newer.clone()]));
        let ring =
            SecretKeyring::parse_wire(read_view::wire(&material).unwrap().as_bytes()).unwrap();
        assert!(verify_current_page(
            g(&v, "response").unwrap(),
            &pin(&v),
            &s(&v, "nonce").unwrap(),
            &query(&v),
            Some(&ring),
            None,
            || Ok(())
        )
        .is_ok());
        set(&mut material, "keys", W::Array(vec![newer]));
        let ring =
            SecretKeyring::parse_wire(read_view::wire(&material).unwrap().as_bytes()).unwrap();
        assert_eq!(
            verify_current_page(
                g(&v, "response").unwrap(),
                &pin(&v),
                &s(&v, "nonce").unwrap(),
                &query(&v),
                Some(&ring),
                None,
                || Ok(())
            )
            .err()
            .unwrap()
            .0,
            "READ_VIEW_HISTORICAL_KEY_REQUIRED"
        );
    }
    #[test]
    fn current_page_service_selected_absence_and_cursor_scope() {
        let v = fixture();
        let ring = ring(&v);
        let mut pin = pin(&v);
        let nonce = s(&v, "nonce").unwrap();
        let mut response = g(&v, "response").unwrap().clone();
        let mut page = g(&response, "page").unwrap().clone();
        let mut p = payload(&page).unwrap().clone();
        let exact = CurrentPageQuery::Get {
            object_kind: "records".into(),
            id: "z".repeat(43),
        };
        set(&mut p, "query", exact.wire().unwrap());
        set(&mut p, "selections", W::Array(vec![]));
        set(&mut p, "next", W::Null);
        set(&mut page, "payload", p);
        set(&mut response, "page", page);
        set(&mut response, "evidence", W::Array(vec![]));
        sign_page(&mut response, &mut pin);
        let result = verify_current_page(
            &response,
            &pin,
            &nonce,
            &exact,
            Some(&ring),
            None,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(g(result.value(), "object").unwrap(), &W::Null);
        let mut query_json: serde_json::Value =
            serde_json::from_str(&read_view::wire(g(&v, "query").unwrap()).unwrap()).unwrap();
        let cursor = g(
            payload(g(g(&v, "response").unwrap(), "page").unwrap()).unwrap(),
            "next",
        )
        .unwrap();
        query_json["cursor"] = serde_json::from_str(&read_view::wire(cursor).unwrap()).unwrap();
        query_json["limit"] = 1.into();
        let query: CurrentPageQuery = serde_json::from_value(query_json).unwrap();
        let mut page = g(&response, "page").unwrap().clone();
        let mut p = payload(&page).unwrap().clone();
        set(&mut p, "query", query.wire().unwrap());
        set(&mut page, "payload", p);
        set(&mut response, "page", page);
        sign_page(&mut response, &mut pin);
        assert_eq!(
            verify_current_page(
                &response,
                &pin,
                &nonce,
                &query,
                Some(&ring),
                None,
                || Ok(())
            )
            .err()
            .unwrap()
            .0,
            "CURRENT_PAGE_RESET_REQUIRED"
        );
    }
    #[test]
    fn current_page_service_cannot_forge_disclosed_original_fields() {
        let v = fixture();
        let ring = ring(&v);
        let mut pin = pin(&v);
        let mut response = g(&v, "response").unwrap().clone();
        let mut page = g(&response, "page").unwrap().clone();
        let mut p = payload(&page).unwrap().clone();
        let mut selections = arr(g(&p, "selections").unwrap()).unwrap().to_vec();
        let mut structure = g(&selections[0], "structure").unwrap().clone();
        let mut fields = g(&structure, "fields").unwrap().clone();
        set(&mut fields, "author", string(&"a".repeat(43)));
        set(&mut structure, "fields", fields);
        set(&mut selections[0], "structure", structure);
        set(&mut p, "selections", W::Array(selections));
        set(&mut page, "payload", p);
        set(&mut response, "page", page);
        sign_page(&mut response, &mut pin);
        assert_eq!(
            verify_current_page(
                &response,
                &pin,
                &s(&v, "nonce").unwrap(),
                &query(&v),
                Some(&ring),
                None,
                || Ok(())
            )
            .err()
            .unwrap()
            .0,
            "CURRENT_PAGE_STRUCTURE_MISMATCH"
        );
    }
}
