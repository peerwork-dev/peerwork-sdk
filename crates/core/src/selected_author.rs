//! Independent cryptographic attribution for selected original commits. This is
//! not a state reducer, currentness proof, or historical policy-chain verifier.
use crate::{
    read_view::{
        self, actor, arr, check, decrypt, digest, equivalent, g, n, number, obj, payload, s,
        signed, size, string, verify_author_certificate, ReadViewError, ReadViewPin, COMMIT_BYTES,
        EVIDENCE_BYTES,
    },
    secure_keyring::SecretKeyring,
    wire_json::WireValue as W,
};
type R<T> = Result<T, ReadViewError>;
pub fn verify_original_operation(
    evidence: &W,
    expected_hash: &str,
    sequence: u64,
    pin: &ReadViewPin,
    visibility: &str,
    ring: Option<&SecretKeyring>,
) -> R<W> {
    let commit = g(evidence, "commit")?;
    let p = payload(commit)?;
    let policy = g(evidence, "policy")?;
    let q = payload(policy)?;
    size(commit, COMMIT_BYTES)?;
    size(policy, EVIDENCE_BYTES)?;
    check(
        read_view::hash(commit)? == expected_hash
            && s(p, "workspace_id")? == pin.workspace_id
            && n(p, "sequence")? == sequence
            && s(p, "mode")? == visibility
            && n(q, "epoch")? == n(p, "epoch")?
            && s(q, "visibility")? == visibility
            && s(q, "workspace_id")? == pin.workspace_id
            && s(q, "owner_id")? == pin.owner_actor_id
            && s(q, "signing_key")? == pin.owner_key_id
            && read_view::hash(policy)? == s(p, "policy_hash")?
            && arr(g(q, "members")?)?.len() <= 128,
        "AUTHOR_EVIDENCE_INVALID",
    )?;
    signed(policy, "peerwork.secure.policy.v1", &pin.owner_key_id)?;
    let author = s(p, "actor_id")?;
    let author_key = s(p, "signing_key")?;
    check(actor(&author_key)? == author, "AUTHOR_EVIDENCE_INVALID")?;
    signed(commit, "peerwork.secure.commit.v1", &author_key)?;
    let principal = if g(p, "delegation")? == &W::Null {
        let member = arr(g(q, "members")?)?
            .iter()
            .find(|m| s(m, "actor_id").ok() == Some(author.clone()))
            .ok_or(ReadViewError("AUTHOR_EVIDENCE_INVALID"))?;
        verify_author_certificate(
            g(member, "certificate")?,
            &author,
            &author_key,
            n(p, "issued_at")?,
        )?;
        crate::secure_action_delegation::verify_member_certificate_at(
            q,
            &author,
            n(p, "issued_at")?,
        )
        .map_err(|_| ReadViewError("AUTHOR_CERTIFICATE_INVALID"))?;
        author.clone()
    } else {
        let delegation = read_view::wire(g(p, "delegation")?)?;
        let scope = crate::secure_action_delegation::resolve_action_scope(
            p,
            q,
            Some(delegation.as_bytes()),
        )
        .map_err(|_| ReadViewError("AUTHOR_DELEGATION_INVALID"))?;
        crate::secure_action_delegation::verify_member_certificate_at(
            q,
            &scope.actor_id,
            n(p, "issued_at")?,
        )
        .map_err(|_| ReadViewError("AUTHOR_CERTIFICATE_INVALID"))?;
        scope.actor_id
    };
    if let Some(guard) = q.get("guard_time").filter(|v| *v != &W::Null) {
        let policy = crate::guard_time::parse_guard_time_policy(guard)
            .map_err(|_| ReadViewError("AUTHOR_GUARD_TIME_INVALID"))?;
        let proofs = arr(g(evidence, "guard_time_attestations")?)?;
        check(proofs.len() == 1, "AUTHOR_GUARD_TIME_INVALID")?;
        let proof = &proofs[0];
        let att = payload(proof)?;
        let source = g(att, "source")?;
        check(
            sequence > 0
                && n(source, "sequence")? == sequence - 1
                && equivalent(g(source, "head")?, g(p, "previous")?)?
                && s(source, "workspace_id")? == pin.workspace_id
                && s(source, "owner_id")? == pin.owner_actor_id
                && s(source, "owner_key")? == pin.owner_key_id
                && digest(&s(source, "policy_hash")?),
            "AUTHOR_GUARD_TIME_INVALID",
        )?;
        let result = obj(vec![
            ("v", number(1)),
            ("workspace_id", string(&pin.workspace_id)),
            ("owner_id", string(&pin.owner_actor_id)),
            ("owner_key", string(&pin.owner_key_id)),
            ("sequence", number(sequence)),
            ("head", string(expected_hash)),
            ("policy_hash", g(p, "policy_hash")?.clone()),
        ]);
        let expected = obj(vec![
            ("v", number(1)),
            ("audience", string(&policy.audience)),
            ("service_key", string(&policy.service_key)),
            ("workspace_id", g(p, "workspace_id")?.clone()),
            ("command_id", g(p, "command_id")?.clone()),
            ("actor_id", g(p, "actor_id")?.clone()),
            ("signing_key", g(p, "signing_key")?.clone()),
            ("action_id", g(p, "action_id")?.clone()),
            ("instance_id", g(p, "instance_id")?.clone()),
            ("epoch", g(p, "epoch")?.clone()),
            ("policy_hash", g(p, "policy_hash")?.clone()),
            ("source", source.clone()),
            ("result", result),
            ("commit_hash", string(expected_hash)),
            ("context", g(p, "guard_time")?.clone()),
            ("admitted_at_ms", g(att, "admitted_at_ms")?.clone()),
        ]);
        crate::guard_time::verify_guard_time_attestation(
            read_view::wire(proof)?.as_bytes(),
            &policy,
            &expected,
        )
        .map_err(|_| ReadViewError("AUTHOR_GUARD_TIME_INVALID"))?;
    }
    let operation = if visibility == "PRIVATE" {
        let ring = ring
            .filter(|r| r.workspace_id() == pin.workspace_id)
            .ok_or(ReadViewError("READ_VIEW_ACTIVE_KEY_REQUIRED"))?;
        let key = ring
            .key_at(n(p, "epoch")?)
            .ok_or(ReadViewError("READ_VIEW_HISTORICAL_KEY_REQUIRED"))?;
        let mut context = p.clone();
        if let W::Object(fields) = &mut context {
            fields.retain(|(k, _)| {
                !k.iter().copied().eq("body".encode_utf16())
                    && !k.iter().copied().eq("mode".encode_utf16())
            });
        }
        decrypt(g(p, "body")?, &context, key, COMMIT_BYTES)?
    } else {
        check(visibility == "PUBLIC", "AUTHOR_EVIDENCE_INVALID")?;
        g(p, "body")?.clone()
    };
    check(
        n(&operation, "v")? == 1 && arr(g(&operation, "objects")?)?.len() <= 128,
        "AUTHOR_EVIDENCE_INVALID",
    )?;
    for object in arr(g(&operation, "objects")?)? {
        if s(object, "kind")? == "records" {
            let value = g(object, "value")?;
            check(
                s(&operation, "kind")? == "ACTION"
                    && s(object, "provenance")? == "AUTHOR_SIGNED"
                    && s(value, "actor_id")? == principal
                    && n(value, "created")? == n(p, "issued_at")?
                    && s(value, "workspace_id")? == pin.workspace_id,
                "AUTHOR_RECORD_ATTRIBUTION_INVALID",
            )?;
        }
    }
    Ok(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_author_typescript_guard_time_original_commit() {
        let v = read_view::parse(
            include_bytes!("../../../conformance/guard-time-attestation-vector.json"),
            EVIDENCE_BYTES,
        )
        .unwrap();
        let policy = g(&v, "policy").unwrap();
        let q = payload(policy).unwrap();
        let commit = g(&v, "commit").unwrap();
        let p = payload(commit).unwrap();
        let pin = ReadViewPin {
            origin: "https://api.example.test".into(),
            workspace_id: s(q, "workspace_id").unwrap(),
            owner_actor_id: s(q, "owner_id").unwrap(),
            owner_key_id: s(q, "signing_key").unwrap(),
            audience: "unused".into(),
            service_key: s(&v, "service_key").unwrap(),
        };
        let proof = obj(vec![
            ("payload", g(&v, "payload").unwrap().clone()),
            ("signature", g(&v, "signature").unwrap().clone()),
        ]);
        let evidence = obj(vec![
            ("commit", commit.clone()),
            ("policy", policy.clone()),
            ("guard_time_attestations", W::Array(vec![proof])),
        ]);
        let ring = SecretKeyring::parse_wire(
            read_view::wire(g(&v, "keyring").unwrap())
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let op = verify_original_operation(
            &evidence,
            &read_view::hash(commit).unwrap(),
            n(p, "sequence").unwrap(),
            &pin,
            &s(p, "mode").unwrap(),
            Some(&ring),
        )
        .unwrap();
        assert_eq!(s(&op, "kind").unwrap(), "ADMIN");
        let missing = obj(vec![
            ("commit", commit.clone()),
            ("policy", policy.clone()),
            ("guard_time_attestations", W::Array(vec![])),
        ]);
        assert_eq!(
            verify_original_operation(
                &missing,
                &read_view::hash(commit).unwrap(),
                n(p, "sequence").unwrap(),
                &pin,
                &s(p, "mode").unwrap(),
                Some(&ring)
            )
            .err()
            .unwrap()
            .0,
            "AUTHOR_GUARD_TIME_INVALID"
        );
    }
}
