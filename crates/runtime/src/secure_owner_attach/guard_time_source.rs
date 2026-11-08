//! Legacy completed-operation caches are evidence candidates, never authority.
use super::*;

fn invalid() -> HistoricalOwnerAttachError { HistoricalOwnerAttachError::GuardTimeInvalid }
fn wire(value: &WireValue) -> Result<String, HistoricalOwnerAttachError> {
    canonical_wire_value(value, CanonicalPath::SecureArtifact).map_err(|_| invalid())
}
fn text(value: &WireValue, key: &str) -> Result<String, HistoricalOwnerAttachError> {
    value.get(key).and_then(WireValue::as_string).ok_or_else(invalid)
}
fn map(value: Option<&WireValue>) -> Result<&[(Vec<u16>, WireValue)], HistoricalOwnerAttachError> {
    match value { None => Ok(&[]), Some(WireValue::Object(rows)) => Ok(rows), _ => Err(invalid()) }
}

pub(super) fn parse(root: &WireValue, input: &HistoricalOwnerAttachInput)
    -> Result<Vec<Zeroizing<Vec<u8>>>, HistoricalOwnerAttachError> {
    if !map(root.get("guard_time_post_responses"))?.is_empty() {
        return Err(HistoricalOwnerAttachError::GuardTimePending);
    }
    let mut result = Vec::new();
    let rows = map(root.get("guard_time_action_intents"))?;
    if rows.len() > MAX_HISTORY { return Err(HistoricalOwnerAttachError::ResourceLimit); }
    for (key, row) in rows {
        let workspace = text(row, "workspace_id")?;
        let operation = text(row, "operation_id")?;
        if workspace != input.workspace_id || !valid_token(&operation)
            || String::from_utf16(key).map_err(|_| invalid())?
                != serde_json::to_string(&[&workspace, &operation]).map_err(|_| invalid())?
            || text(row, "actor_id")? != input.expected_owner_actor_id {
            return Err(invalid());
        }
        match text(row, "status")?.as_str() {
            "CONFIRMED" => (),
            "PREPARING" | "PREPARED" | "ACCEPTED" =>
                return Err(HistoricalOwnerAttachError::GuardTimePending),
            _ => return Err(invalid()),
        }
        let required = ["workspace_id", "operation_id", "actor_id", "action_id", "instance_id",
            "body", "exact_refs", "input_hash", "status", "source", "policy", "command_id",
            "path", "request", "commit", "proof", "result_checkpoint"];
        let WireValue::Object(fields) = row else { return Err(invalid()); };
        if required.iter().any(|name| row.get(name).is_none()) || fields.iter().any(|(key, _)| {
            !required.iter().chain(std::iter::once(&"response"))
                .any(|name| key.iter().copied().eq(name.encode_utf16()))
        }) { return Err(invalid()); }
        let identity = WireValue::Object(["workspace_id", "operation_id", "actor_id", "action_id",
            "instance_id", "body", "exact_refs"].iter().map(|name|
            (name.encode_utf16().collect(), row.get(name).unwrap().clone())).collect());
        if text(row, "input_hash")? != sha256_hex(wire(&identity)?.as_bytes())
            || !valid_token(&text(row, "command_id")?)
            || !valid_token(&text(row, "instance_id")?)
            || text(row, "path")? != format!("/api/workspace/v1/secure/workspaces/{workspace}/commits")
            || row.get("request").and_then(WireValue::object_len) != Some(1)
            || row.get("request").and_then(|v| v.get("commit")) != row.get("commit") {
            return Err(invalid());
        }
        result.push(Zeroizing::new(wire(row)?.into_bytes()));
    }
    Ok(result)
}

pub(super) fn verify(rows: &[Zeroizing<Vec<u8>>], replayed: &TransportReplayedJournal,
    input: &HistoricalOwnerAttachInput) -> Result<(), HistoricalOwnerAttachError> {
    if rows.is_empty() { return Ok(()); }
    let proofs: std::collections::BTreeSet<&[u8]> = replayed.guard_time_attestations()
        .iter().map(Vec::as_slice).collect();
    for saved in rows {
        let mut row = parse_wire_json_bounded(saved, 48, MAX_SOURCE).map_err(|_| invalid())?;
        let result = (|| {
            let commit = row.get("commit").ok_or_else(invalid)?;
            let payload = commit.get("payload").ok_or_else(invalid)?;
            let sequence = exact_u64(payload.get("sequence")).ok_or_else(invalid)?;
            let index = usize::try_from(sequence.checked_sub(1).ok_or_else(invalid)?).map_err(|_| invalid())?;
            let signed = replayed.signed_commit_wires().get(index).ok_or_else(invalid)?;
            if wire(commit)?.as_bytes() != signed.as_slice()
                || text(payload, "workspace_id")? != input.workspace_id
                || text(payload, "actor_id")? != input.expected_owner_actor_id
                || text(payload, "signing_key")? != input.expected_owner_key_id
                || text(payload, "command_id")? != text(&row, "command_id")?
                || text(payload, "action_id")? != text(&row, "action_id")?
                || text(payload, "instance_id")? != text(&row, "instance_id")? {
                return Err(invalid());
            }
            let policy_hash = text(payload, "policy_hash")?;
            let policy = replayed.signed_policy_by_hash(&policy_hash).ok_or_else(invalid)?;
            if wire(row.get("policy").ok_or_else(invalid)?)?.as_bytes() != policy {
                return Err(invalid());
            }
            let operation = replayed.replay().operations().get(index).ok_or_else(invalid)?;
            let action = operation.get("input").ok_or_else(invalid)?;
            if action.get("body") != row.get("body") || action.get("exact_input_refs") != row.get("exact_refs") {
                return Err(invalid());
            }
            let proof = row.get("proof").ok_or_else(invalid)?;
            let proof_wire = wire(proof)?;
            if !proofs.contains(proof_wire.as_bytes()) {
                return Err(invalid());
            }
            let fact = proof.get("payload").ok_or_else(invalid)?;
            if text(fact, "command_id")? != text(&row, "command_id")?
                || text(fact, "commit_hash")? != sha256_hex(signed)
                || fact.get("source") != row.get("source")
                || fact.get("result") != row.get("result_checkpoint") {
                return Err(invalid());
            }
            Ok(())
        })();
        scrub(&mut row);
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_guard_caches_are_not_unresolved_and_malformed_caches_refuse() {
        let input = HistoricalOwnerAttachInput {
            workspace_id: "w".repeat(43), protected_ts_state_path: "/selected/state".into(),
            protected_owner_pkcs8_path: "/selected/key".into(), protected_ts_intent_db_path: "/selected/intents".into(),
            expected_owner_actor_id: "a".repeat(43), expected_owner_key_id: "k".repeat(43),
            recover_pending_action: false, retain_pending_action_command_id: None,
            selected_pending_package_stage_command_id: None, selected_orphan_package_stage_command_id: None,
            expected_ts_state_digest: None, kernel_pending_command_ids: Vec::new(), expected_kernel_intent_db_digest: None,
        };
        for bytes in [b"{}".as_slice(), br#"{"guard_time_action_intents":{},"guard_time_post_responses":{}}"#] {
            assert!(parse(&parse_wire_json_bounded(bytes, 8, 1024).unwrap(), &input).unwrap().is_empty());
        }
        for bytes in [br#"{"guard_time_action_intents":[]}"#.as_slice(), br#"{"guard_time_post_responses":null}"#] {
            assert!(matches!(parse(&parse_wire_json_bounded(bytes, 8, 1024).unwrap(), &input), Err(HistoricalOwnerAttachError::GuardTimeInvalid)));
        }
        let pending = parse_wire_json_bounded(br#"{"guard_time_post_responses":{"saved":{}}}"#, 8, 1024).unwrap();
        assert!(matches!(parse(&pending, &input), Err(HistoricalOwnerAttachError::GuardTimePending)));
    }
}
