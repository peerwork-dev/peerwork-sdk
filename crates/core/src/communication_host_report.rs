//! Independent receiver-signature verification after the service receipt.
use super::*;
pub(super) fn verify(
    value: &WireValue,
    audience: &[u16],
    workspace: &str,
    actor: &str,
) -> Result<()> {
    if text(value, "assurance")? != "SERVICE_RECORDED_RECEIVER_ATTESTATION"
        || text(value, "model_response")? != "NOT_ATTESTED"
    {
        return Err(CommunicationError);
    }
    let author = crate::prepared_command::verify_host_report_intent(
        &text(value, "author_intent")?,
        audience,
    )
    .map_err(|_| CommunicationError)?;
    if author.actor_id() != actor || author.workspace_id() != Some(workspace) {
        return Err(CommunicationError);
    }
    let command = author.command();
    if !matches!(command.get("instance_id"), Some(WireValue::Null))
        || !matches!(command.get("protocol_digest"), Some(WireValue::Null))
    {
        return Err(CommunicationError);
    }
    let body = command.get("body").ok_or(CommunicationError)?;
    let report = body.get("report").ok_or(CommunicationError)?;
    for key in [
        "call_id",
        "attempt",
        "scope",
        "frame_digest",
        "state",
        "facts",
        "report_sequence",
    ] {
        if value.get(key) != report.get(key) {
            return Err(CommunicationError);
        }
    }
    let scope = report.get("scope").ok_or(CommunicationError)?;
    if text(scope, "workspace_id")? != workspace
        || scope.get("mailbox_id") != body.get("mailbox_id")
        || scope.get("call_id") != report.get("call_id")
        || scope.get("frame_digest") != report.get("frame_digest")
        || scope.get("sequence") != report.get("sequence")
        || scope.get("delivery_id") != report.get("delivery_id")
    {
        return Err(CommunicationError);
    }
    token_field(scope, "membership_id")?;
    token_field(scope, "receiver_id")?;
    if number(scope, "epoch")? > number(body, "epoch")?
        || number(report, "attempt")? == 0
        || number(report, "attempt")? > 32
        || number(report, "report_sequence")? == 0
    {
        return Err(CommunicationError);
    }
    let facts = array(report, "facts", 3)?;
    let mut states = std::collections::BTreeSet::new();
    for fact in facts {
        let state = text(fact, "state")?;
        if !states.insert(state.clone()) {
            return Err(CommunicationError);
        }
        match state.as_str() {
            "HOST_QUEUED" | "HOST_ACCEPTED" => {
                let receipt = text(fact, "receipt")?;
                if receipt.is_empty() || receipt.len() > 8192 {
                    return Err(CommunicationError);
                }
            }
            "NOT_SENT" => {
                if !matches!(
                    text(fact, "proof")?.as_str(),
                    "LOCAL_PREFLIGHT_NO_IO" | "PROCESS_NOT_STARTED" | "BOUND_HOST_RECONCILIATION"
                ) {
                    return Err(CommunicationError);
                }
                text(fact, "code")?;
            }
            "RESULT_UNKNOWN" => {
                text(fact, "code")?;
            }
            _ => return Err(CommunicationError),
        }
    }
    let state = text(report, "state")?;
    let expected = if states.contains("HOST_ACCEPTED") {
        "HOST_ACCEPTED"
    } else if states.contains("HOST_QUEUED") {
        "HOST_QUEUED"
    } else if states.contains("NOT_SENT") {
        "NOT_SENT"
    } else if states.contains("RESULT_UNKNOWN") {
        "RESULT_UNKNOWN"
    } else if matches!(state.as_str(), "CALL_OPEN" | "RESULT_UNKNOWN") {
        state.as_str()
    } else {
        return Err(CommunicationError);
    };
    if state != expected || states.contains("NOT_SENT") && (states.contains("HOST_QUEUED") || states.contains("HOST_ACCEPTED")) {
        return Err(CommunicationError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::{json, Value};
    fn wire(value: &Value) -> WireValue {
        parse_wire_json_bounded(value.to_string().as_bytes(), 40, 180000).unwrap()
    }
    #[test]
    fn report_signature_cannot_be_reused_as_business_evidence_or_a_different_delivery() {
        let key = SigningKey::from_bytes(&[53; 32]);
        let actor = crate::crypto::actor_id(&key.verifying_key().to_bytes());
        let audience = "host-report-test".encode_utf16().collect::<Vec<_>>();
        let ws = "W".repeat(43);
        let mailbox = "M".repeat(43);
        let call = "C".repeat(43);
        let scope = json!({"format":"peerwork.host-call.v1","owner":"synthetic-root","namespace":"program:worker","workspace_id":ws,"mailbox_id":mailbox,"membership_id":"G".repeat(43),"sequence":1,"delivery_id":"D".repeat(43),"receiver_id":"R".repeat(43),"epoch":2,"binding_version":1,"destination_digest":"d".repeat(64),"call_id":call,"frame_digest":"e".repeat(64),"source_digest":"f".repeat(64)});
        let report = json!({"sequence":1,"delivery_id":"D".repeat(43),"call_id":call,"attempt":1,"scope":scope,"frame_digest":"e".repeat(64),"state":"HOST_ACCEPTED","facts":[{"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"},{"state":"HOST_ACCEPTED","receipt":"selected-turn"}],"report_sequence":3});
        let command = json!({"v":1,"audience":"host-report-test","actor_id":actor,"command_id":"I".repeat(43),"authority":sha256_hex(actor.as_bytes()),"method":"POST","path":"/api/workspace/v1/commands","action_id":"structure.mailbox.report","workspace_id":ws,"instance_id":null,"protocol_digest":null,"expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"issued_at":1,"expires_at":600001,"body":{"profile":"backend-structure-v1","mailbox_id":mailbox,"receiver_id":"R".repeat(43),"epoch":2,"report":report}});
        let jws=crate::crypto::sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":crate::crypto::key_id(&key.verifying_key().to_bytes())}),&command,&key).unwrap();
        let mut snapshot = report;
        snapshot["author_intent"] = json!(jws);
        snapshot["assurance"] = json!("SERVICE_RECORDED_RECEIVER_ATTESTATION");
        snapshot["model_response"] = json!("NOT_ATTESTED");
        assert!(verify(&wire(&snapshot), &audience, &ws, &actor).is_ok());
        assert!(
            crate::prepared_command::verify_structure_author_intent(&jws, &audience).is_err(),
            "control reports never qualify as business intent"
        );
        assert!(verify(&wire(&snapshot), &audience, &ws, &"A".repeat(43)).is_err());
        assert!(verify(&wire(&snapshot), &audience, &"Z".repeat(43), &actor).is_err());
        let mut forged = snapshot.clone();
        forged["scope"]["delivery_id"] = json!("Z".repeat(43));
        assert!(verify(&wire(&forged), &audience, &ws, &actor).is_err());
        let mut forged = snapshot.clone();
        forged["facts"][1]["receipt"] = json!("different-turn");
        assert!(verify(&wire(&forged), &audience, &ws, &actor).is_err());
        let mut forged = snapshot;
        forged["model_response"] = json!("MODEL_REPLIED");
        assert!(verify(&wire(&forged), &audience, &ws, &actor).is_err());
    }
}
