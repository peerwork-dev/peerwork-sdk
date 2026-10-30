//! Shared verified outcome codec for program, CLI and MCP projections.
use crate::{
    kernel_access::KernelPublicError,
    kernel_client::{KernelAcceptedResult, StructureIntentOutcome},
};
use serde_json::{json, Value};
pub(crate) fn native_error(e: crate::kernel_access::KernelAccessError) -> Value {
    let e = KernelPublicError::from(e);
    let mut out = json!({"state":"FAILED","code":e.code,"details":e.details});
    // These are typed, redacted native diagnostics, not an unverified server
    // body. Keep the original parent ID and known preparation/commit fact at
    // the same envelope level as successful native continuations.
    for field in [
        "command_id",
        "phase",
        "effect_certainty",
        "recovery",
        "server_code",
        "http_status",
    ] {
        if let Some(value) = out["details"].get(field).cloned() {
            out[field] = value;
        }
    }
    out
}
pub(crate) fn accepted(result: KernelAcceptedResult) -> Value {
    let state = result.outcome_state();
    json!({"state":state,"result":{"command_id":result.command_id,"workspace_id":result.workspace_id,
        "instance_id":result.instance_id,"protocol_digest":result.protocol_digest,"event_sequence":result.event_sequence,
        "revision":result.revision,"produced_record_ids":result.produced_record_ids,
        "structure":result.structure_result_json.and_then(|v|serde_json::from_str::<Value>(&v).ok()),
        "opened_contents":result.opened_contents,"opened_messages":result.opened_messages,"local_warnings":result.local_warnings,"key_history":result.key_history}})
}
pub(crate) fn outcome(out: StructureIntentOutcome) -> Value {
    match out {
        StructureIntentOutcome::Accepted(r) => accepted(r),
        StructureIntentOutcome::Completed { command_id, result } => {
            let mut out = accepted(result);
            out["state"] = json!("COMPLETED");
            out["command_id"] = json!(command_id);
            out
        }
        StructureIntentOutcome::Pending {
            command_id,
            code,
            phase,
            retryable,
            recovery,
        } => {
            json!({"state":"PENDING","command_id":command_id,"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"effect_certainty":if phase=="KEY_DELIVERY"{"COMMITTED"}else if phase=="PREPARATION"{"NOT_SUBMITTED"}else{"UNKNOWN"}})
        }
    }
}
