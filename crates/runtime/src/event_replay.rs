//! Helpers for verified `structure.events.read` results. No durable cursor state.
use crate::participant::{ParticipantError, Result};
use serde_json::{json, Value};

/// Build the next business-event request after applying all directory pages in
/// any `presence_reset`. Use only a result returned by `ParticipantClient::request`
/// (which verifies its signed receipt), in the same selected Workspace.
///
/// Complete `presence_reset.snapshot_request` and its directory continuations
/// before calling this helper or persisting the new presence checkpoint. The
/// reset's `resume.after_sequence` is presence-only and must never replace the
/// business cursor/checkpoint. Keep the original command/operation recovery
/// authority for requests whose outcome is unknown.
pub fn next_body_after_snapshot(request_body: &Value, verified_result: &Value) -> Result<Value> {
    let invalid=||ParticipantError::local("EVENT_REPLAY_CONTINUATION_INVALID","EVENT_REPLAY");
    if !matches!(verified_result["state"].as_str(),Some("ACCEPTED"|"COMPLETED")) {return Err(invalid());}
    let verified_result=&verified_result["result"]["structure"];
    let mut body=request_body.as_object().cloned().ok_or_else(invalid)?;
    if body.get("presence_replay")!=Some(&json!("SNAPSHOT_V1")) {return Err(invalid());}
    let checkpoint=verified_result["checkpoint"].as_u64().filter(|n|*n<=9_007_199_254_740_991).ok_or_else(invalid)?;
    let upper=verified_result["frontier"]["upper_sequence"].as_u64().ok_or_else(invalid)?;
    if checkpoint>upper {return Err(invalid());}
    body.remove("cursor");body.remove("after_sequence");
    match verified_result.get("next_cursor") {
        Some(Value::Null) if checkpoint==upper=>{body.insert("after_sequence".into(),json!(checkpoint));},
        Some(Value::String(cursor)) if !cursor.is_empty()=>{body.insert("cursor".into(),json!(cursor));},
        _=>return Err(invalid()),
    }
    if let Some(value)=verified_result["frontier"].get("presence_snapshot_checkpoint") {
        let snapshot=value.as_u64().filter(|n|*n<=9_007_199_254_740_991).ok_or_else(invalid)?;
        if request_body["presence_checkpoint"].as_u64().is_some_and(|old|old>snapshot) {return Err(invalid());}
        body.insert("presence_checkpoint".into(),json!(snapshot));
    }
    Ok(Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_checkpoint_never_advances_the_business_cursor() {
        let request=json!({"profile":"backend-structure-v1","presence_replay":"SNAPSHOT_V1","after_sequence":3,"limit":8});
        let mut response=json!({"checkpoint":12,"frontier":{"upper_sequence":50,"presence_snapshot_checkpoint":100},
            "next_cursor":"original-business-page-2","presence_reset":{"resume":{"after_sequence":100}}});
        let verified=|result:&Value|json!({"state":"ACCEPTED","result":{"structure":result}});
        let next=next_body_after_snapshot(&request,&verified(&response)).unwrap();
        assert_eq!(next["cursor"],"original-business-page-2");assert!(next.get("after_sequence").is_none());
        assert_eq!(next["presence_checkpoint"],100);assert_eq!(next["limit"],8);
        response["checkpoint"]=json!(50);response["next_cursor"]=Value::Null;
        let next=next_body_after_snapshot(&next,&verified(&response)).unwrap();
        assert_eq!(next["after_sequence"],50);assert!(next.get("cursor").is_none());
        assert_eq!(next["presence_checkpoint"],100);
        response["checkpoint"]=json!(100);assert!(next_body_after_snapshot(&next,&verified(&response)).is_err());
    }
}
