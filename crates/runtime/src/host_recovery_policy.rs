//! Host failures are recovery facts, not new authority or input receipts.
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy { Retry, Observe, Change, Defer }
pub(crate) fn policy(code: &str) -> Policy {
    match code {
        "HOST_SESSION_OWNERSHIP_CONFLICT" | "HOST_SESSION_ALREADY_OWNED" | "HOST_SESSION_NOT_LOADED" => Policy::Observe,
        "HOST_WAITING_APPROVAL" | "HOST_BUSY" => Policy::Defer,
        "HOST_BINDING_MISMATCH" | "HOST_SESSION_BINDING_UNAVAILABLE" |
        "HOST_ACCESS_DENIED" | "HOST_AUTHENTICATION_FAILED" | "HOST_API_UNSUPPORTED" |
        "HOST_CONFIG_INVALID" | "HOST_ENDPOINT_INVALID" | "HOST_SELECTION_CONFLICT" | "CODEX_ROUTE_AMBIGUOUS" |
        "OPENCODE_SERVICE_INVALID" | "OPENCODE_SERVICE_SELECTION_REQUIRED" | "OPENCODE_SESSION_SELECTION_REQUIRED" |
        "OPENCODE_RESOURCE_NOT_FOUND" | "OPENCODE_SESSION_ARCHIVED" |
        "HOST_STATE_INVALID" | "HOST_BINDING_CHANGED_REQUIRES_REVIEW" |
        "HOST_SUBSCRIPTION_CONFLICT" | "HOST_CLIENT_BINDING_CHANGED" |
        "HOST_KIND_UNSUPPORTED" | "HOST_UNIX_ENDPOINT_UNSUPPORTED" |
        "CODEX_EXECUTABLE_REQUIRED" | "CODEX_EXECUTABLE_INVALID" |
        "CODEX_EXECUTABLE_UNTRUSTED" | "CODEX_HOME_INVALID" | "CODEX_HOME_REQUIRED" |
        "CODEX_HOST_USER_MISMATCH" | "ANTIGRAVITY_SIDECAR_REQUIRED" |
        "AGY_HOST_ENVIRONMENT_INVALID" | "AGY_HOST_ENVIRONMENT_UNAVAILABLE" |
        "CLAUDE_CHANNEL_SOURCE_ALREADY_BOUND_TO_ANOTHER_HOST" => Policy::Change,
        _ => Policy::Retry,
    }
}
pub(crate) fn action(code: &str) -> &'static str {
    match code {
        "BACKGROUND_NOTIFICATION_READ_PENDING" => "WAIT_FOR_CURRENT_SESSION_BATCH_READ",
        "BACKGROUND_LISTEN_NOT_ARMED" => "REARM_BACKGROUND_LISTENER_IN_CURRENT_SESSION",
        "HOST_SESSION_OWNERSHIP_CONFLICT" => "VERIFY_SELECTED_CODEX_ROUTE_AND_ORIGINAL_SESSION_OWNER",
        "HOST_SESSION_ALREADY_OWNED" => "REUSE_ORIGINAL_HOST_DISPATCHER",
        "HOST_SESSION_NOT_LOADED" => "LOAD_ORIGINAL_THREAD_ON_SELECTED_CODEX_ENDPOINT",
        "BRIDGE_UNAVAILABLE" => "RESTORE_ORIGINAL_BRIDGE",
        "CODEX_ROUTE_AMBIGUOUS" => "VERIFY_UNIQUE_CODEX_THREAD_OWNER",
        "HOST_API_UNSUPPORTED" => "UPDATE_OR_SELECT_SUPPORTED_ORIGINAL_HOST",
        "HOST_ACCESS_DENIED" | "HOST_AUTHENTICATION_FAILED" => "REPAIR_ORIGINAL_HOST_ACCESS",
        "CLAUDE_CHANNEL_SOURCE_ALREADY_BOUND_TO_ANOTHER_HOST" => "USE_SELECTED_HOST_OR_EXPLICIT_REBIND",
        _ => match policy(code) { Policy::Retry => "WAIT_FOR_SAME_TARGET_RECOVERY", Policy::Defer => "WAIT_FOR_ORIGINAL_HOST", _ => "REPAIR_SELECTED_HOST_CONFIGURATION" },
    }
}
pub(crate) fn delay(code: &str, attempt: u32, salt: &str) -> Duration {
    match policy(code) {
        Policy::Observe | Policy::Change => Duration::from_secs(60),
        _ => crate::communication_host::operation::retry_delay(attempt, salt),
    }
}
pub(crate) fn diagnostic(code: &str) -> Value {
    let mut value=json!({"code":code,"retry_policy":match policy(code) {Policy::Retry=>"SAME_TARGET_BACKOFF",Policy::Observe=>"OBSERVE_OWNER",Policy::Change=>"WAIT_FOR_CONFIGURATION_CHANGE",Policy::Defer=>"WAIT_FOR_HOST"},"next_action":action(code)});
    if code=="HOST_SESSION_OWNERSHIP_CONFLICT" {
        value["owner_identity"]=json!("NOT_DETERMINED");
        value["exit_required"]=json!("NOT_DETERMINED");
        value["automatic_second_writer"]=json!(false);
        value["handover"]=json!("ONLY_AFTER_CONFIRMING_UNSUPPORTED_STANDALONE_OWNER");
    }
    value
}
/// A notification wait observes the original receiver; it does not reset or
/// authorize its stream. An actual quarantine must remain visible.
pub(crate) fn notification_wait_retry(error: &crate::participant::ParticipantError) -> bool {
    match error.code.as_str() {
        "NOTIFICATION_RECEIVER_PARTIALLY_AVAILABLE" | "RUNTIME_UNAVAILABLE" | "IPC_DISCONNECTED" | "IPC_OBSERVATION_TIMEOUT"
        | "IPC_HANDSHAKE_TIMEOUT" | "IPC_WRITE_TIMEOUT" | "PRESENTATION_REBIND_PENDING" => true,
        "CLAUDE_CHANNEL_ALREADY_ACTIVE_OR_STATE_UNAVAILABLE" => error.details.as_ref()
            .is_some_and(|detail| detail["local_state"]["cause"] == "BUSY"),
        "NOTIFICATION_RECEIVER_NOT_VERIFIED" => error.details.as_ref().is_none_or(|detail| {
            let fault = &detail["verification_failure"];
            if !fault.is_null() {
                return fault["code"] == "STREAM_TIME_WINDOW_INVALID"
                    && fault["phase"] == "FRAME_VERIFICATION"
                    && fault["scope_authenticated"] == true;
            }
            !matches!(detail["state"].as_str(), Some("BLOCKED" | "LOCAL_STOPPED" | "PAUSED"))
                || detail["state"] == "BLOCKED" && matches!(detail["code"].as_str(),
                    Some("RESOURCE_EXHAUSTED" | "CAPACITY_RESERVATION_EXHAUSTED" | "KEY_SYNC_TIMEOUT"))
        }),
        _ => false,
    }
}

/// Structured host categories win; bounded legacy text is classified locally
/// and discarded. Never retain arbitrary host errors, paths, prompts or tokens.
pub(crate) fn rpc_error(value: &Value) -> &'static str {
    let category=value["data"]["type"].as_str().or_else(||value["data"]["code"].as_str()).unwrap_or("");
    if matches!(category,"activeWriter"|"active_writer"|"threadAlreadyActive"|"sessionAlreadyOwned"|"ACTIVE_WRITER") {return "HOST_SESSION_OWNERSHIP_CONFLICT";}
    if matches!(category,"unauthorized"|"authenticationFailed"|"UNAUTHORIZED") {return "HOST_AUTHENTICATION_FAILED";}
    if value["code"]==-32601 {return "HOST_API_UNSUPPORTED";}
    if let Some(message)=value["message"].as_str().filter(|s|s.len()<=4096) {
        let message=message.to_ascii_lowercase();
        if message.contains("active writer") || message.contains("active_writer") || message.contains("another process holds") && message.contains("session") {return "HOST_SESSION_OWNERSHIP_CONFLICT";}
    }
    "HOST_RPC_REJECTED"
}

#[cfg(test)] mod tests {
    use super::*;
    #[test]
    fn waiting_does_not_treat_invalid_evidence_or_revocation_as_transient() {
        let mut error = crate::participant::ParticipantError::local("NOTIFICATION_RECEIVER_NOT_VERIFIED", "LOCAL_IPC");
        for detail in [
            json!({"state":"BLOCKED","code":"MEMBER_REVOKED"}),
            json!({"state":"BLOCKED","verification_failure":{"code":"STREAM_SIGNATURE_INVALID"}}),
            json!({"state":"BLOCKED","verification_failure":{"code":"STREAM_TIME_WINDOW_INVALID",
                "phase":"FRAME_VERIFICATION","scope_authenticated":false}}),
            json!({"state":"LOCAL_STOPPED"}),
        ] {
            error.details = Some(detail);
            assert!(!notification_wait_retry(&error));
        }
        error.details = Some(json!({"state":"RECONNECTING","code":"RESOURCE_EXHAUSTED"}));
        assert!(notification_wait_retry(&error));
    }
    #[test] fn ownership_and_unsupported_api_are_not_transport_retries() {
        assert_eq!(rpc_error(&json!({"code":-32600,"message":"session has an active writer: SECRET"})),"HOST_SESSION_OWNERSHIP_CONFLICT");
        assert_eq!(rpc_error(&json!({"code":-32600,"data":{"type":"activeWriter"}})),"HOST_SESSION_OWNERSHIP_CONFLICT");
        assert_eq!(rpc_error(&json!({"code":-32601})),"HOST_API_UNSUPPORTED");
        assert_eq!(rpc_error(&json!({"code":-32000,"message":"unknown SECRET"})),"HOST_RPC_REJECTED");
        assert_eq!(policy("HOST_SESSION_OWNERSHIP_CONFLICT"),Policy::Observe);
        assert_eq!(policy("HOST_API_UNSUPPORTED"),Policy::Change);
        assert_eq!(policy("HOST_OPERATION_TIMEOUT"),Policy::Retry);
        assert_eq!(delay("CLAUDE_CHANNEL_SOURCE_ALREADY_BOUND_TO_ANOTHER_HOST",1,"selected"),Duration::from_secs(60));
        assert_eq!(delay("CLAUDE_CHANNEL_SOURCE_ALREADY_BOUND_TO_ANOTHER_HOST",50,"selected"),Duration::from_secs(60));
        assert!(!diagnostic("HOST_API_UNSUPPORTED").to_string().contains("SECRET"));
    }
}
