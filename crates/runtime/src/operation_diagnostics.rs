//! Safe, machine-readable observations. An HTTP refusal never proves that an
//! earlier transmission of the same operation was not accepted.
use peerwork_core::crypto::sha256_hex;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize)]
pub struct ServerRejection {
    pub http_status: u16,
    pub code: &'static str,
    pub constraint: &'static str,
    pub stage: &'static str,
    pub effect_certainty: &'static str,
    pub retryability: &'static str,
    pub response_digest: String,
}

impl ServerRejection {
    pub fn from_response(status: u16, body: &[u8]) -> Self {
        let value = if body.len() <= 16384 { serde_json::from_slice::<Value>(body).ok() } else { None };
        let remote = value.as_ref().and_then(|v| v.get("error"))
            .and_then(|v| v.get("code")).and_then(Value::as_str).unwrap_or("");
        let (code, constraint) = match remote {
            "SECURE_GUARD_TIME_REQUIRED" => ("SECURE_GUARD_TIME_REQUIRED", "guard_time.required"),
            "SECURE_GUARD_TIME_WINDOW_CLOSED" => ("SECURE_GUARD_TIME_WINDOW_CLOSED", "guard_time.window"),
            "SECURE_GUARD_TIME_UNSUPPORTED" => ("SECURE_GUARD_TIME_UNSUPPORTED", "guard_time.support"),
            "SECURE_GUARD_TIME_CLOCK_ROLLBACK" => ("SECURE_GUARD_TIME_CLOCK_ROLLBACK", "guard_time.clock"),
            "SECURE_GUARD_TIME_POLICY_IMMUTABLE" => ("SECURE_GUARD_TIME_POLICY_IMMUTABLE", "guard_time.policy"),
            "SECURE_COMMAND_CONFLICT" => ("SECURE_COMMAND_CONFLICT", "command.identity"),
            "SECURE_CHECKPOINT_CONFLICT" => ("SECURE_CHECKPOINT_CONFLICT", "checkpoint"),
            "SECURE_SEQUENCE_CONFLICT" => ("SECURE_SEQUENCE_CONFLICT", "checkpoint.sequence"),
            "SECURE_POLICY_CONFLICT" => ("SECURE_POLICY_CONFLICT", "policy"),
            "SECURE_AUTHOR_UNAUTHORIZED" => ("SECURE_AUTHOR_UNAUTHORIZED", "authorization"),
            "SECURE_WORKSPACE_NOT_FOUND" => ("SECURE_WORKSPACE_NOT_FOUND", "workspace.access"),
            "SECURE_WORKSPACE_UNAVAILABLE" => ("SECURE_WORKSPACE_UNAVAILABLE", "workspace.state"),
            "SECURE_WIRE_UPGRADE_REQUIRED" => ("SECURE_WIRE_UPGRADE_REQUIRED", "wire.version"),
            "SIGNATURE_INVALID" => ("SIGNATURE_INVALID", "signature"),
            "INVALID_PAYLOAD" => ("INVALID_PAYLOAD", "payload"),
            "FORBIDDEN" => ("FORBIDDEN", "authorization"),
            "NOT_FOUND" => ("NOT_FOUND", "resource.access"),
            "RATE_LIMITED" => ("RATE_LIMITED", "rate_limit"),
            _ => ("SERVER_REJECTED", "unclassified"),
        };
        Self { http_status: status, code, constraint, stage: "submit",
            effect_certainty: "unknown", retryability: "reconcile_only",
            response_digest: sha256_hex(body) }
    }
    pub fn envelope(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("fixed diagnostic serializes");
        value["schema"] = json!("peerwork.operation-error.v1");
        value["recovery_hints"] = json!([{"action":"recover","precondition":"same_saved_operation"}]);
        value
    }
}
impl std::fmt::Display for ServerRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.envelope())
    }
}
impl std::error::Error for ServerRejection {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejection_preserves_constraint_without_leaking_response_or_claiming_nonacceptance() {
        let d=ServerRejection::from_response(409, br#"{"error":{"code":"SECURE_GUARD_TIME_REQUIRED","message":"secret payload"}}"#);
        assert_eq!(d.code,"SECURE_GUARD_TIME_REQUIRED");
        assert_eq!(d.effect_certainty,"unknown");
        assert_eq!(d.retryability,"reconcile_only");
        assert!(!d.to_string().contains("secret payload"));
        let unknown=ServerRejection::from_response(409,br#"{"error":{"code":"PRIVATE_SECRET_VALUE"}}"#);
        assert_eq!(unknown.code,"SERVER_REJECTED");
        assert!(!unknown.to_string().contains("PRIVATE_SECRET_VALUE"));
    }
}
