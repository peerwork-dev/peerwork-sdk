//! The public runtime has exactly one online workspace execution contract.
//! Historical cryptographic primitives remain usable for explicit offline work.
pub const RETIRED_CODE:&str="LEGACY_MODE_RETIRED";
pub const RETIRED_MESSAGE:&str="legacy execution is retired; use backend-structure-v1 with an explicit new Context";

pub fn supports_kernel_operation(operation:&str)->bool{
    matches!(operation,"open"|"prepare"|"status"|"pending"|"pending_page"|"build_pending_index"
        |"publish_selected_record"|"coordinate_content_keys"|"rotate_content_key"|"ensure_local_content_key"|"request_access"|"authorize_access"|"accept_content_keys"|"submit_saved"|"execute_structure_intent"|"resume_structure_intent")
}

pub fn retired_json()->String{
    serde_json::json!({"ok":false,"code":RETIRED_CODE,"message":RETIRED_MESSAGE,
        "required_execution_profile":peerwork_core::structure_execution::PROFILE,"retryable":false}).to_string()
}

pub fn supports_command(value:&peerwork_core::wire_json::WireValue)->bool{
    use peerwork_core::{structure_execution::{is_structure_action,PROFILE},wire_json::WireValue};
    value.get("path").and_then(WireValue::as_string).as_deref()==Some("/api/workspace/v1/commands")
        &&value.get("action_id").and_then(WireValue::as_string).is_some_and(|a|is_structure_action(&a))
        &&value.get("body").and_then(|b|b.get("profile")).and_then(WireValue::as_string).as_deref()==Some(PROFILE)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn only_the_signed_current_contract_is_supported(){
        let parse=|v:serde_json::Value|peerwork_core::wire_json::parse_wire_json_bounded(v.to_string().as_bytes(),40,180_000).unwrap();
        let mut value=serde_json::json!({"path":"/api/workspace/v1/commands","action_id":"structure.record.get","body":{"profile":"backend-structure-v1"}});
        assert!(supports_command(&parse(value.clone())));
        for action in ["workspace.create","workspace.delete","identity.register","secure.action","claim"]{
            value["action_id"]=serde_json::json!(action);assert!(!supports_command(&parse(value.clone())));
        }
        value["action_id"]=serde_json::json!("structure.record.get");value["body"]["profile"]=serde_json::json!("legacy");
        assert!(!supports_command(&parse(value)));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&retired_json()).unwrap()["code"],RETIRED_CODE);
    }
}
