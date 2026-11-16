use super::*;

#[tokio::test]
async fn missing_identity_returns_discovery_without_creating_a_setup() {
    let root=crate::test_support::protected_test_dir();
    let directory=root.path().join("local");
    drop(crate::participant_connect::Connect::open(&directory).unwrap());
    let before=std::fs::read(directory.join("connect.state")).ok();
    let tools=Lifecycle::local(directory.clone(),None,None);
    for intent in [json!({}),json!({"workspace_id":"W".repeat(43)})] {
        let request=AgentRequest::parse("connect",json!({"request":intent})).unwrap();
        let result=tools.call(request).await.unwrap();
        assert_eq!(result["state"],"PENDING");
        assert_eq!(result["blocker"]["code"],"LOCAL_SELECTION_REQUIRED");
        assert_eq!(result["discovery"]["candidates"],json!([]));
        assert!(result.get("setup_id").is_none());
        assert!(!result.to_string().contains(root.path().to_str().unwrap()));
    }
    assert_eq!(std::fs::read(directory.join("connect.state")).ok(),before);
}

#[tokio::test]
async fn discovery_does_not_mask_explicit_selection_resume_new_peer_or_scope_errors() {
    let root=crate::test_support::protected_test_dir();
    let directory=root.path().join("local");
    drop(crate::participant_connect::Connect::open(&directory).unwrap());
    for (participant,workspace,intent,expected) in [
        (None,None,json!({"participant":"missing"}),"LOCAL_SELECTION_REQUIRED"),
        (Some("missing"),None,json!({}),"LOCAL_SELECTION_REQUIRED"),
        (Some("pinned"),None,json!({"participant":"other"}),"FRONTEND_IDENTITY_PIN_MISMATCH"),
        (None,Some("W".repeat(43)),json!({"workspace_id":"X".repeat(43)}),"FRONTEND_WORKSPACE_PIN_MISMATCH"),
        (None,None,json!({"resume_setup_id":"missing"}),"SETUP_NOT_FOUND"),
        (None,None,json!({"new":true}),"NEW_PEER_LOCAL_OWNER_REQUIRED"),
    ] {
        let tools=Lifecycle::local(directory.clone(),participant.map(str::to_owned),workspace);
        let request=AgentRequest::parse("connect",json!({"request":intent})).unwrap();
        assert_eq!(tools.call(request).await.unwrap_err().code,expected);
    }
}
