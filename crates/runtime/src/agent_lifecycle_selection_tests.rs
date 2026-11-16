use super::*;

#[cfg(unix)]
#[test]
fn selected_registry_reuses_original_handle_reads_latest_and_recovers_in_place() {
    use std::os::unix::fs::PermissionsExt;
    let root=crate::test_support::protected_test_dir();let shared=root.path().join("shared");
    std::fs::create_dir(&shared).unwrap();std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o755)).unwrap();
    let directory=shared.join("original");std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700)).unwrap();
    let snapshot=|path:&std::path::Path,handle:&str| {
        let state=json!({"participants":{(handle):{"origin":"https://example.invalid/","actor_id":"A".repeat(43),"endpoint_path":path.join("endpoint.json")}},"setups":{},"active":null});
        let bytes=crate::secure_state::SecureStateStore::snapshot_wire(&serde_json::to_vec(&state).unwrap()).unwrap();
        let stage=path.join("fixture-stage");std::fs::write(&stage,&bytes).unwrap();
        std::fs::set_permissions(&stage,std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(stage,path.join("connect.state")).unwrap();bytes
    };
    snapshot(&directory,"first");std::fs::write(directory.join("pending-original"),b"keep original command ID").unwrap();
    let lifecycle=Lifecycle::local(directory.clone(),None,None);
    assert!(lifecycle.inspect(&directory).unwrap().participant_identity("first").is_some());
    // The established private component is unchanged. A shared project mode
    // change must not force unrelated association/XDG onboarding on each read.
    std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(crate::participant_connect::Connect::inspect(&directory).is_err());
    assert!(lifecycle.inspect(&directory).unwrap().participant_identity("first").is_some());
    let original=snapshot(&directory,"second");
    assert!(lifecycle.inspect(&directory).unwrap().participant_identity("second").is_some());
    std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o775)).unwrap();
    let denied=lifecycle.inspect(&directory).err().unwrap();assert_eq!(denied.code,"ONBOARDING_PATH_UNSAFE");
    assert_eq!(denied.details.unwrap()["local_diagnostic"]["reason"],"CONFIGURATION_PERMISSIONS");
    std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(lifecycle.inspect(&directory).unwrap().participant_identity("second").is_some());
    let moved=shared.join("preserved-original");std::fs::rename(&directory,&moved).unwrap();
    std::fs::create_dir(&directory).unwrap();std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700)).unwrap();snapshot(&directory,"substitute");
    let changed=lifecycle.inspect(&directory).err().unwrap();
    assert_eq!(changed.details.unwrap()["local_diagnostic"]["reason"],"PATH_CHANGED");
    assert_eq!(std::fs::read(moved.join("connect.state")).unwrap(),original);
    assert_eq!(std::fs::read(moved.join("pending-original")).unwrap(),b"keep original command ID");
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn path_diagnostics_survive_async_propagation_without_path_or_payload_in_rpc() {
    let root=crate::test_support::protected_test_dir();let path=root.path().join("original-component");let expected=path.clone();
    let error=tokio::spawn(async move {
        let error=crate::onboarding_files::path_error(&path,"PRIVATE_STATE","OPEN","PERMISSION_DENIED");
        tokio::task::yield_now().await;error
    }).await.unwrap();
    assert_eq!(error.recovery,"ORIGINAL_LOCAL_OWNER_REPAIR_REQUIRED");
    assert_eq!(error.local_diagnostic.as_ref().unwrap()["component"],expected.to_str().unwrap());
    let wire=serde_json::to_value(&error).unwrap();
    assert!(wire.get("local_diagnostic").is_none());
    assert_eq!(wire["details"]["local_diagnostic"]["reason"],"PERMISSION_DENIED");
    assert!(!wire.to_string().contains(root.path().to_str().unwrap()));
}

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
