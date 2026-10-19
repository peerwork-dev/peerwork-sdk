use super::*;
fn config(path: &Path) -> SecureReadProfileConfig {
    SecureReadProfileConfig {
        transport: Default::default(),
        origin: "https://invalid.example/".into(),
        state_dir: path.to_owned(),
        identity_path: path.join("identity.state"),
        workspace_id: base64url(&[7u8; 32]),
        owner_actor_id: Some(base64url(&[8u8; 32])),
        owner_key_id: Some(base64url(&[9u8; 32])),
        authority: None,
        required_features: vec![],
        allow_loopback_http: false,
        max_replay_artifact_bytes: 64 * 1024 * 1024,
        max_replay_commits: 102400,
    }
}
#[test]
fn missing_operation_queries_do_not_create_state_and_context_is_bound() {
    let dir = crate::test_support::protected_test_dir();
    let config = config(dir.path());
    KernelIdentity::create(&config.identity_path).unwrap();
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    assert!(!has_operation(config.clone(), "fp", Some("op"), None).unwrap());
    assert_eq!(operations(config.clone(), "fp").unwrap(), json!([]));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
    let (store, doc) = load(&config, "fp", true).unwrap().unwrap();
    persist(&store, &doc).unwrap();
    drop(store);
    assert!(matches!(
        operations(config, "changed"),
        Err(BrowserApprovalRuntimeError::Context)
    ));
}
#[test]
fn saved_cancelled_recovery_and_listing_never_release_secret() {
    let dir = crate::test_support::protected_test_dir();
    let config = config(dir.path());
    KernelIdentity::create(&config.identity_path).unwrap();
    let secret = base64url(&[42u8; 32]);
    let (store, mut doc) = load(&config, "fp", true).unwrap().unwrap();
    doc.rows.insert(
        "stable-op".into(),
        Row {
            reference: "saved-ref".into(),
            approve_writes: false,
            command_id: base64url(&[3u8; 32]),
            request_id: base64url(&[4u8; 32]),
            body: "{}".into(),
            code: secret.clone(),
            command: "{}".into(),
            expires_at: 1,
            request_expires_at: 1,
            accepted_observed: false,
        },
    );
    persist(&store, &doc).unwrap();
    drop(store);
    assert!(has_operation(config.clone(), "fp", Some("stable-op"), None).unwrap());
    assert!(has_operation(config.clone(), "fp", None, Some(&base64url(&[3u8; 32]))).unwrap());
    let list = operations(config.clone(), "fp").unwrap();
    assert!(!list.to_string().contains(&secret));
    let (store, mut doc) = load(&config, "fp", false).unwrap().unwrap();
    doc.rows.get_mut("stable-op").unwrap().accepted_observed = true;
    persist(&store, &doc).unwrap();
    drop(store);
    assert_eq!(operations(config.clone(), "fp").unwrap(), json!([]));
    // A local observed marker cannot authorize secret release on recovery.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = recover(config, "fp", Some("stable-op"), None, &cancel).unwrap();
    assert_eq!(result["status"], "PENDING");
    assert_eq!(result["reason"], "CANCELLED");
    assert!(result.get("approval_code").is_none());
    assert!(!result.to_string().contains(&secret));
}
#[test]
fn wrong_workspace_reference_fails_before_state_creation() {
    let dir = crate::test_support::protected_test_dir();
    let config = config(dir.path());
    KernelIdentity::create(&config.identity_path).unwrap();
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    let reference = format!(
        "peerwork-browser-approval:v1:{}:{}:{}",
        base64url(&[1u8; 32]),
        base64url(&[2u8; 32]),
        "a".repeat(64)
    );
    assert!(matches!(
        approve(
            config,
            "fp",
            &reference,
            false,
            "op",
            &CancellationToken::new()
        ),
        Err(BrowserApprovalRuntimeError::Context)
    ));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
}
