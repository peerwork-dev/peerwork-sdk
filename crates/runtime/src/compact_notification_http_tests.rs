//! Offline frontend/native-routing checks. No HTTP server or model is started;
//! resident delivery success and authenticated host wake are separate gates.
use crate::{
    agent_lifecycle::Lifecycle,
    agent_tools::{AgentRequest, AgentSelection, AgentTools},
    kernel_identity::KernelIdentity,
    participant::{Capability, ParticipantClient, ParticipantConfig},
};
use serde_json::json;

#[tokio::test]
async fn compact_tools_reach_native_delivery_boundary_without_replacing_attached_identity() {
    let directory = crate::test_support::protected_test_dir();
    let identity_path = directory.path().join("identity");
    let identity = KernelIdentity::create(&identity_path).unwrap();
    let mut config = ParticipantConfig::new(
        "http://127.0.0.1:1/",
        identity.actor_id(),
        identity_path,
        directory.path().join("engine"),
    );
    config.allow_loopback_http = true;
    config.transport.request_timeout_ms = 100;
    let owner = ParticipantClient::open(config).await.unwrap();
    let original = owner
        .restrict("original-notification-client", Capability::owner())
        .unwrap();
    let tools =
        AgentTools::from_client(original.clone(), AgentSelection::for_client(&original)).unwrap();
    let lifecycle = Lifecycle::attached(tools);
    for (tool, args) in [
        (
            "inbox",
            json!({"batch":"synthetic-original-batch","limit":8,"max_bytes":16384}),
        ),
        ("delivery", json!({"mode":"self_test"})),
    ] {
        let error = lifecycle
            .call(AgentRequest::parse(tool, args).unwrap())
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            "RESIDENT_RUNTIME_REQUIRED_FOR_AUTOMATIC_DELIVERY"
        );
    }
    for args in [
        json!({}),
        json!({"view":"active","limit":1,"max_bytes":2048}),
        json!({"after":0}),
    ] {
        let page = lifecycle
            .call(AgentRequest::parse("inbox", args).unwrap())
            .await
            .unwrap();
        assert!(page["items"].as_array().unwrap().is_empty());
        assert_ne!(page["state"], "SELF_TEST_OBSERVED");
    }
    let status = lifecycle
        .call(AgentRequest::parse("delivery", json!({"mode":"status"})).unwrap())
        .await
        .unwrap();
    assert_eq!(status["state"], "NO_AUTOMATIC_HOST");
    assert_eq!(
        lifecycle
            .notification_allowed("synthetic-original-batch", 1)
            .await
            .unwrap_err()
            .code,
        "RESIDENT_RUNTIME_REQUIRED_FOR_AUTOMATIC_DELIVERY"
    );
    assert_eq!(
        original.local_namespace(),
        "program:original-notification-client"
    );
    assert!(original.operations("", 32).await.unwrap()["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!directory.path().join("connect.state").exists());
    let context = lifecycle.call(AgentRequest::Context).await.unwrap();
    assert_eq!(context["actor_id"], original.actor_id());
    assert_eq!(context["local_engine"], "ATTACHED_ORIGINAL_CLIENT");
    owner.close().await.unwrap();
}
