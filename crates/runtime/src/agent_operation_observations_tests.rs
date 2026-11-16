use super::*;
use crate::{kernel_identity::KernelIdentity, participant::{Capability, ParticipantConfig}, participant_store::Store};
use std::sync::atomic::Ordering;

fn configuration(directory: &Path) -> ParticipantConfig {
    let identity_path = directory.join("identity");
    let identity = KernelIdentity::create(&identity_path).unwrap();
    let mut config = ParticipantConfig::new("http://127.0.0.1:1/", identity.actor_id(), identity_path, directory.join("engine"));
    config.allow_loopback_http = true;
    config.transport.request_timeout_ms = 100;
    config
}
fn seed(config: &ParticipantConfig, namespace: &str, request: &Invoke) {
    let identity = KernelIdentity::open(&config.identity_path).unwrap();
    let mut store = Store::open(&config.state_directory, &identity, &config.origin).unwrap();
    store.reserve(namespace, request, &identity, 64, 32 * 1024 * 1024).unwrap();
    store.finish(namespace, &request.operation_id, &identity, &json!({"state":"PENDING","retryable":false,"effect_certainty":"UNKNOWN"})).unwrap();
}
fn reads(tools: &AgentTools) -> usize {
    tools.operation_observations.as_ref().unwrap().reads.load(Ordering::Relaxed)
}
fn scoped_request(id: &str) -> Invoke {
    Invoke::new(id, "structure.action", Scope {
        workspace_id: Some("W".repeat(43)), instance_id: Some("I".repeat(43)), protocol_digest: Some("d".repeat(64)),
    }, json!({"action_id":"task.report","structure":{"kind":"PROGRESS"}}))
}

#[tokio::test]
async fn scope_misses_do_not_hide_a_broader_or_exact_original_and_bindings_are_reused() {
    let root = crate::test_support::protected_test_dir();
    let config = configuration(root.path());
    let request = scoped_request("original");
    seed(&config, "program:worker", &request);
    let owner = ParticipantClient::open(config).await.unwrap();
    let worker = owner.restrict("worker", Capability::owner()).unwrap();
    let mut selected = AgentSelection::for_client(&worker);
    selected.protocols.insert("tasks".into(), request.scope.clone());
    let mut tools = AgentTools::from_client(worker, selected).unwrap().for_call();
    tools.directory_clients.insert("W".repeat(43), tools.client.clone());
    tools.recovery_clients.insert("same-original".into(), ("W".repeat(43), tools.client.clone()));
    let wrong = Scope { instance_id: Some("J".repeat(43)), ..request.scope.clone() };
    assert!(tools.original_general_operation("original", Some(&"X".repeat(43)), None).await.unwrap().is_none());
    assert!(tools.original_general_operation("original", None, Some(&Scope::default())).await.unwrap().is_none());
    assert!(tools.original_general_operation("original", Some(&"W".repeat(43)), Some(&wrong)).await.unwrap().is_none());
    assert!(tools.original_general_operation("original", Some(&"W".repeat(43)), Some(&request.scope)).await.unwrap().is_some());
    assert!(tools.original_general_operation("original", None, None).await.unwrap().is_some());
    assert!(tools.original_protocol_operation("tasks", "original").await.unwrap().is_some());
    assert_eq!(reads(&tools), 1, "all scope filters share the same unfiltered namespace observation");
    assert_eq!(tools.operation_observations.as_ref().unwrap().bindings.lock().await.len(), 1);
    owner.close().await.unwrap();
}

#[tokio::test]
async fn lifecycle_precheck_and_execution_share_original_route_before_recipient_resolution() {
    let root = crate::test_support::protected_test_dir();
    let config = configuration(root.path());
    seed(&config, "program:old", &scoped_request("saved"));
    let owner = ParticipantClient::open(config).await.unwrap();
    let current = owner.restrict("current", Capability::owner()).unwrap();
    let old = owner.restrict("old", Capability::owner()).unwrap();
    let mut selected = AgentSelection::for_client(&current);
    selected.workspaces.insert("space".into(), "W".repeat(43));
    let mut tools = AgentTools::from_client(current, selected).unwrap().for_call();
    tools.recovery_clients.insert("original".into(), ("W".repeat(43), Client::attached(old)));
    let request = AgentRequest::Send { contact: String::new(), to: Some("renamed-peer".into()), workspace: Some("space".into()), operation_id: "saved".into(), text: "changed text".into(), wait_ms: 0 };
    let result = tools.original_request(&request).await.unwrap().unwrap();
    assert_eq!(result["error"]["code"], "EXISTING_OPERATION_USE_STATUS_OR_RECOVER");
    assert_eq!(result["error"]["details"]["recovery_arguments"]["recovery_view"], "original");
    let error = tools.call_observed(request).await.unwrap_err();
    assert_eq!(error.code, "EXISTING_OPERATION_USE_STATUS_OR_RECOVER");
    assert_eq!(error.details.unwrap()["recovery_arguments"]["recovery_view"], "original");
    assert_eq!(reads(&tools), 2, "one observation per actual namespace, not one per routing stage");
    owner.close().await.unwrap();
}

#[tokio::test]
async fn separate_calls_have_independent_observations_and_selected_namespaces() {
    let root = crate::test_support::protected_test_dir();
    let config = configuration(root.path());
    seed(&config, "program:old", &scoped_request("saved"));
    let owner = ParticipantClient::open(config).await.unwrap();
    let current = owner.restrict("current", Capability::owner()).unwrap();
    let old = owner.restrict("old", Capability::owner()).unwrap();
    let tools = AgentTools::from_client(current, AgentSelection::for_client(&owner)).unwrap();
    let one = tools.for_call();
    let mut changed = tools.clone();
    changed.recovery_clients.insert("old".into(), ("W".repeat(43), Client::attached(old)));
    let two = changed.for_call();
    let (missing, found) = tokio::join!(one.original_general_operation("saved", None, None), two.original_general_operation("saved", None, None));
    assert!(missing.unwrap().is_none());
    assert_eq!(found.unwrap().unwrap().1, Some("old"));
    assert_eq!(reads(&one), 1);
    assert_eq!(reads(&two), 2);
    assert!(!Arc::ptr_eq(one.operation_observations.as_ref().unwrap(), two.operation_observations.as_ref().unwrap()));
    assert!(tools.operation_observations.is_none());
    assert!(matches!(tools.for_request(&AgentRequest::Context), std::borrow::Cow::Borrowed(_)));
    owner.close().await.unwrap();
}

#[tokio::test]
async fn distinct_original_namespaces_still_report_ambiguity() {
    let root = crate::test_support::protected_test_dir();
    let config = configuration(root.path());
    let request = scoped_request("same-id");
    for namespace in ["program:one", "program:two"] { seed(&config, namespace, &request); }
    let owner = ParticipantClient::open(config).await.unwrap();
    let one = owner.restrict("one", Capability::owner()).unwrap();
    let two = owner.restrict("two", Capability::owner()).unwrap();
    let mut selected = AgentSelection::for_client(&one);
    selected.protocols.insert("tasks".into(), request.scope);
    let mut tools = AgentTools::from_client(one, selected).unwrap().for_call();
    tools.recovery_clients.insert("two".into(), ("W".repeat(43), Client::attached(two)));
    assert_eq!(tools.original_general_operation("same-id", None, None).await.err().unwrap().code, "OPERATION_SCOPE_AMBIGUOUS_USE_RECOVERY_VIEW");
    assert_eq!(tools.original_protocol_operation("tasks", "same-id").await.err().unwrap().code, "OPERATION_SCOPE_AMBIGUOUS_USE_PROTOCOL_VIEW");
    assert_eq!(reads(&tools), 2);
    owner.close().await.unwrap();
}

#[tokio::test]
async fn invocation_invalidates_pre_admission_misses_and_preserves_frozen_input_checks() {
    let root = crate::test_support::protected_test_dir();
    let config = configuration(root.path());
    let owner = ParticipantClient::open(config).await.unwrap();
    let tools = AgentTools::from_client(owner.clone(), AgentSelection::for_client(&owner)).unwrap().for_call();
    let request = Invoke::new("new-operation", "structure.workspace.create", Scope::default(), json!({"name":"original"}));
    assert!(tools.original_general_operation("new-operation", None, None).await.unwrap().is_none());
    tools.invoke_client(&tools.client, request.clone(), 0).await.unwrap();
    assert!(tools.original_general_operation("new-operation", None, None).await.unwrap().is_some());
    assert_eq!(reads(&tools), 2, "admission invalidates the earlier miss");
    let mut changed = request;
    changed.body = json!({"name":"changed"});
    let error = tools.invoke_client(&tools.client, changed, 0).await.unwrap_err();
    assert_eq!(error.code, "OPERATION_INPUT_CONFLICT");
    owner.close().await.unwrap();
}

#[tokio::test]
async fn cached_observations_do_not_authorize_invocation_and_errors_are_not_negative_cache_entries() {
    let root = crate::test_support::protected_test_dir();
    let config = configuration(root.path());
    let request = scoped_request("saved");
    seed(&config, "program:worker", &request);
    let owner = ParticipantClient::open(config).await.unwrap();
    let worker = owner.restrict("worker", Capability::owner()).unwrap();
    let tools = AgentTools::from_client(worker.clone(), AgentSelection::for_client(&worker)).unwrap().for_call();
    assert!(tools.original_general_operation("saved", None, None).await.unwrap().is_some());
    worker.revoke_local();
    assert_eq!(tools.invoke_client(&tools.client, request, 0).await.unwrap_err().code, "LOCAL_CLIENT_REVOKED");
    for _ in 0..2 {
        assert_eq!(tools.original_general_operation("saved", None, None).await.err().unwrap().code, "LOCAL_CLIENT_REVOKED");
    }
    assert_eq!(reads(&tools), 3, "both revoked observations reach the original engine");
    owner.close().await.unwrap();
}
