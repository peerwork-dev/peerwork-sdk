//! Effective inventory must survive an update without changing host selection.
use super::*;
use crate::communication_runtime::{ClientConfig, EngineConfig, RuntimeConfig};
use crate::participant_dispatch::{HostConfig, HostSubscription};

pub(super) fn bridge(root: &Path, name: &str) -> HostConfig {
    let token = root.join(format!("{name}.token"));
    write_private(&token, "k".repeat(43).as_bytes()).unwrap();
    HostConfig {
        name: name.into(),
        adapter: json!({"kind":"bridge","endpoint":"127.0.0.1:1","token_file":token,
            "destination":{"kind":"test","conversation_id":name,"session_id":"original-session"}}),
        subscriptions: vec![HostSubscription {
            client: "original-receiver".into(), client_generation: Some(7),
            watch: crate::participant::WatchOptions { workspace_id:"w".repeat(43), mailbox_id:"m".repeat(43), membership_id:"g".repeat(43), consumer_id:"inbox".into(), host_destination:None },
        }],
    }
}

fn stopped(root: &Path) -> (Connect, HostConfig, HostConfig, HostConfig) {
    let identity_path = root.join("identity");
    let identity = crate::kernel_identity::KernelIdentity::create(&identity_path).unwrap();
    let directory = root.join("registry");
    let mut connect = Connect::open(&directory).unwrap();
    let runtime = directory.join("runtime-peer");
    create_private_state_directory(&runtime).unwrap();
    let old = bridge(root, "old");
    let replacement = bridge(root, "replacement");
    let added = bridge(root, "added");
    let config = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(), state_directory: runtime.clone(), hosts: vec![old.clone()],
        engines: vec![EngineConfig {
            name:"original".into(), origin:"http://127.0.0.1:1".into(), expected_actor:identity.actor_id().into(),
            identity_path, state_directory:root.join("engine"), journal_path:None, authority:None,
            migration_sources:vec![], allow_loopback_http:true, transport:Default::default(),
            max_inflight:1, max_pending:2, max_stored_bytes:1024 * 1024,
        }],
        clients: vec![ClientConfig { name:"bootstrap".into(), engine:"original".into(), capability:Capability::owner() }],
    };
    let bytes = serde_json::to_vec(&config).unwrap();
    write_private(&runtime.join("config.json"), &bytes).unwrap();
    // PID zero is the existing launch representation of a stopped owned child.
    let launch = SecureStateStore::open(&runtime.join("bootstrap.state")).unwrap();
    launch.write_exact(&serde_json::to_vec(&json!({"config_digest":sha256_hex(&bytes),"pid":0,"process_token":null})).unwrap()).unwrap();
    connect.registry.participants.insert("peer".into(), Registration {
        origin:config.engines[0].origin.clone(), actor_id:identity.actor_id().into(), endpoint_path:runtime.join("client-bootstrap.json"),
    });
    connect.registry.local_runtime_admins.insert("peer".into(), runtime.join("admin.json"));
    connect.save().unwrap();
    crate::runtime_startup::disable(&runtime).unwrap();
    (connect, old, replacement, added)
}

pub(super) fn overlay(directory: &Path, hosts: &[HostConfig], suppressed: &[HostConfig]) -> Vec<u8> {
    let bytes = serde_json::to_vec(&json!({"format":"peerwork.runtime-hosts.v2","configs":hosts,"suppressed_base":suppressed})).unwrap();
    SecureStateStore::open(&directory.join("runtime-hosts.state")).unwrap().write_exact(&bytes).unwrap();
    bytes
}

pub(super) fn names(value: &Value) -> Vec<&str> {
    value["continuation"]["hosts"].as_array().unwrap().iter().map(|host|host["name"].as_str().unwrap()).collect()
}

#[tokio::test]
async fn stopped_update_inventory_uses_effective_hosts_without_changing_stop() {
    let root = crate::test_support::protected_test_dir();
    let (mut connect, old, replacement, added) = stopped(root.path());
    let owned = bootstrap::owned_runtime(&connect, "peer").unwrap();
    let directory = &owned.config.state_directory;
    let bytes = overlay(directory, &[replacement, added], &[old]);
    let config_before = std::fs::read(directory.join("config.json")).unwrap();
    let identity_before = std::fs::read(&owned.config.engines[0].identity_path).unwrap();
    let inspect = connect.update(Some("peer"), false).await.unwrap();
    assert_eq!(inspect["runtime"]["state"], "STOPPED");
    assert_eq!(names(&inspect), ["replacement", "added"]);
    assert_eq!(std::fs::read(directory.join("config.json")).unwrap(), config_before);
    assert_eq!(std::fs::read(&owned.config.engines[0].identity_path).unwrap(), identity_before);
    assert_eq!(SecureStateStore::read_snapshot(&directory.join("runtime-hosts.state"), 512 * 1024).unwrap(), bytes);
    assert!(!crate::runtime_startup::read(directory).unwrap().unwrap().automatic);
    assert!(!directory.join("admin.json").exists());
    assert!(!connect.directory.join("update-peer.state").exists());
}

#[tokio::test]
async fn interrupted_update_inspection_uses_effective_hosts_and_preserves_pending_phase() {
    let root = crate::test_support::protected_test_dir();
    let (mut connect, old, replacement, added) = stopped(root.path());
    let owned = bootstrap::owned_runtime(&connect, "peer").unwrap();
    // Inventory never executes or selects the pending artifact. Completion and
    // restart use the exact CLI process fixture, not this large debug test binary.
    let executable = root.path().join("pending-artifact");
    write_private(&executable, b"synthetic pending artifact").unwrap();
    let update = Update {
        format:"peerwork.owned-update.v1".into(), participant:"peer".into(), registration:owned.registration.clone(),
        executable_digest:executable_digest(&executable).unwrap(), executable,
        required_features:REQUIRED.iter().map(|s|s.to_string()).collect(), original:owned.clone(), was_running:false, phase:Phase::RuntimeReady,
    };
    { let store = SecureStateStore::open(&connect.directory.join("update-peer.state")).unwrap(); save(&store, &update).unwrap(); }
    let pending_before = SecureStateStore::read_snapshot(&connect.directory.join("update-peer.state"), 2 * 1024 * 1024).unwrap();
    let bytes = overlay(&owned.config.state_directory, &[replacement, added], &[old]);
    let result = connect.update(Some("peer"), false).await.unwrap();
    assert_eq!(result["state"], "UPDATE_INVENTORY");
    assert_eq!(result["operation"]["phase"], "RUNTIME_READY");
    assert_eq!(names(&result), ["replacement", "added"]);
    assert_eq!(SecureStateStore::read_snapshot(&connect.directory.join("update-peer.state"), 2 * 1024 * 1024).unwrap(), pending_before);
    assert_eq!(SecureStateStore::read_snapshot(&owned.config.state_directory.join("runtime-hosts.state"), 512 * 1024).unwrap(), bytes);
    assert!(!crate::runtime_startup::read(&owned.config.state_directory).unwrap().unwrap().automatic);
}

#[test]
fn live_inventory_is_authoritative_and_legacy_inventory_uses_overlay() {
    let root = crate::test_support::protected_test_dir();
    let (connect, old, replacement, added) = stopped(root.path());
    let owned = bootstrap::owned_runtime(&connect, "peer").unwrap();
    overlay(&owned.config.state_directory, &[replacement.clone(), added.clone()], &[old]);
    let legacy = host_inventory(&owned, Some(&json!({"hosts":[]}))).unwrap();
    assert_eq!(serde_json::to_value(legacy).unwrap(), json!([replacement, added]));
    let current = host_inventory(&owned, Some(&json!({"host_configurations":[added.clone()],"hosts":[]}))).unwrap();
    assert_eq!(serde_json::to_value(current).unwrap(), json!([added]));
    assert_eq!(host_inventory(&owned, Some(&json!({"host_configurations":null}))).err().unwrap().code, "UPDATE_HOST_INVENTORY_INVALID");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires synthetic loopback IPC"]
async fn authenticated_inventory_includes_blocked_hosts_and_is_not_a_client_command() {
    let root = crate::test_support::protected_test_dir();
    let (connect, old, replacement, added) = stopped(root.path());
    let owned = bootstrap::owned_runtime(&connect, "peer").unwrap();
    overlay(&owned.config.state_directory, &[replacement.clone(), added.clone()], &[old]);
    crate::runtime_startup::enable(&owned.config.state_directory).unwrap();
    let cancel = crate::KernelCancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(crate::communication_runtime::serve(owned.config.clone(), cancel.clone(), tx));
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await.unwrap().unwrap().unwrap();
    let status = observation(&owned).await.unwrap();
    let inventory = host_inventory(&owned, Some(&status)).unwrap();
    assert_eq!(serde_json::to_value(inventory).unwrap(), json!([replacement, added]));
    assert_eq!(status["hosts"][0]["state"], "BLOCKED_SOURCES");
    let denied = crate::communication_runtime::call(&ready.client_endpoints["bootstrap"], json!({"method":"status"})).await.unwrap();
    assert_eq!(denied["ok"], false);
    assert!(denied["value"]["host_configurations"].is_null());
    cancel.cancel(); task.await.unwrap().unwrap();
}
