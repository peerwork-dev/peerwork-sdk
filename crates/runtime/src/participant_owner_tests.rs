use super::*;
use crate::{
    communication_host::write_private,
    communication_runtime::{ClientConfig, EngineConfig, RuntimeConfig},
    kernel_identity::KernelIdentity,
    participant::{Capability, ParticipantClient},
    secure_state::create_private_state_directory,
};
use std::path::{Path, PathBuf};

pub(super) fn config(root: &Path) -> (RuntimeConfig, PathBuf, Vec<u8>) {
    let identity_path = root.join("identity");
    let identity = KernelIdentity::create(&identity_path).unwrap();
    let origin = "http://127.0.0.1:1";
    let normalized = crate::transport::canonical_lifecycle_origin(origin, true).unwrap();
    let binding = logical_binding(
        &identity,
        &normalized,
        &peerwork_core::crypto::sha256_hex(identity.actor_id().as_bytes()),
    );
    let config = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: root.join("runtime"),
        engines: vec![EngineConfig {
            name: "owner".into(),
            origin: origin.into(),
            expected_actor: identity.actor_id().into(),
            authority: None,
            identity_path,
            state_directory: root.join("engine"),
            journal_path: None,
            allow_loopback_http: true,
            transport: Default::default(),
            max_inflight: 1,
            max_pending: 8,
            max_stored_bytes: 4 * 1024 * 1024,
            migration_sources: Vec::new(),
        }],
        clients: vec![ClientConfig {
            name: "worker".into(),
            engine: "owner".into(),
            capability: Capability::owner(),
        }],
        hosts: Vec::new(),
    };
    create_private_state_directory(&config.state_directory).unwrap();
    let file = root.join("runtime.json");
    write_private(&file, &serde_json::to_vec(&config).unwrap()).unwrap();
    (config, file, binding)
}
fn pin(label: &str, revision: u64) -> MaintenancePin {
    MaintenancePin {
        operation_id: label.repeat(43),
        selection_digest: "a".repeat(64),
        expected_revision: revision,
    }
}

#[tokio::test]
async fn pending_owner_blocks_open_before_store_changes_and_keeps_fixed_data_bindings() {
    let root = crate::test_support::protected_test_dir();
    let (config, _, binding) = config(root.path());
    let selected = config.engines[0].participant_config();
    let client = ParticipantClient::open(selected.clone()).await.unwrap();
    client.close().await.unwrap();
    let identity = KernelIdentity::open(&selected.identity_path).unwrap();
    let origin = crate::transport::canonical_lifecycle_origin(&selected.origin, true).unwrap();
    let options = crate::participant::WatchOptions {
        workspace_id: "w".repeat(43),
        mailbox_id: "m".repeat(43),
        membership_id: "g".repeat(43),
        consumer_id: "original".into(),
        host_destination: None,
    };
    let (receiver, original_proof) = {
        let mut inbox = crate::participant_inbox::InboxStore::open_local(
            &selected.state_directory,
            &identity,
            &origin,
        )
        .unwrap();
        inbox
            .bind_service(
                &"synthetic-owner-audience"
                    .encode_utf16()
                    .collect::<Vec<_>>(),
                identity.key_id(),
            )
            .unwrap();
        let saved = inbox.attach_watch(&identity, "program", &options).unwrap();
        inbox.disable_watch("program", &options).unwrap();
        let body = json!({"claim_command_id":saved.claim_id,"mailbox_id":options.mailbox_id,"receiver_id":saved.receiver,"expected_epoch":null,"destination_digest":"d".repeat(64),"replace":false});
        let proof = inbox.receiver_proof(&identity, &saved, &body).unwrap();
        (saved.receiver, proof)
    };
    let file = selected.state_directory.join("engine-owner.state");
    let owner = SecureStateStore::open(&file).unwrap();
    assert_eq!(
        owner.read_exact().unwrap().unwrap().as_slice(),
        binding.as_slice()
    );
    let before = std::fs::read(selected.state_directory.join("participant-inbox.sqlite")).unwrap();
    let key = std::fs::read(&selected.identity_path).unwrap();
    let job = pin("o", 0);
    assert!(begin(&owner, &binding, &job).unwrap());
    assert!(begin(&owner, &binding, &job).unwrap());
    let pending_error = validate_ready(&owner, &binding).unwrap_err();
    assert!(!completed_snapshot(&file, &binding, &job).unwrap());
    assert_eq!(pending_error.operation_id, Some(job.operation_id.clone()));
    assert_eq!(pending_error.recovery, "RESUME_SAME_HOST_REBIND_OPERATION");
    drop(owner);
    let failure = ParticipantClient::open(selected.clone())
        .await
        .err()
        .unwrap();
    assert_eq!(
        failure.code,
        "OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION"
    );
    assert_eq!(failure.operation_id, Some(job.operation_id.clone()));
    assert_eq!(
        std::fs::read(selected.state_directory.join("participant-inbox.sqlite")).unwrap(),
        before
    );
    assert_eq!(std::fs::read(&selected.identity_path).unwrap(), key);
    let owner = SecureStateStore::open(&file).unwrap();
    complete(&owner, &binding, &job).unwrap();
    assert!(completed_snapshot(&file, &binding, &job).unwrap());
    assert!(!begin(&owner, &binding, &job).unwrap());
    assert_eq!(revision(&owner, &binding).unwrap(), 1);
    drop(owner);
    let resumed = ParticipantClient::open(selected.clone()).await.unwrap();
    resumed.close().await.unwrap();
    assert_eq!(std::fs::read(&selected.identity_path).unwrap(), key);
    let owner = SecureStateStore::open(&file).unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&owner.read_exact().unwrap().unwrap()).unwrap();
    assert_eq!(value["format"], "peerwork.participant-owner.v2");
    assert_eq!(value["binding"], std::str::from_utf8(&binding).unwrap());
    let mut inbox = crate::participant_inbox::InboxStore::open_local(
        &selected.state_directory,
        &identity,
        &origin,
    )
    .unwrap();
    let saved = inbox.attach_watch(&identity, "program", &options).unwrap();
    assert_eq!(saved.receiver, receiver);
    let body = json!({"claim_command_id":saved.claim_id,"mailbox_id":options.mailbox_id,"receiver_id":saved.receiver,"expected_epoch":null,"destination_digest":"d".repeat(64),"replace":false});
    assert_eq!(inbox.receiver_proof(&identity,&saved,&body).unwrap(),original_proof,"the original encrypted receiver seed must still decrypt and sign the exact original context");
}
#[test]
fn stale_or_foreign_jobs_cannot_clear_pending_or_replay_over_newer_maintenance() {
    let root = crate::test_support::protected_test_dir();
    let (_, _, binding) = config(root.path());
    let owner = SecureStateStore::open(&root.path().join("owner.state")).unwrap();
    owner.write_exact(&binding).unwrap();
    let first = pin("a", 0);
    begin(&owner, &binding, &first).unwrap();
    complete(&owner, &binding, &first).unwrap();
    let second = pin("b", 1);
    assert!(begin(&owner, &binding, &second).unwrap());
    assert_eq!(
        complete(&owner, &binding, &first).unwrap_err().operation_id,
        Some(second.operation_id.clone())
    );
    assert_eq!(
        begin(&owner, &binding, &first).unwrap_err().operation_id,
        Some(second.operation_id.clone())
    );
    let bytes = owner.read_exact().unwrap().unwrap();
    let mut wrong = second.clone();
    wrong.selection_digest = "b".repeat(64);
    assert!(begin(&owner, &binding, &wrong).is_err());
    assert_eq!(
        owner.read_exact().unwrap().unwrap().as_slice(),
        bytes.as_slice()
    );
    complete(&owner, &binding, &second).unwrap();
    assert_eq!(
        begin(&owner, &binding, &first).unwrap_err().code,
        "OWNER_MAINTENANCE_REVISION_MISMATCH"
    );
    complete(&owner, &binding, &second).unwrap();
    assert_eq!(revision(&owner, &binding).unwrap(), 2);
    let bytes = owner.read_exact().unwrap().unwrap();
    assert_eq!(
        validate_ready(&owner, b"another owner").unwrap_err().code,
        "STATE_BINDING_MISMATCH"
    );
    assert_eq!(
        owner.read_exact().unwrap().unwrap().as_slice(),
        bytes.as_slice()
    );
}
#[tokio::test]
async fn transfer_refuses_pending_maintenance_and_preserves_completed_v2_descriptor() {
    let root = crate::test_support::protected_test_dir();
    let (config, path, binding) = config(root.path());
    let engine = &config.engines[0];
    let source = ParticipantClient::open(engine.participant_config())
        .await
        .unwrap();
    source.close().await.unwrap();
    let owner = SecureStateStore::open(&engine.state_directory.join("engine-owner.state")).unwrap();
    let job = pin("t", 0);
    begin(&owner, &binding, &job).unwrap();
    drop(owner);
    let target = root.path().join("target");
    assert_eq!(
        crate::participant_transfer::transfer_engine(&path, "owner", &target)
            .unwrap_err()
            .code,
        "OWNER_MAINTENANCE_PENDING_RESUME_ORIGINAL_OPERATION"
    );
    assert!(!target.exists());
    let owner = SecureStateStore::open(&engine.state_directory.join("engine-owner.state")).unwrap();
    complete(&owner, &binding, &job).unwrap();
    let before = owner.read_exact().unwrap().unwrap().to_vec();
    drop(owner);
    let transferred =
        crate::participant_transfer::transfer_engine(&path, "owner", &target).unwrap();
    assert_eq!(transferred["state"], "TRANSFER_READY");
    let owner = SecureStateStore::open(&target.join("engine-owner.state")).unwrap();
    assert_eq!(
        owner.read_exact().unwrap().unwrap().as_slice(),
        before.as_slice()
    );
    validate_ready(&owner, &binding).unwrap();
    drop(owner);
    let config: RuntimeConfig = serde_json::from_slice(
        &crate::secure_state::read_private_file_bounded(
            &target.join("transferred-runtime.json"),
            65536,
        )
        .unwrap(),
    )
    .unwrap();
    let client = ParticipantClient::open(config.engines[0].participant_config())
        .await
        .unwrap();
    client.close().await.unwrap();
}
