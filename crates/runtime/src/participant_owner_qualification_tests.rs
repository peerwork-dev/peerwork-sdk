//! Separately selected qualification of an actual retained pre-upgrade binary.
//! The normal three-target unit group does not claim this optional environment.
use super::*;
use crate::participant::ParticipantClient;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[tokio::test]
#[ignore = "requires explicit PEERWORK_OLD_PARTICIPANT_CLI, the retained v1 native candidate"]
async fn actual_v1_reader_refuses_pending_and_completed_v2_owner_before_runtime_ready() {
    let binary = PathBuf::from(
        std::env::var_os("PEERWORK_OLD_PARTICIPANT_CLI")
            .expect("explicit original native candidate"),
    );
    assert!(binary.is_absolute());
    let root = crate::test_support::protected_test_dir();
    let (config, path, binding) = super::tests::config(root.path());
    let selected = config.engines[0].participant_config();
    let client = ParticipantClient::open(selected.clone()).await.unwrap();
    client.close().await.unwrap();
    let job = MaintenancePin {
        operation_id: "o".repeat(43),
        selection_digest: "a".repeat(64),
        expected_revision: 0,
    };
    let file = selected.state_directory.join("engine-owner.state");
    let owner = SecureStateStore::open(&file).unwrap();
    begin(&owner, &binding, &job).unwrap();
    drop(owner);
    for completed in [false, true] {
        if completed {
            let owner = SecureStateStore::open(&file).unwrap();
            complete(&owner, &binding, &job).unwrap();
        }
        let before =
            std::fs::read(selected.state_directory.join("participant-inbox.sqlite")).unwrap();
        let mut child = Command::new(&binary)
            .args(["runtime", "run", path.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut terminal = false;
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                terminal = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !terminal {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("old reader started instead of refusing the versioned owner");
        }
        let result = child.wait_with_output().unwrap();
        assert!(!result.status.success());
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["state"], "FAILED");
        assert_eq!(value["error"]["code"], "STATE_BINDING_MISMATCH");
        assert_eq!(
            std::fs::read(selected.state_directory.join("participant-inbox.sqlite")).unwrap(),
            before
        );
    }
}
