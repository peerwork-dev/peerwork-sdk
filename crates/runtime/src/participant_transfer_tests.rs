use super::*;
use crate::{
    communication_runtime::ClientConfig,
    participant::{Capability, Invoke, ParticipantClient, Scope},
};
fn config(directory: &Path) -> (RuntimeConfig, PathBuf) {
    let identity_path = directory.join("identity");
    let identity = KernelIdentity::create(&identity_path).unwrap();
    let cfg = RuntimeConfig {
        format: "peerwork.participant-runtime.v1".into(),
        state_directory: directory.join("runtime"),
        engines: vec![EngineConfig {
            name: "one".into(),
            origin: "http://127.0.0.1:1".into(),
            expected_actor: identity.actor_id().into(),
            authority: None,
            identity_path,
            state_directory: directory.join("engine"),
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
            engine: "one".into(),
            capability: Capability::owner(),
        }],
        hosts: Vec::new(),
    };
    create_private_state_directory(&cfg.state_directory).unwrap();
    let path = directory.join("runtime.json");
    write_private(&path, &serde_json::to_vec(&cfg).unwrap()).unwrap();
    (cfg, path)
}
#[tokio::test]
async fn transfer_fences_source_and_never_overwrites_active_target_on_retry() {
    let temp = crate::test_support::protected_test_dir();
    let (cfg, file) = config(temp.path());
    let target = temp.path().join("target");
    let source = ParticipantClient::open(cfg.engines[0].participant_config())
        .await
        .unwrap();
    assert_eq!(
        transfer_engine(&file, "one", &target).unwrap_err().code,
        "TRANSFER_SOURCE_STILL_OWNED"
    );
    assert!(!cfg.engines[0].state_directory.join(OUT).exists());
    source.close().await.unwrap();
    let out = transfer_engine(&file, "one", &target).unwrap();
    assert_eq!(out["state"], "TRANSFER_READY");
    let moved: RuntimeConfig = serde_json::from_value(
        private_json(
            Path::new(out["runtime_config_path"].as_str().unwrap()),
            65536,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        moved.engines[0].journal_path,
        Some(cfg.engines[0].participant_config().journal_path)
    );
    assert_eq!(
        ParticipantClient::open(cfg.engines[0].participant_config())
            .await
            .err()
            .unwrap()
            .code,
        "ENGINE_STATE_TRANSFERRED_USE_TARGET"
    );
    let active = ParticipantClient::open(moved.engines[0].participant_config())
        .await
        .unwrap();
    active
        .invoke(
            Invoke::new(
                "new-after-transfer",
                "structure.workspace.create",
                Scope::default(),
                json!({"name":"Synthetic transferred state"}),
            ),
            Duration::ZERO,
        )
        .await
        .unwrap();
    let again = transfer_engine(&file, "one", &target).unwrap();
    assert_eq!(again["job_id"], out["job_id"]);
    assert_eq!(
        active
            .operation("new-after-transfer")
            .await
            .unwrap()
            .operation_id,
        "new-after-transfer"
    );
    assert_eq!(
        transfer_engine(&file, "one", &temp.path().join("different"))
            .unwrap_err()
            .code,
        "TRANSFER_ORIGINAL_SELECTION_REQUIRED"
    );
    active.close().await.unwrap();
}
#[tokio::test]
async fn transfer_preserves_source_on_wrong_identity_or_existing_target() {
    let temp = crate::test_support::protected_test_dir();
    let (cfg, file) = config(temp.path());
    let source = ParticipantClient::open(cfg.engines[0].participant_config())
        .await
        .unwrap();
    source.close().await.unwrap();
    let target = temp.path().join("occupied");
    create_private_state_directory(&target).unwrap();
    write_private(&target.join("unrelated"), b"keep").unwrap();
    assert_eq!(
        transfer_engine(&file, "one", &target).unwrap_err().code,
        "TRANSFER_TARGET_NOT_EMPTY"
    );
    assert_eq!(std::fs::read(target.join("unrelated")).unwrap(), b"keep");
    assert!(!cfg.engines[0].state_directory.join(OUT).exists());
    let another = KernelIdentity::create(&temp.path().join("another-identity")).unwrap();
    let mut wrong = cfg.clone();
    wrong.engines[0].identity_path = temp.path().join("another-identity");
    wrong.engines[0].expected_actor = another.actor_id().into();
    let wrong_file = temp.path().join("wrong.json");
    write_private(&wrong_file, &serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert_eq!(
        transfer_engine(&wrong_file, "one", &temp.path().join("wrong-target"))
            .unwrap_err()
            .code,
        "STATE_BINDING_MISMATCH"
    );
    let source = ParticipantClient::open(cfg.engines[0].participant_config())
        .await
        .unwrap();
    source.close().await.unwrap();
}
#[tokio::test]
async fn interrupted_transfer_resumes_at_each_durable_boundary_without_state_reset() {
    for selected in [
        "TARGET_RESERVED",
        "SOURCE_FENCED",
        "participant.sqlite",
        "participant-inbox.sqlite",
        "TARGET_READY",
    ] {
        let temp = crate::test_support::protected_test_dir();
        let (cfg, file) = config(temp.path());
        let target = temp.path().join("target");
        let source = ParticipantClient::open(cfg.engines[0].participant_config())
            .await
            .unwrap();
        source.close().await.unwrap();
        let failed = transfer_with(&file, "one", &target, |boundary| {
            if boundary == selected {
                Err(error("SYNTHETIC_INTERRUPTION"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(failed.code, "SYNTHETIC_INTERRUPTION");
        if selected == "TARGET_RESERVED" {
            let source = ParticipantClient::open(cfg.engines[0].participant_config())
                .await
                .unwrap();
            source.close().await.unwrap();
        } else {
            assert_eq!(
                ParticipantClient::open(cfg.engines[0].participant_config())
                    .await
                    .err()
                    .unwrap()
                    .code,
                "ENGINE_STATE_TRANSFERRED_USE_TARGET"
            );
        }
        if selected != "TARGET_READY" {
            assert_eq!(
                check_open(&target).unwrap_err().code,
                "ENGINE_TRANSFER_NOT_READY"
            );
        }
        let out = transfer_engine(&file, "one", &target).unwrap();
        assert_eq!(out["state"], "TRANSFER_READY");
        let moved: RuntimeConfig = serde_json::from_value(
            private_json(
                Path::new(out["runtime_config_path"].as_str().unwrap()),
                65536,
            )
            .unwrap(),
        )
        .unwrap();
        let live = ParticipantClient::open(moved.engines[0].participant_config())
            .await
            .unwrap();
        live.close().await.unwrap();
    }
}

#[test]
fn transfer_process_helper() {
    use std::io::{Read, Write};
    let Ok(config) = std::env::var("PEERWORK_SYNTHETIC_TRANSFER_CONFIG") else {
        return;
    };
    let target = std::env::var("PEERWORK_SYNTHETIC_TRANSFER_TARGET").unwrap();
    let phase = std::env::var("PEERWORK_SYNTHETIC_TRANSFER_PHASE").unwrap();
    transfer_with(Path::new(&config), "one", Path::new(&target), |boundary| {
        if boundary == phase {
            println!("TRANSFER_BOUNDARY_READY:{boundary}");
            std::io::stdout().flush().unwrap();
            let mut proceed = [0];
            std::io::stdin().read_exact(&mut proceed).unwrap();
        }
        Ok(())
    })
    .unwrap();
}
#[tokio::test]
async fn killed_handoff_resumes_original_job_and_ready_target_keeps_new_writes() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
    };
    for phase in ["SOURCE_FENCED", "participant.sqlite", "TARGET_READY"] {
        let temp = crate::test_support::protected_test_dir();
        let (cfg, file) = config(temp.path());
        let target = temp.path().join("target");
        let source = ParticipantClient::open(cfg.engines[0].participant_config())
            .await
            .unwrap();
        source.close().await.unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "participant_transfer::tests::transfer_process_helper",
                "--nocapture",
            ])
            .env("PEERWORK_SYNTHETIC_TRANSFER_CONFIG", &file)
            .env("PEERWORK_SYNTHETIC_TRANSFER_TARGET", &target)
            .env("PEERWORK_SYNTHETIC_TRANSFER_PHASE", phase)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut reached = false;
            for line in BufReader::new(stdout).lines().take(8) {
                if line.unwrap().contains("TRANSFER_BOUNDARY_READY:") {
                    reached = true;
                    break;
                }
            }
            let _ = tx.send(reached);
        });
        let reached = rx.recv_timeout(Duration::from_secs(8)).unwrap_or(false);
        if !reached {
            let _ = child.kill();
            let result = child.wait_with_output().unwrap();
            reader.join().unwrap();
            panic!(
                "synthetic handoff child did not reach {phase}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        reader.join().unwrap();
        assert_eq!(
            ParticipantClient::open(cfg.engines[0].participant_config())
                .await
                .err()
                .unwrap()
                .code,
            "STATE_ALREADY_OWNED"
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            check_open(&cfg.engines[0].state_directory)
                .unwrap_err()
                .code,
            "ENGINE_STATE_TRANSFERRED_USE_TARGET"
        );
        let mut live = None;
        if phase == "TARGET_READY" {
            let moved: RuntimeConfig = serde_json::from_value(
                private_json(&target.join("transferred-runtime.json"), 65536).unwrap(),
            )
            .unwrap();
            let active = ParticipantClient::open(moved.engines[0].participant_config())
                .await
                .unwrap();
            active
                .invoke(
                    Invoke::new(
                        "after-ready-crash",
                        "structure.workspace.create",
                        Scope::default(),
                        json!({"name":"Synthetic post-handoff write"}),
                    ),
                    Duration::ZERO,
                )
                .await
                .unwrap();
            live = Some(active);
        } else {
            assert_eq!(
                check_open(&target).unwrap_err().code,
                "ENGINE_TRANSFER_NOT_READY"
            );
        }
        let ready = transfer_engine(&file, "one", &target).unwrap();
        assert_eq!(ready["state"], "TRANSFER_READY");
        if let Some(active) = live {
            assert_eq!(
                active
                    .operation("after-ready-crash")
                    .await
                    .unwrap()
                    .operation_id,
                "after-ready-crash"
            );
            active.close().await.unwrap();
        }
    }
}
