//! Protected PRIVATE package staging against a complete Owner replay. A POST
//! response is only an observation; exact signed commits prove each part.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_lifecycle::SecureLifecycle,
    secure_read_access::{
        SecureReadAccess, SecureReadAccessError, SecureReadConfig, VerifiedReadFloor,
    },
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::{SecureStateError, SecureStateStore},
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, decode_base64url, sha256, sha256_hex},
    prepared_private_install::{
        prepare_private_direct_install_begin_with_options, prepare_private_package_install_begin_with_disclosure,
        prepare_private_package_install_step, prepare_private_package_stage,
        verify_saved_private_direct_install_begin_with_options, verify_saved_private_package_install_begin_with_disclosure,
        verify_saved_private_package_install_step, verify_saved_private_package_stage,
        PrivateInstallError,
    },
    public_direct_install::plan_public_install_snapshot,
    replayed_secure_journal::StructureStatus,
    secure_keyring::SecretKeyring,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
static TEST_CRASH_AFTER_BEGIN_ROW: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(crate) static TEST_STOP_AFTER_IMPORTED_LATER_STAGE_ROW: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn test_crash_after_begin_row() -> Result<(), PrivatePackageInstallError> {
    #[cfg(test)]
    if TEST_CRASH_AFTER_BEGIN_ROW.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(PrivatePackageInstallError::Runtime);
    }
    Ok(())
}

#[cfg(test)]
mod historical_v1_direct_test {
    use super::*;
    use crate::{
        secure_action_access::PublicActionInput,
        secure_owner_attach::{HistoricalOwnerAttachInput, SecureHistoricalOwnerAttach},
        secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerWorkspaceCreate},
        secure_read_profile::SecureReadProfile,
    };
    use std::{
        io::{BufRead, BufReader},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_attached_wire_v1_private_direct_install_to_v2() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let Ok(legacy_root) = std::env::var("PEERWORK_LEGACY_CLIENT_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let helper =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/legacy-owner-source.mjs");
        let source_dir = root.path().join("legacy-owner");
        let setup = Command::new(&node)
            .arg(helper)
            .arg(&origin)
            .arg(&source_dir)
            .arg(legacy_root)
            .arg("legacy-record")
            .output()
            .unwrap();
        assert!(
            setup.status.success(),
            "legacy record setup failed: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let source: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
        assert_eq!(source["policy_v"], 1);
        let workspace_id = source["workspace_id"].as_str().unwrap().to_owned();
        let prior_record_id = source["prior_record_id"].as_str().unwrap().to_owned();
        let config = SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let token = CancellationToken::new();
        let attached = SecureHistoricalOwnerAttach::new(config.clone())
            .attach(
                HistoricalOwnerAttachInput {
                    workspace_id: workspace_id.clone(),
                    protected_ts_state_path: PathBuf::from(source["state_path"].as_str().unwrap()),
                    protected_owner_pkcs8_path: PathBuf::from(source["pem_path"].as_str().unwrap()),
                    protected_ts_intent_db_path: PathBuf::from(
                        source["intent_db_path"].as_str().unwrap(),
                    ),
                    expected_owner_actor_id: source["owner_actor_id"].as_str().unwrap().into(),
                    expected_owner_key_id: source["owner_key_id"].as_str().unwrap().into(),
                    recover_pending_action: false,
                    retain_pending_action_command_id: None,
                    selected_pending_package_stage_command_id: None,
                    selected_orphan_package_stage_command_id: None,
                    expected_ts_state_digest: None,
                    kernel_pending_command_ids: Vec::new(),
                    expected_kernel_intent_db_digest: None,
                },
                &token,
            )
            .unwrap();
        assert_eq!(attached.status, "ATTACHED");
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let before_read: serde_json::Value =
            serde_json::from_str(&owner.read_workspace_json(&workspace_id, &token).unwrap())
                .unwrap();
        assert!(before_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "records"
                && row["id"] == prior_record_id
                && row["value"]["payload"]["title"] == "Legacy encrypted record"
                && row["value"]["payload"]["body"] == "Old wire-v1 encrypted body"));
        let install = owner.private_install_access(&workspace_id).unwrap();
        let (old_policy, old_policy_hash, old_sequence): (serde_json::Value, String, u64) =
            SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    let wire = source
                        .signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Plan)?;
                    let signed: serde_json::Value = serde_json::from_slice(wire)
                        .map_err(|_| PrivatePackageInstallError::Plan)?;
                    Ok::<_, PrivatePackageInstallError>((
                        signed["payload"].clone(),
                        source.replay().policy_hash().to_owned(),
                        source.replay().sequence(),
                    ))
                })
                .unwrap();
        assert_eq!(old_policy["v"], 1);
        assert_eq!(old_policy["visibility"], "PRIVATE");
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let owner_actor = source["owner_actor_id"].as_str().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let counts = || {
            runtime.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        let before_count = counts()["commits"].as_u64().unwrap();
        let arm_drop = || {
            runtime.block_on(async {
                assert!(reqwest::Client::new()
                    .post(format!("{origin}__test/drop-next-post"))
                    .body("{}")
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success());
            })
        };
        arm_drop();
        let first: serde_json::Value = serde_json::from_str(&install.submit_direct_begin_json(PrivateDirectInstallBeginInput {
            closure_json: vector["closure"].to_string(),
            bindings_json: None,
            expected_root_package_digest: vector["closure"]["root_package_digest"].as_str().unwrap().into(),
            expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
            instance_id: random_id().unwrap(),
            entrypoint: "proposal".into(),
            grants_json: serde_json::json!([{ "actor_id": owner_actor, "actions": ["proposal.propose"],
                "protocol_roles": ["AUTHOR"], "capabilities": ["PROPOSE"] }]).to_string(),
            disclose: None,
            command_id: None, issued_at_ms: None,
        }).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        let begin_id = first["begin_command_id"].as_str().unwrap().to_owned();
        assert_eq!(counts()["commits"], before_count + 1);
        drop(install);
        drop(owner);
        let reopened = SecureOwnerWorkspaceCreate::new(config);
        let install = reopened.private_install_access(&workspace_id).unwrap();
        let local: serde_json::Value =
            serde_json::from_str(&install.installs_json().unwrap()).unwrap();
        assert_eq!(local.as_array().unwrap().len(), 1);
        assert_eq!(local[0]["begin_command_id"], begin_id);
        assert_eq!(local[0]["source_kind"], "DIRECT");
        arm_drop();
        let mut progress: serde_json::Value =
            serde_json::from_str(&install.continue_install_json(&begin_id).unwrap()).unwrap();
        assert_eq!(progress["step_action_id"], "secure.structure.page");
        let lost_page_id = progress["step_command_id"].as_str().unwrap().to_owned();
        for _ in 0..8 {
            if progress["status"] == "ACCEPTED" {
                break;
            }
            progress =
                serde_json::from_str(&install.continue_install_json(&begin_id).unwrap()).unwrap();
        }
        assert_eq!(progress["status"], "ACCEPTED");
        assert_ne!(lost_page_id, begin_id);
        assert_eq!(
            counts()["commits"],
            before_count + 4,
            "BEGIN, record PAGE, head PAGE, END without duplicate"
        );
        let (new_policy, new_policy_hash): (serde_json::Value, String) =
            SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    let wire = source
                        .signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Plan)?;
                    let signed: serde_json::Value = serde_json::from_slice(wire)
                        .map_err(|_| PrivatePackageInstallError::Plan)?;
                    Ok::<_, PrivatePackageInstallError>((
                        signed["payload"].clone(),
                        source.replay().policy_hash().to_owned(),
                    ))
                })
                .unwrap();
        assert_ne!(new_policy_hash, old_policy_hash);
        assert_eq!(new_policy["v"], 2);
        assert_eq!(
            new_policy["version"],
            old_policy["version"].as_u64().unwrap() + 1
        );
        assert_eq!(new_policy["previous_policy"], old_policy_hash);
        assert_eq!(new_policy["effective_sequence"], old_sequence + 1);
        for field in [
            "workspace_id",
            "owner_id",
            "signing_key",
            "visibility",
            "epoch",
        ] {
            assert_eq!(
                new_policy[field], old_policy[field],
                "{field} must be retained"
            );
        }
        assert_eq!(
            new_policy["members"].as_array().unwrap().len(),
            old_policy["members"].as_array().unwrap().len()
        );
        for (old, new) in old_policy["members"]
            .as_array()
            .unwrap()
            .iter()
            .zip(new_policy["members"].as_array().unwrap())
        {
            for field in ["actor_id", "certificate", "role"] {
                assert_eq!(new[field], old[field], "member {field}");
            }
            let old_scopes = old["scopes"].as_array().unwrap();
            let new_scopes = new["scopes"].as_array().unwrap();
            assert!(new_scopes.len() >= old_scopes.len());
            assert_eq!(&new_scopes[..old_scopes.len()], old_scopes);
        }
        let structured_protocols = new_policy["structure"]["protocols"].as_array().unwrap();
        assert!(structured_protocols
            .iter()
            .any(|protocol| protocol["protocol_digest"] == vector["protocol_digest"]));
        for object in before_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["kind"] == "protocols")
        {
            let protocol = structured_protocols
                .iter()
                .find(|row| row["protocol_digest"] == object["id"])
                .unwrap();
            for (schema, definition) in object["value"]["manifest"]["record_schemas"]
                .as_object()
                .unwrap()
            {
                for field in definition["fields"].as_object().unwrap().keys() {
                    assert_eq!(
                        protocol["schemas"][schema]["fields"][field]["protection"], "e2ee",
                        "old wire-v1 field {schema}.{field} must remain encrypted"
                    );
                }
            }
        }
        for protocol in structured_protocols {
            for definition in protocol["schemas"].as_object().unwrap().values() {
                for field in definition["fields"].as_object().unwrap().values() {
                    assert_eq!(
                        field["protection"], "e2ee",
                        "direct default must not disclose new fields"
                    );
                }
            }
        }
        assert!(new_policy["structure"]["disclosure"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["fields"].as_array().is_some_and(Vec::is_empty)));
        let read: serde_json::Value =
            serde_json::from_str(&reopened.read_workspace_json(&workspace_id, &token).unwrap())
                .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "records"
                && row["id"] == prior_record_id
                && row["value"]["payload"]["title"] == "Legacy encrypted record"
                && row["value"]["payload"]["body"] == "Old wire-v1 encrypted body"));
        let action = reopened.private_action_access(&workspace_id).unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "proposal.propose".into(),
                    instance_id: progress["instance_id"].as_str().unwrap().into(),
                    body_json:
                        r#"{"title":"After v1 direct install","body":"Encrypted new proposal"}"#
                            .into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &action
                .retry_saved_json(submitted["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let final_read: serde_json::Value =
            serde_json::from_str(&reopened.read_workspace_json(&workspace_id, &token).unwrap())
                .unwrap();
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "records"
                && row["id"] == effect_id
                && row["value"]["payload"]["title"] == "After v1 direct install"
                && row["value"]["payload"]["body"] == "Encrypted new proposal"));
        let count_after = counts()["commits"].as_u64().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &install.continue_install_json(&begin_id).unwrap()
            )
            .unwrap()["status"],
            "ACCEPTED"
        );
        assert_eq!(counts()["commits"], count_after);
    }


}

#[cfg(test)]
mod format_two_direct_test {
    use super::*;
    use crate::{
        secure_action_access::PublicActionInput,
        secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerCreateInput, SecureOwnerWorkspaceCreate},
        secure_owner_format_transition::{
            OwnerFormatTransition, OwnerFormatTransitionInput,
        },
    };
    use std::{
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_private_ceiling_two_direct_typed_install_and_retry() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(&node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .env("PEERWORK_TEST_OWNER_FORMAT", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let config = SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("native-owner"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let token = CancellationToken::new();
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let created = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native PRIVATE typed direct".into(),
                    name_utf16: None,
                    visibility: "PRIVATE".into(),
                    structured: true,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        assert_eq!(owner.resume(&created.command_id, &token).unwrap().status, "CREATED");
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let post = |path: &str| {
            rt.block_on(async {
                reqwest::Client::new()
                    .post(format!("{origin}{path}"))
                    .body("{}")
                    .send()
                    .await
                    .unwrap()
            })
        };
        let counts = || {
            rt.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        assert_eq!(post("__test/activate-protocol-cutover").status(), 200);
        let policy = |owner: &SecureOwnerWorkspaceCreate| -> serde_json::Value {
            let install = owner.private_install_access(&created.workspace_id).unwrap();
            SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    let wire = source
                        .signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Plan)?;
                    serde_json::from_slice::<serde_json::Value>(wire)
                        .map_err(|_| PrivatePackageInstallError::Plan)
                })
                .unwrap()
        };
        let before_raise = policy(&owner);
        assert_eq!(before_raise["payload"]["v"], 3);
        assert_eq!(before_raise["payload"]["structure_mode"], "STRUCTURED");
        assert_eq!(before_raise["payload"]["protocol_format_ceiling"], 1);
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/private-direct-format-two.json"
        ))
        .unwrap();
        assert_eq!(fixture["root_package_digest"], "3e14bcad26a11c7f9a09ce3099bdf4043f6d6ea50bac2463638cc3a79baf691c");
        assert_eq!(fixture["protocol_digest"], "a95f5fb783ad9e5bd04ef85e7b3f3cd7f084f19db07f287075210ce729cf9b72");
        let actor_id = KernelIdentity::open(
            &owner.private_install_access(&created.workspace_id).unwrap().config.identity_path,
        )
        .unwrap()
        .actor_id()
        .to_owned();
        let input = PrivateDirectInstallBeginInput {
            closure_json: fixture["closure"].to_string(),
            bindings_json: None,
            expected_root_package_digest: fixture["root_package_digest"].as_str().unwrap().into(),
            expected_protocol_digest: fixture["protocol_digest"].as_str().unwrap().into(),
            instance_id: random_id().unwrap(),
            entrypoint: "typedPackage".into(),
            grants_json: serde_json::json!([{"actor_id": actor_id,
                "actions": ["lib.replace", "lib.produce"],
                "protocol_roles": [], "capabilities": []}]).to_string(),
            disclose: None,
            command_id: None,
            issued_at_ms: None,
        };
        let install = owner.private_install_access(&created.workspace_id).unwrap();
        let before_invalid = counts()["commits"].as_u64().unwrap();
        assert!(matches!(
            install.submit_direct_begin_json(input.clone()),
            Err(PrivatePackageInstallError::Plan)
        ));
        assert_eq!(counts()["commits"], before_invalid);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&install.installs_json().unwrap()).unwrap(), serde_json::json!([]));
        drop(install);
        let format = owner.private_format_transition_access(&created.workspace_id).unwrap();
        let raised: serde_json::Value = serde_json::from_str(
            &format.submit_json_with_cancel(OwnerFormatTransitionInput {
                workspace_id: created.workspace_id.clone(),
                transition: OwnerFormatTransition::RaisePrivateCeilingTwo,
                command_id: None,
                issued_at_ms: None,
            }, &token).unwrap(),
        ).unwrap();
        let raise_id = raised["command_id"].as_str().unwrap();
        let raised: serde_json::Value = serde_json::from_str(
            &format.resume_json_with_cancel(raise_id, &token).unwrap()
        ).unwrap();
        assert_eq!(raised["status"], "ACCEPTED");
        let raised_policy = policy(&owner);
        assert_eq!(raised_policy["payload"]["v"], 3);
        assert_eq!(raised_policy["payload"]["structure_mode"], "STRUCTURED");
        assert_eq!(raised_policy["payload"]["protocol_format_ceiling"], 2);
        let install = owner.private_install_access(&created.workspace_id).unwrap();
        assert_eq!(post("__test/drop-next-post").status(), 200);
        let before_install = counts()["commits"].as_u64().unwrap();
        let first: serde_json::Value = serde_json::from_str(&install.submit_direct_begin_json(input).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        let begin_id = first["begin_command_id"].as_str().unwrap().to_owned();
        assert_eq!(counts()["commits"], before_install + 1);
        drop(install);
        drop(owner);
        let reopened = SecureOwnerWorkspaceCreate::new(config);
        let install = reopened.private_install_access(&created.workspace_id).unwrap();
        let history: serde_json::Value = serde_json::from_str(&install.installs_json().unwrap()).unwrap();
        assert_eq!(history[0]["begin_command_id"], begin_id);
        assert_eq!(history[0]["source_kind"], "DIRECT");
        let mut progress: serde_json::Value = serde_json::from_str(&install.continue_install_json(&begin_id).unwrap()).unwrap();
        for _ in 0..12 {
            if progress["status"] == "ACCEPTED" { break; }
            progress = serde_json::from_str(&install.continue_install_json(&begin_id).unwrap()).unwrap();
        }
        assert_eq!(progress["status"], "ACCEPTED");
        let after_install = counts()["commits"].as_u64().unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&install.continue_install_json(&begin_id).unwrap()).unwrap()["status"], "ACCEPTED");
        assert_eq!(counts()["commits"], after_install);
        let read: serde_json::Value = serde_json::from_str(&reopened.read_workspace_json(&created.workspace_id, &token).unwrap()).unwrap();
        let objects = read["objects"].as_array().unwrap();
        assert!(objects.iter().any(|object| object["kind"] == "protocols"
            && object["id"] == fixture["protocol_digest"]
            && object["value"]["manifest"]["format_version"] == 2
            && object["value"]["composition"]["v"] == 1
            && object["value"]["composition"]["dependencies"].as_array().is_some_and(|parts| parts.len() == 1)));
        let protocol = objects.iter().find(|object|
            object["kind"] == "protocols" && object["id"] == fixture["protocol_digest"]
        ).unwrap();
        let composition = &protocol["value"]["composition"];
        assert_eq!(composition["source_manifest"], serde_json::json!({
            "name": "Typed imports",
            "display_version": "1",
            "semantics": "peerwork.kernel.v1",
            "dependencies": ["907b06da48ee65359c91c9c015b6ed7ee1a0c7e9b5844b7bdf2e091e97b2b99a"],
            "protocol_roles": [],
            "capabilities": [],
            "role_conflicts": [],
            "historical_role_conflicts": [],
            "constraints": {},
            "record_schemas": {},
            "initial_state": {},
            "actions": [],
        }));
        let source_wrapper = serde_json::json!({
            "semantics": "peerwork.kernel.v1",
            "manifest": composition["source_manifest"],
        });
        let source_wire = parse_wire_json_bounded(source_wrapper.to_string().as_bytes(), 64, 2_000_000).unwrap();
        let source_canonical = canonical_wire_value(&source_wire, CanonicalPath::STRUCTURED).unwrap();
        assert_eq!(composition["source_digest"], "b792d58a1c33218f121d7c742ca85bf63c411ab3aa5733ff88cc8b919f05496a");
        assert_eq!(composition["source_digest"], sha256_hex(source_canonical.as_bytes()));
        assert!(objects.iter().any(|object| object["kind"] == "instances"
            && object["id"] == progress["instance_id"]
            && object["value"]["protocol_digest"] == fixture["protocol_digest"]));
        let action = reopened.private_action_access(&created.workspace_id).unwrap();
        let submitted: serde_json::Value = serde_json::from_str(&action.submit_new_json(PublicActionInput {
            action_id: "lib.replace".into(),
            instance_id: progress["instance_id"].as_str().unwrap().into(),
            body_json: r#"{"value":[{"label":"typed direct"},true]}"#.into(),
            exact_input_refs_json: None,
            allocations_json: None,
            command_id: None,
            issued_at_ms: None,
        }).unwrap()).unwrap();
        let accepted: serde_json::Value = serde_json::from_str(&action.retry_saved_json(submitted["command_id"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let final_read: serde_json::Value = serde_json::from_str(&reopened.read_workspace_json(&created.workspace_id, &token).unwrap()).unwrap();
        assert!(final_read["objects"].as_array().unwrap().iter().rev().any(|object|
            object["kind"] == "instances"
                && object["id"] == progress["instance_id"]
                && object["value"]["state"]["lib"]["data"] == serde_json::json!([{"label":"typed direct"}, true])
        ));
    }
}

#[derive(Debug, Error)]
pub enum PrivatePackageInstallError {
    #[error("complete PRIVATE Owner journal read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("protected Owner identity, lifecycle, or local stage scope is invalid")]
    Identity,
    #[error("package selection or staging context is invalid")]
    Input,
    #[error("install BEGIN command ID is already saved; use exact continuation")]
    DuplicateBegin,
    #[error("native package staging proof failed")]
    Plan,
    #[error("protected stage state failed: {0}")]
    State(#[from] SecureStateError),
    #[error("protected exact command intent failed: {0}")]
    Intent(#[from] SecureIntentError),
    #[error("OS entropy is unavailable")]
    Entropy,
    #[error("configured transport failed")]
    Transport,
    #[error("native async runtime failed")]
    Runtime,
    #[error("service rejected the exact saved stage packet with HTTP {0}")]
    ServerRejected(u16),
    #[error("result could not be encoded")]
    Encoding,
}
impl From<PrivateInstallError> for PrivatePackageInstallError {
    fn from(error: PrivateInstallError) -> Self {
        match error {
            PrivateInstallError::Resource => Self::State(SecureStateError::TooLarge),
            _ => Self::Plan,
        }
    }
}
impl PrivatePackageInstallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(error) => error.code(),
            Self::Identity => "IDENTITY_STATE",
            Self::Input => "INSTALL_INPUT_INVALID",
            Self::DuplicateBegin => "INSTALL_COMMAND_EXISTS",
            Self::Plan => "INSTALL_PLAN_FAILED",
            Self::State(SecureStateError::TooLarge) => "RESOURCE_LIMIT",
            Self::State(SecureStateError::Busy) => "STATE_BUSY",
            Self::State(_) => "INSTALL_STATE",
            Self::Intent(_) => "INTENT_STATE",
            Self::Entropy => "ENTROPY_UNAVAILABLE",
            Self::Transport => "TRANSPORT_FAILED",
            Self::Runtime => "RUNTIME_FAILED",
            Self::ServerRejected(_) => "SERVER_REJECTED",
            Self::Encoding => "RESULT_ENCODING_FAILED",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePackageStageInput {
    pub material_json: String,
    pub expected_root_package_digest: String,
    pub expected_protocol_digest: String,
    #[serde(default)]
    pub stage_id: Option<String>,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PrivatePackageStageResult {
    pub status: &'static str,
    pub stage_id: String,
    pub workspace_id: String,
    pub source_id: String,
    pub root_package_digest: String,
    pub protocol_digest: String,
    pub part_count: usize,
    pub applied_parts: usize,
    pub pending_command_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePackageInstallBeginInput {
    pub stage_id: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    #[serde(default)]
    pub disclose: Option<Vec<PrivateInstallDisclosure>>,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateDirectInstallBeginInput {
    pub closure_json: String,
    #[serde(default)]
    pub bindings_json: Option<String>,
    pub expected_root_package_digest: String,
    pub expected_protocol_digest: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    #[serde(default)]
    pub disclose: Option<Vec<PrivateInstallDisclosure>>,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateInstallDisclosure {
    pub schema: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivatePackageInstallProgress {
    pub status: &'static str,
    pub begin_command_id: String,
    pub step_command_id: String,
    pub step_action_id: &'static str,
    pub workspace_id: String,
    pub protocol_digest: String,
    pub instance_id: String,
    pub commit_hash: String,
}

/// Input from a fully proved, durable Owner attachment. The caller saves this
/// only after PREPARED and rechecks the selected old packet and source plan.
/// It grants no ordinary install authority by itself.
pub(crate) struct ImportedHistoricalCompletedPackageSource {
    pub source_checkpoint_json: String,
    pub source_id: String,
    pub part_count: usize,
    /// Reconstructed signed requests are provenance, never retried stage HTTP bytes.
    pub steps: Vec<ImportedHistoricalStageStep>,
}

pub(crate) struct ImportedHistoricalDirectBegin {
    pub attach_id: String,
    pub command_id: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    pub disclose_json: Option<String>,
    pub issued_at_ms: u64,
    pub request_wire: Vec<u8>,
    pub commit_hash: String,
    pub source_policy_hash: String,
    pub policy_hash: String,
    pub snapshot_json: String,
    pub protocol_digest: String,
    pub material_wire: Vec<u8>,
    pub bindings_json: String,
    pub source_checkpoint_json: String,
    pub root_package_digest: String,
    pub staged_source: Option<ImportedHistoricalCompletedPackageSource>,
    pub object_source_json: Option<String>,
    pub steps: Vec<InstallStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InstallRow {
    /// Attach-imported BEGINs are never ordinary mutable install intents.
    #[serde(default)]
    import_attach_id: Option<String>,
    #[serde(default)]
    native_object_plan_id: Option<String>,
    #[serde(default)]
    source_kind: Option<InstallSourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged_object_source_json: Option<String>,
    #[serde(default)]
    stage_id: Option<String>,
    #[serde(default)]
    direct_source: Option<DirectInstallSource>,
    instance_id: String,
    entrypoint: String,
    grants_json: String,
    #[serde(default)]
    disclose_json: Option<String>,
    issued_at_ms: u64,
    request_b64: String,
    commit_hash: String,
    policy_hash: String,
    snapshot_json: String,
    protocol_digest: String,
    #[serde(default)]
    steps: Vec<InstallStep>,
    #[serde(default)]
    accepted: Option<AcceptedInstall>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum InstallSourceKind {
    Staged,
    Direct,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectInstallSource {
    material_b64: String,
    #[serde(default)]
    bindings_json: Option<String>,
    source_checkpoint_json: String,
    root_package_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    object_source_json: Option<String>,
}
impl InstallRow {
    fn source_kind(&self) -> Result<InstallSourceKind, PrivatePackageInstallError> {
        match (
            self.source_kind,
            self.stage_id.as_deref(),
            &self.direct_source,
        ) {
            (None | Some(InstallSourceKind::Staged), Some(id), None) if token(id) => {
                Ok(InstallSourceKind::Staged)
            }
            (Some(InstallSourceKind::Direct), None, Some(source))
                if !source.material_b64.is_empty()
                    && !source.source_checkpoint_json.is_empty()
                    && source.root_package_digest.len() == 64 =>
            {
                Ok(InstallSourceKind::Direct)
            }
            _ => Err(PrivatePackageInstallError::Identity),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallStep {
    pub command_id: String,
    pub issued_at_ms: u64,
    pub request_b64: String,
    pub commit_hash: String,
    pub action_id: String,
    pub offset: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AcceptedInstall {
    sequence: u64,
    head: String,
    policy_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallDocument {
    v: u8,
    origin: String,
    actor_id: String,
    workspace_id: String,
    owner_key_id: String,
    rows: BTreeMap<String, InstallRow>,
}
impl InstallDocument {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        actor: &str,
        key: &str,
    ) -> Result<Self, PrivatePackageInstallError> {
        let doc = match store.read_exact_secret()? {
            Some(bytes) => serde_json::from_slice::<Self>(&bytes)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            None => Self {
                v: 1,
                origin: config.origin.clone(),
                actor_id: actor.into(),
                workspace_id: config.workspace_id.clone(),
                owner_key_id: key.into(),
                rows: BTreeMap::new(),
            },
        };
        if doc.v != 1
            || doc.origin != config.origin
            || doc.actor_id != actor
            || doc.workspace_id != config.workspace_id
            || doc.owner_key_id != key
            || doc.rows.len() > 16
            || doc
                .rows
                .iter()
                .any(|(id, row)| !token(id) || row.source_kind().is_err()
                    || row.import_attach_id.as_deref().is_some_and(|id| !token(id)))
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        Ok(doc)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), PrivatePackageInstallError> {
        store.write_exact(
            &serde_json::to_vec(self).map_err(|_| PrivatePackageInstallError::Encoding)?,
        )?;
        Ok(())
    }
}

fn reject_saved_begin_id(
    config: &SecureReadProfileConfig,
    command_id: Option<&str>,
    cancel: &CancellationToken,
) -> Result<(), PrivatePackageInstallError> {
    let Some(command_id) = command_id else {
        return Ok(());
    };
    if cancel.is_cancelled() {
        return Err(PrivatePackageInstallError::Read(SecureReadAccessError::Cancelled));
    }
    let identity = KernelIdentity::open(&config.identity_path)
        .map_err(|_| PrivatePackageInstallError::Identity)?;
    let store = SecureStateStore::open(&config.state_dir.join("private-install-operations.state"))?;
    let doc = InstallDocument::open(&store, config, identity.actor_id(), identity.key_id())?;
    if doc.rows.contains_key(command_id) {
        let scope = SecureReadProfile::new(config.clone()).local_pending_scope()?;
        if scope.origin != config.origin
            || scope.workspace_id != config.workspace_id
            || scope.owner_actor_id != identity.actor_id()
            || scope.owner_key_id != identity.key_id()
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        return Err(PrivatePackageInstallError::DuplicateBegin);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageStep {
    command_id: String,
    issued_at_ms: u64,
    request_b64: String,
    commit_hash: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageRow {
    /// Imported historical rows are invisible to ordinary stage discovery
    /// and continuation. Only the matching attach's root-locked recovery may
    /// operate on them after its PREPARED consent has been saved.
    #[serde(default)]
    import_attach_id: Option<String>,
    material_b64: String,
    source_checkpoint_json: String,
    policy_hash: String,
    source_id: String,
    root_package_digest: String,
    protocol_digest: String,
    part_count: usize,
    steps: Vec<StageStep>,
    completed: bool,
}

/// Internal attach output. Earlier requests reconstructed from authenticated
/// signed replay are never represented as original HTTP transport bytes;
/// the selected uncertain step retains its actual saved request bytes.
pub(crate) struct ImportedHistoricalStageStep {
    pub command_id: String,
    pub issued_at_ms: u64,
    pub request_wire: Vec<u8>,
    pub commit_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageDocument {
    v: u8,
    origin: String,
    actor_id: String,
    workspace_id: String,
    owner_actor_id: String,
    owner_key_id: String,
    rows: BTreeMap<String, StageRow>,
}
impl StageDocument {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        actor_id: &str,
        owner_actor_id: &str,
        owner_key_id: &str,
    ) -> Result<Self, PrivatePackageInstallError> {
        let doc = match store.read_exact_secret()? {
            Some(bytes) => serde_json::from_slice::<Self>(&bytes)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            None => Self {
                v: 1,
                origin: config.origin.clone(),
                actor_id: actor_id.to_owned(),
                workspace_id: config.workspace_id.clone(),
                owner_actor_id: owner_actor_id.to_owned(),
                owner_key_id: owner_key_id.to_owned(),
                rows: BTreeMap::new(),
            },
        };
        if doc.v != 1
            || doc.origin != config.origin
            || doc.actor_id != actor_id
            || doc.workspace_id != config.workspace_id
            || doc.owner_actor_id != owner_actor_id
            || doc.owner_key_id != owner_key_id
            || doc.rows.len() > 16
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        Ok(doc)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), PrivatePackageInstallError> {
        store.write_exact(
            &serde_json::to_vec(self).map_err(|_| PrivatePackageInstallError::Encoding)?,
        )?;
        Ok(())
    }
}

fn random_id() -> Result<String, PrivatePackageInstallError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PrivatePackageInstallError::Entropy)?;
    Ok(base64url(&bytes))
}
fn now_ms() -> Result<u64, PrivatePackageInstallError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PrivatePackageInstallError::Input)?;
    u64::try_from(now.as_millis()).map_err(|_| PrivatePackageInstallError::Input)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn number(value: &WireValue, key: &str) -> Result<u64, PrivatePackageInstallError> {
    let n = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(PrivatePackageInstallError::Input)?;
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(PrivatePackageInstallError::Input);
    };
    Ok(n as u64)
}
fn scalar(value: &WireValue, key: &str) -> Result<String, PrivatePackageInstallError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(PrivatePackageInstallError::Input)
}
fn checkpoint_json(
    source: &TransportReplayedJournal,
    sequence: u64,
    head: &str,
    policy_hash: &str,
) -> Result<String, PrivatePackageInstallError> {
    let value = serde_json::json!({"v":1,"workspace_id":source.replay().workspace_id(),
        "owner_id":source.replay().owner_actor_id(),"owner_key":source.replay().owner_signing_key(),
        "sequence":sequence,"head":head,"policy_hash":policy_hash});
    serde_json::to_string(&value).map_err(|_| PrivatePackageInstallError::Encoding)
}

fn install_step_id(begin_id: &str, offset: usize, done: bool) -> String {
    let domain = if done {
        format!("peerwork.private.install.end.v1:{begin_id}")
    } else {
        format!("peerwork.private.install.page.v1:{begin_id}:{offset}")
    };
    base64url(&sha256(domain.as_bytes()))
}
fn same_snapshot(left: &WireValue, right: &WireValue) -> bool {
    ["source", "root", "records", "heads"]
        .iter()
        .all(|field| left.get(field).is_some() && left.get(field) == right.get(field))
}
fn post_saved_private(
    config: &SecureReadProfileConfig,
    origin: &str,
    journal: &mut SecureIntentJournal,
    id: &str,
    packet: Vec<u8>,
    cancel: &CancellationToken,
) -> Result<(), PrivatePackageInstallError> {
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        config.workspace_id
    );
    let mut transport_config = TransportConfig::new(config.origin.clone()).with_options(config.transport.clone());
    transport_config.allow_loopback_http = config.allow_loopback_http;
    let transport =
        HttpTransport::new(transport_config).map_err(|_| PrivatePackageInstallError::Transport)?;
    if transport.trusted_origin() != origin {
        return Err(PrivatePackageInstallError::Transport);
    }
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| PrivatePackageInstallError::Runtime)?;
    match runtime.block_on(transport.post_exact(&path, packet, cancel)) {
        Ok(response) => {
            if !response.wire.is_empty() {
                journal.observe_response(id, &response.wire)?
            }
            if !(200..300).contains(&response.status) {
                return Err(PrivatePackageInstallError::ServerRejected(response.status));
            }
        }
        Err(TransportError::SubmittedUncertain) => {}
        Err(_) => return Err(PrivatePackageInstallError::Transport),
    }
    Ok(())
}

pub struct SecurePrivatePackageInstall {
    config: SecureReadProfileConfig,
}
impl SecurePrivatePackageInstall {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    /// Fetch a complete signed SEEDING candidate while retaining the last
    /// verified ACTIVE profile floor. Candidate bytes cannot authorize a
    /// normal read or replace the protected active generation.
    fn with_install_replay<T, F>(
        &self,
        cancel: &CancellationToken,
        consume: F,
    ) -> Result<T, PrivatePackageInstallError>
    where
        F: FnOnce(
            &TransportReplayedJournal,
            &TransportReplayedJournal,
        ) -> Result<T, PrivatePackageInstallError>,
    {
        SecureReadProfile::new(self.config.clone()).with_pinned_replay(cancel, |prior| {
            let floor = VerifiedReadFloor {
                sequence: prior.replay().sequence(),
                head: prior.replay().head().map(str::to_owned),
                policy_hash: prior.replay().policy_hash().to_owned(),
            };
            let access = SecureReadAccess::new(SecureReadConfig {
            transport: self.config.transport.clone(),
                origin: prior.origin().to_owned(),
                kernel_journal_path: self.config.state_dir.join("kernel.sqlite"),
                read_state_path: self.config.state_dir.join("private-install-read.state"),
                lifecycle_path: self.config.state_dir.join("lifecycle.state"),
                identity_path: self.config.identity_path.clone(),
                workspace_id: prior.replay().workspace_id().to_owned(),
                authority: prior.authority().to_owned(),
                owner_actor_id: prior.replay().owner_actor_id().to_owned(),
                owner_key_id: prior.replay().owner_signing_key().to_owned(),
                required_features: self.config.required_features.clone(),
                allow_loopback_http: self.config.allow_loopback_http,
                max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            max_replay_commits: self.config.max_replay_commits,
            });
            let (fresh, _) = access.replay_checked_install_generation(cancel, &floor)?;
            if fresh.origin() != prior.origin()
                || fresh.authority() != prior.authority()
                || fresh.replay().workspace_id() != prior.replay().workspace_id()
                || fresh.replay().owner_actor_id() != prior.replay().owner_actor_id()
                || fresh.replay().owner_signing_key() != prior.replay().owner_signing_key()
            {
                return Err(PrivatePackageInstallError::Identity);
            }
            consume(prior, &fresh)
        })
    }

    /// Attach-tagged BEGINs pin their historical ACTIVE predecessor from the
    /// complete current signed replay. No ordinary profile floor is advanced
    /// while the journal is SEEDING, and no caller-supplied checkpoint alone
    /// can authorize a retry or a newly signed PAGE/END.
    fn with_imported_install_replay<T, F>(
        &self,
        begin_id: &str,
        attach_id: &str,
        cancel: &CancellationToken,
        consume: F,
    ) -> Result<T, PrivatePackageInstallError>
    where
        F: FnOnce(&TransportReplayedJournal, &TransportReplayedJournal)
            -> Result<T, PrivatePackageInstallError>,
    {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(
            &self.config.state_dir.join("private-install-operations.state"),
        )?;
        let doc = InstallDocument::open(
            &store, &self.config, identity.actor_id(), identity.key_id(),
        )?;
        let row = doc.rows.get(begin_id).ok_or(PrivatePackageInstallError::Input)?;
        if row.import_attach_id.as_deref() != Some(attach_id)
        { return Err(PrivatePackageInstallError::Plan); }
        let source_checkpoint = match row.source_kind()? {
            InstallSourceKind::Direct => row.direct_source.as_ref().ok_or(PrivatePackageInstallError::Plan)?.source_checkpoint_json.clone(),
            InstallSourceKind::Staged => {
                // StageRow retains the pre-stage source. Imported replay must
                // pin the distinct original BEGIN's post-stage predecessor.
                let wire = decode_base64url(&row.request_b64).map_err(|_| PrivatePackageInstallError::Plan)?;
                let request = parse_wire_json_bounded(&wire, 64, 220_000).map_err(|_| PrivatePackageInstallError::Plan)?;
                let payload = request.get("commit").and_then(|commit| commit.get("payload")).ok_or(PrivatePackageInstallError::Plan)?;
                let policy = request.get("policy_update").and_then(|policy| policy.get("payload")).ok_or(PrivatePackageInstallError::Plan)?;
                serde_json::json!({"v":1,"workspace_id":self.config.workspace_id,
                    "owner_id":identity.actor_id(),"owner_key":identity.key_id(),
                    "sequence":number(payload,"sequence")?.checked_sub(1).ok_or(PrivatePackageInstallError::Plan)?,
                    "head":scalar(payload,"previous")?,"policy_hash":scalar(policy,"previous_policy")?}).to_string()
            },
        };
        drop(doc);
        drop(store);
        let lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"), &crate::transport::canonical_lifecycle_origin(&self.config.origin, self.config.allow_loopback_http).map_err(|_| PrivatePackageInstallError::Input)?,
            identity.actor_id(), &self.config.workspace_id,
            identity.actor_id(), identity.key_id(),
        ).map_err(|_| PrivatePackageInstallError::Identity)?;
        let ring_wire = lifecycle.active_keyring_without_pending()
            .ok_or(PrivatePackageInstallError::Identity)?
            .canonical_wire().map_err(|_| PrivatePackageInstallError::Identity)?;
        let ring = SecretKeyring::parse_wire(&ring_wire)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        // The fresh replay reopens lifecycle.state. Keep an owned protected
        // ring and release this nonblocking store lock before that read.
        drop(lifecycle);
        let access = SecureReadAccess::new(SecureReadConfig {
            transport: self.config.transport.clone(),
            origin: self.config.origin.clone(),
            kernel_journal_path: self.config.state_dir.join("kernel.sqlite"),
            read_state_path: self.config.state_dir.join("private-install-imported-read.state"),
            lifecycle_path: self.config.state_dir.join("lifecycle.state"),
            identity_path: self.config.identity_path.clone(),
            workspace_id: self.config.workspace_id.clone(),
            authority: self.config.authority.clone()
                .ok_or(PrivatePackageInstallError::Identity)?,
            owner_actor_id: identity.actor_id().to_owned(),
            owner_key_id: identity.key_id().to_owned(),
            required_features: self.config.required_features.clone(),
            allow_loopback_http: self.config.allow_loopback_http,
            max_replay_artifact_bytes: self.config.max_replay_artifact_bytes,
            max_replay_commits: self.config.max_replay_commits,
        });
        let fresh = access.replay_checked_attach_generation(cancel)?;
        if fresh.replay().owner_actor_id() != identity.actor_id()
            || fresh.replay().owner_signing_key() != identity.key_id()
        { return Err(PrivatePackageInstallError::Identity); }
        let current_policy = fresh.signed_policy_by_hash(fresh.replay().policy_hash())
            .ok_or(PrivatePackageInstallError::Plan)?;
        let current = parse_wire_json_bounded(current_policy, 64, 196_608)
            .map_err(|_| PrivatePackageInstallError::Plan)?;
        let payload = current.get("payload").ok_or(PrivatePackageInstallError::Plan)?;
        let current_epoch = number(payload, "epoch")?;
        let owner_current = matches!(payload.get("members"), Some(WireValue::Array(members))
            if members.iter().any(|member| {
                member.get("actor_id").and_then(WireValue::as_string).as_deref()
                    == Some(identity.actor_id())
                    && member.get("role").and_then(WireValue::as_string).as_deref()
                        == Some("OWNER")
                    && member.get("certificate").and_then(|cert| cert.get("payload"))
                        .and_then(|cert| cert.get("signing_key"))
                        .and_then(WireValue::as_string).as_deref() == Some(identity.key_id())
            }));
        if !owner_current || payload.get("visibility")
            .and_then(WireValue::as_string).as_deref() != Some("PRIVATE")
            || ring.epochs().last() != Some(current_epoch)
        { return Err(PrivatePackageInstallError::Plan); }
        let prior = fresh.authenticated_active_prefix(source_checkpoint.as_bytes(), &ring)
            .map_err(|_| PrivatePackageInstallError::Plan)?;
        consume(&prior, &fresh)
    }

    /// Discover protected generated BEGIN IDs without a network request.
    /// A row is an intent, never evidence that installation was accepted.
    pub fn installs_json(&self) -> Result<String, PrivatePackageInstallError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || scope.owner_actor_id != identity.actor_id()
            || scope.owner_key_id != identity.key_id()
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        let store = SecureStateStore::open(
            &self
                .config
                .state_dir
                .join("private-install-operations.state"),
        )?;
        let doc =
            InstallDocument::open(&store, &self.config, identity.actor_id(), identity.key_id())?;
        let rows: Result<Vec<_>, PrivatePackageInstallError> = doc
            .rows
            .iter()
            .filter(|(_, row)| row.import_attach_id.is_none())
            .map(|(id, row)| {
                let kind = row.source_kind()?;
                let mut item = serde_json::json!({
                    "begin_command_id":id,
                    "source_kind":kind,
                    "workspace_id":doc.workspace_id,
                    "instance_id":row.instance_id,
                    "protocol_digest":row.protocol_digest,
                    "locally_saved":true
                });
                if let Some(stage_id) = &row.stage_id {
                    item["stage_id"] = serde_json::Value::String(stage_id.clone());
                }
                Ok(item)
            })
            .collect();
        let rows = rows?;
        serde_json::to_string(&rows).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Link one exact historical direct BEGIN to a previously durable
    /// attachment. This is an idempotent local write; it never submits the
    /// saved request or makes the imported row visible to ordinary clients.
    pub(crate) fn save_imported_direct_begin_row_for_attach(
        &self,
        imported: ImportedHistoricalDirectBegin,
    ) -> Result<(), PrivatePackageInstallError> {
        self.save_attach_direct_begin_row(imported, None)
    }

    /// A new native BEGIN authorized by one protected object-stage plan.
    /// Reopening this exact plan preserves already-saved continuation steps.
    pub(crate) fn save_native_object_begin_row_for_attach(
        &self, imported: ImportedHistoricalDirectBegin, native_plan_id: &str,
    ) -> Result<(), PrivatePackageInstallError> {
        if !token(native_plan_id) || imported.object_source_json.is_none() || imported.staged_source.is_some()
            || !imported.steps.is_empty() { return Err(PrivatePackageInstallError::Input); }
        self.save_attach_direct_begin_row(imported, Some(native_plan_id.to_owned()))
    }

    fn save_attach_direct_begin_row(&self, imported: ImportedHistoricalDirectBegin,
        native_plan_id: Option<String>) -> Result<(), PrivatePackageInstallError> {
        if !token(&imported.attach_id) || !token(&imported.command_id)
            || imported.object_source_json.as_ref().is_some_and(|wire| wire.is_empty() || wire.len() > 220_000)
            || !token(&imported.instance_id) || imported.entrypoint.is_empty()
            || imported.entrypoint.len() > 256
            || imported.request_wire.is_empty() || imported.request_wire.len() > 220_000
            || imported.material_wire.is_empty() || imported.material_wire.len() > 8 * 1024 * 1024
            || imported.bindings_json.len() > 2 * 1024 * 1024
            || imported.grants_json.len() > 2 * 1024 * 1024
            || imported.disclose_json.as_ref().is_some_and(|wire| wire.len() > 65_536)
            || imported.snapshot_json.len() > 8192
            || imported.source_checkpoint_json.len() > 8192
            || !digest(&imported.commit_hash) || !digest(&imported.source_policy_hash)
            || !digest(&imported.policy_hash)
            || !digest(&imported.protocol_digest) || !digest(&imported.root_package_digest)
        { return Err(PrivatePackageInstallError::Input); }
        let checkpoint = parse_wire_json_bounded(
            imported.source_checkpoint_json.as_bytes(), 32, 8192,
        ).map_err(|_| PrivatePackageInstallError::Input)?;
        if scalar(&checkpoint, "policy_hash")? != imported.source_policy_hash {
            return Err(PrivatePackageInstallError::Plan);
        }
        let request = parse_wire_json_bounded(&imported.request_wire, 64, 220_000)
            .map_err(|_| PrivatePackageInstallError::Input)?;
        let commit = request.get("commit").ok_or(PrivatePackageInstallError::Input)?;
        let payload = commit.get("payload").ok_or(PrivatePackageInstallError::Input)?;
        let commit_wire = canonical_wire_value(commit, CanonicalPath::SecureArtifact)
            .map_err(|_| PrivatePackageInstallError::Input)?;
        if request.object_len() != Some(2)
            || request.get("policy_update").is_none()
            || scalar(payload, "command_id")? != imported.command_id
            || scalar(payload, "action_id")? != "secure.structure.begin"
            || scalar(payload, "workspace_id")? != self.config.workspace_id
            || sha256_hex(commit_wire.as_bytes()) != imported.commit_hash
        { return Err(PrivatePackageInstallError::Plan); }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if self.config.owner_actor_id.as_deref() != Some(identity.actor_id())
            || self.config.owner_key_id.as_deref() != Some(identity.key_id())
            || scalar(payload, "actor_id")? != identity.actor_id()
            || scalar(payload, "signing_key")? != identity.key_id()
        { return Err(PrivatePackageInstallError::Identity); }
        let staged_object_source_json = if imported.staged_source.is_some() { imported.object_source_json.clone() } else { None };
        let (source_kind, stage_id, direct_source) = if let Some(source) = imported.staged_source {
            let id = base64url(&sha256(format!("peerwork.imported-package-install.v1\0{}.{}", imported.attach_id, source.source_id).as_bytes()));
            self.save_imported_stage_row_for_attach(&imported.attach_id, &id, &imported.material_wire,
                &source.source_checkpoint_json, &imported.source_policy_hash, &source.source_id,
                &imported.root_package_digest, &imported.protocol_digest, source.part_count, source.steps, true)?;
            (InstallSourceKind::Staged, Some(id), None)
        } else {
            (InstallSourceKind::Direct, None, Some(DirectInstallSource {
                material_b64: base64url(&imported.material_wire), bindings_json: Some(imported.bindings_json),
                source_checkpoint_json: imported.source_checkpoint_json, root_package_digest: imported.root_package_digest,
                object_source_json: imported.object_source_json,
            }))
        };
        let mut row = InstallRow {
            import_attach_id: Some(imported.attach_id), native_object_plan_id: native_plan_id.clone(),
            source_kind: Some(source_kind), staged_object_source_json, stage_id, direct_source,
            instance_id: imported.instance_id, entrypoint: imported.entrypoint,
            grants_json: imported.grants_json, disclose_json: imported.disclose_json,
            issued_at_ms: imported.issued_at_ms,
            request_b64: base64url(&imported.request_wire),
            commit_hash: imported.commit_hash, policy_hash: imported.policy_hash,
            snapshot_json: imported.snapshot_json,
            protocol_digest: imported.protocol_digest,
            steps: imported.steps, accepted: None,
        };
        let store = SecureStateStore::open(
            &self.config.state_dir.join("private-install-operations.state"),
        )?;
        let mut doc = InstallDocument::open(
            &store, &self.config, identity.actor_id(), identity.key_id(),
        )?;
        if let (Some(plan_id), Some(existing)) = (native_plan_id.as_ref(), doc.rows.get(&imported.command_id)) {
            if existing.native_object_plan_id.as_ref() != Some(plan_id) { return Err(PrivatePackageInstallError::Plan); }
            row.steps = existing.steps.clone();
            row.accepted = existing.accepted.clone();
        }
        match doc.rows.get(&imported.command_id) {
            Some(existing) if existing == &row => Ok(()),
            Some(_) => Err(PrivatePackageInstallError::Plan),
            None if doc.rows.len() >= 16 => Err(PrivatePackageInstallError::Plan),
            None => {
                doc.rows.insert(imported.command_id, row);
                doc.save(&store)
            }
        }
    }

    pub fn submit_begin_json(
        &self,
        input: PrivatePackageInstallBeginInput,
    ) -> Result<String, PrivatePackageInstallError> {
        self.submit_begin_json_with_cancel(input, &CancellationToken::new())
    }
    pub fn submit_begin_json_with_cancel(
        &self,
        input: PrivatePackageInstallBeginInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(&input.stage_id)
            || !token(&input.instance_id)
            || input.command_id.as_deref().is_some_and(|id| !token(id))
            || input.entrypoint.is_empty()
            || input.entrypoint.len() > 64
            || !input.entrypoint.as_bytes()[0].is_ascii_alphabetic()
            || !input
                .entrypoint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || input.entrypoint == "coordination"
        {
            return Err(PrivatePackageInstallError::Input);
        }
        reject_saved_begin_id(&self.config, input.command_id.as_deref(), cancel)?;
        let command_id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued_at = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        let result =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                source
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let identity = KernelIdentity::open(&self.config.identity_path)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                if !self.config.matches_verified_origin(source.origin())
                    || source.source_actor_id() != identity.actor_id()
                    || source.source_key_id() != identity.key_id()
                    || source.replay().owner_actor_id() != identity.actor_id()
                    || source.replay().owner_signing_key() != identity.key_id()
                    || source.replay().workspace_id() != self.config.workspace_id
                {
                    return Err(PrivatePackageInstallError::Identity);
                }
                if source.replay().structure_status() != StructureStatus::Active {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let stage_store =
                    SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
                let stage_doc = StageDocument::open(
                    &stage_store,
                    &self.config,
                    identity.actor_id(),
                    identity.actor_id(),
                    identity.key_id(),
                )?;
                let stage = stage_doc
                    .rows
                    .get(&input.stage_id)
                    .ok_or(PrivatePackageInstallError::Input)?
                    .clone();
                drop(stage_doc);
                drop(stage_store);
                let base =
                    parse_wire_json_bounded(stage.source_checkpoint_json.as_bytes(), 32, 8192)
                        .map_err(|_| PrivatePackageInstallError::Input)?;
                let base_sequence = number(&base, "sequence")?;
                let base_head = scalar(&base, "head")?;
                if !stage.completed
                    || stage.steps.len() != stage.part_count
                    || source.replay().sequence() != base_sequence + stage.part_count as u64
                    || source.replay().policy_hash() != stage.policy_hash
                    || !source.replay().contains_checkpoint(
                        base_sequence,
                        Some(&base_head),
                        &stage.policy_hash,
                    )
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                for (offset, step) in stage.steps.iter().enumerate() {
                    if !source.replay().contains_checkpoint(
                        base_sequence + offset as u64 + 1,
                        Some(&step.commit_hash),
                        &stage.policy_hash,
                    ) {
                        return Err(PrivatePackageInstallError::Plan);
                    }
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    source.replay().workspace_id(),
                    source.replay().owner_actor_id(),
                    source.replay().owner_signing_key(),
                )
                .map_err(|_| PrivatePackageInstallError::Identity)?;
                if lifecycle.active_keyring_without_pending().is_none() {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let policy_wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Input)?;
                let epoch = number(
                    policy
                        .get("payload")
                        .ok_or(PrivatePackageInstallError::Input)?,
                    "epoch",
                )?;
                let key = lifecycle
                    .active_key(epoch)
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let material = decode_base64url(&stage.material_b64)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let disclose_json = serde_json::to_string(input.disclose.as_deref().unwrap_or(&[]))
                    .map_err(|_| PrivatePackageInstallError::Input)?;
                let prepared = prepare_private_package_install_begin_with_disclosure(
                    &material,
                    stage.source_checkpoint_json.as_bytes(),
                    source.checkpoint_canonical_json().as_bytes(),
                    policy_wire,
                    source.replay().objects(),
                    input.grants_json.as_bytes(),
                    disclose_json.as_bytes(),
                    &input.instance_id,
                    &input.entrypoint,
                    &command_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                if prepared.protocol_digest() != stage.protocol_digest {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let store = SecureStateStore::open(
                    &self
                        .config
                        .state_dir
                        .join("private-install-operations.state"),
                )?;
                let mut doc = InstallDocument::open(
                    &store,
                    &self.config,
                    identity.actor_id(),
                    identity.key_id(),
                )?;
                if doc.rows.len() >= 16
                    || doc
                        .rows
                        .values()
                        .any(|existing| existing.accepted.is_none())
                    || doc.rows.contains_key(&command_id)
                {
                    return Err(PrivatePackageInstallError::Input);
                }
                let snapshot_json = peerwork_core::wire_json::canonical_wire_value(
                    prepared.snapshot(),
                    peerwork_core::canonical::Path::SecureArtifact,
                )
                .map_err(|_| PrivatePackageInstallError::Plan)?;
                let row = InstallRow {
                    import_attach_id: None, native_object_plan_id: None,
                    source_kind: Some(InstallSourceKind::Staged),
                    staged_object_source_json: None,
                    stage_id: Some(input.stage_id.clone()),
                    direct_source: None,
                    instance_id: input.instance_id.clone(),
                    entrypoint: input.entrypoint.clone(),
                    grants_json: input.grants_json.clone(),
                    disclose_json: Some(disclose_json),
                    issued_at_ms: issued_at,
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().to_owned(),
                    policy_hash: prepared.policy_hash().to_owned(),
                    snapshot_json,
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    steps: Vec::new(),
                    accepted: None,
                };
                doc.rows.insert(command_id.clone(), row);
                doc.save(&store)?;
                test_crash_after_begin_row()?;
                let mut journal = SecureIntentJournal::open(
                    &self.config.state_dir.join("private-install-intents.state"),
                    source.origin(),
                    identity.actor_id(),
                )?;
                let path = format!(
                    "/api/workspace/v1/secure/workspaces/{}/commits",
                    self.config.workspace_id
                );
                journal.prepare(SecurePacketInput {
                    intent_id: &command_id,
                    path: &path,
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                })?;
                if journal.exact_request(&command_id)? != prepared.request_wire()
                    || journal.intent_digest(&command_id)? != prepared.commit_hash()
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let mut transport_config = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
                transport_config.allow_loopback_http = self.config.allow_loopback_http;
                let transport = HttpTransport::new(transport_config)
                    .map_err(|_| PrivatePackageInstallError::Transport)?;
                if transport.trusted_origin() != source.origin() {
                    return Err(PrivatePackageInstallError::Transport);
                }
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| PrivatePackageInstallError::Runtime)?;
                match runtime.block_on(transport.post_exact(
                    &path,
                    prepared.request_wire().to_vec(),
                    cancel,
                )) {
                    Ok(response) => {
                        if !response.wire.is_empty() {
                            journal.observe_response(&command_id, &response.wire)?
                        }
                        if !(200..300).contains(&response.status) {
                            return Err(PrivatePackageInstallError::ServerRejected(
                                response.status,
                            ));
                        }
                    }
                    Err(TransportError::SubmittedUncertain) => {}
                    Err(_) => return Err(PrivatePackageInstallError::Transport),
                }
                Ok(PrivatePackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: command_id.clone(),
                    step_command_id: command_id,
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    instance_id: prepared.instance_id().to_owned(),
                    commit_hash: prepared.commit_hash().to_owned(),
                })
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Begin a direct install from protected local package selection. This
    /// shares the staged install's durable BEGIN/PAGE/END operation journal;
    /// no package stage ID or stage packet is synthesized.
    pub fn submit_direct_begin_json(
        &self,
        input: PrivateDirectInstallBeginInput,
    ) -> Result<String, PrivatePackageInstallError> {
        self.submit_direct_begin_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_direct_begin_json_with_cancel(
        &self,
        input: PrivateDirectInstallBeginInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(&input.instance_id)
            || input.command_id.as_deref().is_some_and(|id| !token(id))
            || input.entrypoint.is_empty()
            || input.entrypoint.len() > 64
            || !input.entrypoint.as_bytes()[0].is_ascii_alphabetic()
            || !input
                .entrypoint
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || input.entrypoint == "coordination"
            || input.closure_json.is_empty()
        {
            return Err(PrivatePackageInstallError::Input);
        }
        reject_saved_begin_id(&self.config, input.command_id.as_deref(), cancel)?;
        let command_id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued_at = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        let result =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                source
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let identity = KernelIdentity::open(&self.config.identity_path)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                if !self.config.matches_verified_origin(source.origin())
                    || source.source_actor_id() != identity.actor_id()
                    || source.source_key_id() != identity.key_id()
                    || source.replay().owner_actor_id() != identity.actor_id()
                    || source.replay().owner_signing_key() != identity.key_id()
                    || source.replay().workspace_id() != self.config.workspace_id
                {
                    return Err(PrivatePackageInstallError::Identity);
                }
                if source.replay().structure_status() == StructureStatus::Seeding {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    source.replay().workspace_id(),
                    source.replay().owner_actor_id(),
                    source.replay().owner_signing_key(),
                )
                .map_err(|_| PrivatePackageInstallError::Identity)?;
                if lifecycle.active_keyring_without_pending().is_none() {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let policy_wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Input)?;
                let epoch = number(
                    policy
                        .get("payload")
                        .ok_or(PrivatePackageInstallError::Input)?,
                    "epoch",
                )?;
                let key = lifecycle
                    .active_key(epoch)
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let disclose_json = serde_json::to_string(input.disclose.as_deref().unwrap_or(&[]))
                    .map_err(|_| PrivatePackageInstallError::Input)?;
                let bindings_json = input.bindings_json.as_deref().unwrap_or("{}");
                let prepared = prepare_private_direct_install_begin_with_options(
                    input.closure_json.as_bytes(),
                    bindings_json.as_bytes(),
                    &input.expected_root_package_digest,
                    &input.expected_protocol_digest,
                    source.checkpoint_canonical_json().as_bytes(),
                    policy_wire,
                    source.replay().objects(),
                    input.grants_json.as_bytes(),
                    disclose_json.as_bytes(),
                    &input.instance_id,
                    &input.entrypoint,
                    &command_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                let store = SecureStateStore::open(
                    &self
                        .config
                        .state_dir
                        .join("private-install-operations.state"),
                )?;
                let mut doc = InstallDocument::open(
                    &store,
                    &self.config,
                    identity.actor_id(),
                    identity.key_id(),
                )?;
                if doc.rows.len() >= 16
                    || doc
                        .rows
                        .values()
                        .any(|existing| existing.accepted.is_none())
                    || doc.rows.contains_key(&command_id)
                {
                    return Err(PrivatePackageInstallError::Input);
                }
                let snapshot_json =
                    canonical_wire_value(prepared.snapshot(), CanonicalPath::SecureArtifact)
                        .map_err(|_| PrivatePackageInstallError::Plan)?;
                let row = InstallRow {
                    import_attach_id: None, native_object_plan_id: None,
                    source_kind: Some(InstallSourceKind::Direct),
                    staged_object_source_json: None,
                    stage_id: None,
                    direct_source: Some(DirectInstallSource {
                        material_b64: base64url(input.closure_json.as_bytes()),
                        bindings_json: Some(bindings_json.to_owned()),
                        source_checkpoint_json: source.checkpoint_canonical_json().to_owned(),
                        root_package_digest: input.expected_root_package_digest.clone(),
                        object_source_json: None,
                    }),
                    instance_id: input.instance_id.clone(),
                    entrypoint: input.entrypoint.clone(),
                    grants_json: input.grants_json.clone(),
                    disclose_json: Some(disclose_json),
                    issued_at_ms: issued_at,
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().to_owned(),
                    policy_hash: prepared.policy_hash().to_owned(),
                    snapshot_json,
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    steps: Vec::new(),
                    accepted: None,
                };
                doc.rows.insert(command_id.clone(), row);
                doc.save(&store)?;
                test_crash_after_begin_row()?;
                let mut journal = SecureIntentJournal::open(
                    &self.config.state_dir.join("private-install-intents.state"),
                    source.origin(),
                    identity.actor_id(),
                )?;
                let path = format!(
                    "/api/workspace/v1/secure/workspaces/{}/commits",
                    self.config.workspace_id,
                );
                journal.prepare(SecurePacketInput {
                    intent_id: &command_id,
                    path: &path,
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                })?;
                if journal.exact_request(&command_id)? != prepared.request_wire()
                    || journal.intent_digest(&command_id)? != prepared.commit_hash()
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let mut transport_config = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
                transport_config.allow_loopback_http = self.config.allow_loopback_http;
                let transport = HttpTransport::new(transport_config)
                    .map_err(|_| PrivatePackageInstallError::Transport)?;
                if transport.trusted_origin() != source.origin() {
                    return Err(PrivatePackageInstallError::Transport);
                }
                let runtime = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| PrivatePackageInstallError::Runtime)?;
                match runtime.block_on(transport.post_exact(
                    &path,
                    prepared.request_wire().to_vec(),
                    cancel,
                )) {
                    Ok(response) => {
                        if !response.wire.is_empty() {
                            journal.observe_response(&command_id, &response.wire)?;
                        }
                        if !(200..300).contains(&response.status) {
                            return Err(PrivatePackageInstallError::ServerRejected(
                                response.status,
                            ));
                        }
                    }
                    Err(TransportError::SubmittedUncertain) => {}
                    Err(_) => return Err(PrivatePackageInstallError::Transport),
                }
                Ok(PrivatePackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: command_id.clone(),
                    step_command_id: command_id,
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: prepared.protocol_digest().to_owned(),
                    instance_id: prepared.instance_id().to_owned(),
                    commit_hash: prepared.commit_hash().to_owned(),
                })
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    pub fn continue_install_json(
        &self,
        begin_id: &str,
    ) -> Result<String, PrivatePackageInstallError> {
        self.continue_install_json_with_cancel(begin_id, &CancellationToken::new())
    }
    pub fn continue_install_json_with_cancel(
        &self,
        begin_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        self.continue_install_for_attach(begin_id, None, cancel)
    }

    /// Only the Owner attach recovery path may continue an imported BEGIN.
    /// Its caller must hold the attach recovery lock and reprove the protected
    /// selection before entering the producer.
    pub(crate) fn continue_imported_install_json_with_cancel(
        &self,
        begin_id: &str,
        attach_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(attach_id) { return Err(PrivatePackageInstallError::Input); }
        self.continue_install_for_attach(begin_id, Some(attach_id), cancel)
    }

    fn continue_install_for_attach(
        &self,
        begin_id: &str,
        expected_import_attach_id: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(begin_id) {
            return Err(PrivatePackageInstallError::Input);
        }
        let consume = |prior: &TransportReplayedJournal, fresh: &TransportReplayedJournal| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
            if identity.actor_id() != prior.replay().owner_actor_id()
                || identity.key_id() != prior.replay().owner_signing_key()
            {
                return Err(PrivatePackageInstallError::Identity);
            }
            let store = SecureStateStore::open(
                &self
                    .config
                    .state_dir
                    .join("private-install-operations.state"),
            )?;
            let mut doc = InstallDocument::open(
                &store,
                &self.config,
                identity.actor_id(),
                identity.key_id(),
            )?;
            let mut row = doc
                .rows
                .get(begin_id)
                .cloned()
                .ok_or(PrivatePackageInstallError::Input)?;
            if row.import_attach_id.as_deref() != expected_import_attach_id {
                return Err(PrivatePackageInstallError::Plan);
            }
            if let Some(accepted) = &row.accepted {
                if !prior.replay().contains_checkpoint(
                    accepted.sequence,
                    Some(&accepted.head),
                    &accepted.policy_hash,
                ) && !fresh.replay().contains_checkpoint(
                    accepted.sequence,
                    Some(&accepted.head),
                    &accepted.policy_hash,
                ) {
                    return Err(PrivatePackageInstallError::Plan);
                }
                return Ok(PrivatePackageInstallProgress {
                    status: "ACCEPTED",
                    begin_command_id: begin_id.into(),
                    step_command_id: row
                        .steps
                        .last()
                        .map(|s| s.command_id.clone())
                        .unwrap_or_else(|| begin_id.into()),
                    step_action_id: "secure.structure.end",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: row.protocol_digest,
                    instance_id: row.instance_id,
                    commit_hash: row
                        .steps
                        .last()
                        .map(|s| s.commit_hash.clone())
                        .unwrap_or(row.commit_hash),
                });
            }
            let (material, source_checkpoint_json) = match row.source_kind()? {
                InstallSourceKind::Staged => {
                    let stage_store = SecureStateStore::open(
                        &self.config.state_dir.join("private-install.state"),
                    )?;
                    let stage_doc = StageDocument::open(
                        &stage_store,
                        &self.config,
                        identity.actor_id(),
                        identity.actor_id(),
                        identity.key_id(),
                    )?;
                    let stage = stage_doc
                        .rows
                        .get(
                            row.stage_id
                                .as_deref()
                                .ok_or(PrivatePackageInstallError::Identity)?,
                        )
                        .cloned()
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    let base =
                        parse_wire_json_bounded(stage.source_checkpoint_json.as_bytes(), 32, 8192)
                            .map_err(|_| PrivatePackageInstallError::Input)?;
                    let base_sequence = number(&base, "sequence")?;
                    let base_head = scalar(&base, "head")?;
                    let package_end = if let Some(wire) = row.staged_object_source_json.as_ref() {
                        if row.import_attach_id.is_none() { return Err(PrivatePackageInstallError::Identity); }
                        let proof = parse_wire_json_bounded(wire.as_bytes(), 64, 220_000).map_err(|_| PrivatePackageInstallError::Plan)?;
                        peerwork_core::prepared_private_install::verify_completed_protocol_object_source(&proof, prior.replay())?;
                        number(proof.get("source").ok_or(PrivatePackageInstallError::Plan)?, "sequence")?
                    } else { prior.replay().sequence() };
                    if row.import_attach_id.is_some() && stage.import_attach_id != row.import_attach_id
                        || !stage.completed
                        || stage.steps.len() != stage.part_count
                        || package_end != base_sequence + stage.part_count as u64
                        || prior.replay().policy_hash() != stage.policy_hash
                        || !prior.replay().contains_checkpoint(
                            base_sequence,
                            Some(&base_head),
                            &stage.policy_hash,
                        )
                    {
                        return Err(PrivatePackageInstallError::Plan);
                    }
                    for (offset, step) in stage.steps.iter().enumerate() {
                        if !prior.replay().contains_checkpoint(
                            base_sequence + offset as u64 + 1,
                            Some(&step.commit_hash),
                            &stage.policy_hash,
                        ) {
                            return Err(PrivatePackageInstallError::Plan);
                        }
                    }
                    (
                        decode_base64url(&stage.material_b64)
                            .map_err(|_| PrivatePackageInstallError::Identity)?,
                        stage.source_checkpoint_json,
                    )
                }
                InstallSourceKind::Direct => {
                    let source = row
                        .direct_source
                        .as_ref()
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    if source.source_checkpoint_json != prior.checkpoint_canonical_json()
                        || prior.replay().policy_hash()
                            != scalar(
                                &parse_wire_json_bounded(
                                    source.source_checkpoint_json.as_bytes(),
                                    32,
                                    8192,
                                )
                                .map_err(|_| PrivatePackageInstallError::Identity)?,
                                "policy_hash",
                            )?
                    {
                        return Err(PrivatePackageInstallError::Plan);
                    }
                    (
                        decode_base64url(&source.material_b64)
                            .map_err(|_| PrivatePackageInstallError::Identity)?,
                        source.source_checkpoint_json.clone(),
                    )
                }
            };
            let lifecycle = SecureLifecycle::open(
                &self.config.state_dir.join("lifecycle.state"),
                prior.origin(),
                identity.actor_id(),
                prior.replay().workspace_id(),
                prior.replay().owner_actor_id(),
                prior.replay().owner_signing_key(),
            )
            .map_err(|_| PrivatePackageInstallError::Identity)?;
            if lifecycle.active_keyring_without_pending().is_none() {
                return Err(PrivatePackageInstallError::Identity);
            }
            let prior_policy = prior
                .signed_policy_by_hash(prior.replay().policy_hash())
                .ok_or(PrivatePackageInstallError::Identity)?;
            let prior_policy_value = parse_wire_json_bounded(prior_policy, 64, 196_608)
                .map_err(|_| PrivatePackageInstallError::Input)?;
            let prior_epoch = number(
                prior_policy_value
                    .get("payload")
                    .ok_or(PrivatePackageInstallError::Input)?,
                "epoch",
            )?;
            let key = lifecycle
                .active_key(prior_epoch)
                .ok_or(PrivatePackageInstallError::Identity)?;
            let exact_begin = decode_base64url(&row.request_b64)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
            let checked = match row.source_kind()? {
                InstallSourceKind::Staged => if let Some(wire) = row.staged_object_source_json.as_ref() {
                    let proof = parse_wire_json_bounded(wire.as_bytes(), 64, 220_000).map_err(|_| PrivatePackageInstallError::Plan)?;
                    peerwork_core::prepared_private_install::verify_saved_private_package_install_begin_with_object_source(
                        &exact_begin, &material, source_checkpoint_json.as_bytes(), prior.checkpoint_canonical_json().as_bytes(),
                        prior_policy, prior.replay().objects(), row.grants_json.as_bytes(),
                        row.disclose_json.as_deref().unwrap_or("[]").as_bytes(), &row.instance_id, &row.entrypoint,
                        begin_id, row.issued_at_ms, identity.signing_key(), key, &proof,
                    )?
                } else { verify_saved_private_package_install_begin_with_disclosure(
                    &exact_begin,
                    &material,
                    source_checkpoint_json.as_bytes(),
                    prior.checkpoint_canonical_json().as_bytes(),
                    prior_policy,
                    prior.replay().objects(),
                    row.grants_json.as_bytes(),
                    row.disclose_json.as_deref().unwrap_or("[]").as_bytes(),
                    &row.instance_id,
                    &row.entrypoint,
                    begin_id,
                    row.issued_at_ms,
                    identity.signing_key(),
                    key,
                )? },
                InstallSourceKind::Direct => {
                    let source = row
                        .direct_source
                        .as_ref()
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    if let Some(proof_json) = source.object_source_json.as_ref() {
                        if row.import_attach_id.is_none() { return Err(PrivatePackageInstallError::Identity); }
                        let proof = parse_wire_json_bounded(proof_json.as_bytes(), 64, 220_000).map_err(|_| PrivatePackageInstallError::Plan)?;
                        peerwork_core::prepared_private_install::verify_completed_protocol_object_source(&proof, prior.replay())?;
                        peerwork_core::prepared_private_install::verify_saved_private_direct_install_begin_with_object_source(
                            &exact_begin, &material, source.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
                            &source.root_package_digest, &row.protocol_digest, source_checkpoint_json.as_bytes(),
                            prior_policy, prior.replay().objects(), row.grants_json.as_bytes(),
                            row.disclose_json.as_deref().unwrap_or("[]").as_bytes(), &row.instance_id,
                            &row.entrypoint, begin_id, row.issued_at_ms, identity.signing_key(), key, &proof,
                        )?
                    } else { verify_saved_private_direct_install_begin_with_options(
                        &exact_begin,
                        &material,
                        source.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
                        &source.root_package_digest,
                        &row.protocol_digest,
                        source_checkpoint_json.as_bytes(),
                        prior_policy,
                        prior.replay().objects(),
                        row.grants_json.as_bytes(),
                        row.disclose_json.as_deref().unwrap_or("[]").as_bytes(),
                        &row.instance_id,
                        &row.entrypoint,
                        begin_id,
                        row.issued_at_ms,
                        identity.signing_key(),
                        key,
                    )? }
                }
            };
            if checked.commit_hash() != row.commit_hash
                || checked.policy_hash() != row.policy_hash
                || checked.protocol_digest() != row.protocol_digest
                || canonical_wire_value(checked.snapshot(), CanonicalPath::SecureArtifact)
                    .map_err(|_| PrivatePackageInstallError::Plan)?
                    != row.snapshot_json
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("private-install-intents.state"),
                prior.origin(),
                identity.actor_id(),
            )?;
            // The operation row is saved first so a crash before journal
            // preparation cannot lose a generated BEGIN ID. Reconstruct only
            // this already re-proved exact packet. prepare is idempotent for
            // an exact existing entry and refuses any mismatched metadata.
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            journal.prepare(SecurePacketInput {
                intent_id: begin_id,
                path: &path,
                action_id: "secure.structure.begin",
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &row.commit_hash,
                exact_request: &exact_begin,
            })?;
            if journal.exact_request(begin_id)? != exact_begin
                || journal.intent_digest(begin_id)? != row.commit_hash
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            if fresh.replay().sequence() == prior.replay().sequence()
                && fresh.replay().head() == prior.replay().head()
                && fresh.replay().policy_hash() == prior.replay().policy_hash()
            {
                post_saved_private(
                    &self.config,
                    prior.origin(),
                    &mut journal,
                    begin_id,
                    exact_begin,
                    cancel,
                )?;
                return Ok(PrivatePackageInstallProgress {
                    status: "PENDING",
                    begin_command_id: begin_id.into(),
                    step_command_id: begin_id.into(),
                    step_action_id: "secure.structure.begin",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: row.protocol_digest,
                    instance_id: row.instance_id,
                    commit_hash: row.commit_hash,
                });
            }
            if !fresh.replay().contains_checkpoint(
                prior.replay().sequence() + 1,
                Some(&row.commit_hash),
                &row.policy_hash,
            ) || fresh.replay().policy_hash() != row.policy_hash
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            for (index, step) in row.steps.iter().enumerate() {
                let sequence = prior.replay().sequence() + 2 + index as u64;
                if fresh.replay().sequence() >= sequence
                    && !fresh.replay().contains_checkpoint(
                        sequence,
                        Some(&step.commit_hash),
                        &row.policy_hash,
                    )
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
            }
            if fresh.replay().structure_status() == StructureStatus::Active {
                let end = row.steps.last().ok_or(PrivatePackageInstallError::Plan)?;
                if end.action_id != "secure.structure.end"
                    || !fresh.replay().contains_checkpoint(
                        prior.replay().sequence() + 1 + row.steps.len() as u64,
                        Some(&end.commit_hash),
                        &row.policy_hash,
                    )
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                fresh
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let found = fresh.replay().objects().iter().any(|object| {
                    object.get("kind").and_then(WireValue::as_string).as_deref()
                        == Some("instances")
                        && object.get("id").and_then(WireValue::as_string).as_deref()
                            == Some(&row.instance_id)
                        && object
                            .get("value")
                            .and_then(|value| value.get("protocol_digest"))
                            .and_then(WireValue::as_string)
                            .as_deref()
                            == Some(&row.protocol_digest)
                });
                if !found {
                    return Err(PrivatePackageInstallError::Plan);
                }
                row.accepted = Some(AcceptedInstall {
                    sequence: fresh.replay().sequence(),
                    head: fresh
                        .replay()
                        .head()
                        .ok_or(PrivatePackageInstallError::Plan)?
                        .into(),
                    policy_hash: fresh.replay().policy_hash().into(),
                });
                doc.rows.insert(begin_id.into(), row.clone());
                doc.save(&store)?;
                return Ok(PrivatePackageInstallProgress {
                    status: "ACCEPTED",
                    begin_command_id: begin_id.into(),
                    step_command_id: end.command_id.clone(),
                    step_action_id: "secure.structure.end",
                    workspace_id: self.config.workspace_id.clone(),
                    protocol_digest: row.protocol_digest,
                    instance_id: row.instance_id,
                    commit_hash: end.commit_hash.clone(),
                });
            }
            if fresh.replay().structure_status() != StructureStatus::Seeding {
                return Err(PrivatePackageInstallError::Plan);
            }
            let signed_snapshot = fresh
                .replay()
                .structure_snapshot()
                .ok_or(PrivatePackageInstallError::Plan)?;
            let beginning = parse_wire_json_bounded(row.snapshot_json.as_bytes(), 32, 8192)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            if !same_snapshot(signed_snapshot, &beginning) {
                return Err(PrivatePackageInstallError::Plan);
            }
            let signed_policy = fresh
                .signed_policy_by_hash(&row.policy_hash)
                .ok_or(PrivatePackageInstallError::Plan)?;
            let policy = parse_wire_json_bounded(signed_policy, 64, 196_608)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            let structure = policy
                .get("payload")
                .and_then(|p| p.get("structure"))
                .ok_or(PrivatePackageInstallError::Plan)?;
            let plan = plan_public_install_snapshot(
                prior.replay().objects(),
                structure,
                &parse_wire_json_bounded(prior.checkpoint_canonical_json().as_bytes(), 32, 8192)
                    .map_err(|_| PrivatePackageInstallError::Plan)?,
            )
            .map_err(|_| PrivatePackageInstallError::Plan)?;
            if !same_snapshot(plan.snapshot(), &beginning) {
                return Err(PrivatePackageInstallError::Plan);
            }
            let offset = usize::try_from(number(signed_snapshot, "offset")?)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            let total = plan
                .records()
                .len()
                .checked_add(plan.heads().len())
                .ok_or(PrivatePackageInstallError::Plan)?;
            if offset > total {
                return Err(PrivatePackageInstallError::Plan);
            }
            let done = offset == total;
            // Legacy PAGE/END IDs are random. Only imported rows may select
            // a saved step by its already verified snapshot offset; ordinary
            // rows retain the deterministic native ID convention.
            let native_step_id = install_step_id(begin_id, offset, done);
            let candidates: Vec<_> = row.steps.iter().filter(|step|
                if expected_import_attach_id.is_some() { step.offset == offset }
                else { step.command_id == native_step_id }
            ).cloned().collect();
            if candidates.len() > 1 { return Err(PrivatePackageInstallError::Plan); }
            let existing = candidates.into_iter().next();
            let step_id = existing.as_ref().map(|step| step.command_id.clone())
                .unwrap_or(native_step_id);
            let issued_at = existing
                .as_ref()
                .map(|step| step.issued_at_ms)
                .unwrap_or(now_ms()?);
            let signed = if let Some(step) = &existing {
                if step.offset != offset
                    || step.action_id
                        != if done {
                            "secure.structure.end"
                        } else {
                            "secure.structure.page"
                        }
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let saved = decode_base64url(&step.request_b64)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let verified = verify_saved_private_package_install_step(
                    &saved,
                    signed_policy,
                    fresh.checkpoint_canonical_json().as_bytes(),
                    signed_snapshot,
                    &plan,
                    &step_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                if verified.commit_hash() != step.commit_hash {
                    return Err(PrivatePackageInstallError::Plan);
                }
                verified
            } else {
                if fresh.replay().sequence()
                    != prior.replay().sequence() + 1 + row.steps.len() as u64
                {
                    return Err(PrivatePackageInstallError::Plan);
                }
                let authored = prepare_private_package_install_step(
                    signed_policy,
                    fresh.checkpoint_canonical_json().as_bytes(),
                    signed_snapshot,
                    &plan,
                    &step_id,
                    issued_at,
                    identity.signing_key(),
                    key,
                )?;
                row.steps.push(InstallStep {
                    command_id: step_id.clone(),
                    issued_at_ms: issued_at,
                    request_b64: base64url(authored.request_wire()),
                    commit_hash: authored.commit_hash().into(),
                    action_id: authored.action_id().into(),
                    offset,
                });
                doc.rows.insert(begin_id.into(), row.clone());
                doc.save(&store)?;
                authored
            };
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            journal.prepare(SecurePacketInput {
                intent_id: &step_id,
                path: &path,
                action_id: signed.action_id(),
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: signed.commit_hash(),
                exact_request: signed.request_wire(),
            })?;
            if journal.exact_request(&step_id)? != signed.request_wire()
                || journal.intent_digest(&step_id)? != signed.commit_hash()
            {
                return Err(PrivatePackageInstallError::Plan);
            }
            post_saved_private(
                &self.config,
                fresh.origin(),
                &mut journal,
                &step_id,
                signed.request_wire().to_vec(),
                cancel,
            )?;
            Ok(PrivatePackageInstallProgress {
                status: "PENDING",
                begin_command_id: begin_id.into(),
                step_command_id: step_id,
                step_action_id: signed.action_id(),
                workspace_id: self.config.workspace_id.clone(),
                protocol_digest: row.protocol_digest,
                instance_id: row.instance_id,
                commit_hash: signed.commit_hash().into(),
            })
        };
        let result = if let Some(attach_id) = expected_import_attach_id {
            self.with_imported_install_replay(begin_id, attach_id, cancel, consume)?
        } else {
            self.with_install_replay(cancel, consume)?
        };
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Local protected discovery, including completed stage IDs. This does
    /// not fetch the journal or claim that any saved packet was accepted.
    pub fn stages_json(&self) -> Result<String, PrivatePackageInstallError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || identity.actor_id() != scope.owner_actor_id
            || identity.key_id() != scope.owner_key_id
        {
            return Err(PrivatePackageInstallError::Identity);
        };
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store,
            &self.config,
            identity.actor_id(),
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )?;
        let rows:Vec<_>=doc.rows.iter().filter(|(_,row)| row.import_attach_id.is_none()).map(|(id,row)|serde_json::json!({"stage_id":id,"workspace_id":doc.workspace_id,
            "source_id":row.source_id,"root_package_digest":row.root_package_digest,"protocol_digest":row.protocol_digest,
            "part_count":row.part_count,"saved_steps":row.steps.len(),"locally_verified_complete":row.completed})).collect();
        serde_json::to_string(&rows).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Save an attach-provenance stage row only after the matching PREPARED
    /// attachment is durable. This method makes no network request and does
    /// not grant ordinary stage APIs access to the imported packet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn save_imported_stage_row_for_attach(
        &self,
        attach_id: &str,
        stage_id: &str,
        material: &[u8],
        source_checkpoint_json: &str,
        policy_hash: &str,
        source_id: &str,
        root_package_digest: &str,
        protocol_digest: &str,
        part_count: usize,
        steps: Vec<ImportedHistoricalStageStep>,
        completed: bool,
    ) -> Result<(), PrivatePackageInstallError> {
        if !token(attach_id) || !token(stage_id)
            || material.is_empty() || material.len() > 8 * 1024 * 1024
            || !digest(policy_hash) || !digest(source_id)
            || !digest(root_package_digest) || !digest(protocol_digest)
            || part_count == 0 || part_count > peerwork_core::prepared_private_install::MAX_PACKAGE_SOURCE_PARTS
            || steps.is_empty() || steps.len() > part_count
            || completed && steps.len() != part_count
            || steps.iter().any(|step| !token(&step.command_id)
                || !digest(&step.commit_hash) || step.request_wire.is_empty()
                || step.request_wire.len() > 262_144)
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let checkpoint = parse_wire_json_bounded(source_checkpoint_json.as_bytes(), 32, 8192)
            .map_err(|_| PrivatePackageInstallError::Input)?;
        if number(&checkpoint, "sequence").is_err()
            || scalar(&checkpoint, "head").is_err()
            || scalar(&checkpoint, "policy_hash")? != policy_hash
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if self.config.owner_actor_id.as_deref() != Some(identity.actor_id())
            || self.config.owner_key_id.as_deref() != Some(identity.key_id()) {
            return Err(PrivatePackageInstallError::Identity);
        }
        let row = StageRow {
            import_attach_id: Some(attach_id.into()),
            material_b64: base64url(material),
            source_checkpoint_json: source_checkpoint_json.into(),
            policy_hash: policy_hash.into(), source_id: source_id.into(),
            root_package_digest: root_package_digest.into(),
            protocol_digest: protocol_digest.into(), part_count,
            steps: steps.into_iter().map(|step| StageStep {
                command_id: step.command_id, issued_at_ms: step.issued_at_ms,
                request_b64: base64url(&step.request_wire), commit_hash: step.commit_hash,
            }).collect(),
            completed,
        };
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let mut doc = StageDocument::open(
            &store, &self.config, identity.actor_id(), identity.actor_id(), identity.key_id(),
        )?;
        match doc.rows.get(stage_id) {
            Some(existing) if existing == &row => Ok(()),
            Some(_) => Err(PrivatePackageInstallError::Plan),
            None => {
                doc.rows.insert(stage_id.into(), row);
                doc.save(&store)
            }
        }
    }

    pub fn stage_package_json(
        &self,
        input: PrivatePackageStageInput,
    ) -> Result<String, PrivatePackageInstallError> {
        self.stage_package_json_with_cancel(input, &CancellationToken::new())
    }
    pub fn stage_package_json_with_cancel(
        &self,
        input: PrivatePackageStageInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        self.stage_package_json_with_expected_source(input, None, cancel)
    }

    pub(crate) fn stage_exact_orphan_json_with_cancel(
        &self,
        input: PrivatePackageStageInput,
        expected_source_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !digest(expected_source_id) { return Err(PrivatePackageInstallError::Input); }
        self.stage_package_json_with_expected_source(input, Some(expected_source_id), cancel)
    }

    /// Restricted Owner-attach producer for a new stage after a packetless
    /// legacy orphan. The caller persisted the exact stage and first-command
    /// IDs under the attach root lock; the row remains attach-tagged and is
    /// never exposed to ordinary stage continuation.
    pub(crate) fn stage_exact_imported_orphan_json_with_cancel(
        &self,
        input: PrivatePackageStageInput,
        attach_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        let stage_id = input.stage_id.as_deref().ok_or(PrivatePackageInstallError::Input)?;
        let command_id = input.command_id.as_deref().ok_or(PrivatePackageInstallError::Input)?;
        let issued_at = input.issued_at_ms.ok_or(PrivatePackageInstallError::Input)?;
        if !token(attach_id) || !token(stage_id) || !token(command_id)
            || !digest(&input.expected_root_package_digest)
            || !digest(&input.expected_protocol_digest)
            || input.material_json.is_empty() || input.material_json.len() > 8 * 1024 * 1024
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let result = SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            self.stage_from_replay(source, &input, stage_id, command_id, issued_at,
                None, Some(attach_id), cancel)
        })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    fn stage_package_json_with_expected_source(
        &self,
        input: PrivatePackageStageInput,
        expected_source_id: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !digest(&input.expected_root_package_digest)
            || !digest(&input.expected_protocol_digest)
            || input.material_json.is_empty()
            || input.material_json.len() > 8 * 1024 * 1024
            || input.stage_id.as_deref().is_some_and(|id| !token(id))
            || input.command_id.as_deref().is_some_and(|id| !token(id))
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let stage_id = input.stage_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let command_id = input.command_id.clone().map(Ok).unwrap_or_else(random_id)?;
        let issued_at = input.issued_at_ms.map(Ok).unwrap_or_else(now_ms)?;
        let result =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                self.stage_from_replay(source, &input, &stage_id, &command_id, issued_at, expected_source_id, None, cancel)
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Resume a locally discoverable stage without caller-held material or
    /// internal paths. The saved packet remains the only candidate for retry.
    pub fn continue_stage_json(
        &self,
        stage_id: &str,
    ) -> Result<String, PrivatePackageInstallError> {
        self.continue_stage_json_with_cancel(stage_id, &CancellationToken::new())
    }
    pub fn continue_stage_json_with_cancel(
        &self,
        stage_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        self.continue_stage_for_attach(stage_id, None, cancel)
    }

    /// The Owner attach caller holds its root recovery lock and has re-proved
    /// the exact imported packet, material and signed prefix before invoking
    /// this restricted continuation. The row keeps its attach provenance.
    pub(crate) fn continue_imported_stage_json_with_cancel(
        &self,
        stage_id: &str,
        attach_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(attach_id) { return Err(PrivatePackageInstallError::Input); }
        self.continue_stage_for_attach(stage_id, Some(attach_id), cancel)
    }

    /// Return the exact final saved step only after this attach-owned row has
    /// reconciled every part with signed replay. The caller must additionally
    /// verify the complete source and current Owner authority before unlock.
    pub(crate) fn imported_stage_final_step_for_attach(
        &self,
        stage_id: &str,
        attach_id: &str,
        source_id: &str,
        part_count: usize,
    ) -> Result<(String, String), PrivatePackageInstallError> {
        if !token(stage_id) || !token(attach_id) || !digest(source_id) {
            return Err(PrivatePackageInstallError::Input);
        }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store, &self.config, identity.actor_id(), identity.actor_id(), identity.key_id(),
        )?;
        let row = doc.rows.get(stage_id).ok_or(PrivatePackageInstallError::Plan)?;
        if row.import_attach_id.as_deref() != Some(attach_id)
            || row.source_id != source_id || row.part_count != part_count
            || !row.completed || row.steps.len() != part_count
        {
            return Err(PrivatePackageInstallError::Plan);
        }
        let final_step = row.steps.last().ok_or(PrivatePackageInstallError::Plan)?;
        Ok((final_step.command_id.clone(), final_step.commit_hash.clone()))
    }

    #[cfg(test)]
    pub(crate) fn imported_stage_saved_step_for_attach(
        &self,
        stage_id: &str,
        attach_id: &str,
        index: usize,
    ) -> Result<(String, String, String), PrivatePackageInstallError> {
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store, &self.config, identity.actor_id(), identity.actor_id(), identity.key_id(),
        )?;
        let row = doc.rows.get(stage_id).ok_or(PrivatePackageInstallError::Plan)?;
        if row.import_attach_id.as_deref() != Some(attach_id)
            || index >= row.part_count {
            return Err(PrivatePackageInstallError::Plan);
        }
        let step = row.steps.get(index).ok_or(PrivatePackageInstallError::Plan)?;
        let exact = decode_base64url(&step.request_b64)
            .map_err(|_| PrivatePackageInstallError::Plan)?;
        Ok((step.command_id.clone(), step.commit_hash.clone(), sha256_hex(&exact)))
    }

    fn continue_stage_for_attach(
        &self,
        stage_id: &str,
        expected_import_attach_id: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(stage_id) {
            return Err(PrivatePackageInstallError::Input);
        };
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || scope.owner_actor_id != identity.actor_id()
            || scope.owner_key_id != identity.key_id()
        {
            return Err(PrivatePackageInstallError::Identity);
        };
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store,
            &self.config,
            identity.actor_id(),
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )?;
        let row = doc
            .rows
            .get(stage_id)
            .ok_or(PrivatePackageInstallError::Input)?;
        if row.import_attach_id.as_deref() != expected_import_attach_id {
            return Err(PrivatePackageInstallError::Plan);
        }
        let material = decode_base64url(&row.material_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let input = PrivatePackageStageInput {
            material_json: String::from_utf8(material)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            expected_root_package_digest: row.root_package_digest.clone(),
            expected_protocol_digest: row.protocol_digest.clone(),
            stage_id: Some(stage_id.to_owned()),
            command_id: None,
            issued_at_ms: None,
        };
        drop(doc);
        drop(store);
        let result = SecureReadProfile::new(self.config.clone())
            .with_latest_replay(cancel, |source| {
                self.stage_from_replay(source, &input, stage_id, stage_id, 0, None, expected_import_attach_id, cancel)
            })?;
        serde_json::to_string(&result).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    /// Internal restricted Owner handoff: return None only when the producer
    /// has not yet saved its first packet. A saved stage must retain the exact
    /// command/time/material chosen in the prior protected attach mapping.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn continue_exact_orphan_stage_json_with_cancel(
        &self,
        stage_id: &str,
        command_id: &str,
        issued_at_ms: u64,
        material_sha256: &str,
        source_id: &str,
        root_package_digest: &str,
        protocol_digest: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<String>, PrivatePackageInstallError> {
        if !token(stage_id) || !token(command_id) || !digest(material_sha256)
            || !digest(source_id) || !digest(root_package_digest) || !digest(protocol_digest)
        {
            return Err(PrivatePackageInstallError::Input);
        }
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if scope.origin != self.config.origin
            || scope.workspace_id != self.config.workspace_id
            || scope.owner_actor_id != identity.actor_id()
            || scope.owner_key_id != identity.key_id()
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let doc = StageDocument::open(
            &store, &self.config, identity.actor_id(),
            &scope.owner_actor_id, &scope.owner_key_id,
        )?;
        let Some(row) = doc.rows.get(stage_id) else { return Ok(None); };
        let material = decode_base64url(&row.material_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if sha256_hex(&material) != material_sha256
            || row.source_id != source_id
            || row.root_package_digest != root_package_digest
            || row.protocol_digest != protocol_digest
            || row.part_count != 1
            || row.steps.len() != 1
            || row.steps[0].command_id != command_id
            || row.steps[0].issued_at_ms != issued_at_ms
        {
            return Err(PrivatePackageInstallError::Plan);
        }
        let input = PrivatePackageStageInput {
            material_json: String::from_utf8(material)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
            expected_root_package_digest: root_package_digest.to_owned(),
            expected_protocol_digest: protocol_digest.to_owned(),
            stage_id: Some(stage_id.to_owned()),
            command_id: Some(command_id.to_owned()),
            issued_at_ms: Some(issued_at_ms),
        };
        drop(doc);
        drop(store);
        let result = SecureReadProfile::new(self.config.clone())
            .with_latest_replay(cancel, |source| {
                self.stage_from_replay(source, &input, stage_id, command_id, issued_at_ms, Some(source_id), None, cancel)
            })?;
        Ok(Some(serde_json::to_string(&result)
            .map_err(|_| PrivatePackageInstallError::Encoding)?))
    }

    fn stage_from_replay(
        &self,
        source: &TransportReplayedJournal,
        input: &PrivatePackageStageInput,
        stage_id: &str,
        command_id: &str,
        issued_at: u64,
        expected_source_id: Option<&str>,
        expected_import_attach_id: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<PrivatePackageStageResult, PrivatePackageInstallError> {
        source
            .verified_read()
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        if !self.config.matches_verified_origin(source.origin())
            || source.source_actor_id() != identity.actor_id()
            || source.source_key_id() != identity.key_id()
            || source.replay().workspace_id() != self.config.workspace_id
            || source.replay().owner_actor_id() != identity.actor_id()
            || source.replay().owner_signing_key() != identity.key_id()
            || source.replay().structure_status() != StructureStatus::Active
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        let lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            source.origin(),
            identity.actor_id(),
            source.replay().workspace_id(),
            source.replay().owner_actor_id(),
            source.replay().owner_signing_key(),
        )
        .map_err(|_| PrivatePackageInstallError::Identity)?;
        if lifecycle.active_keyring_without_pending().is_none() {
            return Err(PrivatePackageInstallError::Identity);
        }
        let policy_wire = source
            .signed_policy_by_hash(source.replay().policy_hash())
            .ok_or(PrivatePackageInstallError::Identity)?;
        let policy = parse_wire_json_bounded(policy_wire, 64, 196_608)
            .map_err(|_| PrivatePackageInstallError::Input)?;
        let payload = policy
            .get("payload")
            .ok_or(PrivatePackageInstallError::Input)?;
        if scalar(payload, "visibility")? != "PRIVATE" || !matches!(number(payload, "v")?, 2 | 3) {
            return Err(PrivatePackageInstallError::Input);
        };
        let epoch = number(payload, "epoch")?;
        let key = lifecycle
            .active_key(epoch)
            .ok_or(PrivatePackageInstallError::Identity)?;
        let store = SecureStateStore::open(&self.config.state_dir.join("private-install.state"))?;
        let mut doc = StageDocument::open(
            &store,
            &self.config,
            identity.actor_id(),
            source.replay().owner_actor_id(),
            source.replay().owner_signing_key(),
        )?;
        let mut journal = SecureIntentJournal::open(
            &self.config.state_dir.join("private-install-intents.state"),
            source.origin(),
            identity.actor_id(),
        )?;
        if !doc.rows.contains_key(stage_id) {
            if doc.rows.len() == 16 || doc.rows.values().any(|row| !row.completed) {
                return Err(PrivatePackageInstallError::State(
                    SecureStateError::TooLarge,
                ));
            };
            let prepared = prepare_private_package_stage(
                input.material_json.as_bytes(),
                source.checkpoint_canonical_json().as_bytes(),
                source.checkpoint_canonical_json().as_bytes(),
                policy_wire,
                0,
                command_id,
                issued_at,
                identity.signing_key(),
                key,
            )?;
            if prepared.root_package_digest() != input.expected_root_package_digest
                || prepared.protocol_digest() != input.expected_protocol_digest
                || expected_source_id.is_some_and(|source_id| prepared.source_id() != source_id)
            {
                return Err(PrivatePackageInstallError::Input);
            };
            let row = StageRow {
                import_attach_id: expected_import_attach_id.map(str::to_owned),
                material_b64: base64url(input.material_json.as_bytes()),
                source_checkpoint_json: source.checkpoint_canonical_json().to_owned(),
                policy_hash: source.replay().policy_hash().to_owned(),
                source_id: prepared.source_id().to_owned(),
                root_package_digest: prepared.root_package_digest().to_owned(),
                protocol_digest: prepared.protocol_digest().to_owned(),
                part_count: prepared.part_count(),
                steps: vec![StageStep {
                    command_id: command_id.to_owned(),
                    issued_at_ms: issued_at,
                    request_b64: base64url(prepared.request_wire()),
                    commit_hash: prepared.commit_hash().to_owned(),
                }],
                completed: false,
            };
            doc.rows.insert(stage_id.to_owned(), row);
            doc.save(&store)?;
        }
        let mut row = doc
            .rows
            .get(stage_id)
            .cloned()
            .ok_or(PrivatePackageInstallError::Identity)?;
        if row.import_attach_id.as_deref() != expected_import_attach_id {
            return Err(PrivatePackageInstallError::Plan);
        }
        if input.command_id.is_some() && row.steps.first().map(|step| step.command_id.as_str()) != Some(command_id)
            || input.issued_at_ms.is_some() && row.steps.first().map(|step| step.issued_at_ms) != Some(issued_at)
        {
            return Err(PrivatePackageInstallError::Plan);
        }
        if sha256_hex(
            &decode_base64url(&row.material_b64)
                .map_err(|_| PrivatePackageInstallError::Identity)?,
        ) != sha256_hex(input.material_json.as_bytes())
            || row.root_package_digest != input.expected_root_package_digest
            || row.protocol_digest != input.expected_protocol_digest
            || expected_source_id.is_some_and(|source_id| row.source_id != source_id)
        {
            return Err(PrivatePackageInstallError::Input);
        };
        let source_checkpoint =
            parse_wire_json_bounded(row.source_checkpoint_json.as_bytes(), 32, 8192)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
        let base = number(&source_checkpoint, "sequence")?;
        let base_head = scalar(&source_checkpoint, "head")?;
        if !source
            .replay()
            .contains_checkpoint(base, Some(&base_head), &row.policy_hash)
        {
            return Err(PrivatePackageInstallError::Plan);
        };
        let mut applied = 0usize;
        for (index, step) in row.steps.iter().enumerate() {
            let sequence = base + index as u64 + 1;
            if source.replay().contains_checkpoint(
                sequence,
                Some(&step.commit_hash),
                &row.policy_hash,
            ) {
                applied += 1;
            } else if source.replay().sequence() >= sequence {
                return Err(PrivatePackageInstallError::Plan);
            } else {
                break;
            }
        }
        if applied == row.part_count {
            if !row.completed {
                row.completed = true;
                doc.rows.insert(stage_id.to_owned(), row.clone());
                doc.save(&store)?;
            }
            return Ok(PrivatePackageStageResult {
                status: "STAGED",
                stage_id: stage_id.to_owned(),
                workspace_id: self.config.workspace_id.clone(),
                source_id: row.source_id.clone(),
                root_package_digest: row.root_package_digest.clone(),
                protocol_digest: row.protocol_digest.clone(),
                part_count: row.part_count,
                applied_parts: applied,
                pending_command_id: None,
            });
        }
        if source.replay().sequence() != base + applied as u64
            || source.replay().policy_hash() != row.policy_hash
            || applied < row.steps.len().saturating_sub(1)
        {
            return Err(PrivatePackageInstallError::Plan);
        };
        let previous = if applied == 0 {
            base_head
        } else {
            row.steps[applied - 1].commit_hash.clone()
        };
        let current_checkpoint =
            checkpoint_json(source, base + applied as u64, &previous, &row.policy_hash)?;
        if row.steps.len() == applied {
            let next_id = random_id()?;
            let next_at = now_ms()?;
            let material = decode_base64url(&row.material_b64)
                .map_err(|_| PrivatePackageInstallError::Identity)?;
            let prepared = prepare_private_package_stage(
                &material,
                row.source_checkpoint_json.as_bytes(),
                current_checkpoint.as_bytes(),
                policy_wire,
                applied,
                &next_id,
                next_at,
                identity.signing_key(),
                key,
            )?;
            if prepared.source_id() != row.source_id
                || prepared.protocol_digest() != row.protocol_digest
                || prepared.part_count() != row.part_count
            {
                return Err(PrivatePackageInstallError::Plan);
            };
            row.steps.push(StageStep {
                command_id: next_id,
                issued_at_ms: next_at,
                request_b64: base64url(prepared.request_wire()),
                commit_hash: prepared.commit_hash().to_owned(),
            });
            doc.rows.insert(stage_id.to_owned(), row.clone());
            doc.save(&store)?;
            #[cfg(test)]
            if expected_import_attach_id.is_some()
                && TEST_STOP_AFTER_IMPORTED_LATER_STAGE_ROW.swap(
                    false, std::sync::atomic::Ordering::SeqCst,
                ) {
                return Err(PrivatePackageInstallError::Runtime);
            }
        }
        let step = &row.steps[applied];
        let material = decode_base64url(&row.material_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let exact = decode_base64url(&step.request_b64)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        let checked = verify_saved_private_package_stage(
            &exact,
            &material,
            row.source_checkpoint_json.as_bytes(),
            current_checkpoint.as_bytes(),
            policy_wire,
            applied,
            &step.command_id,
            step.issued_at_ms,
            identity.signing_key(),
            key,
        )?;
        if checked.commit_hash() != step.commit_hash || checked.source_id() != row.source_id {
            return Err(PrivatePackageInstallError::Plan);
        };
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            self.config.workspace_id
        );
        journal.prepare(SecurePacketInput {
            intent_id: &step.command_id,
            path: &path,
            action_id: "secure.protocol-package.stage",
            workspace_id: Some(&self.config.workspace_id),
            trusted_owner_key: Some(identity.key_id()),
            intent_digest: &step.commit_hash,
            exact_request: &exact,
        })?;
        if journal.exact_request(&step.command_id)? != exact
            || journal.intent_digest(&step.command_id)? != step.commit_hash
        {
            return Err(PrivatePackageInstallError::Plan);
        };
        let mut transport_config = TransportConfig::new(self.config.origin.clone()).with_options(self.config.transport.clone());
        transport_config.allow_loopback_http = self.config.allow_loopback_http;
        let transport = HttpTransport::new(transport_config)
            .map_err(|_| PrivatePackageInstallError::Transport)?;
        if transport.trusted_origin() != source.origin() {
            return Err(PrivatePackageInstallError::Transport);
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PrivatePackageInstallError::Runtime)?;
        match runtime.block_on(transport.post_exact(&path, exact, cancel)) {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(&step.command_id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(PrivatePackageInstallError::ServerRejected(response.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PrivatePackageInstallError::Transport),
        }
        Ok(PrivatePackageStageResult {
            status: "PENDING",
            stage_id: stage_id.to_owned(),
            workspace_id: self.config.workspace_id.clone(),
            source_id: row.source_id.clone(),
            root_package_digest: row.root_package_digest.clone(),
            protocol_digest: row.protocol_digest.clone(),
            part_count: row.part_count,
            applied_parts: applied,
            pending_command_id: Some(step.command_id.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_action_access::PublicActionInput;
    use crate::secure_owner_create::{
        SecureOwnerCreateConfig, SecureOwnerCreateInput, SecureOwnerWorkspaceCreate,
    };
    use crate::secure_owner_format_transition::{
        OwnerFormatTransition, OwnerFormatTransitionInput,
    };
    use std::{
        fs,
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[test]
    fn saved_begin_id_preflight_refuses_both_sources_with_protected_scope() {
        let root = crate::test_support::protected_test_dir();
        let state_dir = root.path().join("state");
        #[cfg(windows)]
        crate::windows_fs::create_private_directory(&state_dir).unwrap();
        #[cfg(not(windows))]
        fs::create_dir(&state_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity_path = state_dir.join("owner.state");
        let identity = KernelIdentity::create(&identity_path).unwrap();
        let config = SecureReadProfileConfig {
            transport: Default::default(),
            origin: "https://example.invalid/".into(),
            state_dir: state_dir.clone(),
            identity_path: identity_path.clone(),
            workspace_id: "w".repeat(43),
            owner_actor_id: Some(identity.actor_id().into()),
            owner_key_id: Some(identity.key_id().into()),
            authority: Some("a".repeat(64)),
            required_features: vec![],
            allow_loopback_http: false,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let profile = serde_json::json!({
            "version":1,"origin":config.origin,"identity_path":config.identity_path,
            "workspace_id":config.workspace_id,"authority":config.authority,
            "owner_actor_id":identity.actor_id(),"owner_key_id":identity.key_id(),
            "required_features":[],"allow_loopback_http":false,"current":0,
            "staged":null,"staged_ready":false,
            "floor":{"sequence":1,"head":"h".repeat(64),"policy_hash":"p".repeat(64)}
        });
        SecureStateStore::open(&state_dir.join("read.profile")).unwrap()
            .write_exact(&serde_json::to_vec(&profile).unwrap()).unwrap();
        let store = SecureStateStore::open(&state_dir.join("private-install-operations.state")).unwrap();
        let mut doc = InstallDocument::open(&store, &config, identity.actor_id(), identity.key_id()).unwrap();
        let row = |kind: InstallSourceKind| InstallRow {
            import_attach_id: None, native_object_plan_id: None,
            source_kind: Some(kind),
            staged_object_source_json: None,
            stage_id: (kind == InstallSourceKind::Staged).then(|| "s".repeat(43)),
            direct_source: (kind == InstallSourceKind::Direct).then(|| DirectInstallSource {
                material_b64: "e30".into(), bindings_json: Some("{}".into()),
                source_checkpoint_json: "{}".into(), root_package_digest: "d".repeat(64),
                object_source_json: None,
            }),
            instance_id: "i".repeat(43), entrypoint: "readable".into(),
            grants_json: "[]".into(), disclose_json: Some("[]".into()),
            issued_at_ms: 1, request_b64: "e30".into(),
            commit_hash: "c".repeat(64), policy_hash: "p".repeat(64),
            snapshot_json: "{}".into(), protocol_digest: "d".repeat(64),
            steps: vec![], accepted: None,
        };
        // Existing rows omit the additive field; protected serialization must
        // retain both sources when a combined imported row is reopened.
        let legacy = row(InstallSourceKind::Staged);
        let legacy_wire = serde_json::to_value(&legacy).unwrap();
        assert!(legacy_wire.get("staged_object_source_json").is_none());
        let decoded: InstallRow = serde_json::from_value(legacy_wire).unwrap();
        assert!(decoded.staged_object_source_json.is_none());
        let combined_id = "b".repeat(43);
        let mut combined = row(InstallSourceKind::Staged);
        combined.import_attach_id = Some("a".repeat(43));
        combined.staged_object_source_json = Some("{\"retained_encoding_test\":true}".into());
        doc.rows.insert(combined_id.clone(), combined);
        let direct_id = "d".repeat(43);
        let staged_id = "t".repeat(43);
        doc.rows.insert(direct_id.clone(), row(InstallSourceKind::Direct));
        doc.rows.insert(staged_id.clone(), row(InstallSourceKind::Staged));
        doc.save(&store).unwrap();
        let reopened = InstallDocument::open(&store, &config, identity.actor_id(), identity.key_id()).unwrap();
        let retained = reopened.rows.get(&combined_id).unwrap();
        assert_eq!(retained.source_kind().unwrap(), InstallSourceKind::Staged);
        assert_eq!(retained.stage_id.as_deref(), Some("s".repeat(43).as_str()));
        assert_eq!(retained.staged_object_source_json.as_deref(), Some("{\"retained_encoding_test\":true}"));
        assert!(reopened.rows[&direct_id].staged_object_source_json.is_none());
        assert!(reopened.rows[&staged_id].staged_object_source_json.is_none());
        drop(store);
        let cancel = CancellationToken::new();
        for id in [&direct_id, &staged_id] {
            assert!(matches!(reject_saved_begin_id(&config, Some(id), &cancel),
                Err(PrivatePackageInstallError::DuplicateBegin)));
        }
        assert!(reject_saved_begin_id(&config, Some(&"n".repeat(43)), &cancel).is_ok());
        let mut wrong = config.clone();
        wrong.origin = "https://other.invalid/".into();
        assert!(matches!(reject_saved_begin_id(&wrong, Some(&direct_id), &cancel),
            Err(PrivatePackageInstallError::Identity)));
        wrong = config.clone();
        wrong.workspace_id = "q".repeat(43);
        assert!(matches!(reject_saved_begin_id(&wrong, Some(&direct_id), &cancel),
            Err(PrivatePackageInstallError::Identity)));
        wrong = config.clone();
        wrong.owner_actor_id = Some("x".repeat(43));
        assert!(matches!(reject_saved_begin_id(&wrong, Some(&direct_id), &cancel),
            Err(PrivatePackageInstallError::Read(SecureReadAccessError::Profile))));
        wrong = config.clone();
        wrong.owner_key_id = Some("y".repeat(43));
        assert!(matches!(reject_saved_begin_id(&wrong, Some(&direct_id), &cancel),
            Err(PrivatePackageInstallError::Read(SecureReadAccessError::Profile))));
        SecureStateStore::open(&state_dir.join("private-install-operations.state")).unwrap()
            .write_exact(b"{").unwrap();
        assert!(matches!(reject_saved_begin_id(&config, Some(&direct_id), &cancel),
            Err(PrivatePackageInstallError::Identity)));
    }

    #[test]
    fn actual_service_private_package_stage_install_action_recovers_lost_replies() {
        run_actual_service_private_package_install(false);
    }

    #[test]
    fn actual_service_private_package_install_preserves_nonempty_pages_after_lost_reply() {
        run_actual_service_private_package_install(true);
    }

    fn run_actual_service_private_package_install(nonempty: bool) {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let config = SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("sdk-state"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let token = CancellationToken::new();
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let created = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native PRIVATE package stage".into(),
                    name_utf16: None,
                    visibility: "PRIVATE".into(),
                    structured: true,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        let result = owner.resume(&created.command_id, &token).unwrap();
        assert_eq!(result.status, "CREATED");
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let material = serde_json::json!({"v":1,"closure":vector["closure"],"bindings":{}});
        let stage = owner.private_install_access(&created.workspace_id).unwrap();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let counts = || {
            runtime.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        let prior_record = if nonempty {
            let read: serde_json::Value = serde_json::from_str(
                &owner
                    .read_workspace_json(&created.workspace_id, &token)
                    .unwrap(),
            )
            .unwrap();
            let objects = read["objects"].as_array().unwrap();
            let wiki_digest = objects
                .iter()
                .find(|object| {
                    object["kind"] == "protocols"
                        && object["value"]["manifest"]["name"] == "peerwork.wiki.v1"
                })
                .unwrap()["id"]
                .as_str()
                .unwrap();
            let wiki_instance = objects
                .iter()
                .find(|object| {
                    object["kind"] == "instances"
                        && object["value"]["protocol_digest"] == wiki_digest
                })
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let action = owner.private_action_access(&created.workspace_id).unwrap();
            let mut first_record = None;
            for index in 0..51 {
                let title = format!("Prior encrypted wiki {index}");
                let body = format!("Encrypted source history {index}");
                let submitted: serde_json::Value = serde_json::from_str(
                    &action
                        .submit_new_json(PublicActionInput {
                            action_id: "wiki.create".into(),
                            instance_id: wiki_instance.clone(),
                            body_json: serde_json::json!({"title":title,"body":body}).to_string(),
                            exact_input_refs_json: None,
                            allocations_json: None,
                            command_id: None,
                            issued_at_ms: None,
                        })
                        .unwrap(),
                )
                .unwrap();
                let accepted: serde_json::Value = serde_json::from_str(
                    &action
                        .retry_saved_json(submitted["command_id"].as_str().unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(accepted["status"], "ACCEPTED");
                let receipt: serde_json::Value =
                    serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap())
                        .unwrap();
                if index == 0 {
                    first_record = Some((
                        receipt["effects"][0]["record_id"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                        title,
                        body,
                    ));
                }
            }
            let read: serde_json::Value = serde_json::from_str(
                &owner
                    .read_workspace_json(&created.workspace_id, &token)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                read["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|object| object["kind"] == "records")
                    .count(),
                51
            );
            first_record
        } else {
            None
        };
        let before = counts()["commits"].as_u64().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let first: serde_json::Value = serde_json::from_str(
            &stage
                .stage_package_json(PrivatePackageStageInput {
                    material_json: material.to_string(),
                    expected_root_package_digest: vector["closure"]["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                    stage_id: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["status"], "PENDING");
        assert!(first["pending_command_id"].as_str().is_some());
        assert_eq!(counts()["commits"], before + 1);
        let stage_id = first["stage_id"].as_str().unwrap();
        drop(stage);
        drop(owner);
        let reopened = SecureOwnerWorkspaceCreate::new(config);
        let stage = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        let rows: serde_json::Value = serde_json::from_str(&stage.stages_json().unwrap()).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["stage_id"], stage_id);
        let mut next: serde_json::Value =
            serde_json::from_str(&stage.continue_stage_json(stage_id).unwrap()).unwrap();
        for _ in 0..first["part_count"].as_u64().unwrap() + 1 {
            if next["status"] == "STAGED" {
                break;
            }
            next = serde_json::from_str(&stage.continue_stage_json(stage_id).unwrap()).unwrap();
        }
        assert_eq!(next["status"], "STAGED");
        assert_eq!(next["applied_parts"], next["part_count"]);
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        let again: serde_json::Value =
            serde_json::from_str(&stage.continue_stage_json(stage_id).unwrap()).unwrap();
        assert_eq!(again["status"], "STAGED");
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        // Lose the process after the saved row and before journal.prepare.
        let owner_actor = KernelIdentity::open(&stage.config.identity_path)
            .unwrap()
            .actor_id()
            .to_owned();
        let grants_json=serde_json::json!([{"actor_id":owner_actor,"actions":["proposal.propose"],"protocol_roles":["AUTHOR"],"capabilities":["PROPOSE"]}]).to_string();
        TEST_CRASH_AFTER_BEGIN_ROW.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            stage.submit_begin_json(PrivatePackageInstallBeginInput {
                stage_id: stage_id.to_owned(),
                instance_id: random_id().unwrap(),
                entrypoint: "proposal".into(),
                grants_json,
                disclose: None,
                command_id: None,
                issued_at_ms: None,
            }),
            Err(PrivatePackageInstallError::Runtime)
        ));
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        drop(stage);
        drop(reopened);
        let reopened = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("sdk-state"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        });
        let stage = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        let installs: serde_json::Value =
            serde_json::from_str(&stage.installs_json().unwrap()).unwrap();
        assert_eq!(installs.as_array().unwrap().len(), 1);
        assert_eq!(installs[0]["stage_id"], stage_id);
        let begin_id = installs[0]["begin_command_id"].as_str().unwrap();
        assert_eq!(installs[0]["source_kind"], "STAGED");
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap()
        );
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        let first: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        assert_eq!(first["step_action_id"], "secure.structure.begin");
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap() + 1
        );
        let mut progress: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(progress["status"], "PENDING");
        assert_eq!(
            progress["step_action_id"],
            if nonempty {
                "secure.structure.page"
            } else {
                "secure.structure.end"
            }
        );
        assert_eq!(
            counts()["commits"],
            before + next["part_count"].as_u64().unwrap() + 2
        );
        // Reopen again after the first PAGE was applied but its POST reply was
        // lost. The protected BEGIN ID and exact saved PAGE must suffice.
        let (reopened, stage) = if nonempty {
            drop(stage);
            drop(reopened);
            let reopened = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            transport: Default::default(),
                origin: origin.clone(),
                state_dir: root.path().join("sdk-state"),
                allow_loopback_http: true,
                max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
            });
            let stage = reopened
                .private_install_access(&created.workspace_id)
                .unwrap();
            let saved: serde_json::Value =
                serde_json::from_str(&stage.installs_json().unwrap()).unwrap();
            assert_eq!(saved[0]["begin_command_id"], begin_id);
            (reopened, stage)
        } else {
            (reopened, stage)
        };
        let mut page_ids = std::collections::BTreeSet::new();
        if nonempty {
            page_ids.insert(progress["step_command_id"].as_str().unwrap().to_owned());
        }
        for _ in 0..8 {
            if progress["status"] == "ACCEPTED" {
                break;
            }
            progress =
                serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
            if progress["step_action_id"] == "secure.structure.page" {
                page_ids.insert(progress["step_command_id"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(progress["status"], "ACCEPTED");
        if nonempty {
            assert_eq!(page_ids.len(), 4, "51 records and 51 heads need four PAGEs");
            assert_eq!(
                counts()["commits"],
                before + next["part_count"].as_u64().unwrap() + 6,
                "one BEGIN, four PAGEs, one END; retries add no commits"
            );
        }
        let read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "instances"
                && object["id"] == first["instance_id"]
                && object["value"]["protocol_digest"] == first["protocol_digest"]));
        if let Some((record_id, title, body)) = &prior_record {
            assert!(read["objects"].as_array().unwrap().iter().any(|object| {
                object["kind"] == "records"
                    && object["id"] == *record_id
                    && object["value"]["payload"]["title"] == *title
                    && object["value"]["payload"]["body"] == *body
            }));
        }
        let repeat: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(repeat["status"], "ACCEPTED");
        let action = PublicActionInput {
            action_id: "proposal.propose".into(),
            instance_id: first["instance_id"].as_str().unwrap().into(),
            body_json: r#"{"title":"PRIVATE installed wiki","body":"Encrypted after install"}"#
                .into(),
            exact_input_refs_json: None,
            allocations_json: None,
            command_id: None,
            issued_at_ms: None,
        };
        let submitted: serde_json::Value = serde_json::from_str(
            &reopened
                .private_action_access(&created.workspace_id)
                .unwrap()
                .submit_new_json(action)
                .unwrap(),
        )
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &reopened
                .private_action_access(&created.workspace_id)
                .unwrap()
                .retry_saved_json(submitted["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records"
                && object["id"] == effect_id
                && object["value"]["payload"]["title"] == "PRIVATE installed wiki"
                && object["value"]["payload"]["body"] == "Encrypted after install"));

        // The prior protocol keeps its first package-source provenance. A
        // second instance needs a freshly staged proof at the current policy.
        let identity = KernelIdentity::open(&stage.config.identity_path).unwrap();
        let stage_store =
            SecureStateStore::open(&stage.config.state_dir.join("private-install.state")).unwrap();
        let first_stage_doc = StageDocument::open(
            &stage_store,
            &stage.config,
            identity.actor_id(),
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let first_stage_row = first_stage_doc.rows.get(stage_id).unwrap().clone();
        drop(stage_store);
        let current_stage_scope = SecureReadProfile::new(stage.config.clone())
            .with_latest_replay(&token, |source| {
                Ok::<_, PrivatePackageInstallError>((
                    source.replay().policy_hash().to_owned(),
                    source.checkpoint_canonical_json().to_owned(),
                ))
            })
            .unwrap();
        let second_stage: serde_json::Value = serde_json::from_str(
            &stage
                .stage_package_json(PrivatePackageStageInput {
                    material_json: material.to_string(),
                    expected_root_package_digest: vector["closure"]["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                    stage_id: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let second_stage_id = second_stage["stage_id"].as_str().unwrap().to_owned();
        assert_ne!(second_stage_id, stage_id);
        let mut second_stage_progress = second_stage;
        for _ in 0..8 {
            if second_stage_progress["status"] == "STAGED" {
                break;
            }
            second_stage_progress =
                serde_json::from_str(&stage.continue_stage_json(&second_stage_id).unwrap())
                    .unwrap();
        }
        assert_eq!(second_stage_progress["status"], "STAGED");
        let stage_store =
            SecureStateStore::open(&stage.config.state_dir.join("private-install.state")).unwrap();
        let second_stage_doc = StageDocument::open(
            &stage_store,
            &stage.config,
            identity.actor_id(),
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let second_stage_row = second_stage_doc.rows.get(&second_stage_id).unwrap();
        assert_ne!(second_stage_row.policy_hash, first_stage_row.policy_hash);
        assert_ne!(
            second_stage_row.source_checkpoint_json,
            first_stage_row.source_checkpoint_json
        );
        assert_eq!(second_stage_row.policy_hash, current_stage_scope.0);
        assert_eq!(
            second_stage_row.source_checkpoint_json,
            current_stage_scope.1
        );
        drop(stage_store);
        let second_instance_id = random_id().unwrap();
        let second_begin: serde_json::Value = serde_json::from_str(
            &stage
                .submit_begin_json(PrivatePackageInstallBeginInput {
                    stage_id: second_stage_id.clone(),
                    instance_id: second_instance_id.clone(),
                    entrypoint: "proposal".into(),
                    grants_json: serde_json::json!([{
                        "actor_id": owner_actor,
                        "actions": ["proposal.propose"],
                        "protocol_roles": ["AUTHOR"],
                        "capabilities": ["PROPOSE"]
                    }])
                    .to_string(),
                    disclose: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let second_begin_id = second_begin["begin_command_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut second_progress = second_begin;
        for _ in 0..12 {
            if second_progress["status"] == "ACCEPTED" {
                break;
            }
            second_progress =
                serde_json::from_str(&stage.continue_install_json(&second_begin_id).unwrap())
                    .unwrap();
        }
        assert_eq!(second_progress["status"], "ACCEPTED");
        let before_repeat = counts()["commits"].as_u64().unwrap();
        let repeat: serde_json::Value =
            serde_json::from_str(&stage.continue_install_json(&second_begin_id).unwrap()).unwrap();
        assert_eq!(repeat["status"], "ACCEPTED");
        assert_eq!(counts()["commits"], before_repeat);
        let both: serde_json::Value =
            serde_json::from_str(&stage.installs_json().unwrap()).unwrap();
        assert_eq!(both.as_array().unwrap().len(), 2);
        let final_read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            final_read["objects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|object| {
                    object["kind"] == "protocols" && object["id"] == vector["protocol_digest"]
                })
                .count(),
            1
        );
        let instance_ids: std::collections::BTreeSet<_> = final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|object| {
                object["kind"] == "instances"
                    && object["value"]["protocol_digest"] == vector["protocol_digest"]
            })
            .map(|object| object["id"].as_str().unwrap())
            .collect();
        assert_eq!(instance_ids.len(), 2);
        assert!(instance_ids.contains(first["instance_id"].as_str().unwrap()));
        assert!(instance_ids.contains(second_instance_id.as_str()));
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "instances"
                    && object["id"] == second_instance_id
                    && object["value"]["protocol_digest"] == vector["protocol_digest"]
                    && object["value"]["package_source"].is_object()
            }));
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "records"
                    && object["id"] == effect_id
                    && object["value"]["payload"]["title"] == "PRIVATE installed wiki"
                    && object["value"]["payload"]["body"] == "Encrypted after install"
            }));
    }

    #[test]
    fn actual_service_private_direct_install_from_unstructured_owner_recovers_page() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let config = SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("sdk-state"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let token = CancellationToken::new();
        let owner = SecureOwnerWorkspaceCreate::new(config.clone());
        let created = owner
            .prepare(
                SecureOwnerCreateInput {
                    name: "Native PRIVATE direct install".into(),
                    name_utf16: None,
                    visibility: "PRIVATE".into(),
                    structured: false,
                    keep_encrypted_json: "[]".into(),
                    coordination_version: None,
                },
                &token,
            )
            .unwrap();
        assert_eq!(
            owner.resume(&created.command_id, &token).unwrap().status,
            "CREATED"
        );
        let initial: serde_json::Value = serde_json::from_str(
            &owner
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        let objects = initial["objects"].as_array().unwrap();
        let wiki_digest = objects
            .iter()
            .find(|object| {
                object["kind"] == "protocols"
                    && object["value"]["manifest"]["name"] == "peerwork.wiki.v1"
            })
            .unwrap()["id"]
            .as_str()
            .unwrap();
        let wiki_instance = objects
            .iter()
            .find(|object| {
                object["kind"] == "instances" && object["value"]["protocol_digest"] == wiki_digest
            })
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let action = owner.private_action_access(&created.workspace_id).unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "wiki.create".into(),
                    instance_id: wiki_instance,
                    body_json: r#"{"title":"Before direct install","body":"Encrypted old body"}"#
                        .into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &action
                .retry_saved_json(submitted["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let prior_id = receipt["effects"][0]["record_id"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(action);
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let material = vector["closure"].clone();
        let install = owner.private_install_access(&created.workspace_id).unwrap();
        let prior_policy = SecureReadProfile::new(install.config.clone())
            .with_latest_replay(&token, |source| {
                let wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Plan)?;
                let signed = parse_wire_json_bounded(wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let payload = signed
                    .get("payload")
                    .ok_or(PrivatePackageInstallError::Plan)?;
                Ok::<_, PrivatePackageInstallError>((
                    number(payload, "v")?,
                    scalar(payload, "structure_mode")?,
                    number(payload, "version")?,
                ))
            })
            .unwrap();
        assert_eq!(prior_policy.0, 3);
        assert_eq!(prior_policy.1, "NONE");
        let owner_actor = KernelIdentity::open(&install.config.identity_path)
            .unwrap()
            .actor_id()
            .to_owned();
        let grants_json = serde_json::json!([{
            "actor_id": owner_actor,
            "actions": ["proposal.propose"],
            "protocol_roles": ["AUTHOR"],
            "capabilities": ["PROPOSE"]
        }])
        .to_string();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let counts = || {
            runtime.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        let before = counts()["commits"].as_u64().unwrap();
        TEST_CRASH_AFTER_BEGIN_ROW.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            install.submit_direct_begin_json(PrivateDirectInstallBeginInput {
                closure_json: material.to_string(),
                bindings_json: None,
                expected_root_package_digest: vector["closure"]["root_package_digest"]
                    .as_str()
                    .unwrap()
                    .into(),
                expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                instance_id: random_id().unwrap(),
                entrypoint: "proposal".into(),
                grants_json,
                disclose: None,
                command_id: None,
                issued_at_ms: None,
            }),
            Err(PrivatePackageInstallError::Runtime)
        ));
        assert_eq!(counts()["commits"], before);
        drop(install);
        drop(owner);
        let reopened = SecureOwnerWorkspaceCreate::new(config);
        let install = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        let rows: serde_json::Value =
            serde_json::from_str(&install.installs_json().unwrap()).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["source_kind"], "DIRECT");
        assert!(rows[0].get("stage_id").is_none());
        let begin_id = rows[0]["begin_command_id"].as_str().unwrap();
        let identity = KernelIdentity::open(&install.config.identity_path).unwrap();
        let operation_store = SecureStateStore::open(
            &install
                .config
                .state_dir
                .join("private-install-operations.state"),
        )
        .unwrap();
        let saved = InstallDocument::open(
            &operation_store,
            &install.config,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let saved_row = saved.rows.get(begin_id).unwrap();
        let exact_begin = decode_base64url(&saved_row.request_b64).unwrap();
        let commit_hash = saved_row.commit_hash.clone();
        drop(operation_store);
        let journal_path = install
            .config
            .state_dir
            .join("private-install-intents.state");
        let mut conflicting =
            SecureIntentJournal::open(&journal_path, &origin, identity.actor_id()).unwrap();
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            created.workspace_id
        );
        conflicting
            .prepare(SecurePacketInput {
                intent_id: begin_id,
                path: &path,
                action_id: "wiki.create",
                workspace_id: Some(&created.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: &commit_hash,
                exact_request: &exact_begin,
            })
            .unwrap();
        drop(conflicting);
        assert!(matches!(
            install.continue_install_json(begin_id),
            Err(PrivatePackageInstallError::Intent(
                SecureIntentError::Conflict
            ))
        ));
        assert_eq!(counts()["commits"], before);
        std::fs::remove_file(&journal_path).unwrap();
        std::fs::write(&journal_path, b"{").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        assert!(matches!(
            install.continue_install_json(begin_id),
            Err(PrivatePackageInstallError::Intent(
                SecureIntentError::Store(SecureStateError::MigrationRequired)
            ))
        ));
        assert_eq!(counts()["commits"], before);
        std::fs::remove_file(&journal_path).unwrap();
        runtime.block_on(async {
            assert!(reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap()
                .status()
                .is_success());
        });
        let first: serde_json::Value =
            serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(first["status"], "PENDING");
        assert_eq!(first["step_action_id"], "secure.structure.begin");
        assert_eq!(counts()["commits"], before + 1);
        runtime.block_on(async {
            assert!(reqwest::Client::new()
                .post(format!("{origin}__test/drop-next-post"))
                .body("{}")
                .send()
                .await
                .unwrap()
                .status()
                .is_success());
        });
        let mut progress: serde_json::Value =
            serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
        assert_eq!(progress["status"], "PENDING");
        assert_eq!(progress["step_action_id"], "secure.structure.page");
        let saved_page_id = progress["step_command_id"].as_str().unwrap().to_owned();
        let mut page_ids = std::collections::BTreeSet::from([saved_page_id.clone()]);
        drop(install);
        let install = reopened
            .private_install_access(&created.workspace_id)
            .unwrap();
        for _ in 0..5 {
            if progress["status"] == "ACCEPTED" {
                break;
            }
            progress =
                serde_json::from_str(&install.continue_install_json(begin_id).unwrap()).unwrap();
            if progress["step_action_id"] == "secure.structure.page" {
                page_ids.insert(progress["step_command_id"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(progress["status"], "ACCEPTED");
        assert_eq!(page_ids.len(), 2, "one record and one head need two PAGEs");
        assert_eq!(
            counts()["commits"],
            before + 4,
            "BEGIN, two PAGEs, END; no duplicate"
        );
        assert_ne!(saved_page_id, begin_id);
        let read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records"
                && object["id"] == prior_id
                && object["value"]["payload"]["title"] == "Before direct install"
                && object["value"]["payload"]["body"] == "Encrypted old body"));
        let action = reopened
            .private_action_access(&created.workspace_id)
            .unwrap();
        let submitted: serde_json::Value = serde_json::from_str(
            &action
                .submit_new_json(PublicActionInput {
                    action_id: "proposal.propose".into(),
                    instance_id: first["instance_id"].as_str().unwrap().into(),
                    body_json:
                        r#"{"title":"After direct install","body":"Encrypted proposal body"}"#
                            .into(),
                    exact_input_refs_json: None,
                    allocations_json: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        let accepted: serde_json::Value = serde_json::from_str(
            &action
                .retry_saved_json(submitted["command_id"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted["status"], "ACCEPTED");
        let receipt: serde_json::Value =
            serde_json::from_str(accepted["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effect_id = receipt["effects"][0]["record_id"].as_str().unwrap();
        let final_read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        let installed_policy = SecureReadProfile::new(install.config.clone())
            .with_latest_replay(&token, |source| {
                let wire = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Plan)?;
                let signed = parse_wire_json_bounded(wire, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let payload = signed
                    .get("payload")
                    .ok_or(PrivatePackageInstallError::Plan)?;
                Ok::<_, PrivatePackageInstallError>((
                    number(payload, "v")?,
                    scalar(payload, "structure_mode")?,
                    number(payload, "version")?,
                ))
            })
            .unwrap();
        assert_eq!(
            installed_policy,
            (3, "STRUCTURED".into(), prior_policy.2 + 1)
        );
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records"
                && object["id"] == effect_id
                && object["value"]["payload"]["title"] == "After direct install"
                && object["value"]["payload"]["body"] == "Encrypted proposal body"));
        assert_eq!(
            install
                .continue_install_json(begin_id)
                .unwrap()
                .contains("\"ACCEPTED\""),
            true
        );
        // A completed row stays discoverable while the same signed protocol
        // is installed as a second instance. The new BEGIN adds one instance
        // and reuses the existing protocol object.
        let second_instance_id = random_id().unwrap();
        let second: serde_json::Value = serde_json::from_str(
            &install
                .submit_direct_begin_json(PrivateDirectInstallBeginInput {
                    closure_json: material.to_string(),
                    bindings_json: None,
                    expected_root_package_digest: vector["closure"]["root_package_digest"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_protocol_digest: vector["protocol_digest"].as_str().unwrap().into(),
                    instance_id: second_instance_id.clone(),
                    entrypoint: "proposal".into(),
                    grants_json: serde_json::json!([{
                        "actor_id": owner_actor,
                        "actions": ["proposal.propose"],
                        "protocol_roles": ["AUTHOR"],
                        "capabilities": ["PROPOSE"]
                    }])
                    .to_string(),
                    disclose: None,
                    command_id: None,
                    issued_at_ms: None,
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second["status"], "PENDING");
        let second_begin_id = second["begin_command_id"].as_str().unwrap().to_owned();
        assert_ne!(second_begin_id, begin_id);
        let mut second_progress = second;
        for _ in 0..12 {
            if second_progress["status"] == "ACCEPTED" {
                break;
            }
            second_progress =
                serde_json::from_str(&install.continue_install_json(&second_begin_id).unwrap())
                    .unwrap();
        }
        assert_eq!(second_progress["status"], "ACCEPTED");
        let all_installs: serde_json::Value =
            serde_json::from_str(&install.installs_json().unwrap()).unwrap();
        assert_eq!(all_installs.as_array().unwrap().len(), 2);
        assert!(all_installs
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["begin_command_id"] == begin_id));
        assert!(all_installs
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["begin_command_id"] == second_begin_id));
        let before_retries = counts()["commits"].as_u64().unwrap();
        for id in [begin_id, second_begin_id.as_str()] {
            let repeat: serde_json::Value =
                serde_json::from_str(&install.continue_install_json(id).unwrap()).unwrap();
            assert_eq!(repeat["status"], "ACCEPTED");
        }
        assert_eq!(counts()["commits"], before_retries);
        let final_read: serde_json::Value = serde_json::from_str(
            &reopened
                .read_workspace_json(&created.workspace_id, &token)
                .unwrap(),
        )
        .unwrap();
        assert!(final_read["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| {
                object["kind"] == "instances"
                    && object["id"] == second_instance_id
                    && object["value"]["protocol_digest"] == vector["protocol_digest"]
            }));
        if std::env::var("PEERWORK_TEST_PRIVATE_PACKAGE_OPTIONS").as_deref() == Ok("1") {
            let before_raise: serde_json::Value = SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    let wire = source.signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    serde_json::from_slice(wire).map_err(|_| PrivatePackageInstallError::Input)
                }).unwrap();
            assert_eq!(before_raise["payload"]["v"], 3);
            assert_eq!(before_raise["payload"]["structure_mode"], "STRUCTURED");
            assert_eq!(before_raise["payload"]["protocol_format_ceiling"], 1);
            drop(install);
            let format = reopened.private_format_transition_access(&created.workspace_id).unwrap();
            let raised: serde_json::Value = serde_json::from_str(&format
                .submit_json_with_cancel(OwnerFormatTransitionInput {
                    workspace_id: created.workspace_id.clone(),
                    transition: OwnerFormatTransition::RaisePrivateCeilingTwo,
                    command_id: None, issued_at_ms: None,
                }, &token).unwrap()).unwrap();
            let raise_id = raised["command_id"].as_str().unwrap();
            let raised: serde_json::Value = serde_json::from_str(&format
                .resume_json_with_cancel(raise_id, &token).unwrap()).unwrap();
            assert_eq!(raised["status"], "ACCEPTED");
            drop(format);
            let install = reopened.private_install_access(&created.workspace_id).unwrap();
            let after_raise: serde_json::Value = SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    let wire = source.signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    serde_json::from_slice(wire).map_err(|_| PrivatePackageInstallError::Input)
                }).unwrap();
            assert_eq!(after_raise["payload"]["protocol_format_ceiling"], 2);
            let options: serde_json::Value = serde_json::from_str(include_str!(
                "../../../conformance/private-package-options-reference.json"
            )).unwrap();
            let readable = &options["readable"];
            let actor = KernelIdentity::open(&install.config.identity_path)
                .unwrap().actor_id().to_owned();
            let before_options = counts()["commits"].as_u64().unwrap();
            let disclosure = PrivateInstallDisclosure {
                schema: "item".into(), fields: vec!["label".into()],
            };
            let selected_instance_id = random_id().unwrap();
            let selected_grants = serde_json::json!([{"actor_id":actor,"actions":["set"],
                "protocol_roles":[],"capabilities":[]}]).to_string();
            let before_invalid = counts()["commits"].as_u64().unwrap();
            let rows_before_invalid: serde_json::Value =
                serde_json::from_str(&install.installs_json().unwrap()).unwrap();
            assert!(matches!(install.submit_direct_begin_json(PrivateDirectInstallBeginInput {
                closure_json: readable["material"]["closure"].to_string(),
                bindings_json: None,
                expected_root_package_digest: readable["root_package_digest"].as_str().unwrap().into(),
                expected_protocol_digest: readable["protocol_digest"].as_str().unwrap().into(),
                instance_id: random_id().unwrap(), entrypoint: "readable".into(),
                grants_json: selected_grants.clone(),
                disclose: Some(vec![PrivateInstallDisclosure {
                    schema: "item".into(), fields: vec!["not_declared".into()],
                }]), command_id: None, issued_at_ms: None,
            }), Err(PrivatePackageInstallError::Plan)));
            assert_eq!(counts()["commits"], before_invalid);
            assert_eq!(serde_json::from_str::<serde_json::Value>(&install.installs_json().unwrap()).unwrap(), rows_before_invalid);
            let selected: serde_json::Value = serde_json::from_str(&install
                .submit_direct_begin_json(PrivateDirectInstallBeginInput {
                    closure_json: readable["material"]["closure"].to_string(),
                    bindings_json: None,
                    expected_root_package_digest: readable["root_package_digest"].as_str().unwrap().into(),
                    expected_protocol_digest: readable["protocol_digest"].as_str().unwrap().into(),
                    instance_id: selected_instance_id.clone(), entrypoint: "readable".into(),
                    grants_json: selected_grants.clone(),
                    disclose: Some(vec![disclosure]),
                    command_id: None, issued_at_ms: None,
                }).unwrap()).unwrap();
            let selected_id = selected["begin_command_id"].as_str().unwrap().to_owned();
            let before_changed_selection = counts()["commits"].as_u64().unwrap();
            let saved_selection = || {
                let identity = KernelIdentity::open(&install.config.identity_path).unwrap();
                let store = SecureStateStore::open(
                    &install.config.state_dir.join("private-install-operations.state")).unwrap();
                let doc = InstallDocument::open(&store, &install.config,
                    identity.actor_id(), identity.key_id()).unwrap();
                let row = doc.rows.get(&selected_id).unwrap();
                (row.commit_hash.clone(), row.request_b64.clone(), row.disclose_json.clone())
            };
            let original_selection = saved_selection();
            let changed = install.submit_direct_begin_json(PrivateDirectInstallBeginInput {
                closure_json: readable["material"]["closure"].to_string(),
                bindings_json: None,
                expected_root_package_digest: readable["root_package_digest"].as_str().unwrap().into(),
                expected_protocol_digest: readable["protocol_digest"].as_str().unwrap().into(),
                instance_id: selected_instance_id, entrypoint: "readable".into(),
                grants_json: selected_grants,
                disclose: None,
                command_id: Some(selected_id.clone()), issued_at_ms: None,
            });
            assert_eq!(saved_selection(), original_selection);
            assert!(matches!(changed, Err(PrivatePackageInstallError::DuplicateBegin)));
            assert_eq!(counts()["commits"], before_changed_selection);
            let mut progress = selected;
            for _ in 0..8 {
                if progress["status"] == "ACCEPTED" { break; }
                progress = serde_json::from_str(&install.continue_install_json(&selected_id).unwrap()).unwrap();
            }
            assert_eq!(progress["status"], "ACCEPTED");
            let signed: serde_json::Value = SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    source.verified_read().map_err(|_| PrivatePackageInstallError::Identity)?;
                    let wire = source.signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    serde_json::from_slice(wire).map_err(|_| PrivatePackageInstallError::Input)
                }).unwrap();
            let protocol = signed["payload"]["structure"]["protocols"].as_array().unwrap()
                .iter().find(|p| p["protocol_digest"] == readable["protocol_digest"]).unwrap();
            assert_eq!(protocol["schemas"]["item"]["fields"]["label"]["protection"], "server_readable");
            assert_eq!(protocol["schemas"]["item"]["fields"]["label"]["type"], "opaque");
            assert!(signed["payload"]["structure"]["disclosure"].as_array().unwrap().iter().any(|row|
                row["protocol_digest"] == readable["protocol_digest"] && row["schema"] == "item"
                    && row["fields"] == serde_json::json!(["label"])));
            let before_retry = counts()["commits"].as_u64().unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(
                &install.continue_install_json(&selected_id).unwrap()).unwrap()["status"], "ACCEPTED");
            assert_eq!(counts()["commits"], before_retry);
            assert!(before_retry > before_options);
            let stage: serde_json::Value = serde_json::from_str(&install
                .stage_package_json(PrivatePackageStageInput {
                    material_json: readable["material"].to_string(),
                    expected_root_package_digest: readable["root_package_digest"].as_str().unwrap().into(),
                    expected_protocol_digest: readable["protocol_digest"].as_str().unwrap().into(),
                    stage_id: None, command_id: None, issued_at_ms: None,
                }).unwrap()).unwrap();
            let stage_id = stage["stage_id"].as_str().unwrap().to_owned();
            let mut staged = stage;
            for _ in 0..8 {
                if staged["status"] == "STAGED" { break; }
                staged = serde_json::from_str(&install.continue_stage_json(&stage_id).unwrap()).unwrap();
            }
            assert_eq!(staged["status"], "STAGED");
            let staged_begin: serde_json::Value = serde_json::from_str(&install
                .submit_begin_json(PrivatePackageInstallBeginInput {
                    stage_id, instance_id: random_id().unwrap(),
                    entrypoint: "readable".into(),
                    grants_json: serde_json::json!([{"actor_id":actor,"actions":["set"],
                        "protocol_roles":[],"capabilities":[]}]).to_string(),
                    disclose: Some(vec![PrivateInstallDisclosure {
                        schema: "item".into(), fields: vec!["label".into()],
                    }]), command_id: None, issued_at_ms: None,
                }).unwrap()).unwrap();
            let staged_id = staged_begin["begin_command_id"].as_str().unwrap().to_owned();
            let mut staged_progress = staged_begin;
            for _ in 0..8 {
                if staged_progress["status"] == "ACCEPTED" { break; }
                staged_progress = serde_json::from_str(&install.continue_install_json(&staged_id).unwrap()).unwrap();
            }
            assert_eq!(staged_progress["status"], "ACCEPTED");
            let signed_after_stage: serde_json::Value = SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    source.verified_read().map_err(|_| PrivatePackageInstallError::Identity)?;
                    let wire = source.signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    serde_json::from_slice(wire).map_err(|_| PrivatePackageInstallError::Input)
                }).unwrap();
            let staged_protocol = signed_after_stage["payload"]["structure"]["protocols"]
                .as_array().unwrap().iter()
                .find(|p| p["protocol_digest"] == readable["protocol_digest"]).unwrap();
            assert_eq!(staged_protocol["schemas"]["item"]["fields"]["label"]["protection"], "server_readable");
            assert_eq!(staged_protocol["schemas"]["item"]["fields"]["label"]["type"], "opaque");
            assert!(signed_after_stage["payload"]["structure"]["disclosure"].as_array().unwrap().iter().any(|row|
                row["protocol_digest"] == readable["protocol_digest"] && row["schema"] == "item"
                    && row["fields"] == serde_json::json!(["label"])));
            let before_stage_retry = counts()["commits"].as_u64().unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(
                &install.continue_install_json(&staged_id).unwrap()).unwrap()["status"], "ACCEPTED");
            assert_eq!(counts()["commits"], before_stage_retry);
            let binding = &options["binding"];
            let bound: serde_json::Value = serde_json::from_str(&install
                .submit_direct_begin_json(PrivateDirectInstallBeginInput {
                    closure_json: binding["closure"].to_string(),
                    bindings_json: Some(binding["selected_bindings"].to_string()),
                    expected_root_package_digest: binding["root_package_digest"].as_str().unwrap().into(),
                    expected_protocol_digest: binding["selected_protocol_digest"].as_str().unwrap().into(),
                    instance_id: random_id().unwrap(), entrypoint: "binding".into(),
                    grants_json: serde_json::json!([{"actor_id":actor,"actions":["vote"],
                        "protocol_roles":["AUTHOR"],"capabilities":[]}]).to_string(),
                    disclose: None, command_id: None, issued_at_ms: None,
                }).unwrap()).unwrap();
            let bound_id = bound["begin_command_id"].as_str().unwrap().to_owned();
            let mut bound_progress = bound;
            for _ in 0..8 {
                if bound_progress["status"] == "ACCEPTED" { break; }
                bound_progress = serde_json::from_str(&install.continue_install_json(&bound_id).unwrap()).unwrap();
            }
            assert_eq!(bound_progress["status"], "ACCEPTED");
            let before_bound_retry = counts()["commits"].as_u64().unwrap();
            assert_eq!(serde_json::from_str::<serde_json::Value>(
                &install.continue_install_json(&bound_id).unwrap()).unwrap()["status"], "ACCEPTED");
            assert_eq!(counts()["commits"], before_bound_retry);
            let read: serde_json::Value = serde_json::from_str(
                &reopened.read_workspace_json(&created.workspace_id, &token).unwrap()).unwrap();
            assert!(read["objects"].as_array().unwrap().iter().any(|object|
                object["kind"] == "protocols" && object["id"] == binding["selected_protocol_digest"]));
        }
    }
    #[test]
    fn actual_service_private_staged_disclosure_changes_fresh_signed_policy() {
        if std::env::var("PEERWORK_TEST_PRIVATE_STAGED_DISCLOSURE").as_deref() != Ok("1") {
            return;
        }
        let reference_root = std::env::var("PEERWORK_REFERENCE_ROOT").unwrap();
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_FIRST_POST_MODE", "normal")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "pinned service exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let owner = SecureOwnerWorkspaceCreate::new(SecureOwnerCreateConfig {
            transport: Default::default(),
            origin: origin.clone(),
            state_dir: root.path().join("sdk-state"),
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        });
        let token = CancellationToken::new();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let counts = || {
            runtime.block_on(async {
                let bytes = reqwest::get(format!("{origin}__test/secure-counts"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            })
        };
        let options: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/private-package-options-reference.json"
        ))
        .unwrap();
        let readable = &options["readable"];
        let expected_protocol = readable["protocol_digest"].as_str().unwrap();
        let signed_policy = |install: &SecurePrivatePackageInstall| -> serde_json::Value {
            SecureReadProfile::new(install.config.clone())
                .with_latest_replay(&token, |source| {
                    source
                        .verified_read()
                        .map_err(|_| PrivatePackageInstallError::Identity)?;
                    let wire = source
                        .signed_policy_by_hash(source.replay().policy_hash())
                        .ok_or(PrivatePackageInstallError::Identity)?;
                    serde_json::from_slice(wire).map_err(|_| PrivatePackageInstallError::Input)
                })
                .unwrap()
        };

        for (label, selected) in [("omitted", false), ("explicit", true)] {
            let created = owner
                .prepare(
                    SecureOwnerCreateInput {
                        name: format!("Native staged disclosure {label}"),
                        name_utf16: None,
                        visibility: "PRIVATE".into(),
                        structured: true,
                        keep_encrypted_json: "[]".into(),
                        coordination_version: None,
                    },
                    &token,
                )
                .unwrap();
            assert_eq!(
                owner.resume(&created.command_id, &token).unwrap().status,
                "CREATED"
            );
            let mut install = owner.private_install_access(&created.workspace_id).unwrap();
            let initial = signed_policy(&install);
            assert_eq!(initial["payload"]["v"], 3);
            assert_eq!(initial["payload"]["structure_mode"], "STRUCTURED");
            assert_eq!(initial["payload"]["protocol_format_ceiling"], 1);
            assert!(!initial["payload"]["structure"]["protocols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["protocol_digest"] == expected_protocol));
            drop(install);
            let format = owner
                .private_format_transition_access(&created.workspace_id)
                .unwrap();
            let raised: serde_json::Value = serde_json::from_str(
                &format
                    .submit_json_with_cancel(
                        OwnerFormatTransitionInput {
                            workspace_id: created.workspace_id.clone(),
                            transition: OwnerFormatTransition::RaisePrivateCeilingTwo,
                            command_id: None,
                            issued_at_ms: None,
                        },
                        &token,
                    )
                    .unwrap(),
            )
            .unwrap();
            let raised: serde_json::Value = serde_json::from_str(
                &format
                    .resume_json_with_cancel(raised["command_id"].as_str().unwrap(), &token)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(raised["status"], "ACCEPTED");
            drop(format);
            install = owner.private_install_access(&created.workspace_id).unwrap();
            let before = signed_policy(&install);
            assert_eq!(before["payload"]["protocol_format_ceiling"], 2);
            assert!(!before["payload"]["structure"]["protocols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["protocol_digest"] == expected_protocol));

            let stage: serde_json::Value = serde_json::from_str(
                &install
                    .stage_package_json(PrivatePackageStageInput {
                        material_json: readable["material"].to_string(),
                        expected_root_package_digest: readable["root_package_digest"]
                            .as_str()
                            .unwrap()
                            .into(),
                        expected_protocol_digest: expected_protocol.into(),
                        stage_id: None,
                        command_id: None,
                        issued_at_ms: None,
                    })
                    .unwrap(),
            )
            .unwrap();
            let stage_id = stage["stage_id"].as_str().unwrap().to_owned();
            let mut staged = stage;
            for _ in 0..8 {
                if staged["status"] == "STAGED" {
                    break;
                }
                staged = serde_json::from_str(&install.continue_stage_json(&stage_id).unwrap())
                    .unwrap();
            }
            assert_eq!(staged["status"], "STAGED");
            let still_absent = signed_policy(&install);
            assert!(!still_absent["payload"]["structure"]["protocols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["protocol_digest"] == expected_protocol));

            let actor = KernelIdentity::open(&install.config.identity_path)
                .unwrap()
                .actor_id()
                .to_owned();
            let begin: serde_json::Value = serde_json::from_str(
                &install
                    .submit_begin_json(PrivatePackageInstallBeginInput {
                        stage_id,
                        instance_id: random_id().unwrap(),
                        entrypoint: "readable".into(),
                        grants_json: serde_json::json!([{
                            "actor_id": actor,
                            "actions": ["set"],
                            "protocol_roles": [],
                            "capabilities": []
                        }])
                        .to_string(),
                        disclose: selected.then(|| {
                            vec![PrivateInstallDisclosure {
                                schema: "item".into(),
                                fields: vec!["label".into()],
                            }]
                        }),
                        command_id: None,
                        issued_at_ms: None,
                    })
                    .unwrap(),
            )
            .unwrap();
            let begin_id = begin["begin_command_id"].as_str().unwrap().to_owned();
            let mut progress = begin;
            for _ in 0..8 {
                if progress["status"] == "ACCEPTED" {
                    break;
                }
                progress = serde_json::from_str(&install.continue_install_json(&begin_id).unwrap())
                    .unwrap();
            }
            assert_eq!(progress["status"], "ACCEPTED");
            let after = signed_policy(&install);
            let protocol = after["payload"]["structure"]["protocols"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["protocol_digest"] == expected_protocol)
                .unwrap();
            let field = &protocol["schemas"]["item"]["fields"]["label"];
            assert_eq!(
                field["protection"],
                if selected { "server_readable" } else { "e2ee" }
            );
            assert_eq!(field["type"], if selected { "opaque" } else { "string" });
            let disclosure = after["payload"]["structure"]["disclosure"]
                .as_array()
                .unwrap();
            assert_eq!(
                disclosure.iter().any(|row| {
                    row["protocol_digest"] == expected_protocol
                        && row["schema"] == "item"
                        && row["fields"] == serde_json::json!(["label"])
                }),
                selected
            );
            let before_retry = counts()["commits"].as_u64().unwrap();
            let repeat: serde_json::Value = serde_json::from_str(
                &install.continue_install_json(&begin_id).unwrap(),
            )
            .unwrap();
            assert_eq!(repeat, progress);
            assert_eq!(counts()["commits"], before_retry);
        }
    }
}
