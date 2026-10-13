//! PUBLIC direct-install BEGIN from a locally pinned package closure and a
//! complete, origin-bound active journal. A saved BEGIN remains pending until
//! signed replay proves the structure transition; HTTP success is not proof.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{
        PublicInstallSelection, SecureIntentError, SecureIntentJournal, SecurePacketInput,
    },
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_verified_read::TransportReplayedJournal,
    transport::{HttpTransport, TransportConfig, TransportError},
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, sha256_hex},
    public_direct_install::{prepare_public_package_install_begin, DirectInstallError},
    wire_json::{canonical_wire_value, parse_wire_json_bounded},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPackageInstallInput {
    /// Canonical package-closure JSON. Its exact selected digest and version
    /// remain protected locally because PUBLIC install wire has no source.
    pub closure_json: String,
    pub expected_package_id: String,
    pub expected_package_version: String,
    pub expected_package_digest: String,
    pub expected_protocol_digest: String,
    pub instance_id: String,
    pub entrypoint: String,
    pub grants_json: String,
    #[serde(default)]
    pub command_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicPackageInstallResult {
    pub status: &'static str,
    pub command_id: String,
    pub workspace_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_digest: String,
    pub protocol_digest: String,
    pub instance_id: String,
    pub commit_hash: String,
}

#[derive(Debug, Error)]
pub enum PublicPackageInstallError {
    #[error("latest signed journal read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("protected owner identity does not match the signed journal")]
    Identity,
    #[error("selected package, grants, or install context is invalid")]
    Input,
    #[error("OS entropy for a command ID is unavailable")]
    Entropy,
    #[error("PUBLIC direct-install plan could not be proved")]
    Plan,
    #[error("protected install intent failed: {0}")]
    Intent(#[from] SecureIntentError),
    #[error("configured transport could not be opened")]
    Transport,
    #[error("native async runtime could not start")]
    Runtime,
    #[error("server rejected the saved install BEGIN with HTTP {0}")]
    ServerRejected(u16),
    #[error("install result could not be encoded")]
    ResultEncoding,
}

impl From<DirectInstallError> for PublicPackageInstallError {
    fn from(_: DirectInstallError) -> Self {
        Self::Plan
    }
}

pub struct SecurePublicPackageInstall {
    config: SecureReadProfileConfig,
}

impl SecurePublicPackageInstall {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    pub fn submit_begin_json(
        &self,
        input: PublicPackageInstallInput,
    ) -> Result<String, PublicPackageInstallError> {
        self.submit_begin_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_begin_json_with_cancel(
        &self,
        input: PublicPackageInstallInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicPackageInstallError> {
        let command_id = match input.command_id.as_deref() {
            Some(id) => id.to_owned(),
            None => random_id()?,
        };
        let issued_at = input.issued_at_ms.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis() as u64)
                .unwrap_or(0)
        });
        if issued_at == 0 || input.closure_json.len() > 6 * 1024 * 1024 {
            return Err(PublicPackageInstallError::Input);
        }
        let profile = SecureReadProfile::new(self.config.clone());
        let result = profile.with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicPackageInstallError::Identity)?;
            if identity.actor_id() != source.replay().owner_actor_id()
                || identity.key_id() != source.replay().owner_signing_key()
                || source.origin() != self.config.origin
                || source.replay().workspace_id() != self.config.workspace_id
            {
                return Err(PublicPackageInstallError::Identity);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("install-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            if journal.contains_id(&command_id) {
                return Err(PublicPackageInstallError::Intent(
                    SecureIntentError::Conflict,
                ));
            }
            let prior_policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(PublicPackageInstallError::Input)?;
            let grants = parse_wire_json_bounded(input.grants_json.as_bytes(), 32, 65_536)
                .map_err(|_| PublicPackageInstallError::Input)?;
            let grants_json = canonical_wire_value(&grants, CanonicalPath::SecureArtifact)
                .map_err(|_| PublicPackageInstallError::Input)?;
            let prepared = prepare_public_package_install_begin(
                input.closure_json.as_bytes(),
                &input.expected_package_digest,
                &input.expected_protocol_digest,
                prior_policy,
                source.checkpoint_canonical_json().as_bytes(),
                source.replay().objects(),
                grants_json.as_bytes(),
                &input.instance_id,
                &input.entrypoint,
                &command_id,
                issued_at,
                identity.signing_key(),
            )?;
            if prepared.package_id() != input.expected_package_id
                || prepared.package_version() != input.expected_package_version
            {
                return Err(PublicPackageInstallError::Input);
            }
            let selection = PublicInstallSelection {
                package_id: prepared.package_id().to_owned(),
                package_version: prepared.package_version().to_owned(),
                package_digest: prepared.package_digest().to_owned(),
                protocol_digest: prepared.protocol_digest().to_owned(),
                instance_id: prepared.instance_id().to_owned(),
                entrypoint: input.entrypoint.clone(),
                closure_sha256: sha256_hex(input.closure_json.as_bytes()),
                closure_b64: base64url(input.closure_json.as_bytes()),
                prior_checkpoint_json: source.checkpoint_canonical_json().to_owned(),
                grants_json,
            };
            let path = format!(
                "/api/workspace/v1/secure/workspaces/{}/commits",
                self.config.workspace_id
            );
            journal.prepare_public_install(
                SecurePacketInput {
                    intent_id: &command_id,
                    path: &path,
                    action_id: "secure.structure.begin",
                    workspace_id: Some(&self.config.workspace_id),
                    trusted_owner_key: Some(identity.key_id()),
                    intent_digest: prepared.commit_hash(),
                    exact_request: prepared.request_wire(),
                },
                selection,
            )?;
            // Rebuild from protected selection and the same authenticated
            // replay before transport; the saved packet is the only POST body.
            let saved = prove_saved_begin(&journal, &command_id, source, &identity)?;
            let mut transport_config = TransportConfig::new(self.config.origin.clone());
            transport_config.allow_loopback_http = self.config.allow_loopback_http;
            let transport = HttpTransport::new(transport_config)
                .map_err(|_| PublicPackageInstallError::Transport)?;
            if transport.trusted_origin() != source.origin() {
                return Err(PublicPackageInstallError::Transport);
            }
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| PublicPackageInstallError::Runtime)?;
            match runtime.block_on(transport.post_exact(&path, saved, cancel)) {
                Ok(response) => {
                    if !response.wire.is_empty() {
                        journal.observe_response(&command_id, &response.wire)?;
                    }
                    if !(200..300).contains(&response.status) {
                        return Err(PublicPackageInstallError::ServerRejected(response.status));
                    }
                }
                Err(TransportError::SubmittedUncertain) => {}
                Err(_) => return Err(PublicPackageInstallError::Transport),
            }
            Ok(PublicPackageInstallResult {
                status: "PENDING",
                command_id,
                workspace_id: self.config.workspace_id.clone(),
                package_id: prepared.package_id().to_owned(),
                package_version: prepared.package_version().to_owned(),
                package_digest: prepared.package_digest().to_owned(),
                protocol_digest: prepared.protocol_digest().to_owned(),
                instance_id: prepared.instance_id().to_owned(),
                commit_hash: prepared.commit_hash().to_owned(),
            })
        })?;
        serde_json::to_string(&result).map_err(|_| PublicPackageInstallError::ResultEncoding)
    }
}

fn prove_saved_begin(
    journal: &SecureIntentJournal,
    command_id: &str,
    source: &TransportReplayedJournal,
    identity: &KernelIdentity,
) -> Result<Vec<u8>, PublicPackageInstallError> {
    let selection = journal.public_install_selection(command_id)?;
    if selection.prior_checkpoint_json != source.checkpoint_canonical_json() {
        return Err(PublicPackageInstallError::Input);
    }
    let closure = selection.closure_wire()?;
    let prior_policy = source
        .signed_policy_by_hash(source.replay().policy_hash())
        .ok_or(PublicPackageInstallError::Input)?;
    let saved = journal.exact_request(command_id)?;
    let parsed = parse_wire_json_bounded(&saved, 64, 262_144)
        .map_err(|_| PublicPackageInstallError::Input)?;
    let issued_at = parsed
        .get("commit")
        .and_then(|commit| commit.get("payload"))
        .and_then(|payload| payload.get("issued_at"))
        .and_then(|value| value.as_number())
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .map(|value| value as u64)
        .ok_or(PublicPackageInstallError::Input)?;
    let regenerated = prepare_public_package_install_begin(
        &closure,
        &selection.package_digest,
        &selection.protocol_digest,
        prior_policy,
        source.checkpoint_canonical_json().as_bytes(),
        source.replay().objects(),
        selection.grants_json.as_bytes(),
        &selection.instance_id,
        &selection.entrypoint,
        command_id,
        issued_at,
        identity.signing_key(),
    )?;
    if regenerated.request_wire() != saved
        || regenerated.package_id() != selection.package_id
        || regenerated.package_version() != selection.package_version
        || regenerated.commit_hash() != journal.intent_digest(command_id)?
    {
        return Err(PublicPackageInstallError::Input);
    }
    Ok(saved)
}

fn random_id() -> Result<String, PublicPackageInstallError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PublicPackageInstallError::Entropy)?;
    Ok(base64url(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[tokio::test]
    async fn actual_service_public_install_begin_is_saved_before_uncertain_reply() {
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
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .env("PEERWORK_TEST_FIRST_POST_MODE", "drop")
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
        assert!(!line.is_empty(), "reference service did not become ready");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let fixture = &ready["public_read"];
        let identity_path = root.path().join("owner.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &root.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), fixture["actor_id"].as_str().unwrap());
        let config = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: root.path().join("profile"),
            identity_path,
            workspace_id: fixture["workspace_id"].as_str().unwrap().into(),
            owner_actor_id: Some(identity.actor_id().into()),
            owner_key_id: Some(identity.key_id().into()),
            authority: Some(fixture["authority"].as_str().unwrap().into()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        drop(identity);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let closure = vectors["closure"].to_string();
        let digest = vectors["protocol_digest"].as_str().unwrap().to_owned();
        let package_digest = vectors["package_digest"].as_str().unwrap().to_owned();
        let submit_config = config.clone();
        let result = tokio::task::spawn_blocking(move || {
            SecurePublicPackageInstall::new(submit_config).submit_begin_json(
                PublicPackageInstallInput {
                    closure_json: closure,
                    expected_package_id: "peerwork-proposal-adoption".into(),
                    expected_package_version: "1.0.0".into(),
                    expected_package_digest: package_digest,
                    expected_protocol_digest: digest,
                    instance_id: "z".repeat(43),
                    entrypoint: "proposalAdoption".into(),
                    grants_json: "[]".into(),
                    command_id: Some("c".repeat(43)),
                    issued_at_ms: None,
                },
            )
        })
        .await
        .unwrap()
        .unwrap();
        let result: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(result["status"], "PENDING");
        assert_eq!(result["package_id"], "peerwork-proposal-adoption");
        let counts = reqwest::get(format!("{origin}__test/secure-counts"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let counts: serde_json::Value = serde_json::from_slice(&counts).unwrap();
        assert_eq!(counts["head_sequence"], 2);
        assert_eq!(counts["head_hash"], result["commit_hash"]);
        let reopened = SecureIntentJournal::open(
            &config.state_dir.join("install-intents.state"),
            &origin,
            fixture["actor_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.pending().len(), 1);
        assert_eq!(
            reopened
                .public_install_selection("c".repeat(43).as_str())
                .unwrap()
                .package_digest,
            vectors["package_digest"]
        );
    }
}
