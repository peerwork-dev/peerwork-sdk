//! PUBLIC owner invitation transport. The signed offer is persisted before
//! submission; HTTP replies and local rows never grant member authority.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentError, SecureIntentJournal, SecurePacketInput},
    secure_journal_read::sign_read_proof,
    secure_lifecycle::SecureLifecycle,
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    transport::{TransportConfig, TransportError},
};
use peerwork_core::{
    prepared_public_admission::{
        prepare_public_offer_utf16, verify_saved_public_offer, PublicAdmissionError,
    },
    wire_json::{parse_wire_json_js_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

const OFFER_PATH: &str = "/api/workspace/v1/secure/invitations";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicOfferInput {
    pub recipient_certificate_json: String,
    pub scopes_json: String,
    #[serde(default)]
    pub message: String,
    /// Exact JavaScript UTF-16 code units when a message includes an unpaired
    /// surrogate. Omit for ordinary Unicode text.
    #[serde(default)]
    pub message_utf16: Option<Vec<u16>>,
    #[serde(default)]
    pub invite_id: Option<String>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicOfferResult {
    pub status: String,
    pub invite_id: String,
    pub workspace_id: String,
    pub offer_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingPublicOffer {
    pub invite_id: String,
    pub workspace_id: String,
    pub offer_hash: String,
    pub observed_responses: usize,
}

#[derive(Debug, Error)]
pub enum PublicAdmissionRuntimeError {
    #[error(transparent)]
    Read(#[from] SecureReadAccessError),
    #[error(transparent)]
    Intent(#[from] SecureIntentError),
    #[error(transparent)]
    Offer(#[from] PublicAdmissionError),
    #[error("signed admission control proof could not be created")]
    ReadProof,
    #[error("protected owner identity or PUBLIC policy differs")]
    Identity,
    #[error("admission input or saved packet is invalid")]
    Input,
    #[error("configured admission transport failed")]
    Transport,
    #[error("server rejected signed offer with HTTP {0}")]
    ServerRejected(u16),
    #[error("system clock is invalid")]
    Clock,
    #[error("async runtime could not start")]
    Runtime,
    #[error("admission result could not be encoded")]
    Encoding,
}

pub struct SecurePublicAdmission {
    config: SecureReadProfileConfig,
}

impl SecurePublicAdmission {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    /// Local protected ID discovery, usable while offline after cancellation.
    /// Rows are pending transport evidence, not consent or membership.
    pub fn pending_offers_json(&self) -> Result<String, PublicAdmissionRuntimeError> {
        let scope = SecureReadProfile::new(self.config.clone()).local_pending_scope()?;
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
        if identity.actor_id() != scope.owner_actor_id || identity.key_id() != scope.owner_key_id {
            return Err(PublicAdmissionRuntimeError::Identity);
        }
        let _lifecycle = SecureLifecycle::open(
            &self.config.state_dir.join("lifecycle.state"),
            &scope.origin,
            identity.actor_id(),
            &scope.workspace_id,
            &scope.owner_actor_id,
            &scope.owner_key_id,
        )
        .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
        let journal = SecureIntentJournal::open(
            &self.config.state_dir.join("admission-intents.state"),
            &scope.origin,
            identity.actor_id(),
        )?;
        let mut result = Vec::new();
        for row in journal.pending() {
            if row.action_id != "secure.invite.offer" {
                continue;
            }
            if row.workspace_id.as_deref() != Some(scope.workspace_id.as_str())
                || journal.path(&row.intent_id)? != OFFER_PATH
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            result.push(PendingPublicOffer {
                offer_hash: journal.intent_digest(&row.intent_id)?.to_owned(),
                invite_id: row.intent_id,
                workspace_id: scope.workspace_id.clone(),
                observed_responses: row.observed_responses,
            });
        }
        serde_json::to_string(&result).map_err(|_| PublicAdmissionRuntimeError::Encoding)
    }

    pub fn submit_offer_json(
        &self,
        input: PublicOfferInput,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        self.submit_offer_json_with_cancel(input, &CancellationToken::new())
    }

    pub fn submit_offer_json_with_cancel(
        &self,
        input: PublicOfferInput,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        let now = now_ms()?;
        let issued_at = input.issued_at_ms.unwrap_or(now);
        let expires_at = input
            .expires_at_ms
            .unwrap_or(now.saturating_add(7 * 86_400_000));
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            if source.origin() != self.config.origin
                || source.replay().workspace_id() != self.config.workspace_id
                || source.replay().owner_actor_id() != identity.actor_id()
                || source.replay().owner_signing_key() != identity.key_id()
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            let policy = source
                .signed_policy_by_hash(source.replay().policy_hash())
                .ok_or(PublicAdmissionRuntimeError::Input)?;
            if input.message_utf16.is_some() && !input.message.is_empty() {
                return Err(PublicAdmissionRuntimeError::Input);
            }
            let message = input
                .message_utf16
                .clone()
                .unwrap_or_else(|| input.message.encode_utf16().collect());
            let prepared = prepare_public_offer_utf16(
                policy,
                input.recipient_certificate_json.as_bytes(),
                input.scopes_json.as_bytes(),
                &message,
                input.invite_id.as_deref(),
                issued_at,
                expires_at,
                identity.signing_key(),
            )?;
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("admission-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            if journal.contains_id(prepared.id()) {
                return Err(PublicAdmissionRuntimeError::Intent(
                    SecureIntentError::Conflict,
                ));
            }
            journal.prepare(SecurePacketInput {
                intent_id: prepared.id(),
                path: OFFER_PATH,
                action_id: "secure.invite.offer",
                workspace_id: Some(&self.config.workspace_id),
                trusted_owner_key: Some(identity.key_id()),
                intent_digest: prepared.artifact_hash(),
                exact_request: prepared.request_wire(),
            })?;
            self.send_saved_offer(&mut journal, prepared.id(), source, &identity, cancel)?;
            serde_json::to_string(&PublicOfferResult {
                status: "PENDING".into(),
                invite_id: prepared.id().to_owned(),
                workspace_id: self.config.workspace_id.clone(),
                offer_hash: prepared.artifact_hash().to_owned(),
            })
            .map_err(|_| PublicAdmissionRuntimeError::Encoding)
        })
    }

    /// Retry an uncertain POST using the exact protected bytes. The current
    /// signed replay must still include the offer's historical policy.
    pub fn retry_offer_json(&self, invite_id: &str) -> Result<String, PublicAdmissionRuntimeError> {
        self.retry_offer_json_with_cancel(invite_id, &CancellationToken::new())
    }

    pub fn retry_offer_json_with_cancel(
        &self,
        invite_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PublicAdmissionRuntimeError> {
        SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
            let identity = KernelIdentity::open(&self.config.identity_path)
                .map_err(|_| PublicAdmissionRuntimeError::Identity)?;
            if source.replay().owner_actor_id() != identity.actor_id()
                || source.replay().owner_signing_key() != identity.key_id()
            {
                return Err(PublicAdmissionRuntimeError::Identity);
            }
            let mut journal = SecureIntentJournal::open(
                &self.config.state_dir.join("admission-intents.state"),
                source.origin(),
                identity.actor_id(),
            )?;
            self.send_saved_offer(&mut journal, invite_id, source, &identity, cancel)?;
            serde_json::to_string(&PublicOfferResult {
                status: "PENDING".into(),
                invite_id: invite_id.to_owned(),
                workspace_id: self.config.workspace_id.clone(),
                offer_hash: journal.intent_digest(invite_id)?.to_owned(),
            })
            .map_err(|_| PublicAdmissionRuntimeError::Encoding)
        })
    }

    fn send_saved_offer(
        &self,
        journal: &mut SecureIntentJournal,
        invite_id: &str,
        source: &crate::secure_verified_read::TransportReplayedJournal,
        identity: &KernelIdentity,
        cancel: &CancellationToken,
    ) -> Result<(), PublicAdmissionRuntimeError> {
        if journal.path(invite_id)? != OFFER_PATH {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        let saved = journal.exact_request(invite_id)?;
        let parsed = parse_wire_json_js_bounded(&saved, 64, 220_000)
            .map_err(|_| PublicAdmissionRuntimeError::Input)?;
        let policy_hash = parsed
            .get("offer")
            .and_then(|offer| offer.get("payload"))
            .and_then(|payload| payload.get("policy_hash"))
            .and_then(WireValue::as_string)
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let policy = source
            .signed_policy_by_hash(&policy_hash)
            .ok_or(PublicAdmissionRuntimeError::Input)?;
        let checked = verify_saved_public_offer(
            &saved,
            policy,
            identity.actor_id(),
            identity.key_id(),
            &self.config.workspace_id,
        )?;
        if checked.id() != invite_id
            || checked.artifact_hash() != journal.intent_digest(invite_id)?
        {
            return Err(PublicAdmissionRuntimeError::Input);
        }
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PublicAdmissionRuntimeError::Runtime)?;
        let mut transport = TransportConfig::new(self.config.origin.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let features = self
            .config
            .required_features
            .iter()
            .map(|feature| feature.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &self.config.state_dir.join("kernel.sqlite"),
                &features,
                cancel,
            ))
            .map_err(|_| PublicAdmissionRuntimeError::Transport)?;
        if client.origin() != source.origin()
            || source.source_actor_id() != identity.actor_id()
            || source.source_key_id() != identity.key_id()
        {
            return Err(PublicAdmissionRuntimeError::Identity);
        }
        let proof = sign_read_proof(OFFER_PATH, client.discovery(), identity, source.authority())
            .map_err(|_| PublicAdmissionRuntimeError::ReadProof)?;
        let response = runtime.block_on(
            client
                .transport()
                .post_secure_admission_exact(OFFER_PATH, saved, &proof, cancel),
        );
        match response {
            Ok(response) => {
                if !response.wire.is_empty() {
                    journal.observe_response(invite_id, &response.wire)?;
                }
                if !(200..300).contains(&response.status) {
                    return Err(PublicAdmissionRuntimeError::ServerRejected(response.status));
                }
            }
            Err(TransportError::SubmittedUncertain) => {}
            Err(_) => return Err(PublicAdmissionRuntimeError::Transport),
        }
        Ok(())
    }
}

fn now_ms() -> Result<u64, PublicAdmissionRuntimeError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PublicAdmissionRuntimeError::Clock)?
        .as_millis();
    u64::try_from(ms).map_err(|_| PublicAdmissionRuntimeError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_native_public_offer_saved_retry() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", temp.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .env("PEERWORK_TEST_ADMISSION", "1")
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
        let mut ready_line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut ready_line)
            .unwrap();
        assert!(!ready_line.is_empty(), "reference service failed to start");
        let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let workspace = ready["public_read"]["workspace_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner_actor = ready["public_read"]["actor_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner_key = ready["public_read"]["signing_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let authority = ready["public_read"]["authority"]
            .as_str()
            .unwrap()
            .to_owned();
        let identity_path = temp.path().join("native-owner.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &temp.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), owner_actor);
        let config = SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: temp.path().join("native-offer"),
            identity_path,
            workspace_id: workspace.clone(),
            owner_actor_id: Some(owner_actor),
            owner_key_id: Some(owner_key),
            authority: Some(authority.clone()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        SecureReadProfile::new(config.clone())
            .read_latest_json()
            .unwrap();
        let recipient_certificate_json = fs::read_to_string(
            temp.path()
                .join("synthetic-admission-recipient-certificate.json"),
        )
        .unwrap();
        let admission = SecurePublicAdmission::new(config.clone());
        let first = admission
            .submit_offer_json(PublicOfferInput {
                recipient_certificate_json,
                scopes_json: "[]".into(),
                message: "Native invitation consent".into(),
                message_utf16: None,
                invite_id: None,
                issued_at_ms: None,
                expires_at_ms: None,
            })
            .unwrap();
        let first: PublicOfferResult = serde_json::from_str(&first).unwrap();
        assert_eq!(first.status, "PENDING");
        let protected = config.state_dir.join("admission-intents.state");
        let journal = SecureIntentJournal::open(&protected, &origin, identity.actor_id()).unwrap();
        let exact = journal.exact_request(&first.invite_id).unwrap();
        drop(journal);
        let pending: Vec<PendingPublicOffer> =
            serde_json::from_str(&admission.pending_offers_json().unwrap()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].invite_id, first.invite_id);
        assert_eq!(pending[0].offer_hash, first.offer_hash);
        let repeated: PublicOfferResult = serde_json::from_str(
            &SecurePublicAdmission::new(config)
                .retry_offer_json(&first.invite_id)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(repeated, first);
        let journal = SecureIntentJournal::open(&protected, &origin, identity.actor_id()).unwrap();
        assert_eq!(journal.exact_request(&first.invite_id).unwrap(), exact);
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let mut transport = TransportConfig::new(origin.clone());
        transport.allow_loopback_http = true;
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &temp.path().join("native-offer/kernel.sqlite"),
                &[],
                &CancellationToken::new(),
            ))
            .unwrap();
        let path = format!("{OFFER_PATH}/{}", first.invite_id);
        let proof = sign_read_proof(&path, client.discovery(), &identity, &authority).unwrap();
        let control = runtime
            .block_on(client.transport().get_secure_invitation_exact(
                &path,
                &proof,
                &CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(control.status, 200);
        let observed: serde_json::Value = serde_json::from_slice(&control.wire).unwrap();
        assert_eq!(
            observed["offer_hash"].as_str(),
            Some(first.offer_hash.as_str())
        );
        assert_eq!(
            observed["offer"]["payload"]["invite_id"].as_str(),
            Some(first.invite_id.as_str())
        );
        assert!(observed["decision"].is_null());
    }
}
