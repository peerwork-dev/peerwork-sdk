//! Recipient-scoped PRIVATE grant acquisition from authenticated transport.
//! No grant-list label or page artifact authorizes plaintext by itself.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_grant_pending::{GrantEvidence, SecureGrantPending},
    secure_journal_read::{sign_read_proof, SecureJournalRead},
    secure_lifecycle::SecureLifecycle,
    secure_read_access::{SecureReadAccess, SecureReadConfig},
    secure_recipient_state::RecipientState,
    secure_verified_read::{
        collect_unverified_artifacts, replay_authenticated_pages_with_grant,
        SecureJournalReadBudget,
    },
    transport::TransportConfig,
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use serde::Deserialize;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

const MAX_GRANTS_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_POLICY: usize = 256 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurePrivateDirectGrantReadConfig {
    pub read: SecureReadConfig,
    pub recipient_path: PathBuf,
    /// Protected base path; each signed epoch has a separate exact saved
    /// grant so a later rotation cannot overwrite an earlier grant.
    pub grant_state_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum SecurePrivateDirectGrantReadError {
    #[error("protected recipient identity or grant state could not be opened")]
    Local,
    #[error("configured-origin transport or signed GET failed")]
    Transport,
    #[error("secure grant or current member selection is invalid")]
    GrantInvalid,
    #[error("secure journal page acquisition failed")]
    Page,
    #[error("signed grant, journal, or exact checkpoint proof failed")]
    Verification,
    #[error("secure read exceeds the configured resource budget")]
    ResourceLimit,
    #[error("secure read was cancelled")]
    Cancelled,
}

impl SecurePrivateDirectGrantReadError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Local => "LOCAL_STATE",
            Self::Transport => "TRANSPORT_FAILED",
            Self::GrantInvalid => "GRANT_INVALID",
            Self::Page => "READ_FAILED",
            Self::Verification => "VERIFICATION_FAILED",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::Cancelled => "CANCELLED",
        }
    }
}

pub struct SecurePrivateDirectGrantRead {
    config: SecurePrivateDirectGrantReadConfig,
}

impl SecurePrivateDirectGrantRead {
    pub fn new(config: SecurePrivateDirectGrantReadConfig) -> Self {
        Self { config }
    }

    /// Fetch a recipient-scoped encrypted grant and a complete signed
    /// journal. Persist exact grant evidence before any key promotion; a
    /// second active replay renders plaintext only after promotion succeeds.
    pub fn activate_and_read_json(&self) -> Result<String, SecurePrivateDirectGrantReadError> {
        self.activate_and_read_json_with_cancel(&CancellationToken::new())
    }

    pub fn activate_and_read_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, SecurePrivateDirectGrantReadError> {
        if cancel.is_cancelled() {
            return Err(SecurePrivateDirectGrantReadError::Cancelled);
        }
        let config = &self.config.read;
        let budget = SecureJournalReadBudget::new(config.max_replay_artifact_bytes)
            .ok_or(SecurePrivateDirectGrantReadError::ResourceLimit)?;
        let identity = KernelIdentity::open(&config.identity_path)
            .map_err(|_| SecurePrivateDirectGrantReadError::Local)?;
        let recipient = RecipientState::open(&self.config.recipient_path, &identity)
            .map_err(|_| SecurePrivateDirectGrantReadError::Local)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SecurePrivateDirectGrantReadError::Transport)?;
        let mut transport = TransportConfig::new(config.origin.clone());
        transport.allow_loopback_http = config.allow_loopback_http;
        let features = config
            .required_features
            .iter()
            .map(|feature| feature.encode_utf16().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &config.kernel_journal_path,
                &features,
                cancel,
            ))
            .map_err(|_| transport_or_cancel(cancel))?;
        let mut reader = SecureJournalRead::open(
            &config.read_state_path,
            &client,
            &identity,
            &config.workspace_id,
            &config.authority,
        )
        .map_err(|_| SecurePrivateDirectGrantReadError::Page)?;
        if reader
            .progress()
            .map_err(|_| SecurePrivateDirectGrantReadError::Page)?
            .complete_transport
        {
            reader
                .reset_inactive_generation()
                .map_err(|_| SecurePrivateDirectGrantReadError::Page)?;
        }
        while !reader
            .progress()
            .map_err(|_| SecurePrivateDirectGrantReadError::Page)?
            .complete_transport
        {
            if cancel.is_cancelled() {
                return Err(SecurePrivateDirectGrantReadError::Cancelled);
            }
            runtime
                .block_on(reader.fetch_next(&client, &identity, cancel))
                .map_err(|_| transport_or_cancel(cancel))?;
        }
        let pages = reader
            .authenticated_pages(&client, &identity)
            .map_err(|_| SecurePrivateDirectGrantReadError::Page)?;
        let artifacts =
            collect_unverified_artifacts(&pages, budget).map_err(|error| match error {
                crate::secure_verified_read::VerifiedReadError::ResourceLimit => {
                    SecurePrivateDirectGrantReadError::ResourceLimit
                }
                _ => SecurePrivateDirectGrantReadError::Page,
            })?;
        let audience = String::from_utf16(client.discovery().audience_utf16())
            .map_err(|_| SecurePrivateDirectGrantReadError::Transport)?;
        let selection = select_member(&artifacts.policy_wires, &identity, config, audience)?;
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/key-grants",
            config.workspace_id
        );
        let read_proof = sign_read_proof(&path, client.discovery(), &identity, &config.authority)
            .map_err(|_| SecurePrivateDirectGrantReadError::Transport)?;
        let response = runtime
            .block_on(
                client
                    .transport()
                    .get_secure_key_grants_exact(&path, &read_proof, cancel),
            )
            .map_err(|_| transport_or_cancel(cancel))?;
        if response.status != 200 || response.wire.len() > MAX_GRANTS_RESPONSE {
            return Err(SecurePrivateDirectGrantReadError::Transport);
        }
        let grant_wire = select_direct_grant(&response.wire, &selection, config)?;
        let mut lifecycle = SecureLifecycle::open(
            &config.lifecycle_path,
            client.origin(),
            identity.actor_id(),
            &config.workspace_id,
            &config.owner_actor_id,
            &config.owner_key_id,
        )
        .map_err(|_| SecurePrivateDirectGrantReadError::Local)?;
        let grant_path = PathBuf::from(format!(
            "{}.epoch-{}.checkpoint-{}",
            self.config.grant_state_path.display(),
            selection.epoch,
            sha256_hex(pages.checkpoint_canonical_json().as_bytes())
        ));
        let mut pending = SecureGrantPending::open(
            &grant_path,
            client.origin(),
            &selection.audience,
            &config.workspace_id,
            &config.owner_actor_id,
            &config.owner_key_id,
            &identity,
            &recipient,
            now_ms()?,
        )
        .map_err(|_| SecurePrivateDirectGrantReadError::Verification)?;
        let policy_refs = artifacts
            .policy_wires
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let commit_refs = artifacts
            .commit_wires
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let grant = pending
            .stage(
                GrantEvidence {
                    policies: &policy_refs,
                    commits: &commit_refs,
                    checkpoint: pages.checkpoint_canonical_json().as_bytes(),
                    grant: &grant_wire,
                    certificate: &selection.certificate_wire,
                    invitation: None,
                    delegation: None,
                },
                &recipient,
                now_ms()?,
            )
            .map_err(|_| SecurePrivateDirectGrantReadError::Verification)?;
        let replay = replay_authenticated_pages_with_grant(&pages, &lifecycle, &grant, budget)
            .map_err(|_| SecurePrivateDirectGrantReadError::Verification)?;
        let proof = pending
            .bind_to_replay(&recipient, now_ms()?, &replay)
            .map_err(|_| SecurePrivateDirectGrantReadError::Verification)?
            .ok_or(SecurePrivateDirectGrantReadError::Verification)?;
        lifecycle
            .activate_verified_grant(proof)
            .map_err(|_| SecurePrivateDirectGrantReadError::Verification)?;
        drop(pending);
        drop(lifecycle);
        drop(pages);
        drop(reader);
        drop(client);
        drop(runtime);
        SecureReadAccess::new(config.clone())
            .read_json_with_cancel(cancel)
            .map_err(|_| {
                if cancel.is_cancelled() {
                    SecurePrivateDirectGrantReadError::Cancelled
                } else {
                    SecurePrivateDirectGrantReadError::Verification
                }
            })
    }
}

struct MemberSelection {
    epoch: u64,
    policy_hash: String,
    certificate_wire: Vec<u8>,
    audience: String,
}

fn select_member(
    policy_wires: &[Vec<u8>],
    identity: &KernelIdentity,
    config: &SecureReadConfig,
    audience: String,
) -> Result<MemberSelection, SecurePrivateDirectGrantReadError> {
    let latest = policy_wires
        .last()
        .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)?;
    let policy = parse_wire_json_bounded(latest, 32, MAX_POLICY)
        .map_err(|_| SecurePrivateDirectGrantReadError::GrantInvalid)?;
    let payload = policy
        .get("payload")
        .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)?;
    let get = |name| payload.get(name).and_then(WireValue::as_string);
    let epoch = payload
        .get("epoch")
        .and_then(WireValue::as_number)
        .filter(|n| n.is_finite() && *n >= 1.0 && n.fract() == 0.0)
        .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)? as u64;
    if get("workspace_id").as_deref() != Some(&config.workspace_id)
        || get("owner_id").as_deref() != Some(&config.owner_actor_id)
        || get("signing_key").as_deref() != Some(&config.owner_key_id)
        || get("visibility").as_deref() != Some("PRIVATE")
    {
        return Err(SecurePrivateDirectGrantReadError::GrantInvalid);
    }
    let WireValue::Array(members) = payload
        .get("members")
        .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)?
    else {
        return Err(SecurePrivateDirectGrantReadError::GrantInvalid);
    };
    let member = members
        .iter()
        .find(|member| {
            member
                .get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(identity.actor_id())
        })
        .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)?;
    let certificate_wire = canonical_wire_value(
        member
            .get("certificate")
            .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)?,
        CanonicalPath::SecureArtifact,
    )
    .map_err(|_| SecurePrivateDirectGrantReadError::GrantInvalid)?
    .into_bytes();
    Ok(MemberSelection {
        epoch,
        policy_hash: sha256_hex(latest),
        certificate_wire,
        audience,
    })
}

fn select_direct_grant(
    response: &[u8],
    selection: &MemberSelection,
    config: &SecureReadConfig,
) -> Result<Vec<u8>, SecurePrivateDirectGrantReadError> {
    let value = parse_wire_json_bounded(response, 32, MAX_GRANTS_RESPONSE)
        .map_err(|_| SecurePrivateDirectGrantReadError::GrantInvalid)?;
    if value
        .get("workspace_id")
        .and_then(WireValue::as_string)
        .as_deref()
        != Some(&config.workspace_id)
        || value
            .get("policy_hash")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(&selection.policy_hash)
        || value.get("epoch").and_then(WireValue::as_number) != Some(selection.epoch as f64)
    {
        return Err(SecurePrivateDirectGrantReadError::GrantInvalid);
    }
    let WireValue::Array(grants) = value
        .get("grants")
        .ok_or(SecurePrivateDirectGrantReadError::GrantInvalid)?
    else {
        return Err(SecurePrivateDirectGrantReadError::GrantInvalid);
    };
    for grant in grants {
        let Some(payload) = grant.get("payload") else {
            continue;
        };
        let recipient = payload
            .get("recipient")
            .and_then(|value| canonical_wire_value(value, CanonicalPath::SecureArtifact).ok());
        if payload.get("epoch").and_then(WireValue::as_number) == Some(selection.epoch as f64)
            && matches!(payload.get("invite_id"), Some(WireValue::Null))
            && matches!(payload.get("delegation"), Some(WireValue::Null))
            && recipient.as_deref() == std::str::from_utf8(&selection.certificate_wire).ok()
        {
            return canonical_wire_value(grant, CanonicalPath::SecureArtifact)
                .map(String::into_bytes)
                .map_err(|_| SecurePrivateDirectGrantReadError::GrantInvalid);
        }
    }
    Err(SecurePrivateDirectGrantReadError::GrantInvalid)
}

fn now_ms() -> Result<u64, SecurePrivateDirectGrantReadError> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SecurePrivateDirectGrantReadError::Local)?
        .as_millis();
    u64::try_from(time).map_err(|_| SecurePrivateDirectGrantReadError::Local)
}

fn transport_or_cancel(cancel: &CancellationToken) -> SecurePrivateDirectGrantReadError {
    if cancel.is_cancelled() {
        SecurePrivateDirectGrantReadError::Cancelled
    } else {
        SecurePrivateDirectGrantReadError::Transport
    }
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
    fn actual_private_grant_get_replay_and_active_read() {
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
            .env("PEERWORK_TEST_PRIVATE_GRANT", "1")
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
        if ready_line.is_empty() {
            use std::io::Read;
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("reference fixture failed before ready: {stderr}");
        }
        let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
        let fixture = &ready["private_grant"];
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let state = temp.path().join("native-private-recipient");
        fs::create_dir(&state).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity_path = state.join("identity.state");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &identity_path,
            &temp.path().join("private-grant-recipient.pem"),
        )
        .unwrap();
        assert_eq!(
            identity.actor_id(),
            fixture["recipient_actor_id"].as_str().unwrap()
        );
        RecipientState::import_unjoined_ts_state(
            &state.join("recipient.state"),
            &identity,
            &temp.path().join("private-grant-recipient.json"),
        )
        .unwrap();
        drop(identity);
        let read = SecureReadConfig {
            origin,
            kernel_journal_path: state.join("kernel.sqlite"),
            read_state_path: state.join("private-pages.state"),
            lifecycle_path: state.join("lifecycle.state"),
            identity_path,
            workspace_id: fixture["workspace_id"].as_str().unwrap().into(),
            authority: fixture["recipient_authority"].as_str().unwrap().into(),
            owner_actor_id: fixture["owner_actor_id"].as_str().unwrap().into(),
            owner_key_id: fixture["owner_key_id"].as_str().unwrap().into(),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
        };
        let access = SecurePrivateDirectGrantRead::new(SecurePrivateDirectGrantReadConfig {
            read: read.clone(),
            recipient_path: state.join("recipient.state"),
            grant_state_path: state.join("grant.state"),
        });
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{}__test/tamper-next-private-grant", read.origin))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        assert!(matches!(
            access.activate_and_read_json(),
            Err(SecurePrivateDirectGrantReadError::Verification)
        ));
        let untouched = SecureLifecycle::open(
            &read.lifecycle_path,
            &read.origin,
            fixture["recipient_actor_id"].as_str().unwrap(),
            &read.workspace_id,
            &read.owner_actor_id,
            &read.owner_key_id,
        )
        .unwrap();
        assert!(untouched.status().active_epochs.is_empty());
        drop(untouched);
        let output = access.activate_and_read_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["workspace_id"], fixture["workspace_id"]);
        assert_eq!(value["sequence"], fixture["sequence"]);
        assert_eq!(value["head"], fixture["head"]);
        assert!(value["objects"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| {
                row["kind"] == "records"
                    && row["value"]["payload"]["title"] == "Private native grant readback"
                    && row["value"]["payload"]["body"] == "Encrypted record recovered through grant"
            })));
        let repeated = SecureReadAccess::new(read).read_json().unwrap();
        assert_eq!(repeated, output);
    }
}
