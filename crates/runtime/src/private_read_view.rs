//! Current PRIVATE reads from an already active protected profile. Never collects a journal,
//! activates a pending key, or accepts caller-supplied epoch keys/service pins.
use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_journal_read::sign_read_proof,
    secure_lifecycle::SecureLifecycle,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::SecureStateStore,
    transport::{TransportConfig, TransportError},
};
use peerwork_core::{
    crypto::base64url,
    read_view::{self, AuthorizedReadView, ReadViewError, ReadViewPin, ReadViewSelection},
    wire_json::WireValue,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: SecureReadProfileConfig,
    accept_authorized_state: bool,
    selection: ReadViewSelection,
    #[serde(default)]
    floor: Option<serde_json::Value>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedFloor {
    v: u8,
    origin: String,
    workspace_id: String,
    actor_id: String,
    owner_actor_id: String,
    owner_key_id: String,
    service_key: String,
    audience: String,
    floor: serde_json::Value,
}
fn error(code: &'static str) -> ReadViewError {
    ReadViewError(code)
}
fn transport_error(e: TransportError) -> ReadViewError {
    error(match e {
        TransportError::Cancelled => "CANCELLED",
        TransportError::Timeout => "TIMEOUT",
        TransportError::ResponseTooLarge => "READ_VIEW_RESOURCE_LIMIT",
        TransportError::Redirect => "REDIRECT_REJECTED",
        _ => "READ_VIEW_TRANSPORT_FAILED",
    })
}
pub fn private_read_view_json(input: &str, cancel: &CancellationToken) -> String {
    match run(input, cancel) {
        Ok(v) => match read_view::wire(&v) {
            Ok(s) => format!("{{\"ok\":true,\"value\":{s}}}"),
            Err(e) => failure(e),
        },
        Err(e) => failure(e),
    }
}
fn failure(e: ReadViewError) -> String {
    serde_json::json!({"ok":false,"code":e.0,"message":e.0}).to_string()
}
fn run(input: &str, cancel: &CancellationToken) -> Result<WireValue, ReadViewError> {
    if cancel.is_cancelled() {
        return Err(error("CANCELLED"));
    }
    if input.len() > 65536 {
        return Err(error("READ_VIEW_RESOURCE_LIMIT"));
    }
    let request: Input =
        serde_json::from_str(input).map_err(|_| error("READ_VIEW_INPUT_INVALID"))?;
    if !request.accept_authorized_state {
        return Err(error("READ_VIEW_ADOPTION_REQUIRED"));
    }
    let started = Instant::now();
    let active = || {
        if cancel.is_cancelled() {
            Err(error("CANCELLED"))
        } else if started.elapsed() >= Duration::from_secs(60) {
            Err(error("TIMEOUT"))
        } else {
            Ok(())
        }
    };
    let profile = SecureReadProfile::new(request.profile.clone());
    let (config, verified_floor) = profile
        .local_active_view_config()
        .map_err(|_| error("READ_VIEW_ACTIVE_PROFILE_REQUIRED"))?;
    let identity =
        KernelIdentity::open(&config.identity_path).map_err(|_| error("IDENTITY_STATE"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| error("RUNTIME_FAILED"))?;
    let mut transport = TransportConfig::new(&config.origin).with_options(config.transport.clone());
    transport.allow_loopback_http = config.allow_loopback_http;
    let features = config
        .required_features
        .iter()
        .map(|s| s.encode_utf16().collect())
        .collect::<Vec<_>>();
    let client = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(60).saturating_sub(started.elapsed()),
                KernelClient::open_existing(
                    transport,
                    &config.kernel_journal_path,
                    &features,
                    cancel,
                ),
            )
            .await
        })
        .map_err(|_| error("TIMEOUT"))?
        .map_err(|_| {
            if cancel.is_cancelled() {
                error("CANCELLED")
            } else {
                error("READ_VIEW_DISCOVERY_PIN_FAILED")
            }
        })?;
    active()?;
    let lifecycle = SecureLifecycle::open_existing(
        &config.lifecycle_path,
        client.origin(),
        identity.actor_id(),
        &config.workspace_id,
        &config.owner_actor_id,
        &config.owner_key_id,
    )
    .map_err(|_| error("READ_VIEW_ACTIVE_KEY_REQUIRED"))?;
    let ring = lifecycle
        .active_read_keyring()
        .ok_or(error("READ_VIEW_ACTIVE_KEY_REQUIRED"))?;
    let audience = String::from_utf16(client.discovery().audience_utf16())
        .map_err(|_| error("READ_VIEW_DISCOVERY_PIN_FAILED"))?;
    let pin = ReadViewPin {
        origin: client.origin().trim_end_matches('/').into(),
        workspace_id: config.workspace_id.clone(),
        owner_actor_id: config.owner_actor_id.clone(),
        owner_key_id: config.owner_key_id.clone(),
        audience: audience.clone(),
        service_key: client.discovery().receipt_public_key().into(),
    };
    let floor_store =
        SecureStateStore::open(&request.profile.state_dir.join("authorized-read-view.floor"))
            .map_err(|_| error("READ_VIEW_FLOOR_STATE"))?;
    let prior = floor_store
        .read_exact()
        .map_err(|_| error("READ_VIEW_FLOOR_STATE"))?
        .map(|bytes| -> Result<SavedFloor, ReadViewError> {
            if bytes.len() > 65536 {
                return Err(error("READ_VIEW_FLOOR_STATE"));
            }
            serde_json::from_slice(&bytes).map_err(|_| error("READ_VIEW_FLOOR_STATE"))
        })
        .transpose()?;
    if let Some(p) = &prior {
        if p.v != 1
            || p.origin != pin.origin
            || p.workspace_id != pin.workspace_id
            || p.actor_id != identity.actor_id()
            || p.owner_actor_id != pin.owner_actor_id
            || p.owner_key_id != pin.owner_key_id
            || p.service_key != pin.service_key
            || p.audience != pin.audience
        {
            return Err(error("READ_VIEW_FLOOR_PIN_CHANGED"));
        }
        if request.floor.as_ref().is_some_and(|f| f != &p.floor) {
            return Err(error("READ_VIEW_FLOOR_CONFLICT"));
        }
    }
    let floor = prior
        .as_ref()
        .map(|p| &p.floor)
        .or(request.floor.as_ref())
        .map(|f| read_view::parse(f.to_string().as_bytes(), 65536))
        .transpose()?;
    let requests = Cell::new(1usize);
    let response_bytes = Cell::new(client.discovery().raw_wire().len());
    let get = |artifact: &str, parameter: &str, max: usize| -> Result<WireValue, ReadViewError> {
        active()?;
        let target = format!(
            "/api/workspace/v1/secure/workspaces/{}/read-view/{artifact}?{}={parameter}",
            config.workspace_id,
            if artifact == "observe" {
                "nonce"
            } else {
                "root"
            }
        );
        let proof = sign_read_proof(&target, client.discovery(), &identity, &config.authority)
            .map_err(|_| error("READ_VIEW_PROOF_FAILED"))?;
        let response = runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(60).saturating_sub(started.elapsed()),
                    client.transport().get_secure_read_view(
                        &config.workspace_id,
                        artifact,
                        parameter,
                        &proof,
                        max,
                        cancel,
                    ),
                )
                .await
            })
            .map_err(|_| error("TIMEOUT"))?
            .map_err(transport_error)?;
        active()?;
        requests.set(requests.get() + 1);
        response_bytes.set(response_bytes.get() + response.wire.len());
        if response_bytes.get() > read_view::TOTAL_BYTES {
            return Err(error("READ_VIEW_RESOURCE_LIMIT"));
        }
        if response.status != 200 {
            return Err(error("READ_VIEW_HTTP_REJECTED"));
        }
        read_view::parse(&response.wire, max)
    };
    let mut random = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| error("ENTROPY_FAILED"))?;
    let nonce = base64url(&random);
    let bootstrap = get("observe", &nonce, read_view::BOOTSTRAP_BYTES)?;
    let now = read_view::observed_time(&bootstrap, &pin, &nonce)?;
    let view = AuthorizedReadView::open_with_keyring(
        &bootstrap,
        pin.clone(),
        &nonce,
        now,
        true,
        floor.as_ref(),
        ring,
    )?;
    if view.is_public() {
        return Err(error("READ_VIEW_PRIVATE_REQUIRED"));
    }
    view.require_checkpoint_floor(
        verified_floor.sequence,
        verified_floor.head.as_deref(),
        &verified_floor.policy_hash,
    )?;
    let mut result = view.query(
        &request.selection,
        |h| {
            get(
                &format!("nodes/{h}"),
                view.root_hash(),
                read_view::NODE_BYTES,
            )
        },
        |h| {
            get(
                &format!("commits/{h}"),
                view.root_hash(),
                read_view::COMMIT_BYTES + read_view::EVIDENCE_BYTES,
            )
        },
        || {
            active()?;
            view.check_elapsed(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        },
    )?;
    active()?;
    let saved = SavedFloor {
        v: 1,
        origin: pin.origin,
        workspace_id: pin.workspace_id,
        actor_id: identity.actor_id().into(),
        owner_actor_id: pin.owner_actor_id,
        owner_key_id: pin.owner_key_id,
        service_key: pin.service_key,
        audience,
        floor: serde_json::from_str(&read_view::wire(
            result.get("floor").ok_or(error("READ_VIEW_FLOOR_STATE"))?,
        )?)
        .map_err(|_| error("READ_VIEW_FLOOR_STATE"))?,
    };
    floor_store
        .write_exact(&serde_json::to_vec(&saved).map_err(|_| error("READ_VIEW_FLOOR_STATE"))?)
        .map_err(|_| error("READ_VIEW_FLOOR_STATE"))?;
    if let WireValue::Object(fields) = &mut result {
        fields.push(("transport_metrics".encode_utf16().collect(),read_view::parse(serde_json::json!({"requests":requests.get(),"response_bytes":response_bytes.get()}).to_string().as_bytes(),1024)?));
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_view_requires_active_profile_and_explicit_adoption() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let base = serde_json::json!({"profile":{"origin":"https://api.example.test","state_dir":dir.path(),"identity_path":dir.path().join("identity.state"),"workspace_id":"a".repeat(43),"owner_actor_id":null,"owner_key_id":null,"authority":null},"accept_authorized_state":false,"selection":{"kind":"get","object_kind":"records","id":"a".repeat(43)}});
        assert!(
            private_read_view_json(&base.to_string(), &CancellationToken::new())
                .contains("READ_VIEW_ADOPTION_REQUIRED")
        );
        let mut adopted = base;
        adopted["accept_authorized_state"] = true.into();
        assert!(
            private_read_view_json(&adopted.to_string(), &CancellationToken::new())
                .contains("READ_VIEW_ACTIVE_PROFILE_REQUIRED")
        );
        assert!(!dir.path().join("lifecycle.state").exists());
        assert!(!dir.path().join("kernel.sqlite").exists());
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(private_read_view_json(&adopted.to_string(), &cancel).contains("CANCELLED"));
    }
}
