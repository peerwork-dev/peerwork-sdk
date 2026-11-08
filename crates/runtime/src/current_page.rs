//! Default PRIVATE current pages from existing server-maintained structure.
//! Uses protected active keys and source pins; never replays or activates keys.
use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_journal_read::sign_read_proof,
    secure_lifecycle::SecureLifecycle,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::SecureStateStore,
    transport::{TransportConfig, TransportError},
};
use peerwork_core::current_page::{verify_current_page, CurrentPageQuery, RESPONSE_BYTES};
use peerwork_core::{
    crypto::base64url,
    read_view::{self, ReadViewError, ReadViewPin},
    wire_json::WireValue,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: SecureReadProfileConfig,
    query: CurrentPageQuery,
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
pub fn current_page_json(input: &str, cancel: &CancellationToken) -> String {
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
    request.query.validate()?;
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
        SecureStateStore::open(&request.profile.state_dir.join("system-current-page.floor"))
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

    let query_wire = request.query.wire()?;
    let query = base64url(read_view::wire(&query_wire)?.as_bytes());
    let mut random = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| error("ENTROPY_FAILED"))?;
    let nonce = base64url(&random);
    let target = format!(
        "/api/workspace/v1/secure/workspaces/{}/current-page?nonce={nonce}&query={query}",
        config.workspace_id
    );
    let proof = sign_read_proof(&target, client.discovery(), &identity, &config.authority)
        .map_err(|_| error("CURRENT_PAGE_PROOF_FAILED"))?;
    let response = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(60).saturating_sub(started.elapsed()),
                client.transport().get_secure_current_page(
                    &config.workspace_id,
                    &nonce,
                    &query,
                    &proof,
                    cancel,
                ),
            )
            .await
        })
        .map_err(|_| error("TIMEOUT"))?
        .map_err(transport_error)?;
    active()?;
    if response.status != 200 {
        let body = serde_json::from_slice::<serde_json::Value>(&response.wire).ok();
        let code = body
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str());
        return Err(error(match code {
            Some("CURRENT_PAGE_STRUCTURE_REQUIRED") => "CURRENT_PAGE_STRUCTURE_REQUIRED",
            Some("CURRENT_PAGE_SOURCE_UNAVAILABLE") => "CURRENT_PAGE_SOURCE_UNAVAILABLE",
            Some("CURRENT_PAGE_NOT_CAUGHT_UP") => "CURRENT_PAGE_NOT_CAUGHT_UP",
            Some("CURRENT_PAGE_RESET_REQUIRED") => "CURRENT_PAGE_RESET_REQUIRED",
            Some("CURRENT_PAGE_CURSOR_INVALID") => "CURRENT_PAGE_CURSOR_INVALID",
            Some("CURRENT_PAGE_RESOURCE_LIMIT") => "CURRENT_PAGE_RESOURCE_LIMIT",
            Some("CURRENT_PAGE_QUERY_INVALID") => "CURRENT_PAGE_QUERY_INVALID",
            _ => "CURRENT_PAGE_HTTP_REJECTED",
        }));
    }
    let bytes = response.wire.len();
    let response = read_view::parse(&response.wire, RESPONSE_BYTES)?;
    let verified = verify_current_page(
        &response,
        &pin,
        &nonce,
        &request.query,
        Some(ring),
        floor.as_ref(),
        active,
    )?;
    verified.check_elapsed(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))?;
    let mut result = verified.into_value();
    let cp = result
        .get("checkpoint")
        .ok_or(error("CURRENT_PAGE_CHECKPOINT_INVALID"))?;
    let seq = cp
        .get("sequence")
        .and_then(WireValue::as_number)
        .ok_or(error("CURRENT_PAGE_CHECKPOINT_INVALID"))? as u64;
    if seq < verified_floor.sequence {
        return Err(error("CURRENT_PAGE_ROLLBACK"));
    }
    if seq == verified_floor.sequence
        && (cp.get("head").and_then(WireValue::as_string).as_deref()
            != verified_floor.head.as_deref()
            || cp
                .get("policy_hash")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(verified_floor.policy_hash.as_str()))
    {
        return Err(error("CURRENT_PAGE_FORK"));
    }
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
            result
                .get("floor")
                .ok_or(error("CURRENT_PAGE_FLOOR_STATE"))?,
        )?)
        .map_err(|_| error("CURRENT_PAGE_FLOOR_STATE"))?,
    };
    active()?;
    floor_store
        .write_exact(&serde_json::to_vec(&saved).map_err(|_| error("CURRENT_PAGE_FLOOR_STATE"))?)
        .map_err(|_| error("CURRENT_PAGE_FLOOR_STATE"))?;
    if let WireValue::Object(fields) = &mut result {
        fields.push(("transport_metrics".encode_utf16().collect(),read_view::parse(
        serde_json::json!({"requests":2,"response_bytes":bytes+client.discovery().raw_wire().len()}).to_string().as_bytes(),1024)?));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_page_missing_profile_is_not_bootstrap_or_raw_key_import() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let input = serde_json::json!({"profile":{"origin":"https://api.example.test","state_dir":dir.path(),"identity_path":dir.path().join("identity.state"),"workspace_id":"a".repeat(43),"owner_actor_id":null,"owner_key_id":null,"authority":null},"query":{"kind":"instances","limit":5}});
        assert!(
            current_page_json(&input.to_string(), &CancellationToken::new())
                .contains("READ_VIEW_ACTIVE_PROFILE_REQUIRED")
        );
        assert!(!dir.path().join("lifecycle.state").exists());
        assert!(!dir.path().join("kernel.sqlite").exists());
        let mut invalid = input.clone();
        invalid["keyring"] = serde_json::json!({});
        assert!(
            current_page_json(&invalid.to_string(), &CancellationToken::new())
                .contains("READ_VIEW_INPUT_INVALID")
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(current_page_json(&input.to_string(), &cancel).contains("CANCELLED"));
    }
    #[test]
    fn current_page_protected_profile_http_is_two_requests_without_replay() {
        use crate::kernel_intents::KernelIntentJournal;
        use peerwork_core::crypto::{
            decode_base64url, key_id, sha256_hex, sign_canonical, verifying_key,
        };
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let vector: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../core/tests/fixtures/private-current-page-v1.json"
        ))
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let state_dir = {
            let path = dir.path().join("state");
            crate::windows_fs::create_private_directory(&path).unwrap();
            path
        };
        #[cfg(not(windows))]
        let state_dir = dir.path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let canonical_origin = format!("{origin}/");
        let service = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
        let service_key = key_id(&service.verifying_key().to_bytes());
        let workspace = vector["pin"]["workspace"].as_str().unwrap().to_owned();
        let owner = vector["pin"]["ownerId"].as_str().unwrap();
        let owner_key = vector["pin"]["ownerKey"].as_str().unwrap();
        let identity_path = state_dir.as_path().join("identity.state");
        let identity = KernelIdentity::create(&identity_path).unwrap();
        let identity_key = identity.key_id().to_owned();
        let authority = sha256_hex(identity.actor_id().as_bytes());
        let discovery = serde_json::json!({"semantics":"peerwork.kernel.v1","audience":"current-page-http-test","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":service_key,"limits":{}});
        let parsed =
            peerwork_core::discovery::parse_discovery_wire(discovery.to_string().as_bytes(), 65536)
                .unwrap();
        {
            let mut journal =
                KernelIntentJournal::open(&state_dir.as_path().join("kernel.sqlite")).unwrap();
            journal.bind_discovery(&canonical_origin, &parsed).unwrap();
        }
        {
            let mut lifecycle = SecureLifecycle::open(
                &state_dir.as_path().join("lifecycle.state"),
                &canonical_origin,
                identity.actor_id(),
                &workspace,
                owner,
                owner_key,
            )
            .unwrap();
            lifecycle
                .import_active_for_test(vector["keyring"].to_string().as_bytes())
                .unwrap();
        }
        let cp = &vector["response"]["page"]["payload"]["checkpoint"];
        let profile = serde_json::json!({"version":1,"origin":origin,"identity_path":identity_path,"workspace_id":workspace,"authority":authority,"owner_actor_id":owner,"owner_key_id":owner_key,"required_features":[],"allow_loopback_http":true,"current":0,"staged":null,"staged_ready":false,"floor":{"sequence":cp["sequence"],"head":cp["head"],"policy_hash":cp["policy_hash"]}});
        {
            let store = SecureStateStore::open(&state_dir.as_path().join("read.profile")).unwrap();
            store.write_exact(profile.to_string().as_bytes()).unwrap();
        }
        // There is deliberately no read-0.state cached journal. Any replay would fail.
        assert!(!state_dir.as_path().join("read-0.state").exists());
        let mut response = vector["response"].clone();
        let origin_for_server = origin.clone();
        let server_workspace = workspace.clone();
        let server = std::thread::spawn(move || {
            let mut paths = Vec::new();
            listener.set_nonblocking(true).unwrap();
            for request_number in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing request");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut wire = Vec::new();
                let mut buf = [0; 4096];
                while !wire.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    wire.extend_from_slice(&buf[..n]);
                    assert!(wire.len() < 32768);
                }
                let text = String::from_utf8(wire).unwrap();
                let target = text
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                paths.push(target.to_owned());
                let body = if request_number == 0 {
                    assert_eq!(target, "/api/workspace/v1/discovery");
                    discovery.to_string()
                } else {
                    assert!(target.starts_with(&format!(
                        "/api/workspace/v1/secure/workspaces/{server_workspace}/current-page?nonce="
                    )));
                    let proof = text
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(key, _)| key.eq_ignore_ascii_case("x-peerwork-read"))
                                .map(|(_, v)| v.trim())
                        })
                        .unwrap();
                    let parts = proof.split('.').collect::<Vec<_>>();
                    assert_eq!(parts.len(), 3);
                    let header: serde_json::Value =
                        serde_json::from_slice(&decode_base64url(parts[0]).unwrap()).unwrap();
                    assert_eq!(header["kid"], identity_key);
                    let payload: serde_json::Value =
                        serde_json::from_slice(&decode_base64url(parts[1]).unwrap()).unwrap();
                    assert_eq!(payload["target"], target);
                    assert_eq!(payload["method"], "GET");
                    let sig =
                        ed25519_dalek::Signature::from_slice(&decode_base64url(parts[2]).unwrap())
                            .unwrap();
                    verifying_key(&identity_key)
                        .unwrap()
                        .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
                        .unwrap();
                    let url = reqwest::Url::parse(&format!("{origin_for_server}{target}")).unwrap();
                    let pairs = url
                        .query_pairs()
                        .collect::<std::collections::HashMap<_, _>>();
                    let query: serde_json::Value =
                        serde_json::from_slice(&decode_base64url(&pairs["query"]).unwrap())
                            .unwrap();
                    let p = &mut response["page"]["payload"];
                    p["origin"] = origin_for_server.clone().into();
                    p["audience"] = "current-page-http-test".into();
                    p["service_key"] = service_key.clone().into();
                    p["nonce"] = pairs["nonce"].to_string().into();
                    p["query"] = query;
                    response["page"]["signature"] =
                        sign_canonical(peerwork_core::current_page::DOMAIN, p, &service)
                            .unwrap()
                            .into();
                    response.to_string()
                };
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
            paths
        });
        let input = serde_json::json!({"profile":{"origin":origin,"state_dir":state_dir.as_path(),"identity_path":identity_path,"workspace_id":workspace,"allow_loopback_http":true},"query":vector["query"]});
        let result: serde_json::Value = serde_json::from_str(&current_page_json(
            &input.to_string(),
            &CancellationToken::new(),
        ))
        .unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["value"]["objects"].as_array().unwrap().len(), 2);
        assert_eq!(result["value"]["transport_metrics"]["requests"], 2);
        assert_eq!(server.join().unwrap().len(), 2);
        assert!(state_dir
            .as_path()
            .join("system-current-page.floor")
            .exists());
        assert!(!state_dir.as_path().join("read-0.state").exists());
    }
}
