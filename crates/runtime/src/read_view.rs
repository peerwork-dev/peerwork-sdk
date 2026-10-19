//! Anonymous PUBLIC transport for explicitly adopted authorized state.
//! PRIVATE key import and signed historical replay are intentionally separate APIs.
use crate::transport::{HttpTransport, TransportConfig, TransportError, TransportOptions};
use peerwork_core::{
    crypto::base64url,
    read_view::{self, AuthorizedReadView, ReadViewError, ReadViewPin, ReadViewSelection},
    wire_json::WireValue,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    origin: String,
    workspace_id: String,
    owner_actor_id: String,
    owner_key_id: String,
    audience: String,
    service_key: String,
    accept_authorized_state: bool,
    selection: ReadViewSelection,
    #[serde(default)]
    transport: TransportOptions,
    #[serde(default)]
    allow_loopback_http: bool,
    #[serde(default)]
    floor: Option<serde_json::Value>,
}
fn map_transport(error: TransportError) -> ReadViewError {
    ReadViewError(match error {
        TransportError::Cancelled => "CANCELLED",
        TransportError::Timeout => "TIMEOUT",
        TransportError::ResponseTooLarge => "READ_VIEW_RESOURCE_LIMIT",
        TransportError::Redirect => "REDIRECT_REJECTED",
        TransportError::InvalidOrigin => "INVALID_ORIGIN",
        TransportError::InvalidTrust => "INVALID_TRANSPORT",
        _ => "READ_VIEW_TRANSPORT_FAILED",
    })
}
/// Stable native JSON envelope; callers cannot inject a private key or supplied artifacts.
pub fn read_view_json(input: &str, cancel: &CancellationToken) -> String {
    match run(input, cancel) {
        Ok(value) => match read_view::wire(&value) {
            Ok(value) => format!("{{\"ok\":true,\"value\":{value}}}"),
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
        return Err(ReadViewError("CANCELLED"));
    }
    if input.len() > 65536 {
        return Err(ReadViewError("READ_VIEW_RESOURCE_LIMIT"));
    }
    let config: Input =
        serde_json::from_str(input).map_err(|_| ReadViewError("READ_VIEW_INPUT_INVALID"))?;
    if !config.accept_authorized_state {
        return Err(ReadViewError("READ_VIEW_ADOPTION_REQUIRED"));
    }
    let pin = ReadViewPin {
        origin: config.origin.clone(),
        workspace_id: config.workspace_id.clone(),
        owner_actor_id: config.owner_actor_id,
        owner_key_id: config.owner_key_id,
        audience: config.audience,
        service_key: config.service_key,
    };
    let mut transport_config = TransportConfig::new(&config.origin).with_options(config.transport);
    transport_config.allow_loopback_http = config.allow_loopback_http;
    let transport = HttpTransport::new(transport_config).map_err(map_transport)?;
    // The authority signs the exact origin without a trailing slash.
    if transport.trusted_origin().trim_end_matches('/') != config.origin {
        return Err(ReadViewError("INVALID_ORIGIN"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ReadViewError("RUNTIME_FAILED"))?;
    let started = Instant::now();
    let network_bytes = Cell::new(0usize);
    let requests = Cell::new(0usize);
    let active = || {
        if cancel.is_cancelled() {
            Err(ReadViewError("CANCELLED"))
        } else if started.elapsed() >= Duration::from_secs(60) {
            Err(ReadViewError("TIMEOUT"))
        } else {
            Ok(())
        }
    };
    let get = |artifact: &str, parameter: &str, max: usize| -> Result<WireValue, ReadViewError> {
        active()?;
        let remaining = Duration::from_secs(60).saturating_sub(started.elapsed());
        let response = runtime
            .block_on(async {
                tokio::time::timeout(
                    remaining,
                    transport.get_public_read_view(
                        &config.workspace_id,
                        artifact,
                        parameter,
                        max,
                        cancel,
                    ),
                )
                .await
            })
            .map_err(|_| ReadViewError("TIMEOUT"))?
            .map_err(map_transport)?;
        active()?;
        requests.set(requests.get() + 1);
        network_bytes.set(network_bytes.get() + response.wire.len());
        if network_bytes.get() > read_view::TOTAL_BYTES {
            return Err(ReadViewError("READ_VIEW_RESOURCE_LIMIT"));
        }
        if response.status != 200 {
            return Err(ReadViewError("READ_VIEW_HTTP_REJECTED"));
        }
        read_view::parse(&response.wire, max)
    };
    let mut random = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| ReadViewError("ENTROPY_FAILED"))?;
    let nonce = base64url(&random);
    let bootstrap = get("observe", &nonce, read_view::BOOTSTRAP_BYTES)?;
    let now = read_view::observed_time(&bootstrap, &pin, &nonce)?;
    let floor = config
        .floor
        .map(|f| read_view::parse(f.to_string().as_bytes(), 65536))
        .transpose()?;
    let view = AuthorizedReadView::open(&bootstrap, pin, &nonce, now, true, floor.as_ref(), None)?;
    if !view.is_public() {
        return Err(ReadViewError("READ_VIEW_PUBLIC_REQUIRED"));
    }
    let mut result = view.query(
        &config.selection,
        |hash| {
            get(
                &format!("nodes/{hash}"),
                view.root_hash(),
                read_view::NODE_BYTES,
            )
        },
        |hash| {
            get(
                &format!("commits/{hash}"),
                view.root_hash(),
                read_view::EVIDENCE_BYTES + read_view::COMMIT_BYTES,
            )
        },
        || {
            active()?;
            view.check_elapsed(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        },
    )?;
    if let WireValue::Object(fields) = &mut result {
        fields.push((
            "transport_metrics".encode_utf16().collect(),
            read_view::parse(
                serde_json::json!({"requests":requests.get(),"response_bytes":network_bytes.get()})
                    .to_string()
                    .as_bytes(),
                1024,
            )?,
        ));
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_private_key_input_and_honors_cancel() {
        let c = CancellationToken::new();
        assert!(read_view_json("{\"keyring\":{}}", &c).contains("READ_VIEW_INPUT_INVALID"));
        c.cancel();
        assert!(read_view_json("{}", &c).contains("CANCELLED"));
    }
}
