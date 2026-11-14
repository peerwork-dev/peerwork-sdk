//! Authenticated notification/control RPC over the original bridge channel.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeQuery {
    binding: Value,
    destination: Value,
    notification: Value,
}
pub(super) fn owner(binding: &Value) -> R<String> {
    let principal: Value =
        serde_json::from_str(binding["owner"].as_str().ok_or("HOST_BINDING_MISMATCH")?)
            .map_err(|_| "HOST_BINDING_MISMATCH")?;
    Ok(digest_value(&json!([
        principal["origin"],
        principal["actor"],
        binding["namespace"],
        binding["destination_digest"]
    ])))
}
pub(super) async fn request(
    value: Value,
    method: &str,
    grants: &[BridgeGrant],
    destination: &Value,
    fence: &Arc<crate::notification_fence::Fence>,
    provider: &mpsc::Sender<ProviderRequest>,
    deadline: std::time::Instant,
) -> R<Value> {
    let query: NoticeQuery = serde_json::from_value(value).map_err(|_| "BRIDGE_REQUEST_INVALID")?;
    if query.binding["format"] != "peerwork.host-access.v1" {
        return Err("HOST_BINDING_MISMATCH");
    }
    let checked = Query {
        binding: query.binding.clone(),
        destination: query.destination.clone(),
        retry_of: None,
        message: None,
        message_id: None,
        body_hash: None,
        through_sequence: None,
        calls: None,
    };
    validate_query(grants, destination, "health", &checked)?;
    let key = owner(&query.binding)?;
    let n = &query.notification;
    let revision = n["revision"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or("BRIDGE_REQUEST_INVALID")?;
    if method == "notice-control" {
        if n.as_object().is_none_or(|o| {
            o.len() != 5
                || o.keys().any(|k| {
                    !["owner", "revision", "paused", "batch", "allow_probe"].contains(&k.as_str())
                })
        }) || n["owner"] != key
        {
            return Err("BRIDGE_REQUEST_INVALID");
        }
        let paused = n["paused"].as_bool().ok_or("BRIDGE_REQUEST_INVALID")?;
        let batch = n["batch"].as_str();
        if batch.is_some_and(|b| !token(b))
            || (!n["batch"].is_null() && batch.is_none())
            || n["allow_probe"].as_bool().is_none()
        {
            return Err("BRIDGE_REQUEST_INVALID");
        }
        let allowed = if paused && n["allow_probe"] != true {
            None
        } else {
            batch
        };
        return fence.control(&key, revision, allowed, paused);
    }
    if n.as_object().is_none_or(|o| {
        o.len() != 3
            || o.keys()
                .any(|k| !["batch", "revision", "attempt"].contains(&k.as_str()))
    }) {
        return Err("BRIDGE_REQUEST_INVALID");
    }
    let batch = n["batch"]
        .as_str()
        .filter(|b| token(b))
        .ok_or("BRIDGE_REQUEST_INVALID")?;
    let attempt = n["attempt"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or("BRIDGE_REQUEST_INVALID")?;
    if !fence.check(&key, revision, batch)? {
        return Err("DELIVERY_PAUSED_OR_SUPERSEDED");
    }
    let wake = crate::notification_delivery::Wake {
        batch: batch.into(),
        attempt,
        revision,
        ranges: vec![],
        self_test: false,
    };
    let mut binding = query.binding.clone();
    binding["notification"] =
        json!({"owner":key,"batch":batch,"attempt":attempt,"revision":revision});
    let response = provider_request(
        provider,
        Some(destination.clone()),
        Some(crate::communication_notifications::frame(&wake)),
        binding,
        deadline,
    )?
    .await
    .map_err(|_| "HOST_PROVIDER_UNAVAILABLE")??;
    Ok(
        json!({"format":"peerwork.host-notice-result.v1","destination":response.0,"batch":batch,"attempt":attempt,"revision":revision,"outcome":response.1}),
    )
}
