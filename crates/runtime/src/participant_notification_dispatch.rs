//! One compact batch per selected Peer/destination, independent of consume.
use super::*;
pub(super) async fn step(
    config: &HostConfig,
    hub: &Arc<crate::communication_notifications::Hub>,
    watches: &[(ParticipantClient, WatchOptions)],
    adapter: &Option<Arc<Mutex<Host>>>,
    status: &Arc<Mutex<Value>>,
    next: &mut usize,
) -> Result<bool> {
    let health =
        status.lock().map_err(|_| error("HOST_STATE_INVALID"))?["host_observation"].clone();
    if health["execution_state"] == "WAITING_APPROVAL" {
        return Ok(false);
    }
    if health["ready"] != true
        && !(health["can_attempt"] == true && health["input_delivery"] == "DURABLE_QUEUE")
        && config.adapter["kind"] != "agy-app"
        && config.adapter["destination"]["host"] != "ANTIGRAVITY_APP"
    {
        return Ok(false);
    }
    let mut checked = std::collections::BTreeSet::new();
    for offset in 0..watches.len() {
        let index = (*next + offset) % watches.len();
        let (client, options) = &watches[index];
        if !client.locally_live() {
            continue;
        }
        if !checked.insert(crate::communication_notifications::owner(client, options)) {
            continue;
        }
        let Some((owner, wake)) = hub.poll(client, options).await? else {
            continue;
        };
        let scope = match client
            .host_operation(options, HostOperation::AccessScope)
            .await?
        {
            HostReply::AccessScope(value) => value,
            _ => return Err(error("HOST_STATE_INVALID")),
        };
        if config.adapter["kind"] == "bridge" {
            hub.register_remote(&owner, config.adapter.clone(), scope.clone())?;
            hub.sync_remote(&owner, Some(&wake)).await?;
        }
        let selected = adapter
            .as_ref()
            .ok_or_else(|| error("HOST_NOT_READY"))?
            .clone();
        let admitted = hub.clone();
        let key = owner.clone();
        let sent = wake.clone();
        let owned_acp = config.adapter["kind"] == "agy-stdio" && config.adapter["stdio_protocol"] == "acp";
        let result = tokio::task::spawn_blocking(move || {
            crate::communication_host::operation::with_host(
                &selected,
                std::time::Instant::now() + Duration::from_secs(10),
                |host| {
                    // Mark admission under the same local control fence after acquiring
                    // the physical writer. Host IO runs outside the control mutex.
                    let _inflight = admitted
                        .admit(&key, &sent.batch, sent.revision)
                        .map_err(|_| "DELIVERY_PAUSED_OR_SUPERSEDED")?;
                    if owned_acp {
                        admitted.store.protect_owned_input(&key, &sent)
                            .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?;
                    }
                    let result = host.deliver_notice(&scope, &sent);
                    if owned_acp {
                        match host_outcome("agy-stdio", result.clone()) {
                            HostOutcome::NotSent { .. } => admitted.store.release_unwritten_input(&key, &sent)
                                .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?,
                            HostOutcome::HostAccepted { .. } => admitted.store.record_replay_block(&key, &sent,
                                &json!({"state":"HOST_ACCEPTED","replay_blocked":true}))
                                .map_err(|_| "NOTIFICATION_FENCE_STATE_FAILED")?,
                            _ => (),
                        }
                    }
                    result
                },
            )
        })
        .await
        .unwrap_or(Err("HOST_ACK_UNKNOWN"));
        if config.adapter["kind"] == "bridge" {
            if let Ok(outcome) = &result {
                hub.store.record_replay_block(&owner, &wake, outcome)?;
            }
        }
        if let Ok(mut value) = status.lock() {
            value["notification"] = json!({"batch":wake.batch,"attempt":wake.attempt,"revision":wake.revision,"outcome":result.as_ref().ok(),"code":result.as_ref().err(),"content":"REFERENCE_ONLY","model_response":"NOT_ATTESTED"});
            value["delivery_control"] = hub
                .store
                .status(&owner)
                .unwrap_or_else(|e| json!({"state":"UNKNOWN","code":e.code}));
        }
        *next = (index + 1) % watches.len();
        return Ok(true);
    }
    Ok(false)
}
