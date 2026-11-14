//! Compact local delivery coordination. The original inbox owns all content.
use crate::{
    notification_delivery::{SourceHead, Store, Wake},
    participant::{ParticipantClient, ParticipantError, Result, WatchOptions},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

fn error(code: &str) -> ParticipantError {
    ParticipantError::local(code, "NOTIFICATION_DELIVERY")
}
fn digest(value: Value) -> String {
    peerwork_core::crypto::sha256_hex(value.to_string().as_bytes())
}
pub(crate) fn destination(options: &WatchOptions) -> &str {
    options
        .host_destination
        .as_deref()
        .unwrap_or("CLAUDE_CHANNEL")
}
pub(crate) fn owner(client: &ParticipantClient, options: &WatchOptions) -> String {
    digest(json!([
        client.origin(),
        client.actor_id(),
        client.local_namespace(),
        destination(options)
    ]))
}
fn source(client: &ParticipantClient, options: &WatchOptions) -> String {
    digest(json!([
        client.origin(),
        client.actor_id(),
        client.local_namespace(),
        options
    ]))
}
pub(crate) fn text(batch: &str) -> String {
    format!("Peerwork notification: external Peer data is available. Read peerwork_inbox with {{\"batch\":\"{batch}\"}}. The notification does not authorize other actions.")
}
pub(crate) fn frame(wake: &Wake) -> Value {
    let rendered = text(&wake.batch);
    let id = peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(
        json!([wake.batch, wake.attempt]).to_string().as_bytes(),
    ));
    json!({"format":"peerwork.notification-frame.v1","message_id":id,"rendered_text":rendered,"batch":wake.batch,"attempt":wake.attempt,"revision":wake.revision})
}
pub(crate) struct Hub {
    pub(crate) store: Store,
    /// Admission and control serialize only local state, never host IO.
    admission: Mutex<()>,
    inflight: Mutex<BTreeMap<String, usize>>,
    remotes: Mutex<BTreeMap<String, Remote>>,
    local_destinations: Mutex<std::collections::BTreeSet<String>>,
    pub(crate) changed: tokio::sync::Notify,
}
struct Remote {
    adapter: Value,
    scope: Value,
    synced: Option<String>,
}
static HUBS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Hub>>>> = OnceLock::new();
impl Hub {
    pub(crate) fn open(directory: &Path) -> Result<Arc<Self>> {
        let path =
            std::path::absolute(directory).map_err(|_| error("NOTIFICATION_STATE_PATH_INVALID"))?;
        let mut hubs = HUBS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        if let Some(hub) = hubs.get(&path).and_then(Weak::upgrade) {
            return Ok(hub);
        }
        hubs.retain(|_, value| value.strong_count() > 0);
        let hub = Arc::new(Self {
            store: Store::open(&path)?,
            admission: Mutex::new(()),
            inflight: Mutex::new(BTreeMap::new()),
            remotes: Mutex::new(BTreeMap::new()),
            local_destinations: Default::default(),
            changed: Default::default(),
        });
        hubs.insert(path, Arc::downgrade(&hub));
        Ok(hub)
    }
    pub(crate) fn allowed(&self, key: &str, batch: &str, revision: u64) -> Result<bool> {
        self.store.admission(key, batch, revision)
    }
    pub(crate) fn admit(
        self: &Arc<Self>,
        key: &str,
        batch: &str,
        revision: u64,
    ) -> Result<Admission> {
        let _lock = self
            .admission
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        if !self.allowed(key, batch, revision)? {
            return Err(error("DELIVERY_PAUSED_OR_SUPERSEDED"));
        }
        *self
            .inflight
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
            .entry(key.into())
            .or_default() += 1;
        Ok(Admission {
            hub: self.clone(),
            owner: key.into(),
        })
    }
    pub(crate) fn change(&self, key: &str, mode: &str) -> Result<Value> {
        let _lock = self
            .admission
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        let result = self.store.control(key, mode)?;
        self.changed.notify_waiters();
        Ok(result)
    }
    pub(crate) fn register_remote(&self, key: &str, adapter: Value, scope: Value) -> Result<()> {
        let mut remotes = self
            .remotes
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        if remotes.len() >= 64 && !remotes.contains_key(key) {
            return Err(error("NOTIFICATION_HOST_LIMIT"));
        }
        if remotes
            .get(key)
            .is_none_or(|r| r.adapter != adapter || r.scope != scope)
        {
            remotes.insert(
                key.into(),
                Remote {
                    adapter,
                    scope,
                    synced: None,
                },
            );
        }
        Ok(())
    }
    pub(crate) fn register_local(&self, key: &str) -> Result<()> {
        let mut destinations = self
            .local_destinations
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        if destinations.len() >= 128 && !destinations.contains(key) {
            return Err(error("NOTIFICATION_HOST_LIMIT"));
        }
        destinations.insert(key.into());
        Ok(())
    }
    pub(crate) async fn sync_remote(&self, key: &str, _wake: Option<&Wake>) -> Result<Value> {
        let remote = self
            .remotes
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
            .get(key)
            .map(|r| (r.adapter.clone(), r.scope.clone(), r.synced.clone()));
        let Some((adapter, scope, synced)) = remote else {
            return Ok(json!({"state":"LOCAL_FENCE_ONLY"}));
        };
        let (status, wake) = self.store.snapshot(key)?;
        let control = json!({"owner":key,"revision":status["revision"],"paused":status["state"]!="RUNNING"||wake.is_none(),"batch":wake.as_ref().map(|w|w.batch.clone()),"allow_probe":wake.as_ref().is_some_and(|w|w.self_test)});
        let fingerprint = digest(control.clone());
        if synced.as_deref() == Some(fingerprint.as_str()) {
            return Ok(json!({"state":"FENCE_INSTALLED","revision":status["revision"]}));
        }
        let executor = tokio::runtime::Handle::current();
        let selected_adapter = adapter.clone();
        let selected_scope = scope.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::communication_host::Host::notification_control(adapter, scope, control, executor)
        })
        .await
        .map_err(|_| error("NOTIFICATION_CONTROL_TASK_FAILED"))?
        .map_err(error)?;
        let mut remotes = self
            .remotes
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?;
        let remote = remotes
            .get_mut(key)
            .ok_or_else(|| error("NOTIFICATION_CONTROL_TARGET_CHANGED"))?;
        if remote.adapter != selected_adapter || remote.scope != selected_scope {
            return Err(error("NOTIFICATION_CONTROL_TARGET_CHANGED"));
        }
        remote.synced = Some(fingerprint);
        Ok(result)
    }
    fn enforcement_status(&self, key: &str, options: &WatchOptions) -> Result<Value> {
        let (state, wake) = self.store.snapshot(key)?;
        let fingerprint = digest(
            json!({"owner":key,"revision":state["revision"],"paused":state["state"]!="RUNNING"||wake.is_none(),"batch":wake.as_ref().map(|w|w.batch.clone()),"allow_probe":wake.as_ref().is_some_and(|w|w.self_test)}),
        );
        if let Some(remote) = self
            .remotes
            .lock()
            .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
            .get(key)
        {
            return Ok(
                json!({"state":if remote.synced.as_deref()==Some(fingerprint.as_str()){"FENCE_INSTALLED"}else{"PAUSE_PENDING"},"revision":state["revision"]}),
            );
        }
        let local = options.host_destination.is_none()
            || self
                .local_destinations
                .lock()
                .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
                .contains(key);
        Ok(if local {
            json!({"state":"LOCAL_FENCE_ONLY"})
        } else {
            json!({"state":"PAUSE_PENDING","code":"NOTIFICATION_CONTROL_TARGET_NOT_REGISTERED","local_fence":"INSTALLED"})
        })
    }
    pub(crate) async fn maintain(self: Arc<Self>, cancel: crate::KernelCancellationToken) {
        loop {
            let keys = self
                .remotes
                .lock()
                .ok()
                .map(|r| r.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            for key in keys {
                if cancel.is_cancelled() {
                    return;
                }
                let _ = self.sync_remote(&key, None).await;
            }
            tokio::select! {_=cancel.cancelled()=>break,_=self.changed.notified()=>{},_=tokio::time::sleep(std::time::Duration::from_secs(3))=>{}}
        }
    }
    async fn bindings(
        client: &ParticipantClient,
        selected: Option<&WatchOptions>,
    ) -> Result<Vec<WatchOptions>> {
        let bindings = client.watch_bindings().await?;
        if let Some(wanted) = selected {
            if !bindings.iter().any(|b| b == wanted) {
                return Err(error("NOTIFICATION_BINDING_CHANGED"));
            }
            return Ok(bindings
                .into_iter()
                .filter(|b| destination(b) == destination(wanted))
                .collect());
        }
        Ok(bindings)
    }
    pub(crate) async fn poll(
        &self,
        client: &ParticipantClient,
        selected: &WatchOptions,
    ) -> Result<Option<(String, Wake)>> {
        let bindings = Self::bindings(client, Some(selected)).await?;
        let key = owner(client, selected);
        let state = self.store.status(&key)?;
        if state["state"] == "PAUSED"
            && state["self_test_requested"] != true
            && state["pending"]["self_test"] != true
        {
            return Ok(None);
        }
        let mut heads = Vec::new();
        for options in &bindings {
            let head = client.inbox_metadata(options).await?;
            // A stream failure is not an empty inbox. Preserve it without claiming readiness.
            if head["receiver_link_verified"] != true || !head["verification_failure"].is_null() {
                let mut problem = error("NOTIFICATION_RECEIVER_NOT_VERIFIED");
                problem.details = Some(
                    json!({"state":head["state"],"code":head["code"],"verification_failure":head["verification_failure"]}),
                );
                return Err(problem);
            }
            heads.push(SourceHead {
                key: source(client, options),
                checkpoint: head["checkpoint"].as_u64().unwrap_or(0),
                has_pending: head["has_pending"] == true,
            });
        }
        Ok(self
            .store
            .due(&key, &heads, crate::participant_store::now())?
            .map(|wake| (key, wake)))
    }
    pub(crate) async fn wait_poll(
        &self,
        client: &ParticipantClient,
        options: &WatchOptions,
        wait_ms: u64,
    ) -> Result<Option<(String, Wake)>> {
        if wait_ms > 30000 {
            return Err(error("NOTIFICATION_WAIT_BUDGET_INVALID"));
        }
        if wait_ms == 0 {
            return self.poll(client, options).await;
        }
        let mut watch = client.watch(options.clone()).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(wake) = self.poll(client, options).await? {
                return Ok(Some(wake));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            let status = self.store.status(&owner(client, options))?;
            let retry = status["pending"]["retry_at"]
                .as_i64()
                .map(|at| at.saturating_sub(crate::participant_store::now()).max(1) as u64)
                .unwrap_or(wait_ms);
            let until = (tokio::time::Instant::now() + std::time::Duration::from_millis(retry))
                .min(deadline);
            tokio::select! {result=watch.changed()=>{result?;},_=changed=>{},_=tokio::time::sleep_until(until)=>{}}
        }
    }
    pub(crate) async fn control(
        &self,
        client: &ParticipantClient,
        selected: Option<&WatchOptions>,
        mode: &str,
    ) -> Result<Value> {
        if !matches!(mode, "status" | "pause" | "resume" | "self_test") {
            return Err(error("NOTIFICATION_CONTROL_INVALID"));
        }
        let bindings = Self::bindings(client, selected).await?;
        let mut owners = BTreeMap::new();
        for options in bindings {
            owners.entry(owner(client, &options)).or_insert(options);
        }
        let mut states = Vec::new();
        for (key, options) in owners {
            let mut value = if mode == "status" {
                self.store.status(&key)?
            } else {
                self.change(&key, mode)?
            };
            value["already_inflight"] = json!(self
                .inflight
                .lock()
                .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
                .get(&key)
                .copied()
                .unwrap_or(0));
            if mode != "status" {
                let known = options.host_destination.is_none()
                    || self
                        .local_destinations
                        .lock()
                        .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
                        .contains(&key)
                    || self
                        .remotes
                        .lock()
                        .map_err(|_| error("NOTIFICATION_STATE_FAILED"))?
                        .contains_key(&key);
                value["enforcement"] = if !known {
                    json!({"state":"PAUSE_PENDING","code":"NOTIFICATION_CONTROL_TARGET_NOT_REGISTERED","local_fence":"INSTALLED"})
                } else {
                    match self.sync_remote(&key, None).await {
                        Ok(value) => value,
                        Err(problem) => json!({"state":"PAUSE_PENDING","code":problem.code}),
                    }
                };
            } else {
                value["enforcement"] = self.enforcement_status(&key, &options)?;
            }
            value["destination_digest"] = json!(destination(&options));
            states.push(value);
        }
        let pending = states
            .iter()
            .any(|s| s["enforcement"]["state"] == "PAUSE_PENDING");
        Ok(
            json!({"state":if states.is_empty(){"NOT_CONFIGURED"}else if mode=="pause"{if pending{"PAUSE_PENDING"}else{"PAUSED"}}else{"LOCAL_DELIVERY_STATE"},"destinations":states,"messages_deleted":false,"application_consumption_changed":false,"host_accepted_input_retractable":false}),
        )
    }
    pub(crate) async fn validate(
        &self,
        client: &ParticipantClient,
        batch: &str,
        revision: u64,
    ) -> Result<bool> {
        for options in Self::bindings(client, None).await? {
            if self.allowed(&owner(client, &options), batch, revision)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(crate) async fn observe(&self, client: &ParticipantClient, batch: &str) -> Result<Value> {
        for options in Self::bindings(client, None).await? {
            let key = owner(client, &options);
            match self.store.batch(&key, batch) {
                Ok(_) => {
                    let mut result = self.store.observed(&key, batch)?;
                    self.changed.notify_waiters();
                    result["enforcement"] = match self.sync_remote(&key, None).await {
                        Ok(v) => v,
                        Err(e) => json!({"state":"PAUSE_PENDING","code":e.code}),
                    };
                    return Ok(result);
                }
                Err(e) if e.code == "BATCH_EXPIRED" => {}
                Err(e) => return Err(e),
            }
        }
        Err(error("BATCH_EXPIRED_OR_BINDING_CHANGED"))
    }
    pub(crate) async fn read(
        &self,
        client: &ParticipantClient,
        batch: &str,
        view: &str,
        selected: Option<&WatchOptions>,
        after: u64,
        cursor: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Value> {
        if !(1..=32).contains(&limit)
            || !(2048..=1024 * 1024).contains(&max_bytes)
            || !matches!(view, "fresh" | "active" | "pending")
        {
            return Err(error("NOTIFICATION_READ_LIMIT_INVALID"));
        }
        let mut bindings = Self::bindings(client, selected).await?;
        if let Some(exact) = selected {
            bindings.retain(|b| b == exact);
        }
        let mut token = batch.to_owned();
        let mut chosen = None;
        if token.is_empty() && view == "fresh" {
            for options in &bindings {
                let key = owner(client, options);
                if let Some(wake) = self.store.current(&key)? {
                    // A manual inbox query cannot qualify automatic model wake.
                    if !wake.self_test {
                        token = wake.batch.clone();
                        chosen = Some((key, wake));
                        break;
                    }
                }
            }
            if chosen.is_none() {
                return manual_read(client, selected, after, cursor, limit, max_bytes).await;
            }
        }
        if !token.is_empty() && chosen.is_none() {
            for options in &bindings {
                let key = owner(client, options);
                match self.store.batch(&key, &token) {
                    Ok(wake) => {
                        chosen = Some((key, wake));
                        break;
                    }
                    Err(e) if e.code == "BATCH_EXPIRED" => {}
                    Err(e) => return Err(e),
                }
            }
            if chosen.is_none() {
                return Err(error("BATCH_EXPIRED_OR_BINDING_CHANGED"));
            }
        }
        if let Some((_key, wake)) = &chosen {
            if wake.self_test {
                return Ok(
                    json!({"state":"SELF_TEST_READY","batch":token,"acknowledgement_required":!batch.is_empty(),"items":[],"more":false,"evidence":"BOUND_NOTIFICATION_TOOL_READ","business_effect":"NONE"}),
                );
            }
        }
        let selections = if let Some((_, wake)) = &chosen {
            let mut selected = Vec::new();
            for range in &wake.ranges {
                let options = bindings
                    .iter()
                    .find(|o| source(client, o) == range.key)
                    .ok_or_else(|| error("NOTIFICATION_BINDING_CHANGED"))?;
                // Existing historical work is disclosed as backlog, never replayed on upgrade.
                if range.through > range.after {
                    selected.push((options.clone(), range.after, range.through));
                }
            }
            if selected.is_empty() {
                return Ok(
                    json!({"state":"BACKLOG_AVAILABLE","batch":token,"acknowledgement_required":!batch.is_empty(),"items":[],"more":false,"backlog":true,"active_work_retained":true,"next":{"tool":"peerwork_inbox","arguments":{"view":"active"}}}),
                );
            }
            selected
        } else {
            bindings
                .iter()
                .map(|o| (o.clone(), after, u64::MAX))
                .collect()
        };
        let mut page = read_ranges(
            client,
            &selections,
            &token,
            view,
            !batch.is_empty(),
            cursor,
            limit,
            max_bytes,
        )
        .await?;
        if chosen
            .as_ref()
            .is_some_and(|(_, wake)| wake.ranges.iter().any(|range| range.backlog))
        {
            page["backlog_available"] = json!(true);
            page["backlog_access"] = json!({"tool":"peerwork_inbox","arguments":{"view":"active"}});
        }
        Ok(page)
    }
}
pub(crate) struct Admission {
    hub: Arc<Hub>,
    owner: String,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if let Ok(mut active) = self.hub.inflight.lock() {
            if let Some(count) = active.get_mut(&self.owner) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    active.remove(&self.owner);
                }
            }
        }
    }
}

pub(crate) async fn manual_read(
    client: &ParticipantClient,
    selected: Option<&WatchOptions>,
    after: u64,
    cursor: Option<&str>,
    limit: usize,
    max_bytes: usize,
) -> Result<Value> {
    let mut bindings = client.watch_bindings().await?;
    if let Some(exact) = selected {
        if !bindings.iter().any(|o| o == exact) {
            return Err(error("NOTIFICATION_BINDING_CHANGED"));
        }
        bindings.retain(|o| o == exact);
    }
    if bindings.is_empty() {
        return Ok(
            json!({"state":"NOT_CONFIGURED","items":[],"more":false,"automatic_delivery":"NOT_CONFIGURED"}),
        );
    }
    let selections = bindings
        .into_iter()
        .map(|o| (o, after, u64::MAX))
        .collect::<Vec<_>>();
    let mut value = read_ranges(
        client,
        &selections,
        "",
        "pending",
        false,
        cursor,
        limit,
        max_bytes,
    )
    .await?;
    value["selection"] = json!("UNHANDLED_WORK");
    Ok(value)
}
async fn read_ranges(
    client: &ParticipantClient,
    selections: &[(WatchOptions, u64, u64)],
    token: &str,
    view: &str,
    explicit_batch: bool,
    cursor: Option<&str>,
    limit: usize,
    max_bytes: usize,
) -> Result<Value> {
    if !(1..=32).contains(&limit) || !(2048..=1024 * 1024).contains(&max_bytes) {
        return Err(error("NOTIFICATION_READ_LIMIT_INVALID"));
    }
    let wire_budget = max_bytes - 256;
    let selection = digest(json!([token, view, selections]));
    let mut position = match cursor {
        Some(cursor) => Cursor::decode(cursor)?,
        None => Cursor {
            selection: selection.clone(),
            source: 0,
            after: selections.first().map(|s| s.1).unwrap_or(0),
            offset: 0,
            delivery: None,
        },
    };
    if position.selection != selection || position.source > selections.len() {
        return Err(error("NOTIFICATION_CURSOR_INVALID"));
    }
    let mut result = json!({"state":"VERIFIED_INBOX_PAGE","batch":token,"acknowledgement_required":explicit_batch,"items":[],"more":false,"model_response":"NOT_ATTESTED","active_work_retained":true});
    let mut items = Vec::new();
    while position.source < selections.len() && items.len() < limit {
        let (options, lower, upper) = &selections[position.source];
        let page = client.inbox(options, position.after.max(*lower), 1).await?;
        if page.verification_failure.is_some() {
            return Err(error("STREAM_VERIFICATION_FAILED"));
        }
        result["receiving"] = json!({"state":page.state,"code":page.code,"receiver_link_verified":page.receiver_link_verified});
        let entry = page
            .items
            .first()
            .filter(|e| e["sequence"].as_u64().is_some_and(|s| s <= *upper));
        let Some(entry) = entry else {
            if position.offset != 0 {
                return Err(error("NOTIFICATION_EXACT_ITEM_UNAVAILABLE"));
            }
            if !items.is_empty() {
                break;
            }
            position.source += 1;
            position.after = selections.get(position.source).map(|s| s.1).unwrap_or(0);
            continue;
        };
        if position
            .delivery
            .as_ref()
            .is_some_and(|id| entry["delivery_id"] != *id)
        {
            return Err(error("NOTIFICATION_EXACT_ITEM_UNAVAILABLE"));
        }
        result["scope_binding"] = json!({"workspace_id":options.workspace_id,"mailbox_id":options.mailbox_id,"membership_id":options.membership_id});
        let mut projected = compact(entry)?;
        let sequence = entry["sequence"]
            .as_u64()
            .ok_or_else(|| error("NOTIFICATION_ITEM_INVALID"))?;
        let mut next = position.clone();
        next.after = sequence;
        next.offset = 0;
        next.delivery = None;
        let content = projected["message"]["text"].as_str().map(str::to_owned);
        if let Some(content) = content {
            if position.offset > content.len() || !content.is_char_boundary(position.offset) {
                return Err(error("NOTIFICATION_CURSOR_INVALID"));
            }
            projected["message"]["text"] = json!(&content[position.offset..]);
            projected["message"]["offset"] = json!(position.offset);
            projected["message"]["partial"] = json!(false);
            let mut candidate = items.clone();
            candidate.push(projected.clone());
            let mut probe = result.clone();
            probe["items"] = json!(candidate);
            probe["more"] = json!(true);
            probe["continuation"] = json!(next.encode()?);
            if probe.to_string().len() > wire_budget {
                if !items.is_empty() {
                    break;
                }
                let mut length = content.len() - position.offset;
                loop {
                    let mut end = position.offset + length;
                    while !content.is_char_boundary(end) {
                        end -= 1;
                    }
                    if end == position.offset {
                        return Err(error("NOTIFICATION_BUDGET_TOO_SMALL"));
                    }
                    projected["message"]["text"] = json!(&content[position.offset..end]);
                    projected["message"]["partial"] = json!(true);
                    next = position.clone();
                    next.offset = end;
                    next.delivery = entry["delivery_id"].as_str().map(str::to_owned);
                    let mut probe = result.clone();
                    probe["items"] = json!([projected.clone()]);
                    probe["more"] = json!(true);
                    probe["continuation"] = json!(next.encode()?);
                    if probe.to_string().len() <= wire_budget {
                        break;
                    }
                    length /= 2;
                }
            }
        }
        let mut candidate = items.clone();
        candidate.push(projected);
        let mut probe = result.clone();
        probe["items"] = json!(candidate);
        probe["more"] = json!(true);
        probe["continuation"] = json!(next.encode()?);
        if probe.to_string().len() > wire_budget {
            if items.is_empty() {
                return Err(error("NOTIFICATION_STRUCTURED_ITEM_EXCEEDS_BUDGET"));
            }
            break;
        }
        items = candidate;
        position = next;
        // One scope per result keeps reply routing unambiguous.
        if position.offset != 0 {
            break;
        }
    }
    result["items"] = json!(items);
    result["more"] = json!(position.source < selections.len());
    if position.source < selections.len() {
        result["continuation"] = json!(position.encode()?);
    }
    if result.to_string().len() > wire_budget {
        return Err(error("NOTIFICATION_OUTPUT_BUDGET_EXCEEDED"));
    }
    Ok(result)
}

#[derive(Clone, Serialize, Deserialize)]
struct Cursor {
    selection: String,
    source: usize,
    after: u64,
    offset: usize,
    delivery: Option<String>,
}
impl Cursor {
    fn encode(&self) -> Result<String> {
        Ok(peerwork_core::crypto::base64url(
            &serde_json::to_vec(self).map_err(|_| error("NOTIFICATION_CURSOR_INVALID"))?,
        ))
    }
    fn decode(value: &str) -> Result<Self> {
        if value.len() > 2048 {
            return Err(error("NOTIFICATION_CURSOR_INVALID"));
        }
        serde_json::from_slice(
            &peerwork_core::crypto::decode_base64url(value)
                .map_err(|_| error("NOTIFICATION_CURSOR_INVALID"))?,
        )
        .map_err(|_| error("NOTIFICATION_CURSOR_INVALID"))
    }
}
fn compact(entry: &Value) -> Result<Value> {
    let event = if entry["envelope"]["event"].is_object() {
        Some(entry["envelope"]["event"].clone())
    } else if entry["envelope"]["business"].is_object() {
        let mut event = entry["envelope"]["business"].clone();
        event.as_object_mut().unwrap().remove("source_response");
        Some(event)
    } else {
        None
    };
    let mut message = if let Some(event) = event {
        json!({"state":"EVENT","assurance":"SERVICE_ATTESTED_EVENT","text":event.to_string(),"encoding":"JSON_UTF8","partial":false})
    } else {
        entry["opened_message"].clone()
    };
    if entry["state"] == "TERMINAL" {
        message = Value::Null;
    }
    let can_reply = message["state"] == "OPENED"
        && message["assurance"] == "AUTHOR_SIGNATURE_AND_AEAD"
        && (message["reply_address"].is_object()
            || message["message_kind"] == "SPACE_CONVERSATION");
    if let Some(fields) = message.as_object_mut() {
        fields.retain(|key, _| {
            [
                "state",
                "assurance",
                "text",
                "encoding",
                "partial",
                "message_id",
                "sender",
                "sender_actor",
                "reply_to",
                "thread_root",
                "message_kind",
                "conversation_id",
                "context",
                "mentions",
                "event",
            ]
            .contains(&key.as_str())
        });
        fields.insert("can_reply".into(), json!(can_reply));
    }
    if entry["state"] == "PENDING"
        && !matches!(
            message["state"].as_str(),
            Some("OPENED" | "EVENT" | "SOURCE_REFERENCE")
        )
    {
        return Err(error("NOTIFICATION_CONTENT_NOT_READY"));
    }
    if entry["state"] == "PENDING" && message.is_null() {
        return Err(error("NOTIFICATION_CONTENT_NOT_READY"));
    }
    Ok(
        json!({"item":{"sequence":entry["sequence"],"delivery_id":entry["delivery_id"]},"state":entry["state"],"terminal_reason":entry["terminal_reason"],"message":message,"authority":"EXTERNAL_PEER_DATA"}),
    )
}
