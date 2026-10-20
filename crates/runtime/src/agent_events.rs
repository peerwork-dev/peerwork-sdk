//! Native verified ACTION-receipt delivery using full authenticated replay.
//! This is not incremental transport/replay, an all-event source, or a daemon.
use crate::{
    agent_inbox::{
        AgentInbox, InboxBinding, InboxError, InboxLimits, InboxSourceEvent, VerifiedInboxBatch,
    },
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_verified_read::TransportReplayedJournal,
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub const SOURCE: &str = "verified-action-receipts/v1";
#[derive(Debug, Error)]
pub enum AgentEventsError {
    #[error("event source read failed: {0}")]
    Read(#[from] SecureReadAccessError),
    #[error("event inbox operation failed: {0}")]
    Inbox(#[from] InboxError),
    #[error("event source context does not match")]
    Context,
    #[error("verified event source is unsupported or malformed")]
    Source,
    #[error("event request is invalid")]
    Invalid,
    #[error("event operation cancelled")]
    Cancelled,
}
impl AgentEventsError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(e) => e.code(),
            Self::Inbox(e) => match e {
                InboxError::NotReady => "INBOX_NOT_READY",
                InboxError::Gap => "SOURCE_GAP",
                InboxError::Backpressure => "INBOX_BACKPRESSURE",
                InboxError::Busy => "STATE_BUSY",
                InboxError::StaleLease => "STALE_LEASE",
                InboxError::ContextMismatch => "CONTEXT_MISMATCH",
                InboxError::CursorConflict => "CURSOR_CONFLICT",
                InboxError::EventConflict => "EVENT_CONFLICT",
                InboxError::Cancelled => "CANCELLED",
                InboxError::Unsupported => "UNSUPPORTED_PLATFORM",
                InboxError::Invalid => "INVALID_INPUT",
                InboxError::ConsumerMissing => "CONSUMER_MISSING",
                InboxError::Protection => "STATE_PROTECTION",
                InboxError::Storage => "STATE_FAILED",
            },
            Self::Context => "CONTEXT_MISMATCH",
            Self::Source => "UNSUPPORTED_SOURCE",
            Self::Invalid => "INVALID_INPUT",
            Self::Cancelled => "CANCELLED",
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    sequence: u64,
    head: Option<String>,
    policy_hash: String,
}
fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && !s.contains('\0')
}
fn semantics() -> Value {
    json!({"source":SOURCE,"reader":"checkpoint_probe_then_full_history_replay","coverage":"action_receipts_only","incremental":false,"start":"retained_history","ack":"local_delivery_acceptance"})
}
fn local_binding(
    config: &SecureReadProfileConfig,
    fp: &str,
) -> Result<(InboxBinding, String, String), AgentEventsError> {
    let identity = crate::kernel_identity::KernelIdentity::inspect_existing(&config.identity_path)
        .map_err(|_| AgentEventsError::Context)?;
    let owner = config
        .owner_actor_id
        .as_deref()
        .filter(|s| valid(s))
        .ok_or(AgentEventsError::Context)?;
    let owner_key = config
        .owner_key_id
        .as_deref()
        .filter(|s| valid(s))
        .ok_or(AgentEventsError::Context)?;
    let authority = config
        .authority
        .clone()
        .unwrap_or_else(|| sha256_hex(identity.actor_id().as_bytes()));
    let fingerprint=sha256_hex(&serde_json::to_vec(&json!({"context":fp,"origin":config.origin,"authority":authority,"actor":identity.actor_id(),"key":identity.key_id(),"workspace":config.workspace_id,"owner":owner,"owner_key":owner_key})).map_err(|_|AgentEventsError::Invalid)?);
    Ok((
        InboxBinding {
            service: config.origin.clone(),
            principal: identity.actor_id().into(),
            workspace: config.workspace_id.clone(),
            source: SOURCE.into(),
            context_fingerprint: fingerprint,
        },
        identity.key_id().into(),
        authority,
    ))
}
fn local_inbox(config: &SecureReadProfileConfig, fp: &str) -> Result<AgentInbox, AgentEventsError> {
    let (binding, _, _) = local_binding(config, fp)?;
    Ok(AgentInbox::open_existing(
        &config.state_dir.join("agent-events.sqlite"),
        &binding,
        InboxLimits::default(),
    )?)
}
fn open_inbox(
    config: &SecureReadProfileConfig,
    fp: &str,
    source: &TransportReplayedJournal,
) -> Result<AgentInbox, AgentEventsError> {
    source
        .verified_read()
        .map_err(|_| AgentEventsError::Source)?;
    let (binding, key, authority) = local_binding(config, fp)?;
    if source.origin() != binding.service
        || source.source_actor_id() != binding.principal
        || source.source_key_id() != key
        || source.authority() != authority
        || source.replay().workspace_id() != binding.workspace
        || Some(source.replay().owner_actor_id()) != config.owner_actor_id.as_deref()
        || Some(source.replay().owner_signing_key()) != config.owner_key_id.as_deref()
    {
        return Err(AgentEventsError::Context);
    }
    Ok(AgentInbox::open(
        &config.state_dir.join("agent-events.sqlite"),
        &binding,
        InboxLimits::default(),
    )?)
}
fn sync_replay(
    config: &SecureReadProfileConfig,
    fp: &str,
    source: &TransportReplayedJournal,
    cancel: &CancellationToken,
) -> Result<Value, AgentEventsError> {
    let mut inbox = open_inbox(config, fp, source)?;
    let status = inbox.status()?;
    if status.gap {
        return Err(InboxError::Gap.into());
    }
    let prior = status.verified_cursor;
    let old = prior
        .as_ref()
        .map(|s| serde_json::from_str::<Cursor>(s).map_err(|_| AgentEventsError::Source))
        .transpose()?;
    if let Some(old) = &old {
        if !source
            .replay()
            .contains_checkpoint(old.sequence, old.head.as_deref(), &old.policy_hash)
        {
            inbox.report_gap()?;
            return Err(InboxError::Gap.into());
        }
    }
    let next = Cursor {
        sequence: source.replay().sequence(),
        head: source.replay().head().map(str::to_owned),
        policy_hash: source.replay().policy_hash().to_owned(),
    };
    let next_wire = serde_json::to_string(&next).map_err(|_| AgentEventsError::Source)?;
    if prior.as_deref() == Some(&next_wire) {
        return Ok(
            json!({"semantics":semantics(),"changed":false,"enqueued":0,"status":inbox.status()?}),
        );
    }
    let after = old.as_ref().map_or(0, |c| c.sequence);
    // These exact signed artifacts have already passed native replay. Their
    // payload selects a native receipt; it does not itself authorize an event.
    let receipts = source.signed_commit_wires().iter().map(|wire| {
        if cancel.is_cancelled() {
            return Err(AgentEventsError::Cancelled);
        }
        let commit = parse_wire_json_bounded(
            wire,
            64,
            usize::try_from(config.max_replay_artifact_bytes)
                .map_err(|_| AgentEventsError::Invalid)?,
        )
        .map_err(|_| AgentEventsError::Source)?;
        let payload = commit.get("payload").ok_or(AgentEventsError::Source)?;
        let sequence = number(payload, "sequence")?;
        if sequence <= after {
            return Ok((sequence, None));
        }
        let command = payload
            .get("command_id")
            .and_then(WireValue::as_string)
            .ok_or(AgentEventsError::Source)?;
        let event = source
            .action_receipt(&command)
            .map_err(|_| AgentEventsError::Source)?
            .map(|receipt| {
                if number(receipt, "sequence")? != sequence {
                    return Err(AgentEventsError::Source);
                }
                receipt_event(receipt)
            })
            .transpose()?;
        Ok((sequence, event))
    });
    let (events, through) = receipt_batch(
        receipts,
        after,
        next.sequence,
        InboxLimits::default().max_batch_events,
    )?;
    // Only a checkpoint derived from the fully authenticated replay can become
    // the partial cursor. Later syncs replay history and resume after this point.
    let (_, head, policy_hash) = source
        .replay()
        .checkpoint_at(through)
        .ok_or(AgentEventsError::Source)?;
    let partial = Cursor {
        sequence: through,
        head: head.map(str::to_owned),
        policy_hash: policy_hash.to_owned(),
    };
    let next_wire = serde_json::to_string(&partial).map_err(|_| AgentEventsError::Source)?;
    if cancel.is_cancelled() {
        return Err(AgentEventsError::Cancelled);
    }
    let count = events.len();
    inbox.ingest_verified(VerifiedInboxBatch {
        prior_cursor: prior,
        next_cursor: next_wire,
        events,
    })?;
    Ok(
        json!({"semantics":semantics(),"changed":true,"enqueued":count,"has_more":through < next.sequence,"status":inbox.status()?}),
    )
}
// Bounded projection only: callers must provide receipts from native replay.
// Returning at the last included receipt never skips a later ACTION, including
// when intervening non-ACTION commits are present.
fn receipt_batch(
    receipts: impl IntoIterator<Item = Result<(u64, Option<InboxSourceEvent>), AgentEventsError>>,
    after: u64,
    final_sequence: u64,
    limit: usize,
) -> Result<(Vec<InboxSourceEvent>, u64), AgentEventsError> {
    if limit == 0 {
        return Err(AgentEventsError::Invalid);
    }
    let mut events = Vec::new();
    for receipt in receipts {
        let (sequence, event) = receipt?;
        if sequence <= after {
            continue;
        }
        if let Some(event) = event {
            events.push(event);
            if events.len() == limit {
                return Ok((events, sequence));
            }
        }
    }
    Ok((events, final_sequence))
}
fn receipt_event(receipt: &WireValue) -> Result<InboxSourceEvent, AgentEventsError> {
    let hash = receipt
        .get("commit_hash")
        .and_then(WireValue::as_string)
        .ok_or(AgentEventsError::Source)?;
    let payload = canonical_wire_value(receipt, CanonicalPath::SecureArtifact)
        .map_err(|_| AgentEventsError::Source)?
        .into_bytes();
    Ok(InboxSourceEvent {
        event_id: format!("{SOURCE}:{hash}:receipt"),
        version: "1".into(),
        authoritative_hash: hash,
        payload,
    })
}
fn number(value: &WireValue, key: &str) -> Result<u64, AgentEventsError> {
    value
        .get(key)
        .and_then(WireValue::as_number)
        .filter(|v| v.is_finite() && *v >= 0.0 && *v <= 9_007_199_254_740_991.0 && v.fract() == 0.0)
        .map(|v| v as u64)
        .ok_or(AgentEventsError::Source)
}
/// A probe can only recognize an already verified checkpoint. It cannot mint
/// a new trusted floor, adopt policy bytes, enqueue events, or establish global
/// freshness against a service withholding history. Any changed/ambiguous reply
/// goes through the existing full authenticated replay path.
fn unchanged_probe_reply(
    wire: &[u8],
    config: &SecureReadProfileConfig,
    cursor: &Cursor,
    max_bytes: usize,
) -> bool {
    let Ok(value) = parse_wire_json_bounded(wire, 64, max_bytes) else {
        return false;
    };
    let text = |v: &WireValue, k: &str| v.get(k).and_then(WireValue::as_string);
    if text(&value, "state").as_deref() != Some("ACTIVE")
        || text(&value, "visibility").as_deref() != Some("PRIVATE")
        || text(&value, "workspace_id").as_deref() != Some(config.workspace_id.as_str())
        || !matches!(value.get("commits"),Some(WireValue::Array(items)) if items.is_empty())
        || !matches!(value.get("next"), Some(WireValue::Null))
    {
        return false;
    }
    let Some(checkpoint) = value.get("checkpoint") else {
        return false;
    };
    if number(checkpoint, "v").ok() != Some(1)
        || number(checkpoint, "sequence").ok() != Some(cursor.sequence)
        || text(checkpoint, "workspace_id").as_deref() != Some(config.workspace_id.as_str())
        || text(checkpoint, "owner_id").as_deref() != config.owner_actor_id.as_deref()
        || text(checkpoint, "owner_key").as_deref() != config.owner_key_id.as_deref()
        || text(checkpoint, "policy_hash").as_deref() != Some(cursor.policy_hash.as_str())
        || cursor.head.is_none()
        || text(checkpoint, "head").as_deref() != cursor.head.as_deref()
    {
        return false;
    }
    // The selected policy is matched by its already verified digest. No policy
    // in this response is adopted or used to grant authority.
    let Some(WireValue::Array(policies)) = value.get("policies") else {
        return false;
    };
    !policies.is_empty()
        && policies.len() <= 1024
        && policies.iter().any(|policy| {
            canonical_wire_value(policy, CanonicalPath::SecureArtifact)
                .ok()
                .is_some_and(|wire| sha256_hex(wire.as_bytes()) == cursor.policy_hash)
        })
}
fn try_unchanged_probe(
    config: &SecureReadProfileConfig,
    fp: &str,
    cancel: &CancellationToken,
) -> Result<Option<Value>, AgentEventsError> {
    if cancel.is_cancelled() {
        return Err(AgentEventsError::Cancelled);
    }
    let inbox = match local_inbox(config, fp) {
        Ok(inbox) => inbox,
        Err(AgentEventsError::Inbox(InboxError::NotReady)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let before = inbox.status()?;
    if before.gap {
        return Err(InboxError::Gap.into());
    }
    let Some(cursor_wire) = before.verified_cursor.as_deref() else {
        return Ok(None);
    };
    let cursor: Cursor = serde_json::from_str(cursor_wire).map_err(|_| AgentEventsError::Source)?;
    if cursor.sequence == 0 || cursor.head.is_none() {
        return Ok(None);
    }
    // Probe requires existing discovery continuity. Never bootstrap pins merely
    // because an inbox is present; full sync owns initial source verification.
    let journal = config.state_dir.join("kernel.sqlite");
    if !std::fs::symlink_metadata(&journal).is_ok_and(|m| m.file_type().is_file()) {
        return Ok(None);
    }
    let (binding, key, authority) = local_binding(config, fp)?;
    let identity = crate::kernel_identity::KernelIdentity::inspect_existing(&config.identity_path)
        .map_err(|_| AgentEventsError::Context)?;
    if identity.actor_id() != binding.principal || identity.key_id() != key {
        return Err(AgentEventsError::Context);
    }
    let mut transport = crate::transport::TransportConfig::new(&config.origin)
        .with_options(config.transport.clone());
    transport.allow_loopback_http = config.allow_loopback_http;
    let features = config
        .required_features
        .iter()
        .map(|s| s.encode_utf16().collect())
        .collect::<Vec<Vec<u16>>>();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AgentEventsError::Source)?;
    let probe = runtime.block_on(async {
        let client =
            crate::kernel_client::KernelClient::open(transport, &journal, &features, cancel)
                .await
                .ok()?;
        if !crate::secure_read_profile::canonical_origin_matches(&config.origin, client.origin()) {
            return None;
        }
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/journal?after={}&limit=1",
            config.workspace_id, cursor.sequence
        );
        let proof = crate::secure_journal_read::sign_read_proof(
            &path,
            client.discovery(),
            &identity,
            &authority,
        )
        .ok()?;
        let max_bytes = usize::try_from(config.max_replay_artifact_bytes)
            .ok()?
            .min(64 * 1024 * 1024);
        let response = client
            .transport()
            .get_secure_journal_exact(&path, &proof, max_bytes, cancel)
            .await
            .ok()?;
        if response.status != 200
            || !unchanged_probe_reply(&response.wire, config, &cursor, max_bytes)
        {
            return None;
        }
        Some(())
    });
    if cancel.is_cancelled() {
        return Err(AgentEventsError::Cancelled);
    }
    if probe.is_none() {
        return Ok(None);
    }
    // Another writer may have advanced or marked this source while the GET was
    // in flight. The old observation must not describe that new local position.
    let after = inbox.status()?;
    if after.gap {
        return Err(InboxError::Gap.into());
    }
    if after.verified_cursor != before.verified_cursor
        || after.enqueued_cursor != before.enqueued_cursor
    {
        return Ok(None);
    }
    Ok(Some(
        json!({"semantics":semantics(),"changed":false,"enqueued":0,"status":after,"probe":"unchanged","sync_path":"checkpoint_probe"}),
    ))
}
/// Probe an initialized source for the exact protected checkpoint; otherwise
/// fully refresh/verify history and transactionally enqueue verified receipts.
/// Resource/transport/verification failures never assert a retention gap.
pub fn sync(
    config: SecureReadProfileConfig,
    fp: &str,
    cancel: &CancellationToken,
) -> Result<Value, AgentEventsError> {
    if !valid(fp) {
        return Err(AgentEventsError::Invalid);
    }
    if let Some(unchanged) = try_unchanged_probe(&config, fp, cancel)? {
        return Ok(unchanged);
    }
    let mut result = SecureReadProfile::new(config.clone())
        .with_latest_replay(cancel, |source| sync_replay(&config, fp, source, cancel))?;
    result["sync_path"] = json!("full_history_replay");
    Ok(result)
}
/// Offline status requires the protected pinned source, not caller-supplied JSON.
pub fn status(config: SecureReadProfileConfig, fp: &str) -> Result<Value, AgentEventsError> {
    if !valid(fp) {
        return Err(AgentEventsError::Invalid);
    }
    let inbox = local_inbox(&config, fp)?;
    Ok(json!({"semantics":semantics(),"status":inbox.status()?}))
}
pub fn ack(
    config: SecureReadProfileConfig,
    fp: &str,
    consumer: &str,
    filter_version: &str,
    ack_token: &str,
) -> Result<Value, AgentEventsError> {
    if !valid(fp) {
        return Err(AgentEventsError::Invalid);
    }
    if !valid(consumer) || !valid(filter_version) || !valid(ack_token) {
        return Err(AgentEventsError::Invalid);
    }
    let mut inbox = local_inbox(&config, fp)?;
    inbox.ack(consumer, filter_version, ack_token)?;
    Ok(
        json!({"semantics":semantics(),"acknowledged":true,"consumer":inbox.consumer_status(consumer,filter_version)?}),
    )
}
fn receive_local(
    config: &SecureReadProfileConfig,
    fp: &str,
    consumer: &str,
    version: &str,
    lease_ms: u64,
    cancel: &CancellationToken,
) -> Result<Value, AgentEventsError> {
    if cancel.is_cancelled() {
        return Err(AgentEventsError::Cancelled);
    }
    let mut inbox = local_inbox(config, fp)?;
    inbox.register_consumer(consumer, version)?;
    let delivery = inbox.receive(consumer, version, lease_ms, cancel)?;
    // Preserve exact canonical bytes alongside ergonomic decoded JSON.
    // Lone UTF-16 surrogate values remain available in canonical form when
    // serde_json cannot represent them; no lossy substitution is made.
    let delivery=delivery.map(|d| -> Result<Value,AgentEventsError> {
            let canonical=String::from_utf8(d.payload).map_err(|_|AgentEventsError::Source)?;
            let wire=parse_wire_json_bounded(canonical.as_bytes(),4096,64*1024*1024).map_err(|_|AgentEventsError::Source)?;
            let decoded=serde_json::from_str::<Value>(&canonical).ok();
            Ok(json!({"consumer_id":d.consumer_id,"filter_version":d.filter_version,"event_id":d.event_id,"version":d.version,"authoritative_hash":d.authoritative_hash,"workspace_id":config.workspace_id,"command_id":wire.get("command_id").and_then(WireValue::as_string),"actor_id":wire.get("actor_id").and_then(WireValue::as_string),"receipt":decoded,"receipt_canonical_json":canonical,"ack_token":d.ack_token,"lease_until_ms":d.lease_until_ms}))
        }).transpose()?;
    Ok(
        json!({"semantics":semantics(),"delivery":delivery,"consumer":inbox.consumer_status(consumer,version)?}),
    )
}
/// Explicit consumer/version registers a retained-history subscription. Zero
/// wait reads the protected local inbox only (call sync to refresh). Positive
/// waits deliver queued work first, then refresh empty queues with bounded native
/// backoff, never Agent inference.
pub fn receive(
    config: SecureReadProfileConfig,
    fp: &str,
    consumer: &str,
    filter_version: &str,
    lease_ms: u64,
    wait_ms: u64,
    cancel: &CancellationToken,
) -> Result<Value, AgentEventsError> {
    if !valid(fp) {
        return Err(AgentEventsError::Invalid);
    }
    if wait_ms > 60_000
        || !(1..=3_600_000).contains(&lease_ms)
        || !valid(consumer)
        || !valid(filter_version)
    {
        return Err(AgentEventsError::Invalid);
    }
    if cancel.is_cancelled() {
        return Err(AgentEventsError::Cancelled);
    }
    if wait_ms == 0 {
        return receive_local(&config, fp, consumer, filter_version, lease_ms, cancel);
    }
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    // Durable already-enqueued work is available offline regardless of the
    // caller's willingness to wait. Only an empty/uninitialized inbox needs I/O.
    match receive_local(&config, fp, consumer, filter_version, lease_ms, cancel) {
        Ok(mut value) if !value["delivery"].is_null() => {
            value["wait_status"] = json!("delivered");
            return Ok(value);
        }
        Ok(_) | Err(AgentEventsError::Inbox(InboxError::NotReady)) => {}
        Err(error) => return Err(error),
    }
    let child = cancel.child_token();
    let timer = child.clone();
    // Cancellation propagates into all HTTP/page/replay operations. Dropping
    // the guard also stops the short-lived timer after an early delivery.
    struct Stop(CancellationToken);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let _stop = Stop(child.clone());
    std::thread::spawn(move || {
        while !timer.is_cancelled() && Instant::now() < deadline {
            std::thread::sleep(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        timer.cancel();
    });
    let mut backoff = Duration::from_millis(500);
    loop {
        let result = sync(config.clone(), fp, &child)
            .and_then(|_| receive_local(&config, fp, consumer, filter_version, lease_ms, &child));
        if cancel.is_cancelled() {
            return Err(AgentEventsError::Cancelled);
        }
        match result {
            Ok(mut value) => {
                if !value["delivery"].is_null() {
                    value["wait_status"] = json!("delivered");
                    return Ok(value);
                }
            }
            Err(ref error) if Instant::now() >= deadline && error.code() == "CANCELLED" => {
                return Ok(
                    json!({"semantics":semantics(),"delivery":null,"wait_status":"deadline","continuation":{"consumer_id":consumer,"filter_version":filter_version}}),
                )
            }
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Ok(
                json!({"semantics":semantics(),"delivery":null,"wait_status":"deadline","continuation":{"consumer_id":consumer,"filter_version":filter_version}}),
            );
        }
        let pause_until = (Instant::now() + backoff).min(deadline);
        while Instant::now() < pause_until && !child.is_cancelled() {
            std::thread::sleep(
                Duration::from_millis(20)
                    .min(pause_until.saturating_duration_since(Instant::now())),
            );
        }
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}
#[cfg(test)]
mod tests;
