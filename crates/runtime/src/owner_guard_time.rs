//! Explicit durable Owner guard-time activation. Full replay, exact source CAS,
//! protected service pins and exact saved encrypted packets precede submission.
use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_intents::{SecureIntentJournal, SecurePacketInput},
    secure_lifecycle::SecureLifecycle,
    secure_owner_create::{SecureOwnerCreateConfig, SecureOwnerWorkspaceCreate},
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
    secure_state::SecureStateStore,
    transport::TransportConfig,
};
use peerwork_core::{
    crypto::{base64url, decode_base64url},
    prepared_owner_guard_time::{
        prepare_owner_guard_time_enable, verify_saved_owner_guard_time_enable,
    },
    read_view,
    replayed_secure_journal::StructureStatus,
    wire_json::WireValue,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
type R<T> = Result<T, Error>;
#[derive(Debug)]
struct Error(&'static str);
impl From<SecureReadAccessError> for Error {
    fn from(e: SecureReadAccessError) -> Self {
        if matches!(e, SecureReadAccessError::Cancelled) {
            Self("CANCELLED")
        } else {
            Self("GUARD_TIME_SOURCE_UNVERIFIED")
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnableInput {
    workspace_id: String,
    expected_policy_hash: String,
    audience: String,
    service_key: String,
    disclosure: String,
    #[serde(default)]
    operation_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeInput {
    workspace_id: String,
    operation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryInput {
    workspace_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    input: EnableInput,
    issued_at: u64,
    source: Value,
    request: String,
    commit_hash: String,
    policy_hash: String,
    accepted: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    v: u8,
    origin: String,
    workspace_id: String,
    actor_id: String,
    owner_key: String,
    rows: BTreeMap<String, Row>,
}
fn digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn payload(v: &WireValue) -> R<&WireValue> {
    v.get("payload")
        .ok_or(Error("GUARD_TIME_SOURCE_UNVERIFIED"))
}
fn n(v: &WireValue, key: &str) -> R<u64> {
    let n = v
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(Error("GUARD_TIME_SOURCE_UNVERIFIED"))?;
    if !n.is_finite() || n < 0.0 || n > 9007199254740991.0 || n.fract() != 0.0 {
        return Err(Error("GUARD_TIME_SOURCE_UNVERIFIED"));
    }
    Ok(n as u64)
}
fn fail(code: &'static str) -> Error {
    Error(code)
}
fn parse<T: serde::de::DeserializeOwned>(s: &str) -> R<T> {
    if s.len() > 65536 {
        return Err(fail("INPUT_INVALID"));
    }
    serde_json::from_str(s).map_err(|_| fail("INPUT_INVALID"))
}
fn active(cancel: &CancellationToken) -> R<()> {
    if cancel.is_cancelled() {
        Err(fail("CANCELLED"))
    } else {
        Ok(())
    }
}
fn random_id() -> R<String> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| fail("ENTROPY"))?;
    Ok(base64url(&bytes))
}
fn now() -> R<u64> {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| fail("CLOCK"))?
        .as_millis();
    if n > 9007199254740991 {
        return Err(fail("CLOCK"));
    }
    Ok(n as u64)
}
fn policy(input: &EnableInput) -> Value {
    json!({"v":1,"mode":"ALL_COMMITS","audience":input.audience,"service_key":input.service_key,"disclosure":input.disclosure})
}
fn result(id: &str, config: &SecureReadProfileConfig, row: &Row) -> Value {
    json!({"operation_id":id,"command_id":id,"workspace_id":config.workspace_id,"status":if row.accepted{"ACCEPTED"}else{"PENDING"},"sequence":if row.accepted{row.source["sequence"].as_u64().map(|n|n+1)}else{None},"head":if row.accepted{Some(&row.commit_hash)}else{None},"policy_hash":if row.accepted{Some(&row.policy_hash)}else{None}})
}
fn open_history(
    config: &SecureReadProfileConfig,
    identity: &KernelIdentity,
) -> R<(SecureStateStore, History)> {
    let store = SecureStateStore::open(&config.state_dir.join("owner-guard-time.state"))
        .map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?;
    let doc = match store
        .read_exact()
        .map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?
    {
        Some(bytes) => {
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(fail("GUARD_TIME_RESOURCE_LIMIT"));
            }
            serde_json::from_slice(&bytes).map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?
        }
        None => History {
            v: 1,
            origin: config.origin.clone(),
            workspace_id: config.workspace_id.clone(),
            actor_id: identity.actor_id().into(),
            owner_key: identity.key_id().into(),
            rows: BTreeMap::new(),
        },
    };
    if doc.v != 1
        || doc.origin != config.origin
        || doc.workspace_id != config.workspace_id
        || doc.actor_id != identity.actor_id()
        || doc.owner_key != identity.key_id()
        || doc.rows.len() > 128
    {
        return Err(fail("GUARD_TIME_PIN_CHANGED"));
    }
    Ok((store, doc))
}
fn save(store: &SecureStateStore, doc: &History) -> R<()> {
    let bytes = serde_json::to_vec(doc).map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(fail("GUARD_TIME_RESOURCE_LIMIT"));
    }
    store
        .write_exact(&bytes)
        .map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))
}
fn check_service(
    config: &SecureReadProfileConfig,
    input: &EnableInput,
    cancel: &CancellationToken,
) -> R<()> {
    let mut transport = TransportConfig::new(&config.origin).with_options(config.transport.clone());
    transport.allow_loopback_http = config.allow_loopback_http;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| fail("RUNTIME_FAILED"))?;
    let client = runtime
        .block_on(KernelClient::open_existing(
            transport,
            &config.state_dir.join("kernel.sqlite"),
            &[],
            cancel,
        ))
        .map_err(|_| {
            if cancel.is_cancelled() {
                fail("CANCELLED")
            } else {
                fail("GUARD_TIME_SERVICE_PIN_FAILED")
            }
        })?;
    let discovery = client.discovery();
    if String::from_utf16(discovery.audience_utf16())
        .ok()
        .as_deref()
        != Some(input.audience.as_str())
        || discovery.receipt_public_key() != input.service_key
        || !discovery.protocol_features().iter().any(|v| {
            v.iter()
                .copied()
                .eq("signed-private-guard-time-v1".encode_utf16())
        })
    {
        return Err(fail("GUARD_TIME_SERVICE_PIN_FAILED"));
    }
    let cap = runtime
        .block_on(client.transport().guard_time_capabilities(cancel))
        .map_err(|_| {
            if cancel.is_cancelled() {
                fail("CANCELLED")
            } else {
                fail("GUARD_TIME_CAPABILITY_UNAVAILABLE")
            }
        })?;
    if cap.status != 200 {
        return Err(fail("GUARD_TIME_CAPABILITY_UNAVAILABLE"));
    }
    let cap: Value =
        serde_json::from_slice(&cap.wire).map_err(|_| fail("GUARD_TIME_CAPABILITY_UNAVAILABLE"))?;
    if cap["v"] != 1
        || cap["expression_profile"] != "time-add-guard-window-v1"
        || cap["effects"] != "TIME_FREE"
    {
        return Err(fail("GUARD_TIME_CAPABILITY_UNAVAILABLE"));
    }
    Ok(())
}
fn post(
    config: &SecureReadProfileConfig,
    identity: &KernelIdentity,
    id: &str,
    row: &Row,
    cancel: &CancellationToken,
) -> R<()> {
    active(cancel)?;
    let packet = decode_base64url(&row.request).map_err(|_| fail("GUARD_TIME_PACKET_INVALID"))?;
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        config.workspace_id
    );
    let mut journal = SecureIntentJournal::open(
        &config.state_dir.join("guard-time-intents.sqlite"),
        &config.origin,
        identity.actor_id(),
    )
    .map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?;
    journal
        .prepare(SecurePacketInput {
            intent_id: id,
            path: &path,
            action_id: "secure.guard-time.enable",
            workspace_id: Some(&config.workspace_id),
            trusted_owner_key: Some(identity.key_id()),
            intent_digest: &row.commit_hash,
            exact_request: &packet,
        })
        .map_err(|_| fail("GUARD_TIME_INTENT_CONFLICT"))?;
    if journal
        .exact_request(id)
        .map_err(|_| fail("GUARD_TIME_PACKET_INVALID"))?
        != packet
    {
        return Err(fail("GUARD_TIME_PACKET_INVALID"));
    }
    Ok(())
}
fn send(
    config: &SecureReadProfileConfig,
    identity: &KernelIdentity,
    id: &str,
    row: &Row,
    cancel: &CancellationToken,
) -> R<()> {
    post(config, identity, id, row, cancel)?;
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        config.workspace_id
    );
    let mut transport = TransportConfig::new(&config.origin).with_options(config.transport.clone());
    transport.allow_loopback_http = config.allow_loopback_http;
    let transport = crate::transport::HttpTransport::new(transport)
        .map_err(|_| fail("TRANSPORT_CONFIGURATION_INVALID"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| fail("RUNTIME_FAILED"))?;
    let packet = decode_base64url(&row.request).map_err(|_| fail("GUARD_TIME_PACKET_INVALID"))?;
    let response = runtime
        .block_on(transport.post_exact(&path, packet, cancel))
        .map_err(|_| {
            if cancel.is_cancelled() {
                fail("CANCELLED")
            } else {
                fail("GUARD_TIME_TRANSPORT_FAILED")
            }
        })?;
    let mut journal = SecureIntentJournal::open(
        &config.state_dir.join("guard-time-intents.sqlite"),
        &config.origin,
        identity.actor_id(),
    )
    .map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?;
    if !response.wire.is_empty() {
        journal
            .observe_response(id, &response.wire)
            .map_err(|_| fail("GUARD_TIME_LOCAL_STATE"))?;
    }
    if !(200..300).contains(&response.status) {
        return Err(fail("GUARD_TIME_SERVER_REJECTED"));
    }
    Ok(())
}
pub fn owner_guard_time_json(
    config_json: &str,
    operation: &str,
    input_json: &str,
    cancel: &CancellationToken,
) -> String {
    let result = run(config_json, operation, input_json, cancel);
    match result {
        Ok(value) => json!({"ok":true,"value":value}).to_string(),
        Err(e) => json!({"ok":false,"code":e.0,"message":e.0}).to_string(),
    }
}
fn run(
    config_json: &str,
    operation: &str,
    input_json: &str,
    cancel: &CancellationToken,
) -> R<Value> {
    active(cancel)?;
    let owner: SecureOwnerCreateConfig = parse(config_json)?;
    let (workspace, id, mut input) = match operation {
        "enable" => {
            let i: EnableInput = parse(input_json)?;
            if !digest(&i.expected_policy_hash)
                || i.disclosure != "GUARD_WINDOW"
                || !read_view::token(&i.service_key)
                || i.audience.is_empty()
                || i.audience.encode_utf16().count() > 200
            {
                return Err(fail("INPUT_INVALID"));
            }
            let id = i.operation_id.clone().map(Ok).unwrap_or_else(random_id)?;
            (i.workspace_id.clone(), Some(id), Some(i))
        }
        "resume" => {
            let i: ResumeInput = parse(input_json)?;
            (i.workspace_id, Some(i.operation_id), None)
        }
        "history" => {
            let i: HistoryInput = parse(input_json)?;
            (i.workspace_id, None, None)
        }
        _ => return Err(fail("INPUT_INVALID")),
    };
    if !read_view::token(&workspace) || id.as_ref().is_some_and(|id| !read_view::token(id)) {
        return Err(fail("INPUT_INVALID"));
    }
    let config = SecureOwnerWorkspaceCreate::new(owner)
        .guard_time_profile(&workspace)
        .map_err(|_| fail("GUARD_TIME_OWNER_PROFILE_REQUIRED"))?;
    let identity =
        KernelIdentity::open(&config.identity_path).map_err(|_| fail("IDENTITY_STATE"))?;
    let (store, doc) = open_history(&config, &identity)?;
    if operation == "history" {
        return Ok(Value::Array(
            doc.rows
                .iter()
                .map(|(id, row)| result(id, &config, row))
                .collect(),
        ));
    }
    let id = id.unwrap();
    if let Some(i) = input.as_mut() {
        i.operation_id = Some(id.clone());
    }
    let saved = doc.rows.get(&id).cloned();
    if let (Some(i), Some(row)) = (&input, &saved) {
        if i != &row.input {
            return Err(fail("GUARD_TIME_OPERATION_CONFLICT"));
        }
    }
    if operation == "resume" && saved.is_none() {
        return Err(fail("GUARD_TIME_OPERATION_NOT_FOUND"));
    }
    if saved.is_none() && doc.rows.values().any(|r| !r.accepted) {
        return Err(fail("GUARD_TIME_PENDING_OPERATION"));
    }
    let options = saved
        .as_ref()
        .map(|r| r.input.clone())
        .or(input)
        .ok_or(fail("INPUT_INVALID"))?;
    drop(doc);
    drop(store);
    check_service(&config, &options, cancel)?;
    SecureReadProfile::new(config.clone()).with_latest_replay(cancel,|source|->R<Value>{
 source.verified_read().map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;
 if source.origin()!=config.origin||source.source_actor_id()!=identity.actor_id()||source.source_key_id()!=identity.key_id()||source.replay().owner_actor_id()!=identity.actor_id()||source.replay().owner_signing_key()!=identity.key_id()||source.replay().structure_status()==StructureStatus::Seeding{return Err(fail("GUARD_TIME_OWNER_REQUIRED"))}
 let lifecycle=SecureLifecycle::open_existing(&config.state_dir.join("lifecycle.state"),source.origin(),identity.actor_id(),&workspace,identity.actor_id(),identity.key_id()).map_err(|_|fail("GUARD_TIME_ACTIVE_KEY_REQUIRED"))?;
 let ring=lifecycle.active_keyring_without_pending().ok_or(fail("GUARD_TIME_PENDING_KEY_TRANSITION"))?;
 let (store,mut doc)=open_history(&config,&identity)?;
 let mut row=if let Some(row)=doc.rows.get(&id).cloned(){
 if row.input!=options{return Err(fail("GUARD_TIME_OPERATION_CONFLICT"))}
 let seq=row.source["sequence"].as_u64().ok_or(fail("GUARD_TIME_PACKET_INVALID"))?;let head=row.source["head"].as_str().ok_or(fail("GUARD_TIME_PACKET_INVALID"))?;
 if !source.replay().contains_checkpoint(seq,Some(head),&row.input.expected_policy_hash){return Err(fail("GUARD_TIME_SOURCE_FORK"))}
 let old=source.signed_policy_by_hash(&row.input.expected_policy_hash).ok_or(fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;
 let old_value=read_view::parse(old,2*1024*1024).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;let epoch=n(payload(&old_value).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?,"epoch").map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;
 let key=ring.key_at(epoch).ok_or(fail("GUARD_TIME_HISTORICAL_KEY_REQUIRED"))?;
 let checkpoint=peerwork_core::canonical::canonical(&row.source,peerwork_core::canonical::Path::SecureArtifact).map_err(|_|fail("GUARD_TIME_PACKET_INVALID"))?;
 let ring_wire=ring.canonical_wire().map_err(|_|fail("GUARD_TIME_ACTIVE_KEY_REQUIRED"))?;
 let prior=source.authenticated_prefix_replay(checkpoint.as_bytes(),Some(&ring_wire)).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;
 let packet=decode_base64url(&row.request).map_err(|_|fail("GUARD_TIME_PACKET_INVALID"))?;
 let proof=verify_saved_owner_guard_time_enable(&packet,policy(&options).to_string().as_bytes(),old,checkpoint.as_bytes(),prior.objects(),key,identity.signing_key(),&id,row.issued_at).map_err(|_|fail("GUARD_TIME_PACKET_INVALID"))?;
 if proof.commit_hash()!=row.commit_hash||proof.policy_hash()!=row.policy_hash{return Err(fail("GUARD_TIME_PACKET_INVALID"))}
 if source.replay().contains_checkpoint(seq+1,Some(&row.commit_hash),&row.policy_hash){let mut row=row;row.accepted=true;doc.rows.insert(id.clone(),row.clone());save(&store,&doc)?;return Ok(result(&id,&config,&row))}
 if row.accepted||source.replay().sequence()!=seq||source.replay().head()!=Some(head)||source.replay().policy_hash()!=row.input.expected_policy_hash{return Err(fail("GUARD_TIME_SOURCE_CHANGED"))}row
 }else{
 if source.replay().policy_hash()!=options.expected_policy_hash{return Err(fail("GUARD_TIME_POLICY_CHANGED"))}
 let signed=source.signed_policy_by_hash(source.replay().policy_hash()).ok_or(fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;let signed_value=read_view::parse(signed,2*1024*1024).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;let q=payload(&signed_value).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;
 if let Some(existing)=q.get("guard_time") {let requested=read_view::parse(policy(&options).to_string().as_bytes(),8192).map_err(|_|fail("INPUT_INVALID"))?;if read_view::wire(existing).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?!=read_view::wire(&requested).map_err(|_|fail("INPUT_INVALID"))?{return Err(fail("GUARD_TIME_IMMUTABLE"))}return Ok(json!({"operation_id":id,"command_id":id,"workspace_id":workspace,"status":"ALREADY_ENABLED","sequence":source.replay().sequence(),"head":source.replay().head(),"policy_hash":source.replay().policy_hash()}))}
 if doc.rows.len()>=128||doc.rows.values().any(|r|!r.accepted){return Err(fail("GUARD_TIME_PENDING_OPERATION"))}
 let epoch=n(q,"epoch").map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?;let key=ring.key_at(epoch).ok_or(fail("GUARD_TIME_ACTIVE_KEY_REQUIRED"))?;let issued=now()?;
 let proof=prepare_owner_guard_time_enable(policy(&options).to_string().as_bytes(),signed,source.checkpoint_canonical_json().as_bytes(),source.replay().objects(),key,identity.signing_key(),&id,issued).map_err(|_|fail("GUARD_TIME_PREPARE_FAILED"))?;
 let row=Row{input:options.clone(),issued_at:issued,source:serde_json::from_str(source.checkpoint_canonical_json()).map_err(|_|fail("GUARD_TIME_SOURCE_UNVERIFIED"))?,request:base64url(proof.request_wire()),commit_hash:proof.commit_hash().into(),policy_hash:proof.policy_hash().into(),accepted:false};doc.rows.insert(id.clone(),row.clone());save(&store,&doc)?;row
 };
 active(cancel)?;send(&config,&identity,&id,&row,cancel)?;row.accepted=false;Ok(result(&id,&config,&row))
 })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_guard_time_public_input_requires_explicit_disclosure_and_no_raw_key() {
        let config =
            json!({"origin":"https://example.test/","state_dir":"/missing-profile"}).to_string();
        let input = json!({"workspace_id":"a".repeat(43),"expected_policy_hash":"b".repeat(64),"audience":"test","service_key":"c".repeat(43),"disclosure":"NONE"});
        assert!(owner_guard_time_json(
            &config,
            "enable",
            &input.to_string(),
            &CancellationToken::new()
        )
        .contains("INPUT_INVALID"));
        let mut raw = input.clone();
        raw["disclosure"] = "GUARD_WINDOW".into();
        raw["keyring"] = json!({});
        assert!(owner_guard_time_json(
            &config,
            "enable",
            &raw.to_string(),
            &CancellationToken::new()
        )
        .contains("INPUT_INVALID"));
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            owner_guard_time_json(&config, "enable", &input.to_string(), &cancel)
                .contains("CANCELLED")
        );
    }
}
