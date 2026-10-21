//! Explicit durable Owner member scope replacement. Full replay, exact source CAS,
//! protected service pins and exact saved encrypted packets precede submission.
use crate::{
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
    prepared_owner_guard_time::{prepare_owner_member_scopes, verify_saved_owner_member_scopes},
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
struct Error(&'static str, Option<Value>);
impl From<SecureReadAccessError> for Error {
    fn from(e: SecureReadAccessError) -> Self {
        if matches!(e, SecureReadAccessError::Cancelled) {
            Self("CANCELLED", None)
        } else {
            Self("MEMBER_SCOPE_SOURCE_UNVERIFIED", None)
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnableInput {
    workspace_id: String,
    expected_policy_hash: String,
    actor_id: String,
    scopes: Value,
    #[serde(default)]
    operation_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectInput {
    workspace_id: String,
    actor_id: String,
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
    #[serde(default)]
    superseded: bool,
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
        .ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))
}
fn n(v: &WireValue, key: &str) -> R<u64> {
    let n = v
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
    if !n.is_finite() || n < 0.0 || n > 9007199254740991.0 || n.fract() != 0.0 {
        return Err(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"));
    }
    Ok(n as u64)
}
fn fail(code: &'static str) -> Error {
    Error(code, None)
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
fn result(id: &str, config: &SecureReadProfileConfig, row: &Row) -> Value {
    json!({"operation_id":id,"command_id":id,"workspace_id":config.workspace_id,"status":if row.accepted{"ACCEPTED"}else if row.superseded{"SUPERSEDED"}else{"PENDING"},"sequence":if row.accepted{row.source["sequence"].as_u64().map(|n|n+1)}else{None},"head":if row.accepted{Some(&row.commit_hash)}else{None},"policy_hash":if row.accepted{Some(&row.policy_hash)}else{None}})
}
fn open_history(
    config: &SecureReadProfileConfig,
    identity: &KernelIdentity,
) -> R<(SecureStateStore, History)> {
    let store = SecureStateStore::open(&config.state_dir.join("owner-member-scopes.state"))
        .map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?;
    let doc = match store
        .read_exact()
        .map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?
    {
        Some(bytes) => {
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(fail("MEMBER_SCOPE_RESOURCE_LIMIT"));
            }
            serde_json::from_slice(&bytes).map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?
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
        return Err(fail("MEMBER_SCOPE_PIN_CHANGED"));
    }
    Ok((store, doc))
}
fn save(store: &SecureStateStore, doc: &History) -> R<()> {
    let bytes = serde_json::to_vec(doc).map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(fail("MEMBER_SCOPE_RESOURCE_LIMIT"));
    }
    store
        .write_exact(&bytes)
        .map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))
}
fn post(
    config: &SecureReadProfileConfig,
    identity: &KernelIdentity,
    id: &str,
    row: &Row,
    cancel: &CancellationToken,
) -> R<()> {
    active(cancel)?;
    let packet = decode_base64url(&row.request).map_err(|_| fail("MEMBER_SCOPE_PACKET_INVALID"))?;
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        config.workspace_id
    );
    let mut journal = SecureIntentJournal::open(
        &config.state_dir.join("member-scopes-intents.sqlite"),
        &config.origin,
        identity.actor_id(),
    )
    .map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?;
    journal
        .prepare(SecurePacketInput {
            intent_id: id,
            path: &path,
            action_id: "secure.member.scopes",
            workspace_id: Some(&config.workspace_id),
            trusted_owner_key: Some(identity.key_id()),
            intent_digest: &row.commit_hash,
            exact_request: &packet,
        })
        .map_err(|_| fail("MEMBER_SCOPE_INTENT_CONFLICT"))?;
    if journal
        .exact_request(id)
        .map_err(|_| fail("MEMBER_SCOPE_PACKET_INVALID"))?
        != packet
    {
        return Err(fail("MEMBER_SCOPE_PACKET_INVALID"));
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
    let packet = decode_base64url(&row.request).map_err(|_| fail("MEMBER_SCOPE_PACKET_INVALID"))?;
    let response = runtime
        .block_on(transport.post_exact(&path, packet, cancel))
        .map_err(|_| {
            if cancel.is_cancelled() {
                fail("CANCELLED")
            } else {
                Error("MEMBER_SCOPE_TRANSPORT_FAILED",Some(json!({"schema":"peerwork.operation-error.v1","stage":"submit","effect_certainty":"unknown","retryability":"reconcile_only","operation_id":id,"recovery_hints":[{"action":"recover","precondition":"same_saved_operation"}]})))
            }
        })?;
    let mut journal = SecureIntentJournal::open(
        &config.state_dir.join("member-scopes-intents.sqlite"),
        &config.origin,
        identity.actor_id(),
    )
    .map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?;
    if !response.wire.is_empty() {
        journal
            .observe_response(id, &response.wire)
            .map_err(|_| fail("MEMBER_SCOPE_LOCAL_STATE"))?;
    }
    if !(200..300).contains(&response.status) {
        let d = crate::operation_diagnostics::ServerRejection::from_response(
            response.status,
            &response.wire,
        );
        return Err(Error(d.code, Some(d.envelope())));
    }
    Ok(())
}
pub fn owner_member_scopes_json(
    config_json: &str,
    operation: &str,
    input_json: &str,
    cancel: &CancellationToken,
) -> String {
    let result = run(config_json, operation, input_json, cancel).and_then(|value| {
        if matches!(operation, "set" | "retry") && value["status"] == "PENDING" {
            run(
                config_json,
                "recover",
                &json!({"workspace_id":value["workspace_id"],"operation_id":value["operation_id"]})
                    .to_string(),
                cancel,
            )
        } else {
            Ok(value)
        }
    });
    match result {
        Ok(value) => json!({"ok":true,"value":value}).to_string(),
        Err(e) => {
            let mut v = json!({"ok":false,"code":e.0,"message":e.0});
            if let Some(d) = e.1 {
                v["diagnostic"] = d;
            }
            v.to_string()
        }
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
        "set" => {
            let i: EnableInput = parse(input_json)?;
            if !digest(&i.expected_policy_hash) || !read_view::token(&i.actor_id) {
                return Err(fail("MEMBER_SCOPE_INPUT_INVALID"));
            }
            let scopes = read_view::parse(i.scopes.to_string().as_bytes(), 65536)
                .map_err(|_| fail("MEMBER_SCOPE_INPUT_INVALID"))?;
            peerwork_core::member_scopes::validate_scopes(&scopes).map_err(|e| fail(e.0))?;
            let id = i.operation_id.clone().map(Ok).unwrap_or_else(random_id)?;
            (i.workspace_id.clone(), Some(id), Some(i))
        }
        "recover" | "retry" => {
            let i: ResumeInput = parse(input_json)?;
            (i.workspace_id, Some(i.operation_id), None)
        }
        "inspect" => {
            let i: InspectInput = parse(input_json)?;
            if !read_view::token(&i.actor_id) {
                return Err(fail("MEMBER_SCOPE_INPUT_INVALID"));
            }
            (i.workspace_id, None, None)
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
        .map_err(|_| fail("MEMBER_SCOPE_OWNER_PROFILE_REQUIRED"))?;
    let identity =
        KernelIdentity::open(&config.identity_path).map_err(|_| fail("IDENTITY_STATE"))?;
    if operation == "inspect" {
        return SecureReadProfile::new(config.clone()).with_latest_replay(cancel,|source|->R<Value>{
            source.verified_read().map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
            if source.replay().owner_actor_id()!=identity.actor_id()||source.replay().owner_signing_key()!=identity.key_id(){return Err(fail("MEMBER_SCOPE_OWNER_REQUIRED"));}
            let wire=source.signed_policy_by_hash(source.replay().policy_hash()).ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
            let policy=read_view::parse(wire,2*1024*1024).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
            let p=payload(&policy)?;
            let target:InspectInput=parse(input_json)?;
            let Some(WireValue::Array(members))=p.get("members") else{return Err(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"));};
            let member=members.iter().find(|m|m.get("actor_id").and_then(WireValue::as_string).as_deref()==Some(&target.actor_id)).ok_or(fail("MEMBER_NOT_FOUND"))?;
            let member:Value=serde_json::from_str(&read_view::wire(member).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
            let instances=peerwork_core::member_scopes::catalog(source.replay().objects()).map_err(|e|fail(e.0))?;
            let instances:Value=serde_json::from_str(&read_view::wire(&instances).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
            Ok(json!({"workspace_id":workspace,"actor_id":target.actor_id,"role":member["role"],"read":true,"scopes":member["scopes"],"policy_hash":source.replay().policy_hash(),"checkpoint":serde_json::from_str::<Value>(source.checkpoint_canonical_json()).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?,"instances":instances}))
        });
    }
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
            return Err(fail("MEMBER_SCOPE_OPERATION_CONFLICT"));
        }
    }
    if matches!(operation, "recover" | "retry") && saved.is_none() {
        return Err(fail("MEMBER_SCOPE_OPERATION_NOT_FOUND"));
    }
    if saved.is_none() && doc.rows.values().any(|r| !r.accepted && !r.superseded) {
        return Err(fail("MEMBER_SCOPE_PENDING_OPERATION"));
    }
    let options = saved
        .as_ref()
        .map(|r| r.input.clone())
        .or(input)
        .ok_or(fail("INPUT_INVALID"))?;
    drop(doc);
    drop(store);

    SecureReadProfile::new(config.clone()).with_latest_replay(cancel,|source|->R<Value>{
 source.verified_read().map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
 if !crate::secure_read_profile::canonical_origin_matches(&config.origin, source.origin())||source.source_actor_id()!=identity.actor_id()||source.source_key_id()!=identity.key_id()||source.replay().owner_actor_id()!=identity.actor_id()||source.replay().owner_signing_key()!=identity.key_id()||source.replay().structure_status()==StructureStatus::Seeding{return Err(fail("MEMBER_SCOPE_OWNER_REQUIRED"))}
 let lifecycle=SecureLifecycle::open_existing(&config.state_dir.join("lifecycle.state"),source.origin(),identity.actor_id(),&workspace,identity.actor_id(),identity.key_id()).map_err(|_|fail("MEMBER_SCOPE_ACTIVE_KEY_REQUIRED"))?;
 let ring=lifecycle.active_keyring_without_pending().ok_or(fail("MEMBER_SCOPE_PENDING_KEY_TRANSITION"))?;
 let (store,mut doc)=open_history(&config,&identity)?;
 let mut row=if let Some(row)=doc.rows.get(&id).cloned(){
 if row.input!=options{return Err(fail("MEMBER_SCOPE_OPERATION_CONFLICT"))}
 let seq=row.source["sequence"].as_u64().ok_or(fail("MEMBER_SCOPE_PACKET_INVALID"))?;let head=row.source["head"].as_str().ok_or(fail("MEMBER_SCOPE_PACKET_INVALID"))?;
 if !source.replay().contains_checkpoint(seq,Some(head),&row.input.expected_policy_hash){return Err(fail("MEMBER_SCOPE_SOURCE_FORK"))}
 let old=source.signed_policy_by_hash(&row.input.expected_policy_hash).ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
 let old_value=read_view::parse(old,2*1024*1024).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;let epoch=n(payload(&old_value).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?,"epoch").map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
 let key=ring.key_at(epoch).ok_or(fail("MEMBER_SCOPE_HISTORICAL_KEY_REQUIRED"))?;
 let checkpoint=peerwork_core::canonical::canonical(&row.source,peerwork_core::canonical::Path::SecureArtifact).map_err(|_|fail("MEMBER_SCOPE_PACKET_INVALID"))?;
 let ring_wire=ring.canonical_wire().map_err(|_|fail("MEMBER_SCOPE_ACTIVE_KEY_REQUIRED"))?;
 let prior=source.authenticated_prefix_replay(checkpoint.as_bytes(),Some(&ring_wire)).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
 let packet=decode_base64url(&row.request).map_err(|_|fail("MEMBER_SCOPE_PACKET_INVALID"))?;
 let proof=verify_saved_owner_member_scopes(&packet,&row.input.actor_id,row.input.scopes.to_string().as_bytes(),old,checkpoint.as_bytes(),prior.objects(),key,identity.signing_key(),&id,row.issued_at).map_err(|_|fail("MEMBER_SCOPE_PACKET_INVALID"))?;
 validate_roles(source,&row.input.expected_policy_hash,&proof,prior.objects())?;
 if proof.commit_hash()!=row.commit_hash||proof.policy_hash()!=row.policy_hash{return Err(fail("MEMBER_SCOPE_PACKET_INVALID"))}
 if source.replay().contains_checkpoint(seq+1,Some(&row.commit_hash),&row.policy_hash){let mut row=row;row.accepted=true;doc.rows.insert(id.clone(),row.clone());save(&store,&doc)?;return Ok(result(&id,&config,&row))}
 if row.accepted{return Err(fail("MEMBER_SCOPE_SOURCE_FORK"))}
 if row.superseded||source.replay().sequence()>seq {
     let mut row=row;row.superseded=true;doc.rows.insert(id.clone(),row.clone());save(&store,&doc)?;return Ok(result(&id,&config,&row));
 }
 if source.replay().sequence()!=seq||source.replay().head()!=Some(head)||source.replay().policy_hash()!=row.input.expected_policy_hash{return Err(fail("MEMBER_SCOPE_SOURCE_CHANGED"))}row
 }else{
 if source.replay().policy_hash()!=options.expected_policy_hash{return Err(fail("MEMBER_SCOPE_POLICY_CHANGED"))}
 let signed=source.signed_policy_by_hash(source.replay().policy_hash()).ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;let signed_value=read_view::parse(signed,2*1024*1024).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;let q=payload(&signed_value).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
 if n(q,"v")?!=3{return Err(fail("MEMBER_SCOPE_WIRE_V3_REQUIRED"))}
 if q.get("owner_id").and_then(WireValue::as_string).as_deref()!=Some(identity.actor_id()) {return Err(fail("MEMBER_SCOPE_OWNER_REQUIRED"))}
 let member=match q.get("members"){Some(WireValue::Array(ms))=>ms.iter().find(|m|m.get("actor_id").and_then(WireValue::as_string).as_deref()==Some(&options.actor_id)),_=>None}.ok_or(fail("MEMBER_NOT_FOUND"))?;
 let scopes=read_view::parse(options.scopes.to_string().as_bytes(),65536).map_err(|_|fail("MEMBER_SCOPE_INPUT_INVALID"))?;
 if read_view::wire(member.get("scopes").ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?==read_view::wire(&scopes).map_err(|_|fail("MEMBER_SCOPE_INPUT_INVALID"))? {return Ok(json!({"operation_id":id,"command_id":id,"workspace_id":workspace,"status":"UNCHANGED","sequence":source.replay().sequence(),"head":source.replay().head(),"policy_hash":source.replay().policy_hash()}))}
 peerwork_core::member_scopes::validate_permissions(&scopes,source.replay().objects()).map_err(|e|fail(e.0))?;

 if doc.rows.len()>=128||doc.rows.values().any(|r|!r.accepted && !r.superseded){return Err(fail("MEMBER_SCOPE_PENDING_OPERATION"))}
 let epoch=n(q,"epoch").map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;let key=ring.key_at(epoch).ok_or(fail("MEMBER_SCOPE_ACTIVE_KEY_REQUIRED"))?;let issued=now()?;
 let proof=prepare_owner_member_scopes(&options.actor_id,options.scopes.to_string().as_bytes(),signed,source.checkpoint_canonical_json().as_bytes(),source.replay().objects(),key,identity.signing_key(),&id,issued).map_err(|_|fail("MEMBER_SCOPE_PREPARE_FAILED"))?;
 validate_roles(source,&options.expected_policy_hash,&proof,source.replay().objects())?;
 let row=Row{input:options.clone(),issued_at:issued,source:serde_json::from_str(source.checkpoint_canonical_json()).map_err(|_|fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?,request:base64url(proof.request_wire()),commit_hash:proof.commit_hash().into(),policy_hash:proof.policy_hash().into(),accepted:false,superseded:false};doc.rows.insert(id.clone(),row.clone());save(&store,&doc)?;row
 };
 if operation!="recover" {active(cancel)?;send(&config,&identity,&id,&row,cancel)?;}
 row.accepted=false;Ok(result(&id,&config,&row))
 })
}

fn validate_roles(
    source: &crate::secure_verified_read::TransportReplayedJournal,
    old_hash: &str,
    proof: &peerwork_core::prepared_owner_guard_time::PreparedOwnerFormatTransition,
    objects: &[WireValue],
) -> R<()> {
    let mut policies = Vec::new();
    let mut hash = old_hash.to_owned();
    loop {
        let wire = source
            .signed_policy_by_hash(&hash)
            .ok_or(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
        let policy = read_view::parse(wire, 2 * 1024 * 1024)
            .map_err(|_| fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"))?;
        let p = payload(&policy)?.clone();
        let previous = p.get("previous_policy").and_then(WireValue::as_string);
        policies.push(p);
        if policies.len() > source.signed_policy_wires().len() {
            return Err(fail("MEMBER_SCOPE_SOURCE_UNVERIFIED"));
        }
        if let Some(previous) = previous {
            hash = previous
        } else {
            break;
        }
    }
    policies.reverse();
    let packet = read_view::parse(proof.request_wire(), 220000)
        .map_err(|_| fail("MEMBER_SCOPE_PACKET_INVALID"))?;
    let candidate = packet
        .get("policy_update")
        .and_then(|p| p.get("payload"))
        .ok_or(fail("MEMBER_SCOPE_PACKET_INVALID"))?;
    peerwork_core::member_scopes::validate_candidate_roles(&policies, candidate, objects)
        .map_err(|e| fail(e.0))
}
