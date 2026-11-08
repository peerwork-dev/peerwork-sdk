//! One durable logical operation over the existing invitation producer journal.
//! Lock order: operation index (released), management store, read profile,
//! lifecycle and admission journal. No submitted packet is rewritten.
use crate::{kernel_identity::KernelIdentity, secure_intents::SecureIntentJournal,
    secure_public_admission::{PublicAdmissionRuntimeError, SecurePublicAdmission},
    secure_read_profile::SecureReadProfileConfig, secure_state::SecureStateStore};
use peerwork_core::crypto::{base64url, sha256, sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdmissionOperationError {
    #[error("invalid invitation operation or recovery budget")] Input,
    #[error("invitation operation binds a different intent or context")] Conflict,
    #[error("invitation operation is not saved")] NotFound,
    #[error("protected invitation operation state is unavailable")] State,
    #[error(transparent)] Admission(#[from] PublicAdmissionRuntimeError),
}
impl AdmissionOperationError {
    pub fn code(&self)->&'static str {match self {
        Self::Input=>"ADMISSION_OPERATION_INVALID",Self::Conflict=>"INTENT_CONFLICT",
        Self::NotFound=>"OPERATION_NOT_FOUND",Self::State=>"OPERATION_STATE",
        Self::Admission(e)=>e.code()}}
    pub fn detail(&self)->Value {match self {
        Self::Admission(PublicAdmissionRuntimeError::Rejected(e))=>e.envelope(),
        _=>json!({"code":self.code(),"stage":"reconcile","effect_certainty":"unknown",
            "retryability":"reconcile_only","recovery_hints":[{"action":"recover"}]})}}
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizeIntent {
    pub kind:String, pub invite_id:String,
    #[serde(default)] pub saved_grant_id:Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    invite_id:String, intent:Value, intent_digest:String, attempt:u32, grant_id:Option<String>,
    closures:Vec<Value>, result:Option<Value>,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {version:u8,binding:String,rows:BTreeMap<String,Row>}
fn child(id:&str,n:u32)->String {base64url(&sha256(format!("peerwork.invitation.operation.v1\0{id}\0{n}").as_bytes()))}
fn valid(id:&str)->bool {!id.is_empty()&&id.len()<=128&&id.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'.'|b'_'|b'-'))}
fn open(config:&SecureReadProfileConfig,fp:&str)->Result<(SecureStateStore,Document),AdmissionOperationError>{
    let actor=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|AdmissionOperationError::State)?;
    let origin=reqwest::Url::parse(&config.origin).map_err(|_|AdmissionOperationError::Input)?;
    let binding=sha256_hex(json!({"fp":fp,"origin":origin.as_str(),"actor":actor.actor_id(),
        "key":actor.key_id(),"workspace":config.workspace_id,"owner":config.owner_actor_id,
        "owner_key":config.owner_key_id,"authority":config.authority}).to_string().as_bytes());
    let store=SecureStateStore::open(&config.state_dir.join("invitation-operations.state")).map_err(|_|AdmissionOperationError::State)?;
    let doc=match store.read_exact_secret().map_err(|_|AdmissionOperationError::State)? {
        None=>Document{version:1,binding:binding.clone(),rows:BTreeMap::new()},
        Some(wire) if wire.len()<=4*1024*1024=>serde_json::from_slice::<Document>(&wire).map_err(|_|AdmissionOperationError::State)?,
        _=>return Err(AdmissionOperationError::State),
    };
    if doc.version!=1||doc.binding!=binding||doc.rows.len()>4096 {return Err(AdmissionOperationError::Conflict)}
    for (id,row) in &doc.rows {
        let selected:FinalizeIntent=serde_json::from_value(row.intent.clone()).map_err(|_|AdmissionOperationError::State)?;
        let expected=sha256_hex(json!({"workspace":config.workspace_id,"intent":row.intent}).to_string().as_bytes());
        if !valid(id)||row.intent_digest!=expected||row.invite_id!=selected.invite_id
            ||selected.kind!="workspace.invitation.finalize"||row.attempt>4||row.closures.len()!=row.attempt as usize {
            return Err(AdmissionOperationError::State)
        }
    }
    Ok((store,doc))
}
fn persist(store:&SecureStateStore,doc:&Document)->Result<(),AdmissionOperationError>{
    let wire=Zeroizing::new(serde_json::to_vec(doc).map_err(|_|AdmissionOperationError::State)?);
    if wire.len()>4*1024*1024{return Err(AdmissionOperationError::State)}
    store.write_exact(&wire).map_err(|_|AdmissionOperationError::State)
}
fn normalize(config:&SecureReadProfileConfig,id:&str,row:&Row,mut result:Value)->Value{
    result["kind"]=json!("workspace.invitation.finalize");result["workspace_id"]=json!(config.workspace_id);
    result["operation_id"]=json!(id);result["attempt"]=json!(row.attempt);
    result["attempt_operation_id"]=json!(child(id,row.attempt));
    result["closed_attempts"]=json!(row.closures);
    result
}
fn saved_grant(config:&SecureReadProfileConfig,id:&str,row:&Row)->Result<Option<String>,AdmissionOperationError>{
    let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|AdmissionOperationError::State)?;
    let journal=SecureIntentJournal::open(&config.state_dir.join("admission-intents.state"),&config.origin,identity.actor_id())
        .map_err(|_|AdmissionOperationError::State)?;
    let found=journal.action_operation(&child(id,row.attempt)).map_err(|_|AdmissionOperationError::State)?;
    let selected=row.grant_id.clone().or_else(||found.as_ref().map(|(grant,_)|grant.clone()));
    if let Some(grant)=&selected {check_attempt_binding(row,row.attempt,grant,found.as_ref())?;}
    Ok(selected)
}
/// `safe` authorizes at most one saved retransmission OR proven-safe successor.
/// Reconcile-only remains the default. The protected operation lock spans it.
pub(crate) fn run(config:SecureReadProfileConfig,fp:&str,id:&str,intent:Option<Value>,safe:bool,
    cancel:&CancellationToken)->Result<Value,AdmissionOperationError>{
    if !valid(id){return Err(AdmissionOperationError::Input)}
    let (store,mut doc)=open(&config,fp)?;
    let is_new=intent.is_some();
    if let Some(value)=intent {
        let selected:FinalizeIntent=serde_json::from_value(value.clone()).map_err(|_|AdmissionOperationError::Input)?;
        if selected.kind!="workspace.invitation.finalize"||selected.invite_id.len()!=43
            ||!selected.invite_id.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'_'|b'-'))
            ||selected.saved_grant_id.as_ref().is_some_and(|s|s.len()!=43||!s.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'_'|b'-'))){return Err(AdmissionOperationError::Input)}
        let digest=sha256_hex(json!({"workspace":config.workspace_id,"intent":value}).to_string().as_bytes());
        match doc.rows.get(id){Some(row) if row.intent_digest!=digest=>return Err(AdmissionOperationError::Conflict),Some(_)=>{},
            None=>{if doc.rows.len()>=4096{return Err(AdmissionOperationError::State)}
                doc.rows.insert(id.into(),Row{invite_id:selected.invite_id,intent:value,intent_digest:digest,
                    attempt:0,grant_id:selected.saved_grant_id,closures:vec![],result:None});persist(&store,&doc)?;}}
    }
    let mut row=doc.rows.get(id).cloned().ok_or(AdmissionOperationError::NotFound)?;
    validate_closures(&config,id,&row,cancel)?;
    row.grant_id=saved_grant(&config,id,&row)?;
    if let Some(cached)=&row.result {
        verify_cached_result(&config,&row,cached,cancel)?;
        let mut result=cached.clone();result["freshness"]=json!("HISTORICAL_CHECKPOINT");
        return Ok(normalize(&config,id,&row,result));
    }
    let admission=SecurePublicAdmission::new_private(config.clone());
    let decode=|wire:String|serde_json::from_str::<Value>(&wire).map_err(|_|AdmissionOperationError::State);
    let mut submitted=false;
    if row.grant_id.is_none() {
        if !is_new&&!safe{return Ok(normalize(&config,id,&row,json!({"status":"NOT_PREPARED","effect_certainty":"not_sent"})))}
        let result=decode(admission.deliver_operation_json_with_cancel(&row.invite_id,
            Some((&child(id,row.attempt),&row.intent_digest)),cancel)?)?;
        row.grant_id=result["grant_id"].as_str().map(str::to_owned);submitted=true;
        doc.rows.insert(id.into(),row.clone());persist(&store,&doc)?;
    }
    let grant=row.grant_id.clone().ok_or(AdmissionOperationError::State)?;
    let mut result=decode(admission.reconcile_delivery_json_with_cancel(&grant,cancel)?)?;
    if result["invite_id"].as_str()!=Some(row.invite_id.as_str()){return Err(AdmissionOperationError::Conflict)}
    if result["status"]=="REPLACEMENT_SAFE" && safe && !submitted {
        if row.attempt>=4{return Err(AdmissionOperationError::Input)}
        let proof=result["proof"].clone();
        if proof["kind"]!="immutable_policy_packet_inadmissible"||proof["constraint"]!="guard_time.required"{
            return Err(AdmissionOperationError::State)}
        row.closures.push(json!({"attempt":row.attempt,"grant_id":grant,"proof":proof}));
        row.attempt+=1;row.grant_id=None;doc.rows.insert(id.into(),row.clone());persist(&store,&doc)?;
        let prepared=decode(admission.deliver_operation_json_with_cancel(&row.invite_id,
            Some((&child(id,row.attempt),&row.intent_digest)),cancel)?)?;
        row.grant_id=prepared["grant_id"].as_str().map(str::to_owned);
        doc.rows.insert(id.into(),row.clone());persist(&store,&doc)?;
        result=decode(admission.reconcile_delivery_json_with_cancel(row.grant_id.as_deref().ok_or(AdmissionOperationError::State)?,cancel)?)?;
    }else if result["status"]=="PENDING" && safe && !submitted {
        result=decode(admission.retry_delivery_json_with_cancel(&grant,cancel)?)?;
        if result["status"]=="PENDING" {result=decode(admission.reconcile_delivery_json_with_cancel(&grant,cancel)?)?;}
    }
    if result["status"]=="AUTHORIZED" {row.result=Some(result.clone());}
    doc.rows.insert(id.into(),row.clone());persist(&store,&doc)?;
    Ok(normalize(&config,id,&row,result))
}
pub(crate) fn operations(config:&SecureReadProfileConfig,fp:&str)->Result<Value,AdmissionOperationError>{
    let path=config.state_dir.join("invitation-operations.state");
    if crate::secure_state::missing_in_private_parent(&path){return Ok(json!([]))}
    let (_,doc)=open(config,fp)?;
    Ok(Value::Array(doc.rows.iter().filter(|(_,r)|r.result.is_none()).map(|(id,r)|
        json!({"kind":"workspace.invitation.finalize","operation_id":id,"workspace_id":config.workspace_id,
            "grant_id":r.grant_id,"attempt":r.attempt,"closed_attempts":r.closures.len(),
            "continuation":{"operation":"recover","workspace_id":config.workspace_id,"operation_id":id}})).collect()))
}

fn validate_closures(config:&SecureReadProfileConfig,id:&str,row:&Row,cancel:&CancellationToken)->Result<(),AdmissionOperationError>{
    if row.closures.is_empty(){return Ok(())}
    crate::secure_read_profile::SecureReadProfile::new(config.clone()).with_pinned_replay(cancel,|source| {
        let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|AdmissionOperationError::State)?;
        let journal=SecureIntentJournal::open(&config.state_dir.join("admission-intents.state"),&config.origin,identity.actor_id())
            .map_err(|_|AdmissionOperationError::State)?;
        for (index,closure) in row.closures.iter().enumerate(){
            let proof=&closure["proof"];
            if closure["attempt"].as_u64()!=Some(index as u64)||proof["kind"]!="immutable_policy_packet_inadmissible"
                ||proof["constraint"]!="guard_time.required"||proof["verifier"]!="peerwork.v3.guard-time-required.v1" {return Err(AdmissionOperationError::State)}
            let grant=closure["grant_id"].as_str().ok_or(AdmissionOperationError::State)?;
            let binding=journal.action_operation(&child(id,index as u32)).map_err(|_|AdmissionOperationError::State)?;
            check_attempt_binding(row,index as u32,grant,binding.as_ref())?;
            let packet=journal.exact_request(grant).map_err(|_|AdmissionOperationError::State)?;
            let request=peerwork_core::wire_json::parse_wire_json_bounded(&packet,80,220000).map_err(|_|AdmissionOperationError::State)?;
            check_packet_binding(&request,&row.invite_id,grant,&config.workspace_id,identity.actor_id(),identity.key_id())?;
            let predecessor=source.signed_policy_by_hash(proof["predecessor_policy_hash"].as_str().ok_or(AdmissionOperationError::State)?)
                .ok_or(AdmissionOperationError::State)?;
            let checked=peerwork_core::prepared_public_admission::verify_inadmissible_guarded_delivery(
                &packet,predecessor,identity.actor_id(),identity.key_id(),&config.workspace_id).map_err(|_|AdmissionOperationError::State)?;
            if proof["request_digest"].as_str()!=Some(checked.request_digest.as_str())||proof["policy_hash"].as_str()!=Some(checked.policy_hash.as_str())
                ||proof["command_id"].as_str()!=Some(checked.command_id.as_str()){return Err(AdmissionOperationError::State)}
        }
        Ok(())
    })
}
impl From<crate::secure_read_access::SecureReadAccessError> for AdmissionOperationError {
    fn from(error:crate::secure_read_access::SecureReadAccessError)->Self{Self::Admission(PublicAdmissionRuntimeError::Read(error))}
}
fn verify_cached_result(config:&SecureReadProfileConfig,row:&Row,result:&Value,cancel:&CancellationToken)->Result<(),AdmissionOperationError>{
    use peerwork_core::{canonical::Path,crypto::{sha256_hex,verify_secure_signed_wire},wire_json::{canonical_wire_value,parse_wire_json_bounded,WireValue}};
    crate::secure_read_profile::SecureReadProfile::new(config.clone()).with_pinned_replay(cancel,|source| {
        let identity=KernelIdentity::inspect_existing(&config.identity_path).map_err(|_|AdmissionOperationError::State)?;
        let grant_id=row.grant_id.as_deref().ok_or(AdmissionOperationError::State)?;
        let journal=SecureIntentJournal::open(&config.state_dir.join("admission-intents.state"),&config.origin,identity.actor_id()).map_err(|_|AdmissionOperationError::State)?;
        let request=journal.exact_request(grant_id).map_err(|_|AdmissionOperationError::State)?;
        let request=parse_wire_json_bounded(&request,80,220000).map_err(|_|AdmissionOperationError::State)?;
        check_packet_binding(&request,&row.invite_id,grant_id,&config.workspace_id,identity.actor_id(),identity.key_id())?;
        let field=|name:&str|request.get(name).ok_or(AdmissionOperationError::State);
        for (name,domain) in [("policy","peerwork.secure.policy.v3"),("commit","peerwork.secure.commit.v3"),("grant","peerwork.secure.key-grant.v1")] {
            let wire=canonical_wire_value(field(name)?,Path::SecureArtifact).map_err(|_|AdmissionOperationError::State)?;
            if !verify_secure_signed_wire(wire.as_bytes(),domain,identity.key_id()).map_err(|_|AdmissionOperationError::State)?{return Err(AdmissionOperationError::State)}
        }
        let hash=|name:&str|->Result<String,AdmissionOperationError>{Ok(sha256_hex(canonical_wire_value(field(name)?,Path::SecureArtifact).map_err(|_|AdmissionOperationError::State)?.as_bytes()))};
        let policy_hash=hash("policy")?;let commit_hash=hash("commit")?;let grant_hash=hash("grant")?;
        let cp=field("commit")?.get("payload").ok_or(AdmissionOperationError::State)?;
        let seq=cp.get("sequence").and_then(WireValue::as_number).ok_or(AdmissionOperationError::State)? as u64;
        if !source.replay().contains_checkpoint(seq,Some(&commit_hash),&policy_hash)
            ||result["status"]!="AUTHORIZED"||result["verification"]!="verified"||result["workspace_id"].as_str()!=Some(config.workspace_id.as_str())
            ||result["invite_id"].as_str()!=Some(row.invite_id.as_str())||result["grant_id"].as_str()!=Some(grant_id)
            ||result["grant_hash"].as_str()!=Some(grant_hash.as_str())||result["commit_hash"].as_str()!=Some(commit_hash.as_str())
            ||result["sequence"].as_u64()!=Some(seq)
            ||result["command_id"].as_str()!=cp.get("command_id").and_then(WireValue::as_string).as_deref(){return Err(AdmissionOperationError::State)}
        Ok(())
    })
}

// Local cursor metadata may select a packet; it cannot relabel another attempt.
fn check_attempt_binding(row:&Row,attempt:u32,grant:&str,mapped:Option<&(String,String)>)->Result<(),AdmissionOperationError>{
    let selected:FinalizeIntent=serde_json::from_value(row.intent.clone()).map_err(|_|AdmissionOperationError::State)?;
    if attempt==0 {
        if let Some(saved)=selected.saved_grant_id {
            if saved!=grant{return Err(AdmissionOperationError::State)}
            // An imported legacy packet need not have an operation index.
            if mapped.is_none(){return Ok(())}
        }
    }
    if !mapped.is_some_and(|(id,digest)|id==grant&&digest==&row.intent_digest){return Err(AdmissionOperationError::State)}
    Ok(())
}
// Signatures and checkpoint membership are checked separately by each caller.
// These checks bind the signed statements to the requested logical invitation.
fn check_packet_binding(request:&peerwork_core::wire_json::WireValue,invite:&str,grant:&str,workspace:&str,actor:&str,key:&str)->Result<(),AdmissionOperationError>{
    use peerwork_core::{canonical::Path,crypto::sha256_hex,wire_json::{canonical_wire_value,WireValue}};
    let bad=||AdmissionOperationError::State;
    if request.object_len()!=Some(3){return Err(bad())}
    let policy=request.get("policy").ok_or_else(bad)?;
    let pp=policy.get("payload").ok_or_else(bad)?;
    let gp=request.get("grant").and_then(|v|v.get("payload")).ok_or_else(bad)?;
    let cp=request.get("commit").and_then(|v|v.get("payload")).ok_or_else(bad)?;
    let hash=sha256_hex(canonical_wire_value(policy,Path::SecureArtifact).map_err(|_|bad())?.as_bytes());
    let is=|v:&WireValue,k:&str,want:&str|v.get(k).and_then(WireValue::as_string).as_deref()==Some(want);
    if !is(gp,"invite_id",invite)||!is(gp,"grant_id",grant)||!is(cp,"action_id","secure.invite.finalize")
        ||!is(cp,"mode","PRIVATE")||!is(pp,"owner_id",actor)||!is(pp,"signing_key",key)||!is(pp,"workspace_id",workspace)
        ||[gp,cp].iter().any(|v|!is(v,"workspace_id",workspace)||!is(v,"actor_id",actor)||!is(v,"signing_key",key)||!is(v,"policy_hash",&hash)) {
        return Err(bad())
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prior_attempt_cannot_be_replaced_with_an_unrelated_closed_packet(){
        let mut row=Row{invite_id:"invite".into(),intent:json!({"kind":"workspace.invitation.finalize","invite_id":"invite"}),
            intent_digest:"intent".into(),attempt:1,grant_id:None,closures:vec![],result:None};
        let bound=("grant".into(),"intent".into());
        assert!(check_attempt_binding(&row,0,"grant",Some(&bound)).is_ok());
        assert!(check_attempt_binding(&row,0,"other",Some(&bound)).is_err());
        assert!(check_attempt_binding(&row,1,"grant",None).is_err());
        assert!(check_attempt_binding(&row,1,"grant",Some(&("grant".into(),"other-intent".into()))).is_err());
        row.intent["saved_grant_id"]=json!("legacy");
        assert!(check_attempt_binding(&row,0,"legacy",None).is_ok());
        assert!(check_attempt_binding(&row,0,"other",None).is_err());
        assert!(check_attempt_binding(&row,1,"legacy",None).is_err());
    }
    #[test]
    fn cached_result_cannot_relabel_the_packet_invitation_or_policy(){
        use peerwork_core::{canonical::Path,crypto::sha256_hex,wire_json::{canonical_wire_value,parse_wire_json_bounded}};
        let parse=|v:&Value|parse_wire_json_bounded(v.to_string().as_bytes(),32,220000).unwrap();
        // This unit tests semantic binding only; production callers verify the
        // signatures and authenticated checkpoint in addition to this helper.
        let policy=json!({"payload":{"owner_id":"owner","signing_key":"key","workspace_id":"space"},"signature":"fixture"});
        let hash=sha256_hex(canonical_wire_value(&parse(&policy),Path::SecureArtifact).unwrap().as_bytes());
        let common=json!({"actor_id":"owner","signing_key":"key","workspace_id":"space","policy_hash":hash});
        let mut grant=common.clone();grant["invite_id"]=json!("first");grant["grant_id"]=json!("grant");
        let mut commit=common;commit["action_id"]=json!("secure.invite.finalize");commit["mode"]=json!("PRIVATE");
        let mut packet=json!({"policy":policy,"grant":{"payload":grant},"commit":{"payload":commit}});
        let check=|packet:&Value,invite|check_packet_binding(&parse(packet),invite,"grant","space","owner","key");
        assert!(check(&packet,"first").is_ok());assert!(check(&packet,"second").is_err());
        packet["grant"]["payload"]["policy_hash"]=json!("other");assert!(check(&packet,"first").is_err());
        packet["grant"]["payload"]["policy_hash"]=json!(hash);
        packet["commit"]["payload"]["action_id"]=json!("other");assert!(check(&packet,"first").is_err());
    }
}
