//! Native historical key worker. Local stages select original exact packets;
//! backend job cursors select old key epochs. Neither scans retained history.
use super::*;
use super::structure_access_client::data;
use crate::kernel_intents::{StructureContentKeys,ContentKeyError};
use peerwork_core::{crypto::sha256_hex,prepared_command::verify_structure_author_intent,structure_retained_keys::{RetainedKeyAuthority,RetainedKeyEntry,verify_retained_authority,verify_retained_epoch}};
use serde::Serialize;
use serde_json::{json,Value};
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct StructureKeyHistoryReadiness{pub job_id:String,pub through_epoch:u64,pub state:&'static str,pub code:Option<&'static str>}
fn waiting(job:&str,ceiling:u64,code:&'static str)->StructureKeyHistoryReadiness{StructureKeyHistoryReadiness{job_id:job.into(),through_epoch:ceiling,state:"PENDING",code:Some(code)}}
impl KernelClient{
 pub(super) fn require_retained_key_delivery(&self)->Result<(),KernelClientError>{
  if !self.discovery.protocol_features().contains(&"owner-retained-key-delivery-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}Ok(())
 }
 async fn drive_retained_job(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,job:&str,cancel:&CancellationToken)->Result<StructureKeyHistoryReadiness,KernelClientError>{
  self.require_retained_key_delivery()?;let namespace=self.journal.delivery_namespace();
  for _ in 0..128{
   if cancel.is_cancelled(){return Err(TransportError::Cancelled.into());}
   let keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
   if let Some(stage)=keys.history_stage(identity.key_id(),workspace,&namespace,job)?{
    drop(keys);
    let signed=self.journal.verified_pending(&stage.command_id,identity.key_id(),self.discovery.audience_utf16())?.is_some();
    let plan=self.journal.parent_selection(&stage.command_id,identity,self.origin(),self.discovery.audience_utf16(),authority,Some(workspace))?.is_some();
    if signed||plan{
     let outcome=Box::pin(self.resume_structure_intent_scoped(identity,authority,&stage.command_id,Some(workspace),cancel)).await?;
     let StructureIntentOutcome::Accepted(mut result)=outcome else{return Ok(waiting(job,0,"HISTORY_OUTCOME_UNKNOWN"));};
     if result.outcome_state()=="COMMITTED"{result=match Box::pin(self.read_saved_structure_result(identity,authority,&stage.command_id,cancel)).await{Ok(r)=>r,Err(_)=>return Ok(waiting(job,0,"HISTORY_RESULT_UNAVAILABLE"))};}
     if result.outcome_state()=="REJECTED"{
      let refusal=crate::kernel_client::OperationRefusal::from_verified(&result)?;
      if !matches!(refusal.server_code.as_str(),"STALE_REVISION"|"CONTENT_KEY_PAGE_EXPIRED"|"CONTENT_KEY_RECIPIENT_CHANGED"){
       return Err(KernelClientError::OperationRefused(Box::new(refusal)));
      }
     }
    }
    // With neither saved parent nor signed packet, this synchronous stage
    // never reached a business POST. Otherwise the original receipt above
    // establishes acceptance or a definite no-effect refusal before retirement.
    let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
    keys.clear_history_stage(identity.key_id(),workspace,&namespace,&stage.command_id)?;continue;
   }
   drop(keys);
   let query=json!({"action":"structure.content-key.history.get","workspace_id":workspace,"body":{"job_id":job}});
   let outcome=Box::pin(self.execute_structure_intent(identity,authority,query.to_string().as_bytes(),cancel)).await?;
   let StructureIntentOutcome::Accepted(observation)=outcome else{return Ok(waiting(job,0,"HISTORY_OBSERVATION_UNAVAILABLE"));};let page=data(&observation)?;
   let selected=&page["history_job"];let ceiling=selected["through_epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?;
   if selected["id"]!=job||selected["workspace_id"]!=workspace||selected["owner_id"]!=identity.actor_id(){return Err(KernelClientError::InvalidResult);}
   match selected["state"].as_str(){Some("COMPLETE")=>return Ok(StructureKeyHistoryReadiness{job_id:job.into(),through_epoch:ceiling,state:"READY",code:None}),Some("UNAVAILABLE")=>return Ok(StructureKeyHistoryReadiness{job_id:job.into(),through_epoch:ceiling,state:"UNAVAILABLE",code:Some("MEMBERSHIP_OR_CERTIFICATE_ENDED")}),Some("PENDING")=>(),_=>return Err(KernelClientError::InvalidResult)}
   let rows=page["keys"].as_array().filter(|a|a.len()<=32).ok_or(KernelClientError::InvalidResult)?;
   let token=page["page_token"].as_str().filter(|s|s.len()<=12000).ok_or(KernelClientError::InvalidResult)?;
   let revision=selected["revision"].as_u64().ok_or(KernelClientError::InvalidResult)?;
   let envelope=if page["page_state"]=="UNAVAILABLE"||rows.is_empty(){
    if !rows.is_empty(){return Err(KernelClientError::InvalidResult);}Value::Null
   }else{
    if page["page_state"]!="READY"{return Err(KernelClientError::InvalidResult);}
    let sources=page["sources"].as_object().filter(|s|s.len()<=33).ok_or(KernelClientError::InvalidResult)?;
    let auth=sources.get("authorization").ok_or(KernelClientError::InvalidResult)?;
    let auth_jws=auth["author_intent"].as_str().ok_or(KernelClientError::InvalidResult)?;
    let author=verify_structure_author_intent(auth_jws,self.discovery.audience_utf16()).map_err(|_|JournalError::InvalidReceipt)?;
    if auth["intent_digest"]!=author.intent_digest()||auth["command_id"]!=author.command_id()||auth["actor_id"]!=author.actor_id(){return Err(JournalError::InvalidReceipt.into());}
    let r:RetainedKeyAuthority=serde_json::from_value(page["authority"].clone()).map_err(|_|KernelClientError::InvalidResult)?;
    if r.through_epoch!=ceiling||r.actor_id!=selected["actor_id"]||r.membership_id!=selected["membership_id"]||r.recipient_key_id!=selected["recipient_key_id"]||r.authorization_digest!=selected["authorization_digest"]||r.expires_at!=selected["expires_at"]{return Err(KernelClientError::InvalidResult);}
    let (_,_,time)=self.access_context(cancel).await?;let audience=String::from_utf16(self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidResult)?;
    let verified=verify_retained_authority(&author,identity.actor_id(),workspace,r,&audience,self.discovery.receipt_public_key(),time.server_time_ms())?;
    let mut epochs=Vec::new();let mut used=std::collections::BTreeSet::new();
    for row in rows{
     let source_key=row["source_key"].as_str().ok_or(KernelClientError::InvalidResult)?;
     let source=sources.get(source_key).ok_or(KernelClientError::InvalidResult)?;let jws=source["author_intent"].as_str().ok_or(KernelClientError::InvalidResult)?;
     let original=verify_structure_author_intent(jws,self.discovery.audience_utf16()).map_err(|_|JournalError::InvalidReceipt)?;
     if source_key!=format!("{}:{}",original.actor_id(),original.command_id())||source["intent_digest"]!=sha256_hex(jws.as_bytes())||!used.insert(source_key){return Err(JournalError::InvalidReceipt.into());}
     let entry=RetainedKeyEntry{epoch:row["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?,key_id:row["key_id"].as_str().ok_or(KernelClientError::InvalidResult)?.into()};
     epochs.push(verify_retained_epoch(&original,identity.actor_id(),workspace,&verified,entry)?);
    }
    if sources.len()!=used.len()+1{return Err(KernelClientError::InvalidResult);}
    let keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
    serde_json::to_value(keys.seal_history_delivery(identity.key_id(),workspace,&verified,&epochs,&audience,identity.actor_id(),job)?).map_err(|_|KernelClientError::InvalidResult)?
   };
   let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;let stage=keys.prepare_history_stage(identity.key_id(),workspace,&namespace,job,revision)?;drop(keys);
   if stage.revision!=revision{continue;}
   let intent=json!({"action":"structure.content-key.history.deliver","command_id":stage.command_id,"workspace_id":workspace,"body":{"job_id":job,"page_token":token,"envelope":envelope}});
   match Box::pin(self.execute_structure_intent(identity,authority,intent.to_string().as_bytes(),cancel)).await{
    Err(KernelClientError::Store(JournalError::IntentConflict))=>(),
    Err(error)=>return Err(error),
    _=>(),
   }
   // Reconcile/retire this exact selected stage before using the next cursor.
  }
  Ok(waiting(job,0,"HISTORY_DELIVERY_IN_PROGRESS"))
 }
 pub(crate) async fn complete_structure_history_outcome(&mut self,identity:&KernelIdentity,authority:&str,outcome:&mut StructureIntentOutcome,cancel:&CancellationToken){
  let StructureIntentOutcome::Accepted(result)=outcome else{return;};if result.outcome_state()!="ACCEPTED"{return;}
  let Ok(value)=data(result)else{return;};let Some(job)=value["retained_key_job"]["id"].as_str()else{return;};let job=job.to_owned();
  let Some(workspace)=result.workspace_id.clone()else{return;};let ceiling=value["retained_key_job"]["through_epoch"].as_u64().unwrap_or(0);
  // Initialize before awaiting; the outer shared deadline preserves both the
  // original verified approval and this honest separate readiness state.
  result.key_history=Some(waiting(&job,ceiling,"HISTORY_DELIVERY_IN_PROGRESS"));
  match Box::pin(self.drive_retained_job(identity,authority,&workspace,&job,cancel)).await{
   Ok(mut ready)=>{if ready.through_epoch==0{ready.through_epoch=ceiling;}result.key_history=Some(ready);},
   Err(error)=>{let code=match error{KernelClientError::ContentKey(ContentKeyError::Missing)=>"OWNER_HISTORY_KEY_MISSING",KernelClientError::Access(_)|KernelClientError::Store(JournalError::InvalidReceipt)=>"HISTORY_AUTHORITY_INVALID",_=>"HISTORY_DELIVERY_UNAVAILABLE"};result.key_history=Some(waiting(&job,ceiling,code));},
  }
 }
 pub(super) async fn coordinate_retained_keys(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,cancel:&CancellationToken)->Result<bool,KernelClientError>{
  self.require_retained_key_delivery()?;let namespace=self.journal.delivery_namespace();let keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
  let staged=keys.history_stages(identity.key_id(),workspace,&namespace)?;let after=keys.history_after(identity.key_id(),workspace,&namespace)?;drop(keys);
  let mut failed:Option<KernelClientError>=None;let mut complete=true;
  // Saved stages are selected even when a committed final batch has already
  // removed its job from the backend pending queue.
  for stage in staged{match Box::pin(self.drive_retained_job(identity,authority,workspace,&stage.job_id,cancel)).await{
   Ok(outcome)=>{if outcome.state=="PENDING"{complete=false;}},
   Err(error)=>{failed=Some(KernelClientError::HistoryDeliveryBlocked{job_id:stage.job_id,workspace_id:workspace.into(),code:if matches!(error,KernelClientError::ContentKey(ContentKeyError::Missing)){"OWNER_HISTORY_KEY_MISSING"}else{"HISTORY_JOB_RECONCILIATION_REQUIRED"},retryable:matches!(error,KernelClientError::Transport(_))});complete=false;},
  }}
  let mut query=json!({"action":"structure.content-key.history.jobs.read","workspace_id":workspace,"body":{"limit":32}});if !after.is_empty(){query["body"]["after"]=json!(after);}
  let observed=Box::pin(self.execute_structure_intent(identity,authority,query.to_string().as_bytes(),cancel)).await?;let StructureIntentOutcome::Accepted(result)=observed else{return Ok(false);};let page=data(&result)?;
  let jobs=page["jobs"].as_array().filter(|j|j.len()<=32).ok_or(KernelClientError::InvalidResult)?;
  for job in jobs{
   let id=job["id"].as_str().ok_or(KernelClientError::InvalidResult)?;
   match Box::pin(self.drive_retained_job(identity,authority,workspace,id,cancel)).await{
    Ok(outcome)=>{if outcome.state=="PENDING"{complete=false;}},
    Err(error)=>{failed=Some(KernelClientError::HistoryDeliveryBlocked{job_id:id.into(),workspace_id:workspace.into(),code:if matches!(error,KernelClientError::ContentKey(ContentKeyError::Missing)){"OWNER_HISTORY_KEY_MISSING"}else{"HISTORY_JOB_RECONCILIATION_REQUIRED"},retryable:matches!(error,KernelClientError::Transport(_))});complete=false;},
   }
   let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;keys.set_history_after(identity.key_id(),workspace,&namespace,id)?;
  }
  let next=page["next_after"].as_str();let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;keys.set_history_after(identity.key_id(),workspace,&namespace,next.unwrap_or(""))?;
  if let Some(error)=failed{return Err(error);}
  Ok(complete&&next.is_none()&&after.is_empty()&&!keys.has_history_stage(identity.key_id(),workspace,&namespace)?)
 }
}
