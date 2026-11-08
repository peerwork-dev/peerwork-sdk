//! SDK-owned, bounded key delivery with one selected durable local stage and
//! a backend-owned cursor. Recovery never enumerates old business history.
use super::*;
use super::structure_access_client::data;
use crate::kernel_intents::StructureContentKeys;
use peerwork_core::{structure_key_delivery::{CurrentKeyRecipient,verify_follow_recipient},prepared_command::verify_structure_author_intent};
use serde_json::{json,Value};
use std::time::Duration;

fn waiting(parent:&str,code:&'static str,retryable:bool)->StructureIntentOutcome{StructureIntentOutcome::Pending{command_id:parent.into(),code,phase:"KEY_DELIVERY",retryable,recovery:"CONTINUE_KEY_ROTATION"}}
impl KernelClient {
 pub(crate) fn require_current_key_delivery(&self)->Result<(),KernelClientError>{
  self.require_content_key_epochs()?;
  if !self.discovery.protocol_features().contains(&"owner-current-key-delivery-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}Ok(())
 }

 pub(crate) async fn coordinate_structure_keys(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,cancel:&CancellationToken)->Result<StructureIntentOutcome,KernelClientError>{
  self.require_current_key_delivery()?;
  let metadata=self.content_metadata(identity,authority,workspace,cancel).await?;
  if metadata["owner_id"]!=identity.actor_id(){return Err(KernelClientError::InvalidCommand);}
  let outcome=if !metadata["content_key_head"].is_null()&&metadata["content_key_head"]["usable"]!=true{
   let revision=metadata["content_key_head"]["revision"].as_u64().ok_or(KernelClientError::InvalidResult)?;
   let keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;let scope=keys.coordinator_scope(&self.journal.delivery_namespace())?;drop(keys);
   Box::pin(self.rotate_structure_content_key(identity,authority,StructureContentKeyRotation{workspace_id:workspace.into(),idempotency_key:format!("coordinate-{revision}-{scope}")},cancel)).await?
  }else{
   let current=Box::pin(self.sync_structure_content_head(identity,authority,workspace,cancel)).await?;
   let head=&current["content_key_head"];let epoch=head["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?;
   let parent=head["command_id"].as_str().ok_or(KernelClientError::InvalidResult)?;
   Box::pin(self.fanout_structure_key(identity,authority,workspace,epoch,parent,cancel)).await?
  };
  if self.discovery.protocol_features().contains(&"owner-retained-key-delivery-v1".encode_utf16().collect::<Vec<_>>()){
   let history=tokio::time::timeout(Duration::from_secs(30),Box::pin(self.coordinate_retained_keys(identity,authority,workspace,cancel))).await;
   if let StructureIntentOutcome::Completed{command_id,..}=&outcome{
    match history{Ok(Ok(true))=>(),Ok(Err(error))=>return Err(error),_=>return Ok(waiting(command_id,"HISTORY_DELIVERY_IN_PROGRESS",true))}
   }
  }
  Ok(outcome)
 }

 pub(super) async fn fanout_structure_key(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,epoch:u64,parent:&str,cancel:&CancellationToken)->Result<StructureIntentOutcome,KernelClientError>{
  if !self.discovery.protocol_features().contains(&"owner-current-key-delivery-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
  let namespace=self.journal.delivery_namespace();
  let result=tokio::time::timeout(Duration::from_secs(30),async{
   for _ in 0..128 {
    if cancel.is_cancelled(){return Ok(waiting(parent,"CANCELLED",true));}
    let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
    if let Some(stage)=keys.delivery_stage(identity.key_id(),workspace,&namespace)?{
     if self.journal.verified_pending(&stage.command_id,identity.key_id(),self.discovery.audience_utf16())?.is_some(){
      drop(keys);
      let outcome=if let Some(KernelOperationStatus::Accepted(result))=self.status(&stage.command_id,identity.key_id())?{StructureIntentOutcome::Accepted(result)}else{match Box::pin(self.read_saved_structure_result(identity,authority,&stage.command_id,cancel)).await{
       Ok(result)=>StructureIntentOutcome::Accepted(result),
       Err(_)=>Box::pin(self.resume_structure_intent_scoped(identity,authority,&stage.command_id,Some(workspace),cancel)).await?,
      }};
      let StructureIntentOutcome::Accepted(result)=outcome else{return Ok(waiting(parent,"DELIVERY_OUTCOME_UNKNOWN",true));};
      if result.outcome_state()=="COMMITTED"{return Ok(waiting(parent,"DELIVERY_RESULT_UNAVAILABLE",false));}
      let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
      keys.clear_delivery_stage(identity.key_id(),workspace,&namespace,&stage.command_id)?;
      if result.outcome_state()=="REJECTED"{
       let v:Value=serde_json::from_str(result.structure_result_json.as_deref().ok_or(KernelClientError::InvalidResult)?).map_err(|_|KernelClientError::InvalidResult)?;
       if !matches!(v["error"]["code"].as_str(),Some("STALE_REVISION"|"CONTENT_KEY_PAGE_EXPIRED"|"CONTENT_KEY_RECIPIENT_CHANGED")){return Ok(waiting(parent,"DELIVERY_REFUSED",false));}
      }
      continue;
     }
    }
    drop(keys);
    let request=json!({"action":"structure.content-key.delivery.get","workspace_id":workspace,"body":{"epoch":epoch}});
    let outcome=match Box::pin(self.execute_structure_intent(identity,authority,request.to_string().as_bytes(),cancel)).await{Err(KernelClientError::ServerRejected(409))=>return Ok(waiting(parent,"ROTATION_SUPERSEDED_OR_ACCESS_CHANGED",false)),other=>other?};
    let StructureIntentOutcome::Accepted(observation)=outcome else{return Ok(waiting(parent,"DELIVERY_OBSERVATION_UNAVAILABLE",true));};
    let page=match data(&observation){Ok(v)=>v,Err(KernelClientError::OperationRefused(_))=>return Ok(waiting(parent,"ROTATION_SUPERSEDED_OR_ACCESS_CHANGED",false)),Err(e)=>return Err(e)};
    if page["delivery"]["epoch"]!=epoch||page["delivery"]["publication_id"]!=parent{return Err(KernelClientError::InvalidResult);}
    if page["delivery"]["status"]=="COMPLETE"{return Ok(StructureIntentOutcome::Completed{command_id:parent.into(),result:observation});}
    let page_revision=page["delivery"]["revision"].as_u64().ok_or(KernelClientError::InvalidResult)?;
    let key_id=page["content_key_head"]["key_id"].as_str().ok_or(KernelClientError::InvalidResult)?;
    let recipients=page["recipients"].as_array().filter(|r|r.len()<=32).ok_or(KernelClientError::InvalidResult)?;
    let token=page["page_token"].as_str().filter(|s|s.len()<=32000).ok_or(KernelClientError::InvalidResult)?;
    let sources=page["sources"].as_object().filter(|s|s.len()<=32).ok_or(KernelClientError::InvalidResult)?;
    let (_,_,time)=self.access_context(cancel).await?;
    let audience=String::from_utf16(self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidResult)?;
    let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
    let mut deliveries=Vec::new();
    for row in recipients {
     let source_key=row["source_key"].as_str().ok_or(KernelClientError::InvalidResult)?;
     let source=sources.get(source_key).ok_or(KernelClientError::InvalidResult)?;
     let jws=source["author_intent"].as_str().ok_or(KernelClientError::InvalidResult)?;
     let author=verify_structure_author_intent(jws,self.discovery.audience_utf16()).map_err(|_|JournalError::InvalidReceipt)?;
     if source_key!=format!("{}:{}",author.actor_id(),author.command_id())||source["intent_digest"]!=author.intent_digest(){return Err(JournalError::InvalidReceipt.into());}
     let mut row=row.as_object().ok_or(KernelClientError::InvalidResult)?.clone();row.remove("source_key");
     let recipient:CurrentKeyRecipient=serde_json::from_value(Value::Object(row)).map_err(|_|KernelClientError::InvalidResult)?;
     let request=verify_follow_recipient(&author,identity.actor_id(),workspace,&recipient,&audience,self.discovery.receipt_public_key(),time.server_time_ms())?;
     deliveries.push(keys.seal_current_delivery(identity.key_id(),workspace,&request,&recipient,&audience,identity.actor_id(),epoch,key_id)?);
    }
    let old=keys.delivery_stage(identity.key_id(),workspace,&namespace)?;
    if let Some(stage)=old{if stage.epoch!=epoch||stage.revision!=page_revision{keys.clear_delivery_stage(identity.key_id(),workspace,&namespace,&stage.command_id)?;}}
    let stage=keys.prepare_delivery_stage(identity.key_id(),workspace,&namespace,epoch,page_revision)?;drop(keys);
    let command=json!({"action":"structure.content-key.deliver","command_id":stage.command_id,"workspace_id":workspace,"body":{"key_id":key_id,"page_token":token,"next_state":page["next_state"],"deliveries":deliveries}});
    let outcome=match Box::pin(self.execute_structure_intent(identity,authority,command.to_string().as_bytes(),cancel)).await{
     Err(KernelClientError::Store(JournalError::IntentConflict))=>Box::pin(self.resume_structure_intent_scoped(identity,authority,&stage.command_id,Some(workspace),cancel)).await?,other=>other?,
    };
    if !matches!(outcome,StructureIntentOutcome::Accepted(_)){continue;}
    // The next bounded step reconciles and retires this exact stage before
    // reading the next persisted backend cursor.
   }
   Ok(waiting(parent,"DELIVERY_IN_PROGRESS",true))
  }).await;
  match result {
   Ok(Ok(value))=>Ok(value),Err(_)=>Ok(waiting(parent,"DELIVERY_IN_PROGRESS",true)),
   Ok(Err(error))=>{let (code,retryable)=match error{
    KernelClientError::Transport(_)=> ("DELIVERY_TRANSPORT_UNAVAILABLE",true),
    KernelClientError::ServerRejected(429|500..=599)=>("DELIVERY_SERVICE_UNAVAILABLE",true),
    KernelClientError::Access(_)|KernelClientError::Store(JournalError::InvalidReceipt)|KernelClientError::InvalidResult=>("RECIPIENT_PROOF_INVALID",false),
    KernelClientError::ContentKey(_)=>("DELIVERY_KEY_STATE_UNAVAILABLE",false),
    _=>("DELIVERY_RECONCILIATION_REQUIRED",false),
   };Ok(waiting(parent,code,retryable))}
  }
 }
}
