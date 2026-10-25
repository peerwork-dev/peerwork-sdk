//! One native publication operation over an exact verified private record.
//! Preparation is encrypted locally; a saved packet wins before any re-read.
use super::*;
use super::structure_access_client::data;
use peerwork_core::{crypto::base64url,wire_json::WireValue};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use tokio::time::Instant;
use zeroize::{Zeroize,Zeroizing};

#[derive(Clone,Serialize,Deserialize)]
#[serde(tag="from",rename_all="SCREAMING_SNAKE_CASE",deny_unknown_fields)]
pub enum PublicationSnapshotBody{Record,Text{text:String}}
impl Drop for PublicationSnapshotBody{fn drop(&mut self){if let Self::Text{text}=self{text.zeroize();}}}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationSnapshotSelection{
 pub workspace_id:String,pub instance_id:String,pub protocol_digest:String,
 pub record_id:String,pub revision:u64,pub idempotency_key:String,
 #[serde(default)]pub expected_publication_revision:Option<u64>,
 pub title:String,pub disclosure:String,pub body:PublicationSnapshotBody,
}
fn encoded(text:&str)->Result<Value,KernelClientError>{
 if text.len()>peerwork_core::structure_content::MAX_BODY_BYTES{return Err(crate::kernel_intents::ContentKeyError::Content(peerwork_core::structure_content::StructureContentError::TooLarge).into());}
 let bytes=base64url(text.as_bytes());Ok(json!({"format":"PUBLIC_UTF8_BASE64","chunks":bytes.as_bytes().chunks(8192).map(|b|std::str::from_utf8(b).expect("base64 ASCII")).collect::<Vec<_>>()}))
}
impl KernelClient{
 pub(crate) async fn publish_selected_record_until(&mut self,identity:&KernelIdentity,authority:&str,selection:PublicationSnapshotSelection,cancel:&CancellationToken,deadline:Instant)->Result<StructureIntentOutcome,KernelClientError>{
  if !["owner-selected-publication-v1","selected-publication-snapshot-v1"].iter().all(|f|self.discovery.protocol_features().contains(&f.encode_utf16().collect::<Vec<_>>())){return Err(KernelClientError::UnsupportedStructureProfile);}
  if ![&selection.workspace_id,&selection.instance_id,&selection.record_id].into_iter().all(|v|crate::workspace_urls::token(v))||selection.protocol_digest.len()!=64||!selection.protocol_digest.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f'))||selection.revision==0||selection.revision>9_007_199_254_740_991||selection.expected_publication_revision.is_some_and(|n|n>9_007_199_254_740_991)||selection.title.is_empty()||selection.title.encode_utf16().count()>240||selection.disclosure!="PUBLISH_SELECTED_CONTENT"{return Err(KernelClientError::InvalidCommand);}
  if let PublicationSnapshotBody::Text{text}=&selection.body{encoded(text)?;}
  let id=super::structure_keyed_command_id(self.origin(),identity.actor_id(),WireValue::String(selection.workspace_id.encode_utf16().collect()),&selection.idempotency_key.encode_utf16().collect::<Vec<_>>())?;
  let wire=Zeroizing::new(serde_json::to_string(&selection).map_err(|_|KernelClientError::InvalidCommand)?);
  self.bind_structure_parent(identity,authority,&id,"PUBLICATION",Some(&selection.workspace_id),&wire)?;
  let result=tokio::time::timeout_at(deadline,async{
   tokio::select!{biased;
    result=async{
     if self.journal.verified_pending(&id,identity.key_id(),self.discovery.audience_utf16())?.is_some(){return Box::pin(self.resume_saved_structure_intent(identity,authority,&id,Some(&selection.workspace_id),cancel)).await;}
     let query=json!({"action":"structure.publication.prepare.get","workspace_id":selection.workspace_id,"instance_id":selection.instance_id,"protocol_digest":selection.protocol_digest,"body":{"record_id":selection.record_id,"revision":selection.revision}});
     let observed=Box::pin(self.execute_structure_intent(identity,authority,query.to_string().as_bytes(),cancel)).await?;
     let mut selected=match observed{
      StructureIntentOutcome::Accepted(selected)=>selected,
      StructureIntentOutcome::Pending{code,retryable,..}=>return Ok(StructureIntentOutcome::Pending{command_id:id.clone(),code:if code=="OUTCOME_UNKNOWN"{"PREPARATION_UNAVAILABLE"}else{code},phase:"PREPARATION",retryable,recovery:"RESUME_SAME_INTENT"}),
      _=>return Err(KernelClientError::InvalidResult),
     };
     let record=match data(&selected){
      Err(KernelClientError::OperationRefused(mut refusal))=>{refusal.command_id=id.clone();refusal.phase="PREPARATION".into();refusal.effect_certainty="NOT_SUBMITTED";return Err(KernelClientError::OperationRefused(refusal));},
      other=>other?,
     };
     if record["workspace_owner_id"]!=identity.actor_id(){return Err(KernelClientError::InvalidResult);}
     if record["source"].get("document_time").is_some()&&!self.discovery.protocol_features().contains(&"signed-document-time-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
     let text=match &selection.body{
      PublicationSnapshotBody::Text{text}=>Zeroizing::new(text.clone()),
      PublicationSnapshotBody::Record=>{
       if selected.opened_contents.as_ref().is_some_and(|items|items.iter().any(|b|b.state=="KEY_UNAVAILABLE")){
        if let Some(path)=self.access_recipient_path.clone(){let mut outcome=StructureIntentOutcome::Accepted(selected);self.populate_selected_body_keys(identity,authority,&path,&mut outcome,cancel).await;let StructureIntentOutcome::Accepted(opened)=outcome else{return Err(KernelClientError::InvalidResult);};selected=opened;}
       }
       let opened=selected.opened_contents.as_ref().and_then(|items|items.first()).ok_or(KernelClientError::InvalidResult)?;
       match opened.state{"OPENED"=>Zeroizing::new(opened.text.clone().ok_or(KernelClientError::InvalidResult)?),"NO_CONTENT"=>Zeroizing::new(String::new()),"KEY_UNAVAILABLE"=>return Err(crate::kernel_intents::ContentKeyError::Missing.into()),_=>return Err(KernelClientError::InvalidResult)}
      },
     };
     let mut source=json!({"record_id":selection.record_id,"revision":selection.revision,"actor_id":record["source"]["actor_id"],"created_at":record["created_at"],"intent_digest":record["source"]["intent_digest"]});
     if let Some(time)=record["source"].get("document_time"){source["document_time"]=time.clone();}
     if record["source"]["assurance"]=="OWNER_ATTESTED_CONVERSION"{
      // Core receipt verification already compared this exact provenance to
      // the original signed checkpoint record. Preserve unknown values as null.
      let legacy=&record["source"]["legacy_source"];
      source["attribution"]=json!({"assurance":"OWNER_ATTESTED_CONVERSION","actor_id":legacy.get("record_actor_id").unwrap_or(&Value::Null),"created_at":legacy.get("created_at").unwrap_or(&Value::Null),"legacy_source":legacy});
     }
     let revision=selection.expected_publication_revision.or_else(||record["publication_revision"].as_u64()).ok_or(KernelClientError::InvalidResult)?;
     let intent=json!({"action":"structure.publication.entry.set","command_id":id,"workspace_id":selection.workspace_id,"instance_id":selection.instance_id,"protocol_digest":selection.protocol_digest,"body":{"state":"PUBLIC","expected_publication_revision":revision,"source":source,"title":selection.title,"structure":record["structure"],"body":encoded(&text)?,"disclosure":selection.disclosure}});
     match Box::pin(self.execute_structure_intent_prepared(identity,authority,intent.to_string().as_bytes(),cancel)).await{
      Err(KernelClientError::Store(JournalError::IntentConflict))=>Box::pin(self.resume_saved_structure_intent(identity,authority,&id,Some(&selection.workspace_id),cancel)).await,
      other=>other,
     }
    }=>result,
    _=cancel.cancelled()=>Err(TransportError::Cancelled.into()),
   }
  }).await;
  self.parent_result(identity,&id,result)
 }
}
