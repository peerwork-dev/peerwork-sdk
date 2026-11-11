//! One native Owner operation produces a browser invitation. Existing identity,
//! content-key cache and exact transport journal remain authoritative.
use super::*;
use crate::kernel_intents::StructureContentKeys;
use peerwork_core::{canonical::{canonical,Path as CanonicalPath},crypto::{base64url,sha256},structure_invitation as invitation};
use rand_core::{OsRng,RngCore};
use serde::{Serialize,Deserialize};
use serde_json::{json,Value};
use zeroize::Zeroizing;

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureInvitationGrant {
 pub instance_id:String,pub protocol_digest:String,pub actions:Vec<String>,pub protocol_roles:Vec<String>,pub capabilities:Vec<String>,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureInvitationSelection {
 pub workspace_id:String,pub browser_origin:String,pub role_label:String,pub inviter_label:String,pub grants:Vec<StructureInvitationGrant>,
 #[serde(default)]pub key_ids:Vec<String>,
 #[serde(default="default_ttl")]pub ttl_ms:u64,
}
fn default_ttl()->u64{86400000}
impl StructureInvitationSelection{
 pub(crate) fn validate(&self)->Result<(),KernelClientError>{
  fn label(s:&str,max:usize)->bool{!s.is_empty()&&s.encode_utf16().count()<=max}
  fn names(s:&[String],max:usize)->bool{s.len()<=max&&s.iter().all(|v|label(v,120))&&s.iter().collect::<std::collections::BTreeSet<_>>().len()==s.len()}
  if !crate::workspace_urls::token(&self.workspace_id)||crate::workspace_urls::origin(&self.browser_origin,true).is_err()||!label(&self.role_label,80)||!label(&self.inviter_label,80)||!(1000..=7*86400000).contains(&self.ttl_ms)||self.key_ids.len()>32||self.key_ids.iter().any(|v|!crate::workspace_urls::token(v))||self.key_ids.iter().collect::<std::collections::BTreeSet<_>>().len()!=self.key_ids.len()||self.grants.len()>16||self.grants.iter().map(|g|&g.instance_id).collect::<std::collections::BTreeSet<_>>().len()!=self.grants.len(){return Err(KernelClientError::InvalidCommand);}
  for g in &self.grants{if !crate::workspace_urls::token(&g.instance_id)||!crate::participant_migration::digest(&g.protocol_digest)||!names(&g.actions,128)||!names(&g.protocol_roles,32)||!names(&g.capabilities,64){return Err(KernelClientError::InvalidCommand);}}Ok(())
 }
}
impl KernelClient{
 pub(crate) async fn create_structure_invitation(&mut self,identity:&KernelIdentity,authority:&str,mut selection:StructureInvitationSelection,idempotency:&str,cancel:&CancellationToken)->Result<Value,KernelClientError>{
  selection.validate()?;
  if !self.discovery.protocol_features().contains(&invitation::FEATURE.encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
  selection.browser_origin=crate::workspace_urls::origin(&selection.browser_origin,self.origin().starts_with("http://")).map_err(|_|KernelClientError::InvalidCommand)?;
  selection.key_ids.sort();
  let plan=canonical(&json!({"domain":"peerwork.invitation-operation.v1","origin":self.origin(),"actor_id":identity.actor_id(),"authority":authority,"idempotency_key":idempotency,"selection":selection}),CanonicalPath::COMMAND).map_err(|_|KernelClientError::InvalidCommand)?;
  let command_id=base64url(&sha256(plan.as_bytes()));
  let seed=invitation::operation_secret(&Zeroizing::new(identity.signing_key().to_bytes()),plan.as_bytes())?;
  let invitation_id=base64url(&sha256(format!("peerwork.invitation-id.v1\0{command_id}").as_bytes()));
  let out=if self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?.is_some(){
   self.resume_saved_structure_intent(identity,authority,&command_id,Some(&selection.workspace_id),cancel).await?
  }else{
   let current=Box::pin(self.ensure_structure_content_ready(identity,authority,&selection.workspace_id,cancel)).await?;
   if current["owner_id"]!=identity.actor_id()||current["membership"]["role"]!="OWNER"{return Err(KernelClientError::InvalidCommand);}
   let (_,_,time)=self.access_context(cancel).await?;
   let epoch=current["content_key_head"]["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?;
   let revision=current["workspace_revision"].as_u64().ok_or(KernelClientError::InvalidResult)?;
   let audience=String::from_utf16(self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidResult)?;
   let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
   keys.ensure_current(identity.key_id(),&selection.workspace_id)?;
   let mut body=json!({"profile":"backend-structure-v1","invitation_id":invitation_id,"claim_key":invitation::claim_key(&seed)?,"expires_at":time.server_time_ms().checked_add(selection.ttl_ms).ok_or(KernelClientError::InvalidCommand)?,"role_label":selection.role_label,"inviter_label":selection.inviter_label,"grants":selection.grants,"content_key_epoch":epoch});
   keys.package_invitation(identity.key_id(),&selection.workspace_id,&seed,&selection.key_ids,&audience,identity.actor_id(),&mut body)?;drop(keys);
   let intent=json!({"action":"structure.invitation.issue","command_id":command_id,"workspace_id":selection.workspace_id,"expected_workspace_revision":revision,"body":body});
   match self.execute_structure_intent_prepared(identity,authority,intent.to_string().as_bytes(),cancel).await{
    Err(KernelClientError::Store(JournalError::IntentConflict))=>self.resume_saved_structure_intent(identity,authority,&command_id,Some(&selection.workspace_id),cancel).await?,other=>other?,
   }
  };
  let accepted=match &out{StructureIntentOutcome::Accepted(result)if result.outcome_state()=="ACCEPTED"=>Some(result.accepted_author_intent_digest().ok_or(KernelClientError::InvalidResult)?),_=>None};
  let mut value=crate::participant_outcome::outcome(out);
  if let Some(digest)=accepted{
   let secret=Zeroizing::new(base64url(&*seed));
   value["local"]=json!({"invitation_url":format!("{}/join/{invitation_id}#{}.{digest}",selection.browser_origin,&*secret),"authority":"OWNER_SIGNED_ONE_USE_ADMISSION","body_keys":"ENCRYPTED_IN_LINK_PACKAGE"});
  }Ok(value)
 }
}
