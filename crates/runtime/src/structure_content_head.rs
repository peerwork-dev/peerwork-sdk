//! Canonical body-key selection. Selected metadata and one recipient-bound
//! delivery replace any implicit history scan or client-local key guess.
use super::*;
use super::structure_access_client::data;
use crate::kernel_intents::{StructureContentKeys,ContentKeyError};
use peerwork_core::{crypto::{base64url,sha256},prepared_command::verify_structure_author_intent};
use serde::{Serialize,Deserialize};
use serde_json::{json,Value};

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureContentKeyRotation {pub workspace_id:String,pub idempotency_key:String}

impl KernelClient {
    pub(crate) fn require_content_key_epochs(&self)->Result<(),KernelClientError>{
        let feature="canonical-content-key-epochs-v1".encode_utf16().collect::<Vec<_>>();
        if !self.discovery.protocol_features().contains(&feature){return Err(KernelClientError::UnsupportedStructureProfile);}
        Ok(())
    }
    pub(super) async fn content_metadata(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,cancel:&CancellationToken)->Result<Value,KernelClientError>{
        let request=json!({"action":"structure.workspace.get","workspace_id":workspace,"body":{}});
        let outcome=Box::pin(self.execute_structure_intent(identity,authority,request.to_string().as_bytes(),cancel)).await?;
        let StructureIntentOutcome::Accepted(result)=outcome else{return Err(KernelClientError::InvalidResult);};data(&result)
    }
    fn checked_head(&self,metadata:&Value,workspace:&str)->Result<Option<String>,KernelClientError>{
        let head=&metadata["content_key_head"];if head.is_null(){return Ok(None);}
        let owner=metadata["owner_id"].as_str().ok_or(KernelClientError::InvalidResult)?;
        let id=head["key_id"].as_str().ok_or(KernelClientError::InvalidResult)?;
        let jws=head["author_intent"].as_str().ok_or(KernelClientError::InvalidResult)?;
        let proof=verify_structure_author_intent(jws,self.discovery.audience_utf16()).map_err(|_|JournalError::InvalidReceipt)?;
        let body=proof.command().get("body").ok_or(KernelClientError::InvalidResult)?;
        if proof.actor_id()!=owner||proof.workspace_id()!=Some(workspace)||proof.action_id()!="structure.content-key.set"
            ||body.get("key_id").and_then(WireValue::as_string).as_deref()!=Some(id)
            ||head["owner_id"]!=owner||head["command_id"]!=proof.command_id()
            ||head["intent_digest"]!=peerwork_core::crypto::sha256_hex(jws.as_bytes()){
            return Err(JournalError::InvalidReceipt.into());
        }
        let epoch=metadata["content_key_head"]["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?;
        if required_u64(body,"expected_epoch")?.checked_add(1)!=Some(epoch){return Err(JournalError::InvalidReceipt.into());}
        Ok(Some(id.into()))
    }
    pub(super) fn observe_head(&self,identity:&KernelIdentity,metadata:&Value,workspace:&str)->Result<Option<String>,KernelClientError>{
        let id=self.checked_head(metadata,workspace)?;
        let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
        if let Some(id)=id.as_deref(){let h=&metadata["content_key_head"];keys.pin_remote_head(identity.key_id(),workspace,Some((h["owner_id"].as_str().ok_or(KernelClientError::InvalidResult)?,h["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?,id,h["intent_digest"].as_str().ok_or(KernelClientError::InvalidResult)?)))?;}
        else{keys.pin_remote_head(identity.key_id(),workspace,None)?;}
        Ok(id)
    }
    /// Receive-only crypto preparation. This never initializes/publishes a
    /// missing head, rotates keys, grants access, or enumerates workspace history.
    pub(crate) async fn watch_structure_keys(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,mailbox:&str,needed:&[String],cancel:&CancellationToken)->Result<Value,KernelClientError>{
        self.require_content_key_epochs()?;
        if needed.len()>31||needed.iter().any(|id|id.len()!=43){return Err(KernelClientError::InvalidCommand);}
        let query=json!({"action":"structure.mailbox.get","workspace_id":workspace,"body":{"mailbox_id":mailbox}});
        let StructureIntentOutcome::Accepted(result)=Box::pin(self.execute_structure_intent(identity,authority,query.to_string().as_bytes(),cancel)).await? else{return Err(KernelClientError::InvalidResult);};
        let metadata=data(&result)?;
        let current=self.observe_head(identity,&metadata,workspace)?;
        if current.is_none()&&needed.is_empty(){return Ok(json!({"state":"NOT_REQUIRED","key_id":null,"epoch":null,"missing_key_ids":[]}));}
        let head=&metadata["content_key_head"];
        let mut selected=needed.to_vec();if let Some(id)=&current{if !selected.contains(id){selected.push(id.clone());}}
        let keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
        let missing=selected.iter().map(|id|keys.contains_retained(identity.key_id(),workspace,id).map(|present|(id,present))).collect::<Result<Vec<_>,_>>()?.into_iter().filter(|(_,present)|!*present).map(|(id,_)|id.clone()).collect::<Vec<_>>();drop(keys);
        if !missing.is_empty(){
            let path=self.access_recipient_path.clone().ok_or(ContentKeyError::Missing)?;
            let selection=StructureKeyAcceptance{workspace_id:workspace.into(),owner_id:metadata["owner_id"].as_str().ok_or(KernelClientError::InvalidResult)?.into(),key_ids:missing,current_key_id:None,expected_current_key_id:None};
            Box::pin(self.accept_structure_keys_mode(identity,authority,&path,selection,cancel,true)).await?;
        }
        let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
        let unavailable=selected.iter().filter_map(|id|match keys.contains_retained(identity.key_id(),workspace,id){Ok(true)=>None,Ok(false)=>Some(Ok(id.clone())),Err(e)=>Some(Err(e))}).collect::<Result<Vec<_>,_>>()?;
        if let Some(id)=current.as_deref().filter(|id|!unavailable.iter().any(|v|v==id)){
            let previous=match keys.selected(identity.key_id(),workspace){Ok(v)=>Some(v.key_id),Err(ContentKeyError::Missing)=>None,Err(e)=>return Err(e.into())};
            keys.select_retained(identity.key_id(),workspace,id,previous.as_deref())?;
        }
        Ok(json!({"state":if current.is_some()&&head["usable"]!=true{"STALE"}else if !unavailable.is_empty(){"MISSING"}else if current.is_none(){"NOT_REQUIRED"}else{"READY"},"key_id":current,"epoch":head["epoch"],"missing_key_ids":unavailable}))
    }
    pub(crate) async fn sync_structure_content_head(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,cancel:&CancellationToken)->Result<Value,KernelClientError>{
        self.require_content_key_epochs()?;
        let mut metadata=self.content_metadata(identity,authority,workspace,cancel).await?;
        if self.observe_head(identity,&metadata,workspace)?.is_none(){
            if metadata["owner_id"]!=identity.actor_id(){return Err(ContentKeyError::Missing.into());}
            let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
            let head=keys.ensure_current(identity.key_id(),workspace)?;drop(keys);
            let id=base64url(&sha256(format!("peerwork.content-key.initialize.v1\0{}\0{}\0{}\0{}",self.origin(),identity.actor_id(),workspace,head.key_id).as_bytes()));
            let request=json!({"action":"structure.content-key.set","command_id":id,"workspace_id":workspace,"body":{"key_id":head.key_id,"expected_epoch":0,"expected_head_revision":null}});
            let outcome=Box::pin(self.execute_structure_intent(identity,authority,request.to_string().as_bytes(),cancel)).await?;
            let result=match outcome{
                StructureIntentOutcome::Accepted(result)=>result,
                StructureIntentOutcome::Pending{command_id,..}=>Box::pin(self.read_saved_structure_result(identity,authority,&command_id,cancel)).await
                    .map_err(|_|KernelClientError::PrerequisitePending{command_id,workspace_id:workspace.into()})?,
                _=>return Err(KernelClientError::InvalidResult),
            };
            // A concurrent Owner may have published first. Only a fresh,
            // authenticated selected head decides what can subsequently write.
            let value=data(&result);
            if value.as_ref().is_err_and(|e|!matches!(e,KernelClientError::OperationRefused(r) if r.server_code=="STALE_REVISION")){value?;}
            metadata=self.content_metadata(identity,authority,workspace,cancel).await?;
        }
        let id=self.observe_head(identity,&metadata,workspace)?.ok_or(KernelClientError::InvalidResult)?;
        if metadata["owner_id"]==identity.actor_id(){
            let command_id=metadata["content_key_head"]["command_id"].as_str().ok_or(KernelClientError::InvalidResult)?;
            if matches!(self.status(command_id,identity.key_id())?,Some(KernelOperationStatus::Pending)){
                Box::pin(self.read_saved_structure_result(identity,authority,command_id,cancel)).await
                    .map_err(|_|KernelClientError::PrerequisitePending{command_id:command_id.into(),workspace_id:workspace.into()})?;
            }
        }
        if metadata["content_key_head"]["usable"]!=true{return Err(ContentKeyError::RotationRequired.into());}
        let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
        let prior=match keys.selected(identity.key_id(),workspace){Ok(v)=>Some(v.key_id),Err(ContentKeyError::Missing)=>None,Err(e)=>return Err(e.into())};
        if prior.as_deref()==Some(&id){return Ok(metadata);}
        match keys.select_retained(identity.key_id(),workspace,&id,prior.as_deref()){
            Ok(_)=>return Ok(metadata),Err(ContentKeyError::Missing)=>(),Err(e)=>return Err(e.into()),
        }
        drop(keys);
        let path=self.access_recipient_path.clone().ok_or(ContentKeyError::Missing)?;
        let selection=StructureKeyAcceptance{workspace_id:workspace.into(),owner_id:metadata["owner_id"].as_str().ok_or(KernelClientError::InvalidResult)?.into(),key_ids:vec![id.clone()],current_key_id:Some(id),expected_current_key_id:prior};
        Box::pin(self.accept_structure_keys(identity,authority,&path,selection,cancel)).await?;
        Ok(metadata)
    }
    /// Repair only the Owner's crypto prerequisite. Never rebase business
    /// revisions, delegate Owner authority, or wait for every recipient.
    pub(super) async fn ensure_structure_content_ready(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,cancel:&CancellationToken)->Result<Value,KernelClientError>{
        match Box::pin(self.sync_structure_content_head(identity,authority,workspace,cancel)).await{
            Ok(metadata)=>return Ok(metadata),
            Err(KernelClientError::ContentKey(ContentKeyError::RotationRequired))=>(),
            Err(error)=>return Err(error),
        }
        let metadata=self.content_metadata(identity,authority,workspace,cancel).await?;
        // A member may observe that an Owner must rotate, but cannot acquire
        // crypto-maintenance authority through an ordinary business call.
        if metadata["owner_id"]!=identity.actor_id(){return Err(ContentKeyError::RotationRequired.into());}
        if metadata["content_key_head"]["usable"]==true{return Box::pin(self.sync_structure_content_head(identity,authority,workspace,cancel)).await;}
        let revision=metadata["content_key_head"]["revision"].as_u64().ok_or(KernelClientError::InvalidResult)?;
        let keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
        let scope=keys.coordinator_scope(&self.journal.delivery_namespace())?;drop(keys);
        let rotation=StructureContentKeyRotation{workspace_id:workspace.into(),idempotency_key:format!("coordinate-{revision}-{scope}")};
        let outcome=Box::pin(self.publish_structure_content_key(identity,authority,rotation,cancel)).await?;
        match outcome{
            StructureIntentOutcome::Accepted(result)=>{
                if let Err(error)=data(&result){
                    // A proven stale head selection may be superseded by
                    // another Owner's publication. Observe it; never rebase
                    // or resubmit this prerequisite or the business action.
                    if !matches!(&error,KernelClientError::OperationRefused(refusal) if refusal.server_code=="STALE_REVISION"){return Err(error);}
                }
            },
            StructureIntentOutcome::Pending{command_id,code,retryable,..}=>return Err(KernelClientError::CryptoPrerequisitePending{command_id,workspace_id:workspace.into(),code,retryable}),
            _=>return Err(KernelClientError::InvalidResult),
        }
        // A concurrent Owner publication is authenticated by the same selected
        // head path; only that head can choose the subsequent content key.
        Box::pin(self.sync_structure_content_head(identity,authority,workspace,cancel)).await
    }
    pub(super) fn content_config(&self)->TransportConfig{let mut config=TransportConfig::new(self.origin());config.allow_loopback_http=self.origin().starts_with("http://");config}
    pub(crate) async fn rotate_structure_content_key(&mut self,identity:&KernelIdentity,authority:&str,selection:StructureContentKeyRotation,cancel:&CancellationToken)->Result<StructureIntentOutcome,KernelClientError>{
        let outcome=Box::pin(self.publish_structure_content_key(identity,authority,selection.clone(),cancel)).await?;
        if let StructureIntentOutcome::Accepted(result)=&outcome{
            if result.outcome_state()=="ACCEPTED"{let value=data(result)?;let epoch=value["content_key_head"]["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?;return self.fanout_structure_key(identity,authority,&selection.workspace_id,epoch,&result.command_id,cancel).await;}
        }
        Ok(outcome)
    }
    /// Publish only the selected head. Member delivery is an independent
    /// persisted backend job; it must not gate an unrelated business write.
    pub(super) async fn publish_structure_content_key(&mut self,identity:&KernelIdentity,authority:&str,selection:StructureContentKeyRotation,cancel:&CancellationToken)->Result<StructureIntentOutcome,KernelClientError>{
        self.require_current_key_delivery()?;
        if selection.workspace_id.len()!=43||selection.idempotency_key.is_empty()||selection.idempotency_key.len()>128{return Err(KernelClientError::InvalidCommand);}
        let id=base64url(&sha256(format!("peerwork.content-key.rotate.v1\0{}\0{}\0{}\0{}\0{}",self.origin(),identity.actor_id(),authority,selection.workspace_id,selection.idempotency_key).as_bytes()));
        let saved_packet=self.journal.verified_pending(&id,identity.key_id(),self.discovery.audience_utf16())?.is_some();
        let saved_plan=self.journal.parent_selection(&id,identity,self.origin(),self.discovery.audience_utf16(),authority,Some(&selection.workspace_id))?.is_some();
        let mut outcome=if saved_packet||saved_plan{
            Box::pin(self.resume_structure_intent_scoped(identity,authority,&id,Some(&selection.workspace_id),cancel)).await?
        }else{
            let metadata=self.content_metadata(identity,authority,&selection.workspace_id,cancel).await?;
            if metadata["owner_id"]!=identity.actor_id(){return Err(KernelClientError::InvalidCommand);}
            self.observe_head(identity,&metadata,&selection.workspace_id)?;
            let mut keys=StructureContentKeys::open(&self.content_key_store_path(),self.content_config())?;
            let candidate=keys.create_candidate(identity.key_id(),&selection.workspace_id)?;drop(keys);
            let request=json!({"action":"structure.content-key.set","command_id":id,"workspace_id":selection.workspace_id,"body":{"key_id":candidate.key_id,"expected_epoch":metadata["content_key_head"]["epoch"].as_u64().unwrap_or(0),"expected_head_revision":metadata["content_key_head"]["revision"]}});
            match Box::pin(self.execute_structure_intent(identity,authority,request.to_string().as_bytes(),cancel)).await{
                Err(KernelClientError::Store(JournalError::IntentConflict))=>Box::pin(self.resume_structure_intent_scoped(identity,authority,&id,Some(&selection.workspace_id),cancel)).await?,
                other=>other?,
            }
        };
        if let StructureIntentOutcome::Pending{command_id,..}=&outcome{
            if let Ok(result)=Box::pin(self.read_saved_structure_result(identity,authority,command_id,cancel)).await{outcome=StructureIntentOutcome::Accepted(result);}
        }
        // Even after a successful old rotation, select today's head rather
        // than resetting a newer local key during an idempotent retry.
        if matches!(&outcome,StructureIntentOutcome::Accepted(r) if r.outcome_state()=="ACCEPTED"){
            // Local cache refresh cannot turn a verified committed rotation
            // into an unknown operation. The next body write checks afresh.
            let _=tokio::time::timeout(std::time::Duration::from_secs(5),Box::pin(self.sync_structure_content_head(identity,authority,&selection.workspace_id,cancel))).await;
        }
        Ok(outcome)
    }
}
