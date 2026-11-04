//! Bounded context selection before signing. Immutable record routing is
//! cached; mutable default choices carry a binding revision fence. The native
//! parent journal elects each mutation's original and resolved intent once.
use super::*;
use serde_json::{json,Value};
use std::{collections::BTreeMap,sync::{Mutex,OnceLock}};
fn invalid()->KernelClientError{KernelClientError::InvalidCommand}
fn encode(value:&Value)->Result<Vec<u8>,KernelClientError>{serde_json::to_vec(value).map_err(|_|invalid())}
fn cache()->&'static Mutex<BTreeMap<String,(String,String)>>{static CACHE:OnceLock<Mutex<BTreeMap<String,(String,String)>>>=OnceLock::new();CACHE.get_or_init(||Mutex::new(BTreeMap::new()))}
fn routed(action:&str)->bool{crate::participant_actions::execution_routed(action)}
impl KernelClient {
    pub(crate) async fn select_execution_intent(&mut self,identity:&KernelIdentity,authority:&str,wire:&[u8],cancel:&CancellationToken)->Result<Vec<u8>,KernelClientError>{
        let request:Value=serde_json::from_slice(wire).map_err(|_|invalid())?;
        let action=request["action"].as_str().ok_or_else(invalid)?;
        if !routed(action)||!self.discovery.protocol_features().contains(&peerwork_core::structure_execution::PROTOCOL_UPGRADE_FEATURE.encode_utf16().collect::<Vec<_>>()){return Ok(wire.to_vec());}
        self.structure_command(identity,authority,wire)?;
        self.resolve_execution_intent(identity,authority,request,cancel).await
    }
    pub(crate) fn execution_protocol_selection(&self,identity:&KernelIdentity,request:&Value)->Result<Option<String>,KernelClientError>{
        if let Some(protocol)=request["protocol_digest"].as_str(){return Ok(Some(protocol.into()));}
        let Some(action)=request["action"].as_str()else{return Err(invalid());};
        if !peerwork_core::structure_execution::has_body_instance_selector(action){return Ok(None);}
        let Some(instance)=request["body"]["instance_id"].as_str()else{return Ok(None);};
        if let Some(protocol)=request["body"]["protocol_digest"].as_str(){return Ok(Some(protocol.into()));}
        let Some(workspace)=request["workspace_id"].as_str()else{return Err(invalid());};
        let selection=if let Some(context)=request["body"]["execution_context_id"].as_str(){format!("ctx:{context}")}else if let Some(record)=request["body"]["record_id"].as_str(){record.into()}else{return Ok(None);};
        let key=json!([self.origin(),self.discovery.receipt_public_key(),identity.actor_id(),workspace,instance,selection]).to_string();
        cache().lock().map_err(|_|invalid())?.get(&key).map(|(_,protocol)|Some(protocol.clone())).ok_or(KernelClientError::InvalidResult)
    }
    pub(crate) async fn prepare_execution_intent(&mut self,identity:&KernelIdentity,authority:&str,wire:&[u8],cancel:&CancellationToken)->Result<Vec<u8>,KernelClientError>{
        let request:Value=serde_json::from_slice(wire).map_err(|_|invalid())?;
        let action=request["action"].as_str().ok_or_else(invalid)?;
        if !routed(action)||!self.discovery.protocol_features().contains(&peerwork_core::structure_execution::PROTOCOL_UPGRADE_FEATURE.encode_utf16().collect::<Vec<_>>()){return Ok(wire.to_vec());}
        let (id,_,durable)=self.structure_command(identity,authority,wire)?;
        if !durable{return self.resolve_execution_intent(identity,authority,request,cancel).await;}
        let saved=self.journal.verified_pending(&id,identity.key_id(),self.discovery.audience_utf16())?.is_some();
        let parent=self.journal.parent_selection(&id,identity,self.origin(),self.discovery.audience_utf16(),authority,None)?;
        // Rows and packets admitted by older SDKs retain their old legacy
        // interpretation even after a later default upgrade.
        if saved&&parent.as_ref().is_none_or(|p|p.kind!="EXECUTION_INTENT")||parent.as_ref().is_some_and(|p|p.kind!="EXECUTION_INTENT"){return Ok(wire.to_vec());}
        let mut original=request;original.as_object_mut().ok_or_else(invalid)?.remove("idempotency_key");original["command_id"]=json!(id);
        let original=String::from_utf8(encode(&original)?).map_err(|_|invalid())?;
        let child=peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(json!([id,"execution-resolution"]).to_string().as_bytes()));
        if let Some(plan)=self.journal.parent_selection(&child,identity,self.origin(),self.discovery.audience_utf16(),authority,None)?{
            if plan.kind!="EXECUTION_RESOLUTION"{return Err(invalid());}
            let prior=parent.ok_or_else(invalid)?;
            let compare=|s:&str|serde_json::from_str::<Value>(s).map_err(|_|invalid());
            if compare(&original)?!=compare(&prior.wire)?&&compare(&original)?!=compare(&plan.wire)?{return Err(JournalError::IntentConflict.into());}
            return Ok(plan.wire.as_bytes().to_vec());
        }
        let workspace=serde_json::from_str::<Value>(&original).map_err(|_|invalid())?["workspace_id"].as_str().map(str::to_owned);
        self.bind_structure_parent(identity,authority,&id,"EXECUTION_INTENT",workspace.as_deref(),&original)?;
        let resolved=self.resolve_execution_intent(identity,authority,serde_json::from_str(&original).map_err(|_|invalid())?,cancel).await?;
        let resolved=String::from_utf8(resolved).map_err(|_|invalid())?;
        self.bind_structure_parent(identity,authority,&child,"EXECUTION_RESOLUTION",workspace.as_deref(),&resolved)?;
        Ok(resolved.into_bytes())
    }
    async fn execution_instance(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,instance:&str,record:Option<&str>,context:Option<&str>,cancel:&CancellationToken)->Result<Value,KernelClientError>{
        let mut body=json!({"instance_id":instance});if let Some(record)=record{body["record_id"]=json!(record);}if let Some(context)=context{body["execution_context_id"]=json!(context);}
        let request=json!({"action":"structure.instance.resolve","workspace_id":workspace,"body":body});
        let out=self.execute_structure_intent_prepared(identity,authority,&encode(&request)?,cancel).await?;
        let StructureIntentOutcome::Accepted(out)=out else{return Err(KernelClientError::InvalidResult);};structure_access_client::data(&out)
    }
    async fn execution_protocol_instance(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,instance:&str,protocol:&str,cancel:&CancellationToken)->Result<Value,KernelClientError>{
        let request=json!({"action":"structure.instance.resolve","workspace_id":workspace,"body":{"instance_id":instance,"protocol_digest":protocol}});
        let out=self.execute_structure_intent_prepared(identity,authority,&encode(&request)?,cancel).await?;
        let StructureIntentOutcome::Accepted(out)=out else{return Err(KernelClientError::InvalidResult);};structure_access_client::data(&out)
    }
    async fn record_execution(&mut self,identity:&KernelIdentity,authority:&str,workspace:&str,instance:&str,record:&str,cancel:&CancellationToken)->Result<(String,String),KernelClientError>{
        if !crate::workspace_urls::token(record){return Err(invalid());}
        let key=json!([self.origin(),self.discovery.receipt_public_key(),identity.actor_id(),workspace,instance,record]).to_string();
        if let Some(found)=cache().lock().map_err(|_|invalid())?.get(&key).cloned(){return Ok(found);}
        let data=self.execution_instance(identity,authority,workspace,instance,Some(record),None,cancel).await?;
        let selected=&data["instance"];
        let context=selected["execution_context_id"].as_str().filter(|s|crate::workspace_urls::token(s)).ok_or(KernelClientError::InvalidResult)?.to_owned();
        let protocol=selected["protocol_digest"].as_str().filter(|s|crate::participant_migration::digest(s)).ok_or(KernelClientError::InvalidResult)?.to_owned();
        let context_key=json!([self.origin(),self.discovery.receipt_public_key(),identity.actor_id(),workspace,instance,format!("ctx:{context}")]).to_string();
        let mut saved=cache().lock().map_err(|_|invalid())?;while saved.len()>125{if let Some(first)=saved.keys().next().cloned(){saved.remove(&first);}}saved.insert(key,(context.clone(),protocol.clone()));saved.insert(context_key,(context.clone(),protocol.clone()));Ok((context,protocol))
    }
    async fn resolve_execution_intent(&mut self,identity:&KernelIdentity,authority:&str,mut request:Value,cancel:&CancellationToken)->Result<Vec<u8>,KernelClientError>{
        let action=request["action"].as_str().ok_or_else(invalid)?.to_owned();
        let workspace=request["workspace_id"].as_str().ok_or_else(invalid)?.to_owned();
        let Some(instance)=request["instance_id"].as_str().or_else(||request["body"]["instance_id"].as_str()).map(str::to_owned)else{return encode(&request);};
        if let Some(context)=request["body"]["execution_context_id"].as_str().map(str::to_owned){
            let key=json!([self.origin(),self.discovery.receipt_public_key(),identity.actor_id(),workspace,instance,format!("ctx:{context}")]).to_string();
            let found=cache().lock().map_err(|_|invalid())?.get(&key).cloned();
            let protocol=if let Some((_,protocol))=found{protocol}else{let data=self.execution_instance(identity,authority,&workspace,&instance,None,Some(&context),cancel).await?;let protocol=data["instance"]["protocol_digest"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned();let mut saved=cache().lock().map_err(|_|invalid())?;if saved.len()>=128{if let Some(first)=saved.keys().next().cloned(){saved.remove(&first);}}saved.insert(key,(context,protocol.clone()));protocol};
            if !peerwork_core::structure_execution::has_body_instance_selector(&action){request["protocol_digest"]=json!(protocol);}return encode(&request);
        }
        let mut records=Vec::new();
        if let Some(record)=request["record_id"].as_str(){records.push(record.to_owned());}
        if matches!(action.as_str(),"structure.record.get"|"structure.publication.prepare.get"|"structure.instance.resolve"|"structure.protocol.resolve"|"structure.protocol.resource.get"){
            if let Some(record)=request["body"]["record_id"].as_str(){records.push(record.to_owned());}
        }
        if action=="structure.action" {
            if let Some(refs)=request["exact_input_refs"].as_array(){if refs.len()>32{return Err(invalid());}for r in refs{records.push(r["record_id"].as_str().ok_or_else(invalid)?.to_owned());}}
        }
        records.sort();records.dedup();
        let mut selected=None;
        for record in records {
            let context=self.record_execution(identity,authority,&workspace,&instance,&record,cancel).await?;
            if selected.as_ref().is_some_and(|old|old!=&context){return Err(KernelClientError::InvalidCommand);}
            selected=Some(context);
        }
        if selected.is_none()&&peerwork_core::structure_execution::has_body_instance_selector(&action) {
            if let Some(protocol)=request["body"]["protocol_digest"].as_str(){let data=self.execution_protocol_instance(identity,authority,&workspace,&instance,protocol,cancel).await?;selected=Some((data["instance"]["execution_context_id"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned(),data["instance"]["protocol_digest"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned()));}
        }
        if selected.is_none()&&(request["default_execution"]==true||matches!(action.as_str(),"structure.protocol.resolve"|"structure.protocol.resource.get")) {
            let current=self.execution_instance(identity,authority,&workspace,&instance,None,None,cancel).await?;
            selected=Some((current["default_binding"]["execution_context_id"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned(),current["default_binding"]["protocol_digest"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned()));
        }
        if selected.is_none()&&action!="structure.action" {
            if let Some(protocol)=request["protocol_digest"].as_str(){let data=self.execution_protocol_instance(identity,authority,&workspace,&instance,protocol,cancel).await?;selected=Some((data["instance"]["execution_context_id"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned(),protocol.to_owned()));}
        }
        if selected.is_none()&&action=="structure.action" {
            let legacy=if let Some(protocol)=request["protocol_digest"].as_str(){self.execution_protocol_instance(identity,authority,&workspace,&instance,protocol,cancel).await?}else{self.execution_instance(identity,authority,&workspace,&instance,None,None,cancel).await?};
            let action_id=request["body"]["action_id"].as_str().ok_or_else(invalid)?;
            let mut declaration=legacy["instance"]["manifest"]["execution_contexts"]["actions"][action_id].clone();
            // A newly added CREATE action may not exist in the alias's old
            // pinned manifest. Select its default generation before applying
            // the action declaration; exact old-work selectors already won.
            if declaration.is_null()&&legacy["default_binding"]["execution_context_id"]!=legacy["instance"]["execution_context_id"] {
                let context=legacy["default_binding"]["execution_context_id"].as_str().ok_or(KernelClientError::InvalidResult)?;
                let current=self.execution_instance(identity,authority,&workspace,&instance,None,Some(context),cancel).await?;
                declaration=current["instance"]["manifest"]["execution_contexts"]["actions"][action_id].clone();
            }
            match declaration["kind"].as_str(){
                Some("CONTINUE_ROOT")=>{
                    let mut reference=&request["body"]["structure"];
                    for field in declaration["root_ref_path"].as_array().ok_or_else(invalid)?{reference=reference.get(field.as_str().ok_or_else(invalid)?).ok_or_else(invalid)?;}
                    let record=reference.as_str().or_else(||reference["record_id"].as_str()).ok_or_else(invalid)?;
                    selected=Some(self.record_execution(identity,authority,&workspace,&instance,record,cancel).await?);
                },
                Some("CREATE_ROOT")=>{
                    let binding=&legacy["default_binding"];
                    selected=Some((binding["execution_context_id"].as_str().filter(|s|crate::workspace_urls::token(s)).ok_or(KernelClientError::InvalidResult)?.to_owned(),binding["protocol_digest"].as_str().filter(|s|crate::participant_migration::digest(s)).ok_or(KernelClientError::InvalidResult)?.to_owned()));
                    if request["body"].get("expected_binding_revision").is_none(){request["body"]["expected_binding_revision"]=binding["default_revision"].clone();}
                },
                _=>(),
            }
            if selected.is_none(){selected=Some((legacy["instance"]["execution_context_id"].as_str().unwrap_or(&instance).to_owned(),legacy["instance"]["protocol_digest"].as_str().ok_or(KernelClientError::InvalidResult)?.to_owned()));}
        }
        if let Some((context,protocol))=selected {
            let key=json!([self.origin(),self.discovery.receipt_public_key(),identity.actor_id(),workspace,instance,format!("ctx:{context}")]).to_string();
            let mut saved=cache().lock().map_err(|_|invalid())?;if saved.len()>=128{if let Some(first)=saved.keys().next().cloned(){saved.remove(&first);}}saved.insert(key,(context.clone(),protocol.clone()));drop(saved);
            if !peerwork_core::structure_execution::has_body_instance_selector(&action){request["protocol_digest"]=json!(protocol);}
            // Protocol role/schema resolution selects by record before role;
            // its public record selector and explicit context are exclusive.
            if !peerwork_core::structure_execution::has_body_instance_selector(&action)||request["body"].get("record_id").is_none()&&request["body"].get("protocol_digest").is_none(){request["body"]["execution_context_id"]=json!(context);}
        }
        encode(&request)
    }
}
