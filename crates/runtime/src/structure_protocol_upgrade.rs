//! One semantic upgrade, with the original selection and CAS plan retained in
//! the existing encrypted native parent journal. Recovery never resolves again.
use super::*;
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use tokio::time::Instant;
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolUpgradeGrant {
    pub actor_id:String,#[serde(default)]pub membership_id:Option<String>,#[serde(default)]pub expected_grant_revision:Option<u64>,
    pub actions:Vec<String>,pub protocol_roles:Vec<String>,pub capabilities:Vec<String>,pub expires_at:Option<u64>,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolUpgradeSelection {
    pub workspace_id:String,pub instance_id:String,
    #[serde(default,skip_serializing_if="Option::is_none")]pub target_package_digest:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]pub bundle:Option<Value>,
    #[serde(default,skip_serializing_if="Option::is_none")]pub execution_context_id:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]pub record_id:Option<String>,
    #[serde(default,skip_serializing_if="Vec::is_empty")]pub grants:Vec<ProtocolUpgradeGrant>,
    #[serde(default)]pub read_only:bool,
}
impl ProtocolUpgradeSelection {
    pub(crate) fn validate(&self)->Result<(),KernelClientError> {
        if !crate::workspace_urls::token(&self.workspace_id)||!crate::workspace_urls::token(&self.instance_id)
            ||self.execution_context_id.as_ref().is_some_and(|s|!crate::workspace_urls::token(s))
            ||self.record_id.as_ref().is_some_and(|s|!crate::workspace_urls::token(s))||self.record_id.is_some()&&self.execution_context_id.is_some()
            ||self.target_package_digest.is_some()==self.bundle.is_some()||self.grants.len()>32 {
            return Err(KernelClientError::InvalidCommand);
        }
        if self.target_package_digest.as_deref().is_some_and(|s|!crate::participant_migration::digest(s)){return Err(KernelClientError::InvalidCommand);}
        if let Some(bundle)=&self.bundle{peerwork_core::protocol_bundle::inspect(bundle).map_err(|_|KernelClientError::InvalidCommand)?;}
        let mut actors=std::collections::BTreeSet::new();
        for grant in &self.grants {
            if !crate::workspace_urls::token(&grant.actor_id)||grant.membership_id.as_deref().is_some_and(|id|!crate::workspace_urls::token(id))||!actors.insert(&grant.actor_id)
                ||grant.expected_grant_revision.is_some_and(|n|n==0||n>9_007_199_254_740_991)
                ||grant.actions.is_empty()||grant.actions.len()>64||grant.protocol_roles.len()>32||grant.capabilities.len()>32
                ||grant.actions.iter().chain(&grant.protocol_roles).chain(&grant.capabilities).any(|s|s.is_empty()||s.encode_utf16().count()>120)
                ||grant.expires_at.is_some_and(|n|n>9_007_199_254_740_991){return Err(KernelClientError::InvalidCommand);}
        }
        Ok(())
    }
}
impl KernelClient {
    pub async fn upgrade_protocol_instance(&mut self,identity:&KernelIdentity,authority:&str,selection:ProtocolUpgradeSelection,idempotency_key:&str,cancel:&CancellationToken)->Result<StructureIntentOutcome,KernelClientError> {
        self.upgrade_protocol_instance_until(identity,authority,selection,idempotency_key,cancel,Instant::now()+std::time::Duration::from_secs(30)).await
    }
    pub(crate) async fn upgrade_protocol_instance_until(&mut self,identity:&KernelIdentity,authority:&str,selection:ProtocolUpgradeSelection,idempotency_key:&str,cancel:&CancellationToken,deadline:Instant)->Result<StructureIntentOutcome,KernelClientError> {
        selection.validate()?;
        if !self.discovery.protocol_features().contains(&peerwork_core::structure_execution::PROTOCOL_UPGRADE_FEATURE.encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        let id=structure_keyed_command_id(self.origin(),identity.actor_id(),WireValue::String(selection.workspace_id.encode_utf16().collect()),&idempotency_key.encode_utf16().collect::<Vec<_>>())?;
        let wire=serde_json::to_string(&json!({"selection":selection,"idempotency_key":idempotency_key})).map_err(|_|KernelClientError::InvalidCommand)?;
        self.bind_structure_parent(identity,authority,&id,"PROTOCOL_UPGRADE",Some(&selection.workspace_id),&wire)?;
        let result=tokio::time::timeout_at(deadline,async{
            if self.journal.verified_pending(&id,identity.key_id(),self.discovery.audience_utf16())?.is_some(){return self.resume_saved_structure_intent(identity,authority,&id,Some(&selection.workspace_id),cancel).await;}
            let plan_id=peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(json!([id,"upgrade-plan"]).to_string().as_bytes()));
            let plan=if let Some(saved)=self.journal.parent_selection(&plan_id,identity,self.origin(),self.discovery.audience_utf16(),authority,Some(&selection.workspace_id))? {
                if saved.kind!="PROTOCOL_UPGRADE_PLAN"{return Err(KernelClientError::InvalidCommand);}
                serde_json::from_str::<Value>(&saved.wire).map_err(|_|KernelClientError::InvalidResult)?
            }else{
                let binding_id=peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(json!([id,"upgrade-binding"]).to_string().as_bytes()));
                let mut plan=if let Some(saved)=self.journal.parent_selection(&binding_id,identity,self.origin(),self.discovery.audience_utf16(),authority,Some(&selection.workspace_id))? {
                    if saved.kind!="PROTOCOL_UPGRADE_BINDING"{return Err(KernelClientError::InvalidCommand);}
                    serde_json::from_str::<Value>(&saved.wire).map_err(|_|KernelClientError::InvalidResult)?
                }else{
                let mut body=json!({"instance_id":selection.instance_id});if let Some(context)=&selection.execution_context_id{body["execution_context_id"]=json!(context);}if let Some(record)=&selection.record_id{body["record_id"]=json!(record);}
                let query=json!({"action":"structure.instance.resolve","workspace_id":selection.workspace_id,"body":body});
                let observed=self.execute_structure_intent_prepared(identity,authority,query.to_string().as_bytes(),cancel).await?;
                let StructureIntentOutcome::Accepted(observed)=observed else{return Ok(StructureIntentOutcome::Pending{command_id:id.clone(),code:"PREPARATION_IN_PROGRESS",phase:"PREPARATION",retryable:true,recovery:"RESUME_SAME_INTENT"});};
                let data=structure_access_client::data(&observed)?;
                let selected_context=selection.execution_context_id.is_some()||selection.record_id.is_some();
                let binding=&data[if selected_context{"binding"}else{"default_binding"}];
                if binding["instance_id"]!=selection.instance_id||binding["binding_revision"].as_u64().is_none()
                    ||!(binding["package_digest"].is_null()||binding["package_digest"].as_str().is_some_and(crate::participant_migration::digest)){return Err(KernelClientError::InvalidResult);}
                let target=if let Some(bundle)=&selection.bundle{peerwork_core::protocol_bundle::inspect(bundle).map_err(|_|KernelClientError::InvalidCommand)?["package_digest"].clone()}else{json!(selection.target_package_digest)};
                let mut plan=json!({"expected_binding_revision":binding[if selected_context{"binding_revision"}else{"default_revision"}],"expected_package_digest":binding["package_digest"],"target_package_digest":target});
                if selection.record_id.is_some(){plan["execution_context_id"]=binding["execution_context_id"].clone();}
                self.bind_structure_parent(identity,authority,&binding_id,"PROTOCOL_UPGRADE_BINDING",Some(&selection.workspace_id),&plan.to_string())?;plan
                };
                let mut grants=serde_json::to_value(&selection.grants).map_err(|_|KernelClientError::InvalidCommand)?;
                if !selection.grants.is_empty(){
                    let members_id=peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(json!([id,"upgrade-members"]).to_string().as_bytes()));
                    let phase=if let Some(saved)=self.journal.parent_selection(&members_id,identity,self.origin(),self.discovery.audience_utf16(),authority,Some(&selection.workspace_id))? {
                        if saved.kind!="PROTOCOL_UPGRADE_MEMBERS"{return Err(KernelClientError::InvalidCommand);}serde_json::from_str::<Value>(&saved.wire).map_err(|_|KernelClientError::InvalidResult)?
                    }else{
                    let target_protocol=if let Some(bundle)=&selection.bundle{peerwork_core::protocol_bundle::inspect(bundle).map_err(|_|KernelClientError::InvalidCommand)?["protocol_digest"].clone()}else{
                        let query=json!({"action":"structure.protocol.resolve","workspace_id":selection.workspace_id,"body":{"package_digest":plan["target_package_digest"],"view":"inspect","include_resources":false}});
                        let outcome=self.execute_structure_intent_prepared(identity,authority,query.to_string().as_bytes(),cancel).await?;let StructureIntentOutcome::Accepted(outcome)=outcome else{return Err(KernelClientError::InvalidResult);};structure_access_client::data(&outcome)?["protocol_digest"].clone()
                    };
                    let query=json!({"action":"structure.instance.resolve","workspace_id":selection.workspace_id,"body":{"instance_id":selection.instance_id,"protocol_digest":target_protocol}});
                    let target_context=match self.execute_structure_intent_prepared(identity,authority,query.to_string().as_bytes(),cancel).await{
                        Ok(StructureIntentOutcome::Accepted(outcome))=>match structure_access_client::data(&outcome){Ok(data)=>data["instance"]["execution_context_id"].as_str().map(str::to_owned),Err(KernelClientError::OperationRefused(ref e))if e.server_code=="NOT_FOUND"=>None,Err(e)=>return Err(e)},
                        Err(KernelClientError::ServerRejected(404)|KernelClientError::ReadRejected(404))=>None,Err(e)=>return Err(e),_=>return Err(KernelClientError::InvalidResult),
                    };
                    let actors:Vec<_>=selection.grants.iter().map(|grant|grant.actor_id.clone()).collect();
                    let query=json!({"action":"structure.members.read","workspace_id":selection.workspace_id,"body":{"actor_ids":actors,"state":"ACTIVE"}});
                    let outcome=self.execute_structure_intent_prepared(identity,authority,query.to_string().as_bytes(),cancel).await?;let StructureIntentOutcome::Accepted(outcome)=outcome else{return Err(KernelClientError::InvalidResult);};let members=structure_access_client::data(&outcome)?;
                    if members["missing_actor_ids"].as_array().is_none_or(|missing|!missing.is_empty()){return Err(KernelClientError::InvalidCommand);}
                    let members=members["members"].as_array().ok_or(KernelClientError::InvalidResult)?;
                    if members.len()!=actors.len(){return Err(KernelClientError::InvalidResult);}
                    for grant in grants.as_array_mut().ok_or(KernelClientError::InvalidCommand)?{
                        let actor=grant["actor_id"].clone();
                        let member=members.iter().find(|member|member["actor_id"]==actor).ok_or(KernelClientError::InvalidResult)?;
                        if member["state"]!="ACTIVE"||member["access_active"]!=true||member["membership_id"].as_str().is_none_or(|id|!crate::workspace_urls::token(id)){return Err(KernelClientError::InvalidCommand);}
                        if grant["membership_id"].is_null(){grant["membership_id"]=member["membership_id"].clone();}else if grant["membership_id"]!=member["membership_id"]{return Err(KernelClientError::InvalidCommand);}
                    }
                    let phase=json!({"grants":grants,"target_protocol_digest":target_protocol,"execution_context_id":target_context});self.bind_structure_parent(identity,authority,&members_id,"PROTOCOL_UPGRADE_MEMBERS",Some(&selection.workspace_id),&phase.to_string())?;phase
                    };
                    grants=phase["grants"].clone();
                    let actors:Vec<_>=grants.as_array().ok_or(KernelClientError::InvalidResult)?.iter().filter(|grant|grant["expected_grant_revision"].is_null()).map(|grant|grant["actor_id"].clone()).collect();
                    if let Some(context)=phase["execution_context_id"].as_str().filter(|_|!actors.is_empty()) {
                        let query=json!({"action":"structure.grant.get","workspace_id":selection.workspace_id,"instance_id":selection.instance_id,"protocol_digest":phase["target_protocol_digest"],"body":{"execution_context_id":context,"actor_ids":actors}});
                        let outcome=self.execute_structure_intent_prepared(identity,authority,query.to_string().as_bytes(),cancel).await?;let StructureIntentOutcome::Accepted(outcome)=outcome else{return Err(KernelClientError::InvalidResult);};let heads=structure_access_client::data(&outcome)?;let heads=heads["grants"].as_array().ok_or(KernelClientError::InvalidResult)?;if heads.len()!=actors.len(){return Err(KernelClientError::InvalidResult);}
                        for grant in grants.as_array_mut().ok_or(KernelClientError::InvalidResult)?.iter_mut().filter(|grant|grant["expected_grant_revision"].is_null()){
                            let head=heads.iter().find(|head|head["actor_id"]==grant["actor_id"]).ok_or(KernelClientError::InvalidResult)?;grant["expected_grant_revision"]=if head["grant"].is_null(){Value::Null}else{head["grant"]["grant_revision"].clone()};
                        }
                    }
                }
                if !selection.grants.is_empty(){plan["grants"]=grants;}
                self.bind_structure_parent(identity,authority,&plan_id,"PROTOCOL_UPGRADE_PLAN",Some(&selection.workspace_id),&plan.to_string())?;plan
            };
            if let Some(bundle)=&selection.bundle {
                let registration=peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(json!([id,"register-target"]).to_string().as_bytes()));
                let query=json!({"action":"structure.protocol.register","workspace_id":selection.workspace_id,"command_id":registration,"body":{"bundle":bundle}});
                match self.execute_structure_intent_prepared(identity,authority,query.to_string().as_bytes(),cancel).await? {
                    StructureIntentOutcome::Accepted(ref registered) if registered.outcome_state()=="ACCEPTED"=>(),
                    StructureIntentOutcome::Pending{code,retryable,..}=>return Ok(StructureIntentOutcome::Pending{command_id:id.clone(),code,phase:"PREPARATION",retryable,recovery:"RESUME_SAME_INTENT"}),
                    StructureIntentOutcome::Accepted(registered)=>{let mut error=match structure_access_client::data(&registered){Err(KernelClientError::OperationRefused(error))=>error,_=>return Err(KernelClientError::InvalidResult)};error.command_id=id.clone();error.phase="PREPARATION".into();error.effect_certainty="NOT_SUBMITTED".into();return Err(KernelClientError::OperationRefused(error));},
                    _=>return Err(KernelClientError::InvalidResult),
                }
            }
            let mut body=plan;body["instance_id"]=json!(selection.instance_id);body["read_only"]=json!(selection.read_only);
            if let Some(context)=&selection.execution_context_id{body["execution_context_id"]=json!(context);}
            let request=json!({"action":"structure.protocol.upgrade","workspace_id":selection.workspace_id,"command_id":id,"body":body});
            self.execute_structure_intent_prepared(identity,authority,request.to_string().as_bytes(),cancel).await
        }).await;
        self.parent_result(identity,&id,result)
    }
}
