//! Local projections for one stable public alias. Every credential stays
//! immutable; old namespaces remain available for exact-operation recovery.
use super::*;
use crate::agent_tools::{ProtocolView,ProtocolViewScope,MAX_PROTOCOL_VIEWS};
const READS:&[&str]=&["structure.instance.records.read","structure.instance.get","structure.instance.resolve","structure.protocol.resolve","structure.protocol.resource.get","structure.record.get","structure.records.read"];
impl Connect {
    async fn capture_protocol_view(&self,alias:&str,mut scope:Scope,path:PathBuf,read_only:bool,context:Option<String>,profile:&AgentProfile)->Result<(String,ProtocolView)>{
        let client=RuntimeClient::connect(path.clone(),&profile.expected_origin,&profile.expected_actor).await?;
        let binding=crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?);
        let caps=client.call(json!({"method":"capabilities"})).await?;
        let cap:Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|local("LOCAL_CEILING_INVALID"))?;
        // A logical alias can now point at a newer default, while its original
        // endpoint remains pinned to an older execution for pending recovery.
        // Persist the endpoint's actual immutable ceiling, not that alias's
        // mutable selected digest.
        for (allowed,selected) in [(&cap.workspace_ids,&mut scope.workspace_id),(&cap.instance_ids,&mut scope.instance_id)] {
            let value=allowed.as_ref().filter(|set|set.len()==1).and_then(|set|set.iter().next()).ok_or_else(||local("PROTOCOL_VIEW_SCOPE_INVALID"))?;
            if selected.as_ref()!=Some(value){return Err(local("PROTOCOL_VIEW_SCOPE_INVALID"));}
            *selected=Some(value.clone());
        }
        scope.protocol_digest=match &cap.protocol_digests {
            Some(digests) if digests.len()==1=>digests.iter().next().cloned(),
            None if read_only=>None,
            _=>return Err(local("PROTOCOL_VIEW_SCOPE_INVALID")),
        };
        let id=format!("protocol-view-{}",&sha256_hex(json!([alias,read_only,binding]).to_string().as_bytes())[..40]);
        Ok((id,ProtocolView{selected:ProtocolViewScope{alias:alias.into(),scope,execution_context_id:context,read_only,client_generation:binding["client_generation"].as_u64().unwrap_or(0),binding,actions:cap.business_actions},endpoint_path:path}))
    }
    fn keep_protocol_view(profile:&mut AgentProfile,id:String,view:ProtocolView)->Result<()>{
        if !profile.protocol_views.contains_key(&id)&&profile.protocol_views.len()>=MAX_PROTOCOL_VIEWS{return Err(local("PROTOCOL_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
        if let Some(old)=profile.protocol_views.get(&id){if serde_json::to_value(old).ok()!=serde_json::to_value(&view).ok(){return Err(local("PROTOCOL_VIEW_BINDING_CHANGED"));}}
        profile.protocol_views.insert(id,view);Ok(())
    }
    pub(super) async fn extend_protocol_views(&self,participant:&str,previous:Option<&AgentProfile>,profile:&mut AgentProfile,parent:&Capability,client:&RuntimeClient)->Result<()>{
        if let Some(previous)=previous {
            for(alias,path)in &previous.protocol_endpoints {
                let scope=previous.protocols.get(alias).ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?.clone();
                let(id,view)=self.capture_protocol_view(alias,scope,path.clone(),false,None,previous).await?;Self::keep_protocol_view(profile,id,view)?;
            }
        }
        for(alias,path)in profile.protocol_endpoints.clone(){
            let scope=profile.protocols[&alias].clone();let(id,view)=self.capture_protocol_view(&alias,scope,path,false,None,profile).await?;Self::keep_protocol_view(profile,id,view)?;
        }
        for(alias,scope)in profile.protocols.clone(){
            if profile.protocol_views.values().any(|v|v.selected.alias==alias&&v.selected.read_only){continue;}
            let mut cap=parent.clone();cap.allow_root=false;cap.workspace_ids=Some([scope.workspace_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?].into());cap.instance_ids=Some([scope.instance_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?].into());cap.protocol_digests=None;cap.business_actions=Some(Default::default());cap.operations.retain(|op|READS.contains(&op.as_str()));
            if cap.operations.is_empty()||!cap.is_subset_of(parent){continue;}
            if profile.protocol_views.len()>=MAX_PROTOCOL_VIEWS{return Err(local("PROTOCOL_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
            let name=format!("protocol-read-{}",&sha256_hex(json!([participant,alias,scope.workspace_id,scope.instance_id,cap]).to_string().as_bytes())[..40]);
            let derived=client.call(json!({"method":"derive","name":name,"capability":cap})).await?;
            let path=PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?);
            let read_scope=Scope{protocol_digest:None,..scope};let(id,view)=self.capture_protocol_view(&alias,read_scope,path,true,None,profile).await?;Self::keep_protocol_view(profile,id,view)?;
        }
        Ok(())
    }
    pub async fn refresh_protocol_alias(&mut self,participant:Option<&str>,workspace:Option<&str>,alias:&str,target:Option<&Value>)->Result<Value>{
        self.require_writer()?;let handle=self.selected_handle(participant)?.ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let mut profile=self.profile_for_scope(Some(&handle),workspace)?.ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let old=profile.clone();let scope=profile.protocols.get(alias).cloned().ok_or_else(||local("PROTOCOL_ALIAS_UNKNOWN"))?;
        let ws=scope.workspace_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?;
        let instance=scope.instance_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?;
        let active=self.registry.active_by_scope.get(&format!("{handle}:{ws}")).cloned().ok_or_else(||local("BROKEN_BINDING"))?;
        let original=self.original_client(&handle).await?;let caps=original.call(json!({"method":"capabilities"})).await?;
        let parent:Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|local("LOCAL_CEILING_INVALID"))?;
        self.extend_protocol_views(&handle,Some(&old),&mut profile,&parent,&original).await?;
        let desired=self.registry.setups[&active].protocol_intents.get(alias).cloned().or_else(||self.registry.setups[&active].desired.protocols.iter().find(|p|p.alias==alias).cloned());
        let mut blocker=None;
        if let Some(desired)=desired {
            let mut query=json!({"instance_id":instance});if let Some(ctx)=target.and_then(|v|v["execution_context_id"].as_str()){query["execution_context_id"]=json!(ctx);}
            let observed=read(&original,"structure.instance.resolve",Scope{workspace_id:Some(ws.clone()),..Default::default()},query).await?;
            let selected=if target.and_then(|v|v["execution_context_id"].as_str()).is_some(){&observed["binding"]}else{&observed["default_binding"]};
            let protocol=selected["protocol_digest"].as_str().or_else(||observed["instance"]["protocol_digest"].as_str()).ok_or_else(||local("PROTOCOL_RESOLUTION_FAILED"))?.to_owned();
            let context=selected["execution_context_id"].as_str().map(str::to_owned);
            let actual=Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance),protocol_digest:Some(protocol)};
            let mut body=json!({"view":"inspect","include_resources":false});if let Some(ctx)=&context{body["execution_context_id"]=json!(ctx);}
            let bundle=read(&original,"structure.protocol.resolve",actual.clone(),body).await?;
            let mut body=json!({"actor_id":profile.expected_actor});if let Some(ctx)=&context{body["execution_context_id"]=json!(ctx);}
            let rights=read(&original,"structure.grant.get",actual.clone(),body).await?;
            let grant=&rights["grant"];let role=&bundle["bundle_header"]["roles"][&desired.role];
            let declared:std::collections::BTreeSet<String>=role["tools"].as_array().into_iter().flatten().filter_map(|t|t["action"].as_str().map(str::to_owned)).collect();
            let granted:std::collections::BTreeSet<String>=grant["actions"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
            let explicit:std::collections::BTreeSet<String>=desired.actions.iter().cloned().collect();
            if !role.is_object()||grant["effective"]!=true||!grant["protocol_roles"].as_array().is_some_and(|roles|roles.iter().any(|role|role==&desired.role))||!explicit.is_subset(&declared)||!explicit.is_subset(&granted){blocker=Some(local("PROTOCOL_TARGET_ROLE_OR_ACTION_GRANT_REQUIRED"));}
            else{
                let actions:std::collections::BTreeSet<String>=declared.intersection(&granted).filter(|action|(explicit.is_empty()||explicit.contains(*action))&&parent.business_actions.as_ref().is_none_or(|allowed|allowed.contains(*action))).cloned().collect();
                let mut cap=parent.clone();cap.allow_root=false;cap.workspace_ids=Some([ws.clone()].into());cap.instance_ids=Some([actual.instance_id.clone().unwrap()].into());cap.protocol_digests=Some([actual.protocol_digest.clone().unwrap()].into());cap.business_actions=Some(actions);cap.mailbox_ids=Some(Default::default());cap.operations.retain(|op|op=="structure.action"||READS.contains(&op.as_str())&&op!="structure.instance.records.read");
                let name=format!("protocol-write-{}",&sha256_hex(json!([handle,alias,actual,desired.role,cap]).to_string().as_bytes())[..40]);
                if profile.protocol_views.len()>=MAX_PROTOCOL_VIEWS&&!profile.protocol_views.values().any(|v|v.selected.alias==alias&&v.selected.scope==actual&&v.selected.actions==cap.business_actions){return Err(local("PROTOCOL_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
                let derived=original.call(json!({"method":"derive","name":name,"capability":cap})).await?;
                let path=PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?);
                let(id,view)=self.capture_protocol_view(alias,actual.clone(),path,false,context,&profile).await?;Self::keep_protocol_view(&mut profile,id,view)?;profile.protocols.insert(alias.into(),actual);
            }
        }
        profile.validate()?;
        let id=format!("views-{}",&sha256_hex(serde_json::to_vec(&profile).map_err(|_|local("DERIVED_PROFILE_INVALID"))?.as_slice())[..32]);
        if id!=active {
            let mut setup=self.registry.setups[&active].clone();setup.desired.setup_id=id.clone();setup.digest=sha256_hex(&serde_json::to_vec(&setup.desired).map_err(|_|local("CONNECT_ARGUMENT_INVALID"))?);setup.profile=Some(profile.clone());setup.result["setup_id"]=json!(id);
            if !self.registry.setups.contains_key(&id)&&self.registry.setups.len()>=64{return Err(local("SETUP_LIMIT"));}self.registry.setups.insert(id.clone(),setup);self.save()?;
            let path=self.ensure_profile(&id,&profile)?;self.registry.setups.get_mut(&id).unwrap().result["profile_path"]=json!(path);self.registry.active_by_scope.insert(format!("{handle}:{ws}"),id.clone());self.registry.active=Some(id.clone());self.save()?;
        }
        if let Some(mut blocker)=blocker{blocker.details=Some(json!({"alias":alias,"workspace_id":ws,"next_action":"REQUEST_MEANINGFUL_TARGET_ROLE_OR_GRANT","old_operations_preserved":true,"remote_grants_changed":false}));return Err(blocker);}
        if !parent.operations.contains("structure.instance.records.read")||parent.protocol_digests.is_some(){let mut error=local("PROTOCOL_READ_CAPABILITY_REQUIRED");error.details=Some(json!({"next_actor":"LOCAL_RUNTIME_OWNER","missing_operations":["structure.instance.records.read"],"old_operations_preserved":true}));return Err(error);}
        Ok(json!({"state":"PROTOCOL_VIEWS_REFRESHED","setup_id":id,"remote_grants_changed":false,"original_operations_preserved":true}))
    }
}
