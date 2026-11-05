//! Local projections for one stable public alias. Every credential stays
//! immutable; old namespaces remain available for exact-operation recovery.
use super::*;
use crate::agent_tools::{ProtocolView,ProtocolViewScope,MAX_PROTOCOL_VIEWS};
const READS:&[&str]=&["structure.instance.records.read","structure.instance.get","structure.instance.resolve","structure.protocol.resolve","structure.protocol.resource.get","structure.record.get","structure.records.read"];
impl Connect {
    pub(super) async fn workspace_client(&self,participant:&str,workspace:&str,parent:&Capability,client:&RuntimeClient)->Result<(Capability,PathBuf)>{
        let mut cap=parent.clone();cap.allow_root=false;cap.workspace_ids=Some([workspace.to_owned()].into());
        let name=format!("workspace-{}",&sha256_hex(json!([participant,workspace,cap]).to_string().as_bytes())[..40]);
        let derived=client.call(json!({"method":"derive","name":name,"capability":cap})).await?;
        let path=PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?);
        Ok((cap,path))
    }
    pub(super) async fn protocol_endpoint(&self,participant:&str,alias:&str,scope:&Scope,explicit:&[String],parent:&Capability,ordinary:&Path,client:&RuntimeClient)->Result<PathBuf>{
        if explicit.is_empty(){return Ok(ordinary.to_owned());}
        let mut cap=parent.clone();cap.instance_ids=Some([scope.instance_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?].into());
        cap.protocol_digests=Some([scope.protocol_digest.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?].into());
        cap.business_actions=Some(explicit.iter().filter(|action|parent.business_actions.as_ref().is_none_or(|allowed|allowed.contains(*action))).cloned().collect());
        cap.mailbox_ids=Some(Default::default());
        cap.operations.retain(|op|op=="structure.action"||READS.contains(&op.as_str())&&op!="structure.instance.records.read");
        let name=format!("delegate-{}",&sha256_hex(json!([participant,alias,cap]).to_string().as_bytes())[..40]);
        let derived=client.call(json!({"method":"derive","name":name,"capability":cap})).await?;
        Ok(PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?))
    }
    async fn capture_protocol_view(&self,alias:&str,mut scope:Scope,path:PathBuf,read_only:bool,context:Option<String>,profile:&AgentProfile)->Result<(String,ProtocolView)>{
        let client=RuntimeClient::connect(path.clone(),&profile.expected_origin,&profile.expected_actor).await?;
        let binding=crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?);
        let caps=client.call(json!({"method":"capabilities"})).await?;
        let cap:Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|local("LOCAL_CEILING_INVALID"))?;
        // A logical alias can now point at a newer default, while its original
        // endpoint remains pinned to an older execution for pending recovery.
        // Persist the endpoint's actual immutable ceiling, not that alias's
        // mutable selected digest.
        for (allowed,selected) in [(&cap.workspace_ids,&scope.workspace_id),(&cap.instance_ids,&scope.instance_id)] {
            if selected.as_ref().is_none_or(|value|allowed.as_ref().is_some_and(|set|!set.contains(value))){return Err(local("PROTOCOL_VIEW_SCOPE_INVALID"));}
        }
        if read_only {scope.protocol_digest=None;}
        else if let Some(allowed)=&cap.protocol_digests {
            if scope.protocol_digest.as_ref().is_none_or(|digest|!allowed.contains(digest)){return Err(local("PROTOCOL_VIEW_SCOPE_INVALID"));}
        }
        let id=format!("protocol-view-{}",&sha256_hex(json!([alias,read_only,scope,context,binding]).to_string().as_bytes())[..40]);
        Ok((id,ProtocolView{selected:ProtocolViewScope{alias:alias.into(),scope,execution_context_id:context,read_only,client_generation:binding["client_generation"].as_u64().unwrap_or(0),binding,actions:cap.business_actions},endpoint_path:path}))
    }
    fn keep_protocol_view(profile:&mut AgentProfile,id:String,view:ProtocolView)->Result<()>{
        if !profile.protocol_views.contains_key(&id)&&profile.protocol_views.len()>=MAX_PROTOCOL_VIEWS{return Err(local("PROTOCOL_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
        if let Some(old)=profile.protocol_views.get(&id){if serde_json::to_value(old).ok()!=serde_json::to_value(&view).ok(){return Err(local("PROTOCOL_VIEW_BINDING_CHANGED"));}}
        profile.protocol_views.insert(id,view);Ok(())
    }
    pub(super) async fn extend_protocol_views(&self,_participant:&str,previous:Option<&AgentProfile>,profile:&mut AgentProfile,_parent:&Capability,_client:&RuntimeClient)->Result<()>{
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
            if let Some(path)=profile.directory_endpoints.get(scope.workspace_id.as_deref().unwrap_or("")) {
                let read_scope=Scope{protocol_digest:None,..scope};
                let(id,view)=self.capture_protocol_view(&alias,read_scope,path.clone(),true,None,profile).await?;
                Self::keep_protocol_view(profile,id,view)?;
            }
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
        let mut query=json!({"instance_id":instance});
        if let Some(ctx)=target.and_then(|v|v["execution_context_id"].as_str()){query["execution_context_id"]=json!(ctx);}
        let observed=read(&original,"structure.instance.resolve",Scope{workspace_id:Some(ws.clone()),..Default::default()},query).await?;
        let selected=if target.and_then(|v|v["execution_context_id"].as_str()).is_some(){&observed["binding"]}else{&observed["default_binding"]};
        let protocol=selected["protocol_digest"].as_str().or_else(||observed["instance"]["protocol_digest"].as_str()).ok_or_else(||local("PROTOCOL_RESOLUTION_FAILED"))?.to_owned();
        let context=selected["execution_context_id"].as_str().map(str::to_owned);
        let actual=Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance),protocol_digest:Some(protocol)};
        let (cap,ordinary)=self.workspace_client(&handle,&ws,&parent,&original).await?;
        let explicit=desired.as_ref().map(|d|d.actions.as_slice()).unwrap_or_default();
        let path=self.protocol_endpoint(&handle,alias,&actual,explicit,&cap,&ordinary,&original).await?;
        profile.protocols.insert(alias.into(),actual.clone());
        profile.protocol_endpoints.insert(alias.into(),path.clone());
        profile.directory_endpoints.insert(ws.clone(),ordinary);
        let(id,view)=self.capture_protocol_view(alias,actual,path,false,context,&profile).await?;
        Self::keep_protocol_view(&mut profile,id,view)?;
        self.extend_protocol_views(&handle,None,&mut profile,&parent,&original).await?;
        profile.validate()?;
        let id=format!("views-{}",&sha256_hex(serde_json::to_vec(&profile).map_err(|_|local("DERIVED_PROFILE_INVALID"))?.as_slice())[..32]);
        if id!=active {
            let mut setup=self.registry.setups[&active].clone();setup.desired.setup_id=id.clone();setup.digest=sha256_hex(&serde_json::to_vec(&setup.desired).map_err(|_|local("CONNECT_ARGUMENT_INVALID"))?);setup.profile=Some(profile.clone());setup.result["setup_id"]=json!(id);
            if !self.registry.setups.contains_key(&id)&&self.registry.setups.len()>=64{return Err(local("SETUP_LIMIT"));}self.registry.setups.insert(id.clone(),setup);self.save()?;
            let path=self.ensure_profile(&id,&profile)?;self.registry.setups.get_mut(&id).unwrap().result["profile_path"]=json!(path);self.registry.active_by_scope.insert(format!("{handle}:{ws}"),id.clone());self.registry.active=Some(id.clone());self.save()?;
        }
        Ok(json!({"state":"PROTOCOL_VIEWS_REFRESHED","setup_id":id,"remote_grants_changed":false,"original_operations_preserved":true}))
    }
}
