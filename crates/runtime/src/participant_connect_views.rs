//! Local projections for one stable public alias. Every credential stays
//! immutable; old namespaces remain available for exact-operation recovery.
use super::*;
use crate::agent_tools::{ProtocolView,ProtocolViewScope,MAX_PROTOCOL_VIEWS};
const READS:&[&str]=&["structure.instance.records.read","structure.instance.get","structure.instance.resolve","structure.protocol.resolve","structure.protocol.resource.get","structure.record.get","structure.record.relations.read","structure.records.read"];
impl Connect {
    pub(crate) fn workspace_profile_refreshable(&self, participant:Option<&str>, workspace:&str)->Result<bool> {
        let Some(handle)=self.selected_handle(participant)? else {return Ok(false);};
        let Some(setup)=self.registry.active_by_scope.get(&format!("{handle}:{workspace}")).and_then(|id|self.registry.setups.get(id)) else {return Ok(false);};
        Ok(Self::generated_authority_candidate(setup))
    }
    fn generated_authority_candidate(setup:&Setup)->bool {
        setup.result["client_authority_model"]!="SERVICE_CURRENT"
            && setup.profile.as_ref().is_some_and(|profile|!profile.protocol_endpoints.keys().any(|alias|!setup.protocol_intents.contains_key(alias)&&!setup.desired.protocols.iter().any(|p|p.alias==*alias)))
    }
    pub(super) async fn establish_baseline(&mut self, request:&ConnectRequest, selected:&Registration, parent:&Capability, client:&RuntimeClient, membership:&str)->Result<()> {
        if let Some(profile)=self.registry.setups[&request.setup_id].profile.as_ref() {
            self.ensure_profile(&request.setup_id,profile)?;
            let key=format!("{}:{}",request.participant,request.workspace_id);
            if !self.registry.active_by_scope.contains_key(&key) {
                self.registry.active_by_scope.insert(key,request.setup_id.clone());
                self.registry.active=Some(request.setup_id.clone());self.save()?;
            }
            return Ok(());
        }
        let existing=self.registry.active_by_scope.get(&format!("{}:{}",request.participant,request.workspace_id))
            .and_then(|id|self.registry.setups.get(id)).filter(|setup|setup.registration==*selected&&setup.profile.is_some()).cloned();
        if let Some(existing)=existing {
            let setup=self.registry.setups.get_mut(&request.setup_id).unwrap();
            setup.profile=existing.profile;setup.sender_capability=existing.sender_capability;
            setup.result["client_authority_model"]=existing.result["client_authority_model"].clone();
            return self.save();
        }
        let (capability,endpoint)=self.workspace_client(&request.participant,&request.workspace_id,parent,client).await?;
        let profile=AgentProfile{format:"peerwork.agent-profile.v1".into(),endpoint_path:endpoint.clone(),expected_origin:selected.origin.clone(),expected_actor:selected.actor_id.clone(),
            workspaces:[(request.alias.clone(),request.workspace_id.clone())].into(),
            send_scopes:[(request.alias.clone(),SendScope{workspace_id:request.workspace_id.clone(),membership_id:membership.into()})].into(),
            directory_endpoints:[(request.workspace_id.clone(),endpoint)].into(),
            protocols:Default::default(),protocol_endpoints:Default::default(),scopes:Default::default(),contacts:Default::default(),receive_endpoint_path:None,
            recovery_views:Default::default(),protocol_views:Default::default(),management_views:Default::default()};
        profile.validate()?;
        let setup=self.registry.setups.get_mut(&request.setup_id).unwrap();
        setup.profile=Some(profile.clone());setup.sender_capability=Some(capability);setup.result["client_authority_model"]=json!("SERVICE_CURRENT");
        self.save()?;
        self.ensure_profile(&request.setup_id,&profile)?;
        self.registry.active_by_scope.insert(format!("{}:{}",request.participant,request.workspace_id),request.setup_id.clone());
        self.registry.active=Some(request.setup_id.clone());self.save()
    }
    pub(crate) async fn refresh_workspace_profile(&mut self,participant:Option<&str>,workspace:&str)->Result<bool>{
        self.require_writer()?;
        let handle=self.selected_handle(participant)?.ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let active=self.registry.active_by_scope.get(&format!("{handle}:{workspace}")).cloned().ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        // Only the registered original parent can replace a known generated
        // ceiling. Custom and explicit delegations retain the normalizer's
        // provenance checks and are never enlarged from the denied endpoint.
        Ok(self.normalize_cached_authority(&active).await?!=active)
    }
    pub(super) fn inherited_explicit_actions(parent:&Capability,actions:&[String])->bool{actions.is_empty()||parent.business_actions.as_ref()==Some(&actions.iter().cloned().collect())}
    pub(super) fn explicit_setup(setup:&Setup)->bool{setup.profile.is_some()&&setup.result["client_authority_model"]!="SERVICE_CURRENT"&&setup.protocol_intents.values().chain(setup.desired.protocols.iter()).any(|p|!p.actions.is_empty())}
    pub(super) fn check_requested_actions(parent:&Capability,protocols:&[ProtocolSelection])->Result<()>{
        let Some(allowed)=&parent.business_actions else{return Ok(());};
        let missing:std::collections::BTreeSet<_>=protocols.iter().flat_map(|p|p.actions.iter()).filter(|a|!allowed.contains(*a)).cloned().collect();
        if missing.is_empty(){return Ok(());}
        let mut error=local("LOCAL_SCOPE_DENIED");error.phase="AUTHORIZATION".into();error.recovery="REVIEW_EXPLICIT_LOCAL_CAPABILITY".into();
        error.details=Some(json!({"restricted_by":"business_actions","missing_actions":missing,"next_actor":"LOCAL_RUNTIME_OWNER","remote_permission_checked":false}));Err(error)
    }
    pub(super) async fn normalize_cached_authority(&mut self,id:&str)->Result<String>{
        let old=self.registry.setups[id].clone();
        if !Self::generated_authority_candidate(&old){return Ok(id.into());}
        let previous=old.profile.as_ref().unwrap();
        // Unknown/custom aliases are not proof of software-generated ceilings.
        if previous.protocol_endpoints.keys().any(|alias|!old.protocol_intents.contains_key(alias)&&!old.desired.protocols.iter().any(|p|p.alias==*alias)){return Ok(id.into());}
        let client=self.original_client(&old.desired.participant).await?;
        let caps=client.call(json!({"method":"capabilities"})).await?;
        if !missing_runtime_features(&caps).is_empty(){let mut e=local("LOCAL_RUNTIME_UPGRADE_REQUIRED");e.details=Some(json!({"tools_available":true,"existing_configuration_preserved":true,"next_actor":"LOCAL_RUNTIME_OWNER","next_action":"UPGRADE_SELECTED_RUNTIME_PRESERVING_ORIGINAL_STATE"}));return Err(e);}
        let parent:Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|local("LOCAL_CEILING_INVALID"))?;
        parent.authorize(&Invoke::new("connect-directory-preflight","structure.members.read",Scope{workspace_id:Some(old.desired.workspace_id.clone()),..Default::default()},json!({"view":"COLLABORATION","limit":1})))?;
        let (cap,path)=self.workspace_client(&old.desired.participant,&old.desired.workspace_id,&parent,&client).await?;
        let mut profile=previous.clone();profile.endpoint_path=path.clone();profile.directory_endpoints.insert(old.desired.workspace_id.clone(),path.clone());
        for(alias,scope)in &profile.protocols{if scope.workspace_id.as_deref()==Some(&old.desired.workspace_id){profile.protocol_endpoints.insert(alias.clone(),path.clone());}}
        self.retain_recovery_views(Some(previous),&mut profile).await?;
        self.extend_protocol_views(&old.desired.participant,Some(previous),&mut profile,&parent,&client).await?;
        profile.validate()?;
        let revision=format!("authority-{}",&sha256_hex(&serde_json::to_vec(&profile).map_err(|_|local("DERIVED_PROFILE_INVALID"))?)[..32]);
        if !self.registry.setups.contains_key(&revision){
            if self.registry.setups.len()>=64{return Err(local("SETUP_LIMIT"));}
            let mut next=old.clone();next.desired.setup_id=revision.clone();next.digest=sha256_hex(&serde_json::to_vec(&next.desired).map_err(|_|local("CONNECT_ARGUMENT_INVALID"))?);
            next.profile=Some(profile.clone());next.sender_capability=Some(cap);next.result["setup_id"]=json!(revision);next.result["client_authority_model"]=json!("SERVICE_CURRENT");
            self.registry.setups.insert(revision.clone(),next);self.save()?;
        }
        let profile_path=self.ensure_profile(&revision,&profile)?;
        self.registry.setups.get_mut(&revision).unwrap().result["profile_path"]=json!(profile_path);
        self.registry.active_by_scope.insert(format!("{}:{}",old.desired.participant,old.desired.workspace_id),revision.clone());self.registry.active=Some(revision.clone());self.save()?;
        Ok(revision)
    }
    pub(super) async fn retain_recovery_views(&self,previous:Option<&AgentProfile>,profile:&mut AgentProfile)->Result<()>{
        let Some(previous)=previous else{return Ok(());};
        let mut paths=vec![(previous.endpoint_path.clone(),previous.selection().workspaces.values().next().cloned().or_else(||previous.scopes.values().next().map(|s|s.workspace_id.clone())).or_else(||previous.send_scopes.values().next().map(|s|s.workspace_id.clone())))];
        paths.extend(previous.directory_endpoints.iter().map(|(ws,path)|(path.clone(),Some(ws.clone()))));
        paths.extend(previous.management_views.values().map(|view|(view.endpoint_path.clone(),Some(view.workspace_id.clone()))));
        for(path,workspace)in paths {
            let Some(workspace_id)=workspace else{continue;};
            if path==profile.endpoint_path||profile.directory_endpoints.values().any(|current|current==&path){continue;}
            let client=RuntimeClient::connect(path.clone(),&profile.expected_origin,&profile.expected_actor).await?;
            let binding=crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?);
            let id=format!("recovery-{}",&sha256_hex(binding.to_string().as_bytes())[..40]);
            if !profile.recovery_views.contains_key(&id)&&profile.recovery_views.len()>=32{return Err(local("RECOVERY_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
            profile.recovery_views.entry(id).or_insert(crate::agent_tools::RecoveryView{workspace_id,endpoint_path:path,binding});
        }
        Ok(())
    }
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
        let id=format!("protocol-view-{}",&sha256_hex(json!([alias,read_only,binding]).to_string().as_bytes())[..40]);
        Ok((id,ProtocolView{selected:ProtocolViewScope{alias:alias.into(),scope,execution_context_id:context,read_only,client_generation:binding["client_generation"].as_u64().unwrap_or(0),binding,actions:cap.business_actions},endpoint_path:path}))
    }
    fn keep_protocol_view(profile:&mut AgentProfile,id:String,view:ProtocolView)->Result<()>{
        if !profile.protocol_views.contains_key(&id)&&profile.protocol_views.len()>=MAX_PROTOCOL_VIEWS{return Err(local("PROTOCOL_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
        if let Some(old)=profile.protocol_views.get(&id){if old.selected.binding!=view.selected.binding||old.endpoint_path!=view.endpoint_path||old.selected.actions!=view.selected.actions||old.selected.read_only!=view.selected.read_only{return Err(local("PROTOCOL_VIEW_BINDING_CHANGED"));}}
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
        let selected_profile=self.profile_for_scope(Some(&handle),workspace)?.ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let scope=selected_profile.protocols.get(alias).cloned().ok_or_else(||local("PROTOCOL_ALIAS_UNKNOWN"))?;
        let ws=scope.workspace_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?;
        let instance=scope.instance_id.clone().ok_or_else(||local("BROKEN_PROTOCOL_BINDING"))?;
        let active=self.registry.active_by_scope.get(&format!("{handle}:{ws}")).cloned().ok_or_else(||local("BROKEN_BINDING"))?;
        let active=self.normalize_cached_authority(&active).await?;
        let mut profile=self.registry.setups[&active].profile.clone().ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let old=profile.clone();
        let original=self.original_client(&handle).await?;let caps=original.call(json!({"method":"capabilities"})).await?;
        if !missing_runtime_features(&caps).is_empty(){return Err(local("LOCAL_RUNTIME_UPGRADE_REQUIRED"));}
        if self.registry.setups[&active].result["client_authority_model"]!="SERVICE_CURRENT"&&!Self::explicit_setup(&self.registry.setups[&active]){return Err(local("LOCAL_DELEGATION_PROVENANCE_REQUIRED"));}

        let parent:Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|local("LOCAL_CEILING_INVALID"))?;
        if Self::explicit_setup(&self.registry.setups[&active])&&self.registry.setups[&active].protocol_intents.values().chain(self.registry.setups[&active].desired.protocols.iter()).any(|p|!Self::inherited_explicit_actions(&parent,&p.actions)){return Err(local("EXPLICIT_DELEGATION_PARENT_REQUIRED"));}
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
        let path=if Self::explicit_setup(&self.registry.setups[&active]){self.protocol_endpoint(&handle,alias,&actual,explicit,&cap,&ordinary,&original).await?}else{ordinary.clone()};
        profile.protocols.insert(alias.into(),actual.clone());
        profile.protocol_endpoints.insert(alias.into(),path.clone());
        profile.directory_endpoints.insert(ws.clone(),ordinary);
        self.retain_recovery_views(Some(&old),&mut profile).await?;
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
