//! Local projections for one stable public alias. Every credential stays
//! immutable; old namespaces remain available for exact-operation recovery.
use super::*;
use crate::agent_tools::{ProtocolView,ProtocolViewScope,MAX_PROTOCOL_VIEWS};
pub(super) const AUTHORITY_REVISION:u64=2;
impl Connect {
    /// Continue a sealed managed bootstrap or recorded Owner inheritance
    /// through its original issuer. Arbitrary clients remain explicit delegates.
    pub(super) async fn scoped_issuer(&mut self,participant:&str,workspace:&str,client:RuntimeClient,caps:&Value)->Result<RuntimeClient> {
        let capability=Capability::from_observation(caps)?;
        if capability.operations.contains("*"){return Ok(client);}
        let source_owner=self.source_owner_config(participant);
        let (admin,workspaces)=if let Some(path)=source_owner {
            if capability.instance_ids.is_some() || capability.protocol_digests.is_some()
                || capability.business_actions.is_some() || capability.mailbox_ids.is_some() {return Ok(client);}
            let config:crate::communication_runtime::RuntimeConfig=serde_json::from_value(crate::communication_store::private_json(&path,65536)
                .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?;
            let selection=RuntimeSelection{admin_endpoint:config.state_directory.join("admin.json"),config_path:Some(path)};
            self.runtime_for_source(participant,&selection).await?;
            let workspaces=capability.workspace_ids.clone().filter(|spaces|spaces.contains(workspace)).ok_or_else(||local("ORIGINAL_ISSUER_BINDING_MISMATCH"))?;
            (selection.admin_endpoint,workspaces)
        }else{
            let native=self.directory.join(format!("runtime-{participant}"));
            if self.registry.local_runtime_admins.get(participant)!=Some(&native.join("admin.json"))
                || self.registry.participants.get(participant).is_none_or(|registration|registration.endpoint_path!=native.join("client-bootstrap.json")) {return Ok(client);}
            let owned=bootstrap::owned_runtime(self,participant)?;
            if owned.config.clients.len()!=1 || owned.config.clients[0].name!="bootstrap"
                || capability.workspace_ids.is_some() || !capability.allow_root
                || capability.instance_ids.is_some() || capability.protocol_digests.is_some()
                || capability.business_actions.is_some() || capability.mailbox_ids.is_some() {return Ok(client);}
            (owned.config.state_directory.join("admin.json"),[workspace.to_owned()].into())
        };
        if !caps["features"].as_array().is_some_and(|values|values.iter().any(|value|value=="service-operation-policy-v1")) {
            let mut error=local("LOCAL_RUNTIME_UPGRADE_REQUIRED");
            error.details=Some(json!({"next_action":"UPGRADE_SELECTED_RUNTIME_PRESERVING_ORIGINAL_STATE","missing_features":["service-operation-policy-v1"],"remote_changes_submitted":false}));
            return Err(error);
        }
        let binding=client.call(json!({"method":"binding"})).await?;
        let adopted=crate::communication_runtime::call(&admin,json!({"method":"client_adopt","adoption":{
            "source_binding":binding,"workspace_ids":workspaces,"alias":format!("service-space-{}",&sha256_hex(json!([participant,workspaces]).to_string().as_bytes())[..32]),"policy":"INHERIT_ENGINE_FOR_WORKSPACES"}})).await?;
        if adopted["ok"]!=true{return Err(serde_json::from_value(adopted["error"].clone()).unwrap_or_else(|_|local("LOCAL_OWNER_ADOPTION_FAILED")));}
        let path=adopted["value"]["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?;
        RuntimeClient::connect(PathBuf::from(path),client.origin(),client.actor_id()).await
    }
    pub(crate) fn authority_refreshes(&self,participant:Option<&str>,workspace:Option<&str>)->Result<Vec<String>> {
        let Some(handle)=self.selected_handle(participant)? else{return Ok(vec![]);};
        Ok(self.registry.active_by_scope.values().filter_map(|id|self.registry.setups.get(id).map(|setup|(id,setup)))
            .filter(|(_,setup)|setup.desired.participant==handle && workspace.is_none_or(|ws|ws==setup.desired.workspace_id) && self.generated_authority_candidate(setup))
            .map(|(id,_)|id.clone()).collect())
    }
    pub(crate) async fn normalize_selected_authority(&mut self,ids:&[String])->Result<()> {
        self.require_writer()?;
        for id in ids {self.normalize_cached_authority(id).await?;}
        Ok(())
    }
    pub(crate) fn workspace_profile_refreshable(&self, participant:Option<&str>, workspace:&str)->Result<bool> {
        let Some(handle)=self.selected_handle(participant)? else {return Ok(false);};
        let Some(setup)=self.registry.active_by_scope.get(&format!("{handle}:{workspace}")).and_then(|id|self.registry.setups.get(id)) else {return Ok(false);};
        Ok(self.generated_authority_candidate(setup))
    }
    fn owner_adopted(&self,setup:&Setup)->bool {
        setup.result["source_policy"]=="EXPLICIT_LOCAL_ISSUER" && self.source_owner_config(&setup.desired.participant).is_some()
    }
    fn generated_authority_candidate(&self,setup:&Setup)->bool {
        setup.result["client_authority_revision"]!=AUTHORITY_REVISION
            && (setup.result.get("source_policy").is_none() || self.owner_adopted(setup))
            && setup.profile.as_ref().is_some_and(|profile|self.owner_adopted(setup)||!profile.protocol_endpoints.keys().any(|alias|!setup.protocol_intents.contains_key(alias)&&!setup.desired.protocols.iter().any(|p|p.alias==*alias)))
    }
    pub(super) async fn establish_baseline(&mut self, request:&ConnectRequest, selected:&Registration, parent:&Capability, client:&RuntimeClient, membership:&str)->Result<()> {
        if let Some(profile)=self.registry.setups[&request.setup_id].profile.as_ref() {
            profile.validate()?;
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
            setup.result["client_authority_revision"]=existing.result["client_authority_revision"].clone();
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
        setup.profile=Some(profile.clone());setup.sender_capability=Some(capability);setup.result["client_authority_model"]=json!("SERVICE_CURRENT");setup.result["client_authority_revision"]=json!(AUTHORITY_REVISION);
        self.save()?;
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
    pub(super) fn check_requested_actions(parent:&Capability,protocols:&[ProtocolSelection])->Result<()>{
        let Some(allowed)=&parent.business_actions else{return Ok(());};
        let missing:std::collections::BTreeSet<_>=protocols.iter().flat_map(|p|p.actions.iter()).filter(|a|!allowed.contains(*a)).cloned().collect();
        if missing.is_empty(){return Ok(());}
        let mut error=local("LOCAL_SCOPE_DENIED");error.phase="AUTHORIZATION".into();error.recovery="REVIEW_EXPLICIT_LOCAL_CAPABILITY".into();
        error.details=Some(json!({"restricted_by":"business_actions","missing_actions":missing,"next_actor":"LOCAL_RUNTIME_OWNER","remote_permission_checked":false}));Err(error)
    }
    pub(super) async fn normalize_cached_authority(&mut self,id:&str)->Result<String>{
        let old=self.registry.setups[id].clone();
        if !self.generated_authority_candidate(&old){return Ok(id.into());}
        let owner_adopted=self.owner_adopted(&old);
        let previous=old.profile.as_ref().unwrap();
        // Unknown/custom aliases are not proof of software-generated ceilings.
        if !owner_adopted && previous.protocol_endpoints.keys().any(|alias|!old.protocol_intents.contains_key(alias)&&!old.desired.protocols.iter().any(|p|p.alias==*alias)){return Ok(id.into());}
        let client=self.original_client(&old.desired.participant).await?;
        let caps=client.call(json!({"method":"capabilities"})).await?;
        if !missing_runtime_features(&caps).is_empty(){let mut e=local("LOCAL_RUNTIME_UPGRADE_REQUIRED");e.details=Some(json!({"tools_available":true,"existing_configuration_preserved":true,"next_actor":"LOCAL_RUNTIME_OWNER","next_action":"UPGRADE_SELECTED_RUNTIME_PRESERVING_ORIGINAL_STATE"}));return Err(e);}
        let client=self.scoped_issuer(&old.desired.participant,&old.desired.workspace_id,client,&caps).await?;
        let caps=client.call(json!({"method":"capabilities"})).await?;
        let parent:Capability=Capability::from_observation(&caps)?;
        let source=RuntimeClient::connect(previous.endpoint_path.clone(),&previous.expected_origin,&previous.expected_actor).await?;
        let binding=source.call(json!({"method":"binding"})).await?;
        let mut cap=parent.clone();cap.allow_root=false;if !owner_adopted {cap.workspace_ids=Some([old.desired.workspace_id.clone()].into());}
        let name=format!("ordinary-{}",&sha256_hex(json!([old.desired.participant,binding["namespace"],cap]).to_string().as_bytes())[..40]);
        let derived=client.call(json!({"method":"derive","name":name,"capability":cap,"source_binding":binding})).await?;
        let path=PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?);
        let mut profile=previous.clone();profile.endpoint_path=path.clone();
        if owner_adopted {for endpoint in profile.directory_endpoints.values_mut(){if *endpoint==previous.endpoint_path {*endpoint=path.clone();}}}
        profile.directory_endpoints.insert(old.desired.workspace_id.clone(),path.clone());
        for(alias,scope)in &profile.protocols {
            let selected=if owner_adopted {scope.workspace_id.as_ref().is_some_and(|ws|cap.workspace_ids.as_ref().is_some_and(|spaces|spaces.contains(ws)))&&profile.protocol_endpoints.get(alias)==Some(&previous.endpoint_path)}else{scope.workspace_id.as_deref()==Some(&old.desired.workspace_id)};
            if selected {profile.protocol_endpoints.insert(alias.clone(),path.clone());}
        }
        self.retain_recovery_views(Some(previous),&mut profile).await?;
        self.extend_protocol_views(&old.desired.participant,Some(previous),&mut profile,&parent,&client).await?;
        profile.validate()?;
        let revision=format!("authority-{}",&sha256_hex(&serde_json::to_vec(&json!([old.desired.workspace_id,profile])).map_err(|_|local("DERIVED_PROFILE_INVALID"))?)[..32]);
        if !self.registry.setups.contains_key(&revision){
            if self.registry.setups.len()>=64{return Err(local("SETUP_LIMIT"));}
            let mut next=old.clone();next.desired.setup_id=revision.clone();next.digest=sha256_hex(&serde_json::to_vec(&next.desired).map_err(|_|local("CONNECT_ARGUMENT_INVALID"))?);
            next.profile=Some(profile.clone());next.sender_capability=Some(cap);next.result["setup_id"]=json!(revision);next.result["client_authority_model"]=json!("SERVICE_CURRENT");
            self.registry.setups.insert(revision.clone(),next);self.save()?;
        }
        self.registry.setups.get_mut(&revision).unwrap().result["client_authority_revision"]=json!(AUTHORITY_REVISION);
        self.registry.setups.get_mut(&revision).unwrap().result.as_object_mut().unwrap().remove("profile_path");
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
        if let Some(previous)=self.registry.active_by_scope.get(&format!("{participant}:{workspace}")).and_then(|id|self.registry.setups.get(id)).and_then(|setup|setup.profile.as_ref()) {
            let original=RuntimeClient::connect(previous.endpoint_path.clone(),client.origin(),client.actor_id()).await?;
            let observed=Capability::from_observation(&original.call(json!({"method":"capabilities"})).await?)?;
            if observed==cap {
                let source=original.call(json!({"method":"binding"})).await?;
                let issuer=client.call(json!({"method":"binding"})).await?;
                let same_engine=["actor_id","origin","state_binding","engine_digest"].iter().all(|field|source[*field]==issuer[*field]);
                let own_namespace=issuer["namespace"].as_str().zip(source["namespace"].as_str()).is_some_and(|(parent,child)|child==parent||child.starts_with(&format!("{parent}:")));
                if same_engine && own_namespace {return Ok((cap,previous.endpoint_path.clone()));}
            }
        }
        if &cap==parent {return Ok((cap,client.endpoint_path().to_owned()));}
        let name=format!("workspace-{}",&sha256_hex(json!([participant,workspace,cap]).to_string().as_bytes())[..40]);
        let derived=client.call(json!({"method":"derive","name":name,"capability":cap})).await?;
        let path=PathBuf::from(derived["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?);
        Ok((cap,path))
    }
    async fn capture_protocol_view(&self,alias:&str,mut scope:Scope,path:PathBuf,read_only:bool,context:Option<String>,profile:&AgentProfile)->Result<(String,ProtocolView)>{
        let client=RuntimeClient::connect(path.clone(),&profile.expected_origin,&profile.expected_actor).await?;
        let binding=crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?);
        let caps=client.call(json!({"method":"capabilities"})).await?;
        let cap:Capability=Capability::from_observation(&caps)?;
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
        self.check_source_alias(&handle,alias)?;
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
        let original=self.scoped_issuer(&handle,&ws,original,&caps).await?;
        let caps=original.call(json!({"method":"capabilities"})).await?;
        if self.registry.setups[&active].result["client_authority_model"]!="SERVICE_CURRENT"{return Err(local("LOCAL_DELEGATION_PROVENANCE_REQUIRED"));}

        let parent:Capability=Capability::from_observation(&caps)?;
        self.extend_protocol_views(&handle,Some(&old),&mut profile,&parent,&original).await?;
        let mut query=json!({"instance_id":instance});
        if let Some(ctx)=target.and_then(|v|v["execution_context_id"].as_str()){query["execution_context_id"]=json!(ctx);}
        let observed=read(&original,"structure.instance.resolve",Scope{workspace_id:Some(ws.clone()),..Default::default()},query).await?;
        let selected=if target.and_then(|v|v["execution_context_id"].as_str()).is_some(){&observed["binding"]}else{&observed["default_binding"]};
        let protocol=selected["protocol_digest"].as_str().or_else(||observed["instance"]["protocol_digest"].as_str()).ok_or_else(||local("PROTOCOL_RESOLUTION_FAILED"))?.to_owned();
        let context=selected["execution_context_id"].as_str().map(str::to_owned);
        let actual=Scope{workspace_id:Some(ws.clone()),instance_id:Some(instance),protocol_digest:Some(protocol)};
        let (cap,ordinary)=self.workspace_client(&handle,&ws,&parent,&original).await?;
        let path=ordinary.clone();
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
            self.registry.setups.get_mut(&id).unwrap().result.as_object_mut().unwrap().remove("profile_path");self.registry.active_by_scope.insert(format!("{handle}:{ws}"),id.clone());self.registry.active=Some(id.clone());self.save()?;
        }
        Ok(json!({"state":"PROTOCOL_VIEWS_REFRESHED","setup_id":id,"remote_grants_changed":false,"original_operations_preserved":true}))
    }
}
