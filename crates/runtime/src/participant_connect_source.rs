//! Existing profiles enter Connect without changing their engine or pending work.
//! Source access is not issuer authority: only an explicit local-owner selection
//! can replace an unknown restriction. Ordinary MCP never selects owner paths.
use super::*;

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileSource {
    profile:AgentProfile,
    binding:Value,
    participant:String,
    #[serde(default)]
    owner_config:Option<PathBuf>,
}
fn digest(profile:&AgentProfile)->Result<String> {
    profile.validate()?;
    Ok(sha256_hex(&serde_json::to_vec(profile).map_err(|_|local("AGENT_PROFILE_INVALID"))?))
}
fn workspaces(profile:&AgentProfile)->std::collections::BTreeSet<String>{
    profile.workspaces.values().cloned().chain(profile.scopes.values().map(|s|s.workspace_id.clone()))
        .chain(profile.send_scopes.values().map(|s|s.workspace_id.clone()))
        .chain(profile.protocols.values().filter_map(|s|s.workspace_id.clone())).collect()
}
impl Connect {
    pub(crate) fn profile_directory(profile:&AgentProfile)->Result<PathBuf>{
        Ok(profile.endpoint_path.parent().ok_or_else(||local("CLIENT_BINDING_INVALID"))?
            .join(format!("connect-source-{}",&digest(profile)?[..24])))
    }
    /// Only bounded known locations are examined; no key/config discovery scan.
    pub(crate) fn profile_source(profile:&AgentProfile)->Result<Option<(PathBuf,String)>>{
        let id=digest(profile)?;
        let mut directories=vec![Self::profile_directory(profile)?];
        if let Some(runtime)=profile.endpoint_path.parent(){
            if runtime.file_name().and_then(|name|name.to_str()).is_some_and(|name|name.starts_with("runtime-")) {
                if let Some(original)=runtime.parent(){directories.push(original.to_owned());}
            }
        }
        for directory in directories {
            if !directory.join("connect.state").try_exists().map_err(|_|local("CONNECT_RECOVERY_REQUIRED"))? {continue;}
            let connect=Self::inspect(&directory)?;
            if let Some(source)=connect.registry.profile_sources.get(&id){
                if serde_json::to_value(&source.profile).ok()!=serde_json::to_value(profile).ok(){return Err(local("ORIGINAL_PROFILE_SOURCE_CHANGED"));}
                return Ok(Some((directory,source.participant.clone())));
            }
            // A generated immutable profile can recover its original Setup
            // association. Matching file layout alone never grants authority.
            if let Some(setup)=connect.registry.setups.values().find(|s|s.profile.as_ref().is_some_and(|p|serde_json::to_value(p).ok()==serde_json::to_value(profile).ok())) {
                return Ok(Some((directory,setup.desired.participant.clone())));
            }
        }
        Ok(None)
    }
    pub(crate) fn profile_continuation(_profile:&AgentProfile)->Value {
        json!({"tool":"peerwork_connect","next_actor":"LOCAL_RUNTIME_OWNER","workspace_approval_required":false,
            "code":"ORIGINAL_ISSUER_SELECTION_REQUIRED","missing_fields":["original_issuer_or_runtime_config","explicit_local_policy"],
            "native_arguments":["connect","--profile","ORIGINAL_PROFILE","--runtime-config","ORIGINAL_RUNTIME_CONFIG","--adopt-policy","inherit-engine"],
            "alternative_native_arguments":["connect","--profile","ORIGINAL_PROFILE","--issuer","ORIGINAL_ISSUER_ENDPOINT","--adopt-policy","inherit-issuer"],
            "existing_operations":"PRESERVED","restriction_provenance":"NOT_ASSUMED"})
    }
    pub(crate) fn participant_identity(&self,handle:&str)->Option<(String,String)> {
        self.registry.participants.get(handle).map(|registration|(registration.actor_id.clone(),registration.origin.clone()))
    }
    pub(crate) fn source_handle(&self,profile:&AgentProfile)->Result<Option<String>> {
        if let Some(source)=self.registry.profile_sources.get(&digest(profile)?){return Ok(Some(source.participant.clone()));}
        Ok(self.registry.setups.values().find(|s|s.profile.as_ref().is_some_and(|p|serde_json::to_value(p).ok()==serde_json::to_value(profile).ok())).map(|s|s.desired.participant.clone()))
    }
    pub(super) fn check_source_alias(&self,handle:&str,alias:&str)->Result<()> {
        if self.registry.profile_sources.values().filter(|source|source.participant==handle).any(|source|
            source.profile.protocol_endpoints.get(alias).is_some_and(|endpoint|endpoint!=&source.profile.endpoint_path)) {
            let mut error=local("LOCAL_DELEGATION_PROVENANCE_REQUIRED");
            error.details=Some(json!({"protocol":alias,"restricted_by":"INDEPENDENT_PROTOCOL_CLIENT","remote_permission_checked":false,
                "next_actor":"LOCAL_RUNTIME_OWNER","next_action":"SELECT_THE_ORIGINAL_PROTOCOL_ISSUER","existing_operations":"PRESERVED"}));
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn selected_profile_binding(&self,handle:Option<&str>,profile:&AgentProfile)->Result<Option<Value>> {
        let Some(handle)=self.selected_handle(handle)? else{return Ok(None);};
        Ok(self.registry.participants.get(&handle).filter(|r|r.endpoint_path==profile.endpoint_path)
            .and_then(|_|self.registry.verified_bindings.get(&handle)).cloned())
    }
    pub(crate) fn profile_source_binding(&self,profile:&AgentProfile)->Result<Option<Value>> {
        Ok(self.registry.profile_sources.get(&digest(profile)?).map(|source|source.binding.clone()))
    }
    pub(crate) async fn verify_profile_source(&self,profile:&AgentProfile)->Result<()> {
        if let Some(source)=self.registry.profile_sources.get(&digest(profile)?) {
            RuntimeClient::connect_bound(profile.endpoint_path.clone(),&profile.expected_origin,&profile.expected_actor,source.binding.clone()).await?;
        }
        Ok(())
    }
    /// Local tool attachment always preserves the selected ceiling. An issuer
    /// replacement is exclusively invoked by the native local-owner entry.
    pub(crate) async fn adopt_profile(&mut self,profile:&AgentProfile,issuer:Option<PathBuf>,inherit:bool)->Result<String>{
        self.require_writer()?;
        let id=digest(profile)?;
        let source=RuntimeClient::connect(profile.endpoint_path.clone(),&profile.expected_origin,&profile.expected_actor).await?;
        let binding=crate::communication_runtime::canonical_binding(&source.call(json!({"method":"binding"})).await?);
        if let Some(old)=self.registry.profile_sources.get(&id){
            if old.binding!=binding{return Err(local("ORIGINAL_RUNTIME_BINDING_CHANGED"));}
            if issuer.is_none(){return Ok(old.participant.clone());}
        }
        let endpoint=issuer.unwrap_or_else(||profile.endpoint_path.clone());
        if endpoint!=profile.endpoint_path&&!inherit{return Err(local("LOCAL_OWNER_ADOPTION_POLICY_REQUIRED"));}
        let original=RuntimeClient::connect(endpoint.clone(),&profile.expected_origin,&profile.expected_actor).await?;
        let issuer_binding=original.call(json!({"method":"binding"})).await?;
        for field in ["actor_id","origin","engine_digest","state_binding"] {
            if issuer_binding[field]!=binding[field]{return Err(local("ORIGINAL_ISSUER_BINDING_MISMATCH"));}
        }
        let handle=format!("source-{}",&sha256_hex(json!([id,crate::communication_runtime::canonical_binding(&issuer_binding)]).to_string().as_bytes())[..24]);
        self.register_pinned(&handle,Registration{origin:profile.expected_origin.clone(),actor_id:profile.expected_actor.clone(),endpoint_path:endpoint.clone()},Some(crate::communication_runtime::canonical_binding(&issuer_binding)),None).await?;
        let mut next=profile.clone();
        if endpoint!=profile.endpoint_path {
            next.endpoint_path=endpoint.clone();
            // Runtime bindings use canonical Origins. Preserve the source file
            // and its digest, but bind the new recovery-bearing view to the
            // authenticated canonical spelling rather than a caller's URL text.
            next.expected_origin=original.origin().to_owned();
            if !profile.scopes.is_empty() && next.receive_endpoint_path.is_none(){next.receive_endpoint_path=Some(profile.endpoint_path.clone());}
            for path in next.directory_endpoints.values_mut().chain(next.protocol_endpoints.values_mut()) {
                if *path==profile.endpoint_path {*path=endpoint.clone();}
            }
            for workspace in workspaces(profile) {next.directory_endpoints.entry(workspace).or_insert_with(||endpoint.clone());}
            self.retain_recovery_views(Some(profile),&mut next).await?;
            // One namespace may contain operations in several Workspaces. Keep
            // an exact scoped recovery route for each rather than guessing the
            // first alias's Workspace when recovering another operation.
            for workspace_id in workspaces(profile) {
                let key=format!("source-recovery-{}",&sha256_hex(json!([binding,workspace_id]).to_string().as_bytes())[..32]);
                if !next.recovery_views.contains_key(&key)&&next.recovery_views.len()>=32{return Err(local("RECOVERY_VIEW_LIMIT_PRESERVE_ORIGINAL_OPERATIONS"));}
                next.recovery_views.insert(key,crate::agent_tools::RecoveryView{workspace_id,endpoint_path:profile.endpoint_path.clone(),binding:binding.clone()});
            }
        }
        next.validate()?;
        for workspace in workspaces(profile) {
            let alias=profile.workspaces.iter().find(|(_,w)|**w==workspace).map(|(a,_)|a.clone()).unwrap_or_else(||"workspace".into());
            let setup_id=format!("source-{}",&sha256_hex(json!([id,handle,workspace]).to_string().as_bytes())[..32]);
            let request=ConnectRequest{setup_id:setup_id.clone(),participant:handle.clone(),workspace_id:workspace.clone(),alias,
                send:false,receive:false,receive_mode:None,require_body_keys:false,request_membership:false,protocols:vec![],management:vec![],contacts:vec![],host:None};
            if !self.registry.setups.contains_key(&setup_id){self.begin_setup(&request,self.registry.participants[&handle].clone(),false,None)?;}
            // SERVICE_CURRENT here means no generated restriction is inferred.
            // All original endpoint limits are retained unless owner-selected.
            self.record(&request,json!({"state":"LOCAL_ATTACHED","setup_id":setup_id,"client_authority_model":"SERVICE_CURRENT",
                "source_policy":if inherit{"EXPLICIT_LOCAL_ISSUER"}else{"PRESERVE_ORIGINAL"},"remote_changes_submitted":false}),Some(next.clone()))?;
            self.ensure_profile(&setup_id,&next)?;
            self.registry.active_by_scope.insert(format!("{handle}:{workspace}"),setup_id.clone());self.registry.active=Some(setup_id);
        }
        if !self.registry.profile_sources.contains_key(&id)&&self.registry.profile_sources.len()>=8{return Err(local("LOCAL_PARTICIPANT_LIMIT"));}
        self.registry.profile_sources.insert(id,ProfileSource{profile:profile.clone(),binding,participant:handle.clone(),owner_config:None});
        self.registry.selected_source=Some(handle.clone());
        self.save()?;Ok(handle)
    }
    pub(crate) async fn adopt_from_owner(&mut self,profile:&AgentProfile,config_path:PathBuf)->Result<String>{
        let id=digest(profile)?;
        if let Some(source)=self.registry.profile_sources.get(&id).filter(|source|source.owner_config.as_ref()==Some(&config_path)) {
            self.verify_profile_source(profile).await?;self.original_client(&source.participant).await?;
            return Ok(source.participant.clone());
        }
        if let Some(owned)=self.registry.profile_upgrades.get(&id).cloned() {
            if owned.path()!=config_path{return Err(local("ORIGINAL_RUNTIME_CONFIG_CHANGED"));}
            let ready=RuntimeClient::connect(profile.endpoint_path.clone(),&profile.expected_origin,&profile.expected_actor).await;
            if ready.is_err(){owned.stop().await?;owned.restart(&owned.config).await?;}
        }
        let handle=self.adopt_profile(profile,None,false).await?;
        let config:crate::communication_runtime::RuntimeConfig=serde_json::from_value(crate::communication_store::private_json(&config_path,65536)
            .map_err(|_|local("RUNTIME_CONFIG_NOT_PRIVATE"))?).map_err(|_|local("RUNTIME_CONFIG_INVALID"))?;
        let selection=RuntimeSelection{admin_endpoint:config.state_directory.join("admin.json"),config_path:Some(config_path.clone())};
        let owned=self.runtime_for_source(&handle,&selection).await?;
        let admin=selection.admin_endpoint.clone();
        let status=crate::communication_runtime::call(&admin,json!({"method":"status"})).await?;
        if !status["value"]["optional_features"].as_array().is_some_and(|fs|fs.iter().any(|f|f=="source-client-adoption-v1")) {
            // Persist the original config before stopping: retries never choose
            // another engine or synthesize an empty journal after interruption.
            self.registry.profile_upgrades.insert(id.clone(),owned.clone());self.save()?;
            owned.stop().await?;owned.restart(&owned.config).await?;
        }
        let source=self.original_client(&handle).await?;
        let binding=source.call(json!({"method":"binding"})).await?;
        let spaces=workspaces(profile);
        if spaces.is_empty(){return Err(local("PROFILE_ADOPTION_WORKSPACE_REQUIRED"));}
        let result=crate::communication_runtime::call(&admin,json!({"method":"client_adopt","adoption":{"source_binding":binding,
            "workspace_ids":spaces,"alias":format!("profile-{}",&id[..24]),"policy":"INHERIT_ENGINE_FOR_WORKSPACES"}})).await?;
        if result["ok"]!=true{return Err(serde_json::from_value(result["error"].clone()).unwrap_or_else(|_|local("LOCAL_OWNER_ADOPTION_FAILED")));}
        let endpoint=result["value"]["endpoint_path"].as_str().ok_or_else(||local("DERIVED_ENDPOINT_INVALID"))?;
        let handle=self.adopt_profile(profile,Some(PathBuf::from(endpoint)),true).await?;
        self.registry.profile_sources.get_mut(&id).ok_or_else(||local("CONNECT_RECOVERY_REQUIRED"))?.owner_config=Some(config_path);
        self.registry.profile_upgrades.remove(&id);self.save()?;Ok(handle)
    }
}

#[cfg(test)]
#[path="participant_connect_source_tests.rs"]
mod tests;
