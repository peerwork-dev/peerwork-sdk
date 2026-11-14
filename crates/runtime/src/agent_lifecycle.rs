//! Shared selected-participant lifecycle. Transports only decode and render.
use crate::agent_tools::{self, AgentProfile, AgentRequest, AgentTools};
use crate::participant::{ParticipantError, Result};
use serde_json::{json, Value};
use tokio::sync::{OnceCell,Mutex};
use std::sync::Arc;
pub(crate) struct Lifecycle {
    pub(crate) profile: Option<AgentProfile>,
    pub(crate) local: Option<std::path::PathBuf>,
    pub(crate) handle: Option<String>,
    pub(crate) workspace: Option<String>,
    pub(crate) client: OnceCell<AgentTools>,
    selected:Mutex<Option<(String,Arc<AgentTools>)>>,
    source_guard:Mutex<Option<(Value,crate::communication_runtime::RuntimeClient)>>,
    source_directory:std::sync::Mutex<Option<std::path::PathBuf>>,
    identity:std::sync::OnceLock<(String,String)>,
}
impl Lifecycle {
    pub(crate) fn profile(profile:AgentProfile)->Self {
        Self{profile:Some(profile),local:None,handle:None,workspace:None,client:OnceCell::new(),selected:Mutex::new(None),source_guard:Mutex::new(None),source_directory:std::sync::Mutex::new(None),identity:std::sync::OnceLock::new()}
    }
    pub(crate) fn local(directory:std::path::PathBuf,handle:Option<String>,workspace:Option<String>)->Self {
        Self{profile:None,local:Some(directory),handle,workspace,client:OnceCell::new(),selected:Mutex::new(None),source_guard:Mutex::new(None),source_directory:std::sync::Mutex::new(None),identity:std::sync::OnceLock::new()}
    }
    pub(crate) fn attached(tools:AgentTools)->Self {
        Self{profile:None,local:None,handle:None,workspace:None,client:OnceCell::new_with(Some(tools)),selected:Mutex::new(None),source_guard:Mutex::new(None),source_directory:std::sync::Mutex::new(None),identity:std::sync::OnceLock::new()}
    }
    async fn selected_tools(&self,profile:AgentProfile,binding:Option<Value>)->Result<Arc<AgentTools>> {
        let key=serde_json::to_string(&json!([profile,binding])).map_err(|_|ParticipantError::local("AGENT_PROFILE_INVALID","CONNECT"))?;
        let mut selected=self.selected.lock().await;
        if let Some((old,tools))=&*selected {if old==&key{return Ok(tools.clone());}}
        let tools=Arc::new(AgentTools::open_bound(profile,binding).await?);*selected=Some((key,tools.clone()));Ok(tools)
    }
    async fn verify_source(&self,connect:&crate::participant_connect::Connect,profile:&AgentProfile)->Result<()> {
        let Some(binding)=connect.profile_source_binding(profile)? else{return Ok(());};
        let mut guard=self.source_guard.lock().await;
        if let Some((expected,client))=&*guard {
            if expected!=&binding{return Err(ParticipantError::local("ORIGINAL_RUNTIME_BINDING_CHANGED","CONNECT"));}
            return client.verify_current().await;
        }
        let client=crate::communication_runtime::RuntimeClient::connect_bound(profile.endpoint_path.clone(),&profile.expected_origin,&profile.expected_actor,binding.clone()).await?;
        *guard=Some((binding,client));Ok(())
    }
    fn source_selection(&self,profile:&AgentProfile)->Result<Option<(std::path::PathBuf,crate::participant_connect::Connect,String)>> {
        let cached=self.source_directory.lock().map_err(|_|ParticipantError::local("CONNECT_RECOVERY_REQUIRED","CONNECT"))?.clone();
        if let Some(directory)=cached {
            let connect=crate::participant_connect::Connect::inspect(&directory)?;
            let handle=connect.source_handle(profile)?.ok_or_else(||ParticipantError::local("ORIGINAL_PROFILE_SOURCE_CHANGED","CONNECT"))?;
            return Ok(Some((directory,connect,handle)));
        }
        let Some((directory,handle))=crate::participant_connect::Connect::profile_source(profile)? else{return Ok(None);};
        let connect=crate::participant_connect::Connect::inspect(&directory)?;
        *self.source_directory.lock().map_err(|_|ParticipantError::local("CONNECT_RECOVERY_REQUIRED","CONNECT"))?=Some(directory.clone());
        Ok(Some((directory,connect,handle)))
    }
    /// Reuse normal selected-client resolution; never adopt an alternate profile.
    pub(crate) async fn notification_allowed(&self,batch:&str,revision:u64)->Result<bool> {
        let value=self.call(AgentRequest::NotificationValidate{batch:batch.into(),revision}).await?;
        Ok(value["allowed"]==true)
    }
    pub(crate) async fn call(&self,request:AgentRequest)->Result<Value> {
        if let Some(profile)=&self.profile {
            if let Some((directory,connect,handle))=self.source_selection(profile)? {
                self.verify_source(&connect,profile).await?;
                return self.source_result(self.call_snapshot(connect,&directory,Some(&handle),self.workspace.as_deref(),request).await);
            }
            if matches!(request,AgentRequest::Connect{..}|AgentRequest::ConnectApprove{..}) {
                let directory=crate::participant_connect::Connect::profile_directory(profile)?;
                let handle=crate::participant_connect::Connect::open(&directory)?.adopt_profile(profile,None,false).await?;
                return self.source_result(self.call_local(&directory,Some(&handle),self.workspace.as_deref(),request).await);
            }
        }
        match self.call_selected(request).await {
            Err(mut error) if self.profile.is_some() && agent_tools::refresh_workspace_error(&error).is_some()=>{
                // Knowing a restricted endpoint never authenticates its issuer.
                let details=error.details.get_or_insert_with(||json!({}));
                details["continuation"]=crate::participant_connect::Connect::profile_continuation(self.profile.as_ref().unwrap());
                Err(error)
            },other=>other,
        }
    }

    fn source_result(&self,result:Result<Value>)->Result<Value> {
        result.map_err(|mut error| {
            if let Some(profile)=self.profile.as_ref().filter(|_|agent_tools::refresh_workspace_error(&error).is_some()) {
                error.details.get_or_insert_with(||json!({}))["continuation"]=crate::participant_connect::Connect::profile_continuation(profile);
            }
            error
        })
    }
    pub(crate) fn channel_profile(&self)->Result<Option<AgentProfile>> {
        if let Some(directory)=&self.local {
            return crate::participant_connect::Connect::inspect(directory)?.profile_for_scope(self.handle.as_deref(),self.workspace.as_deref());
        }
        if let Some(profile)=&self.profile {
            if let Some((_directory,connect,handle))=self.source_selection(profile)? {
                return connect.profile_for_scope(Some(&handle),self.workspace.as_deref());
            }
        }
        Ok(self.profile.clone())
    }
    async fn call_selected(&self, request: AgentRequest) -> Result<Value> {
        if let Some(directory)=&self.local {
            return self.call_local(directory,self.handle.as_deref(),self.workspace.as_deref(),request).await;
        }
        self.client
            .get_or_try_init(|| AgentTools::open(self.profile.clone().expect("validated profile frontend")))
            .await?
            .call(request)
            .await
    }
    async fn call_local(&self,directory:&std::path::Path,handle_pin:Option<&str>,workspace_pin:Option<&str>,request:AgentRequest)->Result<Value> {
        let connect=crate::participant_connect::Connect::inspect(directory)?;
        self.call_snapshot(connect,directory,handle_pin,workspace_pin,request).await
    }
    async fn call_snapshot(&self,connect:crate::participant_connect::Connect,directory:&std::path::Path,handle_pin:Option<&str>,workspace_pin:Option<&str>,request:AgentRequest)->Result<Value> {
            let identity_handle=match &request {
                AgentRequest::Connect{request:crate::participant_connect::ConnectInput::Configure(desired)} if !desired.participant.is_empty()=>Some(desired.participant.clone()),
                AgentRequest::ConnectApprove{participant,..}=>Some(participant.clone()),
                _=>connect.selected_handle(handle_pin).ok().flatten(),
            };
            if let Some(identity)=identity_handle.as_deref().and_then(|handle|connect.participant_identity(handle)) {
                let selected=self.identity.get_or_init(||identity.clone());
                if selected!=&identity{return Err(ParticipantError::local("FRONTEND_IDENTITY_PIN_MISMATCH","CONNECT"));}
            }
            if let AgentRequest::Connect{request}=request {
                let (request,resume)=connect.resolve_input(request)?;
                // Selection-only observations remain available while another
                // setup holds the writer. They cannot sign or create bindings.
                if workspace_pin.is_some_and(|ws|ws!=request.workspace_id){return Err(ParticipantError::local("FRONTEND_WORKSPACE_PIN_MISMATCH","CONNECT"));}
                if handle_pin.is_some_and(|pin|!request.participant.is_empty() && pin!=request.participant){return Err(ParticipantError::local("FRONTEND_IDENTITY_PIN_MISMATCH","CONNECT"));}
                if resume {drop(connect);return crate::participant_connect::Connect::open(directory)?.resume_selected(&request.setup_id,handle_pin,workspace_pin).await;}
                let discovery=connect.discovery_summary();
                if discovery.candidates.is_empty() && connect.selected_handle(handle_pin)?.is_none() {
                    let mut result=crate::participant_connect::Connect::selection_required(&request.setup_id);
                    result["discovery"]=serde_json::to_value(discovery).unwrap();return Ok(result);
                }
                if discovery.candidates.len()>1 && handle_pin.is_none() && request.participant.is_empty() {
                    return Ok(json!({"state":"PENDING","discovery":discovery,"blocker":{"code":"IDENTITY_SELECTION_REQUIRED","next_actor":"LOCAL_RUNTIME_OWNER","next_action":"CHOOSE_ONE_PUBLIC_IDENTITY_HANDLE"}}));
                }
                drop(connect);
                return crate::participant_connect::Connect::open(directory)?.connect_selected(request,handle_pin,workspace_pin).await;
            }
            if let AgentRequest::ConnectApprove{participant,approval_id,request}=request {
                if handle_pin.is_some_and(|h|h!=participant){return Err(ParticipantError::local("FRONTEND_IDENTITY_PIN_MISMATCH","CONNECT"));}
                if workspace_pin.is_some_and(|ws|ws!=request.workspace_id){return Err(ParticipantError::local("FRONTEND_WORKSPACE_PIN_MISMATCH","CONNECT"));}
                drop(connect);return crate::participant_connect::Connect::open(directory)?.approve(&participant,&approval_id,request).await;
            }
            let handle=match connect.selected_handle(handle_pin) {
                Ok(handle)=>handle,
                Err(error) if matches!(request,AgentRequest::Context) && error.code=="MULTIPLE_IDENTITIES_SELECT_FRONTEND_PARTICIPANT"=>return Ok(connect.context_for(handle_pin,workspace_pin)),
                Err(error)=>return Err(error),
            };
            let context=connect.context_for(handle.as_deref(),workspace_pin);
            let profile=match connect.profile_for_scope(handle_pin,workspace_pin) {
                Ok(profile)=>profile,
                Err(error) if matches!(request,AgentRequest::Context) && error.code=="MULTIPLE_WORKSPACES_SELECT_FRONTEND_WORKSPACE"=>return Ok(context),
                Err(error)=>return Err(error),
            };
            let binding=profile.as_ref().map(|profile|connect.selected_profile_binding(handle_pin,profile)).transpose()?.flatten();
            drop(connect);
            if let Some(profile)=profile {
                let is_context=matches!(request,AgentRequest::Context);
                let alias=agent_tools::protocol_request_alias(&request).map(str::to_owned);let retry=request.clone();
                let has_recovery=!profile.recovery_views.is_empty();
                let selected=self.selected_tools(profile,binding).await?;
                // Cross-namespace mutations consult retained original routes
                // using this same cached client, before any fresh resolution.
                if has_recovery {if let Some(original)=selected.original_request(&request).await?{return Ok(original);}}
                let result=selected.call(request).await;
                let mut value=match result {
                    Err(error)if agent_tools::refresh_workspace_error(&error).is_some() && crate::participant_connect::Connect::inspect(directory)?.workspace_profile_refreshable(handle_pin,agent_tools::refresh_workspace_error(&error).unwrap())?=>{
                        if let Some(original)=selected.original_request(&retry).await?{return Ok(original);}
                        let workspace=agent_tools::refresh_workspace_error(&error).unwrap();
                        if !crate::participant_connect::Connect::open(directory)?.refresh_workspace_profile(handle_pin,workspace).await? {return Err(error);}
                        let next=crate::participant_connect::Connect::inspect(directory)?.profile_for_scope(handle_pin,workspace_pin)?.ok_or_else(||ParticipantError::local("LOCAL_SELECTION_REQUIRED","CONNECT"))?;
                        self.selected_tools(next.clone(),crate::participant_connect::Connect::inspect(directory)?.selected_profile_binding(handle_pin,&next)?).await?.call(retry).await?
                    },
                    Err(error)if alias.is_some()&&error.code=="PROTOCOL_OPERATION_ROUTE_EXISTS"=>{
                        let next=crate::participant_connect::Connect::inspect(directory)?.profile_for_scope(handle_pin,workspace_pin)?.ok_or_else(||ParticipantError::local("LOCAL_SELECTION_REQUIRED","CONNECT"))?;
                        self.selected_tools(next.clone(),crate::participant_connect::Connect::inspect(directory)?.selected_profile_binding(handle_pin,&next)?).await?.call(retry).await?
                    },
                    Err(error)if alias.is_some()&&agent_tools::refresh_protocol_error(&error)=>{
                        if let Some(original)=selected.original_request(&retry).await?{return Ok(original);}
                        if let Err(error)=crate::participant_connect::Connect::open(directory)?.refresh_protocol_alias(handle_pin,workspace_pin,alias.as_deref().unwrap(),error.details.as_ref()).await{if !agent_tools::refresh_nonblocking(&error,&retry){return Err(error);}}
                        let next=crate::participant_connect::Connect::inspect(directory)?.profile_for_scope(handle_pin,workspace_pin)?.ok_or_else(||ParticipantError::local("LOCAL_SELECTION_REQUIRED","CONNECT"))?;
                        self.selected_tools(next.clone(),crate::participant_connect::Connect::inspect(directory)?.selected_profile_binding(handle_pin,&next)?).await?.call(retry).await?
                    },other=>other?,
                };
                if is_context {value["onboarding"]=context;}
                return Ok(value);
            }
            if matches!(request,AgentRequest::Context) { return Ok(context); }
            return Err(ParticipantError::local("LOCAL_SELECTION_REQUIRED_USE_CONNECT","CONNECT"));
    }
    pub(crate) fn catalog(&self)->Result<Vec<Value>> {
        let mut tools=agent_tools::catalog();
        if self.local.is_none() && self.profile.is_none() {
            // An embedded client has no local installation ownership to transfer.
            tools.retain(|v| !matches!(v["name"].as_str(), Some("peerwork_connect" | "peerwork_connect_approve")));
        }
        if let Some(directory)=&self.local {
            let connect=crate::participant_connect::Connect::inspect(directory)?;
            let profile=match connect.profile_for_scope(self.handle.as_deref(),self.workspace.as_deref()) {
                Ok(profile)=>profile,
                Err(error) if ["MULTIPLE_IDENTITIES_SELECT_FRONTEND_PARTICIPANT","MULTIPLE_WORKSPACES_SELECT_FRONTEND_WORKSPACE"].contains(&error.code.as_str())=>None,
                Err(error)=>return Err(error),
            };
            if profile.is_none() {
                let registered=connect.context()["participants"].as_array().is_some_and(|v|!v.is_empty());
                tools.retain(|v|matches!(v["name"].as_str(),Some("peerwork_context"|"peerwork_connect")) || registered && v["name"]=="peerwork_connect_approve");
            }
        }
        Ok(tools)
    }
}
