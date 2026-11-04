//! Stable logical aliases over immutable credential/operation namespaces.
use super::*;
impl AgentTools {
    pub(super) fn protocol_read_client(&self,alias:&str,action:&str)->Result<&Client>{
        let scope=self.protocol(alias)?;
        if let Some((_,client))=self.profile.protocol_views.iter().filter(|(_,v)|v.alias==alias&&v.read_only)
            .filter_map(|(id,v)|self.protocol_view_clients.get(id).map(|client|(v.client_generation,client))).min_by_key(|(generation,_)|*generation){return Ok(client);}
        Ok(self.management_client(scope.workspace_id.as_deref().unwrap_or(""),action).map(|(_,c)|c).unwrap_or(self.protocol_client(alias)?))
    }
    pub(super) async fn original_protocol_operation(&self,alias:&str,id:&str)->Result<Option<(&Client,Scope,Option<&str>,Value)>>{
        let target=self.protocol(alias)?;let mut found=None;let mut seen=std::collections::BTreeSet::new();
        for(view_id,view)in self.profile.protocol_views.iter().filter(|(_,v)|!v.read_only&&v.scope.workspace_id==target.workspace_id&&v.scope.instance_id==target.instance_id){
            let client=self.protocol_view_clients.get(view_id).ok_or_else(||invalid("PROTOCOL_VIEW_RECOVERY_REQUIRED"))?;
            let binding=view.binding.to_string();if !seen.insert(binding){continue;}
            match client.call(json!({"method":"operation","operation_id":id})).await {
                Ok(value)=>{if found.is_some(){return Err(invalid("OPERATION_SCOPE_AMBIGUOUS_USE_PROTOCOL_VIEW"));}found=Some((client,view.scope.clone(),Some(view_id.as_str()),value));},
                Err(e)if e.code=="OPERATION_NOT_FOUND"=>(),Err(e)=>return Err(e),
            }
        }
        for(candidate,scope)in self.profile.protocols.iter().filter(|(_,scope)|scope.workspace_id==target.workspace_id&&scope.instance_id==target.instance_id){
        let client=self.protocol_client(candidate)?;
        let binding=if client.attached_mode(){format!("attached:{client:p}")}else{crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?).to_string()};
        if seen.insert(binding) {
            match client.call(json!({"method":"operation","operation_id":id})).await{
                Ok(value)=>{if found.is_some(){return Err(invalid("OPERATION_SCOPE_AMBIGUOUS_USE_PROTOCOL_VIEW"));}found=Some((client,scope.clone(),None,value));},
                Err(e)if e.code=="OPERATION_NOT_FOUND"=>(),Err(e)=>return Err(e),
            }
        }
        }
        Ok(found)
    }
    pub(super) async fn action_protocol_route(&self,alias:&str,request:&Invoke)->Result<(&Client,Invoke,Option<&str>)>{
        let reader=self.protocol_read_client(alias,"structure.protocol.resolve")?;
        let selected=reader.call(json!({"method":"resolve_execution","request":request})).await;
        // Old engines retain their old working route; they never claim a new
        // context was selected. The backend fences ambiguous legacy writes.
        let selected:Invoke=match selected{
            Ok(selected)=>serde_json::from_value(selected).map_err(|_|invalid("EXECUTION_SELECTION_INVALID"))?,
            Err(e)if matches!(e.code.as_str(),"IPC_REQUEST_INVALID"|"RESIDENT_RUNTIME_REQUIRED_FOR_ADMINISTRATION")=>return Ok((self.protocol_client(alias)?,request.clone(),None)),
            Err(e)=>return Err(e),
        };
        let action=request.body["action_id"].as_str().ok_or_else(||invalid("BUSINESS_ACTION_INVALID"))?;
        let candidate=self.profile.protocol_views.iter().filter(|(_,view)|view.alias==alias&&!view.read_only&&view.scope==selected.scope&&view.actions.as_ref().is_none_or(|actions|actions.contains(action)))
            .filter_map(|(id,view)|self.protocol_view_clients.get(id).map(|client|(view.client_generation,id,client,view)))
            .min_by_key(|(generation,_,_,_)|*generation);
        if let Some((_,id,client,_))=candidate{return Ok((client,selected,Some(id.as_str())));}
        let fallback=self.protocol_client(alias)?;
        let value=fallback.call(json!({"method":"capabilities"})).await?;
        let cap:crate::participant::Capability=serde_json::from_value(value["capability"].clone()).map_err(|_|invalid("LOCAL_CEILING_INVALID"))?;
        if cap.authorize(&selected).is_ok(){return Ok((fallback,selected,None));}
        let mut error=invalid("PROTOCOL_VIEW_REQUIRED");error.details=Some(json!({"alias":alias,"workspace_id":selected.scope.workspace_id,"instance_id":selected.scope.instance_id,"protocol_digest":selected.scope.protocol_digest,"execution_context_id":selected.body["execution_context_id"],"next_action":"REFRESH_AUTHORIZED_PROTOCOL_VIEWS","original_operation_id":request.operation_id}));Err(error)
    }
}
