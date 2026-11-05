//! Old credentials are retained solely to locate exact durable operations.
//! They are never alternate routes for a newly denied action.
use super::*;
impl AgentTools {
    pub(super) async fn observe_original(&self,method:&str,id:&str,protocol:Option<&str>,workspace:Option<&str>,management:Option<&str>,protocol_view:Option<&str>,recovery_view:Option<&str>)->Result<Value>{
        if [protocol,workspace,management,protocol_view,recovery_view].iter().filter(|v|v.is_some()).count()>1{return Err(invalid("OPERATION_SCOPE_AMBIGUOUS"));}
        let mut recovered=None;
        let (client,cached)=if let Some(view)=recovery_view {
            (&self.recovery_clients.get(view).ok_or_else(||invalid("RECOVERY_VIEW_REQUIRED"))?.1,None)
        }else if let Some(alias)=protocol {
            let(client,_,_,value)=self.original_protocol_operation(alias,id).await?.ok_or_else(||invalid("OPERATION_NOT_FOUND"))?;
            (client,Some(value))
        }else if management.is_some()||protocol_view.is_some(){
            (self.operation_client(None,None,management,protocol_view)?,None)
        }else{
            let ws=workspace.map(|w|self.selected_workspace(Some(w))).transpose()?;
            let(client,view,value)=self.original_general_operation(id,ws.as_deref(),None).await?.ok_or_else(||invalid("OPERATION_NOT_FOUND"))?;
            recovered=view;(client,Some(value))
        };
        let value=if method=="operation" {match cached{Some(value)=>value,None=>client.call(json!({"method":"operation","operation_id":id})).await?}}
            else{client.call(json!({"method":"recover","operation_id":id})).await?};
        let mut value=operation_view(value);
        if let Some(view)=recovered.or(recovery_view){value["recovery_arguments"]=json!({"operation_id":id,"recovery_view":view});}
        Ok(value)
    }
    pub(super) async fn original_general_operation(&self,id:&str,workspace:Option<&str>,scope:Option<&Scope>)->Result<Option<(&Client,Option<&str>,Value)>>{
        let mut clients=vec![(&self.client,None)];
        clients.extend(self.directory_clients.values().map(|client|(client,None)));
        clients.extend(self.recovery_clients.iter().filter(|(_,v)|workspace.is_none_or(|ws|ws==v.0)).map(|(id,(_,client))|(client,Some(id.as_str()))));
        let mut seen=std::collections::BTreeSet::new();let mut found=None;
        for(client,view)in clients {
            let binding=if client.attached_mode(){format!("attached:{client:p}")}else{crate::communication_runtime::canonical_binding(&client.call(json!({"method":"binding"})).await?).to_string()};
            if !seen.insert(binding){continue;}
            let value=match client.call(json!({"method":"operation","operation_id":id})).await {Ok(value)=>value,Err(e)if e.code=="OPERATION_NOT_FOUND"=>continue,Err(e)=>return Err(e)};
            let original:Scope=serde_json::from_value(value["scope"].clone()).map_err(|_|invalid("ORIGINAL_OPERATION_SCOPE_INVALID"))?;
            if workspace.is_some_and(|ws|original.workspace_id.as_deref()!=Some(ws))||scope.is_some_and(|s|s.workspace_id!=original.workspace_id||s.instance_id!=original.instance_id){continue;}
            if found.is_some(){let mut e=invalid("OPERATION_SCOPE_AMBIGUOUS_USE_RECOVERY_VIEW");e.details=Some(json!({"operation_id":id,"next_action":"SELECT_ORIGINAL_RECOVERY_VIEW"}));return Err(e);}
            found=Some((client,view,value));
        }
        Ok(found)
    }
}
