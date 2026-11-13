use super::*;
fn stop_arguments(workspace:&str,actor:&str,row:&Value)->Value {
    let mut body=json!({"subscription_id":row["subscription_id"],"mailbox_id":row["mailbox_id"],"expected_revision":row["revision"],"state":"STOPPED","actor_id":row["actor_filter"]});
    for field in ["instance_id","protocol_digest","actions","kinds","schemas","include_self"] {body[field]=row[field].clone();}
    let handle=base64url(json!({"format":"peerwork.subscription-stop.v1","workspace_id":workspace,"actor_id":actor,"body":body}).to_string().as_bytes());
    json!({"tool":"peerwork_subscriptions","arguments":{"mode":"stop","workspace":workspace,"stop_handle":handle},"add_required":["operation_id"]})
}

impl AgentTools {
    pub(super) async fn subscriptions(&self,request:AgentRequest)->Result<Value> {
        let AgentRequest::Subscriptions {workspace,protocol,mode,operation_id,subscription_id,stop_handle,kinds,actor,actions,schemas,expected_revision,wait_ms}=request else{return Err(invalid("SUBSCRIPTION_ARGUMENT_INVALID"));};
        let workspace=self.selected_workspace(workspace.as_deref())?;
        let client=self.directory_client(&workspace);
        let scope=Scope{workspace_id:Some(workspace.clone()),..Default::default()};
        if mode=="list" {
            let mut value=self.read_client(client,"structure.communication.subscriptions.read",scope,json!({"limit":32})).await?;
            if let Some(items)=value["subscriptions"].as_array_mut(){
                for item in items {
                    item["stop"]=stop_arguments(&workspace,self.client.actor_id(),item);
                }
            }
            return Ok(value);
        }
        if mode!="subscribe"&&mode!="stop" {return Err(invalid("SUBSCRIPTION_MODE_USE_LIST_SUBSCRIBE_STOP"));}
        let operation=operation_id.filter(|s|!s.is_empty()).ok_or_else(||invalid("OPERATION_ID_REQUIRED"))?;
        let mut body=if mode=="stop" {
            let handle=stop_handle.ok_or_else(||invalid("COPY_SUBSCRIPTION_STOP_HANDLE"))?;
            let decoded=peerwork_core::crypto::decode_base64url(&handle).map_err(|_|invalid("SUBSCRIPTION_STOP_HANDLE_INVALID"))?;
            if decoded.len()>16384{return Err(invalid("SUBSCRIPTION_STOP_HANDLE_INVALID"));}
            let selected:Value=serde_json::from_slice(&decoded).map_err(|_|invalid("SUBSCRIPTION_STOP_HANDLE_INVALID"))?;
            if selected["format"]!="peerwork.subscription-stop.v1"||selected["workspace_id"]!=workspace||selected["actor_id"]!=self.client.actor_id()||!selected["body"]["mailbox_id"].as_str().is_some_and(token){return Err(invalid("SUBSCRIPTION_STOP_HANDLE_SCOPE_MISMATCH"));}
            let old=&selected["body"];
            let mut body=json!({"state":"STOPPED"});
            for field in ["subscription_id","mailbox_id","expected_revision","instance_id","protocol_digest","actions","kinds","schemas","include_self","actor_id"] {body[field]=old[field].clone();}
            body
        } else {
            let boxes=self.read_client(client,"structure.mailboxes.read",scope.clone(),json!({"limit":8})).await?;
            let mailbox=boxes["mailboxes"].as_array().and_then(|v|v.iter().find(|b|b["name"]=="default")).and_then(|v|v["mailbox_id"].as_str()).ok_or_else(||invalid("DEFAULT_MAILBOX_REQUIRED"))?;
            let id=subscription_id.unwrap_or_else(||base64url(&sha256(json!(["peerwork.subscription.v1",self.client.actor_id(),workspace,operation]).to_string().as_bytes())));
            if !token(&id){return Err(invalid("SUBSCRIPTION_ID_INVALID"));}
            let mut selected=json!({"subscription_id":id,"mailbox_id":mailbox,"expected_revision":expected_revision,"state":"ACTIVE","kinds":if kinds.is_empty()&&protocol.is_some(){vec!["action.accepted".to_owned()]}else{kinds},"actions":actions,"schemas":schemas});
            if let Some(alias)=protocol {
                let selected_protocol=self.protocol(&alias)?;
                if selected_protocol.workspace_id.as_deref()!=Some(workspace.as_str()){return Err(invalid("SUBSCRIPTION_WORKSPACE_MISMATCH"));}
                selected["instance_id"]=json!(selected_protocol.instance_id);selected["protocol_digest"]=json!(selected_protocol.protocol_digest);
            }
            if let Some(actor)=actor {
                let resolved=if token(&actor){actor}else{
                    let result=self.members(Some(&workspace),Some(&actor),None,2).await?;
                    let rows=result["members"].as_array().filter(|v|v.len()==1).ok_or_else(||invalid("SELECT_EXACT_MEMBER_ACTOR"))?;
                    rows[0]["actor_id"].as_str().ok_or_else(||invalid("MEMBER_OBSERVATION_INVALID"))?.to_owned()
                };selected["actor_id"]=json!(resolved);
            }
            selected
        };
        // Stop reuses the exact revision supplied by its handle, even on a
        // retry after the earlier result was lost. A changed handle conflicts
        // with the original operation rather than silently rebasing it.
        let id=body["subscription_id"].clone();
        let request=Invoke::new(operation,"structure.communication.subscription.set",scope,body.take());
        let mut value=match self.invoke_client(client,request,wait_ms).await {
            Ok(value)=>value,
            Err(mut error)=>{if let Some(operation)=error.operation_id.clone(){error.details.get_or_insert_with(||json!({}))["recovery_arguments"]=json!({"workspace":workspace,"operation_id":operation});}return Err(error);}
        };
        value["subscription_id"]=id;
        value["recovery_arguments"]=json!({"workspace":workspace,"operation_id":value["operation_id"]});
        if let Some(row)=value.pointer("/result/structure/subscription").filter(|v|v["revision"].as_u64().is_some()){
            value["stop"]=stop_arguments(&workspace,self.client.actor_id(),row);
        }
        Ok(value)
    }
}
