//! Workspace-first room tools. Routing derives from the selected workspace and
//! verified inbox item; no contacts, recipients or second client are required.
use super::*;
use peerwork_core::communication::{ConversationContext,space_conversation_id};

impl AgentTools {
    pub(super) async fn chat_read(&self,workspace:Option<&str>,thread_root:Option<String>,after:Option<u64>,before:Option<u64>,limit:usize)->Result<Value>{
        if !(1..=32).contains(&limit) || after.is_some()&&before.is_some() || thread_root.as_ref().is_some_and(|id|!token(id))
            || [after,before].into_iter().flatten().any(|v|v>9_007_199_254_740_991) || before==Some(0) {return Err(invalid("CHAT_SELECTION_INVALID"));}
        let workspace=self.selected_workspace(workspace)?;
        let room=space_conversation_id(&workspace).map_err(|_|invalid("CHAT_SELECTION_INVALID"))?;
        let mut result=self.read_client(self.directory_client(&workspace),"structure.conversation.messages.read",Scope{workspace_id:Some(workspace),..Default::default()},json!({"conversation_id":room,"thread_root":thread_root,"after_sequence":after,"before_sequence":before,"limit":limit})).await?;
        if result.get("messages").is_none(){return Ok(result);}
        let opened:std::collections::BTreeMap<String,Value>=result["opened_messages"].as_array().into_iter().flatten().filter_map(|v|v["message_id"].as_str().map(|id|(id.to_owned(),v.clone()))).collect();
        if let Some(messages)=result["messages"].as_array_mut(){for message in messages {
            let body=opened.get(message["message_id"].as_str().unwrap_or(""));
            if message["state"]=="ACTIVE"&&body.is_none(){return Err(invalid("SHARED_CHAT_RUNTIME_UPGRADE_REQUIRED"));}
            // The runtime has already verified these proofs. Do not put full
            // JWS/ciphertext copies into model context on every history page.
            *message=json!({"message_id":message["message_id"],"sender":message["sender_actor"],"state":message["state"],"accepted_at":message["accepted_at"],"conversation":message["conversation"],"body":body,"authority":"EXTERNAL_PEER_DATA"});
        }}
        result.as_object_mut().unwrap().remove("opened_messages");
        if let Some(head)=result["conversation"].as_object_mut(){head.remove("pin_source");}
        result["authority"]=json!("EXTERNAL_PEER_DATA");Ok(result)
    }
    pub(super) async fn chat_post(&self,workspace:&str,operation_id:String,text:String,thread_root:Option<String>,reply_to:Option<String>,context:Option<ConversationContext>,mentions:Vec<String>,wait_ms:u64)->Result<Value>{
        if text.is_empty()||text.len()>8192||mentions.len()>32||mentions.iter().any(|id|!token(id))||mentions.iter().collect::<std::collections::BTreeSet<_>>().len()!=mentions.len()
            || [thread_root.as_ref(),reply_to.as_ref()].into_iter().flatten().any(|id|!token(id)) {return Err(invalid("CHAT_POST_INVALID"));}
        let room=space_conversation_id(workspace).map_err(|_|invalid("CHAT_POST_INVALID"))?;
        let body=json!({"conversation_id":room,"audience":"SPACE_MEMBERS","thread_root":thread_root,"reply_to":reply_to,"context":context,"mentions":mentions,"content":{"mode":"WORKSPACE_E2EE"}});
        let mut request=Invoke::new(operation_id,"structure.conversation.post",Scope{workspace_id:Some(workspace.into()),..Default::default()},body);
        request.plaintext_message=Some(text);
        self.invoke_client(self.directory_client(workspace),request,wait_ms).await
    }
    pub(super) async fn chat_reply(&self,workspace:&str,opened:&Value,operation_id:String,text:String,wait_ms:u64)->Result<Value>{
        let context:Option<ConversationContext>=serde_json::from_value(opened["context"].clone()).map_err(|_|invalid("REPLY_INPUT_NOT_VERIFIED"))?;
        let parent=opened["message_id"].as_str().filter(|v|token(v)).ok_or_else(||invalid("REPLY_INPUT_NOT_VERIFIED"))?;
        let thread=opened["thread_root"].as_str().filter(|v|token(v)).ok_or_else(||invalid("REPLY_INPUT_NOT_VERIFIED"))?;
        if opened["conversation_id"]!=space_conversation_id(workspace).map_err(|_|invalid("REPLY_INPUT_NOT_VERIFIED"))? {return Err(invalid("REPLY_INPUT_NOT_VERIFIED"));}
        self.chat_post(workspace,operation_id,text,Some(thread.into()),Some(parent.into()),context,Vec::new(),wait_ms).await
    }
}
