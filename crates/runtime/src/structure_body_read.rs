//! Local body opening after service/source verification. A missing or damaged
//! body key is isolated from the readable structural result.
use super::*;
use crate::kernel_intents::{StructureContentKeys,ContentKeyError};
use peerwork_core::{prepared_command::verify_structure_author_intent,structure_content::StructureContentError};

#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct OpenedStructureBody {
    pub record_id:String,
    pub revision:u64,
    pub source_command_id:String,
    pub record_index:u8,
    pub key_id:Option<String>,
    pub state:&'static str,
    pub text:Option<String>,
    pub assurance:Option<&'static str>,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct OpenedMessageBody {
    pub message_id:String,pub source_command_id:String,pub key_id:Option<String>,
    pub state:&'static str,pub text:Option<String>,pub assurance:Option<&'static str>,
}
impl KernelClient {
    pub(super) fn open_selected_structure_bodies(&self,result:&mut KernelAcceptedResult,action:&str,local_key:&str)
        ->Result<(),KernelClientError>{
        if matches!(action,"structure.message.get"|"structure.mailbox.inbox.read"){return self.open_selected_message_bodies(result,action,local_key);}
        if result.opened_contents.is_some()||!matches!(action,"structure.record.get"|"structure.publication.prepare.get"|"structure.records.read"){return Ok(());}
        let data=parse_wire_json_bounded(result.structure_result_json.as_deref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024)
            .map_err(|_|KernelClientError::InvalidResult)?;
        if data.get("status").and_then(WireValue::as_string).as_deref()==Some("REJECTED_NO_EFFECT"){return Ok(());}
        let mut records=Vec::new();
        if matches!(action,"structure.record.get"|"structure.publication.prepare.get"){records.push((&data,required_text(&data,"author_intent")?));}else{
            let Some(WireValue::Array(items))=data.get("records")else{return Err(KernelClientError::InvalidResult);};
            if items.len()>32{return Err(KernelClientError::InvalidResult);}
            let sources=data.get("sources").ok_or(KernelClientError::InvalidResult)?;
            for item in items {
                let key=required_text(item,"source_key")?;let source=sources.get(&key).ok_or(KernelClientError::InvalidResult)?;
                records.push((item,required_text(source,"author_intent")?));
            }
        }
        let path=self.content_key_store_path();
        let keys=if path.is_file(){let mut config=TransportConfig::new(self.origin());config.allow_loopback_http=self.origin().starts_with("http://");
            Some(StructureContentKeys::open(&path,config))}else{None};
        let mut opened=Vec::new();
        for (record,jws) in records {
            // The receipt verifier already bound the returned record and its
            // source index to this original signature. Reusing the core
            // proof constructor avoids deriving AAD from mutable read data.
            let author=verify_structure_author_intent(&jws,self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidResult)?;
            let index=u8::try_from(required_u64(record.get("source").ok_or(KernelClientError::InvalidResult)?,"record_index")?).map_err(|_|KernelClientError::InvalidResult)?;
            let sealed=record.get("sealed_content").ok_or(KernelClientError::InvalidResult)?;
            let mut body=OpenedStructureBody{record_id:required_text(record,"record_id")?,revision:required_u64(record,"revision")?,
                source_command_id:author.command_id().into(),record_index:index,key_id:sealed.get("key_id").and_then(WireValue::as_string),
                state:"NO_CONTENT",text:None,assurance:None};
            if let Some(public)=record.get("public_statement").filter(|v|!matches!(v,WireValue::Null)){
                let output=peerwork_core::public_output::for_command(public,author.command(),index.into()).map_err(|_|KernelClientError::InvalidResult)?;body.text=Some(output.text);body.state="OPENED";body.assurance=Some("AUTHOR_PUBLIC_SIGNATURE");
            }else if !matches!(sealed,WireValue::Null){
                let bytes=match &keys {
                    None=>Err(ContentKeyError::Missing),Some(Err(_))=>Err(ContentKeyError::Integrity),
                    Some(Ok(keys))=>keys.open_authored_body(local_key,&author,index),
                };
                match bytes {
                    Ok(plain)=>match std::str::from_utf8(&plain){
                        Ok(text)=>{body.state="OPENED";body.text=Some(text.into());body.assurance=Some("AUTHOR_SIGNATURE_AND_AEAD");},
                        Err(_)=>body.state="UNSUPPORTED_ENCODING",
                    },
                    Err(ContentKeyError::Missing)=>body.state="KEY_UNAVAILABLE",
                    Err(ContentKeyError::Content(StructureContentError::Authentication))=>body.state="AUTHENTICATION_FAILED",
                    Err(ContentKeyError::Content(_))=>body.state="BODY_INVALID",
                    Err(_)=>body.state="KEY_STATE_INVALID",
                }
            }
            opened.push(body);
        }
        result.opened_contents=Some(opened);Ok(())
    }
}

impl KernelClient {
    fn open_selected_message_bodies(&self,result:&mut KernelAcceptedResult,action:&str,local_key:&str)->Result<(),KernelClientError>{
        if result.opened_messages.is_some(){return Ok(());}
        let data=parse_wire_json_bounded(result.structure_result_json.as_deref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),40,2*1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
        if data.get("status").and_then(WireValue::as_string).as_deref()==Some("REJECTED_NO_EFFECT"){return Ok(());}
        let messages=if action=="structure.message.get"{vec![data.get("message").ok_or(KernelClientError::InvalidResult)?]}
            else{let Some(WireValue::Array(items))=data.get("items")else{return Err(KernelClientError::InvalidResult);};if items.len()>32{return Err(KernelClientError::InvalidResult);}items.iter().filter_map(|v|v.get("message")).collect()};
        let path=self.content_key_store_path();
        let keys=if path.is_file(){Some(StructureContentKeys::open(&path,self.content_config()))}else{None};
        let mut opened=Vec::new();
        for message in messages {
            // Original source/recipient bindings were checked by receipt_wire.
            let author=verify_structure_author_intent(&required_text(message,"author_intent")?,self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidResult)?;
            let (_,content)=peerwork_core::communication::authored_message_content(&author).map_err(|_|KernelClientError::InvalidResult)?;
            let mut body=OpenedMessageBody{message_id:required_text(message,"message_id")?,source_command_id:author.command_id().into(),key_id:None,state:"SOURCE_REFERENCE",text:None,assurance:None};
            if let peerwork_core::communication::MessageContent::WorkspaceE2ee{body:sealed}=content {
                body.key_id=Some(sealed.key_id);
                let bytes=match &keys{None=>Err(ContentKeyError::Missing),Some(Err(_))=>Err(ContentKeyError::Integrity),Some(Ok(keys))=>keys.open_message(local_key,&author)};
                match bytes{
                    Ok(plain)=>match std::str::from_utf8(&plain){Ok(text)=>{body.state="OPENED";body.text=Some(text.into());body.assurance=Some("AUTHOR_SIGNATURE_AND_AEAD");},Err(_)=>body.state="UNSUPPORTED_ENCODING"},
                    Err(ContentKeyError::Missing)=>body.state="KEY_UNAVAILABLE",
                    Err(ContentKeyError::Content(StructureContentError::Authentication))=>body.state="AUTHENTICATION_FAILED",
                    Err(ContentKeyError::Content(_))=>body.state="BODY_INVALID",
                    Err(_)=>body.state="KEY_STATE_INVALID",
                }
            }
            opened.push(body);
        }
        result.opened_messages=Some(opened);Ok(())
    }
}
