//! Shared Space history is a different signed audience from directed mail.
//! One author packet and a pinned service acceptance bind the room and fixed
//! membership cut. A room sequence is ordering, never a consumption receipt.
use super::*;

pub const FEATURE: &str = "space-conversation-v1";
pub const FORMAT: &str = "peerwork.space-conversation.v1";
const CONTENT_FORMAT: &str = "peerwork.conversation-content.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConversationRecordContext {
    pub kind: String,
    pub instance_id: String,
    pub execution_context_id: String,
    pub protocol_digest: String,
    pub entity_id: String,
    pub record_id: String,
    pub revision: u64,
}
impl ConversationRecordContext {
    fn validate(&self) -> Result<()> {
        if self.kind != "RECORD" || ![&self.instance_id,&self.execution_context_id,&self.entity_id,&self.record_id].iter().all(|s|token(s))
            || !digest(&self.protocol_digest) || self.revision==0 || self.revision>MAX_SEQUENCE {return Err(CommunicationError);}
        Ok(())
    }
}
pub fn space_conversation_id(workspace: &str) -> Result<String> {
    if !token(workspace) {return Err(CommunicationError);}
    id(json!([FORMAT,workspace]))
}
pub fn conversation_thread_id(workspace: &str,context: &ConversationRecordContext) -> Result<String> {
    context.validate()?;
    if !token(workspace) {return Err(CommunicationError);}
    id(json!(["peerwork.conversation-thread.v1",workspace,context.instance_id,context.entity_id]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationContentContext {
    pub workspace_id: String,
    pub actor_id: String,
    pub command_id: String,
    pub conversation_id: String,
    pub thread_root: Option<String>,
    pub reply_to: Option<String>,
    pub context: Option<ConversationRecordContext>,
    pub mentions: Vec<String>,
}
fn optional_token(v: &WireValue,name: &str) -> Result<Option<String>> {
    match v.get(name) {None|Some(WireValue::Null)=>Ok(None),Some(_)=>Ok(Some(token_field(v,name)?))}
}
impl ConversationContentContext {
    pub fn from_command(command: &WireValue) -> Result<Self> {
        if text(command,"action_id")? != "structure.conversation.post"
            || command.get("instance_id")!=Some(&WireValue::Null) || command.get("protocol_digest")!=Some(&WireValue::Null)
            || command.get("expected_workspace_revision")!=Some(&WireValue::Null) || command.get("expected_instance_revision")!=Some(&WireValue::Null)
            || !matches!(command.get("exact_input_refs"),Some(WireValue::Array(v)) if v.is_empty()) {return Err(CommunicationError);}
        let b=command.get("body").ok_or(CommunicationError)?;
        let WireValue::Object(fields)=b else{return Err(CommunicationError);};
        if fields.iter().any(|(k,_)|!["profile","conversation_id","audience","thread_root","reply_to","context","mentions","content"].iter().any(|n|k.iter().copied().eq(n.encode_utf16())))
            || text(b,"profile")?!=PROFILE || text(b,"audience")?!="SPACE_MEMBERS" {return Err(CommunicationError);}
        let value=Self{workspace_id:token_field(command,"workspace_id")?,actor_id:token_field(command,"actor_id")?,command_id:token_field(command,"command_id")?,conversation_id:token_field(b,"conversation_id")?,
            thread_root:optional_token(b,"thread_root")?,reply_to:optional_token(b,"reply_to")?,context:match b.get("context"){None|Some(WireValue::Null)=>None,Some(v)=>Some(wire(v)?)},
            mentions:match b.get("mentions"){None=>Vec::new(),Some(_)=>array(b,"mentions",32)?.iter().map(|v|v.as_string().ok_or(CommunicationError)).collect::<Result<_>>()?}};
        value.canonical_aad().map_err(|_|CommunicationError)?;Ok(value)
    }
    pub fn canonical_aad(&self) -> std::result::Result<String,StructureContentError> {
        let invalid=||StructureContentError::Invalid;
        if ![&self.workspace_id,&self.actor_id,&self.command_id,&self.conversation_id].iter().all(|s|token(s))
            || self.conversation_id!=space_conversation_id(&self.workspace_id).map_err(|_|invalid())?
            || self.thread_root.as_ref().is_some_and(|s|!token(s)) || self.reply_to.as_ref().is_some_and(|s|!token(s))
            || self.mentions.len()>32 || self.mentions.iter().any(|s|!token(s))
            || self.mentions.iter().collect::<std::collections::BTreeSet<_>>().len()!=self.mentions.len() {return Err(invalid());}
        if let Some(context)=&self.context {context.validate().map_err(|_|invalid())?;}
        if canonical(&json!([self.context,self.mentions]),Path::SecureArtifact).map_err(|_|invalid())?.len()>8192 {return Err(invalid());}
        canonical(&json!({"format":CONTENT_FORMAT,"profile":PROFILE,"workspace_id":self.workspace_id,"actor_id":self.actor_id,"command_id":self.command_id,
            "conversation_id":self.conversation_id,"audience":"SPACE_MEMBERS","thread_root":self.thread_root,"reply_to":self.reply_to,"context":self.context,"mentions":self.mentions}),Path::SecureArtifact).map_err(|_|invalid())
    }
    pub fn message_id(&self) -> Result<String> {id(json!(["peerwork.message.v1",self.workspace_id,self.actor_id,self.command_id]))}
}

/// The selected crypto domain is explicit; an empty directed recipient list
/// is never used as an implicit group message.
#[derive(Debug, Clone)]
pub enum NativeMessageContext {
    Directed(MessageContentContext),
    Conversation(ConversationContentContext),
}
impl NativeMessageContext {
    pub fn from_command(command: &WireValue) -> Result<Self> {
        if text(command,"action_id")?=="structure.conversation.post" {Ok(Self::Conversation(ConversationContentContext::from_command(command)?))}
        else {Ok(Self::Directed(MessageContentContext::from_command(command)?))}
    }
    pub fn workspace_id(&self)->&str {match self {Self::Directed(v)=>&v.workspace_id,Self::Conversation(v)=>&v.workspace_id}}
    pub fn actor_id(&self)->&str {match self {Self::Directed(v)=>&v.actor_id,Self::Conversation(v)=>&v.actor_id}}
    pub fn command_id(&self)->&str {match self {Self::Directed(v)=>&v.command_id,Self::Conversation(v)=>&v.command_id}}
    pub fn canonical_aad(&self)->std::result::Result<String,StructureContentError> {match self {Self::Directed(v)=>v.canonical_aad(),Self::Conversation(v)=>v.canonical_aad()}}
    pub fn seal(&self,key:&[u8;32],plaintext:&[u8])->std::result::Result<StructureSealedContent,StructureContentError>{seal_content_with_aad(key,plaintext,&self.canonical_aad()?)}
    pub fn open(&self,key:&[u8;32],sealed:&StructureSealedContent)->std::result::Result<Zeroizing<Vec<u8>>,StructureContentError>{open_content_with_aad(key,sealed,&self.canonical_aad()?)}
}
pub fn authored_native_message_content(author:&VerifiedStructureAuthorIntent)->Result<(NativeMessageContext,MessageContent)> {
    if author.action_id()!="structure.conversation.post" {let (context,content)=authored_message_content(author)?;return Ok((NativeMessageContext::Directed(context),content));}
    let context=ConversationContentContext::from_command(author.command())?;let body=author.command().get("body").ok_or(CommunicationError)?;
    let content:MessageContent=wire(body.get("content").ok_or(CommunicationError)?)?;
    let MessageContent::WorkspaceE2ee{body:sealed}=&content else{return Err(CommunicationError);};
    sealed.decoded_ciphertext().map_err(|_|CommunicationError)?;
    if sealed.algorithm!="A256GCM" || !token(&sealed.key_id) || sealed.nonce.len()!=16 || decode_base64url(&sealed.nonce).is_err()
        || sealed.aad_digest!=sha256_hex(context.canonical_aad().map_err(|_|CommunicationError)?.as_bytes()) {return Err(CommunicationError);}
    Ok((NativeMessageContext::Conversation(context),content))
}

#[derive(Debug, Clone)]
pub struct VerifiedConversationMessage {
    author: VerifiedStructureAuthorIntent,
    context: ConversationContentContext,
    content: StructureSealedContent,
    message_id: String,
    sequence: u64,
    thread_root: String,
    accepted_at: u64,
}
impl VerifiedConversationMessage {
    pub fn author(&self)->&VerifiedStructureAuthorIntent {&self.author}
    pub fn context(&self)->&ConversationContentContext {&self.context}
    pub fn content(&self)->&StructureSealedContent {&self.content}
    pub fn message_id(&self)->&str {&self.message_id}
    pub fn sequence(&self)->u64 {self.sequence}
    pub fn thread_root(&self)->&str {&self.thread_root}
    pub fn accepted_at(&self)->u64 {self.accepted_at}
}
fn metadata(value:&WireValue,workspace:&str)->Result<()> {
    exact(value,&["conversation_id","sequence","thread_root","audience_digest","audience_count"])?;
    if text(value,"conversation_id")?!=space_conversation_id(workspace)? || number(value,"sequence")?==0
        || !digest(&text(value,"audience_digest")?) || !(1..=256).contains(&number(value,"audience_count")?) {return Err(CommunicationError);}
    token_field(value,"thread_root")?;Ok(())
}
// Object member order is transport presentation, not signed JSON semantics.
// PostgreSQL source JSON and a newly projected room DTO can have different
// insertion order while authenticating the exact same canonical fields.
fn same(a:Option<&WireValue>,b:Option<&WireValue>)->Result<bool> {
    let (a,b)=(a.ok_or(CommunicationError)?,b.ok_or(CommunicationError)?);
    Ok(canonical_wire_value(a,Path::STRUCTURED).map_err(|_|CommunicationError)?
        ==canonical_wire_value(b,Path::STRUCTURED).map_err(|_|CommunicationError)?)
}
fn verify_pin_source(head:&WireValue,audience:&[u16],workspace:&str,key:&str)->Result<()> {
    let revision=number(head,"pin_revision")?;
    if revision==0 {
        if ["pin_reference","pin_author","pin_command","pin_source"].iter().any(|name|head.get(name)!=Some(&WireValue::Null)){return Err(CommunicationError);}return Ok(());
    }
    let source=head.get("pin_source").ok_or(CommunicationError)?;let result=source.get("result").ok_or(CommunicationError)?;
    let jws=text(result,"author_intent")?;let author=verify_structure_author_intent(&jws,audience).map_err(|_|CommunicationError)?;
    if author.action_id()!="structure.conversation.pin.set" || author.workspace_id()!=Some(workspace)
        || author.actor_id()!=text(head,"pin_author")? || author.command_id()!=text(head,"pin_command")? || text(result,"status")?!="APPLIED" {return Err(CommunicationError);}
    let body=author.command().get("body").ok_or(CommunicationError)?;
    if !same(body.get("reference"),head.get("pin_reference"))? || number(body,"expected_revision")?.checked_add(1)!=Some(revision) {return Err(CommunicationError);}
    let accepted=result.get("conversation").ok_or(CommunicationError)?;
    for name in ["conversation_id","workspace_id","pin_reference","pin_revision","pin_author","pin_command"] {if !same(accepted.get(name),head.get(name))? {return Err(CommunicationError);}}
    let response=canonical_wire_value(source,Path::STRUCTURED).map_err(|_|CommunicationError)?;
    verify_http_response_with_path(response.as_bytes(),&WireReceiptExpectation{audience_utf16:audience,receipt_key_id:key,actor_id:author.actor_id(),command_id:author.command_id(),intent_digest:author.intent_digest(),workspace_id:Some(workspace),protocol_digest:None},Path::STRUCTURED).map_err(|_|CommunicationError)?;Ok(())
}
fn verify_message_snapshot(message:&WireValue,audience:&[u16],workspace:&str,key:&str)->Result<()> {
    metadata(message.get("conversation").ok_or(CommunicationError)?,workspace)?;
    if text(message,"state")?=="ACTIVE" {verify_conversation_message(message,audience,workspace,key)?;}
    else {exact(message,&["state","message_id","accepted_at","sender_actor","conversation"])?;if text(message,"state")?!="WITHDRAWN" {return Err(CommunicationError);}token_field(message,"message_id")?;token_field(message,"sender_actor")?;number(message,"accepted_at")?;}
    Ok(())
}
fn verify_pin_message(head:&WireValue,audience:&[u16],workspace:&str,key:&str)->Result<()> {
    let reference=head.get("pin_reference").ok_or(CommunicationError)?;
    if reference.get("kind").and_then(WireValue::as_string).as_deref()!=Some("MESSAGE") {
        if head.get("pin_message")!=Some(&WireValue::Null){return Err(CommunicationError);}return Ok(());
    }
    let message=head.get("pin_message").ok_or(CommunicationError)?;
    if message.get("message_id")!=reference.get("message_id") || number(message.get("conversation").ok_or(CommunicationError)?,"sequence")?>number(head,"sequence")? {return Err(CommunicationError);}
    verify_message_snapshot(message,audience,workspace,key)
}
pub fn verify_conversation_message(value:&WireValue,audience:&[u16],workspace:&str,key:&str)->Result<VerifiedConversationMessage> {
    exact(value,&["state","message_id","sender_actor","sender_membership","accepted_at","command_id","intent_digest","author_intent","conversation","acceptance"])?;
    if text(value,"state")?!="ACTIVE" {return Err(CommunicationError);}
    let jws=text(value,"author_intent")?;let author=verify_structure_author_intent(&jws,audience).map_err(|_|CommunicationError)?;
    let (NativeMessageContext::Conversation(context),MessageContent::WorkspaceE2ee{body:content})=authored_native_message_content(&author)? else{return Err(CommunicationError);};
    let mid=context.message_id()?;let meta=value.get("conversation").ok_or(CommunicationError)?;metadata(meta,workspace)?;
    if context.workspace_id!=workspace || context.actor_id!=text(value,"sender_actor")? || context.command_id!=text(value,"command_id")?
        || author.intent_digest()!=text(value,"intent_digest")? || mid!=text(value,"message_id")? {return Err(CommunicationError);}
    token_field(value,"sender_membership")?;
    if author.command().get("expected_membership_id").is_some_and(|generation|Some(generation)!=value.get("sender_membership")){return Err(CommunicationError);}
    let thread=token_field(meta,"thread_root")?;
    if context.thread_root.as_ref().is_some_and(|s|s!=&thread)
        || context.context.as_ref().is_some_and(|c|conversation_thread_id(workspace,c).ok().as_deref()!=Some(thread.as_str()))
        || context.context.is_none() && context.reply_to.is_none() && context.thread_root.is_none() && thread!=mid {return Err(CommunicationError);}
    let acceptance=value.get("acceptance").ok_or(CommunicationError)?;exact(acceptance,&["receipt","result"])?;
    let result=acceptance.get("result").ok_or(CommunicationError)?;
    if result.get("author_intent").is_some() || !same(result.get("conversation"),Some(meta))? || text(result,"message_id")?!=mid
        || text(result,"status")?!="APPLIED" || text(result,"profile")?!=PROFILE || text(result,"assurance")?!="BACKEND_CURRENT_STATE"
        || result.get("sender_membership")!=value.get("sender_membership") || text(result,"workspace_id")?!=workspace || number(result,"accepted_at")?!=number(value,"accepted_at")? {return Err(CommunicationError);}
    let mut restored:serde_json::Value=wire(result)?;restored["author_intent"]=json!(jws);
    let response=json!({"command_id":context.command_id,"receipt":text(acceptance,"receipt")?,"result":restored});
    verify_http_response_with_path(response.to_string().as_bytes(),&WireReceiptExpectation{audience_utf16:audience,receipt_key_id:key,actor_id:author.actor_id(),command_id:author.command_id(),intent_digest:author.intent_digest(),workspace_id:Some(workspace),protocol_digest:None},Path::STRUCTURED).map_err(|_|CommunicationError)?;
    Ok(VerifiedConversationMessage{message_id:mid,sequence:number(meta,"sequence")?,accepted_at:number(value,"accepted_at")?,thread_root:thread,author,context,content})
}

pub(super) fn verify_read(result:&WireValue,command:&WireValue,prepared:&VerifiedPreparedCommand,key:&str)->Result<()> {
    let workspace=prepared.workspace_id().ok_or(CommunicationError)?;let body=command.get("body").ok_or(CommunicationError)?;
    if command.get("instance_id")!=Some(&WireValue::Null) || command.get("protocol_digest")!=Some(&WireValue::Null)
        || command.get("expected_workspace_revision")!=Some(&WireValue::Null) || command.get("expected_instance_revision")!=Some(&WireValue::Null)
        || !matches!(command.get("exact_input_refs"),Some(WireValue::Array(v)) if v.is_empty()) {return Err(CommunicationError);}
    match prepared.action_id() {
        "structure.conversation.post"=>{
            let ctx=ConversationContentContext::from_command(command)?;let meta=result.get("conversation").ok_or(CommunicationError)?;metadata(meta,workspace)?;
            if text(result,"message_id")?!=ctx.message_id()? || text(result,"status")?!="APPLIED" {return Err(CommunicationError);}
            if ctx.thread_root.as_ref().is_some_and(|s|Some(s.as_str())!=meta.get("thread_root").and_then(WireValue::as_string).as_deref()) {return Err(CommunicationError);}
            let thread=text(meta,"thread_root")?;
            if ctx.context.as_ref().is_some_and(|c|conversation_thread_id(workspace,c).ok().as_deref()!=Some(thread.as_str()))
                || ctx.context.is_none()&&ctx.reply_to.is_none()&&ctx.thread_root.is_none()&&thread!=ctx.message_id()? {return Err(CommunicationError);}
        }
        "structure.conversation.get"|"structure.conversation.pin.set"=>{
            let head=result.get("conversation").ok_or(CommunicationError)?;
            if text(head,"conversation_id")?!=space_conversation_id(workspace)? || text(head,"workspace_id")?!=workspace || text(head,"message_format")?!=FORMAT {return Err(CommunicationError);}
            number(head,"sequence")?;number(head,"pin_revision")?;
            if prepared.action_id()=="structure.conversation.get" {verify_pin_source(head,prepared.audience_utf16(),workspace,key)?;verify_pin_message(head,prepared.audience_utf16(),workspace,key)?;}
            if prepared.action_id()=="structure.conversation.pin.set" && (number(head,"pin_revision")?!=number(body,"expected_revision")?.checked_add(1).ok_or(CommunicationError)? || !same(head.get("pin_reference"),body.get("reference"))? || text(head,"pin_author")?!=prepared.actor_id() || text(head,"pin_command")?!=prepared.command_id()) {return Err(CommunicationError);}
        }
        "structure.conversation.messages.read"=>{
            let head=result.get("conversation").ok_or(CommunicationError)?;
            if text(head,"conversation_id")?!=text(body,"conversation_id")? || text(head,"conversation_id")?!=space_conversation_id(workspace)? || text(head,"workspace_id")?!=workspace || text(head,"message_format")?!=FORMAT {return Err(CommunicationError);}
            let frontier=number(head,"sequence")?;let messages=array(result,"messages",32)?;let limit=body.get("limit").map(|_|number(body,"limit")).transpose()?.unwrap_or(20);
            if messages.len() as u64>limit {return Err(CommunicationError);}
            let mut previous=0;
            for message in messages {
                let meta=message.get("conversation").ok_or(CommunicationError)?;metadata(meta,workspace)?;let sequence=number(meta,"sequence")?;
                if sequence<=previous || sequence>frontier || body.get("after_sequence").filter(|v|!matches!(v,WireValue::Null)).is_some_and(|_|number(body,"after_sequence").is_ok_and(|n|sequence<=n))
                    || body.get("before_sequence").filter(|v|!matches!(v,WireValue::Null)).is_some_and(|_|number(body,"before_sequence").is_ok_and(|n|sequence>=n))
                    || optional_token(body,"thread_root")?.is_some_and(|t|meta.get("thread_root").and_then(WireValue::as_string).as_deref()!=Some(t.as_str())) {return Err(CommunicationError);}
                previous=sequence;
                verify_message_snapshot(message,prepared.audience_utf16(),workspace,key)?;
            }
            flag(result,"more")?;
        }
        "structure.conversation.deliveries.read"=>{
            if result.get("message_id")!=body.get("message_id") || !digest(&text(result,"audience_digest")?) || text(result,"model_response")?!="NOT_ATTESTED" {return Err(CommunicationError);}
            let counts=result.get("counts").ok_or(CommunicationError)?;let targets=number(counts,"targets")?;if targets>256 {return Err(CommunicationError);}
            for field in ["pending","terminal","receiver_stored","application_consumed"] {if number(counts,field)?>targets {return Err(CommunicationError);}}
            let mut previous=optional_token(body,"after")?.unwrap_or_default();
            for row in array(result,"deliveries",32)? {let mailbox=token_field(row,"mailbox_id")?;if mailbox<=previous {return Err(CommunicationError);}previous=mailbox;token_field(row,"actor_id")?;token_field(row,"membership_id")?;
                if let Some(delivery)=optional_token(row,"delivery_id")? {if delivery!=id(json!(["peerwork.delivery.v1",workspace,previous,text(body,"message_id")?,null]))? || number(row,"sequence")?==0 {return Err(CommunicationError);}}
                if let Some(report)=row.get("host_report").filter(|v|!matches!(v,WireValue::Null)) {
                    host_report::verify(report,prepared.audience_utf16(),workspace,&text(row,"actor_id")?)?;
                    let scope=report.get("scope").ok_or(CommunicationError)?;
                    for field in ["mailbox_id","membership_id","sequence","delivery_id"] {if !same(scope.get(field),row.get(field))? {return Err(CommunicationError);}}
                }
            }
        }
        _=>return Err(CommunicationError),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer,SigningKey};
    fn as_wire(value:&serde_json::Value)->WireValue {parse_wire_json_bounded(value.to_string().as_bytes(),40,16000).unwrap()}
    fn sign(value:&serde_json::Value,typ:&str,key:&SigningKey)->String {
        let header=base64url(json!({"alg":"EdDSA","typ":typ,"kid":base64url(key.verifying_key().as_bytes())}).to_string().as_bytes());
        let input=format!("{header}.{}",base64url(value.to_string().as_bytes()));format!("{input}.{}",base64url(&key.sign(input.as_bytes()).to_bytes()))
    }
    fn fixture()->(serde_json::Value,String,Vec<u16>) {
        let sender=SigningKey::from_bytes(&[23;32]);let service=SigningKey::from_bytes(&[7;32]);
        let actor=base64url(&sha256(&[b"peerwork.identity.v1\0".as_slice(),sender.verifying_key().as_bytes()].concat()));
        let workspace="W".repeat(43);let room=space_conversation_id(&workspace).unwrap();
        let mut command=json!({"v":1,"audience":"unit","command_id":"C".repeat(43),"actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST","path":"/api/workspace/v1/commands","workspace_id":workspace,"instance_id":null,"protocol_digest":null,"action_id":"structure.conversation.post","expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"issued_at":1800000000000_u64,"expires_at":1800000060000_u64,
            "body":{"profile":PROFILE,"conversation_id":room,"audience":"SPACE_MEMBERS","thread_root":null,"reply_to":null,"context":null,"mentions":[],"content":{"mode":"WORKSPACE_E2EE"}}});
        let context=ConversationContentContext::from_command(&as_wire(&command)).unwrap();
        let sealed=seal_content_with_aad(&[37;32],b"Shared verified message",&context.canonical_aad().unwrap()).unwrap();
        command["body"]["content"]["body"]=serde_json::to_value(sealed).unwrap();
        let author=sign(&command,"peerwork.kernel-command.v1+jws",&sender);let intent=sha256_hex(author.as_bytes());
        let metadata=json!({"conversation_id":room,"sequence":1,"thread_root":context.message_id().unwrap(),"audience_digest":"a".repeat(64),"audience_count":2});
        let mut accepted=json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":workspace,"instance_id":null,"protocol_digest":null,"status":"APPLIED","message_id":context.message_id().unwrap(),"sender_membership":"S".repeat(43),"accepted_at":1800000000000_u64,"conversation":metadata,"author_intent":author});
        let result_digest=sha256_hex(canonical_wire_value(&as_wire(&accepted),Path::STRUCTURED).unwrap().as_bytes());
        let receipt=sign(&json!({"v":1,"audience":"unit","actor_id":actor,"workspace_id":workspace,"command_id":"C".repeat(43),"intent_digest":intent,"result_digest":result_digest,"protocol_digest":null,"event_sequence":null,"instance_revision":null,"accepted_at":1800000000000_u64}),"peerwork.kernel-receipt.v1+jws",&service);
        accepted.as_object_mut().unwrap().remove("author_intent");
        (json!({"state":"ACTIVE","message_id":context.message_id().unwrap(),"sender_actor":actor,"sender_membership":"S".repeat(43),"accepted_at":1800000000000_u64,"command_id":"C".repeat(43),"intent_digest":intent,"author_intent":author,"conversation":metadata,"acceptance":{"receipt":receipt,"result":accepted}}),base64url(service.verifying_key().as_bytes()),"unit".encode_utf16().collect())
    }
    #[test]
    fn conversation_authenticates_author_service_cut_body_and_physical_recipient() {
        let (value,key,audience)=fixture();let workspace="W".repeat(43);let verified=verify_conversation_message(&as_wire(&value),&audience,&workspace,&key).unwrap();
        let bytes=open_content_with_aad(&[37;32],verified.content(),&verified.context().canonical_aad().unwrap()).unwrap();assert_eq!(bytes.as_slice(),b"Shared verified message");
        let pins=MailboxPins{workspace_id:workspace.clone(),mailbox_id:"M".repeat(43),membership_id:"G".repeat(43),receiver_id:"R".repeat(43),epoch:1,destination_digest:"d".repeat(64),binding_version:1,after_sequence:0,after_control_sequence:None};
        let item=json!({"delivery_id":id(json!(["peerwork.delivery.v1",workspace,pins.mailbox_id,verified.message_id(),null])).unwrap(),"sequence":1,"kind":"MESSAGE","created_at":verified.accepted_at(),"message":value});
        let delivery=super::super::delivery(&as_wire(&item),&audience,&"A".repeat(43),&pins,&key).unwrap();assert!(delivery.message().is_none());assert_eq!(delivery.conversation_message().unwrap().message_id(),verified.message_id());assert!(delivery.sealed_message_content().is_some());
        let mut other=pins.clone();other.mailbox_id="N".repeat(43);assert!(super::super::delivery(&as_wire(&item),&audience,&"A".repeat(43),&other,&key).is_err());
        assert!(verify_conversation_message(&as_wire(&value),&audience,&"Q".repeat(43),&key).is_err());
        assert!(verify_conversation_message(&as_wire(&value),&audience,&workspace,&base64url(SigningKey::from_bytes(&[9;32]).verifying_key().as_bytes())).is_err());
        for (field,changed) in [("sequence",json!(2)),("thread_root",json!("T".repeat(43))),("audience_digest",json!("b".repeat(64))),("audience_count",json!(3))] {
            let mut bad=value.clone();bad["conversation"][field]=changed.clone();bad["acceptance"]["result"]["conversation"][field]=changed;assert!(verify_conversation_message(&as_wire(&bad),&audience,&workspace,&key).is_err(),"{field}");
        }
        for field in ["sender_actor","sender_membership","message_id","command_id","intent_digest","author_intent"] {
            let mut bad=value.clone();bad[field]=json!("X".repeat(43));assert!(verify_conversation_message(&as_wire(&bad),&audience,&workspace,&key).is_err(),"{field}");
        }
    }
    #[test]
    fn conversation_proof_ignores_object_presentation_order_but_keeps_its_signed_fields() {
        let (value,key,audience)=fixture();let mut wire=as_wire(&value);
        let WireValue::Object(fields)=&mut wire else{panic!("fixture object");};
        let (_,meta)=fields.iter_mut().find(|(name,_)|name.iter().copied().eq("conversation".encode_utf16())).unwrap();
        let WireValue::Object(metadata)=meta else{panic!("room metadata");};metadata.reverse();
        assert!(verify_conversation_message(&wire,&audience,&"W".repeat(43),&key).is_ok());
        metadata_tamper(&mut wire);
        assert!(verify_conversation_message(&wire,&audience,&"W".repeat(43),&key).is_err());
        fn metadata_tamper(value:&mut WireValue){
            let WireValue::Object(fields)=value else{unreachable!()};
            let (_,WireValue::Object(meta))=fields.iter_mut().find(|(name,_)|name.iter().copied().eq("conversation".encode_utf16())).unwrap() else{unreachable!()};
            let (_,digest)=meta.iter_mut().find(|(name,_)|name.iter().copied().eq("audience_digest".encode_utf16())).unwrap();*digest=as_wire(&json!("b".repeat(64)));
        }
    }
    #[test]
    fn pinned_body_is_independent_of_the_loaded_history_page_and_cannot_be_substituted() {
        let (message,key,audience)=fixture();let workspace="W".repeat(43);
        let mut head=json!({"pin_reference":{"kind":"MESSAGE","message_id":message["message_id"]},"sequence":100,"pin_message":message});
        assert!(verify_pin_message(&as_wire(&head),&audience,&workspace,&key).is_ok());
        head["pin_message"]["message_id"]=json!("T".repeat(43));assert!(verify_pin_message(&as_wire(&head),&audience,&workspace,&key).is_err());
        let (message,_,_)=fixture();head["pin_message"]=message;head["sequence"]=json!(0);assert!(verify_pin_message(&as_wire(&head),&audience,&workspace,&key).is_err());
        head["sequence"]=json!(100);let m=&head["pin_message"];head["pin_message"]=json!({"state":"WITHDRAWN","message_id":m["message_id"],"accepted_at":m["accepted_at"],"sender_actor":m["sender_actor"],"conversation":m["conversation"]});assert!(verify_pin_message(&as_wire(&head),&audience,&workspace,&key).is_ok());
        head["pin_reference"]=json!(null);assert!(verify_pin_message(&as_wire(&head),&audience,&workspace,&key).is_err());head["pin_message"]=json!(null);assert!(verify_pin_message(&as_wire(&head),&audience,&workspace,&key).is_ok());
    }
    #[test]
    fn conversation_context_binds_all_metadata_without_reinterpreting_directed_mail() {
        let (value,_,audience)=fixture();let author=verify_structure_author_intent(value["author_intent"].as_str().unwrap(),&audience).unwrap();
        assert!(authored_message_content(&author).is_err());let (NativeMessageContext::Conversation(mut context),_)=authored_native_message_content(&author).unwrap() else{panic!("wrong domain");};
        let original=context.canonical_aad().unwrap();let sealed=seal_content_with_aad(&[37;32],b"context",&original).unwrap();
        context.mentions.push("A".repeat(43));assert!(open_content_with_aad(&[37;32],&sealed,&context.canonical_aad().unwrap()).is_err());context.mentions.push("A".repeat(43));assert!(context.canonical_aad().is_err());
        let mut command:serde_json::Value=wire(author.command()).unwrap();command["body"]["audience"]=json!("ONLINE_MEMBERS");assert!(ConversationContentContext::from_command(&as_wire(&command)).is_err());
        command["body"]["audience"]=json!("SPACE_MEMBERS");command["body"]["recipients"]=json!([]);assert!(ConversationContentContext::from_command(&as_wire(&command)).is_err());
        let mut record=ConversationRecordContext{kind:"RECORD".into(),instance_id:"I".repeat(43),execution_context_id:"E".repeat(43),protocol_digest:"f".repeat(64),entity_id:"O".repeat(43),record_id:"R".repeat(43),revision:1};
        let first=conversation_thread_id(&context.workspace_id,&record).unwrap();record.record_id="V".repeat(43);record.revision=2;assert_eq!(first,conversation_thread_id(&context.workspace_id,&record).unwrap());record.entity_id="Q".repeat(43);assert_ne!(first,conversation_thread_id(&context.workspace_id,&record).unwrap());
    }
}
