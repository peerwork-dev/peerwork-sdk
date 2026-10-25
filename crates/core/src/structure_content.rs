//! Body-only encryption for backend-structure-v1. Business fields are never
//! encrypted here or available through this module to a business evaluator.
use crate::{canonical::{canonical,Path},crypto::{base64url,decode_base64url,sha256,sha256_hex},
    structure_execution::PROFILE};
use aes_gcm::{aead::{Aead,KeyInit,Payload},Aes256Gcm,Nonce};
use rand_core::{OsRng,RngCore};
use serde::{Deserialize,Serialize};
use serde_json::json;
use thiserror::Error;
use zeroize::Zeroizing;
use crate::{prepared_command::VerifiedStructureAuthorIntent,wire_json::WireValue};

/// Body and aggregate plaintext limits. Ciphertext uses canonical 8192-byte
/// base64url segments without enlarging ordinary JSON scalar/request budgets.
pub const MAX_BODY_BYTES:usize=65536;
pub const MAX_BODY_BATCH_BYTES:usize=65536;
pub const INLINE_BODY_BYTES:usize=6128;
pub const CIPHERTEXT_CHUNK_BYTES:usize=8192;
pub const MAX_BODY_REQUEST_BYTES:usize=512*1024;

#[derive(Debug,Error,PartialEq,Eq)]
pub enum StructureContentError {
    #[error("invalid body encryption context, key selection or wire format")]
    Invalid,
    #[error("body exceeds the supported attachment limit")]
    TooLarge,
    #[error("body authentication failed")]
    Authentication,
    #[error("OS random source failed")]
    Entropy,
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct StructureSealedContent {
    pub algorithm:String,
    pub key_id:String,
    pub nonce:String,
    #[serde(default,skip_serializing_if="String::is_empty")]
    pub ciphertext:String,
    #[serde(default,skip_serializing_if="Vec::is_empty")]
    pub ciphertext_chunks:Vec<String>,
    pub aad_digest:String,
}

/// All target fields come from the original authenticated author's command,
/// not a mutable service projection or the current reader's command.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct StructureContentContext {
    pub workspace_id:String,
    pub instance_id:String,
    pub protocol_digest:String,
    pub actor_id:String,
    pub command_id:String,
    pub action_id:String,
    pub record_index:u8,
}
fn token(v:&str)->bool{v.len()==43&&v.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'))}
impl StructureContentContext {
    pub fn from_author(author:&VerifiedStructureAuthorIntent,record_index:u8)->Result<Self,StructureContentError>{
        if !matches!(author.action_id(),"structure.action"|"structure.checkpoint.records"){return Err(StructureContentError::Invalid);}
        let c=author.command();let text=|value:Option<&WireValue>|value.and_then(WireValue::as_string).ok_or(StructureContentError::Invalid);
        let context=Self{workspace_id:author.workspace_id().ok_or(StructureContentError::Invalid)?.into(),
            instance_id:text(c.get("instance_id"))?,protocol_digest:author.protocol_digest().ok_or(StructureContentError::Invalid)?.into(),
            actor_id:author.actor_id().into(),command_id:author.command_id().into(),
            action_id:text(c.get("body").and_then(|b|b.get("action_id")))?,record_index};
        context.canonical_aad()?;Ok(context)
    }
    pub fn canonical_aad(&self)->Result<String,StructureContentError>{
        if ![&self.workspace_id,&self.instance_id,&self.actor_id,&self.command_id].into_iter().all(|s|token(s))
            ||self.protocol_digest.len()!=64||!self.protocol_digest.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f'))
            ||self.action_id.is_empty()||self.action_id.encode_utf16().count()>120||self.record_index>=8{
            return Err(StructureContentError::Invalid);
        }
        canonical(&json!({"profile":PROFILE,"workspace_id":self.workspace_id,"instance_id":self.instance_id,
            "protocol_digest":self.protocol_digest,"actor_id":self.actor_id,"command_id":self.command_id,
            "action_id":self.action_id,"record_index":self.record_index}),Path::SecureArtifact)
            .map_err(|_|StructureContentError::Invalid)
    }
}

/// Select bytes from the original signature proof, not from caller-supplied
/// current state. Receipt verification separately binds a returned record to
/// this author and record index. Work is bounded by eight attachments.
pub fn authored_structure_content(author:&VerifiedStructureAuthorIntent,index:u8)
    ->Result<(StructureContentContext,StructureSealedContent),StructureContentError>{
    let context=StructureContentContext::from_author(author,index)?;
    let Some(WireValue::Array(contents))=author.command().get("body").and_then(|b|b.get("contents"))else{
        return Err(StructureContentError::Invalid);
    };
    if contents.len()>8{return Err(StructureContentError::Invalid);}
    let mut indices=std::collections::BTreeSet::new();let mut selected=None;
    for item in contents {
        let at=item.get("record_index").and_then(WireValue::as_number).filter(|n|n.is_finite()&&n.fract()==0.0&&(0.0..8.0).contains(n))
            .ok_or(StructureContentError::Invalid)? as u8;
        if item.object_len()!=Some(2)||!indices.insert(at){return Err(StructureContentError::Invalid);}
        if at==index{selected=item.get("body");}
    }
    let body=selected.ok_or(StructureContentError::Invalid)?;
    if body.object_len()!=Some(5){return Err(StructureContentError::Invalid);}
    let wire=crate::wire_json::canonical_wire_value(body,Path::KERNEL).map_err(|_|StructureContentError::Invalid)?;
    let sealed:StructureSealedContent=serde_json::from_str(&wire).map_err(|_|StructureContentError::Invalid)?;
    sealed.decoded_ciphertext()?;
    Ok((context,sealed))
}

/// Domain-separated commitment to a uniformly random 256-bit key. Callers
/// must not derive these keys from passwords or other low-entropy inputs.
pub fn structure_content_key_id(key:&[u8;32])->String{
    let mut input=Zeroizing::new(b"peerwork.structure-content-key.v1\0".to_vec());
    input.extend_from_slice(key);base64url(&sha256(&input))
}

pub fn seal_structure_content(key:&[u8;32],plaintext:&[u8],context:&StructureContentContext)
    ->Result<StructureSealedContent,StructureContentError>{
    if plaintext.len()>MAX_BODY_BYTES{return Err(StructureContentError::TooLarge);}
    let aad=context.canonical_aad()?;
    let mut nonce=[0;12];OsRng.try_fill_bytes(&mut nonce).map_err(|_|StructureContentError::Entropy)?;
    let ciphertext=Aes256Gcm::new_from_slice(key).map_err(|_|StructureContentError::Invalid)?
        .encrypt(Nonce::from_slice(&nonce),Payload{msg:plaintext,aad:aad.as_bytes()})
        .map_err(|_|StructureContentError::Authentication)?;
    let encoded=base64url(&ciphertext);
    let (ciphertext,ciphertext_chunks)=if encoded.len()<=CIPHERTEXT_CHUNK_BYTES{(encoded,Vec::new())}else{
        (String::new(),encoded.as_bytes().chunks(CIPHERTEXT_CHUNK_BYTES).map(|s|String::from_utf8(s.to_vec()).expect("base64url is ASCII")).collect())
    };
    Ok(StructureSealedContent{algorithm:"A256GCM".into(),key_id:structure_content_key_id(key),nonce:base64url(&nonce),
        ciphertext,ciphertext_chunks,aad_digest:sha256_hex(aad.as_bytes())})
}

pub fn open_structure_content(key:&[u8;32],sealed:&StructureSealedContent,context:&StructureContentContext)
    ->Result<Zeroizing<Vec<u8>>,StructureContentError>{
    let aad=context.canonical_aad()?;
    if sealed.algorithm!="A256GCM"||sealed.key_id!=structure_content_key_id(key)
        ||sealed.aad_digest!=sha256_hex(aad.as_bytes())||sealed.nonce.len()!=16{
        return Err(StructureContentError::Invalid);
    }
    let nonce=decode_base64url(&sealed.nonce).map_err(|_|StructureContentError::Invalid)?;
    let ciphertext=sealed.decoded_ciphertext()?;
    if nonce.len()!=12||!(16..=MAX_BODY_BYTES+16).contains(&ciphertext.len()){
        return Err(StructureContentError::Invalid);
    }
    Aes256Gcm::new_from_slice(key).map_err(|_|StructureContentError::Invalid)?
        .decrypt(Nonce::from_slice(&nonce),Payload{msg:&ciphertext,aad:aad.as_bytes()})
        .map(Zeroizing::new).map_err(|_|StructureContentError::Authentication)
}

impl StructureSealedContent {
    fn decoded_ciphertext(&self)->Result<Vec<u8>,StructureContentError>{
        let encoded=if self.ciphertext_chunks.is_empty(){
            if self.ciphertext.len()>CIPHERTEXT_CHUNK_BYTES{return Err(StructureContentError::Invalid);}
            self.ciphertext.clone()
        }else{
            if !self.ciphertext.is_empty()||!(2..=11).contains(&self.ciphertext_chunks.len())
                ||self.ciphertext_chunks.iter().any(|c|c.is_empty()||c.len()>CIPHERTEXT_CHUNK_BYTES)
                ||self.ciphertext_chunks[..self.ciphertext_chunks.len()-1].iter().any(|c|c.len()!=CIPHERTEXT_CHUNK_BYTES){return Err(StructureContentError::Invalid);}
            let joined=self.ciphertext_chunks.join("");if joined.len()<=CIPHERTEXT_CHUNK_BYTES||joined.len()>87403{return Err(StructureContentError::Invalid);}joined
        };
        let bytes=decode_base64url(&encoded).map_err(|_|StructureContentError::Invalid)?;
        if !(16..=MAX_BODY_BYTES+16).contains(&bytes.len())||base64url(&bytes)!=encoded{return Err(StructureContentError::Invalid);}
        Ok(bytes)
    }
}
