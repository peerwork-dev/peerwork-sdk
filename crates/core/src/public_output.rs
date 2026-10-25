//! Individually disclosable author signatures. A selected proof never carries
//! another output or the complete private business command.
use crate::{crypto::{actor_id,decode_base64url,verifying_key},wire_json::{WireValue,parse_wire_json_bounded}};
use ed25519_dalek::{Signature,Verifier};
pub const TYPE:&str="peerwork.public-output.v1+jws";
#[derive(Debug)]pub struct Invalid;
pub struct VerifiedOutput{pub payload:WireValue,pub text:String}
fn string(value:&WireValue,key:&str)->Result<String,Invalid>{value.get(key).and_then(WireValue::as_string).ok_or(Invalid)}
fn token(s:&str)->bool{s.len()==43&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
fn integer(v:&WireValue)->Result<u64,Invalid>{v.as_number().filter(|n|n.fract()==0.0&&(0.0..=9_007_199_254_740_991.0).contains(n)).map(|n|n as u64).ok_or(Invalid)}
pub fn verify(statement:&WireValue,audience:&[u16])->Result<VerifiedOutput,Invalid>{
 if audience.is_empty()||audience.len()>200{return Err(Invalid)}
 if statement.object_len()!=Some(2)||string(statement,"format")?!="AUTHOR_PUBLIC_OUTPUT_V1"{return Err(Invalid)}
 let Some(WireValue::Array(chunks))=statement.get("chunks")else{return Err(Invalid)};if chunks.is_empty()||chunks.len()>16{return Err(Invalid)}let mut joined=String::new();for chunk in chunks{let s=chunk.as_string().filter(|s|!s.is_empty()&&s.len()<=8192).ok_or(Invalid)?;joined.push_str(&s);}
 let parts=joined.split('.').collect::<Vec<_>>();if parts.len()!=3{return Err(Invalid)}
 let header=parse_wire_json_bounded(&decode_base64url(parts[0]).map_err(|_|Invalid)?,3,256).map_err(|_|Invalid)?;if header.object_len()!=Some(3)||string(&header,"alg")?!="EdDSA"||string(&header,"typ")?!=TYPE{return Err(Invalid)}let key=verifying_key(&string(&header,"kid")?).map_err(|_|Invalid)?;
 let sig:[u8;64]=decode_base64url(parts[2]).map_err(|_|Invalid)?.try_into().map_err(|_|Invalid)?;key.verify(format!("{}.{}",parts[0],parts[1]).as_bytes(),&Signature::from_bytes(&sig)).map_err(|_|Invalid)?;
 let payload=parse_wire_json_bounded(&decode_base64url(parts[1]).map_err(|_|Invalid)?,32,100000).map_err(|_|Invalid)?;
 if payload.object_len()!=Some(if payload.get("document_time").is_some(){15}else{14})||payload.get("v").and_then(WireValue::as_number)!=Some(1.0)||string(&payload,"profile")?!=crate::structure_execution::PROFILE||payload.get("audience").and_then(WireValue::as_utf16)!=Some(audience)||string(&payload,"actor_id")?!=actor_id(&key.to_bytes())||string(&payload,"disclosure")?!="PUBLISH_SELECTED_RECORD"{return Err(Invalid)}
 if let Some(time)=payload.get("document_time"){if time.object_len()!=Some(2){return Err(Invalid)}crate::document_time::normalized(time).map_err(|_|Invalid)?;}
 for field in ["actor_id","command_id","workspace_id","instance_id"]{if !token(&string(&payload,field)?){return Err(Invalid)}}let digest=string(&payload,"protocol_digest")?;if digest.len()!=64||!digest.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f')){return Err(Invalid)}
 let action=payload.get("action_id").and_then(WireValue::as_utf16).ok_or(Invalid)?;let title=payload.get("title").and_then(WireValue::as_utf16).ok_or(Invalid)?;if action.is_empty()||action.len()>120||title.is_empty()||title.len()>240||integer(payload.get("policy_revision").ok_or(Invalid)?)?==0||integer(payload.get("record_index").ok_or(Invalid)?)?>7{return Err(Invalid)}
 let body=payload.get("body").ok_or(Invalid)?;if body.object_len()!=Some(2)||string(body,"format")?!="PUBLIC_UTF8_BASE64"{return Err(Invalid)}let Some(WireValue::Array(chunks))=body.get("chunks")else{return Err(Invalid)};if chunks.len()>11{return Err(Invalid)}let mut encoded=String::new();for part in chunks{let s=part.as_string().filter(|s|!s.is_empty()&&s.len()<=8192).ok_or(Invalid)?;encoded.push_str(&s);}let bytes=decode_base64url(&encoded).map_err(|_|Invalid)?;if bytes.len()>65536{return Err(Invalid)}let text=String::from_utf8(bytes).map_err(|_|Invalid)?;Ok(VerifiedOutput{payload,text})
}
pub fn for_command(statement:&WireValue,command:&WireValue,index:u64)->Result<VerifiedOutput,Invalid>{
 let output=verify(statement,command.get("audience").and_then(WireValue::as_utf16).ok_or(Invalid)?)?;for field in ["actor_id","command_id","workspace_id","instance_id","protocol_digest"]{if output.payload.get(field)!=command.get(field){return Err(Invalid)}}
 let expected=crate::document_time::for_command(command,index).map_err(|_|Invalid)?;if !crate::document_time::matches_claim(output.payload.get("document_time"),expected.as_ref()){return Err(Invalid)}
 let body=command.get("body").ok_or(Invalid)?;if output.payload.get("action_id")!=body.get("action_id")||output.payload.get("policy_revision")!=body.get("publication").and_then(|p|p.get("policy_revision"))||integer(output.payload.get("record_index").ok_or(Invalid)?)?!=index{return Err(Invalid)}Ok(output)
}
