//! Individually disclosable author signatures. A selected proof never carries
//! another output or the complete private business command.
use crate::{crypto::{actor_id,decode_base64url,verifying_key},wire_json::{WireValue,parse_wire_json_bounded}};
use ed25519_dalek::{Signature,Verifier};
pub const TYPE:&str="peerwork.public-output.v1+jws";
pub const HUMAN_TYPE:&str="peerwork.human-public-output.v1+jws";
#[derive(Debug)]pub struct Invalid;
pub struct VerifiedOutput{pub payload:WireValue,pub text:String}
fn string(value:&WireValue,key:&str)->Result<String,Invalid>{value.get(key).and_then(WireValue::as_string).ok_or(Invalid)}
fn token(s:&str)->bool{s.len()==43&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
fn integer(v:&WireValue)->Result<u64,Invalid>{v.as_number().filter(|n|n.fract()==0.0&&(0.0..=9_007_199_254_740_991.0).contains(n)).map(|n|n as u64).ok_or(Invalid)}
pub fn verify(statement:&WireValue,audience:&[u16])->Result<VerifiedOutput,Invalid>{
 if audience.is_empty()||audience.len()>200{return Err(Invalid)}
 let human=string(statement,"format")?=="AUTHOR_PUBLIC_OUTPUT_HUMAN_V1";if statement.object_len()!=Some(if human{3}else{2})||!human&&string(statement,"format")?!="AUTHOR_PUBLIC_OUTPUT_V1"{return Err(Invalid)}
 let Some(WireValue::Array(chunks))=statement.get("chunks")else{return Err(Invalid)};if chunks.is_empty()||chunks.len()>16{return Err(Invalid)}let mut joined=String::new();for chunk in chunks{let s=chunk.as_string().filter(|s|!s.is_empty()&&s.len()<=8192).ok_or(Invalid)?;joined.push_str(&s);}
 let parts=joined.split('.').collect::<Vec<_>>();if parts.len()!=3{return Err(Invalid)}
 let header=parse_wire_json_bounded(&decode_base64url(parts[0]).map_err(|_|Invalid)?,3,256).map_err(|_|Invalid)?;if header.object_len()!=Some(3)||string(&header,"alg")?!="EdDSA"||string(&header,"typ")?!=if human{HUMAN_TYPE}else{TYPE}{return Err(Invalid)}let key=verifying_key(&string(&header,"kid")?).map_err(|_|Invalid)?;
 let sig:[u8;64]=decode_base64url(parts[2]).map_err(|_|Invalid)?.try_into().map_err(|_|Invalid)?;key.verify(format!("{}.{}",parts[0],parts[1]).as_bytes(),&Signature::from_bytes(&sig)).map_err(|_|Invalid)?;
 let payload=parse_wire_json_bounded(&decode_base64url(parts[1]).map_err(|_|Invalid)?,32,100000).map_err(|_|Invalid)?;
 if human{let container:serde_json::Value=serde_json::from_str(&crate::wire_json::canonical_wire_value(statement,crate::canonical::Path::SecureArtifact).map_err(|_|Invalid)?).map_err(|_|Invalid)?;let proofs=crate::human_author::AuthorProofContext::from_json_container(&container).map_err(|_|Invalid)?.ok_or(Invalid)?;if proofs.roots.len()!=1||proofs.devices.len()!=1{return Err(Invalid)}let verified=crate::human_author::verify_account_payload(&joined,HUMAN_TYPE,audience,Some(&proofs)).map_err(|_|Invalid)?;if verified.author().kind!="human-device-v1"{return Err(Invalid)}}
 if payload.object_len()!=Some((if payload.get("document_time").is_some(){15}else{14})+if human{1}else{0})||payload.get("v").and_then(WireValue::as_number)!=Some(1.0)||string(&payload,"profile")?!=crate::structure_execution::PROFILE||payload.get("audience").and_then(WireValue::as_utf16)!=Some(audience)||!human&&string(&payload,"actor_id")?!=actor_id(&key.to_bytes())||string(&payload,"disclosure")?!="PUBLISH_SELECTED_RECORD"{return Err(Invalid)}
 if let Some(time)=payload.get("document_time"){if time.object_len()!=Some(2){return Err(Invalid)}crate::document_time::normalized(time).map_err(|_|Invalid)?;}
 for field in ["actor_id","command_id","workspace_id","instance_id"]{if !token(&string(&payload,field)?){return Err(Invalid)}}let digest=string(&payload,"protocol_digest")?;if digest.len()!=64||!digest.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f')){return Err(Invalid)}
 let action=payload.get("action_id").and_then(WireValue::as_utf16).ok_or(Invalid)?;let title=payload.get("title").and_then(WireValue::as_utf16).ok_or(Invalid)?;if action.is_empty()||action.len()>120||title.is_empty()||title.len()>240||integer(payload.get("policy_revision").ok_or(Invalid)?)?==0||integer(payload.get("record_index").ok_or(Invalid)?)?>7{return Err(Invalid)}
 let body=payload.get("body").ok_or(Invalid)?;if body.object_len()!=Some(2)||string(body,"format")?!="PUBLIC_UTF8_BASE64"{return Err(Invalid)}let Some(WireValue::Array(chunks))=body.get("chunks")else{return Err(Invalid)};if chunks.len()>11{return Err(Invalid)}let mut encoded=String::new();for part in chunks{let s=part.as_string().filter(|s|!s.is_empty()&&s.len()<=8192).ok_or(Invalid)?;encoded.push_str(&s);}let bytes=decode_base64url(&encoded).map_err(|_|Invalid)?;if bytes.len()>65536{return Err(Invalid)}let text=String::from_utf8(bytes).map_err(|_|Invalid)?;Ok(VerifiedOutput{payload,text})
}
pub fn for_command(statement:&WireValue,command:&WireValue,index:u64)->Result<VerifiedOutput,Invalid>{
 let output=verify(statement,command.get("audience").and_then(WireValue::as_utf16).ok_or(Invalid)?)?;if output.payload.get("author")!=command.get("author"){return Err(Invalid)}for field in ["actor_id","command_id","workspace_id","instance_id","protocol_digest"]{if output.payload.get(field)!=command.get(field){return Err(Invalid)}}
 let expected=crate::document_time::for_command(command,index).map_err(|_|Invalid)?;if !crate::document_time::matches_claim(output.payload.get("document_time"),expected.as_ref()){return Err(Invalid)}
 let body=command.get("body").ok_or(Invalid)?;if output.payload.get("action_id")!=body.get("action_id")||output.payload.get("policy_revision")!=body.get("publication").and_then(|p|p.get("policy_revision"))||integer(output.payload.get("record_index").ok_or(Invalid)?)?!=index{return Err(Invalid)}Ok(output)
}

#[cfg(test)]mod tests{
 use super::*;
 use crate::crypto::{base64url,sign_compact};
 use ed25519_dalek::SigningKey;
 use serde_json::{Value,json};
 fn wire(value:&Value)->WireValue{parse_wire_json_bounded(value.to_string().as_bytes(),40,250000).unwrap()}
 fn statement(payload:&Value,key:&SigningKey,proofs:Option<Value>)->Value{
  let human=proofs.is_some();let signed=sign_compact(&json!({"alg":"EdDSA","typ":if human{HUMAN_TYPE}else{TYPE},"kid":base64url(&key.verifying_key().to_bytes())}),payload,key).unwrap();
  let mut result=json!({"format":if human{"AUTHOR_PUBLIC_OUTPUT_HUMAN_V1"}else{"AUTHOR_PUBLIC_OUTPUT_V1"},"chunks":[signed]});if let Some(proofs)=proofs{result["author_proofs"]=proofs}result
 }
 fn fixture()->(Value,Value,Value,SigningKey){
  let source:Value=serde_json::from_str(include_str!("../../../tests/fixtures/human-author-v1.json")).unwrap();let key=SigningKey::from_bytes(&[6;32]);
  let command:Value=serde_json::from_slice(&decode_base64url(source["commands"]["human1"].as_str().unwrap().split('.').nth(1).unwrap()).unwrap()).unwrap();
  let mut payload=json!({"v":1,"profile":"backend-structure-v1","audience":source["audience"],"actor_id":source["peer_id"],"command_id":command["command_id"],"workspace_id":command["workspace_id"],"instance_id":command["instance_id"],"protocol_digest":command["protocol_digest"],"action_id":"post","policy_revision":1,"record_index":0,"disclosure":"PUBLISH_SELECTED_RECORD","title":"Selected public output","body":{"format":"PUBLIC_UTF8_BASE64","chunks":[base64url(b"Selected Human output")]}});payload["author"]=source["first"]["author"].clone();
  let mut proofs=json!({"format":"peerwork.human-author-proofs.v1","roots":{},"devices":{}});proofs["roots"][source["first"]["root_hash"].as_str().unwrap()]=source["first"]["root_wire"].clone();proofs["devices"][source["first"]["device_hash"].as_str().unwrap()]=source["first"]["device_wire"].clone();
  (payload,proofs,command,key)
 }
 #[test]fn human_selected_output_uses_exact_historical_author_and_cannot_be_execution_authority(){
  let(payload,proofs,mut command,key)=fixture();let output=statement(&payload,&key,Some(proofs.clone()));let audience="human-author-fixture".encode_utf16().collect::<Vec<_>>();
  assert_eq!(verify(&wire(&output),&audience).unwrap().text,"Selected Human output");command["body"]["publication"]=json!({"policy_revision":1});assert!(for_command(&wire(&output),&wire(&command),0).is_ok());
  command["author"]["device_id"]=json!(base64url(&[31;32]));assert!(for_command(&wire(&output),&wire(&command),0).is_err());
  let context=crate::human_author::AuthorProofContext::from_json_container(&output).unwrap().unwrap();assert!(crate::human_author::verify_account_command(output["chunks"][0].as_str().unwrap(),&audience,Some(&context)).is_err());
  let typed_command=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":base64url(&key.verifying_key().to_bytes())}),&payload,&key).unwrap();assert!(crate::human_author::verify_account_command(&typed_command,&audience,Some(&context)).is_err(),"a valid Human signature cannot bypass command schema validation");
 }
 #[test]fn selected_public_output_rejects_proof_downgrade_substitution_and_wrong_audience(){
  let(payload,proofs,_,key)=fixture();let audience="human-author-fixture".encode_utf16().collect::<Vec<_>>();let output=statement(&payload,&key,Some(proofs));
  let mut missing=output.clone();missing["author_proofs"]["devices"]=json!({});assert!(verify(&wire(&missing),&audience).is_err());
  let mut extra=output.clone();extra["author_proofs"]["roots"]["0".repeat(64)]=json!("unrelated");assert!(verify(&wire(&extra),&audience).is_err());
  let mut downgrade=output.clone();downgrade["format"]=json!("AUTHOR_PUBLIC_OUTPUT_V1");downgrade.as_object_mut().unwrap().remove("author_proofs");assert!(verify(&wire(&downgrade),&audience).is_err());
  assert!(verify(&wire(&output),&"another-service".encode_utf16().collect::<Vec<_>>()).is_err());
  let mut substituted=payload.clone();substituted["actor_id"]=json!(base64url(&[32;32]));assert!(verify(&wire(&statement(&substituted,&key,output.get("author_proofs").cloned())),&audience).is_err());
 }
 #[test]fn native_public_output_retains_its_original_key_identity_contract(){
  let(mut payload,_,_,_)=fixture();let key=SigningKey::from_bytes(&[42;32]);payload.as_object_mut().unwrap().remove("author");payload["actor_id"]=json!(actor_id(&key.verifying_key().to_bytes()));let audience="human-author-fixture".encode_utf16().collect::<Vec<_>>();
  assert_eq!(verify(&wire(&statement(&payload,&key,None)),&audience).unwrap().text,"Selected Human output");payload["actor_id"]=json!(base64url(&[33;32]));assert!(verify(&wire(&statement(&payload,&key,None)),&audience).is_err());
 }
}
