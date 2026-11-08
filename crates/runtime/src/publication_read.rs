//! Anonymous selected PUBLIC reads. Owner publication signatures bind content;
//! fresh service receipts attest selection, not full-history business replay.
use crate::{transport::{HttpTransport,TransportConfig,TransportError,TransportOptions},workspace_urls::{self,WorkspaceUrlInput}};
use peerwork_core::{crypto::{actor_id,base64url,decode_base64url,sha256_hex,verifying_key},discovery::parse_discovery_wire,prepared_command::verify_structure_author_intent,wire_json::{parse_wire_json_bounded,canonical_wire_value},canonical::Path};
use ed25519_dalek::{Signature,Verifier};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use rand_core::{OsRng,RngCore};
use tokio_util::sync::CancellationToken;
const RECEIPT:&str="peerwork.publication-read.v1+jws";
type R<T>=Result<T,&'static str>;
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSource{
 pub control_origin:String,pub browser_origin:String,pub workspace_id:String,pub owner_actor_id:String,pub owner_key_id:String,
 #[serde(default)]pub audience:Option<String>,#[serde(default)]pub service_key:Option<String>,
 #[serde(default)]pub allow_loopback_http:bool,#[serde(default)]pub transport:TransportOptions,
}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint{pub profile:String,pub control_origin:String,pub workspace_id:String,pub owner_actor_id:String,pub owner_key_id:String,pub audience:String,pub service_key:String,pub publication_revision:u64}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRequest{
 pub source:PublicSource,#[serde(default="list")]pub kind:String,
 #[serde(default)]pub instance_id:Option<String>,#[serde(default)]pub record_id:Option<String>,
 #[serde(default="limit")]pub limit:usize,#[serde(default="order")]pub order:String,#[serde(default)]pub cursor:Option<String>,#[serde(default)]pub checkpoint:Option<Checkpoint>,
}
fn order()->String{"RECORD_ID_ASC".into()}
fn list()->String{"ENTRIES".into()}fn limit()->usize{20}
fn text(v:&Value,k:&str)->R<String>{v[k].as_str().map(str::to_owned).ok_or("PUBLIC_RESPONSE_INVALID")}
fn wire(bytes:&[u8],max:usize)->R<Value>{let v=parse_wire_json_bounded(bytes,42,max).map_err(|_|"PUBLIC_RESPONSE_INVALID")?;serde_json::from_str(&canonical_wire_value(&v,Path::STRUCTURED).map_err(|_|"PUBLIC_RESPONSE_INVALID")?).map_err(|_|"PUBLIC_RESPONSE_INVALID")}
fn canon(v:&Value)->R<String>{let bytes=serde_json::to_vec(v).map_err(|_|"PUBLIC_RESPONSE_INVALID")?;let value=parse_wire_json_bounded(&bytes,42,1_048_576).map_err(|_|"PUBLIC_RESPONSE_INVALID")?;canonical_wire_value(&value,Path::STRUCTURED).map_err(|_|"PUBLIC_RESPONSE_INVALID")}
fn fail_transport(e:TransportError)->&'static str{match e{TransportError::Cancelled=>"CANCELLED",TransportError::Timeout=>"PUBLIC_TIMEOUT",TransportError::ResponseTooLarge=>"PUBLIC_RESPONSE_LIMIT",_=>"PUBLIC_TRANSPORT_FAILED"}}
fn receipt(jws:&str,key:&str)->R<Value>{
 let parts=jws.split('.').collect::<Vec<_>>();if parts.len()!=3||jws.len()>8192{return Err("PUBLIC_RECEIPT_INVALID")}
 let h=decode_base64url(parts[0]).map_err(|_|"PUBLIC_RECEIPT_INVALID")?;let header=wire(&h,256)?;
 if header.as_object().map(|o|o.len())!=Some(3)||header["alg"]!="EdDSA"||header["typ"]!=RECEIPT||header["kid"]!=key{return Err("PUBLIC_RECEIPT_INVALID")}
 let signature:[u8;64]=decode_base64url(parts[2]).map_err(|_|"PUBLIC_RECEIPT_INVALID")?.try_into().map_err(|_|"PUBLIC_RECEIPT_INVALID")?;
 verifying_key(key).map_err(|_|"PUBLIC_RECEIPT_INVALID")?.verify(format!("{}.{}",parts[0],parts[1]).as_bytes(),&Signature::from_bytes(&signature)).map_err(|_|"PUBLIC_RECEIPT_INVALID")?;
 wire(&decode_base64url(parts[1]).map_err(|_|"PUBLIC_RECEIPT_INVALID")?,4096)
}
fn authored(source:&Value,scope:&PublicSource,audience:&str)->R<Value>{
 let jws=text(source,"author_intent")?;let verified=verify_structure_author_intent(&jws,&audience.encode_utf16().collect::<Vec<_>>()).map_err(|_|"PUBLIC_SOURCE_INVALID")?;
 if verified.workspace_id()!=Some(scope.workspace_id.as_str())||source["actor_id"]!=verified.actor_id()||source["command_id"]!=verified.command_id()||source["intent_digest"]!=verified.intent_digest(){return Err("PUBLIC_SOURCE_INVALID")}
 serde_json::from_str(&canonical_wire_value(verified.command(),Path::STRUCTURED).map_err(|_|"PUBLIC_SOURCE_INVALID")?).map_err(|_|"PUBLIC_SOURCE_INVALID")
}
fn publisher(source:&Value,owner:&PublicSource,audience:&str)->R<Value>{let command=authored(source,owner,audience)?;if command["actor_id"]!=owner.owner_actor_id{return Err("PUBLIC_SOURCE_INVALID")}Ok(command)}
fn reference(source:&Value,sources:&Value,used:&mut std::collections::BTreeSet<String>,cache:&mut std::collections::BTreeMap<String,Value>,scope:&PublicSource,audience:&str)->R<Value>{
 let k=text(source,"source_key")?;let original=sources.get(&k).ok_or("PUBLIC_SOURCE_INVALID")?;
 if ["actor_id","command_id","intent_digest"].iter().any(|field|source[*field]!=original[*field])||k!=sha256_hex(canon(&json!([original["actor_id"],scope.workspace_id,original["command_id"]]))?.as_bytes()){return Err("PUBLIC_SOURCE_INVALID")}
 used.insert(k.clone());if !cache.contains_key(&k){cache.insert(k.clone(),authored(original,scope,audience)?);}Ok(cache[&k].clone())
}

fn revision(value:&Value)->R<u64>{value.as_u64().filter(|n|*n>0&&*n<=9_007_199_254_740_991).ok_or("PUBLIC_RESPONSE_INVALID")}
fn validate_source(s:&PublicSource)->R<()> {
 workspace_urls::origin(&s.control_origin,s.allow_loopback_http)?;workspace_urls::origin(&s.browser_origin,s.allow_loopback_http)?;
 if !workspace_urls::token(&s.workspace_id)||!workspace_urls::token(&s.owner_actor_id)||s.audience.as_ref().is_some_and(|s|s.is_empty()||s.encode_utf16().count()>200){return Err("PUBLIC_SOURCE_INVALID")}
 let key=verifying_key(&s.owner_key_id).map_err(|_|"PUBLIC_SOURCE_INVALID")?;if actor_id(&key.to_bytes())!=s.owner_actor_id{return Err("PUBLIC_SOURCE_INVALID")}
 if s.service_key.as_ref().is_some_and(|k|verifying_key(k).is_err()){return Err("PUBLIC_SOURCE_INVALID")}
 Ok(())
}
async fn page(transport:&HttpTransport,source:&PublicSource,kind:&str,order:&str,instance:Option<&str>,record:Option<&str>,limit:usize,cursor:Option<&str>,audience:&str,key:&str,cancel:&CancellationToken)->R<Value>{
 let mut nonce=[0;32];OsRng.try_fill_bytes(&mut nonce).map_err(|_|"PUBLIC_ENTROPY")?;let nonce=base64url(&nonce);
 let mut query=json!({"kind":kind,"order":order,"nonce":nonce,"workspace_id":source.workspace_id,"limit":limit,"cursor":cursor});if let Some(i)=instance{query["instance_id"]=json!(i)}if let Some(r)=record{query["record_id"]=json!(r)}
 let pairs=query.as_object().unwrap().iter().filter(|(_,v)|!v.is_null()).map(|(k,v)|(k.clone(),v.as_str().map(str::to_owned).unwrap_or_else(||v.to_string()))).collect::<Vec<_>>();
 let response=transport.get_publication(&pairs,cancel).await.map_err(fail_transport)?;if response.status==404{return Err("PUBLIC_NOT_FOUND")}if response.status!=200{if let Ok(error)=wire(&response.wire,16384){match error["error"]["code"].as_str(){Some("STRUCTURE_CURSOR_INVALID")=>return Err("STRUCTURE_CURSOR_INVALID"),Some("STRUCTURE_QUERY_CHANGED")=>return Err("STRUCTURE_QUERY_CHANGED"),_=>{}}}return Err("PUBLIC_READ_UNAVAILABLE")}
 let value=wire(&response.wire,1_048_576)?;let r=receipt(&text(&value,"receipt")?,key)?;let result=value.get("result").ok_or("PUBLIC_RESPONSE_INVALID")?;
 if value.as_object().map(|o|o.len())!=Some(2)||r["v"]!=1||r["profile"]!="backend-structure-v1"||r["audience"]!=audience||r["nonce"]!=nonce||r["query_digest"]!=sha256_hex(canon(&Value::Object(pairs.iter().map(|(k,v)|(k.clone(),Value::String(v.clone()))).collect()))?.as_bytes())||r["result_digest"]!=sha256_hex(canon(result)?.as_bytes())||r["accepted_at"].as_u64().is_none_or(|n|n>9_007_199_254_740_991)||result["workspace_id"]!=source.workspace_id||result["kind"]!=kind{return Err("PUBLIC_RECEIPT_INVALID")}
 Ok(result.clone())
}
pub(crate) fn public_text(body:&Value)->R<String>{
 if body.as_object().map(|o|o.len())!=Some(2)||body["format"]!="PUBLIC_UTF8_BASE64"{return Err("PUBLIC_BODY_INVALID")}
 let chunks=body["chunks"].as_array().ok_or("PUBLIC_BODY_INVALID")?;if chunks.len()>11{return Err("PUBLIC_BODY_INVALID")}
 let mut joined=String::new();for chunk in chunks{let s=chunk.as_str().filter(|s|!s.is_empty()&&s.len()<=8192).ok_or("PUBLIC_BODY_INVALID")?;joined.push_str(s)}
 let bytes=decode_base64url(&joined).map_err(|_|"PUBLIC_BODY_INVALID")?;if bytes.len()>65536{return Err("PUBLIC_BODY_INVALID")}
 String::from_utf8(bytes).map_err(|_|"PUBLIC_BODY_INVALID")
}
async fn run(r:PublicRequest,cancel:&CancellationToken)->R<Value>{
 let s=&r.source;validate_source(s)?;
 if !matches!(r.order.as_str(),"RECORD_ID_ASC"|"PUBLISHED_DESC")||!(1..=32).contains(&r.limit)||!matches!(r.kind.as_str(),"WORKSPACE"|"ENTRIES"|"ENTRY")||r.instance_id.as_ref().is_some_and(|i|!workspace_urls::token(i))||r.record_id.as_ref().is_some_and(|i|!workspace_urls::token(i))||r.cursor.as_ref().is_some_and(|s|s.is_empty()||s.len()>8192)||(r.kind=="ENTRY")!=r.record_id.is_some()||r.kind=="WORKSPACE"&&(r.instance_id.is_some()||r.cursor.is_some())||r.kind=="ENTRY"&&r.cursor.is_some(){return Err("PUBLIC_INPUT_INVALID")}
 let mut config=TransportConfig::new(&s.control_origin).with_options(s.transport.clone());config.allow_loopback_http=s.allow_loopback_http;let transport=HttpTransport::new(config).map_err(fail_transport)?;
 let discovery=transport.discovery(cancel).await.map_err(fail_transport)?;if discovery.status!=200{return Err("PUBLIC_DISCOVERY_UNAVAILABLE")}
 let d=parse_discovery_wire(&discovery.wire,262144).map_err(|_|"PUBLIC_DISCOVERY_INVALID")?;if !d.protocol_features().contains(&"owner-selected-publication-v1".encode_utf16().collect::<Vec<_>>()){return Err("CAPABILITY_UNAVAILABLE")}
 let audience=String::from_utf16(d.audience_utf16()).map_err(|_|"PUBLIC_DISCOVERY_INVALID")?;let key=d.receipt_public_key();
 if s.audience.as_ref().is_some_and(|a|a!=&audience)||s.service_key.as_ref().is_some_and(|k|k!=key){return Err("PUBLIC_SERVICE_IDENTITY_CHANGED")}
 let view=page(&transport,s,"WORKSPACE","RECORD_ID_ASC",None,None,20,None,&audience,key,cancel).await?;let c=publisher(&view["publication"],s,&audience)?;let b=&c["body"];let current=revision(&view["revision"])?;
 if c["action_id"]!="structure.publication.set"||!c["instance_id"].is_null()||b["state"]!="PUBLIC"||b["disclosure"]!="PUBLISH_SELECTED_CONTENT"||b["expected_publication_revision"].as_u64().and_then(|v|v.checked_add(1))!=Some(current)||b["title"]!=view["title"]||b["description"]!=view["description"]{return Err("PUBLIC_SOURCE_INVALID")}
 let checkpoint=Checkpoint{profile:"backend-structure-v1".into(),control_origin:s.control_origin.clone(),workspace_id:s.workspace_id.clone(),owner_actor_id:s.owner_actor_id.clone(),owner_key_id:s.owner_key_id.clone(),audience:audience.clone(),service_key:key.into(),publication_revision:current};
 if let Some(floor)=r.checkpoint{if floor.profile!=checkpoint.profile||floor.control_origin!=checkpoint.control_origin||floor.workspace_id!=checkpoint.workspace_id||floor.owner_actor_id!=checkpoint.owner_actor_id||floor.owner_key_id!=checkpoint.owner_key_id||floor.audience!=checkpoint.audience||floor.service_key!=checkpoint.service_key||floor.publication_revision>current{return Err("PUBLIC_CHECKPOINT_CHANGED")}}
 let workspace_alias=match view.get("workspace_alias"){None|Some(Value::Null)=>None,Some(Value::String(a)) if workspace_urls::alias(a)=>Some(a.clone()),_=>return Err("PUBLIC_SOURCE_INVALID")};
 let mut result=if r.kind=="WORKSPACE"{view}else{page(&transport,s,&r.kind,&r.order,r.instance_id.as_deref(),r.record_id.as_deref(),r.limit,r.cursor.as_deref(),&audience,key,cancel).await?};
 if r.kind!="WORKSPACE"{
  let sources=result.get("sources").cloned().unwrap_or_else(||json!({}));if sources.as_object().is_none_or(|v|v.len()>64){return Err("PUBLIC_SOURCE_INVALID")}
  let mut used=std::collections::BTreeSet::new();let mut cache=std::collections::BTreeMap::new();
  let entries=result["entries"].as_array_mut().ok_or("PUBLIC_RESPONSE_INVALID")?;if entries.len()>r.limit||r.kind=="ENTRY"&&entries.len()!=1{return Err("PUBLIC_RESPONSE_INVALID")}
  for entry in entries{
   let member=entry["kind"]=="AUTHOR_ACTION";let c=if member{let statement=parse_wire_json_bounded(entry["publication"]["statement"].to_string().as_bytes(),8,140000).map_err(|_|"PUBLIC_SOURCE_INVALID")?;let output=peerwork_core::public_output::verify(&statement,&audience.encode_utf16().collect::<Vec<_>>()).map_err(|_|"PUBLIC_SOURCE_INVALID")?;serde_json::from_str(&canonical_wire_value(&output.payload,Path::STRUCTURED).map_err(|_|"PUBLIC_SOURCE_INVALID")?).map_err(|_|"PUBLIC_SOURCE_INVALID")?}else{publisher(&entry["publication"],s,&audience)?};let b=&c["body"];let rev=revision(&entry["revision"])?;
   if c["instance_id"]!=entry["instance_id"]||c["protocol_digest"]!=entry["protocol_digest"]||entry["workspace_id"]!=s.workspace_id||r.instance_id.as_ref().is_some_and(|i|entry["instance_id"]!=*i)||r.record_id.as_ref().is_some_and(|id|entry["record_id"]!=*id){return Err("PUBLIC_SOURCE_INVALID")}
   let body=if member{
    let policy=reference(&entry["policy"]["source"],&sources,&mut used,&mut cache,s,&audience)?;let p=&policy["body"];
    if c["workspace_id"]!=s.workspace_id||c["actor_id"]!=entry["publication"]["actor_id"]||c["command_id"]!=entry["publication"]["command_id"]||c["record_index"]!=entry["record_index"]||policy["actor_id"]!=s.owner_actor_id||policy["action_id"]!="structure.publication.policy.set"||policy["instance_id"]!=c["instance_id"]||policy["protocol_digest"]!=c["protocol_digest"]||p["profile"]!="backend-structure-v1"||p["state"]!="ACTIVE"||p["disclosure"]!="ALLOW_AUTHOR_SIGNED_ACTION_PUBLICATION"||p["expected_policy_revision"].as_u64().and_then(|v|v.checked_add(1))!=entry["policy"]["revision"].as_u64()||entry["policy"]["revision"]!=c["policy_revision"]||entry["policy"]["intent_digest"]!=entry["policy"]["source"]["intent_digest"]||p["actions"].as_array().is_none_or(|actions|!actions.contains(&c["action_id"]))||rev!=1||c["title"]!=entry["title"]||c["body"]!=entry["body"]||entry["source"]["record_id"]!=entry["record_id"]||entry["source"]["actor_id"]!=c["actor_id"]||entry["source"]["intent_digest"]!=entry["publication"]["intent_digest"]||entry["source"].get("document_time")!=c.get("document_time")||entry["source"].get("attribution").is_some()||!workspace_urls::token(&text(entry,"record_id")?)||revision(&entry["source"]["revision"]).is_err()||entry["source"]["created_at"].as_u64().is_none_or(|v|v>9_007_199_254_740_991){return Err("PUBLIC_SOURCE_INVALID")}
    c["body"].clone()
   }else{
    if c["action_id"]!="structure.publication.entry.set"||b["state"]!="PUBLIC"||b["disclosure"]!="PUBLISH_SELECTED_CONTENT"||b["expected_publication_revision"].as_u64().and_then(|v|v.checked_add(1))!=Some(rev)||b["source"]!=entry["source"]||b["source"]["record_id"]!=entry["record_id"]||b["title"]!=entry["title"]||b["structure"]!=entry["structure"]||b["body"]!=entry["body"]{return Err("PUBLIC_SOURCE_INVALID")}
    if let Some(time)=b["source"].get("document_time"){
     let value=peerwork_core::wire_json::parse_wire_json_bounded(time.to_string().as_bytes(),4,1024).map_err(|_|"PUBLIC_SOURCE_INVALID")?;
     if value.object_len()!=Some(2)||peerwork_core::document_time::normalized(&value).is_err(){return Err("PUBLIC_SOURCE_INVALID")}
    }
    let attribution=&b["source"]["attribution"];if !attribution.is_null()&&(attribution["assurance"]!="OWNER_ATTESTED_CONVERSION"||attribution["actor_id"]!=attribution["legacy_source"]["record_actor_id"]||attribution["created_at"]!=attribution["legacy_source"]["created_at"]){return Err("PUBLIC_SOURCE_INVALID")}
    b["body"].clone()
   };
   entry["text"]=json!(public_text(&body)?);
   entry["url"]=workspace_urls::build(&WorkspaceUrlInput{browser_origin:s.browser_origin.clone(),control_origin:s.control_origin.clone(),workspace_id:s.workspace_id.clone(),workspace_alias:workspace_alias.clone(),visibility:"PUBLIC".into(),kind:"record".into(),instance_id:Some(text(entry,"instance_id")?),record_id:Some(text(entry,"record_id")?),entity_id:None,revision:Some(revision(&entry["source"]["revision"])?),allow_loopback_http:s.allow_loopback_http})?["browser_url"].clone();
  }
  if used.len()!=sources.as_object().unwrap().len(){return Err("PUBLIC_SOURCE_INVALID")}
 }
 if result["next_cursor"].as_str().is_some_and(|s|s.len()>8192)||!result["next_cursor"].is_null()&&!result["next_cursor"].is_string(){return Err("PUBLIC_RESPONSE_INVALID")}
 Ok(json!({"result":result,"checkpoint":checkpoint,"assurance":"PUBLISHER_SIGNATURE_AND_SERVICE_SELECTION","identity_required":false,"metrics":{"discovery_requests":1,"public_requests":if r.kind=="WORKSPACE"{1}else{2},"history_reads":0}}))
}
pub fn read_json(input:&str,cancel:&CancellationToken)->String{
 let parsed=if input.len()>65536{Err("PUBLIC_INPUT_INVALID")}else{serde_json::from_str::<PublicRequest>(input).map_err(|_|"PUBLIC_INPUT_INVALID")};
 let value=parsed.and_then(|r|tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"PUBLIC_RUNTIME_FAILED")?.block_on(async{tokio::time::timeout(std::time::Duration::from_secs(30),run(r,cancel)).await.map_err(|_|"PUBLIC_TIMEOUT")?}));
 match value{Ok(value)=>json!({"ok":true,"value":value}).to_string(),Err(code)=>{let retryable=matches!(code,"PUBLIC_TRANSPORT_FAILED"|"PUBLIC_TIMEOUT"|"PUBLIC_DISCOVERY_UNAVAILABLE"|"PUBLIC_READ_UNAVAILABLE");let phase=if retryable{"TRANSPORT"}else if matches!(code,"STRUCTURE_CURSOR_INVALID"|"STRUCTURE_QUERY_CHANGED"|"PUBLIC_NOT_FOUND"){"SELECTION"}else if code=="CAPABILITY_UNAVAILABLE"{"DISCOVERY"}else{"VERIFICATION"};let recovery=if retryable{"RETRY_SAME_READ"}else if matches!(code,"STRUCTURE_CURSOR_INVALID"|"STRUCTURE_QUERY_CHANGED"){"START_NEW_PAGE"}else if code=="PUBLIC_NOT_FOUND"{"CHECK_PUBLICATION_STATE"}else{"REVIEW_SOURCE_AND_CHECKPOINT"};json!({"ok":false,"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"message":"No verified public page was produced. Check source pins, selection and checkpoint; there is no journal fallback."}).to_string()}}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn public_body_is_bounded_utf8_and_explicit(){assert_eq!(public_text(&json!({"format":"PUBLIC_UTF8_BASE64","chunks":[]})).unwrap(),"");assert!(public_text(&json!({"format":"PUBLIC_UTF8_BASE64","chunks":[base64url(&[255])]})).is_err());assert!(public_text(&json!({"format":"PUBLIC_UTF8_BASE64","chunks":["A".repeat(8193)]})).is_err());assert_eq!(public_text(&json!({"format":"PUBLIC_UTF8_BASE64","chunks":[base64url(b"Public text")]})).unwrap(),"Public text");}
 #[test]fn invalid_input_never_needs_identity_or_network(){let v:Value=serde_json::from_str(&read_json("{}",&CancellationToken::new())).unwrap();assert_eq!(v["ok"],false);assert_eq!(v["code"],"PUBLIC_INPUT_INVALID");}
}
