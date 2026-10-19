//! Anonymous, owner-pinned public changelog reads using the shared journal verifier.
use crate::{transport::{HttpTransport,TransportConfig,TransportOptions,TransportError},workspace_urls::{self,WorkspaceUrlInput}};
use peerwork_core::{canonical::Path,wire_json::{canonical_wire_value,parse_wire_json_bounded,WireValue},replayed_secure_journal::{replay_secure_journal_exact,JournalReplayInput,StructureStatus}};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use tokio_util::sync::CancellationToken;
const MAX_BYTES:usize=64*1024*1024;
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangelogSource{
 pub origin:String,pub browser_origin:String,pub control_origin:String,pub workspace_id:String,
 pub owner_actor_id:String,pub owner_key_id:String,pub instance_id:Option<String>,
 #[serde(default)]pub allow_loopback_http:bool,
 #[serde(default)]pub transport:TransportOptions,
}
pub fn official_source()->ChangelogSource{ChangelogSource{
 origin:"https://peerwork.dev".into(),browser_origin:"https://peerwork.dev".into(),control_origin:"https://api.peerwork.dev".into(),
 workspace_id:"_DUzeGzLjP4ZMxvNq9Nh93oLv4GPi0bGn76xYzb0ZsU".into(),owner_actor_id:"g4h4CplPUi4dCpjT69jLjC9CyG-zkGDpCMj4RSoUcWM".into(),owner_key_id:"xoIfxp8-t6D5Vy1kC-DaT82g5hlFH8H2JmOYNWZYhxM".into(),instance_id:Some("d-U9W6Hb7Uf3sUfYzI_5No5NPHFPStXtVKc_3SRziRk".into()),allow_loopback_http:false,transport:TransportOptions::default()}}
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangelogCheckpoint{pub origin:String,pub workspace_id:String,pub owner_actor_id:String,pub owner_key_id:String,pub instance_id:String,pub sequence:u64,pub head:Option<String>,pub policy_hash:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request{
 #[serde(default="official_source")]source:ChangelogSource,
 #[serde(default="limit")]limit:usize,
 #[serde(default)]offset:usize,
 checkpoint:Option<ChangelogCheckpoint>,
}
fn limit()->usize{20}
fn canon(v:&WireValue)->Result<Vec<u8>,&'static str>{canonical_wire_value(v,Path::SecureArtifact).map(|v|v.into_bytes()).map_err(|_|"CHANGELOG_INVALID_RESPONSE")}
fn value(v:&WireValue)->Result<Value,&'static str>{serde_json::from_slice(&canon(v)?).map_err(|_|"CHANGELOG_UNSUPPORTED_TEXT")}
fn field(v:&Value,k:&str)->Result<String,&'static str>{v[k].as_str().map(str::to_owned).ok_or("CHANGELOG_INVALID_RESPONSE")}
fn transport_error(e:TransportError)->&'static str{match e{TransportError::Cancelled=>"CANCELLED",TransportError::ResponseTooLarge=>"CHANGELOG_RESOURCE_LIMIT",_=>"CHANGELOG_TRANSPORT_FAILED"}}
fn browser_url(s:&ChangelogSource,kind:&str,iid:Option<String>,record:Option<String>)->Result<Value,&'static str>{workspace_urls::build(&WorkspaceUrlInput{browser_origin:s.browser_origin.clone(),control_origin:s.control_origin.clone(),workspace_id:s.workspace_id.clone(),visibility:"PUBLIC".into(),kind:kind.into(),instance_id:iid,record_id:record,entity_id:None,allow_loopback_http:s.allow_loopback_http})}
fn project(objects:&[Value],s:&ChangelogSource)->Result<(String,Vec<Value>),&'static str>{
 let instances=objects.iter().filter(|o|o["kind"]=="instances"&&o["value"]["workspace_id"]==s.workspace_id&&o["value"]["origin_entrypoint"]=="changelog").collect::<Vec<_>>();
 let selected=match &s.instance_id{Some(id)=>instances.iter().find(|o|o["id"]==*id).copied().ok_or("CHANGELOG_INSTANCE_NOT_FOUND")?,None=>{if instances.len()!=1{return Err("CHANGELOG_INSTANCE_AMBIGUOUS")}instances[0]}};
 let iid=field(selected,"id")?;
 let heads=objects.iter().filter(|o|o["kind"]=="entity_heads"&&o["value"]["instance_id"]==iid).filter_map(|o|o["value"]["record_id"].as_str()).collect::<std::collections::HashSet<_>>();
 let mut rows=Vec::new();
 for o in objects.iter().filter(|o|o["kind"]=="records"&&o["value"]["instance_id"]==iid){
  let id=field(o,"id")?;if !heads.contains(id.as_str()){continue}
  let v=&o["value"];let payload=if let Some(raw)=v["payload"].as_str(){serde_json::from_str::<Value>(raw).map_err(|_|"CHANGELOG_INVALID_ENTRY")?}else{v["payload"].clone()};
  let title=field(&payload,"title")?;let body=field(&payload,"body")?;
  rows.push(json!({"record_id":id,"entity_id":v["entity_id"],"revision":v["revision"],"instance_id":iid,"title":title,"body":body,"author_actor_id":v["actor_id"],"created_at":v["created"],"url":browser_url(s,"record",None,Some(id.clone()))?["browser_url"]}));
 }
 rows.sort_by(|a,b|b["created_at"].as_u64().cmp(&a["created_at"].as_u64()).then_with(||a["record_id"].as_str().cmp(&b["record_id"].as_str())));
 Ok((iid,rows))
}
fn read(request:Request,cancel:&CancellationToken)->Result<Value,&'static str>{
 let s=&request.source;if !(1..=100).contains(&request.limit)||request.offset>100000||!workspace_urls::token(&s.workspace_id)||!workspace_urls::token(&s.owner_actor_id)||!workspace_urls::token(&s.owner_key_id)||s.instance_id.as_ref().is_some_and(|i|!workspace_urls::token(i)){return Err("CHANGELOG_INPUT_INVALID")}
 let origin=workspace_urls::origin(&s.origin,s.allow_loopback_http)?;
 // Validate browser/API bindings before network access or local state changes.
 browser_url(s,"workspace",None,None)?;
 let mut cfg=TransportConfig::new(&origin).with_options(s.transport.clone());cfg.allow_loopback_http=s.allow_loopback_http;
 let transport=HttpTransport::new(cfg).map_err(transport_error)?;
 let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"RUNTIME_FAILED")?;
 let mut after=0;let mut policies:Option<Vec<Vec<u8>>>=None;let mut commits=Vec::new();let mut checkpoint:Option<Vec<u8>>=None;let mut total=0usize;
 loop{
  if cancel.is_cancelled(){return Err("CANCELLED")}
  let response=runtime.block_on(transport.get_public_journal_exact(&s.workspace_id,after,cancel)).map_err(transport_error)?;
  if response.status!=200{return Err(if response.status==404{"CHANGELOG_PUBLIC_SOURCE_UNAVAILABLE"}else{"CHANGELOG_HTTP_FAILED"})}
  total=total.checked_add(response.wire.len()).filter(|n|*n<=MAX_BYTES).ok_or("CHANGELOG_RESOURCE_LIMIT")?;
  let page=parse_wire_json_bounded(&response.wire,128,8*1024*1024).map_err(|_|"CHANGELOG_INVALID_RESPONSE")?;
  let metadata=value(&page)?;if metadata["workspace_id"]!=s.workspace_id||metadata["visibility"]!="PUBLIC"||metadata["state"]!="ACTIVE"{return Err("CHANGELOG_PUBLIC_SOURCE_UNAVAILABLE")}
  let WireValue::Array(p)=page.get("policies").ok_or("CHANGELOG_INVALID_RESPONSE")?else{return Err("CHANGELOG_INVALID_RESPONSE")};
  let p=p.iter().map(canon).collect::<Result<Vec<_>,_>>()?;
  if let Some(saved)=&policies{if saved!=&p{return Err("CHANGELOG_SOURCE_CHANGED")}}else{policies=Some(p)}
  let cp=canon(page.get("checkpoint").ok_or("CHANGELOG_INVALID_RESPONSE")?)?;
  if let Some(saved)=&checkpoint{if saved!=&cp{return Err("CHANGELOG_SOURCE_CHANGED")}}else{checkpoint=Some(cp)}
  let WireValue::Array(c)=page.get("commits").ok_or("CHANGELOG_INVALID_RESPONSE")?else{return Err("CHANGELOG_INVALID_RESPONSE")};
  if commits.len()+c.len()>100000{return Err("CHANGELOG_RESOURCE_LIMIT")}
  for commit in c{commits.push(canon(commit)?)}
  match metadata.get("next"){
   Some(Value::Null)=>break,
   Some(Value::Number(n))=>{let next=n.as_u64().filter(|n|*n>after).ok_or("CHANGELOG_INVALID_RESPONSE")?;if c.is_empty(){return Err("CHANGELOG_INVALID_RESPONSE")}after=next;},
   _=>return Err("CHANGELOG_INVALID_RESPONSE"),
  }
 }
 let policies=policies.ok_or("CHANGELOG_INVALID_RESPONSE")?;let cp=checkpoint.ok_or("CHANGELOG_INVALID_RESPONSE")?;let cpv:Value=serde_json::from_slice(&cp).map_err(|_|"CHANGELOG_INVALID_RESPONSE")?;
 // PUBLIC is a signed policy property, not inferred from a path or HTTP 404.
 for p in &policies{let v:Value=serde_json::from_slice(p).map_err(|_|"CHANGELOG_INVALID_RESPONSE")?;if v["payload"]["visibility"]!="PUBLIC"{return Err("CHANGELOG_PUBLIC_SOURCE_UNAVAILABLE")}}
 let pr=policies.iter().map(Vec::as_slice).collect::<Vec<_>>();let cr=commits.iter().map(Vec::as_slice).collect::<Vec<_>>();
 let sequence=cpv["sequence"].as_u64().ok_or("CHANGELOG_INVALID_RESPONSE")?;let policy_hash=field(&cpv,"policy_hash")?;
 let replay=replay_secure_journal_exact(JournalReplayInput{policy_wires:&pr,commit_wires:&cr,checkpoint_wire:&cp,workspace_id:&s.workspace_id,owner_actor_id:&s.owner_actor_id,owner_signing_key:&s.owner_key_id,final_sequence:sequence,final_head:cpv["head"].as_str(),final_policy_hash:&policy_hash,keyring_wire:None}).map_err(|_|"CHANGELOG_VERIFICATION_FAILED")?;
 if replay.structure_status()!=StructureStatus::Active{return Err("CHANGELOG_NOT_ACTIVE")}
 let objects=replay.objects().iter().map(value).collect::<Result<Vec<_>,_>>()?;
 let(iid,rows)=project(&objects,s)?;
 if let Some(old)=&request.checkpoint{
  if old.origin!=origin||old.workspace_id!=s.workspace_id||old.owner_actor_id!=s.owner_actor_id||old.owner_key_id!=s.owner_key_id||old.instance_id!=iid||!replay.contains_checkpoint(old.sequence,old.head.as_deref(),&old.policy_hash){return Err("CHANGELOG_CHECKPOINT_MISMATCH")}
  if request.offset>0&&(old.sequence!=replay.sequence()||old.head.as_deref()!=replay.head()){return Err("CHANGELOG_SOURCE_CHANGED")}
 }else if request.offset>0{return Err("CHANGELOG_CHECKPOINT_REQUIRED")}
 let checkpoint=ChangelogCheckpoint{origin,workspace_id:s.workspace_id.clone(),owner_actor_id:s.owner_actor_id.clone(),owner_key_id:s.owner_key_id.clone(),instance_id:iid.clone(),sequence:replay.sequence(),head:replay.head().map(str::to_owned),policy_hash:replay.policy_hash().into()};
 let end=request.offset.saturating_add(request.limit).min(rows.len());let start=request.offset.min(rows.len());
 Ok(json!({"source":s,"instance_id":iid,"url":browser_url(s,"instance",Some(iid.clone()),None)?["browser_url"],"checkpoint":checkpoint,"entries":rows[start..end],"next_offset":if end<rows.len(){Some(end)}else{None},"total_entries":rows.len(),"verification":"SIGNED_JOURNAL_REPLAY","freshness":"SERVER_OBSERVATION","identity_required":false}))
}
pub fn navigation_json(operation:&str,input:&str,cancel:&CancellationToken)->String{
 if operation=="url"{return workspace_urls::workspace_url_json(input)}
 let result=match operation{
  "changelog.source"=>Ok(json!({"source":official_source(),"official_reference":"https://github.com/peerwork-dev/peerwork-sdk/blob/f8b4415/docs/project-identity.json"})),
  "changelog.read"=>serde_json::from_str::<Request>(input).map_err(|_|"CHANGELOG_INPUT_INVALID").and_then(|r|read(r,cancel)),
  _=>Err("NAVIGATION_OPERATION_INVALID"),
 };
 match result{Ok(v)=>json!({"ok":true,"value":v}).to_string(),Err(code)=>json!({"ok":false,"code":code,"message":"Changelog read did not produce verified content; check the explicit public source, owner pin, checkpoint and resource limits."}).to_string()}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn official_source_is_explicit_and_has_no_identity(){let v=navigation_json("changelog.source","{}",&CancellationToken::new());let v:Value=serde_json::from_str(&v).unwrap();assert_eq!(v["ok"],true);assert_eq!(v["value"]["source"]["origin"],"https://peerwork.dev");assert!(v.to_string().find("identity_path").is_none());}
 #[test]fn invalid_inputs_do_not_fetch(){for input in [r#"{"limit":0}"#,r#"{"limit":101}"#,r#"{"unexpected":true}"#]{let v:Value=serde_json::from_str(&navigation_json("changelog.read",input,&CancellationToken::new())).unwrap();assert_eq!(v["ok"],false);}}
 #[test]fn only_current_heads_in_selected_changelog_are_returned(){let s=official_source();let iid=s.instance_id.as_ref().unwrap();let head="a".repeat(43);let old="b".repeat(43);let rows=vec![json!({"kind":"instances","id":iid,"value":{"workspace_id":s.workspace_id,"origin_entrypoint":"changelog"}}),json!({"kind":"entity_heads","value":{"instance_id":iid,"record_id":head}}),json!({"kind":"records","id":old,"value":{"instance_id":iid,"payload":{"title":"old","body":"old"}}}),json!({"kind":"records","id":head,"value":{"instance_id":iid,"created":2,"payload":{"title":"new","body":"current"}}})];let(selected,entries)=project(&rows,&s).unwrap();assert_eq!(selected,*iid);assert_eq!(entries.len(),1);assert_eq!(entries[0]["record_id"],head);assert_eq!(entries[0]["body"],"current");}
}
