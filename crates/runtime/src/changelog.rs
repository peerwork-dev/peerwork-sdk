//! Current navigation and explicit official source. The old journal-replay
//! Changelog reader is retired; no online fallback is available.
use crate::{transport::TransportOptions,workspace_urls};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use crate::publication_read;
use tokio_util::sync::CancellationToken;
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
pub struct ChangelogCheckpoint(pub publication_read::Checkpoint);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request{#[serde(default="official_source")]source:ChangelogSource,#[serde(default="limit")]limit:usize,#[serde(default)]cursor:Option<String>,#[serde(default)]checkpoint:Option<publication_read::Checkpoint>}
fn limit()->usize{20}
fn read_changelog(input:&str,cancel:&CancellationToken)->String{
 if input.len()>65536{return json!({"ok":false,"code":"CHANGELOG_INPUT_INVALID"}).to_string()}
 let r=match serde_json::from_str::<Request>(input){Ok(r) if input.len()<=65536&&(1..=32).contains(&r.limit)=>r,_=>return json!({"ok":false,"code":"CHANGELOG_INPUT_INVALID","message":"Select a bounded page and explicit source; offset and full-history reads are unsupported."}).to_string()};
 if workspace_urls::origin(&r.source.origin,r.source.allow_loopback_http).is_err(){return json!({"ok":false,"code":"PUBLIC_SOURCE_INVALID","message":"Use an explicit trusted public origin without credentials or API paths."}).to_string()}
 let source=publication_read::PublicSource{control_origin:r.source.control_origin.clone(),browser_origin:r.source.browser_origin.clone(),workspace_id:r.source.workspace_id.clone(),owner_actor_id:r.source.owner_actor_id.clone(),owner_key_id:r.source.owner_key_id.clone(),audience:None,service_key:None,allow_loopback_http:r.source.allow_loopback_http,transport:r.source.transport.clone()};
 let request=json!({"source":source,"kind":"ENTRIES","order":"PUBLISHED_DESC","instance_id":r.source.instance_id,"limit":r.limit,"cursor":r.cursor,"checkpoint":r.checkpoint});
 let mut result:Value=match serde_json::from_str(&publication_read::read_json(&request.to_string(),cancel)){Ok(v)=>v,Err(_)=>return json!({"ok":false,"code":"CHANGELOG_RESULT_INVALID"}).to_string()};
 if result["ok"]==true{
  let value=&result["value"];let entries=value["result"]["entries"].as_array().unwrap().iter().map(|e|json!({"record_id":e["record_id"],"revision":e["source"]["revision"],"instance_id":e["instance_id"],"title":e["title"],"body":e["text"],"author_actor_id":if e["source"]["attribution"].is_object(){&e["source"]["attribution"]["actor_id"]}else{&e["source"]["actor_id"]},"created_at":if e["source"]["attribution"].is_object(){&e["source"]["attribution"]["created_at"]}else{&e["source"]["created_at"]},"source_signer_actor_id":e["source"]["actor_id"],"attribution_assurance":if e["source"]["attribution"].is_object(){"OWNER_ATTESTED_CONVERSION"}else if e["kind"]=="AUTHOR_ACTION"{"AUTHOR_SIGNED_PUBLIC_ACTION"}else{"OWNER_ATTESTED_RECORD_SOURCE"},"document_time":e["source"].get("document_time").unwrap_or(&Value::Null),"document_time_assurance":if e["source"]["document_time"].is_object(){if e["kind"]=="AUTHOR_ACTION"{json!("AUTHOR_SIGNATURE")}else{json!("PUBLISHER_ATTESTATION")}}else{Value::Null},"submitted_at":e["source"]["created_at"],"published_at":e["updated_at"],"url":e["url"]})).collect::<Vec<_>>();
  result["value"]=json!({"source":r.source,"entries":entries,"checkpoint":value["checkpoint"],"next_cursor":value["result"]["next_cursor"],"verification":if value["result"]["entries"].as_array().unwrap().iter().any(|e|e["kind"]=="AUTHOR_ACTION"){"AUTHOR_AND_OWNER_POLICY_SIGNATURES"}else{"OWNER_PUBLICATION_SIGNATURES"},"freshness":"SERVICE_CURRENT_SELECTION","identity_required":false,"metrics":value["metrics"]});
 }
 result.to_string()
}
pub fn navigation_json(operation:&str,input:&str,cancel:&CancellationToken)->String{
 if operation=="url"{return workspace_urls::workspace_url_json(input)}
 if operation=="publication.read"{return publication_read::read_json(input,cancel);}
 if operation=="changelog.read"{return read_changelog(input,cancel);}
 let result=match operation{
  "changelog.source"=>Ok(json!({"source":official_source(),"official_reference":"https://github.com/peerwork-dev/peerwork-sdk/blob/f8b4415/docs/project-identity.json"})),

  _=>Err("NAVIGATION_OPERATION_INVALID"),
 };
 match result{Ok(v)=>json!({"ok":true,"value":v}).to_string(),Err(code)=>json!({"ok":false,"code":code,"message":"Changelog read did not produce verified content; check the explicit public source, owner pin, checkpoint and resource limits."}).to_string()}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn official_source_is_explicit_and_has_no_identity(){let v=navigation_json("changelog.source","{}",&CancellationToken::new());let v:Value=serde_json::from_str(&v).unwrap();assert_eq!(v["ok"],true);assert_eq!(v["value"]["source"]["origin"],"https://peerwork.dev");assert!(v.to_string().find("identity_path").is_none());}
 #[test]fn invalid_inputs_do_not_fetch(){for input in [r#"{"limit":0}"#,r#"{"limit":101}"#,r#"{"unexpected":true}"#]{let v:Value=serde_json::from_str(&navigation_json("changelog.read",input,&CancellationToken::new())).unwrap();assert_eq!(v["ok"],false);}}
}
