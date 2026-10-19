//! Browser locators are distinct from API endpoints and never confer access.
use reqwest::Url;
use serde::{Deserialize,Serialize};
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceUrlInput {
 pub browser_origin:String,
 pub control_origin:String,
 pub workspace_id:String,
 #[serde(default="private")] pub visibility:String,
 #[serde(default="workspace")] pub kind:String,
 pub instance_id:Option<String>,
 pub record_id:Option<String>,
 pub entity_id:Option<String>,
 #[serde(default)] pub allow_loopback_http:bool,
}
fn private()->String{"PRIVATE".into()}
fn workspace()->String{"workspace".into()}
pub(crate) fn token(id:&str)->bool{id.len()==43&&id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
pub(crate) fn origin(raw:&str,loopback:bool)->Result<String,&'static str>{
 let u=Url::parse(raw).map_err(|_|"URL_ORIGIN_INVALID")?;
 let local=matches!(u.host_str(),Some("localhost"|"127.0.0.1"|"[::1]"));
 if !(u.scheme()=="https"||loopback&&local&&u.scheme()=="http")||u.host_str().is_none()||!u.username().is_empty()||u.password().is_some()||u.path()!="/"||u.query().is_some()||u.fragment().is_some(){return Err("URL_ORIGIN_INVALID")}
 Ok(u.origin().ascii_serialization())
}
pub fn build(input:&WorkspaceUrlInput)->Result<serde_json::Value,&'static str>{
 let browser=origin(&input.browser_origin,input.allow_loopback_http)?;let control=origin(&input.control_origin,input.allow_loopback_http)?;
 if !token(&input.workspace_id)||!matches!(input.visibility.as_str(),"PUBLIC"|"PRIVATE"){return Err("WORKSPACE_REFERENCE_INVALID")}
 for id in [&input.instance_id,&input.record_id,&input.entity_id].into_iter().flatten(){if !token(id){return Err("WORKSPACE_REFERENCE_INVALID")}}
 let resource=match (input.kind.as_str(),input.instance_id.as_deref(),input.record_id.as_deref(),input.entity_id.as_deref()){
  ("workspace",None,None,None)=>String::new(),
  ("instance",Some(i),None,None)=>format!("/instances/{i}"),
  ("record",None,Some(r),None)=>format!("/records/{r}"),
  ("thread",Some(i),None,Some(e))=>format!("/instances/{i}/threads/{e}"),
  ("document",Some(i),None,Some(e)) if input.visibility=="PRIVATE"=>format!("/instances/{i}/docs/{e}"),
  _=>return Err("WORKSPACE_RESOURCE_INVALID"),
 };
 let prefix=if input.visibility=="PRIVATE"{"/private/workspaces/"}else{"/workspaces/"};
 let journal=if input.visibility=="PRIVATE"{format!("{control}/api/workspace/v1/secure/workspaces/{}/journal",input.workspace_id)}else{format!("{browser}/api/workspace/v1/public/secure/workspaces/{}/journal",input.workspace_id)};
 Ok(serde_json::json!({"browser_url":format!("{browser}{prefix}{}{resource}",input.workspace_id),"journal_url":journal,"browser_origin":browser,"control_origin":control,"workspace_id":input.workspace_id,"visibility":input.visibility,"kind":input.kind}))
}
pub fn workspace_url_json(input:&str)->String{
 match serde_json::from_str::<WorkspaceUrlInput>(input).map_err(|_|"WORKSPACE_REFERENCE_INVALID").and_then(|v|build(&v)){
  Ok(v)=>serde_json::json!({"ok":true,"value":v}).to_string(),Err(code)=>serde_json::json!({"ok":false,"code":code,"message":"Use explicit browser/control origins, valid resource IDs and PUBLIC or PRIVATE visibility."}).to_string()
 }
}
#[cfg(test)]mod tests{
 use super::*;
 fn input()->WorkspaceUrlInput{serde_json::from_value(serde_json::json!({"browser_origin":"https://peerwork.dev","control_origin":"https://api.peerwork.dev","workspace_id":"a".repeat(43)})).unwrap()}
 #[test]fn private_default_and_public_journal_origin(){let mut i=input();let v=build(&i).unwrap();assert!(v["browser_url"].as_str().unwrap().contains("/private/workspaces/"));assert!(v["journal_url"].as_str().unwrap().starts_with("https://api.peerwork.dev/"));i.visibility="PUBLIC".into();let v=build(&i).unwrap();assert!(!v["browser_url"].as_str().unwrap().contains("/private/"));assert!(v["journal_url"].as_str().unwrap().starts_with("https://peerwork.dev/api/"));}
 #[test]fn reject_credentials_api_paths_and_resource_confusion(){let mut i=input();for raw in ["https://u:p@example.com","https://peerwork.dev/api/workspace/v1","https://peerwork.dev/?x=1","http://example.com"]{i.browser_origin=raw.into();assert!(build(&i).is_err());}i=input();i.kind="record".into();i.record_id=Some("b".repeat(43));assert!(build(&i).unwrap()["browser_url"].as_str().unwrap().ends_with(&format!("/records/{}","b".repeat(43))));i.entity_id=Some("c".repeat(43));assert!(build(&i).is_err());i=input();i.workspace_id="../oops".into();assert!(build(&i).is_err());}
}
