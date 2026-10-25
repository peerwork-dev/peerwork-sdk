//! Browser locators are distinct from API endpoints and never confer access.
use reqwest::Url;
use serde::{Deserialize,Serialize};
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceUrlInput {
 pub browser_origin:String,
 pub control_origin:String,
 pub workspace_id:String,
 #[serde(default)] pub workspace_alias:Option<String>,
 #[serde(default="private")] pub visibility:String,
 #[serde(default="workspace")] pub kind:String,
 pub instance_id:Option<String>,
 pub record_id:Option<String>,
 pub entity_id:Option<String>,
 #[serde(default)]pub revision:Option<u64>,
 #[serde(default)] pub allow_loopback_http:bool,
}
fn private()->String{"PRIVATE".into()}
fn workspace()->String{"workspace".into()}
pub(crate) fn alias(id:&str)->bool{id.len()==16&&id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
pub(crate) fn token(id:&str)->bool{id.len()==43&&id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
pub(crate) fn origin(raw:&str,loopback:bool)->Result<String,&'static str>{
 let u=Url::parse(raw).map_err(|_|"URL_ORIGIN_INVALID")?;
 let local=matches!(u.host_str(),Some("localhost"|"127.0.0.1"|"[::1]"));
 if !(u.scheme()=="https"||loopback&&local&&u.scheme()=="http")||u.host_str().is_none()||!u.username().is_empty()||u.password().is_some()||u.path()!="/"||u.query().is_some()||u.fragment().is_some(){return Err("URL_ORIGIN_INVALID")}
 Ok(u.origin().ascii_serialization())
}
pub fn build(input:&WorkspaceUrlInput)->Result<serde_json::Value,&'static str>{
 let browser=origin(&input.browser_origin,input.allow_loopback_http)?;let control=origin(&input.control_origin,input.allow_loopback_http)?;
 if input.workspace_alias.as_deref().is_some_and(|id|!alias(id))||!token(&input.workspace_id)||!matches!(input.visibility.as_str(),"PUBLIC"|"PRIVATE"){return Err("WORKSPACE_REFERENCE_INVALID")}
 for id in [&input.instance_id,&input.record_id,&input.entity_id].into_iter().flatten(){if !token(id){return Err("WORKSPACE_REFERENCE_INVALID")}}
 let resource=match (input.kind.as_str(),input.instance_id.as_deref(),input.record_id.as_deref(),input.entity_id.as_deref(),input.revision){
  ("workspace",None,None,None,None)=>String::new(),
  ("instance",Some(i),None,None,None)=>format!("/instances/{i}"),
  ("record",Some(i),Some(r),None,Some(revision)) if revision>0&&revision<=9_007_199_254_740_991=>format!("/instances/{i}/records/{r}?revision={revision}"),
  _=>return Err("WORKSPACE_RESOURCE_INVALID"),
 };
 let suffix=if input.visibility=="PRIVATE"{if resource.contains('?'){"&access=private"}else{"?access=private"}}else{""};
 let base=match &input.workspace_alias{Some(alias)=>format!("{browser}/w/{alias}"),None=>format!("{browser}/workspaces/{}",input.workspace_id)};
 Ok(serde_json::json!({"execution_profile":"backend-structure-v1","browser_url":format!("{base}{resource}{suffix}"),
 "commands_url":format!("{control}/api/workspace/v1/commands"),"context_endpoint":format!("{control}/api/workspace/v1/structure/context"),"public_read_endpoint":format!("{control}/api/workspace/v1/structure/public"),
 "browser_origin":browser,"control_origin":control,"workspace_id":input.workspace_id,"workspace_alias":input.workspace_alias,"visibility":input.visibility,"kind":input.kind}))
}
pub fn workspace_url_json(input:&str)->String{
 match serde_json::from_str::<WorkspaceUrlInput>(input).map_err(|_|"WORKSPACE_REFERENCE_INVALID").and_then(|v|build(&v)){
  Ok(v)=>serde_json::json!({"ok":true,"value":v}).to_string(),Err(code)=>serde_json::json!({"ok":false,"code":code,"message":"Use explicit browser/control origins and PUBLIC or PRIVATE visibility. Record links require instance_id, record_id and a positive revision. Only workspace, instance and record routes are supported."}).to_string()
 }
}
#[cfg(test)]mod tests{
 use super::*;
 fn input()->WorkspaceUrlInput{serde_json::from_value(serde_json::json!({"browser_origin":"https://peerwork.dev","control_origin":"https://api.peerwork.dev","workspace_id":"a".repeat(43)})).unwrap()}
 #[test]fn private_default_and_current_api_endpoints(){let mut i=input();let v=build(&i).unwrap();assert!(v["browser_url"].as_str().unwrap().ends_with("?access=private"));assert!(v.get("journal_url").is_none());assert_eq!(v["commands_url"],"https://api.peerwork.dev/api/workspace/v1/commands");i.visibility="PUBLIC".into();let v=build(&i).unwrap();assert!(!v["browser_url"].as_str().unwrap().contains("?access="));assert_eq!(v["public_read_endpoint"],"https://api.peerwork.dev/api/workspace/v1/structure/public");}
 #[test]fn aliases_preserve_private_default_and_exact_record_selection(){let mut i=input();i.workspace_alias=Some("A".repeat(15));assert!(build(&i).is_err());i.workspace_alias=Some("AbCd0123456789_X".into());assert_eq!(build(&i).unwrap()["browser_url"],"https://peerwork.dev/w/AbCd0123456789_X?access=private");i.kind="record".into();i.instance_id=Some("i".repeat(43));i.record_id=Some("r".repeat(43));i.revision=Some(3);assert!(build(&i).unwrap()["browser_url"].as_str().unwrap().ends_with("?revision=3&access=private"));i.workspace_alias=Some("../not-a-locator".into());assert!(build(&i).is_err());}
 #[test]fn reject_unqualified_records_and_unsupported_resources(){let mut i=input();i.kind="record".into();i.record_id=Some("b".repeat(43));assert!(build(&i).is_err());i.instance_id=Some("c".repeat(43));assert!(build(&i).is_err());i.revision=Some(7);let v=build(&i).unwrap();assert!(v["browser_url"].as_str().unwrap().ends_with(&format!("/instances/{}/records/{}?revision=7&access=private","c".repeat(43),"b".repeat(43))));i.visibility="PUBLIC".into();assert!(build(&i).unwrap()["browser_url"].as_str().unwrap().ends_with("?revision=7"));i.revision=Some(0);assert!(build(&i).is_err());i=input();i.kind="thread".into();i.entity_id=Some("c".repeat(43));assert!(build(&i).is_err());}
 #[test]fn reject_credentials_api_paths_and_invalid_references(){let mut i=input();for raw in ["https://u:p@example.com","https://peerwork.dev/api/workspace/v1","https://peerwork.dev/?x=1","http://example.com"]{i.browser_origin=raw.into();assert!(build(&i).is_err());}i=input();i.workspace_id="../oops".into();assert!(build(&i).is_err());}
}
