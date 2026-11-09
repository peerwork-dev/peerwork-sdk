//! Immutable protocol role bundles. This verifies authored resources and bindings,
//! not business-rule execution or a model's obedience to prose.
use crate::{canonical::{canonical,Path},crypto::sha256_hex,prepared_command::verify_structure_author_intent_with_proofs,human_author::AuthorProofContext,wire_json::{canonical_wire_value,WireValue}};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use std::collections::{BTreeMap,BTreeSet};
#[derive(Debug,thiserror::Error)]
#[error("PROTOCOL_BUNDLE_VERIFICATION_FAILED")]
pub struct BundleError;
type Result<T>=std::result::Result<T,BundleError>;
#[derive(Deserialize,Serialize)] #[serde(deny_unknown_fields)]
struct Resource{media_type:String,text:String}
#[derive(Deserialize,Serialize)] #[serde(deny_unknown_fields)]
struct Tool{name:String,action:String}
#[derive(Deserialize,Serialize)] #[serde(deny_unknown_fields)]
struct Role{instructions:String,tools:Vec<Tool>,context:Vec<String>}
#[derive(Deserialize,Serialize)] #[serde(deny_unknown_fields)]
struct Bundle{format:String,metadata:Value,manifest:Value,roles:BTreeMap<String,Role>,resources:BTreeMap<String,Resource>,dependencies:Vec<Value>}
fn text<'a>(v:&'a Value,key:&str)->Result<&'a str>{v.get(key).and_then(Value::as_str).ok_or(BundleError)}
fn encoded(v:&Value)->Result<String>{canonical(v,Path::STRUCTURED).map_err(|_|BundleError)}
fn same(a:&Value,b:&Value)->Result<()>{if encoded(a)?!=encoded(b)?{return Err(BundleError)}Ok(())}
fn path(s:&str)->bool{!s.is_empty()&&s.len()<=160&&s.split('/').all(|p|!p.is_empty()&&!matches!(p,"."|".."|"__proto__"|"prototype"|"constructor")&&p.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)))}
fn name(s:&str)->bool{!s.is_empty()&&s.len()<=80&&s.as_bytes()[0].is_ascii_alphabetic()&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))}
pub fn build_header(input:&Value)->Result<Value>{
 if encoded(input)?.len()>114688{return Err(BundleError)}
 let b:Bundle=serde_json::from_value(input.clone()).map_err(|_|BundleError)?;
 if b.format!="peerwork.protocol-bundle.v1"||b.resources.len()>32||b.roles.len()>32||b.dependencies.len()>16{return Err(BundleError)}
 let declared=b.manifest["protocol_roles"].as_array().ok_or(BundleError)?;
 if declared.len()!=b.roles.len()||b.roles.keys().any(|r|!name(r)||!declared.iter().any(|v|v.as_str()==Some(r))){return Err(BundleError)}
 let mut resources=BTreeMap::new();
 for(p,r)in &b.resources{
  if !path(p)||r.text.is_empty()||r.text.len()>8192||!matches!(r.media_type.as_str(),"text/markdown"|"text/plain"|"application/json"){return Err(BundleError)}
  if p==crate::protocol_presentation::RESOURCE_PATH {
   if r.media_type!="application/json"{return Err(BundleError)}
   crate::protocol_presentation::parse_resource(&r.text,&b.manifest).map_err(|_|BundleError)?;
  }
  resources.insert(p.clone(),json!({"sha256":sha256_hex(r.text.as_bytes()),"bytes":r.text.len(),"media_type":r.media_type}));
 }
 let actions=b.manifest["actions"].as_array().ok_or(BundleError)?;
 for r in b.roles.values(){
  if !b.resources.get(&r.instructions).is_some_and(|v|v.media_type=="text/markdown")||r.tools.len()>32||r.context.len()>3{return Err(BundleError)}
  let mut names=BTreeSet::new();let mut ids=BTreeSet::new();let mut contexts=BTreeSet::new();
  for t in &r.tools{if !name(&t.name)||!names.insert(&t.name)||!ids.insert(&t.action)||!actions.iter().any(|a|a["id"].as_str()==Some(&t.action)){return Err(BundleError)}}
  for c in &r.context{if !matches!(c.as_str(),"goal"|"selected_state"|"updates")||!contexts.insert(c){return Err(BundleError)}}
 }
 let protocol=sha256_hex(encoded(&json!({"semantics":"peerwork.kernel.v1","manifest":b.manifest}))?.as_bytes());
 Ok(json!({"format":b.format,"metadata":b.metadata,"manifest":b.manifest,"protocol_digest":protocol,"roles":b.roles,"resources":resources,"dependencies":b.dependencies}))
}
pub fn inspect(input:&Value)->Result<Value>{let header=build_header(input)?;Ok(json!({"package_digest":sha256_hex(encoded(&header)?.as_bytes()),"protocol_digest":header["protocol_digest"],"bundle_header":header,"submitted":false}))}
fn authored(source:&Value,audience:&[u16],workspace:&str,header:&Value,digest:&str,binding:Option<&str>,proofs:Option<&AuthorProofContext>)->Result<()>{
 let proof=verify_structure_author_intent_with_proofs(text(source,"author_intent")?,audience,proofs).map_err(|_|BundleError)?;
 if proof.actor_id()!=text(source,"actor_id")?||proof.command_id()!=text(source,"command_id")?||proof.intent_digest()!=text(source,"intent_digest")?||proof.workspace_id()!=Some(workspace){return Err(BundleError)}
 let c=canonical_wire_value(proof.command(),crate::prepared_command::command_canonical_path(proof.command())).map_err(|_|BundleError)?;let c:Value=serde_json::from_str(&c).map_err(|_|BundleError)?;let body=&c["body"];
 if let Some(instance)=binding{
  if proof.action_id()=="structure.protocol.upgrade" {
   if body["instance_id"].as_str()!=Some(instance)||body["target_package_digest"].as_str()!=Some(digest){return Err(BundleError)}
   return Ok(());
  }
  if proof.action_id()=="structure.protocol.bind"{if body["instance_id"].as_str()!=Some(instance)||body["protocol_digest"]!=header["protocol_digest"]{return Err(BundleError)}}else if proof.action_id()!="structure.adopt"{return Err(BundleError)}
  if let Some(selected)=body["package_digest"].as_str(){if selected!=digest{return Err(BundleError)}}else{same(&build_header(&body["bundle"])?,header)?;}
 }else{
  if !matches!(proof.action_id(),"structure.protocol.register"|"structure.protocol.bind"|"structure.adopt"){return Err(BundleError)}
  same(&build_header(&body["bundle"])?,header)?;
 }
 Ok(())
}
pub fn verify_result(result:&WireValue,command:&WireValue,audience:&[u16])->Result<()>{
 let proofs=AuthorProofContext::from_container(result).map_err(|_|BundleError)?;verify_result_with_proofs(result,command,audience,proofs.as_ref())
}
pub fn verify_result_with_proofs(result:&WireValue,command:&WireValue,audience:&[u16],proofs:Option<&AuthorProofContext>)->Result<()>{
 let r:Value=serde_json::from_str(&canonical_wire_value(result,Path::STRUCTURED).map_err(|_|BundleError)?).map_err(|_|BundleError)?;
 let c:Value=serde_json::from_str(&canonical_wire_value(command,crate::prepared_command::command_canonical_path(command)).map_err(|_|BundleError)?).map_err(|_|BundleError)?;
 if r["status"].as_str().is_some_and(|s|matches!(s,"REJECTED_NO_EFFECT"|"COMMITTED_RESULT_UNAVAILABLE")){return Ok(())}
 let action=text(&c,"action_id")?;let body=&c["body"];
 if action=="structure.protocol.upgrade" {
  if r["status"]!="APPLIED"||!matches!(r["upgrade_kind"].as_str(),Some("UNCHANGED"|"ROLE_BUNDLE_UPDATED"|"DEFAULT_ACTIVATED"|"DEFAULT_REACTIVATED"))
   ||r["instance_id"]!=body["instance_id"]||r["package_digest"]!=body["target_package_digest"]
   ||body["expected_binding_revision"].as_u64().and_then(|v|v.checked_add(if r["upgrade_kind"]=="UNCHANGED"{0}else{1}))!=r[if body.get("execution_context_id").is_some(){"binding_revision"}else{"default_revision"}].as_u64()
   ||r["execution_context_id"].as_str().is_none_or(|s|!crate::structure_content::is_context_token(s))
   ||body.get("execution_context_id").is_some_and(|v|v!=&r["execution_context_id"]){return Err(BundleError)}
 }else if matches!(action,"structure.protocol.register"|"structure.protocol.bind"|"structure.adopt"){
  if let Some(bundle)=body.get("bundle"){let h=build_header(bundle)?;if text(&r,"package_digest")?!=sha256_hex(encoded(&h)?.as_bytes())||r["protocol_digest"]!=h["protocol_digest"]{return Err(BundleError)}}
  else if let Some(d)=body["package_digest"].as_str(){if text(&r,"package_digest")?!=d{return Err(BundleError)}}
  if action=="structure.protocol.bind"&&(r["instance_id"]!=body["instance_id"]||r["protocol_digest"]!=body["protocol_digest"]){return Err(BundleError)}
 }else if action=="structure.protocol.resolve"{
  let h=&r["bundle_header"];let d=text(&r,"package_digest")?;
  if sha256_hex(encoded(h)?.as_bytes())!=d||r["protocol_digest"]!=h["protocol_digest"]||sha256_hex(encoded(&json!({"semantics":"peerwork.kernel.v1","manifest":h["manifest"]}))?.as_bytes())!=text(h,"protocol_digest")?{return Err(BundleError)}
  if body["package_digest"].as_str().is_some_and(|selected|selected!=d){return Err(BundleError)}
  if body["protocol_digest"].as_str().is_some_and(|selected|r["protocol_digest"].as_str()!=Some(selected)){return Err(BundleError)}
  let workspace=text(&c,"workspace_id")?;authored(&r["evidence"]["registration"],audience,workspace,h,d,None,proofs)?;
  if let Some(instance)=body["instance_id"].as_str(){let b=&r["evidence"]["binding"];if b["instance_id"].as_str()!=Some(instance){return Err(BundleError)}authored(&b["source"],audience,workspace,h,d,Some(instance),proofs)?;
   if let Some(context)=r.get("execution_context_id") {
    if b["execution_context_id"]!=*context||b["protocol_digest"]!=r["protocol_digest"]||b["package_digest"]!=r["package_digest"]||b["binding_revision"]!=r["binding_revision"]
     ||body.get("execution_context_id").is_some_and(|v|v!=context){return Err(BundleError)}
    let proof=verify_structure_author_intent_with_proofs(text(&b["source"],"author_intent")?,audience,proofs).map_err(|_|BundleError)?;
    let source:Value=serde_json::from_str(&canonical_wire_value(proof.command(),crate::prepared_command::command_canonical_path(proof.command())).map_err(|_|BundleError)?).map_err(|_|BundleError)?;
    if proof.action_id()=="structure.protocol.upgrade"&&source["body"].get("execution_context_id").is_some_and(|v|v!=context){return Err(BundleError)}
   }
  }
  if body["view"].as_str()==Some("runtime"){
   let role=text(body,"role")?;let runtime=&r["runtime"];let declared=&h["roles"][role];
   if runtime["actor_id"]!=c["actor_id"]||runtime["role"]!=body["role"]||runtime["instructions_resource"]!=declared["instructions"]||runtime["context"]!=declared["context"]{return Err(BundleError)}
   for t in runtime["tools"].as_array().ok_or(BundleError)?{let id=text(t,"action")?;let name=text(t,"name")?;
    if !declared["tools"].as_array().ok_or(BundleError)?.iter().any(|d|d["name"].as_str()==Some(name)&&d["action"].as_str()==Some(id))||!runtime["granted_actions"].as_array().ok_or(BundleError)?.iter().any(|a|a.as_str()==Some(id)){return Err(BundleError)}
    let action=h["manifest"]["actions"].as_array().ok_or(BundleError)?.iter().find(|a|a["id"].as_str()==Some(id)).ok_or(BundleError)?;same(&t["input_schema"],&action["inputs"])?;
   }
  }
  if body["include_resources"].as_bool()==Some(true){
   let expected:Vec<String>=if body["view"].as_str()==Some("runtime"){vec![text(&h["roles"][text(body,"role")?],"instructions")?.to_owned()]}else{h["resources"].as_object().ok_or(BundleError)?.keys().cloned().collect()};
   let resources=r["resources"].as_object().ok_or(BundleError)?;if resources.len()!=expected.len(){return Err(BundleError)}
   for path in expected{let resource=resources.get(&path).ok_or(BundleError)?;let entry=&h["resources"][&path];let content=text(resource,"content")?;
    if resource["path"].as_str()!=Some(&path)||sha256_hex(content.as_bytes())!=text(entry,"sha256")?||resource["sha256"]!=entry["sha256"]||resource["bytes"].as_u64()!=Some(content.len() as u64)||resource["bytes"]!=entry["bytes"]||resource["media_type"]!=entry["media_type"]{return Err(BundleError)}
   }
  }
 }else if action=="structure.protocol.resource.get"{
  let resource=&r["resource"];let content=text(resource,"content")?;
  if resource["path"]!=body["path"]||sha256_hex(content.as_bytes())!=text(resource,"sha256")?||resource["bytes"].as_u64()!=Some(content.len() as u64)||body["package_digest"].as_str().is_some_and(|d|r["package_digest"].as_str()!=Some(d)){return Err(BundleError)}
 }
 Ok(())
}
#[cfg(test)] mod tests{
 use super::*;
 #[test]fn backend_fixture_hash_and_resource_tampering(){
  let f:Value=serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();let actual=inspect(&f["bundle"]).unwrap();assert_eq!(actual["package_digest"],f["package_digest"]);assert_eq!(actual["protocol_digest"],f["protocol_digest"]);
  let mut changed=f["bundle"].clone();changed["resources"]["roles/worker.md"]["text"]=json!("different instructions");assert_ne!(inspect(&changed).unwrap()["package_digest"],actual["package_digest"]);
  changed["roles"]["WORKER"]["tools"][0]["action"]=json!("undeclared");assert!(inspect(&changed).is_err());
 }
 #[test]fn upgrade_outcome_fences_default_and_selected_bindings_and_preserves_noop(){
  let wire=|value:&Value|crate::wire_json::parse_wire_json_bounded(&serde_json::to_vec(value).unwrap(),40,180000).unwrap();
  let instance="I".repeat(43);let context="C".repeat(43);let package="a".repeat(64);
  let mut command=json!({"action_id":"structure.protocol.upgrade","body":{"instance_id":instance,"expected_binding_revision":7,"expected_package_digest":null,"target_package_digest":package}});
  let mut result=json!({"status":"APPLIED","upgrade_kind":"DEFAULT_ACTIVATED","instance_id":instance,"execution_context_id":context,"package_digest":package,"binding_revision":1,"default_revision":8});
  let verify=|result:&Value,command:&Value|verify_result(&wire(result),&wire(command),&[]);
  verify(&result,&command).unwrap();
  result["default_revision"]=json!(7);assert!(verify(&result,&command).is_err());
  result["upgrade_kind"]=json!("UNCHANGED");verify(&result,&command).unwrap();
  result["default_revision"]=json!(8);assert!(verify(&result,&command).is_err());
  command["body"]["execution_context_id"]=json!(context);result["upgrade_kind"]=json!("ROLE_BUNDLE_UPDATED");result["binding_revision"]=json!(8);result["default_revision"]=json!(42);
  verify(&result,&command).unwrap();
  result["execution_context_id"]=json!("X".repeat(43));assert!(verify(&result,&command).is_err());
  result["execution_context_id"]=json!(context);result["package_digest"]=json!("b".repeat(64));assert!(verify(&result,&command).is_err());
 }
}
