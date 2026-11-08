//! Explicit Owner authority for a bounded history range. The admission CSR is
//! evidence of the original grant, never resubmitted as another admission.
use crate::{canonical::{canonical,Path},crypto::{base64url,decode_base64url,sha256_hex},
    e2ee::{hpke_open_wire,hpke_seal_wire,KeyBox},prepared_command::VerifiedStructureAuthorIntent,
    secure_recipient::SecretRecipient,structure_access::{AccessError,AccessKeyMaterial,OpenedAccessKeys,VerifiedAccessRequest,verify_access_request},
    structure_content::structure_content_key_id,wire_json::{WireValue,canonical_wire_value}};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use zeroize::{Zeroize,Zeroizing};
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct RetainedKeyAuthority{pub actor_id:String,pub membership_id:String,pub recipient_key_id:String,pub authorization_digest:String,pub certificate_digest:String,pub expires_at:u64,pub through_epoch:u64}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct RetainedKeyEntry{pub epoch:u64,pub key_id:String}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedKeyEnvelope{
 pub actor_id:String,pub membership_id:String,pub recipient_key_id:String,pub authorization_digest:String,pub certificate_digest:String,pub expires_at:u64,pub through_epoch:u64,
 pub keys:Vec<RetainedKeyEntry>,pub r#box:KeyBox,
}
impl RetainedKeyEnvelope{pub fn authority(&self)->RetainedKeyAuthority{RetainedKeyAuthority{actor_id:self.actor_id.clone(),membership_id:self.membership_id.clone(),recipient_key_id:self.recipient_key_id.clone(),authorization_digest:self.authorization_digest.clone(),certificate_digest:self.certificate_digest.clone(),expires_at:self.expires_at,through_epoch:self.through_epoch}}}
pub struct VerifiedRetainedAuthority{request:VerifiedAccessRequest,authority:RetainedKeyAuthority,owner:String,workspace:String,audience:String}
pub struct VerifiedRetainedEpoch{entry:RetainedKeyEntry,authorization_digest:String}
impl VerifiedRetainedEpoch{pub fn entry(&self)->&RetainedKeyEntry{&self.entry}}
fn text(v:&WireValue,k:&str)->Result<String,AccessError>{v.get(k).and_then(WireValue::as_string).ok_or(AccessError::Invalid)}
fn integer(v:&WireValue,k:&str)->Result<u64,AccessError>{v.get(k).and_then(WireValue::as_number).filter(|n|n.is_finite()&&n.fract()==0.0&&(0.0..=9_007_199_254_740_991.0).contains(n)).map(|n|n as u64).ok_or(AccessError::Invalid)}
fn token(v:&str)->bool{v.len()==43&&decode_base64url(v).is_ok_and(|b|b.len()==32)}
fn valid_authority(r:&RetainedKeyAuthority)->bool{
 [&r.actor_id,&r.membership_id,&r.recipient_key_id].into_iter().all(|v|token(v))&&[&r.authorization_digest,&r.certificate_digest].into_iter().all(|d|d.len()==64&&d.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()))&&r.expires_at>0&&r.expires_at<=9_007_199_254_740_991&&r.through_epoch>0&&r.through_epoch<=9_007_199_254_740_991
}
pub fn verify_retained_authority(author:&VerifiedStructureAuthorIntent,owner:&str,workspace:&str,r:RetainedKeyAuthority,audience:&str,service_key:&str,now:u64)->Result<VerifiedRetainedAuthority,AccessError>{
 if !valid_authority(&r)||author.actor_id()!=owner||author.workspace_id()!=Some(workspace)||author.action_id()!="structure.access.authorize"||author.intent_digest()!=r.authorization_digest||r.expires_at<=now{return Err(AccessError::Invalid);}
 let c=author.command();let b=c.get("body").ok_or(AccessError::Invalid)?;
 if integer(b,"retained_key_epoch_ceiling")?!=r.through_epoch||matches!(b.get("content_grant"),None|Some(WireValue::Null)){return Err(AccessError::Invalid);}
 let request=verify_access_request(&text(b,"request_jws")?,workspace,&audience.encode_utf16().collect::<Vec<_>>(),service_key,integer(c,"issued_at")?)?;
 let certificate=serde_json::to_value(&request.request().certificate).map_err(|_|AccessError::Invalid)?;
 let cert_digest=sha256_hex(canonical(&certificate,Path::SecureArtifact).map_err(|_|AccessError::Invalid)?.as_bytes());
 let cert_expiry=certificate["payload"]["expires_at"].as_u64().ok_or(AccessError::Invalid)?;
 if request.request().actor_id!=r.actor_id||request.recipient_key_id()!=r.recipient_key_id||cert_digest!=r.certificate_digest||r.expires_at>cert_expiry||cert_expiry<=now{return Err(AccessError::Invalid);}
 match text(b,"mode")?.as_str(){"SESSION" if r.expires_at<=integer(b,"expires_at")?=>(),"KEYS_ONLY"=>(),_=>return Err(AccessError::Invalid)};
 Ok(VerifiedRetainedAuthority{request,authority:r,owner:owner.into(),workspace:workspace.into(),audience:audience.into()})
}
pub fn verify_retained_epoch(author:&VerifiedStructureAuthorIntent,owner:&str,workspace:&str,authority:&VerifiedRetainedAuthority,entry:RetainedKeyEntry)->Result<VerifiedRetainedEpoch,AccessError>{
 let b=author.command().get("body").ok_or(AccessError::Invalid)?;
 if authority.owner!=owner||authority.workspace!=workspace||text(author.command(),"audience")?!=authority.audience||author.actor_id()!=owner||author.workspace_id()!=Some(workspace)||author.action_id()!="structure.content-key.set"||!token(&entry.key_id)||entry.epoch==0||entry.epoch>authority.authority.through_epoch||integer(b,"expected_epoch")?.checked_add(1)!=Some(entry.epoch)||text(b,"key_id")?!=entry.key_id{return Err(AccessError::Invalid);}
 Ok(VerifiedRetainedEpoch{entry,authorization_digest:authority.authority.authorization_digest.clone()})
}
fn context(audience:&str,workspace:&str,owner:&str,job:&str,authority:&RetainedKeyAuthority,entries:&[RetainedKeyEntry])->Value{
 let mut result=serde_json::to_value(authority).expect("metadata serializes");let object=result.as_object_mut().expect("authority object");
 object.insert("domain".into(),json!("peerwork.retained-body-keys.v1"));object.insert("audience".into(),json!(audience));object.insert("workspace_id".into(),json!(workspace));object.insert("owner_id".into(),json!(owner));object.insert("job_id".into(),json!(job));object.insert("keys".into(),json!(entries));result
}
fn valid_entries(entries:&[RetainedKeyEntry],ceiling:u64)->bool{!entries.is_empty()&&entries.len()<=32&&entries.iter().all(|e|e.epoch>0&&e.epoch<=ceiling&&token(&e.key_id))&&entries.windows(2).all(|w|w[0].epoch<w[1].epoch)&&entries.iter().map(|e|&e.key_id).collect::<std::collections::BTreeSet<_>>().len()==entries.len()}
pub fn seal_retained_keys(verified:&VerifiedRetainedAuthority,epochs:&[VerifiedRetainedEpoch],keys:&[AccessKeyMaterial],audience:&str,workspace:&str,owner:&str,job:&str)->Result<RetainedKeyEnvelope,AccessError>{
 let entries:Vec<_>=epochs.iter().map(|e|e.entry.clone()).collect();let r=&verified.authority;
 if !token(job)||!token(owner)||verified.owner!=owner||verified.workspace!=workspace||verified.audience!=audience||epochs.iter().any(|e|e.authorization_digest!=r.authorization_digest)||verified.request.request().workspace_id!=workspace||!valid_entries(&entries,r.through_epoch)||entries.len()!=keys.len(){return Err(AccessError::Invalid);}
 let mut plain=Zeroizing::new(String::from("{\"keys\":["));
 for (i,(entry,key)) in entries.iter().zip(keys).enumerate(){
  if key.key_id()!=entry.key_id||structure_content_key_id(key.secret())!=entry.key_id{return Err(AccessError::Invalid);}
  if i>0{plain.push(',');}plain.push_str("{\"key_id\":\"");plain.push_str(&entry.key_id);plain.push_str("\",\"secret\":\"");let encoded=Zeroizing::new(base64url(key.secret()));plain.push_str(&encoded);plain.push_str("\"}");
 }plain.push_str("]}");
 let wire=serde_json::to_vec(&context(audience,workspace,owner,job,r,&entries)).map_err(|_|AccessError::Invalid)?;
 let boxed=hpke_seal_wire(verified.request.recipient(),plain.as_bytes(),&wire).map_err(|_|AccessError::Invalid)?;
 Ok(RetainedKeyEnvelope{actor_id:r.actor_id.clone(),membership_id:r.membership_id.clone(),recipient_key_id:r.recipient_key_id.clone(),authorization_digest:r.authorization_digest.clone(),certificate_digest:r.certificate_digest.clone(),expires_at:r.expires_at,through_epoch:r.through_epoch,keys:entries,r#box:boxed})
}
struct WipingWire(WireValue);
impl Drop for WipingWire{fn drop(&mut self){fn wipe(v:&mut WireValue){match v{WireValue::String(s)=>s.zeroize(),WireValue::Array(a)=>a.iter_mut().for_each(wipe),WireValue::Object(a)=>a.iter_mut().for_each(|(k,v)|{k.zeroize();wipe(v)}),_=>()}}wipe(&mut self.0)}}
pub fn open_owner_retained_keys(author:&VerifiedStructureAuthorIntent,owner:&str,actor:&str,recipient:&SecretRecipient,workspace:&str,audience:&str)->Result<OpenedAccessKeys,AccessError>{
 if author.actor_id()!=owner||author.workspace_id()!=Some(workspace)||author.action_id()!="structure.content-key.history.deliver"||text(author.command(),"audience")?!=audience{return Err(AccessError::Invalid);}
 let body=author.command().get("body").ok_or(AccessError::Invalid)?;let job=text(body,"job_id")?;
 let envelope=canonical_wire_value(body.get("envelope").ok_or(AccessError::Invalid)?,Path::SecureArtifact).map_err(|_|AccessError::Invalid)?;
 let envelope:RetainedKeyEnvelope=serde_json::from_str(&envelope).map_err(|_|AccessError::Invalid)?;let authority=envelope.authority();let r=&authority;
 if !token(&job)||!valid_authority(r)||r.actor_id!=actor||r.recipient_key_id!=recipient.encryption_key_id()||!valid_entries(&envelope.keys,r.through_epoch){return Err(AccessError::Invalid);}
 let plain=WipingWire(hpke_open_wire(recipient.private_bytes(),&envelope.r#box,&serde_json::to_vec(&context(audience,workspace,owner,&job,r,&envelope.keys)).map_err(|_|AccessError::Invalid)?).map_err(|_|AccessError::Authentication)?);
 let Some(WireValue::Array(material))=plain.0.get("keys")else{return Err(AccessError::Invalid);};if plain.0.object_len()!=Some(1)||material.len()!=envelope.keys.len(){return Err(AccessError::Invalid);}
 let mut keys=Vec::new();
 for (entry,item) in envelope.keys.iter().zip(material){
  if item.object_len()!=Some(2)||text(item,"key_id")?!=entry.key_id{return Err(AccessError::Invalid);}
  let encoded=Zeroizing::new(text(item,"secret")?);let bytes=Zeroizing::new(decode_base64url(&encoded).map_err(|_|AccessError::Invalid)?);if bytes.len()!=32{return Err(AccessError::Invalid);}
  let mut secret=Zeroizing::new([0;32]);secret.copy_from_slice(&bytes);keys.push(AccessKeyMaterial::new(entry.key_id.clone(),secret)?);
 }
 // The normal native importer retains selected historical material without
 // selecting this field as current. A newer authenticated head stays pinned.
 let current_key_id=keys.last().ok_or(AccessError::Invalid)?.key_id().to_owned();Ok(OpenedAccessKeys{keys,current_key_id})
}

#[cfg(test)]
mod tests{
 use super::*;
 use crate::{crypto::{sign_compact,key_id},prepared_command::verify_structure_author_intent};
 use ed25519_dalek::SigningKey;
 const NOW:u64=1_800_000_000_000;
 fn fixture()->Value{serde_json::from_str(include_str!("../../../tests/fixtures/structure-access-v1.json")).unwrap()}
 fn signed(command:&Value)->VerifiedStructureAuthorIntent{let key=SigningKey::from_bytes(&[9;32]);let jws=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":key_id(&key.verifying_key().to_bytes())}),command,&key).unwrap();verify_structure_author_intent(&jws,&"structure-test".encode_utf16().collect::<Vec<_>>()).unwrap()}
 fn approval(ceiling:Option<u64>)->(Value,VerifiedStructureAuthorIntent,RetainedKeyAuthority){
  let f=fixture();let jws=f["owner_jws"].as_str().unwrap();let mut c:Value=serde_json::from_slice(&decode_base64url(jws.split('.').nth(1).unwrap()).unwrap()).unwrap();
  if let Some(n)=ceiling{c["body"]["retained_key_epoch_ceiling"]=json!(n);}let a=signed(&c);
  let request=verify_access_request(c["body"]["request_jws"].as_str().unwrap(),&base64url(&[3;32]),&"structure-test".encode_utf16().collect::<Vec<_>>(),f["service_key"].as_str().unwrap(),NOW).unwrap();
  let certificate=serde_json::to_value(&request.request().certificate).unwrap();let r=RetainedKeyAuthority{actor_id:request.request().actor_id.clone(),membership_id:base64url(&[14;32]),recipient_key_id:request.recipient_key_id().into(),authorization_digest:a.intent_digest().into(),certificate_digest:sha256_hex(canonical(&certificate,Path::SecureArtifact).unwrap().as_bytes()),expires_at:c["body"]["expires_at"].as_u64().unwrap(),through_epoch:ceiling.unwrap_or(3)};(c,a,r)
 }
 fn epoch(c:&Value,n:u64,key:&str)->VerifiedStructureAuthorIntent{let mut c=c.clone();c["action_id"]=json!("structure.content-key.set");c["expected_workspace_revision"]=Value::Null;c["body"]=json!({"profile":"backend-structure-v1","key_id":key,"expected_epoch":n-1,"expected_head_revision":if n==1{Value::Null}else{json!(n-1)}});signed(&c)}
 #[test]
 fn history_authority_is_explicit_and_bounds_actor_device_time_and_epoch(){
  let f=fixture();let owner=f["owner_id"].as_str().unwrap();let ws=base64url(&[3;32]);let (_,no,mut r)=approval(None);
  assert!(verify_retained_authority(&no,owner,&ws,r.clone(),"structure-test",f["service_key"].as_str().unwrap(),NOW).is_err());
  let (c,yes,valid)=approval(Some(3));r=valid.clone();
  assert!(verify_retained_authority(&yes,owner,&ws,r.clone(),"structure-test",f["service_key"].as_str().unwrap(),NOW+1000).is_ok());
  for change in 0..6{let mut bad=r.clone();match change{0=>bad.through_epoch=4,1=>bad.expires_at+=1,2=>bad.authorization_digest="a".repeat(64),3=>bad.certificate_digest="b".repeat(64),4=>bad.actor_id=base64url(&[20;32]),_=>bad.recipient_key_id=base64url(&[21;32])};assert!(verify_retained_authority(&yes,owner,&ws,bad,"structure-test",f["service_key"].as_str().unwrap(),NOW).is_err());}
  assert!(verify_retained_authority(&yes,owner,&ws,r.clone(),"structure-test",f["service_key"].as_str().unwrap(),r.expires_at).is_err());
  let authority=verify_retained_authority(&yes,owner,&ws,r,"structure-test",f["service_key"].as_str().unwrap(),NOW).unwrap();let id=structure_content_key_id(&[99;32]);
  assert!(verify_retained_epoch(&epoch(&c,2,&id),owner,&ws,&authority,RetainedKeyEntry{epoch:2,key_id:id.clone()}).is_ok());
  for n in [0,1,4]{assert!(verify_retained_epoch(&epoch(&c,2,&id),owner,&ws,&authority,RetainedKeyEntry{epoch:n,key_id:id.clone()}).is_err());}
 }
 #[test]
 fn retained_envelope_round_trip_has_distinct_domain_and_authenticates_exact_scope(){
  let f=fixture();let owner=f["owner_id"].as_str().unwrap();let ws=base64url(&[3;32]);let (c,a,r)=approval(Some(3));let authority=verify_retained_authority(&a,owner,&ws,r.clone(),"structure-test",f["service_key"].as_str().unwrap(),NOW).unwrap();
  let material:Vec<_>=[55u8,99].into_iter().map(|b|AccessKeyMaterial::new(structure_content_key_id(&[b;32]),Zeroizing::new([b;32])).unwrap()).collect();
  let epochs:Vec<_>=material.iter().enumerate().map(|(i,k)|verify_retained_epoch(&epoch(&c,i as u64+1,k.key_id()),owner,&ws,&authority,RetainedKeyEntry{epoch:i as u64+1,key_id:k.key_id().into()}).unwrap()).collect();let job=base64url(&[22;32]);
  let envelope=seal_retained_keys(&authority,&epochs,&material,"structure-test",&ws,owner,&job).unwrap();let wire=serde_json::to_string(&envelope).unwrap();assert!(!wire.contains(&base64url(&[55;32])));assert!(serde_json::from_str::<RetainedKeyEnvelope>(&wire).is_ok());
  assert!(seal_retained_keys(&authority,&epochs,&material,"other-service",&ws,owner,&job).is_err());
  assert!(seal_retained_keys(&authority,&epochs,&material,"structure-test",&ws,&base64url(&[23;32]),&job).is_err());
  let other_workspace=base64url(&[24;32]);let mut foreign=c.clone();foreign["workspace_id"]=json!(other_workspace);
  assert!(verify_retained_epoch(&epoch(&foreign,1,material[0].key_id()),owner,&other_workspace,&authority,RetainedKeyEntry{epoch:1,key_id:material[0].key_id().into()}).is_err());
  let mut delivery=c.clone();delivery["action_id"]=json!("structure.content-key.history.deliver");delivery["expected_workspace_revision"]=Value::Null;delivery["body"]=json!({"profile":"backend-structure-v1","job_id":job,"page_token":"Owner-signed opaque service page","envelope":envelope});
  let recipient=SecretRecipient::from_private(Zeroizing::new([4;32])).unwrap();let opened=open_owner_retained_keys(&signed(&delivery),owner,&r.actor_id,&recipient,&ws,"structure-test").unwrap();assert_eq!(opened.keys.len(),2);assert_eq!(opened.keys[0].secret(),&[55;32]);
  for change in 0..7{let mut bad=delivery.clone();match change{0=>bad["body"]["job_id"]=json!(base64url(&[23;32])),1=>bad["body"]["envelope"]["through_epoch"]=json!(4),2=>bad["body"]["envelope"]["authorization_digest"]=json!("a".repeat(64)),3=>bad["body"]["envelope"]["membership_id"]=json!(base64url(&[24;32])),4=>bad["body"]["envelope"]["keys"][0]["epoch"]=json!(2),5=>bad["body"]["envelope"]["keys"][0]["key_id"]=json!(base64url(&[25;32])),_=>bad["body"]["envelope"]["extra"]=json!(true)};assert!(open_owner_retained_keys(&signed(&bad),owner,&r.actor_id,&recipient,&ws,"structure-test").is_err());}
  let mut current=delivery;current["action_id"]=json!("structure.content-key.deliver");assert!(open_owner_retained_keys(&signed(&current),owner,&r.actor_id,&recipient,&ws,"structure-test").is_err());
  let wrong=SecretRecipient::generate().unwrap();assert!(open_owner_retained_keys(&signed(&c),owner,&r.actor_id,&wrong,&ws,"structure-test").is_err());
 }
}
