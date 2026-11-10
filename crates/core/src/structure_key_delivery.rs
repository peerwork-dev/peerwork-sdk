//! Standing Owner authority and HPKE current-key envelopes. No plaintext key
//! enters a public result or a transport journal.
use crate::{crypto::{sha256_hex,base64url},canonical::{canonical,Path},e2ee::{hpke_seal_wire,hpke_open_wire,KeyBox},prepared_command::VerifiedStructureAuthorIntent,secure_recipient::SecretRecipient,structure_access::{AccessError,VerifiedAccessRequest,verify_access_request,AccessKeyMaterial,OpenedAccessKeys},structure_content::structure_content_key_id,wire_json::WireValue};
use serde::{Serialize,Deserialize};
use serde_json::{Value,json};
use zeroize::{Zeroizing,Zeroize};
use crate::{e2ee::RecipientPublicJwk,human_author::{AccountBinding,RootCertificate,verify_root}};

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentAccountRecipient{pub account_id:String,pub root_generation:u64,pub root_certificate_hash:String,pub root_certificate:String,pub source_recipient_key_id:String}

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentKeyRecipient {pub actor_id:String,pub membership_id:String,pub recipient_key_id:String,pub intent_digest:String,pub certificate_digest:String,pub expires_at:Option<u64>,#[serde(default,skip_serializing_if="Option::is_none")]pub authorization_version:Option<u8>,#[serde(default,skip_serializing_if="Option::is_none")]pub account_root:Option<CurrentAccountRecipient>}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentKeyEnvelope {
 pub actor_id:String,pub membership_id:String,pub recipient_key_id:String,pub intent_digest:String,pub certificate_digest:String,pub expires_at:Option<u64>,#[serde(default,skip_serializing_if="Option::is_none")]pub authorization_version:Option<u8>,#[serde(default,skip_serializing_if="Option::is_none")]pub account_root:Option<CurrentAccountRecipient>,pub r#box:KeyBox,
}
fn invalid<E>(_:E)->AccessError{AccessError::Invalid}
fn text(v:&WireValue,key:&str)->Result<String,AccessError>{v.get(key).and_then(WireValue::as_string).ok_or(AccessError::Invalid)}
fn integer(v:&WireValue,key:&str)->Result<u64,AccessError>{v.get(key).and_then(WireValue::as_number).filter(|n|n.is_finite()&&n.fract()==0.0&&*n>=0.0&&*n<=9_007_199_254_740_991.0).map(|n|n as u64).ok_or(AccessError::Invalid)}
fn selected_recipient(request:&VerifiedAccessRequest,r:&CurrentKeyRecipient,audience:&str)->Result<RecipientPublicJwk,AccessError>{
 let Some(next)=&r.account_root else{if request.recipient_key_id()!=r.recipient_key_id{return Err(AccessError::Invalid)}return Ok(request.recipient().clone())};
 if request.request().v!=3||r.authorization_version!=Some(2)||next.source_recipient_key_id!=request.recipient_key_id()||next.root_certificate.len()>4096{return Err(AccessError::Invalid)}
 let old_wire=request.request().certificate.payload["root_certificate"].as_str().ok_or(AccessError::Invalid)?;
 let payload=old_wire.split('.').nth(1).ok_or(AccessError::Invalid)?;let old:RootCertificate=serde_json::from_slice(&crate::crypto::decode_base64url(payload).map_err(invalid)?).map_err(invalid)?;
 if old.account_id!=next.account_id||old.peer_id!=r.actor_id||next.root_generation<=old.root_generation{return Err(AccessError::Invalid)}
 let binding=AccountBinding{audience:audience.into(),account_id:next.account_id.clone(),peer_id:r.actor_id.clone(),root_generation:old.root_generation};let previous=verify_root(old_wire,&binding).map_err(invalid)?;
 let current=verify_root(&next.root_certificate,&AccountBinding{root_generation:next.root_generation,..binding}).map_err(invalid)?;
 if current.hash()!=next.root_certificate_hash||current.recovery_public_key()!=previous.recovery_public_key()||current.certificate().recipient_key_id!=r.recipient_key_id||r.recipient_key_id==next.source_recipient_key_id{return Err(AccessError::Invalid)}
 Ok(current.certificate().recipient_public_key.clone())
}
pub fn verify_follow_recipient(author:&VerifiedStructureAuthorIntent,owner:&str,workspace:&str,r:&CurrentKeyRecipient,audience:&str,service_key:&str,now:u64)->Result<VerifiedAccessRequest,AccessError>{
 if author.actor_id()!=owner||author.intent_digest()!=r.intent_digest||author.workspace_id()!=Some(workspace)||author.action_id()!="structure.access.authorize"||r.expires_at.is_some_and(|end|end<=now){return Err(AccessError::Invalid);}
 let command=author.command();let body=command.get("body").ok_or(AccessError::Invalid)?;
 if !matches!(body.get("follow_current_key"),Some(WireValue::Bool(true))){return Err(AccessError::Invalid);}
 if matches!(body.get("content_grant"),None|Some(WireValue::Null)){return Err(AccessError::Invalid);}
 let request=verify_access_request(&text(body,"request_jws")?,workspace,&audience.encode_utf16().collect::<Vec<_>>(),service_key,integer(command,"issued_at")?)?;
 let certificate=serde_json::to_value(&request.request().certificate).map_err(invalid)?;
 let digest=sha256_hex(canonical(&certificate,Path::SecureArtifact).map_err(invalid)?.as_bytes());
 let certificate_expiry=request.request().certificate.payload["expires_at"].as_u64().ok_or(AccessError::Invalid)?;
 if request.request().actor_id!=r.actor_id||digest!=r.certificate_digest{return Err(AccessError::Invalid);}selected_recipient(&request,r,audience)?;
 let policy=crate::structure_access::verify_access_authorization(body,&request)?;
 if policy.persistent {
  if r.authorization_version!=Some(2)||r.expires_at!=policy.expires_at{return Err(AccessError::Invalid);}
 }else if r.authorization_version.is_some()||r.expires_at.is_none_or(|end|end>certificate_expiry)||certificate_expiry<=now||policy.expires_at.is_some_and(|end|r.expires_at.is_none_or(|actual|actual>end)){return Err(AccessError::Invalid);}
 Ok(request)
}
fn context(audience:&str,workspace:&str,owner:&str,epoch:u64,key_id:&str,r:&CurrentKeyRecipient)->Value{
 let mut result=json!({"domain":if r.authorization_version==Some(2){"peerwork.current-body-key.v2"}else{"peerwork.current-body-key.v1"},"audience":audience,"workspace_id":workspace,"owner_id":owner,"epoch":epoch,"key_id":key_id,"actor_id":r.actor_id,"membership_id":r.membership_id,"recipient_key_id":r.recipient_key_id,"authorization_digest":r.intent_digest,"certificate_digest":r.certificate_digest,"expires_at":r.expires_at});
 if let Some(version)=r.authorization_version{result["authorization_version"]=json!(version);}if let Some(root)=&r.account_root{result["account_root"]=json!(root);}result
}
pub fn seal_current_key(request:&VerifiedAccessRequest,r:&CurrentKeyRecipient,audience:&str,workspace:&str,owner:&str,epoch:u64,secret:&[u8;32])->Result<CurrentKeyEnvelope,AccessError>{
 if !matches!(r.authorization_version,None|Some(2))||r.expires_at.is_none()&&r.authorization_version!=Some(2)||epoch==0||request.request().workspace_id!=workspace||request.request().actor_id!=r.actor_id{return Err(AccessError::Invalid);}let recipient=selected_recipient(request,r,audience)?;
 let key_id=structure_content_key_id(secret);let ctx=context(audience,workspace,owner,epoch,&key_id,r);
 let mut plain=Zeroizing::new(String::from("{\"secret\":\""));let encoded=Zeroizing::new(base64url(secret));plain.push_str(&encoded);plain.push_str("\"}");
 let boxed=hpke_seal_wire(&recipient,plain.as_bytes(),&serde_json::to_vec(&ctx).map_err(invalid)?).map_err(invalid)?;
 Ok(CurrentKeyEnvelope{actor_id:r.actor_id.clone(),membership_id:r.membership_id.clone(),recipient_key_id:r.recipient_key_id.clone(),intent_digest:r.intent_digest.clone(),certificate_digest:r.certificate_digest.clone(),expires_at:r.expires_at,authorization_version:r.authorization_version,account_root:r.account_root.clone(),r#box:boxed})
}
struct WipingValue(WireValue);
impl Drop for WipingValue{fn drop(&mut self){fn wipe(v:&mut WireValue){match v{WireValue::String(s)=>s.zeroize(),WireValue::Array(a)=>a.iter_mut().for_each(wipe),WireValue::Object(o)=>o.iter_mut().for_each(|(k,v)|{k.zeroize();wipe(v)}),_=>()}}wipe(&mut self.0)}}
pub fn open_owner_current_key(author:&VerifiedStructureAuthorIntent,owner:&str,actor:&str,recipient:&SecretRecipient,workspace:&str,audience:&str)->Result<OpenedAccessKeys,AccessError>{
 if author.actor_id()!=owner||author.workspace_id()!=Some(workspace)||author.action_id()!="structure.content-key.deliver"||text(author.command(),"audience")?!=audience{return Err(AccessError::Invalid);}
 let body=author.command().get("body").ok_or(AccessError::Invalid)?;let key_id=text(body,"key_id")?;
 let list=body.get("deliveries").ok_or(AccessError::Invalid)?;let WireValue::Array(items)=list else{return Err(AccessError::Invalid);};if items.len()>32{return Err(AccessError::Invalid);}
 let page=text(body,"page_token")?;let payload=page.split('.').nth(1).ok_or(AccessError::Invalid)?;
 // Epoch is also covered by the Owner signature over this exact page token.
 // The service receipt authenticates acceptance; recipients need no backend
 // signing key to authenticate their independently Owner-signed envelope.
 let page:Value=serde_json::from_slice(&crate::crypto::decode_base64url(payload).map_err(invalid)?).map_err(invalid)?;
 let epoch=page["epoch"].as_u64().filter(|n|*n>0).ok_or(AccessError::Invalid)?;
 let mut matched=None;
 for item in items{
  let value=crate::wire_json::canonical_wire_value(item,Path::SecureArtifact).map_err(invalid)?;
  let d:CurrentKeyEnvelope=serde_json::from_str(&value).map_err(invalid)?;
  if !matches!(d.authorization_version,None|Some(2))||d.expires_at.is_none()&&d.authorization_version!=Some(2){return Err(AccessError::Invalid);}
  if d.actor_id!=actor||d.recipient_key_id!=recipient.encryption_key_id(){continue;}
  if matched.is_some(){return Err(AccessError::Invalid);}
  let r=CurrentKeyRecipient{actor_id:d.actor_id,membership_id:d.membership_id,recipient_key_id:d.recipient_key_id,intent_digest:d.intent_digest,certificate_digest:d.certificate_digest,expires_at:d.expires_at,authorization_version:d.authorization_version,account_root:d.account_root};
  let plain=WipingValue(hpke_open_wire(recipient.private_bytes(),&d.r#box,&serde_json::to_vec(&context(audience,workspace,owner,epoch,&key_id,&r)).map_err(invalid)?).map_err(|_|AccessError::Authentication)?);
  if plain.0.object_len()!=Some(1){return Err(AccessError::Invalid);}
  let encoded=Zeroizing::new(text(&plain.0,"secret")?);let decoded=Zeroizing::new(crate::crypto::decode_base64url(&encoded).map_err(invalid)?);
  if decoded.len()!=32{return Err(AccessError::Invalid);}
  let mut secret=Zeroizing::new([0;32]);secret.copy_from_slice(&decoded);if structure_content_key_id(&secret)!=key_id{return Err(AccessError::Invalid);}
  matched=Some(AccessKeyMaterial::new(key_id.clone(),secret)?);
 }
 Ok(OpenedAccessKeys{keys:vec![matched.ok_or(AccessError::Invalid)?],current_key_id:key_id})
}

#[cfg(test)]
mod tests{
 use super::*;
 use crate::{prepared_command::verify_structure_author_intent,crypto::{sign_compact,key_id},structure_content::structure_content_key_id};
 use ed25519_dalek::SigningKey;
 const NOW:u64=1_800_000_000_000;
 fn fixture()->Value{serde_json::from_str(include_str!("../../../tests/fixtures/structure-access-v1.json")).unwrap()}
 fn signed(command:&Value)->VerifiedStructureAuthorIntent{let key=SigningKey::from_bytes(&[9;32]);let jws=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":key_id(&key.verifying_key().to_bytes())}),command,&key).unwrap();verify_structure_author_intent(&jws,&"structure-test".encode_utf16().collect::<Vec<_>>()).unwrap()}
 fn approval(follow:bool)->(Value,VerifiedStructureAuthorIntent,CurrentKeyRecipient){
  let f=fixture();let parts:Vec<_>=f["owner_jws"].as_str().unwrap().split('.').collect();let mut c:Value=serde_json::from_slice(&crate::crypto::decode_base64url(parts[1]).unwrap()).unwrap();c["body"]["follow_current_key"]=json!(follow);let a=signed(&c);
  let request=verify_access_request(c["body"]["request_jws"].as_str().unwrap(),f["workspace_id"].as_str().unwrap_or(&base64url(&[3;32])),&"structure-test".encode_utf16().collect::<Vec<_>>(),f["service_key"].as_str().unwrap(),NOW).unwrap();
  let certificate=serde_json::to_value(&request.request().certificate).unwrap();let r=CurrentKeyRecipient{actor_id:request.request().actor_id.clone(),membership_id:base64url(&[14;32]),recipient_key_id:request.recipient_key_id().into(),intent_digest:a.intent_digest().into(),certificate_digest:sha256_hex(canonical(&certificate,Path::SecureArtifact).unwrap().as_bytes()),expires_at:Some(c["body"]["expires_at"].as_u64().unwrap()),authorization_version:None,account_root:None};(c,a,r)
 }
 #[test]
 fn standing_owner_authority_follows_a_direct_current_account_root_and_rejects_substitutions(){
  let f:Value=serde_json::from_str(include_str!("../../../tests/fixtures/current-account-recipient-v1.json")).unwrap();
  let audience=f["audience"].as_str().unwrap();let owner=f["owner_actor"].as_str().unwrap();let workspace=f["workspace_id"].as_str().unwrap();let service=f["service_key"].as_str().unwrap();let now=f["at"].as_u64().unwrap();
  let author=verify_structure_author_intent(f["owner_jws"].as_str().unwrap(),&audience.encode_utf16().collect::<Vec<_>>()).unwrap();let recipient:CurrentKeyRecipient=serde_json::from_value(f["recipient"].clone()).unwrap();
  let request=verify_follow_recipient(&author,owner,workspace,&recipient,audience,service,now).unwrap();assert_ne!(request.recipient_key_id(),recipient.recipient_key_id);
  let sealed=seal_current_key(&request,&recipient,audience,workspace,owner,2,&[99;32]).unwrap();assert_eq!(sealed.recipient_key_id,recipient.recipient_key_id);assert_eq!(sealed.account_root.as_ref().unwrap().root_generation,2);
  for change in 0..7{
   let mut bad=recipient.clone();let root=bad.account_root.as_mut().unwrap();match change{0=>root.account_id=base64url(&[41;32]),1=>root.root_generation=1,2=>root.root_certificate_hash="0".repeat(64),3=>root.source_recipient_key_id=base64url(&[42;32]),4=>bad.recipient_key_id=base64url(&[43;32]),5=>bad.certificate_digest="0".repeat(64),_=>root.root_certificate=request.request().certificate.payload["root_certificate"].as_str().unwrap().into()};
   assert!(verify_follow_recipient(&author,owner,workspace,&bad,audience,service,now).is_err());assert!(change==5||seal_current_key(&request,&bad,audience,workspace,owner,2,&[99;32]).is_err());
  }
  let (_,native_author,mut native)=approval(true);native.account_root=recipient.account_root.clone();assert!(verify_follow_recipient(&native_author,native_author.actor_id(),workspace,&native,audience,service,now).is_err());
  if let Ok(path)=std::env::var("PEERWORK_CURRENT_ACCOUNT_SEAL_OUTPUT"){std::fs::write(path,serde_json::to_vec(&json!({"format":"peerwork.synthetic-current-account-seal.v1","envelope":sealed,"key_id":f["key_id"]})).unwrap()).unwrap();}
 }
 fn delivery(command:&Value,envelope:CurrentKeyEnvelope,epoch:u64)->Value{let mut c=command.clone();c["command_id"]=json!(base64url(&[19;32]));c["action_id"]=json!("structure.content-key.deliver");c["expected_workspace_revision"]=Value::Null;let page=format!("e30.{}.AA",base64url(serde_json::to_string(&json!({"epoch":epoch})).unwrap().as_bytes()));c["body"]=json!({"profile":"backend-structure-v1","key_id":structure_content_key_id(&[99;32]),"page_token":page,"deliveries":[envelope]});c}
 #[test]
 fn persistent_current_keys_follow_the_original_pinned_authority_beyond_bootstrap_expiry(){
  let f=fixture();let workspace=base64url(&[3;32]);let (mut command,_,mut r)=approval(true);
  let csr=command["body"]["request_jws"].as_str().unwrap();let parts:Vec<_>=csr.split('.').collect();
  let mut payload:Value=serde_json::from_slice(&crate::crypto::decode_base64url(parts[1]).unwrap()).unwrap();
  payload["v"]=json!(2);payload["authorization"]=json!({"mode":"PERSISTENT","absolute_expires_at":null,"key_binding":"PINNED_UNTIL_AUTHORIZATION_END"});
  let device=SigningKey::from_bytes(&[5;32]);
  command["body"]["request_jws"]=json!(sign_compact(&json!({"alg":"EdDSA","typ":crate::structure_access::PERSISTENT_ACCESS_REQUEST_TYPE,"kid":key_id(&device.verifying_key().to_bytes())}),&payload,&device).unwrap());
  command["body"]["mode"]=json!("PERSISTENT");command["body"]["authorization_version"]=json!(2);command["body"]["expires_at"]=Value::Null;
  let author=signed(&command);r.intent_digest=author.intent_digest().into();r.expires_at=None;r.authorization_version=Some(2);
  let owner=f["owner_id"].as_str().unwrap();let later=NOW+90*86400000;
  let verified=verify_follow_recipient(&author,owner,&workspace,&r,"structure-test",f["service_key"].as_str().unwrap(),later).unwrap();
  let envelope=seal_current_key(&verified,&r,"structure-test",&workspace,owner,2,&[99;32]).unwrap();
  let mut delivered=delivery(&command,envelope,2);delivered["issued_at"]=json!(later);delivered["expires_at"]=json!(later+600000);
  let recipient=SecretRecipient::from_private(Zeroizing::new([4;32])).unwrap();
  assert_eq!(open_owner_current_key(&signed(&delivered),owner,&r.actor_id,&recipient,&workspace,"structure-test").unwrap().keys[0].secret(),&[99;32]);
  for version in [None,Some(1),Some(3)]{let mut bad=r.clone();bad.authorization_version=version;assert!(verify_follow_recipient(&author,owner,&workspace,&bad,"structure-test",f["service_key"].as_str().unwrap(),later).is_err());}
  delivered["body"]["deliveries"][0].as_object_mut().unwrap().remove("authorization_version");
  assert!(open_owner_current_key(&signed(&delivered),owner,&r.actor_id,&recipient,&workspace,"structure-test").is_err());
 }
 #[test]
 fn standing_authority_is_explicit_and_bounded_by_original_scope(){
  let f=fixture();let workspace=base64url(&[3;32]);let (_,yes,r)=approval(true);let (_,no,mut denied)=approval(false);
  assert!(verify_follow_recipient(&yes,f["owner_id"].as_str().unwrap(),&workspace,&r,"structure-test",f["service_key"].as_str().unwrap(),NOW+1000).is_ok());
  denied.intent_digest=no.intent_digest().into();assert!(verify_follow_recipient(&no,f["owner_id"].as_str().unwrap(),&workspace,&denied,"structure-test",f["service_key"].as_str().unwrap(),NOW).is_err());
  for change in 0..4{let mut bad=r.clone();match change{0=>bad.intent_digest="a".repeat(64),1=>bad.certificate_digest="b".repeat(64),2=>bad.expires_at=bad.expires_at.map(|end|end+1),_=>bad.actor_id=base64url(&[42;32])};assert!(verify_follow_recipient(&yes,f["owner_id"].as_str().unwrap(),&workspace,&bad,"structure-test",f["service_key"].as_str().unwrap(),NOW+1000).is_err());}
  assert!(verify_follow_recipient(&yes,f["owner_id"].as_str().unwrap(),&workspace,&r,"structure-test",f["service_key"].as_str().unwrap(),r.expires_at.unwrap()).is_err());
 }
 #[test]
 fn current_key_delivery_binds_epoch_workspace_owner_and_exact_recipient(){
  let f=fixture();let workspace=base64url(&[3;32]);let (command,auth,r)=approval(true);let owner=f["owner_id"].as_str().unwrap();let request=verify_follow_recipient(&auth,owner,&workspace,&r,"structure-test",f["service_key"].as_str().unwrap(),NOW).unwrap();
  let envelope=seal_current_key(&request,&r,"structure-test",&workspace,owner,2,&[99;32]).unwrap();assert!(!serde_json::to_string(&envelope).unwrap().contains(&base64url(&[99;32])));
  let c=delivery(&command,envelope,2);let recipient=SecretRecipient::from_private(Zeroizing::new([4;32])).unwrap();let opened=open_owner_current_key(&signed(&c),owner,&r.actor_id,&recipient,&workspace,"structure-test").unwrap();assert_eq!(opened.keys[0].secret(),&[99;32]);
  for field in ["membership_id","intent_digest","certificate_digest"]{let mut bad=c.clone();bad["body"]["deliveries"][0][field]=json!("x".repeat(if field=="membership_id"{43}else{64}));assert!(open_owner_current_key(&signed(&bad),owner,&r.actor_id,&recipient,&workspace,"structure-test").is_err());}
  let other=SecretRecipient::generate().unwrap();assert!(open_owner_current_key(&signed(&c),owner,&r.actor_id,&other,&workspace,"structure-test").is_err());assert!(open_owner_current_key(&signed(&c),owner,&r.actor_id,&recipient,&base64url(&[4;32]),"structure-test").is_err());
 }
}
