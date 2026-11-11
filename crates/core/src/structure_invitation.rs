//! Owner-authorized one-use Human admission. Bearer secrets and body keys stay
//! local; the service receives only a claim public key and encrypted package.
use crate::{canonical::{canonical,Path},crypto::{base64url,sha256_hex,verify_canonical},
 prepared_command::VerifiedStructureAuthorIntent,structure_access::{AccessError,AccessKeyMaterial,VerifiedAccessRequest,verify_access_request},wire_json::canonical_wire_value};
use aes_gcm::{Aes256Gcm,KeyInit,aead::{Aead,Payload},Nonce};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use serde_json::{json,Value};
use zeroize::Zeroizing;

pub const FEATURE:&str="owner-authorized-space-invitations-v1";
fn invalid<E>(_:E)->AccessError{AccessError::Invalid}
fn derive(seed:&[u8;32],salt:&[u8],info:&[u8])->Result<Zeroizing<[u8;32]>,AccessError>{
 let mut key=Zeroizing::new([0;32]);Hkdf::<sha2_hkdf::Sha256>::new(Some(salt),seed).expand(info,&mut *key).map_err(invalid)?;Ok(key)
}
/// A stable local secret for one frozen operation; never derive from public IDs alone.
pub fn operation_secret(owner_seed:&[u8;32],selection:&[u8])->Result<Zeroizing<[u8;32]>,AccessError>{
 derive(owner_seed,b"peerwork.owner-invitation-operation.v1",selection)
}
pub fn claim_key(seed:&[u8;32])->Result<String,AccessError>{
 let secret=derive(seed,b"peerwork.space-invitation.v1",b"claim-signing")?;
 Ok(base64url(&SigningKey::from_bytes(&secret).verifying_key().to_bytes()))
}
pub fn key_context(audience:&str,workspace:&str,owner:&str,body:&Value)->Value{
 let mut out=json!({"domain":"peerwork.space-invitation-keys.v1","audience":audience,"workspace_id":workspace,"owner_id":owner});
 for name in ["invitation_id","claim_key","expires_at","role_label","inviter_label","grants","key_ids","current_key_id","content_key_epoch"]{out[name]=body[name].clone();}out
}
pub fn seal_keys(seed:&[u8;32],keys:&[AccessKeyMaterial],context:&Value,nonce:&[u8;12])->Result<Value,AccessError>{
 if keys.is_empty()||keys.len()>32||context["key_ids"]!=json!(keys.iter().map(|key|key.key_id()).collect::<Vec<_>>()){return Err(AccessError::Invalid);}
 // Encoded secret strings live only in the wiping plaintext buffer, not Value.
 let mut plain=Zeroizing::new(String::from("{\"format\":\"peerwork.invitation-keys.v1\",\"keys\":["));
 for (index,key) in keys.iter().enumerate(){if index>0{plain.push(',');}plain.push_str("{\"key_id\":\"");plain.push_str(key.key_id());plain.push_str("\",\"secret\":\"");let encoded=Zeroizing::new(base64url(key.secret()));plain.push_str(&encoded);plain.push_str("\"}");}plain.push_str("]}");
 let aad=canonical(context,Path::SecureArtifact).map_err(invalid)?;
 let secret=derive(seed,b"peerwork.space-invitation.v1",b"key-package")?;
 let cipher=Aes256Gcm::new_from_slice(&*secret).map_err(invalid)?;
 let ciphertext=cipher.encrypt(Nonce::from_slice(nonce),Payload{msg:plain.as_bytes(),aad:aad.as_bytes()}).map_err(invalid)?;
 Ok(json!({"algorithm":"A256GCM","nonce":base64url(nonce),"aad_digest":sha256_hex(aad.as_bytes()),"ciphertext":base64url(&ciphertext)}))
}
fn body(author:&VerifiedStructureAuthorIntent)->Result<Value,AccessError>{
 let wire=author.command().get("body").ok_or(AccessError::Invalid)?;
 serde_json::from_str(&canonical_wire_value(wire,Path::SecureArtifact).map_err(invalid)?).map_err(invalid)
}
/// Independently authenticate delegated admission, preserving both real authors.
pub fn verify_authority(redeemer:&VerifiedStructureAuthorIntent,issuer:&VerifiedStructureAuthorIntent,owner:&str,workspace:&str,audience:&str,service_key:&str)->Result<VerifiedAccessRequest,AccessError>{
 if redeemer.action_id()!="structure.invitation.redeem"||issuer.action_id()!="structure.invitation.issue"||issuer.actor_id()!=owner||issuer.workspace_id()!=Some(workspace)||redeemer.workspace_id()!=Some(workspace){return Err(AccessError::Invalid);}
 let issue=body(issuer)?;let redemption=body(redeemer)?;
 let at=redeemer.command().get("issued_at").and_then(|v|v.as_number()).filter(|n|n.fract()==0.0&&*n>=0.0&&*n<=9_007_199_254_740_991.0).ok_or(AccessError::Invalid)? as u64;
 let end=issue["expires_at"].as_u64().ok_or(AccessError::Invalid)?;
 if redemption["issue_digest"]!=issuer.intent_digest()||redemption["invitation_id"]!=issue["invitation_id"]||end<=at||issue["profile"]!="backend-structure-v1"||redemption["profile"]!="backend-structure-v1"{return Err(AccessError::Invalid);}
 let request_jws=redemption["request_jws"].as_str().ok_or(AccessError::Invalid)?;
 let request=verify_access_request(request_jws,workspace,&audience.encode_utf16().collect::<Vec<_>>(),service_key,at)?;
 let policy=request.request().authorization.as_ref().ok_or(AccessError::Invalid)?;
 if request.request().v!=3||request.request().actor_id!=redeemer.actor_id()||policy.absolute_expires_at.is_some(){return Err(AccessError::Invalid);}
 let expected=json!({"format":"peerwork.invitation-redemption.v1","audience":audience,"workspace_id":workspace,"invitation_id":issue["invitation_id"],"issue_digest":issuer.intent_digest(),"request_digest":sha256_hex(request_jws.as_bytes())});
 if redemption["claim"]["payload"]!=expected||!verify_canonical("peerwork.space-invitation-claim.v1",&expected,redemption["claim"]["signature"].as_str().ok_or(AccessError::Invalid)?,issue["claim_key"].as_str().ok_or(AccessError::Invalid)?).map_err(invalid)?{return Err(AccessError::Invalid);}
 let context=key_context(audience,workspace,owner,&issue);
 if issue["key_package"]["algorithm"]!="A256GCM"||issue["key_package"]["aad_digest"]!=sha256_hex(canonical(&context,Path::SecureArtifact).map_err(invalid)?.as_bytes())||issue["content_key_epoch"].as_u64().is_none_or(|n|n==0){return Err(AccessError::Invalid);}
 Ok(request)
}

#[cfg(test)]mod tests{
 use super::*;
 use crate::{human_author::AuthorProofContext,prepared_command::verify_structure_author_intent_with_proofs,structure_key_delivery::{CurrentKeyRecipient,verify_follow_invitation_recipient}};
 #[test]fn accepted_human_invitation_preserves_the_actual_owner_and_delegated_signer(){
  let f:Value=serde_json::from_str(include_str!("../../../tests/fixtures/space-invitation-authority-v1.json")).unwrap();
  let audience=f["audience"].as_str().unwrap();let ws=f["workspace_id"].as_str().unwrap();let owner=f["owner_id"].as_str().unwrap();let service=f["service_key"].as_str().unwrap();
  let proofs=AuthorProofContext::from_json_container(&f).unwrap();let source=&f["approval"];let issued=&source["invitation_source"];let owner_proofs=AuthorProofContext::from_json_container(issued).unwrap();
  let redeemer=verify_structure_author_intent_with_proofs(source["author_intent"].as_str().unwrap(),&audience.encode_utf16().collect::<Vec<_>>(),proofs.as_ref()).unwrap();
  let issuer=verify_structure_author_intent_with_proofs(issued["author_intent"].as_str().unwrap(),&audience.encode_utf16().collect::<Vec<_>>(),owner_proofs.as_ref()).unwrap();
  assert_ne!(redeemer.actor_id(),issuer.actor_id());let request=verify_authority(&redeemer,&issuer,owner,ws,audience,service).unwrap();assert_eq!(request.request().actor_id,redeemer.actor_id());
  let recipient:CurrentKeyRecipient=serde_json::from_value(f["recipient"].clone()).unwrap();
  verify_follow_invitation_recipient(&redeemer,&issuer,owner,ws,&recipient,audience,service).unwrap();
  assert!(verify_authority(&redeemer,&issuer,redeemer.actor_id(),ws,audience,service).is_err());
  assert!(verify_authority(&redeemer,&issuer,owner,&base64url(&[1;32]),audience,service).is_err());
  for change in 0..5{let mut bad=recipient.clone();match change{0=>bad.intent_digest="0".repeat(64),1=>bad.actor_id=owner.into(),2=>bad.certificate_digest="0".repeat(64),3=>bad.authorization_version=None,_=>bad.expires_at=Some(f["now"].as_u64().unwrap()+1000)};assert!(verify_follow_invitation_recipient(&redeemer,&issuer,owner,ws,&bad,audience,service).is_err());}
 }
 #[test]fn local_secret_and_claim_are_stable_but_separate_for_distinct_operations(){
  let one=operation_secret(&[7;32],b"original").unwrap();let same=operation_secret(&[7;32],b"original").unwrap();let two=operation_secret(&[7;32],b"another").unwrap();
  assert_eq!(*one,*same);assert_ne!(*one,*two);assert_ne!(base64url(&*one),claim_key(&one).unwrap());assert_ne!(claim_key(&one).unwrap(),claim_key(&two).unwrap());
 }
}
