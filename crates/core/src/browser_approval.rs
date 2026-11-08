//! PRIVATE browser approval producer. Request provenance and receipt-gated code
//! release belong to the runtime; policy authority comes from typed full replay.
use crate::{canonical::{canonical, Path}, crypto::{actor_id, base64url, decode_base64url, key_id, sha256_hex, sign_canonical}, e2ee::{hpke_seal_wire, RecipientPublicJwk}, replayed_secure_journal::ReplayedSecureJournal, secure_keyring::SecretKeyring, wire_json::parse_wire_json_bounded};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng,RngCore};
use serde_json::{json,Value};
use thiserror::Error;
use zeroize::Zeroizing;
const MAX:u64=9_007_199_254_740_991;
#[derive(Debug,Error,PartialEq,Eq)]
pub enum BrowserApprovalError {
    #[error("browser approval request or reference is invalid")] Invalid,
    #[error("browser approval request binding differs from selected context")] Binding,
    #[error("browser approval request or session has expired")] Expired,
    #[error("browser approval requires explicit write consent")] WriteConsent,
    #[error("browser approval scope is not authorized by the verified member policy")] Scope,
    #[error("PRIVATE browser approval requires read scope and active epoch history")] PrivateRead,
    #[error("browser device certificate is invalid or expired")] Certificate,
    #[error("browser approval cryptographic preparation failed")] Crypto,
}
impl BrowserApprovalError {pub fn code(&self)->&'static str {match self {Self::Invalid=>"BROWSER_APPROVAL_INVALID",Self::Binding=>"BROWSER_APPROVAL_BINDING",Self::Expired=>"BROWSER_APPROVAL_EXPIRED",Self::WriteConsent=>"BROWSER_APPROVAL_WRITE_CONSENT",Self::Scope=>"BROWSER_APPROVAL_SCOPE",Self::PrivateRead=>"BROWSER_APPROVAL_PRIVATE_READ",Self::Certificate=>"BROWSER_APPROVAL_CERTIFICATE",Self::Crypto=>"BROWSER_APPROVAL_CRYPTO"}}}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct BrowserApprovalReference {pub workspace_id:String,pub request_id:String,pub binding_sha256:String}
pub struct BrowserApprovalInput<'a> {
    pub request_wire:&'a [u8],pub reference:&'a str,pub control_origin:&'a str,pub audience:&'a str,
    pub replay:&'a ReplayedSecureJournal,pub policy_wire:&'a [u8],pub keyring:&'a SecretKeyring,
    pub signing_key:&'a SigningKey,pub now:u64,pub approve_writes:bool,
}
/// Secret-bearing trusted Rust result: never serialize/debug or return `code`
/// through a binding before the exact approval command receipt is verified.
pub struct PreparedBrowserApproval {
    pub body_canonical_json:String,pub code:Zeroizing<String>,pub request_id:String,
    pub workspace_id:String,pub binding_sha256:String,pub request_expires_at:u64,
}
fn token(s:&str)->bool{ s.len()==43 && decode_base64url(s).is_ok_and(|b|b.len()==32 && base64url(&b)==s) }
fn text<'a>(v:&'a Value,k:&str)->Result<&'a str,BrowserApprovalError>{v.get(k).and_then(Value::as_str).ok_or(BrowserApprovalError::Invalid)}
fn n(v:&Value,k:&str)->Result<u64,BrowserApprovalError>{v.get(k).and_then(Value::as_u64).filter(|n|*n<=MAX).ok_or(BrowserApprovalError::Invalid)}
fn canon(v:&Value)->Result<String,BrowserApprovalError>{canonical(v,Path::SecureArtifact).map_err(|_|BrowserApprovalError::Invalid)}
fn parse(w:&[u8])->Result<Value,BrowserApprovalError>{parse_wire_json_bounded(w,64,512*1024).map_err(|_|BrowserApprovalError::Invalid)?;serde_json::from_slice(w).map_err(|_|BrowserApprovalError::Invalid)}
fn sign(domain:&str,payload:Value,key:&SigningKey)->Result<Value,BrowserApprovalError>{let signature=sign_canonical(domain,&payload,key).map_err(|_|BrowserApprovalError::Crypto)?;Ok(json!({"payload":payload,"signature":signature}))}
fn random_token()->Result<Zeroizing<String>,BrowserApprovalError>{let mut bytes=Zeroizing::new([0u8;32]);OsRng.try_fill_bytes(&mut *bytes).map_err(|_|BrowserApprovalError::Crypto)?;Ok(Zeroizing::new(base64url(&*bytes)))}
pub fn parse_browser_approval_reference(reference:&str)->Result<BrowserApprovalReference,BrowserApprovalError>{
    if reference.len()>300{return Err(BrowserApprovalError::Invalid);}
    let parts:Vec<_>=reference.split(':').collect();
    if parts.len()!=5 || parts[0]!="peerwork-browser-approval" || parts[1]!="v1" || !token(parts[2]) || !token(parts[3]) || parts[4].len()!=64 || !parts[4].bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(BrowserApprovalError::Invalid);}
    Ok(BrowserApprovalReference{workspace_id:parts[2].into(),request_id:parts[3].into(),binding_sha256:parts[4].into()})
}
fn binding(request:&Value)->Result<Value,BrowserApprovalError>{
    let id=request.get("request_id").or_else(||request.get("id")).and_then(Value::as_str).ok_or(BrowserApprovalError::Invalid)?;
    let mut b=json!({"request_id":id,"workspace_id":request["workspace_id"],"device_key":request["device_key"],"device_key_sha256":request["device_key_sha256"],"origin":request["origin"],"browser_origin":request["browser_origin"],"control_origin":request["control_origin"],"audience":request["audience"],"verifier_challenge":request["verifier_challenge"],"scope":{"read":request["requested_scope"]["read"],"writes":request["requested_scope"]["writes"],"session_expires_at":request["session_expires_at"]},"request_expires_at":request["request_expires_at"],"session_expires_at":request["session_expires_at"]});
    if let Some(cert)=request.get("secure_certificate"){b["secure_certificate"]=cert.clone();}
    Ok(b)
}
fn validate_request(request:&Value,reference:&BrowserApprovalReference,control_origin:&str,audience:&str,now:u64,approve_writes:bool)->Result<Value,BrowserApprovalError>{
    if now>MAX || text(request,"state")?!="PENDING" {return Err(BrowserApprovalError::Invalid);}
    let b=binding(request)?;
    if text(&b,"workspace_id")?!=reference.workspace_id || text(&b,"request_id")?!=reference.request_id || sha256_hex(canon(&b)?.as_bytes())!=reference.binding_sha256 || text(&b,"control_origin")?!=control_origin || text(&b,"audience")?!=audience || text(&b,"origin")?!=text(&b,"browser_origin")? || control_origin.is_empty() || audience.is_empty(){return Err(BrowserApprovalError::Binding);}
    if !token(text(&b,"verifier_challenge")?){return Err(BrowserApprovalError::Binding);}
    let device=text(&b,"device_key")?;
    if !token(device) || sha256_hex(&decode_base64url(device).map_err(|_|BrowserApprovalError::Invalid)?)!=text(&b,"device_key_sha256")?{return Err(BrowserApprovalError::Binding);}
    let expires=n(request,"request_expires_at")?;let session=n(request,"session_expires_at")?;let created=n(request,"created")?;
    if expires<=now || session<=now {return Err(BrowserApprovalError::Expired);}
    let writes=request["requested_scope"]["writes"].as_array().ok_or(BrowserApprovalError::Invalid)?;
    if !writes.is_empty() && !approve_writes{return Err(BrowserApprovalError::WriteConsent);}
    let lifetime=if writes.is_empty(){30*86_400_000}else{3_600_000};
    if created==0 || created>now || session>created.checked_add(lifetime).ok_or(BrowserApprovalError::Invalid)? || n(&request["requested_scope"],"session_expires_at")?!=session{return Err(BrowserApprovalError::Invalid);}
    if request["requested_scope"]["read"]!=true{return Err(BrowserApprovalError::PrivateRead);}
    let cert=request.get("secure_certificate").ok_or(BrowserApprovalError::Certificate)?;
    if text(&cert["payload"],"signing_key")?!=device || n(&cert["payload"],"expires_at")?<=session{return Err(BrowserApprovalError::Certificate);}
    let policy=json!({"members":[{"actor_id":cert["payload"]["actor_id"],"certificate":cert}]});
    let p=parse_wire_json_bounded(canon(&policy)?.as_bytes(),64,512*1024).map_err(|_|BrowserApprovalError::Certificate)?;
    crate::secure_action_delegation::verify_member_certificate_at(&p,text(&cert["payload"],"actor_id")?,now).map_err(|_|BrowserApprovalError::Certificate)?;
    Ok(b)
}
fn delegated_scopes(member:&Value,writes:&[Value],now:u64)->Result<Vec<Value>,BrowserApprovalError>{
    if writes.len()>128{return Err(BrowserApprovalError::Scope);}
    let grants=member["scopes"].as_array().ok_or(BrowserApprovalError::Scope)?;let mut result=Vec::new();
    for write in writes {
        let fields=write.as_object().ok_or(BrowserApprovalError::Scope)?;
        if fields.len()!=2 || !fields.contains_key("instance_id") || !fields.contains_key("actions"){return Err(BrowserApprovalError::Scope);}
        let instance=text(write,"instance_id")?;if !token(instance){return Err(BrowserApprovalError::Scope);}
        let actions=write["actions"].as_array().filter(|v|!v.is_empty()&&v.len()<=64).ok_or(BrowserApprovalError::Scope)?;
        let active:Vec<_>=grants.iter().filter(|g|(g["expires_at"].is_null() || g["expires_at"].as_u64().is_some_and(|t|t>now))&&(g["instance_id"].is_null() || g["instance_id"]==write["instance_id"])).collect();
        let mut seen=Vec::new();for action in actions {let s=action.as_str().filter(|s|!s.is_empty()&&s.encode_utf16().count()<=120).ok_or(BrowserApprovalError::Scope)?;if seen.contains(&s) || !active.iter().any(|g|g["actions"].as_array().is_some_and(|a|a.contains(action))){return Err(BrowserApprovalError::Scope);}seen.push(s);}
        let union=|field:&str|->Result<Vec<Value>,BrowserApprovalError>{let mut all=Vec::new();for grant in &active {for value in grant[field].as_array().ok_or(BrowserApprovalError::Scope)? {if !all.contains(value){all.push(value.clone());}}}if all.len()>64{return Err(BrowserApprovalError::Scope);}Ok(all)};
        result.push(json!({"instance_id":instance,"actions":actions,"protocol_roles":union("protocol_roles")?,"capabilities":union("capabilities")?}));
    }Ok(result)
}
pub fn prepare_private_browser_approval(input:BrowserApprovalInput<'_>)->Result<PreparedBrowserApproval,BrowserApprovalError>{
    if input.replay.structure_status()==crate::replayed_secure_journal::StructureStatus::Seeding {return Err(BrowserApprovalError::PrivateRead);}
    let reference=parse_browser_approval_reference(input.reference)?;let request=parse(input.request_wire)?;
    let b=validate_request(&request,&reference,input.control_origin,input.audience,input.now,input.approve_writes)?;
    let policy=parse(input.policy_wire)?;
    if sha256_hex(canon(&policy)?.as_bytes())!=input.replay.policy_hash() || input.replay.workspace_id()!=reference.workspace_id || text(&policy["payload"],"workspace_id")?!=reference.workspace_id || text(&policy["payload"],"owner_id")?!=input.replay.owner_actor_id() || text(&policy["payload"],"signing_key")?!=input.replay.owner_signing_key(){return Err(BrowserApprovalError::Binding);}
    if policy["payload"]["visibility"]!="PRIVATE" || input.keyring.workspace_id()!=reference.workspace_id{return Err(BrowserApprovalError::PrivateRead);}
    let epoch=n(&policy["payload"],"epoch")?;
    if epoch==0 || input.keyring.key_at(epoch).is_none() || input.keyring.epochs().any(|e|e>epoch){return Err(BrowserApprovalError::PrivateRead);}
    let public=input.signing_key.verifying_key().to_bytes();let actor=actor_id(&public);let key=key_id(&public);
    let member=policy["payload"]["members"].as_array().ok_or(BrowserApprovalError::Scope)?.iter().find(|m|m["actor_id"]==actor && m["certificate"]["payload"]["signing_key"]==key).ok_or(BrowserApprovalError::Scope)?;
    let policy_wire=parse_wire_json_bounded(canon(&policy["payload"])?.as_bytes(),64,512*1024).map_err(|_|BrowserApprovalError::Scope)?;
    crate::secure_action_delegation::verify_member_certificate_at(&policy_wire,&actor,input.now).map_err(|_|BrowserApprovalError::Scope)?;
    let scopes=delegated_scopes(member,request["requested_scope"]["writes"].as_array().ok_or(BrowserApprovalError::Scope)?,input.now)?;
    let cert=request["secure_certificate"].clone();
    let delegation=sign("peerwork.secure.device-delegation.v1",json!({"v":1,"workspace_id":reference.workspace_id,"actor_id":actor,"signing_key":key,"device":cert,"request_id":reference.request_id,"scope":scopes,"read":true,"origin":b["origin"],"audience":input.audience,"issued_at":input.now,"expires_at":request["session_expires_at"]}),input.signing_key)?;
    let grant_id=random_token()?;
    let mut grant=json!({"v":1,"grant_id":grant_id.as_str(),"workspace_id":reference.workspace_id,"actor_id":actor,"signing_key":key,"recipient":cert,"policy_hash":input.replay.policy_hash(),"epoch":epoch,"invite_id":null,"acceptance_hash":null,"delegation":delegation,"issued_at":input.now});
    let recipient:RecipientPublicJwk=serde_json::from_value(cert["payload"]["encryption_key"].clone()).map_err(|_|BrowserApprovalError::Certificate)?;
    let ring=input.keyring.canonical_wire().map_err(|_|BrowserApprovalError::PrivateRead)?;
    let sealed=hpke_seal_wire(&recipient,&ring,canon(&grant)?.as_bytes()).map_err(|_|BrowserApprovalError::Crypto)?;
    grant["box"]=serde_json::to_value(sealed).map_err(|_|BrowserApprovalError::Crypto)?;
    let grant=sign("peerwork.secure.key-grant.v1",grant,input.signing_key)?;
    let code=random_token()?;let decoded=Zeroizing::new(decode_base64url(&code).map_err(|_|BrowserApprovalError::Crypto)?);
    let body=json!({"request_id":reference.request_id,"expected_state":"PENDING","code_hash":sha256_hex(&decoded),"scope":b["scope"],"secure_delegation":delegation,"secure_key_grant":grant});
    Ok(PreparedBrowserApproval{body_canonical_json:canon(&body)?,code,request_id:reference.request_id,workspace_id:reference.workspace_id,binding_sha256:reference.binding_sha256,request_expires_at:n(&request,"request_expires_at")?})
}

#[cfg(test)]
mod tests;
