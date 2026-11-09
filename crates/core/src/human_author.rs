//! Explicit fixed-depth Human Peer authorship. Authenticity is separate from
//! indexed account/device activation, Workspace authority and acceptance time.
use crate::{
    canonical::Path,
    crypto::{actor_id,decode_base64url,sha256_hex,verifying_key},
    e2ee::{encryption_key_id,RecipientPublicJwk},
    prepared_command::validate_command_schema,
    wire_json::{canonical_wire_value,parse_wire_json_bounded,WireValue},
};
use ed25519_dalek::{Signature,Verifier};
use serde::{Deserialize,Serialize};
use std::collections::BTreeMap;

pub const ROOT_TYPE:&str="peerwork.account-root.v1+jws";
pub const DEVICE_TYPE:&str="peerwork.human-device.v1+jws";
const COMMAND_TYPE:&str="peerwork.kernel-command.v1+jws";
const MAX_SAFE:u64=9_007_199_254_740_991;
#[derive(Debug,thiserror::Error)]
pub enum HumanAuthorError {
    #[error("ACCOUNT_PROOF_INVALID")] Invalid,
    #[error("ACCOUNT_PROOF_MISSING")] Missing,
    #[error("ACCOUNT_AUTHOR_INVALID")] Author,
}
type Result<T>=std::result::Result<T,HumanAuthorError>;
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBinding{pub audience:String,pub account_id:String,pub peer_id:String,pub root_generation:u64}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCertificate{
    pub v:u64,pub domain:String,pub audience:String,pub account_id:String,pub peer_id:String,
    pub root_generation:u64,pub operational_signing_key:String,pub recipient_public_key:RecipientPublicJwk,
    pub recipient_key_id:String,pub issued_at:u64,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCertificate{
    pub v:u64,pub domain:String,pub audience:String,pub account_id:String,pub peer_id:String,
    pub root_generation:u64,pub root_certificate_hash:String,pub device_id:String,pub device_signing_key:String,
    pub device_recipient_public_key:RecipientPublicJwk,pub device_recipient_key_id:String,pub issued_at:u64,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorReference{pub kind:String,pub root_generation:u64,pub root_certificate_hash:String,pub device_certificate_hash:String,pub device_id:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorProofContext{pub format:String,pub roots:BTreeMap<String,String>,pub devices:BTreeMap<String,String>}
#[derive(Debug,Clone,Serialize)]
pub struct ResolvedCommandAuthor{
    pub kind:&'static str,pub principal_actor_id:String,pub actual_signer_id:String,
    #[serde(skip_serializing_if="Option::is_none")]pub account_id:Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]pub root_generation:Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]pub device_id:Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]pub root_certificate_hash:Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]pub device_certificate_hash:Option<String>,
}
#[derive(Debug,Clone)]
pub struct VerifiedAccountRoot{certificate:RootCertificate,recovery_public_key:String,hash:String}
impl VerifiedAccountRoot{
    pub fn certificate(&self)->&RootCertificate{&self.certificate}
    pub fn recovery_public_key(&self)->&str{&self.recovery_public_key}
    pub fn hash(&self)->&str{&self.hash}
}
#[derive(Debug,Clone)]
pub struct VerifiedDevice{certificate:DeviceCertificate,hash:String}
impl VerifiedDevice{pub fn certificate(&self)->&DeviceCertificate{&self.certificate}pub fn hash(&self)->&str{&self.hash}}
#[derive(Debug,Clone)]
pub struct VerifiedAccountCommand{command:WireValue,author:ResolvedCommandAuthor}
impl VerifiedAccountCommand{pub fn command(&self)->&WireValue{&self.command}pub fn author(&self)->&ResolvedCommandAuthor{&self.author}}

fn text(value:&WireValue,key:&str)->Result<String>{value.get(key).and_then(WireValue::as_string).ok_or(HumanAuthorError::Invalid)}
fn token(value:&str)->bool{decode_base64url(value).is_ok_and(|b|b.len()==32)}
fn digest(value:&str)->bool{value.len()==64&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn audience(value:&str)->bool{!value.is_empty()&&value.encode_utf16().count()<=200&&!value.chars().any(|c|c<='\u{1f}'||c=='\u{7f}')}
fn json<T:serde::de::DeserializeOwned>(value:&WireValue)->Result<T>{
    let wire=canonical_wire_value(value,Path::SecureArtifact).map_err(|_|HumanAuthorError::Invalid)?;
    serde_json::from_str(&wire).map_err(|_|HumanAuthorError::Invalid)
}
fn signed(wire:&str,typ:&str,max:usize)->Result<(String,WireValue)>{
    if wire.len()>max{return Err(HumanAuthorError::Invalid)}
    let parts:Vec<_>=wire.split('.').collect();if parts.len()!=3{return Err(HumanAuthorError::Invalid)}
    let header=decode_base64url(parts[0]).map_err(|_|HumanAuthorError::Invalid)?;
    let payload=decode_base64url(parts[1]).map_err(|_|HumanAuthorError::Invalid)?;
    let h=parse_wire_json_bounded(&header,3,256).map_err(|_|HumanAuthorError::Invalid)?;
    if h.object_len()!=Some(3)||text(&h,"alg")?!="EdDSA"||text(&h,"typ")?!=typ{return Err(HumanAuthorError::Invalid)}
    let kid=text(&h,"kid")?;let key=verifying_key(&kid).map_err(|_|HumanAuthorError::Invalid)?;
    let sig:[u8;64]=decode_base64url(parts[2]).map_err(|_|HumanAuthorError::Invalid)?.try_into().map_err(|_|HumanAuthorError::Invalid)?;
    key.verify(format!("{}.{}",parts[0],parts[1]).as_bytes(),&Signature::from_bytes(&sig)).map_err(|_|HumanAuthorError::Invalid)?;
    let value=parse_wire_json_bounded(&payload,if max==4096{8}else{40},if max==4096{2048}else{180000}).map_err(|_|HumanAuthorError::Invalid)?;
    Ok((kid,value))
}
fn root_inner(wire:&str,expected_audience:&str,peer:&str,generation:u64,account:Option<&str>)->Result<VerifiedAccountRoot>{
    let (kid,value)=signed(wire,ROOT_TYPE,4096)?;let p:RootCertificate=json(&value)?;
    let key=verifying_key(&kid).map_err(|_|HumanAuthorError::Invalid)?;
    if p.v!=1||p.domain!="peerwork.account-root.v1"||!audience(&p.audience)||p.audience!=expected_audience
        ||!token(&p.account_id)||!token(&p.peer_id)||p.peer_id!=peer||actor_id(&key.to_bytes())!=peer
        ||p.root_generation==0||p.root_generation>MAX_SAFE||p.root_generation!=generation
        ||account.is_some_and(|a|a!=p.account_id)||p.issued_at>MAX_SAFE||!token(&p.operational_signing_key)
        ||encryption_key_id(&p.recipient_public_key).map_err(|_|HumanAuthorError::Invalid)?!=p.recipient_key_id{
        return Err(HumanAuthorError::Invalid)
    }
    Ok(VerifiedAccountRoot{certificate:p,recovery_public_key:kid,hash:sha256_hex(wire.as_bytes())})
}
pub fn verify_root(wire:&str,expected:&AccountBinding)->Result<VerifiedAccountRoot>{
    root_inner(wire,&expected.audience,&expected.peer_id,expected.root_generation,Some(&expected.account_id))
}
pub fn verify_device(wire:&str,root:&VerifiedAccountRoot)->Result<VerifiedDevice>{
    let (kid,value)=signed(wire,DEVICE_TYPE,4096)?;let p:DeviceCertificate=json(&value)?;let r=&root.certificate;
    if p.v!=1||p.domain!="peerwork.human-device.v1"||kid!=r.operational_signing_key||p.audience!=r.audience
        ||p.account_id!=r.account_id||p.peer_id!=r.peer_id||p.root_generation!=r.root_generation
        ||p.root_certificate_hash!=root.hash||!token(&p.device_id)||!token(&p.device_signing_key)
        ||p.issued_at<r.issued_at||p.issued_at>MAX_SAFE
        ||encryption_key_id(&p.device_recipient_public_key).map_err(|_|HumanAuthorError::Invalid)?!=p.device_recipient_key_id{
        return Err(HumanAuthorError::Invalid)
    }
    Ok(VerifiedDevice{certificate:p,hash:sha256_hex(wire.as_bytes())})
}
/// No network or implicit directory. Resolve two selected hashes at fixed depth;
/// execution must separately check current account/device state and authority.
pub fn verify_account_command(wire:&str,expected_audience:&[u16],proofs:Option<&AuthorProofContext>)->Result<VerifiedAccountCommand>{
    let expected=String::from_utf16(expected_audience).map_err(|_|HumanAuthorError::Author)?;
    if !audience(&expected){return Err(HumanAuthorError::Author)}
    let (kid,command)=signed(wire,COMMAND_TYPE,250000)?;let key=verifying_key(&kid).map_err(|_|HumanAuthorError::Author)?;
    let actual=actor_id(&key.to_bytes());let principal=text(&command,"actor_id")?;
    if command.get("audience").and_then(WireValue::as_utf16)!=Some(expected_audience){return Err(HumanAuthorError::Author)}
    let direct=ResolvedCommandAuthor{kind:"direct-key-v1",principal_actor_id:actual.clone(),actual_signer_id:actual.clone(),account_id:None,root_generation:None,device_id:None,root_certificate_hash:None,device_certificate_hash:None};
    let Some(raw_author)=command.get("author")else{
        if principal!=actual{return Err(HumanAuthorError::Author)}
        validate_command_schema(&command,expected_audience,&actual).map_err(|_|HumanAuthorError::Author)?;
        return Ok(VerifiedAccountCommand{command,author:direct})
    };
    let a:AuthorReference=json(raw_author)?;
    if a.kind!="human-device-v1"||a.root_generation==0||a.root_generation>MAX_SAFE||!digest(&a.root_certificate_hash)||!digest(&a.device_certificate_hash)||!token(&a.device_id){return Err(HumanAuthorError::Author)}
    let proofs=proofs.ok_or(HumanAuthorError::Missing)?;
    if proofs.format!="peerwork.human-author-proofs.v1"||proofs.roots.len()>32||proofs.devices.len()>32{return Err(HumanAuthorError::Invalid)}
    let root_wire=proofs.roots.get(&a.root_certificate_hash).ok_or(HumanAuthorError::Missing)?;let device_wire=proofs.devices.get(&a.device_certificate_hash).ok_or(HumanAuthorError::Missing)?;
    if [root_wire,device_wire].iter().any(|wire|wire.is_empty()||wire.len()>4096||!wire.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))){return Err(HumanAuthorError::Invalid)}
    if sha256_hex(root_wire.as_bytes())!=a.root_certificate_hash||sha256_hex(device_wire.as_bytes())!=a.device_certificate_hash{return Err(HumanAuthorError::Invalid)}
    let root=root_inner(root_wire,&expected,&principal,a.root_generation,None)?;let device=verify_device(device_wire,&root)?;
    if device.certificate.device_id!=a.device_id||device.certificate.device_signing_key!=kid||device.hash!=a.device_certificate_hash{return Err(HumanAuthorError::Author)}
    // Reuse the ordinary structural schema without altering signed bytes or
    // weakening its native direct-key verification entry point.
    let WireValue::Object(mut fields)=command.clone()else{return Err(HumanAuthorError::Author)};
    fields.retain(|(name,_)|!name.iter().copied().eq("author".encode_utf16()));
    validate_command_schema(&WireValue::Object(fields),expected_audience,&principal).map_err(|_|HumanAuthorError::Author)?;
    let author=ResolvedCommandAuthor{kind:"human-device-v1",principal_actor_id:principal,actual_signer_id:actual,account_id:Some(root.certificate.account_id),root_generation:Some(a.root_generation),device_id:Some(a.device_id),root_certificate_hash:Some(a.root_certificate_hash),device_certificate_hash:Some(a.device_certificate_hash)};
    Ok(VerifiedAccountCommand{command,author})
}

#[cfg(test)]mod tests{
    use super::*;
    use crate::crypto::{base64url,sha256};
    use ed25519_dalek::{Signer,SigningKey};
    use serde_json::{Value,json};
    fn fixture()->Value{serde_json::from_str(include_str!("../../../tests/fixtures/human-author-v1.json")).unwrap()}
    fn proofs(v:&Value)->AuthorProofContext{serde_json::from_value(v["proofs"].clone()).unwrap()}
    fn sign(typ:&str,payload:&Value,key:&SigningKey)->String{
        let h=base64url(serde_json::to_vec(&json!({"alg":"EdDSA","typ":typ,"kid":base64url(&key.verifying_key().to_bytes())})).unwrap().as_slice());
        let p=base64url(serde_json::to_vec(payload).unwrap().as_slice());let input=format!("{h}.{p}");
        format!("{input}.{}",base64url(&key.sign(input.as_bytes()).to_bytes()))
    }
    #[test]fn independent_typescript_node_vector_and_both_generations(){
        let v=fixture();let ctx=proofs(&v);let aud=v["audience"].as_str().unwrap().encode_utf16().collect::<Vec<_>>();
        for (name,signer,generation)in[("human1","first",1),("human2","second",2)]{
            let result=verify_account_command(v["commands"][name].as_str().unwrap(),&aud,Some(&ctx)).unwrap();
            assert_eq!(result.author().principal_actor_id,v["peer_id"]);assert_eq!(result.author().actual_signer_id,v["expected_signers"][signer]);assert_eq!(result.author().root_generation,Some(generation));
        }
        let direct=verify_account_command(v["commands"]["direct"].as_str().unwrap(),&aud,None).unwrap();assert_eq!(direct.author().kind,"direct-key-v1");
        assert!(crate::prepared_command::verify_structure_author_intent(v["commands"]["human1"].as_str().unwrap(),&aud).is_err(),"the old direct-key boundary cannot accept Human aliases without proofs");
    }
    #[test]fn missing_and_substituted_proofs_never_use_a_directory_fallback(){
        let v=fixture();let mut ctx=proofs(&v);let aud=v["audience"].as_str().unwrap().encode_utf16().collect::<Vec<_>>();let wire=v["commands"]["human1"].as_str().unwrap();
        assert!(verify_account_command(wire,&aud,None).is_err());ctx.roots.clear();assert!(verify_account_command(wire,&aud,Some(&ctx)).is_err());
        let mut ctx=proofs(&v);ctx.roots.insert(v["first"]["root_hash"].as_str().unwrap().into(),v["second"]["root_wire"].as_str().unwrap().into());assert!(verify_account_command(wire,&aud,Some(&ctx)).is_err());
        assert!(verify_account_command(wire,&"another-service".encode_utf16().collect::<Vec<_>>(),Some(&proofs(&v))).is_err());
    }
    #[test]fn valid_signatures_still_require_the_exact_account_generation_recipient_and_device(){
        let v=fixture();let ctx=proofs(&v);let b=AccountBinding{audience:v["audience"].as_str().unwrap().into(),account_id:v["account_id"].as_str().unwrap().into(),peer_id:v["peer_id"].as_str().unwrap().into(),root_generation:1};
        let root=verify_root(v["first"]["root_wire"].as_str().unwrap(),&b).unwrap();
        for (field,value)in[("account_id",json!(base64url(&[21;32]))),("root_generation",json!(2)),("root_certificate_hash",json!("0".repeat(64))),("device_id",json!("short")),("device_recipient_key_id",json!(base64url(&[22;32])))]{
            let mut device=v["first"]["device"].clone();device[field]=value;let wire=sign(DEVICE_TYPE,&device,&SigningKey::from_bytes(&[2;32]));assert!(verify_device(&wire,&root).is_err(),"{field}");
        }
        let wire=v["commands"]["human1"].as_str().unwrap();let (_,parsed)=signed(wire,COMMAND_TYPE,250000).unwrap();let mut command:Value=json(&parsed).unwrap();
        command["author"]["device_id"]=json!(base64url(&[23;32]));let substituted=sign(COMMAND_TYPE,&command,&SigningKey::from_bytes(&[6;32]));assert!(verify_account_command(&substituted,&b.audience.encode_utf16().collect::<Vec<_>>(),Some(&ctx)).is_err());
        assert_eq!(root.hash(),sha256_hex(v["first"]["root_wire"].as_str().unwrap().as_bytes()));assert_eq!(root.recovery_public_key(),v["recovery_public_key"]);
        assert_ne!(sha256(v["first"]["root_wire"].as_str().unwrap().as_bytes()),[0;32]);
    }
    #[test]fn bounded_context_and_selected_proof_wires(){
        let v=fixture();let mut ctx=proofs(&v);let aud=v["audience"].as_str().unwrap().encode_utf16().collect::<Vec<_>>();let wire=v["commands"]["human1"].as_str().unwrap();
        for n in 0..33{if ctx.roots.len()>=33{break}ctx.roots.insert(format!("{n:064x}"),v["first"]["root_wire"].as_str().unwrap().into());}
        assert!(verify_account_command(wire,&aud,Some(&ctx)).is_err());
        let mut ctx=proofs(&v);ctx.roots.insert(v["first"]["root_hash"].as_str().unwrap().into(),"a".repeat(1000000));assert!(verify_account_command(wire,&aud,Some(&ctx)).is_err());
    }
    #[test]fn actual_chromium_generated_certificates_and_command_interoperate(){
        let v:Value=serde_json::from_str(include_str!("../../../tests/fixtures/human-author-chromium-v1.json")).unwrap();let ctx=proofs(&v);
        let aud=v["audience"].as_str().unwrap().encode_utf16().collect::<Vec<_>>();
        let result=verify_account_command(v["command"].as_str().unwrap(),&aud,Some(&ctx)).unwrap();
        assert_eq!(serde_json::to_value(result.author()).unwrap(),v["expected_author"]);
        assert_eq!(result.command().get("author").unwrap().get("device_id").unwrap().as_string(),result.author().device_id);
    }
}
