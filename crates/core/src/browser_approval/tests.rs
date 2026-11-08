use super::*;
use crate::{secure_recipient::SecretRecipient, crypto::verify_canonical, e2ee::{KeyBox,hpke_open_wire}, wire_json::canonical_wire_value, replayed_secure_journal::{replay_secure_journal_exact,JournalReplayInput}, prepared_secure_author::author_private_bootstrap, prepared_secure_request::SecureCommitRequestPins};
fn request(workspace:&str,recipient:&SecretRecipient,device:&SigningKey,writes:Value)->Value{
    let key=key_id(&device.verifying_key().to_bytes());
    json!({"request_id":base64url(&[20;32]),"state":"PENDING","workspace_id":workspace,"device_key":key,"device_key_sha256":sha256_hex(&device.verifying_key().to_bytes()),"origin":"https://browser.invalid","browser_origin":"https://browser.invalid","control_origin":"https://control.invalid","audience":"test-audience","verifier_challenge":base64url(&[21;32]),"requested_scope":{"read":true,"writes":writes,"session_expires_at":10000},"request_expires_at":5000,"session_expires_at":10000,"created":100,"secure_certificate":recipient.certify(device,100).unwrap()})
}
fn reference(request:&Value)->String{let b=binding(request).unwrap();format!("peerwork-browser-approval:v1:{}:{}:{}",b["workspace_id"].as_str().unwrap(),b["request_id"].as_str().unwrap(),sha256_hex(canon(&b).unwrap().as_bytes()))}
#[test]
fn copied_reference_certificate_time_and_write_consent_are_exact(){
    let recipient=SecretRecipient::generate().unwrap();let device=SigningKey::from_bytes(&[19;32]);let workspace=base64url(&[18;32]);
    let row=request(&workspace,&recipient,&device,json!([]));let reference=parse_browser_approval_reference(&reference(&row)).unwrap();
    assert!(validate_request(&row,&reference,"https://control.invalid","test-audience",200,false).is_ok());
    let mut changed=row.clone();changed["device_key_sha256"]=json!("0".repeat(64));assert_eq!(validate_request(&changed,&reference,"https://control.invalid","test-audience",200,false).unwrap_err(),BrowserApprovalError::Binding);
    assert_eq!(validate_request(&row,&reference,"https://other.invalid","test-audience",200,false).unwrap_err(),BrowserApprovalError::Binding);
    assert_eq!(validate_request(&row,&reference,"https://control.invalid","test-audience",6000,false).unwrap_err(),BrowserApprovalError::Expired);
    let writing=request(&workspace,&recipient,&device,json!([{"instance_id":base64url(&[22;32]),"actions":["wiki.create"]}]));let r=parse_browser_approval_reference(&super::tests::reference(&writing)).unwrap();
    assert_eq!(validate_request(&writing,&r,"https://control.invalid","test-audience",200,false).unwrap_err(),BrowserApprovalError::WriteConsent);
    let mut invalid=row.clone();invalid["secure_certificate"]["signature"]=json!(base64url(&[0;64]));let r=parse_browser_approval_reference(&super::tests::reference(&invalid)).unwrap();assert_eq!(validate_request(&invalid,&r,"https://control.invalid","test-audience",200,false).unwrap_err(),BrowserApprovalError::Certificate);
}
#[test]
fn delegation_never_adds_actions_or_expired_authority(){
    let instance=base64url(&[5;32]);let member=json!({"scopes":[{"instance_id":instance,"actions":["wiki.create"],"protocol_roles":["EDITOR"],"capabilities":["EDIT"],"expires_at":300}]});
    let requested=json!([{"instance_id":instance,"actions":["wiki.create"]}]);let scopes=delegated_scopes(&member,requested.as_array().unwrap(),200).unwrap();assert_eq!(scopes[0]["actions"],requested[0]["actions"]);assert_eq!(scopes[0]["protocol_roles"],json!(["EDITOR"]));
    assert!(delegated_scopes(&member,requested.as_array().unwrap(),300).is_err());
    let denied=json!([{"instance_id":instance,"actions":["wiki.delete"]}]);assert!(delegated_scopes(&member,denied.as_array().unwrap(),200).is_err());
}
#[test]
fn private_grant_roundtrips_from_real_native_signed_replay(){
    let signer=SigningKey::from_bytes(&[7;32]);let actor=actor_id(&signer.verifying_key().to_bytes());let key=key_id(&signer.verifying_key().to_bytes());let workspace=base64url(&[8;32]);
    let owner_recipient=SecretRecipient::generate().unwrap();let certificate=owner_recipient.certify(&signer,100).unwrap();
    let policy=sign("peerwork.secure.policy.v1",json!({"v":1,"workspace_id":workspace,"owner_id":actor,"signing_key":key,"version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PRIVATE","epoch":1,"issued_at":100,"members":[{"actor_id":actor,"certificate":certificate,"role":"OWNER","scopes":[]}]}),&signer).unwrap();
    let policy_wire=canon(&policy).unwrap();let policy_hash=sha256_hex(policy_wire.as_bytes());let ring=SecretKeyring::new_private(&workspace,1).unwrap();
    let context=json!({"v":1,"workspace_id":workspace,"sequence":1,"previous":null,"policy_hash":policy_hash,"epoch":1,"actor_id":actor,"signing_key":key,"command_id":base64url(&[9;32]),"action_id":"secure.bootstrap","instance_id":null,"issued_at":100,"delegation":null});
    let operation=json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":[{"kind":"workspaces","id":workspace,"revision":1,"provenance":"AUTHOR_SIGNED","value":{"id":workspace,"name":"Approval test","visibility":"PRIVATE","owner":actor,"created":100}}]});
    let pins=SecureCommitRequestPins{actor_id:&actor,signing_key:&key,workspace_id:&workspace,policy_hash:&policy_hash,sequence:1,previous:None,epoch:1,mode:"PRIVATE",version:1,protocol_format_ceiling:None};
    let authored=author_private_bootstrap(policy_wire.as_bytes(),canon(&context).unwrap().as_bytes(),canon(&operation).unwrap().as_bytes(),ring.key_at(1).unwrap(),&signer,&pins).unwrap();
    let packet:Value=serde_json::from_slice(authored.request_wire()).unwrap();let commit=canon(&packet["commit"]).unwrap();let head=sha256_hex(commit.as_bytes());let checkpoint=json!({"v":1,"workspace_id":workspace,"owner_id":actor,"owner_key":key,"sequence":1,"head":head,"policy_hash":policy_hash});let checkpoint=canon(&checkpoint).unwrap();let ring_wire=ring.canonical_wire().unwrap();
    let replay=replay_secure_journal_exact(JournalReplayInput{policy_wires:&[policy_wire.as_bytes()],commit_wires:&[commit.as_bytes()],checkpoint_wire:checkpoint.as_bytes(),workspace_id:&workspace,owner_actor_id:&actor,owner_signing_key:&key,final_sequence:1,final_head:Some(&head),final_policy_hash:&policy_hash,keyring_wire:Some(&ring_wire)}).unwrap();
    let device=SigningKey::from_bytes(&[19;32]);let recipient=SecretRecipient::generate().unwrap();let row=request(&workspace,&recipient,&device,json!([]));let reference=reference(&row);let wire=canon(&row).unwrap();
    let prepared=prepare_private_browser_approval(BrowserApprovalInput{request_wire:wire.as_bytes(),reference:&reference,control_origin:"https://control.invalid",audience:"test-audience",replay:&replay,policy_wire:policy_wire.as_bytes(),keyring:&ring,signing_key:&signer,now:200,approve_writes:false}).unwrap();
    let body:Value=serde_json::from_str(&prepared.body_canonical_json).unwrap();assert_eq!(body["code_hash"],sha256_hex(&decode_base64url(&prepared.code).unwrap()));
    for (field,domain) in [("secure_delegation","peerwork.secure.device-delegation.v1"),("secure_key_grant","peerwork.secure.key-grant.v1")]{assert!(verify_canonical(domain,&body[field]["payload"],body[field]["signature"].as_str().unwrap(),&key).unwrap());}
    assert_eq!(body["secure_delegation"]["payload"]["device"],row["secure_certificate"]);assert_eq!(body["secure_delegation"]["payload"]["scope"],json!([]));
    let mut context=body["secure_key_grant"]["payload"].clone();let sealed:KeyBox=serde_json::from_value(context.as_object_mut().unwrap().remove("box").unwrap()).unwrap();
    let opened=hpke_open_wire(recipient.private_bytes(),&sealed,canon(&context).unwrap().as_bytes()).unwrap();assert_eq!(canonical_wire_value(&opened,Path::SecureArtifact).unwrap().as_bytes(),ring_wire.as_slice());
    context["workspace_id"]=json!(base64url(&[99;32]));assert!(hpke_open_wire(recipient.private_bytes(),&sealed,canon(&context).unwrap().as_bytes()).is_err());
}
