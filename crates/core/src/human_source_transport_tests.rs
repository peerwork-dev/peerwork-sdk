//! Independent synthetic service HTTP/SSE wires. The producer uses the real
//! account/Space handlers and PostgreSQL, not these Rust verification functions.
use crate::{
    canonical::Path,
    communication::{self,FramePins,MailboxPins,FrameVerificationError},
    crypto::{base64url,decode_base64url,sha256_hex},
    human_author::AuthorProofContext,
    prepared_command::{verify_prepared_command_wire,verify_structure_author_intent_with_proofs,CommandPins,VerifiedPreparedCommand},
    receipt_wire::{verify_http_response_for_prepared,VerifiedCommandResponse},
    structure_content::{authored_structure_content,open_structure_content,open_content_with_aad},
    wire_json::{canonical_wire_value,parse_wire_json_bounded,WireValue},
};
use ed25519_dalek::{Signer,SigningKey};
use serde_json::{Value,json};

fn fixture()->Value{serde_json::from_str(include_str!("../../../tests/fixtures/human-source-transport-v1.json")).unwrap()}
fn wire(v:&Value)->WireValue{parse_wire_json_bounded(&serde_json::to_vec(v).unwrap(),40,2*1024*1024).unwrap()}
fn audience(v:&Value)->Vec<u16>{v["audience"].as_str().unwrap().encode_utf16().collect()}
fn prepared(v:&Value,name:&str)->VerifiedPreparedCommand{
    let request=&v["cases"][name]["request"];
    verify_prepared_command_wire(request["jws"].as_str().unwrap(),&serde_json::to_vec(request).unwrap(),&CommandPins{local_key_id:v["native_key"].as_str().unwrap(),audience_utf16:&audience(v)}).unwrap()
}
fn verify(v:&Value,name:&str,response:&Value)->Result<VerifiedCommandResponse,crate::receipt_wire::VerifyWireReceiptError>{
    verify_http_response_for_prepared(&serde_json::to_vec(response).unwrap(),&prepared(v,name),v["service_key"].as_str().unwrap())
}
fn sign(value:&Value,typ:&str)->String{
    let key=SigningKey::from_bytes(&[7;32]);
    let h=base64url(serde_json::to_vec(&json!({"alg":"EdDSA","typ":typ,"kid":base64url(key.verifying_key().as_bytes())})).unwrap().as_slice());
    let input=format!("{h}.{}",base64url(&serde_json::to_vec(value).unwrap()));format!("{input}.{}",base64url(&key.sign(input.as_bytes()).to_bytes()))
}
fn payload(jws:&str)->Value{serde_json::from_slice(&decode_base64url(jws.split('.').nth(1).unwrap()).unwrap()).unwrap()}
fn resign_response(response:&mut Value){
    let mut receipt=payload(response["receipt"].as_str().unwrap());receipt["result_digest"]=json!(sha256_hex(canonical_wire_value(&wire(&response["result"]),Path::STRUCTURED).unwrap().as_bytes()));response["receipt"]=json!(sign(&receipt,"peerwork.kernel-receipt.v1+jws"));
}
fn mailbox(v:&Value)->MailboxPins{
    let p=&v["frame"]["pins"]["mailbox"];
    MailboxPins{workspace_id:p["workspace_id"].as_str().unwrap().into(),mailbox_id:p["mailbox_id"].as_str().unwrap().into(),membership_id:p["membership_id"].as_str().unwrap().into(),receiver_id:p["receiver_id"].as_str().unwrap().into(),epoch:p["epoch"].as_u64().unwrap(),destination_digest:p["destination_digest"].as_str().unwrap().into(),binding_version:p["binding_version"].as_u64().unwrap(),after_sequence:p["after_sequence"].as_u64().unwrap(),after_control_sequence:p["after_control_sequence"].as_u64()}
}
fn frame(v:&Value,value:&Value)->Result<communication::VerifiedMailboxPage,FrameVerificationError>{
    let audience=audience(v);let mailbox=mailbox(v);let p=&v["frame"]["pins"];
    communication::verify_mailbox_frame_detailed(&serde_json::to_vec(value).unwrap(),&FramePins{audience:&audience,actor_id:p["actor_id"].as_str().unwrap(),stream_id:p["stream_id"].as_str().unwrap(),mailbox:&mailbox,service_key:v["service_key"].as_str().unwrap(),server_time_floor:p["server_time_floor"].as_u64().unwrap(),expires_at:p["expires_at"].as_u64().unwrap()})
}
fn resign_frame(value:&mut Value){
    let mut proof=payload(value["proof"].as_str().unwrap());
    for(name,digest)in[("items","items_digest"),("controls","controls_digest"),("author_proofs","author_proofs_digest")]{
        if let Some(data)=value.get(name){proof[digest]=json!(sha256_hex(canonical_wire_value(&wire(data),Path::STRUCTURED).unwrap().as_bytes()));}else{proof.as_object_mut().unwrap().remove(digest);}
    }
    value["proof"]=json!(sign(&proof,"peerwork.mailbox-frame.v1+jws"));
}

#[test]
fn independent_http_matrix_verifies_human_records_bundles_mail_pins_and_observed_events(){
    let v=fixture();assert_ne!(v["human_actor"],v["native_actor"]);
    for(name,case)in v["cases"].as_object().unwrap(){
        let result=verify(&v,name,&case["response"]).unwrap_or_else(|error|panic!("{name}: {error}"));assert!(result.author_proofs().is_some(),"{name}");
        if name=="protocol"{let result=wire(&case["response"]["result"]);let command=payload(case["request"]["jws"].as_str().unwrap());crate::protocol_bundle::verify_result(&result,&wire(&command),&audience(&v)).unwrap();}
    }
}

#[test]
fn human_record_and_messages_keep_stable_actor_aad_and_open_without_history_or_a_directory(){
    let v=fixture();let audience=audience(&v);let key:[u8;32]=decode_base64url(v["synthetic_body_key"].as_str().unwrap()).unwrap().try_into().unwrap();
    let record=&v["cases"]["record"]["response"]["result"];let context=AuthorProofContext::from_json_container(record).unwrap().unwrap();let author=verify_structure_author_intent_with_proofs(record["author_intent"].as_str().unwrap(),&audience,Some(&context)).unwrap();assert_eq!(author.actor_id(),v["human_actor"]);assert_ne!(author.author().actual_signer_id,author.actor_id());
    let (mut aad,sealed)=authored_structure_content(&author,0).unwrap();assert_eq!(open_structure_content(&key,&sealed,&aad).unwrap().as_slice(),b"Synthetic Human record body");aad.actor_id=author.author().actual_signer_id.clone();assert!(open_structure_content(&key,&sealed,&aad).is_err());
    for(name,text)in[("message","Synthetic Human direct message"),("conversation","Synthetic Human shared message")]{
        let result=&v["cases"][name]["response"]["result"];let context=AuthorProofContext::from_json_container(result).unwrap().unwrap();let message=if name=="message"{&result["message"]}else{&result["messages"][0]};let author=verify_structure_author_intent_with_proofs(message["author_intent"].as_str().unwrap(),&audience,Some(&context)).unwrap();
        let (context,communication::MessageContent::WorkspaceE2ee{body})=communication::authored_native_message_content(&author).unwrap()else{panic!("expected ciphertext")};
        let aad=match context{communication::NativeMessageContext::Directed(v)=>v.canonical_aad().unwrap(),communication::NativeMessageContext::Conversation(v)=>v.canonical_aad().unwrap()};assert_eq!(open_content_with_aad(&key,&body,&aad).unwrap().as_slice(),text.as_bytes());
    }
}

#[test]
fn valid_service_signature_cannot_replace_missing_certificate_proofs_with_business_metadata(){
    let v=fixture();let original=&v["cases"]["record"]["response"];
    let mut modified=original.clone();let proofs=modified["result"].as_object_mut().unwrap().remove("author_proofs").unwrap();modified["result"]["structure"]["author_proofs"]=proofs;resign_response(&mut modified);assert!(verify(&v,"record",&modified).is_err());
    let mut modified=original.clone();let root=modified["result"]["author_proofs"]["roots"].as_object().unwrap().keys().next().unwrap().clone();modified["result"]["author_proofs"]["roots"][root]=json!("substituted");resign_response(&mut modified);assert!(verify(&v,"record",&modified).is_err());
    let mut modified=original.clone();modified["result"]["sealed_content"]["nonce"]=json!(base64url(&[0;12]));resign_response(&mut modified);assert!(verify(&v,"record",&modified).is_err(),"a valid service receipt cannot detach ciphertext from the Human signature");
}

#[test]
fn real_sse_frame_carries_bounded_proofs_and_preserves_original_author_for_restart(){
    let v=fixture();let value=&v["frame"]["envelope"];let verified=frame(&v,value).unwrap();assert_eq!(verified.items().len(),1);assert_eq!(verified.author_proofs().unwrap().devices.len(),1);let message=verified.items()[0].message().unwrap();assert_eq!(message.author().actor_id(),v["human_actor"]);
    let restored:Value=serde_json::from_str(verified.frame_wire().unwrap()).unwrap();assert_eq!(frame(&v,&restored).unwrap().items()[0].message().unwrap().author().intent_digest(),message.author().intent_digest());
    let mut modified=value.clone();modified["items"][0]["message"]["sender_actor"]=v["native_actor"].clone();resign_frame(&mut modified);assert_eq!(frame(&v,&modified).unwrap_err(),FrameVerificationError::ItemEvidence);
    let mut modified=value.clone();modified.as_object_mut().unwrap().remove("author_proofs");resign_frame(&mut modified);assert!(frame(&v,&modified).is_err(),"a signed frame with missing Human proof is not an empty inbox");
}

#[test]
fn proof_section_budget_and_both_wire_bridges_reject_malformed_maps(){
    let v=fixture();let original=&v["cases"]["record"]["response"]["result"];
    let a=AuthorProofContext::from_container(&wire(original)).unwrap().unwrap();let b=AuthorProofContext::from_json_container(original).unwrap().unwrap();assert_eq!(serde_json::to_value(&a).unwrap(),serde_json::to_value(&b).unwrap());
    let command=payload(original["author_intent"].as_str().unwrap());let selected=a.select_for_command(&wire(&command)).unwrap().unwrap();assert_eq!(selected.roots.len(),1);assert_eq!(selected.devices.len(),1);verify_structure_author_intent_with_proofs(original["author_intent"].as_str().unwrap(),&audience(&v),Some(&selected)).unwrap();let native=payload(v["cases"]["record"]["request"]["jws"].as_str().unwrap());assert!(a.select_for_command(&wire(&native)).unwrap().is_none());
    let mut oversized=original.clone();for n in 0..33{let wire=format!("unused{n}");oversized["author_proofs"]["roots"][sha256_hex(wire.as_bytes())]=json!(wire);}assert!(AuthorProofContext::from_container(&wire(&oversized)).is_err());assert!(AuthorProofContext::from_json_container(&oversized).is_err());
    let mut extra=original.clone();extra["author_proofs"]["directory_url"]=json!("https://invalid.example");assert!(AuthorProofContext::from_container(&wire(&extra)).is_err());assert!(AuthorProofContext::from_json_container(&extra).is_err());
}

#[test]
fn a_presence_control_signature_is_event_evidence_and_cannot_be_used_as_business_authorship(){
    let v=fixture();let result=&v["cases"]["events"]["response"]["result"];
    assert!(result["sources"].as_object().unwrap().values().any(|source|source["assurance"]=="SERVICE_ATTESTED_EVENT"&&source["event"]["kind"]=="communication.member.presence.changed"));
    let mut command=payload(v["cases"]["events"]["request"]["jws"].as_str().unwrap());command["action_id"]=json!("structure.mailbox.pulse");command["actor_id"]=json!(crate::crypto::actor_id(SigningKey::from_bytes(&[7;32]).verifying_key().as_bytes()));
    let jws=sign(&command,"peerwork.kernel-command.v1+jws");assert!(verify_structure_author_intent_with_proofs(&jws,&audience(&v),None).is_err());crate::prepared_command::verify_event_source_intent_with_proofs(&jws,&audience(&v),None).unwrap();
    let mut modified=v["cases"]["events"]["response"].clone();let row=modified["result"]["events"].as_array_mut().unwrap().iter_mut().find(|row|row["kind"]=="communication.member.presence.changed").unwrap();row["summary"]["action_id"]=json!("structure.action");resign_response(&mut modified);assert!(verify(&v,"events",&modified).is_err(),"an observed presence event cannot attest a business action");
    let mut modified=v["cases"]["events"]["response"].clone();let source=modified["result"]["sources"].as_object_mut().unwrap().values_mut().find(|source|source["event"]["kind"]=="communication.member.presence.changed").unwrap();source["event"]["source"]["origin"]=json!("AUTHOR_COMMAND");let mut receipt=payload(source["event_receipt"].as_str().unwrap());receipt["event_digest"]=json!(sha256_hex(canonical_wire_value(&wire(&source["event"]),Path::STRUCTURED).unwrap().as_bytes()));source["event_receipt"]=json!(sign(&receipt,"peerwork.workspace-event.v1+jws"));resign_response(&mut modified);assert!(verify(&v,"events",&modified).is_err(),"even a re-signed service observation is not immutable author intent");
}
