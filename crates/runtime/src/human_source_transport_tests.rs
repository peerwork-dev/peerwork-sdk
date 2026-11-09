//! Native custody and selected-body opening of independently produced Human
//! HTTP/SSE sources. No directory query, authority refresh or history replay.
use crate::{kernel_access::KernelAccess,kernel_identity::KernelIdentity,kernel_intents::{KernelIntentJournal,StructureContentKeys,KernelPath},participant_inbox::InboxStore,transport::TransportConfig};
use peerwork_core::{communication::{FramePins,MailboxPins,verify_mailbox_frame_detailed},crypto::decode_base64url,discovery::parse_discovery_wire};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

const ORIGIN:&str="https://interop.example/";
fn fixture()->Value{serde_json::from_str(include_str!("../../../tests/fixtures/human-source-transport-v1.json")).unwrap()}
fn identity(root:&std::path::Path)->KernelIdentity{
    let seed=root.join("synthetic.seed");std::fs::write(&seed,[17;32]).unwrap();
    #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&seed,std::fs::Permissions::from_mode(0o600)).unwrap();}
    KernelIdentity::import_seed_file(&root.join("identity"),&seed).unwrap()
}
fn access(root:&std::path::Path)->KernelAccess{KernelAccess::new(ORIGIN,root.join("journal"),root.join("identity"),&[],false)}
fn keys(root:&std::path::Path,v:&Value,id:&KernelIdentity){
    let path=access(root).content_key_path_for_origin(ORIGIN);
    let mut keys=StructureContentKeys::open(&path,TransportConfig::new(ORIGIN)).unwrap();
    let body=&v["cases"]["record"]["response"]["result"]["sealed_content"];
    let secret:[u8;32]=decode_base64url(v["synthetic_body_key"].as_str().unwrap()).unwrap().try_into().unwrap();
    let workspace=v["frame"]["pins"]["mailbox"]["workspace_id"].as_str().unwrap();
    keys.retain_current(id.key_id(),workspace,&secret,body["key_id"].as_str().unwrap(),None).unwrap();
}
fn command_id(case:&Value)->String{
    let encoded=case["request"]["jws"].as_str().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice::<Value>(&decode_base64url(encoded).unwrap()).unwrap()["command_id"].as_str().unwrap().into()
}

#[test]
fn original_native_journal_reopens_human_http_sources_and_decrypts_selected_bodies(){
    let v=fixture();let dir=crate::test_support::protected_test_dir();let id=identity(dir.path());assert_eq!(id.key_id(),v["native_key"]);
    let discovery=parse_discovery_wire(&serde_json::to_vec(&v["discovery"]).unwrap(),262144).unwrap();
    let mut journal=KernelIntentJournal::open(&dir.path().join("journal")).unwrap();journal.bind_discovery(ORIGIN,&discovery).unwrap();
    for(name,case)in v["cases"].as_object().unwrap(){
        let command=command_id(case);journal.prepare(&command,KernelPath::Command,case["request"]["jws"].as_str().unwrap(),&serde_json::to_vec(&case["request"]).unwrap()).unwrap();
        // Retain one genuine unresolved original command while accepting the
        // remaining responses. Reading Human authors must not rewrite it.
        if name=="workspace"{continue}
        let saved=journal.verified_pending(&command,id.key_id(),discovery.audience_utf16()).unwrap().unwrap();
        journal.record_verified_response(&saved,&serde_json::to_vec(&case["response"]).unwrap(),discovery.receipt_public_key()).unwrap_or_else(|error|panic!("{name}: {error}"));
    }
    drop(journal);
    let cancel=CancellationToken::new();
    let missing=access(dir.path()).cached_participant_result(&command_id(&v["cases"]["record"]),&cancel).unwrap().unwrap();assert_eq!(missing.opened_contents.unwrap()[0].state,"KEY_UNAVAILABLE");
    keys(dir.path(),&v,&id);
    for name in ["record","records","message","inbox","conversation","pin"]{
        let result=access(dir.path()).cached_participant_result(&command_id(&v["cases"][name]),&cancel).unwrap().unwrap();
        assert_eq!(result.command_id,command_id(&v["cases"][name]));
        if matches!(name,"record"|"records"){let opened=result.opened_contents.unwrap();assert_eq!(opened.len(),1);assert_eq!(opened[0].state,"OPENED");assert_eq!(opened[0].text.as_deref(),Some("Synthetic Human record body"));}
        else{let opened=result.opened_messages.unwrap();assert_eq!(opened.len(),1,"{name}");assert_eq!(opened[0].state,"OPENED","{name}");assert_eq!(opened[0].assurance,Some("AUTHOR_SIGNATURE_AND_AEAD"));}
    }
    let journal=KernelIntentJournal::open(&dir.path().join("journal")).unwrap();let command=command_id(&v["cases"]["workspace"]);let saved=journal.verified_pending(&command,id.key_id(),discovery.audience_utf16()).unwrap().unwrap();assert!(journal.accepted_response(&saved,discovery.receipt_public_key()).unwrap().is_none());assert_eq!(saved.jws,v["cases"]["workspace"]["request"]["jws"]);
}

#[test]
fn durable_inbox_keeps_exact_human_frame_and_only_projects_selected_certificates_after_restart(){
    let v=fixture();let dir=crate::test_support::protected_test_dir();let id=identity(dir.path());keys(dir.path(),&v,&id);
    let p=&v["frame"]["pins"];let m=&p["mailbox"];let audience=v["audience"].as_str().unwrap().encode_utf16().collect::<Vec<_>>();
    let pins=MailboxPins{workspace_id:m["workspace_id"].as_str().unwrap().into(),mailbox_id:m["mailbox_id"].as_str().unwrap().into(),membership_id:m["membership_id"].as_str().unwrap().into(),receiver_id:m["receiver_id"].as_str().unwrap().into(),epoch:m["epoch"].as_u64().unwrap(),destination_digest:m["destination_digest"].as_str().unwrap().into(),binding_version:m["binding_version"].as_u64().unwrap(),after_sequence:m["after_sequence"].as_u64().unwrap(),after_control_sequence:m["after_control_sequence"].as_u64()};
    let page=verify_mailbox_frame_detailed(&serde_json::to_vec(&v["frame"]["envelope"]).unwrap(),&FramePins{audience:&audience,actor_id:id.actor_id(),stream_id:p["stream_id"].as_str().unwrap(),mailbox:&pins,service_key:v["service_key"].as_str().unwrap(),server_time_floor:p["server_time_floor"].as_u64().unwrap(),expires_at:p["expires_at"].as_u64().unwrap()}).unwrap();
    let mut inbox=InboxStore::open(&dir.path().join("inbox"),&id,ORIGIN,&audience,v["service_key"].as_str().unwrap()).unwrap();inbox.register(&pins).unwrap();let cursor=inbox.ingest(&id,&page,1024*1024).unwrap();drop(inbox);
    let inbox=InboxStore::open(&dir.path().join("inbox"),&id,ORIGIN,&audience,v["service_key"].as_str().unwrap()).unwrap();assert_eq!(inbox.cursor(&pins.workspace_id,&pins.mailbox_id).unwrap().unwrap().item,cursor.item);
    let mut entries=inbox.pending(&id,&pins.workspace_id,&pins.mailbox_id,0,8).unwrap();assert_eq!(entries.len(),1);let entry=&mut entries[0];assert_eq!(entry["envelope"],v["frame"]["envelope"]["items"][0]);assert_eq!(entry["author_proofs"]["roots"].as_object().unwrap().len(),1);assert_eq!(entry["author_proofs"]["devices"].as_object().unwrap().len(),1);
    access(dir.path()).open_cached_mail(entry,&audience);assert_eq!(entry["opened_message"]["state"],"OPENED");assert_eq!(entry["opened_message"]["sender"],v["human_actor"]);assert_eq!(entry["opened_message"]["text"],"Synthetic Human direct message");
    entry.as_object_mut().unwrap().remove("author_proofs");access(dir.path()).open_cached_mail(entry,&audience);assert_eq!(entry["opened_message"]["state"],"KEY_STATE_INVALID");
}
