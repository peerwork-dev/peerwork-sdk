//! Selected durable preparation plans in the existing intent journal. These
//! rows never prove submission or acceptance: exact packets and receipts do.
//! Only one primary-key row is decrypted, with no history/index rebuild.
use super::*;
use crate::kernel_identity::KernelIdentity;
use aes_gcm::{aead::{Aead,KeyInit,Payload},Aes256Gcm,Nonce};
use peerwork_core::crypto::sha256;
use rand_core::{OsRng,RngCore};
use serde_json::{json,Value};
use zeroize::Zeroizing;

pub(super) const SQL:&str="CREATE TABLE kernel_parent_operations(
                 command_id TEXT PRIMARY KEY NOT NULL,
                 binding_json TEXT NOT NULL CHECK(length(binding_json)<=8192),
                 sealed_selection BLOB NOT NULL CHECK(length(sealed_selection)>28 AND length(sealed_selection)<=524316)
             )";
pub(super) const PREPARING_SQL:&str="CREATE TABLE kernel_parent_preparations(
                 command_id TEXT PRIMARY KEY NOT NULL REFERENCES kernel_parent_operations(command_id),
                 local_key_id TEXT NOT NULL
             )";
pub(super) const KEY_SQL:&str="CREATE INDEX kernel_parent_preparations_by_key ON kernel_parent_preparations(local_key_id,command_id)";
pub(super) const SIGNED_SQL:&str="CREATE TRIGGER kernel_parent_signed AFTER INSERT ON kernel_intents BEGIN
                 DELETE FROM kernel_parent_preparations WHERE command_id=NEW.command_id;
             END";
pub(super) fn objects()->Vec<(String,String,String)>{vec![
    ("table".into(),"kernel_parent_operations".into(),SQL.into()),
    ("table".into(),"kernel_parent_preparations".into(),PREPARING_SQL.into()),
    ("index".into(),"kernel_parent_preparations_by_key".into(),KEY_SQL.into()),
    ("trigger".into(),"kernel_parent_signed".into(),SIGNED_SQL.into()),
]}
const MAX_PLAN:usize=524288;
#[derive(Debug,PartialEq,Eq)]
pub(crate) struct ParentSelection {
    pub kind:String,
    pub workspace_id:Option<String>,
    pub wire:Zeroizing<String>,
}
fn binding(id:&str,identity:&KernelIdentity,origin:&str,audience:&[u16],authority:&str,kind:&str,workspace:Option<&str>)->Result<String,JournalError>{
    if !valid_token(id)||!matches!(kind,"INTENT"|"ACCESS"|"PUBLICATION"|"ARCHIVE_MIGRATION"|"ARCHIVE_ARTIFACT")||authority.len()>4096 {
        return Err(JournalError::InvalidIntent);
    }
    let audience=String::from_utf16(audience).map_err(|_|JournalError::InvalidIntent)?;
    Ok(json!({"domain":"peerwork.local-parent-operation.v1","command_id":id,"origin":origin,
        "audience":audience,"actor_id":identity.actor_id(),"key_id":identity.key_id(),
        "authority":authority,"kind":kind,"workspace_id":workspace}).to_string())
}
fn cipher(identity:&KernelIdentity)->Result<Aes256Gcm,JournalError>{
    // The input is an OS-generated 256-bit identity seed, never a password.
    // Separate local recovery encryption from signing and workspace body keys.
    let mut input=Zeroizing::new(b"peerwork.local-parent-encryption-key.v1\0".to_vec());
    let seed=Zeroizing::new(identity.signing_key().to_bytes());input.extend_from_slice(seed.as_ref());
    let key=Zeroizing::new(sha256(&input));
    Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_|JournalError::IncompatibleStore)
}
fn open(identity:&KernelIdentity,aad:&str,sealed:&[u8])->Result<Zeroizing<String>,JournalError>{
    if !(29..=MAX_PLAN+28).contains(&sealed.len()){return Err(JournalError::IncompatibleStore);}
    let bytes=Zeroizing::new(cipher(identity)?.decrypt(Nonce::from_slice(&sealed[..12]),Payload{msg:&sealed[12..],aad:aad.as_bytes()})
        .map_err(|_|JournalError::IncompatibleStore)?);
    let text=std::str::from_utf8(&bytes).map_err(|_|JournalError::IncompatibleStore)?;
    Ok(Zeroizing::new(text.to_owned()))
}
impl KernelIntentJournal {
    pub(crate) fn preparations_page(&self,identity:&KernelIdentity,origin:&str,audience:&[u16],authority:&str,after:Option<&str>,limit:usize)->Result<Value,JournalError>{
        if after.is_some_and(|v|!valid_token(v))||!(1..=32).contains(&limit){return Err(JournalError::InvalidIntent);}
        let tx=self.db.unchecked_transaction()?;
        let mut ids:Vec<String>=tx.prepare("SELECT command_id FROM kernel_parent_preparations WHERE local_key_id=?1 AND command_id>?2 ORDER BY command_id LIMIT ?3")?
            .query_map(params![identity.key_id(),after.unwrap_or(""),limit+1],|r|r.get(0))?.collect::<Result<_,_>>()?;
        let more=ids.len()>limit;ids.truncate(limit);let mut items=Vec::new();
        for id in &ids {
            let selected=self.parent_selection(id,identity,origin,audience,authority,None)?.ok_or(JournalError::IncompatibleStore)?;
            items.push(json!({"command_id":id,"workspace_id":selected.workspace_id,"kind":selected.kind,"phase":"PREPARATION","effect_certainty":"NOT_SUBMITTED","recovery":"RESUME_SAME_INTENT"}));
        }
        let next=if more{ids.last().cloned()}else{None};
        tx.commit()?;Ok(json!({"items":items,"next_after":next,"consistency":"LIVE_KEYSET"}))
    }
    pub(crate) fn parent_selection(&self,id:&str,identity:&KernelIdentity,origin:&str,audience:&[u16],authority:&str,workspace:Option<&str>)
        ->Result<Option<ParentSelection>,JournalError>{
        if !valid_token(id){return Err(JournalError::InvalidIntent);}
        let row:Option<(String,Vec<u8>)>=self.db.query_row("SELECT binding_json,sealed_selection FROM kernel_parent_operations WHERE command_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((aad,sealed))=row else{return Ok(None);};
        if aad.len()>8192{return Err(JournalError::IncompatibleStore);}
        let metadata:Value=serde_json::from_str(&aad).map_err(|_|JournalError::IncompatibleStore)?;
        let kind=metadata["kind"].as_str().ok_or(JournalError::IncompatibleStore)?;
        let ws=metadata["workspace_id"].as_str();
        if !(metadata["workspace_id"].is_null()||ws.is_some())||workspace.is_some_and(|w|Some(w)!=ws)
            ||binding(id,identity,origin,audience,authority,kind,ws)?!=aad{return Err(JournalError::IntentConflict);}
        let wire=open(identity,&aad,&sealed)?;
        Ok(Some(ParentSelection{kind:kind.into(),workspace_id:ws.map(str::to_owned),wire}))
    }
    pub(crate) fn bind_parent_selection(&mut self,id:&str,identity:&KernelIdentity,origin:&str,audience:&[u16],authority:&str,kind:&str,workspace:Option<&str>,wire:&str)
        ->Result<(),JournalError>{
        if wire.is_empty()||wire.len()>MAX_PLAN{return Err(JournalError::InvalidIntent);}
        let aad=binding(id,identity,origin,audience,authority,kind,workspace)?;
        let check=|saved:ParentSelection|if saved.kind==kind&&saved.workspace_id.as_deref()==workspace&&saved.wire.as_str()==wire{Ok(())}else{Err(JournalError::IntentConflict)};
        if let Some(saved)=self.parent_selection(id,identity,origin,audience,authority,workspace)?{return check(saved);}
        let mut nonce=[0;12];OsRng.try_fill_bytes(&mut nonce).map_err(|_|JournalError::InvalidIntent)?;
        let encrypted=cipher(identity)?.encrypt(Nonce::from_slice(&nonce),Payload{msg:wire.as_bytes(),aad:aad.as_bytes()}).map_err(|_|JournalError::InvalidIntent)?;
        let mut sealed=nonce.to_vec();sealed.extend_from_slice(&encrypted);
        // Atomic election; a racing producer's different ciphertext cannot
        // replace the winner, even before any signed child packet exists.
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted=tx.execute("INSERT INTO kernel_parent_operations VALUES(?1,?2,?3) ON CONFLICT(command_id) DO NOTHING",params![id,aad,sealed])?;
        if inserted==1&&kind!="ARCHIVE_ARTIFACT" {
            tx.execute("INSERT INTO kernel_parent_preparations SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM kernel_intents WHERE command_id=?1)",params![id,identity.key_id()])?;
        }
        tx.commit()?;
        check(self.parent_selection(id,identity,origin,audience,authority,workspace)?.ok_or(JournalError::IncompatibleStore)?)
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    fn fixture()->(crate::test_support::ProtectedTestDir,KernelIdentity,KernelIntentJournal){
        let dir=crate::test_support::protected_test_dir();
        let identity=KernelIdentity::create(&dir.path().join("identity")).unwrap();
        let journal=KernelIntentJournal::open(&dir.path().join("operations.sqlite")).unwrap();(dir,identity,journal)
    }
    #[test]
    fn encrypted_parent_survives_restart_and_rejects_changed_input_and_scope(){
        let (dir,identity,mut journal)=fixture();let id="a".repeat(43);let ws="w".repeat(43);let audience:Vec<u16>="service".encode_utf16().collect();
        let secret="synthetic private staged text";
        journal.bind_parent_selection(&id,&identity,"https://example.invalid/",&audience,"authority","INTENT",Some(&ws),secret).unwrap();
        journal.bind_parent_selection(&id,&identity,"https://example.invalid/",&audience,"authority","INTENT",Some(&ws),secret).unwrap();
        assert!(matches!(journal.bind_parent_selection(&id,&identity,"https://example.invalid/",&audience,"authority","INTENT",Some(&ws),"changed"),Err(JournalError::IntentConflict)));
        for (origin,authority,workspace) in [("https://other.invalid/","authority",ws.as_str()),("https://example.invalid/","other",ws.as_str()),("https://example.invalid/","authority","other")]{
            assert!(matches!(journal.parent_selection(&id,&identity,origin,&audience,authority,Some(workspace)),Err(JournalError::IntentConflict)));
        }
        let other=KernelIdentity::create(&dir.path().join("other-identity")).unwrap();
        assert!(journal.parent_selection(&id,&other,"https://example.invalid/",&audience,"authority",None).is_err());
        drop(journal);
        for name in ["operations.sqlite","operations.sqlite-wal"]{
            if let Ok(wire)=fs::read(dir.path().join(name)){assert!(!wire.windows(secret.len()).any(|v|v==secret.as_bytes()));}
        }
        let journal=KernelIntentJournal::open(&dir.path().join("operations.sqlite")).unwrap();
        let parent=journal.parent_selection(&id,&identity,"https://example.invalid/",&audience,"authority",Some(&ws)).unwrap().unwrap();
        assert_eq!(parent.kind,"INTENT");assert_eq!(parent.wire.as_str(),secret);
    }
    #[test]
    fn swapped_ciphertexts_and_modified_bindings_never_recover(){
        let (_dir,identity,mut journal)=fixture();let a="a".repeat(43);let b="b".repeat(43);let audience:Vec<u16>="service".encode_utf16().collect();
        for id in [&a,&b]{journal.bind_parent_selection(id,&identity,"https://example.invalid/",&audience,"authority","INTENT",None,"{\"body\":\"secret\"}").unwrap();}
        let ciphertext:Vec<u8>=journal.db.query_row("SELECT sealed_selection FROM kernel_parent_operations WHERE command_id=?1",[&a],|r|r.get(0)).unwrap();
        journal.db.execute("UPDATE kernel_parent_operations SET sealed_selection=?1 WHERE command_id=?2",params![ciphertext,b]).unwrap();
        assert!(matches!(journal.parent_selection(&b,&identity,"https://example.invalid/",&audience,"authority",None),Err(JournalError::IncompatibleStore)));
        journal.db.execute("UPDATE kernel_parent_operations SET binding_json=replace(binding_json,'INTENT','ACCESS') WHERE command_id=?1",[&a]).unwrap();
        assert!(matches!(journal.parent_selection(&a,&identity,"https://example.invalid/",&audience,"authority",None),Err(JournalError::IncompatibleStore)));
    }
    #[test]
    fn preparation_listing_is_bounded_identity_scoped_and_packet_insert_retires_locator(){
        let (dir,identity,mut journal)=fixture();let audience:Vec<u16>="service".encode_utf16().collect();
        for n in 0..35{let id=format!("{:043}",n);journal.bind_parent_selection(&id,&identity,"https://example.invalid/",&audience,"authority","INTENT",None,"{\"body\":\"secret\"}").unwrap();}
        let first=journal.preparations_page(&identity,"https://example.invalid/",&audience,"authority",None,32).unwrap();
        assert_eq!(first["items"].as_array().unwrap().len(),32);let after=first["next_after"].as_str().unwrap();
        assert_eq!(journal.preparations_page(&identity,"https://example.invalid/",&audience,"authority",Some(after),32).unwrap()["items"].as_array().unwrap().len(),3);
        let other=KernelIdentity::create(&dir.path().join("other")).unwrap();
        assert!(journal.preparations_page(&other,"https://example.invalid/",&audience,"authority",None,32).unwrap()["items"].as_array().unwrap().is_empty());
        let id=first["items"][0]["command_id"].as_str().unwrap();
        // The locator retires atomically with the exact packet INSERT, before
        // any network await; the immutable encrypted binding is retained.
        journal.db.execute("INSERT INTO kernel_intents VALUES(?1,'command','synthetic','digest',x'01','PENDING',1)",[id]).unwrap();
        assert_eq!(journal.db.query_row("SELECT count(*) FROM kernel_parent_preparations WHERE command_id=?1",[id],|r|r.get::<_,i64>(0)).unwrap(),0);
        assert!(journal.parent_selection(id,&identity,"https://example.invalid/",&audience,"authority",None).unwrap().is_some());
        let plan:Vec<String>=journal.db.prepare("EXPLAIN QUERY PLAN SELECT command_id FROM kernel_parent_preparations WHERE local_key_id=?1 AND command_id>?2 ORDER BY command_id LIMIT 33").unwrap().query_map(params![identity.key_id(),""],|r|r.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
        assert!(plan.iter().any(|s|s.contains("COVERING INDEX kernel_parent_preparations_by_key")));
    }
    #[test]
    fn concurrent_preparers_keep_one_immutable_parent(){
        let (dir,identity,journal)=fixture();let path=dir.path().join("operations.sqlite");let identity_path=dir.path().join("identity");drop(journal);
        let barrier=std::sync::Arc::new(std::sync::Barrier::new(8));let mut threads=Vec::new();
        for _ in 0..8{let path=path.clone();let identity_path=identity_path.clone();let barrier=barrier.clone();threads.push(std::thread::spawn(move||{
            let identity=KernelIdentity::open(&identity_path).unwrap();let mut journal=KernelIntentJournal::open(&path).unwrap();let audience:Vec<u16>="service".encode_utf16().collect();barrier.wait();
            journal.bind_parent_selection(&"a".repeat(43),&identity,"https://example.invalid/",&audience,"authority","INTENT",None,"private elected plan").unwrap();
        }));}for thread in threads{thread.join().unwrap();}
        let journal=KernelIntentJournal::open(&path).unwrap();let audience:Vec<u16>="service".encode_utf16().collect();
        assert_eq!(journal.preparations_page(&identity,"https://example.invalid/",&audience,"authority",None,32).unwrap()["items"].as_array().unwrap().len(),1);
    }
    #[test]
    fn version_five_additive_upgrade_preserves_pins_packets_and_locator_checkpoint(){
        let (dir,_identity,journal)=fixture();
        journal.db.execute_batch("DROP TRIGGER kernel_parent_signed; DROP TABLE kernel_parent_preparations; DROP TABLE kernel_parent_operations; PRAGMA user_version=5;").unwrap();
        let before:Vec<(String,String)>=journal.db.prepare("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?))).unwrap().collect::<Result<_,_>>().unwrap();
        drop(journal);let journal=KernelIntentJournal::open(&dir.path().join("operations.sqlite")).unwrap();
        for (name,sql) in before{assert_eq!(journal.db.query_row("SELECT sql FROM sqlite_master WHERE name=?1",[name],|r|r.get::<_,String>(0)).unwrap(),sql);}
        assert_eq!(journal.db.pragma_query_value(None,"user_version",|r|r.get::<_,i64>(0)).unwrap(),6);
    }
}
