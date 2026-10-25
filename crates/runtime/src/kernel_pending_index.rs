//! A locator, never an acceptance proof. Completed history is not inspected by
//! ordinary pending reads. Selected rows still require the original verifier.
use super::*;

pub(super) const ENTRIES_SQL: &str = "CREATE TABLE kernel_pending_entries(
                 command_id TEXT PRIMARY KEY NOT NULL REFERENCES kernel_intents(command_id),
                 local_key_id TEXT NOT NULL
             )";
pub(super) const KEY_SQL: &str = "CREATE INDEX kernel_pending_by_key ON kernel_pending_entries(local_key_id,command_id)";
pub(super) const STATE_SQL: &str = "CREATE TABLE kernel_pending_index_state(
                 id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
                 legacy_after TEXT NOT NULL,
                 legacy_through TEXT,
                 complete INTEGER NOT NULL CHECK(complete IN (0,1))
             )";
pub(super) const INSERT_SQL: &str = "CREATE TRIGGER kernel_pending_insert AFTER INSERT ON kernel_intents BEGIN
                 INSERT INTO kernel_pending_entries(command_id,local_key_id) VALUES(NEW.command_id,'');
             END";
pub(super) const ACCEPT_SQL: &str = "CREATE TRIGGER kernel_pending_accept AFTER INSERT ON accepted_responses BEGIN
                 DELETE FROM kernel_pending_entries WHERE command_id=NEW.command_id;
             END";
pub(super) const CATALOG_SQL:&str="CREATE TABLE kernel_catalog_begins(
                 command_id TEXT PRIMARY KEY NOT NULL REFERENCES kernel_intents(command_id),
                 local_key_id TEXT NOT NULL,
                 upload_id TEXT NOT NULL
             )";
pub(super) const CATALOG_KEY_SQL:&str="CREATE INDEX kernel_catalog_begin_lookup ON kernel_catalog_begins(local_key_id,upload_id,command_id)";

pub(super) fn objects() -> Vec<(String,String,String)> {
    vec![
        ("index".into(),"kernel_catalog_begin_lookup".into(),CATALOG_KEY_SQL.into()),
        ("index".into(),"kernel_pending_by_key".into(),KEY_SQL.into()),
        ("table".into(),"kernel_catalog_begins".into(),CATALOG_SQL.into()),
        ("table".into(),"kernel_pending_entries".into(),ENTRIES_SQL.into()),
        ("table".into(),"kernel_pending_index_state".into(),STATE_SQL.into()),
        ("trigger".into(),"kernel_pending_accept".into(),ACCEPT_SQL.into()),
        ("trigger".into(),"kernel_pending_insert".into(),INSERT_SQL.into()),
    ]
}

pub(super) fn initialize(tx: &rusqlite::Transaction<'_>) -> Result<(),JournalError> {
    tx.execute_batch(&format!("{ENTRIES_SQL};{KEY_SQL};{STATE_SQL};{INSERT_SQL};{ACCEPT_SQL};{CATALOG_SQL};{CATALOG_KEY_SQL};"))?;
    // MAX on the primary key is one index endpoint, not a history scan. New
    // inserts are already covered by the trigger and application transaction.
    let through:Option<String>=tx.query_row("SELECT MAX(command_id) FROM kernel_intents",[],|r|r.get(0))?;
    tx.execute("INSERT INTO kernel_pending_index_state VALUES(1,'',?1,?2)",params![through,i64::from(through.is_none())])?;
    Ok(())
}

pub(super) fn locate_pending(db:&Connection,id:&str,jws:&str)->Result<(),JournalError>{
    // Untrusted routing metadata only. A malformed packet is retained under
    // the empty-key sentinel and cannot silently disappear from pending reads.
    db.execute("UPDATE kernel_pending_entries SET local_key_id=?1 WHERE command_id=?2",
        params![signer_key_id(jws).unwrap_or_default(),id])?;
    locate_catalog_begin(db,id,jws)?;
    Ok(())
}

pub(super) fn locate_catalog_begin(db:&Connection,id:&str,jws:&str)->Result<(),JournalError>{
    use peerwork_core::{crypto::decode_base64url,wire_json::parse_wire_json_bounded};
    let accepted:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM accepted_responses WHERE command_id=?1)",[id],|r|r.get(0))?;
    if !accepted{return Ok(());}
    let Some(kid)=signer_key_id(jws)else{return Ok(());};
    let Some(payload)=jws.split('.').nth(1).and_then(|s|decode_base64url(s).ok())else{return Ok(());};
    let Ok(command)=parse_wire_json_bounded(&payload,40,180_000)else{return Ok(());};
    if command.get("action_id").and_then(|v|v.as_string()).as_deref()!=Some("catalog.upload.begin"){return Ok(());}
    let Some(upload)=command.get("body").and_then(|v|v.get("upload_id")).and_then(|v|v.as_string()).filter(|s|valid_token(s))else{return Ok(());};
    // Metadata only. Both the original signature and accepted service reply
    // are checked after the indexed lookup, never trusted from this register.
    db.execute("INSERT OR IGNORE INTO kernel_catalog_begins VALUES(?1,?2,?3)",params![id,kid,upload])?;
    Ok(())
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct PendingIntentPage {
    pub items:Vec<PendingKernelIntent>,
    pub next_after:Option<String>,
    pub consistency:&'static str,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct PendingIndexProgress {
    pub complete:bool,
    /// Rows visited in this invocation, not a COUNT over retained history.
    pub scanned_rows:usize,
}

impl KernelIntentJournal {
    /// Explicit, restart-safe local transport maintenance. This does not
    /// migrate identities, submit requests or claim to audit signed history.
    pub fn build_pending_index(&mut self,max_rows:usize)->Result<PendingIndexProgress,JournalError>{
        if !(1..=32).contains(&max_rows){return Err(JournalError::InvalidIntent);}
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (after,through,complete):(String,Option<String>,bool)=tx.query_row(
            "SELECT legacy_after,legacy_through,complete FROM kernel_pending_index_state WHERE id=1",[],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if complete {return Ok(PendingIndexProgress{complete:true,scanned_rows:0});}
        let through=through.ok_or(JournalError::IncompatibleStore)?;
        let rows:Vec<(String,String,bool)>=tx.prepare(
            "SELECT i.command_id,i.signed_jws,EXISTS(SELECT 1 FROM accepted_responses a WHERE a.command_id=i.command_id)
             FROM kernel_intents i WHERE i.command_id>?1 AND i.command_id<=?2 ORDER BY i.command_id LIMIT ?3")?
            .query_map(params![after,through,max_rows],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?
            .collect::<Result<_,_>>()?;
        for (id,jws,accepted) in &rows {
            if !accepted {
                tx.execute("INSERT OR IGNORE INTO kernel_pending_entries VALUES(?1,?2)",
                    params![id,signer_key_id(jws).unwrap_or_default()])?;
            }
            if *accepted {locate_catalog_begin(&tx,id,jws)?;}
        }
        let next=rows.last().map(|r|r.0.as_str()).unwrap_or(&after);
        let done=rows.len()<max_rows || next==through;
        tx.execute("UPDATE kernel_pending_index_state SET legacy_after=?1,complete=?2 WHERE id=1",
            params![next,i64::from(done)])?;
        tx.commit()?;
        Ok(PendingIndexProgress{complete:done,scanned_rows:rows.len()})
    }

    pub(crate) fn catalog_begin_ids(&self,key:&str,upload:&str)->Result<Vec<String>,JournalError>{
        let complete:bool=self.db.query_row("SELECT complete FROM kernel_pending_index_state WHERE id=1",[],|r|r.get(0))?;
        if !complete{return Err(JournalError::PendingIndexIncomplete);}
        let rows=self.db.prepare("SELECT command_id FROM kernel_catalog_begins WHERE local_key_id=?1 AND upload_id=?2 ORDER BY command_id LIMIT 2")?
            .query_map(params![key,upload],|r|r.get(0))?.collect::<Result<_,_>>()?;
        Ok(rows)
    }

    /// Live keyset page, ordered by command ID; no fixed historical snapshot.
    /// Completion claims belong to selected status(), never to this locator.
    pub fn pending_page(&self,key:&str,audience:&[u16],after:Option<&str>,limit:usize)
        ->Result<PendingIntentPage,JournalError>{
        if !valid_token(key)||after.is_some_and(|v|!valid_token(v))||!(1..=32).contains(&limit){
            return Err(JournalError::InvalidIntent);
        }
        // One read transaction prevents mixed index/receipt observations when
        // another SDK process accepts an operation during verification.
        let tx=self.db.unchecked_transaction()?;
        let complete:bool=tx.query_row("SELECT complete FROM kernel_pending_index_state WHERE id=1",[],|r|r.get(0))?;
        if !complete{return Err(JournalError::PendingIndexIncomplete);}
        let malformed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM kernel_pending_entries WHERE local_key_id='')",[],|r|r.get(0))?;
        if malformed{return Err(JournalError::IncompatibleStore);}
        let mut rows:Vec<PendingKernelIntent>=tx.prepare(
            "SELECT i.command_id,i.intent_digest,i.created_at_ms FROM kernel_pending_entries p
             JOIN kernel_intents i ON i.command_id=p.command_id
             WHERE p.local_key_id=?1 AND p.command_id>?2 ORDER BY p.command_id LIMIT ?3")?
            .query_map(params![key,after.unwrap_or(""),limit+1],|r|Ok(PendingKernelIntent{
                command_id:r.get(0)?,intent_digest:r.get(1)?,created_at_ms:r.get(2)?}))?
            .collect::<Result<_,_>>()?;
        let more=rows.len()>limit;
        rows.truncate(limit);
        for row in &rows {
            let saved=self.verified_pending(&row.command_id,key,audience)?.ok_or(JournalError::IncompatibleStore)?;
            if saved.proof.intent_digest()!=row.intent_digest {
                return Err(JournalError::IncompatibleStore);
            }
            // A queue entry with a receipt is an invariant violation. Never
            // silently present it as unresolved or infer verified acceptance.
            let accepted:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM accepted_responses WHERE command_id=?1)",
                [&row.command_id],|r|r.get(0))?;
            if accepted{return Err(JournalError::IncompatibleStore);}
        }
        let next_after=if more{rows.last().map(|r|r.command_id.clone())}else{None};
        tx.commit()?;
        Ok(PendingIntentPage{items:rows,next_after,consistency:"LIVE_KEYSET"})
    }
}

#[cfg(all(test,unix))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use peerwork_core::{crypto::{actor_id,key_id},discovery::parse_discovery_wire,
        prepared_command::prepare_signed_command_wire,wire_json::parse_wire_json_bounded};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn directory()->tempfile::TempDir{
        let dir=tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(),fs::Permissions::from_mode(0o700)).unwrap();dir
    }
    fn discovery()->ParsedDiscovery{
        let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"pending-test",
            "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
            "receipt_public_key":key_id(&SigningKey::from_bytes(&[22;32]).verifying_key().to_bytes()),"limits":{"max":1}})).unwrap();
        parse_discovery_wire(&wire,wire.len()).unwrap()
    }
    fn command(n:u64,seed:u8)->SignedPreparedCommand{
        let signing=SigningKey::from_bytes(&[seed;32]);let actor=actor_id(&signing.verifying_key().to_bytes());
        let mut id_bytes=[0;32];id_bytes[..8].copy_from_slice(&n.to_be_bytes());let id=key_id(&id_bytes);
        let wire=serde_json::to_vec(&json!({"v":1,"audience":"pending-test","command_id":id,"actor_id":actor,
            "authority":sha256_hex(actor.as_bytes()),"method":"POST","path":"/api/workspace/v1/commands",
            "workspace_id":null,"instance_id":null,"protocol_digest":null,"action_id":"catalog.namespace.claim",
            "expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],
            "body":{"namespace":actor},"issued_at":1,"expires_at":600001})).unwrap();
        prepare_signed_command_wire(&parse_wire_json_bounded(&wire,40,180_000).unwrap(),&signing,&discovery(),None).unwrap()
    }
    fn key(seed:u8)->String{key_id(&SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())}
    fn save(j:&mut KernelIntentJournal,n:u64)->PendingKernelIntent{
        let c=command(n,21);j.prepare(c.proof().command_id(),KernelPath::Command,c.jws(),c.http_body()).unwrap()
    }
    fn seed_noise(j:&mut KernelIntentJournal,count:u64){
        let header=peerwork_core::crypto::base64url(serde_json::to_string(&json!({"kid":key(23)})).unwrap().as_bytes());
        let bogus=format!("{header}.e30.AA");
        let tx=j.db.transaction().unwrap();
        for n in 0..count {
            let id=format!("N{n:042}");
            tx.execute("INSERT INTO kernel_intents VALUES(?1,'/api/workspace/v1/commands',?2,'not-a-proof',x'01','PENDING',0)",params![id,bogus]).unwrap();
            locate_pending(&tx,&id,&bogus).unwrap();
            // Half are completed history; the rest belong to another actor.
            if n%2==0{tx.execute("INSERT INTO accepted_responses VALUES(?1,x'01')",[&id]).unwrap();}
        }
        tx.commit().unwrap();
    }

    #[test]
    fn indexed_pages_ignore_large_completed_and_other_actor_history_but_verify_selected(){
        let dir=directory();let path=dir.path().join("journal.sqlite");let mut j=KernelIntentJournal::open(&path).unwrap();
        let mut selected=Vec::new();for n in 0..35{selected.push(save(&mut j,n));}
        selected.sort_by(|a,b|a.command_id.cmp(&b.command_id));
        seed_noise(&mut j,10000);
        drop(j);let j=KernelIntentJournal::open(&path).unwrap();
        let a=j.pending_page(&key(21),discovery().audience_utf16(),None,32).unwrap();
        assert_eq!(a.items,selected[..32]);assert_eq!(a.next_after.as_deref(),Some(selected[31].command_id.as_str()));
        let b=j.pending_page(&key(21),discovery().audience_utf16(),a.next_after.as_deref(),32).unwrap();
        assert_eq!(b.items,selected[32..]);assert_eq!(b.next_after,None);
        let plan:Vec<String>=j.db.prepare("EXPLAIN QUERY PLAN SELECT i.command_id FROM kernel_pending_entries p JOIN kernel_intents i ON i.command_id=p.command_id WHERE p.local_key_id=?1 AND p.command_id>?2 ORDER BY p.command_id LIMIT 33").unwrap()
            .query_map(params![key(21),""],|r|r.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
        assert!(plan.iter().any(|s|s.contains("kernel_pending_by_key")&&s.contains("local_key_id=?")&&s.contains("command_id>?")),"{plan:?}");
        assert!(!plan.iter().any(|s|s.contains("SCAN ")||s.contains("TEMP B-TREE")),"{plan:?}");
        j.db.execute("UPDATE kernel_intents SET http_body=x'00' WHERE command_id=?1",[&selected[0].command_id]).unwrap();
        assert!(matches!(j.pending_page(&key(21),discovery().audience_utf16(),None,32),Err(JournalError::IncompatibleStore)));
    }

    #[test]
    fn legacy_build_is_explicit_bounded_restartable_and_does_not_block_selected_recovery(){
        let dir=directory();let path=dir.path().join("journal.sqlite");let mut j=KernelIntentJournal::open(&path).unwrap();
        let selected=save(&mut j,1);seed_noise(&mut j,80);
        // Reproduce the exact old v4 schema and retained bytes, without using
        // private application data or bypassing any selected signature check.
        j.db.execute_batch("DROP TRIGGER kernel_parent_signed;DROP TABLE kernel_parent_preparations;DROP TABLE kernel_parent_operations;DROP TRIGGER kernel_pending_insert;DROP TRIGGER kernel_pending_accept;DROP INDEX kernel_pending_by_key;DROP TABLE kernel_pending_entries;DROP TABLE kernel_pending_index_state;DROP TABLE kernel_catalog_begins;PRAGMA user_version=4;").unwrap();
        drop(j);let mut j=KernelIntentJournal::open(&path).unwrap();
        assert_eq!(j.db.query_row("SELECT count(*) FROM kernel_pending_entries",[],|r|r.get::<_,i64>(0)).unwrap(),0,"open must not backfill history");
        assert!(matches!(j.pending_page(&key(21),discovery().audience_utf16(),None,32),Err(JournalError::PendingIndexIncomplete)));
        assert!(j.verified_pending(&selected.command_id,&key(21),discovery().audience_utf16()).unwrap().is_some());
        let step=j.build_pending_index(7).unwrap();assert_eq!(step,PendingIndexProgress{complete:false,scanned_rows:7});
        // New writes remain indexed even when they sort behind the old cursor.
        let after:String=j.db.query_row("SELECT legacy_after FROM kernel_pending_index_state",[],|r|r.get(0)).unwrap();
        let c=(2..1000).map(|n|command(n,21)).find(|c|c.proof().command_id()<after.as_str()).unwrap();
        let added=j.prepare(c.proof().command_id(),KernelPath::Command,c.jws(),c.http_body()).unwrap();
        drop(j);let mut j=KernelIntentJournal::open(&path).unwrap();
        let mut scanned=step.scanned_rows;
        loop{let step=j.build_pending_index(7).unwrap();assert!(step.scanned_rows<=7);scanned+=step.scanned_rows;if step.complete{break;}}
        assert_eq!(scanned,81,"new indexed writes behind the checkpoint must not require rewinding history");
        assert_eq!(j.build_pending_index(7).unwrap(),PendingIndexProgress{complete:true,scanned_rows:0});
        let page=j.pending_page(&key(21),discovery().audience_utf16(),None,32).unwrap();
        let mut wanted=vec![selected,added];wanted.sort_by(|a,b|a.command_id.cmp(&b.command_id));assert_eq!(page.items,wanted);
    }

    #[test]
    fn locator_and_acceptance_are_atomic_and_corrupt_unclassified_packets_stay_visible(){
        let dir=directory();let mut j=KernelIntentJournal::open(&dir.path().join("journal.sqlite")).unwrap();
        let row=save(&mut j,1);
        {let tx=j.db.transaction().unwrap();tx.execute("INSERT INTO accepted_responses VALUES(?1,x'01')",[&row.command_id]).unwrap();}
        assert_eq!(j.pending_page(&key(21),discovery().audience_utf16(),None,32).unwrap().items,vec![row.clone()]);
        // Simulate a receipt write; acceptance proof remains the separate
        // selected verifier's job. The transaction's trigger only locates.
        j.db.execute("INSERT INTO accepted_responses VALUES(?1,x'01')",[&row.command_id]).unwrap();
        assert!(j.pending_page(&key(21),discovery().audience_utf16(),None,32).unwrap().items.is_empty());
        let c=command(1,21);j.prepare(&row.command_id,KernelPath::Command,c.jws(),c.http_body()).unwrap();
        assert!(j.pending_page(&key(21),discovery().audience_utf16(),None,32).unwrap().items.is_empty(),"idempotent prepare must not resurrect an accepted operation");
        j.prepare(&"Z".repeat(43),KernelPath::Command,"malformed",b"x").unwrap();
        assert!(matches!(j.pending_page(&key(21),discovery().audience_utf16(),None,32),Err(JournalError::IncompatibleStore)));
        assert!(matches!(j.pending_page(&key(21),discovery().audience_utf16(),None,33),Err(JournalError::InvalidIntent)));
    }

    #[test]
    fn interrupted_legacy_step_rolls_back_entries_and_cursor_together(){
        let dir=directory();let mut j=KernelIntentJournal::open(&dir.path().join("journal.sqlite")).unwrap();
        save(&mut j,1);save(&mut j,2);
        j.db.execute("DELETE FROM kernel_pending_entries",[]).unwrap();
        j.db.execute("UPDATE kernel_pending_index_state SET complete=0,legacy_through=(SELECT MAX(command_id) FROM kernel_intents)",[]).unwrap();
        j.db.execute_batch("CREATE TEMP TRIGGER fail_step BEFORE UPDATE ON kernel_pending_index_state BEGIN SELECT RAISE(ABORT,'injected checkpoint failure');END;").unwrap();
        assert!(matches!(j.build_pending_index(1),Err(JournalError::Storage(_))));
        assert_eq!(j.db.query_row("SELECT count(*) FROM kernel_pending_entries",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        assert_eq!(j.db.query_row("SELECT legacy_after FROM kernel_pending_index_state",[],|r|r.get::<_,String>(0)).unwrap(),"");
        j.db.execute_batch("DROP TRIGGER fail_step;").unwrap();assert!(j.build_pending_index(2).unwrap().complete);
    }
}
