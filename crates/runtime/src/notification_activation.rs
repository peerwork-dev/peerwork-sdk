//! Presentation ownership on the original receiving authority. Destination
//! notification batches, custody and pause records are deliberately untouched.
use super::{db_error, error, valid, Store};
use crate::participant::Result;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub source: String,
    pub operation_id: String,
    pub generation: u64,
    pub target: Value,
}

pub(crate) fn member_key(client:&crate::participant::ParticipantClient,namespace:&str,options:&crate::participant::WatchOptions)->String {
    peerwork_core::crypto::sha256_hex(json!(["peerwork.presentation-member.v1",client.origin(),client.actor_id(),client.state_binding(),namespace,options.workspace_id,options.mailbox_id,options.membership_id]).to_string().as_bytes())
}
pub(crate) fn source_key(client:&crate::participant::ParticipantClient,bindings:&[crate::participant::WatchOptions])->String {
    let mut selected=bindings.iter().map(|w|(&w.workspace_id,&w.mailbox_id,&w.membership_id)).collect::<Vec<_>>();selected.sort();
    peerwork_core::crypto::sha256_hex(json!(["peerwork.presentation-source-group.v1",client.origin(),client.actor_id(),client.state_binding(),client.local_namespace(),selected]).to_string().as_bytes())
}

pub(crate) struct Admission {
    pub source:String,
    pub members:Vec<String>,
    pub activation:Option<Activation>,
}
impl Admission {
    pub(crate) fn for_bindings(client:&crate::participant::ParticipantClient,bindings:&[crate::participant::WatchOptions])->Self {
        let mut members=bindings.iter().map(|w|member_key(client,client.local_namespace(),w)).collect::<Vec<_>>();members.sort();
        Self{source:source_key(client,bindings),members,activation:None}
    }
    pub(super) fn check(&self,db:&Connection)->Result<()> {
        if pending(db,&self.source,&self.members)? {return Err(error("PRESENTATION_REBIND_PENDING"));}
        if selected_groups(db,&self.members)?.iter().any(|source|source!=&self.source) {return Err(error("PRESENTATION_GROUP_SELECTION_REQUIRED"));}
        let generation=current(db,&self.source)?;
        if let Some(selected)=&self.activation {
            if selected.source!=self.source {return Err(error("PRESENTATION_SOURCE_CHANGED"));}
            if selected.generation<generation {return Err(error("PRESENTATION_ACTIVATION_SUPERSEDED"));}
            let (_,saved)=decision(db,&self.source,&selected.operation_id)?.ok_or_else(||error("PRESENTATION_ACTIVATION_UNKNOWN"))?;
            if &saved!=selected {return Err(error("PRESENTATION_ACTIVATION_MISMATCH"));}
            if selected.generation!=generation {return Err(error("PRESENTATION_ACTIVATION_SUPERSEDED"));}
        } else if managed(db,&self.source)? {return Err(error("PRESENTATION_ACTIVATION_REQUIRED"));}
        Ok(())
    }
}

pub(super) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS presentation_sources(source TEXT PRIMARY KEY,generation INTEGER NOT NULL,operation_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS presentation_decisions(source TEXT NOT NULL,operation_id TEXT NOT NULL,expected_generation INTEGER NOT NULL,generation INTEGER NOT NULL,target TEXT NOT NULL,PRIMARY KEY(source,operation_id));
        CREATE TABLE IF NOT EXISTS presentation_group_members(source TEXT NOT NULL,member TEXT NOT NULL,PRIMARY KEY(source,member));
        CREATE INDEX IF NOT EXISTS presentation_group_member_source ON presentation_group_members(member,source);
        CREATE TABLE IF NOT EXISTS presentation_rebind_members(member TEXT PRIMARY KEY,operation TEXT NOT NULL,state TEXT NOT NULL);")
        .map_err(db_error)
}

fn current(db: &Connection, source: &str) -> Result<u64> {
    Ok(db.query_row("SELECT generation FROM presentation_sources WHERE source=?1", [source], |r| r.get::<_, u64>(0))
        .optional().map_err(db_error)?.unwrap_or(0))
}

fn managed(db:&Connection,source:&str)->Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM presentation_sources s JOIN presentation_decisions d ON d.source=s.source AND d.operation_id=s.operation_id AND d.generation=s.generation WHERE s.source=?1)",[source],|r|r.get(0)).map_err(db_error)
}

fn decision(db: &Connection, source: &str, operation: &str) -> Result<Option<(u64, Activation)>> {
    let row: Option<(u64, u64, String)> = db.query_row(
        "SELECT expected_generation,generation,target FROM presentation_decisions WHERE source=?1 AND operation_id=?2",
        params![source, operation], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional().map_err(db_error)?;
    row.map(|(expected, generation, target)| Ok((expected, Activation {
        source:source.into(), operation_id: operation.into(), generation,
        target: serde_json::from_str(&target).map_err(|_| error("PRESENTATION_STATE_INVALID"))?,
    }))).transpose()
}

fn outcome(source: &str, selected: &Activation, generation: u64) -> Value {
    json!({"state":if selected.generation==generation{"ACTIVE"}else{"SUPERSEDED"},
        "source":source,"activation":selected,"current_generation":generation})
}

fn group_members(db:&Connection,source:&str)->Result<Vec<String>> {
    db.prepare("SELECT member FROM presentation_group_members WHERE source=?1 ORDER BY member").map_err(db_error)?
        .query_map([source],|r|r.get(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)
}
fn pending(db:&Connection,_source:&str,members:&[String])->Result<bool> {
    for member in members {
        if db.query_row("SELECT EXISTS(SELECT 1 FROM presentation_rebind_members WHERE member=?1 AND state='PENDING')",[member],|r|r.get::<_,bool>(0)).map_err(db_error)? {return Ok(true);}
    }
    Ok(false)
}
fn members_valid(members:&[String])->Result<()> {
    if members.is_empty()||members.len()>8||members.windows(2).any(|pair|pair[0]>=pair[1]) {return Err(error("PRESENTATION_GROUP_SELECTION_REQUIRED"));}
    for member in members {valid(member)?;}Ok(())
}
fn selected_groups(db:&Connection,members:&[String])->Result<Vec<String>> {
    let mut sources=std::collections::BTreeSet::new();
    for member in members {
        let found=db.prepare("SELECT m.source FROM presentation_group_members m JOIN presentation_sources s ON s.source=m.source JOIN presentation_decisions d ON d.source=s.source AND d.operation_id=s.operation_id AND d.generation=s.generation WHERE m.member=?1")
            .map_err(db_error)?.query_map([member],|r|r.get::<_,String>(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        for source in found {
            if group_members(db,&source)?.iter().any(|member|members.binary_search(member).is_err()) {return Err(error("PRESENTATION_GROUP_SELECTION_REQUIRED"));}
            sources.insert(source);
        }
    }
    Ok(sources.into_iter().collect())
}

impl Store {
    /// Final admission reads both authorities under one mutex. Replacement can
    /// follow admission, but cannot race between the generation and batch check.
    pub(crate) fn presentation_notification_allowed(&self, source:&str, members:&[String], selected:Option<&Activation>, owner:&str, batch:&str, revision:u64) -> Result<bool> {
        valid(source)?;valid(owner)?;
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        Admission{source:source.into(),members:members.to_vec(),activation:selected.cloned()}.check(&db)?;
        let state:Option<String>=db.query_row("SELECT state FROM notification_owners WHERE owner=?1",[owner],|r|r.get(0)).optional().map_err(db_error)?;
        let Some(state)=state else {return Ok(false);};
        if state.len()>131072 {return Err(error("NOTIFICATION_STATE_CAPACITY"));}
        let state:super::State=serde_json::from_str(&state).map_err(|_|error("NOTIFICATION_STATE_INVALID"))?;
        if state.owner!=owner {return Err(error("NOTIFICATION_STATE_INVALID"));}
        Ok(state.revision==revision && state.active.as_deref()==Some(batch)
            && (state.mode!="PAUSED"||state.probe)
            && state.batches.iter().any(|b|b.wake.batch==batch&&!b.observed&&!b.retired&&b.wake.revision==revision))
    }

    /// Only authenticated lifecycle authority may invoke this mutation. A lost
    /// reply resumes the same decision; a loser never refreshes its CAS itself.
    pub(crate) fn presentation_replace(&self, source: &str, members:&[String], operation: &str, expected: u64, target: &Value) -> Result<Value> {
        valid(source)?; valid(operation)?;
        members_valid(members)?;
        if !target.is_object() || target.to_string().len()>8192 {
            return Err(error("PRESENTATION_TARGET_INVALID"));
        }
        let mut db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_error)?;
        if pending(&tx,source,members)? {return Err(error("PRESENTATION_REBIND_PENDING"));}
        let generation=current(&tx,source)?;
        if let Some((original_expected,selected))=decision(&tx,source,operation)? {
            if original_expected!=expected || &selected.target!=target {
                return Err(error("PRESENTATION_ORIGINAL_OPERATION_REQUIRED"));
            }
            return Ok(outcome(source,&selected,generation));
        }
        if generation!=expected {return Err(error("PRESENTATION_GENERATION_CONFLICT"));}
        let saved=group_members(&tx,source)?;
        if !saved.is_empty()&&saved!=members {return Err(error("PRESENTATION_SOURCE_CHANGED"));}
        // A narrowed namespace view may not elect an overlapping source group.
        if selected_groups(&tx,members)?.iter().any(|other|other!=source) {return Err(error("PRESENTATION_GROUP_SELECTION_REQUIRED"));}
        let next=generation.checked_add(1).filter(|g|*g<=i64::MAX as u64)
            .ok_or_else(||error("PRESENTATION_GENERATION_EXHAUSTED"))?;
        let selected=Activation{source:source.into(),operation_id:operation.into(),generation:next,target:target.clone()};
        for member in members {tx.execute("INSERT OR IGNORE INTO presentation_group_members VALUES(?1,?2)",params![source,member]).map_err(db_error)?;}
        tx.execute("INSERT INTO presentation_decisions VALUES(?1,?2,?3,?4,?5)",params![source,operation,expected,next,target.to_string()]).map_err(db_error)?;
        tx.execute("INSERT INTO presentation_sources VALUES(?1,?2,?3) ON CONFLICT(source) DO UPDATE SET generation=excluded.generation,operation_id=excluded.operation_id",params![source,next,operation]).map_err(db_error)?;
        // Keep recent lost-response receipts; the generation watermark still
        // rejects every retired token after its receipt is pruned.
        tx.execute("DELETE FROM presentation_decisions WHERE source=?1 AND generation < ?2",params![source,next.saturating_sub(31)]).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(outcome(source,&selected,next))
    }

    /// Reading or reconnecting cannot create an activation or advance its epoch.
    pub(crate) fn presentation_resume(&self, source: &str, selected: &Activation) -> Result<Value> {
        valid(source)?; valid(&selected.operation_id)?;
        if selected.source!=source {return Err(error("PRESENTATION_SOURCE_CHANGED"));}
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        let generation=current(&db,source)?;
        if selected.generation<generation {return Ok(outcome(source,selected,generation));}
        if pending(&db,source,&group_members(&db,source)?)? {return Err(error("PRESENTATION_REBIND_PENDING"));}
        let (_,saved)=decision(&db,source,&selected.operation_id)?.ok_or_else(||error("PRESENTATION_ACTIVATION_UNKNOWN"))?;
        if &saved!=selected {return Err(error("PRESENTATION_ACTIVATION_MISMATCH"));}
        Ok(outcome(source,selected,current(&db,source)?))
    }

    pub(crate) fn presentation_managed(&self,source:&str)->Result<bool> {
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;managed(&db,source)
    }
    pub(crate) fn presentation_check(&self,admission:&Admission)->Result<()> {
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;admission.check(&db)
    }

    pub(crate) fn presentation_generation(&self, source: &str) -> Result<u64> {
        valid(source)?;
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        current(&db,source)
    }

    pub(crate) fn presentation_pending(&self,source:&str,members:&[String])->Result<bool> {
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        pending(&db,source,members)
    }

    /// Reserve only complete managed groups, retaining the sealed rebind ID.
    /// Empty source sets still fence new activation while custody is moving.
    pub(crate) fn presentation_rebind_reserve(&self,operation:&str,members:&[String])->Result<()> {
        valid(operation)?;members_valid(members)?;
        let mut db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_error)?;
        let mut same_terminal=0;
        for member in members {
            let prior:Option<(String,String)>=tx.query_row("SELECT operation,state FROM presentation_rebind_members WHERE member=?1",[member],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db_error)?;
            if let Some((saved,state))=prior {
                if saved==operation && state!="PENDING" {same_terminal+=1;}
                if saved!=operation && state=="PENDING" {return Err(error("PRESENTATION_REBIND_PENDING"));}
            }
        }
        if same_terminal==members.len() {return Ok(());}
        if same_terminal>0 {return Err(error("PRESENTATION_ORIGINAL_OPERATION_REQUIRED"));}
        selected_groups(&tx,members)?;
        for member in members {
            tx.execute("INSERT INTO presentation_rebind_members VALUES(?1,?2,'PENDING') ON CONFLICT(member) DO UPDATE SET operation=excluded.operation,state=excluded.state",params![member,operation]).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)
    }

    pub(crate) fn presentation_rebind_check(&self,members:&[String])->Result<()> {
        members_valid(members)?;
        let db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        selected_groups(&db,members).map(|_|())
    }

    /// Finish before the sealed owner clears its active job, so restart can
    /// always replay this idempotent fence transition from that original job.
    pub(crate) fn presentation_rebind_finish(&self,operation:&str,members:&[String],committed:bool)->Result<()> {
        valid(operation)?;members_valid(members)?;
        let mut db=self.db.lock().map_err(|_|error("NOTIFICATION_STATE_FAILED"))?;
        let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_error)?;
        let wanted=if committed{"COMMITTED"}else{"ABORTED"};
        let mut completed=0;
        for member in members {
            let saved:Option<(String,String)>=tx.query_row("SELECT operation,state FROM presentation_rebind_members WHERE member=?1",[member],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db_error)?;
            let Some((saved,state))=saved else{return Err(error("PRESENTATION_ORIGINAL_OPERATION_REQUIRED"));};
            if saved!=operation || (state!="PENDING"&&state!=wanted) {return Err(error("PRESENTATION_ORIGINAL_OPERATION_REQUIRED"));}
            if state==wanted {completed+=1;}
        }
        if completed==members.len() {return Ok(());}
        if completed>0 {return Err(error("PRESENTATION_STATE_INVALID"));}
        if committed {
            for source in selected_groups(&tx,members)? {
                let next=current(&tx,&source)?.checked_add(1).filter(|g|*g<=i64::MAX as u64).ok_or_else(||error("PRESENTATION_GENERATION_EXHAUSTED"))?;
                // Retire presentation only; the original rebind job owns all
                // destination, custody and ambiguous delivery facts.
                tx.execute("UPDATE presentation_sources SET generation=?2,operation_id=?3 WHERE source=?1",params![source,next,format!("rebind-{operation}")]).map_err(db_error)?;
                tx.execute("DELETE FROM presentation_group_members WHERE source=?1",[source]).map_err(db_error)?;
            }
        }
        for member in members {tx.execute("UPDATE presentation_rebind_members SET state=?2 WHERE member=?1",params![member,wanted]).map_err(db_error)?;}
        tx.commit().map_err(db_error)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_waiter_cannot_advance_batch_attempt_or_retry_deadline() {
        let root=crate::test_support::protected_test_dir();let store=Store::open(&root.path().join("state")).unwrap();
        let members=vec!["member".into()];let target=json!({"kind":"channel"});
        let first=store.presentation_replace("source",&members,"first",0,&target).unwrap();
        let old=Admission{source:"source".into(),members:members.clone(),activation:Some(serde_json::from_value(first["activation"].clone()).unwrap())};
        let wake=store.due_checked("owner",&[],1,Some(&old)).unwrap().unwrap();
        let second=store.presentation_replace("source",&members,"second",1,&target).unwrap();
        let current=Admission{source:"source".into(),members:members.clone(),activation:Some(serde_json::from_value(second["activation"].clone()).unwrap())};
        let before=store.status("owner").unwrap();
        let due=before["pending"]["retry_at"].as_i64().unwrap()+1;
        assert_eq!(store.due_checked("owner",&[],due,Some(&old)).unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
        assert_eq!(store.status("owner").unwrap(),before);
        let next=store.due_checked("owner",&[],due,Some(&current)).unwrap().unwrap();
        assert_eq!(next.batch,wake.batch);assert_eq!(next.revision,wake.revision);assert_eq!(next.attempt,wake.attempt+1);
        let before=store.status("owner").unwrap();
        store.presentation_rebind_reserve("move",&members).unwrap();
        assert_eq!(store.due_checked("owner",&[],due+100000,Some(&current)).unwrap_err().code,"PRESENTATION_REBIND_PENDING");
        assert_eq!(store.status("owner").unwrap(),before);
    }
    #[test]
    fn thousand_successors_prune_receipts_without_resurrecting_old_tokens() {
        let root=crate::test_support::protected_test_dir();let store=Store::open(&root.path().join("state")).unwrap();
        let members=vec!["member".into()];let target=json!({"kind":"channel"});
        let first=store.presentation_replace("source",&members,"first",0,&target).unwrap();
        let old:Activation=serde_json::from_value(first["activation"].clone()).unwrap();
        for generation in 1..=1000 {
            store.presentation_replace("source",&members,&format!("successor-{generation}"),generation,&target).unwrap();
        }
        assert_eq!(store.presentation_resume("source",&old).unwrap()["state"],"SUPERSEDED");
        assert_eq!(store.presentation_replace("source",&members,"first",0,&target).unwrap_err().code,"PRESENTATION_GENERATION_CONFLICT");
        let db=store.db.lock().unwrap();
        assert_eq!(db.query_row("SELECT count(*) FROM presentation_decisions",[],|r|r.get::<_,u64>(0)).unwrap(),32);
        assert_eq!(db.query_row("SELECT count(*) FROM presentation_sources",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(db.query_row("SELECT count(*) FROM presentation_group_members",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        drop(db);drop(store);let store=Store::open(&root.path().join("state")).unwrap();
        assert_eq!(store.presentation_resume("source",&old).unwrap()["state"],"SUPERSEDED");
    }
    #[test]
    fn group_overlap_is_rejected_and_rebind_fence_replays_without_retiring_a_successor() {
        let root=crate::test_support::protected_test_dir();let store=Store::open(&root.path().join("state")).unwrap();
        let members=vec!["a".into(),"b".into()];let target=json!({"kind":"channel"});
        let selected=store.presentation_replace("group",&members,"first",0,&target).unwrap();
        let old:Activation=serde_json::from_value(selected["activation"].clone()).unwrap();
        assert_eq!(store.presentation_replace("partial",&["a".into()],"partial",0,&target).unwrap_err().code,"PRESENTATION_GROUP_SELECTION_REQUIRED");
        assert_eq!(store.presentation_rebind_check(&["a".into()]).unwrap_err().code,"PRESENTATION_GROUP_SELECTION_REQUIRED");
        store.presentation_rebind_reserve("abort",&members).unwrap();
        assert_eq!(store.presentation_resume("group",&old).unwrap_err().code,"PRESENTATION_REBIND_PENDING");
        assert_eq!(store.presentation_replace("group",&members,"blocked",1,&target).unwrap_err().code,"PRESENTATION_REBIND_PENDING");
        store.presentation_rebind_finish("abort",&members,false).unwrap();
        assert_eq!(store.presentation_resume("group",&old).unwrap()["state"],"ACTIVE");
        store.presentation_rebind_reserve("commit",&members).unwrap();
        drop(store);let store=Store::open(&root.path().join("state")).unwrap();
        assert!(store.presentation_pending("group",&members).unwrap());
        store.presentation_rebind_finish("commit",&members,true).unwrap();
        assert_eq!(store.presentation_resume("group",&old).unwrap()["state"],"SUPERSEDED");
        assert!(!store.presentation_managed("group").unwrap());
        let host=Admission{source:"group".into(),members:members.clone(),activation:None};
        // The retired watermark fences old tokens without requiring a direct
        // host to invent a Channel/background activation after committed rebind.
        store.presentation_check(&host).unwrap();
        assert!(store.due_checked("direct-host-owner",&[],1,Some(&host)).unwrap().is_some());
        let next=store.presentation_replace("group",&members,"new",2,&target).unwrap();
        let next:Activation=serde_json::from_value(next["activation"].clone()).unwrap();
        assert!(store.presentation_managed("group").unwrap());
        assert_eq!(store.presentation_check(&host).unwrap_err().code,"PRESENTATION_ACTIVATION_REQUIRED");
        let partial=Admission{source:"partial".into(),members:vec!["a".into()],activation:None};
        assert_eq!(store.presentation_check(&partial).unwrap_err().code,"PRESENTATION_GROUP_SELECTION_REQUIRED");
        store.presentation_rebind_reserve("commit",&members).unwrap();
        store.presentation_rebind_finish("commit",&members,true).unwrap();
        assert_eq!(store.presentation_resume("group",&next).unwrap()["state"],"ACTIVE");
        for n in 0..1000 {
            let operation=format!("abort-{n}");
            store.presentation_rebind_reserve(&operation,&members).unwrap();
            store.presentation_rebind_finish(&operation,&members,false).unwrap();
        }
        assert_eq!(store.db.lock().unwrap().query_row("SELECT count(*) FROM presentation_rebind_members",[],|r|r.get::<_,u64>(0)).unwrap(),2);
    }
    #[test]
    fn successor_is_cas_idempotent_and_old_resume_cannot_reclaim() {
        let root=crate::test_support::protected_test_dir();
        let store=Store::open(&root.path().join("state")).unwrap();let target=json!({"kind":"channel","thread":"exact"});
        let first=store.presentation_replace("source",&["member".into()],"first",0,&target).unwrap();
        let old:Activation=serde_json::from_value(first["activation"].clone()).unwrap();
        assert_eq!(store.presentation_replace("source",&["member".into()],"first",0,&target).unwrap(),first);
        assert_eq!(store.presentation_replace("source",&["member".into()],"loser",0,&target).unwrap_err().code,"PRESENTATION_GENERATION_CONFLICT");
        let second=store.presentation_replace("source",&["member".into()],"second",1,&target).unwrap();
        assert_eq!(second["current_generation"],2);
        assert_eq!(store.presentation_resume("source",&old).unwrap()["state"],"SUPERSEDED");
        assert_eq!(store.presentation_replace("source",&["member".into()],"first",0,&target).unwrap()["state"],"SUPERSEDED");
        assert_eq!(store.presentation_replace("source",&["member".into()],"first",2,&target).unwrap_err().code,"PRESENTATION_ORIGINAL_OPERATION_REQUIRED");
        assert_eq!(store.presentation_generation("unrelated").unwrap(),0);
        drop(store);let store=Store::open(&root.path().join("state")).unwrap();
        assert_eq!(store.presentation_generation("source").unwrap(),2);
        assert_eq!(store.presentation_resume("source",&old).unwrap()["state"],"SUPERSEDED");
    }
    #[test]
    fn activation_does_not_reset_notification_pause_or_batches() {
        let root=crate::test_support::protected_test_dir();let store=Store::open(&root.path().join("state")).unwrap();
        store.control("destination","pause").unwrap();let before=store.status("destination").unwrap();
        store.presentation_replace("source",&["member".into()],"one",0,&json!({"kind":"channel"})).unwrap();
        store.presentation_replace("source",&["member".into()],"two",1,&json!({"kind":"channel"})).unwrap();
        assert_eq!(store.status("destination").unwrap(),before);
    }
    #[test]
    fn racing_successors_commit_once_and_forged_resume_cannot_select_another_source() {
        let root=crate::test_support::protected_test_dir();
        let store=std::sync::Arc::new(Store::open(&root.path().join("state")).unwrap());
        let barrier=std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles=["left","right"].map(|operation| {
            let store=store.clone();let barrier=barrier.clone();
            std::thread::spawn(move || {barrier.wait();store.presentation_replace("source",&["member".into()],operation,0,&json!({"kind":"channel"}))})
        });
        let results=handles.map(|handle|handle.join().unwrap());
        assert_eq!(results.iter().filter(|r|r.is_ok()).count(),1);
        assert_eq!(results.iter().filter(|r|r.as_ref().is_err_and(|e|e.code=="PRESENTATION_GENERATION_CONFLICT")).count(),1);
        let selected:Activation=serde_json::from_value(results.iter().find_map(|r|r.as_ref().ok()).unwrap()["activation"].clone()).unwrap();
        assert_eq!(store.presentation_resume("different-source",&selected).unwrap_err().code,"PRESENTATION_SOURCE_CHANGED");
        let mut forged=selected.clone();forged.target=json!({"kind":"different"});
        assert_eq!(store.presentation_resume("source",&forged).unwrap_err().code,"PRESENTATION_ACTIVATION_MISMATCH");
        assert_eq!(store.presentation_generation("source").unwrap(),1);
    }
    #[test]
    fn successor_fences_queued_output_without_resetting_the_original_batch() {
        let root=crate::test_support::protected_test_dir();let store=Store::open(&root.path().join("state")).unwrap();
        let target=json!({"kind":"channel"});
        let first=store.presentation_replace("source",&["member".into()],"first",0,&target).unwrap();
        let old:Activation=serde_json::from_value(first["activation"].clone()).unwrap();
        let wake=store.due("owner",&[],1).unwrap().unwrap();
        assert!(store.presentation_notification_allowed("source",&["member".into()],Some(&old),"owner",&wake.batch,wake.revision).unwrap());
        let before=store.status("owner").unwrap();
        let second=store.presentation_replace("source",&["member".into()],"second",1,&target).unwrap();
        let current:Activation=serde_json::from_value(second["activation"].clone()).unwrap();
        assert_eq!(store.status("owner").unwrap(),before);
        assert_eq!(store.presentation_notification_allowed("source",&["member".into()],Some(&old),"owner",&wake.batch,wake.revision).unwrap_err().code,"PRESENTATION_ACTIVATION_SUPERSEDED");
        assert_eq!(store.presentation_notification_allowed("source",&["member".into()],None,"owner",&wake.batch,wake.revision).unwrap_err().code,"PRESENTATION_ACTIVATION_REQUIRED");
        assert!(store.presentation_notification_allowed("source",&["member".into()],Some(&current),"owner",&wake.batch,wake.revision).unwrap());
        store.control("owner","pause").unwrap();
        assert!(!store.presentation_notification_allowed("source",&["member".into()],Some(&current),"owner",&wake.batch,wake.revision).unwrap());
    }
}
