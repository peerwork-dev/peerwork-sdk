//! Protected, indexed body keys. This local cache neither grants workspace
//! membership nor publishes/delivers keys to another actor or browser.
use super::{ensure_private_parent,create_or_check_private_file,set_wal_with_retry};
use crate::{secure_state::read_private_seed_file,transport::{canonical_lifecycle_origin,TransportConfig}};
use peerwork_core::structure_content::{StructureContentContext,StructureSealedContent,StructureContentError,
    seal_structure_content,open_structure_content,structure_content_key_id};
use rand_core::{OsRng,RngCore};
use rusqlite::{params,Connection,OptionalExtension,TransactionBehavior};
use serde::Serialize;
use std::{path::Path,time::Duration};
use thiserror::Error;
use zeroize::Zeroizing;

const APPLICATION_ID:i64=0x5057_434b; // PWCK, never the transport journal.
const KEYS:&str="CREATE TABLE content_keys(local_key_id TEXT NOT NULL,workspace_id TEXT NOT NULL,key_id TEXT NOT NULL,secret BLOB NOT NULL CHECK(length(secret)=32),PRIMARY KEY(local_key_id,workspace_id,key_id)) WITHOUT ROWID";
const HEADS:&str="CREATE TABLE content_key_heads(local_key_id TEXT NOT NULL,workspace_id TEXT NOT NULL,key_id TEXT NOT NULL,PRIMARY KEY(local_key_id,workspace_id),FOREIGN KEY(local_key_id,workspace_id,key_id) REFERENCES content_keys(local_key_id,workspace_id,key_id)) WITHOUT ROWID";
const REMOTE_HEADS:&str="CREATE TABLE content_key_remote_heads(local_key_id TEXT NOT NULL,workspace_id TEXT NOT NULL,owner_id TEXT NOT NULL,epoch INTEGER NOT NULL,key_id TEXT NOT NULL,intent_digest TEXT NOT NULL,PRIMARY KEY(local_key_id,workspace_id)) WITHOUT ROWID";
const COORDINATOR:&str="CREATE TABLE content_key_coordinator(id INTEGER PRIMARY KEY CHECK(id=1),public_id TEXT NOT NULL)";
const STAGES:&str="CREATE TABLE content_key_delivery_stages(local_key_id TEXT NOT NULL,workspace_id TEXT NOT NULL,journal_namespace TEXT NOT NULL,epoch INTEGER NOT NULL,revision INTEGER NOT NULL,command_id TEXT NOT NULL,PRIMARY KEY(local_key_id,workspace_id,journal_namespace,epoch)) WITHOUT ROWID";
const HISTORY_STAGES:&str="CREATE TABLE content_key_history_stages(local_key_id TEXT NOT NULL,workspace_id TEXT NOT NULL,journal_namespace TEXT NOT NULL,job_id TEXT NOT NULL,revision INTEGER NOT NULL,command_id TEXT NOT NULL,PRIMARY KEY(local_key_id,workspace_id,journal_namespace,job_id)) WITHOUT ROWID";
const HISTORY_WORKER:&str="CREATE TABLE content_key_history_worker(local_key_id TEXT NOT NULL,workspace_id TEXT NOT NULL,journal_namespace TEXT NOT NULL,after_job TEXT NOT NULL,PRIMARY KEY(local_key_id,workspace_id,journal_namespace)) WITHOUT ROWID";
const BINDING:&str="CREATE TABLE content_key_binding(id INTEGER PRIMARY KEY CHECK(id=1),origin TEXT NOT NULL)";

#[derive(Debug,Error)]
pub enum ContentKeyError {
    #[error("body-key origin or selection is invalid")]
    Selection,
    #[error("body key is not available for this local identity and workspace")]
    Missing,
    #[error("workspace body-key rotation is required before encrypting new content")]
    RotationRequired,
    #[error("canonical body-key epoch or Owner rolled back or equivocated")]
    HeadRollback,
    #[error("selected body key or schema failed integrity validation")]
    Integrity,
    #[error("body-key origin differs from the protected binding")]
    OriginChanged,
    #[error("current local body key changed; reopen the selected operation")]
    Conflict,
    #[error("protected body-key state is unavailable")]
    Protection,
    #[error("body-key storage failed")]
    Storage(#[from]rusqlite::Error),
    #[error("OS random source failed")]
    Entropy,
    #[error(transparent)]
    Content(#[from]StructureContentError),
}
#[derive(Debug,Clone,Serialize,PartialEq,Eq)]
pub struct ContentKeyInfo {pub workspace_id:String,pub key_id:String}
#[derive(Clone)]
pub(crate) struct ContentDeliveryStage {pub epoch:u64,pub revision:u64,pub command_id:String}
#[derive(Clone)]
pub(crate) struct HistoryDeliveryStage{pub job_id:String,pub revision:u64,pub command_id:String}
pub struct StructureContentKeys {db:Connection}
fn token(v:&str)->bool{v.len()==43&&v.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'))}
fn scope(key:&str,workspace:&str)->Result<(),ContentKeyError>{
    if !token(key)||!token(workspace){return Err(ContentKeyError::Selection);}Ok(())
}
fn current(db:&Connection,key:&str,workspace:&str)->Result<Option<String>,ContentKeyError>{
    Ok(db.query_row("SELECT key_id FROM content_key_heads WHERE local_key_id=?1 AND workspace_id=?2",
        params![key,workspace],|r|r.get(0)).optional()?)
}
fn load(db:&Connection,local:&str,workspace:&str,id:&str)->Result<Zeroizing<[u8;32]>,ContentKeyError>{
    scope(local,workspace)?;if !token(id){return Err(ContentKeyError::Selection);}
    let raw:Option<Vec<u8>>=db.query_row("SELECT secret FROM content_keys WHERE local_key_id=?1 AND workspace_id=?2 AND key_id=?3",
        params![local,workspace,id],|r|r.get(0)).optional()?;
    let raw=Zeroizing::new(raw.ok_or(ContentKeyError::Missing)?);
    if raw.len()!=32{return Err(ContentKeyError::Integrity);}
    let mut secret=Zeroizing::new([0;32]);secret.copy_from_slice(&raw);
    if structure_content_key_id(&secret)!=id{return Err(ContentKeyError::Integrity);}Ok(secret)
}
impl StructureContentKeys {
    pub fn open(path:&Path,transport:TransportConfig)->Result<Self,ContentKeyError>{
        // This is a protected local database, not a network client. Normalize
        // the same Origin without rebuilding TLS roots/pools on every key read.
        let origin=canonical_lifecycle_origin(&transport.origin,transport.allow_loopback_http).map_err(|_|ContentKeyError::Selection)?;
        ensure_private_parent(path).map_err(|_|ContentKeyError::Protection)?;
        create_or_check_private_file(path).map_err(|_|ContentKeyError::Protection)?;
        #[cfg(windows)]
        {super::check_private_sidecars(path).map_err(|_|ContentKeyError::Protection)?;
        super::create_missing_private_wal_sidecars(path).map_err(|_|ContentKeyError::Protection)?;}
        let mut db=Connection::open(path)?;db.busy_timeout(Duration::from_secs(5))?;
        let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let app:i64=tx.pragma_query_value(None,"application_id",|r|r.get(0))?;
        let version:i64=tx.pragma_query_value(None,"user_version",|r|r.get(0))?;
        let objects=|db:&Connection|->Result<Vec<(String,String,String)>,rusqlite::Error>{
            db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?
                .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect()
        };
        let before=objects(&tx)?;
        if app==0&&version==0&&before.is_empty(){
            tx.execute_batch(&format!("{KEYS};{HEADS};{BINDING};{REMOTE_HEADS};{COORDINATOR};{STAGES};PRAGMA application_id={APPLICATION_ID};PRAGMA user_version=3;"))?;
            tx.execute("INSERT INTO content_key_binding VALUES(1,?1)",[&origin])?;
        }else if app!=APPLICATION_ID||![1,2,3,4].contains(&version){return Err(ContentKeyError::Integrity);}
        let mut expected=vec![("table".into(),"content_key_binding".into(),BINDING.into()),
            ("table".into(),"content_key_heads".into(),HEADS.into()),("table".into(),"content_keys".into(),KEYS.into())];
        if app==APPLICATION_ID&&version==1{
            if objects(&tx)?!=expected{return Err(ContentKeyError::Integrity);}
            tx.execute_batch(&format!("{REMOTE_HEADS};PRAGMA user_version=2;"))?;
        }
        expected.push(("table".into(),"content_key_remote_heads".into(),REMOTE_HEADS.into()));expected.sort();
        if app==APPLICATION_ID&&version<=2{
            if objects(&tx)?!=expected{return Err(ContentKeyError::Integrity);}
            tx.execute_batch(&format!("{COORDINATOR};{STAGES};PRAGMA user_version=3;"))?;
        }
        expected.push(("table".into(),"content_key_coordinator".into(),COORDINATOR.into()));expected.push(("table".into(),"content_key_delivery_stages".into(),STAGES.into()));expected.sort();
        if version<4{
            if objects(&tx)?!=expected{return Err(ContentKeyError::Integrity);}
            tx.execute_batch(&format!("{HISTORY_STAGES};{HISTORY_WORKER};PRAGMA user_version=4;"))?;
        }
        expected.push(("table".into(),"content_key_history_stages".into(),HISTORY_STAGES.into()));expected.push(("table".into(),"content_key_history_worker".into(),HISTORY_WORKER.into()));expected.sort();
        if objects(&tx)?!=expected{return Err(ContentKeyError::Integrity);}
        if tx.query_row("SELECT public_id FROM content_key_coordinator WHERE id=1",[],|r|r.get::<_,String>(0)).optional()?.is_none(){let mut public=[0;32];OsRng.try_fill_bytes(&mut public).map_err(|_|ContentKeyError::Entropy)?;tx.execute("INSERT INTO content_key_coordinator VALUES(1,?1)",[peerwork_core::crypto::base64url(&public)])?;}
        let prior:String=tx.query_row("SELECT origin FROM content_key_binding WHERE id=1",[],|r|r.get(0))?;
        if prior!=origin{return Err(ContentKeyError::OriginChanged);}
        tx.commit()?;set_wal_with_retry(&db).map_err(|_|ContentKeyError::Protection)?;
        #[cfg(windows)]
        super::check_private_sidecars(path).map_err(|_|ContentKeyError::Protection)?;
        db.pragma_update(None,"synchronous","FULL")?;db.pragma_update(None,"foreign_keys","ON")?;
        Ok(Self{db})
    }

    /// Pin only an authenticated selected epoch, never a historical key grant.
    /// This fixed-size row prevents replaying an older Owner-signed selection
    /// after this identity has observed a newer one.
    pub(crate) fn pin_remote_head(&mut self,local:&str,workspace:&str,head:Option<(&str,u64,&str,&str)>)->Result<(),ContentKeyError>{
        scope(local,workspace)?;let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior:Option<(String,u64,String,String)>=tx.query_row("SELECT owner_id,epoch,key_id,intent_digest FROM content_key_remote_heads WHERE local_key_id=?1 AND workspace_id=?2",params![local,workspace],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((owner,epoch,id,digest))=head{
            if !token(owner)||!token(id)||epoch==0||epoch>9_007_199_254_740_991||digest.len()!=64||!digest.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f')){return Err(ContentKeyError::Integrity);}
            if prior.as_ref().is_some_and(|p|p.0!=owner||epoch<p.1||epoch==p.1&&(p.2!=id||p.3!=digest)){return Err(ContentKeyError::HeadRollback);}
            tx.execute("INSERT INTO content_key_remote_heads VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(local_key_id,workspace_id) DO UPDATE SET owner_id=excluded.owner_id,epoch=excluded.epoch,key_id=excluded.key_id,intent_digest=excluded.intent_digest",params![local,workspace,owner,epoch,id,digest])?;
        }else if prior.is_some(){return Err(ContentKeyError::HeadRollback);}
        tx.commit()?;Ok(())
    }

    pub(crate) fn coordinator_scope(&self,namespace:&str)->Result<String,ContentKeyError>{let id:String=self.db.query_row("SELECT public_id FROM content_key_coordinator WHERE id=1",[],|r|r.get(0))?;Ok(peerwork_core::crypto::sha256_hex(format!("{id}\0{namespace}").as_bytes()))}
    pub(crate) fn delivery_stage(&self,local:&str,ws:&str,namespace:&str)->Result<Option<ContentDeliveryStage>,ContentKeyError>{
        scope(local,ws)?;Ok(self.db.query_row("SELECT epoch,revision,command_id FROM content_key_delivery_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 ORDER BY epoch LIMIT 1",params![local,ws,namespace],|r|Ok(ContentDeliveryStage{epoch:r.get(0)?,revision:r.get(1)?,command_id:r.get(2)?})).optional()?)
    }
    pub(crate) fn prepare_delivery_stage(&mut self,local:&str,ws:&str,namespace:&str,epoch:u64,revision:u64)->Result<ContentDeliveryStage,ContentKeyError>{
        scope(local,ws)?;let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id:String=tx.query_row("SELECT public_id FROM content_key_coordinator WHERE id=1",[],|r|r.get(0))?;
        // Namespace separation prevents two journals sharing an identity cache
        // from assigning the same command ID to independently randomized boxes.
        let mut nonce=[0;32];OsRng.try_fill_bytes(&mut nonce).map_err(|_|ContentKeyError::Entropy)?;
        let command=peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(format!("peerwork.key-delivery-stage.v1\0{id}\0{namespace}\0{}",peerwork_core::crypto::base64url(&nonce)).as_bytes()));
        tx.execute("INSERT OR IGNORE INTO content_key_delivery_stages VALUES(?1,?2,?3,?4,?5,?6)",params![local,ws,namespace,epoch,revision,command])?;
        let stage=tx.query_row("SELECT epoch,revision,command_id FROM content_key_delivery_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 AND epoch=?4",params![local,ws,namespace,epoch],|r|Ok(ContentDeliveryStage{epoch:r.get(0)?,revision:r.get(1)?,command_id:r.get(2)?}))?;tx.commit()?;Ok(stage)
    }
    pub(crate) fn clear_delivery_stage(&mut self,local:&str,ws:&str,namespace:&str,id:&str)->Result<(),ContentKeyError>{scope(local,ws)?;self.db.execute("DELETE FROM content_key_delivery_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 AND command_id=?4",params![local,ws,namespace,id])?;Ok(())}
    pub(crate) fn seal_current_delivery(&self,local:&str,ws:&str,request:&peerwork_core::structure_access::VerifiedAccessRequest,recipient:&peerwork_core::structure_key_delivery::CurrentKeyRecipient,audience:&str,owner:&str,epoch:u64,key_id:&str)->Result<peerwork_core::structure_key_delivery::CurrentKeyEnvelope,ContentKeyError>{
        let secret=load(&self.db,local,ws,key_id)?;peerwork_core::structure_key_delivery::seal_current_key(request,recipient,audience,ws,owner,epoch,&secret).map_err(|_|ContentKeyError::Integrity)
    }

    /// Explicit local initialization only; never rotates an existing key or
    /// claims other members can decrypt it. Remote key delivery is separate.
    pub(crate) fn history_stages(&self,local:&str,ws:&str,namespace:&str)->Result<Vec<HistoryDeliveryStage>,ContentKeyError>{
        scope(local,ws)?;Ok(self.db.prepare("SELECT job_id,revision,command_id FROM content_key_history_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 ORDER BY job_id LIMIT 32")?.query_map(params![local,ws,namespace],|r|Ok(HistoryDeliveryStage{job_id:r.get(0)?,revision:r.get(1)?,command_id:r.get(2)?}))?.collect::<Result<_,_>>()?)
    }
    pub(crate) fn history_stage(&self,local:&str,ws:&str,namespace:&str,job:&str)->Result<Option<HistoryDeliveryStage>,ContentKeyError>{scope(local,ws)?;Ok(self.db.query_row("SELECT job_id,revision,command_id FROM content_key_history_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 AND job_id=?4",params![local,ws,namespace,job],|r|Ok(HistoryDeliveryStage{job_id:r.get(0)?,revision:r.get(1)?,command_id:r.get(2)?})).optional()?)}
    pub(crate) fn prepare_history_stage(&mut self,local:&str,ws:&str,namespace:&str,job:&str,revision:u64)->Result<HistoryDeliveryStage,ContentKeyError>{
        scope(local,ws)?;if !token(job){return Err(ContentKeyError::Selection);}
        let mut random=[0;32];OsRng.try_fill_bytes(&mut random).map_err(|_|ContentKeyError::Entropy)?;let command=peerwork_core::crypto::base64url(&random);
        self.db.execute("INSERT INTO content_key_history_stages VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT DO NOTHING",params![local,ws,namespace,job,revision,command])?;
        Ok(self.db.query_row("SELECT job_id,revision,command_id FROM content_key_history_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 AND job_id=?4",params![local,ws,namespace,job],|r|Ok(HistoryDeliveryStage{job_id:r.get(0)?,revision:r.get(1)?,command_id:r.get(2)?}))?)
    }
    pub(crate) fn clear_history_stage(&mut self,local:&str,ws:&str,namespace:&str,command:&str)->Result<(),ContentKeyError>{scope(local,ws)?;self.db.execute("DELETE FROM content_key_history_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3 AND command_id=?4",params![local,ws,namespace,command])?;Ok(())}
    pub(crate) fn has_history_stage(&self,local:&str,ws:&str,namespace:&str)->Result<bool,ContentKeyError>{scope(local,ws)?;Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM content_key_history_stages WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3)",params![local,ws,namespace],|r|r.get(0))?)}
    pub(crate) fn history_after(&self,local:&str,ws:&str,namespace:&str)->Result<String,ContentKeyError>{scope(local,ws)?;Ok(self.db.query_row("SELECT after_job FROM content_key_history_worker WHERE local_key_id=?1 AND workspace_id=?2 AND journal_namespace=?3",params![local,ws,namespace],|r|r.get(0)).optional()?.unwrap_or_default())}
    pub(crate) fn set_history_after(&mut self,local:&str,ws:&str,namespace:&str,after:&str)->Result<(),ContentKeyError>{scope(local,ws)?;if !after.is_empty()&&!token(after){return Err(ContentKeyError::Selection);}self.db.execute("INSERT INTO content_key_history_worker VALUES(?1,?2,?3,?4) ON CONFLICT(local_key_id,workspace_id,journal_namespace) DO UPDATE SET after_job=excluded.after_job",params![local,ws,namespace,after])?;Ok(())}
    pub(crate) fn seal_history_delivery(&self,local:&str,ws:&str,authority:&peerwork_core::structure_retained_keys::VerifiedRetainedAuthority,epochs:&[peerwork_core::structure_retained_keys::VerifiedRetainedEpoch],audience:&str,owner:&str,job:&str)->Result<peerwork_core::structure_retained_keys::RetainedKeyEnvelope,ContentKeyError>{
        scope(local,ws)?;let mut keys=Vec::new();for epoch in epochs{let id=&epoch.entry().key_id;keys.push(peerwork_core::structure_access::AccessKeyMaterial::new(id.clone(),load(&self.db,local,ws,id)?).map_err(|_|ContentKeyError::Integrity)?);}
        peerwork_core::structure_retained_keys::seal_retained_keys(authority,epochs,&keys,audience,ws,owner,job).map_err(|_|ContentKeyError::Integrity)
    }
    pub fn ensure_current(&mut self,local:&str,workspace:&str)->Result<ContentKeyInfo,ContentKeyError>{
        scope(local,workspace)?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id=if let Some(id)=current(&tx,local,workspace)?{let _=load(&tx,local,workspace,&id)?;id}else{
            let mut secret=Zeroizing::new([0;32]);OsRng.try_fill_bytes(&mut *secret).map_err(|_|ContentKeyError::Entropy)?;
            let id=structure_content_key_id(&secret);
            tx.execute("INSERT INTO content_keys VALUES(?1,?2,?3,?4)",params![local,workspace,id,&secret[..]])?;
            tx.execute("INSERT INTO content_key_heads VALUES(?1,?2,?3)",params![local,workspace,id])?;id
        };
        tx.commit()?;Ok(ContentKeyInfo{workspace_id:workspace.into(),key_id:id})
    }

    /// A protected import is not proof of remote authority or key provenance.
    /// The caller supplies its authenticated selection and expected key ID.
    pub fn import_current_from_file(&mut self,local:&str,workspace:&str,source:&Path,id:&str,expected_current:Option<&str>)
        ->Result<ContentKeyInfo,ContentKeyError>{
        let secret=read_private_seed_file(source).map_err(|_|ContentKeyError::Protection)?.ok_or(ContentKeyError::Integrity)?;
        self.retain_current(local,workspace,&secret,id,expected_current)
    }
    pub(crate) fn retain_current(&mut self,local:&str,workspace:&str,secret:&[u8;32],id:&str,expected_current:Option<&str>)
        ->Result<ContentKeyInfo,ContentKeyError>{
        scope(local,workspace)?;if structure_content_key_id(secret)!=id{return Err(ContentKeyError::Integrity);}
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior=current(&tx,local,workspace)?;
        if prior.as_deref()!=expected_current&&prior.as_deref()!=Some(id){return Err(ContentKeyError::Conflict);}
        tx.execute("INSERT OR IGNORE INTO content_keys VALUES(?1,?2,?3,?4)",params![local,workspace,id,&secret[..]])?;
        let checked=load(&tx,local,workspace,id)?;
        if &*checked!=secret{return Err(ContentKeyError::Integrity);}
        tx.execute("INSERT INTO content_key_heads VALUES(?1,?2,?3) ON CONFLICT(local_key_id,workspace_id) DO UPDATE SET key_id=excluded.key_id",params![local,workspace,id])?;
        tx.commit()?;Ok(ContentKeyInfo{workspace_id:workspace.into(),key_id:id.into()})
    }
    /// Package only explicitly selected cached keys plus the current key. The
    /// plaintext never crosses a binding or appears in an operation journal.
    pub(crate) fn package_access_keys(&self,local:&str,workspace:&str,request:&peerwork_core::structure_access::VerifiedAccessRequest,
        audience:&str,owner:&str,selected:&[String])->Result<peerwork_core::structure_access::AccessContentGrant,ContentKeyError>{
        scope(local,workspace)?;
        if request.request().workspace_id!=workspace||selected.len()>32||selected.iter().any(|id|!token(id)){
            return Err(ContentKeyError::Selection);
        }
        let mut ids=selected.to_vec();ids.sort();if ids.windows(2).any(|w|w[0]==w[1]){return Err(ContentKeyError::Selection);}
        let head=self.selected(local,workspace)?;
        if !ids.contains(&head.key_id){ids.push(head.key_id.clone());ids.sort();}
        if ids.len()>32{return Err(ContentKeyError::Selection);}
        let mut keys=Vec::with_capacity(ids.len());
        for id in ids{keys.push(peerwork_core::structure_access::AccessKeyMaterial::new(id.clone(),load(&self.db,local,workspace,&id)?)
            .map_err(|_|ContentKeyError::Integrity)?);}
        peerwork_core::structure_access::seal_access_keys(request,audience,owner,&keys,&head.key_id).map_err(|_|ContentKeyError::Integrity)
    }

    /// Import an already authenticated grant atomically. Historical key reads
    /// retain decryption material without changing a newer current selection.
    /// The source signature/Owner/recipient must be verified by core first.
    pub(crate) fn retain_access_keys(&mut self,local:&str,workspace:&str,opened:&peerwork_core::structure_access::OpenedAccessKeys,
        select_current:bool,expected_current:Option<&str>)->Result<Vec<ContentKeyInfo>,ContentKeyError>{
        scope(local,workspace)?;
        if opened.keys.is_empty()||opened.keys.len()>32||!opened.keys.iter().any(|k|k.key_id()==opened.current_key_id){return Err(ContentKeyError::Integrity);}
        let mut unique=std::collections::BTreeSet::new();
        for key in &opened.keys{if !unique.insert(key.key_id())||structure_content_key_id(key.secret())!=key.key_id(){return Err(ContentKeyError::Integrity);}}
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior=current(&tx,local,workspace)?;
        if select_current&&prior.as_deref()!=expected_current&&prior.as_deref()!=Some(opened.current_key_id.as_str()){return Err(ContentKeyError::Conflict);}
        for key in &opened.keys{
            tx.execute("INSERT OR IGNORE INTO content_keys VALUES(?1,?2,?3,?4)",params![local,workspace,key.key_id(),&key.secret()[..]])?;
            if &*load(&tx,local,workspace,key.key_id())?!=key.secret(){return Err(ContentKeyError::Integrity);}
        }
        if select_current{tx.execute("INSERT INTO content_key_heads VALUES(?1,?2,?3) ON CONFLICT(local_key_id,workspace_id) DO UPDATE SET key_id=excluded.key_id",params![local,workspace,opened.current_key_id])?;}
        tx.commit()?;Ok(opened.keys.iter().map(|key|ContentKeyInfo{workspace_id:workspace.into(),key_id:key.key_id().into()}).collect())
    }
    /// Retain an unpublished random candidate without changing the selected
    /// key. The saved signed intent owns retries; a failed publication cannot
    /// silently select an unaccepted epoch.
    pub(crate) fn create_candidate(&mut self,local:&str,workspace:&str)->Result<ContentKeyInfo,ContentKeyError>{
        scope(local,workspace)?;let mut secret=Zeroizing::new([0;32]);
        OsRng.try_fill_bytes(&mut *secret).map_err(|_|ContentKeyError::Entropy)?;
        let id=structure_content_key_id(&secret);
        self.db.execute("INSERT INTO content_keys VALUES(?1,?2,?3,?4)",params![local,workspace,id,&secret[..]])?;
        Ok(ContentKeyInfo{workspace_id:workspace.into(),key_id:id})
    }
    pub(crate) fn select_retained(&mut self,local:&str,workspace:&str,id:&str,expected:Option<&str>)->Result<ContentKeyInfo,ContentKeyError>{
        let secret=load(&self.db,local,workspace,id)?;self.retain_current(local,workspace,&secret,id,expected)
    }
    pub(crate) fn contains_retained(&self,local:&str,workspace:&str,id:&str)->Result<bool,ContentKeyError>{
        match load(&self.db,local,workspace,id){Ok(_)=>Ok(true),Err(ContentKeyError::Missing)=>Ok(false),Err(e)=>Err(e)}
    }
    pub fn selected(&self,local:&str,workspace:&str)->Result<ContentKeyInfo,ContentKeyError>{
        scope(local,workspace)?;let id=current(&self.db,local,workspace)?.ok_or(ContentKeyError::Missing)?;
        let _=load(&self.db,local,workspace,&id)?;Ok(ContentKeyInfo{workspace_id:workspace.into(),key_id:id})
    }
    pub fn seal(&self,local:&str,plaintext:&[u8],context:&StructureContentContext)
        ->Result<StructureSealedContent,ContentKeyError>{
        let id=current(&self.db,local,&context.workspace_id)?.ok_or(ContentKeyError::Missing)?;
        let secret=load(&self.db,local,&context.workspace_id,&id)?;
        Ok(seal_structure_content(&secret,plaintext,context)?)
    }
    pub fn open_body(&self,local:&str,sealed:&StructureSealedContent,context:&StructureContentContext)
        ->Result<Zeroizing<Vec<u8>>,ContentKeyError>{
        let secret=load(&self.db,local,&context.workspace_id,&sealed.key_id)?;
        Ok(open_structure_content(&secret,sealed,context)?)
    }
    /// A retained, previously verified remote selection is sufficient to
    /// construct a candidate. The service still rejects stale epochs atomically;
    /// this cache is never a claim that today's remote head is unchanged.
    pub(crate) fn has_pinned_selected(&self,local:&str,workspace:&str)->Result<bool,ContentKeyError>{
        let selected=match self.selected(local,workspace){Ok(v)=>v,Err(ContentKeyError::Missing)=>return Ok(false),Err(e)=>return Err(e)};
        let pinned:Option<String>=self.db.query_row("SELECT key_id FROM content_key_remote_heads WHERE local_key_id=?1 AND workspace_id=?2",params![local,workspace],|r|r.get(0)).optional()?;
        Ok(pinned.as_deref()==Some(selected.key_id.as_str()))
    }
    pub(crate) fn invalidate_selected(&mut self,local:&str,workspace:&str,stale_key:&str)->Result<(),ContentKeyError>{
        scope(local,workspace)?;
        // Retain the remote continuity pin and all decryption material. A
        // concurrent newer selection must not be invalidated by an old reply.
        self.db.execute("DELETE FROM content_key_heads WHERE local_key_id=?1 AND workspace_id=?2 AND key_id=?3",params![local,workspace,stale_key])?;
        Ok(())
    }
    pub fn seal_message(&self,local:&str,plaintext:&[u8],context:&peerwork_core::communication::MessageContentContext)
        ->Result<StructureSealedContent,ContentKeyError>{
        let id=current(&self.db,local,&context.workspace_id)?.ok_or(ContentKeyError::Missing)?;
        let secret=load(&self.db,local,&context.workspace_id,&id)?;
        Ok(peerwork_core::communication::seal_message_content(&secret,plaintext,context)?)
    }
    pub fn open_message(&self,local:&str,author:&peerwork_core::prepared_command::VerifiedStructureAuthorIntent)
        ->Result<Zeroizing<Vec<u8>>,ContentKeyError>{
        let (context,content)=peerwork_core::communication::authored_message_content(author).map_err(|_|ContentKeyError::Integrity)?;
        let peerwork_core::communication::MessageContent::WorkspaceE2ee{body}=content else{return Err(ContentKeyError::Selection);};
        let secret=load(&self.db,local,&context.workspace_id,&body.key_id)?;
        Ok(peerwork_core::communication::open_message_content(&secret,&body,&context)?)
    }
    pub fn open_authored_body(&self,local:&str,author:&peerwork_core::prepared_command::VerifiedStructureAuthorIntent,index:u8)
        ->Result<Zeroizing<Vec<u8>>,ContentKeyError>{
        let (context,sealed)=peerwork_core::structure_content::authored_structure_content(author,index)?;
        self.open_body(local,&sealed,&context)
    }
}

#[cfg(all(test,unix))]
mod tests {
    use super::*;
    use std::{fs,os::unix::fs::PermissionsExt};
    fn config()->TransportConfig{TransportConfig::new("https://example.invalid")}
    fn context()->StructureContentContext{StructureContentContext{workspace_id:"W".repeat(43),instance_id:"I".repeat(43),
        protocol_digest:"a".repeat(64),actor_id:"A".repeat(43),command_id:"C".repeat(43),action_id:"post".into(),record_index:0}}
    fn opened_access_fixture()->peerwork_core::structure_access::OpenedAccessKeys{
        let vector:serde_json::Value=serde_json::from_str(include_str!("../../../tests/fixtures/structure-access-v1.json")).unwrap();
        let author=peerwork_core::prepared_command::verify_structure_author_intent(vector["owner_jws"].as_str().unwrap(),&"structure-test".encode_utf16().collect::<Vec<_>>()).unwrap();
        let recipient=peerwork_core::secure_recipient::SecretRecipient::from_private(Zeroizing::new([4;32])).unwrap();
        peerwork_core::structure_access::open_owner_access_keys(&author,vector["owner_id"].as_str().unwrap(),vector["actor_id"].as_str().unwrap(),&recipient,&peerwork_core::crypto::base64url(&[3;32]),"structure-test",vector["service_key"].as_str().unwrap()).unwrap()
    }
    #[test]
    fn authenticated_access_keys_import_atomically_and_do_not_reset_newer_current_key(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("body.sqlite");
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();let local="A".repeat(43);let workspace=peerwork_core::crypto::base64url(&[3;32]);let opened=opened_access_fixture();
        let first=keys.retain_access_keys(&local,&workspace,&opened,true,None).unwrap();assert_eq!(first.len(),2);
        assert_eq!(keys.retain_access_keys(&local,&workspace,&opened,true,None).unwrap(),first,"same grant acceptance is idempotent");
        let before=keys.selected(&local,&workspace).unwrap();assert_eq!(before.key_id,opened.current_key_id);
        let newer=structure_content_key_id(&[99;32]);keys.retain_current(&local,&workspace,&[99;32],&newer,Some(&before.key_id)).unwrap();
        assert!(matches!(keys.retain_access_keys(&local,&workspace,&opened,true,Some(&before.key_id)),Err(ContentKeyError::Conflict)));
        keys.retain_access_keys(&local,&workspace,&opened,false,None).unwrap();assert_eq!(keys.selected(&local,&workspace).unwrap().key_id,newer);
        let mut c=context();c.workspace_id=workspace.clone();let sealed=seal_structure_content(opened.keys[0].secret(),b"shared body",&c).unwrap();
        assert_eq!(&**keys.open_body(&local,&sealed,&c).unwrap(),b"shared body");assert!(matches!(keys.open_body(&"B".repeat(43),&sealed,&c),Err(ContentKeyError::Missing)));
        drop(keys);let keys=StructureContentKeys::open(&path,config()).unwrap();assert_eq!(keys.selected(&local,&workspace).unwrap().key_id,newer);assert_eq!(&**keys.open_body(&local,&sealed,&c).unwrap(),b"shared body");
    }
    #[test]
    fn unpublished_rotation_candidate_retains_history_without_selecting_an_unaccepted_key(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("keys.sqlite");
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();let local="A".repeat(43);let c=context();
        let old=keys.ensure_current(&local,&c.workspace_id).unwrap();let body=keys.seal(&local,b"historical body",&c).unwrap();
        let candidate=keys.create_candidate(&local,&c.workspace_id).unwrap();assert_ne!(candidate.key_id,old.key_id);
        assert_eq!(keys.selected(&local,&c.workspace_id).unwrap(),old);drop(keys);
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();assert_eq!(keys.selected(&local,&c.workspace_id).unwrap(),old);
        keys.select_retained(&local,&c.workspace_id,&candidate.key_id,Some(&old.key_id)).unwrap();
        assert_eq!(keys.selected(&local,&c.workspace_id).unwrap(),candidate);assert_eq!(&**keys.open_body(&local,&body,&c).unwrap(),b"historical body");
        assert!(matches!(keys.select_retained(&local,&c.workspace_id,&"X".repeat(43),Some(&candidate.key_id)),Err(ContentKeyError::Missing)));
        assert_eq!(keys.selected(&local,&c.workspace_id).unwrap(),candidate);
    }
    #[test]
    fn remote_epoch_pins_reject_rollback_equivocation_and_owner_change_after_restart(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("keys.sqlite");let local="A".repeat(43);let ws="W".repeat(43);let owner="O".repeat(43);
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();keys.pin_remote_head(&local,&ws,None).unwrap();
        keys.pin_remote_head(&local,&ws,Some((&owner,1,&"K".repeat(43),&"a".repeat(64)))).unwrap();
        keys.pin_remote_head(&local,&ws,Some((&owner,2,&"L".repeat(43),&"b".repeat(64)))).unwrap();drop(keys);
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();keys.pin_remote_head(&local,&ws,Some((&owner,2,&"L".repeat(43),&"b".repeat(64)))).unwrap();
        for head in [None,Some((owner.as_str(),1,"K".repeat(43),"a".repeat(64))),Some((owner.as_str(),2,"K".repeat(43),"b".repeat(64))),Some((owner.as_str(),2,"L".repeat(43),"c".repeat(64))),Some(("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",3,"M".repeat(43),"c".repeat(64)))]{
            let borrowed=head.as_ref().map(|h|(h.0,h.1,h.2.as_str(),h.3.as_str()));assert!(matches!(keys.pin_remote_head(&local,&ws,borrowed),Err(ContentKeyError::HeadRollback)));
        }
        keys.pin_remote_head(&"B".repeat(43),&ws,Some((&owner,1,&"K".repeat(43),&"a".repeat(64)))).unwrap();
        keys.pin_remote_head(&local,&ws,Some((&owner,3,&"M".repeat(43),&"c".repeat(64)))).unwrap();
    }
    #[test]
    fn additive_local_epoch_metadata_preserves_v1_keys_and_current_selection(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("keys.sqlite");let local="A".repeat(43);let c=context();
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();let old=keys.ensure_current(&local,&c.workspace_id).unwrap();let sealed=keys.seal(&local,b"retained v1 body",&c).unwrap();
        keys.db.execute_batch("DROP TABLE content_key_history_stages;DROP TABLE content_key_history_worker;DROP TABLE content_key_remote_heads;DROP TABLE content_key_coordinator;DROP TABLE content_key_delivery_stages;PRAGMA user_version=1;").unwrap();drop(keys);
        let keys=StructureContentKeys::open(&path,config()).unwrap();assert_eq!(keys.selected(&local,&c.workspace_id).unwrap(),old);assert_eq!(&**keys.open_body(&local,&sealed,&c).unwrap(),b"retained v1 body");
        assert_eq!(keys.db.pragma_query_value::<i64,_>(None,"user_version",|r|r.get(0)).unwrap(),4);
    }
    #[test]
    fn delivery_stage_survives_restart_and_isolated_journals_cannot_reuse_ciphertext_commands(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("keys.sqlite");let local="A".repeat(43);let ws="W".repeat(43);
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();let first=keys.prepare_delivery_stage(&local,&ws,"journal-a",2,0).unwrap();
        let same=keys.prepare_delivery_stage(&local,&ws,"journal-a",2,0).unwrap();assert_eq!(first.command_id,same.command_id);
        let other=keys.prepare_delivery_stage(&local,&ws,"journal-b",2,0).unwrap();assert_ne!(first.command_id,other.command_id);drop(keys);
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();assert_eq!(keys.delivery_stage(&local,&ws,"journal-a").unwrap().unwrap().command_id,first.command_id);
        keys.clear_delivery_stage(&local,&ws,"journal-a",&other.command_id).unwrap();assert!(keys.delivery_stage(&local,&ws,"journal-a").unwrap().is_some());
        keys.clear_delivery_stage(&local,&ws,"journal-a",&first.command_id).unwrap();assert!(keys.delivery_stage(&local,&ws,"journal-a").unwrap().is_none());assert!(keys.delivery_stage(&local,&ws,"journal-b").unwrap().is_some());
        let next=keys.prepare_delivery_stage(&local,&ws,"journal-a",2,1).unwrap();assert_ne!(first.command_id,next.command_id);
    }
    #[test]
    fn interrupted_access_import_leaves_no_partial_keys_and_can_retry_same_grant(){
        let dir=crate::test_support::protected_test_dir();let mut keys=StructureContentKeys::open(&dir.path().join("body.sqlite"),config()).unwrap();
        let local="A".repeat(43);let workspace=peerwork_core::crypto::base64url(&[3;32]);let opened=opened_access_fixture();
        keys.db.execute_batch("CREATE TEMP TRIGGER fail_access_head BEFORE INSERT ON content_key_heads BEGIN SELECT RAISE(ABORT,'injected head failure');END;").unwrap();
        assert!(matches!(keys.retain_access_keys(&local,&workspace,&opened,true,None),Err(ContentKeyError::Storage(_))));
        assert_eq!(keys.db.query_row("SELECT count(*) FROM content_keys",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        keys.db.execute_batch("DROP TRIGGER fail_access_head;").unwrap();assert_eq!(keys.retain_access_keys(&local,&workspace,&opened,true,None).unwrap().len(),2);
    }
    #[test]
    fn owner_key_packaging_is_selected_workspace_bound_and_contains_no_plaintext_keys(){
        let dir=crate::test_support::protected_test_dir();let mut keys=StructureContentKeys::open(&dir.path().join("body.sqlite"),config()).unwrap();
        let vector:serde_json::Value=serde_json::from_str(include_str!("../../../tests/fixtures/structure-access-v1.json")).unwrap();let local="A".repeat(43);let workspace=peerwork_core::crypto::base64url(&[3;32]);
        let req=peerwork_core::structure_access::verify_access_request(vector["request_jws"].as_str().unwrap(),&workspace,&"structure-test".encode_utf16().collect::<Vec<_>>(),vector["service_key"].as_str().unwrap(),1_800_000_000_000).unwrap();
        let old=keys.ensure_current(&local,&workspace).unwrap();let id=structure_content_key_id(&[99;32]);keys.retain_current(&local,&workspace,&[99;32],&id,Some(&old.key_id)).unwrap();
        let packaged=keys.package_access_keys(&local,&workspace,&req,"structure-test",vector["owner_id"].as_str().unwrap(),&[old.key_id.clone()]).unwrap();assert_eq!(packaged.key_ids.len(),2);assert_eq!(packaged.current_key_id,id);
        assert!(!serde_json::to_string(&packaged).unwrap().contains(&peerwork_core::crypto::base64url(&[99;32])));
        assert!(matches!(keys.package_access_keys(&local,&"X".repeat(43),&req,"structure-test",vector["owner_id"].as_str().unwrap(),&[]),Err(ContentKeyError::Selection)));
        assert!(matches!(keys.package_access_keys(&local,&workspace,&req,"structure-test",vector["owner_id"].as_str().unwrap(),&[old.key_id.clone(),old.key_id]),Err(ContentKeyError::Selection)));
    }
    #[test]
    fn body_keys_are_origin_identity_workspace_bound_and_survive_restart(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("body-keys.sqlite");
        let mut keys=StructureContentKeys::open(&path,config()).unwrap();let a="A".repeat(43);let b="B".repeat(43);let c=context();
        let selected=keys.ensure_current(&a,&c.workspace_id).unwrap();assert_eq!(keys.ensure_current(&a,&c.workspace_id).unwrap(),selected);
        let other=keys.ensure_current(&b,&c.workspace_id).unwrap();assert_ne!(selected.key_id,other.key_id);
        let sealed=keys.seal(&a,b"private body",&c).unwrap();assert_eq!(sealed.key_id,selected.key_id);
        assert!(matches!(keys.open_body(&b,&sealed,&c),Err(ContentKeyError::Missing)));
        let mut different=c.clone();different.workspace_id="X".repeat(43);
        assert!(matches!(keys.open_body(&a,&sealed,&different),Err(ContentKeyError::Missing)));
        drop(keys);let keys=StructureContentKeys::open(&path,config()).unwrap();
        assert_eq!(&**keys.open_body(&a,&sealed,&c).unwrap(),b"private body");assert_eq!(keys.selected(&a,&c.workspace_id).unwrap(),selected);
        assert!(matches!(StructureContentKeys::open(&path,TransportConfig::new("https://other.invalid")),Err(ContentKeyError::OriginChanged)));
        assert_eq!(fs::metadata(path).unwrap().permissions().mode()&0o077,0);
    }
    #[test]
    fn explicit_import_checks_key_commitment_and_current_selection_without_discarding_old_keys(){
        let dir=crate::test_support::protected_test_dir();let mut keys=StructureContentKeys::open(&dir.path().join("body.sqlite"),config()).unwrap();
        let local="A".repeat(43);let c=context();let old=keys.ensure_current(&local,&c.workspace_id).unwrap();
        let sealed=keys.seal(&local,b"old body",&c).unwrap();let source=dir.path().join("import.key");
        fs::write(&source,[42;32]).unwrap();fs::set_permissions(&source,fs::Permissions::from_mode(0o600)).unwrap();
        let id=structure_content_key_id(&[42;32]);
        assert!(matches!(keys.import_current_from_file(&local,&c.workspace_id,&source,&id,None),Err(ContentKeyError::Conflict)));
        assert_eq!(keys.selected(&local,&c.workspace_id).unwrap(),old);
        let current=keys.import_current_from_file(&local,&c.workspace_id,&source,&id,Some(&old.key_id)).unwrap();
        assert_eq!(current.key_id,id);assert_eq!(&**keys.open_body(&local,&sealed,&c).unwrap(),b"old body");
        assert_eq!(keys.import_current_from_file(&local,&c.workspace_id,&source,&id,Some(&old.key_id)).unwrap(),current,"same import is idempotent");
        assert!(matches!(keys.import_current_from_file(&local,&c.workspace_id,&source,&old.key_id,Some(&id)),Err(ContentKeyError::Integrity)));
        fs::set_permissions(&source,fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(keys.import_current_from_file(&local,&c.workspace_id,&source,&id,Some(&id)),Err(ContentKeyError::Protection)));
        assert_eq!(fs::read(&source).unwrap(),[42;32],"import source remains untouched");
    }
    #[test]
    fn local_key_open_does_not_initialize_network_trust_but_preserves_origin_pin(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("local.sqlite");
        let options=crate::transport::TransportOptions{additional_root_pem_files:vec![dir.path().join("absent-network-root.pem")],..Default::default()};
        let config=||TransportConfig::new("https://EXAMPLE.invalid:443").with_options(options.clone());
        assert!(matches!(crate::transport::HttpTransport::new(config()),Err(crate::transport::TransportError::InvalidTrust)));
        let keys=StructureContentKeys::open(&path,config()).unwrap();drop(keys);
        assert!(StructureContentKeys::open(&path,TransportConfig::new("https://example.invalid/")).is_ok());
        assert!(matches!(StructureContentKeys::open(&path,TransportConfig::new("https://other.invalid")),Err(ContentKeyError::OriginChanged)));
        for origin in ["http://example.invalid","https://user@example.invalid","https://example.invalid/path","https://example.invalid/?q=1"]{
            assert!(matches!(StructureContentKeys::open(&path,TransportConfig::new(origin)),Err(ContentKeyError::Selection)));
        }
    }

    #[test]
    fn selected_key_lookup_does_not_scan_old_or_other_actor_keys_and_detects_selected_corruption(){
        let dir=crate::test_support::protected_test_dir();let path=dir.path().join("body.sqlite");let mut keys=StructureContentKeys::open(&path,config()).unwrap();
        let local="A".repeat(43);let c=context();let selected=keys.ensure_current(&local,&c.workspace_id).unwrap();
        let tx=keys.db.transaction().unwrap();
        for n in 0..10000 {tx.execute("INSERT INTO content_keys VALUES(?1,?2,?3,?4)",params![local,c.workspace_id,format!("N{n:042}"),&[1u8;32][..]]).unwrap();}
        tx.commit().unwrap();drop(keys);let keys=StructureContentKeys::open(&path,config()).unwrap();
        let sealed=keys.seal(&local,b"chosen body",&c).unwrap();assert_eq!(&**keys.open_body(&local,&sealed,&c).unwrap(),b"chosen body");
        let plan:Vec<String>=keys.db.prepare("EXPLAIN QUERY PLAN SELECT secret FROM content_keys WHERE local_key_id=?1 AND workspace_id=?2 AND key_id=?3").unwrap()
            .query_map(params![local,c.workspace_id,selected.key_id],|r|r.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
        assert!(plan.iter().any(|s|s.contains("PRIMARY KEY")&&s.contains("local_key_id=?")&&s.contains("workspace_id=?")&&s.contains("key_id=?")),"{plan:?}");
        assert!(!plan.iter().any(|s|s.contains("SCAN ")),"{plan:?}");
        keys.db.execute("UPDATE content_keys SET secret=?1 WHERE local_key_id=?2 AND workspace_id=?3 AND key_id=?4",params![&[2u8;32][..],local,c.workspace_id,selected.key_id]).unwrap();
        assert!(matches!(keys.open_body(&local,&sealed,&c),Err(ContentKeyError::Integrity)));
    }
    #[test]
    fn failed_key_head_write_does_not_leave_orphaned_secret_or_reset_an_existing_selection(){
        let dir=crate::test_support::protected_test_dir();let mut keys=StructureContentKeys::open(&dir.path().join("body.sqlite"),config()).unwrap();
        keys.db.execute_batch("CREATE TEMP TRIGGER fail_head BEFORE INSERT ON content_key_heads BEGIN SELECT RAISE(ABORT,'injected head failure');END;").unwrap();
        assert!(matches!(keys.ensure_current(&"A".repeat(43),&"W".repeat(43)),Err(ContentKeyError::Storage(_))));
        assert_eq!(keys.db.query_row("SELECT count(*) FROM content_keys",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        keys.db.execute_batch("DROP TRIGGER fail_head;").unwrap();assert!(keys.ensure_current(&"A".repeat(43),&"W".repeat(43)).is_ok());
    }
}
