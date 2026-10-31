//! Durable verified program inbox. One engine owns this connection. Immutable
//! service/author evidence is retained separately from withdrawal/stop state.
#[path = "participant_host_ledger.rs"]
mod host_ledger;
#[path = "participant_key_queue.rs"]
mod key_queue;
use crate::{
    communication_store::single_owner_database as database,
    kernel_identity::KernelIdentity,
    kernel_intents::parent_operations::{open_bounded, seal_bounded},
    participant::{ParticipantError, Result},
};
pub(crate) use host_ledger::{HostBinding, HostOperation, HostOutcome, HostReply};
pub(crate) use host_ledger::rebind::HostRebind;
use peerwork_core::{
    canonical::Path as CanonicalPath,
    communication::{MailboxPins, VerifiedMailboxPage, MAX_FRAME_BYTES},
    crypto::sha256_hex,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::path::Path;
fn failure(code: &str) -> ParticipantError {
    ParticipantError {
        code: code.into(),
        phase: "INBOX_STATE".into(),
        effect_certainty: "UNKNOWN".into(),
        recovery: if code.starts_with("RECEIVER_CONTINUITY_KEY_") {
            "RESTORE_ORIGINAL_RECEIVER_STATE"
        } else {
            "RETAIN_CURSOR_AND_RECONNECT"
        }
        .into(),
        operation_id: None,
    }
}
fn state() -> ParticipantError {
    failure("INBOX_STATE_FAILED")
}
fn db_error(error: rusqlite::Error) -> ParticipantError {
    let _ = error;
    state()
}
fn invalid() -> ParticipantError {
    failure("INBOX_STATE_INVALID")
}
fn text(v: &WireValue, k: &str) -> Result<String> {
    v.get(k).and_then(WireValue::as_string).ok_or_else(invalid)
}
fn number(v: &WireValue, k: &str) -> Result<u64> {
    v.get(k)
        .and_then(WireValue::as_number)
        .filter(|n| {
            n.is_finite() && n.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(n)
        })
        .map(|n| n as u64)
        .ok_or_else(invalid)
}
fn json_value(v: &WireValue) -> Result<Value> {
    serde_json::from_str(
        &canonical_wire_value(v, CanonicalPath::STRUCTURED).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub item: u64,
    pub control: Option<u64>,
}
pub(crate) struct InboxStore {
    db: Connection,
    binding: String,
    actor: String,
    key_id: String,
    audience: Vec<u16>,
    service_key: String,
}
impl InboxStore {
    pub fn open(
        directory: &Path,
        identity: &KernelIdentity,
        origin: &str,
        audience: &[u16],
        service_key: &str,
    ) -> Result<Self> {
        let mut store = Self::open_local(directory, identity, origin)?;
        store.bind_service(audience, service_key)?;
        Ok(store)
    }
    pub fn open_local(directory: &Path, identity: &KernelIdentity, origin: &str) -> Result<Self> {
        let db = database(directory, "participant-inbox.sqlite").map_err(|_| state())?;
        let binding=json!({"format":"peerwork.participant-inbox.v1","actor":identity.actor_id(),"key":identity.key_id(),"origin":origin}).to_string();
        // Reject another principal before recovery changes any old call facts.
        let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbox_meta')", [], |r|r.get(0)).map_err(db_error)?;
        if exists {
            let old: Option<String> = db
                .query_row("SELECT binding FROM inbox_meta WHERE id=1", [], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(db_error)?;
            if old.as_deref() != Some(binding.as_str()) {
                return Err(failure("INBOX_BINDING_MISMATCH"));
            }
        }
        db.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS inbox_service(id INTEGER PRIMARY KEY CHECK(id=1),pins TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS inbox_watches(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,namespace TEXT NOT NULL,descriptor TEXT NOT NULL,receiver TEXT NOT NULL,claim_id TEXT NOT NULL,claim_wire TEXT,enabled INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox));
            CREATE TABLE IF NOT EXISTS inbox_receiver_keys(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sealed BLOB NOT NULL,PRIMARY KEY(workspace,mailbox));
            CREATE INDEX IF NOT EXISTS inbox_watches_active ON inbox_watches(enabled,workspace,mailbox);
            CREATE TABLE IF NOT EXISTS inbox_meta(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL,allocated INTEGER NOT NULL,rows INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS inbox_mailboxes(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,membership TEXT NOT NULL,receiver TEXT NOT NULL,epoch INTEGER NOT NULL,destination TEXT NOT NULL,binding_version INTEGER NOT NULL,item_cursor INTEGER NOT NULL,control_cursor INTEGER,last_frame TEXT,gc_after TEXT NOT NULL,PRIMARY KEY(workspace,mailbox));
            CREATE TABLE IF NOT EXISTS inbox_frames(digest TEXT PRIMARY KEY,workspace TEXT NOT NULL,mailbox TEXT NOT NULL,evidence BLOB NOT NULL,allocation INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS inbox_items(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,delivery_id TEXT NOT NULL,kind TEXT NOT NULL,frame TEXT NOT NULL REFERENCES inbox_frames(digest),item_index INTEGER NOT NULL,item_digest TEXT NOT NULL,status TEXT NOT NULL,terminal_reason TEXT,stored_uploaded INTEGER NOT NULL DEFAULT 0,consume_requested INTEGER NOT NULL DEFAULT 0,consumed_uploaded INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(workspace,mailbox,sequence),UNIQUE(workspace,mailbox,delivery_id));
            CREATE TABLE IF NOT EXISTS inbox_consumed(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,delivery_id TEXT NOT NULL,PRIMARY KEY(workspace,mailbox,sequence));
            CREATE INDEX IF NOT EXISTS inbox_ready ON inbox_items(workspace,mailbox,consume_requested,sequence);
            CREATE INDEX IF NOT EXISTS inbox_stored_ack ON inbox_items(workspace,mailbox,stored_uploaded,sequence);
            CREATE INDEX IF NOT EXISTS inbox_consumed_ack ON inbox_items(workspace,mailbox,stored_uploaded,consume_requested,consumed_uploaded,sequence);
            CREATE INDEX IF NOT EXISTS inbox_custody_only_ack ON inbox_items(workspace,mailbox,stored_uploaded,consume_requested,sequence);
            CREATE INDEX IF NOT EXISTS inbox_cumulative_ack ON inbox_items(workspace,mailbox,consume_requested,consumed_uploaded,sequence);
            CREATE INDEX IF NOT EXISTS inbox_item_frames ON inbox_items(frame);
            CREATE INDEX IF NOT EXISTS inbox_cursor_frame ON inbox_mailboxes(last_frame);
            CREATE TABLE IF NOT EXISTS inbox_subjects(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,revision INTEGER NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox,kind,subject,revision,sequence));
            CREATE TABLE IF NOT EXISTS inbox_terminal(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,revision INTEGER NOT NULL,reason TEXT NOT NULL,frame TEXT NOT NULL REFERENCES inbox_frames(digest),retire_after INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox,kind,subject));
            CREATE INDEX IF NOT EXISTS inbox_subject_item ON inbox_subjects(workspace,mailbox,sequence,kind,subject,revision);
            CREATE INDEX IF NOT EXISTS inbox_terminal_frame ON inbox_terminal(frame);
            CREATE INDEX IF NOT EXISTS inbox_terminal_gc ON inbox_terminal(workspace,mailbox,retire_after,kind,subject);") .map_err(db_error)?;
        host_ledger::initialize(&db)?;
        key_queue::initialize(&db)?;
        db.execute(
            "INSERT OR IGNORE INTO inbox_meta VALUES(1,?1,0,0)",
            [&binding],
        )
        .map_err(db_error)?;
        let old: String = db
            .query_row("SELECT binding FROM inbox_meta WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(db_error)?;
        if old != binding {
            return Err(failure("INBOX_BINDING_MISMATCH"));
        }
        let pins: Option<String> = db
            .query_row("SELECT pins FROM inbox_service WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_error)?;
        let (audience, service_key) = pins
            .map(|v| serde_json::from_str::<(Vec<u16>, String)>(&v).map_err(|_| invalid()))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            db,
            binding,
            actor: identity.actor_id().into(),
            key_id: identity.key_id().into(),
            audience,
            service_key,
        })
    }
    pub fn bind_service(&mut self, audience: &[u16], service_key: &str) -> Result<()> {
        let pins = serde_json::to_string(&(audience, service_key)).map_err(|_| invalid())?;
        self.db
            .execute("INSERT OR IGNORE INTO inbox_service VALUES(1,?1)", [&pins])
            .map_err(db_error)?;
        let old: String = self
            .db
            .query_row("SELECT pins FROM inbox_service WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(db_error)?;
        if pins != old {
            return Err(failure("INBOX_SERVICE_MISMATCH"));
        }
        self.audience = audience.to_vec();
        self.service_key = service_key.into();
        Ok(())
    }
    pub fn watch_bindings(&self) -> Result<Vec<crate::participant_watch::Binding>> {
        let rows=self.db.prepare("SELECT namespace,descriptor,receiver,claim_id,claim_wire FROM inbox_watches WHERE enabled=1 ORDER BY workspace,mailbox LIMIT 9").map_err(db_error)?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        if rows.len() > 8 {
            return Err(invalid());
        }
        rows.into_iter()
            .map(|(namespace, wire, receiver, claim_id, claim_wire)| {
                let options: crate::participant_watch::WatchOptions =
                    serde_json::from_str(&wire).map_err(|_| invalid())?;
                options.validate()?;
                let pins = self.pins(&options.workspace_id, &options.mailbox_id)?;
                Ok(crate::participant_watch::Binding {
                    namespace,
                    options,
                    receiver,
                    claim_id,
                    claim_wire,
                    pins,
                })
            })
            .collect()
    }
    pub fn attach_watch(
        &mut self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &crate::participant_watch::WatchOptions,
    ) -> Result<crate::participant_watch::Binding> {
        options.validate()?;
        self.host_rebind_available(options)?;
        let wire = serde_json::to_string(options).map_err(|_| invalid())?;
        let active:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_watches WHERE workspace=?1 AND mailbox=?2 AND enabled=1)",params![options.workspace_id,options.mailbox_id],|r|r.get(0)).map_err(db_error)?;
        let count: usize = self
            .db
            .query_row(
                "SELECT count(*) FROM inbox_watches WHERE enabled=1",
                [],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if !active && count >= 8 {
            return Err(failure("WATCH_SCOPE_LIMIT"));
        }
        let prior: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT namespace,descriptor FROM inbox_watches WHERE workspace=?1 AND mailbox=?2",
                params![options.workspace_id, options.mailbox_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        if let Some((owner, old)) = prior {
            if owner != namespace || old != wire {
                return Err(failure("WATCH_BINDING_MISMATCH"));
            }
            let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_receiver_keys WHERE workspace=?1 AND mailbox=?2)",params![options.workspace_id,options.mailbox_id],|r|r.get(0)).map_err(db_error)?;
            if !exists {
                return Err(failure("RECEIVER_CONTINUITY_KEY_MISSING"));
            }
        } else {
            let retained: usize = self
                .db
                .query_row("SELECT count(*) FROM inbox_watches", [], |r| r.get(0))
                .map_err(db_error)?;
            if retained >= 256 {
                return Err(failure("WATCH_BINDING_LIMIT"));
            }
            use rand_core::RngCore;
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            rand_core::OsRng
                .try_fill_bytes(&mut *seed)
                .map_err(|_| state())?;
            let receiver = peerwork_core::communication::receiver_id(&seed);
            let aad = self.receiver_key_aad(namespace, options);
            let encoded = zeroize::Zeroizing::new(peerwork_core::crypto::base64url(&*seed));
            let sealed = seal_bounded(identity, &aad, &encoded, 128).map_err(|_| state())?;
            let claim = crate::communication_host::random_token().map_err(|_| state())?;
            let tx = self.db.unchecked_transaction().map_err(db_error)?;
            tx.execute(
                "INSERT INTO inbox_receiver_keys VALUES(?1,?2,?3)",
                params![options.workspace_id, options.mailbox_id, sealed],
            )
            .map_err(db_error)?;
            tx.execute(
                "INSERT INTO inbox_watches VALUES(?1,?2,?3,?4,?5,?6,NULL,1)",
                params![
                    options.workspace_id,
                    options.mailbox_id,
                    namespace,
                    wire,
                    receiver,
                    claim
                ],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
        }
        self.db
            .execute(
                "UPDATE inbox_watches SET enabled=1 WHERE workspace=?1 AND mailbox=?2",
                params![options.workspace_id, options.mailbox_id],
            )
            .map_err(db_error)?;
        self.watch_bindings()?
            .into_iter()
            .find(|b| {
                b.options.workspace_id == options.workspace_id
                    && b.options.mailbox_id == options.mailbox_id
            })
            .ok_or_else(invalid)
    }
    pub fn disable_watch(
        &mut self,
        namespace: &str,
        options: &crate::participant_watch::WatchOptions,
    ) -> Result<()> {
        let prior: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT namespace,descriptor FROM inbox_watches WHERE workspace=?1 AND mailbox=?2",
                params![options.workspace_id, options.mailbox_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        if prior
            != Some((
                namespace.into(),
                serde_json::to_string(options).map_err(|_| invalid())?,
            ))
        {
            return Err(failure("WATCH_BINDING_MISMATCH"));
        }
        self.db
            .execute(
                "UPDATE inbox_watches SET enabled=0 WHERE workspace=?1 AND mailbox=?2",
                params![options.workspace_id, options.mailbox_id],
            )
            .map_err(db_error)?;
        Ok(())
    }
    fn receiver_key_aad(
        &self,
        namespace: &str,
        options: &crate::participant_watch::WatchOptions,
    ) -> String {
        json!([
            "peerwork.receiver-key.v1",
            self.binding,
            namespace,
            options.workspace_id,
            options.mailbox_id,
            options.membership_id
        ])
        .to_string()
    }
    pub fn receiver_proof(
        &self,
        identity: &KernelIdentity,
        binding: &crate::participant_watch::Binding,
        body: &Value,
    ) -> Result<String> {
        let sealed: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT sealed FROM inbox_receiver_keys WHERE workspace=?1 AND mailbox=?2",
                params![binding.options.workspace_id, binding.options.mailbox_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let sealed = sealed.ok_or_else(|| failure("RECEIVER_CONTINUITY_KEY_MISSING"))?;
        let plain = open_bounded(
            identity,
            &self.receiver_key_aad(&binding.namespace, &binding.options),
            &sealed,
            128,
        )
        .map_err(|_| failure("RECEIVER_CONTINUITY_KEY_INVALID"))?;
        let decoded = zeroize::Zeroizing::new(
            peerwork_core::crypto::decode_base64url(&plain)
                .map_err(|_| failure("RECEIVER_CONTINUITY_KEY_INVALID"))?,
        );
        let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| failure("RECEIVER_CONTINUITY_KEY_INVALID"))?,
        );
        if peerwork_core::communication::receiver_id(&seed) != binding.receiver {
            return Err(failure("RECEIVER_CONTINUITY_KEY_INVALID"));
        }
        let audience = String::from_utf16(&self.audience)
            .map_err(|_| failure("RECEIVER_CONTINUITY_KEY_INVALID"))?;
        peerwork_core::communication::receiver_claim_proof(
            &seed,
            &audience,
            &self.actor,
            &binding.options.workspace_id,
            body,
        )
        .map_err(|_| failure("RECEIVER_CONTINUITY_KEY_INVALID"))
    }
    pub fn freeze_claim(
        &mut self,
        binding: &crate::participant_watch::Binding,
        wire: &str,
    ) -> Result<()> {
        let old: Option<String> = self
            .db
            .query_row(
                "SELECT claim_wire FROM inbox_watches WHERE workspace=?1 AND mailbox=?2",
                params![binding.options.workspace_id, binding.options.mailbox_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if old.as_ref().is_some_and(|v| v != wire) {
            return Err(failure("WATCH_CLAIM_CONFLICT"));
        }
        self.db
            .execute(
                "UPDATE inbox_watches SET claim_wire=?3 WHERE workspace=?1 AND mailbox=?2",
                params![
                    binding.options.workspace_id,
                    binding.options.mailbox_id,
                    wire
                ],
            )
            .map_err(db_error)?;
        Ok(())
    }
    /// Called only after the engine verifies this exact claim's signed
    /// REJECTED_NO_EFFECT/BUSY result. The original native packet/result stays
    /// in its journal; only the next claim selection advances. Unknown results
    /// never reach this method. A stale callback cannot rotate a newer claim.
    pub fn rotate_refused_claim(
        &mut self,
        binding: &crate::participant_watch::Binding,
    ) -> Result<String> {
        if binding.pins.is_some() || binding.claim_wire.is_none() {
            return Err(failure("WATCH_CLAIM_NOT_REFUSABLE"));
        }
        let next = crate::communication_host::random_token().map_err(|_| state())?;
        let changed = self.db.execute(
            "UPDATE inbox_watches SET claim_id=?1,claim_wire=NULL WHERE workspace=?2 AND mailbox=?3 AND namespace=?4 AND descriptor=?5 AND receiver=?6 AND claim_id=?7 AND claim_wire=?8 AND enabled=1",
            params![next,binding.options.workspace_id,binding.options.mailbox_id,binding.namespace,serde_json::to_string(&binding.options).map_err(|_|invalid())?,binding.receiver,binding.claim_id,binding.claim_wire],
        ).map_err(db_error)?;
        if changed != 1 {
            return Err(failure("WATCH_CLAIM_CONFLICT"));
        }
        Ok(next)
    }
    pub fn pins(&self, workspace: &str, mailbox: &str) -> Result<Option<MailboxPins>> {
        self.db.query_row("SELECT membership,receiver,epoch,destination,binding_version,item_cursor,control_cursor FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",params![workspace,mailbox],|r|Ok(MailboxPins{workspace_id:workspace.into(),mailbox_id:mailbox.into(),membership_id:r.get(0)?,receiver_id:r.get(1)?,epoch:r.get(2)?,destination_digest:r.get(3)?,binding_version:r.get(4)?,after_sequence:r.get(5)?,after_control_sequence:r.get(6)?})).optional().map_err(db_error)
    }
    pub fn bootstrap_control(&mut self, pins: &MailboxPins, cursor: u64) -> Result<()> {
        let old = self
            .cursor(&pins.workspace_id, &pins.mailbox_id)?
            .ok_or_else(invalid)?;
        if old.item != pins.after_sequence || old.control.is_some_and(|v| v != cursor) {
            return Err(failure("INBOX_CURSOR_CONFLICT"));
        }
        self.db
            .execute(
                "UPDATE inbox_mailboxes SET control_cursor=?3 WHERE workspace=?1 AND mailbox=?2",
                params![pins.workspace_id, pins.mailbox_id, cursor],
            )
            .map_err(db_error)?;
        Ok(())
    }
    pub fn compact(&mut self, workspace: &str, mailbox: &str) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let cursor: Option<u64> = tx
            .query_row(
                "SELECT item_cursor FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",
                params![workspace, mailbox],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        if let Some(cursor) = cursor {
            let mut garbage = std::collections::BTreeSet::new();
            retire_terminals(&tx, workspace, mailbox, cursor, &mut garbage)?;
            collect_frames(&tx, &garbage)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(())
    }
    fn aad(&self, workspace: &str, mailbox: &str, digest: &str) -> String {
        json!({"format":"peerwork.participant-inbox-frame.v1","binding":self.binding,"workspace_id":workspace,"mailbox_id":mailbox,"digest":digest}).to_string()
    }
    pub fn audience(&self) -> &[u16] {
        &self.audience
    }
    pub fn cursor(&self, workspace: &str, mailbox: &str) -> Result<Option<Cursor>> {
        self.db.query_row("SELECT item_cursor,control_cursor FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",params![workspace,mailbox],|r|Ok(Cursor{item:r.get(0)?,control:r.get(1)?})).optional().map_err(db_error)
    }
    /// Called only after the engine verifies the selected mailbox claim and
    /// stream grant. A new epoch may reclaim the same destination, never move it.
    pub fn register(&mut self, pins: &MailboxPins) -> Result<()> {
        pins.validate().map_err(|_| invalid())?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let old:Option<(String,String,u64,String,u64,u64,Option<u64>)>=tx.query_row("SELECT membership,receiver,epoch,destination,binding_version,item_cursor,control_cursor FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",params![pins.workspace_id,pins.mailbox_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(db_error)?;
        if let Some((membership, receiver, epoch, destination, version, item, control)) = old {
            if membership != pins.membership_id
                || destination != pins.destination_digest
                || version != pins.binding_version
                || pins.epoch < epoch
                || pins.epoch == epoch && receiver != pins.receiver_id
                || item != pins.after_sequence
                || control != pins.after_control_sequence
            {
                return Err(failure("INBOX_BINDING_MISMATCH"));
            }
            tx.execute(
                "UPDATE inbox_mailboxes SET receiver=?3,epoch=?4 WHERE workspace=?1 AND mailbox=?2",
                params![
                    pins.workspace_id,
                    pins.mailbox_id,
                    pins.receiver_id,
                    pins.epoch
                ],
            )
            .map_err(db_error)?;
        } else {
            let count: u64 = tx
                .query_row("SELECT count(*) FROM inbox_mailboxes", [], |r| r.get(0))
                .map_err(db_error)?;
            if count >= 256 {
                return Err(failure("INBOX_CAPACITY"));
            }
            if pins.after_sequence != 0 {
                return Err(failure("INBOX_INITIAL_CURSOR_INVALID"));
            }
            tx.execute(
                r#"INSERT INTO inbox_mailboxes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,'[0,"",""]')"#,
                params![
                    pins.workspace_id,
                    pins.mailbox_id,
                    pins.membership_id,
                    pins.receiver_id,
                    pins.epoch,
                    pins.destination_digest,
                    pins.binding_version,
                    pins.after_sequence,
                    pins.after_control_sequence
                ],
            )
            .map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(())
    }
    /// Evidence and both cursors commit together. A failed transaction neither
    /// ACKs nor skips data, and a duplicate frame cannot replace old evidence.
    pub fn ingest(
        &mut self,
        identity: &KernelIdentity,
        page: &VerifiedMailboxPage,
        max_bytes: usize,
    ) -> Result<Cursor> {
        self.ingest_with_keys(identity, page, max_bytes, &Default::default())
    }
    pub fn ingest_with_keys(
        &mut self,
        identity: &KernelIdentity,
        page: &VerifiedMailboxPage,
        max_bytes: usize,
        known_keys: &std::collections::BTreeSet<String>,
    ) -> Result<Cursor> {
        let pins = page.mailbox();
        if page.actor_id() != self.actor
            || identity.actor_id() != self.actor
            || identity.key_id() != self.key_id
            || page.audience() != self.audience
            || page.service_key() != self.service_key
        {
            return Err(failure("INBOX_BINDING_MISMATCH"));
        }
        let wire = page.frame_wire().ok_or_else(invalid)?;
        let hash = sha256_hex(wire.as_bytes());
        let aad = self.aad(&pins.workspace_id, &pins.mailbox_id, &hash);
        let sealed = seal_bounded(identity, &aad, wire, MAX_FRAME_BYTES).map_err(|_| invalid())?;
        let subjects: Vec<_> = page
            .items()
            .iter()
            .map(|item| subjects(item.envelope()))
            .collect::<Result<_>>()?;
        let allocation =
            sealed.len() + 4096 + subjects.iter().map(|s| s.len() * 256 + 2048).sum::<usize>();
        let key_refs = key_queue::prepare_refs(identity, &self.binding, page, &hash)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let (membership,receiver,epoch,destination,version,cursor,control):(String,String,u64,String,u64,u64,Option<u64>)=tx.query_row("SELECT membership,receiver,epoch,destination,binding_version,item_cursor,control_cursor FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",params![pins.workspace_id,pins.mailbox_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(db_error)?;
        if membership != pins.membership_id
            || receiver != pins.receiver_id
            || epoch != pins.epoch
            || destination != pins.destination_digest
            || version != pins.binding_version
        {
            return Err(failure("INBOX_BINDING_MISMATCH"));
        }
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT workspace,mailbox FROM inbox_frames WHERE digest=?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        if let Some((ws, mailbox)) = prior {
            if ws != pins.workspace_id || mailbox != pins.mailbox_id {
                return Err(invalid());
            }
            return Ok(Cursor {
                item: cursor,
                control,
            });
        }
        if cursor != pins.after_sequence || control != pins.after_control_sequence {
            return Err(failure("INBOX_CURSOR_CONFLICT"));
        }
        let (_allocated, rows): (usize, usize) = tx
            .query_row(
                "SELECT allocated,rows FROM inbox_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        if rows + page.items().len() > 65536 {
            return Err(failure("INBOX_CAPACITY"));
        }
        tx.execute(
            "INSERT INTO inbox_frames VALUES(?1,?2,?3,?4,?5)",
            params![hash, pins.workspace_id, pins.mailbox_id, sealed, allocation],
        )
        .map_err(db_error)?;
        let mut garbage = std::collections::BTreeSet::new();
        let old_frame: Option<String> = tx
            .query_row(
                "SELECT last_frame FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",
                params![pins.workspace_id, pins.mailbox_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if let Some(frame) = old_frame {
            garbage.insert(frame);
        }
        let mut added = 0;
        for (index, item) in page.items().iter().enumerate() {
            let value = item.envelope();
            let digest = sha256_hex(
                canonical_wire_value(value, CanonicalPath::STRUCTURED)
                    .map_err(|_| invalid())?
                    .as_bytes(),
            );
            let kind = text(value, "kind")?;
            let terminal = value.get("terminal_reason").and_then(WireValue::as_string);
            let old:Option<(String,String,String,String)>=tx.query_row("SELECT delivery_id,kind,item_digest,status FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![pins.workspace_id,pins.mailbox_id,item.sequence()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(db_error)?;
            if let Some((id, old_kind, old_digest, status)) = old {
                if id != item.delivery_id()
                    || old_kind != kind
                    || old_digest != digest && terminal.is_none() && status != "TERMINAL"
                {
                    return Err(failure("INBOX_ITEM_CONFLICT"));
                }
                if let Some(reason) = terminal {
                    tx.execute("UPDATE inbox_items SET status='TERMINAL',terminal_reason=COALESCE(terminal_reason,?4) WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![pins.workspace_id,pins.mailbox_id,item.sequence(),reason]).map_err(db_error)?;
                }
                continue;
            }
            tx.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status,terminal_reason) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![pins.workspace_id,pins.mailbox_id,item.sequence(),item.delivery_id(),kind,hash,index,digest,if terminal.is_some(){"TERMINAL"}else{"PENDING"},terminal]).map_err(db_error)?;
            if let Some(reference) = &key_refs[index] {
                key_queue::insert_ref(&tx, pins, item.sequence(), reference, known_keys)?;
            }
            let lane = if let Some(message) = item.message() {
                format!("MESSAGE:{}", message.context().conversation_id)
            } else {
                format!(
                    "BUSINESS:{}",
                    value
                        .get("business")
                        .and_then(|v| v.get("instance_id"))
                        .and_then(WireValue::as_string)
                        .unwrap_or_default()
                )
            };
            tx.execute(
                "INSERT INTO inbox_item_lanes VALUES(?1,?2,?3,?4)",
                params![
                    pins.workspace_id,
                    pins.mailbox_id,
                    item.sequence(),
                    sha256_hex(lane.as_bytes())
                ],
            )
            .map_err(db_error)?;
            added += 1;
            for (kind, subject, revision) in &subjects[index] {
                tx.execute(
                    "INSERT INTO inbox_subjects VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        pins.workspace_id,
                        pins.mailbox_id,
                        kind,
                        subject,
                        revision,
                        item.sequence()
                    ],
                )
                .map_err(db_error)?;
            }
        }
        for control in page.controls() {
            let target = control.get("target").ok_or_else(invalid)?;
            if text(control, "kind")? == "communication.message.withdrawn" {
                // One native message withdrawal names exactly one delivery.
                let delivery = text(target, "delivery_id")?;
                tx.execute("DELETE FROM inbox_key_refs WHERE workspace=?1 AND mailbox=?2 AND sequence=(SELECT sequence FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND delivery_id=?3)",params![pins.workspace_id,pins.mailbox_id,delivery]).map_err(db_error)?;
            }
            let (kind, subject, revision, reason) = match text(control, "kind")?.as_str() {
                "record.withdrawn" => ("RECORD", text(target, "record_id")?, 0, "SOURCE_WITHDRAWN"),
                "communication.message.withdrawn" => (
                    "MESSAGE",
                    text(target, "message_id")?,
                    0,
                    "MESSAGE_WITHDRAWN",
                ),
                "communication.subscription.changed" => (
                    "SUBSCRIPTION",
                    text(target, "subscription_id")?,
                    number(target, "stopped_revision")?,
                    "SUBSCRIPTION_STOPPED",
                ),
                _ => return Err(invalid()),
            };
            let prior:Option<String>=tx.query_row("SELECT frame FROM inbox_terminal WHERE workspace=?1 AND mailbox=?2 AND kind=?3 AND subject=?4",params![pins.workspace_id,pins.mailbox_id,kind,subject],|r|r.get(0)).optional().map_err(db_error)?;
            if let Some(old) = prior {
                garbage.insert(old);
            }
            tx.execute("INSERT INTO inbox_terminal VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(workspace,mailbox,kind,subject) DO UPDATE SET revision=max(revision,excluded.revision),frame=excluded.frame,retire_after=max(retire_after,excluded.retire_after)",params![pins.workspace_id,pins.mailbox_id,kind,subject,revision,reason,hash,page.mailbox_frontier()]).map_err(db_error)?;
            // Project terminal state lazily for the selected <=32 entries.
            // STOP never expands into a write over all retained deliveries.
        }
        tx.execute(
            "UPDATE inbox_meta SET allocated=allocated+?1,rows=rows+?2 WHERE id=1",
            params![allocation, added],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE inbox_mailboxes SET item_cursor=?3,control_cursor=?4,last_frame=?5 WHERE workspace=?1 AND mailbox=?2",params![pins.workspace_id,pins.mailbox_id,page.checkpoint(),page.control_checkpoint(),hash]).map_err(db_error)?;
        retire_terminals(
            &tx,
            &pins.workspace_id,
            &pins.mailbox_id,
            page.checkpoint(),
            &mut garbage,
        )?;
        collect_frames(&tx, &garbage)?;
        let allocated: usize = tx
            .query_row("SELECT allocated FROM inbox_meta WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(db_error)?;
        if allocated > max_bytes {
            return Err(failure("INBOX_CAPACITY"));
        }
        tx.commit().map_err(db_error)?;
        Ok(Cursor {
            item: page.checkpoint(),
            control: Some(page.control_checkpoint()),
        })
    }
    /// Return selected pending entries, suppressing terminal payloads. Decrypted
    /// message bodies are opened only on application access and are never stored.
    pub fn pending(
        &self,
        identity: &KernelIdentity,
        workspace: &str,
        mailbox: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<Value>> {
        if identity.actor_id() != self.actor || identity.key_id() != self.key_id {
            return Err(failure("INBOX_BINDING_MISMATCH"));
        }
        if !(1..=32).contains(&limit) {
            return Err(invalid());
        }
        let rows=self.db.prepare("SELECT sequence,delivery_id,kind,frame,item_index,item_digest,status,terminal_reason FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND consume_requested=0 AND sequence>?3 ORDER BY sequence LIMIT ?4").map_err(db_error)?
            .query_map(params![workspace,mailbox,after,limit],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,usize>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,Option<String>>(7)?))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        let mut result = Vec::new();
        let mut cached_frame: Option<(String, WireValue)> = None;
        for (sequence, id, kind, frame, index, hash, mut status, mut terminal) in rows {
            let projected:Option<String>=self.db.query_row("SELECT t.reason FROM inbox_subjects s INDEXED BY inbox_subject_item JOIN inbox_terminal t ON t.workspace=s.workspace AND t.mailbox=s.mailbox AND t.kind=s.kind AND t.subject=s.subject WHERE s.workspace=?1 AND s.mailbox=?2 AND s.sequence=?3 AND (s.kind<>'SUBSCRIPTION' OR s.revision<=t.revision) LIMIT 1",params![workspace,mailbox,sequence],|r|r.get(0)).optional().map_err(db_error)?;
            if let Some(reason) = projected {
                status = "TERMINAL".into();
                terminal = Some(reason);
            }
            let mut entry = json!({"workspace_id":workspace,"mailbox_id":mailbox,"sequence":sequence,"delivery_id":id,"kind":kind,"state":status,"terminal_reason":terminal});
            if status == "PENDING" {
                if cached_frame
                    .as_ref()
                    .is_none_or(|(digest, _)| digest != &frame)
                {
                    let evidence:Vec<u8>=self.db.query_row("SELECT evidence FROM inbox_frames WHERE digest=?1 AND workspace=?2 AND mailbox=?3",params![frame,workspace,mailbox],|r|r.get(0)).map_err(db_error)?;
                    let wire = open_bounded(
                        identity,
                        &self.aad(workspace, mailbox, &frame),
                        &evidence,
                        MAX_FRAME_BYTES,
                    )
                    .map_err(|_| invalid())?;
                    if sha256_hex(wire.as_bytes()) != frame {
                        return Err(invalid());
                    }
                    let parsed = parse_wire_json_bounded(wire.as_bytes(), 40, MAX_FRAME_BYTES)
                        .map_err(|_| invalid())?;
                    cached_frame = Some((frame.to_string(), parsed));
                }
                let frame = &cached_frame.as_ref().ok_or_else(invalid)?.1;
                let Some(WireValue::Array(items)) = frame.get("items") else {
                    return Err(invalid());
                };
                let item = items.get(index).ok_or_else(invalid)?;
                if sha256_hex(
                    canonical_wire_value(item, CanonicalPath::STRUCTURED)
                        .map_err(|_| invalid())?
                        .as_bytes(),
                ) != hash
                {
                    return Err(invalid());
                }
                entry["envelope"] = json_value(item)?;
            }
            result.push(entry);
        }
        Ok(result)
    }
    pub fn consume(
        &mut self,
        workspace: &str,
        mailbox: &str,
        items: &[(u64, String)],
    ) -> Result<()> {
        if items.is_empty() || items.len() > 32 {
            return Err(invalid());
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        for (sequence, id) in items {
            let updated=tx.execute("UPDATE inbox_items SET consume_requested=1 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![workspace,mailbox,sequence,id]).map_err(db_error)?;
            if updated != 1 {
                let confirmed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_consumed WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4)",params![workspace,mailbox,sequence,id],|r|r.get(0)).map_err(db_error)?;
                if !confirmed {
                    return Err(failure("INBOX_ITEM_NOT_FOUND"));
                }
            }
            tx.execute("DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![workspace,mailbox,sequence,id]).map_err(db_error)?;
            tx.execute("UPDATE inbox_host_lanes SET state='RETIRED' WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND state='WAITING'",params![workspace,mailbox,sequence]).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(())
    }
    pub fn acknowledgements(
        &self,
        workspace: &str,
        mailbox: &str,
        consumed: bool,
    ) -> Result<Vec<(u64, String)>> {
        let sql = if consumed {
            "SELECT sequence,delivery_id FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND consume_requested=1 AND consumed_uploaded=0 ORDER BY sequence LIMIT 32"
        } else {
            "SELECT sequence,delivery_id FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND stored_uploaded=0 AND consume_requested=0 ORDER BY sequence LIMIT 32"
        };
        let result = self
            .db
            .prepare(sql)
            .map_err(db_error)?
            .query_map(params![workspace, mailbox], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db_error)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_error)?;
        Ok(result)
    }
    pub fn receiver_ack_pending(&self, workspace: &str, mailbox: &str) -> Result<bool> {
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND stored_uploaded=0)",params![workspace,mailbox],|r|r.get(0)).map_err(db_error)
    }
    pub fn acknowledged(
        &mut self,
        workspace: &str,
        mailbox: &str,
        items: &[(u64, String)],
        consumed: bool,
    ) -> Result<()> {
        if items.is_empty() || items.len() > 32 {
            return Err(invalid());
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let sql = if consumed {
            "UPDATE inbox_items SET stored_uploaded=1,consumed_uploaded=1 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4 AND consume_requested=1"
        } else {
            "UPDATE inbox_items SET stored_uploaded=1 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4"
        };
        let mut garbage = std::collections::BTreeSet::new();
        for (seq, id) in items {
            if consumed {
                let confirmed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_consumed WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4)",params![workspace,mailbox,seq,id],|r|r.get(0)).map_err(db_error)?;
                if confirmed {
                    continue;
                }
            }
            if tx
                .execute(sql, params![workspace, mailbox, seq, id])
                .map_err(db_error)?
                != 1
            {
                return Err(invalid());
            }
            if consumed {
                tx.execute(
                    "INSERT INTO inbox_consumed VALUES(?1,?2,?3,?4)",
                    params![workspace, mailbox, seq, id],
                )
                .map_err(db_error)?;
                let frame:String=tx.query_row("SELECT frame FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![workspace,mailbox,seq,id],|r|r.get(0)).map_err(db_error)?;
                garbage.insert(frame);
                tx.execute(
                    "DELETE FROM inbox_subjects WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",
                    params![workspace, mailbox, seq],
                )
                .map_err(db_error)?;
                tx.execute("DELETE FROM inbox_items WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![workspace,mailbox,seq,id]).map_err(db_error)?;
                tx.execute("DELETE FROM inbox_host_ready WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND delivery_id=?4",params![workspace,mailbox,seq,id]).map_err(db_error)?;

                tx.execute("UPDATE inbox_meta SET rows=rows-1 WHERE id=1", [])
                    .map_err(db_error)?;
            }
        }
        if consumed {
            // Keep a fixed retry window. Older confirmations remain available
            // through the service's selected message receipt, not a local scan.
            let cutoff:Option<u64>=tx.query_row("SELECT sequence FROM inbox_consumed WHERE workspace=?1 AND mailbox=?2 ORDER BY sequence DESC LIMIT 1 OFFSET 1023",params![workspace,mailbox],|r|r.get(0)).optional().map_err(db_error)?;
            if let Some(cutoff) = cutoff {
                tx.execute(
                    "DELETE FROM inbox_consumed WHERE workspace=?1 AND mailbox=?2 AND sequence<?3",
                    params![workspace, mailbox, cutoff],
                )
                .map_err(db_error)?;
            }
        }
        let cursor: u64 = tx
            .query_row(
                "SELECT item_cursor FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",
                params![workspace, mailbox],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        retire_terminals(&tx, workspace, mailbox, cursor, &mut garbage)?;
        collect_frames(&tx, &garbage)?;
        tx.commit().map_err(db_error)?;
        Ok(())
    }
}
/// Retire at most 32 projections per pass. The signed mailbox frontier at
/// disclosure is the barrier: all older obligations have then been selected,
/// and future accepted writes cannot resurrect withdrawn sources/old revisions.
fn retire_terminals(
    tx: &rusqlite::Transaction<'_>,
    workspace: &str,
    mailbox: &str,
    cursor: u64,
    garbage: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let after: String = tx
        .query_row(
            "SELECT gc_after FROM inbox_mailboxes WHERE workspace=?1 AND mailbox=?2",
            params![workspace, mailbox],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    let after: (u64, String, String) = serde_json::from_str(&after).map_err(|_| invalid())?;
    let rows=tx.prepare("SELECT retire_after,kind,subject,revision,frame FROM inbox_terminal INDEXED BY inbox_terminal_gc WHERE workspace=?1 AND mailbox=?2 AND retire_after<=?3 AND (retire_after,kind,subject)>(?4,?5,?6) ORDER BY retire_after,kind,subject LIMIT 32").map_err(db_error)?.query_map(params![workspace,mailbox,cursor,after.0,after.1,after.2],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,u64>(3)?,r.get::<_,String>(4)?))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
    for (_, kind, subject, revision, frame) in &rows {
        // Non-subscription subjects use revision zero. A direct range avoids
        // scanning newer reactivated revisions when no old references remain.
        let bound = if kind == "SUBSCRIPTION" { *revision } else { 0 };
        let live:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_subjects WHERE workspace=?1 AND mailbox=?2 AND kind=?3 AND subject=?4 AND revision<=?5 LIMIT 1)",params![workspace,mailbox,kind,subject,bound],|r|r.get(0)).map_err(db_error)?;
        if !live {
            tx.execute("DELETE FROM inbox_terminal WHERE workspace=?1 AND mailbox=?2 AND kind=?3 AND subject=?4",params![workspace,mailbox,kind,subject]).map_err(db_error)?;
            garbage.insert(frame.clone());
        }
    }
    let next = rows
        .last()
        .map(|r| (r.0, r.1.clone(), r.2.clone()))
        .unwrap_or((0, String::new(), String::new()));
    tx.execute(
        "UPDATE inbox_mailboxes SET gc_after=?3 WHERE workspace=?1 AND mailbox=?2",
        params![
            workspace,
            mailbox,
            serde_json::to_string(&next).map_err(|_| invalid())?
        ],
    )
    .map_err(db_error)?;
    Ok(())
}
fn collect_frames(
    tx: &rusqlite::Transaction<'_>,
    candidates: &std::collections::BTreeSet<String>,
) -> Result<()> {
    // Each caller supplies a bounded set of old references. Never scan history.
    for hash in candidates {
        let live:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM inbox_items WHERE frame=?1) OR EXISTS(SELECT 1 FROM inbox_mailboxes WHERE last_frame=?1) OR EXISTS(SELECT 1 FROM inbox_terminal WHERE frame=?1)",[hash],|r|r.get(0)).map_err(db_error)?;
        if live {
            continue;
        }
        let bytes: Option<usize> = tx
            .query_row(
                "SELECT allocation FROM inbox_frames WHERE digest=?1",
                [hash],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        if let Some(bytes) = bytes {
            tx.execute("DELETE FROM inbox_frames WHERE digest=?1", [hash])
                .map_err(db_error)?;
            tx.execute(
                "UPDATE inbox_meta SET allocated=allocated-?1 WHERE id=1",
                [bytes],
            )
            .map_err(db_error)?;
        }
    }
    Ok(())
}
fn subjects(value: &WireValue) -> Result<Vec<(String, String, u64)>> {
    if value.get("terminal_reason").is_some() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    if let Some(message) = value.get("message") {
        result.push(("MESSAGE".into(), text(message, "message_id")?, 0));
        // SOURCE references are signed in the original command. Use the already
        // verified envelope to derive the withdrawal index, never caller hints.
        let jws = text(message, "author_intent")?;
        let parts: Vec<_> = jws.split('.').collect();
        let payload = peerwork_core::crypto::decode_base64url(parts.get(1).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let command = parse_wire_json_bounded(&payload, 40, 180000).map_err(|_| invalid())?;
        let content = command
            .get("body")
            .and_then(|v| v.get("content"))
            .ok_or_else(invalid)?;
        if content
            .get("mode")
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("SOURCE")
        {
            result.push(("RECORD".into(), text(content, "record_id")?, 0));
        }
    } else if let Some(business) = value.get("business") {
        result.push((
            "SUBSCRIPTION".into(),
            text(value, "subscription_id")?,
            number(value, "subscription_revision")?,
        ));
        if let Some(WireValue::Array(ids)) = business
            .get("summary")
            .and_then(|v| v.get("produced_record_ids"))
        {
            if ids.len() > 128 {
                return Err(invalid());
            }
            for id in ids {
                result.push(("RECORD".into(), id.as_string().ok_or_else(invalid)?, 0));
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use peerwork_core::{
        canonical::canonical,
        communication::{verify_mailbox_frame, FramePins, FRAME_TYPE},
        crypto::{key_id, sign_compact},
    };
    fn pins() -> MailboxPins {
        MailboxPins {
            workspace_id: "W".repeat(43),
            mailbox_id: "M".repeat(43),
            membership_id: "G".repeat(43),
            receiver_id: "R".repeat(43),
            epoch: 1,
            destination_digest: "a".repeat(64),
            binding_version: 1,
            after_sequence: 0,
            after_control_sequence: Some(0),
        }
    }
    fn empty(
        identity: &KernelIdentity,
        key: &SigningKey,
        pins: &MailboxPins,
        control: u64,
    ) -> VerifiedMailboxPage {
        let hash = sha256_hex(b"[]");
        let audience = "inbox-test".encode_utf16().collect::<Vec<_>>();
        let service_key = key_id(&key.verifying_key().to_bytes());
        let stream = "S".repeat(43);
        let p = json!({"kind":"peerwork.mailbox-frame.v1","audience":"inbox-test","actor_id":identity.actor_id(),"stream_id":stream,"workspace_id":pins.workspace_id,"mailbox_id":pins.mailbox_id,"receiver_id":pins.receiver_id,"epoch":pins.epoch,"destination_digest":pins.destination_digest,"binding_version":pins.binding_version,"server_time":1000+control,"mailbox_frontier":pins.after_sequence,"checkpoint":pins.after_sequence,"more":false,"items_digest":hash,"control_checkpoint":control,"controls_more":false,"controls_digest":hash});
        let jws = sign_compact(
            &json!({"alg":"EdDSA","typ":FRAME_TYPE,"kid":service_key}),
            &p,
            key,
        )
        .unwrap();
        let wire = canonical(
            &json!({"proof":jws,"items":[],"controls":[]}),
            CanonicalPath::STRUCTURED,
        )
        .unwrap();
        verify_mailbox_frame(
            wire.as_bytes(),
            &FramePins {
                audience: &audience,
                actor_id: identity.actor_id(),
                stream_id: &stream,
                mailbox: pins,
                service_key: &service_key,
                server_time_floor: 0,
                expires_at: 61000,
            },
        )
        .unwrap()
    }
    #[test]
    fn empty_progress_is_compacted_atomically_and_pins_service_and_identity() {
        let directory = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&directory.path().join("identity")).unwrap();
        let key = SigningKey::from_bytes(&[41; 32]);
        let service_key = key_id(&key.verifying_key().to_bytes());
        let audience = "inbox-test".encode_utf16().collect::<Vec<_>>();
        let mut inbox = InboxStore::open(
            &directory.path().join("inbox"),
            &identity,
            "https://example.invalid/",
            &audience,
            &service_key,
        )
        .unwrap();
        let mut current = pins();
        inbox.register(&current).unwrap();
        let first = empty(&identity, &key, &current, 1);
        assert_eq!(
            inbox.ingest(&identity, &first, 1).unwrap_err().code,
            "INBOX_CAPACITY"
        );
        assert_eq!(
            inbox
                .cursor(&current.workspace_id, &current.mailbox_id)
                .unwrap()
                .unwrap()
                .control,
            Some(0)
        );
        for next in 1..=120 {
            let page = empty(&identity, &key, &current, next);
            inbox.ingest(&identity, &page, 16384).unwrap();
            current.after_control_sequence = Some(next);
        }
        assert_eq!(
            inbox
                .db
                .query_row("SELECT count(*) FROM inbox_frames", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert!(
            inbox
                .db
                .query_row("SELECT allocated FROM inbox_meta", [], |r| r
                    .get::<_, usize>(0))
                .unwrap()
                < 16384
        );
        let different = crate::test_support::protected_test_dir();
        let other_key = key_id(&SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes());
        let mut other = InboxStore::open(
            &different.path().join("inbox"),
            &identity,
            "https://other.invalid/",
            &audience,
            &other_key,
        )
        .unwrap();
        other.register(&pins()).unwrap();
        assert!(other.ingest(&identity, &first, 16384).is_err());
        let stranger = KernelIdentity::create(&directory.path().join("stranger")).unwrap();
        assert!(inbox
            .ingest(&stranger, &empty(&stranger, &key, &current, 121), 16384)
            .is_err());
        drop(inbox);
        let inbox = InboxStore::open(
            &directory.path().join("inbox"),
            &identity,
            "https://example.invalid/",
            &audience,
            &service_key,
        )
        .unwrap();
        assert_eq!(
            inbox
                .cursor(&current.workspace_id, &current.mailbox_id)
                .unwrap()
                .unwrap()
                .control,
            Some(120)
        );
    }
    #[test]
    fn stopped_subscription_projects_only_selected_items_without_history_updates() {
        let directory = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&directory.path().join("identity")).unwrap();
        let key = SigningKey::from_bytes(&[41; 32]);
        let service_key = key_id(&key.verifying_key().to_bytes());
        let audience = "inbox-test".encode_utf16().collect::<Vec<_>>();
        let pins = pins();
        let mut inbox = InboxStore::open(
            &directory.path().join("inbox"),
            &identity,
            "https://example.invalid/",
            &audience,
            &service_key,
        )
        .unwrap();
        inbox.register(&pins).unwrap();
        let page = empty(&identity, &key, &pins, 1);
        inbox.ingest(&identity, &page, 16384).unwrap();
        let hash = sha256_hex(page.frame_wire().unwrap().as_bytes());
        // Populate a retained-history fixture to check the indexed projection,
        // not to claim these synthetic rows contain authenticated deliveries.
        let tx = inbox.db.transaction().unwrap();
        for seq in 1..=10000 {
            tx.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'BUSINESS',?5,0,'synthetic','PENDING')",params![pins.workspace_id,pins.mailbox_id,seq,format!("{seq:043}"),hash]).unwrap();
            tx.execute(
                "INSERT INTO inbox_subjects VALUES(?1,?2,'SUBSCRIPTION','subscription',1,?3)",
                params![pins.workspace_id, pins.mailbox_id, seq],
            )
            .unwrap();
        }
        tx.execute("INSERT INTO inbox_terminal VALUES(?1,?2,'SUBSCRIPTION','subscription',2,'SUBSCRIPTION_STOPPED',?3,10000)",params![pins.workspace_id,pins.mailbox_id,hash]).unwrap();
        tx.commit().unwrap();
        let selected = inbox
            .pending(&identity, &pins.workspace_id, &pins.mailbox_id, 0, 32)
            .unwrap();
        assert_eq!(selected.len(), 32);
        assert!(selected
            .iter()
            .all(|v| v["state"] == "TERMINAL" && v.get("envelope").is_none()));
        assert_eq!(
            inbox
                .db
                .query_row(
                    "SELECT count(*) FROM inbox_items WHERE status='PENDING'",
                    [],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            10000,
            "projection does not rewrite retained history"
        );
        let plan:Vec<String>=inbox.db.prepare("EXPLAIN QUERY PLAN SELECT t.reason FROM inbox_subjects s INDEXED BY inbox_subject_item JOIN inbox_terminal t ON t.workspace=s.workspace AND t.mailbox=s.mailbox AND t.kind=s.kind AND t.subject=s.subject WHERE s.workspace=?1 AND s.mailbox=?2 AND s.sequence=?3 AND (s.kind<>'SUBSCRIPTION' OR s.revision<=t.revision) LIMIT 1").unwrap().query_map(params![pins.workspace_id,pins.mailbox_id,1],|r|r.get(3)).unwrap().collect::<std::result::Result<_,_>>().unwrap();
        assert!(
            plan.iter().any(|v| v.contains("inbox_subject_item")),
            "{plan:?}"
        );
    }
    #[test]
    fn distinct_withdrawals_retire_after_signed_mailbox_frontier_without_capacity_growth() {
        let directory = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&directory.path().join("identity")).unwrap();
        let key = SigningKey::from_bytes(&[41; 32]);
        let service_key = key_id(&key.verifying_key().to_bytes());
        let audience = "inbox-test".encode_utf16().collect::<Vec<_>>();
        let mut current = pins();
        let mut inbox = InboxStore::open(
            &directory.path().join("inbox"),
            &identity,
            "https://example.invalid/",
            &audience,
            &service_key,
        )
        .unwrap();
        inbox.register(&current).unwrap();
        for next in 1..=120u64 {
            let record = format!("{next:043}");
            let command_id = format!("{:043}", next + 1000);
            let command = json!({"v":1,"audience":"inbox-test","actor_id":identity.actor_id(),"command_id":command_id,"authority":sha256_hex(identity.actor_id().as_bytes()),"method":"POST","path":"/api/workspace/v1/commands","action_id":"structure.record.withdraw","workspace_id":current.workspace_id,"instance_id":"I".repeat(43),"protocol_digest":"a".repeat(64),"expected_workspace_revision":null,"expected_instance_revision":1,"exact_input_refs":[],"issued_at":1,"expires_at":600001,"body":{"profile":"backend-structure-v1","record_id":record,"revision":1}});
            let author=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":identity.key_id()}),&command,identity.signing_key()).unwrap();
            let intent = sha256_hex(author.as_bytes());
            let result = json!({"profile":"backend-structure-v1","assurance":"BACKEND_CURRENT_STATE","workspace_id":current.workspace_id,"instance_id":command["instance_id"],"protocol_digest":command["protocol_digest"],"status":"APPLIED","revision":2,"author_intent":author,"event_sequence":next});
            let digest = sha256_hex(
                canonical(&result, CanonicalPath::STRUCTURED)
                    .unwrap()
                    .as_bytes(),
            );
            let receipt=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":service_key}),&json!({"v":1,"audience":"inbox-test","actor_id":identity.actor_id(),"workspace_id":current.workspace_id,"command_id":command_id,"intent_digest":intent,"result_digest":digest,"protocol_digest":command["protocol_digest"],"event_sequence":next,"instance_revision":2,"accepted_at":1000}),&key).unwrap();
            let controls = json!([{"sequence":next,"kind":"record.withdrawn","target":{"instance_id":command["instance_id"],"protocol_digest":command["protocol_digest"],"record_id":record,"revision":1},"intent_digest":intent,"author_intent":author,"source_response":{"command_id":command_id,"receipt":receipt,"result":result}}]);
            let proof = json!({"kind":"peerwork.mailbox-frame.v1","audience":"inbox-test","actor_id":identity.actor_id(),"stream_id":"S".repeat(43),"workspace_id":current.workspace_id,"mailbox_id":current.mailbox_id,"receiver_id":current.receiver_id,"epoch":current.epoch,"destination_digest":current.destination_digest,"binding_version":current.binding_version,"server_time":1000+next,"mailbox_frontier":1,"checkpoint":1,"more":false,"items_digest":sha256_hex(b"[]"),"control_checkpoint":next,"controls_more":false,"controls_digest":sha256_hex(canonical(&controls,CanonicalPath::STRUCTURED).unwrap().as_bytes())});
            let proof = sign_compact(
                &json!({"alg":"EdDSA","typ":FRAME_TYPE,"kid":service_key}),
                &proof,
                &key,
            )
            .unwrap();
            let wire = json!({"proof":proof,"items":[],"controls":controls}).to_string();
            let page = verify_mailbox_frame(
                wire.as_bytes(),
                &FramePins {
                    audience: &audience,
                    actor_id: identity.actor_id(),
                    stream_id: &"S".repeat(43),
                    mailbox: &current,
                    service_key: &service_key,
                    server_time_floor: 0,
                    expires_at: 61000,
                },
            )
            .unwrap();
            inbox.ingest(&identity, &page, 32768).unwrap();
            current.after_sequence = 1;
            current.after_control_sequence = Some(next);
        }
        assert_eq!(
            inbox
                .db
                .query_row("SELECT count(*) FROM inbox_terminal", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            inbox
                .db
                .query_row("SELECT count(*) FROM inbox_frames", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            inbox
                .cursor(&current.workspace_id, &current.mailbox_id)
                .unwrap()
                .unwrap()
                .control,
            Some(120)
        );
    }
    #[test]
    fn watch_registration_preserves_claim_identity_and_bounds_active_and_retained_rows() {
        let directory = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&directory.path().join("identity")).unwrap();
        let path = directory.path().join("inbox");
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        let options = |n: u64| crate::participant_watch::WatchOptions {
            host_destination: None,
            workspace_id: "W".repeat(43),
            mailbox_id: format!("{n:043}"),
            membership_id: "G".repeat(43),
            consumer_id: "program".into(),
        };
        let first = store
            .attach_watch(&identity, "program", &options(0))
            .unwrap();
        store
            .freeze_claim(&first, "original frozen synthetic claim")
            .unwrap();
        for n in 1..8 {
            store
                .attach_watch(&identity, "program", &options(n))
                .unwrap();
        }
        assert_eq!(
            store
                .attach_watch(&identity, "program", &options(8))
                .err()
                .unwrap()
                .code,
            "WATCH_SCOPE_LIMIT"
        );
        for n in 0..8 {
            store.disable_watch("program", &options(n)).unwrap();
        }
        for n in 8..256 {
            store
                .attach_watch(&identity, "program", &options(n))
                .unwrap();
            store.disable_watch("program", &options(n)).unwrap();
        }
        assert_eq!(
            store
                .attach_watch(&identity, "program", &options(256))
                .err()
                .unwrap()
                .code,
            "WATCH_BINDING_LIMIT"
        );
        drop(store);
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        let recovered = store
            .attach_watch(&identity, "program", &options(0))
            .unwrap();
        assert_eq!(recovered.receiver, first.receiver);
        assert_eq!(recovered.claim_id, first.claim_id);
        assert_eq!(
            recovered.claim_wire.as_deref(),
            Some("original frozen synthetic claim")
        );
        assert_eq!(
            store
                .freeze_claim(&recovered, "replacement")
                .unwrap_err()
                .code,
            "WATCH_CLAIM_CONFLICT"
        );
        assert_eq!(
            store
                .attach_watch(&identity, "another-program", &options(0))
                .err()
                .unwrap()
                .code,
            "WATCH_BINDING_MISMATCH"
        );
        let next = store.rotate_refused_claim(&recovered).unwrap();
        assert_ne!(next, recovered.claim_id);
        assert_eq!(
            store.rotate_refused_claim(&recovered).unwrap_err().code,
            "WATCH_CLAIM_CONFLICT"
        );
        drop(store);
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        let rotated = store
            .attach_watch(&identity, "program", &options(0))
            .unwrap();
        assert_eq!(rotated.claim_id, next);
        assert_eq!(rotated.receiver, recovered.receiver);
        assert!(rotated.claim_wire.is_none());
        assert_eq!(
            store.rotate_refused_claim(&rotated).unwrap_err().code,
            "WATCH_CLAIM_NOT_REFUSABLE"
        );
        store
            .db
            .execute(
                "UPDATE inbox_watches SET descriptor='{}' WHERE workspace=?1 AND mailbox=?2",
                params!["W".repeat(43), options(0).mailbox_id],
            )
            .unwrap();
        assert_eq!(
            store.watch_bindings().err().unwrap().code,
            "INBOX_STATE_INVALID"
        );
    }
    #[test]
    fn device_key_survives_reopen_and_missing_state_never_rotates_receiver() {
        let directory = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&directory.path().join("identity")).unwrap();
        let path = directory.path().join("inbox");
        let options = crate::participant_watch::WatchOptions {
            host_destination: None,
            workspace_id: "W".repeat(43),
            mailbox_id: "M".repeat(43),
            membership_id: "G".repeat(43),
            consumer_id: "program".into(),
        };
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        store.audience = "device-test".encode_utf16().collect();
        let original = store.attach_watch(&identity, "program", &options).unwrap();
        let body = json!({"claim_command_id":original.claim_id,"mailbox_id":options.mailbox_id,
            "receiver_id":original.receiver,"expected_epoch":null,"destination_digest":"d".repeat(64),"replace":false});
        let proof = store.receiver_proof(&identity, &original, &body).unwrap();
        drop(store);
        let mut store =
            InboxStore::open_local(&path, &identity, "https://example.invalid/").unwrap();
        store.audience = "device-test".encode_utf16().collect();
        let resumed = store.attach_watch(&identity, "program", &options).unwrap();
        assert_eq!(resumed.receiver, original.receiver);
        assert_eq!(
            store.receiver_proof(&identity, &resumed, &body).unwrap(),
            proof
        );
        store
            .db
            .execute("DELETE FROM inbox_receiver_keys", [])
            .unwrap();
        let error = store
            .attach_watch(&identity, "program", &options)
            .err()
            .unwrap();
        assert_eq!(error.code, "RECEIVER_CONTINUITY_KEY_MISSING");
        assert_eq!(error.recovery, "RESTORE_ORIGINAL_RECEIVER_STATE");
        let stored: String = store
            .db
            .query_row("SELECT receiver FROM inbox_watches", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, original.receiver);
    }
}
