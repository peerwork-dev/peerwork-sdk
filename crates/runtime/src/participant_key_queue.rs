//! Indexed receive-only key prerequisites. Tiny sealed derived references avoid
//! reopening large frames just to select a key. Original signed frames stay intact.
use super::*;
use peerwork_core::communication::MessageContent;
use std::collections::BTreeSet;

pub(super) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS inbox_key_needs(workspace TEXT NOT NULL,key_id TEXT NOT NULL,refs INTEGER NOT NULL,available INTEGER NOT NULL,wake_pending INTEGER NOT NULL DEFAULT 0,wake_mailbox TEXT NOT NULL DEFAULT '',wake_sequence INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(workspace,key_id));
        CREATE INDEX IF NOT EXISTS inbox_key_missing ON inbox_key_needs(workspace,available,key_id);
        CREATE INDEX IF NOT EXISTS inbox_key_waking ON inbox_key_needs(workspace,wake_pending,key_id);
        CREATE TABLE IF NOT EXISTS inbox_key_refs(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,sequence INTEGER NOT NULL,key_id TEXT NOT NULL,evidence BLOB NOT NULL,PRIMARY KEY(workspace,mailbox,sequence),FOREIGN KEY(workspace,mailbox,sequence) REFERENCES inbox_items(workspace,mailbox,sequence) ON DELETE CASCADE);
        CREATE INDEX IF NOT EXISTS inbox_key_witness ON inbox_key_refs(workspace,key_id,mailbox,sequence);
        CREATE TABLE IF NOT EXISTS inbox_key_cursor(workspace TEXT PRIMARY KEY,after_key TEXT NOT NULL DEFAULT '',after_wake TEXT NOT NULL DEFAULT '');
        CREATE TRIGGER IF NOT EXISTS inbox_key_ref_delete AFTER DELETE ON inbox_key_refs BEGIN
            UPDATE inbox_key_needs SET refs=refs-1 WHERE workspace=OLD.workspace AND key_id=OLD.key_id;
            DELETE FROM inbox_key_needs WHERE workspace=OLD.workspace AND key_id=OLD.key_id AND refs=0;
            DELETE FROM inbox_key_cursor WHERE workspace=OLD.workspace AND NOT EXISTS(SELECT 1 FROM inbox_key_needs WHERE workspace=OLD.workspace);
        END;
        CREATE TRIGGER IF NOT EXISTS inbox_key_item_retire AFTER UPDATE OF consume_requested,status ON inbox_items WHEN NEW.consume_requested=1 OR NEW.status='TERMINAL' BEGIN
            DELETE FROM inbox_key_refs WHERE workspace=NEW.workspace AND mailbox=NEW.mailbox AND sequence=NEW.sequence;
        END;") .map_err(db_error)
}
pub(super) struct Reference {
    key_id: String,
    evidence: Vec<u8>,
}
fn aad(binding: &str, workspace: &str, mailbox: &str, sequence: u64) -> String {
    json!([
        "peerwork.inbox-key-ref.v1",
        binding,
        workspace,
        mailbox,
        sequence
    ])
    .to_string()
}
pub(super) fn prepare_refs(
    identity: &KernelIdentity,
    binding: &str,
    page: &VerifiedMailboxPage,
    frame: &str,
) -> Result<Vec<Option<Reference>>> {
    let pins = page.mailbox();
    page.items().iter().map(|item| {
        if item.envelope().get("terminal_reason").is_some_and(|v|v.as_string().is_some()) { return Ok(None); }
        let Some(message)=item.message() else { return Ok(None); };
        let MessageContent::WorkspaceE2ee{body}=message.content() else { return Ok(None); };
        let proof=json!({"key_id":body.key_id,"delivery_id":item.delivery_id(),"frame":frame,"membership":pins.membership_id});
        let evidence=seal_bounded(identity,&aad(binding,&pins.workspace_id,&pins.mailbox_id,item.sequence()),&proof.to_string(),1024).map_err(|_|invalid())?;
        Ok(Some(Reference{key_id:body.key_id.clone(),evidence}))
    }).collect()
}
pub(super) fn insert_ref(
    tx: &rusqlite::Transaction<'_>,
    pins: &MailboxPins,
    sequence: u64,
    reference: &Reference,
    known: &BTreeSet<String>,
) -> Result<()> {
    let available = known.contains(&reference.key_id);
    tx.execute("INSERT INTO inbox_key_needs(workspace,key_id,refs,available) VALUES(?1,?2,1,?3) ON CONFLICT(workspace,key_id) DO UPDATE SET refs=refs+1",params![pins.workspace_id,reference.key_id,available]).map_err(db_error)?;
    tx.execute(
        "INSERT INTO inbox_key_refs VALUES(?1,?2,?3,?4,?5)",
        params![
            pins.workspace_id,
            pins.mailbox_id,
            sequence,
            reference.key_id,
            reference.evidence
        ],
    )
    .map_err(db_error)?;
    Ok(())
}
impl InboxStore {
    /// Advance the durable cursor before IO: unavailable keys/timeouts cannot
    /// monopolize the first batch after a restart. Each witness is <1KiB.
    pub fn key_batch(&mut self, identity: &KernelIdentity, workspace: &str) -> Result<Vec<String>> {
        if identity.actor_id() != self.actor || identity.key_id() != self.key_id {
            return Err(failure("INBOX_BINDING_MISMATCH"));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let after: String = tx
            .query_row(
                "SELECT after_key FROM inbox_key_cursor WHERE workspace=?1",
                [workspace],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?
            .unwrap_or_default();
        let select = |after: &str| -> Result<Vec<String>> {
            tx.prepare("SELECT key_id FROM inbox_key_needs WHERE workspace=?1 AND available=0 AND key_id>?2 ORDER BY key_id LIMIT 31").map_err(db_error)?.query_map(params![workspace,after],|r|r.get(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)
        };
        let mut ids = select(&after)?;
        if ids.is_empty() && !after.is_empty() {
            ids = select("")?;
        }
        for id in &ids {
            let (mailbox,seq,evidence,delivery,frame,membership):(String,u64,Vec<u8>,String,String,String)=tx.query_row("SELECT r.mailbox,r.sequence,r.evidence,i.delivery_id,i.frame,m.membership FROM inbox_key_refs r JOIN inbox_items i ON i.workspace=r.workspace AND i.mailbox=r.mailbox AND i.sequence=r.sequence JOIN inbox_mailboxes m ON m.workspace=r.workspace AND m.mailbox=r.mailbox WHERE r.workspace=?1 AND r.key_id=?2 ORDER BY r.mailbox,r.sequence LIMIT 1",params![workspace,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(db_error)?;
            let wire = open_bounded(
                identity,
                &aad(&self.binding, workspace, &mailbox, seq),
                &evidence,
                1024,
            )
            .map_err(|_| invalid())?;
            let proof: Value = serde_json::from_str(&wire).map_err(|_| invalid())?;
            if proof
                != json!({"key_id":id,"delivery_id":delivery,"frame":frame,"membership":membership})
            {
                return Err(invalid());
            }
        }
        if let Some(last) = ids.last() {
            tx.execute("INSERT INTO inbox_key_cursor(workspace,after_key) VALUES(?1,?2) ON CONFLICT(workspace) DO UPDATE SET after_key=excluded.after_key",params![workspace,last]).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)?;
        Ok(ids)
    }
    pub fn key_missing(&self, workspace: &str) -> Result<bool> {
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM inbox_key_needs WHERE workspace=?1 AND available=0)",
                [workspace],
                |r| r.get(0),
            )
            .map_err(db_error)
    }
    pub fn keys_checked(
        &mut self,
        workspace: &str,
        selected: &[String],
        missing: &BTreeSet<String>,
    ) -> Result<()> {
        if selected.len() > 32 {
            return Err(invalid());
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        for id in selected {
            let available = !missing.contains(id);
            tx.execute("UPDATE inbox_key_needs SET wake_pending=CASE WHEN ?3=0 THEN 0 WHEN available=0 THEN 1 ELSE wake_pending END,wake_mailbox=CASE WHEN available=0 THEN '' ELSE wake_mailbox END,wake_sequence=CASE WHEN available=0 THEN 0 ELSE wake_sequence END,available=?3 WHERE workspace=?1 AND key_id=?2",params![workspace,id,available]).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)
    }
    pub fn key_unavailable(
        &self,
        workspace: &str,
        mailbox: &str,
        sequence: u64,
        id: &str,
    ) -> Result<()> {
        // Only a locally verified exact item may downgrade a cached key fact.
        self.db.execute("UPDATE inbox_key_needs SET available=0,wake_pending=0 WHERE workspace=?1 AND key_id=?4 AND EXISTS(SELECT 1 FROM inbox_key_refs WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND key_id=?4)",params![workspace,mailbox,sequence,id]).map_err(db_error)?;
        Ok(())
    }
    /// At most 32 references for one fairly selected restored key. Never wake
    /// unrelated missing keys and never repeat the same prefix indefinitely.
    pub fn wake_key_heads(&mut self, workspace: &str) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let after: String = tx
            .query_row(
                "SELECT after_wake FROM inbox_key_cursor WHERE workspace=?1",
                [workspace],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?
            .unwrap_or_default();
        let choose = |after: &str| -> Result<Option<(String, String, u64)>> {
            tx.query_row("SELECT key_id,wake_mailbox,wake_sequence FROM inbox_key_needs WHERE workspace=?1 AND wake_pending=1 AND key_id>?2 ORDER BY key_id LIMIT 1",params![workspace,after],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)
        };
        let selected = choose(&after)?.or(choose("")?);
        if let Some((id, mailbox, sequence)) = selected {
            let rows=tx.prepare("SELECT mailbox,sequence FROM inbox_key_refs WHERE workspace=?1 AND key_id=?2 AND (mailbox,sequence)>(?3,?4) ORDER BY mailbox,sequence LIMIT 32").map_err(db_error)?.query_map(params![workspace,id,mailbox,sequence],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u64>(1)?))).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
            for (mailbox, seq) in &rows {
                tx.execute("UPDATE inbox_host_ready SET next_retry=0,code='KEY_READY' WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND code='CONTENT_KEY_REQUIRED'",params![workspace,mailbox,seq]).map_err(db_error)?;
            }
            if let Some((mailbox, seq)) = rows.last() {
                tx.execute("UPDATE inbox_key_needs SET wake_mailbox=?3,wake_sequence=?4,wake_pending=?5 WHERE workspace=?1 AND key_id=?2",params![workspace,id,mailbox,seq,rows.len()==32]).map_err(db_error)?;
            } else {
                tx.execute(
                    "UPDATE inbox_key_needs SET wake_pending=0 WHERE workspace=?1 AND key_id=?2",
                    params![workspace, id],
                )
                .map_err(db_error)?;
            }
            tx.execute("INSERT INTO inbox_key_cursor(workspace,after_wake) VALUES(?1,?2) ON CONFLICT(workspace) DO UPDATE SET after_wake=excluded.after_wake",params![workspace,id]).map_err(db_error)?;
        }
        tx.commit().map_err(db_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (
        crate::test_support::ProtectedTestDir,
        KernelIdentity,
        InboxStore,
        MailboxPins,
    ) {
        let dir = crate::test_support::protected_test_dir();
        let identity = KernelIdentity::create(&dir.path().join("identity")).unwrap();
        let mut store = InboxStore::open_local(
            &dir.path().join("inbox"),
            &identity,
            "https://example.invalid/",
        )
        .unwrap();
        let pins = MailboxPins {
            workspace_id: "W".repeat(43),
            mailbox_id: "M".repeat(43),
            membership_id: "G".repeat(43),
            receiver_id: "R".repeat(43),
            epoch: 1,
            destination_digest: "a".repeat(64),
            binding_version: 1,
            after_sequence: 0,
            after_control_sequence: Some(0),
        };
        store.register(&pins).unwrap();
        // These rows exercise the local derived index, not service verification.
        store
            .db
            .execute(
                "INSERT INTO inbox_frames VALUES('frame',?1,?2,X'00',0)",
                params![pins.workspace_id, pins.mailbox_id],
            )
            .unwrap();
        (dir, identity, store, pins)
    }
    fn add(
        store: &mut InboxStore,
        identity: &KernelIdentity,
        pins: &MailboxPins,
        seq: u64,
        key: &str,
    ) {
        let id = format!("{seq:043}");
        let proof =
            json!({"key_id":key,"delivery_id":id,"frame":"frame","membership":pins.membership_id});
        let reference = Reference {
            key_id: key.into(),
            evidence: seal_bounded(
                identity,
                &aad(&store.binding, &pins.workspace_id, &pins.mailbox_id, seq),
                &proof.to_string(),
                1024,
            )
            .unwrap(),
        };
        let tx = store.db.transaction().unwrap();
        tx.execute("INSERT INTO inbox_items(workspace,mailbox,sequence,delivery_id,kind,frame,item_index,item_digest,status) VALUES(?1,?2,?3,?4,'MESSAGE','frame',0,'test','PENDING')",params![pins.workspace_id,pins.mailbox_id,seq,id]).unwrap();
        insert_ref(&tx, pins, seq, &reference, &BTreeSet::new()).unwrap();
        tx.commit().unwrap();
    }
    #[test]
    fn unavailable_batches_rotate_across_restart_and_preserve_unselected_needs() {
        let (dir, identity, mut store, pins) = fixture();
        for seq in 1..=70 {
            add(&mut store, &identity, &pins, seq, &format!("{seq:043}"));
        }
        let first = store.key_batch(&identity, &pins.workspace_id).unwrap();
        assert_eq!(first.len(), 31);
        // No result at all: emulate interrupted network IO, then reopen.
        drop(store);
        let mut store = InboxStore::open_local(
            &dir.path().join("inbox"),
            &identity,
            "https://example.invalid/",
        )
        .unwrap();
        let second = store.key_batch(&identity, &pins.workspace_id).unwrap();
        assert_eq!(second.len(), 31);
        assert!(second.iter().all(|id| !first.contains(id)));
        let third = store.key_batch(&identity, &pins.workspace_id).unwrap();
        assert_eq!(third.len(), 8);
        assert_eq!(
            store.key_batch(&identity, &pins.workspace_id).unwrap(),
            first
        );
        let missing = second.iter().skip(1).cloned().collect();
        store
            .keys_checked(&pins.workspace_id, &second, &missing)
            .unwrap();
        assert!(store.key_missing(&pins.workspace_id).unwrap());
        let ready: Vec<String> = store
            .db
            .prepare("SELECT key_id FROM inbox_key_needs WHERE available=1")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(ready, vec![second[0].clone()]);
        // Corrupt derived metadata cannot select another key or advance a cursor.
        store
            .db
            .execute(
                "UPDATE inbox_key_refs SET evidence=X'00' WHERE sequence=2",
                [],
            )
            .unwrap();
        store
            .db
            .execute("UPDATE inbox_key_cursor SET after_key=''", [])
            .unwrap();
        assert_eq!(
            store
                .key_batch(&identity, &pins.workspace_id)
                .unwrap_err()
                .code,
            "INBOX_STATE_INVALID"
        );
        let cursor: String = store
            .db
            .query_row("SELECT after_key FROM inbox_key_cursor", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cursor, "");
    }
    #[test]
    fn restored_keys_wake_selectively_in_bounded_pages_and_retire_with_items() {
        let (_dir, identity, mut store, pins) = fixture();
        let restored = "K".repeat(43);
        let unavailable = "Z".repeat(43);
        for seq in 1..=71 {
            add(
                &mut store,
                &identity,
                &pins,
                seq,
                if seq == 71 { &unavailable } else { &restored },
            );
            store.db.execute("INSERT INTO inbox_host_ready(workspace,mailbox,sequence,delivery_id,host,next_retry,failures,attempts,code) VALUES(?1,?2,?3,?4,'host',9999999999999,1,0,'CONTENT_KEY_REQUIRED')",params![pins.workspace_id,pins.mailbox_id,seq,format!("{seq:043}")]).unwrap();
        }
        store
            .keys_checked(
                &pins.workspace_id,
                &[restored.clone(), unavailable.clone()],
                &BTreeSet::from([unavailable.clone()]),
            )
            .unwrap();
        store.wake_key_heads(&pins.workspace_id).unwrap();
        let count = |s: &InboxStore| {
            s.db.query_row(
                "SELECT count(*) FROM inbox_host_ready WHERE next_retry=0",
                [],
                |r| r.get::<_, u32>(0),
            )
            .unwrap()
        };
        assert_eq!(count(&store), 32);
        // Rechecking the current head does not reset a long wake traversal.
        store
            .keys_checked(&pins.workspace_id, &[restored.clone()], &BTreeSet::new())
            .unwrap();
        store.wake_key_heads(&pins.workspace_id).unwrap();
        assert_eq!(count(&store), 64);
        store.wake_key_heads(&pins.workspace_id).unwrap();
        assert_eq!(count(&store), 70);
        assert!(store.key_missing(&pins.workspace_id).unwrap());
        store
            .consume(
                &pins.workspace_id,
                &pins.mailbox_id,
                &[(71, format!("{:043}", 71))],
            )
            .unwrap();
        assert!(!store.key_missing(&pins.workspace_id).unwrap());
        store.db.execute("DELETE FROM inbox_items", []).unwrap();
        assert_eq!(
            store
                .db
                .query_row("SELECT count(*) FROM inbox_key_needs", [], |r| r
                    .get::<_, u32>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .db
                .query_row("SELECT count(*) FROM inbox_key_cursor", [], |r| r
                    .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
}
