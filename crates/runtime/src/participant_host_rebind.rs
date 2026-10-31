//! Local half of an explicit, stopped-dispatcher physical rebind. Remote pins
//! must already be independently verified; ordinary register/attach never move
//! them. This module performs no network or host IO and never creates a call.
use super::*;

#[derive(Clone)]
pub(crate) struct HostRebind {
    pub operation_id: String,
    pub namespace: String,
    pub old: WatchOptions,
    pub new: WatchOptions,
    pub expected: MailboxPins,
    pub confirmed: MailboxPins,
    pub host: HostBinding,
}
fn pins(p: &MailboxPins) -> Value {
    json!({"workspace_id":p.workspace_id,"mailbox_id":p.mailbox_id,"membership_id":p.membership_id,
        "receiver_id":p.receiver_id,"epoch":p.epoch,"destination_digest":p.destination_digest,
        "binding_version":p.binding_version,"after_sequence":p.after_sequence,"after_control_sequence":p.after_control_sequence})
}
pub(super) fn lane_key(version: u64, host: &str, original: &str) -> String {
    if version == 1 {
        original.into()
    } else {
        json!(["peerwork.host-lane.v2", version, host, original]).to_string()
    }
}
pub(super) fn initialize(db: &Connection) -> Result<()> {
    let had:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbox_host_retired_v2')",[],|r|r.get(0)).map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS inbox_host_retired_v2(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,host TEXT NOT NULL,through_sequence INTEGER NOT NULL,lane_after INTEGER NOT NULL,lane_pending INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox,host));
        CREATE TABLE IF NOT EXISTS inbox_host_rebinds(workspace TEXT NOT NULL,mailbox TEXT NOT NULL,version INTEGER NOT NULL,digest TEXT NOT NULL,namespace TEXT NOT NULL,old_watch TEXT NOT NULL,old_host TEXT NOT NULL,old_pins TEXT NOT NULL,phase TEXT NOT NULL,cursor INTEGER NOT NULL,allocation INTEGER NOT NULL,PRIMARY KEY(workspace,mailbox,version));
        CREATE INDEX IF NOT EXISTS inbox_host_rebind_phase ON inbox_host_rebinds(workspace,mailbox,phase);
        CREATE INDEX IF NOT EXISTS inbox_host_scope_lane_state ON inbox_host_lanes(workspace,mailbox,state,sequence);").map_err(db_error)?;
    if !had {
        // The old table contains one metadata row per retained mailbox (<=256),
        // not event history. Copy once, transactionally; retain the old table.
        let count: u64 = tx
            .query_row("SELECT count(*) FROM inbox_host_retired", [], |r| r.get(0))
            .map_err(db_error)?;
        if count > 256 {
            return Err(invalid());
        }
        tx.execute(
            "INSERT INTO inbox_host_retired_v2 SELECT * FROM inbox_host_retired",
            [],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)
}
impl InboxStore {
    pub(crate) fn host_rebind_available(&self, options: &WatchOptions) -> Result<()> {
        let pending:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_rebinds WHERE workspace=?1 AND mailbox=?2 AND phase='COPYING')",params![options.workspace_id,options.mailbox_id],|r|r.get(0)).map_err(db_error)?;
        if pending {
            return Err(failure("HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"));
        }
        Ok(())
    }
    /// Historical evidence access is separate from an active delivery link.
    /// This check never grants watch/claim/deliver authority to the old binding.
    pub(super) fn host_evidence_scope(
        &self,
        namespace: &str,
        options: &WatchOptions,
    ) -> Result<bool> {
        match self.host_link(namespace, options) {
            Ok(_) => return Ok(false),
            Err(e)
                if matches!(
                    e.code.as_str(),
                    "HOST_BINDING_MISMATCH"
                        | "HOST_EVIDENCE_SCOPE_MISMATCH"
                        | "HOST_REBIND_PENDING_RESUME_ORIGINAL_OPERATION"
                ) =>
            {
                ()
            }
            Err(e) => return Err(e),
        }
        options.validate()?;
        let wire = serde_json::to_string(options).map_err(|_| invalid())?;
        let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_rebinds WHERE workspace=?1 AND mailbox=?2 AND namespace=?3 AND old_watch=?4)",params![options.workspace_id,options.mailbox_id,namespace,wire],|r|r.get(0)).map_err(db_error)?;
        if !exists {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        Ok(true)
    }
    /// An active receiver may upload facts for its original anchored calls.
    /// The archived binding/version must match the immutable decrypted scope.
    pub(super) fn host_original_scope(
        &self,
        namespace: &str,
        options: &WatchOptions,
        call: &HostCall,
    ) -> Result<()> {
        if call.scope["namespace"] != namespace
            || call.scope["workspace_id"] != options.workspace_id
            || call.scope["mailbox_id"] != options.mailbox_id
            || call.scope["membership_id"] != options.membership_id
        {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        let current = self
            .pins(&options.workspace_id, &options.mailbox_id)?
            .ok_or_else(invalid)?;
        if call.scope["destination_digest"] == current.destination_digest
            && call.scope["binding_version"] == current.binding_version
            && call.scope["receiver_id"] == current.receiver_id
        {
            return Ok(());
        }
        let row:Option<String>=self.db.query_row("SELECT old_pins FROM inbox_host_rebinds WHERE workspace=?1 AND mailbox=?2 AND namespace=?3 AND version=?4",params![options.workspace_id,options.mailbox_id,namespace,call.scope["binding_version"].as_u64().ok_or_else(invalid)?],|r|r.get(0)).optional().map_err(db_error)?;
        let old: Value =
            serde_json::from_str(&row.ok_or_else(|| failure("HOST_EVIDENCE_SCOPE_MISMATCH"))?)
                .map_err(|_| invalid())?;
        if ["receiver_id", "destination_digest", "binding_version"]
            .iter()
            .any(|k| old[*k] != call.scope[*k])
            || call.scope["epoch"]
                .as_u64()
                .is_none_or(|v| v > old["epoch"].as_u64().unwrap_or(0))
        {
            return Err(failure("HOST_EVIDENCE_SCOPE_MISMATCH"));
        }
        Ok(())
    }
    /// Exact original-call access; no latest-call substitution, host IO or retry.
    pub(crate) fn host_original_call(
        &self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
        id: &str,
    ) -> Result<HostCall> {
        self.host_evidence_scope(namespace, options)?;
        let call = self.host_call(identity, id)?;
        self.host_original_scope(namespace, options, &call)?;
        Ok(call)
    }
    pub(crate) fn host_rebind_commit(&mut self, selection: &HostRebind) -> Result<Value> {
        self.host_rebind_with_boundary(selection, |_| Ok(()))
    }
    fn host_rebind_with_boundary(
        &mut self,
        s: &HostRebind,
        mut boundary: impl FnMut(&str) -> Result<()>,
    ) -> Result<Value> {
        s.old.validate()?;
        s.new.validate()?;
        s.expected.validate().map_err(|_| invalid())?;
        s.confirmed.validate().map_err(|_| invalid())?;
        s.host.validate()?;
        let mut changed = s.old.clone();
        changed.host_destination = Some(s.host.digest.clone());
        if changed != s.new
            || s.old.host_destination.as_deref() != Some(&s.expected.destination_digest)
            || s.expected.destination_digest == s.host.digest
            || s.confirmed.destination_digest != s.host.digest
            || s.confirmed.epoch != s.expected.epoch.checked_add(1).ok_or_else(invalid)?
            || s.confirmed.binding_version
                != s.expected
                    .binding_version
                    .checked_add(1)
                    .ok_or_else(invalid)?
            || [&s.old.workspace_id, &s.expected.workspace_id]
                .iter()
                .any(|v| *v != &s.confirmed.workspace_id)
            || s.old.mailbox_id != s.expected.mailbox_id
            || s.old.mailbox_id != s.confirmed.mailbox_id
            || s.old.membership_id != s.expected.membership_id
            || s.old.membership_id != s.confirmed.membership_id
            || s.expected.receiver_id != s.confirmed.receiver_id
            || s.expected.after_sequence != s.confirmed.after_sequence
            || s.expected.after_control_sequence != s.confirmed.after_control_sequence
            || s.operation_id.len() != 43
            || !s
                .operation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(failure("HOST_REBIND_SELECTION_INVALID"));
        }
        let digest = sha256_hex(
            json!([
                "peerwork.host-rebind.v1",
                self.binding,
                s.operation_id,
                s.namespace,
                s.old,
                s.new,
                pins(&s.expected),
                pins(&s.confirmed),
                s.host
            ])
            .to_string()
            .as_bytes(),
        );
        let row:Option<(String,String,u64)>=self.db.query_row("SELECT digest,phase,cursor FROM inbox_host_rebinds WHERE workspace=?1 AND mailbox=?2 AND version=?3",params![s.old.workspace_id,s.old.mailbox_id,s.expected.binding_version],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
        let mut cursor = 0;
        if let Some((old, phase, after)) = row {
            if old != digest {
                return Err(failure("HOST_REBIND_ORIGINAL_SELECTION_REQUIRED"));
            }
            if phase == "COMMITTED" {
                return Ok(
                    json!({"state":"LOCAL_REBIND_COMMITTED","operation_id":s.operation_id,"replayed":true,"readiness":"NOT_ATTESTED"}),
                );
            }
            if phase != "COPYING" {
                return Err(invalid());
            }
            cursor = after;
        } else {
            self.host_watch_scope(&s.namespace, &s.old)?;
            let (host, _) = self.host_link(&s.namespace, &s.old)?;
            if host != s.expected.destination_digest
                || self
                    .pins(&s.old.workspace_id, &s.old.mailbox_id)?
                    .as_ref()
                    .map(pins)
                    != Some(pins(&s.expected))
            {
                return Err(failure("HOST_REBIND_SOURCE_CHANGED"));
            }
            let enabled: bool = self
                .db
                .query_row(
                    "SELECT enabled FROM inbox_watches WHERE workspace=?1 AND mailbox=?2",
                    params![s.old.workspace_id, s.old.mailbox_id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if enabled {
                return Err(failure("HOST_REBIND_STOP_DISPATCHER_FIRST"));
            }
            let pending:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND report_pending>0)",params![s.old.workspace_id,s.old.mailbox_id],|r|r.get(0)).map_err(db_error)?;
            if pending {
                return Err(failure("HOST_REBIND_FLUSH_ORIGINAL_REPORTS_FIRST"));
            }
            let descriptor: String = self
                .db
                .query_row(
                    "SELECT descriptor FROM inbox_host_links WHERE workspace=?1 AND mailbox=?2",
                    params![s.old.workspace_id, s.old.mailbox_id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            let old = serde_json::to_string(&s.old).map_err(|_| invalid())?;
            let oldpins = pins(&s.expected).to_string();
            let allocation = old.len() + descriptor.len() + oldpins.len() + 1024;
            let tx = self.db.transaction().map_err(db_error)?;
            let (bytes, rows): (usize, usize) = tx
                .query_row(
                    "SELECT allocated,rows FROM inbox_host_meta WHERE id=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(db_error)?;
            if bytes.saturating_add(allocation) > 32 * 1024 * 1024 || rows >= 65536 {
                return Err(failure("HOST_STATE_CAPACITY"));
            }
            tx.execute(
                "INSERT INTO inbox_host_rebinds VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'COPYING',0,?9)",
                params![
                    s.old.workspace_id,
                    s.old.mailbox_id,
                    s.expected.binding_version,
                    digest,
                    s.namespace,
                    old,
                    descriptor,
                    oldpins,
                    allocation
                ],
            )
            .map_err(db_error)?;
            tx.execute(
                "UPDATE inbox_host_meta SET allocated=allocated+?1,rows=rows+1 WHERE id=1",
                [allocation],
            )
            .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            boundary("FENCED")?;
        }
        // Explicit maintenance only. Each copied page and its cursor commit
        // together; attachment stays fenced until the final pointer swap.
        let mut copied_all = false;
        for _ in 0..=2048 {
            let rows=self.db.prepare("SELECT sequence FROM inbox_host_lanes WHERE workspace=?1 AND mailbox=?2 AND state='WAITING' AND sequence>?3 ORDER BY sequence LIMIT 32").map_err(db_error)?.query_map(params![s.old.workspace_id,s.old.mailbox_id,cursor],|r|r.get::<_,u64>(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
            let tx = self.db.transaction().map_err(db_error)?;
            for sequence in &rows {
                let original:String=tx.query_row("SELECT COALESCE((SELECT lane FROM inbox_item_lanes WHERE workspace=?1 AND mailbox=?2 AND sequence=?3),'MAILBOX')",params![s.old.workspace_id,s.old.mailbox_id,sequence],|r|r.get(0)).map_err(db_error)?;
                let lane = lane_key(s.confirmed.binding_version, &s.host.digest, &original);
                tx.execute("UPDATE inbox_host_lanes SET lane=?4 WHERE workspace=?1 AND mailbox=?2 AND sequence=?3 AND state='WAITING'",params![s.old.workspace_id,s.old.mailbox_id,sequence,lane]).map_err(db_error)?;
                tx.execute("UPDATE inbox_host_ready SET host=?4,next_retry=0,failures=0,code=NULL WHERE workspace=?1 AND mailbox=?2 AND sequence=?3",params![s.old.workspace_id,s.old.mailbox_id,sequence,s.host.digest]).map_err(db_error)?;
                // Retagging alone leaves an unattempted queue stranded behind
                // the old unknown head. Schedule its new head while fenced.
                promote_lane(
                    &tx,
                    &s.old.workspace_id,
                    &s.old.mailbox_id,
                    &lane,
                    &s.host.digest,
                )?;
            }
            if let Some(last) = rows.last() {
                cursor = *last;
            }
            tx.execute("UPDATE inbox_host_rebinds SET cursor=?4 WHERE workspace=?1 AND mailbox=?2 AND version=?3",params![s.old.workspace_id,s.old.mailbox_id,s.expected.binding_version,cursor]).map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            boundary("PAGE")?;
            if rows.len() < 32 {
                copied_all = true;
                break;
            }
        }
        if !copied_all {
            return Err(failure(
                "HOST_REBIND_COPY_PENDING_RESUME_ORIGINAL_OPERATION",
            ));
        }
        if self
            .pins(&s.old.workspace_id, &s.old.mailbox_id)?
            .as_ref()
            .map(pins)
            != Some(pins(&s.expected))
        {
            return Err(failure("HOST_REBIND_SOURCE_CHANGED"));
        }
        let tx = self.db.transaction().map_err(db_error)?;
        let next = peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(
            format!("peerwork.rebind-restart.v1\0{}", s.operation_id).as_bytes(),
        ));
        tx.execute("UPDATE inbox_mailboxes SET epoch=?3,destination=?4,binding_version=?5 WHERE workspace=?1 AND mailbox=?2",params![s.old.workspace_id,s.old.mailbox_id,s.confirmed.epoch,s.host.digest,s.confirmed.binding_version]).map_err(db_error)?;
        tx.execute("UPDATE inbox_watches SET descriptor=?3,claim_id=?4,claim_wire=NULL WHERE workspace=?1 AND mailbox=?2",params![s.old.workspace_id,s.old.mailbox_id,serde_json::to_string(&s.new).map_err(|_|invalid())?,next]).map_err(db_error)?;
        tx.execute(
            "UPDATE inbox_host_links SET host=?3,descriptor=?4 WHERE workspace=?1 AND mailbox=?2",
            params![
                s.old.workspace_id,
                s.old.mailbox_id,
                s.host.digest,
                serde_json::to_string(&s.host).map_err(|_| invalid())?
            ],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE inbox_host_rebinds SET phase='COMMITTED' WHERE workspace=?1 AND mailbox=?2 AND version=?3",params![s.old.workspace_id,s.old.mailbox_id,s.expected.binding_version]).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        boundary("COMMITTED")?;
        Ok(
            json!({"state":"LOCAL_REBIND_COMMITTED","operation_id":s.operation_id,"replayed":false,"readiness":"NOT_ATTESTED"}),
        )
    }
}

#[cfg(test)]
#[path = "participant_host_rebind_tests.rs"]
mod tests;
