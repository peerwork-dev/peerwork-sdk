//! One frozen payload per notification, with bounded completion reservations.
use super::*;

fn payload_scope(scope: &Value) -> String {
    let mut value = scope.clone();
    value.as_object_mut().unwrap().remove("call_id");
    value.as_object_mut().unwrap().remove("attempt");
    value.to_string()
}
pub(in crate::participant_inbox) fn account(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
) -> Result<()> {
    let old: u64 = tx
        .query_row(
            "SELECT allocation FROM inbox_host_calls WHERE call_id=?1",
            [id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    let actual:u64=tx.query_row("SELECT length(scope)+length(frame)+COALESCE(length(retry_of),0)+COALESCE(length(diagnostic),0)+COALESCE(length(outcome),0)+(SELECT COALESCE(sum(length(evidence)),0) FROM inbox_host_facts WHERE call_id=?1)+1024+CASE WHEN consumed_confirmed=0 AND state IN ('CALL_OPEN','RESULT_UNKNOWN','HOST_QUEUED') THEN 16496 ELSE 0 END FROM inbox_host_calls WHERE call_id=?1",[id],|r|r.get(0)).map_err(db_error)?;
    tx.execute(
        "UPDATE inbox_host_calls SET allocation=?2 WHERE call_id=?1",
        params![id, actual],
    )
    .map_err(db_error)?;
    tx.execute(
        "UPDATE inbox_host_meta SET allocated=allocated-?1+?2 WHERE id=1",
        params![old, actual],
    )
    .map_err(db_error)?;
    Ok(())
}
pub(in crate::participant_inbox) fn collect_payload(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
) -> Result<()> {
    let allocation:Option<u64>=tx.query_row("SELECT allocation FROM inbox_host_payloads WHERE key=?1 AND NOT EXISTS(SELECT 1 FROM inbox_host_calls WHERE payload_key=?1)",[key],|r|r.get(0)).optional().map_err(db_error)?;
    if let Some(bytes) = allocation {
        tx.execute("DELETE FROM inbox_host_payloads WHERE key=?1", [key])
            .map_err(db_error)?;
        tx.execute(
            "UPDATE inbox_host_meta SET allocated=allocated-?1 WHERE id=1",
            [bytes],
        )
        .map_err(db_error)?;
    }
    Ok(())
}
impl InboxStore {
    pub(super) fn host_compact_page(
        &self,
        identity: &KernelIdentity,
        namespace: &str,
        options: &WatchOptions,
    ) -> Result<()> {
        self.host_evidence_scope(namespace, options)?;
        let ids=self.db.prepare("SELECT call_id FROM inbox_host_calls WHERE workspace=?1 AND mailbox=?2 AND host=?3 AND storage_version=0 ORDER BY call_id LIMIT 32").map_err(db_error)?.query_map(params![options.workspace_id,options.mailbox_id,options.host_destination],|r|r.get::<_,String>(0)).map_err(db_error)?.collect::<std::result::Result<Vec<_>,_>>().map_err(db_error)?;
        for id in ids {
            let call = self.host_call(identity, &id)?;
            self.host_original_scope(namespace, options, &call)?;
            let aad = payload_scope(&call.scope);
            let key = sha256_hex(aad.as_bytes());
            let sealed = seal_bounded(identity, &aad, &call.frame.to_string(), 65536)
                .map_err(|_| invalid())?;
            let tx = self.db.unchecked_transaction().map_err(db_error)?;
            let consumed:bool=tx.query_row("SELECT consumed_confirmed=1 OR EXISTS(SELECT 1 FROM inbox_consumed a WHERE a.workspace=inbox_host_calls.workspace AND a.mailbox=inbox_host_calls.mailbox AND a.sequence=inbox_host_calls.sequence AND a.delivery_id=inbox_host_calls.delivery_id) FROM inbox_host_calls WHERE call_id=?1",[&id],|r|r.get(0)).map_err(db_error)?;
            if !consumed {
                let added = tx
                    .execute(
                        "INSERT OR IGNORE INTO inbox_host_payloads VALUES(?1,?2,?3,?4)",
                        params![key, aad, sealed, aad.len() + sealed.len()],
                    )
                    .map_err(db_error)?;
                if added == 1 {
                    tx.execute(
                        "UPDATE inbox_host_meta SET allocated=allocated+?1 WHERE id=1",
                        [aad.len() + sealed.len()],
                    )
                    .map_err(db_error)?;
                }
            }
            tx.execute("UPDATE inbox_host_calls SET frame=X'',payload_key=?2,storage_version=1,consumed_confirmed=max(consumed_confirmed,?3) WHERE call_id=?1",params![id,if consumed{None}else{Some(&key)},consumed]).map_err(db_error)?;
            account(&tx, &id)?;
            tx.commit().map_err(db_error)?;
        }
        Ok(())
    }
    pub(super) fn host_frame(
        &self,
        identity: &KernelIdentity,
        id: &str,
        aad: &str,
        legacy: &[u8],
        hash: &str,
    ) -> Result<Value> {
        let (key, consumed): (Option<String>, bool) = self
            .db
            .query_row(
                "SELECT payload_key,consumed_confirmed=1 FROM inbox_host_calls WHERE call_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        if legacy.is_empty() && key.is_none() && consumed {
            return Ok(Value::Null);
        }
        let scope: Value = serde_json::from_str(aad).map_err(|_| invalid())?;
        let expected = payload_scope(&scope);
        let (associated, encrypted) = if let Some(key) = key {
            if sha256_hex(expected.as_bytes()) != key {
                return Err(invalid());
            }
            let (associated, encrypted): (String, Vec<u8>) = self
                .db
                .query_row(
                    "SELECT aad,frame FROM inbox_host_payloads WHERE key=?1",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(db_error)?;
            if associated != expected {
                return Err(invalid());
            }
            (associated, encrypted)
        } else {
            (aad.to_owned(), legacy.to_vec())
        };
        let wire = open_bounded(identity, &associated, &encrypted, 65536).map_err(|_| invalid())?;
        if sha256_hex(wire.as_bytes()) != hash {
            return Err(invalid());
        }
        serde_json::from_str(&wire).map_err(|_| invalid())
    }
}
