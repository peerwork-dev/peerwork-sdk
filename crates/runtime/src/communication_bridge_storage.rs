//! Bridge evidence never needs a second persistent copy of the rendered input.
use super::*;
pub(super) fn account(tx: &rusqlite::Transaction<'_>, id: &str) -> R<()> {
    let (old,actual):(usize,usize)=tx.query_row("SELECT allocation,length(proof)+COALESCE(length(outcome),0)+512+CASE WHEN state IN ('CALL_OPEN','RESULT_UNKNOWN','HOST_QUEUED') THEN 4124 ELSE 0 END FROM bridge_calls WHERE call_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"BRIDGE_STATE_FAILED")?;
    tx.execute(
        "UPDATE bridge_calls SET allocation=?2 WHERE call_id=?1",
        params![id, actual],
    )
    .map_err(|_| "BRIDGE_STATE_FAILED")?;
    tx.execute(
        "UPDATE bridge_meta SET allocated=allocated-?1+?2 WHERE id=1",
        params![old, actual],
    )
    .map_err(|_| "BRIDGE_STATE_FAILED")?;
    Ok(())
}
impl Store {
    pub(super) fn compact_page(&self) -> R<()> {
        let rows=self.db.prepare("SELECT call_id,proof,frame FROM bridge_calls WHERE storage_version=0 ORDER BY call_id LIMIT 32").map_err(|_|"BRIDGE_STATE_FAILED")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Option<Vec<u8>>>(2)?))).map_err(|_|"BRIDGE_STATE_FAILED")?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|"BRIDGE_STATE_FAILED")?;
        for (id, proof, frame) in rows {
            let proof = self.open_value(&id, "PROOF", &proof, 16384)?;
            self.get(
                &proof["binding"],
                proof["message_id"].as_str().ok_or("BRIDGE_STATE_INVALID")?,
                proof["frame_digest"]
                    .as_str()
                    .ok_or("BRIDGE_STATE_INVALID")?,
            )?
            .ok_or("BRIDGE_STATE_INVALID")?;
            if let Some(frame) = frame {
                if digest_value(&self.open_value(&id, "FRAME", &frame, 65536)?)
                    != proof["frame_digest"]
                {
                    return Err("BRIDGE_STATE_INVALID");
                }
            }
            let tx = self
                .db
                .unchecked_transaction()
                .map_err(|_| "BRIDGE_STATE_FAILED")?;
            tx.execute(
                "UPDATE bridge_calls SET frame=NULL,storage_version=1 WHERE call_id=?1",
                [&id],
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
            account(&tx, &id)?;
            tx.commit().map_err(|_| "BRIDGE_STATE_FAILED")?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_legacy_bridge_releases_duplicate_inputs_before_new_admission() {
        let root = crate::test_support::protected_test_dir();
        let path = root.path().join("bridge");
        create_private_state_directory(&path).unwrap();
        let store = Store::open(&path, "full-upgrade", true).unwrap();
        let frame = json!({"message_id":"old-frozen-input","rendered_text":"x".repeat(50000)});
        let hash = digest_value(&frame);
        let mut bytes = 0usize;
        let mut count = 0u64;
        let mut original = Value::Null;
        let tx = store.db.unchecked_transaction().unwrap();
        loop {
            let id = format!("{count:043}");
            let binding = json!({"call_id":id,"sequence":count+1,"workspace_id":"W".repeat(43),"mailbox_id":"M".repeat(43),"membership_id":"G".repeat(43),"destination_digest":"d".repeat(64),"owner":json!({"origin":"https://example.invalid/","actor":"A".repeat(43)}).to_string(),"frame_digest":hash});
            let proof = store
                .seal(
                    &id,
                    "PROOF",
                    &json!({"binding":binding,"message_id":"old-frozen-input","frame_digest":hash}),
                )
                .unwrap();
            let encrypted = store.seal(&id, "FRAME", &frame).unwrap();
            let allocation = proof.len() + encrypted.len() + 16384;
            if bytes + allocation > MAX_BYTES {
                break;
            }
            let outcome=store.seal(&id,"OUTCOME",&json!({"state":"NOT_SENT","code":"HOST_NOT_READY","proof":"LOCAL_PREFLIGHT_NO_IO"})).unwrap();
            tx.execute("INSERT INTO bridge_calls(call_id,scope_hash,message_id,frame_digest,proof,frame,state,outcome,allocation,storage_version) VALUES(?1,?2,'old-frozen-input',?3,?4,?5,'NOT_SENT',?6,?7,0)",params![id,digest_value(&binding),hash,proof,encrypted,outcome,allocation]).unwrap();
            if count == 0 {
                original = binding;
            }
            bytes += allocation;
            count += 1;
        }
        tx.execute(
            "UPDATE bridge_meta SET allocated=?1,rows=?2",
            params![bytes, count],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(MAX_BYTES - bytes < 70000);
        assert!(store.capacity().unwrap());
        assert_eq!(
            store
                .get(&original, "old-frozen-input", &hash)
                .unwrap()
                .unwrap()["state"],
            "NOT_SENT"
        );
        let (after,remaining):(usize,u64)=store.db.query_row("SELECT allocated,(SELECT count(*) FROM bridge_calls WHERE storage_version=0) FROM bridge_meta",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert!(after + 1000000 < bytes);
        assert_eq!(remaining, count - 32);
    }
}
