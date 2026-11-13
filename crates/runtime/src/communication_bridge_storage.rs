//! Bridge evidence never needs a second persistent copy of the rendered input.
use super::*;
pub(super) fn account(tx:&rusqlite::Transaction<'_>,id:&str)->R<()> {
    let (old,actual):(usize,usize)=tx.query_row("SELECT allocation,length(proof)+COALESCE(length(outcome),0)+512+CASE WHEN state IN ('CALL_OPEN','RESULT_UNKNOWN','HOST_QUEUED') THEN 4124 ELSE 0 END FROM bridge_calls WHERE call_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"BRIDGE_STATE_FAILED")?;
    tx.execute("UPDATE bridge_calls SET allocation=?2 WHERE call_id=?1",params![id,actual]).map_err(|_|"BRIDGE_STATE_FAILED")?;
    tx.execute("UPDATE bridge_meta SET allocated=allocated-?1+?2 WHERE id=1",params![old,actual]).map_err(|_|"BRIDGE_STATE_FAILED")?;
    Ok(())
}
impl Store {
    pub(super) fn compact_page(&self)->R<()> {
        let rows=self.db.prepare("SELECT call_id,proof,frame FROM bridge_calls WHERE storage_version=0 ORDER BY call_id LIMIT 32").map_err(|_|"BRIDGE_STATE_FAILED")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Option<Vec<u8>>>(2)?))).map_err(|_|"BRIDGE_STATE_FAILED")?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|"BRIDGE_STATE_FAILED")?;
        for (id,proof,frame) in rows {
            let proof=self.open_value(&id,"PROOF",&proof,16384)?;
            self.get(&proof["binding"],proof["message_id"].as_str().ok_or("BRIDGE_STATE_INVALID")?,proof["frame_digest"].as_str().ok_or("BRIDGE_STATE_INVALID")?)?.ok_or("BRIDGE_STATE_INVALID")?;
            if let Some(frame)=frame {
                if digest_value(&self.open_value(&id,"FRAME",&frame,65536)?)!=proof["frame_digest"] {return Err("BRIDGE_STATE_INVALID");}
            }
            let tx=self.db.unchecked_transaction().map_err(|_|"BRIDGE_STATE_FAILED")?;
            tx.execute("UPDATE bridge_calls SET frame=NULL,storage_version=1 WHERE call_id=?1",[&id]).map_err(|_|"BRIDGE_STATE_FAILED")?;
            account(&tx,&id)?;tx.commit().map_err(|_|"BRIDGE_STATE_FAILED")?;
        }
        Ok(())
    }
}
