//! Explicit terminal-call retirement with a durable no-reinjection frontier.
use super::*;
impl Store {
    fn frontier(&self, scope: &Value) -> R<u64> {
        let source = super::super::source_scope(scope);
        let key = digest_value(&source);
        let row: Option<(u64, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT through_sequence,proof FROM bridge_retirements WHERE scope_key=?1",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        let Some((through, proof)) = row else {
            return Ok(0);
        };
        let value = self.open_value(&key, "RETIREMENT", &proof, 16384)?;
        if value != json!({"scope":source,"through_sequence":through}) {
            return Err("BRIDGE_STATE_INVALID");
        }
        Ok(through)
    }
    pub fn source_available(&self, binding: &Value) -> R<()> {
        let key = digest_value(&super::super::source_scope(binding));
        let found:Option<String>=self.db.query_row("SELECT call_id FROM bridge_inputs INDEXED BY bridge_single_input WHERE source_key=?1 AND sequence=?2 AND state<>'NOT_SENT'",params![key,binding["sequence"].as_u64().ok_or("BRIDGE_REQUEST_INVALID")?],|r|r.get(0)).optional().map_err(|_|"BRIDGE_STATE_FAILED")?;
        if found.is_some() {
            return Err("HOST_ORIGINAL_INPUT_REQUIRES_RECOVERY");
        }
        Ok(())
    }
    pub fn retired(&self, binding: &Value) -> R<bool> {
        let sequence = binding["sequence"]
            .as_u64()
            .ok_or("BRIDGE_REQUEST_INVALID")?;
        Ok(sequence <= self.frontier(&super::super::access_scope(binding))?)
    }
    pub fn retire(&mut self, scope: &Value, through: u64, calls: &[Value]) -> R<usize> {
        if calls.len() > 32 || through == 0 || through > 9_007_199_254_740_991 {
            return Err("BRIDGE_REQUEST_INVALID");
        }
        let source = super::super::source_scope(scope);
        let key = digest_value(&source);
        let previous = self.frontier(scope)?;
        let frontier = through.max(previous);
        let mut selected = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for call in calls {
            let id = call["call_id"]
                .as_str()
                .filter(|v| token(v))
                .ok_or("BRIDGE_REQUEST_INVALID")?;
            let sequence = call["sequence"]
                .as_u64()
                .filter(|n| *n > 0 && *n <= through)
                .ok_or("BRIDGE_REQUEST_INVALID")?;
            if !ids.insert(id) {
                return Err("BRIDGE_REQUEST_INVALID");
            }
            let row: Option<(Vec<u8>, usize)> = self
                .db
                .query_row(
                    "SELECT proof,allocation FROM bridge_calls WHERE call_id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|_| "BRIDGE_STATE_FAILED")?;
            let Some((proof, allocation)) = row else {
                if sequence > previous {
                    return Err("BRIDGE_RETIREMENT_NOT_FOUND");
                }
                continue; // Idempotent retirement ACK, never a host-result assertion.
            };
            let proof = self.open_value(id, "PROOF", &proof, 16384)?;
            let binding = &proof["binding"];
            if binding["call_id"] != id
                || binding["sequence"] != sequence
                || super::super::access_scope(binding) != *scope
                || binding["frame_digest"] != call["frame_digest"]
            {
                return Err("BRIDGE_RETIREMENT_CONFLICT");
            }
            let value = self
                .get(
                    binding,
                    proof["message_id"].as_str().ok_or("BRIDGE_STATE_INVALID")?,
                    proof["frame_digest"]
                        .as_str()
                        .ok_or("BRIDGE_STATE_INVALID")?,
                )?
                .ok_or("BRIDGE_STATE_INVALID")?;
            if !matches!(value["state"].as_str(), Some("HOST_ACCEPTED" | "NOT_SENT"))
                || value["state"] != call["state"]
                || digest_value(&value) != call["outcome_digest"]
            {
                return Err("BRIDGE_RETIREMENT_CONFLICT");
            }
            selected.push((id.to_owned(), allocation));
        }
        let proof = self.seal(
            &key,
            "RETIREMENT",
            &json!({"scope":source,"through_sequence":frontier}),
        )?;
        let tx = self.db.transaction().map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.execute("INSERT INTO bridge_retirements VALUES(?1,?2,?3) ON CONFLICT(scope_key) DO UPDATE SET through_sequence=excluded.through_sequence,proof=excluded.proof",params![key,frontier,proof]).map_err(|_|"BRIDGE_STATE_FAILED")?;
        for (id, allocation) in &selected {
            tx.execute("DELETE FROM bridge_inputs WHERE call_id=?1", [id])
                .map_err(|_| "BRIDGE_STATE_FAILED")?;
            tx.execute("DELETE FROM bridge_calls WHERE call_id=?1", [id])
                .map_err(|_| "BRIDGE_STATE_FAILED")?;
            tx.execute(
                "UPDATE bridge_meta SET allocated=allocated-?1,rows=rows-1 WHERE id=1",
                [allocation],
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        }
        tx.commit().map_err(|_| "BRIDGE_STATE_FAILED")?;
        Ok(selected.len())
    }
}
