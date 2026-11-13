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
    pub fn obsolete(&self, binding: &Value) -> R<bool> {
        let key = digest_value(&super::super::source_scope(binding));
        let row:Option<(u64,String,Vec<u8>)>=self.db.query_row("SELECT attempt,call_id,proof FROM bridge_generations WHERE source_key=?1 AND sequence=?2",params![key,binding["sequence"].as_u64()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|"BRIDGE_STATE_FAILED")?;
        let Some((attempt, id, proof)) = row else {
            return Ok(false);
        };
        let saved = self.open_value(&key, "GENERATION", &proof, 16384)?;
        if saved["attempt"] != attempt
            || saved["call_id"] != id
            || saved["sequence"] != binding["sequence"]
            || super::super::source_scope(&saved) != super::super::source_scope(binding)
        {
            return Err("BRIDGE_STATE_INVALID");
        }
        Ok(binding["attempt"]
            .as_u64()
            .is_none_or(|n| n < attempt || (n == attempt && binding["call_id"] != id)))
    }
    pub fn source_available(&self, binding: &Value) -> R<()> {
        if self.obsolete(binding)? {
            return Err("HOST_EVIDENCE_RETIRED");
        }
        let key = digest_value(&super::super::source_scope(binding));
        let found:Option<String>=self.db.query_row("SELECT call_id FROM bridge_inputs INDEXED BY bridge_single_input WHERE source_key=?1 AND sequence=?2 AND state NOT IN ('NOT_SENT','SUPERSEDED')",params![key,binding["sequence"].as_u64().ok_or("BRIDGE_REQUEST_INVALID")?],|r|r.get(0)).optional().map_err(|_|"BRIDGE_STATE_FAILED")?;
        if found.is_some() {
            return Err("HOST_ORIGINAL_INPUT_REQUIRES_RECOVERY");
        }
        Ok(())
    }
    pub fn retired(&self, binding: &Value) -> R<bool> {
        let sequence = binding["sequence"]
            .as_u64()
            .ok_or("BRIDGE_REQUEST_INVALID")?;
        let access = super::super::access_scope(binding);
        if sequence <= self.frontier(&access)? {
            return Ok(true);
        }
        let key = digest_value(&access);
        let row:Option<(u64,u64,Vec<u8>)>=self.db.query_row("SELECT lo,hi,proof FROM (SELECT lo,hi,proof FROM bridge_closed_ranges WHERE scope_key=?1 AND lo<=?2 ORDER BY lo DESC LIMIT 1) WHERE hi>=?2",params![key,sequence],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|"BRIDGE_STATE_FAILED")?;
        let Some((lo, hi, proof)) = row else {
            return Ok(false);
        };
        if self.open_value(&key, "CLOSED_RANGE", &proof, 16384)?
            != json!({"scope":access,"lo":lo,"hi":hi})
        {
            return Err("BRIDGE_STATE_INVALID");
        }
        Ok(true)
    }
    pub fn retire(&mut self, scope: &Value, through: u64, calls: &[Value]) -> R<usize> {
        if calls.len() > 32 || (through == 0 && calls.is_empty()) || through > 9_007_199_254_740_991
        {
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
                .filter(|n| *n > 0 && *n <= 9_007_199_254_740_991)
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
                let key = digest_value(scope);
                let range:Option<(u64,u64,Vec<u8>)>=self.db.query_row("SELECT lo,hi,proof FROM (SELECT lo,hi,proof FROM bridge_closed_ranges WHERE scope_key=?1 AND lo<=?2 ORDER BY lo DESC LIMIT 1) WHERE hi>=?2",params![key,sequence],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|"BRIDGE_STATE_FAILED")?;
                let closed = if let Some((lo, hi, proof)) = range {
                    self.open_value(&key, "CLOSED_RANGE", &proof, 16384)?
                        == json!({"scope":scope,"lo":lo,"hi":hi})
                } else {
                    false
                };
                let mut binding = scope.clone();
                binding["sequence"] = json!(sequence);
                binding["call_id"] = json!(id);
                binding["attempt"] = call["attempt"].clone();
                let obsolete = call["retirement"] == "SUPERSEDED" && self.obsolete(&binding)?;
                if sequence > previous && !closed && !obsolete {
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
            let consumed = call["retirement"] == "SERVICE_CONFIRMED_CONSUMED";
            if call["retirement"] == "SUPERSEDED" {
                let inactive:bool=self.db.query_row("SELECT state IN ('SUPERSEDED','NOT_SENT') FROM bridge_inputs WHERE call_id=?1",[id],|r|r.get(0)).map_err(|_|"BRIDGE_STATE_FAILED")?;
                if !inactive || !self.obsolete(binding)? {
                    return Err("BRIDGE_RETIREMENT_CONFLICT");
                }
            } else if consumed {
                let active: bool = self
                    .db
                    .query_row(
                        "SELECT state='CALL_OPEN' FROM bridge_calls WHERE call_id=?1",
                        [id],
                        |r| r.get(0),
                    )
                    .map_err(|_| "BRIDGE_STATE_FAILED")?;
                if active {
                    return Err("HOST_RETIREMENT_ACTIVE_INPUT");
                }
            } else if sequence > through
                || !matches!(value["state"].as_str(), Some("HOST_ACCEPTED" | "NOT_SENT"))
                || value["state"] != call["state"]
                || digest_value(&value) != call["outcome_digest"]
            {
                return Err("BRIDGE_RETIREMENT_CONFLICT");
            }
            selected.push((
                id.to_owned(),
                allocation,
                sequence,
                call["retirement"] != "SUPERSEDED",
            ));
        }
        // Authenticate existing neighbors before constructing each merged proof.
        let range_key = digest_value(scope);
        let mut ranges = Vec::new();
        for (_, _, sequence, completed) in &selected {
            if !completed {
                continue;
            }
            let neighbors=self.db.prepare("SELECT lo,hi,proof FROM (SELECT lo,hi,proof FROM bridge_closed_ranges WHERE scope_key=?1 AND lo<=?2 ORDER BY lo DESC LIMIT 1) WHERE hi>=?2-1 UNION SELECT lo,hi,proof FROM bridge_closed_ranges WHERE scope_key=?1 AND lo=?2+1").map_err(|_|"BRIDGE_STATE_FAILED")?.query_map(params![range_key,sequence],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?,r.get::<_,Vec<u8>>(2)?))).map_err(|_|"BRIDGE_STATE_FAILED")?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|"BRIDGE_STATE_FAILED")?;
            for (lo, hi, proof) in &neighbors {
                if self.open_value(&range_key, "CLOSED_RANGE", proof, 16384)?
                    != json!({"scope":scope,"lo":lo,"hi":hi})
                {
                    return Err("BRIDGE_STATE_INVALID");
                }
            }
            ranges.push(*sequence);
        }
        let proof = self.seal(
            &key,
            "RETIREMENT",
            &json!({"scope":source,"through_sequence":frontier}),
        )?;
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.execute("INSERT INTO bridge_retirements VALUES(?1,?2,?3) ON CONFLICT(scope_key) DO UPDATE SET through_sequence=excluded.through_sequence,proof=excluded.proof",params![key,frontier,proof]).map_err(|_|"BRIDGE_STATE_FAILED")?;
        for sequence in ranges {
            let neighbors=tx.prepare("SELECT lo,hi FROM (SELECT lo,hi FROM bridge_closed_ranges WHERE scope_key=?1 AND lo<=?2 ORDER BY lo DESC LIMIT 1) WHERE hi>=?2-1 UNION SELECT lo,hi FROM bridge_closed_ranges WHERE scope_key=?1 AND lo=?2+1").map_err(|_|"BRIDGE_STATE_FAILED")?.query_map(params![range_key,sequence],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?))).map_err(|_|"BRIDGE_STATE_FAILED")?.collect::<std::result::Result<Vec<_>,_>>().map_err(|_|"BRIDGE_STATE_FAILED")?;
            let lo = neighbors
                .iter()
                .map(|r| r.0)
                .min()
                .unwrap_or(sequence)
                .min(sequence);
            let hi = neighbors
                .iter()
                .map(|r| r.1)
                .max()
                .unwrap_or(sequence)
                .max(sequence);
            let proof = self.seal(
                &range_key,
                "CLOSED_RANGE",
                &json!({"scope":scope,"lo":lo,"hi":hi}),
            )?;
            for (start, _) in neighbors {
                tx.execute(
                    "DELETE FROM bridge_closed_ranges WHERE scope_key=?1 AND lo=?2",
                    params![range_key, start],
                )
                .map_err(|_| "BRIDGE_STATE_FAILED")?;
            }
            tx.execute(
                "INSERT INTO bridge_closed_ranges VALUES(?1,?2,?3,?4)",
                params![range_key, lo, hi, proof],
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        }
        for (id, allocation, _, _) in &selected {
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
        tx.execute("DELETE FROM bridge_closed_ranges WHERE scope_key=?1 AND lo IN (SELECT lo FROM bridge_closed_ranges WHERE scope_key=?1 AND lo<=?2 AND hi<=?2 ORDER BY lo LIMIT 32)",params![range_key,frontier]).map_err(|_|"BRIDGE_STATE_FAILED")?;
        let sequences = selected
            .iter()
            .map(|r| r.2)
            .collect::<std::collections::BTreeSet<_>>();
        for sequence in sequences {
            tx.execute("DELETE FROM bridge_generations WHERE source_key=?1 AND sequence=?2 AND NOT EXISTS(SELECT 1 FROM bridge_inputs WHERE source_key=?1 AND sequence=?2)",params![key,sequence]).map_err(|_|"BRIDGE_STATE_FAILED")?;
        }
        tx.commit().map_err(|_| "BRIDGE_STATE_FAILED")?;
        Ok(selected.len())
    }
}
