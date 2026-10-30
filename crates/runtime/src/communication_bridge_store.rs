//! Private host-side evidence. This key protects local rendered frames only;
//! it is not a Peerwork identity, body key or service credential.
use super::*;
#[path = "communication_bridge_gc.rs"]
mod retirement;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ROWS: usize = 4096;
const RESERVE: usize = 16384;
pub(super) struct Store {
    db: Connection,
    key: Zeroizing<[u8; 32]>,
    pin: String,
}
impl Store {
    pub fn open(directory: &Path, pin: &str, initializing: bool) -> R<Self> {
        let file = directory.join("bridge-key");
        if !file.exists() {
            if directory
                .join("bridge.sqlite")
                .metadata()
                .is_ok_and(|m| m.len() > 0)
            {
                return Err("BRIDGE_KEY_MISSING");
            }
            let mut key = Zeroizing::new([0; 32]);
            OsRng
                .try_fill_bytes(&mut *key)
                .map_err(|_| "ENTROPY_UNAVAILABLE")?;
            write_private(&file, &*key)?;
            sync_directory(directory)?;
        }
        let key = crate::secure_state::read_private_seed_file(&file)
            .map_err(|_| "BRIDGE_KEY_INVALID")?
            .ok_or("BRIDGE_KEY_INVALID")?;
        let existing = directory
            .join("bridge.sqlite")
            .metadata()
            .is_ok_and(|m| m.len() > 0);
        let mut db = crate::communication_store::database(directory, "bridge.sqlite")?;
        if existing && !initializing {
            for (name, kind) in [
                ("bridge_meta", "table"),
                ("bridge_calls", "table"),
                ("bridge_single_open", "index"),
                ("bridge_retirements", "table"),
                ("bridge_inputs", "table"),
                ("bridge_single_input", "index"),
            ] {
                let found: bool = db
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name=?1 AND type=?2)",
                        params![name, kind],
                        |r| r.get(0),
                    )
                    .map_err(|_| "BRIDGE_STATE_INVALID")?;
                if !found {
                    return Err("BRIDGE_STATE_INVALID");
                }
            }
            let old: Option<String> = db
                .query_row("SELECT pin FROM bridge_meta WHERE id=1", [], |r| r.get(0))
                .optional()
                .map_err(|_| "BRIDGE_STATE_INVALID")?;
            if old.as_deref() != Some(pin) {
                return Err("BRIDGE_BINDING_CHANGED_REQUIRES_REVIEW");
            }
        }
        let tx = db.transaction().map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS bridge_meta(id INTEGER PRIMARY KEY CHECK(id=1),pin TEXT NOT NULL,allocated INTEGER NOT NULL,rows INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS bridge_calls(call_id TEXT PRIMARY KEY,scope_hash TEXT NOT NULL,message_id TEXT NOT NULL,frame_digest TEXT NOT NULL,proof BLOB NOT NULL,frame BLOB,state TEXT NOT NULL,outcome BLOB,allocation INTEGER NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS bridge_single_open ON bridge_calls(state) WHERE state='CALL_OPEN';
            CREATE TABLE IF NOT EXISTS bridge_inputs(call_id TEXT PRIMARY KEY,source_key TEXT NOT NULL,sequence INTEGER NOT NULL,delivery_id TEXT NOT NULL,state TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS bridge_single_input ON bridge_inputs(source_key,sequence) WHERE state<>'NOT_SENT';
            CREATE TABLE IF NOT EXISTS bridge_retirements(scope_key TEXT PRIMARY KEY,through_sequence INTEGER NOT NULL,proof BLOB NOT NULL);").map_err(|_|"BRIDGE_STATE_FAILED")?;
        tx.execute("INSERT OR IGNORE INTO bridge_meta VALUES(1,?1,0,0)", [pin])
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.commit().map_err(|_| "BRIDGE_STATE_FAILED")?;
        let old: String = db
            .query_row("SELECT pin FROM bridge_meta WHERE id=1", [], |r| r.get(0))
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        if old != pin {
            return Err("BRIDGE_BINDING_CHANGED_REQUIRES_REVIEW");
        }
        if initializing
            && db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM bridge_calls LIMIT 1)",
                    [],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(|_| "BRIDGE_STATE_FAILED")?
        {
            return Err("BRIDGE_INITIALIZATION_HAS_CALLS");
        }
        let recovery = db.transaction().map_err(|_| "BRIDGE_STATE_FAILED")?;

        recovery.execute("UPDATE bridge_inputs SET state='RESULT_UNKNOWN' WHERE call_id IN(SELECT call_id FROM bridge_calls WHERE state='CALL_OPEN')",[]).map_err(|_|"BRIDGE_STATE_FAILED")?;
        recovery
            .execute(
                "UPDATE bridge_calls SET state='RESULT_UNKNOWN' WHERE state='CALL_OPEN'",
                [],
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        recovery.commit().map_err(|_| "BRIDGE_STATE_FAILED")?;
        Ok(Self {
            db,
            key,
            pin: pin.into(),
        })
    }
    fn aad(&self, id: &str, kind: &str) -> String {
        json!(["peerwork.bridge-local.v1", self.pin, id, kind]).to_string()
    }
    fn seal(&self, id: &str, kind: &str, value: &Value) -> R<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "BRIDGE_STATE_INVALID")?;
        let mut nonce = [0; 12];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "ENTROPY_UNAVAILABLE")?;
        let bytes = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value.to_string().as_bytes(),
                    aad: self.aad(id, kind).as_bytes(),
                },
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&bytes);
        Ok(out)
    }
    fn open_value(&self, id: &str, kind: &str, bytes: &[u8], max: usize) -> R<Value> {
        if !(28..=max + 28).contains(&bytes.len()) {
            return Err("BRIDGE_STATE_INVALID");
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "BRIDGE_STATE_INVALID")?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&bytes[..12]),
                    Payload {
                        msg: &bytes[12..],
                        aad: self.aad(id, kind).as_bytes(),
                    },
                )
                .map_err(|_| "BRIDGE_STATE_INVALID")?,
        );
        peerwork_core::strict_json::parse_strict_json(&plain).map_err(|_| "BRIDGE_STATE_INVALID")
    }
    pub fn capacity(&self) -> R<bool> {
        let (bytes, rows): (usize, usize) = self
            .db
            .query_row(
                "SELECT allocated,rows FROM bridge_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        Ok(bytes + 65536 + RESERVE <= MAX_BYTES && rows < MAX_ROWS)
    }
    pub fn get(&self, binding: &Value, message: &str, digest: &str) -> R<Option<Value>> {
        let id = binding["call_id"]
            .as_str()
            .ok_or("BRIDGE_REQUEST_INVALID")?;
        let row:Option<(String,String,String,Vec<u8>,String,Option<Vec<u8>>)>=self.db.query_row("SELECT scope_hash,message_id,frame_digest,proof,state,outcome FROM bridge_calls WHERE call_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|_|"BRIDGE_STATE_FAILED")?;
        let Some((hash, old_message, old_digest, proof, state, outcome)) = row else {
            return Ok(None);
        };
        if hash != digest_value(binding) || old_message != message || old_digest != digest {
            return Err("HOST_INPUT_CONFLICT");
        }
        let proof = self.open_value(id, "PROOF", &proof, 16384)?;
        if proof != json!({"binding":binding,"message_id":message,"frame_digest":digest}) {
            return Err("BRIDGE_STATE_INVALID");
        }
        let value = if let Some(bytes) = outcome {
            let value = self.open_value(id, "OUTCOME", &bytes, 4096)?;
            if value["state"] != state {
                return Err("BRIDGE_STATE_INVALID");
            }
            value
        } else {
            json!({"state":"RESULT_UNKNOWN","code":"HOST_ACK_UNKNOWN"})
        };
        Ok(Some(value))
    }
    pub fn reserve(
        &mut self,
        binding: &Value,
        message: &str,
        digest: &str,
        frame: Option<&Value>,
    ) -> R<()> {
        let id = binding["call_id"]
            .as_str()
            .ok_or("BRIDGE_REQUEST_INVALID")?;
        if self.retired(binding)? {
            return Err("HOST_EVIDENCE_RETIRED");
        }
        self.source_available(binding)?;
        let proof = self.seal(
            id,
            "PROOF",
            &json!({"binding":binding,"message_id":message,"frame_digest":digest}),
        )?;
        let frame = frame.map(|f| self.seal(id, "FRAME", f)).transpose()?;
        let allocation = proof.len() + frame.as_ref().map_or(0, Vec::len) + RESERVE;
        let no_send = if frame.is_none() {
            Some(self.seal(id,"OUTCOME",&json!({"state":"NOT_SENT","code":"HOST_CONFIRMED_NOT_SENT","proof":"BOUND_HOST_RECONCILIATION"}))?)
        } else {
            None
        };
        let tx = self.db.transaction().map_err(|_| "BRIDGE_STATE_FAILED")?;
        let (bytes, rows): (usize, usize) = tx
            .query_row(
                "SELECT allocated,rows FROM bridge_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        if bytes + allocation > MAX_BYTES || rows >= MAX_ROWS {
            return Err("BRIDGE_CAPACITY");
        }
        tx.execute(
            "INSERT INTO bridge_calls VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                id,
                digest_value(binding),
                message,
                digest,
                proof,
                frame,
                if no_send.is_some() {
                    "NOT_SENT"
                } else {
                    "CALL_OPEN"
                },
                no_send,
                allocation
            ],
        )
        .map_err(|_| "BRIDGE_STATE_FAILED")?;

        tx.execute(
            "INSERT INTO bridge_inputs VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                digest_value(&super::source_scope(binding)),
                binding["sequence"]
                    .as_u64()
                    .ok_or("BRIDGE_REQUEST_INVALID")?,
                binding["delivery_id"]
                    .as_str()
                    .ok_or("BRIDGE_REQUEST_INVALID")?,
                if no_send.is_some() {
                    "NOT_SENT"
                } else {
                    "CALL_OPEN"
                }
            ],
        )
        .map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.execute(
            "UPDATE bridge_meta SET allocated=allocated+?1,rows=rows+1 WHERE id=1",
            [allocation],
        )
        .map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.commit().map_err(|_| "BRIDGE_STATE_FAILED")
    }
    pub fn finish(&self, binding: &Value, value: &Value) -> R<()> {
        let id = binding["call_id"]
            .as_str()
            .ok_or("BRIDGE_REQUEST_INVALID")?;
        let sealed = self.seal(id, "OUTCOME", value)?;
        if sealed.len() > 4096 {
            return Err("BRIDGE_OUTCOME_INVALID");
        }
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| "BRIDGE_STATE_FAILED")?;
        let updated=tx.execute("UPDATE bridge_calls SET state=?2,outcome=?3 WHERE call_id=?1 AND state='CALL_OPEN'",params![id,value["state"].as_str().ok_or("BRIDGE_OUTCOME_INVALID")?,sealed]).map_err(|_|"BRIDGE_STATE_FAILED")?;
        if updated != 1 {
            return Err("BRIDGE_OUTCOME_CONFLICT");
        }

        tx.execute(
            "UPDATE bridge_inputs SET state=?2 WHERE call_id=?1",
            params![id, value["state"].as_str().ok_or("BRIDGE_OUTCOME_INVALID")?],
        )
        .map_err(|_| "BRIDGE_STATE_FAILED")?;
        tx.commit().map_err(|_| "BRIDGE_STATE_FAILED")?;
        Ok(())
    }
}
