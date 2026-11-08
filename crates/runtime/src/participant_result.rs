//! Bounded access to one authorized operation's result, never journal history.
use crate::participant::{ParticipantError, Result};
use peerwork_core::crypto::{base64url, sha256_hex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::Arc};

pub(crate) struct PreparedResult {
    wire: Vec<u8>,
    digest: String,
    source: String,
}
type CacheKey = (String, String, String, String);
#[derive(Default)]
pub(crate) struct ResultCache {
    entries: VecDeque<(CacheKey, Arc<PreparedResult>)>,
    bytes: usize,
    hits: u64,
    misses: u64,
}
impl ResultCache {
    pub fn metrics(&self) -> Value {
        json!({"entries":self.entries.len(),"bytes":self.bytes,"hits":self.hits,"preparations":self.misses,"max_entries":8,"max_bytes":32*1024*1024})
    }
    pub fn get(
        &mut self,
        namespace: &str,
        id: &str,
        selection: &ResultSelection,
    ) -> Option<Arc<PreparedResult>> {
        let Some(digest) = selection.expected_sha256.as_ref() else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        let key = (
            namespace.into(),
            id.into(),
            selection.pointer.clone(),
            digest.clone(),
        );
        let Some(at) = self.entries.iter().position(|(k, _)| k == &key) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        self.hits = self.hits.saturating_add(1);
        let entry = self.entries.remove(at)?;
        let value = entry.1.clone();
        self.entries.push_back(entry);
        Some(value)
    }
    pub fn insert(
        &mut self,
        namespace: String,
        id: String,
        pointer: String,
        data: Arc<PreparedResult>,
    ) {
        let key = (namespace, id, pointer, data.digest.clone());
        if self.entries.iter().any(|(k, _)| k == &key) {
            return;
        }
        while self.entries.len() >= 8 || self.bytes + data.wire.len() > 32 * 1024 * 1024 {
            let Some((_, old)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= old.wire.len();
        }
        self.bytes += data.wire.len();
        self.entries.push_back((key, data));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSelection {
    /// JSON Pointer in the operation outcome (e.g. /result/structure).
    #[serde(default)]
    pub pointer: String,
    /// Byte offset in the selected value's JSON UTF-8 serialization.
    #[serde(default)]
    pub offset: usize,
    pub limit: usize,
    /// Pin all continuation chunks to the digest returned on the first chunk.
    #[serde(default)]
    pub expected_sha256: Option<String>,
}
impl ResultSelection {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=65536).contains(&self.limit)
            || self.offset > 32 * 1024 * 1024
            || self.pointer.len() > 1024
            || (!self.pointer.is_empty() && !self.pointer.starts_with('/'))
            || (self.offset > 0 && self.expected_sha256.is_none())
            || self.expected_sha256.as_ref().is_some_and(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            })
        {
            return Err(ParticipantError::local(
                "RESULT_SELECTION_INVALID",
                "VALIDATION",
            ));
        }
        Ok(())
    }
    pub(crate) fn prepare(&self, source: &str, value: &Value) -> Result<Arc<PreparedResult>> {
        self.validate()?;
        let selected = value
            .pointer(&self.pointer)
            .ok_or_else(|| ParticipantError::local("RESULT_PATH_NOT_FOUND", "OBSERVATION"))?;
        let wire = serde_json::to_vec(selected)
            .map_err(|_| ParticipantError::local("RESULT_INVALID", "LOCAL_STATE"))?;
        if wire.len() > 32 * 1024 * 1024 {
            return Err(ParticipantError::local("RESULT_TOO_LARGE", "OBSERVATION"));
        }
        let digest = sha256_hex(&wire);
        if self.expected_sha256.as_ref().is_some_and(|s| s != &digest) {
            return Err(ParticipantError::local("RESULT_CHANGED", "OBSERVATION"));
        }
        Ok(Arc::new(PreparedResult {
            wire,
            digest,
            source: source.into(),
        }))
    }
    pub(crate) fn chunk(&self, id: &str, certainty: &str, data: &PreparedResult) -> Result<Value> {
        self.validate()?;
        if self
            .expected_sha256
            .as_ref()
            .is_some_and(|s| s != &data.digest)
        {
            return Err(ParticipantError::local("RESULT_CHANGED", "OBSERVATION"));
        }
        if self.offset > data.wire.len() {
            return Err(ParticipantError::local(
                "RESULT_OFFSET_INVALID",
                "OBSERVATION",
            ));
        }
        let end = data.wire.len().min(self.offset + self.limit);
        Ok(
            json!({"format":"peerwork.participant-result-chunk.v1","operation_id":id,
            "effect_certainty":certainty,"source":data.source,"pointer":self.pointer,
            "encoding":"JSON_UTF8_BASE64URL","sha256":data.digest,"total_bytes":data.wire.len(),
            "offset":self.offset,"data":base64url(&data.wire[self.offset..end]),
            "next_offset":if end<data.wire.len(){Some(end)}else{None}}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunks_pin_complete_json_and_handle_multibyte_text() {
        let value = json!({"body":"界".repeat(100000)});
        let mut s = ResultSelection {
            pointer: "/body".into(),
            offset: 0,
            limit: 65536,
            expected_sha256: None,
        };
        let prepared = s.prepare("LOCAL_DURABLE_OUTCOME", &value).unwrap();
        let mut cache = ResultCache::default();
        cache.insert(
            "program".into(),
            "original".into(),
            s.pointer.clone(),
            prepared.clone(),
        );
        let mut bytes = Vec::new();
        loop {
            let chunk = s.chunk("original", "COMMITTED", &prepared).unwrap();
            bytes.extend(
                peerwork_core::crypto::decode_base64url(chunk["data"].as_str().unwrap()).unwrap(),
            );
            s.expected_sha256 = Some(chunk["sha256"].as_str().unwrap().into());
            assert!(Arc::ptr_eq(
                &cache.get("program", "original", &s).unwrap(),
                &prepared
            ));
            assert!(cache.get("other-program", "original", &s).is_none());
            let Some(next) = chunk["next_offset"].as_u64() else {
                break;
            };
            s.offset = next as usize;
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            value["body"]
        );
        assert_eq!(
            s.prepare("LOCAL_DURABLE_OUTCOME", &json!({"body":"different"}))
                .err()
                .unwrap()
                .code,
            "RESULT_CHANGED"
        );
        s.expected_sha256 = None;
        assert!(s.validate().is_err());
    }
}
