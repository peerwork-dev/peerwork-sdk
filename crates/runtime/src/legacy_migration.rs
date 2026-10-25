//! One-off Owner-local legacy migration. A sealed capsule is authenticated
//! local recovery state, not a claim that the service read encrypted bodies.
use crate::{
    kernel_identity::KernelIdentity,
    owner_cache_review::{with_owner_snapshot, Error, OwnerCacheSelection},
    secure_verified_read::TransportReplayedJournal,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use peerwork_core::{
    canonical::Path as WirePath,
    crypto::{sha256, sha256_hex},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
type R<T> = Result<T, Error>;
fn bad(code: &'static str) -> Error {
    Error(code, None)
}
const MAGIC: &[u8] = b"PEERWORK-LEGACY-CAPSULE\n1\n";
const MAX: usize = 128 * 1024 * 1024;

pub(crate) struct MigrationSource {
    pub(crate) pin: Value,
    objects: Vec<WireValue>,
    sources: Vec<WireValue>,
    roles: Vec<WireValue>,
    status: String,
}
impl MigrationSource {
    fn from_verified(s: &TransportReplayedJournal, snapshot: &str) -> Self {
        Self {
            pin: json!({"snapshot_sha256":snapshot,"workspace_id":s.replay().workspace_id(),"owner_id":s.replay().owner_actor_id(),"owner_kid":s.replay().owner_signing_key(),"authority":s.authority(),"sequence":s.replay().sequence(),"head":s.replay().head(),"policy_hash":s.replay().policy_hash()}),
            objects: s.replay().objects().to_vec(),
            sources: s.replay().object_sources().to_vec(),
            roles: s.replay().historical_role_claims().to_vec(),
            status: format!("{:?}", s.replay().structure_status()),
        }
    }
    pub(crate) fn replay(&self) -> &Self {
        self
    }
    pub(crate) fn objects(&self) -> &[WireValue] {
        &self.objects
    }
    pub(crate) fn object_sources(&self) -> &[WireValue] {
        &self.sources
    }
    pub(crate) fn historical_role_claims(&self) -> &[WireValue] {
        &self.roles
    }
    pub(crate) fn workspace_id(&self) -> &str {
        self.pin["workspace_id"].as_str().unwrap_or("")
    }
    pub(crate) fn owner_actor_id(&self) -> &str {
        self.pin["owner_id"].as_str().unwrap_or("")
    }
    pub(crate) fn owner_signing_key(&self) -> &str {
        self.pin["owner_kid"].as_str().unwrap_or("")
    }
    pub(crate) fn authority(&self) -> &str {
        self.pin["authority"].as_str().unwrap_or("")
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.pin["sequence"].as_u64().unwrap_or(0)
    }
    pub(crate) fn head(&self) -> Option<&str> {
        self.pin["head"].as_str()
    }
    pub(crate) fn policy_hash(&self) -> &str {
        self.pin["policy_hash"].as_str().unwrap_or("")
    }
    pub(crate) fn structure_status(&self) -> &str {
        &self.status
    }
    fn wire(&self) -> R<Zeroizing<Vec<u8>>> {
        let encode = |rows: &[WireValue]| {
            rows.iter()
                .map(|r| {
                    canonical_wire_value(r, WirePath::SecureArtifact)
                        .map_err(|_| bad("LEGACY_CAPSULE_ENCODING_FAILED"))
                })
                .collect::<R<Vec<_>>>()
        };
        let value = json!({"format":"peerwork.verified-legacy-source.v1","verifier":"peerwork-runtime-legacy-capsule-v1","pin":self.pin,"objects":encode(&self.objects)?,"object_sources":encode(&self.sources)?,"historical_role_claims":encode(&self.roles)?,"structure_status":self.status});
        let bytes = Zeroizing::new(
            serde_json::to_vec(&value).map_err(|_| bad("LEGACY_CAPSULE_ENCODING_FAILED"))?,
        );
        if bytes.len() > MAX {
            return Err(bad("LEGACY_CAPSULE_LIMIT"));
        }
        Ok(bytes)
    }
}
fn cipher(identity: &KernelIdentity) -> R<Aes256Gcm> {
    let mut input = Zeroizing::new(b"peerwork.legacy-capsule-encryption.v1\0".to_vec());
    let seed = Zeroizing::new(identity.signing_key().to_bytes());
    input.extend_from_slice(seed.as_ref());
    let key = Zeroizing::new(sha256(&input));
    Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| bad("LEGACY_CAPSULE_ENCRYPTION_FAILED"))
}
fn aad(identity: &KernelIdentity, workspace: &str, snapshot: &str) -> Vec<u8> {
    json!([
        "peerwork.legacy-capsule.v1",
        identity.actor_id(),
        identity.key_id(),
        workspace,
        snapshot
    ])
    .to_string()
    .into_bytes()
}
fn save(path: &Path, identity: &KernelIdentity, source: &MigrationSource) -> R<Value> {
    crate::kernel_intents::ensure_private_parent(path)
        .map_err(|_| bad("LEGACY_CAPSULE_PROTECTION_INVALID"))?;
    let parent = path
        .parent()
        .ok_or_else(|| bad("LEGACY_CAPSULE_PROTECTION_INVALID"))?;
    if path.exists() {
        return Err(bad("LEGACY_CAPSULE_EXISTS"));
    }
    let bytes = source.wire()?;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| bad("LEGACY_CAPSULE_ENTROPY_FAILED"))?;
    let binding = aad(
        identity,
        source.workspace_id(),
        source.pin["snapshot_sha256"]
            .as_str()
            .ok_or_else(|| bad("LEGACY_CAPSULE_BINDING_INVALID"))?,
    );
    let encrypted = cipher(identity)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &bytes,
                aad: &binding,
            },
        )
        .map_err(|_| bad("LEGACY_CAPSULE_ENCRYPTION_FAILED"))?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| bad("LEGACY_CAPSULE_WRITE_FAILED"))?;
    file.write_all(MAGIC)
        .and_then(|_| file.write_all(&nonce))
        .and_then(|_| file.write_all(&encrypted))
        .map_err(|_| bad("LEGACY_CAPSULE_WRITE_FAILED"))?;
    file.as_file()
        .sync_all()
        .map_err(|_| bad("LEGACY_CAPSULE_WRITE_FAILED"))?;
    file.persist_noclobber(path)
        .map_err(|_| bad("LEGACY_CAPSULE_EXISTS"))?;
    Ok(
        json!({"status":"SEALED_VERIFIED_SOURCE","capsule_path":path,"source_frontier":source.pin,"objects":source.objects.len(),"relations":source.objects.iter().filter(|r|r.get("kind").and_then(WireValue::as_string).as_deref()==Some("record_relations")).count(),"plaintext_body_persisted":false,"identity_copied":false,"legacy_structure_status":source.status,"legacy_index_reused":false}),
    )
}
pub(crate) fn open_capsule(
    path: &Path,
    identity: &KernelIdentity,
    workspace: &str,
    snapshot: &str,
) -> R<MigrationSource> {
    let bytes = crate::secure_state::read_private_file_bounded(path, MAX + 256)
        .map_err(|_| bad("LEGACY_CAPSULE_PROTECTION_INVALID"))?;
    if bytes.len() < MAGIC.len() + 28 || !bytes.starts_with(MAGIC) {
        return Err(bad("LEGACY_CAPSULE_FORMAT_INVALID"));
    }
    let at = MAGIC.len();
    let binding = aad(identity, workspace, snapshot);
    let plain = Zeroizing::new(
        cipher(identity)?
            .decrypt(
                Nonce::from_slice(&bytes[at..at + 12]),
                Payload {
                    msg: &bytes[at + 12..],
                    aad: &binding,
                },
            )
            .map_err(|_| bad("LEGACY_CAPSULE_AUTHENTICATION_FAILED"))?,
    );
    let value: Value =
        serde_json::from_slice(&plain).map_err(|_| bad("LEGACY_CAPSULE_FORMAT_INVALID"))?;
    if value["format"] != "peerwork.verified-legacy-source.v1"
        || value["verifier"] != "peerwork-runtime-legacy-capsule-v1"
        || value["pin"]["workspace_id"] != workspace
        || value["pin"]["owner_id"] != identity.actor_id()
        || value["pin"]["owner_kid"] != identity.key_id()
        || value["pin"]["snapshot_sha256"] != snapshot
    {
        return Err(bad("LEGACY_CAPSULE_BINDING_INVALID"));
    }
    let parse = |key: &str| {
        value[key]
            .as_array()
            .ok_or_else(|| bad("LEGACY_CAPSULE_FORMAT_INVALID"))?
            .iter()
            .map(|v| {
                let s = v
                    .as_str()
                    .ok_or_else(|| bad("LEGACY_CAPSULE_FORMAT_INVALID"))?;
                parse_wire_json_bounded(s.as_bytes(), 64, 2 * 1024 * 1024)
                    .map_err(|_| bad("LEGACY_CAPSULE_FORMAT_INVALID"))
            })
            .collect::<R<Vec<_>>>()
    };
    Ok(MigrationSource {
        pin: value["pin"].clone(),
        objects: parse("objects")?,
        sources: parse("object_sources")?,
        roles: parse("historical_role_claims")?,
        status: value["structure_status"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .into(),
    })
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn with_migration_source<T, F: FnOnce(&MigrationSource) -> R<T>>(
    state: &Path,
    workspace: &str,
    working: &Path,
    actor: Option<&str>,
    selection: OwnerCacheSelection,
    refresh: bool,
    capsule: Option<&Path>,
    snapshot: &str,
    consume: F,
) -> R<T> {
    if let Some(path) = capsule {
        if refresh {
            return Err(bad("LEGACY_SOURCE_SELECTION_CONFLICT"));
        }
        let identity = KernelIdentity::open(&state.join("identity.state"))
            .map_err(|_| bad("OWNER_CACHE_IDENTITY_INVALID"))?;
        if actor.is_some_and(|a| a != identity.actor_id()) {
            return Err(bad("OWNER_CACHE_OWNER_MISMATCH"));
        }
        return consume(&open_capsule(path, &identity, workspace, snapshot)?);
    }
    with_owner_snapshot(
        state,
        workspace,
        working,
        actor,
        selection,
        refresh,
        |source| consume(&MigrationSource::from_verified(source, snapshot)),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    state_dir: PathBuf,
    workspace_id: String,
    expected_actor: String,
    snapshot_sha256: String,
    capsule_path: PathBuf,
    #[serde(default)]
    cache_selection: OwnerCacheSelection,
    #[serde(default)]
    refresh_source: bool,
}
pub fn capture_cache_json(input: &str) -> String {
    let result = (|| {
        let q: Capture = serde_json::from_str(input).map_err(|_| bad("LEGACY_REQUEST_INVALID"))?;
        if q.snapshot_sha256.len() != 64
            || !q
                .snapshot_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || q.capsule_path.parent() != Some(q.state_dir.as_path())
        {
            return Err(bad("LEGACY_CAPSULE_BINDING_INVALID"));
        }
        let identity = KernelIdentity::open(&q.state_dir.join("identity.state"))
            .map_err(|_| bad("OWNER_CACHE_IDENTITY_INVALID"))?;
        with_migration_source(
            &q.state_dir,
            &q.workspace_id,
            &q.state_dir,
            Some(&q.expected_actor),
            q.cache_selection,
            q.refresh_source,
            None,
            &q.snapshot_sha256,
            |source| save(&q.capsule_path, &identity, source),
        )
    })();
    match result {
        Ok(value) => json!({"ok":true,"value":value}).to_string(),
        Err(e) => {
            json!({"ok":false,"code":e.0,"diagnostic":e.1,"effect_certainty":"NOT_SUBMITTED"})
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_source_reuse_is_bound_to_identity_workspace_and_frontier() {
        let dir = crate::test_support::protected_test_dir();
        let id = KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let ws = "W".repeat(43);
        let snap = "a".repeat(64);
        let wire=parse_wire_json_bounded(br#"{"kind":"records","id":"R","revision":1,"value":{"body":"PRIVATE MIGRATION BODY"}}"#,16,4096).unwrap();
        let s = MigrationSource {
            pin: json!({"snapshot_sha256":snap,"workspace_id":ws,"owner_id":id.actor_id(),"owner_kid":id.key_id(),"authority":"b".repeat(64),"sequence":7,"head":"c".repeat(64),"policy_hash":"d".repeat(64)}),
            objects: vec![wire],
            sources: vec![],
            roles: vec![],
            status: "Active".into(),
        };
        let path = dir.path().join("source.capsule");
        save(&path, &id, &s).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw
            .windows(b"PRIVATE MIGRATION BODY".len())
            .any(|v| v == b"PRIVATE MIGRATION BODY"));
        let reused = open_capsule(&path, &id, &ws, &snap).unwrap();
        assert_eq!(
            canonical_wire_value(&reused.objects[0], WirePath::SecureArtifact).unwrap(),
            canonical_wire_value(&s.objects[0], WirePath::SecureArtifact).unwrap()
        );
        assert_eq!(reused.pin, s.pin);
        assert!(open_capsule(&path, &id, &ws, &"f".repeat(64)).is_err());
        let other = KernelIdentity::create(&dir.path().join("other.state")).unwrap();
        assert!(open_capsule(&path, &other, &ws, &snap).is_err());
        let mut bad_bytes = raw.clone();
        let at = bad_bytes.len() - 1;
        bad_bytes[at] ^= 1;
        std::fs::write(&path, bad_bytes).unwrap();
        assert!(open_capsule(&path, &id, &ws, &snap).is_err());
    }
}

use crate::secure_recipient_state::RecipientState;
use ed25519_dalek::{Signature, Verifier};
use peerwork_core::{
    crypto::{base64url, decode_base64url, sign_compact, verifying_key},
    e2ee::{hpke_open_wire, KeyBox},
    replayed_secure_journal::{
        replay_secure_journal_exact_with_guard_time_attestations_and_limits, JournalReplayInput,
        JournalReplayLimits,
    },
};
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Read},
};
const REQUEST_TYPE: &str = "peerwork.legacy-export-request.v1+jws";
const RECEIPT_TYPE: &str = "peerwork.legacy-export-receipt.v1+jws";
fn hash_value(v: &Value) -> R<String> {
    let raw = serde_json::to_vec(v).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    let wire =
        parse_wire_json_bounded(&raw, 64, MAX).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    Ok(sha256_hex(
        canonical_wire_value(&wire, WirePath::SecureArtifact)
            .map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?
            .as_bytes(),
    ))
}
fn typed_jws(jws: &str, typ: &str, key: &str) -> R<Value> {
    if jws.len() > 250000 {
        return Err(bad("LEGACY_SIGNATURE_INVALID"));
    }
    let parts = jws.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(bad("LEGACY_SIGNATURE_INVALID"));
    }
    let decode = |s: &str| decode_base64url(s).map_err(|_| bad("LEGACY_SIGNATURE_INVALID"));
    let header: Value =
        serde_json::from_slice(&decode(parts[0])?).map_err(|_| bad("LEGACY_SIGNATURE_INVALID"))?;
    if header["alg"] != "EdDSA"
        || header["typ"] != typ
        || header["kid"] != key
        || header.as_object().is_none_or(|m| m.len() != 3)
    {
        return Err(bad("LEGACY_SIGNATURE_INVALID"));
    }
    let sig: [u8; 64] = decode(parts[2])?
        .try_into()
        .map_err(|_| bad("LEGACY_SIGNATURE_INVALID"))?;
    verifying_key(key)
        .map_err(|_| bad("LEGACY_SIGNATURE_INVALID"))?
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| bad("LEGACY_SIGNATURE_INVALID"))?;
    serde_json::from_slice(&decode(parts[1])?).map_err(|_| bad("LEGACY_SIGNATURE_INVALID"))
}
fn private_json(path: &Path, max: usize) -> R<Value> {
    let bytes = crate::secure_state::read_private_file_bounded(path, max)
        .map_err(|_| bad("LEGACY_PROTECTED_FILE_INVALID"))?;
    serde_json::from_slice(&bytes).map_err(|_| bad("LEGACY_REQUEST_INVALID"))
}
fn write_json(path: &Path, value: &Value) -> R<()> {
    crate::kernel_intents::ensure_private_parent(path)
        .map_err(|_| bad("LEGACY_PROTECTED_FILE_INVALID"))?;
    let parent = path
        .parent()
        .ok_or_else(|| bad("LEGACY_PROTECTED_FILE_INVALID"))?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| bad("LEGACY_OUTPUT_FAILED"))?;
    file.write_all(&serde_json::to_vec(value).map_err(|_| bad("LEGACY_OUTPUT_FAILED"))?)
        .map_err(|_| bad("LEGACY_OUTPUT_FAILED"))?;
    file.as_file()
        .sync_all()
        .map_err(|_| bad("LEGACY_OUTPUT_FAILED"))?;
    file.persist_noclobber(path)
        .map_err(|_| bad("LEGACY_OUTPUT_EXISTS"))?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRequest {
    identity_path: PathBuf,
    expected_actor: String,
    recipient_path: PathBuf,
    request_path: PathBuf,
    workspace_id: String,
    snapshot_sha256: String,
    audience: String,
    service_key: String,
    #[serde(default)]
    authority: Option<String>,
}
fn request_source(q: SourceRequest) -> R<Value> {
    let identity =
        KernelIdentity::open(&q.identity_path).map_err(|_| bad("OWNER_CACHE_IDENTITY_INVALID"))?;
    if identity.actor_id() != q.expected_actor
        || q.workspace_id.len() != 43
        || q.snapshot_sha256.len() != 64
    {
        return Err(bad("LEGACY_SOURCE_BINDING_INVALID"));
    }
    let recipient = if q.recipient_path.exists() {
        RecipientState::open(&q.recipient_path, &identity)
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| bad("LEGACY_CLOCK_INVALID"))?
            .as_millis() as u64;
        RecipientState::create(&q.recipient_path, &identity, now)
    }
    .map_err(|_| bad("LEGACY_RECIPIENT_INVALID"))?;
    let mut payload = json!({"schema":"peerwork.legacy-export-request.v1","workspace_id":q.workspace_id,"snapshot_sha256":q.snapshot_sha256,"owner_id":identity.actor_id(),"audience":q.audience,"service_key":q.service_key,"recipient":recipient.recipient().public_jwk()});
    if let Some(a) = q.authority {
        payload["authority"] = json!(a);
    }
    payload["operation_id"] = json!(base64url(&sha256(hash_value(&payload)?.as_bytes())));
    let header = json!({"alg":"EdDSA","typ":REQUEST_TYPE,"kid":identity.key_id()});
    let jws = sign_compact(&header, &payload, identity.signing_key())
        .map_err(|_| bad("LEGACY_SIGNATURE_INVALID"))?;
    let value = json!({"jws":jws});
    if q.request_path.exists() {
        if private_json(&q.request_path, 65536)? != value {
            return Err(bad("LEGACY_REQUEST_CONFLICT"));
        }
    } else {
        write_json(&q.request_path, &value)?;
    }
    Ok(
        json!({"status":"OWNER_SOURCE_REQUEST_SIGNED","request_path":q.request_path,"request_digest":sha256_hex(jws.as_bytes()),"operation_id":payload["operation_id"],"workspace_id":payload["workspace_id"],"private_key_exported":false}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCapture {
    identity_path: PathBuf,
    expected_actor: String,
    recipient_path: PathBuf,
    request_path: PathBuf,
    source_path: PathBuf,
    capsule_path: PathBuf,
    #[serde(default)]
    state_dir: Option<PathBuf>,
    #[serde(default)]
    keyring_path: Option<PathBuf>,
}
fn capture_source(q: SourceCapture) -> R<Value> {
    if q.state_dir.is_some() && q.keyring_path.is_some() {
        return Err(bad("LEGACY_KEYRING_SELECTION_CONFLICT"));
    }
    if q.capsule_path.exists() {
        return Err(bad("LEGACY_CAPSULE_EXISTS"));
    }
    let identity =
        KernelIdentity::open(&q.identity_path).map_err(|_| bad("OWNER_CACHE_IDENTITY_INVALID"))?;
    if identity.actor_id() != q.expected_actor {
        return Err(bad("OWNER_CACHE_OWNER_MISMATCH"));
    }
    let request = private_json(&q.request_path, 65536)?;
    let jws = request["jws"]
        .as_str()
        .ok_or_else(|| bad("LEGACY_REQUEST_INVALID"))?;
    let selected = typed_jws(jws, REQUEST_TYPE, identity.key_id())?;
    let digest = sha256_hex(jws.as_bytes());
    let recipient = RecipientState::open(&q.recipient_path, &identity)
        .map_err(|_| bad("LEGACY_RECIPIENT_INVALID"))?;
    if selected["recipient"]
        != serde_json::to_value(recipient.recipient().public_jwk())
            .map_err(|_| bad("LEGACY_RECIPIENT_INVALID"))?
    {
        return Err(bad("LEGACY_RECIPIENT_INVALID"));
    }
    let metadata =
        fs::symlink_metadata(&q.source_path).map_err(|_| bad("LEGACY_SOURCE_MISSING"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(bad("LEGACY_PROTECTED_FILE_INVALID"));
    }
    crate::kernel_intents::ensure_private_parent(&q.source_path)
        .map_err(|_| bad("LEGACY_PROTECTED_FILE_INVALID"))?;
    crate::kernel_intents::create_or_check_private_file(&q.source_path)
        .map_err(|_| bad("LEGACY_PROTECTED_FILE_INVALID"))?;
    let file = fs::File::open(&q.source_path).map_err(|_| bad("LEGACY_SOURCE_MISSING"))?;
    if file
        .metadata()
        .map_err(|_| bad("LEGACY_SOURCE_MISSING"))?
        .len() as usize
        > MAX * 2
    {
        return Err(bad("LEGACY_SOURCE_LIMIT"));
    }
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader
        .by_ref()
        .take(65536)
        .read_line(&mut line)
        .map_err(|_| bad("LEGACY_SOURCE_READ_FAILED"))?;
    let envelope: Value =
        serde_json::from_str(&line).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    let h = &envelope["header"];
    if h["schema"] != "peerwork.legacy-source.v1"
        || h["request_digest"] != digest
        || h["source"]["workspace_id"] != selected["workspace_id"]
        || h["source"]["snapshot_sha256"] != selected["snapshot_sha256"]
        || h["source"]["owner_id"] != identity.actor_id()
        || h["source"]["owner_kid"] != identity.key_id()
        || h["service_key"] != selected["service_key"]
        || h["audience"] != selected["audience"]
        || h["operation_id"] != selected["operation_id"]
        || selected
            .get("authority")
            .is_some_and(|a| a != &h["source"]["authority"])
    {
        return Err(bad("LEGACY_SOURCE_BINDING_INVALID"));
    }
    let header_hash = hash_value(h)?;
    let key_box: KeyBox = serde_json::from_value(envelope["wrapped_key"].clone())
        .map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    let context = json!({"domain":"peerwork.legacy-source-key.v1","header_digest":header_hash});
    let opened = hpke_open_wire(
        recipient.recipient().private_bytes(),
        &key_box,
        &serde_json::to_vec(&context).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?,
    )
    .map_err(|_| bad("LEGACY_SOURCE_AUTHENTICATION_FAILED"))?;
    let key_text = opened
        .get("key")
        .and_then(WireValue::as_string)
        .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    let key = Zeroizing::new(
        decode_base64url(&key_text).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?,
    );
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    let mut head = header_hash.clone();
    let mut index = 0u64;
    let mut count = 0u64;
    let mut bytes = 0usize;
    let mut rows = Vec::new();
    let mut footer = None;
    loop {
        line.clear();
        let n = reader
            .by_ref()
            .take(8 * 1024 * 1024)
            .read_line(&mut line)
            .map_err(|_| bad("LEGACY_SOURCE_READ_FAILED"))?;
        if n == 0 {
            break;
        }
        if !line.ends_with('\n') {
            return Err(bad("LEGACY_SOURCE_FORMAT_INVALID"));
        }
        let page: Value =
            serde_json::from_str(&line).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
        if let Some(jws) = page["receipt"].as_str() {
            if footer.is_some() {
                return Err(bad("LEGACY_SOURCE_FORMAT_INVALID"));
            }
            footer = Some(typed_jws(
                jws,
                RECEIPT_TYPE,
                selected["service_key"]
                    .as_str()
                    .ok_or_else(|| bad("LEGACY_SOURCE_BINDING_INVALID"))?,
            )?);
            continue;
        }
        if footer.is_some()
            || page["index"].as_u64() != Some(index)
            || page["previous_digest"] != head
            || index >= 65536
        {
            return Err(bad("LEGACY_SOURCE_CHAIN_INVALID"));
        }
        let decode = |key: &str| {
            decode_base64url(
                page[key]
                    .as_str()
                    .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?,
            )
            .map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))
        };
        let nonce = decode("nonce")?;
        if nonce.len() != 12 {
            return Err(bad("LEGACY_SOURCE_FORMAT_INVALID"));
        }
        let aad = serde_json::to_vec(&json!([
            "peerwork.legacy-source-page.v1",
            header_hash,
            index,
            head
        ]))
        .map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &decode("ciphertext")?,
                        aad: &aad,
                    },
                )
                .map_err(|_| bad("LEGACY_SOURCE_AUTHENTICATION_FAILED"))?,
        );
        bytes += plain.len();
        if bytes > 64 * 1024 * 1024 {
            return Err(bad("LEGACY_SOURCE_LIMIT"));
        }
        let items: Vec<Value> =
            serde_json::from_slice(&plain).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
        count += items.len() as u64;
        rows.extend(items);
        head = hash_value(&page)?;
        index += 1;
    }
    let footer = footer.ok_or_else(|| bad("LEGACY_SOURCE_TRUNCATED"))?;
    if footer["schema"] != "peerwork.legacy-export-receipt.v1"
        || footer["header_digest"] != header_hash
        || footer["request_digest"] != digest
        || footer["source"] != h["source"]
        || footer["page_count"].as_u64() != Some(index)
        || footer["row_count"].as_u64() != Some(count)
        || footer["final_digest"] != head
    {
        return Err(bad("LEGACY_SOURCE_CHAIN_INVALID"));
    }
    let source = if h["source"]["kind"] == "PLAIN_PUBLIC" {
        plain_source(h["source"].clone(), &rows)?
    } else {
        secure_source(&q, &identity, h["source"].clone(), &rows)?
    };
    save(&q.capsule_path, &identity, &source)
}
fn secure_source(
    q: &SourceCapture,
    identity: &KernelIdentity,
    pin: Value,
    rows: &[Value],
) -> R<MigrationSource> {
    let ws = pin["workspace_id"]
        .as_str()
        .ok_or_else(|| bad("LEGACY_SOURCE_BINDING_INVALID"))?;
    let mut policies = rows
        .iter()
        .filter(|r| r["table"] == "secure_policies")
        .map(|r| {
            r["row"]["artifact"]
                .as_str()
                .map(str::as_bytes)
                .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))
        })
        .collect::<R<Vec<_>>>()?;
    let mut commits = rows
        .iter()
        .filter(|r| r["table"] == "secure_commits")
        .collect::<Vec<_>>();
    commits.sort_by_key(|r| r["row"]["sequence"].as_u64());
    let commits = commits
        .iter()
        .map(|r| {
            r["row"]["artifact"]
                .as_str()
                .map(str::as_bytes)
                .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))
        })
        .collect::<R<Vec<_>>>()?;
    policies.sort_by_key(|bytes| {
        serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|v| v["payload"]["version"].as_u64())
            .unwrap_or(0)
    });
    let mut proofs = HashMap::new();
    for row in rows
        .iter()
        .filter(|r| r["table"] == "secure_guard_time_attestations")
    {
        let r = &row["row"];
        proofs.insert(
            r["commit_hash"]
                .as_str()
                .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?
                .to_owned(),
            r["artifact"]
                .as_str()
                .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?
                .as_bytes()
                .to_vec(),
        );
    }
    let mut floor = None;
    let ring = if let Some(path) = &q.keyring_path {
        Some(
            crate::secure_state::read_private_file_bounded(path, 131072)
                .map_err(|_| bad("LEGACY_KEYRING_UNAVAILABLE"))?,
        )
    } else if let Some(state) = &q.state_dir {
        let (profile, _) = crate::secure_read_profile::SecureReadProfile::cached_export_config(
            &state.join("workspaces").join(ws),
            &q.identity_path,
            ws,
        )
        .map_err(|_| bad("LEGACY_OWNER_PROFILE_INVALID"))?;
        if profile.owner_actor_id.as_deref() != Some(identity.actor_id())
            || profile.owner_key_id.as_deref() != Some(identity.key_id())
        {
            return Err(bad("LEGACY_OWNER_PROFILE_INVALID"));
        }
        let (config, saved_floor) = crate::secure_read_profile::SecureReadProfile::new(profile)
            .local_active_view_config()
            .map_err(|_| bad("LEGACY_OWNER_PROFILE_INVALID"))?;
        if config.authority != pin["authority"].as_str().unwrap_or("") {
            return Err(bad("LEGACY_OWNER_PROFILE_INVALID"));
        }
        floor = Some(saved_floor);
        let lifecycle = crate::secure_lifecycle::SecureLifecycle::open_existing(
            &config.lifecycle_path,
            &config.origin,
            identity.actor_id(),
            ws,
            identity.actor_id(),
            identity.key_id(),
        )
        .map_err(|_| bad("LEGACY_KEYRING_UNAVAILABLE"))?;
        lifecycle
            .replay_keyring_candidate()
            .map(|candidate| {
                candidate
                    .ring
                    .canonical_wire()
                    .map_err(|_| bad("LEGACY_KEYRING_UNAVAILABLE"))
            })
            .transpose()?
    } else {
        None
    };
    let checkpoint = json!({"v":1,"workspace_id":ws,"owner_id":identity.actor_id(),"owner_key":identity.key_id(),"sequence":pin["sequence"],"head":pin["head"],"policy_hash":pin["policy_hash"]});
    let checkpoint =
        serde_json::to_vec(&checkpoint).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    let replay = replay_secure_journal_exact_with_guard_time_attestations_and_limits(
        JournalReplayInput {
            policy_wires: &policies,
            commit_wires: &commits,
            checkpoint_wire: &checkpoint,
            workspace_id: ws,
            owner_actor_id: identity.actor_id(),
            owner_signing_key: identity.key_id(),
            final_sequence: pin["sequence"]
                .as_u64()
                .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?,
            final_head: pin["head"].as_str(),
            final_policy_hash: pin["policy_hash"]
                .as_str()
                .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?,
            keyring_wire: ring.as_deref().map(|v| v.as_slice()),
        },
        JournalReplayLimits::new(102400).ok_or_else(|| bad("LEGACY_SOURCE_LIMIT"))?,
        Some(&proofs),
    )
    .map_err(|_| bad("LEGACY_SOURCE_VERIFICATION_FAILED"))?;
    if floor
        .is_some_and(|f| !replay.contains_checkpoint(f.sequence, f.head.as_deref(), &f.policy_hash))
    {
        return Err(bad("LEGACY_SOURCE_ROLLBACK"));
    }
    Ok(MigrationSource {
        pin,
        objects: replay.objects().to_vec(),
        sources: replay.object_sources().to_vec(),
        roles: replay.historical_role_claims().to_vec(),
        status: format!("{:?}", replay.structure_status()),
    })
}
fn plain_source(pin: Value, rows: &[Value]) -> R<MigrationSource> {
    let mut objects = Vec::new();
    let mut sources = Vec::new();
    let ws = pin["workspace_id"]
        .as_str()
        .ok_or_else(|| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
    for entry in rows {
        let kind = entry["table"].as_str().unwrap_or("");
        if !matches!(
            kind,
            "protocols" | "instances" | "records" | "entity_heads" | "record_relations"
        ) {
            continue;
        }
        let row = &entry["row"];
        if kind != "record_relations" && row["workspace_id"] != ws {
            return Err(bad("LEGACY_SOURCE_BINDING_INVALID"));
        }
        let id = match kind {
            "protocols" => row["digest"].clone(),
            "entity_heads" => row["entity_id"].clone(),
            "record_relations" => json!(hash_value(row)?),
            _ => row["id"].clone(),
        };
        let revision = row["revision"].as_u64().unwrap_or(1);
        let mut value = row.clone();
        if kind == "protocols" && value.get("resolved_manifest").is_none() {
            value["resolved_manifest"] = value["manifest"].clone();
        }
        let object = json!({"kind":kind,"id":id,"revision":revision,"value":value});
        let bytes = serde_json::to_vec(&object).map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
        let wire = parse_wire_json_bounded(&bytes, 64, 2 * 1024 * 1024)
            .map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?;
        if kind == "records" {
            let source = json!({"kind":kind,"id":id,"revision":revision,"sequence":0,"commit_hash":hash_value(row)?,"actor_id":row["actor_id"],"object_digest":sha256_hex(canonical_wire_value(&wire,WirePath::SecureArtifact).map_err(|_|bad("LEGACY_SOURCE_FORMAT_INVALID"))?.as_bytes())});
            sources.push(
                parse_wire_json_bounded(&serde_json::to_vec(&source).unwrap(), 16, 4096)
                    .map_err(|_| bad("LEGACY_SOURCE_FORMAT_INVALID"))?,
            );
        }
        objects.push(wire);
    }
    Ok(MigrationSource {
        pin,
        objects,
        sources,
        roles: vec![],
        status: "Unstructured".into(),
    })
}
pub fn source_json(verb: &str, input: &str) -> String {
    let result = (|| {
        if input.len() > 65536 {
            return Err(bad("LEGACY_REQUEST_LIMIT"));
        }
        match verb {
            "request-source" => request_source(
                serde_json::from_str(input).map_err(|_| bad("LEGACY_REQUEST_INVALID"))?,
            ),
            "capture-source" => capture_source(
                serde_json::from_str(input).map_err(|_| bad("LEGACY_REQUEST_INVALID"))?,
            ),
            _ => Err(bad("LEGACY_OPERATION_INVALID")),
        }
    })();
    match result {
        Ok(value) => json!({"ok":true,"value":value}).to_string(),
        Err(e) => {
            json!({"ok":false,"code":e.0,"diagnostic":e.1,"effect_certainty":"NOT_SUBMITTED"})
                .to_string()
        }
    }
}

#[cfg(test)]
mod offline_source_tests {
    use super::*;
    use peerwork_core::{
        crypto::key_id,
        e2ee::{hpke_seal_wire, RecipientPublicJwk},
    };
    fn private(path: &Path, text: &str) {
        crate::kernel_intents::create_or_check_private_file(path).unwrap();
        fs::write(path, text).unwrap();
    }
    #[test]
    fn conflicting_key_sources_fail_before_opening_or_creating_any_files() {
        let dir = crate::test_support::protected_test_dir();
        let missing = dir.path().join("missing");
        let result = capture_source(SourceCapture {
            identity_path: missing.clone(),
            expected_actor: "A".repeat(43),
            recipient_path: missing.clone(),
            request_path: missing.clone(),
            source_path: missing.clone(),
            capsule_path: dir.path().join("output"),
            state_dir: Some(missing.clone()),
            keyring_path: Some(missing.clone()),
        });
        assert_eq!(result.unwrap_err().0, "LEGACY_KEYRING_SELECTION_CONFLICT");
        assert!(!missing.exists());
        assert!(!dir.path().join("output").exists());
    }
    #[test]
    fn encrypted_archive_to_capsule_to_readonly_checkpoint_needs_no_old_profile_or_network() {
        let dir = crate::test_support::protected_test_dir();
        let identity_path = dir.path().join("identity.state");
        let id = KernelIdentity::create(&identity_path).unwrap();
        let service = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let service_key = key_id(&service.verifying_key().to_bytes());
        let ws = "W".repeat(43);
        let snapshot = "a".repeat(64);
        let recipient_path = dir.path().join("recipient.state");
        let request_path = dir.path().join("request.json");
        let q = || SourceRequest {
            identity_path: identity_path.clone(),
            expected_actor: id.actor_id().into(),
            recipient_path: recipient_path.clone(),
            request_path: request_path.clone(),
            workspace_id: ws.clone(),
            snapshot_sha256: snapshot.clone(),
            audience: "legacy-offline-test".into(),
            service_key: service_key.clone(),
            authority: None,
        };
        request_source(q()).unwrap();
        let original = fs::read(&request_path).unwrap();
        request_source(q()).unwrap();
        assert_eq!(original, fs::read(&request_path).unwrap());
        let request = private_json(&request_path, 65536).unwrap();
        let signed = request["jws"].as_str().unwrap();
        let r = typed_jws(signed, REQUEST_TYPE, id.key_id()).unwrap();
        let pin = json!({"kind":"PLAIN_PUBLIC","snapshot_sha256":snapshot,"workspace_id":ws,"owner_id":id.actor_id(),"owner_kid":id.key_id(),"authority":sha256_hex(id.actor_id().as_bytes()),"sequence":0,"head":"b".repeat(64),"policy_hash":"c".repeat(64)});
        let header = json!({"schema":"peerwork.legacy-source.v1","request_digest":sha256_hex(signed.as_bytes()),"source":pin,"audience":r["audience"],"service_key":service_key,"operation_id":r["operation_id"]});
        let header_hash = hash_value(&header).unwrap();
        let key_bytes = [9u8; 32];
        let context = json!({"domain":"peerwork.legacy-source-key.v1","header_digest":header_hash});
        let recipient: RecipientPublicJwk = serde_json::from_value(r["recipient"].clone()).unwrap();
        let wrapped = hpke_seal_wire(
            &recipient,
            &serde_json::to_vec(&json!({"key":base64url(&key_bytes)})).unwrap(),
            &serde_json::to_vec(&context).unwrap(),
        )
        .unwrap();
        let instance = "I".repeat(43);
        let record = "R".repeat(43);
        let protocol = "d".repeat(64);
        let manifest = json!({"name":"legacy","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{},"record_schemas":{"note":{"type":"object","fields":{"status":"string","body":"string"},"required":["status","body"],"max_bytes":4096}},"actions":[{"id":"post","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":[]}]}]});
        let rows = json!([{"table":"protocols","row":{"workspace_id":ws,"digest":protocol,"resolved_manifest":manifest.to_string()}},{"table":"instances","row":{"id":instance,"workspace_id":ws,"protocol_digest":protocol,"state":"{}","revision":1}},{"table":"records","row":{"id":record,"entity_id":record,"workspace_id":ws,"instance_id":instance,"protocol_digest":protocol,"schema_ref":"note","payload":json!({"status":"OPEN","body":"PRIVATE SNAPSHOT BODY"}).to_string(),"revision":1,"actor_id":id.actor_id(),"created":123}}]);
        let key = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
        let nonce = [1u8; 12];
        let aad = serde_json::to_vec(&json!([
            "peerwork.legacy-source-page.v1",
            header_hash,
            0,
            header_hash
        ]))
        .unwrap();
        let encrypted = key
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &serde_json::to_vec(&rows).unwrap(),
                    aad: &aad,
                },
            )
            .unwrap();
        let page = json!({"index":0,"previous_digest":header_hash,"nonce":base64url(&nonce),"ciphertext":base64url(&encrypted)});
        let footer = json!({"schema":"peerwork.legacy-export-receipt.v1","header_digest":header_hash,"request_digest":sha256_hex(signed.as_bytes()),"source":pin,"page_count":1,"row_count":3,"final_digest":hash_value(&page).unwrap()});
        let receipt = sign_compact(
            &json!({"alg":"EdDSA","typ":RECEIPT_TYPE,"kid":service_key}),
            &footer,
            &service,
        )
        .unwrap();
        let source_path = dir.path().join("source.encrypted");
        let text = format!(
            "{}\n{}\n{}\n",
            json!({"header":header,"wrapped_key":wrapped}),
            page,
            json!({"receipt":receipt})
        );
        private(&source_path, &text);
        let capsule = dir.path().join("source.capsule");
        capture_source(SourceCapture {
            identity_path: identity_path.clone(),
            expected_actor: id.actor_id().into(),
            recipient_path: recipient_path.clone(),
            request_path: request_path.clone(),
            source_path: source_path.clone(),
            capsule_path: capsule.clone(),
            state_dir: None,
            keyring_path: None,
        })
        .unwrap();
        assert!(!dir.path().join("workspaces").exists());
        let execute_path = dir.path().join("must-not-execute.json");
        let refused:Value=serde_json::from_str(&crate::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&json!({"state_dir":dir.path(),"workspace_id":ws,"expected_actor":id.actor_id(),"snapshot_sha256":snapshot,"name":"Unsafe executable migration","plan_path":execute_path,"capsule_path":capsule}).to_string())).unwrap();
        assert_eq!(refused["code"], "LEGACY_SOURCE_REQUIRES_READ_ONLY_SNAPSHOT");
        assert!(!execute_path.exists());
        // A fully verified logical source can outlive its unfinished legacy
        // derived index. Only an explicitly inert snapshot may use it.
        let mut seeding = open_capsule(&capsule, &id, &ws, &snapshot).unwrap();
        seeding.pin.as_object_mut().unwrap().remove("kind");
        seeding.status = "Seeding".into();
        let seeding_path = dir.path().join("seeding.capsule");
        save(&seeding_path, &id, &seeding).unwrap();
        let selection = json!({"state_dir":dir.path(),"workspace_id":ws,"expected_actor":id.actor_id(),"snapshot_sha256":snapshot,"name":"Verified logical snapshot","plan_path":execute_path,"capsule_path":seeding_path});
        let refused: Value = serde_json::from_str(
            &crate::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&selection.to_string()),
        )
        .unwrap();
        assert_eq!(refused["code"], "LEGACY_SOURCE_REQUIRES_READ_ONLY_SNAPSHOT");
        let mut selected = selection;
        selected["read_only_snapshot"] = json!(true);
        let accepted: Value = serde_json::from_str(
            &crate::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&selected.to_string()),
        )
        .unwrap();
        assert_eq!(accepted["ok"], true, "{accepted}");
        assert_eq!(
            open_capsule(&seeding_path, &id, &ws, &snapshot)
                .unwrap()
                .objects
                .len(),
            seeding.objects.len()
        );
        let plan = dir.path().join("plan.json");
        let planned:Value=serde_json::from_str(&crate::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&json!({"state_dir":dir.path(),"workspace_id":ws,"expected_actor":id.actor_id(),"snapshot_sha256":snapshot,"name":"Imported historical data","plan_path":plan,"capsule_path":capsule,"read_only_snapshot":true}).to_string())).unwrap();
        assert_eq!(planned["ok"], true, "{planned}");
        let output = dir.path().join("checkpoint.jsonl");
        let prepared:Value=serde_json::from_str(&crate::owner_cache_checkpoint::prepare_owner_checkpoint_from_cache_json(&json!({"state_dir":dir.path(),"workspace_id":ws,"expected_actor":id.actor_id(),"plan_path":plan,"capsule_path":capsule,"output_path":output,"origin":"https://new.example.invalid","audience":"legacy-offline-test"}).to_string())).unwrap();
        assert_eq!(prepared["ok"], true, "{prepared}");
        assert_eq!(prepared["value"]["records"], 1);
        let bytes = fs::read(&output).unwrap();
        assert!(!bytes
            .windows(b"PRIVATE SNAPSHOT BODY".len())
            .any(|v| v == b"PRIVATE SNAPSHOT BODY"));
        let lines = String::from_utf8(bytes).unwrap();
        let begin: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        let intent = begin["jws"].as_str().unwrap();
        let parts = intent.split('.').collect::<Vec<_>>();
        let body: Value = serde_json::from_slice(&decode_base64url(parts[1]).unwrap()).unwrap();
        assert_eq!(body["body"]["migration_mode"], "READ_ONLY_SNAPSHOT");
        assert_eq!(body["body"]["source"]["kind"], "PLAIN_PUBLIC");
        private(
            &source_path,
            &text.lines().take(2).collect::<Vec<_>>().join("\n"),
        );
        let refused = capture_source(SourceCapture {
            identity_path,
            expected_actor: id.actor_id().into(),
            recipient_path,
            request_path,
            source_path,
            capsule_path: dir.path().join("bad.capsule"),
            state_dir: None,
            keyring_path: None,
        });
        assert!(refused.is_err());
        assert!(!dir.path().join("bad.capsule").exists());
    }
}
