//! Credential-only import. Workspace authority still comes from signed replay.
use super::*;
use peerwork_core::{crypto::sha256_hex, wire_json::{parse_wire_json_bounded, WireValue}};
use serde::{Deserialize, Serialize};

const MAX_SOURCE: usize = 32 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRecipientImportInput {
    pub protected_ts_state_path: std::path::PathBuf,
    pub expected_actor_id: String,
    pub expected_signing_key_id: String,
    pub expected_source_digest: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyRecipientImportResult {
    pub status: String,
    pub actor_id: String,
    pub signing_key_id: String,
    pub certificate_digest: String,
    pub historical_certificates: usize,
    pub source_digest: String,
}

struct ProtectedSource(WireValue);
impl Drop for ProtectedSource {
    fn drop(&mut self) { scrub(&mut self.0); }
}
fn scrub(value: &mut WireValue) {
    match value {
        WireValue::String(s) => s.zeroize(),
        WireValue::Array(a) => a.iter_mut().for_each(scrub),
        WireValue::Object(a) => a.iter_mut().for_each(|(k,v)| { k.zeroize(); scrub(v); }),
        _ => {}
    }
}
fn text(value: Option<&WireValue>) -> Result<Zeroizing<String>, RecipientStateError> {
    value.and_then(WireValue::as_string).map(Zeroizing::new).ok_or(RecipientStateError::Invalid)
}
fn pair(value: &WireValue, secret_field: &str, identity: &KernelIdentity)
    -> Result<(RecipientCertificate, SecretRecipient), RecipientStateError> {
    let encoded = text(value.get(secret_field))?;
    let bytes = Zeroizing::new(decode_base64url(&encoded).map_err(|_| RecipientStateError::Invalid)?);
    if bytes.len() != 32 { return Err(RecipientStateError::Invalid); }
    let mut secret = Zeroizing::new([0u8;32]); secret.copy_from_slice(&bytes);
    let recipient = SecretRecipient::from_private(secret)?;
    let cert = value.get("certificate").ok_or(RecipientStateError::Invalid)?;
    // Only a public certificate is serialized outside the protected source.
    let cert_json = peerwork_core::wire_json::canonical_wire_value(cert,
        peerwork_core::canonical::Path::SecureArtifact).map_err(|_| RecipientStateError::Invalid)?;
    let certificate: RecipientCertificate = serde_json::from_str(&cert_json).map_err(|_| RecipientStateError::Invalid)?;
    let at = certificate.payload["issued_at"].as_u64().ok_or(RecipientStateError::Invalid)?;
    recipient.verify_local_certificate(&certificate, identity.actor_id(), identity.key_id(), at)?;
    Ok((certificate, recipient))
}

impl RecipientState {
    pub(crate) fn import_legacy_keys(path: &Path, identity: &KernelIdentity,
        input: &LegacyRecipientImportInput) -> Result<LegacyRecipientImportResult, RecipientStateError> {
        if path == input.protected_ts_state_path || input.expected_source_digest.len()!=64
            || !input.expected_source_digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(RecipientStateError::Invalid);
        }
        if input.expected_actor_id != identity.actor_id() || input.expected_signing_key_id != identity.key_id() {
            return Err(RecipientStateError::IdentityChanged);
        }
        let raw = read_private_file_bounded(&input.protected_ts_state_path, MAX_SOURCE)?;
        let digest = sha256_hex(&raw);
        if digest != input.expected_source_digest { return Err(RecipientStateError::SourceChanged); }
        let source = ProtectedSource(parse_wire_json_bounded(&raw,128,MAX_SOURCE).map_err(|_| RecipientStateError::Invalid)?);
        let source = &source.0;
        if source.get("v").and_then(WireValue::as_number)!=Some(1.0)
            || text(source.get("actor_id"))?.as_str()!=identity.actor_id()
            || !matches!(source.get("workspaces"),Some(WireValue::Object(_)))
            || !matches!(source.get("pending"),Some(WireValue::Object(_))) {
            return Err(RecipientStateError::Invalid);
        }
        // A prepared rotation may hold the only successor secret. Do not turn
        // credential import into implicit key-update recovery.
        if let Some(updates)=source.get("identity_key_intents") {
            let WireValue::Object(rows)=updates else { return Err(RecipientStateError::Invalid); };
            for (_,row) in rows {
                if text(row.get("state"))?.as_str()!="PUBLISHED" { return Err(RecipientStateError::SourcePending); }
            }
        }
        let mut entries=vec![pair(source,"encryption_private_key",identity)?];
        let mut seen=std::collections::HashSet::from([certificate_hash(&entries[0].0)?]);
        if let Some(history)=source.get("encryption_history") {
            let WireValue::Object(rows)=history else { return Err(RecipientStateError::Invalid); };
            if rows.len()>MAX_HISTORY { return Err(RecipientStateError::Invalid); }
            // Stable ordering makes same-source retries independent of object insertion order.
            let mut rows=rows.iter().collect::<Vec<_>>(); rows.sort_by(|a,b|a.0.cmp(&b.0));
            for (hash,row) in rows {
                let hash=String::from_utf16(hash).map_err(|_| RecipientStateError::Invalid)?;
                let entry=pair(row,"private_key",identity)?;
                if certificate_hash(&entry.0)?!=hash || !seen.insert(hash) { return Err(RecipientStateError::Invalid); }
                entries.push(entry);
            }
        }
        let refs=entries.iter().map(|(c,k)|(c,k)).collect::<Vec<_>>();
        let encoded=encode_v2(identity,&refs)?;
        let store=SecureStateStore::open(path)?;
        let status=if let Some(existing)=store.read_exact_secret()? {
            let (key,cert,history)=decode(&existing,identity)?;
            let mut actual=std::collections::BTreeMap::new(); actual.insert(certificate_hash(&cert)?,&key);
            for (cert,key) in &history { actual.insert(certificate_hash(cert)?,key); }
            let equal=certificate_hash(&cert)?==certificate_hash(&entries[0].0)? && actual.len()==entries.len()
                && entries.iter().all(|(c,k)| certificate_hash(c).ok().and_then(|hash|actual.get(&hash)).is_some_and(|v|v.private_bytes()==k.private_bytes()));
            if !equal { return Err(RecipientStateError::ImportConflict); }
            "ALREADY_IMPORTED"
        } else { store.write_exact(&encoded)?; "IMPORTED" };
        Ok(LegacyRecipientImportResult { status:status.into(), actor_id:identity.actor_id().into(),
            signing_key_id:identity.key_id().into(), certificate_digest:certificate_hash(&entries[0].0)?,
            historical_certificates:entries.len()-1, source_digest:digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::protected_test_dir;
    use peerwork_core::crypto::base64url;
    use serde_json::{json,Value};
    use std::fs;
    #[cfg(unix)] use std::os::unix::fs::PermissionsExt;
    fn write(path:&Path,value:&Value) -> String {
        let bytes=serde_json::to_vec(value).unwrap();
        #[cfg(windows)] crate::windows_fs::create_or_check_file(path).unwrap();
        fs::write(path,&bytes).unwrap();
        #[cfg(unix)] fs::set_permissions(path,fs::Permissions::from_mode(0o600)).unwrap();
        sha256_hex(&bytes)
    }
    fn fixture(identity:&KernelIdentity) -> Value {
        let old=SecretRecipient::generate().unwrap();let next=SecretRecipient::generate().unwrap();
        let old_cert=old.certify(identity.signing_key(),1_700_000_000_000).unwrap();
        let cert=next.certify(identity.signing_key(),1_700_000_001_000).unwrap();
        let hash=certificate_hash(&old_cert).unwrap();
        json!({"v":1,"actor_id":identity.actor_id(),"certificate":cert,
            "encryption_private_key":base64url(next.private_bytes()),
            "encryption_history":{hash:{"certificate":old_cert,"private_key":base64url(old.private_bytes())}},
            "workspaces":{"A":{"keyring":{"keys":{}}},"B":{}},"pending":{},"inbox_receipts":{"A.0":{}}})
    }
    fn input(path:&Path,id:&KernelIdentity,digest:String)->LegacyRecipientImportInput {
        LegacyRecipientImportInput{protected_ts_state_path:path.into(),expected_actor_id:id.actor_id().into(),
            expected_signing_key_id:id.key_id().into(),expected_source_digest:digest}
    }
    #[test]
    fn joined_credentials_and_history_import_without_authority_or_source_changes() {
        let dir=protected_test_dir();let id=KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let source=dir.path().join("legacy.json");let path=dir.path().join("recipient.state");let value=fixture(&id);
        let request=input(&source,&id,write(&source,&value));let original=fs::read(&source).unwrap();
        let imported=RecipientState::import_legacy_keys(&path,&id,&request).unwrap();assert_eq!(imported.status,"IMPORTED");assert_eq!(imported.historical_certificates,1);
        let saved=fs::read(&path).unwrap();let reopened=RecipientState::open(&path,&id).unwrap();
        let old:RecipientCertificate=serde_json::from_value(value["encryption_history"].as_object().unwrap().values().next().unwrap()["certificate"].clone()).unwrap();
        assert!(reopened.recipient_for_certificate(&old).is_ok());assert_eq!(reopened.history.len(),1);drop(reopened);
        assert_eq!(RecipientState::import_legacy_keys(&path,&id,&request).unwrap().status,"ALREADY_IMPORTED");
        assert_eq!(fs::read(&path).unwrap(),saved);assert_eq!(fs::read(&source).unwrap(),original);
        assert!(!dir.path().join("lifecycle.state").exists());assert!(!dir.path().join("kernel.sqlite").exists());
    }
    #[test]
    fn invalid_credentials_pins_and_pending_rotation_never_promote() {
        let dir=protected_test_dir();let id=KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let source=dir.path().join("legacy.json");let path=dir.path().join("recipient.state");let value=fixture(&id);
        let mut request=input(&source,&id,write(&source,&value));request.expected_source_digest="0".repeat(64);
        assert!(matches!(RecipientState::import_legacy_keys(&path,&id,&request),Err(RecipientStateError::SourceChanged)));
        for kind in ["actor","secret","history-hash","history-secret","pending","signature"] {
            let mut v=value.clone();
            match kind {
                "actor"=>v["actor_id"]=json!("wrong"),
                "secret"=>v["encryption_private_key"]=json!(base64url(&[7u8;32])),
                "history-hash"=>{let map=v["encryption_history"].as_object_mut().unwrap();let key=map.keys().next().unwrap().clone();let row=map.remove(&key).unwrap();map.insert("0".repeat(64),row);},
                "history-secret"=>v["encryption_history"].as_object_mut().unwrap().values_mut().next().unwrap()["private_key"]=json!(base64url(&[7u8;32])),
                "pending"=>v["identity_key_intents"]=json!({"test":{"state":"PREPARED"}}),
                _=>v["certificate"]["signature"]=json!("invalid"),
            }
            let request=input(&source,&id,write(&source,&v));assert!(RecipientState::import_legacy_keys(&path,&id,&request).is_err(),"{kind}");assert!(!path.exists(),"{kind}");
        }
        let mut request=input(&source,&id,write(&source,&value));request.expected_signing_key_id="wrong".into();
        assert!(matches!(RecipientState::import_legacy_keys(&path,&id,&request),Err(RecipientStateError::IdentityChanged)));
        assert!(!path.exists());
    }
    #[test]
    fn different_existing_recipient_is_never_overwritten() {
        let dir=protected_test_dir();let id=KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let source=dir.path().join("legacy.json");let path=dir.path().join("recipient.state");
        let request=input(&source,&id,write(&source,&fixture(&id)));drop(RecipientState::create(&path,&id,1_700_000_002_000).unwrap());
        let before=fs::read(&path).unwrap();assert!(matches!(RecipientState::import_legacy_keys(&path,&id,&request),Err(RecipientStateError::ImportConflict)));
        assert_eq!(fs::read(&path).unwrap(),before);
    }
}
