//! Authenticated owner-side identity-directory discovery. An explicit actor
//! and signing-key pin precede first contact; a protected head prevents
//! rollback or fork on subsequent lookups. A certificate is public identity
//! material, not workspace membership or recipient-secret authority.

use crate::{
    kernel_client::KernelClient, kernel_identity::KernelIdentity,
    secure_journal_read::sign_read_proof, secure_state::SecureStateStore,
    transport::TransportConfig,
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{actor_id, decode_base64url, sha256_hex, verify_secure_signed_wire},
    e2ee::{encryption_key_id, RecipientPublicJwk},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

const DIRECTORY_DOMAIN: &str = "peerwork.secure.identity-directory.v1";
const CERTIFICATE_DOMAIN: &str = "peerwork.secure.key-certificate.v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDirectoryConfig {
    pub origin: String,
    pub identity_path: PathBuf,
    pub kernel_journal_path: PathBuf,
    pub pins_path: PathBuf,
    #[serde(default)]
    pub allow_loopback_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedIdentityCertificate {
    pub actor_id: String,
    pub signing_key_id: String,
    pub directory_version: usize,
    pub directory_head: String,
    pub certificate_json: String,
}

#[derive(Debug, Error)]
pub enum IdentityDirectoryError {
    #[error("directory identity pin, chain, or signed certificate is invalid")]
    Invalid,
    #[error("directory history rolled back or forked from a protected pin")]
    Continuity,
    #[error("protected local identity or directory state failed")]
    Local,
    #[error("configured identity directory transport failed")]
    Transport,
    #[error("directory server rejected read with HTTP {0}")]
    ServerRejected(u16),
    #[error("requested identity has no published directory entry")]
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    key: String,
    version: usize,
    head: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinsDocument {
    v: u8,
    origin: String,
    reader_actor_id: String,
    reader_key_id: String,
    pins: BTreeMap<String, Pin>,
}

pub struct SecureIdentityDirectory {
    config: IdentityDirectoryConfig,
}

impl SecureIdentityDirectory {
    pub fn new(config: IdentityDirectoryConfig) -> Self {
        Self { config }
    }

    /// The target signing key is deliberately caller-pinned on first contact;
    /// subsequent calls must match the protected pin and signed chain head.
    pub fn lookup_certificate(
        &self,
        target_actor_id: &str,
        target_signing_key_id: &str,
    ) -> Result<VerifiedIdentityCertificate, IdentityDirectoryError> {
        self.lookup_certificate_with_cancel(
            target_actor_id,
            target_signing_key_id,
            &CancellationToken::new(),
        )
    }

    pub fn lookup_certificate_with_cancel(
        &self,
        target_actor_id: &str,
        target_signing_key_id: &str,
        cancel: &CancellationToken,
    ) -> Result<VerifiedIdentityCertificate, IdentityDirectoryError> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| IdentityDirectoryError::Transport)?;
        runtime.block_on(self.lookup_async(target_actor_id, target_signing_key_id, cancel, true))
    }

    pub(crate) fn lookup_for_update(
        &self,
        target_actor_id: &str,
        target_signing_key_id: &str,
        cancel: &CancellationToken,
    ) -> Result<VerifiedIdentityCertificate, IdentityDirectoryError> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| IdentityDirectoryError::Transport)?;
        runtime.block_on(self.lookup_async(target_actor_id, target_signing_key_id, cancel, false))
    }

    pub(crate) async fn lookup_async(
        &self,
        target_actor_id: &str,
        target_signing_key_id: &str,
        cancel: &CancellationToken,
        require_current: bool,
    ) -> Result<VerifiedIdentityCertificate, IdentityDirectoryError> {
        let key: [u8; 32] = decode_base64url(target_signing_key_id)
            .map_err(|_| IdentityDirectoryError::Invalid)?
            .try_into()
            .map_err(|_| IdentityDirectoryError::Invalid)?;
        if actor_id(&key) != target_actor_id
            || target_actor_id.len() != 43
            || target_signing_key_id.len() != 43
        {
            return Err(IdentityDirectoryError::Invalid);
        }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| IdentityDirectoryError::Local)?;
        let store = SecureStateStore::open(&self.config.pins_path)
            .map_err(|_| IdentityDirectoryError::Local)?;
        let mut document = match store
            .read_exact()
            .map_err(|_| IdentityDirectoryError::Local)?
        {
            Some(bytes) => serde_json::from_slice::<PinsDocument>(&bytes)
                .map_err(|_| IdentityDirectoryError::Invalid)?,
            None => PinsDocument {
                v: 1,
                origin: self.config.origin.clone(),
                reader_actor_id: identity.actor_id().into(),
                reader_key_id: identity.key_id().into(),
                pins: BTreeMap::new(),
            },
        };
        if document.v != 1
            || document.origin != self.config.origin
            || document.reader_actor_id != identity.actor_id()
            || document.reader_key_id != identity.key_id()
            || document.pins.len() > 128
        {
            return Err(IdentityDirectoryError::Continuity);
        }
        if document
            .pins
            .get(target_actor_id)
            .is_some_and(|pin| pin.key != target_signing_key_id)
        {
            return Err(IdentityDirectoryError::Continuity);
        }
        let mut transport = TransportConfig::new(self.config.origin.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let client = KernelClient::open(transport, &self.config.kernel_journal_path, &[], cancel)
            .await
            .map_err(|_| IdentityDirectoryError::Transport)?;
        if client.origin() != self.config.origin {
            return Err(IdentityDirectoryError::Continuity);
        }
        let path = format!("/api/workspace/v1/secure/identity-keys/{target_actor_id}");
        let authority = sha256_hex(identity.actor_id().as_bytes());
        let proof = sign_read_proof(&path, client.discovery(), &identity, &authority)
            .map_err(|_| IdentityDirectoryError::Transport)?;
        let response = client
            .transport()
            .get_secure_identity_keys_exact(&path, &proof, cancel)
            .await
            .map_err(|_| IdentityDirectoryError::Transport)?;
        if !(200..300).contains(&response.status) {
            return Err(IdentityDirectoryError::ServerRejected(response.status));
        }
        let directory = parse_wire_json_js_bounded(&response.wire, 100, 2 * 1024 * 1024)
            .map_err(|_| IdentityDirectoryError::Invalid)?;
        if directory.object_len() != Some(2)
            || directory
                .get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(target_actor_id)
        {
            return Err(IdentityDirectoryError::Invalid);
        }
        let WireValue::Array(entries) = directory
            .get("entries")
            .ok_or(IdentityDirectoryError::Invalid)?
        else {
            return Err(IdentityDirectoryError::Invalid);
        };
        if entries.is_empty() {
            return Err(if document.pins.contains_key(target_actor_id) {
                IdentityDirectoryError::Continuity
            } else {
                IdentityDirectoryError::NotFound
            });
        }
        if entries.len() > 128 {
            return Err(IdentityDirectoryError::Invalid);
        }
        let prior = document.pins.get(target_actor_id);
        let at = now_ms()?;
        let mut previous: Option<String> = None;
        let mut issued = 0u64;
        let mut latest_cert = None;
        for (index, entry) in entries.iter().enumerate() {
            let (entry_issued, certificate) = verify_entry(
                entry,
                target_actor_id,
                target_signing_key_id,
                index + 1,
                previous.as_deref(),
                issued,
                at,
                index + 1 == entries.len(),
                require_current,
            )?;
            let wire = canonical_wire_value(entry, CanonicalPath::SecureArtifact)
                .map_err(|_| IdentityDirectoryError::Invalid)?;
            let head = sha256_hex(wire.as_bytes());
            if prior.is_some_and(|pin| pin.version == index + 1 && pin.head != head) {
                return Err(IdentityDirectoryError::Continuity);
            }
            previous = Some(head);
            issued = entry_issued;
            latest_cert = Some(certificate);
        }
        if prior.is_some_and(|pin| pin.version > entries.len()) {
            return Err(IdentityDirectoryError::Continuity);
        }
        let head = previous.ok_or(IdentityDirectoryError::Invalid)?;
        let certificate_json = latest_cert.ok_or(IdentityDirectoryError::Invalid)?;
        document.pins.insert(
            target_actor_id.into(),
            Pin {
                key: target_signing_key_id.into(),
                version: entries.len(),
                head: head.clone(),
            },
        );
        let bytes = serde_json::to_vec(&document).map_err(|_| IdentityDirectoryError::Invalid)?;
        if bytes.len() > 32 * 1024 {
            return Err(IdentityDirectoryError::Invalid);
        }
        store
            .write_exact(&bytes)
            .map_err(|_| IdentityDirectoryError::Local)?;
        Ok(VerifiedIdentityCertificate {
            actor_id: target_actor_id.into(),
            signing_key_id: target_signing_key_id.into(),
            directory_version: entries.len(),
            directory_head: head,
            certificate_json,
        })
    }
}

fn verify_entry(
    entry: &WireValue,
    actor: &str,
    key: &str,
    version: usize,
    previous: Option<&str>,
    min_issued: u64,
    now: u64,
    current: bool,
    require_current: bool,
) -> Result<(u64, String), IdentityDirectoryError> {
    if entry.object_len() != Some(2) {
        return Err(IdentityDirectoryError::Invalid);
    }
    let payload = entry
        .get("payload")
        .ok_or(IdentityDirectoryError::Invalid)?;
    if payload.object_len() != Some(7)
        || payload.get("v").and_then(WireValue::as_number) != Some(1.0)
        || payload
            .get("actor_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(actor)
        || payload
            .get("signing_key")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(key)
        || payload.get("version").and_then(WireValue::as_number) != Some(version as f64)
        || match previous {
            Some(head) => {
                payload
                    .get("previous")
                    .and_then(WireValue::as_string)
                    .as_deref()
                    != Some(head)
            }
            None => !matches!(payload.get("previous"), Some(WireValue::Null)),
        }
    {
        return Err(IdentityDirectoryError::Invalid);
    }
    let entry_issued = exact_u64(
        payload
            .get("issued_at")
            .ok_or(IdentityDirectoryError::Invalid)?,
    )?;
    if entry_issued < min_issued || entry_issued > now {
        return Err(IdentityDirectoryError::Invalid);
    }
    let wire = canonical_wire_value(entry, CanonicalPath::SecureArtifact)
        .map_err(|_| IdentityDirectoryError::Invalid)?;
    if !verify_secure_signed_wire(wire.as_bytes(), DIRECTORY_DOMAIN, key)
        .map_err(|_| IdentityDirectoryError::Invalid)?
    {
        return Err(IdentityDirectoryError::Invalid);
    }
    let cert = payload
        .get("certificate")
        .ok_or(IdentityDirectoryError::Invalid)?;
    verify_certificate(
        cert,
        actor,
        key,
        if current && require_current {
            now
        } else {
            entry_issued
        },
    )?;
    let cert_json = canonical_wire_value(cert, CanonicalPath::SecureArtifact)
        .map_err(|_| IdentityDirectoryError::Invalid)?;
    Ok((entry_issued, cert_json))
}

fn verify_certificate(
    cert: &WireValue,
    actor: &str,
    key: &str,
    at: u64,
) -> Result<(), IdentityDirectoryError> {
    if cert.object_len() != Some(2) {
        return Err(IdentityDirectoryError::Invalid);
    }
    let payload = cert.get("payload").ok_or(IdentityDirectoryError::Invalid)?;
    if payload.get("v").and_then(WireValue::as_number) != Some(1.0)
        || payload
            .get("actor_id")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(actor)
        || payload
            .get("signing_key")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(key)
    {
        return Err(IdentityDirectoryError::Invalid);
    }
    let issued = exact_u64(
        payload
            .get("issued_at")
            .ok_or(IdentityDirectoryError::Invalid)?,
    )?;
    let expires = exact_u64(
        payload
            .get("expires_at")
            .ok_or(IdentityDirectoryError::Invalid)?,
    )?;
    if issued > at || at >= expires || expires <= issued || expires - issued > 366 * 86_400_000 {
        return Err(IdentityDirectoryError::Invalid);
    }
    let jwk = payload
        .get("encryption_key")
        .ok_or(IdentityDirectoryError::Invalid)?;
    if jwk.object_len() != Some(4) {
        return Err(IdentityDirectoryError::Invalid);
    }
    let jwk_wire = canonical_wire_value(jwk, CanonicalPath::SecureArtifact)
        .map_err(|_| IdentityDirectoryError::Invalid)?;
    let jwk: RecipientPublicJwk =
        serde_json::from_str(&jwk_wire).map_err(|_| IdentityDirectoryError::Invalid)?;
    let id = encryption_key_id(&jwk).map_err(|_| IdentityDirectoryError::Invalid)?;
    if payload
        .get("encryption_key_id")
        .and_then(WireValue::as_string)
        .as_deref()
        != Some(id.as_str())
    {
        return Err(IdentityDirectoryError::Invalid);
    }
    let wire = canonical_wire_value(cert, CanonicalPath::SecureArtifact)
        .map_err(|_| IdentityDirectoryError::Invalid)?;
    if !verify_secure_signed_wire(wire.as_bytes(), CERTIFICATE_DOMAIN, key)
        .map_err(|_| IdentityDirectoryError::Invalid)?
    {
        return Err(IdentityDirectoryError::Invalid);
    }
    Ok(())
}

fn exact_u64(value: &WireValue) -> Result<u64, IdentityDirectoryError> {
    let Some(number) = value.as_number() else {
        return Err(IdentityDirectoryError::Invalid);
    };
    if !number.is_finite()
        || number < 0.0
        || number > 9_007_199_254_740_991.0
        || number.fract() != 0.0
    {
        return Err(IdentityDirectoryError::Invalid);
    }
    Ok(number as u64)
}

fn now_ms() -> Result<u64, IdentityDirectoryError> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityDirectoryError::Invalid)?
        .as_millis();
    u64::try_from(ms)
        .ok()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or(IdentityDirectoryError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure_recipient_enrollment::{RecipientEnrollmentConfig, SecureRecipientEnrollment},
        secure_recipient_state::RecipientState,
    };
    use peerwork_core::{
        canonical::{canonical, Path},
        crypto::sign_canonical,
    };
    use serde_json::json;
    use std::{
        fs,
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };

    #[test]
    fn actual_service_owner_lookup_pin_rollback_and_rotation() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", temp.path())
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "reference service failed to start");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let mut recipient_config = RecipientEnrollmentConfig::for_state_dir(
            origin.clone(),
            &temp.path().join("recipient"),
        );
        recipient_config.allow_loopback_http = true;
        let enrollment = SecureRecipientEnrollment::new(recipient_config.clone());
        let local = enrollment.create_local().unwrap();
        assert_eq!(enrollment.publish().unwrap().status, "REGISTRATION_PENDING");
        assert_eq!(enrollment.publish().unwrap().status, "PUBLISHED");
        let owner_path = temp.path().join("owner.identity");
        KernelIdentity::import_pkcs8_pem_file(
            &owner_path,
            &temp.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        let directory = SecureIdentityDirectory::new(IdentityDirectoryConfig {
            origin: origin.clone(),
            identity_path: owner_path,
            kernel_journal_path: temp.path().join("owner.kernel.sqlite"),
            pins_path: temp.path().join("owner.directory.state"),
            allow_loopback_http: true,
        });
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/tamper-next-identity-directory"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        assert!(matches!(
            directory.lookup_certificate(&local.actor_id, &local.signing_key_id),
            Err(IdentityDirectoryError::Invalid)
        ));
        let first = directory
            .lookup_certificate(&local.actor_id, &local.signing_key_id)
            .unwrap();
        assert_eq!(first.directory_version, 1);
        assert_eq!(
            first.certificate_json,
            enrollment.certificate_json().unwrap()
        );
        assert_eq!(
            directory
                .lookup_certificate(&local.actor_id, &local.signing_key_id)
                .unwrap(),
            first
        );
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/serve-stale-identity-directory"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        assert!(matches!(
            directory.lookup_certificate(&local.actor_id, &local.signing_key_id),
            Err(IdentityDirectoryError::Continuity)
        ));
        runtime.block_on(async {
            let response = reqwest::Client::new()
                .post(format!("{origin}__test/restore-identity-directory"))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        });
        assert_eq!(
            directory
                .lookup_certificate(&local.actor_id, &local.signing_key_id)
                .unwrap(),
            first
        );
        // A source-valid second signed directory entry changes the P-256
        // certificate while retaining the signing actor and previous head.
        let signer = KernelIdentity::open(&recipient_config.identity_path).unwrap();
        let replacement = RecipientState::create(
            &temp.path().join("replacement.state"),
            &signer,
            now_ms().unwrap(),
        )
        .unwrap();
        let payload = json!({"v":1,"actor_id":local.actor_id,"signing_key":local.signing_key_id,
            "version":2,"previous":first.directory_head,"certificate":replacement.certificate(),"issued_at":now_ms().unwrap()});
        let signature = sign_canonical(DIRECTORY_DOMAIN, &payload, signer.signing_key()).unwrap();
        let request = canonical(
            &json!({"entry":{"payload":payload,"signature":signature}}),
            Path::SecureArtifact,
        )
        .unwrap();
        let mut transport = TransportConfig::new(origin.clone());
        transport.allow_loopback_http = true;
        let client = runtime
            .block_on(KernelClient::open(
                transport,
                &recipient_config.kernel_journal_path,
                &[],
                &CancellationToken::new(),
            ))
            .unwrap();
        let authority = sha256_hex(signer.actor_id().as_bytes());
        let proof = sign_read_proof(
            "/api/workspace/v1/secure/identity-keys",
            client.discovery(),
            &signer,
            &authority,
        )
        .unwrap();
        let posted = runtime
            .block_on(client.transport().post_secure_identity_key_exact(
                request.into_bytes(),
                &proof,
                &CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(posted.status, 201);
        drop(replacement);
        let second = directory
            .lookup_certificate(&local.actor_id, &local.signing_key_id)
            .unwrap();
        assert_eq!(second.directory_version, 2);
        assert_ne!(second.directory_head, first.directory_head);
        assert_ne!(second.certificate_json, first.certificate_json);
        assert_eq!(
            directory
                .lookup_certificate(&local.actor_id, &local.signing_key_id)
                .unwrap(),
            second
        );
    }
}
