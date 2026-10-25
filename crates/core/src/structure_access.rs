//! Device access requests and recipient-bound body-key delivery. This module
//! handles only public certificates and opaque key boxes on the wire. It does
//! not infer Owner authority from a request or from service-readable records.
use crate::{
    canonical::{canonical, Path},
    crypto::{
        actor_id, base64url, decode_base64url, key_id, sha256_hex, sign_compact, verify_canonical,
        verifying_key,
    },
    e2ee::{encryption_key_id, hpke_open_wire, hpke_seal_wire, KeyBox, RecipientPublicJwk},
    prepared_command::VerifiedStructureAuthorIntent,
    secure_recipient::{RecipientCertificate, SecretRecipient},
    strict_json::parse_strict_json,
    structure_content::structure_content_key_id,
    structure_context::verify_structure_context,
    structure_execution::PROFILE,
    wire_json::{canonical_wire_value, WireValue},
};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const ACCESS_REQUEST_TYPE: &str = "peerwork.access-request.v1+jws";
const MAX_SAFE_TIME: u64 = 9_007_199_254_740_991;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccessError {
    #[error("invalid access request or recipient binding")]
    Invalid,
    #[error("access request has expired")]
    Expired,
    #[error("body-key grant authentication failed")]
    Authentication,
}
fn invalid<E>(_: E) -> AccessError {
    AccessError::Invalid
}
fn token(value: &str) -> bool {
    value.len() == 43 && decode_base64url(value).is_ok_and(|v| v.len() == 32)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessKind {
    Agent,
    Browser,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessWrite {
    pub instance_id: String,
    pub protocol_digest: String,
    pub action_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    pub v: u8,
    pub profile: String,
    pub workspace_id: String,
    pub actor_id: String,
    pub request_id: String,
    pub kind: AccessKind,
    pub label: String,
    pub certificate: RecipientCertificate,
    pub time_context: String,
    pub write: Option<AccessWrite>,
}
/// Can only be constructed after signature, audience, platform time, workspace
/// and self-certificate validation. The label is presentation, never authority.
pub struct VerifiedAccessRequest {
    request: AccessRequest,
    jws: String,
    deadline: u64,
    recipient: RecipientPublicJwk,
}
impl VerifiedAccessRequest {
    pub fn request(&self) -> &AccessRequest {
        &self.request
    }
    pub fn jws(&self) -> &str {
        &self.jws
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline
    }
    pub fn recipient(&self) -> &RecipientPublicJwk {
        &self.recipient
    }
    pub fn recipient_key_id(&self) -> &str {
        self.request.certificate.payload["encryption_key_id"]
            .as_str()
            .unwrap()
    }
}

pub struct AccessRequestOptions<'a> {
    pub workspace_id: &'a str,
    pub nonce: &'a str,
    pub kind: AccessKind,
    pub label: &'a str,
    pub write: Option<AccessWrite>,
    pub context_wire: &'a [u8],
    pub audience_utf16: &'a [u16],
    pub service_key: &'a str,
}
/// Uses a verified platform time context; no browser/host wall clock is read.
/// The caller persists the request and recipient key before displaying a code.
pub fn create_access_request(
    key: &SigningKey,
    recipient: &SecretRecipient,
    options: AccessRequestOptions<'_>,
) -> Result<VerifiedAccessRequest, AccessError> {
    let context = verify_structure_context(
        options.context_wire,
        options.nonce,
        options.audience_utf16,
        options.service_key,
    )
    .map_err(invalid)?;
    let response = parse_strict_json(options.context_wire).map_err(invalid)?;
    let request = AccessRequest {
        v: 1,
        profile: PROFILE.into(),
        workspace_id: options.workspace_id.into(),
        actor_id: actor_id(&key.verifying_key().to_bytes()),
        request_id: options.nonce.into(),
        kind: options.kind,
        label: options.label.into(),
        certificate: recipient
            .certify(key, context.server_time_ms())
            .map_err(invalid)?,
        time_context: response["context"]
            .as_str()
            .ok_or(AccessError::Invalid)?
            .into(),
        write: options.write,
    };
    let jws=sign_compact(&json!({"alg":"EdDSA","typ":ACCESS_REQUEST_TYPE,"kid":key_id(&key.verifying_key().to_bytes())}),&serde_json::to_value(request).map_err(invalid)?,key).map_err(invalid)?;
    verify_access_request(
        &jws,
        options.workspace_id,
        options.audience_utf16,
        options.service_key,
        context.server_time_ms(),
    )
}

pub fn verify_access_request(
    jws: &str,
    workspace: &str,
    audience_utf16: &[u16],
    service_key: &str,
    at: u64,
) -> Result<VerifiedAccessRequest, AccessError> {
    if jws.len() > 12000 || !token(workspace) || at > MAX_SAFE_TIME {
        return Err(AccessError::Invalid);
    }
    let parts: Vec<_> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(AccessError::Invalid);
    }
    let header =
        parse_strict_json(&decode_base64url(parts[0]).map_err(invalid)?).map_err(invalid)?;
    if header.as_object().map(|v| v.len()) != Some(3)
        || header["alg"] != "EdDSA"
        || header["typ"] != ACCESS_REQUEST_TYPE
    {
        return Err(AccessError::Invalid);
    }
    let kid = header["kid"].as_str().ok_or(AccessError::Invalid)?;
    let signer = verifying_key(kid).map_err(invalid)?;
    let signature: [u8; 64] = decode_base64url(parts[2])
        .map_err(invalid)?
        .try_into()
        .map_err(invalid)?;
    signer
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .map_err(invalid)?;
    let payload = decode_base64url(parts[1]).map_err(invalid)?;
    // Bounded public request; reject duplicate members before typed decoding.
    crate::wire_json::parse_wire_json_bounded(&payload, 12, 9000).map_err(invalid)?;
    let request: AccessRequest = serde_json::from_slice(&payload).map_err(invalid)?;
    if request.v != 1
        || request.profile != PROFILE
        || request.workspace_id != workspace
        || request.actor_id != actor_id(&signer.to_bytes())
        || !token(&request.request_id)
        || request.label.is_empty()
        || request.label.encode_utf16().count() > 80
        || request.time_context.len() > 4096
        || request.write.as_ref().is_some_and(|w| {
            !token(&w.instance_id)
                || !digest(&w.protocol_digest)
                || w.action_id.is_empty()
                || w.action_id.encode_utf16().count() > 120
        })
    {
        return Err(AccessError::Invalid);
    }
    let context = verify_structure_context(
        &serde_json::to_vec(&json!({"context":request.time_context})).map_err(invalid)?,
        &request.request_id,
        audience_utf16,
        service_key,
    )
    .map_err(invalid)?;
    if context.server_time_ms() > at || at >= context.expires_at_ms() {
        return Err(AccessError::Expired);
    }
    let cert = &request.certificate.payload;
    if cert.as_object().map(|v| v.len()) != Some(7)
        || cert["v"] != 1
        || cert["actor_id"] != request.actor_id
        || cert["signing_key"] != kid
        || cert["issued_at"].as_u64() != Some(context.server_time_ms())
        || cert["expires_at"]
            .as_u64()
            .is_none_or(|t| t <= at || t > MAX_SAFE_TIME)
        || !verify_canonical(
            "peerwork.secure.key-certificate.v1",
            cert,
            &request.certificate.signature,
            kid,
        )
        .map_err(invalid)?
    {
        return Err(AccessError::Invalid);
    }
    let recipient: RecipientPublicJwk =
        serde_json::from_value(cert["encryption_key"].clone()).map_err(invalid)?;
    if cert["encryption_key_id"] != encryption_key_id(&recipient).map_err(invalid)? {
        return Err(AccessError::Invalid);
    }
    Ok(VerifiedAccessRequest {
        request,
        jws: jws.into(),
        deadline: context.expires_at_ms(),
        recipient,
    })
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessContentGrant {
    pub key_ids: Vec<String>,
    pub current_key_id: String,
    pub r#box: KeyBox,
}
/// Trusted Rust storage boundary only. Never serialize or expose secret bytes
/// through Node/Python/CLI. Even error paths wipe decoded key material.
pub struct AccessKeyMaterial {
    id: String,
    secret: Zeroizing<[u8; 32]>,
}
impl AccessKeyMaterial {
    pub fn new(id: String, secret: Zeroizing<[u8; 32]>) -> Result<Self, AccessError> {
        if structure_content_key_id(&secret) != id {
            return Err(AccessError::Invalid);
        }
        Ok(Self { id, secret })
    }
    pub fn key_id(&self) -> &str {
        &self.id
    }
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}
pub struct OpenedAccessKeys {
    pub keys: Vec<AccessKeyMaterial>,
    pub current_key_id: String,
}
fn key_context(
    audience: &str,
    workspace: &str,
    owner: &str,
    request: &VerifiedAccessRequest,
    key_ids: &[String],
) -> Result<Value, AccessError> {
    if !token(owner)
        || key_ids.is_empty()
        || key_ids.len() > 32
        || key_ids.iter().any(|s| !token(s))
        || key_ids.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(AccessError::Invalid);
    }
    Ok(
        json!({"domain":"peerwork.structure-access-key-grant.v1","audience":audience,"workspace_id":workspace,
        "owner_id":owner,"recipient_actor_id":request.request.actor_id,"request_id":request.request.request_id,
        "certificate_digest":sha256_hex(canonical(&serde_json::to_value(&request.request.certificate).map_err(invalid)?,Path::SecureArtifact).map_err(invalid)?.as_bytes()),"key_ids":key_ids}),
    )
}
pub fn seal_access_keys(
    request: &VerifiedAccessRequest,
    audience: &str,
    owner: &str,
    keys: &[AccessKeyMaterial],
    current_key_id: &str,
) -> Result<AccessContentGrant, AccessError> {
    let ids: Vec<_> = keys.iter().map(|key| key.id.clone()).collect();
    let context = key_context(
        audience,
        &request.request.workspace_id,
        owner,
        request,
        &ids,
    )?;
    if !ids.iter().any(|id| id == current_key_id) {
        return Err(AccessError::Invalid);
    }
    // Build only bounded ASCII JSON directly in a wiping allocation. Avoid
    // intermediate serde Values or DTOs containing raw/base64 secret strings.
    let mut wire = Zeroizing::new(String::from("{\"keys\":["));
    for (i, key) in keys.iter().enumerate() {
        if structure_content_key_id(&key.secret) != key.id {
            return Err(AccessError::Invalid);
        }
        if i > 0 {
            wire.push(',');
        }
        wire.push_str("{\"key_id\":\"");
        wire.push_str(&key.id);
        wire.push_str("\",\"secret\":\"");
        let encoded = Zeroizing::new(base64url(&*key.secret));
        wire.push_str(&encoded);
        wire.push_str("\"}");
    }
    wire.push_str("]}");
    let box_value = hpke_seal_wire(
        request.recipient(),
        wire.as_bytes(),
        &serde_json::to_vec(&context).map_err(invalid)?,
    )
    .map_err(invalid)?;
    Ok(AccessContentGrant {
        key_ids: ids,
        current_key_id: current_key_id.into(),
        r#box: box_value,
    })
}
struct WipingWire(WireValue);
impl Drop for WipingWire {
    fn drop(&mut self) {
        fn wipe(value: &mut WireValue) {
            match value {
                WireValue::String(s) => s.zeroize(),
                WireValue::Array(a) => a.iter_mut().for_each(wipe),
                WireValue::Object(o) => o.iter_mut().for_each(|(k, v)| {
                    k.zeroize();
                    wipe(v)
                }),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

/// An independently verified Owner signature is required. The expected Owner
/// actor comes from the caller's selected workspace authority, not the response
/// that supplies the key box. Expiry is checked at original authorization time;
/// reading a committed grant later does not require a new browser approval.
pub fn open_owner_access_keys(
    author: &VerifiedStructureAuthorIntent,
    expected_owner: &str,
    recipient_actor: &str,
    recipient: &SecretRecipient,
    workspace: &str,
    audience: &str,
    service_key: &str,
) -> Result<OpenedAccessKeys, AccessError> {
    if author.action_id()=="structure.content-key.history.deliver"{return crate::structure_retained_keys::open_owner_retained_keys(author,expected_owner,recipient_actor,recipient,workspace,audience);}
    if author.action_id()=="structure.content-key.deliver"{return crate::structure_key_delivery::open_owner_current_key(author,expected_owner,recipient_actor,recipient,workspace,audience);}
    if author.action_id() != "structure.access.authorize"
        || author.actor_id() != expected_owner
        || author.workspace_id() != Some(workspace)
    {
        return Err(AccessError::Invalid);
    }
    let command = author.command();
    if command.get("audience").and_then(WireValue::as_utf16)
        != Some(audience.encode_utf16().collect::<Vec<_>>().as_slice())
    {
        return Err(AccessError::Invalid);
    }
    let body = command.get("body").ok_or(AccessError::Invalid)?;
    let jws = body
        .get("request_jws")
        .and_then(WireValue::as_string)
        .ok_or(AccessError::Invalid)?;
    let at = command
        .get("issued_at")
        .and_then(WireValue::as_number)
        .filter(|n| n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n <= MAX_SAFE_TIME as f64)
        .ok_or(AccessError::Invalid)? as u64;
    let request = verify_access_request(
        &jws,
        workspace,
        &audience.encode_utf16().collect::<Vec<_>>(),
        service_key,
        at,
    )?;
    if request.request.actor_id != recipient_actor
        || request.recipient_key_id() != recipient.encryption_key_id()
    {
        return Err(AccessError::Invalid);
    }
    let grant: AccessContentGrant = serde_json::from_str(
        &canonical_wire_value(
            body.get("content_grant").ok_or(AccessError::Invalid)?,
            Path::SecureArtifact,
        )
        .map_err(invalid)?,
    )
    .map_err(invalid)?;
    let context = key_context(
        audience,
        workspace,
        expected_owner,
        &request,
        &grant.key_ids,
    )?;
    if !grant.key_ids.contains(&grant.current_key_id)
        || grant.r#box.chunks.is_empty()
        || grant.r#box.chunks.len() > 8
        || grant.r#box.chunks.iter().any(|s| s.len() > 8192)
    {
        return Err(AccessError::Invalid);
    }
    let plain = WipingWire(
        hpke_open_wire(
            recipient.private_bytes(),
            &grant.r#box,
            &serde_json::to_vec(&context).map_err(invalid)?,
        )
        .map_err(|_| AccessError::Authentication)?,
    );
    let Some(WireValue::Array(values)) = plain.0.get("keys") else {
        return Err(AccessError::Invalid);
    };
    if plain.0.object_len() != Some(1) || values.len() != grant.key_ids.len() {
        return Err(AccessError::Invalid);
    }
    let mut keys = Vec::with_capacity(values.len());
    for (value, id) in values.iter().zip(&grant.key_ids) {
        if value.object_len() != Some(2)
            || value
                .get("key_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(id)
        {
            return Err(AccessError::Invalid);
        }
        let encoded = Zeroizing::new(
            value
                .get("secret")
                .and_then(WireValue::as_string)
                .ok_or(AccessError::Invalid)?,
        );
        let bytes = Zeroizing::new(decode_base64url(&encoded).map_err(invalid)?);
        if bytes.len() != 32 {
            return Err(AccessError::Invalid);
        }
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(&bytes);
        keys.push(AccessKeyMaterial::new(id.clone(), secret)?);
    }
    Ok(OpenedAccessKeys {
        keys,
        current_key_id: grant.current_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::sign_compact, prepared_command::verify_structure_author_intent};
    const NOW: u64 = 1_800_000_000_000;
    fn token_byte(byte: u8) -> String {
        base64url(&[byte; 32])
    }
    fn context(service: &SigningKey, nonce: &str, at: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({"context":sign_compact(
            &json!({"alg":"EdDSA","typ":crate::structure_context::CONTEXT_TYPE,"kid":key_id(&service.verifying_key().to_bytes())}),
            &json!({"v":1,"audience":"structure-test","profile":PROFILE,"nonce":nonce,"server_time_ms":at,
                "authorization_ttl_ms":600000,"idempotency":"BUSINESS_INTENT_V1","assurance":"BACKEND_CURRENT_STATE"}),service).unwrap()})).unwrap()
    }
    fn request(key: &SigningKey, recipient: &SecretRecipient, at: u64) -> VerifiedAccessRequest {
        let service = SigningKey::from_bytes(&[7; 32]);
        create_access_request(
            key,
            recipient,
            AccessRequestOptions {
                workspace_id: &token_byte(3),
                nonce: &token_byte(2),
                kind: AccessKind::Browser,
                label: "Browser with arbitrary display label",
                write: None,
                context_wire: &context(&service, &token_byte(2), at),
                audience_utf16: &"structure-test".encode_utf16().collect::<Vec<_>>(),
                service_key: &key_id(&service.verifying_key().to_bytes()),
            },
        )
        .unwrap()
    }
    fn service_key() -> String {
        key_id(&SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())
    }
    fn owner_author(
        request: &VerifiedAccessRequest,
        grant: &AccessContentGrant,
        owner: &SigningKey,
    ) -> VerifiedStructureAuthorIntent {
        let public = owner.verifying_key().to_bytes();
        let c = json!({"v":1,"audience":"structure-test","command_id":token_byte(8),"actor_id":actor_id(&public),"authority":sha256_hex(actor_id(&public).as_bytes()),
            "method":"POST","path":"/api/workspace/v1/commands","workspace_id":token_byte(3),"instance_id":null,"protocol_digest":null,
            "action_id":"structure.access.authorize","expected_workspace_revision":1,"expected_instance_revision":null,"exact_input_refs":[],
            "body":{"profile":PROFILE,"request_jws":request.jws(),"mode":"SESSION","expires_at":NOW+3600000,"content_grant":grant,"selected_write":null},
            "issued_at":NOW,"expires_at":NOW+600000});
        let jws = sign_compact(
            &json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":key_id(&public)}),
            &c,
            owner,
        )
        .unwrap();
        verify_structure_author_intent(&jws, &"structure-test".encode_utf16().collect::<Vec<_>>())
            .unwrap()
    }
    fn material(byte: u8) -> AccessKeyMaterial {
        let secret = Zeroizing::new([byte; 32]);
        AccessKeyMaterial::new(structure_content_key_id(&secret), secret).unwrap()
    }
    #[test]
    fn access_request_uses_nonce_bound_platform_time_and_preserves_recipient() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let recipient = SecretRecipient::from_private(Zeroizing::new([4; 32])).unwrap();
        let a = request(&key, &recipient, NOW);
        let audience: Vec<_> = "structure-test".encode_utf16().collect();
        assert!(verify_access_request(
            a.jws(),
            &token_byte(3),
            &audience,
            &service_key(),
            NOW + 9 * 60000
        )
        .is_ok());
        assert!(matches!(
            verify_access_request(
                a.jws(),
                &token_byte(3),
                &audience,
                &service_key(),
                NOW + 600000
            ),
            Err(AccessError::Expired)
        ));
        assert!(
            verify_access_request(a.jws(), &token_byte(4), &audience, &service_key(), NOW).is_err()
        );
        assert!(
            verify_access_request(a.jws(), &token_byte(3), &audience, &token_byte(9), NOW).is_err()
        );
        let next = request(&key, &recipient, NOW + 1000);
        assert_eq!(a.recipient_key_id(), next.recipient_key_id());
        assert_ne!(a.jws(), next.jws());
        let mut changed = a.request.clone();
        changed.request_id = token_byte(9);
        let jws=sign_compact(&json!({"alg":"EdDSA","typ":ACCESS_REQUEST_TYPE,"kid":key_id(&key.verifying_key().to_bytes())}),&serde_json::to_value(changed).unwrap(),&key).unwrap();
        assert!(
            verify_access_request(&jws, &token_byte(3), &audience, &service_key(), NOW).is_err()
        );
    }
    #[test]
    fn access_certificate_and_jws_signing_domains_are_distinct() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let recipient = SecretRecipient::generate().unwrap();
        let a = request(&key, &recipient, NOW);
        let audience: Vec<_> = "structure-test".encode_utf16().collect();
        let mut changed = a.request.clone();
        changed.certificate.signature = base64url(&[0; 64]);
        let header = json!({"alg":"EdDSA","typ":ACCESS_REQUEST_TYPE,"kid":key_id(&key.verifying_key().to_bytes())});
        let jws = sign_compact(&header, &serde_json::to_value(changed).unwrap(), &key).unwrap();
        assert!(
            verify_access_request(&jws, &token_byte(3), &audience, &service_key(), NOW).is_err()
        );
        let mut header = header;
        header["typ"] = json!("peerwork.kernel-command.v1+jws");
        let jws = sign_compact(&header, &serde_json::to_value(a.request()).unwrap(), &key).unwrap();
        assert!(
            verify_access_request(&jws, &token_byte(3), &audience, &service_key(), NOW).is_err()
        );
    }
    #[test]
    fn owner_key_delivery_authenticates_author_recipient_workspace_and_every_key() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let recipient = SecretRecipient::generate().unwrap();
        let req = request(&key, &recipient, NOW);
        let owner = SigningKey::from_bytes(&[9; 32]);
        let owner_id = actor_id(&owner.verifying_key().to_bytes());
        let mut keys = vec![material(11), material(12)];
        keys.sort_by(|a, b| a.id.cmp(&b.id));
        let grant =
            seal_access_keys(&req, "structure-test", &owner_id, &keys, &keys[0].id).unwrap();
        let author = owner_author(&req, &grant, &owner);
        let opened = open_owner_access_keys(
            &author,
            &owner_id,
            &req.request.actor_id,
            &recipient,
            &token_byte(3),
            "structure-test",
            &service_key(),
        )
        .unwrap();
        assert_eq!(opened.keys.len(), 2);
        for (expected, actual) in keys.iter().zip(&opened.keys) {
            assert_eq!(expected.secret(), actual.secret());
        }
        assert_eq!(opened.current_key_id, keys[0].id);
        assert!(open_owner_access_keys(
            &author,
            &token_byte(9),
            &req.request.actor_id,
            &recipient,
            &token_byte(3),
            "structure-test",
            &service_key()
        )
        .is_err());
        let stranger = SecretRecipient::generate().unwrap();
        assert!(open_owner_access_keys(
            &author,
            &owner_id,
            &req.request.actor_id,
            &stranger,
            &token_byte(3),
            "structure-test",
            &service_key()
        )
        .is_err());
        assert!(open_owner_access_keys(
            &author,
            &owner_id,
            &token_byte(8),
            &recipient,
            &token_byte(3),
            "structure-test",
            &service_key()
        )
        .is_err());
        assert!(open_owner_access_keys(
            &author,
            &owner_id,
            &req.request.actor_id,
            &recipient,
            &token_byte(4),
            "structure-test",
            &service_key()
        )
        .is_err());
        let mut tampered = grant.clone();
        tampered.r#box.chunks[0] = base64url(&[0; 100]);
        let forged = owner_author(&req, &tampered, &owner);
        assert!(matches!(
            open_owner_access_keys(
                &forged,
                &owner_id,
                &req.request.actor_id,
                &recipient,
                &token_byte(3),
                "structure-test",
                &service_key()
            ),
            Err(AccessError::Authentication)
        ));
        keys.reverse();
        assert!(seal_access_keys(&req, "structure-test", &owner_id, &keys, &keys[0].id).is_err());
        assert!(AccessKeyMaterial::new(token_byte(11), Zeroizing::new([11; 32])).is_err());
    }
    #[test]
    fn authenticated_but_mismatched_plaintext_keys_are_rejected() {
        let recipient = SecretRecipient::generate().unwrap();
        let req = request(&SigningKey::from_bytes(&[5; 32]), &recipient, NOW);
        let owner = SigningKey::from_bytes(&[9; 32]);
        let owner_id = actor_id(&owner.verifying_key().to_bytes());
        let ids = vec![material(11).id];
        let context = key_context("structure-test", &token_byte(3), &owner_id, &req, &ids).unwrap();
        let plain = Zeroizing::new(format!(
            "{{\"keys\":[{{\"key_id\":\"{}\",\"secret\":\"{}\"}}]}}",
            ids[0],
            base64url(&[12; 32])
        ));
        let grant = AccessContentGrant {
            key_ids: ids.clone(),
            current_key_id: ids[0].clone(),
            r#box: hpke_seal_wire(
                req.recipient(),
                plain.as_bytes(),
                &serde_json::to_vec(&context).unwrap(),
            )
            .unwrap(),
        };
        let author = owner_author(&req, &grant, &owner);
        assert!(matches!(
            open_owner_access_keys(
                &author,
                &owner_id,
                &req.request.actor_id,
                &recipient,
                &token_byte(3),
                "structure-test",
                &service_key()
            ),
            Err(AccessError::Invalid)
        ));
    }
}
