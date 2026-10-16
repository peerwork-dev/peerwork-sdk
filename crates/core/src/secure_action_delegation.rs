//! Narrow signed device-delegation and ACTION scope resolver. The selected
//! policy and commit context must already come from authenticated replay.
//! These checked facts are not a journal, effect, or submission proof.

use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, decode_base64url, sha256, verify_secure_signed_wire},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue},
};
use hpke::{kem::DhP256HkdfSha256, Deserializable, Kem as KemTrait};

const MAX_DELEGATION_BYTES: usize = 512 * 1024;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
const CERT_LIFETIME_MS: f64 = 366.0 * 86_400_000.0;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ActionScopeError {
    Invalid,
    Denied,
    Source(&'static str),
}

impl ActionScopeError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Invalid | Self::Denied => "AUTHOR_SCOPE_DENIED",
            Self::Source(code) => code,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CheckedActionScope {
    pub actor_id: String,
    pub role: String,
    pub scopes: Vec<WireValue>,
    action_id: WireValue,
    instance_id: WireValue,
}

impl CheckedActionScope {
    pub(crate) fn permits_action(&self) -> bool {
        self.scopes.iter().any(|scope| {
            matches_instance(scope, &self.instance_id)
                && includes(scope, "actions", &self.action_id)
        })
    }
    pub(crate) fn permits_protocol_role(&self, role: &WireValue) -> bool {
        self.scopes.iter().any(|scope| {
            matches_instance(scope, &self.instance_id) && includes(scope, "protocol_roles", role)
        })
    }
    pub(crate) fn permits_capability(&self, capability: &WireValue) -> bool {
        self.scopes.iter().any(|scope| {
            matches_instance(scope, &self.instance_id)
                && includes(scope, "capabilities", capability)
        })
    }
}

fn field<'a>(value: &'a WireValue, key: &str) -> Result<&'a WireValue, ActionScopeError> {
    value.get(key).ok_or(ActionScopeError::Invalid)
}
fn string(value: &WireValue) -> Result<String, ActionScopeError> {
    value.as_string().ok_or(ActionScopeError::Invalid)
}
fn number(value: &WireValue) -> Result<f64, ActionScopeError> {
    let n = value.as_number().ok_or(ActionScopeError::Invalid)?;
    if !n.is_finite() || n < 0.0 || n > MAX_SAFE || n.fract() != 0.0 {
        return Err(ActionScopeError::Invalid);
    }
    Ok(n)
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn actor_key_matches(actor: &str, key: &str) -> Result<bool, ActionScopeError> {
    let public: [u8; 32] = decode_base64url(key)
        .map_err(|_| ActionScopeError::Invalid)?
        .try_into()
        .map_err(|_| ActionScopeError::Invalid)?;
    Ok(actor_id(&public) == actor)
}
fn canonical(value: &WireValue) -> Result<String, ActionScopeError> {
    canonical_wire_value(value, Path::SecureArtifact).map_err(|_| ActionScopeError::Invalid)
}
fn equal(a: &WireValue, b: &WireValue) -> Result<bool, ActionScopeError> {
    Ok(canonical(a)? == canonical(b)?)
}
fn list(value: &WireValue) -> Result<&[WireValue], ActionScopeError> {
    let WireValue::Array(values) = value else {
        return Err(ActionScopeError::Invalid);
    };
    Ok(values)
}
fn member<'a>(policy: &'a WireValue, actor: &str) -> Result<&'a WireValue, ActionScopeError> {
    list(field(policy, "members")?)?
        .iter()
        .find(|row| {
            row.get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                == Some(actor)
        })
        .ok_or(ActionScopeError::Denied)
}
fn matches_instance(scope: &WireValue, instance: &WireValue) -> bool {
    matches!(scope.get("instance_id"), Some(WireValue::Null))
        || scope.get("instance_id") == Some(instance)
}
fn active(scope: &WireValue, at: f64) -> Result<bool, ActionScopeError> {
    match scope.get("expires_at") {
        None | Some(WireValue::Null) => Ok(true),
        Some(value) => Ok(number(value)? > at),
    }
}
fn includes(scope: &WireValue, field: &str, wanted: &WireValue) -> bool {
    scope
        .get(field)
        .and_then(|value| match value {
            WireValue::Array(rows) => Some(rows),
            _ => None,
        })
        .is_some_and(|rows| rows.iter().any(|row| row == wanted))
}
fn scope_valid(scopes: &WireValue) -> Result<(), ActionScopeError> {
    let rows = list(scopes)?;
    if rows.len() > 128 {
        return Err(ActionScopeError::Invalid);
    }
    for row in rows {
        let WireValue::Object(fields) = row else {
            return Err(ActionScopeError::Invalid);
        };
        if fields.iter().any(|(key, _)| {
            ![
                "instance_id",
                "actions",
                "protocol_roles",
                "capabilities",
                "expires_at",
            ]
            .iter()
            .any(|allowed| *key == allowed.encode_utf16().collect::<Vec<_>>())
        }) {
            return Err(ActionScopeError::Invalid);
        }
        match field(row, "instance_id")? {
            WireValue::Null => (),
            value if value.as_string().is_some_and(|id| token(&id)) => (),
            _ => return Err(ActionScopeError::Invalid),
        }
        if let Some(expires) = row.get("expires_at") {
            if !matches!(expires, WireValue::Null) && number(expires)? < 1.0 {
                return Err(ActionScopeError::Invalid);
            }
        }
        for key in ["actions", "protocol_roles", "capabilities"] {
            let values = list(field(row, key)?)?;
            if values.len() > 64 {
                return Err(ActionScopeError::Invalid);
            }
            let mut seen = Vec::new();
            for value in values {
                let units = value.as_utf16().ok_or(ActionScopeError::Invalid)?;
                if units.is_empty() || units.len() > 120 || seen.contains(&units) {
                    return Err(ActionScopeError::Invalid);
                }
                seen.push(units);
            }
        }
    }
    Ok(())
}
fn verify_certificate(cert: &WireValue, at: f64) -> Result<(), ActionScopeError> {
    let payload = field(cert, "payload")?;
    if number(field(payload, "v")?)? != 1.0 {
        return Err(ActionScopeError::Source("CERTIFICATE_INVALID"));
    }
    let actor = string(field(payload, "actor_id")?)?;
    let key = string(field(payload, "signing_key")?)?;
    if !token(&actor) || !token(&key) {
        return Err(ActionScopeError::Source("CERTIFICATE_INVALID"));
    }
    if !actor_key_matches(&actor, &key)? {
        return Err(ActionScopeError::Source("CERTIFICATE_IDENTITY_MISMATCH"));
    }
    let issued = number(field(payload, "issued_at")?)?;
    let expires = number(field(payload, "expires_at")?)?;
    if expires <= issued || expires - issued > CERT_LIFETIME_MS {
        return Err(ActionScopeError::Source("CERTIFICATE_INVALID"));
    }
    if at < issued || at >= expires {
        return Err(ActionScopeError::Source("CERTIFICATE_EXPIRED"));
    }
    let jwk = field(payload, "encryption_key")?;
    if jwk.object_len() != Some(4)
        || string(field(jwk, "kty")?)? != "EC"
        || string(field(jwk, "crv")?)? != "P-256"
    {
        return Err(ActionScopeError::Source("CERTIFICATE_KEY_INVALID"));
    }
    let x = string(field(jwk, "x")?)?;
    let y = string(field(jwk, "y")?)?;
    if !token(&x) || !token(&y) {
        return Err(ActionScopeError::Source("CERTIFICATE_KEY_INVALID"));
    }
    let xb =
        decode_base64url(&x).map_err(|_| ActionScopeError::Source("CERTIFICATE_KEY_INVALID"))?;
    let yb =
        decode_base64url(&y).map_err(|_| ActionScopeError::Source("CERTIFICATE_KEY_INVALID"))?;
    if xb.len() != 32 || yb.len() != 32 {
        return Err(ActionScopeError::Source("CERTIFICATE_KEY_INVALID"));
    }
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&xb);
    point[33..65].copy_from_slice(&yb);
    <DhP256HkdfSha256 as KemTrait>::PublicKey::from_bytes(&point)
        .map_err(|_| ActionScopeError::Source("CERTIFICATE_KEY_INVALID"))?;
    if string(field(payload, "encryption_key_id")?)?
        != base64url(&sha256(canonical(jwk)?.as_bytes()))
    {
        return Err(ActionScopeError::Source("CERTIFICATE_KEY_MISMATCH"));
    }
    if !verify_secure_signed_wire(
        canonical(cert)?.as_bytes(),
        "peerwork.secure.key-certificate.v1",
        &key,
    )
    .map_err(|_| ActionScopeError::Source("SIGNATURE_INVALID"))?
    {
        return Err(ActionScopeError::Source("SIGNATURE_INVALID"));
    }
    Ok(())
}

pub(crate) fn verify_member_certificate_at(
    policy_payload: &WireValue,
    actor_id: &str,
    at: u64,
) -> Result<(), ActionScopeError> {
    let row = member(policy_payload, actor_id)?;
    verify_certificate(field(row, "certificate")?, at as f64)
}

/// The caller must supply the signed, selected policy payload and signed
/// commit context from full replay. This function checks only ACTION actor,
/// device delegation and effective scope at `context.issued_at`.
pub(crate) fn resolve_action_scope(
    context: &WireValue,
    authenticated_policy_payload: &WireValue,
    exact_delegation_wire: Option<&[u8]>,
) -> Result<CheckedActionScope, ActionScopeError> {
    let at = number(field(context, "issued_at")?)?;
    let actor = string(field(context, "actor_id")?)?;
    let key = string(field(context, "signing_key")?)?;
    let workspace = string(field(context, "workspace_id")?)?;
    if !actor_key_matches(&actor, &key)? {
        return Err(ActionScopeError::Source("AUTHOR_KEY_MISMATCH"));
    }
    let action = field(context, "action_id")?;
    let instance = field(context, "instance_id")?;
    let delegation = field(context, "delegation")?;
    let principal = if matches!(delegation, WireValue::Null) {
        if exact_delegation_wire.is_some() {
            return Err(ActionScopeError::Invalid);
        }
        let row = member(authenticated_policy_payload, &actor)
            .map_err(|_| ActionScopeError::Source("AUTHOR_NOT_MEMBER"))?;
        if string(field(
            field(field(row, "certificate")?, "payload")?,
            "signing_key",
        )?)? != key
        {
            return Err(ActionScopeError::Source("AUTHOR_NOT_MEMBER"));
        }
        row
    } else {
        let wire = exact_delegation_wire.ok_or(ActionScopeError::Invalid)?;
        if wire.is_empty() || wire.len() > MAX_DELEGATION_BYTES {
            return Err(ActionScopeError::Invalid);
        }
        let signed = parse_wire_json_js_bounded(wire, 64, MAX_DELEGATION_BYTES)
            .map_err(|_| ActionScopeError::Invalid)?;
        if !equal(&signed, delegation)? || signed.object_len() != Some(2) {
            return Err(ActionScopeError::Invalid);
        }
        let d = field(&signed, "payload")?;
        if number(field(d, "v")?)? != 1.0
            || string(field(d, "workspace_id")?)? != workspace
            || field(field(d, "device")?, "payload")?
                .get("actor_id")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(actor.as_str())
            || field(field(d, "device")?, "payload")?
                .get("signing_key")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(key.as_str())
        {
            return Err(ActionScopeError::Source("DELEGATION_INVALID"));
        }
        let start = number(field(d, "issued_at")?)?;
        let end = number(field(d, "expires_at")?)?;
        if at < start || at >= end {
            return Err(ActionScopeError::Source("DELEGATION_INVALID"));
        }
        let principal_actor = string(field(d, "actor_id")?)?;
        let principal_key = string(field(d, "signing_key")?)?;
        let row = member(authenticated_policy_payload, &principal_actor)
            .map_err(|_| ActionScopeError::Source("DELEGATOR_NOT_MEMBER"))?;
        if string(field(
            field(field(row, "certificate")?, "payload")?,
            "signing_key",
        )?)? != principal_key
        {
            return Err(ActionScopeError::Source("DELEGATOR_NOT_MEMBER"));
        }
        if !verify_secure_signed_wire(wire, "peerwork.secure.device-delegation.v1", &principal_key)
            .map_err(|_| ActionScopeError::Invalid)?
        {
            return Err(ActionScopeError::Source("SIGNATURE_INVALID"));
        }
        verify_certificate(field(d, "device")?, at)?;
        let device_scopes = field(d, "scope")?;
        scope_valid(device_scopes).map_err(|_| ActionScopeError::Source("SCOPE_INVALID"))?;
        let delegated_action = list(device_scopes)?.iter().any(|scope| {
            active(scope, at).unwrap_or(false)
                && matches_instance(scope, instance)
                && includes(scope, "actions", action)
        });
        let principal_action = list(field(row, "scopes")?)?.iter().any(|scope| {
            active(scope, at).unwrap_or(false)
                && matches_instance(scope, instance)
                && includes(scope, "actions", action)
        });
        if !delegated_action || !principal_action {
            return Err(ActionScopeError::Source("DELEGATION_SCOPE_DENIED"));
        }
        row
    };
    let principal_actor = string(field(principal, "actor_id")?)?;
    let role = if matches!(delegation, WireValue::Null) {
        string(field(principal, "role")?)?
    } else {
        "MEMBER".into()
    };
    let principal_scopes = list(field(principal, "scopes")?)?;
    let mut scopes = Vec::new();
    for scope in if matches!(delegation, WireValue::Null) {
        principal_scopes
    } else {
        list(field(field(delegation, "payload")?, "scope")?)?
    } {
        if !active(scope, at)? {
            continue;
        }
        let mut effective = scope.clone();
        if !matches!(delegation, WireValue::Null) {
            for key in ["protocol_roles", "capabilities"] {
                let filtered = list(field(scope, key)?)?
                    .iter()
                    .filter(|wanted| {
                        principal_scopes.iter().any(|grant| {
                            active(grant, at).unwrap_or(false)
                                && matches_instance(grant, instance)
                                && includes(grant, key, wanted)
                        })
                    })
                    .cloned()
                    .collect();
                if let WireValue::Object(fields) = &mut effective {
                    if let Some((_, value)) = fields
                        .iter_mut()
                        .find(|(name, _)| name.iter().copied().eq(key.encode_utf16()))
                    {
                        *value = WireValue::Array(filtered);
                    }
                }
            }
        }
        scopes.push(effective);
    }
    Ok(CheckedActionScope {
        actor_id: principal_actor,
        role,
        scopes,
        action_id: action.clone(),
        instance_id: instance.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_typescript_author_scope_vectors() {
        let cases = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/action-delegation-vectors.json"),
            64,
            512 * 1024,
        )
        .unwrap();
        let WireValue::Array(rows) = cases else {
            panic!("vector array")
        };
        for row in rows {
            let name = string(field(&row, "name").unwrap()).unwrap();
            let context = field(&row, "context").unwrap();
            let policy = field(&row, "policy_payload").unwrap();
            let delegation_wire = match field(context, "delegation").unwrap() {
                WireValue::Null => None,
                value => Some(canonical(value).unwrap()),
            };
            let result = resolve_action_scope(
                context,
                policy,
                delegation_wire.as_deref().map(str::as_bytes),
            );
            if let Some(expected) = row.get("result") {
                let result = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(
                    result.actor_id,
                    string(field(expected, "actor_id").unwrap()).unwrap(),
                    "{name}"
                );
                assert_eq!(
                    result.role,
                    string(field(expected, "role").unwrap()).unwrap(),
                    "{name}"
                );
                assert_eq!(
                    canonical(&WireValue::Array(result.scopes.clone())).unwrap(),
                    canonical(field(expected, "scopes").unwrap()).unwrap(),
                    "{name}"
                );
                if name == "valid_delegated" {
                    assert!(result.permits_action());
                    assert!(result.permits_protocol_role(&WireValue::String(
                        "author".encode_utf16().collect()
                    )));
                    assert!(!result.permits_protocol_role(&WireValue::String(
                        "reviewer".encode_utf16().collect()
                    )));
                    assert!(result
                        .permits_capability(&WireValue::String("edit".encode_utf16().collect())));
                    assert!(!result.permits_capability(&WireValue::String(
                        "approve".encode_utf16().collect()
                    )));
                }
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    string(field(&row, "error").unwrap()).unwrap(),
                    "{name}"
                );
            }
        }
    }
}
