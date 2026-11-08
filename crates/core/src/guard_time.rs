//! Native private guard-time wire and deterministic window primitives.
//! Preparation and replay callers must still authenticate their source state,
//! policy and proof before using these results.

use crate::{
    canonical::Path,
    crypto::verify_secure_signed_wire,
    interpreter::{resolve_guard_time_operand, validate_manifest, InterpreterAuth, ResolvedInput},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};

pub const GUARD_TIME_ATTESTATION_DOMAIN: &str = "peerwork.secure.guard-time-attestation.v1";
pub const GUARD_TIME_ATTESTATION_MAX_BYTES: usize = 8192;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardTimePolicyV1 {
    pub audience: String,
    pub service_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardTimeContextV1 {
    pub lower_ms: u64,
    pub upper_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardTimeError {
    Invalid,
    Unsupported,
    Empty,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuardTimeAttestationV1 {
    /// Lossless canonical payload. Its exact typed claims are validated by
    /// `verify_guard_time_attestation` against the caller's chain-derived value.
    pub payload: WireValue,
    pub signature: String,
}

impl GuardTimeContextV1 {
    pub const fn universal() -> Self {
        Self {
            lower_ms: 0,
            upper_ms: MAX_SAFE_INTEGER,
        }
    }

    pub fn to_wire(self) -> WireValue {
        object(vec![
            ("v", WireValue::Number(1.0)),
            ("lower_ms", WireValue::Number(self.lower_ms as f64)),
            ("upper_ms", WireValue::Number(self.upper_ms as f64)),
        ])
    }
}

pub fn parse_guard_time_policy(value: &WireValue) -> Result<GuardTimePolicyV1, GuardTimeError> {
    exact(
        value,
        &["v", "mode", "audience", "service_key", "disclosure"],
    )?;
    if number(value, "v")? != 1
        || text(value, "mode")? != "ALL_COMMITS"
        || text(value, "disclosure")? != "GUARD_WINDOW"
    {
        return Err(GuardTimeError::Invalid);
    }
    let audience = value
        .get("audience")
        .and_then(WireValue::as_string)
        .ok_or(GuardTimeError::Invalid)?;
    let service_key = text(value, "service_key")?;
    if audience.is_empty() || !token(&service_key) {
        return Err(GuardTimeError::Invalid);
    }
    Ok(GuardTimePolicyV1 {
        audience,
        service_key,
    })
}

/// A time-independent ADMIN producer must bind this context before AEAD and
/// signature creation. This validates the authenticated policy; it never adds
/// authority or changes invitation/certificate expiry constraints.
pub fn administrative_guard_context(policy_payload: &WireValue) -> Result<Option<WireValue>, GuardTimeError> {
    policy_payload.get("guard_time").map(|policy| {
        parse_guard_time_policy(policy)?;
        Ok(GuardTimeContextV1::universal().to_wire())
    }).transpose()
}

pub fn parse_guard_time_context(value: &WireValue) -> Result<GuardTimeContextV1, GuardTimeError> {
    exact(value, &["v", "lower_ms", "upper_ms"])?;
    if number(value, "v")? != 1 {
        return Err(GuardTimeError::Invalid);
    }
    let lower_ms = integer(value, "lower_ms")?;
    let upper_ms = integer(value, "upper_ms")?;
    if lower_ms > upper_ms {
        return Err(GuardTimeError::Invalid);
    }
    Ok(GuardTimeContextV1 { lower_ms, upper_ms })
}

/// Verify a pinned service signature and require the entire attestation
/// payload to equal the caller's chain-derived expected payload byte-for-byte
/// after canonical wire normalization.
pub fn verify_guard_time_attestation(
    wire: &[u8],
    policy: &GuardTimePolicyV1,
    expected_payload: &WireValue,
) -> Result<GuardTimeAttestationV1, GuardTimeError> {
    if wire.len() > GUARD_TIME_ATTESTATION_MAX_BYTES {
        return Err(GuardTimeError::Invalid);
    }
    let envelope = parse_wire_json_bounded(wire, 32, GUARD_TIME_ATTESTATION_MAX_BYTES)
        .map_err(|_| GuardTimeError::Invalid)?;
    exact(&envelope, &["payload", "signature"])?;
    let payload = envelope.get("payload").ok_or(GuardTimeError::Invalid)?;
    exact(
        payload,
        &[
            "v",
            "audience",
            "service_key",
            "workspace_id",
            "command_id",
            "actor_id",
            "signing_key",
            "action_id",
            "instance_id",
            "epoch",
            "policy_hash",
            "source",
            "result",
            "commit_hash",
            "context",
            "admitted_at_ms",
        ],
    )?;
    if number(payload, "v")? != 1
        || text(payload, "audience")? != policy.audience
        || text(payload, "service_key")? != policy.service_key
        || !token(&text(payload, "workspace_id")?)
        || !token(&text(payload, "command_id")?)
        || !token(&text(payload, "actor_id")?)
        || !token(&text(payload, "signing_key")?)
        || text(payload, "action_id")?.is_empty()
        || text(payload, "action_id")?.encode_utf16().count() > 120
        || !digest(&text(payload, "policy_hash")?)
        || !digest(&text(payload, "commit_hash")?)
    {
        return Err(GuardTimeError::Invalid);
    }
    let instance = payload.get("instance_id").ok_or(GuardTimeError::Invalid)?;
    if !matches!(instance, WireValue::Null)
        && !instance.as_string().is_some_and(|value| token(&value))
    {
        return Err(GuardTimeError::Invalid);
    }
    let epoch = integer(payload, "epoch")?;
    let admitted_at = integer(payload, "admitted_at_ms")?;
    let context = parse_guard_time_context(payload.get("context").ok_or(GuardTimeError::Invalid)?)?;
    validate_checkpoint(payload.get("source").ok_or(GuardTimeError::Invalid)?)?;
    validate_checkpoint(payload.get("result").ok_or(GuardTimeError::Invalid)?)?;
    if admitted_at < context.lower_ms || admitted_at > context.upper_ms || epoch > MAX_SAFE_INTEGER
    {
        return Err(GuardTimeError::Invalid);
    }
    let canonical_expected = canonical_wire_value(expected_payload, Path::SecureArtifact)
        .map_err(|_| GuardTimeError::Invalid)?;
    let canonical_actual =
        canonical_wire_value(payload, Path::SecureArtifact).map_err(|_| GuardTimeError::Invalid)?;
    if canonical_expected != canonical_actual {
        return Err(GuardTimeError::Invalid);
    }
    let signature = text(&envelope, "signature")?;
    if signature.len() != 86
        || !signature
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || !verify_secure_signed_wire(wire, GUARD_TIME_ATTESTATION_DOMAIN, &policy.service_key)
            .map_err(|_| GuardTimeError::Invalid)?
    {
        return Err(GuardTimeError::Invalid);
    }
    Ok(GuardTimeAttestationV1 {
        payload: payload.clone(),
        signature,
    })
}

fn validate_checkpoint(value: &WireValue) -> Result<(), GuardTimeError> {
    exact(
        value,
        &[
            "v",
            "workspace_id",
            "owner_id",
            "owner_key",
            "sequence",
            "head",
            "policy_hash",
        ],
    )?;
    if number(value, "v")? != 1
        || !token(&text(value, "workspace_id")?)
        || !token(&text(value, "owner_id")?)
        || !token(&text(value, "owner_key")?)
        || !digest(&text(value, "policy_hash")?)
    {
        return Err(GuardTimeError::Invalid);
    }
    integer(value, "sequence")?;
    match value.get("head").ok_or(GuardTimeError::Invalid)? {
        WireValue::Null => Ok(()),
        WireValue::String(_) if digest(&text(value, "head")?) => Ok(()),
        _ => Err(GuardTimeError::Invalid),
    }
}

/// Derive the only guard-time interval supported by v1. Time-free selector
/// operands are resolved with the existing interpreter's selector semantics.
pub(crate) fn derive_private_guard_time_window(
    manifest: &WireValue,
    action_id: &[u16],
    state: &WireValue,
    body: &WireValue,
    auth: &InterpreterAuth,
    exact_inputs: &[ResolvedInput],
) -> Result<GuardTimeContextV1, GuardTimeError> {
    validate_manifest(manifest).map_err(|_| GuardTimeError::Invalid)?;
    let actions = array(manifest.get("actions").ok_or(GuardTimeError::Invalid)?)?;
    let action = actions
        .iter()
        .find(|item| item.get("id").and_then(WireValue::as_utf16) == Some(action_id))
        .ok_or(GuardTimeError::Invalid)?;
    let variants = array(action.get("variants").ok_or(GuardTimeError::Invalid)?)?;
    let timed = variants.iter().any(|variant| {
        array_or_empty(variant.get("when"))
            .iter()
            .any(guard_has_time)
            || array_or_empty(variant.get("effects"))
                .iter()
                .any(effect_has_time)
    });
    if !timed {
        return Ok(GuardTimeContextV1::universal());
    }
    if variants.len() != 1 {
        return Err(GuardTimeError::Unsupported);
    }
    if array_or_empty(variants[0].get("effects"))
        .iter()
        .any(effect_has_time)
    {
        return Err(GuardTimeError::Unsupported);
    }
    let mut window = GuardTimeContextV1::universal();
    for guard in array(variants[0].get("when").ok_or(GuardTimeError::Invalid)?)? {
        apply_guard(
            guard,
            manifest,
            action_id,
            state,
            body,
            auth,
            exact_inputs,
            &mut window,
        )?;
    }
    if window.lower_ms > window.upper_ms {
        return Err(GuardTimeError::Empty);
    }
    Ok(window)
}

fn apply_guard(
    guard: &WireValue,
    manifest: &WireValue,
    action_id: &[u16],
    state: &WireValue,
    body: &WireValue,
    auth: &InterpreterAuth,
    exact_inputs: &[ResolvedInput],
    window: &mut GuardTimeContextV1,
) -> Result<(), GuardTimeError> {
    let op = text(guard, "op")?;
    match op.as_str() {
        "and" => {
            for child in array(guard.get("rules").ok_or(GuardTimeError::Invalid)?)? {
                apply_guard(
                    child,
                    manifest,
                    action_id,
                    state,
                    body,
                    auth,
                    exact_inputs,
                    window,
                )?;
            }
            return Ok(());
        }
        "or" | "not" => {
            if guard_has_time(guard) {
                return Err(GuardTimeError::Unsupported);
            }
            return Ok(());
        }
        "lt" | "lte" | "gt" | "gte" | "eq" => {}
        _ => {
            if guard_has_time(guard) {
                return Err(GuardTimeError::Unsupported);
            }
            return Ok(());
        }
    }
    let left = guard.get("left").ok_or(GuardTimeError::Invalid)?;
    let right = guard.get("right").ok_or(GuardTimeError::Invalid)?;
    let left_time = selector_has_time(left);
    let right_time = selector_has_time(right);
    if !left_time && !right_time {
        return Ok(());
    }
    if op == "eq" || left_time == right_time {
        return Err(GuardTimeError::Unsupported);
    }
    let (time, other, time_on_left) = if left_time {
        (left, right, true)
    } else {
        (right, left, false)
    };
    if selector_has_time(other) {
        return Err(GuardTimeError::Unsupported);
    }
    let offset = time_offset(time, manifest, action_id, state, body, auth, exact_inputs)?;
    window.upper_ms = window.upper_ms.min(MAX_SAFE_INTEGER - offset);
    let resolved =
        resolve_guard_time_operand(manifest, action_id, state, body, auth, exact_inputs, other)
            .map_err(|_| GuardTimeError::Invalid)?;
    let bound = i128::from(safe_integer_value(&resolved)?) - i128::from(offset);
    let normalized = if time_on_left {
        op.as_str()
    } else {
        reverse_comparison(&op)
    };
    intersect(window, normalized, bound)?;
    Ok(())
}

fn time_offset(
    value: &WireValue,
    manifest: &WireValue,
    action_id: &[u16],
    state: &WireValue,
    body: &WireValue,
    auth: &InterpreterAuth,
    inputs: &[ResolvedInput],
) -> Result<u64, GuardTimeError> {
    if is_direct_time(value) {
        return Ok(0);
    }
    if text(value, "from")? != "time_add" {
        return Err(GuardTimeError::Unsupported);
    }
    let timestamp = value.get("timestamp").ok_or(GuardTimeError::Invalid)?;
    let milliseconds = value.get("milliseconds").ok_or(GuardTimeError::Invalid)?;
    if !selector_has_time(timestamp) || selector_has_time(milliseconds) {
        return Err(GuardTimeError::Unsupported);
    }
    let resolved =
        resolve_guard_time_operand(manifest, action_id, state, body, auth, inputs, milliseconds)
            .map_err(|_| GuardTimeError::Invalid)?;
    let duration = safe_integer_value(&resolved)?;
    if duration < 0 {
        return Err(GuardTimeError::Unsupported);
    }
    let offset = time_offset(timestamp, manifest, action_id, state, body, auth, inputs)?
        .checked_add(duration as u64)
        .ok_or(GuardTimeError::Empty)?;
    if offset > MAX_SAFE_INTEGER {
        return Err(GuardTimeError::Empty);
    }
    Ok(offset)
}
fn intersect(window: &mut GuardTimeContextV1, op: &str, bound: i128) -> Result<(), GuardTimeError> {
    let mut lower = i128::from(window.lower_ms);
    let mut upper = i128::from(window.upper_ms);
    match op {
        "lt" => upper = upper.min(bound - 1),
        "lte" => upper = upper.min(bound),
        "gt" => lower = lower.max(bound + 1),
        "gte" => lower = lower.max(bound),
        _ => return Err(GuardTimeError::Unsupported),
    }
    if lower > upper {
        return Err(GuardTimeError::Empty);
    }
    window.lower_ms = lower as u64;
    window.upper_ms = upper as u64;
    Ok(())
}

fn reverse_comparison(op: &str) -> &'static str {
    match op {
        "lt" => "gt",
        "lte" => "gte",
        "gt" => "lt",
        "gte" => "lte",
        _ => "eq",
    }
}

fn is_direct_time(value: &WireValue) -> bool {
    value.object_len() == Some(1)
        && value.get("from").and_then(WireValue::as_string).as_deref() == Some("time")
}

fn selector_has_time(value: &WireValue) -> bool {
    match value.get("from").and_then(WireValue::as_string).as_deref() {
        Some("time") => true,
        Some("time_add") => {
            value.get("timestamp").is_some_and(selector_has_time)
                || value.get("milliseconds").is_some_and(selector_has_time)
        }
        Some("object") => value
            .get("fields")
            .and_then(|v| {
                if let WireValue::Object(items) = v {
                    Some(items)
                } else {
                    None
                }
            })
            .is_some_and(|items| items.iter().any(|(_, v)| selector_has_time(v))),
        Some("array") => array_or_empty(value.get("items"))
            .iter()
            .any(selector_has_time),
        _ => false,
    }
}

fn guard_has_time(guard: &WireValue) -> bool {
    match guard.get("op").and_then(WireValue::as_string).as_deref() {
        Some("and" | "or") => array_or_empty(guard.get("rules"))
            .iter()
            .any(guard_has_time),
        Some("not") => guard.get("rule").is_some_and(guard_has_time),
        Some("lt" | "lte" | "gt" | "gte" | "eq") => {
            guard.get("left").is_some_and(selector_has_time)
                || guard.get("right").is_some_and(selector_has_time)
        }
        Some("in") => {
            guard.get("value").is_some_and(selector_has_time)
                || array_or_empty(guard.get("set"))
                    .iter()
                    .any(selector_has_time)
        }
        _ => false,
    }
}

fn effect_has_time(effect: &WireValue) -> bool {
    [
        "value",
        "expected",
        "target",
        "expected_max",
        "expected_head",
    ]
    .iter()
    .any(|k| effect.get(k).is_some_and(selector_has_time))
        || array_or_empty(effect.get("relations"))
            .iter()
            .any(|r| r.get("target").is_some_and(selector_has_time))
        || effect
            .get("entity")
            .is_some_and(|e| e.get("parent").is_some_and(selector_has_time))
}

fn safe_integer_value(value: &WireValue) -> Result<i64, GuardTimeError> {
    let number = value.as_number().ok_or(GuardTimeError::Unsupported)?;
    if !number.is_finite()
        || number.fract() != 0.0
        || number < -(MAX_SAFE_INTEGER as f64)
        || number > MAX_SAFE_INTEGER as f64
    {
        return Err(GuardTimeError::Unsupported);
    }
    Ok(number as i64)
}

fn exact(value: &WireValue, expected: &[&str]) -> Result<(), GuardTimeError> {
    let WireValue::Object(fields) = value else {
        return Err(GuardTimeError::Invalid);
    };
    if fields.len() != expected.len()
        || fields.iter().any(|(key, _)| {
            !expected
                .iter()
                .any(|name| key.iter().copied().eq(name.encode_utf16()))
        })
    {
        return Err(GuardTimeError::Invalid);
    }
    Ok(())
}
fn array(value: &WireValue) -> Result<&[WireValue], GuardTimeError> {
    if let WireValue::Array(items) = value {
        Ok(items)
    } else {
        Err(GuardTimeError::Invalid)
    }
}
fn array_or_empty(value: Option<&WireValue>) -> &[WireValue] {
    match value {
        Some(WireValue::Array(items)) => items,
        _ => &[],
    }
}
fn text(value: &WireValue, key: &str) -> Result<String, GuardTimeError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(GuardTimeError::Invalid)
}
fn number(value: &WireValue, key: &str) -> Result<u64, GuardTimeError> {
    let n = value
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(GuardTimeError::Invalid)?;
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > MAX_SAFE_INTEGER as f64 {
        Err(GuardTimeError::Invalid)
    } else {
        Ok(n as u64)
    }
}
fn integer(value: &WireValue, key: &str) -> Result<u64, GuardTimeError> {
    number(value, key)
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.encode_utf16().collect(), v))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{key_id, sign_canonical},
        interpreter::InterpreterAuth,
        wire_json::parse_wire_json_bounded,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn wire(value: serde_json::Value) -> WireValue {
        parse_wire_json_bounded(&serde_json::to_vec(&value).unwrap(), 64, 32 * 1024).unwrap()
    }
    fn manifest(guard: serde_json::Value) -> WireValue {
        wire(
            json!({"actions":[{"id":"test.action","reads":[],"writes":[],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[guard],"effects":[]}]}]}),
        )
    }
    fn auth() -> InterpreterAuth {
        InterpreterAuth {
            actor_id: "A".repeat(43),
            workspace_roles: vec![],
            protocol_roles: vec![],
            capabilities: vec![],
        }
    }
    fn derive(manifest: &WireValue) -> Result<GuardTimeContextV1, GuardTimeError> {
        derive_private_guard_time_window(
            manifest,
            &"test.action".encode_utf16().collect::<Vec<_>>(),
            &wire(json!({})),
            &wire(json!({})),
            &auth(),
            &[],
        )
    }

    #[test]
    fn derives_direct_and_swapped_integer_bounds_and_rejects_unsupported_time_uses() {
        let direct = manifest(json!({"op":"and","rules":[
            {"op":"gte","left":{"from":"time"},"right":{"from":"literal","value":4}},
            {"op":"lt","left":{"from":"time"},"right":{"from":"literal","value":9}}
        ]}));
        assert_eq!(
            derive(&direct),
            Ok(GuardTimeContextV1 {
                lower_ms: 4,
                upper_ms: 8
            })
        );
        let swapped = manifest(
            json!({"op":"gte","left":{"from":"literal","value":8},"right":{"from":"time"}}),
        );
        assert_eq!(
            derive(&swapped),
            Ok(GuardTimeContextV1 {
                lower_ms: 0,
                upper_ms: 8
            })
        );
        let empty = manifest(
            json!({"op":"lt","left":{"from":"time"},"right":{"from":"literal","value":0}}),
        );
        assert_eq!(derive(&empty), Err(GuardTimeError::Empty));
        let negative_lower = manifest(
            json!({"op":"gte","left":{"from":"time"},"right":{"from":"literal","value":-9}}),
        );
        assert_eq!(derive(&negative_lower), Ok(GuardTimeContextV1::universal()));
        let negative_swapped = manifest(
            json!({"op":"lt","left":{"from":"literal","value":-1},"right":{"from":"time"}}),
        );
        assert_eq!(
            derive(&negative_swapped),
            Ok(GuardTimeContextV1::universal())
        );
        let negative_empty = manifest(
            json!({"op":"lte","left":{"from":"time"},"right":{"from":"literal","value":-1}}),
        );
        assert_eq!(derive(&negative_empty), Err(GuardTimeError::Empty));
        let max_only = manifest(
            json!({"op":"gte","left":{"from":"time"},"right":{"from":"literal","value":9007199254740991u64}}),
        );
        assert_eq!(
            derive(&max_only),
            Ok(GuardTimeContextV1 {
                lower_ms: MAX_SAFE_INTEGER,
                upper_ms: MAX_SAFE_INTEGER
            })
        );
        let beyond_max = manifest(
            json!({"op":"gt","left":{"from":"time"},"right":{"from":"literal","value":9007199254740991u64}}),
        );
        assert_eq!(derive(&beyond_max), Err(GuardTimeError::Empty));
        let disjunction = manifest(
            json!({"op":"or","rules":[{"op":"gt","left":{"from":"time"},"right":{"from":"literal","value":0}}]}),
        );
        assert_eq!(derive(&disjunction), Err(GuardTimeError::Unsupported));
        let time_add = manifest(
            json!({"op":"gt","left":{"from":"time_add","timestamp":{"from":"time"},"milliseconds":{"from":"literal","value":1}},"right":{"from":"literal","value":0}}),
        );
        assert_eq!(
            derive(&time_add),
            Ok(GuardTimeContextV1 {
                lower_ms: 0,
                upper_ms: MAX_SAFE_INTEGER - 1
            })
        );
    }

    #[test]
    fn verifies_pinned_attestation_signature_and_exact_chain_payload() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let service_key = key_id(&key.verifying_key().to_bytes());
        let context = json!({"v":1,"lower_ms":10,"upper_ms":20});
        let source = json!({"v":1,"workspace_id":"W".repeat(43),"owner_id":"O".repeat(43),"owner_key":"K".repeat(43),"sequence":1,"head":"a".repeat(64),"policy_hash":"b".repeat(64)});
        let result = json!({"v":1,"workspace_id":"W".repeat(43),"owner_id":"O".repeat(43),"owner_key":"K".repeat(43),"sequence":2,"head":"c".repeat(64),"policy_hash":"d".repeat(64)});
        let payload = json!({
            "v":1,"audience":"private.example","service_key":service_key,"workspace_id":"W".repeat(43),
            "command_id":"C".repeat(43),"actor_id":"O".repeat(43),"signing_key":"K".repeat(43),
            "action_id":"secure.action","instance_id":null,"epoch":1,"policy_hash":"d".repeat(64),
            "source":source,"result":result,"commit_hash":"c".repeat(64),"context":context,"admitted_at_ms":15
        });
        let signature = sign_canonical(GUARD_TIME_ATTESTATION_DOMAIN, &payload, &key).unwrap();
        let bytes = serde_json::to_vec(&json!({"payload":payload,"signature":signature})).unwrap();
        let parsed = wire(serde_json::from_slice(&bytes).unwrap());
        let expected = parsed.get("payload").unwrap().clone();
        let policy = GuardTimePolicyV1 {
            audience: "private.example".into(),
            service_key,
        };
        let proof = verify_guard_time_attestation(&bytes, &policy, &expected).unwrap();
        assert_eq!(proof.payload, expected);
        let wrong_expected = wire(json!({"v":1,"audience":"private.example"}));
        assert_eq!(
            verify_guard_time_attestation(&bytes, &policy, &wrong_expected),
            Err(GuardTimeError::Invalid)
        );
    }

    #[test]
    fn accepts_shared_typescript_service_attestation_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/guard-time-attestation-vector.json"
        ))
        .unwrap();
        assert_eq!(vector["schema"], "peerwork.guard-time-rust-vector.v1");
        let payload = wire(vector["payload"].clone());
        let policy =
            parse_guard_time_policy(&wire(vector["policy"]["payload"]["guard_time"].clone()))
                .unwrap();
        let proof = serde_json::json!({
            "payload": vector["payload"],
            "signature": vector["signature"]
        });
        let proof_wire = serde_json::to_vec(&proof).unwrap();
        let verified = verify_guard_time_attestation(&proof_wire, &policy, &payload).unwrap();
        assert_eq!(verified.payload, payload);

        let mut changed = vector["payload"].clone();
        changed["admitted_at_ms"] = serde_json::json!(1001);
        assert_eq!(
            verify_guard_time_attestation(&proof_wire, &policy, &wire(changed),),
            Err(GuardTimeError::Invalid)
        );
    }

    #[test]
    fn astra_independent_ts_guard_time_matrix_and_limits() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/guard-time-astra-vectors.json"
        ))
        .unwrap();
        assert_eq!(fixture["matrixComparisons"], 288);
        assert_eq!(fixture["boundary"]["nodes"], 8192);
        let mut compared = 0;
        for vector in fixture["vectors"].as_array().unwrap() {
            let name = vector["name"].as_str().unwrap();
            let manifest = parse_wire_json_bounded(
                &serde_json::to_vec(&vector["manifest"]).unwrap(),
                64,
                1024 * 1024,
            )
            .unwrap();
            crate::interpreter::validate_manifest(&manifest).unwrap();
            let action = "t".encode_utf16().collect::<Vec<_>>();
            let empty = wire(json!({}));
            let actual =
                derive_private_guard_time_window(&manifest, &action, &empty, &empty, &auth(), &[]);
            if vector["window"].is_null() {
                assert_eq!(actual, Err(GuardTimeError::Empty), "{name}");
            } else {
                assert_eq!(
                    actual,
                    Ok(GuardTimeContextV1 {
                        lower_ms: vector["window"]["lower_ms"].as_u64().unwrap(),
                        upper_ms: vector["window"]["upper_ms"].as_u64().unwrap(),
                    }),
                    "{name}"
                );
            }
            if name.contains(':') {
                for time in [0, 1, 6, 7, 8, MAX_SAFE_INTEGER] {
                    let accepted = crate::interpreter::evaluate_action(
                        &manifest,
                        &action,
                        &empty,
                        &empty,
                        &auth(),
                        &[],
                        Some(time),
                    )
                    .is_ok();
                    let inside = actual
                        .as_ref()
                        .is_ok_and(|window| time >= window.lower_ms && time <= window.upper_ms);
                    assert_eq!(inside, accepted, "{name} at {time}");
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 288);
    }
    #[test]
    fn time_add_bounded_lease_cross_language_vectors() {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/guard-time-add-vectors.json"
        ))
        .unwrap();
        assert_eq!(fixture["profile"], "time-add-guard-window-v1");
        for case in fixture["cases"].as_array().unwrap() {
            let manifest = wire(case["manifest"].clone());
            let state = wire(case["state"].clone());
            let body = wire(case["body"].clone());
            let action = case["action_id"]
                .as_str()
                .unwrap()
                .encode_utf16()
                .collect::<Vec<_>>();
            let derived =
                derive_private_guard_time_window(&manifest, &action, &state, &body, &auth(), &[]);
            if let Some(error) = case["error"].as_str() {
                assert_eq!(
                    derived.unwrap_err(),
                    match error {
                        "CONSTRAINT_FAILED" => GuardTimeError::Empty,
                        "PRIVATE_GUARD_TIME_UNSUPPORTED" => GuardTimeError::Unsupported,
                        _ => panic!("unknown fixture error"),
                    },
                    "{}",
                    case["name"]
                );
                continue;
            }
            let actual = derived.unwrap();
            assert_eq!(
                (actual.lower_ms, actual.upper_ms),
                (
                    case["window"]["lower_ms"].as_u64().unwrap(),
                    case["window"]["upper_ms"].as_u64().unwrap()
                ),
                "{}",
                case["name"]
            );
            for time in [actual.lower_ms, actual.upper_ms] {
                assert!(
                    crate::interpreter::evaluate_action(
                        &manifest,
                        &action,
                        &state,
                        &body,
                        &auth(),
                        &[],
                        Some(time)
                    )
                    .is_ok(),
                    "{} at {}",
                    case["name"],
                    time
                );
            }
            if actual.lower_ms > 0 {
                assert!(
                    crate::interpreter::evaluate_action(
                        &manifest,
                        &action,
                        &state,
                        &body,
                        &auth(),
                        &[],
                        Some(actual.lower_ms - 1)
                    )
                    .is_err(),
                    "{} below",
                    case["name"]
                );
            }
            if actual.upper_ms < MAX_SAFE_INTEGER {
                assert!(
                    crate::interpreter::evaluate_action(
                        &manifest,
                        &action,
                        &state,
                        &body,
                        &auth(),
                        &[],
                        Some(actual.upper_ms + 1)
                    )
                    .is_err(),
                    "{} above",
                    case["name"]
                );
            }
        }
    }
}
