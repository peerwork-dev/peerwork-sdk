//! Strict kernel discovery schema parsing. Discovery itself is unsigned: the
//! caller must bind this parsed value to its configured HTTPS origin and
//! persisted continuity pin before using it as a command/receipt authority.

use crate::{
    canonical::Path,
    prepared_command::CommandPins,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use thiserror::Error;

const SEMANTICS: &str = "peerwork.kernel.v1";
const COMMAND_TYPE: &str = "peerwork.kernel-command.v1+jws";
const RECEIPT_TYPE: &str = "peerwork.kernel-receipt.v1+jws";

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("invalid discovery JSON or unsupported schema")]
    Invalid,
}

/// Schema-validated data only. HTTP origin and continuity are runtime facts.
#[derive(Debug, Clone)]
pub struct ParsedDiscovery {
    audience_utf16: Vec<u16>,
    receipt_public_key: String,
    protocol_features: Vec<Vec<u16>>,
    limits: Vec<(Vec<u16>, f64)>,
    manifest_language: Option<Vec<u16>>,
    canonical_context: String,
    raw_wire: Vec<u8>,
}

impl ParsedDiscovery {
    pub fn audience_utf16(&self) -> &[u16] {
        &self.audience_utf16
    }
    pub fn receipt_public_key(&self) -> &str {
        &self.receipt_public_key
    }
    pub fn protocol_features(&self) -> &[Vec<u16>] {
        &self.protocol_features
    }
    pub fn supports_required_features(&self, required: &[Vec<u16>]) -> bool {
        required
            .iter()
            .all(|feature| self.protocol_features.contains(feature))
    }
    /// Match the tracked client's persisted discovery upgrade rule. A changed
    /// context may only add capabilities and newly named limits.
    pub fn permits_update_from(&self, previous: &ParsedDiscovery) -> bool {
        if self.canonical_context == previous.canonical_context {
            return true;
        }
        if self.audience_utf16 != previous.audience_utf16
            || self.receipt_public_key != previous.receipt_public_key
            || self.manifest_language != previous.manifest_language
            || !all_unique(&self.protocol_features)
            || !all_unique(&previous.protocol_features)
            || !previous
                .protocol_features
                .iter()
                .all(|feature| self.protocol_features.contains(feature))
        {
            return false;
        }
        previous.limits.iter().all(|(name, value)| {
            self.limits
                .iter()
                .any(|(next_name, next_value)| next_name == name && next_value == value)
        })
    }
    pub fn canonical_context(&self) -> &str {
        &self.canonical_context
    }
    pub fn raw_wire(&self) -> &[u8] {
        &self.raw_wire
    }
    pub fn command_pins<'a>(&'a self, local_key_id: &'a str) -> CommandPins<'a> {
        CommandPins {
            local_key_id,
            audience_utf16: &self.audience_utf16,
        }
    }
}

/// `max_bytes` is the transport's explicit response cap. The tracked TS
/// discovery endpoint has no path-specific byte cap; callers must record any
/// transport cap as an interoperability limit.
pub fn parse_discovery_wire(
    wire: &[u8],
    max_bytes: usize,
) -> Result<ParsedDiscovery, DiscoveryError> {
    let value = parse_wire_json_bounded(wire, 8, max_bytes).map_err(|_| DiscoveryError::Invalid)?;
    let WireValue::Object(fields) = &value else {
        return Err(DiscoveryError::Invalid);
    };
    let required = [
        "semantics",
        "audience",
        "command_type",
        "receipt_type",
        "receipt_public_key",
        "limits",
    ];
    let optional = ["protocol_features", "manifest_language"];
    if required.iter().any(|field| value.get(field).is_none())
        || fields.iter().any(|(name, _)| {
            !required
                .iter()
                .chain(optional.iter())
                .any(|allowed| name.iter().copied().eq(allowed.encode_utf16()))
        })
        || value
            .get("semantics")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(SEMANTICS)
        || value
            .get("command_type")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(COMMAND_TYPE)
        || value
            .get("receipt_type")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(RECEIPT_TYPE)
    {
        return Err(DiscoveryError::Invalid);
    }
    let audience = utf16(&value, "audience")?;
    if audience.is_empty() || audience.len() > 200 {
        return Err(DiscoveryError::Invalid);
    }
    let receipt_public_key = value
        .get("receipt_public_key")
        .and_then(WireValue::as_string)
        .ok_or(DiscoveryError::Invalid)?;
    if !token(&receipt_public_key) {
        return Err(DiscoveryError::Invalid);
    }
    let WireValue::Object(limits) = value.get("limits").ok_or(DiscoveryError::Invalid)? else {
        return Err(DiscoveryError::Invalid);
    };
    let limits = limits
        .iter()
        .map(|(name, number)| {
            number
                .as_number()
                .map(|number| (name.clone(), number))
                .ok_or(DiscoveryError::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let protocol_features = match value.get("protocol_features") {
        None => Vec::new(),
        Some(WireValue::Array(features)) if features.len() <= 32 => {
            let mut output = Vec::with_capacity(features.len());
            for feature in features {
                let units = feature.as_utf16().ok_or(DiscoveryError::Invalid)?;
                if units.is_empty() || units.len() > 80 {
                    return Err(DiscoveryError::Invalid);
                }
                output.push(units.to_vec());
            }
            output
        }
        _ => return Err(DiscoveryError::Invalid),
    };
    let manifest_language = match value.get("manifest_language") {
        None => None,
        Some(language) => {
            let units = language.as_utf16().ok_or(DiscoveryError::Invalid)?;
            if units.is_empty() || units.len() > 80 {
                return Err(DiscoveryError::Invalid);
            }
            Some(units.to_vec())
        }
    };
    let canonical_context =
        canonical_wire_value(&value, Path::KERNEL).map_err(|_| DiscoveryError::Invalid)?;
    Ok(ParsedDiscovery {
        audience_utf16: audience.to_vec(),
        receipt_public_key,
        protocol_features,
        limits,
        manifest_language,
        canonical_context,
        raw_wire: wire.to_vec(),
    })
}

fn all_unique(values: &[Vec<u16>]) -> bool {
    let mut unique = std::collections::HashSet::new();
    values.iter().all(|value| unique.insert(value))
}

fn utf16<'a>(value: &'a WireValue, field: &str) -> Result<&'a [u16], DiscoveryError> {
    value
        .get(field)
        .and_then(WireValue::as_utf16)
        .ok_or(DiscoveryError::Invalid)
}

fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
