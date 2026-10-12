//! Lossless JSON wire parser for JavaScript UTF-16 strings. `serde_json::Value`
//! cannot represent unpaired surrogates accepted by the TypeScript baseline.

use crate::canonical::Path;
use std::{cmp::Ordering, collections::HashSet, str};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum WireValue {
    Null,
    Bool(bool),
    Number(f64),
    String(Vec<u16>),
    Array(Vec<WireValue>),
    Object(Vec<(Vec<u16>, WireValue)>),
}

impl WireValue {
    pub fn get(&self, key: &str) -> Option<&WireValue> {
        let WireValue::Object(fields) = self else {
            return None;
        };
        fields
            .iter()
            .find(|(name, _)| name.iter().copied().eq(key.encode_utf16()))
            .map(|(_, value)| value)
    }
    pub fn object_len(&self) -> Option<usize> {
        if let WireValue::Object(fields) = self {
            Some(fields.len())
        } else {
            None
        }
    }
    pub fn as_string(&self) -> Option<String> {
        if let WireValue::String(units) = self {
            String::from_utf16(units).ok()
        } else {
            None
        }
    }
    pub fn as_utf16(&self) -> Option<&[u16]> {
        if let WireValue::String(units) = self {
            Some(units)
        } else {
            None
        }
    }
    pub fn as_number(&self) -> Option<f64> {
        if let WireValue::Number(number) = self {
            Some(*number)
        } else {
            None
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("invalid JSON or duplicate member")]
    Invalid,
    #[error("invalid canonical value")]
    InvalidValue,
    #[error("unsafe number")]
    UnsafeNumber,
    #[error("canonical resource bound exceeded")]
    BoundExceeded,
}

pub fn parse_wire_json(input: &[u8]) -> Result<WireValue, WireError> {
    parse_wire_json_bounded(input, 2048, 512 * 1024 * 1024)
}

/// Parse with limits selected by the caller's wire format. Secure replay and
/// kernel receipts have different accepted byte limits.
pub fn parse_wire_json_bounded(
    input: &[u8],
    max_depth: usize,
    max_bytes: usize,
) -> Result<WireValue, WireError> {
    parse_wire_json_with_mode(input, max_depth, max_bytes, false)
}

/// Match plain JavaScript `JSON.parse`: duplicate decoded keys replace the
/// earlier value while retaining the key's first insertion position.
pub fn parse_wire_json_js_bounded(
    input: &[u8],
    max_depth: usize,
    max_bytes: usize,
) -> Result<WireValue, WireError> {
    parse_wire_json_with_mode(input, max_depth, max_bytes, true)
}

/// Parse JSON text already held in a JavaScript UTF-16 string. A raw lone
/// surrogate inside a JSON string is accepted by `JSON.parse`; transport
/// through Rust UTF-8 would otherwise reject or replace it.
pub fn parse_js_json_string_bounded(
    input: &[u16],
    max_depth: usize,
    max_bytes: usize,
) -> Result<WireValue, WireError> {
    if input.first() == Some(&0xfeff) {
        return Err(WireError::Invalid);
    }
    let mut utf8 = Vec::new();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < input.len() {
        let unit = input[index];
        if (0xd800..=0xdbff).contains(&unit)
            && input
                .get(index + 1)
                .is_some_and(|next| (0xdc00..=0xdfff).contains(next))
        {
            let high = u32::from(unit) - 0xd800;
            let low = u32::from(input[index + 1]) - 0xdc00;
            let scalar = char::from_u32(0x10000 + high * 0x400 + low).ok_or(WireError::Invalid)?;
            let mut bytes = [0; 4];
            utf8.extend_from_slice(scalar.encode_utf8(&mut bytes).as_bytes());
            index += 2;
        } else if (0xd800..=0xdfff).contains(&unit) {
            if !in_string || escaped {
                return Err(WireError::Invalid);
            }
            utf8.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
            index += 1;
        } else {
            let scalar = char::from_u32(u32::from(unit)).ok_or(WireError::Invalid)?;
            let mut bytes = [0; 4];
            utf8.extend_from_slice(scalar.encode_utf8(&mut bytes).as_bytes());
            if unit == u16::from(b'"') && !escaped {
                in_string = !in_string;
            }
            if in_string && unit == u16::from(b'\\') && !escaped {
                escaped = true;
            } else {
                escaped = false;
            }
            index += 1;
        }
        if utf8.len() > max_bytes {
            return Err(WireError::BoundExceeded);
        }
    }
    parse_wire_json_js_bounded(&utf8, max_depth, max_bytes)
}

#[cfg(test)]
mod js_string_tests {
    use super::*;

    #[test]
    fn decoded_json_string_keeps_raw_lone_surrogate_and_last_duplicate() {
        let mut units: Vec<u16> = "{\"key\":\"".encode_utf16().collect();
        units.push(0xd800);
        let mut only_surrogate = units.clone();
        only_surrogate.extend("\"}".encode_utf16());
        let value = parse_js_json_string_bounded(&only_surrogate, 12, 1024).unwrap();
        assert_eq!(
            canonical_wire_value(&value, Path::SecureArtifact).unwrap(),
            "{\"key\":\"\\ud800\"}"
        );
        units.extend("\",\"\\u006bey\":\"last\"}".encode_utf16());
        let value = parse_js_json_string_bounded(&units, 12, 1024).unwrap();
        assert_eq!(
            canonical_wire_value(&value, Path::SecureArtifact).unwrap(),
            "{\"key\":\"last\"}"
        );
        let invalid: Vec<u16> = "{\"key\":\"\\"
            .encode_utf16()
            .chain([0xd800])
            .chain("\"}".encode_utf16())
            .collect();
        assert_eq!(
            parse_js_json_string_bounded(&invalid, 12, 1024),
            Err(WireError::Invalid)
        );
    }
}

fn parse_wire_json_with_mode(
    input: &[u8],
    max_depth: usize,
    max_bytes: usize,
    js_duplicates: bool,
) -> Result<WireValue, WireError> {
    if input.len() > max_bytes {
        return Err(WireError::BoundExceeded);
    }
    // Both tracked HTTP readers and the secure crypto decoder use fatal UTF-8
    // TextDecoder, whose default BOM handling removes one leading UTF-8 BOM.
    let input = input.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(input);
    str::from_utf8(input).map_err(|_| WireError::Invalid)?;
    let mut parser = Parser {
        input,
        at: 0,
        depth: 0,
        max_depth,
        js_duplicates,
    };
    let value = parser.value()?;
    parser.space();
    if parser.at != input.len() {
        return Err(WireError::Invalid);
    }
    Ok(value)
}

pub fn canonical_wire_json(input: &[u8], path: Path) -> Result<String, WireError> {
    let max_depth = match path {
        Path::Kernel { max_depth } => max_depth,
        Path::SecureArtifact => 2048,
    };
    let max_bytes = match path {
        Path::Kernel { .. } => 32 * 1024 * 1024,
        Path::SecureArtifact => 512 * 1024 * 1024,
    };
    let value = match path {
        Path::SecureArtifact => parse_wire_json_js_bounded(input, max_depth, max_bytes)?,
        Path::Kernel { .. } => parse_wire_json_bounded(input, max_depth, max_bytes)?,
    };
    canonical_wire_value(&value, path)
}

pub fn canonical_wire_value(value: &WireValue, path: Path) -> Result<String, WireError> {
    let mut output = String::new();
    let mut nodes = 0;
    encode(value, path, 0, &mut nodes, &mut output)?;
    Ok(output)
}

struct Parser<'a> {
    input: &'a [u8],
    at: usize,
    depth: usize,
    max_depth: usize,
    js_duplicates: bool,
}
impl Parser<'_> {
    fn space(&mut self) {
        while matches!(self.input.get(self.at), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }
    fn byte(&mut self, expected: u8) -> Result<(), WireError> {
        if self.input.get(self.at) != Some(&expected) {
            return Err(WireError::Invalid);
        }
        self.at += 1;
        Ok(())
    }
    fn value(&mut self) -> Result<WireValue, WireError> {
        self.space();
        if self.depth > self.max_depth {
            return Err(WireError::Invalid);
        }
        match self.input.get(self.at).copied() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(WireValue::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(WireValue::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(WireValue::Bool(false))
            }
            Some(b'"') => Ok(WireValue::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(WireError::Invalid),
        }
    }
    fn literal(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        if self.input.get(self.at..self.at + bytes.len()) != Some(bytes) {
            return Err(WireError::Invalid);
        }
        self.at += bytes.len();
        Ok(())
    }
    fn array(&mut self) -> Result<WireValue, WireError> {
        self.byte(b'[')?;
        self.depth += 1;
        let mut values = Vec::new();
        self.space();
        if self.input.get(self.at) == Some(&b']') {
            self.at += 1;
            self.depth -= 1;
            return Ok(WireValue::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.space();
            match self.input.get(self.at) {
                Some(b',') => {
                    self.at += 1;
                }
                Some(b']') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(WireError::Invalid),
            }
        }
        self.depth -= 1;
        Ok(WireValue::Array(values))
    }
    fn object(&mut self) -> Result<WireValue, WireError> {
        self.byte(b'{')?;
        self.depth += 1;
        let mut fields: Vec<(Vec<u16>, WireValue)> = Vec::new();
        let mut names = HashSet::new();
        self.space();
        if self.input.get(self.at) == Some(&b'}') {
            self.at += 1;
            self.depth -= 1;
            return Ok(WireValue::Object(fields));
        }
        loop {
            if self.input.get(self.at) != Some(&b'"') {
                return Err(WireError::Invalid);
            }
            let key = self.string()?;
            let duplicate = !names.insert(key.clone());
            if duplicate && !self.js_duplicates {
                return Err(WireError::Invalid);
            }
            self.space();
            self.byte(b':')?;
            let value = self.value()?;
            if duplicate {
                let old = fields
                    .iter_mut()
                    .find(|(name, _)| *name == key)
                    .ok_or(WireError::Invalid)?;
                old.1 = value;
            } else {
                fields.push((key, value));
            }
            self.space();
            match self.input.get(self.at) {
                Some(b',') => {
                    self.at += 1;
                    self.space();
                }
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(WireError::Invalid),
            }
        }
        self.depth -= 1;
        Ok(WireValue::Object(fields))
    }
    fn number(&mut self) -> Result<WireValue, WireError> {
        let start = self.at;
        while matches!(
            self.input.get(self.at),
            Some(b'-' | b'+' | b'.' | b'0'..=b'9' | b'e' | b'E')
        ) {
            self.at += 1;
        }
        let text = str::from_utf8(&self.input[start..self.at]).map_err(|_| WireError::Invalid)?;
        let _: serde_json::Number = text.parse().map_err(|_| WireError::Invalid)?;
        let number: f64 = text.parse().map_err(|_| WireError::Invalid)?;
        if !number.is_finite() {
            return Err(WireError::Invalid);
        }
        Ok(WireValue::Number(number))
    }
    fn string(&mut self) -> Result<Vec<u16>, WireError> {
        self.byte(b'"')?;
        let mut units = Vec::new();
        loop {
            let byte = *self.input.get(self.at).ok_or(WireError::Invalid)?;
            if byte == b'"' {
                self.at += 1;
                return Ok(units);
            }
            if byte < 0x20 {
                return Err(WireError::Invalid);
            }
            if byte == b'\\' {
                self.at += 1;
                let escape = *self.input.get(self.at).ok_or(WireError::Invalid)?;
                self.at += 1;
                match escape {
                    b'"' | b'\\' | b'/' => units.push(escape as u16),
                    b'b' => units.push(8),
                    b'f' => units.push(12),
                    b'n' => units.push(10),
                    b'r' => units.push(13),
                    b't' => units.push(9),
                    b'u' => {
                        let hex = self
                            .input
                            .get(self.at..self.at + 4)
                            .ok_or(WireError::Invalid)?;
                        let mut unit = 0u16;
                        for digit in hex {
                            unit =
                                (unit << 4) | hex_digit(*digit).ok_or(WireError::Invalid)? as u16;
                        }
                        units.push(unit);
                        self.at += 4;
                    }
                    _ => return Err(WireError::Invalid),
                }
            } else {
                let rest =
                    str::from_utf8(&self.input[self.at..]).map_err(|_| WireError::Invalid)?;
                let ch = rest.chars().next().ok_or(WireError::Invalid)?;
                units.extend(ch.encode_utf16(&mut [0; 2]).iter().copied());
                self.at += ch.len_utf8();
            }
        }
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode(
    value: &WireValue,
    path: Path,
    depth: usize,
    nodes: &mut usize,
    out: &mut String,
) -> Result<(), WireError> {
    if let Path::Kernel { max_depth } = path {
        *nodes += 1;
        if *nodes > 2048 || depth > max_depth {
            return Err(WireError::BoundExceeded);
        }
    }
    match value {
        WireValue::Null => out.push_str("null"),
        WireValue::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        WireValue::Number(v) => {
            if !v.is_finite() || v.fract() != 0.0 || v.abs() > 9_007_199_254_740_991.0 {
                return Err(WireError::UnsafeNumber);
            }
            if *v == 0.0 {
                out.push('0');
            } else {
                out.push_str(&format!("{v:.0}"));
            }
        }
        WireValue::String(units) => encode_string(units, out),
        WireValue::Array(items) => {
            if matches!(path, Path::Kernel { .. }) && items.len() > 128 {
                return Err(WireError::BoundExceeded);
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, path, depth + 1, nodes, out)?;
            }
            out.push(']');
        }
        WireValue::Object(fields) => {
            let mut sorted: Vec<_> = fields.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| compare_keys(a, b, path));
            out.push('{');
            for (i, (key, value)) in sorted.into_iter().enumerate() {
                if forbidden_key(key) || (key.is_empty() && matches!(path, Path::Kernel { .. })) {
                    return Err(WireError::InvalidValue);
                }
                if i > 0 {
                    out.push(',');
                }
                encode_string(key, out);
                out.push(':');
                encode(value, path, depth + 1, nodes, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn compare_keys(a: &[u16], b: &[u16], path: Path) -> Ordering {
    if matches!(path, Path::Kernel { .. }) {
        match (array_index(a), array_index(b)) {
            (Some(x), Some(y)) => return x.cmp(&y),
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            _ => {}
        }
    }
    a.cmp(b)
}
fn array_index(units: &[u16]) -> Option<u32> {
    let text = String::from_utf16(units).ok()?;
    let number = text.parse::<u32>().ok()?;
    (number != u32::MAX && number.to_string() == text).then_some(number)
}
fn forbidden_key(key: &[u16]) -> bool {
    ["__proto__", "prototype", "constructor"]
        .iter()
        .any(|word| key.iter().copied().eq(word.encode_utf16()))
}
fn encode_string(units: &[u16], out: &mut String) {
    out.push('"');
    let mut at = 0;
    while at < units.len() {
        let unit = units[at];
        match unit {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            0x00..=0x1f => out.push_str(&format!("\\u{unit:04x}")),
            0xd800..=0xdbff
                if at + 1 < units.len() && (0xdc00..=0xdfff).contains(&units[at + 1]) =>
            {
                let scalar =
                    0x10000 + (((unit as u32 - 0xd800) << 10) | (units[at + 1] as u32 - 0xdc00));
                out.push(char::from_u32(scalar).unwrap());
                at += 1;
            }
            0xd800..=0xdfff => out.push_str(&format!("\\u{unit:04x}")),
            _ => out.push(char::from_u32(unit as u32).unwrap()),
        }
        at += 1;
    }
    out.push('"');
}
