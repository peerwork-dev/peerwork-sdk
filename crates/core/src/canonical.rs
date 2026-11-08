//! Byte-compatible canonical JSON for the two accepted TypeScript paths.

use serde_json::Value;
use thiserror::Error;

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("invalid JSON value")]
    InvalidValue,
    #[error("unsafe number")]
    UnsafeNumber,
    #[error("resource bound exceeded")]
    BoundExceeded,
}

#[derive(Clone, Copy)]
pub enum Path {
    SecureArtifact,
    Kernel { max_depth: usize },
    /// Bounded program structure; action/state data keep the Kernel budget.
    Structure { max_depth: usize },
}

impl Path {
    pub(crate) fn kernel_bounds(self) -> Option<(usize, usize)> {
        match self {
            Self::Kernel { max_depth } => Some((max_depth, 2048)),
            Self::Structure { max_depth } => Some((max_depth, 8192)),
            Self::SecureArtifact => None,
        }
    }
    pub const KERNEL: Self = Self::Kernel { max_depth: 12 };
    pub const COMMAND: Self = Self::Kernel { max_depth: 40 };
    pub const STRUCTURED: Self = Self::Structure { max_depth: 32 };
    pub const RESPONSE: Self = Self::Kernel { max_depth: 13 };
}

/// Canonicalize a parsed JSON value. Callers handling untrusted wire text must
/// reject duplicate object keys before constructing `Value`.
pub fn canonical(value: &Value, path: Path) -> Result<String, CanonicalError> {
    let mut out = String::new();
    let mut nodes = 0;
    write_value(value, path, 0, &mut nodes, &mut out)?;
    Ok(out)
}

fn write_value(
    value: &Value,
    path: Path,
    depth: usize,
    nodes: &mut usize,
    out: &mut String,
) -> Result<(), CanonicalError> {
    if let Some((max_depth, max_nodes)) = path.kernel_bounds() {
        *nodes += 1;
        if *nodes > max_nodes || depth > max_depth {
            return Err(CanonicalError::BoundExceeded);
        }
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::String(v) => {
            out.push_str(&serde_json::to_string(v).map_err(|_| CanonicalError::InvalidValue)?)
        }
        Value::Number(v) => {
            if let Some(i) = v.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                    return Err(CanonicalError::UnsafeNumber);
                }
            }
            if let Some(i) = v.as_u64() {
                if i > MAX_SAFE_INTEGER as u64 {
                    return Err(CanonicalError::UnsafeNumber);
                }
            }
            let number = v.as_f64().ok_or(CanonicalError::UnsafeNumber)?;
            if !number.is_finite() || number.abs() > MAX_SAFE_INTEGER || number.fract() != 0.0 {
                return Err(CanonicalError::UnsafeNumber);
            }
            if number == 0.0 {
                out.push('0');
            } else {
                out.push_str(&format!("{number:.0}"));
            }
        }
        Value::Array(items) => {
            if path.kernel_bounds().is_some() && items.len() > 128 {
                return Err(CanonicalError::BoundExceeded);
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write_value(item, path, depth + 1, nodes, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                if path.kernel_bounds().is_some() {
                    // `normalized` inserts sorted keys into a JS object. JSON.stringify
                    // subsequently enumerates canonical array-index keys first.
                    match (array_index(a), array_index(b)) {
                        (Some(x), Some(y)) => return x.cmp(&y),
                        (Some(_), None) => return std::cmp::Ordering::Less,
                        (None, Some(_)) => return std::cmp::Ordering::Greater,
                        _ => {}
                    }
                }
                a.encode_utf16().cmp(b.encode_utf16())
            });
            for (index, key) in keys.iter().enumerate() {
                if key.is_empty() && path.kernel_bounds().is_some()
                    || matches!(key.as_str(), "__proto__" | "prototype" | "constructor")
                {
                    return Err(CanonicalError::InvalidValue);
                }
                if index != 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key).map_err(|_| CanonicalError::InvalidValue)?,
                );
                out.push(':');
                write_value(&map[*key], path, depth + 1, nodes, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn array_index(key: &str) -> Option<u32> {
    let index = key.parse::<u32>().ok()?;
    if index == u32::MAX || index.to_string() != key {
        return None;
    }
    Some(index)
}
