//! Reject duplicate JSON members before any signed or authorized data is used.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("JSON without duplicate object members") }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> { Ok(StrictValue(Value::Bool(v))) }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> { Ok(StrictValue(Value::Number(v.into()))) }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> { Ok(StrictValue(Value::Number(v.into()))) }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
        let n = serde_json::Number::from_f64(v).ok_or_else(|| E::custom("non-finite number"))?;
        Ok(StrictValue(Value::Number(n)))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> { Ok(StrictValue(Value::String(v.into()))) }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> { Ok(StrictValue(Value::String(v))) }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> { Ok(StrictValue(Value::Null)) }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> { Ok(StrictValue(Value::Null)) }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> { StrictValue::deserialize(d) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(item) = seq.next_element::<StrictValue>()? { out.push(item.0); }
        Ok(StrictValue(Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
            if out.insert(key, value.0).is_some() { return Err(serde::de::Error::custom("duplicate JSON member")); }
        }
        Ok(StrictValue(Value::Object(out)))
    }
}

pub fn parse_strict_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}
