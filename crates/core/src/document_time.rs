//! Signed source-document time claims, never a service/lease clock.
use crate::{wire_json::WireValue,source_provenance::valid_source_timestamp};
#[derive(Debug)]pub struct Invalid;
fn key(value:&[u16],name:&str)->bool{value.iter().copied().eq(name.encode_utf16())}
pub fn normalized(value:&WireValue)->Result<WireValue,Invalid>{
 let WireValue::Object(fields)=value else{return Err(Invalid)};
 if fields.is_empty()||fields.len()>2||fields.iter().any(|(k,_)|!key(k,"created_at")&&!key(k,"updated_at")){return Err(Invalid)}
 let mut output=Vec::new();let mut present=false;
 for name in ["created_at","updated_at"]{
  let v=value.get(name).cloned().unwrap_or(WireValue::Null);
  if !matches!(v,WireValue::Null){if !valid_source_timestamp(&v){return Err(Invalid)}present=true;}
  output.push((name.encode_utf16().collect(),v));
 }
 if !present{return Err(Invalid)}Ok(WireValue::Object(output))
}
pub fn at(value:Option<&WireValue>,index:u64)->Result<Option<WireValue>,Invalid>{
 let Some(value)=value else{return Ok(None)};let WireValue::Array(rows)=value else{return Err(Invalid)};
 if rows.is_empty()||rows.len()>8{return Err(Invalid)}let mut seen=std::collections::BTreeSet::new();let mut selected=None;
 for row in rows{
  let WireValue::Object(fields)=row else{return Err(Invalid)};
  if fields.iter().any(|(k,_)|!key(k,"record_index")&&!key(k,"created_at")&&!key(k,"updated_at")){return Err(Invalid)}
  let n=row.get("record_index").and_then(WireValue::as_number).filter(|n|n.fract()==0.0&&(0.0..=7.0).contains(n)).ok_or(Invalid)? as u64;
  if !seen.insert(n){return Err(Invalid)}let time=normalized(&WireValue::Object(fields.iter().filter(|(k,_)|!key(k,"record_index")).cloned().collect()))?;
  if n==index{selected=Some(time);}
 }Ok(selected)
}
pub fn matches_claim(actual:Option<&WireValue>,expected:Option<&WireValue>)->bool{
 match expected{
  None=>actual.is_none_or(|v|matches!(v,WireValue::Null)),
  Some(expected)=>actual.filter(|v|v.object_len()==Some(2)).and_then(|v|normalized(v).ok()).is_some_and(|value|&value==expected),
 }
}
pub fn for_command(command:&WireValue,index:u64)->Result<Option<WireValue>,Invalid>{at(command.get("body").and_then(|b|b.get("document_times")),index)}
#[cfg(test)]mod tests{
 use super::*;use crate::wire_json::parse_wire_json;
 #[test]fn exact_offset_and_nanoseconds_are_retained(){let v=parse_wire_json(br#"[{"record_index":0,"created_at":"1998-12-31T16:59:59.123456789-07:00"}]"#).unwrap();let time=at(Some(&v),0).unwrap().unwrap();assert_eq!(time.get("created_at").and_then(WireValue::as_string).as_deref(),Some("1998-12-31T16:59:59.123456789-07:00"));assert!(matches!(time.get("updated_at"),Some(WireValue::Null)));assert!(at(Some(&v),1).unwrap().is_none());}
 #[test]fn metadata_object_order_is_not_a_new_signature_condition(){let a=parse_wire_json(br#"{"created_at":"2000-01-01T00:00:00Z","updated_at":null}"#).unwrap();let b=parse_wire_json(br#"{"updated_at":null,"created_at":"2000-01-01T00:00:00Z"}"#).unwrap();assert!(matches_claim(Some(&b),Some(&a)));}
 #[test]fn rejects_invalid_calendar_duplicate_selection_and_unknown_fields(){for input in [r#"[{"record_index":0,"created_at":"2026-02-30T00:00:00Z"}]"#,r#"[{"record_index":0,"created_at":"2020-01-01T00:00:00Z"},{"record_index":0,"updated_at":"2021-01-01T00:00:00Z"}]"#,r#"[{"record_index":0,"created_at":null}]"#,r#"[{"record_index":8,"created_at":"2020-01-01T00:00:00Z"}]"#,r#"[{"record_index":0,"created_at":"2020-01-01T00:00:00Z","author":"unverified"}]"#]{let v=parse_wire_json(input.as_bytes()).unwrap();assert!(at(Some(&v),0).is_err());}}
}
