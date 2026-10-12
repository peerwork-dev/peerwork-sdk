//! Historical LEGACY_OWNER_ATTESTED protocol source and composition checks.
//! This validates archived protocol rows only; it does not attest a journal.

use crate::{
    canonical::Path,
    crypto::sha256_hex,
    full_manifest::{validate_full_manifest, ManifestError},
    wire_json::{canonical_wire_value, parse_js_json_string_bounded, parse_wire_json_bounded, WireValue},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use thiserror::Error;

const MAX_ROWS: usize = 4096;
const MAX_TEXT: usize = 65_536;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyError {
    #[error("invalid legacy protocol binding")]
    Invalid,
    #[error("legacy protocol resource bound exceeded")]
    Resource,
}

#[derive(Clone)]
struct Row {
    id: Vec<u16>,
    source_digest: Vec<u16>,
    source: WireValue,
    resolved: WireValue,
    closure: Vec<Vec<u16>>,
}

fn units(text: &str) -> Vec<u16> { text.encode_utf16().collect() }
fn string(text: &str) -> WireValue { WireValue::String(units(text)) }
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(fields.into_iter().map(|(k,v)|(units(k),v)).collect())
}
fn array(value: &WireValue) -> Result<&[WireValue], LegacyError> {
    if let WireValue::Array(v)=value { Ok(v) } else { Err(LegacyError::Invalid) }
}
fn fields(value: &WireValue) -> Result<&[(Vec<u16>,WireValue)], LegacyError> {
    if let WireValue::Object(v)=value { Ok(v) } else { Err(LegacyError::Invalid) }
}
fn field<'a>(value: &'a WireValue, key: &str) -> Result<&'a WireValue, LegacyError> {
    value.get(key).ok_or(LegacyError::Invalid)
}
fn exact(value: &WireValue, required: &[&str]) -> Result<(), LegacyError> {
    let values=fields(value)?;
    if values.len()!=required.len() || required.iter().any(|name|value.get(name).is_none()) { return Err(LegacyError::Invalid); }
    Ok(())
}
fn text_units<'a>(value: &'a WireValue, key: &str) -> Result<&'a [u16], LegacyError> {
    value.get(key).and_then(WireValue::as_utf16).ok_or(LegacyError::Invalid)
}
fn text(value: &WireValue, key: &str) -> Result<String, LegacyError> {
    String::from_utf16(text_units(value,key)?).map_err(|_|LegacyError::Invalid)
}
fn integer(value: &WireValue) -> Result<u64, LegacyError> {
    let n=value.as_number().ok_or(LegacyError::Invalid)?;
    if !n.is_finite() || n.fract()!=0.0 || !(0.0..=MAX_SAFE).contains(&n) { return Err(LegacyError::Invalid); }
    Ok(n as u64)
}
fn is_token(value: &[u16]) -> bool {
    value.len()==43 && value.iter().all(|c|matches!(*c,48..=57|65..=90|97..=122|45|95))
}
fn is_digest(value: &[u16]) -> bool {
    value.len()==64 && value.iter().all(|c|matches!(*c,48..=57|97..=102))
}
fn canonical(value: &WireValue) -> Result<String, LegacyError> {
    canonical_wire_value(value,Path::STRUCTURED).map_err(|_|LegacyError::Invalid)
}
fn same(a: &WireValue,b: &WireValue)->Result<bool,LegacyError>{Ok(canonical(a)?==canonical(b)?)}
fn normalize_manifest(value: &WireValue) -> Result<WireValue,LegacyError> {
    let encoded=validate_full_manifest(value).map_err(|e|match e {ManifestError::Resource=>LegacyError::Resource,_=>LegacyError::Invalid})?;
    let wrapped=parse_wire_json_bounded(encoded.as_bytes(),32,MAX_TEXT).map_err(|_|LegacyError::Invalid)?;
    Ok(field(&wrapped,"manifest")?.clone())
}
fn parse_canonical_text(value: &WireValue) -> Result<WireValue,LegacyError> {
    let units=value.as_utf16().ok_or(LegacyError::Invalid)?;
    if units.len()>MAX_TEXT { return Err(LegacyError::Resource); }
    let parsed=parse_js_json_string_bounded(units,32,MAX_TEXT).map_err(|_|LegacyError::Invalid)?;
    let encoded=canonical(&parsed)?;
    if encoded.encode_utf16().ne(units.iter().copied()) { return Err(LegacyError::Invalid); }
    Ok(parsed)
}
fn string_digest(value: &WireValue) -> Result<String,LegacyError> {
    let s=String::from_utf16(value.as_utf16().ok_or(LegacyError::Invalid)?).map_err(|_|LegacyError::Invalid)?;
    Ok(sha256_hex(s.as_bytes()))
}
fn manifest_digest(value: &WireValue) -> Result<String,LegacyError> {
    let wrapped=object(vec![("semantics",string("peerwork.kernel.v1")),("manifest",value.clone())]);
    Ok(sha256_hex(canonical(&wrapped)?.as_bytes()))
}
fn parse_closure(value: &WireValue) -> Result<Vec<Vec<u16>>,LegacyError> {
    let raw=parse_canonical_text(value)?;
    let values=array(&raw)?;
    if values.len()>16 { return Err(LegacyError::Resource); }
    let mut out=Vec::with_capacity(values.len()); let mut seen=HashSet::new();
    for value in values { let key=value.as_utf16().ok_or(LegacyError::Invalid)?.to_vec(); if !is_digest(&key)||!seen.insert(key.clone()){return Err(LegacyError::Invalid);} out.push(key); }
    Ok(out)
}

fn latest_protocols(objects: &[WireValue]) -> Result<Vec<WireValue>,LegacyError> {
    let mut rows=Vec::<(Vec<u16>,u64,WireValue)>::new();
    for row in objects {
        if row.get("kind").and_then(WireValue::as_string).as_deref()!=Some("protocols") { continue; }
        let id=row.get("id").and_then(WireValue::as_utf16).ok_or(LegacyError::Invalid)?.to_vec();
        let revision=integer(row.get("revision").ok_or(LegacyError::Invalid)?)?;
        if let Some((_,old_revision,old))=rows.iter_mut().find(|(key,_,_)|*key==id) {
            if revision>*old_revision { *old_revision=revision; *old=row.clone(); }
        } else { rows.push((id,revision,row.clone())); }
        if rows.len()>MAX_ROWS { return Err(LegacyError::Resource); }
    }
    Ok(rows.into_iter().map(|(_,_,row)|row).collect())
}

fn parse_legacy(row: &WireValue, workspace: &[u16]) -> Result<Row,LegacyError> {
    let provenance=row.get("provenance").and_then(WireValue::as_string).ok_or(LegacyError::Invalid)?;
    if provenance!="LEGACY_OWNER_ATTESTED" { return Err(LegacyError::Invalid); }
    if integer(row.get("revision").ok_or(LegacyError::Invalid)?)?!=1 { return Err(LegacyError::Invalid); }
    let id=text_units(row,"id")?.to_vec();
    let value=field(row,"value")?;
    exact(value,&["digest","workspace_id","source_digest","resolved_manifest","manifest","dependency_closure","created_by","created"])?;
    let digest=text_units(value,"digest")?.to_vec();
    let source_digest=text_units(value,"source_digest")?.to_vec();
    let row_workspace=text_units(value,"workspace_id")?;
    if !is_digest(&id)||id!=digest||!is_digest(&source_digest)||!is_token(row_workspace)||row_workspace!=workspace
        || !is_token(text_units(value,"created_by")?) || integer(field(value,"created")?).is_err() {
        return Err(LegacyError::Invalid);
    }
    let source_envelope=parse_canonical_text(field(value,"manifest")?)?;
    exact(&source_envelope,&["semantics","manifest"])?;
    if text(&source_envelope,"semantics")?!="peerwork.kernel.v1" { return Err(LegacyError::Invalid); }
    let source=normalize_manifest(field(&source_envelope,"manifest")?)?;
    let resolved_raw=parse_canonical_text(field(value,"resolved_manifest")?)?;
    let resolved=normalize_manifest(&resolved_raw)?;
    if source.get("format_version").is_some()||resolved.get("format_version").is_some() { return Err(LegacyError::Invalid); }
    let closure=parse_closure(field(value,"dependency_closure")?)?;
    if string_digest(field(value,"manifest")?)?!=String::from_utf16(&source_digest).map_err(|_|LegacyError::Invalid)?
        || manifest_digest(&resolved_raw)?!=String::from_utf16(&id).map_err(|_|LegacyError::Invalid)? {
        return Err(LegacyError::Invalid);
    }
    Ok(Row{id,source_digest,source,resolved,closure})
}

/// Validates latest archived protocol rows and their historical dependency
/// compositions. The caller binds this private result into complete replay.
pub(crate) fn validate_legacy_protocol_bindings(objects: &[WireValue], workspace_id: &str) -> Result<(),LegacyError> {
    if objects.len()>MAX_ROWS*16 { return Err(LegacyError::Resource); }
    let workspace=units(workspace_id);
    if !is_token(&workspace) { return Err(LegacyError::Invalid); }
    let protocols=latest_protocols(objects)?;
    let mut rows=HashMap::<Vec<u16>,Row>::new();
    for object in &protocols {
        match object.get("provenance").and_then(WireValue::as_string).as_deref() {
            Some("LEGACY_OWNER_ATTESTED")=>{ let row=parse_legacy(object,&workspace)?; rows.insert(row.id.clone(),row); },
            Some("AUTHOR_SIGNED")=>{},
            _=>return Err(LegacyError::Invalid),
        }
    }
    validate_compositions(&rows)
}

// The TS legacy loader selects a dependency by archived object ID and checks
// that its raw source digest is the requested dependency string. Composition
// then follows UTF-16 sorted source-digest edges and post-order closure.
fn validate_compositions(rows: &HashMap<Vec<u16>,Row>) -> Result<(),LegacyError> {
    for row in rows.values() {
        let (resolved,closure)=compose(row,rows)?;
        let expected=WireValue::Array(row.closure.iter().cloned().map(WireValue::String).collect());
        let actual=WireValue::Array(closure.into_iter().map(WireValue::String).collect());
        if !same(&expected,&actual)?||!same(&row.resolved,&resolved)? { return Err(LegacyError::Invalid); }
    }
    Ok(())
}

fn compose(root: &Row, rows: &HashMap<Vec<u16>,Row>) -> Result<(WireValue,Vec<Vec<u16>>),LegacyError> {
    let mut ordered=Vec::<WireValue>::new(); let mut closure=Vec::<Vec<u16>>::new();
    let mut active=HashSet::<Vec<u16>>::new(); let mut done=HashSet::<Vec<u16>>::new();
    fn visit(key:Vec<u16>,depth:usize,rows:&HashMap<Vec<u16>,Row>,active:&mut HashSet<Vec<u16>>,done:&mut HashSet<Vec<u16>>,ordered:&mut Vec<WireValue>,closure:&mut Vec<Vec<u16>>)->Result<(),LegacyError>{
        if active.contains(&key){return Err(LegacyError::Invalid)} if done.contains(&key){return Ok(())}
        if depth>16||active.len()+done.len()>=16{return Err(LegacyError::Resource)}
        let row=rows.get(&key).filter(|r|r.source_digest==key).ok_or(LegacyError::Invalid)?;
        let deps=array(field(&row.source,"dependencies")?)?; let mut children=Vec::with_capacity(deps.len());
        for d in deps {let d=d.as_utf16().ok_or(LegacyError::Invalid)?.to_vec();if !is_digest(&d){return Err(LegacyError::Invalid)} children.push(d)}
        children.sort(); active.insert(key.clone()); for child in children {visit(child,depth+1,rows,active,done,ordered,closure)?;} active.remove(&key); done.insert(key.clone()); closure.push(key); ordered.push(row.source.clone()); Ok(())
    }
    let deps=array(field(&root.source,"dependencies")?)?; let mut children=Vec::with_capacity(deps.len());
    for d in deps {let d=d.as_utf16().ok_or(LegacyError::Invalid)?.to_vec();if !is_digest(&d){return Err(LegacyError::Invalid)} children.push(d)}
    children.sort();for child in children {visit(child,1,rows,&mut active,&mut done,&mut ordered,&mut closure)?;} ordered.push(root.source.clone());
    let merged=merge_manifests(&root.source,&ordered,&closure)?;
    Ok((merged,closure))
}

fn merge_manifests(root:&WireValue,ordered:&[WireValue],closure:&[Vec<u16>])->Result<WireValue,LegacyError>{
    let closure_count=ordered.len().saturating_sub(1); let standalone=closure_count==0;
    let initial=field(root,"initial_state")?; let non_object_root=matches!(initial,WireValue::Object(_))==false;
    let stateless=|manifest:&WireValue|->Result<bool,LegacyError>{
        fn uses(value:&WireValue)->bool{match value {WireValue::Array(a)=>a.iter().any(uses),WireValue::Object(fields)=>{let literal=value.get("from").and_then(WireValue::as_string).as_deref()==Some("literal");if value.get("from").and_then(WireValue::as_string).as_deref()==Some("state")||value.get("source").and_then(WireValue::as_string).as_deref()==Some("state")||value.get("op").and_then(WireValue::as_string).as_deref()==Some("set"){return true}fields.iter().any(|(k,v)|!(literal&&k.iter().copied().eq("value".encode_utf16()))&&uses(v))},_=>false}}
        let actions=array(field(manifest,"actions")?)?; let constraints=fields(field(manifest,"constraints")?)?;
        Ok(actions.iter().all(|a|a.get("reads").and_then(|v|array(v).ok()).is_some_and(|v|v.is_empty())&&a.get("writes").and_then(|v|array(v).ok()).is_some_and(|v|v.is_empty())&&!uses(a))&&constraints.iter().all(|(_,v)|!uses(v)))
    };
    if non_object_root&&!standalone&&(ordered[..closure_count].iter().any(|m|m.get("initial_state").and_then(WireValue::object_len)!=Some(0))||ordered.iter().any(|m|stateless(m)!=Ok(true))){return Err(LegacyError::Invalid)}
    let mut schemas=BTreeMap::<Vec<u16>,WireValue>::new(); let mut actions=BTreeMap::<Vec<u16>,WireValue>::new(); let mut roles=BTreeSet::<Vec<u16>>::new(); let mut caps=BTreeSet::<Vec<u16>>::new(); let mut conflicts=BTreeMap::<Vec<u16>,WireValue>::new(); let mut historical=BTreeMap::<Vec<u16>,WireValue>::new();
    let mut state=if standalone||non_object_root{initial.clone()}else{WireValue::Object(vec![])};let mut owners=HashMap::<Vec<u16>,Vec<WireValue>>::new();let mut arrays=BTreeMap::<Vec<u16>,WireValue>::new();let mut constraints=BTreeMap::<Vec<u16>,Vec<WireValue>>::new();
    for manifest in ordered {
        for (name,schema) in fields(field(manifest,"record_schemas")?)?{if schemas.get(name).is_some_and(|p|same(p,schema)!=Ok(true)){return Err(LegacyError::Invalid)} schemas.insert(name.clone(),schema.clone());}
        for action in array(field(manifest,"actions")?)?{let id=field(action,"id")?.as_utf16().ok_or(LegacyError::Invalid)?.to_vec();if actions.insert(id,action.clone()).is_some(){return Err(LegacyError::Invalid)}}
        for v in array(field(manifest,"protocol_roles")?)?{roles.insert(v.as_utf16().ok_or(LegacyError::Invalid)?.to_vec());}
        for v in array(field(manifest,"capabilities")?)?{caps.insert(v.as_utf16().ok_or(LegacyError::Invalid)?.to_vec());}
        for (field_name,target) in [("role_conflicts",&mut conflicts),("historical_role_conflicts",&mut historical)]{for pair in array(field(manifest,field_name)?)?{let mut pair=array(pair)?.iter().map(|v|v.as_utf16().map(<[u16]>::to_vec).ok_or(LegacyError::Invalid)).collect::<Result<Vec<_>,_>>()?;if pair.len()!=2{return Err(LegacyError::Invalid)}pair.sort();let mut key=pair[0].clone();key.push(0);key.extend(&pair[1]);target.insert(key,WireValue::Array(pair.into_iter().map(WireValue::String).collect()));}}
        if !standalone&&!non_object_root {for (key,value) in fields(field(manifest,"initial_state")?)?{let declarations=manifest.get("state_array_types").map(array).transpose()?.unwrap_or(&[]).iter().filter(|entry|entry.get("path").and_then(|v|array(v).ok()).and_then(|p|p.first()).and_then(WireValue::as_utf16)==Some(key.as_slice())).cloned().collect::<Vec<_>>();let existing=if let WireValue::Object(fs)=&state{fs.iter().find(|(k,_)|k==key).map(|(_,v)|v)}else{None};if existing.is_some_and(|p|same(p,value)!=Ok(true)||owners.get(key).is_some_and(|o|same(&WireValue::Array(o.clone()),&WireValue::Array(declarations.clone()))!=Ok(true))){return Err(LegacyError::Invalid)}if existing.is_none(){if let WireValue::Object(fs)=&mut state{fs.push((key.clone(),value.clone()));}}owners.insert(key.clone(),declarations);}}
        if let Some(list)=manifest.get("state_array_types"){for declaration in array(list)?{let key=canonical(field(declaration,"path")?)?.encode_utf16().collect::<Vec<_>>();if arrays.get(&key).is_some_and(|prior|same(prior,declaration)!=Ok(true)){return Err(LegacyError::Invalid)}arrays.insert(key,declaration.clone());}}
        for (id,rules) in fields(field(manifest,"constraints")?)?{constraints.entry(id.clone()).or_default().extend(array(rules)?.iter().cloned());}
    }
    if !actions.is_empty()&&constraints.keys().any(|key|!actions.contains_key(key)){return Err(LegacyError::Invalid)}
    let mut resolved_actions=Vec::new();for (id,mut action) in actions{if let Some(extra)=constraints.remove(&id){let mut variants=array(field(&action,"variants")?)?.to_vec();for variant in &mut variants{let mut when=extra.clone();when.extend(array(field(variant,"when")?)?.iter().cloned());put(variant,"when",WireValue::Array(when))?;}put(&mut action,"variants",WireValue::Array(variants))?;}resolved_actions.push((id,action));}
    // TS composeProtocol sorts actions with localeCompare. Manifest action IDs
    // are normally ASCII, where UTF-16 ordinal order agrees; retain UTF-16 order
    // here and keep this comparator explicit for differential coverage.
    resolved_actions.sort_by(|a,b|a.0.cmp(&b.0));
    let resolved_actions=resolved_actions.into_iter().map(|(_,action)|action).collect();
    let mut role_conflicts=conflicts.into_values().collect::<Vec<_>>(); role_conflicts.sort_by(|a,b|joined_pair(a).cmp(&joined_pair(b)));
    let mut historical_conflicts=historical.into_values().collect::<Vec<_>>(); historical_conflicts.sort_by(|a,b|joined_pair(a).cmp(&joined_pair(b)));
    let mut merged=object(vec![("name",field(root,"name")?.clone()),("display_version",field(root,"display_version")?.clone()),("semantics",field(root,"semantics")?.clone()),("dependencies",WireValue::Array(closure.iter().cloned().map(WireValue::String).collect())),("protocol_roles",WireValue::Array(roles.into_iter().map(WireValue::String).collect())),("capabilities",WireValue::Array(caps.into_iter().map(WireValue::String).collect())),("role_conflicts",WireValue::Array(role_conflicts)),("historical_role_conflicts",WireValue::Array(historical_conflicts)),("constraints",WireValue::Object(constraints.into_iter().map(|(k,v)|(k,WireValue::Array(v))).collect())),("record_schemas",WireValue::Object(schemas.into_iter().collect())),("initial_state",state),("actions",WireValue::Array(resolved_actions))]);
    if !arrays.is_empty(){put(&mut merged,"format_version",WireValue::Number(2.0))?;put(&mut merged,"state_array_types",WireValue::Array(arrays.into_values().collect()))?;}
    if let Some(exports)=root.get("state_exports"){put(&mut merged,"state_exports",exports.clone())?;}
    let mut reqs=ordered.iter().filter_map(|m|m.get("execution_requirements")).collect::<Vec<_>>();if let Some(req)=root.get("execution_requirements"){reqs.push(req);}
    if let Some(root_req)=root.get("execution_requirements"){if root_req.get("closure_complete")==Some(&WireValue::Bool(true)){put(&mut merged,"execution_requirements",root_req.clone())?;}else if !reqs.is_empty(){let ports=reqs.iter().flat_map(|r|r.get("ports").and_then(|p|array(p).ok()).unwrap_or(&[]).iter().cloned()).collect();put(&mut merged,"execution_requirements",object(vec![("format",string("peerwork.protocol-execution-requirements.v1")),("closure_complete",WireValue::Bool(true)),("ports",WireValue::Array(ports))]))?;}}else if !reqs.is_empty(){let ports=reqs.iter().flat_map(|r|r.get("ports").and_then(|p|array(p).ok()).unwrap_or(&[]).iter().cloned()).collect();put(&mut merged,"execution_requirements",object(vec![("format",string("peerwork.protocol-execution-requirements.v1")),("closure_complete",WireValue::Bool(true)),("ports",WireValue::Array(ports))]))?;}
    normalize_manifest(&merged)
}
fn put(value:&mut WireValue,key:&str,replacement:WireValue)->Result<(),LegacyError>{let WireValue::Object(items)=value else{return Err(LegacyError::Invalid)};let name=units(key);if let Some((_,v))=items.iter_mut().find(|(k,_)|*k==name){*v=replacement}else{items.push((name,replacement));}Ok(())}
fn joined_pair(value:&WireValue)->Vec<u16>{let WireValue::Array(items)=value else{return vec![]};let mut result=Vec::new();for (index,item) in items.iter().enumerate(){if index>0{result.push(',' as u16)}if let Some(units)=item.as_utf16(){result.extend(units)}}result}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_pinned_typescript_vectors_match() {
        let vectors = parse_wire_json_bounded(
            include_bytes!("../../../conformance/legacy-protocol-bindings-vectors.json"),
            32,
            2 * 1024 * 1024,
        )
        .expect("generated vector JSON parses");
        for case in array(&vectors).expect("vector array") {
            let workspace = text(case, "workspace_id").expect("workspace id");
            let expected = matches!(field(case, "valid"), Ok(WireValue::Bool(true)));
            let objects = array(field(case, "objects").expect("objects"))
                .expect("object list");
            let actual = validate_legacy_protocol_bindings(objects, &workspace).is_ok();
            assert_eq!(actual, expected, "{}", text(case, "name").unwrap());
        }
    }
}
