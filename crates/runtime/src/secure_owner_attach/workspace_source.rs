//! Route legacy workspace records before validating a selected attachment.
//! This only projects a parsed in-memory value. Source files and other native
//! workspace profiles are never rewritten, imported, retired or acknowledged.
use super::*;

fn text(v: &WireValue, key: &str) -> Option<String> { v.get(key)?.as_string() }
fn at<'a>(v: &'a WireValue, path: &[&str]) -> Option<&'a WireValue> {
    path.iter().try_fold(v, |v, key| v.get(key))
}
fn unresolved(field: &'static str) -> HistoricalOwnerAttachError {
    HistoricalOwnerAttachError::SourceScopeUnresolved(field)
}
fn conflict(field: &'static str) -> HistoricalOwnerAttachError {
    HistoricalOwnerAttachError::SourceScopeConflict(field)
}
fn same(v: Option<&WireValue>, workspace: &str, field: &'static str)
    -> Result<(), HistoricalOwnerAttachError> {
    if let Some(v)=v { if v.as_string().as_deref()!=Some(workspace) {return Err(conflict(field));} }
    Ok(())
}
fn prefix(key: &str, field: &'static str) -> Result<String, HistoricalOwnerAttachError> {
    let (workspace,tail)=key.split_once('.').ok_or_else(||unresolved(field))?;
    if !valid_token(workspace)||tail.is_empty() {return Err(unresolved(field));}
    Ok(workspace.into())
}
fn rows<'a>(root: &'a WireValue, field: &'static str)
    -> Result<&'a [(Vec<u16>,WireValue)],HistoricalOwnerAttachError> {
    match root.get(field) {None=>Ok(&[]),Some(WireValue::Object(rows))=>Ok(rows),_=>Err(unresolved(field))}
}
fn select(root: &mut WireValue, field: &'static str, target: &str,
    known: &std::collections::BTreeSet<String>,
    route: impl Fn(&str,&WireValue)->Result<String,HistoricalOwnerAttachError>)
    -> Result<(),HistoricalOwnerAttachError> {
    let mut keep=Vec::new();
    for (key,row) in rows(root,field)? {
        let key=String::from_utf16(key).map_err(|_|unresolved(field))?;
        let workspace=route(&key,row)?;
        if !valid_token(&workspace)||!known.contains(&workspace) {return Err(unresolved(field));}
        keep.push(workspace==target);
    }
    let WireValue::Object(fields)=root else {return Err(unresolved(field));};
    if let Some((_,WireValue::Object(rows)))=fields.iter_mut().find(|(k,_)|k.iter().copied().eq(field.encode_utf16())) {
        let mut index=0;
        rows.retain_mut(|(key,row)| {
            let retain=keep[index];index+=1;
            if !retain {key.zeroize();scrub(row);}
            retain
        });
    }
    Ok(())
}

pub(super) fn project(root: &mut WireValue, input: &HistoricalOwnerAttachInput)
    -> Result<(),HistoricalOwnerAttachError> {
    let known:std::collections::BTreeSet<_>=rows(root,"workspaces")?.iter().map(|(key,_)|
        String::from_utf16(key).map_err(|_|unresolved("workspaces"))).collect::<Result<_,_>>()?;
    if known.len()>MAX_HISTORY {return Err(HistoricalOwnerAttachError::ResourceLimit);}
    if known.iter().any(|w|!valid_token(w))||!known.contains(&input.workspace_id) {return Err(unresolved("workspaces"));}
    let target=&input.workspace_id;
    // Pending routes are pinned to both the exact HTTP target and packet. A
    // directory/admission packet with no provable workspace stays a blocker.
    let mut pending=std::collections::BTreeMap::new();
    for (key,row) in rows(root,"pending")? {
        let id=String::from_utf16(key).map_err(|_|unresolved("pending"))?;
        let path=text(row,"path").ok_or_else(||unresolved("pending"))?;
        let workspace=path.strip_prefix("/api/workspace/v1/secure/workspaces/")
            .and_then(|p|p.strip_suffix("/commits")).filter(|w|valid_token(w));
        let Some(workspace)=workspace else {
            // Preserve existing single-workspace specialized import behavior.
            if known.len()==1 {continue;} else {return Err(unresolved("pending"));}
        };
        same(at(row,&["body","commit","payload","workspace_id"]),workspace,"pending")?;
        if workspace!=target {
            let payload=at(row,&["body","commit","payload"]).ok_or_else(||unresolved("pending"))?;
            if text(payload,"workspace_id").as_deref()!=Some(workspace)
                || text(payload,"command_id").as_deref()!=Some(id.as_str())
                || text(payload,"actor_id").as_deref()!=Some(input.expected_owner_actor_id.as_str())
                || text(payload,"signing_key").as_deref()!=Some(input.expected_owner_key_id.as_str()) {
                return Err(conflict("pending"));
            }
        }
        pending.insert(id,workspace.to_owned());
    }
    select(root,"pending",target,&known,|key,_| {
        pending.get(key).cloned().or_else(||(known.len()==1).then(||target.clone()))
            .ok_or_else(||unresolved("pending"))
    })?;
    for field in ["guard_time_post_responses","wire_upgrade_observations"] {
        select(root,field,target,&known,|key,row| {
            let direct=if field=="guard_time_post_responses" {text(row,"workspace_id")} else {None};
            let workspace=pending.get(key).cloned().or(direct)
                .or_else(||(known.len()==1).then(||target.clone())).ok_or_else(||unresolved(field))?;
            if field=="guard_time_post_responses" {
                for path in [&["workspace_id"][..],&["checkpoint","workspace_id"],
                    &["guard_time_attestation","payload","workspace_id"],
                    &["guard_time_attestation","payload","source","workspace_id"],
                    &["guard_time_attestation","payload","result","workspace_id"]] {
                    same(at(row,path),&workspace,field)?;
                }
            }
            Ok(workspace)
        })?;
    }
    select(root,"inbox_receipts",target,&known,|key,row| {
        let workspace=prefix(key,"inbox_receipts")?;
        same(row.get("workspace_id"),&workspace,"inbox_receipts")?;
        if row.get("workspace_id").is_none(){return Err(unresolved("inbox_receipts"));}
        Ok(workspace)
    })?;
    select(root,"coordination_intents",target,&known,|key,_| {
        let workspace=prefix(key,"coordination_intents")?;
        if let Some(tail)=key.strip_prefix(&format!("{workspace}.coordination.")) {
            let (_,item)=tail.split_once('.').ok_or_else(||unresolved("coordination_intents"))?;
            if item.split('.').next()!=Some(workspace.as_str()) {return Err(conflict("coordination_intents"));}
        }
        Ok(workspace)
    })?;
    select(root,"guard_time_action_intents",target,&known,|key,row| {
        let pair:Vec<String>=serde_json::from_str(key).map_err(|_|unresolved("guard_time_action_intents"))?;
        if pair.len()!=2||text(row,"workspace_id").as_deref()!=Some(pair[0].as_str())
            ||text(row,"operation_id").as_deref()!=Some(pair[1].as_str()) {
            return Err(conflict("guard_time_action_intents"));
        }
        for path in [&["source","workspace_id"][..],&["policy","payload","workspace_id"],
            &["commit","payload","workspace_id"],&["request","commit","payload","workspace_id"],
            &["result_checkpoint","workspace_id"],&["proof","payload","workspace_id"]] {
            same(at(row,path),&pair[0],"guard_time_action_intents")?;
        }
        Ok(pair[0].clone())
    })?;
    select(root,"field_policy_intents",target,&known,|key,_|Ok(key.into()))?;
    for field in ["protocol_install_intents","package_stage_intents","protocol_object_stage_intents"] {
        select(root,field,target,&known,|key,row| {
            let workspace=prefix(key,field)?;
            for path in [&["workspace_id"][..],&["source","workspace_id"],
                &["proof","workspace_id"],&["proof","source","workspace_id"]] {
                same(at(row,path),&workspace,field)?;
            }
            Ok(workspace)
        })?;
    }
    select(root,"configuration_receipts",target,&known,|_,row| {
        let workspace=text(row,"workspace_id").ok_or_else(||unresolved("configuration_receipts"))?;
        same(at(row,&["receipt","payload","workspace_id"]),&workspace,"configuration_receipts")?;
        Ok(workspace)
    })?;
    select(root,"intake_intents",target,&known,|_,row|
        at(row,&["binding","workspace_id"]).and_then(WireValue::as_string).ok_or_else(||unresolved("intake_intents")))?;
    // Only the selected workspace's keyring/conversion/read pins are interpreted.
    select(root,"workspaces",target,&known,|key,_|Ok(key.into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> HistoricalOwnerAttachInput {
        let input = HistoricalOwnerAttachInput {
            workspace_id: "w".repeat(43), protected_ts_state_path: "/selected/state".into(),
            protected_owner_pkcs8_path: "/selected/key".into(), protected_ts_intent_db_path: "/selected/intents".into(),
            expected_owner_actor_id: "a".repeat(43), expected_owner_key_id: "k".repeat(43),
            recover_pending_action: false, retain_pending_action_command_id: None,
            selected_pending_package_stage_command_id: None, selected_orphan_package_stage_command_id: None,
            expected_ts_state_digest: None, kernel_pending_command_ids: Vec::new(), expected_kernel_intent_db_digest: None,
        };
        input
    }
    fn wire(value: serde_json::Value) -> WireValue {
        parse_wire_json_bounded(&serde_json::to_vec(&value).unwrap(),48,MAX_SOURCE).unwrap()
    }
    #[test]
    fn workspace_projection_does_not_apply_foreign_keyring_or_field_policy_work() {
        let input=input();let other="b".repeat(43);
        let mut source=wire(serde_json::json!({"workspaces":{(input.workspace_id.clone()):{},(other.clone()):{"pending_keyring":{"not":"imported"},"conversion":{}}},"pending":{},"field_policy_intents":{(other.clone()):"retained"}}));
        project(&mut source,&input).unwrap();
        assert_eq!(source.get("workspaces").unwrap().object_len(),Some(1));
        assert_eq!(source.get("field_policy_intents").unwrap().object_len(),Some(0));
    }
    #[test]
    fn workspace_projection_rejects_disguised_selected_response_and_unscoped_pending() {
        let input=input();let other="b".repeat(43);let id="c".repeat(43);
        let mut source=wire(serde_json::json!({"workspaces":{(input.workspace_id.clone()):{},(other.clone()):{}},"pending":{},"guard_time_post_responses":{(id.clone()):{"workspace_id":&other,"checkpoint":{"workspace_id":&input.workspace_id}}}}));
        assert!(matches!(project(&mut source,&input),Err(HistoricalOwnerAttachError::SourceScopeConflict("guard_time_post_responses"))));
        let mut source=wire(serde_json::json!({"workspaces":{(input.workspace_id.clone()):{},(other.clone()):{}},"pending":{(id.clone()):{"path":"/api/workspace/v1/secure/identity-keys","body":{}}}}));
        assert!(matches!(project(&mut source,&input),Err(HistoricalOwnerAttachError::SourceScopeUnresolved("pending"))));
    }
}
