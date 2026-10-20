//! Classify retained TS coordination markers against authenticated plaintext
//! operations. A packetless marker is a local intent, never proof of delivery.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoricalCoordinationIntent {
    pub marker_key: String,
    pub input_hash: String,
    pub action: String,
    pub status: String,
    pub proof_sequence: Option<u64>,
    pub proof_commit_hash: Option<String>,
}

pub(super) struct Marker {
    key: String,
    hash: String,
    action: String,
    id: String,
}

fn invalid() -> HistoricalOwnerAttachError { HistoricalOwnerAttachError::CoordinationInvalid }
fn text(v: &WireValue, key: &str) -> Option<String> { v.get(key)?.as_string() }
fn hash(v: &WireValue) -> Result<String, HistoricalOwnerAttachError> {
    let value = Zeroizing::new(canonical_wire_value(v, CanonicalPath::SecureArtifact).map_err(|_| invalid())?);
    Ok(sha256_hex(value.as_bytes()))
}
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(fields.into_iter().map(|(k,v)|(k.encode_utf16().collect(),v)).collect())
}

pub(super) fn parse(root: &WireValue, input: &HistoricalOwnerAttachInput)
    -> Result<Vec<Marker>, HistoricalOwnerAttachError> {
    let rows = match root.get("coordination_intents") {
        None => return Ok(Vec::new()),
        Some(WireValue::Object(rows)) => rows,
        _ => return Err(invalid()),
    };
    if rows.len() > MAX_HISTORY { return Err(HistoricalOwnerAttachError::ResourceLimit); }
    if !rows.is_empty() && !matches!(root.get("pending"),Some(WireValue::Object(p)) if p.is_empty()) {
        return Err(HistoricalOwnerAttachError::CoordinationPending);
    }
    let prefix = format!("{}.", input.workspace_id);
    let mut result = Vec::new();
    for (key,value) in rows {
        let key = String::from_utf16(key).map_err(|_| invalid())?;
        let tail = key.strip_prefix(&prefix).ok_or_else(invalid)?;
        let (action,id) = if let Some(id)=tail.strip_prefix("send.") {
            ("send",id)
        } else {
            ["coordination.ack","coordination.disposition","coordination.remind","coordination.cancel"]
                .into_iter().find_map(|action|tail.strip_prefix(&format!("{action}.")).map(|id|(action,id)))
                .ok_or_else(invalid)?
        };
        let input_hash=value.as_string().filter(|h|valid_digest(h)).ok_or_else(invalid)?;
        if action=="send" {
            if !valid_token(id) { return Err(invalid()); }
        } else {
            let parts:Vec<_>=id.split('.').collect();
            if !matches!(parts.len(),3|4) || parts[0]!=input.workspace_id
                || !valid_token(parts[1]) || !valid_token(parts[2])
                || (parts.len()==4 && parts[3]!="deadline") { return Err(invalid()); }
        }
        if matches!(action,"coordination.ack"|"coordination.remind")
            && input_hash != hash(&WireValue::Object(Vec::new()))? { return Err(invalid()); }
        result.push(Marker{key:key.clone(),hash:input_hash,action:action.into(),id:id.into()});
    }
    Ok(result)
}

fn matches_input(marker: &Marker, body: &WireValue, action: &str)
    -> Result<bool,HistoricalOwnerAttachError> {
    let value = match marker.action.as_str() {
        "send" if matches!(action,"coordination.send"|"coordination.reply")
            && text(body,"request_id").as_deref()==Some(marker.id.as_str()) => object(vec![
                ("recipients",body.get("recipients").ok_or_else(invalid)?.clone()),
                ("message",body.get("message").ok_or_else(invalid)?.clone()),
                ("source",body.get("source_ref").cloned().unwrap_or(WireValue::Null)),
            ]),
        kind if kind==action && text(body,"item_id").as_deref()==Some(marker.id.as_str()) => {
            match kind {
                "coordination.ack"|"coordination.remind" => WireValue::Object(Vec::new()),
                "coordination.cancel" => object(vec![("note",body.get("note").ok_or_else(invalid)?.clone())]),
                "coordination.disposition" => {
                    let mut fields=Vec::new();
                    for key in ["state","expected_version","note","defer_until"] {
                        fields.push((key,body.get(key).ok_or_else(invalid)?.clone()));
                    }
                    if let Some(reference)=body.get("result_ref").filter(|v| !matches!(v,WireValue::Null)) {
                        fields.push(("result_ref",reference.clone()));
                    }
                    object(fields)
                },
                _ => return Ok(false),
            }
        },
        _ => return Ok(false),
    };
    let mut value=value;
    let result=hash(&value).map(|hash| hash==marker.hash);
    scrub(&mut value);
    result
}

pub(super) fn classify(markers: &[Marker], replayed: &TransportReplayedJournal,
    input: &HistoricalOwnerAttachInput) -> Result<Vec<HistoricalCoordinationIntent>,HistoricalOwnerAttachError> {
    let mut result: Vec<_> = markers.iter().map(|marker| HistoricalCoordinationIntent {
        marker_key:marker.key.clone(),input_hash:marker.hash.clone(),action:marker.action.clone(),
        status:"RETAINED_UNRESOLVED".into(),proof_sequence:None,proof_commit_hash:None,
    }).collect();
    if markers.is_empty() { return Ok(result); }
    let selected: BTreeMap<_,_> = markers.iter().enumerate().map(|(i,m)|(m.key.as_str(),i)).collect();
    // Scan signed history once, rather than replaying or reparsing it per marker.
    for (index,wire) in replayed.signed_commit_wires().iter().enumerate() {
        let sequence=(index+1) as u64;
        if replayed.replay().recoveries().iter().any(|notice| {
            let base=notice.get("base").and_then(|c|exact_u64(c.get("sequence")));
            let through=notice.get("through").and_then(|c|exact_u64(c.get("sequence")));
            matches!((base,through),(Some(base),Some(through)) if sequence>base && sequence<=through)
        }) {continue;}
        let commit=parse_wire_json_bounded(wire,64,2*1024*1024).map_err(|_|invalid())?;
        let payload=commit.get("payload").ok_or_else(invalid)?;
        if text(payload,"actor_id").as_deref()!=Some(input.expected_owner_actor_id.as_str())
            || text(payload,"signing_key").as_deref()!=Some(input.expected_owner_key_id.as_str())
            || text(payload,"workspace_id").as_deref()!=Some(input.workspace_id.as_str()) {continue;}
        let action=text(payload,"action_id").ok_or_else(invalid)?;
        if !matches!(action.as_str(),"coordination.send"|"coordination.reply"|"coordination.ack"|"coordination.disposition"|"coordination.cancel") {continue;}
        // Reminders can intentionally repeat the same item and {} input. Their
        // hashes cannot bind new markers to earlier invocations; retain them.
        let operation=replayed.replay().operations().get(index).ok_or_else(invalid)?;
        if text(operation,"kind").as_deref()!=Some("ACTION") {continue;}
        let body=operation.get("input").and_then(|i|i.get("body")).ok_or_else(invalid)?;
        let (kind,id)=if matches!(action.as_str(),"coordination.send"|"coordination.reply") {
            ("send",text(body,"request_id").ok_or_else(invalid)?)
        } else {(action.as_str(),text(body,"item_id").ok_or_else(invalid)?)};
        let key=format!("{}.{kind}.{id}",input.workspace_id);
        let Some(&position)=selected.get(key.as_str()) else {continue;};
        if result[position].status=="ARCHIVED_COMPLETED" || !matches_input(&markers[position],body,&action)? {continue;}
        let policy_hash=text(payload,"policy_hash").ok_or_else(invalid)?;
        let policy=parse_wire_json_bounded(replayed.signed_policy_by_hash(&policy_hash).ok_or_else(invalid)?,64,262144).map_err(|_|invalid())?;
        let configured=policy.get("payload").and_then(|p|p.get("structure")).and_then(|s|s.get("coordination"))
            .and_then(|c|text(c,"instance_id"));
        if configured.is_none() || configured!=text(payload,"instance_id") {continue;}
        result[position].status="ARCHIVED_COMPLETED".into();
        result[position].proof_sequence=Some((index+1) as u64);
        result[position].proof_commit_hash=Some(sha256_hex(wire));
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireInput { attach_id:String,marker_key:String,expected_input_hash:String }

impl SecureHistoricalOwnerAttach {
    /// Retire only a previously retained packetless local marker. No POST,
    /// cancellation, receipt, or remote delivery is invented by this operation.
    pub fn retire_coordination_marker_json(&self, input: &str, cancel: &CancellationToken)
        -> Result<HistoricalOwnerAttachResult,HistoricalOwnerAttachError> {
        if cancel.is_cancelled(){return Err(HistoricalOwnerAttachError::Cancelled);}
        if input.len()>16384{return Err(HistoricalOwnerAttachError::Input);}
        let selected:RetireInput=serde_json::from_str(input).map_err(|_|HistoricalOwnerAttachError::Input)?;
        if !valid_token(&selected.attach_id)||!valid_digest(&selected.expected_input_hash){return Err(HistoricalOwnerAttachError::Input);}
        let _lock=SecureStateStore::open(&self.config.state_dir.join("owner-attach-recovery.state")).map_err(|_|HistoricalOwnerAttachError::Local)?;
        let store=SecureStateStore::open(&self.history_path()).map_err(|_|HistoricalOwnerAttachError::Local)?;
        let mut history=read_history(&store,&self.config.origin)?;
        let row=history.rows.get_mut(&selected.attach_id).ok_or(HistoricalOwnerAttachError::NotFound)?;
        if row.attached_sequence.is_none(){return Err(HistoricalOwnerAttachError::Conflict);}
        let owner=KernelIdentity::open(&self.identity_path()).map_err(|_|HistoricalOwnerAttachError::Identity)?;
        if owner.actor_id()!=row.input.expected_owner_actor_id||owner.key_id()!=row.input.expected_owner_key_id {return Err(HistoricalOwnerAttachError::Identity);}
        let marker=row.coordination_intents.iter_mut().find(|m|m.marker_key==selected.marker_key)
            .ok_or(HistoricalOwnerAttachError::NotFound)?;
        if marker.input_hash!=selected.expected_input_hash||!matches!(marker.status.as_str(),"RETAINED_UNRESOLVED"|"RETIRED_LOCAL") {
            return Err(HistoricalOwnerAttachError::Conflict);
        }
        marker.status="RETIRED_LOCAL".into();
        let result=summary(&selected.attach_id,row);save_history(&store,&history)?;Ok(result)
    }
}
