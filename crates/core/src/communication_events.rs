//! Compact event observations are attested by the pinned service, not presented
//! as a new signature or instruction from the actor named in the observation.
use super::*;

pub const FORMAT: &str = "peerwork.workspace-event.v1";
const RECEIPT_TYPE: &str = "peerwork.workspace-event.v1+jws";
const KINDS: &[&str] = &[
    "action.accepted", "structure.protocol.upgraded", "structure.protocol.bound",
    "structure.instance.adopted", "structure.member.admitted", "structure.member.revoked",
    "structure.member.name.changed", "structure.grant.assigned", "structure.grant.revoked", "structure.member.availability.changed",
    "communication.member.presence.changed", "structure.workspace.collaboration.changed",
];

pub(super) fn delivery(value: &WireValue, audience: &[u16], pins: &MailboxPins, key: &str) -> Result<VerifiedDelivery> {
    let sequence = number(value, "event_source_sequence")?;
    if sequence == 0 || text(value,"kind")? != "BUSINESS"
        || text(value,"delivery_id")? != id(json!(["peerwork.delivery.v1",pins.workspace_id,pins.mailbox_id,sequence,null]))? {
        return Err(CommunicationError);
    }
    if value.get("terminal_reason").is_some() {
        exact(value,&["sequence","delivery_id","kind","created_at","event_source_sequence","terminal_reason"])?;
        if !["WORKSPACE_INFORMATION_HIDDEN","SUBSCRIPTION_STOPPED","SOURCE_WITHDRAWN","MEMBERSHIP_CHANGED","ACCESS_EXPIRED"].contains(&text(value,"terminal_reason")?.as_str()) {
            return Err(CommunicationError);
        }
    } else {
        exact(value,&["sequence","delivery_id","kind","created_at","event_source_sequence","event","event_receipt"])?;
        let event=value.get("event").ok_or(CommunicationError)?;
        exact(event,&["format","event_id","workspace_id","sequence","kind","actor_id","instance_id","execution_context_id","protocol_digest","observed_at","summary","record_refs","source"])?;
        if text(event,"format")? != FORMAT || text(event,"workspace_id")? != pins.workspace_id
            || number(event,"sequence")? != sequence
            || !KINDS.contains(&text(event,"kind")?.as_str())
            || text(event,"event_id")? != id(json!(["peerwork.event.v1",pins.workspace_id,sequence]))?
            || number(value,"created_at")? != number(event,"observed_at")? {
            return Err(CommunicationError);
        }
        token_field(event,"actor_id")?;
        for field in ["instance_id","execution_context_id"] {
            if event.get(field)!=Some(&WireValue::Null) { token_field(event,field)?; }
        }
        if event.get("protocol_digest")!=Some(&WireValue::Null) && !digest(&text(event,"protocol_digest")?) {
            return Err(CommunicationError);
        }
        if !matches!(event.get("summary"),Some(WireValue::Object(_))) { return Err(CommunicationError); }
        for reference in array(event,"record_refs",8)? {
            exact(reference,&["record_id","revision","schema"])?;
            token_field(reference,"record_id")?;
            if number(reference,"revision")?==0 || text(reference,"schema")?.is_empty() || text(reference,"schema")?.len()>120 { return Err(CommunicationError); }
        }
        let source=event.get("source").ok_or(CommunicationError)?;
        exact(source,&["command_id","intent_digest","origin"])?;
        token_field(source,"command_id")?;
        if !digest(&text(source,"intent_digest")?) || !["AUTHOR_COMMAND","SERVICE_OBSERVATION"].contains(&text(source,"origin")?.as_str()) { return Err(CommunicationError); }
        let proof=verify_typed(&text(value,"event_receipt")?,RECEIPT_TYPE,key)?;
        exact(&proof,&["v","audience","workspace_id","event_id","event_sequence","event_digest","accepted_at"])?;
        if number(&proof,"v")?!=1
            || proof.get("audience").and_then(WireValue::as_utf16)!=Some(audience)
            || proof.get("workspace_id")!=event.get("workspace_id") || proof.get("event_id")!=event.get("event_id")
            || number(&proof,"event_sequence")?!=sequence || number(&proof,"accepted_at")?!=number(event,"observed_at")?
            || text(&proof,"event_digest")?!=sha256_hex(canonical_wire_value(event,Path::STRUCTURED).map_err(|_|CommunicationError)?.as_bytes()) {
            return Err(CommunicationError);
        }
    }
    Ok(VerifiedDelivery { envelope:value.clone(), message:None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer,SigningKey};

    fn wire(value:&serde_json::Value)->WireValue {
        parse_wire_json_bounded(value.to_string().as_bytes(),32,4096).unwrap()
    }
    fn fixture()->(serde_json::Value,MailboxPins,String) {
        let key=SigningKey::from_bytes(&[19;32]);let public=base64url(key.verifying_key().as_bytes());
        let pins=MailboxPins{workspace_id:"W".repeat(43),mailbox_id:"M".repeat(43),membership_id:"G".repeat(43),receiver_id:"R".repeat(43),epoch:1,destination_digest:"d".repeat(64),binding_version:1,after_sequence:0,after_control_sequence:None};
        let event=json!({"format":FORMAT,"event_id":id(json!(["peerwork.event.v1",pins.workspace_id,12])).unwrap(),"workspace_id":pins.workspace_id,"sequence":12,"kind":"structure.protocol.upgraded","actor_id":"A".repeat(43),"instance_id":"I".repeat(43),"execution_context_id":"I".repeat(43),"protocol_digest":"a".repeat(64),"observed_at":1000,"summary":{"default_revision":2},"record_refs":[],"source":{"command_id":"C".repeat(43),"intent_digest":"b".repeat(64),"origin":"AUTHOR_COMMAND"}});
        let proof=json!({"v":1,"audience":"unit","workspace_id":pins.workspace_id,"event_id":event["event_id"],"event_sequence":12,"event_digest":sha256_hex(canonical_wire_value(&wire(&event),Path::STRUCTURED).unwrap().as_bytes()),"accepted_at":1000});
        let header=base64url(json!({"alg":"EdDSA","typ":RECEIPT_TYPE,"kid":public}).to_string().as_bytes());let body=base64url(proof.to_string().as_bytes());let input=format!("{header}.{body}");let receipt=format!("{input}.{}",base64url(&key.sign(input.as_bytes()).to_bytes()));
        let envelope=json!({"sequence":1,"delivery_id":id(json!(["peerwork.delivery.v1",pins.workspace_id,pins.mailbox_id,12,null])).unwrap(),"kind":"BUSINESS","created_at":1000,"event_source_sequence":12,"event":event,"event_receipt":receipt});
        (envelope,pins,public)
    }
    #[test]
    fn pinned_event_rejects_payload_substitution_wrong_recipient_and_wrong_service_key() {
        let (value,pins,key)=fixture();let audience="unit".encode_utf16().collect::<Vec<_>>();
        assert!(delivery(&wire(&value),&audience,&pins,&key).is_ok());
        let mut modified=value.clone();modified["event"]["summary"]["default_revision"]=json!(9);
        assert!(delivery(&wire(&modified),&audience,&pins,&key).is_err());
        let mut other=pins.clone();other.mailbox_id="N".repeat(43);
        assert!(delivery(&wire(&value),&audience,&other,&key).is_err());
        let other_key=base64url(SigningKey::from_bytes(&[20;32]).verifying_key().as_bytes());
        assert!(delivery(&wire(&value),&audience,&pins,&other_key).is_err());
    }
}
