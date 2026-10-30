//! Exact-byte kernel receipt verification with lossless JavaScript strings.

use crate::{
    canonical::Path,
    crypto::{decode_base64url, sha256_hex, verifying_key},
    prepared_command::{verify_structure_author_intent, VerifiedPreparedCommand, VerifiedStructureAuthorIntent},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signature, Verifier};
use thiserror::Error;

const RECEIPT_TYPE: &str = "peerwork.kernel-receipt.v1+jws";

#[derive(Debug, Clone)]
pub struct WireReceiptExpectation<'a> {
    pub audience_utf16: &'a [u16],
    pub receipt_key_id: &'a str,
    pub actor_id: &'a str,
    pub command_id: &'a str,
    pub intent_digest: &'a str,
    pub workspace_id: Option<&'a str>,
    pub protocol_digest: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct VerifiedCommandResponse {
    command_id: String,
    actor_id: String,
    intent_digest: String,
    receipt_key_id: String,
    audience_utf16: Vec<u16>,
    workspace_id: Option<String>,
    protocol_digest: Option<String>,
    result_digest: String,
    result_canonical_json: String,
    event_sequence: Option<u64>,
    instance_revision: Option<u64>,
}

impl VerifiedCommandResponse {
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
    pub fn receipt_key_id(&self) -> &str {
        &self.receipt_key_id
    }
    pub fn audience_utf16(&self) -> &[u16] {
        &self.audience_utf16
    }
    pub fn workspace_id(&self) -> Option<&str> {
        self.workspace_id.as_deref()
    }
    pub fn protocol_digest(&self) -> Option<&str> {
        self.protocol_digest.as_deref()
    }
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
    /// Lossless, kernel-canonical JSON for the digest-bound result. This may
    /// contain escaped lone UTF-16 surrogates; consumers must keep it as wire
    /// JSON until mapping an audited response DTO.
    pub fn result_canonical_json(&self) -> &str {
        &self.result_canonical_json
    }
    pub fn event_sequence(&self) -> Option<u64> {
        self.event_sequence
    }
    pub fn instance_revision(&self) -> Option<u64> {
        self.instance_revision
    }
}

#[derive(Debug, Error)]
pub enum VerifyWireReceiptError {
    #[error("receipt or result wire format invalid")]
    Invalid,
    #[error("receipt does not bind the expected command and result")]
    Mismatch,
}

pub fn verify_command_response_wire(
    jws: &str,
    result_wire: &[u8],
    expected: &WireReceiptExpectation<'_>,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    verify_command_response_with_path(jws, result_wire, expected, Path::KERNEL)
}

fn verify_command_response_with_path(
    jws: &str,
    result_wire: &[u8],
    expected: &WireReceiptExpectation<'_>,
    result_path: Path,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    if jws.len() > 250_000 {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let header = decode_part(parts[0], 256)?;
    if header.object_len() != Some(3)
        || ascii_field(&header, "alg") != Some("EdDSA".into())
        || ascii_field(&header, "typ") != Some(RECEIPT_TYPE.into())
        || ascii_field(&header, "kid") != Some(expected.receipt_key_id.into())
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let sig: [u8; 64] = decode_base64url(parts[2])
        .map_err(|_| VerifyWireReceiptError::Invalid)?
        .try_into()
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let key =
        verifying_key(expected.receipt_key_id).map_err(|_| VerifyWireReceiptError::Invalid)?;
    key.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let receipt = decode_part(parts[1], 180_000)?;
    if receipt.object_len() != Some(11)
        || ![
            "v",
            "audience",
            "actor_id",
            "workspace_id",
            "command_id",
            "intent_digest",
            "result_digest",
            "protocol_digest",
            "event_sequence",
            "instance_revision",
            "accepted_at",
        ]
        .iter()
        .all(|field| receipt.get(field).is_some())
        || number(&receipt, "v") != Some(1)
        || !receipt
            .get("audience")
            .and_then(WireValue::as_utf16)
            .is_some_and(|value| value == expected.audience_utf16)
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    if ascii_field(&receipt, "actor_id").as_deref() != Some(expected.actor_id)
        || ascii_field(&receipt, "command_id").as_deref() != Some(expected.command_id)
        || ascii_field(&receipt, "intent_digest").as_deref() != Some(expected.intent_digest)
        || !optional_field_equals(&receipt, "workspace_id", expected.workspace_id)
        || !optional_field_equals(&receipt, "protocol_digest", expected.protocol_digest)
    {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    let digest = ascii_field(&receipt, "result_digest").ok_or(VerifyWireReceiptError::Invalid)?;
    if !valid_token(expected.actor_id)
        || !valid_token(expected.command_id)
        || !valid_token(expected.receipt_key_id)
        || !valid_digest(expected.intent_digest)
        || !valid_digest(&digest)
        || !expected.workspace_id.is_none_or(valid_token)
        || !expected.protocol_digest.is_none_or(valid_digest)
        || number(&receipt, "accepted_at").is_none()
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let sequence = optional_number(&receipt, "event_sequence")?;
    let revision = optional_number(&receipt, "instance_revision")?;
    let result = parse_wire_json_bounded(result_wire, result_path.kernel_bounds().unwrap().0, 32 * 1024 * 1024)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    if result.object_len().is_none() {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let canonical =
        canonical_wire_value(&result, result_path).map_err(|_| VerifyWireReceiptError::Invalid)?;
    if sha256_hex(canonical.as_bytes()) != digest
        || optional_number(&result, "event_sequence")? != sequence
        || optional_number(&result, "revision")? != revision
    {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    Ok(VerifiedCommandResponse {
        command_id: expected.command_id.into(),
        actor_id: expected.actor_id.into(),
        intent_digest: expected.intent_digest.into(),
        receipt_key_id: expected.receipt_key_id.into(),
        audience_utf16: expected.audience_utf16.into(),
        workspace_id: expected.workspace_id.map(str::to_owned),
        protocol_digest: expected.protocol_digest.map(str::to_owned),
        result_digest: digest,
        result_canonical_json: canonical,
        event_sequence: sequence,
        instance_revision: revision,
    })
}

/// Verify a complete HTTP response body without converting its result through
/// Rust `String`/`serde_json::Value`. A runtime may mark a kernel intent accepted
/// only after this returns successfully for its stored command expectation.
pub fn verify_http_response_wire(
    response_wire: &[u8],
    expected: &WireReceiptExpectation<'_>,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    verify_http_response_with_path(response_wire, expected, Path::KERNEL)
}

pub(crate) fn verify_http_response_with_path(
    response_wire: &[u8],
    expected: &WireReceiptExpectation<'_>,
    result_path: Path,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    let response = parse_wire_json_bounded(response_wire, result_path.kernel_bounds().unwrap().0 + 1, 32 * 1024 * 1024)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    if response.object_len() != Some(3)
        || !["command_id", "receipt", "result"]
            .iter()
            .all(|field| response.get(field).is_some())
        || ascii_field(&response, "command_id").as_deref() != Some(expected.command_id)
    {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let jws = ascii_field(&response, "receipt").ok_or(VerifyWireReceiptError::Invalid)?;
    let result = response
        .get("result")
        .ok_or(VerifyWireReceiptError::Invalid)?;
    let result_wire =
        canonical_wire_value(result, result_path).map_err(|_| VerifyWireReceiptError::Invalid)?;
    verify_command_response_with_path(&jws, result_wire.as_bytes(), expected, result_path)
}

/// Bind a response to a locally authenticated exact signed command. The
/// receipt authority key must come from the caller's pinned discovery.
pub fn verify_http_response_for_prepared(
    response_wire: &[u8],
    prepared: &VerifiedPreparedCommand,
    receipt_key_id: &str,
) -> Result<VerifiedCommandResponse, VerifyWireReceiptError> {
    let command = parse_wire_json_bounded(prepared.command_canonical_json().as_bytes(), 40, 180_000)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let structured = command.get("action_id").and_then(WireValue::as_string)
        .is_some_and(|action| crate::structure_execution::is_structure_action(&action))
        && command.get("body").and_then(|body| body.get("profile")).and_then(WireValue::as_string).as_deref()
            == Some(crate::structure_execution::PROFILE);
    let result_path = if structured { Path::STRUCTURED } else { Path::KERNEL };
    let response = parse_wire_json_bounded(response_wire, result_path.kernel_bounds().unwrap().0 + 1, 32 * 1024 * 1024)
        .map_err(|_| VerifyWireReceiptError::Invalid)?;
    let result = response
        .get("result")
        .ok_or(VerifyWireReceiptError::Invalid)?;
    if structured && (result.get("profile").and_then(WireValue::as_string).as_deref() != Some(crate::structure_execution::PROFILE)
        || result.get("assurance").and_then(WireValue::as_string).as_deref() != Some("BACKEND_CURRENT_STATE")) {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    let workspace = result_string_or_fallback(result, "workspace_id", prepared.workspace_id())?;
    let protocol =
        result_string_or_fallback(result, "protocol_digest", prepared.protocol_digest())?;
    if structured && (prepared.workspace_id().is_some_and(|expected| workspace.as_deref() != Some(expected))
        || prepared.protocol_digest().is_some_and(|expected| protocol.as_deref() != Some(expected))) {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    // A renewed authorization can recover the original immutable outcome. The
    // service receipt still binds the exact original signed bytes; independently
    // verify those bytes and require the same business intent before accepting.
    // Record reads carry another actor's author_intent and must never enter this
    // mutation-only path. Legacy receipts remain strictly byte-bound.
    let original = if structured && crate::structure_execution::is_structure_mutation(prepared.action_id()) {
        result.get("author_intent").map(|value| {
            let jws = value.as_string().ok_or(VerifyWireReceiptError::Invalid)?;
            verify_original_structure_intent(&jws, prepared)
        }).transpose()?
    } else { None };
    let receipt_intent_digest = original.as_ref().map(|author|author.intent_digest()).unwrap_or_else(||prepared.intent_digest());
    let verified = verify_http_response_with_path(
        response_wire,
        &WireReceiptExpectation {
            audience_utf16: prepared.audience_utf16(),
            receipt_key_id,
            actor_id: prepared.actor_id(),
            command_id: prepared.command_id(),
            intent_digest: receipt_intent_digest,
            workspace_id: workspace.as_deref(),
            protocol_digest: protocol.as_deref(),
        },
        result_path,
    )?;
    let terminal=structured&&verify_structure_terminal(result,prepared)?;
    if structured && !terminal && command.get("action_id").and_then(WireValue::as_string).as_deref() == Some("structure.operation.get") {
        verify_structure_lookup(result, &command, prepared, receipt_key_id)?;
    }
    if structured && !terminal { verify_structure_read_authors(result, &command, prepared)?; crate::communication::verify_read(result,&command,prepared,receipt_key_id).map_err(|_| VerifyWireReceiptError::Mismatch)?; }
    Ok(verified)
}

/// Terminal observations have a deliberately small schema. They cannot carry
/// records/state while bypassing the normal selected-author checks.
fn verify_structure_terminal(result:&WireValue,prepared:&VerifiedPreparedCommand)->Result<bool,VerifyWireReceiptError>{
    let invalid=||VerifyWireReceiptError::Mismatch;
    // A lookup can wrap the original operation's rejection; verify that full
    // nested receipt instead of treating the observation as a direct refusal.
    if prepared.action_id()=="structure.operation.get"&&result.get("response").is_some(){return Ok(false);}
    let status=ascii_field(result,"status");let committed=status.as_deref()==Some("COMMITTED_RESULT_UNAVAILABLE");
    if !committed&&status.as_deref()!=Some("REJECTED_NO_EFFECT"){return Ok(false);}
    let allowed=["profile","assurance","workspace_id","instance_id","protocol_digest","status","effect_certainty","error","author_intent"];
    let WireValue::Object(fields)=result else{return Err(invalid());};
    if fields.iter().any(|(key,_)|!allowed.iter().any(|name|key.iter().copied().eq(name.encode_utf16()))){return Err(invalid());}
    if committed&&(!crate::structure_execution::is_structure_mutation(prepared.action_id())||ascii_field(result,"effect_certainty").as_deref()!=Some("COMMITTED"))
        ||!committed&&result.get("effect_certainty").is_some_and(|v|v.as_string().as_deref()!=Some("NOT_APPLIED")){return Err(invalid());}
    let error=result.get("error").ok_or_else(invalid)?;let WireValue::Object(error_fields)=error else{return Err(invalid());};
    if error_fields.iter().any(|(key,_)|!["phase","code","http_status","retryable","recovery"].iter().any(|name|key.iter().copied().eq(name.encode_utf16())))
        ||error.get("retryable")!=Some(&WireValue::Bool(false)){return Err(invalid());}
    let phase=ascii_field(error,"phase").ok_or_else(invalid)?;
    if !["AUTHORIZATION","VALIDATION","EXECUTION","RESULT_ACCESS"].contains(&phase.as_str()){return Err(invalid());}
    for key in ["code","recovery"]{let value=ascii_field(error,key).ok_or_else(invalid)?;if value.is_empty()||value.len()>100||!value.bytes().all(|b|b.is_ascii_uppercase()||b.is_ascii_digit()||b==b'_'){return Err(invalid());}}
    if error.get("http_status").is_some()&&number(error,"http_status").is_none_or(|v|!(400..=599).contains(&v)){return Err(invalid());}
    if committed&&(phase!="RESULT_ACCESS"||ascii_field(error,"code").as_deref()!=Some("OUTCOME_RECORDED_ACCESS_DENIED")||ascii_field(error,"recovery").as_deref()!=Some("REQUEST_ACCESS_AND_READ_ORIGINAL_OUTCOME")){return Err(invalid());}
    Ok(true)
}

fn source_matches(source:&WireValue,author:&VerifiedStructureAuthorIntent)->bool {
    ascii_field(source,"actor_id").as_deref()==Some(author.actor_id())
        && ascii_field(source,"command_id").as_deref()==Some(author.command_id())
        && ascii_field(source,"intent_digest").as_deref()==Some(author.intent_digest())
}
fn source_author(source:&WireValue,prepared:&VerifiedPreparedCommand)->Result<VerifiedStructureAuthorIntent,VerifyWireReceiptError>{
    let jws=ascii_field(source,"author_intent").ok_or(VerifyWireReceiptError::Mismatch)?;
    let author=verify_structure_author_intent(&jws,prepared.audience_utf16()).map_err(|_|VerifyWireReceiptError::Invalid)?;
    if !source_matches(source,&author)
        || author.workspace_id().is_some_and(|ws|Some(ws)!=prepared.workspace_id())
        || author.workspace_id().is_none()&&author.action_id()!="structure.workspace.create" {return Err(VerifyWireReceiptError::Mismatch);}
    Ok(author)
}
fn record_author(record:&WireValue,author:&VerifiedStructureAuthorIntent,command:&WireValue,prepared:&VerifiedPreparedCommand)->Result<(),VerifyWireReceiptError>{
    let invalid=||VerifyWireReceiptError::Mismatch;
    let source=record.get("source").ok_or_else(invalid)?;
    if !source_matches(source,author)||!matches!(author.action_id(),"structure.action"|"structure.checkpoint.records")||author.workspace_id()!=prepared.workspace_id()
        ||author.protocol_digest()!=prepared.protocol_digest()||author.command().get("instance_id")!=command.get("instance_id") {return Err(invalid());}
    let query=command.get("body").ok_or_else(invalid)?;
    if matches!(prepared.action_id(),"structure.record.get"|"structure.publication.prepare.get") && (record.get("record_id")!=query.get("record_id")||record.get("revision")!=query.get("revision")){return Err(invalid());}
    if query.get("schema").is_some_and(|schema|matches!(schema,WireValue::String(_))&&record.get("schema")!=Some(schema)){return Err(invalid());}
    let index=number(source,"record_index").filter(|i|*i<8).ok_or_else(invalid)?;
    let body=author.command().get("body").ok_or_else(invalid)?;
    let original_time=if author.action_id()=="structure.action"{crate::document_time::for_command(author.command(),index).map_err(|_|invalid())?}else{None};
    if !crate::document_time::matches_claim(source.get("document_time"),original_time.as_ref()){return Err(invalid());}
    if author.action_id()=="structure.checkpoint.records" {
        let Some(WireValue::Array(records))=body.get("records")else{return Err(invalid());};
        let selected=records.get(index as usize).ok_or_else(invalid)?;
        if records.len()>8||ascii_field(body,"action_id").as_deref()!=Some("checkpoint.import")
            ||ascii_field(source,"assurance").as_deref()!=Some("OWNER_ATTESTED_CONVERSION")
            ||["record_id","entity_id","revision","schema","structure"].iter().any(|field|!same_checkpoint_value(record.get(field),selected.get(field)))
            ||!same_checkpoint_value(source.get("legacy_source"),selected.get("legacy_source")) {return Err(invalid());}
    }
    let mut public_statement=None;
    if let Some(publication)=body.get("publication"){
        if author.action_id()!="structure.action"||ascii_field(publication,"disclosure").as_deref()!=Some("PUBLISH_ACTION_AND_SELECTED_RECORDS"){return Err(invalid());}
        let Some(WireValue::Array(entries))=publication.get("entries")else{return Err(invalid());};if entries.is_empty()||entries.len()>8{return Err(invalid());}
        let mut seen=std::collections::BTreeSet::new();for entry in entries{let at=number(entry,"record_index").filter(|i|*i<8).ok_or_else(invalid)?;if !seen.insert(at){return Err(invalid());}if at==index{let statement=entry.get("statement").ok_or_else(invalid)?;crate::public_output::for_command(statement,author.command(),index).map_err(|_|invalid())?;public_statement=Some(statement);}}
        if body.get("contents").is_some_and(|v|!matches!(v,WireValue::Array(items) if items.is_empty())){return Err(invalid());}
    }
    if record.get("public_statement").unwrap_or(&WireValue::Null)!=public_statement.unwrap_or(&WireValue::Null){return Err(invalid());}
    let mut expected=None;let mut indices=std::collections::BTreeSet::new();
    if let Some(contents)=body.get("contents"){
        let WireValue::Array(contents)=contents else{return Err(invalid());};if contents.len()>8{return Err(invalid());}
        for item in contents{
            let at=number(item,"record_index").filter(|i|*i<8).ok_or_else(invalid)?;
            if !indices.insert(at){return Err(invalid());}
            if at==index{expected=Some(item.get("body").ok_or_else(invalid)?);}
        }
    }
    let actual=record.get("sealed_content").ok_or_else(invalid)?;
    if let Some(expected)=expected {
        if canonical_wire_value(expected,Path::KERNEL).map_err(|_|invalid())?!=canonical_wire_value(actual,Path::KERNEL).map_err(|_|invalid())? {return Err(invalid());}
    }else if !matches!(actual,WireValue::Null){return Err(invalid());}
    Ok(())
}
fn same_checkpoint_value(left:Option<&WireValue>,right:Option<&WireValue>)->bool{
    match(left,right){(Some(left),Some(right))=>match(canonical_wire_value(left,Path::KERNEL),canonical_wire_value(right,Path::KERNEL)){
        (Ok(left),Ok(right))=>left==right,_=>false,
    },_=>false}
}
fn verify_workspace_deletion(job:&WireValue,result:&WireValue,command:&WireValue,prepared:&VerifiedPreparedCommand,listing:bool)->Result<(),VerifyWireReceiptError>{
    let invalid=||VerifyWireReceiptError::Mismatch;
    let workspace=ascii_field(job,"workspace_id").filter(|v|valid_token(v)).ok_or_else(invalid)?;
    let owner=ascii_field(job,"owner_id").ok_or_else(invalid)?;
    let id=ascii_field(job,"command_id").filter(|v|valid_token(v)).ok_or_else(invalid)?;
    let status=ascii_field(job,"status").ok_or_else(invalid)?;
    let created=number(job,"created_at").ok_or_else(invalid)?;
    if owner!=prepared.actor_id()||!listing&&Some(workspace.as_str())!=prepared.workspace_id()
        ||ascii_field(job,"kind").as_deref()!=Some("WORKSPACE_DELETE")||ascii_field(job,"job_id").as_deref()!=Some(id.as_str())
        ||!matches!(status.as_str(),"ORDERED"|"APPLIED"|"VERIFICATION_BLOCKED")||number(job,"removed_rows").is_none()
        ||status=="APPLIED"&&(ascii_field(job,"phase").as_deref()!=Some("DONE")||number(job,"completed_at").is_none_or(|time|time<created))
        ||status=="ORDERED"&&!matches!(job.get("completed_at"),Some(WireValue::Null))
        ||status!="APPLIED"&&ascii_field(job,"phase").as_deref()==Some("DONE"){return Err(invalid());}
    let initial=prepared.action_id()=="structure.workspace.delete";
    if initial&&id!=prepared.command_id()||!initial&&!listing&&command.get("body").and_then(|b|ascii_field(b,"command_id")).as_deref()!=Some(id.as_str()){return Err(invalid());}
    let author=if initial{
        verify_original_structure_intent(&ascii_field(result,"author_intent").ok_or_else(invalid)?,prepared)?
    }else{
        let source=job.get("source").ok_or_else(invalid)?;
        if matches!(source,WireValue::Null){return if status=="VERIFICATION_BLOCKED"&&ascii_field(job,"source_verification").as_deref()==Some("BLOCKED"){Ok(())}else{Err(invalid())};}
        let proof=verify_structure_author_intent(&ascii_field(source,"author_intent").ok_or_else(invalid)?,prepared.audience_utf16()).map_err(|_|VerifyWireReceiptError::Invalid)?;
        if !source_matches(source,&proof){return Err(invalid());}proof
    };
    let original=author.command();let body=original.get("body").ok_or_else(invalid)?;
    if author.action_id()!="structure.workspace.delete"||author.actor_id()!=owner||author.workspace_id()!=Some(workspace.as_str())
        ||author.protocol_digest().is_some()||!matches!(original.get("instance_id"),Some(WireValue::Null))
        ||ascii_field(body,"confirm_workspace_id").as_deref()!=Some(workspace.as_str())
        ||author.command_id()!=id||ascii_field(job,"intent_digest").as_deref()!=Some(author.intent_digest())
        ||job.get("base_revision")!=original.get("expected_workspace_revision") {return Err(invalid());}
    Ok(())
}

fn verify_structure_read_authors(result:&WireValue,command:&WireValue,prepared:&VerifiedPreparedCommand)->Result<(),VerifyWireReceiptError>{
    let invalid=||VerifyWireReceiptError::Mismatch;
    match prepared.action_id(){
        "structure.workspace.delete"|"structure.workspace.deletion.get"=>{
            if ascii_field(result,"status").as_deref()==Some("REJECTED_NO_EFFECT"){return Ok(());}
            verify_workspace_deletion(result.get("deletion").ok_or_else(invalid)?,result,command,prepared,false)
        },
        "structure.workspace.deletions.read"=>{
            let WireValue::Array(jobs)=result.get("deletions").ok_or_else(invalid)? else{return Err(invalid());};
            if jobs.len()>32||prepared.workspace_id().is_some(){return Err(invalid());}
            let mut previous:Option<String>=None;for job in jobs{
                let workspace=ascii_field(job,"workspace_id").ok_or_else(invalid)?;if previous.as_ref().is_some_and(|old|old>=&workspace){return Err(invalid());}previous=Some(workspace);
                if command.get("body").and_then(|b|ascii_field(b,"view")).as_deref()!=Some("HISTORY")&&ascii_field(job,"status").as_deref()==Some("APPLIED"){return Err(invalid());}
                verify_workspace_deletion(job,result,command,prepared,true)?;
            }Ok(())
        },
        "structure.operations.read"=>verify_structure_operations(result,command,prepared),
        "structure.maintenance.rebuild"|"structure.maintenance.get"|"structure.maintenance.cancel"=>verify_structure_maintenance(result,command,prepared),
        "structure.publication.policy.get"=>{
            let policy=result.get("policy").ok_or_else(invalid)?;if matches!(policy,WireValue::Null){return Ok(());}
            let author=source_author(policy.get("source").ok_or_else(invalid)?,prepared)?;let body=author.command().get("body").ok_or_else(invalid)?;
            if author.action_id()!="structure.publication.policy.set"||author.workspace_id()!=prepared.workspace_id()||author.protocol_digest()!=prepared.protocol_digest()||author.command().get("instance_id")!=command.get("instance_id")||number(body,"expected_policy_revision").and_then(|v|v.checked_add(1))!=number(policy,"revision")||body.get("state")!=policy.get("state")||body.get("actions")!=policy.get("actions"){return Err(invalid());}Ok(())
        },
        "structure.record.get"|"structure.publication.prepare.get"=>{
            let metadata=result.get("source").ok_or_else(invalid)?;
            let mut source=Vec::new();for field in ["actor_id","command_id","intent_digest"]{source.push((field.encode_utf16().collect(),metadata.get(field).cloned().ok_or_else(invalid)?));}
            source.push(("author_intent".encode_utf16().collect(),result.get("author_intent").cloned().ok_or_else(invalid)?));
            record_author(result,&source_author(&WireValue::Object(source),prepared)?,command,prepared)
        }
        action @ ("structure.records.read"|"structure.events.read")=>{
            let WireValue::Object(sources)=result.get("sources").ok_or_else(invalid)? else{return Err(invalid());};
            let WireValue::Array(items)=result.get(if action=="structure.records.read"{"records"}else{"events"}).ok_or_else(invalid)? else{return Err(invalid());};
            if sources.len()>32||items.len()>32||prepared.workspace_id().is_none(){return Err(invalid());}
            let mut authors=std::collections::BTreeMap::new();
            for (name,source) in sources{
                let name=String::from_utf16(name).map_err(|_|invalid())?;let author=source_author(source,prepared)?;
                let expected=if action=="structure.events.read" {
                    crate::crypto::sha256_hex(format!(r#"["{}","{}","{}"]"#,author.actor_id(),author.workspace_id().unwrap_or("-"),author.command_id()).as_bytes())
                }else{format!("{}:{}",author.actor_id(),author.command_id())};
                if name!=expected{return Err(invalid());}
                authors.insert(name,author);
            }
            let mut used=std::collections::BTreeSet::new();
            for item in items{
                let source_key=ascii_field(item,"source_key").ok_or_else(invalid)?;
                let author=authors.get(&source_key).ok_or_else(invalid)?;used.insert(source_key);
                if action=="structure.records.read" {record_author(item,author,command,prepared)?;}
                else if ascii_field(item,"actor_id").as_deref()!=Some(author.actor_id())
                    ||item.get("summary").and_then(|s|ascii_field(s,"action_id")).as_deref()!=Some(author.action_id()){return Err(invalid());}
                else if command.get("instance_id").is_some_and(|id|!matches!(id,WireValue::Null))
                    && (item.get("instance_id")!=command.get("instance_id")
                        ||author.action_id()!="structure.adopt"&&(author.command().get("instance_id")!=command.get("instance_id")||author.protocol_digest()!=prepared.protocol_digest())){return Err(invalid());}
            }
            if used.len()!=authors.len(){return Err(invalid());}
            Ok(())
        }
        _=>Ok(()),
    }
}

fn verify_structure_maintenance(result:&WireValue,command:&WireValue,prepared:&VerifiedPreparedCommand)->Result<(),VerifyWireReceiptError>{
    let invalid=||VerifyWireReceiptError::Mismatch;
    if ascii_field(result,"status").as_deref()==Some("REJECTED_NO_EFFECT") && result.get("maintenance").is_none(){return Ok(());}
    let job=result.get("maintenance").ok_or_else(invalid)?;
    let listing=prepared.action_id()=="structure.operations.read";
    let id=ascii_field(job,"job_id").filter(|s|valid_token(s)).ok_or_else(invalid)?;
    let status=ascii_field(job,"status").ok_or_else(invalid)?;let state=ascii_field(job,"state").ok_or_else(invalid)?;
    if ascii_field(job,"kind").as_deref()!=Some("CURRENT_RECORDS")
        ||!matches!(status.as_str(),"ORDERED"|"APPLIED"|"REJECTED_NO_EFFECT"|"VERIFICATION_BLOCKED")
        ||!matches!(state.as_str(),"BUILDING"|"CLEANUP"|"DONE"|"BLOCKED")
        ||state=="BLOCKED"&&status!="VERIFICATION_BLOCKED"
        ||(status=="ORDERED")!=(state=="BUILDING") {return Err(invalid());}
    if !listing&&prepared.action_id()!="structure.maintenance.rebuild" && command.get("body").and_then(|b|ascii_field(b,"job_id")).as_deref()!=Some(id.as_str()){return Err(invalid());}
    if ascii_field(job,"workspace_id").as_deref()!=prepared.workspace_id()
        ||!listing&&(job.get("instance_id")!=command.get("instance_id")||ascii_field(job,"protocol_digest").as_deref()!=prepared.protocol_digest()){return Err(invalid());}
    let author=if prepared.action_id()=="structure.maintenance.rebuild" {
        let text=ascii_field(result,"author_intent").ok_or_else(invalid)?;
        verify_original_structure_intent(&text,prepared)?
    }else{
        let source=job.get("source").ok_or_else(invalid)?;
        if matches!(source,WireValue::Null){
            return if status=="VERIFICATION_BLOCKED"&&state!="BUILDING"{Ok(())}else{Err(invalid())};
        }
        source_author(source,prepared)?
    };
    let original=author.command();let body=original.get("body").ok_or_else(invalid)?;
    if author.action_id()!="structure.maintenance.rebuild"||author.workspace_id()!=prepared.workspace_id()
        ||!listing&&(author.protocol_digest()!=prepared.protocol_digest()||original.get("instance_id")!=command.get("instance_id"))
        ||job.get("instance_id")!=original.get("instance_id")
        ||ascii_field(job,"actor_id").as_deref()!=Some(author.actor_id())||ascii_field(job,"command_id").as_deref()!=Some(author.command_id())
        ||ascii_field(job,"intent_digest").as_deref()!=Some(author.intent_digest())||ascii_field(job,"protocol_digest").as_deref()!=author.protocol_digest()
        ||job.get("base_revision")!=original.get("expected_instance_revision")||job.get("base_event_revision")!=body.get("expected_event_revision")
        ||ascii_field(job,"target_generation").as_deref()!=Some(id.as_str()) {return Err(invalid());}
    let created=number(job,"created_at").ok_or_else(invalid)?;let deadline=number(job,"deadline_at").ok_or_else(invalid)?;
    let ttl=number(body,"ttl_ms").unwrap_or(600_000);
    if !(1000..=600_000).contains(&ttl)||created.checked_add(ttl)!=Some(deadline){return Err(invalid());}
    Ok(())
}

fn verify_structure_operations(result:&WireValue,command:&WireValue,prepared:&VerifiedPreparedCommand)->Result<(),VerifyWireReceiptError>{
    let invalid=||VerifyWireReceiptError::Mismatch;
    let WireValue::Array(items)=result.get("operations").ok_or_else(invalid)? else{return Err(invalid());};
    let WireValue::Object(sources)=result.get("sources").ok_or_else(invalid)? else{return Err(invalid());};
    if items.len()>32||sources.len()>32||prepared.workspace_id().is_none(){return Err(invalid());}
    let body=command.get("body").ok_or_else(invalid)?;
    let mine=ascii_field(body,"scope").as_deref()!=Some("WORKSPACE");let open=ascii_field(body,"view").as_deref()!=Some("HISTORY");
    let mut selected=std::collections::BTreeMap::new();for (key,source) in sources{selected.insert(String::from_utf16(key).map_err(|_|invalid())?,source);}
    let mut used=std::collections::BTreeSet::new();let mut previous=None;
    for item in items{
        let id=ascii_field(item,"job_id").filter(|s|valid_token(s)).ok_or_else(invalid)?;
        if previous.as_ref().is_some_and(|old:&String|old>=&id){return Err(invalid());}previous=Some(id);
        let actor=ascii_field(item,"actor_id").filter(|s|valid_token(s)).ok_or_else(invalid)?;
        let cid=ascii_field(item,"command_id").filter(|s|valid_token(s)).ok_or_else(invalid)?;
        let key=ascii_field(item,"source_key").ok_or_else(invalid)?;let source=*selected.get(&key).ok_or_else(invalid)?;used.insert(key.clone());
        if key!=format!("{actor}:{cid}")||mine&&actor!=prepared.actor_id()||!matches!(item.get("unsettled"),Some(WireValue::Bool(_)))||open&&item.get("unsettled")!=Some(&WireValue::Bool(true))
            ||ascii_field(item,"workspace_id").as_deref()!=prepared.workspace_id()||item.get("source").is_some(){return Err(invalid());}
        if ascii_field(item,"source_verification").as_deref()==Some("BLOCKED"){
            if !matches!(source,WireValue::Null)||ascii_field(item,"status").as_deref()!=Some("VERIFICATION_BLOCKED")
                ||ascii_field(item,"error_code").as_deref()!=Some("STRUCTURE_MAINTENANCE_SOURCE_INVALID")
                ||ascii_field(item,"recovery").as_deref()!=Some("INSPECT_SELECTED_OPERATION")
                ||ascii_field(item,"kind").as_deref()!=Some("CURRENT_RECORDS")
                ||ascii_field(item,"instance_id").is_none_or(|s|!valid_token(&s))
                ||ascii_field(item,"protocol_digest").is_none_or(|s|!valid_digest(&s)){return Err(invalid());}
        }else{
            if ascii_field(item,"source_verification").as_deref()!=Some("VERIFIED")||matches!(source,WireValue::Null){return Err(invalid());}
            let WireValue::Object(mut fields)=item.clone() else{return Err(invalid());};fields.push(("source".encode_utf16().collect(),source.clone()));
            let wrapper=WireValue::Object(vec![("maintenance".encode_utf16().collect(),WireValue::Object(fields))]);
            verify_structure_maintenance(&wrapper,command,prepared)?;
        }
    }
    if used.len()!=selected.len(){return Err(invalid());}Ok(())
}

fn verify_original_structure_intent(jws: &str, prepared: &VerifiedPreparedCommand)
    -> Result<VerifiedStructureAuthorIntent, VerifyWireReceiptError> {
    let original=verify_structure_author_intent(jws,prepared.audience_utf16()).map_err(|_|VerifyWireReceiptError::Invalid)?;
    let business = prepared.structure_business_intent().ok_or(VerifyWireReceiptError::Mismatch)?;
    if original.business_intent_digest().as_deref() != Some(business.as_str()) {
        return Err(VerifyWireReceiptError::Mismatch);
    }
    Ok(original)
}

fn verify_structure_lookup(result: &WireValue, command: &WireValue, prepared: &VerifiedPreparedCommand, receipt_key: &str)
    -> Result<(), VerifyWireReceiptError> {
    let invalid = || VerifyWireReceiptError::Mismatch;
    let body=command.get("body").ok_or_else(invalid)?;
    let command_id=ascii_field(body,"command_id").ok_or_else(invalid)?;
    let exact=ascii_field(body,"intent_digest");let business=ascii_field(body,"business_intent_digest");
    if exact.is_some()==business.is_some(){return Err(invalid());}
    match result.get("status").and_then(WireValue::as_string).as_deref() {
        Some("NOT_FOUND") => {
            let recovery=if business.is_some(){"RESUBMIT_SAME_INTENT"}else{"RESUBMIT_EXACT_INTENT"};
            if result.get("response").is_some()
                || result.get("recovery").and_then(WireValue::as_string).as_deref() != Some(recovery) { return Err(invalid()); }
        }
        Some(status @ ("APPLIED" | "REJECTED_NO_EFFECT" | "ORDERED")) => {
            let response = result.get("response").ok_or_else(invalid)?;
            let inner = response.get("result").ok_or_else(invalid)?;
            let intent_digest=if let Some(expected)=exact {expected} else {
                let jws=ascii_field(inner,"author_intent").ok_or_else(invalid)?;
                let author=verify_structure_author_intent(&jws,prepared.audience_utf16()).map_err(|_|invalid())?;
                if author.actor_id()!=prepared.actor_id()||author.command_id()!=command_id
                    ||author.business_intent_digest()!=business
                    ||prepared.workspace_id().is_some_and(|ws|author.workspace_id()!=Some(ws)){return Err(invalid());}
                author.intent_digest().to_owned()
            };
            if (inner.get("status").and_then(WireValue::as_string).as_deref() == Some("REJECTED_NO_EFFECT")) != (status == "REJECTED_NO_EFFECT") { return Err(invalid()); }
            if (ascii_field(inner,"status").as_deref()==Some("ORDERED"))!=(status=="ORDERED"){return Err(invalid());}
            if inner.get("profile").and_then(WireValue::as_string).as_deref() != Some(crate::structure_execution::PROFILE)
                || inner.get("assurance").and_then(WireValue::as_string).as_deref() != Some("BACKEND_CURRENT_STATE") { return Err(invalid()); }
            let workspace = result_string_or_fallback(inner, "workspace_id", prepared.workspace_id())?;
            let protocol = result_string_or_fallback(inner, "protocol_digest", None)?;
            if prepared.workspace_id().is_some_and(|expected| workspace.as_deref() != Some(expected)) { return Err(invalid()); }
            let wire = canonical_wire_value(response, Path::STRUCTURED).map_err(|_| VerifyWireReceiptError::Invalid)?;
            verify_http_response_with_path(wire.as_bytes(), &WireReceiptExpectation {
                audience_utf16:prepared.audience_utf16(), receipt_key_id:receipt_key, actor_id:prepared.actor_id(),
                command_id:&command_id, intent_digest:&intent_digest, workspace_id:workspace.as_deref(), protocol_digest:protocol.as_deref(),
            }, Path::STRUCTURED)?;
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

fn result_string_or_fallback(
    result: &WireValue,
    field: &str,
    fallback: Option<&str>,
) -> Result<Option<String>, VerifyWireReceiptError> {
    match result.get(field) {
        Some(WireValue::String(units)) => String::from_utf16(units)
            .map(Some)
            .map_err(|_| VerifyWireReceiptError::Invalid),
        _ => Ok(fallback.map(str::to_owned)),
    }
}

fn decode_part(text: &str, max: usize) -> Result<WireValue, VerifyWireReceiptError> {
    if text.is_empty() {
        return Err(VerifyWireReceiptError::Invalid);
    }
    let bytes = decode_base64url(text).map_err(|_| VerifyWireReceiptError::Invalid)?;
    if bytes.len() > max {
        return Err(VerifyWireReceiptError::Invalid);
    }
    parse_wire_json_bounded(&bytes, 16, max).map_err(|_| VerifyWireReceiptError::Invalid)
}
fn ascii_field(value: &WireValue, field: &str) -> Option<String> {
    value.get(field)?.as_string()
}
fn number(value: &WireValue, field: &str) -> Option<u64> {
    let value = value.get(field)?.as_number()?;
    (value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= 9_007_199_254_740_991.0)
        .then_some(value as u64)
}
fn optional_number(value: &WireValue, field: &str) -> Result<Option<u64>, VerifyWireReceiptError> {
    match value.get(field) {
        Some(WireValue::Null) => Ok(None),
        Some(_) => number(value, field)
            .map(Some)
            .ok_or(VerifyWireReceiptError::Invalid),
        None => Ok(None),
    }
}
fn optional_field_equals(value: &WireValue, field: &str, expected: Option<&str>) -> bool {
    match (value.get(field), expected) {
        (Some(WireValue::Null), None) => true,
        (Some(value), Some(expected)) => value.as_string().as_deref() == Some(expected),
        _ => false,
    }
}
fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
