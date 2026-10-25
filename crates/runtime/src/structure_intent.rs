//! One-call intent transport. No business evaluator, history reader or implicit
//! CAS rebase lives here. All retries retain the same logical operation.

use super::*;
use peerwork_core::{
    canonical::Path as CanonicalPath,
    prepared_command::SignedPreparedCommand,
    crypto::{base64url, sha256},
    structure_context::verify_structure_context,
    structure_execution::{is_structure_action, is_structure_mutation, PROFILE},
    wire_json::canonical_wire_value,
};
use rand_core::{OsRng, RngCore};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructureIntentOutcome {
    Accepted(KernelAcceptedResult),
    /// Immutable admission remains separately saved. `result` is a fresh,
    /// independently signed observation; its command ID is not rewritten to
    /// impersonate the original mutation's receipt.
    Completed { command_id: String, result: KernelAcceptedResult },
    Pending {
        command_id: String,
        code: &'static str,
        phase: &'static str,
        retryable: bool,
        recovery: &'static str,
    },
}

fn string(value: &str) -> WireValue { WireValue::String(value.encode_utf16().collect()) }
fn set(value: &mut WireValue, key: &str, field: WireValue) {
    let WireValue::Object(fields) = value else { unreachable!("constructed object"); };
    let name: Vec<u16> = key.encode_utf16().collect();
    if let Some((_, old)) = fields.iter_mut().find(|(k, _)| *k == name) { *old = field; }
    else { fields.push((name, field)); }
}
fn pending(command_id: &str, code: &'static str, phase: &'static str, retryable: bool) -> StructureIntentOutcome {
    StructureIntentOutcome::Pending { command_id: command_id.into(), code, phase, retryable, recovery: "RESUME_SAME_INTENT" }
}

pub(crate) fn keyed_command_id(origin: &str, actor: &str, workspace: WireValue, key: &[u16]) -> Result<String, KernelClientError> {
    if key.is_empty() || key.len() > 128 { return Err(KernelClientError::InvalidCommand); }
    let scope = WireValue::Array(vec![string("peerwork.structure-intent.v1"), string(origin), string(actor), workspace, WireValue::String(key.to_vec())]);
    Ok(base64url(&sha256(canonical_wire_value(&scope, CanonicalPath::COMMAND).map_err(|_| KernelClientError::InvalidCommand)?.as_bytes())))
}

/// Both operands come from core-authenticated canonical commands. Comparing all
/// fields except the two authorization timestamps also covers selected reads;
/// it does not make reads eligible for mutation deduplication or renewal.
fn same_request(a: &VerifiedPreparedCommand, b: &VerifiedPreparedCommand) -> Result<bool, KernelClientError> {
    let mut a = parse_wire_json_bounded(a.command_canonical_json().as_bytes(), 40, 180_000).map_err(|_| KernelClientError::InvalidCommand)?;
    let mut b = parse_wire_json_bounded(b.command_canonical_json().as_bytes(), 40, 180_000).map_err(|_| KernelClientError::InvalidCommand)?;
    for command in [&mut a, &mut b] {
        set(command, "issued_at", WireValue::Number(1.0));
        set(command, "expires_at", WireValue::Number(600_001.0));
    }
    Ok(a == b)
}

impl KernelClient {
    /// A restricted commit acknowledgment closes submission uncertainty. Once
    /// access is restored, fetch the original signed outcome with an indexed
    /// read, without ever posting the mutation again.
    pub(crate) async fn complete_known_structure_outcome(&mut self,identity:&KernelIdentity,authority:&str,outcome:&mut StructureIntentOutcome,cancel:&CancellationToken){
        let StructureIntentOutcome::Accepted(result)=outcome else{return;};if result.outcome_state()!="COMMITTED"{return;}
        let command_id=result.command_id.clone();
        if let Ok(full)=Box::pin(self.read_saved_structure_result(identity,authority,&command_id,cancel)).await{*result=full;}
    }
    /// One indexed observation of the original operation, with full nested
    /// signature validation. No mutation replay or history replay is needed.
    pub(crate) async fn read_saved_structure_result(&mut self,identity:&KernelIdentity,authority:&str,command_id:&str,cancel:&CancellationToken)->Result<KernelAcceptedResult,KernelClientError>{
        tokio::time::timeout(Duration::from_secs(5),async{
            let saved=self.journal.verified_pending(command_id,identity.key_id(),self.discovery.audience_utf16())?.ok_or(KernelClientError::IntentNotFound)?;
            let query=serde_json::json!({"action":"structure.operation.get","workspace_id":saved.proof.workspace_id(),"body":{"command_id":command_id,"business_intent_digest":saved.proof.structure_business_intent().ok_or(KernelClientError::InvalidCommand)?}});
            let observed=Box::pin(self.execute_structure_intent(identity,authority,query.to_string().as_bytes(),cancel)).await?;
            let StructureIntentOutcome::Accepted(observed)=observed else{return Err(KernelClientError::InvalidResult);};
            let value=parse_wire_json_bounded(observed.structure_result_json.as_deref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
            let original=value.get("response").ok_or(KernelClientError::InvalidResult)?;
            let wire=canonical_wire_value(original,CanonicalPath::STRUCTURED).map_err(|_|KernelClientError::InvalidResult)?;
            let proof=self.journal.record_verified_response(&saved,wire.as_bytes(),self.discovery.receipt_public_key())?;
            KernelAcceptedResult::from_verified(proof,&saved.proof,None)
        }).await.map_err(|_|KernelClientError::Transport(TransportError::Timeout))?
    }

    /// Follow an admitted backend job from a fresh local journal. This observes
    /// current authorized progress; it never imports or resubmits its author's
    /// mutation, and does not require the old device's pending state.
    pub async fn follow_structure_operation(&mut self,identity:&KernelIdentity,authority:&str,selection_wire:&[u8],cancel:&CancellationToken)
        ->Result<StructureIntentOutcome,KernelClientError>{
        let selection=parse_wire_json_bounded(selection_wire,12,8192).map_err(|_|KernelClientError::InvalidCommand)?;
        let deletion=selection.get("action").and_then(WireValue::as_string).as_deref()==Some("structure.workspace.deletion.get");
        let phase=if deletion{"DELETION"}else{"MAINTENANCE"};
        if !matches!(selection.get("action").and_then(WireValue::as_string).as_deref(),Some("structure.maintenance.get"|"structure.workspace.deletion.get"))
            ||selection.get("command_id").is_some()||selection.get("idempotency_key").is_some(){return Err(KernelClientError::InvalidCommand);}
        let (mut observed_id,mut template,_)=self.structure_command(identity,authority,selection_wire)?;
        let result=tokio::time::timeout(Duration::from_secs(30),async {
            let initial=self.execute_structure_intent(identity,authority,selection_wire,cancel).await?;
            match initial{
                StructureIntentOutcome::Accepted(result)=>{
                    if result.outcome_state()=="REJECTED"{return Ok(StructureIntentOutcome::Pending{command_id:observed_id.clone(),code:"OBSERVATION_REFUSED",phase:"OBSERVATION",retryable:false,recovery:"OBSERVE_SAME_OPERATION"});}
                    let data=parse_wire_json_bounded(result.structure_result_json.as_ref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
                    let job=data.get(if deletion{"deletion"}else{"maintenance"}).ok_or(KernelClientError::InvalidResult)?;
                    observed_id=job.get("command_id").and_then(WireValue::as_string).ok_or(KernelClientError::InvalidResult)?;
                    if deletion&&job.get("status").and_then(WireValue::as_string).as_deref()==Some("VERIFICATION_BLOCKED"){
                        return Ok(StructureIntentOutcome::Pending{command_id:observed_id.clone(),code:"VERIFICATION_FAILED",phase,retryable:false,recovery:"INSPECT_SELECTED_OPERATION"});
                    }
                    if job.get("status").and_then(WireValue::as_string).as_deref()!=Some("ORDERED"){
                        return Ok(StructureIntentOutcome::Completed{command_id:observed_id.clone(),result});
                    }
                    set(&mut template,"command_id",string(&observed_id));
                    if deletion{self.wait_workspace_deletion(identity,&template,&data,cancel).await}else{self.wait_structure_maintenance(identity,&template,&data,cancel).await}
                },
                other=>Ok(other),
            }
        }).await;
        let outcome=match result{
            Ok(Ok(outcome))=>outcome,
            Err(_)=>pending(&observed_id,"IN_PROGRESS",phase,true),
            Ok(Err(error))=>{
                let (code,retryable)=match error{
                    KernelClientError::Transport(TransportError::Cancelled)=>("CANCELLED",true),
                    KernelClientError::Transport(TransportError::Network|TransportError::Timeout|TransportError::SubmittedUncertain)=>("OUTCOME_UNKNOWN",true),
                    KernelClientError::ServerRejected(429)=>("RATE_LIMITED",true),
                    KernelClientError::ServerRejected(401|403)=>("UNVERIFIED_AUTHORIZATION_RESPONSE",true),
                    KernelClientError::ServerRejected(500..=599)=>("SERVICE_UNAVAILABLE",true),
                    KernelClientError::Store(JournalError::InvalidReceipt)|KernelClientError::InvalidResult=>("VERIFICATION_FAILED",false),
                    other=>return Err(other),
                };pending(&observed_id,code,phase,retryable)
            },
        };
        Ok(match outcome{
            StructureIntentOutcome::Pending{command_id,code,phase,retryable,..}=>StructureIntentOutcome::Pending{command_id,code,phase,retryable,recovery:if code=="VERIFICATION_FAILED"&&!retryable{"INSPECT_SELECTED_OPERATION"}else{"OBSERVE_SAME_OPERATION"}},
            other=>other,
        })
    }
    /// Resume a selected saved operation by ID; callers do not reconstruct its
    /// metadata, ciphertext or business request. Authorization is renewed only
    /// under the same verified business intent and pinned service.
    pub async fn resume_structure_intent(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        command_id: &str,
        cancel: &CancellationToken,
    ) -> Result<StructureIntentOutcome, KernelClientError> {
        self.resume_structure_intent_scoped(identity, authority, command_id, None, cancel).await
    }

    pub(super) async fn resume_saved_structure_intent(
        &mut self, identity: &KernelIdentity, authority: &str, command_id: &str,
        workspace: Option<&str>, cancel: &CancellationToken,
    ) -> Result<StructureIntentOutcome, KernelClientError> {
        let saved=self.journal.verified_pending(command_id,identity.key_id(),self.discovery.audience_utf16())?
            .ok_or(KernelClientError::IntentNotFound)?;
        if workspace.is_some_and(|expected| saved.proof.workspace_id() != Some(expected)) {
            return Err(KernelClientError::InvalidCommand);
        }
        if !is_structure_action(saved.proof.action_id()) {return Err(KernelClientError::InvalidCommand);}
        let command=parse_wire_json_bounded(saved.proof.command_canonical_json().as_bytes(),40,180_000).map_err(|_|KernelClientError::InvalidCommand)?;
        let mut intent=WireValue::Object(Vec::new());
        for field in ["body","workspace_id","instance_id","protocol_digest","expected_workspace_revision","expected_instance_revision","exact_input_refs"] {
            set(&mut intent,field,command.get(field).cloned().ok_or(KernelClientError::InvalidCommand)?);
        }
        set(&mut intent,"action",string(saved.proof.action_id()));set(&mut intent,"command_id",string(command_id));
        let wire=canonical_wire_value(&intent,peerwork_core::prepared_command::command_canonical_path(&intent)).map_err(|_|KernelClientError::InvalidCommand)?;
        Box::pin(self.execute_structure_intent_prepared(identity,authority,wire.as_bytes(),cancel)).await
    }

    /// Execute a bounded business request with SDK-owned signing metadata,
    /// nonce-bound service time, durable intent and at most two POST attempts.
    /// A pending result always names the original saved operation. The caller
    /// can repeat its idempotency key/request or resume the returned command ID.
    pub(super) async fn execute_structure_intent_prepared(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        intent_wire: &[u8],
        cancel: &CancellationToken,
    ) -> Result<StructureIntentOutcome, KernelClientError> {
        let started=Instant::now();
        let (command_id, mut command, durable) = self.structure_command(identity, authority, intent_wire)?;
        let request=parse_wire_json_bounded(intent_wire,38,peerwork_core::structure_content::MAX_BODY_REQUEST_BYTES).map_err(|_|KernelClientError::InvalidCommand)?;
        if request.get("plaintext_contents").is_some() && self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?.is_none(){
            let workspace=required_text(&command,"workspace_id")?;
            Box::pin(self.ensure_structure_content_ready(identity,authority,&workspace,cancel)).await?;
        }
        let mut persisted = self.prepare_plaintext_contents(identity,intent_wire,&mut command,cancel)?;
        let mut phase="SUBMISSION";
        let result = tokio::time::timeout(Duration::from_secs(30),async {
            let outcome=self.drive_structure_intent(identity,command.clone(),durable,&mut persisted,cancel).await?;
            match outcome {
                StructureIntentOutcome::Accepted(result) if command.get("action_id").and_then(WireValue::as_string).as_deref()==Some("structure.workspace.delete")=>{
                    let initial=parse_wire_json_bounded(result.structure_result_json.as_ref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
                    if initial.get("status").and_then(WireValue::as_string).as_deref()!=Some("ORDERED"){return Ok(StructureIntentOutcome::Accepted(result));}
                    phase="DELETION";self.wait_workspace_deletion(identity,&command,&initial,cancel).await
                },
                StructureIntentOutcome::Accepted(result) if command.get("action_id").and_then(WireValue::as_string).as_deref()==Some("structure.maintenance.rebuild")=>{
                    let initial=parse_wire_json_bounded(result.structure_result_json.as_ref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
                    if initial.get("status").and_then(WireValue::as_string).as_deref()!=Some("ORDERED"){return Ok(StructureIntentOutcome::Accepted(result));}
                    phase="MAINTENANCE";self.wait_structure_maintenance(identity,&command,&initial,cancel).await
                },
                other=>Ok(other),
            }
        }).await;
        let mut outcome=match result {
            Ok(Err(error)) if persisted => {
                let (code,retryable)=match error {
                    KernelClientError::Transport(TransportError::Cancelled)=>("CANCELLED",true),
                    KernelClientError::Transport(TransportError::Network|TransportError::Timeout|TransportError::SubmittedUncertain)=>("OUTCOME_UNKNOWN",true),
                    KernelClientError::Store(JournalError::IntentConflict)=>("COMMAND_CONFLICT",false),
                    KernelClientError::Store(JournalError::InvalidReceipt)|KernelClientError::InvalidResult=>("VERIFICATION_FAILED",false),
                    KernelClientError::UnsupportedStructureProfile=>("CAPABILITY_UNAVAILABLE",false),
                    KernelClientError::ServerRejected(429)=>("RATE_LIMITED",true),
                    KernelClientError::ServerRejected(401|403)=>("UNVERIFIED_AUTHORIZATION_RESPONSE",true),
                    KernelClientError::ServerRejected(500..=599)=>("SERVICE_UNAVAILABLE",true),
                    _=>("RECOVERY_FAILED",false),
                };
                Ok(pending(&command_id,code,if phase!="SUBMISSION"{phase}else{"RECOVERY"},retryable))
            }
            Ok(result) => result,
            Err(_) if persisted => Ok(pending(&command_id, if phase!="SUBMISSION"{"IN_PROGRESS"}else{"OUTCOME_UNKNOWN"}, phase, true)),
            Err(_) => Err(TransportError::Timeout.into()),
        }?;
        // A lost POST reply is often resolved by one indexed observation in
        // the same SDK call. NOT_FOUND is not proof of non-commit: preserve the
        // exact pending packet if observation cannot establish a signed result.
        if persisted&&!cancel.is_cancelled()&&started.elapsed()<Duration::from_secs(25)
            &&matches!(&outcome,StructureIntentOutcome::Pending{retryable:true,code,..} if matches!(*code,"OUTCOME_UNKNOWN"|"SERVICE_UNAVAILABLE"|"UNVERIFIED_AUTHORIZATION_RESPONSE"))
            && !matches!(command.get("action_id").and_then(WireValue::as_string).as_deref(),Some("structure.maintenance.rebuild"|"structure.workspace.delete")){
            if let Ok(result)=Box::pin(self.read_saved_structure_result(identity,authority,&command_id,cancel)).await{outcome=StructureIntentOutcome::Accepted(result);}
        }
        Ok(match outcome{
            StructureIntentOutcome::Accepted(mut result)=>{
                let action=command.get("action_id").and_then(WireValue::as_string).ok_or(KernelClientError::InvalidCommand)?;
                self.open_selected_structure_bodies(&mut result,&action,identity.key_id())?;
                StructureIntentOutcome::Accepted(result)
            },other=>other,
        })
    }

    async fn wait_workspace_deletion(&self,identity:&KernelIdentity,original:&WireValue,initial:&WireValue,cancel:&CancellationToken)
        ->Result<StructureIntentOutcome,KernelClientError>{
        let command_id=required_text(original,"command_id")?;
        let initial=initial.get("deletion").ok_or(KernelClientError::InvalidResult)?;
        let context=self.fresh_structure_context(cancel).await?;
        for _ in 0..60 {
            let mut bytes=[0u8;32];OsRng.try_fill_bytes(&mut bytes).map_err(|_|KernelClientError::InvalidCommand)?;
            let mut command=original.clone();set(&mut command,"command_id",string(&base64url(&bytes)));
            set(&mut command,"action_id",string("structure.workspace.deletion.get"));
            set(&mut command,"body",WireValue::Object(vec![("profile".encode_utf16().collect(),string(PROFILE)),("command_id".encode_utf16().collect(),string(&command_id))]));
            set(&mut command,"expected_workspace_revision",WireValue::Null);set(&mut command,"expected_instance_revision",WireValue::Null);set(&mut command,"exact_input_refs",WireValue::Array(Vec::new()));
            set(&mut command,"issued_at",WireValue::Number(context.server_time_ms() as f64));set(&mut command,"expires_at",WireValue::Number(context.expires_at_ms() as f64));
            let signed=prepare_signed_command_wire(&command,identity.signing_key(),&self.discovery,None).map_err(|_|KernelClientError::InvalidCommand)?;
            let result=self.submit_structure_read(&signed,cancel).await?;
            if result.outcome_state()=="REJECTED"{return Ok(StructureIntentOutcome::Pending{command_id,code:"OBSERVATION_REFUSED",phase:"DELETION",retryable:false,recovery:"OBSERVE_SAME_OPERATION"});}
            let data=parse_wire_json_bounded(result.structure_result_json.as_ref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
            let job=data.get("deletion").ok_or(KernelClientError::InvalidResult)?;
            for field in ["workspace_id","owner_id","command_id","intent_digest","base_revision","created_at","job_id","kind"]{
                if job.get(field)!=initial.get(field){return Err(KernelClientError::InvalidResult);}
            }
            match job.get("status").and_then(WireValue::as_string).as_deref(){
                Some("APPLIED")=>return Ok(StructureIntentOutcome::Completed{command_id,result}),
                Some("VERIFICATION_BLOCKED")=>return Ok(StructureIntentOutcome::Pending{command_id,code:"VERIFICATION_FAILED",phase:"DELETION",retryable:false,recovery:"INSPECT_SELECTED_OPERATION"}),
                Some("ORDERED")=>{},_=>return Err(KernelClientError::InvalidResult),
            }
            tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled.into()),_=tokio::time::sleep(Duration::from_millis(250))=>{}}
        }
        Ok(pending(&command_id,"IN_PROGRESS","DELETION",true))
    }

    async fn wait_structure_maintenance(&self,identity:&KernelIdentity,original:&WireValue,initial:&WireValue,cancel:&CancellationToken)
        ->Result<StructureIntentOutcome,KernelClientError>{
        let command_id=original.get("command_id").and_then(WireValue::as_string).ok_or(KernelClientError::InvalidResult)?;
        let initial=initial.get("maintenance").ok_or(KernelClientError::InvalidResult)?;
        let job_id=initial.get("job_id").and_then(WireValue::as_string).ok_or(KernelClientError::InvalidResult)?;
        // One fresh, nonce-bound authorization window covers this bounded wait.
        // Polls are selected reads, never new business authorizations or writes.
        let context=self.fresh_structure_context(cancel).await?;
        for _ in 0..60 {
            let mut bytes=[0u8;32];OsRng.try_fill_bytes(&mut bytes).map_err(|_|KernelClientError::InvalidCommand)?;
            let mut command=original.clone();set(&mut command,"command_id",string(&base64url(&bytes)));
            set(&mut command,"action_id",string("structure.maintenance.get"));
            set(&mut command,"body",WireValue::Object(vec![("profile".encode_utf16().collect(),string(PROFILE)),("job_id".encode_utf16().collect(),string(&job_id))]));
            for field in ["expected_workspace_revision","expected_instance_revision"]{set(&mut command,field,WireValue::Null);}
            set(&mut command,"exact_input_refs",WireValue::Array(Vec::new()));
            set(&mut command,"issued_at",WireValue::Number(context.server_time_ms() as f64));
            set(&mut command,"expires_at",WireValue::Number(context.expires_at_ms() as f64));
            let signed=prepare_signed_command_wire(&command,identity.signing_key(),&self.discovery,None).map_err(|_|KernelClientError::InvalidCommand)?;
            let result=match self.submit_structure_read(&signed,cancel).await {
                Err(KernelClientError::Transport(TransportError::Network|TransportError::Timeout|TransportError::SubmittedUncertain)|KernelClientError::ServerRejected(500..=599))=>self.submit_structure_read(&signed,cancel).await?,
                result=>result?,
            };
            let data=parse_wire_json_bounded(result.structure_result_json.as_ref().ok_or(KernelClientError::InvalidResult)?.as_bytes(),32,1024*1024).map_err(|_|KernelClientError::InvalidResult)?;
            if result.outcome_state()=="REJECTED"{return Ok(StructureIntentOutcome::Pending{command_id:command_id.clone(),code:"OBSERVATION_REFUSED",phase:"OBSERVATION",retryable:false,recovery:"OBSERVE_SAME_OPERATION"});}
            let job=data.get("maintenance").ok_or(KernelClientError::InvalidResult)?;
            for field in ["workspace_id","instance_id","job_id","kind","actor_id","membership_id","command_id","intent_digest","protocol_digest","base_revision","base_event_revision","source_generation","target_generation","deadline_at","created_at"] {
                if job.get(field)!=initial.get(field){return Err(KernelClientError::InvalidResult);}
            }
            if job.get("status").and_then(WireValue::as_string).as_deref()!=Some("ORDERED"){
                return Ok(StructureIntentOutcome::Completed{command_id,result});
            }
            tokio::select!{_=cancel.cancelled()=>return Err(TransportError::Cancelled.into()),_=tokio::time::sleep(Duration::from_millis(500))=>{}}
        }
        Ok(pending(&command_id,"IN_PROGRESS","MAINTENANCE",true))
    }

    pub(super) async fn fresh_structure_context(&self,cancel:&CancellationToken)->Result<peerwork_core::structure_context::VerifiedStructureContext,KernelClientError>{
        let mut nonce=[0u8;32];OsRng.try_fill_bytes(&mut nonce).map_err(|_|KernelClientError::InvalidCommand)?;
        let nonce=base64url(&nonce);let started=Instant::now();let response=self.transport.structure_context(&nonce,cancel).await?;
        if response.status==404{return Err(KernelClientError::UnsupportedStructureProfile);}
        if !(200..300).contains(&response.status){return Err(KernelClientError::ServerRejected(response.status));}
        if started.elapsed()>Duration::from_secs(30){return Err(TransportError::Timeout.into());}
        verify_structure_context(&response.wire,&nonce,self.discovery.audience_utf16(),self.discovery.receipt_public_key()).map_err(|_|JournalError::InvalidReceipt.into())
    }

    pub(super) fn structure_command(&self, identity: &KernelIdentity, authority: &str, intent_wire: &[u8])
        -> Result<(String, WireValue, bool), KernelClientError> {
        let invalid = || KernelClientError::InvalidCommand;
        let request = parse_wire_json_bounded(intent_wire, 38, peerwork_core::structure_content::MAX_BODY_REQUEST_BYTES).map_err(|_| invalid())?;
        let WireValue::Object(fields) = &request else { return Err(invalid()); };
        let allowed = ["action", "body", "command_id", "idempotency_key", "workspace_id", "instance_id", "protocol_digest", "plaintext_contents",
            "expected_workspace_revision", "expected_instance_revision", "exact_input_refs"];
        if fields.iter().any(|(key, _)| !allowed.iter().any(|name| key.iter().copied().eq(name.encode_utf16()))) { return Err(invalid()); }
        let action = request.get("action").and_then(WireValue::as_string).ok_or_else(invalid)?;
        if !is_structure_action(&action) { return Err(invalid()); }
        if matches!(action.as_str(),"structure.workspace.delete"|"structure.workspace.deletion.get"|"structure.workspace.deletions.read")&&!self.discovery.protocol_features().contains(&"durable-workspace-deletion-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if action=="structure.record.withdraw"&&!self.discovery.protocol_features().contains(&"selected-record-withdrawal-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if action.starts_with("structure.content-key.history.")&&!self.discovery.protocol_features().contains(&"owner-retained-key-delivery-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if action=="structure.publication.prepare.get"&&!self.discovery.protocol_features().contains(&"selected-publication-snapshot-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if action.starts_with("structure.publication.")&&!self.discovery.protocol_features().contains(&"owner-selected-publication-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if matches!(action.as_str(),"structure.content-key.set"|"structure.content-key.get"|"structure.content-key.deliver"|"structure.content-key.delivery.get")||request.get("plaintext_contents").is_some(){self.require_content_key_epochs()?;}
        if matches!(action.as_str(),"structure.content-key.deliver"|"structure.content-key.delivery.get"){self.require_current_key_delivery()?;}
        if let Some(times)=request.get("body").and_then(|b|b.get("document_times")){
            if action!="structure.action"{return Err(invalid());}
            if !self.discovery.protocol_features().contains(&"signed-document-time-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            peerwork_core::document_time::at(Some(times),0).map_err(|_|KernelClientError::InvalidDocumentTime)?;
        }
        if let Some(time)=request.get("body").and_then(|b|b.get("source")).and_then(|s|s.get("document_time")){
            if !self.discovery.protocol_features().contains(&"signed-document-time-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            if action!="structure.publication.entry.set"||time.object_len()!=Some(2){return Err(invalid());}
            peerwork_core::document_time::normalized(time).map_err(|_|KernelClientError::InvalidDocumentTime)?;
        }
        let mut already_signed_public=false;
        let body=request.get("body").ok_or_else(invalid)?;
        if matches!(action.as_str(),"structure.publication.policy.set"|"structure.publication.policy.get"|"structure.publication.entry.withdraw")||body.get("publication").is_some(){
            if !self.discovery.protocol_features().contains(&"member-public-actions-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            if let Some(publication)=body.get("publication"){
                if action!="structure.action"||request.get("plaintext_contents").is_some()||body.get("contents").is_some_and(|v|!matches!(v,WireValue::Array(items) if items.is_empty())){return Err(invalid());}
                let value:serde_json::Value=serde_json::from_str(&canonical_wire_value(publication,CanonicalPath::STRUCTURED).map_err(|_|invalid())?).map_err(|_|invalid())?;
                already_signed_public=value["entries"].as_array().is_some_and(|entries|!entries.is_empty()&&entries.iter().all(|entry|entry.get("statement").is_some()));
                if !already_signed_public{super::validate_public_action(&value)?;}
            }
        }
        // Validate plaintext byte/aggregate limits and capability before key
        // initialization or any service await. Large content never expands
        // ordinary structural fields or reaches the transport journal in clear.
        if let Some(contents)=request.get("plaintext_contents"){
            use peerwork_core::structure_content::{MAX_BODY_BYTES,MAX_BODY_BATCH_BYTES,INLINE_BODY_BYTES};
            let WireValue::Array(items)=contents else{return Err(invalid());};
            if items.is_empty()||items.len()>8{return Err(invalid());}
            let mut total=0usize;let mut indices=std::collections::BTreeSet::new();
            for item in items{
                let index=item.get("record_index").and_then(WireValue::as_number).filter(|n|n.fract()==0.0&&(0.0..8.0).contains(n)).ok_or_else(invalid)? as u8;
                let text=item.get("text").and_then(WireValue::as_string).ok_or_else(invalid)?;
                if item.object_len()!=Some(2)||!indices.insert(index){return Err(invalid());}
                total=total.checked_add(text.len()).ok_or_else(invalid)?;
                if text.len()>MAX_BODY_BYTES||total>MAX_BODY_BATCH_BYTES{return Err(crate::kernel_intents::ContentKeyError::Content(peerwork_core::structure_content::StructureContentError::TooLarge).into());}
                if text.len()>INLINE_BODY_BYTES&&!self.discovery.protocol_features().contains(&"chunked-content-bodies-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
            }
        }
        let mut body = request.get("body").cloned().ok_or_else(invalid)?;
        if !matches!(body, WireValue::Object(_)) { return Err(invalid()); }
        if body.get("profile").is_some_and(|v| v.as_string().as_deref() != Some(PROFILE)) { return Err(invalid()); }
        if matches!(body.get("contents"),Some(WireValue::Array(items)) if items.iter().any(|item|item.get("body").is_some_and(|b|b.get("ciphertext_chunks").is_some())))
            &&!self.discovery.protocol_features().contains(&"chunked-content-bodies-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}

        set(&mut body, "profile", string(PROFILE));
        if request.get("command_id").is_some() && request.get("idempotency_key").is_some() { return Err(invalid()); }
        let command_id = if let Some(id) = request.get("command_id") {
            let id = id.as_string().filter(|v| super::valid_token(v)).ok_or_else(invalid)?;
            id
        } else if let Some(key) = request.get("idempotency_key") {
            let key = key.as_utf16().filter(|v| !v.is_empty() && v.len() <= 128).ok_or_else(invalid)?;
            keyed_command_id(self.origin(), identity.actor_id(), request.get("workspace_id").cloned().unwrap_or(WireValue::Null), key)?
        } else {
            let mut bytes=[0u8;32];OsRng.try_fill_bytes(&mut bytes).map_err(|_| invalid())?;base64url(&bytes)
        };
        let mut command = WireValue::Object(Vec::new());
        for (key, value) in [
            ("v", WireValue::Number(1.0)), ("audience", WireValue::String(self.discovery.audience_utf16().to_vec())),
            ("command_id",string(&command_id)), ("actor_id",string(identity.actor_id())), ("authority",string(authority)),
            ("method",string("POST")), ("path",string("/api/workspace/v1/commands")), ("action_id",string(&action)),
            ("body",body), ("issued_at",WireValue::Number(1.0)), ("expires_at",WireValue::Number(600_001.0)),
        ] { set(&mut command,key,value); }
        for field in ["workspace_id","instance_id","protocol_digest","expected_workspace_revision","expected_instance_revision"] {
            set(&mut command,field,request.get(field).cloned().unwrap_or(WireValue::Null));
        }
        set(&mut command,"exact_input_refs",request.get("exact_input_refs").cloned().unwrap_or(WireValue::Array(Vec::new())));
        if already_signed_public{super::validate_public_wire(&command)?;}
        else if request.get("body").is_some_and(|b|b.get("publication").is_some()){
            let value:serde_json::Value=serde_json::from_str(&canonical_wire_value(&command,CanonicalPath::STRUCTURED).map_err(|_|invalid())?).map_err(|_|invalid())?;
            let mut entries=Vec::new();for entry in value["body"]["publication"]["entries"].as_array().ok_or_else(invalid)?{
                let mut output=serde_json::json!({"v":1,"profile":PROFILE,"audience":value["audience"],"actor_id":value["actor_id"],"command_id":value["command_id"],"workspace_id":value["workspace_id"],"instance_id":value["instance_id"],"protocol_digest":value["protocol_digest"],"action_id":value["body"]["action_id"],"policy_revision":value["body"]["publication"]["policy_revision"],"record_index":entry["record_index"],"disclosure":"PUBLISH_SELECTED_RECORD","title":entry["title"],"body":entry["body"]});
                if let Some(time)=peerwork_core::document_time::for_command(&command,entry["record_index"].as_u64().ok_or_else(invalid)?).map_err(|_|invalid())?{
                    output["document_time"]=serde_json::from_str(&canonical_wire_value(&time,CanonicalPath::STRUCTURED).map_err(|_|invalid())?).map_err(|_|invalid())?;
                }
                let jws=peerwork_core::crypto::sign_compact(&serde_json::json!({"alg":"EdDSA","typ":peerwork_core::public_output::TYPE,"kid":identity.key_id()}),&output,identity.signing_key()).map_err(|_|invalid())?;
                let statement=serde_json::json!({"format":"AUTHOR_PUBLIC_OUTPUT_V1","chunks":jws.as_bytes().chunks(8192).map(|v|std::str::from_utf8(v).expect("JWS ASCII")).collect::<Vec<_>>()});
                let signed=parse_wire_json_bounded(statement.to_string().as_bytes(),8,140000).map_err(|_|invalid())?;peerwork_core::public_output::verify(&signed,self.discovery.audience_utf16()).map_err(|_|invalid())?;
                entries.push(serde_json::json!({"record_index":entry["record_index"],"statement":statement}));
            }
            let publication=serde_json::json!({"policy_revision":value["body"]["publication"]["policy_revision"],"disclosure":"PUBLISH_ACTION_AND_SELECTED_RECORDS","entries":entries});let mut next_body=command.get("body").cloned().ok_or_else(invalid)?;set(&mut next_body,"publication",parse_wire_json_bounded(publication.to_string().as_bytes(),20,180000).map_err(|_|invalid())?);set(&mut command,"body",next_body);
        }
        let durable=is_structure_mutation(&action)||request.get("command_id").is_some()||request.get("idempotency_key").is_some();
        Ok((command_id, command, durable))
    }

    /// Encrypt and elect one exact ciphertext before any network await. A
    /// concurrent producer adopts the saved winner only after decrypting and
    /// comparing its requested bytes; a retry never invents a fresh nonce.
    fn prepare_plaintext_contents(&mut self,identity:&KernelIdentity,wire:&[u8],command:&mut WireValue,cancel:&CancellationToken)
        ->Result<bool,KernelClientError>{
        use crate::kernel_intents::{StructureContentKeys,ContentKeyError};
        use peerwork_core::structure_content::StructureContentContext;
        use peerwork_core::prepared_command::verify_structure_author_intent;
        use zeroize::Zeroizing;
        let request=parse_wire_json_bounded(wire,38,peerwork_core::structure_content::MAX_BODY_REQUEST_BYTES).map_err(|_|KernelClientError::InvalidCommand)?;
        let Some(contents)=request.get("plaintext_contents")else{return Ok(false);};
        if cancel.is_cancelled(){return Err(TransportError::Cancelled.into());}
        if command.get("action_id").and_then(WireValue::as_string).as_deref()!=Some("structure.action"){
            return Err(KernelClientError::InvalidCommand);
        }
        let WireValue::Array(contents)=contents else{return Err(KernelClientError::InvalidCommand);};
        if contents.is_empty()||contents.len()>8{return Err(KernelClientError::InvalidCommand);}
        let body=command.get("body").ok_or(KernelClientError::InvalidCommand)?;
        if body.get("contents").is_some_and(|v|!matches!(v,WireValue::Array(items) if items.is_empty())){
            return Err(KernelClientError::InvalidCommand);
        }
        let text=|value:Option<&WireValue>|value.and_then(WireValue::as_string).ok_or(KernelClientError::InvalidCommand);
        let command_id=text(command.get("command_id"))?;
        let workspace=text(command.get("workspace_id"))?;
        let key_path=self.content_key_store_path();if !key_path.is_file(){return Err(ContentKeyError::Missing.into());}
        let mut config=crate::transport::TransportConfig::new(self.origin());config.allow_loopback_http=self.origin().starts_with("http://");
        let keys=StructureContentKeys::open(&key_path,config)?;
        let mut selected=Vec::new();let mut indices=std::collections::BTreeSet::new();
        for item in contents {
            let index=item.get("record_index").and_then(WireValue::as_number).filter(|n|n.is_finite()&&n.fract()==0.0&&(0.0..8.0).contains(n))
                .ok_or(KernelClientError::InvalidCommand)? as u8;
            if item.object_len()!=Some(2)||!indices.insert(index){return Err(KernelClientError::InvalidCommand);}
            let plaintext=Zeroizing::new(text(item.get("text"))?);
            if plaintext.len()>peerwork_core::structure_content::MAX_BODY_BYTES{return Err(ContentKeyError::Content(peerwork_core::structure_content::StructureContentError::TooLarge).into());}
            selected.push((index,plaintext));
        }
        let existing=self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?;
        if existing.is_none(){
            let mut sealed=Vec::new();
            for (index,plaintext) in &selected {
                let context=StructureContentContext{workspace_id:workspace.clone(),instance_id:text(command.get("instance_id"))?,
                    protocol_digest:text(command.get("protocol_digest"))?,actor_id:identity.actor_id().into(),command_id:command_id.clone(),
                    action_id:text(body.get("action_id"))?,record_index:*index};
                let content=keys.seal(identity.key_id(),plaintext.as_bytes(),&context)?;
                let wire=serde_json::to_vec(&serde_json::json!({"record_index":index,"body":content})).map_err(|_|KernelClientError::InvalidCommand)?;
                sealed.push(parse_wire_json_bounded(&wire,8,100_000).map_err(|_|KernelClientError::InvalidCommand)?);
            }
            let mut updated=body.clone();set(&mut updated,"contents",WireValue::Array(sealed));set(command,"body",updated);
            let prepared=prepare_signed_command_wire(command,identity.signing_key(),&self.discovery,None).map_err(|_|KernelClientError::InvalidCommand)?;
            if cancel.is_cancelled(){return Err(TransportError::Cancelled.into());}
            match self.journal.prepare(&command_id,KernelPath::Command,prepared.jws(),prepared.http_body()){
                Ok(_)|Err(JournalError::IntentConflict)=>(),Err(e)=>return Err(e.into()),
            }
        }
        let saved=self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?.ok_or(JournalError::IncompatibleStore)?;
        if saved.proof.action_id()!="structure.action"{return Err(JournalError::IntentConflict.into());}
        let author=verify_structure_author_intent(&saved.jws,self.discovery.audience_utf16()).map_err(|_|JournalError::IncompatibleStore)?;
        if author.workspace_id()!=Some(workspace.as_str()){return Err(JournalError::IntentConflict.into());}
        let saved_contents=author.command().get("body").and_then(|b|b.get("contents")).ok_or(JournalError::IntentConflict)?;
        if !matches!(saved_contents,WireValue::Array(items) if items.len()==selected.len()){return Err(JournalError::IntentConflict.into());}
        for (index,plaintext) in &selected {
            let original=keys.open_authored_body(identity.key_id(),&author,*index)?;
            if &original[..]!=plaintext.as_bytes(){return Err(JournalError::IntentConflict.into());}
        }
        let mut updated=command.get("body").cloned().ok_or(KernelClientError::InvalidCommand)?;
        set(&mut updated,"contents",saved_contents.clone());set(command,"body",updated);
        let candidate=prepare_signed_command_wire(command,identity.signing_key(),&self.discovery,None).map_err(|_|KernelClientError::InvalidCommand)?;
        if !same_request(&saved.proof,candidate.proof())?{return Err(JournalError::IntentConflict.into());}
        Ok(true)
    }

    /// Fresh selected reads are verified in memory. They are not an ever-
    /// growing archive of pages/events in the local mutation outbox. Explicit
    /// caller IDs/keys retain the durable historical-query behavior.
    pub(super) async fn submit_structure_read(&self,signed:&SignedPreparedCommand,cancel:&CancellationToken)->Result<KernelAcceptedResult,KernelClientError>{
        let response=self.transport.post_exact(signed.proof().path(),signed.http_body().to_vec(),cancel).await?;
        let proof=verify_http_response_for_prepared(&response.wire,signed.proof(),self.discovery.receipt_public_key());
        if !(200..300).contains(&response.status)&&proof.is_err(){
            let has_receipt=parse_wire_json_bounded(&response.wire,33,1024*1024).is_ok_and(|v|v.get("receipt").is_some());
            if has_receipt{return Err(JournalError::InvalidReceipt.into());}
            return Err(KernelClientError::ServerRejected(response.status));
        }
        let proof=proof.map_err(|_|KernelClientError::Store(JournalError::InvalidReceipt))?;
        KernelAcceptedResult::from_verified(proof,signed.proof(),None)
    }

    async fn drive_structure_intent(
        &mut self,
        identity: &KernelIdentity,
        mut command: WireValue,
        durable: bool,
        persisted: &mut bool,
        cancel: &CancellationToken,
    ) -> Result<StructureIntentOutcome, KernelClientError> {
        let candidate=prepare_signed_command_wire(&command,identity.signing_key(),&self.discovery,None).map_err(|_|KernelClientError::InvalidCommand)?;
        let command_id=candidate.proof().command_id().to_owned();
        let saved=if durable{self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?}else{None};
        if let Some(saved)=&saved {
            if !same_request(&saved.proof,candidate.proof())? {return Err(JournalError::IntentConflict.into());}
            *persisted=true;
            if let Some(proof)=self.journal.accepted_response(saved,self.discovery.receipt_public_key())? {
                return Ok(StructureIntentOutcome::Accepted(KernelAcceptedResult::from_verified(proof,&saved.proof,None)?));
            }
        }
        if cancel.is_cancelled() {
            return if *persisted {Ok(pending(&command_id,"CANCELLED","AUTHORIZATION",true))} else {Err(TransportError::Cancelled.into())};
        }
        let context=self.fresh_structure_context(cancel).await?;
        set(&mut command,"issued_at",WireValue::Number(context.server_time_ms() as f64));
        set(&mut command,"expires_at",WireValue::Number(context.expires_at_ms() as f64));
        let signed=prepare_signed_command_wire(&command,identity.signing_key(),&self.discovery,None).map_err(|_|KernelClientError::InvalidCommand)?;
        if durable {
        if self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?.is_none() {
            match self.journal.prepare(&command_id,KernelPath::Command,signed.jws(),signed.http_body()) {
                Ok(_)|Err(JournalError::IntentConflict)=>(),
                Err(error)=>return Err(error.into()),
            }
        }
        // Re-read after context acquisition and any prepare race. Another
        // process may have renewed or accepted the operation in the meantime.
        let current=self.journal.verified_pending(&command_id,identity.key_id(),self.discovery.audience_utf16())?
            .ok_or(JournalError::IncompatibleStore)?;
        if !same_request(&current.proof,signed.proof())? {return Err(JournalError::IntentConflict.into());}
        *persisted=true;
        if let Some(proof)=self.journal.accepted_response(&current,self.discovery.receipt_public_key())? {
            return Ok(StructureIntentOutcome::Accepted(KernelAcceptedResult::from_verified(proof,&current.proof,None)?));
        }
        if current.proof.expires_at_ms() <= context.server_time_ms()+5_000 {
            if !is_structure_mutation(current.proof.action_id()) {
                return Ok(StructureIntentOutcome::Pending { command_id,code:"READ_AUTHORIZATION_EXPIRED",phase:"AUTHORIZATION",retryable:false,recovery:"NEW_READ" });
            }
            self.journal.renew_structure_authorization(&signed,&self.discovery)?;
        }
        *persisted=true;
        }
        for attempt in 0..2 {
            let result=if durable{self.submit_saved(&command_id,identity.key_id(),cancel).await}else{self.submit_structure_read(&signed,cancel).await};
            match result {
                Ok(result)=>return Ok(StructureIntentOutcome::Accepted(result)),
                Err(error)=>{
                    let transient=matches!(error,KernelClientError::Transport(TransportError::Network|TransportError::Timeout|TransportError::SubmittedUncertain))
                        ||matches!(error,KernelClientError::ServerRejected(401|403|500..=599));
                    if transient && attempt==0 && !cancel.is_cancelled() {continue;}
                    let (code,phase,retryable)=match error {
                        KernelClientError::Store(JournalError::InvalidReceipt)|KernelClientError::InvalidResult=>("VERIFICATION_FAILED","VERIFICATION",false),
                        KernelClientError::Transport(TransportError::Cancelled)=>("CANCELLED","SUBMISSION",true),
                        KernelClientError::ServerRejected(429)=>("RATE_LIMITED","SUBMISSION",true),
                        KernelClientError::ServerRejected(401|403)=>("UNVERIFIED_AUTHORIZATION_RESPONSE","HTTP_RESPONSE",true),
                        KernelClientError::ServerRejected(409)=>("COMMAND_CONFLICT","SUBMISSION",false),
                        _ if transient=>("OUTCOME_UNKNOWN","SUBMISSION",true),
                        _=>return Err(error),
                    };
                    return Ok(StructureIntentOutcome::Pending{command_id:command_id.clone(),code,phase,retryable,recovery:if durable{"RESUME_SAME_INTENT"}else{"NEW_READ"}});
                }
            }
        }
        unreachable!("bounded attempts return an outcome")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use peerwork_core::crypto::sha256_hex;
    use serde_json::{json, Value};
    use std::{io::{BufRead, BufReader}, process::{Child, Command, Stdio}, path::PathBuf};
    struct Server(Child);
    impl Drop for Server { fn drop(&mut self) { let _=self.0.kill();let _=self.0.wait(); } }
    fn accepted(outcome: StructureIntentOutcome) -> KernelAcceptedResult {
        match outcome { StructureIntentOutcome::Accepted(result)=>result,other=>panic!("expected accepted outcome: {other:?}") }
    }

    #[test]
    fn concurrent_plaintext_producers_elect_one_ciphertext_without_persisting_plaintext(){
        use crate::kernel_intents::StructureContentKeys;
        use std::sync::{Arc,Barrier};
        let state=crate::test_support::protected_test_dir();let path=state.path().join("operations.sqlite");
        let identity_path=state.path().join("identity");let identity=KernelIdentity::create(&identity_path).unwrap();
        let discovery_wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"body-race","protocol_features":["canonical-content-key-epochs-v1"],
            "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
            "receipt_public_key":peerwork_core::crypto::key_id(&ed25519_dalek::SigningKey::from_bytes(&[22;32]).verifying_key().to_bytes()),"limits":{"max":1}})).unwrap();
        let discovery=peerwork_core::discovery::parse_discovery_wire(&discovery_wire,discovery_wire.len()).unwrap();
        let mut journal=crate::kernel_intents::KernelIntentJournal::open(&path).unwrap();journal.bind_discovery("https://example.invalid/",&discovery).unwrap();drop(journal);
        let mut keys=StructureContentKeys::open(&path.with_extension("content-keys.sqlite"),TransportConfig::new("https://example.invalid")).unwrap();
        let workspace="W".repeat(43);keys.ensure_current(identity.key_id(),&workspace).unwrap();drop(keys);
        let input=json!({"action":"structure.action","workspace_id":workspace,"instance_id":"I".repeat(43),"protocol_digest":"a".repeat(64),
            "expected_instance_revision":1,"idempotency_key":"one-body","body":{"action_id":"post","structure":{}},
            "plaintext_contents":[{"record_index":0,"text":"private concurrent body"}]});
        let wire=serde_json::to_vec(&input).unwrap();let barrier=Arc::new(Barrier::new(8));let mut workers=Vec::new();
        for _ in 0..8{
            let barrier=barrier.clone();let path=path.clone();let identity_path=identity_path.clone();let wire=wire.clone();
            workers.push(std::thread::spawn(move||{
                let identity=KernelIdentity::open(&identity_path).unwrap();let cancel=CancellationToken::new();
                let mut client=KernelClient::open_cached(TransportConfig::new("https://example.invalid"),&path,&[],&cancel).unwrap();
                let authority=sha256_hex(identity.actor_id().as_bytes());let (_,mut command,_)=client.structure_command(&identity,&authority,&wire).unwrap();
                barrier.wait();assert!(client.prepare_plaintext_contents(&identity,&wire,&mut command,&cancel).unwrap());
                canonical_wire_value(&command,CanonicalPath::COMMAND).unwrap()
            }));
        }
        let commands:Vec<_>=workers.into_iter().map(|h|h.join().unwrap()).collect();
        assert!(commands.iter().all(|c|c==&commands[0]));assert!(!commands[0].contains("private concurrent body"));
        let db=rusqlite::Connection::open(&path).unwrap();assert_eq!(db.query_row("SELECT count(*) FROM kernel_intents",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        let mut client=KernelClient::open_cached(TransportConfig::new("https://example.invalid"),&path,&[],&CancellationToken::new()).unwrap();
        let authority=sha256_hex(identity.actor_id().as_bytes());
        for which in 0..3 {
            let mut changed=input.clone();match which{
                0=>changed["plaintext_contents"][0]["text"]=json!("different private body"),
                1=>changed["plaintext_contents"][0]["text"]=json!("x".repeat(peerwork_core::structure_content::MAX_BODY_BYTES+1)),
                _=>changed["plaintext_contents"]=json!([{"record_index":0,"text":"private concurrent body"},{"record_index":0,"text":"duplicate"}]),
            }
            let wire=serde_json::to_vec(&changed).unwrap();
            match client.structure_command(&identity,&authority,&wire){
                Err(_)=>assert!(which!=0),
                Ok((_,mut command,_))=>assert!(client.prepare_plaintext_contents(&identity,&wire,&mut command,&CancellationToken::new()).is_err()),
            }
        }
        assert_eq!(db.query_row("SELECT count(*) FROM kernel_intents",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    }

    #[tokio::test]
    #[ignore = "requires a frozen candidate service and synthetic loopback HTTP"]
    async fn one_call_driver_recovers_expired_uncertain_intent_using_only_service_time() {
        let state=crate::test_support::protected_test_dir();
        let node=std::env::var("PEERWORK_TEST_NODE").expect("test Node required");
        let fixture=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/structure-profile-service.mjs");
        let mut server=Server(Command::new(node).arg(fixture).env("PEERWORK_TEST_STATE",state.path())
            .env("PEERWORK_STRUCTURE_TEST_CLOCK","1600000000000").env("PEERWORK_STRUCTURE_TEST_DROPS","2")
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
        let mut line=String::new();BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let origin=serde_json::from_str::<Value>(&line).expect("fixture starts")["origin"].as_str().unwrap().to_owned();
        let config=||{let mut config=TransportConfig::new(&origin);config.allow_loopback_http=true;config};
        let identity=KernelIdentity::create(&state.path().join("identity")).unwrap();
        let authority=peerwork_core::crypto::sha256_hex(identity.actor_id().as_bytes());let cancel=CancellationToken::new();
        let path=state.path().join("operations.sqlite");let mut client=KernelClient::open(config(),&path,&[],&cancel).await.unwrap();
        let wire=|v:Value|serde_json::to_vec(&v).unwrap();
        let created=accepted(client.execute_structure_intent(&identity,&authority,&wire(json!({"action":"structure.workspace.create","idempotency_key":"workspace","body":{"name":"One-call driver"}})),&cancel).await.unwrap());
        let workspace=created.workspace_id.unwrap();
        let manifest=json!({"name":"driver-claim","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],
            "initial_state":{"count":0},"record_schemas":{"change":{"type":"object","fields":{"count":"integer"},"required":["count"],"max_bytes":256}},
            "actions":[{"id":"advance","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},
                "variants":[{"when":[{"op":"eq","left":{"from":"state","path":["count"]},"right":{"from":"literal","value":0}}],
                    "effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}},
                    {"op":"append","schema":"change","value":{"from":"literal","value":{"count":1}},"relations":[]}]}]}]});
        let adopted=accepted(client.execute_structure_intent(&identity,&authority,&wire(json!({"action":"structure.adopt","workspace_id":workspace,
            "idempotency_key":"protocol-v1","body":{"manifest":manifest,"bootstrap_grant":{"actions":["advance"]}}})),&cancel).await.unwrap());
        let instance=adopted.instance_id.unwrap();let protocol=adopted.protocol_digest.unwrap();
        let action=json!({"action":"structure.action","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,
            "expected_instance_revision":1,"idempotency_key":"advance-once","body":{"action_id":"advance","structure":{}}});
        let pending=client.execute_structure_intent(&identity,&authority,&wire(action.clone()),&cancel).await.unwrap();
        let command_id=match pending {StructureIntentOutcome::Pending{command_id,code,retryable,..}=>{assert_eq!(code,"OUTCOME_UNKNOWN");assert!(retryable);command_id},_=>panic!("two dropped replies must remain pending")};
        assert!(matches!(client.status(&command_id,identity.key_id()).unwrap(),Some(KernelOperationStatus::Pending)));
        drop(client);
        assert!(reqwest::get(format!("{origin}__test/advance-clock")).await.unwrap().status().is_success());
        let mut client=KernelClient::open(config(),&path,&[],&cancel).await.unwrap();
        let result=accepted(client.resume_structure_intent(&identity,&authority,&command_id,&cancel).await.unwrap());
        assert_eq!(result.command_id,command_id);let data:Value=serde_json::from_str(result.structure_result_json.as_deref().unwrap()).unwrap();
        assert_eq!(data["state"],json!({"count":1}));assert_eq!(data["status"],"APPLIED");
        let original=data["author_intent"].as_str().unwrap().split('.').nth(1).unwrap();
        let original:Value=serde_json::from_slice(&peerwork_core::crypto::decode_base64url(original).unwrap()).unwrap();
        assert_eq!(original["issued_at"],1_600_000_000_000_u64,"authorization uses signed service time, even far from the local clock");
        let repeated=accepted(client.execute_structure_intent(&identity,&authority,&wire(action.clone()),&cancel).await.unwrap());assert_eq!(repeated,result);
        let mut changed=action;changed["expected_instance_revision"]=json!(2);
        assert!(matches!(client.execute_structure_intent(&identity,&authority,&wire(changed),&cancel).await,Err(KernelClientError::Store(JournalError::IntentConflict))));
        let read=accepted(client.execute_structure_intent(&identity,&authority,&wire(json!({"action":"structure.instance.get","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{}})),&cancel).await.unwrap());
        let read:Value=serde_json::from_str(read.structure_result_json.as_deref().unwrap()).unwrap();assert_eq!(read["revision"],2);
        let counts:Value=serde_json::from_slice(&reqwest::get(format!("{origin}__test/counts")).await.unwrap().bytes().await.unwrap()).unwrap();
        assert_eq!(counts,json!({"records":1,"dropped":2,"journal_reads":0}));
    }
}

#[cfg(all(test, unix))]
mod collaboration_tests {
    use super::*;
    use serde_json::{json,Value};
    use std::{io::{BufRead,BufReader},process::{Child,Command,Stdio},path::PathBuf};
    struct Server(Child);
    impl Drop for Server { fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();} }
    async fn call(client:&mut KernelClient,identity:&KernelIdentity,value:Value)->KernelAcceptedResult{
        let authority=peerwork_core::crypto::sha256_hex(identity.actor_id().as_bytes());let wire=serde_json::to_vec(&value).unwrap();
        match client.execute_structure_intent(identity,&authority,&wire,&CancellationToken::new()).await.unwrap(){
            StructureIntentOutcome::Accepted(result)=>result,
            other=>panic!("expected verified result: {other:?}"),
        }
    }
    fn data(result:KernelAcceptedResult)->Value{serde_json::from_str(result.structure_result_json.as_deref().unwrap()).unwrap()}

    #[tokio::test]
    #[ignore="requires a frozen candidate service and synthetic loopback HTTP"]
    async fn backend_maintenance_resumes_lost_admission_and_waits_for_signed_completion_without_client_paging(){
        let state=crate::test_support::protected_test_dir();let fixture=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/structure-profile-service.mjs");
        let mut server=Server(Command::new(std::env::var("PEERWORK_TEST_NODE").expect("test Node required")).arg(fixture)
            .env("PEERWORK_TEST_STATE",state.path()).env("PEERWORK_STRUCTURE_TEST_DROPS","0").env("PEERWORK_STRUCTURE_TEST_MAINTENANCE_DROPS","2")
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
        let mut line=String::new();BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let origin=serde_json::from_str::<Value>(&line).unwrap()["origin"].as_str().unwrap().to_owned();
        let config=||{let mut c=TransportConfig::new(&origin);c.allow_loopback_http=true;c};let cancel=CancellationToken::new();
        let identity=KernelIdentity::create(&state.path().join("identity")).unwrap();let path=state.path().join("operations.sqlite");
        let mut client=KernelClient::open(config(),&path,&[],&cancel).await.unwrap();
        let workspace=call(&mut client,&identity,json!({"action":"structure.workspace.create","body":{"name":"Backend maintenance"},"idempotency_key":"create"})).await.workspace_id.unwrap();
        let manifest=json!({"name":"maintenance-posts","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{},
            "record_schemas":{"note":{"type":"object","fields":{"text":"string"},"required":["text"],"max_bytes":128}},
            "actions":[{"id":"post","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"append","schema":"note","value":{"from":"literal","value":{"text":"original"}},"relations":[]}]}]}]});
        let adopted=call(&mut client,&identity,json!({"action":"structure.adopt","workspace_id":workspace,"idempotency_key":"adopt","body":{"manifest":manifest,"bootstrap_grant":{"actions":["post"]}}})).await;
        let instance=adopted.instance_id.unwrap();let protocol=adopted.protocol_digest.unwrap();
        for i in 0..5 {call(&mut client,&identity,json!({"action":"structure.action","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"expected_instance_revision":1,"idempotency_key":format!("post-{i}"),"body":{"action_id":"post","structure":{}}})).await;}
        let current=data(call(&mut client,&identity,json!({"action":"structure.instance.get","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{}})).await);
        let authority=peerwork_core::crypto::sha256_hex(identity.actor_id().as_bytes());
        let request=serde_json::to_vec(&json!({"action":"structure.maintenance.rebuild","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,
            "expected_instance_revision":1,"idempotency_key":"rebuild-current","body":{"expected_event_revision":current["event_revision"]}})).unwrap();
        let command_id=match client.execute_structure_intent(&identity,&authority,&request,&cancel).await.unwrap(){
            StructureIntentOutcome::Pending{command_id,code,..}=>{assert_eq!(code,"OUTCOME_UNKNOWN");command_id},other=>panic!("lost admission must remain recoverable: {other:?}"),
        };
        drop(client);let mut client=KernelClient::open(config(),&path,&[],&cancel).await.unwrap();
        let result=match client.resume_structure_intent(&identity,&authority,&command_id,&cancel).await.unwrap(){
            StructureIntentOutcome::Completed{command_id:root,result}=>{assert_eq!(root,command_id);assert_ne!(result.command_id,root);result},other=>panic!("driver must wait for completion: {other:?}"),
        };
        let result=data(result);assert_eq!(result["maintenance"]["status"],"APPLIED");assert_eq!(result["maintenance"]["scanned_records"],5);assert_eq!(result["maintenance"]["scanned_heads"],5);
        let original=match client.status(&command_id,identity.key_id()).unwrap().unwrap(){KernelOperationStatus::Accepted(result)=>data(result),_=>panic!("original admission not saved")};
        assert_eq!(original["status"],"ORDERED");assert_eq!(original["maintenance"]["job_id"],result["maintenance"]["job_id"]);
        assert!(matches!(client.resume_structure_intent(&identity,&authority,&command_id,&cancel).await.unwrap(),StructureIntentOutcome::Completed{..}));
        let db=rusqlite::Connection::open(path).unwrap();assert_eq!(db.query_row("SELECT count(*) FROM kernel_intents",[],|row|row.get::<_,i64>(0)).unwrap(),8,"progress reads never enter the mutation archive");
        let counts:Value=serde_json::from_slice(&reqwest::get(format!("{origin}__test/maintenance-counts")).await.unwrap().bytes().await.unwrap()).unwrap();
        assert_eq!(counts,json!({"jobs":1,"maintenance_dropped":2,"journal_reads":0}));
    }

    #[tokio::test]
    #[ignore="requires a frozen candidate service and synthetic loopback HTTP"]
    async fn two_native_actors_use_current_grants_pages_and_events_without_history_or_identity_migration(){
        let state=crate::test_support::protected_test_dir();
        let fixture=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/structure-profile-service.mjs");
        let mut server=Server(Command::new(std::env::var("PEERWORK_TEST_NODE").expect("test Node required")).arg(fixture)
            .env("PEERWORK_TEST_STATE",state.path()).env("PEERWORK_STRUCTURE_TEST_DROPS","0")
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
        let mut line=String::new();BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let origin=serde_json::from_str::<Value>(&line).unwrap()["origin"].as_str().unwrap().to_owned();
        let config=||{let mut c=TransportConfig::new(&origin);c.allow_loopback_http=true;c};let cancel=CancellationToken::new();
        let owner=KernelIdentity::create(&state.path().join("owner-identity")).unwrap();let worker=KernelIdentity::create(&state.path().join("worker-identity")).unwrap();
        let mut owner_client=KernelClient::open(config(),&state.path().join("owner-operations.sqlite"),&[],&cancel).await.unwrap();
        let mut worker_client=KernelClient::open(config(),&state.path().join("worker-operations.sqlite"),&[],&cancel).await.unwrap();
        let workspace=call(&mut owner_client,&owner,json!({"action":"structure.workspace.create","body":{"name":"Native collaboration"},"idempotency_key":"create"})).await.workspace_id.unwrap();
        let manifest=json!({"name":"native-collaboration","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{"holder":null},
            "record_schemas":{"claim":{"type":"object","fields":{"status":"string"},"required":["status"],"max_bytes":256}},
            "actions":[{"id":"claim","reads":[["holder"]],"writes":[["holder"]],"revisionEffects":{"control":true,"contentEntities":[]},
                "variants":[{"when":[{"op":"eq","left":{"from":"state","path":["holder"]},"right":{"from":"literal","value":null}}],
                    "effects":[{"op":"set","path":["holder"],"value":{"from":"auth","field":"actorId"}},
                    {"op":"append","schema":"claim","value":{"from":"literal","value":{"status":"claimed"}},"relations":[]}]}]}]});
        let adopted=data(call(&mut owner_client,&owner,json!({"action":"structure.adopt","workspace_id":workspace,"body":{"manifest":manifest,"bootstrap_grant":{"actions":["claim"]}},"idempotency_key":"adopt"})).await);
        let instance=adopted["instance_id"].as_str().unwrap();let protocol=adopted["protocol_digest"].as_str().unwrap();
        let admitted=data(call(&mut owner_client,&owner,json!({"action":"structure.member.set","workspace_id":workspace,"expected_workspace_revision":adopted["workspace_revision"],"body":{"actor_id":worker.actor_id(),"state":"ACTIVE","expected_membership_id":null},"idempotency_key":"admit-worker"})).await);
        let grant=data(call(&mut owner_client,&owner,json!({"action":"structure.grant.set","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,
            "body":{"actor_id":worker.actor_id(),"membership_id":admitted["membership_id"],"expected_grant_revision":null,"actions":["claim"]},"idempotency_key":"authorize-worker"})).await);
        assert_eq!(grant["grant_revision"],1);
        let tail=data(call(&mut worker_client,&worker,json!({"action":"structure.events.read","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{}})).await);
        assert_eq!(tail["events"],json!([]));
        let applied=call(&mut worker_client,&worker,json!({"action":"structure.action","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"expected_instance_revision":1,"body":{"action_id":"claim","structure":{}},"idempotency_key":"claim-once"})).await;
        let applied_json=data(applied.clone());assert_eq!(applied_json["state"]["holder"],worker.actor_id());
        let records=data(call(&mut worker_client,&worker,json!({"action":"structure.records.read","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{"schema":"claim","limit":1}})).await);
        assert_eq!(records["records"].as_array().unwrap().len(),1);assert_eq!(records["records"][0]["source"]["actor_id"],worker.actor_id());
        let selected=data(call(&mut worker_client,&worker,json!({"action":"structure.record.get","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{"record_id":records["records"][0]["record_id"],"revision":1}})).await);
        assert_eq!(selected["record_id"],records["records"][0]["record_id"]);
        let events=data(call(&mut worker_client,&worker,json!({"action":"structure.events.read","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{"after_sequence":tail["checkpoint"]}})).await);
        assert_eq!(events["events"].as_array().unwrap().len(),1);assert_eq!(events["events"][0]["actor_id"],worker.actor_id());
        let revoked=data(call(&mut owner_client,&owner,json!({"action":"structure.grant.revoke","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{"actor_id":worker.actor_id(),"expected_grant_revision":1},"idempotency_key":"revoke-worker"})).await);
        assert_eq!(revoked["grant_revision"],2);
        let effective=data(call(&mut worker_client,&worker,json!({"action":"structure.grant.get","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"body":{"actor_id":worker.actor_id()}})).await);assert_eq!(effective["grant"]["effective"],false);
        let denied=worker_client.execute_structure_intent(&worker,&peerwork_core::crypto::sha256_hex(worker.actor_id().as_bytes()),&serde_json::to_vec(&json!({"action":"structure.action","workspace_id":workspace,"instance_id":instance,"protocol_digest":protocol,"expected_instance_revision":2,"body":{"action_id":"claim","structure":{}},"idempotency_key":"after-revocation"})).unwrap(),&cancel).await.unwrap();
        assert!(matches!(denied,StructureIntentOutcome::Pending{code:"AUTHORIZATION_REJECTED",retryable:false,..}));
        let worker_db=rusqlite::Connection::open(state.path().join("worker-operations.sqlite")).unwrap();
        assert_eq!(worker_db.query_row("SELECT count(*) FROM kernel_intents",[],|row|row.get::<_,i64>(0)).unwrap(),2,"only the successful and denied writes belong in the durable outbox");
        assert_eq!(worker_db.query_row("SELECT count(*) FROM accepted_responses",[],|row|row.get::<_,i64>(0)).unwrap(),1,"ordinary record/event queries do not accumulate response snapshots");
        let counts:Value=serde_json::from_slice(&reqwest::get(format!("{origin}__test/collaboration-counts")).await.unwrap().bytes().await.unwrap()).unwrap();
        assert_eq!(counts,json!({"workspaces":1,"identities":2,"grant_heads":2,"current_records":1}));
        let counts:Value=serde_json::from_slice(&reqwest::get(format!("{origin}__test/counts")).await.unwrap().bytes().await.unwrap()).unwrap();assert_eq!(counts["records"],1);assert_eq!(counts["journal_reads"],0);
    }
}
