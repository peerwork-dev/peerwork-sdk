//! Native parent operations span preparation and exact packet submission.
//! A continuation always points to an existing encrypted plan or signed packet.
use super::*;
use peerwork_core::{canonical::Path as CanonicalPath, wire_json::canonical_wire_value};
use std::time::Duration;
use tokio::time::Instant;
use zeroize::Zeroizing;

fn pending(id:&str,code:&'static str,phase:&'static str)->StructureIntentOutcome{
    StructureIntentOutcome::Pending{command_id:id.into(),code,phase,retryable:true,recovery:"RESUME_SAME_INTENT"}
}
impl KernelClient {
    pub(super) fn bind_structure_parent(&mut self,identity:&KernelIdentity,authority:&str,id:&str,kind:&str,workspace:Option<&str>,wire:&str)->Result<(),KernelClientError>{
        let origin=self.origin().to_owned();
        self.journal.bind_parent_selection(id,identity,&origin,self.discovery.audience_utf16(),authority,kind,workspace,wire)?;Ok(())
    }
    pub(super) fn parent_result(&self,identity:&KernelIdentity,id:&str,result:Result<Result<StructureIntentOutcome,KernelClientError>,tokio::time::error::Elapsed>)
        ->Result<StructureIntentOutcome,KernelClientError>{
        let phase=if self.journal.verified_pending(id,identity.key_id(),self.discovery.audience_utf16())?.is_some(){"SUBMISSION"}else{"PREPARATION"};
        match result{
            Ok(Ok(outcome))=>Ok(outcome),
            Err(_)=>Ok(pending(id,if phase=="SUBMISSION"{"OUTCOME_UNKNOWN"}else{"PREPARATION_IN_PROGRESS"},phase)),
            Ok(Err(error))=>{
                let code=match error{
                    KernelClientError::Transport(TransportError::Cancelled)=>"CANCELLED",
                    KernelClientError::Transport(TransportError::Network|TransportError::Timeout|TransportError::SubmittedUncertain)=>if phase=="SUBMISSION"{"OUTCOME_UNKNOWN"}else{"PREPARATION_UNAVAILABLE"},
                    KernelClientError::PrerequisitePending{..}=>"PREREQUISITE_PENDING",
                    KernelClientError::CryptoPrerequisitePending{code,retryable,..}=>return Ok(StructureIntentOutcome::Pending{command_id:id.into(),code,phase,retryable,recovery:"RESUME_SAME_INTENT"}),
                    KernelClientError::InvalidResult|KernelClientError::Store(JournalError::InvalidReceipt) if phase=="PREPARATION"=>return Ok(StructureIntentOutcome::Pending{command_id:id.into(),code:"VERIFICATION_FAILED",phase,retryable:false,recovery:"RESUME_SAME_INTENT"}),
                    KernelClientError::ServerRejected(429)=>"RATE_LIMITED",
                    KernelClientError::ServerRejected(500..=599)=>"SERVICE_UNAVAILABLE",
                    other=>return Err(other),
                };Ok(pending(id,code,phase))
            }
        }
    }
    pub async fn execute_structure_intent(&mut self,identity:&KernelIdentity,authority:&str,wire:&[u8],cancel:&CancellationToken)
        ->Result<StructureIntentOutcome,KernelClientError>{
        Box::pin(self.execute_structure_intent_until(identity,authority,wire,cancel,Instant::now()+Duration::from_secs(30))).await
    }
    pub(crate) async fn execute_structure_intent_until(&mut self,identity:&KernelIdentity,authority:&str,wire:&[u8],cancel:&CancellationToken,deadline:Instant)
        ->Result<StructureIntentOutcome,KernelClientError>{
        let (id,command,durable)=self.structure_command(identity,authority,wire)?;
        if !durable{return tokio::time::timeout_at(deadline,self.execute_structure_intent_prepared(identity,authority,wire,cancel)).await.map_err(|_|TransportError::Timeout)?;}
        let saved=self.journal.verified_pending(&id,identity.key_id(),self.discovery.audience_utf16())?.is_some();
        let parent=self.journal.parent_selection(&id,identity,self.origin(),self.discovery.audience_utf16(),authority,None)?;
        // Preexisting exact packets remain their own authoritative producer.
        // Never attach an unvalidated new semantic plan to an older packet.
        if saved&&parent.is_none(){return tokio::time::timeout_at(deadline,self.execute_structure_intent_prepared(identity,authority,wire,cancel)).await.map_err(|_|TransportError::Timeout)?;}
        let mut request=parse_wire_json_bounded(wire,38,peerwork_core::structure_content::MAX_BODY_REQUEST_BYTES).map_err(|_|KernelClientError::InvalidCommand)?;
        let WireValue::Object(fields)=&mut request else{return Err(KernelClientError::InvalidCommand);};
        fields.retain(|(key,_)|!key.iter().copied().eq("idempotency_key".encode_utf16())&&!key.iter().copied().eq("command_id".encode_utf16()));
        fields.push(("command_id".encode_utf16().collect(),WireValue::String(id.encode_utf16().collect())));
        let normalized=Zeroizing::new(canonical_wire_value(&request,CanonicalPath::SecureArtifact).map_err(|_|KernelClientError::InvalidCommand)?);
        let workspace=command.get("workspace_id").and_then(WireValue::as_string);
        self.bind_structure_parent(identity,authority,&id,"INTENT",workspace.as_deref(),&normalized)?;
        let result=tokio::time::timeout_at(deadline,async{
            tokio::select!{biased;
                result=async{if saved{Box::pin(self.resume_saved_structure_intent(identity,authority,&id,None,cancel)).await}else{Box::pin(self.execute_structure_intent_prepared(identity,authority,normalized.as_bytes(),cancel)).await}}=>result,
                _=cancel.cancelled()=>Err(TransportError::Cancelled.into()),
            }
        }).await;
        self.parent_result(identity,&id,result)
    }
    pub(crate) async fn authorize_structure_access(&mut self,identity:&KernelIdentity,authority:&str,selection:StructureAccessApproval,cancel:&CancellationToken)
        ->Result<StructureIntentOutcome,KernelClientError>{
        Box::pin(self.authorize_structure_access_until(identity,authority,selection,cancel,Instant::now()+Duration::from_secs(30))).await
    }
    pub(crate) async fn authorize_structure_access_until(&mut self,identity:&KernelIdentity,authority:&str,selection:StructureAccessApproval,cancel:&CancellationToken,deadline:Instant)
        ->Result<StructureIntentOutcome,KernelClientError>{
        let (selection,id)=self.normalize_structure_access(identity,authority,selection)?;
        let wire=Zeroizing::new(serde_json::to_string(&selection).map_err(|_|KernelClientError::InvalidCommand)?);
        // There is no plaintext body here, but encrypt the whole plan so all
        // native producers obey one storage and binding contract.
        self.bind_structure_parent(identity,authority,&id,"ACCESS",Some(&selection.workspace_id),&wire)?;
        let result=tokio::time::timeout_at(deadline,async{
            tokio::select!{biased;
                result=Box::pin(self.authorize_structure_access_prepared(identity,authority,selection,cancel))=>result,
                _=cancel.cancelled()=>Err(TransportError::Cancelled.into()),
            }
        }).await;
        self.parent_result(identity,&id,result)
    }
    pub(crate) async fn resume_structure_intent_scoped(&mut self,identity:&KernelIdentity,authority:&str,id:&str,workspace:Option<&str>,cancel:&CancellationToken)
        ->Result<StructureIntentOutcome,KernelClientError>{
        Box::pin(self.resume_structure_parent_until(identity,authority,id,workspace,cancel,Instant::now()+Duration::from_secs(30))).await
    }
    pub(crate) async fn resume_structure_parent_until(&mut self,identity:&KernelIdentity,authority:&str,id:&str,workspace:Option<&str>,cancel:&CancellationToken,deadline:Instant)
        ->Result<StructureIntentOutcome,KernelClientError>{
        if let Some(parent)=self.journal.parent_selection(id,identity,self.origin(),self.discovery.audience_utf16(),authority,workspace)?{
            if parent.kind=="ARCHIVE_MIGRATION"{let selection=serde_json::from_str(&parent.wire).map_err(|_|JournalError::IncompatibleStore)?;return Box::pin(self.migrate_archive_until(identity,authority,selection,cancel,Instant::now()+Duration::from_secs(180))).await;}
        }
        if self.journal.verified_pending(id,identity.key_id(),self.discovery.audience_utf16())?.is_some(){
            let result=tokio::time::timeout_at(deadline,self.resume_saved_structure_intent(identity,authority,id,workspace,cancel)).await;
            return self.parent_result(identity,id,result);
        }
        let parent=self.journal.parent_selection(id,identity,self.origin(),self.discovery.audience_utf16(),authority,workspace)?;
        let parent=parent.ok_or(KernelClientError::IntentNotFound)?;
        match parent.kind.as_str(){
            "INTENT"=>Box::pin(self.execute_structure_intent_until(identity,authority,parent.wire.as_bytes(),cancel,deadline)).await,
            "PUBLICATION"=>{
                let selection=serde_json::from_str(&parent.wire).map_err(|_|JournalError::IncompatibleStore)?;
                Box::pin(self.publish_selected_record_until(identity,authority,selection,cancel,deadline)).await
            },
            "ACCESS"=>{
                let selection=serde_json::from_str(&parent.wire).map_err(|_|JournalError::IncompatibleStore)?;
                Box::pin(self.authorize_structure_access_until(identity,authority,selection,cancel,deadline)).await
            },_=>Err(JournalError::IncompatibleStore.into()),
        }
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use serde_json::json;
    fn fixture(origin:&str)->(crate::test_support::ProtectedTestDir,KernelIdentity,KernelClient){
        let dir=crate::test_support::protected_test_dir();let identity=KernelIdentity::create(&dir.path().join("identity")).unwrap();
        let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"parent-tests","protocol_features":["canonical-content-key-epochs-v1","owner-approved-key-floor-v1","owner-selected-publication-v1","selected-publication-snapshot-v1"],"command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":peerwork_core::crypto::key_id(&ed25519_dalek::SigningKey::from_bytes(&[22;32]).verifying_key().to_bytes()),"limits":{"max":1}})).unwrap();
        let discovery=peerwork_core::discovery::parse_discovery_wire(&wire,wire.len()).unwrap();let path=dir.path().join("operations.sqlite");
        let mut journal=KernelIntentJournal::open(&path).unwrap();journal.bind_discovery(origin,&discovery).unwrap();drop(journal);
        let mut config=TransportConfig::new(origin);config.allow_loopback_http=origin.starts_with("http://");
        let client=KernelClient::open_cached(config,&path,&[],&CancellationToken::new()).unwrap();(dir,identity,client)
    }
    fn command(outcome:StructureIntentOutcome)->String{match outcome{StructureIntentOutcome::Pending{command_id,phase,recovery,..}=>{assert_eq!(phase,"PREPARATION");assert_eq!(recovery,"RESUME_SAME_INTENT");command_id},other=>panic!("expected durable preparation, got {other:?}")}}
    #[test]
    fn incomplete_crypto_preparation_keeps_parent_id_and_verified_retryability(){
        let (_dir,identity,mut client)=fixture("https://example.invalid/");
        let parent="p".repeat(43);let child="c".repeat(43);
        client.bind_structure_parent(&identity,"authority",&parent,"INTENT",None,"{\"action\":\"structure.action\"}").unwrap();
        let outcome=client.parent_result(&identity,&parent,Ok(Err(KernelClientError::CryptoPrerequisitePending{command_id:child,workspace_id:"w".repeat(43),code:"RECIPIENT_PROOF_INVALID",retryable:false}))).unwrap();
        match outcome{StructureIntentOutcome::Pending{command_id,code,phase,retryable,recovery}=>{
            assert_eq!(command_id,parent);assert_eq!(phase,"PREPARATION");assert_eq!(code,"RECIPIENT_PROOF_INVALID");assert!(!retryable);assert_eq!(recovery,"RESUME_SAME_INTENT");
        },other=>panic!("expected a pending parent: {other:?}")}
    }
    #[tokio::test]
    async fn preparation_deadline_covers_crypto_and_survives_restart_without_signed_packet(){
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let origin=format!("http://{}/",listener.local_addr().unwrap());
        let (_dir,identity,mut client)=fixture(&origin);let authority_value="a".repeat(64);let authority=authority_value.as_str();let ws="w".repeat(43);
        let input=json!({"action":"structure.action","workspace_id":ws,"instance_id":"I".repeat(43),"protocol_digest":"a".repeat(64),"expected_instance_revision":1,"idempotency_key":"one-operation","body":{"action_id":"post","structure":{}},"plaintext_contents":[{"record_index":0,"text":"durable private preparation"}]});
        let wire=input.to_string();let start=Instant::now();
        // A real TCP peer accepts but never replies. The parent deadline must
        // win over the transport's much longer per-request timeout.
        let server=tokio::spawn(async move{let (_socket,_)=listener.accept().await.unwrap();std::future::pending::<()>().await;});
        let id=command(client.execute_structure_intent_until(&identity,authority,wire.as_bytes(),&CancellationToken::new(),Instant::now()+Duration::from_millis(35)).await.unwrap());
        assert!(start.elapsed()<Duration::from_secs(2));assert!(client.journal.verified_pending(&id,identity.key_id(),client.discovery.audience_utf16()).unwrap().is_none());
        let path=_dir.path().join("operations.sqlite");drop(client);let mut config=TransportConfig::new(&origin);config.allow_loopback_http=true;
        let mut client=KernelClient::open_cached(config,&path,&[],&CancellationToken::new()).unwrap();let cancel=CancellationToken::new();cancel.cancel();
        assert_eq!(command(client.resume_structure_intent_scoped(&identity,authority,&id,Some(&ws),&cancel).await.unwrap()),id);
        let mut changed=input;changed["plaintext_contents"][0]["text"]=json!("different private text");
        assert!(matches!(client.execute_structure_intent(&identity,authority,changed.to_string().as_bytes(),&cancel).await,Err(KernelClientError::Store(JournalError::IntentConflict))));
        assert!(client.resume_structure_intent_scoped(&identity,authority,&id,Some(&"x".repeat(43)),&cancel).await.is_err());server.abort();
    }
    #[tokio::test]
    async fn access_preparation_can_resume_without_a_packet_and_plain_selected_reads_do_not_stage(){
        let (_dir,identity,mut client)=fixture("https://example.invalid/");let cancel=CancellationToken::new();cancel.cancel();
        let selection:StructureAccessApproval=serde_json::from_value(json!({"workspace_id":"w".repeat(43),"request_jws":"synthetic-request-not-yet-verified","deliver_content_keys":false})).unwrap();
        let id=command(client.authorize_structure_access(&identity,"authority",selection.clone(),&cancel).await.unwrap());
        assert_eq!(command(client.resume_structure_intent(&identity,"authority",&id,&cancel).await.unwrap()),id);
        assert!(matches!(client.resume_structure_intent(&identity,"other-authority",&id,&cancel).await,Err(KernelClientError::Store(JournalError::IntentConflict))));
        assert!(client.execute_structure_intent(&identity,"authority",br#"{"action":"structure.workspace.get","workspace_id":"wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww","body":{}}"#,&cancel).await.is_err());
        let journal=KernelIntentJournal::open(&_dir.path().join("operations.sqlite")).unwrap();
        assert!(journal.parent_selection(&id,&identity,"https://example.invalid/",client.discovery.audience_utf16(),"authority",None).unwrap().is_some());
    }
    #[test]
    fn preparation_verification_failure_keeps_parent_and_never_claims_unknown_submission(){
        let (_dir,identity,mut client)=fixture("https://example.invalid/");let id="p".repeat(43);
        client.bind_structure_parent(&identity,"authority",&id,"PUBLICATION",Some(&"w".repeat(43)),"{}").unwrap();
        for error in [KernelClientError::InvalidResult,KernelClientError::Store(JournalError::InvalidReceipt)]{
            match client.parent_result(&identity,&id,Ok(Err(error))).unwrap(){
                StructureIntentOutcome::Pending{command_id,code,phase,retryable,recovery}=>{assert_eq!(command_id,id);assert_eq!(code,"VERIFICATION_FAILED");assert_eq!(phase,"PREPARATION");assert!(!retryable);assert_eq!(recovery,"RESUME_SAME_INTENT");},other=>panic!("expected a recoverable unsubmitted preparation: {other:?}")
            }
        }
    }
    #[tokio::test]
    async fn publication_preparation_is_encrypted_restartable_and_input_bound(){
        let (dir,identity,mut client)=fixture("https://example.invalid/");let cancel=CancellationToken::new();cancel.cancel();
        let selection:PublicationSnapshotSelection=serde_json::from_value(json!({"workspace_id":"w".repeat(43),"instance_id":"i".repeat(43),"protocol_digest":"a".repeat(64),"record_id":"r".repeat(43),"revision":1,"idempotency_key":"publication-selection","title":"Selected note","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"TEXT","text":"private-staged-publication-plaintext"}})).unwrap();
        let id=command(client.publish_selected_record_until(&identity,&"a".repeat(64),selection.clone(),&cancel,Instant::now()+Duration::from_secs(1)).await.unwrap());
        let path=dir.path().join("operations.sqlite");drop(client);let mut client=KernelClient::open_cached(TransportConfig::new("https://example.invalid/"),&path,&[],&CancellationToken::new()).unwrap();
        assert_eq!(command(client.resume_structure_intent_scoped(&identity,&"a".repeat(64),&id,Some(&selection.workspace_id),&cancel).await.unwrap()),id);
        let mut changed=selection.clone();changed.title="Different title".into();assert!(matches!(client.publish_selected_record_until(&identity,&"a".repeat(64),changed,&cancel,Instant::now()+Duration::from_secs(1)).await,Err(KernelClientError::Store(JournalError::IntentConflict))));
        let raw=std::fs::read(&path).unwrap();assert!(!raw.windows(b"private-staged-publication-plaintext".len()).any(|w|w==b"private-staged-publication-plaintext"));
        let mut oversized=selection;oversized.idempotency_key="oversized".into();oversized.body=PublicationSnapshotBody::Text{text:"a".repeat(65537)};assert!(client.publish_selected_record_until(&identity,&"a".repeat(64),oversized,&cancel,Instant::now()+Duration::from_secs(1)).await.is_err());
    }
    #[tokio::test]
    async fn publication_preparation_uses_the_call_deadline(){
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let origin=format!("http://{}/",listener.local_addr().unwrap());let (_dir,identity,mut client)=fixture(&origin);
        let server=tokio::spawn(async move{let (_socket,_)=listener.accept().await.unwrap();std::future::pending::<()>().await;});
        let selection=serde_json::from_value(json!({"workspace_id":"w".repeat(43),"instance_id":"i".repeat(43),"protocol_digest":"a".repeat(64),"record_id":"r".repeat(43),"revision":1,"idempotency_key":"bounded","title":"Selected note","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"RECORD"}})).unwrap();
        let start=Instant::now();let id=command(client.publish_selected_record_until(&identity,&"a".repeat(64),selection,&CancellationToken::new(),Instant::now()+Duration::from_millis(35)).await.unwrap());assert!(start.elapsed()<Duration::from_secs(2));assert!(client.journal.verified_pending(&id,identity.key_id(),client.discovery.audience_utf16()).unwrap().is_none());server.abort();
    }

}
