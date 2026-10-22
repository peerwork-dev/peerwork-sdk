//! Explicit reviewed recovery. Keys remain in the protected Owner profile;
//! invalid original BEGINs are retained rather than deleted or retried as valid.
use super::*;
use crate::{
    kernel_client::KernelClient,
    secure_journal_read::SecureJournalRead,
    secure_verified_read::{
        collect_unverified_artifacts, SecureJournalReadBudget, UnverifiedSignedArtifacts,
    },
};
use peerwork_core::{
    private_install_recovery::{inspect_invalid_install_recovery, InstallRecoveryCandidate},
    replayed_secure_journal::{JournalReplayInput, JournalReplayLimits},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidInstallRecoveryInput {
    pub begin_command_id: String,
    pub expected_review_hash: String,
    pub operation_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryDocument {
    v: u8,
    origin: String,
    workspace_id: String,
    actor_id: String,
    key_id: String,
    rows: BTreeMap<String, RecoveryRow>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RecoveryRow {
    begin_id: String,
    review_hash: String,
    plan_json: String,
    issued_at: u64,
    request_b64: String,
    commit_hash: String,
    policy_hash: String,
    sequence: u64,
    steps: Vec<InstallStep>,
    accepted: bool,
}
impl RecoveryDocument {
    fn open(
        store: &SecureStateStore,
        c: &SecureReadProfileConfig,
        i: &KernelIdentity,
    ) -> Result<Self, PrivatePackageInstallError> {
        let d: Self = match store.read_exact_secret()? {
            Some(b) => {
                serde_json::from_slice(&b).map_err(|_| PrivatePackageInstallError::Identity)?
            }
            None => Self {
                v: 1,
                origin: c.origin.clone(),
                workspace_id: c.workspace_id.clone(),
                actor_id: i.actor_id().into(),
                key_id: i.key_id().into(),
                rows: BTreeMap::new(),
            },
        };
        if d.v != 1
            || d.origin != c.origin
            || d.workspace_id != c.workspace_id
            || d.actor_id != i.actor_id()
            || d.key_id != i.key_id()
            || d.rows.len() > 16
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        Ok(d)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), PrivatePackageInstallError> {
        store.write_exact(
            &serde_json::to_vec(self).map_err(|_| PrivatePackageInstallError::Encoding)?,
        )?;
        Ok(())
    }
}
fn raw_candidate(
    c: &SecureReadProfileConfig,
    prior: &TransportReplayedJournal,
    i: &KernelIdentity,
    cancel: &CancellationToken,
) -> Result<(UnverifiedSignedArtifacts, String), PrivatePackageInstallError> {
    let mut transport = TransportConfig::new(c.origin.clone()).with_options(c.transport.clone());
    transport.allow_loopback_http = c.allow_loopback_http;
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| PrivatePackageInstallError::Runtime)?;
    let features = c
        .required_features
        .iter()
        .map(|s| s.encode_utf16().collect())
        .collect::<Vec<_>>();
    let client = rt
        .block_on(KernelClient::open(
            transport,
            &c.state_dir.join("kernel.sqlite"),
            &features,
            cancel,
        ))
        .map_err(|_| PrivatePackageInstallError::Transport)?;
    if client.origin() != prior.origin() {
        return Err(PrivatePackageInstallError::Identity);
    }
    let mut reader = SecureJournalRead::open(
        &c.state_dir.join("private-recovery-read.state"),
        &client,
        i,
        &c.workspace_id,
        prior.authority(),
    )
    .map_err(|_| PrivatePackageInstallError::Plan)?;
    reader
        .reset_inactive_generation()
        .map_err(|_| PrivatePackageInstallError::Plan)?;
    while !reader
        .progress()
        .map_err(|_| PrivatePackageInstallError::Plan)?
        .complete_transport
    {
        if cancel.is_cancelled() {
            return Err(SecureReadAccessError::Cancelled.into());
        }
        rt.block_on(reader.fetch_next(&client, i, cancel))
            .map_err(|_| PrivatePackageInstallError::Transport)?;
    }
    let pages = reader
        .authenticated_pages(&client, i)
        .map_err(|_| PrivatePackageInstallError::Plan)?;
    let budget =
        SecureJournalReadBudget::new_with_limits(c.max_replay_artifact_bytes, c.max_replay_commits)
            .ok_or(PrivatePackageInstallError::Input)?;
    let artifacts = collect_unverified_artifacts(&pages, budget)
        .map_err(|_| PrivatePackageInstallError::Plan)?;
    Ok((artifacts, pages.checkpoint_canonical_json().into()))
}
impl SecurePrivatePackageInstall {
    pub fn invalid_install_recovery_plan_json(
        &self,
        begin_id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        self.run_invalid_install_recovery(begin_id, None, cancel)
    }
    pub fn recover_invalid_install_json(
        &self,
        input: InvalidInstallRecoveryInput,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(&input.begin_command_id)
            || !token(&input.operation_id)
            || !digest(&input.expected_review_hash)
        {
            return Err(PrivatePackageInstallError::Input);
        }
        self.run_invalid_install_recovery(&input.begin_command_id, Some(&input), cancel)
    }
    fn run_invalid_install_recovery(
        &self,
        begin_id: &str,
        input: Option<&InvalidInstallRecoveryInput>,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        if !token(begin_id) {
            return Err(PrivatePackageInstallError::Input);
        }
        let mut transport_config = TransportConfig::new(self.config.origin.clone())
            .with_options(self.config.transport.clone());
        transport_config.allow_loopback_http = self.config.allow_loopback_http;
        let transport = HttpTransport::new(transport_config)
            .map_err(|_| PrivatePackageInstallError::Transport)?;
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| PrivatePackageInstallError::Runtime)?;
        let capabilities = rt
            .block_on(transport.install_capabilities(cancel))
            .map_err(|e| match e {
                TransportError::Cancelled => {
                    PrivatePackageInstallError::Read(SecureReadAccessError::Cancelled)
                }
                _ => PrivatePackageInstallError::Transport,
            })?;
        let cap: serde_json::Value = serde_json::from_slice(&capabilities.wire)
            .map_err(|_| PrivatePackageInstallError::RecoveryServiceUnsupported)?;
        if capabilities.status != 200
            || cap["v"] != 1
            || cap["recovery_profile"] != "owner-single-invalid-inline-install-v1"
            || cap["policy_restore"] != "EXACT_PREDECESSOR_STRUCTURE"
        {
            return Err(PrivatePackageInstallError::RecoveryServiceUnsupported);
        }
        drop(rt);
        SecureReadProfile::new(self.config.clone()).with_pinned_replay(cancel,|prior|{
            let identity=KernelIdentity::open(&self.config.identity_path).map_err(|_|PrivatePackageInstallError::Identity)?;
            if prior.replay().owner_actor_id()!=identity.actor_id()||prior.replay().owner_signing_key()!=identity.key_id(){return Err(PrivatePackageInstallError::Identity)}
            let installs=SecureStateStore::open(&self.config.state_dir.join("private-install-operations.state"))?;
            let originals=InstallDocument::open(&installs,&self.config,identity.actor_id(),identity.key_id())?;
            let original=originals.rows.get(begin_id).cloned().ok_or(PrivatePackageInstallError::Input)?;
            if original.import_attach_id.is_some()||original.accepted.is_some(){return Err(PrivatePackageInstallError::Plan)}
            drop(originals);drop(installs);
            let lifecycle=SecureLifecycle::open(&self.config.state_dir.join("lifecycle.state"),prior.origin(),identity.actor_id(),&self.config.workspace_id,identity.actor_id(),identity.key_id()).map_err(|_|PrivatePackageInstallError::Identity)?;
            let ring_wire=Zeroizing::new(lifecycle.active_keyring_without_pending().ok_or(PrivatePackageInstallError::Identity)?.canonical_wire().map_err(|_|PrivatePackageInstallError::Identity)?);
            let ring=SecretKeyring::parse_wire(&ring_wire).map_err(|_|PrivatePackageInstallError::Identity)?;drop(lifecycle);
            let store=SecureStateStore::open(&self.config.state_dir.join("private-install-recoveries.state"))?;
            let mut doc=RecoveryDocument::open(&store,&self.config,&identity)?;
            let (artifacts,checkpoint_json)=raw_candidate(&self.config,prior,&identity,cancel)?;
            let checkpoint=parse_wire_json_bounded(checkpoint_json.as_bytes(),32,8192).map_err(|_|PrivatePackageInstallError::Plan)?;
            if scalar(&checkpoint,"workspace_id")?!=self.config.workspace_id||scalar(&checkpoint,"owner_id")?!=identity.actor_id()||scalar(&checkpoint,"owner_key")?!=identity.key_id(){return Err(PrivatePackageInstallError::Identity)}
            let mut proofs=std::collections::HashMap::new();
            for wire in &artifacts.guard_time_attestation_wires{
                let p=parse_wire_json_bounded(wire,32,8192).map_err(|_|PrivatePackageInstallError::Plan)?;
                let hash=scalar(p.get("payload").ok_or(PrivatePackageInstallError::Plan)?,"commit_hash")?;
                if proofs.insert(hash,wire.clone()).is_some(){return Err(PrivatePackageInstallError::Plan)}
            }
            let policies=artifacts.policy_wires.iter().map(Vec::as_slice).collect::<Vec<_>>();let commits=artifacts.commit_wires.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let head=scalar(&checkpoint,"head")?;let policy_hash=scalar(&checkpoint,"policy_hash")?;
            let candidate=inspect_invalid_install_recovery(prior.replay(),JournalReplayInput{policy_wires:&policies,commit_wires:&commits,checkpoint_wire:checkpoint_json.as_bytes(),workspace_id:&self.config.workspace_id,owner_actor_id:identity.actor_id(),owner_signing_key:identity.key_id(),final_sequence:number(&checkpoint,"sequence")?,final_head:Some(&head),final_policy_hash:&policy_hash,keyring_wire:Some(&ring_wire)},JournalReplayLimits::new(self.config.max_replay_commits).ok_or(PrivatePackageInstallError::Plan)?,&proofs,begin_id,&original.commit_hash).map_err(PrivatePackageInstallError::Recovery)?;
            match candidate{
                InstallRecoveryCandidate::Invalid(draft)=>{
                    let Some(input)=input else{
                        let mut report:serde_json::Value=serde_json::from_str(draft.report_json()).map_err(|_|PrivatePackageInstallError::Encoding)?;
                        if let Some((id,_))=doc.rows.iter().find(|(_,r)|r.begin_id==begin_id&&r.review_hash==draft.review_hash()){
                            report["operation_id"]=id.clone().into();report["status"]="PENDING".into();
                        }
                        return Ok(report.to_string());
                    };
                    if draft.review_hash()!=input.expected_review_hash{return Err(PrivatePackageInstallError::RecoveryReviewConflict)}
                    if input.operation_id==begin_id{return Err(PrivatePackageInstallError::Input)}
                    if doc.rows.values().any(|r|r.begin_id==begin_id)&&!doc.rows.contains_key(&input.operation_id){return Err(PrivatePackageInstallError::RecoveryOperationConflict)}
                    let policy=artifacts.policy_wires.iter().find(|w|sha256_hex(w)==policy_hash).ok_or(PrivatePackageInstallError::Plan)?;
                    let policy=parse_wire_json_bounded(policy,64,196_608).map_err(|_|PrivatePackageInstallError::Plan)?;
                    let epoch=number(policy.get("payload").ok_or(PrivatePackageInstallError::Plan)?,"epoch")?;
                    let key=ring.key_at(epoch).ok_or(PrivatePackageInstallError::Identity)?;
                    if !doc.rows.contains_key(&input.operation_id){
                        if doc.rows.len()>=16{return Err(PrivatePackageInstallError::Input)}
                        let issued=now_ms()?;let (wire,hash,policy)=draft.prepare(identity.signing_key(),key,&input.operation_id,issued).map_err(|_|PrivatePackageInstallError::Plan)?;
                        doc.rows.insert(input.operation_id.clone(),RecoveryRow{begin_id:begin_id.into(),review_hash:input.expected_review_hash.clone(),plan_json:draft.report_json().into(),issued_at:issued,request_b64:base64url(&wire),commit_hash:hash,policy_hash:policy,sequence:number(&checkpoint,"sequence")?+1,steps:vec![],accepted:false});doc.save(&store)?;
                    }
                    let row=doc.rows.get(&input.operation_id).ok_or(PrivatePackageInstallError::Plan)?;
                    if row.begin_id!=begin_id||row.review_hash!=input.expected_review_hash{return Err(PrivatePackageInstallError::RecoveryOperationConflict)}
                    let wire=decode_base64url(&row.request_b64).map_err(|_|PrivatePackageInstallError::Plan)?;
                    let (hash,policy)=draft.verify_saved(&wire,identity.signing_key(),key,&input.operation_id,row.issued_at).map_err(|_|PrivatePackageInstallError::Plan)?;
                    if hash!=row.commit_hash||policy!=row.policy_hash{return Err(PrivatePackageInstallError::Plan)}
                    let mut journal=SecureIntentJournal::open(&self.config.state_dir.join("private-install-recovery-intents.state"),prior.origin(),identity.actor_id())?;
                    let path=format!("/api/workspace/v1/secure/workspaces/{}/commits",self.config.workspace_id);
                    journal.prepare(SecurePacketInput{intent_id:&input.operation_id,path:&path,action_id:"secure.recover",workspace_id:Some(&self.config.workspace_id),trusted_owner_key:Some(identity.key_id()),intent_digest:&hash,exact_request:&wire})?;
                    post_saved_private(&self.config,prior.origin(),&mut journal,&input.operation_id,wire,cancel)?;
                    Ok(serde_json::json!({"schema":"peerwork.install-recovery-progress.v1","status":"PENDING","operation_id":input.operation_id,"original_begin_id":begin_id,"phase":"RECOVERY","new_begin_required":true}).to_string())
                }
                InstallRecoveryCandidate::Verified(current)=>{
                    let (operation_id,mut row)=if let Some(input)=input{
                        let row=doc.rows.get(&input.operation_id).cloned().ok_or(PrivatePackageInstallError::Plan)?;
                        if row.begin_id!=begin_id||row.review_hash!=input.expected_review_hash{return Err(PrivatePackageInstallError::RecoveryOperationConflict)}
                        (input.operation_id.clone(),row)
                    }else{
                        let (id,row)=doc.rows.iter().find(|(_,r)|r.begin_id==begin_id).ok_or(PrivatePackageInstallError::Plan)?;
                        return Ok(serde_json::json!({"schema":"peerwork.install-recovery-plan.v1","status":if row.accepted{"RECOVERED"}else{"PENDING"},"operation_id":id,"original_begin_id":begin_id,"review_hash":row.review_hash,"submitted":false}).to_string());
                    };
                    if !current.contains_checkpoint(row.sequence,Some(&row.commit_hash),&row.policy_hash){return Err(PrivatePackageInstallError::Plan)}
                    for (index,step) in row.steps.iter().enumerate(){if current.sequence()>=row.sequence+index as u64+1&&!current.contains_checkpoint(row.sequence+index as u64+1,Some(&step.commit_hash),&row.policy_hash){return Err(PrivatePackageInstallError::Plan)}}
                    if current.structure_status()==StructureStatus::Active{
                        let end=row.steps.last().ok_or(PrivatePackageInstallError::Plan)?;
                        if end.action_id!="secure.structure.end"||!current.contains_checkpoint(row.sequence+row.steps.len() as u64,Some(&end.commit_hash),&row.policy_hash){return Err(PrivatePackageInstallError::Plan)}
                        row.accepted=true;doc.rows.insert(operation_id.clone(),row);doc.save(&store)?;
                        let installs=SecureStateStore::open(&self.config.state_dir.join("private-install-operations.state"))?;
                        let mut originals=InstallDocument::open(&installs,&self.config,identity.actor_id(),identity.key_id())?;
                        originals.rows.get_mut(begin_id).ok_or(PrivatePackageInstallError::Plan)?.recovered_by=Some(operation_id.clone());originals.save(&installs)?;
                        return Ok(serde_json::json!({"schema":"peerwork.install-recovery-progress.v1","status":"ACCEPTED","operation_id":operation_id,"original_begin_id":begin_id,"phase":"ACTIVE","new_begin_required":true}).to_string());
                    }
                    if current.structure_status()!=StructureStatus::Seeding||current.policy_hash()!=row.policy_hash{return Err(PrivatePackageInstallError::Plan)}
                    let snapshot=current.structure_snapshot().ok_or(PrivatePackageInstallError::Plan)?;
                    let policy=artifacts.policy_wires.iter().find(|w|sha256_hex(w)==row.policy_hash).ok_or(PrivatePackageInstallError::Plan)?;
                    let policy_value=parse_wire_json_bounded(policy,64,196_608).map_err(|_|PrivatePackageInstallError::Plan)?;
                    let p=policy_value.get("payload").ok_or(PrivatePackageInstallError::Plan)?;
                    let key=ring.key_at(number(p,"epoch")?).ok_or(PrivatePackageInstallError::Identity)?;
                    let plan=plan_public_install_snapshot(prior.replay().objects(),p.get("structure").ok_or(PrivatePackageInstallError::Plan)?,snapshot.get("source").ok_or(PrivatePackageInstallError::Plan)?).map_err(|_|PrivatePackageInstallError::Plan)?;
                    if !same_snapshot(plan.snapshot(),snapshot){return Err(PrivatePackageInstallError::Plan)}
                    let offset=usize::try_from(number(snapshot,"offset")?).map_err(|_|PrivatePackageInstallError::Plan)?;
                    let done=offset==plan.records().len()+plan.heads().len();let id=install_step_id(&operation_id,offset,done);
                    let issued=if let Some(step)=row.steps.iter().find(|s|s.command_id==id){step.issued_at_ms}else{now_ms()?};
                    let prepared=if let Some(step)=row.steps.iter().find(|s|s.command_id==id){
                        let wire=decode_base64url(&step.request_b64).map_err(|_|PrivatePackageInstallError::Plan)?;
                        let prepared=verify_saved_private_package_install_step(&wire,policy,checkpoint_json.as_bytes(),snapshot,&plan,&id,issued,identity.signing_key(),key)?;
                        if prepared.commit_hash()!=step.commit_hash{return Err(PrivatePackageInstallError::Plan)}prepared
                    }else{
                        if current.sequence()!=row.sequence+row.steps.len() as u64{return Err(PrivatePackageInstallError::Plan)}
                        let prepared=prepare_private_package_install_step(policy,checkpoint_json.as_bytes(),snapshot,&plan,&id,issued,identity.signing_key(),key)?;
                        row.steps.push(InstallStep{command_id:id.clone(),issued_at_ms:issued,request_b64:base64url(prepared.request_wire()),commit_hash:prepared.commit_hash().into(),action_id:prepared.action_id().into(),offset});doc.rows.insert(operation_id.clone(),row);doc.save(&store)?;prepared
                    };
                    let mut journal=SecureIntentJournal::open(&self.config.state_dir.join("private-install-recovery-intents.state"),prior.origin(),identity.actor_id())?;
                    let path=format!("/api/workspace/v1/secure/workspaces/{}/commits",self.config.workspace_id);
                    journal.prepare(SecurePacketInput{intent_id:&id,path:&path,action_id:prepared.action_id(),workspace_id:Some(&self.config.workspace_id),trusted_owner_key:Some(identity.key_id()),intent_digest:prepared.commit_hash(),exact_request:prepared.request_wire()})?;
                    post_saved_private(&self.config,prior.origin(),&mut journal,&id,prepared.request_wire().to_vec(),cancel)?;
                    Ok(serde_json::json!({"schema":"peerwork.install-recovery-progress.v1","status":"PENDING","operation_id":operation_id,"original_begin_id":begin_id,"phase":"SNAPSHOT","new_begin_required":true}).to_string())
                }
            }
        })
    }
}
