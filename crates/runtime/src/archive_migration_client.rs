//! One recoverable Owner operation: current archive source, local preparation,
//! one bounded bulk upload, and backend-owned validation/import/activation.
use super::structure_access_client::data;
use super::*;
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, sha256_hex},
    prepared_command::{verify_structure_author_intent, SignedPreparedCommand},
    wire_json::canonical_wire_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::time::Duration;
use tokio::time::Instant;
use zeroize::Zeroizing;
const FEATURE: &str = "owner-self-service-archive-migration-v1";
const MAX: usize = 64 * 1024 * 1024;
type Result<T> = std::result::Result<T, KernelClientError>;
fn bad(code: &'static str) -> KernelClientError {
    KernelClientError::ArchiveMigration(code)
}
fn value(wire: &str) -> Result<WireValue> {
    parse_wire_json_bounded(wire.as_bytes(), 40, 524288).map_err(|_| bad("MIGRATION_INPUT_INVALID"))
}
fn set(command: &mut WireValue, key: &str, item: WireValue) {
    let WireValue::Object(fields) = command else {
        unreachable!()
    };
    let key = key.encode_utf16().collect::<Vec<_>>();
    if let Some((_, old)) = fields.iter_mut().find(|(k, _)| *k == key) {
        *old = item;
    } else {
        fields.push((key, item));
    }
}
fn child(parent: &str, tag: &str) -> String {
    base64url(&peerwork_core::crypto::sha256(
        format!("peerwork.archive-migration-child.v1:{parent}:{tag}").as_bytes(),
    ))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMigrationSelection {
    pub workspace_id: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub checkpoint_path: Option<PathBuf>,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    #[serde(default)]
    pub plan_path: Option<PathBuf>,
    #[serde(default)]
    pub read_only_snapshot: bool,
    #[serde(default)]
    pub name: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Artifact {
    path: PathBuf,
    sha256: String,
    bytes: usize,
    begin_jws: String,
    snapshot_sha256: String,
}
fn inspect(
    path: &Path,
    identity: &KernelIdentity,
    audience: &[u16],
    workspace: &str,
    authority: &str,
) -> Result<Artifact> {
    let bytes = crate::secure_state::read_private_file_bounded(path, MAX)
        .map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?;
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(bad("MIGRATION_CHECKPOINT_FILE_INVALID"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?;
    let mut begin = None;
    let mut chain = String::new();
    let mut index = 0u64;
    for line in text.lines() {
        if line.len() > 250000 {
            return Err(bad("MIGRATION_CHECKPOINT_PACKET_LIMIT"));
        }
        let wrapper: Value =
            serde_json::from_str(line).map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?;
        if wrapper.as_object().map(|m| m.len()) != Some(1) {
            return Err(bad("MIGRATION_CHECKPOINT_FILE_INVALID"));
        }
        let jws = wrapper["jws"]
            .as_str()
            .ok_or_else(|| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?;
        let proof = verify_structure_author_intent(jws, audience)
            .map_err(|_| bad("MIGRATION_CHECKPOINT_SIGNATURE_INVALID"))?;
        if proof.actor_id() != identity.actor_id()
            || proof.workspace_id() != Some(workspace)
            || proof
                .command()
                .get("authority")
                .and_then(WireValue::as_string)
                .as_deref()
                != Some(authority)
        {
            return Err(bad("MIGRATION_CHECKPOINT_OWNER_MISMATCH"));
        }
        let command: Value = serde_json::from_str(
            &canonical_wire_value(proof.command(), CanonicalPath::STRUCTURED)
                .map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?,
        )
        .map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?;
        let body = &command["body"];
        if begin.is_none() {
            if proof.action_id() != "structure.checkpoint.begin" {
                return Err(bad("MIGRATION_CHECKPOINT_BEGIN_REQUIRED"));
            }
            chain = sha256_hex(
                canonical_wire_value(
                    &value(
                        &json!([
                            "peerwork.owner-checkpoint.v1",
                            body["source"],
                            body["mapping_digest"],
                            body["conversion_id"]
                        ])
                        .to_string(),
                    )?,
                    CanonicalPath::STRUCTURED,
                )
                .map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?
                .as_bytes(),
            );
            begin = Some((jws.to_owned(), body.clone()));
        } else {
            let first = &begin.as_ref().unwrap().1;
            if !matches!(
                proof.action_id(),
                "structure.checkpoint.instance"
                    | "structure.checkpoint.records"
                    | "structure.checkpoint.relations"
            ) || body["conversion_id"] != first["conversion_id"]
                || body["page_index"].as_u64() != Some(index)
                || body["previous_digest"].as_str() != Some(&chain)
            {
                return Err(bad("MIGRATION_CHECKPOINT_CHAIN_INVALID"));
            }
            chain = sha256_hex(
                canonical_wire_value(
                    &value(&json!([chain, index, sha256_hex(jws.as_bytes())]).to_string())?,
                    CanonicalPath::STRUCTURED,
                )
                .map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?
                .as_bytes(),
            );
            index += 1;
        }
    }
    let (begin_jws, body) = begin.ok_or_else(|| bad("MIGRATION_CHECKPOINT_BEGIN_REQUIRED"))?;
    if body["page_count"].as_u64() != Some(index) || body["final_digest"].as_str() != Some(&chain) {
        return Err(bad("MIGRATION_CHECKPOINT_FINAL_DIGEST_INVALID"));
    }
    Ok(Artifact {
        path: path.to_owned(),
        sha256: sha256_hex(&bytes),
        bytes: bytes.len(),
        begin_jws,
        snapshot_sha256: body["source"]["snapshot_sha256"]
            .as_str()
            .ok_or_else(|| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?
            .into(),
    })
}
fn job_failure(id: &str, state: &Value) -> KernelClientError {
    let job = &state["migration"];
    KernelClientError::OperationRefused(Box::new(OperationRefusal {
        command_id: id.into(),
        server_code: job["error"]["code"]
            .as_str()
            .unwrap_or("MIGRATION_FAILED")
            .into(),
        phase: job["phase"].as_str().unwrap_or("MIGRATION").into(),
        http_status: None,
        retryable: job["error"]["retryable"].as_bool().unwrap_or(false),
        recovery: "CORRECT_INPUT_AND_NEW_OPERATION".into(),
        effect_certainty: if job["phase"] == "IMPORT" {
            "UNKNOWN"
        } else {
            "NOT_APPLIED"
        },
    }))
}
impl KernelClient {
    async fn migration_read(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        workspace: &str,
        action: &str,
        body: Value,
        cancel: &CancellationToken,
    ) -> Result<KernelAcceptedResult> {
        match Box::pin(
            self.execute_structure_intent_prepared(
                identity,
                authority,
                json!({"action":action,"workspace_id":workspace,"body":body})
                    .to_string()
                    .as_bytes(),
                cancel,
            ),
        )
        .await?
        {
            StructureIntentOutcome::Accepted(result) => {
                data(&result)?;
                Ok(result)
            }
            _ => Err(bad("MIGRATION_OBSERVATION_UNAVAILABLE")),
        }
    }
    async fn migration_signed_read(
        &self,
        identity: &KernelIdentity,
        authority: &str,
        workspace: &str,
        action: &str,
        body: Value,
        cancel: &CancellationToken,
    ) -> Result<SignedPreparedCommand> {
        let (_, mut command, _) = self.structure_command(
            identity,
            authority,
            json!({"action":action,"workspace_id":workspace,"body":body})
                .to_string()
                .as_bytes(),
        )?;
        let context = self.fresh_structure_context(cancel).await?;
        set(
            &mut command,
            "issued_at",
            WireValue::Number(context.server_time_ms() as f64),
        );
        set(
            &mut command,
            "expires_at",
            WireValue::Number(context.expires_at_ms() as f64),
        );
        prepare_signed_command_wire(&command, identity.signing_key(), &self.discovery, None)
            .map_err(|_| bad("MIGRATION_AUTHORIZATION_INVALID"))
    }
    fn verify_migration_response(
        &self,
        signed: &SignedPreparedCommand,
        response: &ExactHttpResponse,
    ) -> Result<KernelAcceptedResult> {
        if !(200..300).contains(&response.status) {
            return Err(KernelClientError::ServerRejected(response.status));
        }
        let proof = verify_http_response_for_prepared(
            &response.wire,
            signed.proof(),
            self.discovery.receipt_public_key(),
        )
        .map_err(|_| JournalError::InvalidReceipt)?;
        let result = KernelAcceptedResult::from_verified(proof, signed.proof(), None)?;
        data(&result)?;
        Ok(result)
    }
    pub(crate) async fn migrate_archive_until(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        selection: ArchiveMigrationSelection,
        cancel: &CancellationToken,
        deadline: Instant,
    ) -> Result<StructureIntentOutcome> {
        if !self
            .discovery
            .protocol_features()
            .contains(&FEATURE.encode_utf16().collect::<Vec<_>>())
        {
            return Err(KernelClientError::UnsupportedStructureProfile);
        }
        if !valid_token(&selection.workspace_id)
            || selection.checkpoint_path.is_some() == selection.state_dir.is_some()
            || selection.state_dir.is_some() && !selection.read_only_snapshot
        {
            return Err(bad("MIGRATION_SELECTION_INVALID"));
        }
        let id = super::structure_keyed_command_id(
            self.origin(),
            identity.actor_id(),
            WireValue::String(selection.workspace_id.encode_utf16().collect()),
            &selection.idempotency_key.encode_utf16().collect::<Vec<_>>(),
        )?;
        let wire = Zeroizing::new(
            serde_json::to_string(&selection).map_err(|_| bad("MIGRATION_SELECTION_INVALID"))?,
        );
        self.bind_structure_parent(
            identity,
            authority,
            &id,
            "ARCHIVE_MIGRATION",
            Some(&selection.workspace_id),
            &wire,
        )?;
        let result = tokio::time::timeout_at(
            deadline,
            self.migrate_archive_prepared(identity, authority, &id, &selection, cancel),
        )
        .await;
        match result {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(KernelClientError::ArchiveMigration("MIGRATION_SOURCE_REQUEST_PENDING")))
            | Err(_)
            | Ok(Err(KernelClientError::Transport(
                TransportError::Cancelled
                | TransportError::Network
                | TransportError::Timeout
                | TransportError::SubmittedUncertain,
            ))) => Ok(StructureIntentOutcome::Pending {
                command_id: id,
                code: "MIGRATION_IN_PROGRESS",
                phase: "MIGRATION",
                retryable: true,
                recovery: "RESUME_SAME_INTENT",
            }),
            Ok(Err(KernelClientError::ServerRejected(401 | 403 | 429 | 500..=599))) => {
                Ok(StructureIntentOutcome::Pending {
                    command_id: id,
                    code: "MIGRATION_SERVICE_UNAVAILABLE",
                    phase: "MIGRATION",
                    retryable: true,
                    recovery: "RESUME_SAME_INTENT",
                })
            }
            Ok(Err(
                KernelClientError::InvalidResult
                | KernelClientError::Store(JournalError::InvalidReceipt),
            )) => Ok(StructureIntentOutcome::Pending {
                command_id: id,
                code: "VERIFICATION_FAILED",
                phase: "MIGRATION",
                retryable: false,
                recovery: "RESUME_SAME_INTENT",
            }),
            Ok(Err(KernelClientError::ArchiveMigration(code))) => Err(
                KernelClientError::OperationRefused(Box::new(OperationRefusal {
                    command_id: id.clone(),
                    server_code: code.into(),
                    phase: if self
                        .journal
                        .verified_pending(&id, identity.key_id(), self.discovery.audience_utf16())?
                        .is_some()
                    {
                        "MIGRATION"
                    } else {
                        "LOCAL_PREPARATION"
                    }
                    .into(),
                    http_status: None,
                    retryable: false,
                    recovery: "INSPECT_SOURCE_AND_RESUME_SAME_OPERATION".into(),
                    effect_certainty: if self
                        .journal
                        .verified_pending(&id, identity.key_id(), self.discovery.audience_utf16())?
                        .is_some()
                    {
                        "UNKNOWN"
                    } else {
                        "NOT_SUBMITTED"
                    },
                })),
            ),
            Ok(Err(error)) => Err(error),
        }
    }
    async fn migrate_archive_prepared(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        id: &str,
        q: &ArchiveMigrationSelection,
        cancel: &CancellationToken,
    ) -> Result<StructureIntentOutcome> {
        // Recover admission first. A committed job does not depend on a still-present
        // local artifact and is never replaced with a newly signed mapping.
        if self
            .journal
            .verified_pending(id, identity.key_id(), self.discovery.audience_utf16())?
            .is_some()
        {
            let admission = Box::pin(self.resume_saved_structure_intent(
                identity,
                authority,
                id,
                Some(&q.workspace_id),
                cancel,
            ))
            .await?;
            if let StructureIntentOutcome::Accepted(result) = admission {
                data(&result)?;
            } else {
                return Ok(admission);
            }
            let current = self
                .migration_read(
                    identity,
                    authority,
                    &q.workspace_id,
                    "structure.migration.get",
                    json!({"job_id":id}),
                    cancel,
                )
                .await?;
            let state = data(&current)?;
            if state["migration"]["state"] == "COMPLETE" {
                return Ok(StructureIntentOutcome::Completed {
                    command_id: id.into(),
                    result: current,
                });
            }
            if state["migration"]["state"] == "FAILED" {
                return Err(job_failure(id, &state));
            }
        }
        let artifact_id = child(id, "artifact");
        let artifact = match self.journal.parent_selection(
            &artifact_id,
            identity,
            self.origin(),
            self.discovery.audience_utf16(),
            authority,
            Some(&q.workspace_id),
        )? {
            Some(saved) => serde_json::from_str::<Artifact>(&saved.wire)
                .map_err(|_| JournalError::IncompatibleStore)?,
            None => {
                let artifact = if let Some(path) = &q.checkpoint_path {
                    inspect(
                        path,
                        identity,
                        self.discovery.audience_utf16(),
                        &q.workspace_id,
                        authority,
                    )?
                } else {
                    self.prepare_archive_source(identity, authority, id, q, cancel)
                        .await?
                };
                let wire = serde_json::to_string(&artifact)
                    .map_err(|_| bad("MIGRATION_SELECTION_INVALID"))?;
                let origin = self.origin().to_owned();
                self.journal.bind_parent_selection(
                    &artifact_id,
                    identity,
                    &origin,
                    self.discovery.audience_utf16(),
                    authority,
                    "ARCHIVE_ARTIFACT",
                    Some(&q.workspace_id),
                    &wire,
                )?;
                artifact
            }
        };
        if self
            .journal
            .verified_pending(id, identity.key_id(), self.discovery.audience_utf16())?
            .is_none()
        {
            let source = self
                .migration_read(
                    identity,
                    authority,
                    &q.workspace_id,
                    "structure.migration.info",
                    json!({}),
                    cancel,
                )
                .await?;
            if data(&source)?["source"]["snapshot_sha256"] != artifact.snapshot_sha256 {
                return Err(bad("MIGRATION_SNAPSHOT_CHANGED"));
            }
            let admission = json!({"action":"structure.migration.open","workspace_id":q.workspace_id,"command_id":id,"body":{"artifact_sha256":artifact.sha256,"artifact_bytes":artifact.bytes,"begin_jws":artifact.begin_jws}});
            let result = Box::pin(self.execute_structure_intent_prepared(
                identity,
                authority,
                admission.to_string().as_bytes(),
                cancel,
            ))
            .await?;
            if let StructureIntentOutcome::Accepted(result) = result {
                data(&result)?;
            } else {
                return Ok(result);
            }
        }
        let current = self
            .migration_read(
                identity,
                authority,
                &q.workspace_id,
                "structure.migration.get",
                json!({"job_id":id}),
                cancel,
            )
            .await?;
        let status = data(&current)?;
        let job = &status["migration"];
        if job["state"] == "UPLOADING" {
            let offset = job["uploaded_bytes"]
                .as_u64()
                .filter(|n| *n <= artifact.bytes as u64)
                .ok_or(KernelClientError::InvalidResult)? as usize;
            if offset < artifact.bytes {
                // Revalidate the immutable selected file before resuming at its committed
                // offset. No key import or historical workspace replay occurs here.
                let bytes = crate::secure_state::read_private_file_bounded(&artifact.path, MAX)
                    .map_err(|_| bad("MIGRATION_CHECKPOINT_FILE_INVALID"))?;
                if bytes.len() != artifact.bytes || sha256_hex(&bytes) != artifact.sha256 {
                    return Err(bad("MIGRATION_ARTIFACT_CHANGED"));
                }
                let signed = self
                    .migration_signed_read(
                        identity,
                        authority,
                        &q.workspace_id,
                        "structure.migration.upload.get",
                        json!({"job_id":id,"offset":offset,"artifact_sha256":artifact.sha256}),
                        cancel,
                    )
                    .await?;
                let response = self
                    .transport
                    .migration_upload(signed.jws(), bytes[offset..].to_vec(), cancel)
                    .await?;
                let uploaded = self.verify_migration_response(&signed, &response)?;
                let state = data(&uploaded)?;
                if state["migration"]["artifact_sha256"] != artifact.sha256
                    || state["migration"]["uploaded_bytes"].as_u64() != Some(artifact.bytes as u64)
                {
                    return Err(KernelClientError::InvalidResult);
                }
            }
            let commit = json!({"action":"structure.migration.commit","workspace_id":q.workspace_id,"idempotency_key":format!("migration-commit-{id}"),"body":{"job_id":id}});
            let result = Box::pin(self.execute_structure_intent_prepared(
                identity,
                authority,
                commit.to_string().as_bytes(),
                cancel,
            ))
            .await?;
            if let StructureIntentOutcome::Accepted(result) = result {
                data(&result)?;
            } else {
                return Ok(StructureIntentOutcome::Pending {
                    command_id: id.into(),
                    code: "MIGRATION_IN_PROGRESS",
                    phase: "MIGRATION",
                    retryable: true,
                    recovery: "RESUME_SAME_INTENT",
                });
            }
        }
        loop {
            let observed = self
                .migration_read(
                    identity,
                    authority,
                    &q.workspace_id,
                    "structure.migration.get",
                    json!({"job_id":id}),
                    cancel,
                )
                .await?;
            let state = data(&observed)?;
            match state["migration"]["state"].as_str() {
                Some("COMPLETE") => {
                    return Ok(StructureIntentOutcome::Completed {
                        command_id: id.into(),
                        result: observed,
                    })
                }
                Some("FAILED") => return Err(job_failure(id, &state)),
                Some("QUEUED" | "VALIDATING" | "IMPORTING" | "UPLOADING") => {}
                _ => return Err(KernelClientError::InvalidResult),
            }
            tokio::select! {_=cancel.cancelled()=>return Err(TransportError::Cancelled.into()),_=tokio::time::sleep(Duration::from_millis(300))=>{}}
        }
    }
    async fn prepare_archive_source(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        id: &str,
        q: &ArchiveMigrationSelection,
        cancel: &CancellationToken,
    ) -> Result<Artifact> {
        let directory = q
            .state_dir
            .as_ref()
            .ok_or_else(|| bad("MIGRATION_STATE_DIR_REQUIRED"))?;
        let selected = KernelIdentity::open(&directory.join("identity.state"))
            .map_err(|_| bad("MIGRATION_OWNER_STATE_INVALID"))?;
        if selected.key_id() != identity.key_id() {
            return Err(bad("MIGRATION_OWNER_STATE_MISMATCH"));
        }
        let info = self
            .migration_read(
                identity,
                authority,
                &q.workspace_id,
                "structure.migration.info",
                json!({}),
                cancel,
            )
            .await?;
        let info = data(&info)?;
        let snapshot = info["source"]["snapshot_sha256"]
            .as_str()
            .ok_or(KernelClientError::InvalidResult)?;
        let base = directory.join(format!("self-migrate-{id}"));
        let recipient = base.with_extension("recipient");
        let request = base.with_extension("request.json");
        let source = base.with_extension("source.encrypted");
        let capsule = base.with_extension("capsule");
        let plan = q
            .plan_path
            .clone()
            .unwrap_or_else(|| base.with_extension("plan.json"));
        let checkpoint = base.with_extension("checkpoint.jsonl");
        let local = |result: String| -> Result<Value> {
            let parsed: Value =
                serde_json::from_str(&result).map_err(|_| bad("MIGRATION_PREPARATION_FAILED"))?;
            if parsed["ok"] != true {
                return Err(KernelClientError::OperationRefused(Box::new(
                    OperationRefusal {
                        command_id: id.into(),
                        server_code: parsed["code"]
                            .as_str()
                            .unwrap_or("MIGRATION_LOCAL_PREPARATION_FAILED")
                            .into(),
                        phase: "LOCAL_PREPARATION".into(),
                        http_status: None,
                        retryable: false,
                        recovery: "CORRECT_MAPPING_AND_RESUME_SAME_CAPSULE".into(),
                        effect_certainty: "NOT_SUBMITTED",
                    },
                )));
            }
            Ok(parsed["value"].clone())
        };
        let export_id = child(id, "source");
        if !capsule.exists() {
            local(crate::legacy_migration::source_json("request-source",&json!({"identity_path":directory.join("identity.state"),"expected_actor":identity.actor_id(),"recipient_path":recipient,"request_path":request,"workspace_id":q.workspace_id,"snapshot_sha256":snapshot,"audience":String::from_utf16(self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidCommand)?,"service_key":self.discovery.receipt_public_key(),"authority":authority}).to_string()))?;
            let requested: Value = serde_json::from_slice(
                &crate::secure_state::read_private_file_bounded(&request, 65536)
                    .map_err(|_| bad("MIGRATION_SOURCE_REQUEST_INVALID"))?,
            )
            .map_err(|_| bad("MIGRATION_SOURCE_REQUEST_INVALID"))?;
            let export = json!({"action":"structure.migration.source.request","workspace_id":q.workspace_id,"command_id":export_id,"body":{"request_jws":requested["jws"]}});
            let result = Box::pin(self.execute_structure_intent_prepared(
                identity,
                authority,
                export.to_string().as_bytes(),
                cancel,
            ))
            .await?;
            if let StructureIntentOutcome::Accepted(result) = result {
                data(&result)?;
            } else {
                return Err(bad("MIGRATION_SOURCE_REQUEST_PENDING"));
            }
            loop {
                let observed = self
                    .migration_read(
                        identity,
                        authority,
                        &q.workspace_id,
                        "structure.migration.source.get",
                        json!({"job_id":export_id}),
                        cancel,
                    )
                    .await?;
                let state = data(&observed)?;
                match state["migration"]["state"].as_str() {
                    Some("COMPLETE") => break,
                    Some("FAILED") => return Err(bad("MIGRATION_SOURCE_EXPORT_FAILED")),
                    _ => {}
                }
                tokio::select! {_=cancel.cancelled()=>return Err(TransportError::Cancelled.into()),_=tokio::time::sleep(Duration::from_millis(300))=>{}}
            }
            if !source.exists() {
                let signed = self
                    .migration_signed_read(
                        identity,
                        authority,
                        &q.workspace_id,
                        "structure.migration.source.read",
                        json!({"job_id":export_id}),
                        cancel,
                    )
                    .await?;
                let (receipt, bytes) = self
                    .transport
                    .migration_source(signed.jws(), cancel)
                    .await?;
                let result = self.verify_migration_response(&signed, &receipt)?;
                let state = data(&result)?;
                if sha256_hex(&bytes)
                    != state["migration"]["artifact_sha256"]
                        .as_str()
                        .ok_or(KernelClientError::InvalidResult)?
                    || state["migration"]["artifact_bytes"].as_u64() != Some(bytes.len() as u64)
                {
                    return Err(KernelClientError::InvalidResult);
                }
                crate::kernel_intents::ensure_private_parent(&source)
                    .map_err(|_| bad("MIGRATION_SOURCE_PATH_INVALID"))?;
                let mut file = tempfile::NamedTempFile::new_in(directory)
                    .map_err(|_| bad("MIGRATION_SOURCE_WRITE_FAILED"))?;
                file.write_all(&bytes)
                    .map_err(|_| bad("MIGRATION_SOURCE_WRITE_FAILED"))?;
                file.as_file()
                    .sync_all()
                    .map_err(|_| bad("MIGRATION_SOURCE_WRITE_FAILED"))?;
                file.persist_noclobber(&source)
                    .map_err(|_| bad("MIGRATION_SOURCE_WRITE_FAILED"))?;
            }
            local(crate::legacy_migration::source_json("capture-source",&json!({"identity_path":directory.join("identity.state"),"expected_actor":identity.actor_id(),"recipient_path":recipient,"request_path":request,"source_path":source,"capsule_path":capsule,"state_dir":directory}).to_string()))?;
        }
        let ack = json!({"action":"structure.migration.source.ack","workspace_id":q.workspace_id,"idempotency_key":format!("migration-source-ack-{id}"),"body":{"job_id":export_id}});
        let _ = Box::pin(self.execute_structure_intent_prepared(
            identity,
            authority,
            ack.to_string().as_bytes(),
            cancel,
        ))
        .await?;
        if !plan.exists() {
            local(crate::owner_cache_plan::plan_owner_checkpoint_from_cache_json(&json!({"state_dir":directory,"workspace_id":q.workspace_id,"expected_actor":identity.actor_id(),"snapshot_sha256":snapshot,"capsule_path":capsule,"name":q.name.as_deref().unwrap_or("Historical workspace"),"plan_path":plan,"read_only_snapshot":true}).to_string()))?;
        }
        local(crate::owner_cache_checkpoint::prepare_owner_checkpoint_from_cache_json(&json!({"state_dir":directory,"workspace_id":q.workspace_id,"expected_actor":identity.actor_id(),"capsule_path":capsule,"plan_path":plan,"output_path":checkpoint,"origin":self.origin(),"audience":String::from_utf16(self.discovery.audience_utf16()).map_err(|_|KernelClientError::InvalidCommand)?}).to_string()))?;
        inspect(
            &checkpoint,
            identity,
            self.discovery.audience_utf16(),
            &q.workspace_id,
            authority,
        )
    }
}
