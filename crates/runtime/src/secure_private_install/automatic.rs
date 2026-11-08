//! Automatic transport selection for large DIRECT protocol installations.
//! Every part is signed once and saved before POST. BEGIN keeps the caller's
//! stable operation ID; authenticated staging ancestry remains mandatory.
use super::*;
use crate::kernel_client::KernelClient;
use peerwork_core::prepared_private_install::{
    plan_private_direct_object_source, prepare_private_direct_install_begin_with_object_source,
    prepare_private_protocol_object_stage, verify_private_protocol_object_stage_material,
    verify_protocol_object_source_prefix, verify_saved_private_protocol_object_stage,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutomaticDirectDocument {
    v: u8,
    origin: String,
    workspace_id: String,
    actor_id: String,
    key_id: String,
    rows: BTreeMap<String, AutomaticDirectRow>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutomaticDirectRow {
    input: PrivateDirectInstallBeginInput,
    issued_at: u64,
    proof_json: String,
    parts_json: String,
    packets: Vec<StageStep>,
}
impl AutomaticDirectDocument {
    fn open(
        store: &SecureStateStore,
        config: &SecureReadProfileConfig,
        identity: &KernelIdentity,
    ) -> Result<Self, PrivatePackageInstallError> {
        let doc: Self = match store.read_exact_secret()? {
            Some(wire) => {
                serde_json::from_slice(&wire).map_err(|_| PrivatePackageInstallError::Identity)?
            }
            None => Self {
                v: 1,
                origin: config.origin.clone(),
                workspace_id: config.workspace_id.clone(),
                actor_id: identity.actor_id().into(),
                key_id: identity.key_id().into(),
                rows: BTreeMap::new(),
            },
        };
        if doc.v != 1
            || doc.origin != config.origin
            || doc.workspace_id != config.workspace_id
            || doc.actor_id != identity.actor_id()
            || doc.key_id != identity.key_id()
            || doc.rows.len() > 16
            || doc.rows.iter().any(|(id, row)| {
                !token(id)
                    || row.input.command_id.as_deref() != Some(id.as_str())
                    || row.packets.len() > 2048
            })
        {
            return Err(PrivatePackageInstallError::Identity);
        }
        Ok(doc)
    }
    fn save(&self, store: &SecureStateStore) -> Result<(), PrivatePackageInstallError> {
        store.write_exact(
            &serde_json::to_vec(self).map_err(|_| PrivatePackageInstallError::Encoding)?,
        )?;
        Ok(())
    }
}
impl SecurePrivatePackageInstall {
    fn automatic_store(&self) -> Result<SecureStateStore, PrivatePackageInstallError> {
        Ok(SecureStateStore::open(
            &self.config.state_dir.join("private-direct-staging.state"),
        )?)
    }

    pub(super) fn automatic_saved_rows(
        &self,
        identity: &KernelIdentity,
    ) -> Result<Vec<serde_json::Value>, PrivatePackageInstallError> {
        let store = self.automatic_store()?;
        let doc = AutomaticDirectDocument::open(&store, &self.config, identity)?;
        Ok(doc.rows.iter().map(|(id, row)| serde_json::json!({
            "begin_command_id":id,"source_kind":"DIRECT","workspace_id":doc.workspace_id,
            "instance_id":row.input.instance_id,"protocol_digest":row.input.expected_protocol_digest,
            "locally_saved":true,"phase":"OBJECT_STAGING","saved_steps":row.packets.len(),
        })).collect())
    }

    pub(super) fn has_automatic_direct_install(
        &self,
        id: &str,
    ) -> Result<bool, PrivatePackageInstallError> {
        if !token(id) {
            return Err(PrivatePackageInstallError::Input);
        }
        let identity = KernelIdentity::open(&self.config.identity_path)
            .map_err(|_| PrivatePackageInstallError::Identity)?;
        // Once BEGIN is durable, only the existing strict continuation owns it.
        let store = SecureStateStore::open(
            &self
                .config
                .state_dir
                .join("private-install-operations.state"),
        )?;
        let doc =
            InstallDocument::open(&store, &self.config, identity.actor_id(), identity.key_id())?;
        if let Some(row) = doc.rows.get(id) {
            if row.recovered_by.is_some() {
                return Err(PrivatePackageInstallError::RecoveredBegin);
            }
            return Ok(false);
        }
        drop(doc);
        drop(store);
        let store = self.automatic_store()?;
        Ok(
            AutomaticDirectDocument::open(&store, &self.config, &identity)?
                .rows
                .contains_key(id),
        )
    }

    pub(super) fn start_automatic_direct_install(
        &self,
        input: &PrivateDirectInstallBeginInput,
        source: &TransportReplayedJournal,
        identity: &KernelIdentity,
        key: &[u8; 32],
        id: &str,
        issued_at: u64,
        cancel: &CancellationToken,
    ) -> Result<PrivatePackageInstallProgress, PrivatePackageInstallError> {
        let mut transport = TransportConfig::new(self.config.origin.clone())
            .with_options(self.config.transport.clone());
        transport.allow_loopback_http = self.config.allow_loopback_http;
        let client = KernelClient::open_cached(
            transport,
            &self.config.state_dir.join("kernel.sqlite"),
            &[],
            cancel,
        )
        .map_err(|_| PrivatePackageInstallError::Identity)?;
        if !client.discovery().protocol_features().iter().any(|s| {
            s.iter()
                .copied()
                .eq("signed-protocol-object-source-v1".encode_utf16())
        }) {
            return Err(PrivatePackageInstallError::ObjectSourceUnsupported);
        }
        drop(client);
        let installs = SecureStateStore::open(
            &self
                .config
                .state_dir
                .join("private-install-operations.state"),
        )?;
        let saved = InstallDocument::open(
            &installs,
            &self.config,
            identity.actor_id(),
            identity.key_id(),
        )?;
        if saved.rows.len() >= 16
            || saved
                .rows
                .values()
                .any(|r| r.accepted.is_none() && r.recovered_by.is_none())
        {
            return Err(PrivatePackageInstallError::Input);
        }
        drop(saved);
        drop(installs);
        let policy = source
            .signed_policy_by_hash(source.replay().policy_hash())
            .ok_or(PrivatePackageInstallError::Plan)?;
        let policy_value = parse_wire_json_bounded(policy, 64, 196_608)
            .map_err(|_| PrivatePackageInstallError::Plan)?;
        let payload = policy_value
            .get("payload")
            .ok_or(PrivatePackageInstallError::Plan)?;
        if number(payload, "v")? != 3
            || scalar(payload, "visibility")? != "PRIVATE"
            || scalar(payload, "structure_mode")? != "STRUCTURED"
        {
            return Err(PrivatePackageInstallError::ObjectSourceUnsupported);
        }
        let disclose = serde_json::to_string(input.disclose.as_deref().unwrap_or(&[]))
            .map_err(|_| PrivatePackageInstallError::Input)?;
        let planned = plan_private_direct_object_source(
            input.closure_json.as_bytes(),
            input.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
            &input.expected_root_package_digest,
            &input.expected_protocol_digest,
            source.checkpoint_canonical_json().as_bytes(),
            policy,
            source.replay().objects(),
            &input.instance_id,
            &input.entrypoint,
            input.grants_json.as_bytes(),
            disclose.as_bytes(),
            identity.signing_key(),
        )?;
        let store = self.automatic_store()?;
        let mut doc = AutomaticDirectDocument::open(&store, &self.config, identity)?;
        if !doc.rows.is_empty() {
            return Err(PrivatePackageInstallError::DuplicateBegin);
        }
        let mut selected = input.clone();
        selected.command_id = Some(id.into());
        doc.rows.insert(
            id.into(),
            AutomaticDirectRow {
                input: selected,
                issued_at,
                proof_json: canonical_wire_value(&planned.proof, CanonicalPath::SecureArtifact)
                    .map_err(|_| PrivatePackageInstallError::Plan)?,
                parts_json: canonical_wire_value(
                    &WireValue::Array(planned.parts),
                    CanonicalPath::SecureArtifact,
                )
                .map_err(|_| PrivatePackageInstallError::Plan)?,
                packets: vec![],
            },
        );
        doc.save(&store)?;
        self.automatic_direct_step(id, source, identity, key, &store, &mut doc, cancel)
    }

    pub(super) fn continue_automatic_direct_install(
        &self,
        id: &str,
        cancel: &CancellationToken,
    ) -> Result<String, PrivatePackageInstallError> {
        let value =
            SecureReadProfile::new(self.config.clone()).with_latest_replay(cancel, |source| {
                source
                    .verified_read()
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                let identity = KernelIdentity::open(&self.config.identity_path)
                    .map_err(|_| PrivatePackageInstallError::Identity)?;
                if source.replay().owner_actor_id() != identity.actor_id()
                    || source.replay().owner_signing_key() != identity.key_id()
                {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let lifecycle = SecureLifecycle::open(
                    &self.config.state_dir.join("lifecycle.state"),
                    source.origin(),
                    identity.actor_id(),
                    &self.config.workspace_id,
                    identity.actor_id(),
                    identity.key_id(),
                )
                .map_err(|_| PrivatePackageInstallError::Identity)?;
                let policy = source
                    .signed_policy_by_hash(source.replay().policy_hash())
                    .ok_or(PrivatePackageInstallError::Plan)?;
                let policy_value = parse_wire_json_bounded(policy, 64, 196_608)
                    .map_err(|_| PrivatePackageInstallError::Plan)?;
                let epoch = number(
                    policy_value
                        .get("payload")
                        .ok_or(PrivatePackageInstallError::Plan)?,
                    "epoch",
                )?;
                if lifecycle.active_keyring_without_pending().is_none() {
                    return Err(PrivatePackageInstallError::Identity);
                }
                let key = lifecycle
                    .active_key(epoch)
                    .ok_or(PrivatePackageInstallError::Identity)?;
                let store = self.automatic_store()?;
                let mut doc = AutomaticDirectDocument::open(&store, &self.config, &identity)?;
                self.automatic_direct_step(id, source, &identity, key, &store, &mut doc, cancel)
            })?;
        serde_json::to_string(&value).map_err(|_| PrivatePackageInstallError::Encoding)
    }

    fn automatic_direct_step(
        &self,
        id: &str,
        source: &TransportReplayedJournal,
        identity: &KernelIdentity,
        key: &[u8; 32],
        store: &SecureStateStore,
        doc: &mut AutomaticDirectDocument,
        cancel: &CancellationToken,
    ) -> Result<PrivatePackageInstallProgress, PrivatePackageInstallError> {
        let row = doc
            .rows
            .get_mut(id)
            .ok_or(PrivatePackageInstallError::Input)?;
        let proof = parse_wire_json_bounded(row.proof_json.as_bytes(), 64, 512 * 1024)
            .map_err(|_| PrivatePackageInstallError::Plan)?;
        let WireValue::Array(parts) =
            parse_wire_json_bounded(row.parts_json.as_bytes(), 64, 48 * 1024 * 1024)
                .map_err(|_| PrivatePackageInstallError::Plan)?
        else {
            return Err(PrivatePackageInstallError::Plan);
        };
        verify_protocol_object_source_prefix(&proof, source.replay())?;
        let base = number(
            proof
                .get("source")
                .ok_or(PrivatePackageInstallError::Plan)?,
            "sequence",
        )?;
        let count = usize::try_from(
            source
                .replay()
                .sequence()
                .checked_sub(base)
                .ok_or(PrivatePackageInstallError::Plan)?,
        )
        .map_err(|_| PrivatePackageInstallError::Plan)?;
        if count > parts.len() || row.packets.len() > count + 1 || row.packets.len() < count {
            return Err(PrivatePackageInstallError::Plan);
        }
        let policy = source
            .signed_policy_by_hash(source.replay().policy_hash())
            .ok_or(PrivatePackageInstallError::Plan)?;
        let input = &row.input;
        let disclose = serde_json::to_string(input.disclose.as_deref().unwrap_or(&[]))
            .map_err(|_| PrivatePackageInstallError::Input)?;
        verify_private_protocol_object_stage_material(
            input.closure_json.as_bytes(),
            input.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
            &input.expected_root_package_digest,
            &input.expected_protocol_digest,
            &proof,
            &parts,
            policy,
            source.replay().objects(),
            &input.instance_id,
            &input.entrypoint,
            input.grants_json.as_bytes(),
            disclose.as_bytes(),
            identity.signing_key(),
        )?;
        // Reprove every saved signature, context, ciphertext and exact signed
        // ancestry before authoring another part or handing off to BEGIN.
        for (index, packet) in row.packets.iter().enumerate() {
            let (sequence, head, hash) = source
                .replay()
                .checkpoint_at(base + index as u64)
                .ok_or(PrivatePackageInstallError::Plan)?;
            let checkpoint = checkpoint_json(
                source,
                sequence,
                head.ok_or(PrivatePackageInstallError::Plan)?,
                hash,
            )?;
            let bytes = decode_base64url(&packet.request_b64)
                .map_err(|_| PrivatePackageInstallError::Plan)?;
            let checked = verify_saved_private_protocol_object_stage(
                &bytes,
                &proof,
                parts.get(index).ok_or(PrivatePackageInstallError::Plan)?,
                index,
                checkpoint.as_bytes(),
                policy,
                &packet.command_id,
                identity.signing_key(),
                key,
            )?;
            if checked != packet.commit_hash
                || index < count
                    && !source
                        .replay()
                        .contains_checkpoint(sequence + 1, Some(&checked), hash)
            {
                return Err(PrivatePackageInstallError::Plan);
            }
        }
        if count == parts.len() {
            let prepared = prepare_private_direct_install_begin_with_object_source(
                input.closure_json.as_bytes(),
                input.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
                &input.expected_root_package_digest,
                &input.expected_protocol_digest,
                source.checkpoint_canonical_json().as_bytes(),
                policy,
                source.replay().objects(),
                input.grants_json.as_bytes(),
                disclose.as_bytes(),
                &input.instance_id,
                &input.entrypoint,
                id,
                row.issued_at,
                identity.signing_key(),
                key,
                &proof,
            )?;
            let result = self.save_and_post_direct_begin(
                input,
                source,
                identity,
                id,
                row.issued_at,
                &prepared,
                Some(&row.proof_json),
                cancel,
            )?;
            doc.rows.remove(id);
            doc.save(store)?;
            return Ok(result);
        }
        if row.packets.len() == count {
            let command_id = base64url(&sha256(
                format!("peerwork.private.direct.object.part.v1:{id}:{count}").as_bytes(),
            ));
            let issued_at = now_ms()?;
            let prepared = prepare_private_protocol_object_stage(
                &proof,
                &parts[count],
                count,
                source.checkpoint_canonical_json().as_bytes(),
                policy,
                &command_id,
                issued_at,
                identity.signing_key(),
                key,
            )?;
            row.packets.push(StageStep {
                command_id,
                issued_at_ms: issued_at,
                request_b64: base64url(prepared.request_wire()),
                commit_hash: prepared.commit_hash().into(),
            });
            doc.save(store)?;
        }
        let row = doc.rows.get(id).ok_or(PrivatePackageInstallError::Plan)?;
        let packet = &row.packets[count];
        let bytes =
            decode_base64url(&packet.request_b64).map_err(|_| PrivatePackageInstallError::Plan)?;
        let checked = verify_saved_private_protocol_object_stage(
            &bytes,
            &proof,
            &parts[count],
            count,
            source.checkpoint_canonical_json().as_bytes(),
            policy,
            &packet.command_id,
            identity.signing_key(),
            key,
        )?;
        if checked != packet.commit_hash {
            return Err(PrivatePackageInstallError::Plan);
        }
        let mut journal = SecureIntentJournal::open(
            &self.config.state_dir.join("private-install-intents.state"),
            source.origin(),
            identity.actor_id(),
        )?;
        let path = format!(
            "/api/workspace/v1/secure/workspaces/{}/commits",
            self.config.workspace_id
        );
        journal.prepare(SecurePacketInput {
            intent_id: &packet.command_id,
            path: &path,
            action_id: "secure.protocol-object.stage",
            workspace_id: Some(&self.config.workspace_id),
            trusted_owner_key: Some(identity.key_id()),
            intent_digest: &checked,
            exact_request: &bytes,
        })?;
        post_saved_private(
            &self.config,
            source.origin(),
            &mut journal,
            &packet.command_id,
            bytes,
            cancel,
        )?;
        Ok(PrivatePackageInstallProgress {
            status: "PENDING",
            begin_command_id: id.into(),
            step_command_id: packet.command_id.clone(),
            step_action_id: "secure.protocol-object.stage",
            workspace_id: self.config.workspace_id.clone(),
            protocol_digest: row.input.expected_protocol_digest.clone(),
            instance_id: row.input.instance_id.clone(),
            commit_hash: checked,
        })
    }
}
