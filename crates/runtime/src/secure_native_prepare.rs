//! Private native identity/keyring to durable secure packet bridge.
//! Caller-supplied policy and operation pins are not authenticated here;
//! no public action API or final outcome can use this without full replay.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{
        PendingSecureIntent, SecureIntentError, SecureIntentJournal, SecurePacketInput,
    },
    secure_lifecycle::SecureLifecycle,
};
use peerwork_core::{
    bootstrap_objects::{owner_bootstrap_objects, BootstrapObjectsError},
    canonical::{canonical, Path as CanonicalPath},
    crypto::{sha256_hex, sign_canonical},
    prepared_secure_author::{author_private_bootstrap, author_private_commit, SecureAuthorError},
    prepared_secure_request::SecureCommitRequestPins,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum NativePrepareError {
    #[error("protected identity, keyring, journal, or caller policy context differs")]
    Context,
    #[error("intent ID is already saved; use the exact saved packet for retry")]
    Existing,
    #[error("active private epoch key is unavailable")]
    NoActiveKey,
    #[error(transparent)]
    Author(#[from] SecureAuthorError),
    #[error(transparent)]
    Journal(#[from] SecureIntentError),
    #[error(transparent)]
    Objects(#[from] BootstrapObjectsError),
}

/// Native composition of the tracked default PRIVATE owner-create objects,
/// scopes and signed v3 genesis policy. This is still a private preparatory
/// path: identity registration, policy/operation replay, and key activation
/// are separate gates. Stable caller IDs are required for crash recovery.
pub(crate) fn prepare_default_owner_workspace(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    lifecycle: &mut SecureLifecycle,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 6],
) -> Result<PendingSecureIntent, NativePrepareError> {
    if journal.contains_id(intent_id) {
        return Err(NativePrepareError::Existing);
    }
    let workspace = lifecycle.workspace_id().to_owned();
    let built =
        owner_bootstrap_objects(name, &workspace, identity.actor_id(), created, instance_ids)?;
    let payload = json!({"v":3,"protocol_format_ceiling":1,"structure_mode":"NONE",
        "workspace_id":workspace,"owner_id":identity.actor_id(),"signing_key":identity.key_id(),
        "version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PRIVATE",
        "epoch":1,"members":[{"actor_id":identity.actor_id(),"certificate":recipient.certificate(),
            "role":"OWNER","scopes":built.scopes()}],"issued_at":created});
    let policy = json!({"signature":sign_canonical("peerwork.secure.policy.v3",&payload,
        identity.signing_key()).map_err(|_| NativePrepareError::Context)?,"payload":payload});
    let policy_hash = sha256_hex(
        canonical(&policy, CanonicalPath::SecureArtifact)
            .map_err(|_| NativePrepareError::Context)?
            .as_bytes(),
    );
    let context = json!({"v":3,"workspace_id":workspace,"sequence":1,"previous":null,
        "policy_hash":policy_hash,"epoch":1,"actor_id":identity.actor_id(),
        "signing_key":identity.key_id(),"command_id":intent_id,"action_id":"secure.bootstrap",
        "instance_id":null,"issued_at":created,"delegation":null,"protocol_format_ceiling":1});
    let pins = SecureCommitRequestPins {
        actor_id: identity.actor_id(),
        signing_key: identity.key_id(),
        workspace_id: &workspace,
        policy_hash: &policy_hash,
        sequence: 1,
        previous: None,
        epoch: 1,
        mode: "PRIVATE",
        version: 3,
        protocol_format_ceiling: Some(1),
    };
    prepare_new_owner_bootstrap(
        journal,
        identity,
        lifecycle,
        intent_id,
        &serde_json::to_vec(&policy).map_err(|_| NativePrepareError::Context)?,
        &serde_json::to_vec(&context).map_err(|_| NativePrepareError::Context)?,
        &serde_json::to_vec(built.operation()).map_err(|_| NativePrepareError::Context)?,
        &pins,
    )
}

/// Stages the initial private key and exact signed `{policy,commit}` request.
/// A crash after key staging but before request persistence leaves only a
/// pending key; repeating preparation reuses it. A saved ID is never re-signed.
/// Policy/object authority and key activation require complete replay later.
pub(crate) fn prepare_new_owner_bootstrap(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &mut SecureLifecycle,
    intent_id: &str,
    policy_wire: &[u8],
    context_wire: &[u8],
    operation_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    if identity.actor_id() != lifecycle.actor_id()
        || identity.actor_id() != lifecycle.owner_actor_id()
        || identity.actor_id() != journal.actor_id()
        || identity.key_id() != lifecycle.owner_key_id()
        || pins.actor_id != identity.actor_id()
        || pins.signing_key != identity.key_id()
        || pins.workspace_id != lifecycle.workspace_id()
        || lifecycle.origin() != journal.trusted_origin()
        || pins.sequence != 1
        || pins.previous.is_some()
        || pins.epoch != 1
        || pins.mode != "PRIVATE"
    {
        return Err(NativePrepareError::Context);
    }
    if journal.contains_id(intent_id) {
        return Err(NativePrepareError::Existing);
    }
    lifecycle
        .stage_initial(1)
        .map_err(|_| NativePrepareError::Context)?;
    let key = lifecycle
        .pending_bootstrap_key()
        .ok_or(NativePrepareError::NoActiveKey)?;
    let authored = author_private_bootstrap(
        policy_wire,
        context_wire,
        operation_wire,
        key,
        identity.signing_key(),
        pins,
    )?;
    let proof = authored.proof();
    if proof.command_id() != intent_id
        || proof.workspace_id() != lifecycle.workspace_id()
        || proof.policy_hash() != pins.policy_hash
    {
        return Err(NativePrepareError::Context);
    }
    Ok(journal.prepare(SecurePacketInput {
        intent_id: proof.command_id(),
        path: proof.path(),
        action_id: "secure.bootstrap",
        workspace_id: Some(proof.workspace_id()),
        trusted_owner_key: Some(identity.key_id()),
        intent_digest: proof.commit_digest(),
        exact_request: authored.request_wire(),
    })?)
}

/// This only signs and durably stages a new packet. It never sends one. A
/// repeated ID fails before encryption, preserving the first saved nonce and
/// signature. The signed policy/checkpoint/operation proof is still absent.
pub(crate) fn prepare_new_private_commit(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    intent_id: &str,
    context_wire: &[u8],
    operation_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    if identity.actor_id() != lifecycle.actor_id()
        || identity.actor_id() != journal.actor_id()
        || pins.actor_id != identity.actor_id()
        || pins.signing_key != identity.key_id()
        || pins.workspace_id != lifecycle.workspace_id()
        || lifecycle.origin() != journal.trusted_origin()
        || pins.mode != "PRIVATE"
    {
        return Err(NativePrepareError::Context);
    }
    if journal.contains_id(intent_id) {
        return Err(NativePrepareError::Existing);
    }
    let key = lifecycle
        .active_key(pins.epoch)
        .ok_or(NativePrepareError::NoActiveKey)?;
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        lifecycle.workspace_id()
    );
    let authored = author_private_commit(
        context_wire,
        operation_wire,
        key,
        identity.signing_key(),
        &path,
        pins,
    )?;
    let proof = authored.proof();
    if proof.command_id() != intent_id
        || proof.workspace_id() != lifecycle.workspace_id()
        || proof.actor_id() != identity.actor_id()
        || proof.signing_key() != identity.key_id()
        || proof.path() != path
        || proof.policy_hash() != pins.policy_hash
    {
        return Err(NativePrepareError::Context);
    }
    Ok(journal.prepare(SecurePacketInput {
        intent_id: proof.command_id(),
        path: proof.path(),
        action_id: proof.action_id(),
        workspace_id: Some(proof.workspace_id()),
        trusted_owner_key: Some(lifecycle.owner_key_id()),
        intent_digest: proof.commit_digest(),
        exact_request: authored.request_wire(),
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secure_state::read_private_file_bounded,
        transport::{HttpTransport, TransportConfig, TransportError},
    };
    use peerwork_core::crypto::base64url;
    use serde_json::json;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        fs,
        io::BufRead,
        process::{Child, Command, Stdio},
    };
    use tokio_util::sync::CancellationToken;

    #[test]
    fn default_owner_workspace_uses_six_embedded_presets_without_posting() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&dir.path().join("owner.state")).unwrap();
        let recipient = crate::secure_recipient_state::RecipientState::create(
            &dir.path().join("recipient.state"),
            &identity,
            100,
        )
        .unwrap();
        let workspace = base64url(&[71; 32]);
        let ids = std::array::from_fn(|i| base64url(&[i as u8 + 80; 32]));
        let command_id = base64url(&[72; 32]);
        let origin = "https://example.invalid/";
        let mut lifecycle = SecureLifecycle::open(
            &dir.path().join("keys.state"),
            origin,
            identity.actor_id(),
            &workspace,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let mut journal = SecureIntentJournal::open(
            &dir.path().join("intents.state"),
            origin,
            identity.actor_id(),
        )
        .unwrap();
        prepare_default_owner_workspace(
            &mut journal,
            &identity,
            &recipient,
            &mut lifecycle,
            &command_id,
            "Native workspace",
            100,
            &ids,
        )
        .unwrap();
        let wire = journal.exact_request(&command_id).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(request["policy"]["payload"]["v"], 3);
        assert_eq!(
            request["policy"]["payload"]["members"][0]["scopes"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert_eq!(
            request["commit"]["payload"]["action_id"],
            "secure.bootstrap"
        );
        let transport = HttpTransport::new(TransportConfig::new(origin)).unwrap();
        journal
            .verified_saved_bootstrap(&command_id, &identity, &transport, &lifecycle)
            .unwrap();
        assert!(matches!(
            prepare_default_owner_workspace(
                &mut journal,
                &identity,
                &recipient,
                &mut lifecycle,
                &command_id,
                "Different",
                100,
                &ids
            ),
            Err(NativePrepareError::Existing)
        ));
        assert_eq!(journal.exact_request(&command_id).unwrap(), wire);
        assert_eq!(journal.pending()[0].observed_responses, 0);
    }

    #[tokio::test]
    async fn actual_service_native_owner_bootstrap_lost_reply_exact_retry() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_BOOTSTRAP", "1")
            .env("PEERWORK_TEST_FIRST_JOURNAL_DELAY_MS", "300")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "reference bridge exited before ready");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap();
        let actor = ready["bootstrap"]["actor_id"].as_str().unwrap();
        let signer = ready["bootstrap"]["signing_key"].as_str().unwrap();
        let authority = ready["bootstrap"]["authority"].as_str().unwrap();
        assert_eq!(
            authority,
            peerwork_core::crypto::sha256_hex(actor.as_bytes())
        );
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &root.path().join("native-owner.state"),
            &root.path().join("synthetic-bootstrap-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), actor);
        assert_eq!(identity.key_id(), signer);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let recipient = crate::secure_recipient_state::RecipientState::create(
            &root.path().join("native-recipient.state"),
            &identity,
            now,
        )
        .unwrap();
        let workspace = base64url(&[101; 32]);
        let ids = std::array::from_fn(|i| base64url(&[i as u8 + 110; 32]));
        let command = base64url(&[102; 32]);
        let lifecycle_path = root.path().join("native-epochs.state");
        let journal_path = root.path().join("native-intents.state");
        let mut lifecycle =
            SecureLifecycle::open(&lifecycle_path, origin, actor, &workspace, actor, signer)
                .unwrap();
        let mut journal = SecureIntentJournal::open(&journal_path, origin, actor).unwrap();
        let mut config = TransportConfig::new(origin);
        config.allow_loopback_http = true;
        let transport = HttpTransport::new(config).unwrap();
        let counts_url = format!("{origin}__test/secure-counts");
        let counts = || async {
            serde_json::from_slice::<serde_json::Value>(
                &reqwest::get(&counts_url)
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
            )
            .unwrap()
        };
        let before = counts().await;
        assert_eq!(before["commits"].as_u64(), Some(0));
        prepare_default_owner_workspace(
            &mut journal,
            &identity,
            &recipient,
            &mut lifecycle,
            &command,
            "Native owner workspace",
            now,
            &ids,
        )
        .unwrap();
        let exact = journal.exact_request(&command).unwrap();
        let (prepared, _) = journal
            .verified_saved_bootstrap(&command, &identity, &transport, &lifecycle)
            .unwrap();
        let expected_head = prepared.commit_digest().to_owned();
        assert_eq!(counts().await, before, "preparation must not submit");
        let first = journal
            .submit_saved_bootstrap(
                &command,
                &identity,
                &transport,
                &lifecycle,
                &CancellationToken::new(),
            )
            .await;
        assert!(
            matches!(
                first,
                Err(SecureIntentError::Transport(
                    TransportError::SubmittedUncertain
                ))
            ),
            "first post outcome: {first:?}"
        );
        assert_eq!(journal.pending()[0].observed_responses, 0);
        drop(journal);
        drop(lifecycle);
        let applied = counts().await;
        assert_eq!(applied["commits"].as_u64(), Some(1));
        assert_eq!(applied["head_sequence"].as_u64(), Some(1));
        assert_eq!(applied["head_hash"].as_str(), Some(expected_head.as_str()));
        let mut lifecycle =
            SecureLifecycle::open(&lifecycle_path, origin, actor, &workspace, actor, signer)
                .unwrap();
        let mut journal = SecureIntentJournal::open(&journal_path, origin, actor).unwrap();
        assert_eq!(journal.exact_request(&command).unwrap(), exact);
        journal
            .submit_saved_bootstrap(
                &command,
                &identity,
                &transport,
                &lifecycle,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(journal.pending()[0].observed_responses, 1);
        let observations = journal.exact_observations(&command).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&observations[0]).unwrap();
        assert_eq!(response["workspace_id"], workspace);
        assert_eq!(response["sequence"], 1);
        assert_eq!(response["head"], expected_head);
        assert_eq!(
            counts().await,
            applied,
            "same-ID exact retry must not reapply"
        );
        // Fixture-only activation stands in for the unavailable complete
        // replay/grant proof. These 50 service-accepted packets exercise
        // pagination; they do not establish valid action effects.
        lifecycle.confirm_pending_for_test().unwrap();
        let genesis: serde_json::Value = serde_json::from_slice(&exact).unwrap();
        let policy_hash = genesis["commit"]["payload"]["policy_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut previous = expected_head.clone();
        for sequence in 2..=51_u64 {
            let next_id = base64url(&[(sequence + 120) as u8; 32]);
            let context = json!({"v":3,"workspace_id":workspace,"sequence":sequence,
                "previous":previous,"policy_hash":policy_hash,"epoch":1,
                "actor_id":identity.actor_id(),"signing_key":identity.key_id(),
                "command_id":next_id,"action_id":"discussion.post","instance_id":ids[0],
                "issued_at":now+sequence,"delegation":null,"protocol_format_ceiling":1});
            let operation = json!({"v":1,"kind":"ACTION",
                "input":{"message":format!("pagination fixture {sequence}")},"objects":[]});
            let pins = SecureCommitRequestPins {
                actor_id: identity.actor_id(),
                signing_key: identity.key_id(),
                workspace_id: &workspace,
                policy_hash: &policy_hash,
                sequence,
                previous: Some(&previous),
                epoch: 1,
                mode: "PRIVATE",
                version: 3,
                protocol_format_ceiling: Some(1),
            };
            prepare_new_private_commit(
                &mut journal,
                &identity,
                &lifecycle,
                &next_id,
                &serde_json::to_vec(&context).unwrap(),
                &serde_json::to_vec(&operation).unwrap(),
                &pins,
            )
            .unwrap();
            let (proof, _) = journal
                .verified_saved_commit(&next_id, &identity, &transport, identity.key_id(), &pins)
                .unwrap();
            let next_head = proof.commit_digest().to_owned();
            journal
                .submit_saved_commit(
                    &next_id,
                    &identity,
                    &transport,
                    identity.key_id(),
                    &pins,
                    &CancellationToken::new(),
                )
                .await
                .unwrap();
            previous = next_head;
        }
        let paginated = counts().await;
        assert_eq!(paginated["commits"].as_u64(), Some(51));
        assert_eq!(paginated["head_sequence"].as_u64(), Some(51));
        assert_eq!(paginated["head_hash"].as_str(), Some(previous.as_str()));
        // A separate signed GET obtains exact, unverified journal bytes after
        // the lost-reply restart. This read cannot promote the pending key or
        // secure intent to an authenticated final outcome.
        let mut read_config = TransportConfig::new(origin);
        read_config.allow_loopback_http = true;
        let client = crate::kernel_client::KernelClient::open(
            read_config,
            &root.path().join("native-discovery.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let read_path = root.path().join("native-journal-pages.state");
        let mut read = crate::secure_journal_read::SecureJournalRead::open(
            &read_path, &client, &identity, &workspace, &authority,
        )
        .unwrap();
        assert_eq!(read.progress().unwrap().pages, 0);
        assert!(
            read_path.exists(),
            "empty reader must persist its discovery pin"
        );
        let cancelled = CancellationToken::new();
        let trigger = cancelled.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            trigger.cancel();
        });
        assert!(matches!(
            read.fetch_next(&client, &identity, &cancelled).await,
            Err(crate::secure_journal_read::JournalReadError::Transport(
                TransportError::Cancelled
            ))
        ));
        assert_eq!(read.progress().unwrap().pages, 0);
        drop(read);
        let mut read = crate::secure_journal_read::SecureJournalRead::open(
            &read_path, &client, &identity, &workspace, &authority,
        )
        .unwrap();
        let progress = read
            .fetch_next(&client, &identity, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(progress.pages, 1);
        assert_eq!(progress.saved_commits, 50);
        assert_eq!(progress.checkpoint_sequence, Some(51));
        assert_eq!(progress.next_after, Some(50));
        assert!(!progress.complete_transport);
        let exact_pages = read.exact_pages().unwrap();
        assert_eq!(exact_pages.len(), 1);
        let smaller_budget = exact_pages[0].len() - 1;
        drop(read);
        let mut reopened = crate::secure_journal_read::SecureJournalRead::open(
            &read_path, &client, &identity, &workspace, &authority,
        )
        .unwrap();
        assert_eq!(reopened.exact_pages().unwrap(), exact_pages);
        assert_eq!(reopened.progress().unwrap(), progress);
        let finished = reopened
            .fetch_next(&client, &identity, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(finished.pages, 2);
        assert_eq!(finished.saved_commits, 51);
        assert_eq!(finished.checkpoint_sequence, Some(51));
        assert!(finished.complete_transport);
        drop(reopened);
        let reopened = crate::secure_journal_read::SecureJournalRead::open(
            &read_path, &client, &identity, &workspace, &authority,
        )
        .unwrap();
        assert_eq!(reopened.progress().unwrap(), finished);
        assert_eq!(reopened.exact_pages().unwrap().len(), 2);
        drop(reopened);
        // A 50-commit response just over the configured budget must be
        // retried with a new proof for a smaller canonical page limit, while
        // all later pages remain bound to the first successful checkpoint.
        let adaptive_path = root.path().join("adaptive-journal-pages.state");
        let mut adaptive = crate::secure_journal_read::SecureJournalRead::open(
            &adaptive_path,
            &client,
            &identity,
            &workspace,
            &authority,
        )
        .unwrap();
        let mut adaptive_progress = adaptive
            .fetch_next_with_budget(
                &client,
                &identity,
                smaller_budget,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(adaptive_progress.saved_commits > 0 && adaptive_progress.saved_commits < 50);
        while !adaptive_progress.complete_transport {
            adaptive_progress = adaptive
                .fetch_next_with_budget(
                    &client,
                    &identity,
                    smaller_budget,
                    &CancellationToken::new(),
                )
                .await
                .unwrap();
        }
        assert_eq!(adaptive_progress.saved_commits, 51);
        assert_eq!(adaptive_progress.checkpoint_sequence, Some(51));
        drop(adaptive);
        let adaptive = crate::secure_journal_read::SecureJournalRead::open(
            &adaptive_path,
            &client,
            &identity,
            &workspace,
            &authority,
        )
        .unwrap();
        assert_eq!(adaptive.progress().unwrap(), adaptive_progress);
        drop(adaptive);
        let wrong_identity =
            KernelIdentity::create(&root.path().join("wrong-reader.state")).unwrap();
        assert!(matches!(
            crate::secure_journal_read::SecureJournalRead::open(
                &read_path,
                &client,
                &wrong_identity,
                &workspace,
                authority
            ),
            Err(crate::secure_journal_read::JournalReadError::Incompatible)
        ));
        let mut other_config = TransportConfig::new(format!(
            "{}/",
            ready["bootstrap"]["real_origin"].as_str().unwrap()
        ));
        other_config.allow_loopback_http = true;
        let other_client = crate::kernel_client::KernelClient::open(
            other_config,
            &root.path().join("other-origin-discovery.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(matches!(
            crate::secure_journal_read::SecureJournalRead::open(
                &read_path,
                &other_client,
                &identity,
                &workspace,
                authority
            ),
            Err(crate::secure_journal_read::JournalReadError::Incompatible)
        ));
        let wrong_authority = "f".repeat(64);
        let mut wrong = crate::secure_journal_read::SecureJournalRead::open(
            &root.path().join("wrong-authority-pages.state"),
            &client,
            &identity,
            &workspace,
            &wrong_authority,
        )
        .unwrap();
        assert!(matches!(
            wrong
                .fetch_next(&client, &identity, &CancellationToken::new())
                .await,
            Err(crate::secure_journal_read::JournalReadError::ServerRejected(401))
        ));
        assert_eq!(wrong.progress().unwrap().pages, 0);
        assert_eq!(counts().await, paginated, "signed reads must not submit");
    }

    #[tokio::test]
    async fn owner_bootstrap_stages_key_and_exact_packet_across_restart() {
        use peerwork_core::{
            canonical::{canonical, Path},
            crypto::{sha256_hex, sign_canonical},
            secure_recipient::SecretRecipient,
        };
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&dir.path().join("owner.state")).unwrap();
        let workspace = base64url(&[41; 32]);
        let command_id = base64url(&[42; 32]);
        let origin = "https://example.invalid/";
        let lifecycle_path = dir.path().join("epoch.state");
        let journal_path = dir.path().join("intents.state");
        let mut lifecycle = SecureLifecycle::open(
            &lifecycle_path,
            origin,
            identity.actor_id(),
            &workspace,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let mut journal =
            SecureIntentJournal::open(&journal_path, origin, identity.actor_id()).unwrap();
        let cert = SecretRecipient::generate()
            .unwrap()
            .certify(identity.signing_key(), 100)
            .unwrap();
        let payload = json!({"v":1,"workspace_id":workspace,"owner_id":identity.actor_id(),
            "signing_key":identity.key_id(),"version":1,"previous_policy":null,
            "effective_sequence":1,"visibility":"PRIVATE","epoch":1,
            "members":[{"actor_id":identity.actor_id(),"certificate":cert,"role":"OWNER","scopes":[]}],
            "issued_at":100});
        let policy = json!({"signature":sign_canonical("peerwork.secure.policy.v1",&payload,identity.signing_key()).unwrap(),"payload":payload});
        let policy_hash = sha256_hex(canonical(&policy, Path::SecureArtifact).unwrap().as_bytes());
        let context = json!({"v":1,"workspace_id":workspace,"sequence":1,"previous":null,
            "policy_hash":policy_hash,"epoch":1,"actor_id":identity.actor_id(),
            "signing_key":identity.key_id(),"command_id":command_id,"action_id":"secure.bootstrap",
            "instance_id":null,"issued_at":100,"delegation":null});
        let operation = json!({"v":1,"kind":"BOOTSTRAP","input":{},"objects":[]});
        let pins = SecureCommitRequestPins {
            actor_id: identity.actor_id(),
            signing_key: identity.key_id(),
            workspace_id: &workspace,
            policy_hash: &policy_hash,
            sequence: 1,
            previous: None,
            epoch: 1,
            mode: "PRIVATE",
            version: 1,
            protocol_format_ceiling: None,
        };
        prepare_new_owner_bootstrap(
            &mut journal,
            &identity,
            &mut lifecycle,
            &command_id,
            &serde_json::to_vec(&policy).unwrap(),
            &serde_json::to_vec(&context).unwrap(),
            &serde_json::to_vec(&operation).unwrap(),
            &pins,
        )
        .unwrap();
        let exact = journal.exact_request(&command_id).unwrap();
        assert_eq!(journal.pending()[0].observed_responses, 0);
        assert_eq!(lifecycle.status().active_epochs, Vec::<u64>::new());
        assert_eq!(lifecycle.status().pending_epochs, vec![1]);
        assert!(matches!(
            prepare_new_owner_bootstrap(
                &mut journal,
                &identity,
                &mut lifecycle,
                &command_id,
                &serde_json::to_vec(&policy).unwrap(),
                &serde_json::to_vec(&context).unwrap(),
                &serde_json::to_vec(&operation).unwrap(),
                &pins
            ),
            Err(NativePrepareError::Existing)
        ));
        drop(journal);
        drop(lifecycle);
        let reopened =
            SecureIntentJournal::open(&journal_path, origin, identity.actor_id()).unwrap();
        let lifecycle = SecureLifecycle::open(
            &lifecycle_path,
            origin,
            identity.actor_id(),
            &workspace,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        assert_eq!(lifecycle.status().pending_epochs, vec![1]);
        assert!(lifecycle.status().active_epochs.is_empty());
        assert_eq!(reopened.exact_request(&command_id).unwrap(), exact);
        let transport = HttpTransport::new(TransportConfig::new(origin)).unwrap();
        reopened
            .verified_saved_bootstrap(&command_id, &identity, &transport, &lifecycle)
            .unwrap();
        let wrong = SecureLifecycle::open(
            &dir.path().join("wrong-epoch.state"),
            origin,
            identity.actor_id(),
            &base64url(&[43; 32]),
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        assert!(reopened
            .verified_saved_bootstrap(&command_id, &identity, &transport, &wrong)
            .is_err());
        let mut mismatched = SecureLifecycle::open(
            &dir.path().join("mismatched-epoch.state"),
            origin,
            identity.actor_id(),
            &workspace,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        mismatched.stage_initial(1).unwrap();
        assert!(reopened
            .verified_saved_bootstrap(&command_id, &identity, &transport, &mismatched)
            .is_err());
        let mut reopened = reopened;
        assert!(matches!(
            reopened
                .submit_saved_bootstrap(
                    &command_id,
                    &identity,
                    &transport,
                    &mismatched,
                    &CancellationToken::new()
                )
                .await,
            Err(SecureIntentError::Incompatible)
        ));
        assert_eq!(reopened.exact_request(&command_id).unwrap(), exact);
    }

    #[test]
    fn native_protected_keys_stage_one_exact_pending_packet_without_reauthoring() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let workspace = base64url(&[17u8; 32]);
        let owner = base64url(&[18u8; 32]);
        let origin = "https://example.invalid/";
        let lifecycle_path = dir.path().join("keys.state");
        let mut lifecycle = SecureLifecycle::open(
            &lifecycle_path,
            origin,
            identity.actor_id(),
            &workspace,
            &owner,
            &owner,
        )
        .unwrap();
        lifecycle.stage_initial(1).unwrap();
        let journal_path = dir.path().join("intents.state");
        let mut journal =
            SecureIntentJournal::open(&journal_path, origin, identity.actor_id()).unwrap();
        let command_id = base64url(&[19u8; 32]);
        let policy = "a".repeat(64);
        let previous = "b".repeat(64);
        let pins = SecureCommitRequestPins {
            actor_id: identity.actor_id(),
            signing_key: identity.key_id(),
            workspace_id: &workspace,
            policy_hash: &policy,
            sequence: 2,
            previous: Some(&previous),
            epoch: 1,
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let context = json!({
            "v":3,"workspace_id":workspace,"sequence":2,"previous":previous,
            "policy_hash":policy,"epoch":1,"actor_id":identity.actor_id(),
            "signing_key":identity.key_id(),"command_id":command_id,
            "action_id":"discussion.post","instance_id":base64url(&[20u8;32]),
            "issued_at":1_700_000_000_000_u64,"delegation":null,
            "protocol_format_ceiling":1
        });
        let context_wire = serde_json::to_vec(&context).unwrap();
        let operation_wire = serde_json::to_vec(&json!({
            "v":1,"kind":"ACTION","input":{"message":"native lifecycle"},"objects":[]
        }))
        .unwrap();
        assert!(matches!(
            prepare_new_private_commit(
                &mut journal,
                &identity,
                &lifecycle,
                &command_id,
                &context_wire,
                &operation_wire,
                &pins,
            ),
            Err(NativePrepareError::NoActiveKey)
        ));
        assert!(journal.pending().is_empty());

        // Test-only activation stands in for a future complete journal proof.
        // Production cannot promote pending keys or call this private bridge.
        lifecycle.confirm_pending_for_test().unwrap();
        let pending = prepare_new_private_commit(
            &mut journal,
            &identity,
            &lifecycle,
            &command_id,
            &context_wire,
            &operation_wire,
            &pins,
        )
        .unwrap();
        assert_eq!(pending.intent_id, command_id);
        assert_eq!(pending.observed_responses, 0);
        let first = journal.exact_request(&command_id).unwrap();
        assert!(matches!(
            prepare_new_private_commit(
                &mut journal,
                &identity,
                &lifecycle,
                &command_id,
                &context_wire,
                &operation_wire,
                &pins,
            ),
            Err(NativePrepareError::Existing)
        ));
        assert_eq!(journal.exact_request(&command_id).unwrap(), first);
        drop(journal);
        drop(lifecycle);
        let reopened =
            SecureIntentJournal::open(&journal_path, origin, identity.actor_id()).unwrap();
        assert_eq!(reopened.exact_request(&command_id).unwrap(), first);
        assert_eq!(reopened.pending().len(), 1);
    }

    #[tokio::test]
    async fn actual_service_accepts_native_authored_packet_then_exact_retry() {
        let Ok(reference_root) = std::env::var("PEERWORK_REFERENCE_ROOT") else {
            return;
        };
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap_or_else(|_| "node".into());
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bridge = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/reference-kernel-server.mjs");
        let child = Command::new(node)
            .arg(bridge)
            .env("PEERWORK_REFERENCE_ROOT", reference_root)
            .env("PEERWORK_TEST_STATE", root.path())
            .env("PEERWORK_TEST_SECURE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        struct Stop(Child);
        impl Drop for Stop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Stop(child);
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(!line.is_empty(), "reference bridge exited before ready");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let text = |key: &str| ready["secure"][key].as_str().unwrap().to_owned();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let workspace = text("workspace_id");
        let actor = text("actor_id");
        let signing_key = text("signing_key");
        let owner = text("owner_key");
        let policy = text("policy_hash");
        let previous = text("previous");
        let command_id = text("command_id");
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &root.path().join("native-identity.state"),
            &root.path().join("synthetic-agent-ed25519.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), actor);
        assert_eq!(identity.key_id(), signing_key);
        let keyring_wire =
            read_private_file_bounded(&root.path().join("synthetic-secure-keyring.json"), 131_072)
                .unwrap();
        let context_wire =
            read_private_file_bounded(&root.path().join("synthetic-secure-context.json"), 196_608)
                .unwrap();
        let operation_wire = read_private_file_bounded(
            &root.path().join("synthetic-secure-operation.json"),
            16 * 1024 * 1024,
        )
        .unwrap();
        let lifecycle_path = root.path().join("native-keys.state");
        let mut lifecycle =
            SecureLifecycle::open(&lifecycle_path, &origin, &actor, &workspace, &actor, &owner)
                .unwrap();
        // Only this fixture bypasses the unavailable complete signed grant
        // proof. Product code cannot call import_active_for_test.
        lifecycle.import_active_for_test(&keyring_wire).unwrap();
        let pins = SecureCommitRequestPins {
            actor_id: &actor,
            signing_key: &signing_key,
            workspace_id: &workspace,
            policy_hash: &policy,
            sequence: ready["secure"]["sequence"].as_u64().unwrap(),
            previous: Some(&previous),
            epoch: ready["secure"]["epoch"].as_u64().unwrap(),
            mode: "PRIVATE",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let mut config = TransportConfig::new(origin.clone());
        config.allow_loopback_http = true;
        let transport = HttpTransport::new(config).unwrap();
        let counts_url = format!("{origin}__test/secure-counts");
        let count = || async {
            serde_json::from_str::<serde_json::Value>(
                &reqwest::get(&counts_url)
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
            )
            .unwrap()
        };
        let baseline = count().await;
        assert_eq!(baseline["commits"].as_u64(), Some(1));
        assert_eq!(baseline["head_sequence"].as_u64(), Some(1));
        let journal_path = root.path().join("native-secure-intents.state");
        let mut journal = SecureIntentJournal::open(&journal_path, &origin, &actor).unwrap();
        prepare_new_private_commit(
            &mut journal,
            &identity,
            &lifecycle,
            &command_id,
            &context_wire,
            &operation_wire,
            &pins,
        )
        .unwrap();
        let exact = journal.exact_request(&command_id).unwrap();
        let old_ts_request = read_private_file_bounded(
            &root.path().join("synthetic-secure-request.json"),
            2 * 1024 * 1024,
        )
        .unwrap();
        assert_ne!(exact, *old_ts_request, "fixture must use native ciphertext");
        assert_eq!(count().await, baseline, "native prepare must not POST");
        let cancel = CancellationToken::new();
        assert!(matches!(
            journal
                .submit_saved_commit(&command_id, &identity, &transport, &owner, &pins, &cancel)
                .await,
            Err(SecureIntentError::Transport(
                TransportError::SubmittedUncertain
            ))
        ));
        assert_eq!(journal.pending()[0].observed_responses, 0);
        drop(journal);
        drop(lifecycle);
        let applied = count().await;
        assert_eq!(applied["commits"].as_u64(), Some(2));
        assert_eq!(applied["head_sequence"].as_u64(), Some(2));
        let mut reopened = SecureIntentJournal::open(&journal_path, &origin, &actor).unwrap();
        assert_eq!(reopened.exact_request(&command_id).unwrap(), exact);
        reopened
            .submit_saved_commit(&command_id, &identity, &transport, &owner, &pins, &cancel)
            .await
            .unwrap();
        assert_eq!(reopened.pending()[0].observed_responses, 1);
        assert_eq!(count().await, applied, "exact retry must not reapply");
    }
}
