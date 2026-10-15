//! Private native identity/keyring to durable secure packet bridge.
//! Legacy low-level preparation takes caller-supplied policy and operation pins.
//! Replay-backed action preparation authenticates those inputs before saving a packet;
//! final outcomes still require the signed journal replay and receipt checks.

use crate::{
    kernel_identity::KernelIdentity,
    secure_intents::{
        PendingSecureIntent, SecureIntentError, SecureIntentJournal, SecurePacketInput,
    },
    secure_lifecycle::SecureLifecycle,
    secure_verified_read::TransportReplayedJournal,
};
use peerwork_core::{
    bootstrap_objects::{
        owner_bootstrap_objects, owner_bootstrap_objects_with_coordination,
        owner_bootstrap_objects_with_visibility, BootstrapObjectsError, OwnerBootstrapObjects,
    },
    canonical::{canonical, Path as CanonicalPath},
    crypto::{sha256_hex, sign_canonical},
    genesis_structure_policy::{
        derive_genesis_structure_policy_with_coordination_and_keep_encrypted,
        derive_genesis_structure_policy_with_keep_encrypted,
    },
    prepared_secure_action::{
        build_prepared_action_with_context, validate_prepared_action_operation,
        ValidatedPreparedAction,
    },
    prepared_secure_author::{
        author_private_bootstrap, author_private_commit, author_private_validated_action,
        author_public_bootstrap, author_public_validated_action, SecureAuthorError,
    },
    prepared_secure_request::SecureCommitRequestPins,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
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

/// The tracked writer retains the original JavaScript UTF-16 workspace name
/// in the signed BOOTSTRAP object, including lone surrogates. The embedded
/// preset builder uses serde_json for its otherwise scalar fields; replace
/// only that one generated name through the lossless wire representation.
pub(crate) fn owner_operation_wire(
    built: &OwnerBootstrapObjects,
    name_utf16: Option<&[u16]>,
) -> Result<Vec<u8>, NativePrepareError> {
    let raw = serde_json::to_vec(built.operation()).map_err(|_| NativePrepareError::Context)?;
    let Some(name) = name_utf16 else {
        return Ok(raw);
    };
    if name.is_empty() {
        return Err(NativePrepareError::Context);
    }
    let mut operation =
        parse_wire_json_bounded(&raw, 64, 2_000_000).map_err(|_| NativePrepareError::Context)?;
    let objects = wire_field_mut(&mut operation, "objects").ok_or(NativePrepareError::Context)?;
    let WireValue::Array(objects) = objects else {
        return Err(NativePrepareError::Context);
    };
    let first = objects.first_mut().ok_or(NativePrepareError::Context)?;
    if first.get("kind").and_then(WireValue::as_string).as_deref() != Some("workspaces") {
        return Err(NativePrepareError::Context);
    }
    let value = wire_field_mut(first, "value").ok_or(NativePrepareError::Context)?;
    let field = wire_field_mut(value, "name").ok_or(NativePrepareError::Context)?;
    if !matches!(field, WireValue::String(_)) {
        return Err(NativePrepareError::Context);
    }
    *field = WireValue::String(name.to_vec());
    canonical_wire_value(&operation, CanonicalPath::SecureArtifact)
        .map(String::into_bytes)
        .map_err(|_| NativePrepareError::Context)
}

fn wire_field_mut<'a>(value: &'a mut WireValue, key: &str) -> Option<&'a mut WireValue> {
    let WireValue::Object(fields) = value else {
        return None;
    };
    fields
        .iter_mut()
        .find(|(name, _)| name.iter().copied().eq(key.encode_utf16()))
        .map(|(_, value)| value)
}

pub(crate) fn owner_objects_wire(operation_wire: &[u8]) -> Result<Vec<u8>, NativePrepareError> {
    let operation = parse_wire_json_bounded(operation_wire, 64, 2_000_000)
        .map_err(|_| NativePrepareError::Context)?;
    canonical_wire_value(
        operation
            .get("objects")
            .ok_or(NativePrepareError::Context)?,
        CanonicalPath::SecureArtifact,
    )
    .map(String::into_bytes)
    .map_err(|_| NativePrepareError::Context)
}

/// Owner-create's lossless-name bridge. `name_utf16` is the exact JS string;
/// the scalar placeholder never enters the saved/signed operation.
pub(crate) fn prepare_owner_workspace_with_utf16_name(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    lifecycle: Option<&mut SecureLifecycle>,
    workspace_id: &str,
    intent_id: &str,
    name_utf16: &[u16],
    created: u64,
    instance_ids: &[String],
    visibility: &str,
    structured: bool,
    coordination_version: Option<u8>,
    keep_encrypted_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    if name_utf16.is_empty() || coordination_version.is_some() && !structured {
        return Err(NativePrepareError::Context);
    }
    let built = if let Some(version) = coordination_version {
        if instance_ids.len() != 7 {
            return Err(NativePrepareError::Context);
        }
        let ids: [String; 7] = std::array::from_fn(|i| instance_ids[i].clone());
        owner_bootstrap_objects_with_coordination(
            "_",
            workspace_id,
            identity.actor_id(),
            created,
            &ids,
            visibility,
            version,
        )?
    } else {
        if instance_ids.len() != 6 {
            return Err(NativePrepareError::Context);
        }
        let ids: [String; 6] = std::array::from_fn(|i| instance_ids[i].clone());
        owner_bootstrap_objects_with_visibility(
            "_",
            workspace_id,
            identity.actor_id(),
            created,
            &ids,
            visibility,
        )?
    };
    let coordination_digest = if coordination_version.is_some() {
        Some(
            built.operation()["objects"][13]["id"]
                .as_str()
                .ok_or(NativePrepareError::Context)?
                .to_owned(),
        )
    } else {
        None
    };
    let coordination = coordination_version.map(|version| {
        (
            instance_ids[6].as_str(),
            coordination_digest.as_deref().unwrap_or(""),
            version,
        )
    });
    match visibility {
        "PRIVATE" => {
            let lifecycle = lifecycle.ok_or(NativePrepareError::Context)?;
            if lifecycle.workspace_id() != workspace_id {
                return Err(NativePrepareError::Context);
            }
            prepare_private_owner_workspace_from_built(
                journal,
                identity,
                recipient,
                lifecycle,
                intent_id,
                created,
                built,
                structured,
                coordination,
                keep_encrypted_wire,
                Some(name_utf16),
            )
        }
        "PUBLIC" => prepare_public_owner_workspace_from_built(
            journal,
            identity,
            recipient,
            workspace_id,
            intent_id,
            created,
            built,
            structured,
            coordination,
            keep_encrypted_wire,
            Some(name_utf16),
        ),
        _ => Err(NativePrepareError::Context),
    }
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
    prepare_private_owner_workspace_with_options(
        journal,
        identity,
        recipient,
        lifecycle,
        intent_id,
        name,
        created,
        instance_ids,
        false,
        b"[]",
    )
}

pub(crate) fn prepare_private_owner_workspace_with_options(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    lifecycle: &mut SecureLifecycle,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 6],
    structured: bool,
    keep_encrypted_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    let workspace = lifecycle.workspace_id().to_owned();
    let built =
        owner_bootstrap_objects(name, &workspace, identity.actor_id(), created, instance_ids)?;
    prepare_private_owner_workspace_from_built(
        journal,
        identity,
        recipient,
        lifecycle,
        intent_id,
        created,
        built,
        structured,
        None,
        keep_encrypted_wire,
        None,
    )
}

pub(crate) fn prepare_coordinated_private_owner_workspace(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    lifecycle: &mut SecureLifecycle,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 7],
    coordination_version: u8,
    keep_encrypted_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    let workspace = lifecycle.workspace_id().to_owned();
    let built = owner_bootstrap_objects_with_coordination(
        name,
        &workspace,
        identity.actor_id(),
        created,
        instance_ids,
        "PRIVATE",
        coordination_version,
    )?;
    let digest = built.operation()["objects"][13]["id"]
        .as_str()
        .ok_or(NativePrepareError::Context)?
        .to_owned();
    prepare_private_owner_workspace_from_built(
        journal,
        identity,
        recipient,
        lifecycle,
        intent_id,
        created,
        built,
        true,
        Some((&instance_ids[6], &digest, coordination_version)),
        keep_encrypted_wire,
        None,
    )
}

fn prepare_private_owner_workspace_from_built(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    lifecycle: &mut SecureLifecycle,
    intent_id: &str,
    created: u64,
    built: OwnerBootstrapObjects,
    structured: bool,
    coordination: Option<(&str, &str, u8)>,
    keep_encrypted_wire: &[u8],
    name_utf16: Option<&[u16]>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    if journal.contains_id(intent_id) {
        return Err(NativePrepareError::Existing);
    }
    let workspace = lifecycle.workspace_id().to_owned();
    let operation_wire = owner_operation_wire(&built, name_utf16)?;
    let structure = if structured {
        let objects = owner_objects_wire(&operation_wire)?;
        let canonical = if let Some((instance, digest, version)) = coordination {
            derive_genesis_structure_policy_with_coordination_and_keep_encrypted(
                &objects,
                keep_encrypted_wire,
                instance,
                digest,
                identity.actor_id(),
                version,
            )
            .map_err(|_| NativePrepareError::Context)?
        } else {
            derive_genesis_structure_policy_with_keep_encrypted(&objects, keep_encrypted_wire)
                .map_err(|_| NativePrepareError::Context)?
        };
        Some(
            serde_json::from_str::<serde_json::Value>(&canonical)
                .map_err(|_| NativePrepareError::Context)?,
        )
    } else if coordination.is_none() && keep_encrypted_wire == b"[]" {
        None
    } else {
        return Err(NativePrepareError::Context);
    };
    let mut payload = json!({"v":3,"protocol_format_ceiling":1,
        "structure_mode":if structured {"STRUCTURED"} else {"NONE"},
        "workspace_id":workspace,"owner_id":identity.actor_id(),"signing_key":identity.key_id(),
        "version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PRIVATE",
        "epoch":1,"members":[{"actor_id":identity.actor_id(),"certificate":recipient.certificate(),
            "role":"OWNER","scopes":built.scopes()}],"issued_at":created});
    if let Some(structure) = structure {
        payload["structure"] = structure;
    }
    let policy = json!({"signature":sign_canonical("peerwork.secure.policy.v3",&payload,
        identity.signing_key()).map_err(|_| NativePrepareError::Context)?,"payload":payload});
    let policy_hash = sha256_hex(
        canonical(&policy, CanonicalPath::SecureArtifact)
            .map_err(|_| NativePrepareError::Context)?
            .as_bytes(),
    );
    let mut context = json!({"v":3,"workspace_id":workspace,"sequence":1,"previous":null,
        "policy_hash":policy_hash,"epoch":1,"actor_id":identity.actor_id(),
        "signing_key":identity.key_id(),"command_id":intent_id,"action_id":"secure.bootstrap",
        "instance_id":null,"issued_at":created,"delegation":null,"protocol_format_ceiling":1});
    if structured {
        context["structure"] = json!({"v":1,"mode":"DELTA","records":[],"heads":[]});
    }
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
        &operation_wire,
        &pins,
    )
}

/// Native PUBLIC owner-create uses the same six pinned presets but no epoch
/// secret. The signed plaintext BOOTSTRAP is saved before any HTTP request;
/// later retries use this immutable row, never re-sign it.
pub(crate) fn prepare_default_public_owner_workspace(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    workspace_id: &str,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 6],
) -> Result<PendingSecureIntent, NativePrepareError> {
    prepare_default_public_owner_workspace_with_structure(
        journal,
        identity,
        recipient,
        workspace_id,
        intent_id,
        name,
        created,
        instance_ids,
        false,
    )
}

pub(crate) fn prepare_default_public_owner_workspace_with_structure(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    workspace_id: &str,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 6],
    structured: bool,
) -> Result<PendingSecureIntent, NativePrepareError> {
    let built = owner_bootstrap_objects_with_visibility(
        name,
        workspace_id,
        identity.actor_id(),
        created,
        instance_ids,
        "PUBLIC",
    )?;
    prepare_public_owner_workspace_from_built(
        journal,
        identity,
        recipient,
        workspace_id,
        intent_id,
        created,
        built,
        structured,
        None,
        b"[]",
        None,
    )
}

pub(crate) fn prepare_coordinated_public_owner_workspace(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    workspace_id: &str,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 7],
    coordination_version: u8,
) -> Result<PendingSecureIntent, NativePrepareError> {
    prepare_coordinated_public_owner_workspace_with_options(
        journal,
        identity,
        recipient,
        workspace_id,
        intent_id,
        name,
        created,
        instance_ids,
        coordination_version,
        b"[]",
    )
}

pub(crate) fn prepare_coordinated_public_owner_workspace_with_options(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    workspace_id: &str,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 7],
    coordination_version: u8,
    keep_encrypted_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    let built = owner_bootstrap_objects_with_coordination(
        name,
        workspace_id,
        identity.actor_id(),
        created,
        instance_ids,
        "PUBLIC",
        coordination_version,
    )?;
    let digest = built.operation()["objects"][13]["id"]
        .as_str()
        .ok_or(NativePrepareError::Context)?
        .to_owned();
    prepare_public_owner_workspace_from_built(
        journal,
        identity,
        recipient,
        workspace_id,
        intent_id,
        created,
        built,
        true,
        Some((&instance_ids[6], &digest, coordination_version)),
        keep_encrypted_wire,
        None,
    )
}

pub(crate) fn prepare_public_owner_workspace_with_options(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    workspace_id: &str,
    intent_id: &str,
    name: &str,
    created: u64,
    instance_ids: &[String; 6],
    keep_encrypted_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    let built = owner_bootstrap_objects_with_visibility(
        name,
        workspace_id,
        identity.actor_id(),
        created,
        instance_ids,
        "PUBLIC",
    )?;
    prepare_public_owner_workspace_from_built(
        journal,
        identity,
        recipient,
        workspace_id,
        intent_id,
        created,
        built,
        true,
        None,
        keep_encrypted_wire,
        None,
    )
}

fn prepare_public_owner_workspace_from_built(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    recipient: &crate::secure_recipient_state::RecipientState,
    workspace_id: &str,
    intent_id: &str,
    created: u64,
    built: OwnerBootstrapObjects,
    structured: bool,
    coordination: Option<(&str, &str, u8)>,
    keep_encrypted_wire: &[u8],
    name_utf16: Option<&[u16]>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    if journal.contains_id(intent_id) {
        return Err(NativePrepareError::Existing);
    }
    if journal.actor_id() != identity.actor_id() {
        return Err(NativePrepareError::Context);
    }
    recipient
        .recipient()
        .verify_local_certificate(
            recipient.certificate(),
            identity.actor_id(),
            identity.key_id(),
            created,
        )
        .map_err(|_| NativePrepareError::Context)?;
    let operation_wire = owner_operation_wire(&built, name_utf16)?;
    let structure = if structured {
        let objects = owner_objects_wire(&operation_wire)?;
        let canonical = if let Some((instance, digest, version)) = coordination {
            derive_genesis_structure_policy_with_coordination_and_keep_encrypted(
                &objects,
                keep_encrypted_wire,
                instance,
                digest,
                identity.actor_id(),
                version,
            )
            .map_err(|_| NativePrepareError::Context)?
        } else {
            derive_genesis_structure_policy_with_keep_encrypted(&objects, keep_encrypted_wire)
                .map_err(|_| NativePrepareError::Context)?
        };
        Some(
            serde_json::from_str::<serde_json::Value>(&canonical)
                .map_err(|_| NativePrepareError::Context)?,
        )
    } else {
        None
    };
    let mut payload = json!({"v":3,"protocol_format_ceiling":1,
        "structure_mode":if structured {"STRUCTURED"} else {"NONE"},
        "workspace_id":workspace_id,"owner_id":identity.actor_id(),"signing_key":identity.key_id(),
        "version":1,"previous_policy":null,"effective_sequence":1,"visibility":"PUBLIC",
        "epoch":0,"members":[{"actor_id":identity.actor_id(),"certificate":recipient.certificate(),
            "role":"OWNER","scopes":built.scopes()}],"issued_at":created});
    if let Some(structure) = structure {
        payload["structure"] = structure;
    }
    let policy = json!({"signature":sign_canonical("peerwork.secure.policy.v3",&payload,
        identity.signing_key()).map_err(|_| NativePrepareError::Context)?,"payload":payload});
    let policy_hash = sha256_hex(
        canonical(&policy, CanonicalPath::SecureArtifact)
            .map_err(|_| NativePrepareError::Context)?
            .as_bytes(),
    );
    let mut context = json!({"v":3,"workspace_id":workspace_id,"sequence":1,"previous":null,
        "policy_hash":policy_hash,"epoch":0,"actor_id":identity.actor_id(),
        "signing_key":identity.key_id(),"command_id":intent_id,"action_id":"secure.bootstrap",
        "instance_id":null,"issued_at":created,"delegation":null,"protocol_format_ceiling":1});
    if structured {
        context["structure"] = json!({"v":1,"mode":"DELTA","records":[],"heads":[]});
    }
    let pins = SecureCommitRequestPins {
        actor_id: identity.actor_id(),
        signing_key: identity.key_id(),
        workspace_id,
        policy_hash: &policy_hash,
        sequence: 1,
        previous: None,
        epoch: 0,
        mode: "PUBLIC",
        version: 3,
        protocol_format_ceiling: Some(1),
    };
    let authored = author_public_bootstrap(
        &serde_json::to_vec(&policy).map_err(|_| NativePrepareError::Context)?,
        &serde_json::to_vec(&context).map_err(|_| NativePrepareError::Context)?,
        &operation_wire,
        identity.signing_key(),
        &pins,
    )?;
    let proof = authored.proof();
    if proof.command_id() != intent_id
        || proof.workspace_id() != workspace_id
        || proof.policy_hash() != policy_hash
        || proof.visibility() != "PUBLIC"
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
    prepare_new_private_commit_inner(
        journal,
        identity,
        lifecycle,
        intent_id,
        context_wire,
        operation_wire,
        pins,
        None,
    )
}

/// Prepare the next PRIVATE packet against a complete authenticated replay.
/// Only the selected signed policy and exact checkpoint from that replay may
/// authorize the low-level structured/delegated signing path.
pub(crate) fn prepare_new_private_commit_from_replay(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    source: &TransportReplayedJournal,
    intent_id: &str,
    context_wire: &[u8],
    operation_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    source
        .verified_read()
        .map_err(|_| NativePrepareError::Context)?;
    if source.origin() != lifecycle.origin()
        || source.source_actor_id() != identity.actor_id()
        || source.source_key_id() != identity.key_id()
        || source.replay().workspace_id() != lifecycle.workspace_id()
        || source.replay().owner_actor_id() != lifecycle.owner_actor_id()
        || source.replay().owner_signing_key() != lifecycle.owner_key_id()
        || pins.sequence
            != source
                .replay()
                .sequence()
                .checked_add(1)
                .ok_or(NativePrepareError::Context)?
        || pins.previous != source.replay().head()
        || pins.policy_hash != source.replay().policy_hash()
    {
        return Err(NativePrepareError::Context);
    }
    let policy_wire = source
        .signed_policy_by_hash(pins.policy_hash)
        .ok_or(NativePrepareError::Context)?;
    let action = validate_prepared_action_operation(
        operation_wire,
        context_wire,
        policy_wire,
        source.replay().objects(),
    )
    .map_err(|_| NativePrepareError::Context)?;
    prepare_new_private_commit_inner(
        journal,
        identity,
        lifecycle,
        intent_id,
        context_wire,
        operation_wire,
        pins,
        Some((policy_wire, lifecycle.owner_key_id(), &action)),
    )
}

/// Author and persist a PUBLIC ACTION from a complete authenticated current
/// history. The candidate operation is recomputed against prior objects before
/// it is signed; no epoch key exists for a PUBLIC policy.
pub(crate) fn prepare_new_public_action_from_replay(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    source: &TransportReplayedJournal,
    intent_id: &str,
    context_wire: &[u8],
    operation_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    source
        .verified_read()
        .map_err(|_| NativePrepareError::Context)?;
    if pins.mode != "PUBLIC"
        || pins.epoch != 0
        || identity.actor_id() != lifecycle.actor_id()
        || identity.actor_id() != journal.actor_id()
        || pins.actor_id != identity.actor_id()
        || pins.signing_key != identity.key_id()
        || pins.workspace_id != lifecycle.workspace_id()
        || lifecycle.origin() != journal.trusted_origin()
        || source.origin() != lifecycle.origin()
        || source.source_actor_id() != identity.actor_id()
        || source.source_key_id() != identity.key_id()
        || source.replay().workspace_id() != lifecycle.workspace_id()
        || source.replay().owner_actor_id() != lifecycle.owner_actor_id()
        || source.replay().owner_signing_key() != lifecycle.owner_key_id()
        || pins.sequence
            != source
                .replay()
                .sequence()
                .checked_add(1)
                .ok_or(NativePrepareError::Context)?
        || pins.previous != source.replay().head()
        || pins.policy_hash != source.replay().policy_hash()
    {
        return Err(NativePrepareError::Context);
    }
    if journal.contains_id(intent_id) {
        return Err(NativePrepareError::Existing);
    }
    let policy_wire = source
        .signed_policy_by_hash(pins.policy_hash)
        .ok_or(NativePrepareError::Context)?;
    let action = validate_prepared_action_operation(
        operation_wire,
        context_wire,
        policy_wire,
        source.replay().objects(),
    )
    .map_err(|_| NativePrepareError::Context)?;
    let path = format!(
        "/api/workspace/v1/secure/workspaces/{}/commits",
        lifecycle.workspace_id()
    );
    let authored = author_public_validated_action(
        context_wire,
        &action,
        identity.signing_key(),
        &path,
        pins,
        policy_wire,
        lifecycle.owner_key_id(),
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

/// Build the ACTION operation natively from its input, then author and save
/// the exact PUBLIC packet against the same authenticated replay.
pub(crate) fn prepare_new_public_action_input_from_replay(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    source: &TransportReplayedJournal,
    intent_id: &str,
    context_wire: &[u8],
    action_input_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    source
        .verified_read()
        .map_err(|_| NativePrepareError::Context)?;
    let policy_wire = source
        .signed_policy_by_hash(pins.policy_hash)
        .ok_or(NativePrepareError::Context)?;
    let operation = build_prepared_action_with_context(
        action_input_wire,
        context_wire,
        policy_wire,
        source.replay().objects(),
    )
    .map_err(|_| NativePrepareError::Context)?;
    prepare_new_public_action_from_replay(
        journal,
        identity,
        lifecycle,
        source,
        intent_id,
        operation.context_wire(),
        operation.action().operation_wire(),
        pins,
    )
}

/// The caller supplies action values; `allocations:null` generates OS-random
/// tokens once. Instance revision comes from the authenticated replay.
pub(crate) fn prepare_new_public_action_values_from_replay(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    source: &TransportReplayedJournal,
    intent_id: &str,
    context_wire: &[u8],
    action_id: &str,
    instance_id: &str,
    body_wire: &[u8],
    exact_refs_wire: &[u8],
    allocations_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
) -> Result<PendingSecureIntent, NativePrepareError> {
    let parse = |wire: &[u8]| {
        parse_wire_json_bounded(wire, 64, 16 * 1024 * 1024).map_err(|_| NativePrepareError::Context)
    };
    let body = parse(body_wire)?;
    let refs = parse(exact_refs_wire)?;
    let allocations = parse(allocations_wire)?;
    if !matches!(refs, WireValue::Array(_))
        || !matches!(allocations, WireValue::Array(_) | WireValue::Null)
    {
        return Err(NativePrepareError::Context);
    }
    let latest = source
        .replay()
        .objects()
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && object.get("id").and_then(WireValue::as_string).as_deref() == Some(instance_id)
        })
        .max_by_key(|object| {
            object
                .get("revision")
                .and_then(WireValue::as_number)
                .unwrap_or(0.0) as u64
        })
        .ok_or(NativePrepareError::Context)?;
    let revision = latest
        .get("value")
        .and_then(|value| value.get("revision"))
        .and_then(WireValue::as_number)
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .ok_or(NativePrepareError::Context)?;
    let field = |name: &str, value: WireValue| (name.encode_utf16().collect(), value);
    let input = WireValue::Object(vec![
        field(
            "instance_id",
            WireValue::String(instance_id.encode_utf16().collect()),
        ),
        field("expected_instance_revision", WireValue::Number(revision)),
        field(
            "action_id",
            WireValue::String(action_id.encode_utf16().collect()),
        ),
        field("body", body),
        field("exact_input_refs", refs),
        field("allocations", allocations),
    ]);
    let input_wire = canonical_wire_value(&input, CanonicalPath::SecureArtifact)
        .map_err(|_| NativePrepareError::Context)?;
    prepare_new_public_action_input_from_replay(
        journal,
        identity,
        lifecycle,
        source,
        intent_id,
        context_wire,
        input_wire.as_bytes(),
        pins,
    )
}

/// Author a PUBLIC v3 action from the current verified checkpoint
/// and action values. Context and instance revision are derived locally;
/// allocation tokens may be supplied or generated once before the first POST
/// and retained in the exact saved request.
pub(crate) fn prepare_public_action_from_replay(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    source: &TransportReplayedJournal,
    command_id: &str,
    action_id: &str,
    instance_id: &str,
    issued_at: u64,
    body_wire: &[u8],
    exact_refs_wire: &[u8],
    allocations_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    if issued_at > 9_007_199_254_740_991 {
        return Err(NativePrepareError::Context);
    }
    source
        .verified_read()
        .map_err(|_| NativePrepareError::Context)?;
    let policy_hash = source.replay().policy_hash();
    let policy_wire = source
        .signed_policy_by_hash(policy_hash)
        .ok_or(NativePrepareError::Context)?;
    let policy = parse_wire_json_bounded(policy_wire, 64, 16 * 1024 * 1024)
        .map_err(|_| NativePrepareError::Context)?;
    let payload = policy.get("payload").ok_or(NativePrepareError::Context)?;
    let version = payload
        .get("v")
        .and_then(WireValue::as_number)
        .ok_or(NativePrepareError::Context)?;
    if version != 3.0
        || payload
            .get("visibility")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some("PUBLIC")
        || !matches!(
            payload
                .get("structure_mode")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("NONE" | "STRUCTURED")
        )
    {
        return Err(NativePrepareError::Context);
    }
    let epoch = payload
        .get("epoch")
        .and_then(WireValue::as_number)
        .filter(|value| *value == 0.0)
        .ok_or(NativePrepareError::Context)? as u64;
    let ceiling = payload
        .get("protocol_format_ceiling")
        .and_then(WireValue::as_number)
        .filter(|value| value.is_finite() && *value >= 1.0 && value.fract() == 0.0)
        .ok_or(NativePrepareError::Context)? as u64;
    let sequence = source
        .replay()
        .sequence()
        .checked_add(1)
        .ok_or(NativePrepareError::Context)?;
    let previous = source.replay().head();
    let pins = SecureCommitRequestPins {
        actor_id: identity.actor_id(),
        signing_key: identity.key_id(),
        workspace_id: lifecycle.workspace_id(),
        policy_hash,
        sequence,
        previous,
        epoch,
        mode: "PUBLIC",
        version: 3,
        protocol_format_ceiling: Some(ceiling),
    };
    let context = serde_json::json!({
        "v": 3,
        "workspace_id": lifecycle.workspace_id(),
        "sequence": sequence,
        "previous": previous,
        "policy_hash": policy_hash,
        "epoch": epoch,
        "actor_id": identity.actor_id(),
        "signing_key": identity.key_id(),
        "command_id": command_id,
        "action_id": action_id,
        "instance_id": instance_id,
        "issued_at": issued_at,
        "delegation": null,
        "protocol_format_ceiling": ceiling,
    });
    let context_wire = serde_json::to_vec(&context).map_err(|_| NativePrepareError::Context)?;
    prepare_new_public_action_values_from_replay(
        journal,
        identity,
        lifecycle,
        source,
        command_id,
        &context_wire,
        action_id,
        instance_id,
        body_wire,
        exact_refs_wire,
        allocations_wire,
        &pins,
    )
}

/// Build, encrypt, sign and durably save a PRIVATE ACTION from the active
/// complete replay. The latest signed policy supplies the epoch and format;
/// only the protected lifecycle's active key can encrypt the operation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_private_action_from_replay(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    source: &TransportReplayedJournal,
    command_id: &str,
    action_id: &str,
    instance_id: &str,
    issued_at: u64,
    body_wire: &[u8],
    exact_refs_wire: &[u8],
    allocations_wire: &[u8],
) -> Result<PendingSecureIntent, NativePrepareError> {
    if issued_at > 9_007_199_254_740_991 {
        return Err(NativePrepareError::Context);
    }
    source
        .verified_read()
        .map_err(|_| NativePrepareError::Context)?;
    let policy_hash = source.replay().policy_hash();
    let policy_wire = source
        .signed_policy_by_hash(policy_hash)
        .ok_or(NativePrepareError::Context)?;
    let policy = parse_wire_json_bounded(policy_wire, 64, 16 * 1024 * 1024)
        .map_err(|_| NativePrepareError::Context)?;
    let payload = policy.get("payload").ok_or(NativePrepareError::Context)?;
    let version = payload
        .get("v")
        .and_then(WireValue::as_number)
        .filter(|value| matches!(*value, 1.0 | 2.0 | 3.0))
        .ok_or(NativePrepareError::Context)? as u64;
    if payload
        .get("visibility")
        .and_then(WireValue::as_string)
        .as_deref()
        != Some("PRIVATE")
    {
        return Err(NativePrepareError::Context);
    }
    let epoch = payload
        .get("epoch")
        .and_then(WireValue::as_number)
        .filter(|value| value.is_finite() && *value >= 1.0 && value.fract() == 0.0)
        .ok_or(NativePrepareError::Context)? as u64;
    let ceiling = if version == 3 {
        Some(
            payload
                .get("protocol_format_ceiling")
                .and_then(WireValue::as_number)
                .filter(|value| matches!(*value, 1.0 | 2.0))
                .ok_or(NativePrepareError::Context)? as u64,
        )
    } else {
        None
    };
    let sequence = source
        .replay()
        .sequence()
        .checked_add(1)
        .ok_or(NativePrepareError::Context)?;
    let previous = source.replay().head();
    let pins = SecureCommitRequestPins {
        actor_id: identity.actor_id(),
        signing_key: identity.key_id(),
        workspace_id: lifecycle.workspace_id(),
        policy_hash,
        sequence,
        previous,
        epoch,
        mode: "PRIVATE",
        version,
        protocol_format_ceiling: ceiling,
    };
    let mut context = serde_json::json!({
        "v": version, "workspace_id": lifecycle.workspace_id(), "sequence": sequence,
        "previous": previous, "policy_hash": policy_hash, "epoch": epoch,
        "actor_id": identity.actor_id(), "signing_key": identity.key_id(),
        "command_id": command_id, "action_id": action_id,
        "instance_id": instance_id, "issued_at": issued_at, "delegation": null,
    });
    if let Some(ceiling) = ceiling {
        context["protocol_format_ceiling"] = serde_json::json!(ceiling);
    }
    let parse = |wire: &[u8]| {
        parse_wire_json_bounded(wire, 64, 16 * 1024 * 1024).map_err(|_| NativePrepareError::Context)
    };
    let body = parse(body_wire)?;
    let refs = parse(exact_refs_wire)?;
    let allocations = parse(allocations_wire)?;
    if !matches!(refs, WireValue::Array(_))
        || !matches!(allocations, WireValue::Array(_) | WireValue::Null)
    {
        return Err(NativePrepareError::Context);
    }
    let latest = source
        .replay()
        .objects()
        .iter()
        .filter(|object| {
            object.get("kind").and_then(WireValue::as_string).as_deref() == Some("instances")
                && object.get("id").and_then(WireValue::as_string).as_deref() == Some(instance_id)
        })
        .max_by_key(|object| {
            object
                .get("revision")
                .and_then(WireValue::as_number)
                .unwrap_or(0.0) as u64
        })
        .ok_or(NativePrepareError::Context)?;
    let revision = latest
        .get("value")
        .and_then(|value| value.get("revision"))
        .and_then(WireValue::as_number)
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .ok_or(NativePrepareError::Context)?;
    let field = |name: &str, value: WireValue| (name.encode_utf16().collect(), value);
    let input = WireValue::Object(vec![
        field(
            "instance_id",
            WireValue::String(instance_id.encode_utf16().collect()),
        ),
        field("expected_instance_revision", WireValue::Number(revision)),
        field(
            "action_id",
            WireValue::String(action_id.encode_utf16().collect()),
        ),
        field("body", body),
        field("exact_input_refs", refs),
        field("allocations", allocations),
    ]);
    let input_wire = canonical_wire_value(&input, CanonicalPath::SecureArtifact)
        .map_err(|_| NativePrepareError::Context)?;
    let context_wire = serde_json::to_vec(&context).map_err(|_| NativePrepareError::Context)?;
    let built = build_prepared_action_with_context(
        input_wire.as_bytes(),
        &context_wire,
        policy_wire,
        source.replay().objects(),
    )
    .map_err(|_| NativePrepareError::Context)?;
    prepare_new_private_commit_from_replay(
        journal,
        identity,
        lifecycle,
        source,
        command_id,
        built.context_wire(),
        built.action().operation_wire(),
        &pins,
    )
}

fn prepare_new_private_commit_inner(
    journal: &mut SecureIntentJournal,
    identity: &KernelIdentity,
    lifecycle: &SecureLifecycle,
    intent_id: &str,
    context_wire: &[u8],
    operation_wire: &[u8],
    pins: &SecureCommitRequestPins<'_>,
    policy: Option<(&[u8], &str, &ValidatedPreparedAction)>,
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
    let authored = if let Some((policy_wire, owner_key, action)) = policy {
        author_private_validated_action(
            context_wire,
            action,
            key,
            identity.signing_key(),
            &path,
            pins,
            policy_wire,
            owner_key,
        )
    } else {
        author_private_commit(
            context_wire,
            operation_wire,
            key,
            identity.signing_key(),
            &path,
            pins,
        )
    }?;
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
    use crate::test_support::protected_test_dir;
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
        let dir = protected_test_dir();
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
    async fn actual_service_native_public_owner_bootstrap_lost_reply_exact_retry() {
        actual_service_public_owner_bootstrap(false, None, false).await;
    }

    #[tokio::test]
    async fn actual_service_native_structured_public_owner_bootstrap_lost_reply_exact_retry() {
        actual_service_public_owner_bootstrap(true, None, false).await;
    }

    #[tokio::test]
    async fn actual_service_native_coordinated_public_owner_bootstrap_lost_reply_exact_retry() {
        actual_service_public_owner_bootstrap(true, Some(1), false).await;
        actual_service_public_owner_bootstrap(true, Some(2), false).await;
    }

    #[tokio::test]
    async fn actual_service_native_keep_encrypted_owner_bootstrap_lost_reply_exact_retry() {
        actual_service_public_owner_bootstrap(true, None, true).await;
    }

    async fn actual_service_public_owner_bootstrap(
        structured: bool,
        coordination: Option<u8>,
        keep_encrypted: bool,
    ) {
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
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &root.path().join("native-public-owner.state"),
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
            &root.path().join("native-public-recipient.state"),
            &identity,
            now,
        )
        .unwrap();
        let workspace = base64url(&[201; 32]);
        let ids: [String; 7] = std::array::from_fn(|i| base64url(&[i as u8 + 210; 32]));
        let first_six = std::array::from_fn(|i| ids[i].clone());
        let command = base64url(&[202; 32]);
        let journal_path = root.path().join("native-public-intents.state");
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
        if let Some(version) = coordination {
            prepare_coordinated_public_owner_workspace(
                &mut journal,
                &identity,
                &recipient,
                &workspace,
                &command,
                "Native public workspace",
                now,
                &ids,
                version,
            )
            .unwrap();
        } else if keep_encrypted {
            let built = owner_bootstrap_objects_with_visibility(
                "Native public workspace",
                &workspace,
                actor,
                now,
                &first_six,
                "PUBLIC",
            )
            .unwrap();
            let digest = built.operation()["objects"][1]["id"].as_str().unwrap();
            let choices = serde_json::to_vec(&json!([{
                "schema":"discussion.message", "fields":["author"],
                "protocol_digest":digest,
            }]))
            .unwrap();
            prepare_public_owner_workspace_with_options(
                &mut journal,
                &identity,
                &recipient,
                &workspace,
                &command,
                "Native public workspace",
                now,
                &first_six,
                &choices,
            )
            .unwrap();
        } else {
            prepare_default_public_owner_workspace_with_structure(
                &mut journal,
                &identity,
                &recipient,
                &workspace,
                &command,
                "Native public workspace",
                now,
                &first_six,
                structured,
            )
            .unwrap();
        }
        let exact = journal.exact_request(&command).unwrap();
        let (prepared, _) = journal
            .verified_saved_public_bootstrap(&command, &workspace, &identity, &transport)
            .unwrap();
        assert_eq!(prepared.visibility(), "PUBLIC");
        let expected_head = prepared.commit_digest().to_owned();
        let packet: serde_json::Value = serde_json::from_slice(&exact).unwrap();
        assert_eq!(packet["policy"]["payload"]["epoch"], 0);
        assert_eq!(packet["commit"]["payload"]["mode"], "PUBLIC");
        assert_eq!(
            packet["policy"]["payload"]["structure_mode"],
            if structured { "STRUCTURED" } else { "NONE" }
        );
        if structured {
            assert_eq!(
                packet["policy"]["payload"]["structure"]["protocols"]
                    .as_array()
                    .unwrap()
                    .len(),
                if coordination.is_some() { 7 } else { 6 }
            );
            assert_eq!(packet["commit"]["payload"]["structure"]["mode"], "DELTA");
            if keep_encrypted {
                let fields = &packet["policy"]["payload"]["structure"]["protocols"][0]["schemas"]
                    ["discussion.message"]["fields"];
                assert_eq!(fields["author"]["protection"], "e2ee");
                assert!(
                    !packet["policy"]["payload"]["structure"]["disclosure"][0]["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|field| field == "author")
                );
            }
            if let Some(version) = coordination {
                assert_eq!(
                    packet["policy"]["payload"]["structure"]["coordination"]["v"],
                    version
                );
                assert_eq!(
                    packet["policy"]["payload"]["structure"]["coordination"]["instance_id"],
                    ids[6]
                );
            }
        } else {
            assert!(packet["policy"]["payload"].get("structure").is_none());
            assert!(packet["commit"]["payload"].get("structure").is_none());
        }
        assert_eq!(
            packet["commit"]["payload"]["body"]["objects"]
                .as_array()
                .unwrap()
                .len(),
            if coordination.is_some() { 15 } else { 13 }
        );
        assert_eq!(counts().await, before, "preparation must not submit");
        let first = journal
            .submit_saved_public_bootstrap(
                &command,
                &workspace,
                &identity,
                &transport,
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
        let applied = counts().await;
        assert_eq!(applied["commits"].as_u64(), Some(1));
        assert_eq!(applied["head_sequence"].as_u64(), Some(1));
        assert_eq!(applied["head_hash"].as_str(), Some(expected_head.as_str()));
        let mut journal = SecureIntentJournal::open(&journal_path, origin, actor).unwrap();
        assert_eq!(journal.exact_request(&command).unwrap(), exact);
        journal
            .submit_saved_public_bootstrap(
                &command,
                &workspace,
                &identity,
                &transport,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(journal.pending()[0].observed_responses, 1);
        assert_eq!(counts().await, applied, "same-ID retry must not reapply");
        if !structured && coordination.is_none() && !keep_encrypted {
            let mut proof_config = TransportConfig::new(origin);
            proof_config.allow_loopback_http = true;
            let proof_client = crate::kernel_client::KernelClient::open(
                proof_config,
                &root.path().join("native-public-proof-discovery.sqlite"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .unwrap();
            let public_lifecycle = SecureLifecycle::open(
                &root.path().join("native-public-proof-lifecycle.state"),
                origin,
                actor,
                &workspace,
                actor,
                signer,
            )
            .unwrap();
            let mut proof_reader = crate::secure_journal_read::SecureJournalRead::open(
                &root.path().join("native-public-proof-journal.state"),
                &proof_client,
                &identity,
                &workspace,
                ready["bootstrap"]["authority"].as_str().unwrap(),
            )
            .unwrap();
            assert!(
                proof_reader
                    .fetch_next(&proof_client, &identity, &CancellationToken::new())
                    .await
                    .unwrap()
                    .complete_transport
            );
            let proof_pages = proof_reader
                .authenticated_pages(&proof_client, &identity)
                .unwrap();
            let proof = crate::secure_verified_read::replay_authenticated_pages(
                &proof_pages,
                &public_lifecycle,
            )
            .unwrap();
            let read = proof.verified_read().unwrap();
            assert_eq!(read.workspace_id(), workspace);
            assert_eq!(read.sequence(), 1);
            assert_eq!(read.head(), Some(expected_head.as_str()));
            assert_eq!(read.objects().len(), 13);
            assert_eq!(read.operations().len(), 1);
            assert!(read.recoveries().is_empty());
            assert_eq!(
                read.structure_status(),
                peerwork_core::replayed_secure_journal::StructureStatus::Unstructured
            );
        }
        assert!(journal
            .verified_saved_bootstrap(
                &command,
                &identity,
                &transport,
                &SecureLifecycle::open(
                    &root.path().join("wrong-private-keys.state"),
                    origin,
                    actor,
                    &workspace,
                    actor,
                    signer
                )
                .unwrap()
            )
            .is_err());
        if !structured && coordination.is_none() && !keep_encrypted {
            drop(identity);
            let config = crate::secure_read_access::SecureReadConfig {
                origin: origin.to_owned(),
                kernel_journal_path: root.path().join("native-public-proof-discovery.sqlite"),
                read_state_path: root.path().join("native-public-proof-journal.state"),
                lifecycle_path: root.path().join("native-public-proof-lifecycle.state"),
                identity_path: root.path().join("native-public-owner.state"),
                workspace_id: workspace.clone(),
                authority: ready["bootstrap"]["authority"].as_str().unwrap().to_owned(),
                owner_actor_id: actor.to_owned(),
                owner_key_id: signer.to_owned(),
                required_features: Vec::new(),
                allow_loopback_http: true,
                max_replay_artifact_bytes: crate::SecureJournalReadBudget::default()
                    .max_replay_artifact_bytes,
                max_replay_commits: crate::secure_verified_read::default_replay_commits(),
            };
            let result = std::thread::spawn(move || {
                let access = crate::secure_read_access::SecureReadAccess::new(config);
                let first = access.read_json().unwrap();
                let reopened = access.read_json().unwrap();
                assert_eq!(first, reopened, "protected read reopen must be stable");
                first
            })
            .join()
            .unwrap();
            let result: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(result["sequence"], 1);
            assert_eq!(result["head"], expected_head);
            assert_eq!(result["objects"].as_array().unwrap().len(), 13);
            assert_eq!(result["operations"].as_array().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn actual_service_native_private_structured_bootstrap_exact_retry() {
        actual_service_private_structured_bootstrap(None).await;
    }

    #[tokio::test]
    async fn actual_service_native_private_coordinated_bootstrap_exact_retry() {
        actual_service_private_structured_bootstrap(Some(1)).await;
        actual_service_private_structured_bootstrap(Some(2)).await;
    }

    async fn actual_service_private_structured_bootstrap(coordination: Option<u8>) {
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
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &root.path().join("owner.state"),
            &root.path().join("synthetic-bootstrap-owner.pem"),
        )
        .unwrap();
        assert_eq!(identity.actor_id(), actor);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let recipient = crate::secure_recipient_state::RecipientState::create(
            &root.path().join("recipient.state"),
            &identity,
            now,
        )
        .unwrap();
        let workspace = base64url(&[142; 32]);
        let ids: [String; 7] = std::array::from_fn(|i| base64url(&[i as u8 + 143; 32]));
        let first_six = std::array::from_fn(|i| ids[i].clone());
        let command = base64url(&[151; 32]);
        let lifecycle_path = root.path().join("epochs.state");
        let journal_path = root.path().join("intents.state");
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
        let built = owner_bootstrap_objects(
            "Native structured private",
            &workspace,
            actor,
            now,
            &first_six,
        )
        .unwrap();
        let digest = built.operation()["objects"][1]["id"].as_str().unwrap();
        let choices = serde_json::to_vec(&json!([{
            "schema":"discussion.message", "fields":["author"],
            "protocol_digest":digest,
        }]))
        .unwrap();
        if let Some(version) = coordination {
            prepare_coordinated_private_owner_workspace(
                &mut journal,
                &identity,
                &recipient,
                &mut lifecycle,
                &command,
                "Native structured private",
                now,
                &ids,
                version,
                &choices,
            )
            .unwrap();
        } else {
            prepare_private_owner_workspace_with_options(
                &mut journal,
                &identity,
                &recipient,
                &mut lifecycle,
                &command,
                "Native structured private",
                now,
                &first_six,
                true,
                &choices,
            )
            .unwrap();
        }
        let exact = journal.exact_request(&command).unwrap();
        let packet: serde_json::Value = serde_json::from_slice(&exact).unwrap();
        assert_eq!(packet["policy"]["payload"]["structure_mode"], "STRUCTURED");
        assert_eq!(packet["policy"]["payload"]["visibility"], "PRIVATE");
        assert_eq!(packet["commit"]["payload"]["mode"], "PRIVATE");
        assert_eq!(packet["commit"]["payload"]["structure"]["mode"], "DELTA");
        assert_eq!(
            packet["policy"]["payload"]["structure"]["protocols"]
                .as_array()
                .unwrap()
                .len(),
            if coordination.is_some() { 7 } else { 6 }
        );
        if let Some(version) = coordination {
            assert_eq!(
                packet["policy"]["payload"]["structure"]["coordination"]["v"],
                version
            );
            assert_eq!(
                packet["policy"]["payload"]["structure"]["coordination"]["instance_id"],
                ids[6]
            );
        }
        assert_eq!(
            packet["policy"]["payload"]["structure"]["protocols"][0]["schemas"]
                ["discussion.message"]["fields"]["author"]["protection"],
            "e2ee"
        );
        let (proof, _) = journal
            .verified_saved_bootstrap(&command, &identity, &transport, &lifecycle)
            .unwrap();
        let expected_head = proof.commit_digest().to_owned();
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
        assert_eq!(
            counts().await,
            applied,
            "exact same-ID retry must not reapply"
        );
        assert_eq!(journal.pending()[0].observed_responses, 1);
        if coordination.is_none() {
            // The real one-commit service journal crosses configured-origin page
            // custody, protected pending key material, and signed core replay.
            // Pending material still cannot authorize an ACTION outcome.
            let mut proof_config = TransportConfig::new(origin);
            proof_config.allow_loopback_http = true;
            let proof_client = crate::kernel_client::KernelClient::open(
                proof_config,
                &root.path().join("native-proof-discovery.sqlite"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .unwrap();
            let mut proof_reader = crate::secure_journal_read::SecureJournalRead::open(
                &root.path().join("native-proof-journal.state"),
                &proof_client,
                &identity,
                &workspace,
                ready["bootstrap"]["authority"].as_str().unwrap(),
            )
            .unwrap();
            assert!(proof_reader
                .authenticated_pages(&proof_client, &identity)
                .is_err());
            let proof_progress = proof_reader
                .fetch_next(&proof_client, &identity, &CancellationToken::new())
                .await
                .unwrap();
            assert!(proof_progress.complete_transport);
            let proof_pages = proof_reader
                .authenticated_pages(&proof_client, &identity)
                .unwrap();
            assert!(matches!(
                crate::secure_verified_read::replay_authenticated_pages_with_budget(
                    &proof_pages,
                    &lifecycle,
                    crate::SecureJournalReadBudget::new(1).unwrap(),
                ),
                Err(crate::secure_verified_read::VerifiedReadError::ResourceLimit)
            ));
            let verified =
                crate::secure_verified_read::replay_authenticated_pages(&proof_pages, &lifecycle)
                    .unwrap();
            assert_eq!(verified.origin(), origin);
            assert_eq!(verified.replay().sequence(), 1);
            assert_eq!(verified.replay().head(), Some(expected_head.as_str()));
            assert_eq!(verified.source_actor_id(), identity.actor_id());
            assert_eq!(verified.source_key_id(), identity.key_id());
            assert_eq!(
                verified.keyring_state(),
                Some(crate::secure_lifecycle::ReplayKeyringState::Pending)
            );
            assert!(matches!(
                verified.verified_read(),
                Err(crate::secure_verified_read::VerifiedReadError::NotActive)
            ));
            assert!(verified.action_receipt(&command).unwrap().is_none());
            // The service supplied the signed journal; this owner-signed
            // direct grant is synthetic local evidence for the activation
            // composition, not a grant fetched from the service.
            let policy_wire = serde_json::to_vec(&packet["policy"]).unwrap();
            let commit_wire = serde_json::to_vec(&packet["commit"]).unwrap();
            let checkpoint_wire = proof_pages.checkpoint_canonical_json().as_bytes();
            let checkpoint: serde_json::Value = serde_json::from_slice(checkpoint_wire).unwrap();
            let certificate = serde_json::to_value(recipient.certificate()).unwrap();
            let ring = lifecycle.replay_keyring_candidate().unwrap();
            let grant_context = json!({
                "v":1,"grant_id":base64url(&[152;32]),"workspace_id":workspace,
                "actor_id":actor,"signing_key":signer,"recipient":certificate,
                "policy_hash":checkpoint["policy_hash"],"epoch":1,
                "invite_id":null,"acceptance_hash":null,"delegation":null,
                "issued_at":now+1
            });
            let grant_context_wire = peerwork_core::canonical::canonical(
                &grant_context,
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .unwrap();
            let mut grant_payload = grant_context;
            grant_payload["box"] = serde_json::to_value(
                ring.ring
                    .seal_to(
                        recipient.recipient().public_jwk(),
                        grant_context_wire.as_bytes(),
                    )
                    .unwrap(),
            )
            .unwrap();
            let signature = peerwork_core::crypto::sign_canonical(
                "peerwork.secure.key-grant.v1",
                &grant_payload,
                identity.signing_key(),
            )
            .unwrap();
            let grant_wire =
                serde_json::to_vec(&json!({"payload":grant_payload,"signature":signature}))
                    .unwrap();
            let certificate_wire = serde_json::to_vec(&certificate).unwrap();
            let policies = [&policy_wire[..]];
            let commits = [&commit_wire[..]];
            let mut pending_grant = crate::secure_grant_pending::SecureGrantPending::open(
                &root.path().join("native-proof-grant.state"),
                origin,
                ready["bootstrap"]["authority"].as_str().unwrap(),
                &workspace,
                actor,
                signer,
                &identity,
                &recipient,
                now + 1,
            )
            .unwrap();
            let grant_material = pending_grant
                .stage(
                    crate::secure_grant_pending::GrantEvidence {
                        policies: &policies,
                        commits: &commits,
                        checkpoint: checkpoint_wire,
                        grant: &grant_wire,
                        certificate: &certificate_wire,
                        invitation: None,
                        delegation: None,
                    },
                    &recipient,
                    now + 1,
                )
                .unwrap();
            let candidate = crate::secure_verified_read::replay_authenticated_pages_with_grant(
                &proof_pages,
                &lifecycle,
                &grant_material,
                crate::SecureJournalReadBudget::default(),
            )
            .unwrap();
            assert!(candidate.verified_read().is_err());
            assert!(matches!(
                pending_grant.bind_to_replay(&recipient, now + 1, &verified),
                Err(crate::secure_grant_pending::PendingGrantError::ReplayMismatch)
            ));
            let checkpoint_before_commit = serde_json::to_vec(&json!({
                "v":1,"workspace_id":workspace,"owner_id":actor,"owner_key":signer,
                "sequence":0,"head":null,"policy_hash":checkpoint["policy_hash"]
            }))
            .unwrap();
            let mut earlier_grant = crate::secure_grant_pending::SecureGrantPending::open(
                &root.path().join("native-earlier-grant.state"),
                origin,
                ready["bootstrap"]["authority"].as_str().unwrap(),
                &workspace,
                actor,
                signer,
                &identity,
                &recipient,
                now + 1,
            )
            .unwrap();
            earlier_grant
                .stage(
                    crate::secure_grant_pending::GrantEvidence {
                        policies: &policies,
                        commits: &[],
                        checkpoint: &checkpoint_before_commit,
                        grant: &grant_wire,
                        certificate: &certificate_wire,
                        invitation: None,
                        delegation: None,
                    },
                    &recipient,
                    now + 1,
                )
                .unwrap();
            assert!(matches!(
                earlier_grant.bind_to_replay(&recipient, now + 1, &candidate),
                Err(crate::secure_grant_pending::PendingGrantError::ReplayMismatch)
            ));
            let activation = pending_grant
                .bind_to_replay(&recipient, now + 1, &candidate)
                .unwrap()
                .unwrap();
            assert_eq!(
                lifecycle
                    .activate_verified_grant(activation)
                    .unwrap()
                    .active_epochs,
                vec![1]
            );
            let active =
                crate::secure_verified_read::replay_authenticated_pages(&proof_pages, &lifecycle)
                    .unwrap();
            assert_eq!(active.verified_read().unwrap().objects().len(), 13);
            drop(lifecycle);
            let reopened =
                SecureLifecycle::open(&lifecycle_path, origin, actor, &workspace, actor, signer)
                    .unwrap();
            assert_eq!(reopened.status().active_epochs, vec![1]);
            let reopened_read =
                crate::secure_verified_read::replay_authenticated_pages(&proof_pages, &reopened)
                    .unwrap();
            assert_eq!(reopened_read.verified_read().unwrap().operations().len(), 1);
        }
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
        client.transport().fail_one_journal_get_and_record_proofs();
        let progress = read
            .fetch_next(&client, &identity, &CancellationToken::new())
            .await
            .unwrap();
        let proofs = client.transport().take_journal_get_probe_proofs();
        assert_eq!(proofs.len(), 2, "only one journal GET network retry");
        assert_ne!(proofs[0], proofs[1], "retry must use a fresh signed read proof");
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
        let after_reads = counts().await;
        for field in ["commits", "head_sequence", "head_hash"] {
            assert_eq!(after_reads[field], paginated[field], "signed reads must not submit");
        }
        assert!(after_reads["journal_gets"].as_u64().unwrap()
            > paginated["journal_gets"].as_u64().unwrap());
    }

    #[tokio::test]
    async fn owner_bootstrap_stages_key_and_exact_packet_across_restart() {
        use peerwork_core::{
            canonical::{canonical, Path},
            crypto::{sha256_hex, sign_canonical},
            secure_recipient::SecretRecipient,
        };
        let dir = protected_test_dir();
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
        let dir = protected_test_dir();
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

    #[tokio::test]
    async fn actual_service_public_action_is_natively_authored_from_replayed_state() {
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
            .env("PEERWORK_TEST_PUBLIC_READ", "1")
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
        assert!(!line.is_empty(), "public fixture exited before readiness");
        let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
        let origin = ready["origin"].as_str().unwrap().to_owned();
        let fixture = &ready["public_read"];
        let workspace = fixture["workspace_id"].as_str().unwrap().to_owned();
        let authority = fixture["authority"].as_str().unwrap();
        let identity = KernelIdentity::import_pkcs8_pem_file(
            &root.path().join("native-public-identity.state"),
            &root.path().join("synthetic-public-read-owner.pem"),
        )
        .unwrap();
        let lifecycle = SecureLifecycle::open(
            &root.path().join("native-public-lifecycle.state"),
            &origin,
            identity.actor_id(),
            &workspace,
            identity.actor_id(),
            identity.key_id(),
        )
        .unwrap();
        let mut config = TransportConfig::new(origin.clone());
        config.allow_loopback_http = true;
        let mut read_config = TransportConfig::new(origin.clone());
        read_config.allow_loopback_http = true;
        let client = crate::kernel_client::KernelClient::open(
            read_config,
            &root.path().join("native-public-discovery.sqlite"),
            &[],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut reader = crate::secure_journal_read::SecureJournalRead::open(
            &root.path().join("native-public-prior.state"),
            &client,
            &identity,
            &workspace,
            authority,
        )
        .unwrap();
        assert!(
            reader
                .fetch_next(&client, &identity, &CancellationToken::new())
                .await
                .unwrap()
                .complete_transport
        );
        let pages = reader.authenticated_pages(&client, &identity).unwrap();
        let source =
            crate::secure_verified_read::replay_authenticated_pages(&pages, &lifecycle).unwrap();
        assert_eq!(source.replay().sequence(), 1);
        let instance_id = fixture["instance_id"].as_str().unwrap();
        let previous = source.replay().head();
        let pins = SecureCommitRequestPins {
            actor_id: identity.actor_id(),
            signing_key: identity.key_id(),
            workspace_id: &workspace,
            policy_hash: source.replay().policy_hash(),
            sequence: source.replay().sequence() + 1,
            previous,
            epoch: 0,
            mode: "PUBLIC",
            version: 3,
            protocol_format_ceiling: Some(1),
        };
        let intent_id = "p".repeat(43);
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let body_wire =
            serde_json::to_vec(&json!({"message":"native public authored action"})).unwrap();
        let refs_wire = b"[]";
        let allocations_wire = b"null";
        let mut journal = SecureIntentJournal::open(
            &root.path().join("native-public-action.state"),
            &origin,
            identity.actor_id(),
        )
        .unwrap();
        assert!(prepare_public_action_from_replay(
            &mut journal,
            &identity,
            &lifecycle,
            &source,
            &intent_id,
            "discussion.wrong",
            instance_id,
            issued_at,
            &body_wire,
            refs_wire,
            allocations_wire,
        )
        .is_err());
        assert!(journal.pending().is_empty());
        prepare_public_action_from_replay(
            &mut journal,
            &identity,
            &lifecycle,
            &source,
            &intent_id,
            "discussion.post",
            instance_id,
            issued_at,
            &body_wire,
            refs_wire,
            allocations_wire,
        )
        .unwrap();
        let transport = HttpTransport::new(config).unwrap();
        journal
            .verified_saved_commit_from_replay(&intent_id, &identity, &transport, &source, &pins)
            .unwrap();
        let sent = journal
            .submit_saved_commit_from_replay(
                &intent_id,
                &identity,
                &transport,
                &source,
                &pins,
                &CancellationToken::new(),
            )
            .await;
        assert!(matches!(
            sent,
            Err(SecureIntentError::Transport(
                TransportError::SubmittedUncertain
            ))
        ));
        let counts: serde_json::Value = serde_json::from_slice(
            &reqwest::get(format!("{origin}__test/secure-counts"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(counts["commits"], 2);
        assert_eq!(counts["head_sequence"], 2);
        let mut after = crate::secure_journal_read::SecureJournalRead::open(
            &root.path().join("native-public-after.state"),
            &client,
            &identity,
            &workspace,
            authority,
        )
        .unwrap();
        assert!(
            after
                .fetch_next(&client, &identity, &CancellationToken::new())
                .await
                .unwrap()
                .complete_transport
        );
        let after_pages = after.authenticated_pages(&client, &identity).unwrap();
        let verified =
            crate::secure_verified_read::replay_authenticated_pages(&after_pages, &lifecycle)
                .unwrap();
        let accepted = journal
            .accept_replayed_action(&intent_id, &identity, &transport, &verified)
            .unwrap();
        assert_eq!(accepted.sequence, 2);
        assert!(journal.pending().is_empty());

        let profile_config = crate::secure_read_profile::SecureReadProfileConfig {
            origin: origin.clone(),
            state_dir: root.path().to_path_buf(),
            identity_path: root.path().join("native-public-identity.state"),
            workspace_id: workspace.clone(),
            owner_actor_id: Some(identity.actor_id().to_owned()),
            owner_key_id: Some(identity.key_id().to_owned()),
            authority: Some(authority.to_owned()),
            required_features: vec![],
            allow_loopback_http: true,
            max_replay_artifact_bytes: 64 * 1024 * 1024,
            max_replay_commits: crate::secure_verified_read::default_replay_commits(),
        };
        let reconcile_config = profile_config.clone();
        let readback_config = profile_config.clone();
        let retry_config = profile_config.clone();
        let facade_instance_id = instance_id.to_owned();
        assert!(reqwest::Client::new()
            .post(format!("{origin}__test/drop-next-post"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        let submitted_wire = tokio::task::spawn_blocking(move || {
            let facade = crate::secure_action_access::SecurePublicActionAccess::new(profile_config);
            facade.submit_new_json(crate::secure_action_access::PublicActionInput {
                action_id: "discussion.post".into(),
                instance_id: facade_instance_id,
                body_json: r#"{"message":"native facade authored record"}"#.into(),
                exact_input_refs_json: None,
                allocations_json: None,
                command_id: Some("q".repeat(43)),
                issued_at_ms: None,
            })
        })
        .await
        .unwrap()
        .unwrap();
        let submitted: serde_json::Value = serde_json::from_str(&submitted_wire).unwrap();
        assert_eq!(submitted["status"], "PENDING");
        let applied_counts: serde_json::Value = serde_json::from_slice(
            &reqwest::get(format!("{origin}__test/secure-counts"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(applied_counts["commits"], 3);
        let reconciled_wire = tokio::task::spawn_blocking(move || {
            let facade =
                crate::secure_action_access::SecurePublicActionAccess::new(reconcile_config);
            facade.reconcile_json("q".repeat(43).as_str())
        })
        .await
        .unwrap()
        .unwrap();
        let reconciled: serde_json::Value = serde_json::from_str(&reconciled_wire).unwrap();
        assert_eq!(reconciled["status"], "ACCEPTED");
        assert_eq!(reconciled["sequence"], 3);
        let retried_wire = tokio::task::spawn_blocking(move || {
            let facade = crate::secure_action_access::SecurePublicActionAccess::new(retry_config);
            facade.retry_saved_json("q".repeat(43).as_str())
        })
        .await
        .unwrap()
        .unwrap();
        let retried: serde_json::Value = serde_json::from_str(&retried_wire).unwrap();
        assert_eq!(retried["status"], "ACCEPTED");
        let final_counts: serde_json::Value = serde_json::from_slice(
            &reqwest::get(format!("{origin}__test/secure-counts"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(final_counts["commits"], 3);
        let receipt: serde_json::Value =
            serde_json::from_str(reconciled["receipt_canonical_json"].as_str().unwrap()).unwrap();
        let effects = receipt["effects"].as_array().unwrap();
        assert_eq!(effects.len(), 1);
        let record_id = effects[0]["record_id"].as_str().unwrap();
        let readback_wire = tokio::task::spawn_blocking(move || {
            crate::secure_read_profile::SecureReadProfile::new(readback_config).read_latest_json()
        })
        .await
        .unwrap()
        .unwrap();
        let readback: serde_json::Value = serde_json::from_str(&readback_wire).unwrap();
        assert_eq!(readback["sequence"], 3);
        assert!(readback["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|object| object["kind"] == "records" && object["id"] == record_id));
    }
}
