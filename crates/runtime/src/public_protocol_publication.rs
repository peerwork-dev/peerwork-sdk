//! Durable PUBLIC `protocol.publish` execution from a compiler-validated
//! package closure. Instance creation and grants remain explicit caller work.

use crate::{
    kernel_client::{KernelClient, KernelClientError, KernelOperationStatus},
    kernel_identity::KernelIdentity,
    secure_state::{SecureStateError, SecureStateStore},
};
use peerwork_core::{
    crypto::{base64url, sha256, sha256_hex},
    prepared_command::prepare_signed_command_wire,
    public_direct_install::{
        normalize_install_protocol_manifest, resolve_install_protocol_with_available,
        PublicPackageCompilation,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
    canonical::Path as CanonicalPath,
};
use std::{collections::HashSet, path::Path, time::{SystemTime, UNIX_EPOCH}};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const OPERATION_FORMAT: &str = "peerwork.native-publication-operation.v1";
const MAX_OPERATION_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum PublicProtocolPublicationError {
    #[error("publication compiler artifact, workspace, operation, or CAS is invalid")]
    Invalid,
    #[error("operation id is already bound to different publication intent")]
    OperationConflict,
    #[error("saved publication step was rejected or has an unexpected digest/revision")]
    StepConflict,
    #[error("authenticated workspace readback does not match the publication")]
    ReadbackMismatch,
    #[error(transparent)]
    Client(#[from] KernelClientError),
    #[error(transparent)]
    State(#[from] SecureStateError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProtocolPublicationOutcome {
    pub workspace_id: String,
    pub protocol_digest: String,
    pub workspace_revision: u64,
    pub command_ids: Vec<String>,
}

/// Publish every compiler-resolved dependency followed by the root. The
/// protected operation file pins caller identity, the complete artifact,
/// initial revision and exact signed-command IDs before any request is sent.
#[allow(clippy::too_many_arguments)]
pub async fn publish_public_protocol(
    client: &mut KernelClient,
    identity: &KernelIdentity,
    authority: &str,
    operation_state_path: &Path,
    compilation: &PublicPackageCompilation,
    workspace_id: &str,
    operation_id: &str,
    initial_workspace_revision: u64,
    cancel: &CancellationToken,
) -> Result<PublicProtocolPublicationOutcome, PublicProtocolPublicationError> {
    if !token(workspace_id) || !token(operation_id) || !hex_digest(authority)
        || initial_workspace_revision == 0 || initial_workspace_revision > 9_007_199_254_740_991
    { return Err(PublicProtocolPublicationError::Invalid); }
    let artifact = compilation.publication_artifact();
    validate_compilation(compilation)?;

    let artifact_wire = canonical_wire_value(artifact.wire(), CanonicalPath::SecureArtifact)
        .map_err(|_| PublicProtocolPublicationError::Invalid)?;
    let artifact_digest = sha256_hex(artifact_wire.as_bytes());
    let intent_value = object(vec![
        ("format", text(OPERATION_FORMAT)), ("workspace_id", text(workspace_id)),
        ("operation_id", text(operation_id)), ("initial_workspace_revision", number(initial_workspace_revision)),
        ("actor_id", text(identity.actor_id())), ("key_id", text(identity.key_id())),
        ("authority", text(authority)),
        ("audience", WireValue::String(client.discovery().audience_utf16().to_vec())),
        ("origin", text(client.origin())), ("artifact_digest", text(&artifact_digest)),
    ]);
    let intent_canonical = canonical_wire_value(&intent_value, CanonicalPath::SecureArtifact)
        .map_err(|_| PublicProtocolPublicationError::Invalid)?;

    let entries = publication_entries(artifact)?;
    if initial_workspace_revision.checked_add(entries.len() as u64)
        .filter(|value| *value <= 9_007_199_254_740_991).is_none()
    { return Err(PublicProtocolPublicationError::Invalid); }
    let store = SecureStateStore::open(operation_state_path)?;
    let saved = store.read_exact()?;
    let saved_wire = if let Some(bytes) = saved {
        if bytes.len() > MAX_OPERATION_BYTES { return Err(PublicProtocolPublicationError::Invalid); }
        let value = parse_wire_json_bounded(&bytes, 48, MAX_OPERATION_BYTES)
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
        let canonical = canonical_wire_value(&value, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
        if canonical.as_bytes() != bytes.as_slice()
            || value.get("format").and_then(WireValue::as_string).as_deref() != Some(OPERATION_FORMAT)
            || value.get("intent").and_then(|v| canonical_wire_value(v, CanonicalPath::SecureArtifact).ok()).as_deref() != Some(intent_canonical.as_str())
        { return Err(PublicProtocolPublicationError::OperationConflict); }
        value
    } else {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| PublicProtocolPublicationError::Invalid)?.as_millis();
        if now > 9_007_199_254_000_000 { return Err(PublicProtocolPublicationError::Invalid); }
        let issued_at = now as u64;
        let expires_at = issued_at.checked_add(300_000)
            .filter(|value| *value <= 9_007_199_254_740_991)
            .ok_or(PublicProtocolPublicationError::Invalid)?;
        let commands = entries.iter().enumerate().map(|(index, (digest, manifest))| {
            let command_id = step_command_id(operation_id, workspace_id, index);
            Ok(object(vec![
                ("v", number(1)), ("command_id", text(&command_id)),
                ("audience", WireValue::String(client.discovery().audience_utf16().to_vec())),
                ("actor_id", text(identity.actor_id())), ("authority", text(authority)),
                ("method", text("POST")), ("path", text("/api/workspace/v1/commands")),
                ("workspace_id", text(workspace_id)), ("instance_id", WireValue::Null),
                ("protocol_digest", WireValue::Null), ("action_id", text("protocol.publish")),
                ("expected_workspace_revision", number(initial_workspace_revision + index as u64)),
                ("expected_instance_revision", WireValue::Null),
                ("exact_input_refs", WireValue::Array(vec![])),
                ("issued_at", number(issued_at)), ("expires_at", number(expires_at)),
                ("body", object(vec![("manifest", manifest.clone())])),
                ("expected_protocol_digest", text(digest)),
            ]))
        }).collect::<Result<Vec<_>, PublicProtocolPublicationError>>()?;
        let anchor_wire = object(vec![
            ("format", text(OPERATION_FORMAT)), ("intent", intent_value.clone()),
            ("artifact", artifact.wire().clone()), ("commands", WireValue::Array(commands)),
        ]);
        let canonical = canonical_wire_value(&anchor_wire, CanonicalPath::SecureArtifact)
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
        preflight_saved_commands(&anchor_wire, identity, client)?;
        store.write_exact(canonical.as_bytes())?;
        anchor_wire
    };

    preflight_saved_commands(&saved_wire, identity, client)?;
    let commands = saved_wire.get("commands").and_then(as_array)
        .ok_or(PublicProtocolPublicationError::Invalid)?;
    if commands.len() != entries.len() { return Err(PublicProtocolPublicationError::OperationConflict); }
    let mut command_ids = Vec::with_capacity(commands.len());
    let mut expected = Vec::with_capacity(commands.len());
    for (index, (saved, (digest, manifest))) in commands.iter().zip(entries.iter()).enumerate() {
        let id = saved.get("command_id").and_then(WireValue::as_string)
            .ok_or(PublicProtocolPublicationError::Invalid)?;
        let index_revision = initial_workspace_revision.checked_add(index as u64)
            .filter(|value| *value <= 9_007_199_254_740_991)
            .ok_or(PublicProtocolPublicationError::Invalid)?;
        if id != step_command_id(operation_id, workspace_id, index)
            || saved.get("expected_protocol_digest").and_then(WireValue::as_string).as_deref() != Some(digest)
            || !canonical_wire_equal(
                saved.get("body").and_then(|v| v.get("manifest")),
                Some(manifest),
                CanonicalPath::SecureArtifact,
            )
            || saved.get("workspace_id").and_then(WireValue::as_string).as_deref() != Some(workspace_id)
            || saved.get("action_id").and_then(WireValue::as_string).as_deref() != Some("protocol.publish")
            || saved.get("actor_id").and_then(WireValue::as_string).as_deref() != Some(identity.actor_id())
            || saved.get("authority").and_then(WireValue::as_string).as_deref() != Some(authority)
            || saved.get("audience").and_then(WireValue::as_utf16) != Some(client.discovery().audience_utf16())
            || saved.get("method").and_then(WireValue::as_string).as_deref() != Some("POST")
            || saved.get("path").and_then(WireValue::as_string).as_deref() != Some("/api/workspace/v1/commands")
            || saved.get("expected_workspace_revision").and_then(WireValue::as_number).map(|v| v as u64) != Some(index_revision)
            || !matches!(saved.get("instance_id"), Some(WireValue::Null))
            || !matches!(saved.get("protocol_digest"), Some(WireValue::Null))
            || !matches!(saved.get("expected_instance_revision"), Some(WireValue::Null))
            || !matches!(saved.get("exact_input_refs"), Some(WireValue::Array(items)) if items.is_empty())
            || saved.get("issued_at").and_then(WireValue::as_number).is_none_or(|v| !v.is_finite() || v < 0.0 || v.fract() != 0.0)
            || saved.get("expires_at").and_then(WireValue::as_number).is_none_or(|v| !v.is_finite() || v <= saved.get("issued_at").and_then(WireValue::as_number).unwrap_or(-1.0) || v > 9_007_199_254_740_991.0 || v.fract() != 0.0)
        { return Err(PublicProtocolPublicationError::OperationConflict); }
        let mut public_command = saved.clone();
        if let WireValue::Object(fields) = &mut public_command {
            fields.retain(|(key, _)| key.iter().copied().ne("expected_protocol_digest".encode_utf16()));
        }
        let command_wire = canonical_wire_value(&public_command, CanonicalPath::Kernel { max_depth: 32 })
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
        prepare_signed_command_wire(&public_command, identity.signing_key(), client.discovery(), None)
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
        command_ids.push(id);
        expected.push((digest.clone(), initial_workspace_revision + index as u64, command_wire.into_bytes()));
    }

    // Prepare and durably persist every exact request before the first POST.
    for (command_id, (_, _, command_wire)) in command_ids.iter().zip(expected.iter()) {
        let pending = client.prepare_command(identity, command_wire, None)?;
        if pending.command_id != *command_id { return Err(PublicProtocolPublicationError::Invalid); }
    }

    let mut final_revision = initial_workspace_revision;
    for (command_id, (digest, revision_before, _)) in command_ids.iter().zip(expected.iter()) {
        let accepted = match client.status(command_id, identity.key_id())? {
            Some(KernelOperationStatus::Accepted(result)) => result,
            Some(KernelOperationStatus::Pending) => client.submit_saved(command_id, identity.key_id(), cancel).await?,
            None => return Err(PublicProtocolPublicationError::Invalid),
        };
        let published_revision = client.verified_published_workspace_revision(command_id, identity.key_id())?;
        if accepted.protocol_digest.as_deref() != Some(digest)
            || published_revision != Some(revision_before + 1)
            || *revision_before != final_revision
        { return Err(PublicProtocolPublicationError::StepConflict); }
        final_revision = revision_before + 1;
    }
    verify_snapshot(client, identity, authority, workspace_id, artifact, &entries, cancel).await?;
    Ok(PublicProtocolPublicationOutcome {
        workspace_id: workspace_id.to_owned(),
        protocol_digest: artifact.expected_resolved_digest().to_owned(),
        workspace_revision: final_revision,
        command_ids,
    })
}

fn preflight_saved_commands(
    anchor: &WireValue,
    identity: &KernelIdentity,
    client: &KernelClient,
) -> Result<(), PublicProtocolPublicationError> {
    let commands = anchor.get("commands").and_then(as_array)
        .ok_or(PublicProtocolPublicationError::Invalid)?;
    if commands.is_empty() || commands.len() > 17 { return Err(PublicProtocolPublicationError::Invalid); }
    for saved in commands {
        let mut public_command = saved.clone();
        if let WireValue::Object(fields) = &mut public_command {
            fields.retain(|(key, _)| key.iter().copied().ne("expected_protocol_digest".encode_utf16()));
        }
        prepare_signed_command_wire(&public_command, identity.signing_key(), client.discovery(), None)
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
    }
    Ok(())
}

fn validate_compilation(compilation: &PublicPackageCompilation) -> Result<(), PublicProtocolPublicationError> {
    let artifact = compilation.publication_artifact();
    let provenance = artifact.provenance();
    let lock = provenance.compilation_lock();
    if artifact.expected_resolved_digest() != compilation.protocol_digest()
        || provenance.package_digest() != compilation.package_digest()
        || lock.get("root_package_digest").and_then(WireValue::as_string).as_deref() != Some(provenance.package_digest())
        || lock.get("source_digest").and_then(WireValue::as_string).as_deref() != Some(provenance.source_digest())
        || lock.get("protocol_digest").and_then(WireValue::as_string).as_deref() != Some(artifact.expected_resolved_digest())
        || lock.get("compiler_version").and_then(WireValue::as_string).as_deref() != Some(provenance.compiler_version())
        || lock.get("semantics").and_then(WireValue::as_string).as_deref() != Some(provenance.semantics())
    { return Err(PublicProtocolPublicationError::Invalid); }
    let bindings = lock.get("bindings").ok_or(PublicProtocolPublicationError::Invalid)?;
    let binding_wire = canonical_wire_value(bindings, CanonicalPath::SecureArtifact)
        .map_err(|_| PublicProtocolPublicationError::Invalid)?;
    if sha256_hex(binding_wire.as_bytes()) != provenance.binding_digest() {
        return Err(PublicProtocolPublicationError::Invalid);
    }
    let _ = publication_entries(artifact)?;
    Ok(())
}

fn publication_entries(artifact: &peerwork_core::public_direct_install::ProtocolPublicationArtifact)
    -> Result<Vec<(String, WireValue)>, PublicProtocolPublicationError> {
    let mut available = Vec::with_capacity(artifact.dependencies().len());
    let mut seen = HashSet::new();
    for dependency in artifact.dependencies() {
        let (manifest, digest) = normalize_install_protocol_manifest(dependency.manifest())
            .map_err(|_| PublicProtocolPublicationError::Invalid)?;
        if digest != dependency.protocol_digest() || !seen.insert(digest.clone()) {
            return Err(PublicProtocolPublicationError::Invalid);
        }
        available.push((digest, manifest));
    }
    let (resolved, digest, _) = resolve_install_protocol_with_available(
        artifact.root_manifest(), None, &available,
    ).map_err(|_| PublicProtocolPublicationError::Invalid)?;
    if digest != artifact.expected_resolved_digest() { return Err(PublicProtocolPublicationError::Invalid); }
    let closure = resolved.get("dependencies").and_then(as_array)
        .ok_or(PublicProtocolPublicationError::Invalid)?;
    let expected_closure = artifact.dependencies().iter().map(|item| item.protocol_digest()).collect::<Vec<_>>();
    if closure.len() != expected_closure.len()
        || closure.iter().zip(expected_closure).any(|(value, expected)| value.as_string().as_deref() != Some(expected))
    { return Err(PublicProtocolPublicationError::Invalid); }
    let mut entries = available;
    // PUBLIC protocol.publish must receive the unresolved compiler root; the
    // root is independently reassembled above only to verify its final digest.
    entries.push((digest, artifact.root_manifest().clone()));
    Ok(entries)
}

async fn verify_snapshot(
    client: &KernelClient,
    identity: &KernelIdentity,
    authority: &str,
    workspace_id: &str,
    artifact: &peerwork_core::public_direct_install::ProtocolPublicationArtifact,
    entries: &[(String, WireValue)],
    cancel: &CancellationToken,
) -> Result<(), PublicProtocolPublicationError> {
    let response = client.read_public_workspace_snapshot(identity, authority, workspace_id, cancel).await?;
    if !(200..300).contains(&response.status) { return Err(PublicProtocolPublicationError::ReadbackMismatch); }
    let snapshot = parse_wire_json_bounded(&response.wire, 64, 4 * 1024 * 1024)
        .map_err(|_| PublicProtocolPublicationError::ReadbackMismatch)?;
    if snapshot.get("workspaceId").and_then(WireValue::as_string).as_deref() != Some(workspace_id) {
        return Err(PublicProtocolPublicationError::ReadbackMismatch);
    }
    let rows = snapshot.get("protocols").and_then(as_array)
        .ok_or(PublicProtocolPublicationError::ReadbackMismatch)?;
    let expected_source_digest = normalize_install_protocol_manifest(artifact.root_manifest())
        .map_err(|_| PublicProtocolPublicationError::Invalid)?.1;
    for (index, (digest, _)) in entries.iter().enumerate() {
        let row = rows.iter().find(|row| row.get("digest").and_then(WireValue::as_string).as_deref() == Some(digest))
            .ok_or(PublicProtocolPublicationError::ReadbackMismatch)?;
        if row.get("state").and_then(WireValue::as_string).as_deref() != Some("ACTIVE") {
            return Err(PublicProtocolPublicationError::ReadbackMismatch);
        }
        let expected_source = if index + 1 == entries.len() { &expected_source_digest } else { digest };
        if row.get("sourceDigest").and_then(WireValue::as_string).as_deref() != Some(expected_source) {
            return Err(PublicProtocolPublicationError::ReadbackMismatch);
        }
        if index + 1 == entries.len() {
            let closure = row.get("dependencyClosure").and_then(as_array)
                .ok_or(PublicProtocolPublicationError::ReadbackMismatch)?;
            let expected = artifact.dependencies().iter().map(|item| item.protocol_digest()).collect::<Vec<_>>();
            if closure.len() != expected.len()
                || closure.iter().zip(expected).any(|(actual, expected)| actual.as_string().as_deref() != Some(expected))
            { return Err(PublicProtocolPublicationError::ReadbackMismatch); }
        }
    }
    Ok(())
}

fn step_command_id(operation_id: &str, workspace_id: &str, index: usize) -> String {
    let bytes = format!("peerwork.publication-step.v1\0{operation_id}\0{workspace_id}\0{index}");
    base64url(&sha256(bytes.as_bytes()))
}
fn canonical_wire_equal(left: Option<&WireValue>, right: Option<&WireValue>, path: CanonicalPath) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => match (
            canonical_wire_value(left, path),
            canonical_wire_value(right, path),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        },
        _ => false,
    }
}
fn token(value: &str) -> bool { value.len() == 43 && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) }
fn hex_digest(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) }
fn as_array(value: &WireValue) -> Option<&[WireValue]> { if let WireValue::Array(items) = value { Some(items) } else { None } }
fn text(value: &str) -> WireValue { WireValue::String(value.encode_utf16().collect()) }
fn number(value: u64) -> WireValue { WireValue::Number(value as f64) }
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(fields.into_iter().map(|(name, value)| (name.encode_utf16().collect(), value)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kernel_identity::KernelIdentity,
        transport::{test_drop_next_secure_post_response, TransportConfig},
    };
    use peerwork_core::public_direct_install::compile_public_package_closure_with_bindings;
    use serde::Deserialize;
    use std::path::PathBuf;

    #[test]
    fn saved_manifest_comparison_ignores_object_member_order_after_canonical_reopen() {
        let expected = object(vec![
            ("root", object(vec![("name", text("root")), ("version", text("1"))])),
            ("actions", WireValue::Array(vec![text("read"), text("write")])),
        ]);
        let reopened = object(vec![
            ("actions", WireValue::Array(vec![text("read"), text("write")])),
            ("root", object(vec![("version", text("1")), ("name", text("root"))])),
        ]);
        assert_ne!(expected, reopened, "WireValue preserves input object order");
        assert!(canonical_wire_equal(Some(&reopened), Some(&expected), CanonicalPath::SecureArtifact));
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        schema: String,
        origin: String,
        workspace_id: String,
        initial_workspace_revision: u64,
        operation_id: String,
        owner_actor_id: String,
        owner_key_id: String,
        authority: String,
        owner_pkcs8_pem_path: PathBuf,
        closure_path: PathBuf,
        native_state_dir: PathBuf,
        bindings: serde_json::Value,
    }

    fn fixture() -> Fixture {
        let path = std::env::var_os("PEERWORK_T155_PUBLICATION_FIXTURE")
            .map(PathBuf::from).expect("T155 fixture path is required for ignored HTTP test");
        let bytes = std::fs::read(path).expect("T155 fixture must be readable");
        assert!(bytes.len() <= 64 * 1024);
        serde_json::from_slice(&bytes).expect("T155 fixture schema must match")
    }

    fn identity(fixture: &Fixture) -> KernelIdentity {
        let path = fixture.native_state_dir.join("identity.state");
        if path.exists() {
            KernelIdentity::open(&path).expect("native identity must reopen")
        } else {
            KernelIdentity::import_pkcs8_pem_file(&path, &fixture.owner_pkcs8_pem_path)
                .expect("protected synthetic identity must import")
        }
    }

    fn compilation(fixture: &Fixture) -> PublicPackageCompilation {
        let closure = std::fs::read(&fixture.closure_path).expect("exact package closure must read");
        assert!(closure.len() <= 6 * 1024 * 1024);
        let bindings = serde_json::to_vec(&fixture.bindings).unwrap();
        compile_public_package_closure_with_bindings(&closure, &bindings)
            .expect("PUBLIC package closure and selected fixtures must compile")
    }

    #[tokio::test]
    #[ignore = "requires the opt-in live T155 HTTP fixture"]
    async fn actual_publication_facade_runs_against_shared_http_fixture() {
        let fixture = fixture();
        assert_eq!(fixture.schema, "peerwork.t155.publication-http.v1");
        std::fs::create_dir_all(&fixture.native_state_dir).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fixture.native_state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity = identity(&fixture);
        assert_eq!(identity.actor_id(), fixture.owner_actor_id);
        assert_eq!(identity.key_id(), fixture.owner_key_id);
        let phase = std::env::var("PEERWORK_T155_PUBLICATION_PHASE").unwrap_or_else(|_| "identity_reopen".into());
        if phase == "identity_import" { return; }
        assert!(matches!(phase.as_str(), "identity_reopen" | "submit_lost_response" | "recover_same_operation"));
        if phase == "identity_reopen" { return; }
        let compilation = compilation(&fixture);
        let cancellation = CancellationToken::new();
        let journal_path = fixture.native_state_dir.join("kernel.sqlite");
        let operation_path = fixture.native_state_dir.join("publication.operation.state");
        let open = || KernelClient::open(
            {
                let mut config = TransportConfig::new(fixture.origin.clone());
                config.allow_loopback_http = true;
                config
            },
            &journal_path,
            &[],
            &cancellation,
        );
        let mut client = open().await.unwrap();
        if phase == "submit_lost_response" {
            test_drop_next_secure_post_response();
            let result = publish_public_protocol(
                &mut client, &identity, &fixture.authority, &operation_path, &compilation,
                &fixture.workspace_id, &fixture.operation_id,
                fixture.initial_workspace_revision, &cancellation,
            ).await;
            assert!(matches!(result, Err(PublicProtocolPublicationError::Client(KernelClientError::Transport(crate::transport::TransportError::SubmittedUncertain)))));
            return;
        }
        assert_eq!(phase, "recover_same_operation");
        drop(client);
        let mut client = open().await.unwrap();
        let outcome = publish_public_protocol(
            &mut client, &identity, &fixture.authority, &operation_path, &compilation,
            &fixture.workspace_id, &fixture.operation_id,
            fixture.initial_workspace_revision, &cancellation,
        ).await.expect("same operation resumes exact saved publication steps");
        assert_eq!(outcome.protocol_digest, compilation.protocol_digest());
        assert_eq!(outcome.command_ids.len(), compilation.publication_artifact().dependencies().len() + 1);
        let conflict = publish_public_protocol(
            &mut client, &identity, &fixture.authority, &operation_path, &compilation,
            &fixture.workspace_id, &fixture.operation_id,
            fixture.initial_workspace_revision + 1, &cancellation,
        ).await;
        assert!(matches!(conflict, Err(PublicProtocolPublicationError::OperationConflict)));
    }
}
