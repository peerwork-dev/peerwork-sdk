//! Minimized adapters over existing exact package/compiler proof helpers.
//! Input DTOs are caller observations, not authenticated SDK handles. These
//! adapters never upgrade the caller's principal/evidence verification flags.
use super::*;
use peerwork_core::{
    public_catalog_package::inspect_public_catalog_package,
    public_direct_install::compile_public_package_closure_with_bindings,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogObservation {
    pub event: ObservationEvent,
    pub catalog_origin: String,
    pub bundle_digest: String,
    pub bundle_canonical_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallObservation {
    pub event: ObservationEvent,
    pub closure_json: String,
    #[serde(default)]
    pub bindings_json: Option<String>,
    pub expected_package_id: String,
    pub expected_package_version: String,
    pub expected_package_digest: String,
    pub expected_protocol_digest: String,
    pub selected_instance_id: String,
    /// Minimized SDK progress, or signed-read instance selection for an
    /// existing installation; never the whole read/receipt/effects object.
    pub result_package_digest: Option<String>,
    pub result_protocol_digest: String,
    pub result_instance_id: String,
    pub result_status: String,
    pub result_step_action_id: Option<String>,
    pub result_commit_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionObservation {
    pub event: ObservationEvent,
    pub selected_instance_id: String,
    pub result_instance_id: String,
    pub result_status: String,
    pub result_command_id: String,
    pub result_commit_hash: String,
    pub result_sequence: u64,
}

fn instance_id(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl AcquisitionObservations {
    pub fn record_catalog_result(
        &self,
        input: CatalogObservation,
    ) -> Result<AppendResult, ObservationError> {
        if !matches!(
            input.event.event_type,
            EventType::ReleaseVerified | EventType::ReleaseVisible
        ) || input.event.outcome != Outcome::Pass
            || input.bundle_canonical_json.len() > 1024 * 1024
        {
            return Err(ObservationError::Input);
        }
        let release = input
            .event
            .release
            .as_ref()
            .ok_or(ObservationError::Input)?;
        if release.catalog_origin != input.catalog_origin
            || release.bundle_digest != input.bundle_digest
        {
            return Err(ObservationError::Input);
        }
        let inspected = inspect_public_catalog_package(
            input.bundle_canonical_json.as_bytes(),
            &input.bundle_digest,
        )
        .map_err(|_| ObservationError::Input)?;
        let summary: serde_json::Value = serde_json::from_str(&inspected.summary_canonical_json)
            .map_err(|_| ObservationError::Input)?;
        if summary["metadata"]["package_id"].as_str() != Some(release.package_id.as_str())
            || summary["metadata"]["version"].as_str() != Some(release.version.as_str())
        {
            return Err(ObservationError::Input);
        }
        self.append(input.event)
    }
    pub fn record_install_result(
        &self,
        input: InstallObservation,
    ) -> Result<AppendResult, ObservationError> {
        if !matches!(
            input.event.event_type,
            EventType::AdoptionSelected | EventType::InstallAccepted
        ) || input.event.outcome != Outcome::Pass
            || input.closure_json.len() > 6 * 1024 * 1024
            || input
                .bindings_json
                .as_ref()
                .is_some_and(|s| s.len() > 65_536)
            || !instance_id(&input.selected_instance_id)
            || input.selected_instance_id != input.result_instance_id
            || input.event.instance_ref.is_none()
        {
            return Err(ObservationError::Input);
        }
        let compiled = compile_public_package_closure_with_bindings(
            input.closure_json.as_bytes(),
            input.bindings_json.as_deref().unwrap_or("{}").as_bytes(),
        )
        .map_err(|_| ObservationError::Input)?;
        let release = input
            .event
            .release
            .as_ref()
            .ok_or(ObservationError::Input)?;
        if compiled.package_id() != input.expected_package_id
            || compiled.package_version() != input.expected_package_version
            || compiled.package_digest() != input.expected_package_digest
            || compiled.protocol_digest() != input.expected_protocol_digest
            || release.package_id != input.expected_package_id
            || release.version != input.expected_package_version
            || release.bundle_digest != input.expected_package_digest
            || input
                .result_package_digest
                .as_deref()
                .is_some_and(|d| d != input.expected_package_digest)
            || input.result_protocol_digest != input.expected_protocol_digest
            || input.event.protocol_digest.as_deref()
                != Some(input.expected_protocol_digest.as_str())
        {
            return Err(ObservationError::Input);
        }
        if input.event.event_type == EventType::InstallAccepted
            && (input.result_status != "ACCEPTED"
                || input.result_package_digest.as_deref()
                    != Some(input.expected_package_digest.as_str())
                || input.result_step_action_id.as_deref() != Some("secure.structure.end")
                || !input.result_commit_hash.as_deref().is_some_and(digest))
        {
            return Err(ObservationError::Input);
        }
        if input.event.event_type == EventType::AdoptionSelected {
            match input.event.adoption_branch {
                Some(AdoptionBranch::NewInstall) if input.result_status == "SELECTED" => (),
                Some(AdoptionBranch::ExistingInstall) if input.result_status == "ACTIVE" => (),
                _ => return Err(ObservationError::Input),
            }
        }
        // Checked source bytes do not establish publisher/controller identity
        // or authenticate a caller-supplied progress/read DTO.
        self.append(input.event)
    }
    pub fn record_action_result(
        &self,
        input: ActionObservation,
    ) -> Result<AppendResult, ObservationError> {
        if input.event.event_type != EventType::TaskOutcomeVerified
            || input.event.outcome != Outcome::Pass
            || input.event.acceptance_predicate_ref.is_none()
            || input.event.instance_ref.is_none()
            || input.result_status != "ACCEPTED"
            || !instance_id(&input.selected_instance_id)
            || input.selected_instance_id != input.result_instance_id
            || !instance_id(&input.result_command_id)
            || !digest(&input.result_commit_hash)
            || input.result_sequence == 0
            || input.result_sequence > MAX_SAFE_INTEGER
        {
            return Err(ObservationError::Input);
        }
        // The authorized observer retains signed receipt/predicate evidence
        // separately. Neither arbitrary JSON nor an accepted receipt alone
        // establishes useful task acceptance or external adoption.
        self.append(input.event)
    }
}
