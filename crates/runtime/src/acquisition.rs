//! Explicit local observations. This module never starts network requests or
//! infers principal/controller identity from keys, workspaces or device data.

use crate::secure_state::SecureStateStore;
use peerwork_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
mod proofs;
mod scorecard;
pub use proofs::{ActionObservation, CatalogObservation, InstallObservation};
pub use scorecard::{Metric as AcquisitionMetric, Scorecard, ScorecardRequest};

#[derive(Debug, Error)]
pub enum ObservationError {
    #[error("invalid observation input")]
    Input,
    #[error("observation resource limit exceeded")]
    Resource,
    #[error("protected observation storage unavailable")]
    Storage,
    #[error("observation storage is invalid")]
    Corrupt,
}

impl ObservationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input => "OBSERVATION_INPUT_INVALID",
            Self::Resource => "OBSERVATION_RESOURCE_LIMIT",
            Self::Storage => "OBSERVATION_STORAGE_UNAVAILABLE",
            Self::Corrupt => "OBSERVATION_STATE_INVALID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    Unknown,
    Claimed,
    Checked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub status: Verification,
    pub reference: Option<String>,
}

impl Evidence {
    fn valid(&self) -> bool {
        self.reference.as_deref().is_none_or(opaque_ref)
            && (self.status != Verification::Checked || self.reference.is_some())
    }
    fn checked(&self) -> bool {
        self.status == Verification::Checked && self.reference.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    OfficialSeed,
    OperatorSynthetic,
    ExternalEvidenced,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Production,
    Staging,
    LocalTest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Newness {
    ProvedNew,
    FirstObserved,
    Existing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptClass {
    FirstAttempt,
    Recovery,
    Redundant,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
    Pending,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    QualifiedStart,
    DiscoveryObserved,
    ReleaseVerified,
    AdoptionSelected,
    InstallAccepted,
    TaskOutcomeVerified,
    PublishRequested,
    PublishAccepted,
    ReleaseVisible,
    ShareReferenceObserved,
    AttemptFinished,
    CoverageEnded,
    Correction,
    Withdrawal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionBranch {
    NewInstall,
    ExistingInstall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    McpSearch,
    AgentEntry,
    CanonicalShare,
    RepositoryRelease,
    Direct,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Lost,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    NaturalAgent,
    Scripted,
    Unknown,
}

/// Only public release identifiers and exact byte identities may be stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub catalog_origin: String,
    pub namespace: Option<String>,
    pub package_id: String,
    pub version: String,
    pub bundle_digest: String,
}

impl Release {
    fn valid(&self) -> bool {
        let Ok(origin) = reqwest::Url::parse(&self.catalog_origin) else {
            return false;
        };
        matches!(origin.scheme(), "http" | "https")
            && origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none()
            && token(&self.package_id, 128)
            && token(&self.version, 64)
            && self.namespace.as_deref().is_none_or(|s| token(s, 128))
            && digest(&self.bundle_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredCost {
    pub amount_microunits: u64,
    pub unit: String,
    pub basis_ref: String,
}

/// Epoch milliseconds are UTC. observed_at is assigned at append and cannot
/// be backdated by callers. Opaque refs have a fixed prefix and random/digest
/// suffix, never arbitrary text, URL, path or authenticated identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEvent {
    pub event_id: String,
    pub occurred_at: u64,
    pub environment: Environment,
    pub audience_class: Audience,
    pub principal_ref: Option<String>,
    pub principal_binding: Evidence,
    #[serde(default)]
    pub external_status_evidence: Option<Evidence>,
    pub newness: Newness,
    pub newness_evidence: Evidence,
    pub journey_id: String,
    pub task_ref: Option<String>,
    pub logical_operation_id: String,
    pub attempt_id: String,
    pub event_type: EventType,
    pub outcome: Outcome,
    pub attempt_class: AttemptClass,
    pub evidence: Evidence,
    pub observer: String,
    pub observer_version: String,
    #[serde(default)]
    pub release: Option<Release>,
    #[serde(default)]
    pub protocol_digest: Option<String>,
    #[serde(default)]
    pub protocol_ref: Option<String>,
    #[serde(default)]
    pub instance_ref: Option<String>,
    #[serde(default)]
    pub association_evidence: Option<Evidence>,
    #[serde(default)]
    pub adoption_branch: Option<AdoptionBranch>,
    #[serde(default)]
    pub acceptance_predicate_ref: Option<String>,
    #[serde(default)]
    pub signed_result_evidence: Option<Evidence>,
    #[serde(default)]
    pub enrollment_timing_evidence: Option<Evidence>,
    #[serde(default)]
    pub source_channel: Option<Channel>,
    #[serde(default)]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub source_evidence: Option<Evidence>,
    #[serde(default)]
    pub referrer_principal_ref: Option<String>,
    #[serde(default)]
    pub referrer_audience_class: Option<Audience>,
    #[serde(default)]
    pub referrer_binding: Option<Evidence>,
    #[serde(default)]
    pub referrer_external_status_evidence: Option<Evidence>,
    #[serde(default)]
    pub distinct_controller_evidence: Option<Evidence>,
    #[serde(default)]
    pub publisher_principal_ref: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub client_ref: Option<String>,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub model_ref: Option<String>,
    #[serde(default)]
    pub model_version: Option<String>,
    #[serde(default)]
    pub instruction_ref: Option<String>,
    #[serde(default)]
    pub instruction_version: Option<String>,
    #[serde(default)]
    pub variant_ref: Option<String>,
    #[serde(default)]
    pub source_release: Option<Release>,
    #[serde(default)]
    pub lineage_evidence: Option<Evidence>,
    #[serde(default)]
    pub active_execution_ms: Option<u64>,
    #[serde(default)]
    pub external_wait_ms: Option<u64>,
    #[serde(default)]
    pub calls: Option<u64>,
    #[serde(default)]
    pub tokens: Option<u64>,
    #[serde(default)]
    pub cost: Option<MeasuredCost>,
    #[serde(default)]
    pub observation_end: Option<u64>,
    #[serde(default)]
    pub coverage: Option<Coverage>,
    #[serde(default)]
    pub run_kind: Option<RunKind>,
    #[serde(default)]
    pub workflow_outcome: Option<Outcome>,
    #[serde(default)]
    pub supersedes: Option<String>,
}

fn token(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn opaque_ref(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("obs:") else {
        return false;
    };
    let Some((kind, suffix)) = tail.split_once(':') else {
        return false;
    };
    token(kind, 24)
        && suffix.len() == 32
        && suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
/// Closed schema vocabulary. Unknown SDK/application errors use UNCLASSIFIED;
/// details remain in the separately protected evidence store.
const ERROR_CODES: &[&str] = &[
    "UNCLASSIFIED",
    "CANCELLED",
    "INPUT_INVALID",
    "RESOURCE_LIMIT",
    "STATE_BUSY",
    "LOCAL_STATE",
    "VERIFICATION_FAILED",
    "IDENTITY_MISSING",
    "IDENTITY_CHANGED",
    "SERVER_REJECTED",
    "TRANSPORT_FAILED",
    "RUNTIME_FAILED",
    "RESULT_ENCODING_FAILED",
    "ACTION_INPUT_INVALID",
    "ACTION_PREPARE_FAILED",
    "INTENT_CONFLICT",
    "INTENT_NOT_FOUND",
    "INTENT_PROOF_FAILED",
    "INTENT_STATE",
    "CATALOG_INPUT_INVALID",
    "CATALOG_DIGEST_MISMATCH",
    "CATALOG_INVALID_RESPONSE",
    "CATALOG_RESOURCE_LIMIT",
    "CATALOG_SERVER_REJECTED",
    "CATALOG_TRANSPORT_FAILED",
    "INSTALL_INPUT_INVALID",
    "SOURCE_UNRESOLVED",
    "NOT_FOUND",
    "OBSERVATION_INPUT_INVALID",
    "OBSERVATION_RESOURCE_LIMIT",
    "OBSERVATION_STORAGE_UNAVAILABLE",
    "OBSERVATION_STATE_INVALID",
];

fn clock_ms() -> Result<u64, ObservationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| d.as_millis().try_into().ok())
        .ok_or(ObservationError::Storage)
}

impl ObservationEvent {
    fn validate(&self, observed_at: u64) -> Result<(), ObservationError> {
        let refs = [
            &self.principal_ref,
            &self.task_ref,
            &self.instance_ref,
            &self.acceptance_predicate_ref,
            &self.source_ref,
            &self.referrer_principal_ref,
            &self.publisher_principal_ref,
            &self.supersedes,
            &self.protocol_ref,
            &self.client_ref,
            &self.model_ref,
            &self.instruction_ref,
            &self.variant_ref,
        ];
        let evidences = [
            &self.external_status_evidence,
            &self.association_evidence,
            &self.signed_result_evidence,
            &self.enrollment_timing_evidence,
            &self.distinct_controller_evidence,
            &self.referrer_binding,
            &self.referrer_external_status_evidence,
            &self.source_evidence,
            &self.lineage_evidence,
        ];
        if !opaque_ref(&self.event_id)
            || !opaque_ref(&self.journey_id)
            || !opaque_ref(&self.logical_operation_id)
            || !opaque_ref(&self.attempt_id)
            || refs
                .into_iter()
                .any(|v| v.as_deref().is_some_and(|s| !opaque_ref(s)))
            || !self.principal_binding.valid()
            || !self.newness_evidence.valid()
            || !self.evidence.valid()
            || evidences
                .into_iter()
                .any(|e| e.as_ref().is_some_and(|v| !v.valid()))
            || !token(&self.observer, 64)
            || !token(&self.observer_version, 32)
            || self.occurred_at > observed_at
            || self.release.as_ref().is_some_and(|r| !r.valid())
            || self.source_release.as_ref().is_some_and(|r| !r.valid())
            || [
                &self.client_version,
                &self.model_version,
                &self.instruction_version,
            ]
            .into_iter()
            .any(|v| v.as_deref().is_some_and(|s| !token(s, 32)))
            || self.protocol_digest.as_deref().is_some_and(|s| !digest(s))
            || self
                .error_code
                .as_deref()
                .is_some_and(|s| !ERROR_CODES.contains(&s))
            || self
                .cost
                .as_ref()
                .is_some_and(|c| !token(&c.unit, 16) || !opaque_ref(&c.basis_ref))
            || [
                Some(self.occurred_at),
                Some(observed_at),
                self.active_execution_ms,
                self.external_wait_ms,
                self.calls,
                self.tokens,
                self.observation_end,
                self.cost.as_ref().map(|c| c.amount_microunits),
            ]
            .into_iter()
            .flatten()
            .any(|n| n > MAX_SAFE_INTEGER)
            || self
                .observation_end
                .is_some_and(|end| end < self.occurred_at || end > observed_at)
            || matches!(
                self.event_type,
                EventType::Correction | EventType::Withdrawal
            ) != self.supersedes.is_some()
        {
            return Err(ObservationError::Input);
        }
        if serde_json::to_vec(self)
            .map_err(|_| ObservationError::Input)?
            .len()
            > MAX_RECORD_BYTES
        {
            return Err(ObservationError::Resource);
        }
        Ok(())
    }
    fn external_claims(&self) -> bool {
        self.audience_class == Audience::ExternalEvidenced
            && self.principal_ref.is_some()
            && self.principal_binding.checked()
            && self.evidence.checked()
            && self
                .external_status_evidence
                .as_ref()
                .is_some_and(Evidence::checked)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedObservation {
    pub event: ObservationEvent,
    pub observed_at: u64,
    pub payload_sha256: String,
    #[serde(skip)]
    eligible_external: bool,
    #[serde(skip)]
    eligible_referrer: bool,
}
impl RecordedObservation {
    fn external(&self) -> bool {
        self.eligible_external && self.event.external_claims()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalEvidenceBasis {
    ConsentedControllerGrouping,
    PublicControllerEvidence,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAttestationStatement {
    ObserverCheckedExternalPrincipalBinding,
}
/// A deliberate local observer attestation, not independent controller proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalPrincipalAttestation {
    pub attestation_id: String,
    pub principal_ref: String,
    pub binding_evidence_ref: String,
    pub external_status_evidence_ref: String,
    pub observer: String,
    pub observer_version: String,
    pub statement: ExternalAttestationStatement,
    pub evidence_basis: ExternalEvidenceBasis,
}
impl ExternalPrincipalAttestation {
    fn valid(&self) -> bool {
        [
            &self.attestation_id,
            &self.principal_ref,
            &self.binding_evidence_ref,
            &self.external_status_evidence_ref,
        ]
        .into_iter()
        .all(|s| opaque_ref(s))
            && token(&self.observer, 64)
            && token(&self.observer_version, 32)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedAttestation {
    pub attestation: ExternalPrincipalAttestation,
    pub observed_at: u64,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerState {
    format: u32,
    events: Vec<RecordedObservation>,
    #[serde(default)]
    attestations: Vec<RecordedAttestation>,
    #[serde(default)]
    snapshots: Vec<StoredScorecard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredScorecard {
    pub generated_at: u64,
    pub scorecard: Scorecard,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub max_records: Option<usize>,
    #[serde(default)]
    pub max_store_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppendResult {
    pub event_id: String,
    pub disposition: &'static str,
    pub observed_at: u64,
    pub payload_sha256: String,
    pub records: usize,
}

pub struct AcquisitionObservations {
    config: ObservationConfig,
}

impl AcquisitionObservations {
    pub fn new(config: ObservationConfig) -> Result<Self, ObservationError> {
        if !config.path.is_absolute()
            || config
                .max_records
                .is_some_and(|n| n == 0 || n > MAX_RECORDS)
            || config
                .max_store_bytes
                .is_some_and(|n| n == 0 || n > MAX_STORE_BYTES)
        {
            return Err(ObservationError::Input);
        }
        Ok(Self { config })
    }
    fn read(&self, store: &SecureStateStore) -> Result<LedgerState, ObservationError> {
        let Some(bytes) = store.read_exact().map_err(|_| ObservationError::Storage)? else {
            return Ok(LedgerState {
                format: 1,
                events: Vec::new(),
                attestations: Vec::new(),
                snapshots: Vec::new(),
            });
        };
        if bytes.len() > self.config.max_store_bytes.unwrap_or(MAX_STORE_BYTES) {
            return Err(ObservationError::Resource);
        }
        let state: LedgerState =
            serde_json::from_slice(&bytes).map_err(|_| ObservationError::Corrupt)?;
        if state.format != 1
            || state.events.len() + state.attestations.len()
                > self.config.max_records.unwrap_or(MAX_RECORDS)
            || state.snapshots.len() > 128
        {
            return Err(ObservationError::Corrupt);
        }
        for row in &state.events {
            row.event
                .validate(row.observed_at)
                .map_err(|_| ObservationError::Corrupt)?;
            let payload = serde_json::to_vec(&row.event).map_err(|_| ObservationError::Corrupt)?;
            if sha256_hex(&payload) != row.payload_sha256 {
                return Err(ObservationError::Corrupt);
            }
        }
        for row in &state.attestations {
            if !row.attestation.valid()
                || row.observed_at > MAX_SAFE_INTEGER
                || sha256_hex(
                    &serde_json::to_vec(&row.attestation).map_err(|_| ObservationError::Corrupt)?,
                ) != row.payload_sha256
            {
                return Err(ObservationError::Corrupt);
            }
        }
        for snapshot in &state.snapshots {
            if snapshot.scorecard.window.as_of > snapshot.generated_at {
                return Err(ObservationError::Corrupt);
            }
            let expected = scorecard::compute(
                &state.events,
                &state.attestations,
                &snapshot.scorecard.window,
            )
            .map_err(|_| ObservationError::Corrupt)?;
            if serde_json::to_value(expected).map_err(|_| ObservationError::Corrupt)?
                != serde_json::to_value(&snapshot.scorecard)
                    .map_err(|_| ObservationError::Corrupt)?
            {
                return Err(ObservationError::Corrupt);
            }
        }
        Ok(state)
    }
    pub fn append(&self, event: ObservationEvent) -> Result<AppendResult, ObservationError> {
        self.append_at(event, clock_ms()?)
    }
    fn append_at(
        &self,
        event: ObservationEvent,
        observed_at: u64,
    ) -> Result<AppendResult, ObservationError> {
        event.validate(observed_at)?;
        let store =
            SecureStateStore::open(&self.config.path).map_err(|_| ObservationError::Storage)?;
        let mut state = self.read(&store)?;
        if state
            .events
            .last()
            .is_some_and(|r| r.observed_at > observed_at)
            || state
                .snapshots
                .last()
                .is_some_and(|s| s.generated_at > observed_at)
        {
            return Err(ObservationError::Storage);
        }
        if state
            .attestations
            .last()
            .is_some_and(|s| s.observed_at > observed_at)
        {
            return Err(ObservationError::Storage);
        }
        let hash = sha256_hex(&serde_json::to_vec(&event).map_err(|_| ObservationError::Input)?);
        if let Some(old) = state
            .events
            .iter()
            .find(|r| r.event.event_id == event.event_id && r.payload_sha256 == hash)
        {
            return Ok(AppendResult {
                event_id: event.event_id,
                disposition: "DUPLICATE",
                observed_at: old.observed_at,
                payload_sha256: hash,
                records: state.events.len(),
            });
        }
        let disposition = if state
            .events
            .iter()
            .any(|r| r.event.event_id == event.event_id)
        {
            "CONFLICT"
        } else {
            "APPENDED"
        };
        if state.events.len() + state.attestations.len()
            >= self.config.max_records.unwrap_or(MAX_RECORDS)
        {
            return Err(ObservationError::Resource);
        }
        let row = RecordedObservation {
            event: event.clone(),
            observed_at,
            payload_sha256: hash.clone(),
            eligible_external: false,
            eligible_referrer: false,
        };
        state.events.push(row);
        let wire = serde_json::to_vec(&state).map_err(|_| ObservationError::Corrupt)?;
        if wire.len() > self.config.max_store_bytes.unwrap_or(MAX_STORE_BYTES) {
            return Err(ObservationError::Resource);
        }
        store
            .write_exact(&wire)
            .map_err(|_| ObservationError::Storage)?;
        Ok(AppendResult {
            event_id: event.event_id,
            disposition,
            observed_at,
            payload_sha256: hash,
            records: state.events.len(),
        })
    }
    pub fn attest_external_principal(
        &self,
        input: ExternalPrincipalAttestation,
    ) -> Result<AppendResult, ObservationError> {
        self.attest_at(input, clock_ms()?)
    }
    fn attest_at(
        &self,
        input: ExternalPrincipalAttestation,
        now: u64,
    ) -> Result<AppendResult, ObservationError> {
        if !input.valid() || now > MAX_SAFE_INTEGER {
            return Err(ObservationError::Input);
        }
        let store =
            SecureStateStore::open(&self.config.path).map_err(|_| ObservationError::Storage)?;
        let mut state = self.read(&store)?;
        if state.events.last().is_some_and(|r| r.observed_at > now)
            || state
                .attestations
                .last()
                .is_some_and(|r| r.observed_at > now)
            || state.snapshots.last().is_some_and(|r| r.generated_at > now)
        {
            return Err(ObservationError::Storage);
        }
        let hash = sha256_hex(&serde_json::to_vec(&input).map_err(|_| ObservationError::Input)?);
        if let Some(old) = state.attestations.iter().find(|r| {
            r.attestation.attestation_id == input.attestation_id && r.payload_sha256 == hash
        }) {
            return Ok(AppendResult {
                event_id: input.attestation_id,
                disposition: "DUPLICATE",
                observed_at: old.observed_at,
                payload_sha256: hash,
                records: state.attestations.len(),
            });
        }
        if state.events.len() + state.attestations.len()
            >= self.config.max_records.unwrap_or(MAX_RECORDS)
        {
            return Err(ObservationError::Resource);
        }
        let disposition = if state
            .attestations
            .iter()
            .any(|r| r.attestation.attestation_id == input.attestation_id)
        {
            "CONFLICT"
        } else {
            "APPENDED"
        };
        state.attestations.push(RecordedAttestation {
            attestation: input.clone(),
            observed_at: now,
            payload_sha256: hash.clone(),
        });
        let bytes = serde_json::to_vec(&state).map_err(|_| ObservationError::Corrupt)?;
        if bytes.len() > self.config.max_store_bytes.unwrap_or(MAX_STORE_BYTES) {
            return Err(ObservationError::Resource);
        }
        store
            .write_exact(&bytes)
            .map_err(|_| ObservationError::Storage)?;
        Ok(AppendResult {
            event_id: input.attestation_id,
            disposition,
            observed_at: now,
            payload_sha256: hash,
            records: state.attestations.len(),
        })
    }
    pub fn attestations(&self) -> Result<Vec<RecordedAttestation>, ObservationError> {
        let store =
            SecureStateStore::open(&self.config.path).map_err(|_| ObservationError::Storage)?;
        Ok(self.read(&store)?.attestations)
    }
    pub fn export(&self) -> Result<Vec<RecordedObservation>, ObservationError> {
        let store =
            SecureStateStore::open(&self.config.path).map_err(|_| ObservationError::Storage)?;
        Ok(self.read(&store)?.events)
    }
    pub fn snapshots(&self) -> Result<Vec<StoredScorecard>, ObservationError> {
        let store =
            SecureStateStore::open(&self.config.path).map_err(|_| ObservationError::Storage)?;
        Ok(self.read(&store)?.snapshots)
    }
    pub fn scorecard(
        &self,
        request: ScorecardRequest,
    ) -> Result<StoredScorecard, ObservationError> {
        self.scorecard_at(request, clock_ms()?)
    }
    fn scorecard_at(
        &self,
        request: ScorecardRequest,
        now: u64,
    ) -> Result<StoredScorecard, ObservationError> {
        if request.as_of > now {
            return Err(ObservationError::Input);
        }
        let store =
            SecureStateStore::open(&self.config.path).map_err(|_| ObservationError::Storage)?;
        let mut state = self.read(&store)?;
        if state.events.last().is_some_and(|r| r.observed_at > now)
            || state
                .attestations
                .last()
                .is_some_and(|s| s.observed_at > now)
            || state.snapshots.last().is_some_and(|s| s.generated_at > now)
        {
            return Err(ObservationError::Storage);
        }
        if state
            .attestations
            .last()
            .is_some_and(|s| s.observed_at > now)
        {
            return Err(ObservationError::Storage);
        }
        let result = scorecard::compute(&state.events, &state.attestations, &request)?;
        if let Some(old) = state
            .snapshots
            .iter()
            .find(|s| s.scorecard.snapshot_sha256 == result.snapshot_sha256)
        {
            return Ok(old.clone());
        }
        if state.snapshots.len() >= 128 {
            return Err(ObservationError::Resource);
        }
        let snapshot = StoredScorecard {
            generated_at: now,
            scorecard: result,
        };
        state.snapshots.push(snapshot.clone());
        let wire = serde_json::to_vec(&state).map_err(|_| ObservationError::Corrupt)?;
        if wire.len() > self.config.max_store_bytes.unwrap_or(MAX_STORE_BYTES) {
            return Err(ObservationError::Resource);
        }
        store
            .write_exact(&wire)
            .map_err(|_| ObservationError::Storage)?;
        Ok(snapshot)
    }
}

/// Common bounded envelope used by all public language/CLI entrypoints.
/// Proof input bytes are used transiently and never become ledger fields.
pub fn acquisition_json(operation: &str, config_json: &str, input_json: Option<&str>) -> String {
    fn run(
        operation: &str,
        config_json: &str,
        input: Option<&str>,
    ) -> Result<serde_json::Value, ObservationError> {
        if config_json.len() > 8192 || input.is_some_and(|s| s.len() > 8 * 1024 * 1024) {
            return Err(ObservationError::Resource);
        }
        let config = serde_json::from_str(config_json).map_err(|_| ObservationError::Input)?;
        let ledger = AcquisitionObservations::new(config)?;
        fn parse<T: serde::de::DeserializeOwned>(
            input: Option<&str>,
        ) -> Result<T, ObservationError> {
            serde_json::from_str(input.ok_or(ObservationError::Input)?)
                .map_err(|_| ObservationError::Input)
        }
        let value = match operation {
            "append" => serde_json::to_value(ledger.append(parse(input)?)?),
            "attest_external_principal" => {
                serde_json::to_value(ledger.attest_external_principal(parse(input)?)?)
            }
            "attestations" if input.is_none() => serde_json::to_value(ledger.attestations()?),
            "catalog_result" => serde_json::to_value(ledger.record_catalog_result(parse(input)?)?),
            "install_result" => serde_json::to_value(ledger.record_install_result(parse(input)?)?),
            "action_result" => serde_json::to_value(ledger.record_action_result(parse(input)?)?),
            "scorecard" => serde_json::to_value(ledger.scorecard(parse(input)?)?),
            "export" if input.is_none() => serde_json::to_value(ledger.export()?),
            "snapshots" if input.is_none() => serde_json::to_value(ledger.snapshots()?),
            _ => return Err(ObservationError::Input),
        };
        value.map_err(|_| ObservationError::Corrupt)
    }
    match run(operation, config_json, input_json) {
        Ok(value) => serde_json::json!({"ok":true,"value":value}).to_string(),
        Err(error) => {
            serde_json::json!({"ok":false,"code":error.code(),"message":error.to_string()})
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(kind: &str, number: u64) -> String {
        format!("obs:{kind}:{number:032x}")
    }
    fn event(number: u64) -> ObservationEvent {
        serde_json::from_value(serde_json::json!({
            "event_id":reference("event",number),"occurred_at":100,
            "environment":"local_test","audience_class":"operator_synthetic",
            "principal_ref":reference("principal",1),
            "principal_binding":{"status":"claimed","reference":null},
            "newness":"unknown","newness_evidence":{"status":"unknown","reference":null},
            "journey_id":reference("journey",1),"task_ref":reference("task",1),
            "logical_operation_id":reference("operation",1),"attempt_id":reference("attempt",1),
            "event_type":"qualified_start","outcome":"pending","attempt_class":"first_attempt",
            "evidence":{"status":"claimed","reference":null},
            "observer":"sdk-local-test","observer_version":"1"
        }))
        .unwrap()
    }
    fn ledger() -> (crate::test_support::ProtectedTestDir, AcquisitionObservations) {
        let dir = crate::test_support::protected_test_dir();
        let client = AcquisitionObservations::new(ObservationConfig {
            path: dir.path().join("observations.state"),
            max_records: None,
            max_store_bytes: None,
        })
        .unwrap();
        (dir, client)
    }
    #[test]
    fn strict_allowlist_rejects_raw_fields_and_backdated_arrival() {
        for field in [
            "prompt",
            "task_body",
            "private_key",
            "workspace_id",
            "raw_response",
            "observed_at",
        ] {
            let mut value = serde_json::to_value(event(1)).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!("raw"));
            assert!(
                serde_json::from_value::<ObservationEvent>(value).is_err(),
                "{field}"
            );
        }
        let mut nested = serde_json::to_value(event(1)).unwrap();
        nested["evidence"]["raw_response"] = serde_json::json!("raw");
        assert!(serde_json::from_value::<ObservationEvent>(nested).is_err());
        assert!(event(1).validate(99).is_err());
        let mut unsafe_number = event(1);
        unsafe_number.tokens = Some(MAX_SAFE_INTEGER + 1);
        assert!(unsafe_number.validate(100).is_err());
    }
    #[test]
    fn opaque_references_and_finite_errors_reject_unstructured_text() {
        for bad in [
            "/private/key.pem",
            "https://example.com/secret",
            "A".repeat(43).as_str(),
        ] {
            let mut value = event(1);
            value.task_ref = Some(bad.into());
            assert!(value.validate(100).is_err());
        }
        let mut value = event(1);
        value.error_code = Some("transport failed at secret URL".into());
        assert!(value.validate(100).is_err());
        value.error_code = Some("CATALOG_TRANSPORT_FAILED".into());
        assert!(value.validate(100).is_ok());
        value.error_code = Some("ARBITRARY_SECRET_1234".into());
        assert!(value.validate(100).is_err());
    }
    #[test]
    fn unknown_claims_and_synthetic_keys_never_establish_external_eligibility() {
        let mut value = event(1);
        value.audience_class = Audience::ExternalEvidenced;
        assert!(!value.external_claims());
        value.principal_binding = Evidence {
            status: Verification::Checked,
            reference: Some(reference("evidence", 1)),
        };
        assert!(!value.external_claims());
        value.evidence = Evidence {
            status: Verification::Checked,
            reference: Some(reference("evidence", 2)),
        };
        value.external_status_evidence = Some(checked_evidence(3));
        assert!(value.external_claims());
        value.audience_class = Audience::OperatorSynthetic;
        assert!(!value.external_claims());
        value.audience_class = Audience::OfficialSeed;
        assert!(!value.external_claims());
        value.audience_class = Audience::Unknown;
        assert!(!value.external_claims());
    }
    #[test]
    fn duplicate_conflict_and_reopen_preserve_every_original_observation() {
        let (dir, client) = ledger();
        let original = event(1);
        let first = client.append_at(original.clone(), 100).unwrap();
        assert_eq!(first.disposition, "APPENDED");
        let duplicate = client.append_at(original.clone(), 200).unwrap();
        assert_eq!(duplicate.disposition, "DUPLICATE");
        assert_eq!(duplicate.observed_at, 100);
        let mut different = original.clone();
        different.outcome = Outcome::Fail;
        assert_eq!(
            client.append_at(different, 200).unwrap().disposition,
            "CONFLICT"
        );
        drop(client);
        let fresh = AcquisitionObservations::new(ObservationConfig {
            path: dir.path().join("observations.state"),
            max_records: None,
            max_store_bytes: None,
        })
        .unwrap();
        let rows = fresh.export().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event, original);
        assert_ne!(rows[0].payload_sha256, rows[1].payload_sha256);
    }
    #[test]
    fn bounds_fail_before_storage_and_preserve_existing_record() {
        let (dir, client) = ledger();
        client.append_at(event(1), 100).unwrap();
        let bounded = AcquisitionObservations::new(ObservationConfig {
            path: dir.path().join("observations.state"),
            max_records: Some(1),
            max_store_bytes: None,
        })
        .unwrap();
        assert!(matches!(
            bounded.append_at(event(2), 100),
            Err(ObservationError::Resource)
        ));
        assert_eq!(bounded.export().unwrap().len(), 1);
        let mut bad = event(2);
        bad.observer = "x".repeat(65);
        assert!(matches!(
            bounded.append_at(bad, 100),
            Err(ObservationError::Input)
        ));
        assert_eq!(bounded.export().unwrap().len(), 1);
    }
    fn checked_evidence(number: u64) -> Evidence {
        Evidence {
            status: Verification::Checked,
            reference: Some(reference("evidence", number)),
        }
    }
    fn external(number: u64, at: u64, kind: EventType) -> ObservationEvent {
        let mut value = event(number);
        value.occurred_at = at;
        value.event_type = kind;
        value.audience_class = Audience::ExternalEvidenced;
        value.principal_binding = checked_evidence(1);
        value.evidence = checked_evidence(number);
        value.external_status_evidence = Some(checked_evidence(3));
        value.newness = Newness::ProvedNew;
        value.newness_evidence = checked_evidence(2);
        value.observer = "arithmetic-fixture".into();
        value.acceptance_predicate_ref = Some(reference("predicate", 1));
        value
    }
    fn row(value: ObservationEvent, observed_at: u64) -> RecordedObservation {
        value.validate(observed_at).unwrap();
        RecordedObservation {
            payload_sha256: sha256_hex(&serde_json::to_vec(&value).unwrap()),
            event: value,
            observed_at,
            eligible_external: false,
            eligible_referrer: false,
        }
    }
    fn release() -> Release {
        Release {
            catalog_origin: "https://example.com/".into(),
            namespace: Some("fixture".into()),
            package_id: "fixture-protocol".into(),
            version: "1.0.0".into(),
            bundle_digest: "a".repeat(64),
        }
    }
    fn journey(branch: AdoptionBranch) -> Vec<RecordedObservation> {
        const DAY: u64 = 86_400_000;
        let start = external(1, DAY, EventType::QualifiedStart);
        let mut rows = vec![row(start, DAY)];
        for (id, kind) in [
            (2, EventType::ReleaseVerified),
            (3, EventType::AdoptionSelected),
            (4, EventType::InstallAccepted),
            (5, EventType::TaskOutcomeVerified),
        ] {
            if kind == EventType::InstallAccepted && branch == AdoptionBranch::ExistingInstall {
                continue;
            }
            let mut value = external(id, DAY + id, kind);
            value.outcome = Outcome::Pass;
            value.release = Some(release());
            value.protocol_digest = Some("b".repeat(64));
            value.instance_ref = Some(reference("instance", 1));
            value.association_evidence = Some(checked_evidence(3));
            value.signed_result_evidence = Some(checked_evidence(4));
            if kind == EventType::AdoptionSelected {
                value.adoption_branch = Some(branch)
            }
            rows.push(row(value, DAY + id));
        }
        let mut end = external(6, 36 * DAY, EventType::CoverageEnded);
        end.coverage = Some(Coverage::Complete);
        end.observation_end = Some(36 * DAY);
        rows.push(row(end, 36 * DAY));
        rows
    }
    fn request() -> ScorecardRequest {
        ScorecardRequest {
            from: 0,
            to_exclusive: 2 * 86_400_000,
            as_of: 40 * 86_400_000,
        }
    }
    fn attestation_for(event: &ObservationEvent) -> ExternalPrincipalAttestation {
        ExternalPrincipalAttestation {
            attestation_id: reference("attestation", 1),
            principal_ref: event.principal_ref.clone().unwrap(),
            binding_evidence_ref: event.principal_binding.reference.clone().unwrap(),
            external_status_evidence_ref: event
                .external_status_evidence
                .as_ref()
                .unwrap()
                .reference
                .clone()
                .unwrap(),
            observer: event.observer.clone(),
            observer_version: event.observer_version.clone(),
            statement: ExternalAttestationStatement::ObserverCheckedExternalPrincipalBinding,
            evidence_basis: ExternalEvidenceBasis::ConsentedControllerGrouping,
        }
    }
    fn fixture_compute(
        rows: &[RecordedObservation],
        req: &ScorecardRequest,
    ) -> Result<Scorecard, ObservationError> {
        let mut attestations = Vec::new();
        let mut keys = std::collections::BTreeSet::new();
        for row in rows.iter().filter(|r| r.event.external_claims()) {
            let mut attestation = attestation_for(&row.event);
            let key = serde_json::to_string(&attestation).unwrap();
            if keys.insert(key) {
                attestation.attestation_id =
                    reference("attestation", attestations.len() as u64 + 1);
                attestations.push(RecordedAttestation {
                    payload_sha256: sha256_hex(&serde_json::to_vec(&attestation).unwrap()),
                    attestation,
                    observed_at: 0,
                });
            }
        }
        for row in rows.iter().filter(|r| {
            r.event
                .referrer_external_status_evidence
                .as_ref()
                .is_some_and(Evidence::checked)
        }) {
            let mut event = row.event.clone();
            event.principal_ref = event.referrer_principal_ref.clone();
            event.principal_binding = event.referrer_binding.clone().unwrap();
            event.external_status_evidence = event.referrer_external_status_evidence.clone();
            let mut attestation = attestation_for(&event);
            let key = serde_json::to_string(&attestation).unwrap();
            if keys.insert(key) {
                attestation.attestation_id =
                    reference("attestation", attestations.len() as u64 + 1);
                attestations.push(RecordedAttestation {
                    payload_sha256: sha256_hex(&serde_json::to_vec(&attestation).unwrap()),
                    attestation,
                    observed_at: 0,
                });
            }
        }
        scorecard::compute(rows, &attestations, req)
    }
    fn metric<'a>(score: &'a Scorecard, id: &str) -> &'a AcquisitionMetric {
        score.metrics.iter().find(|m| m.id == id).unwrap()
    }
    #[test]
    fn new_and_existing_selection_need_exact_release_and_signed_result_join() {
        for branch in [AdoptionBranch::NewInstall, AdoptionBranch::ExistingInstall] {
            let rows = journey(branch);
            let score = fixture_compute(&rows, &request()).unwrap();
            assert_eq!(metric(&score, "ACQ-01").numerator, Some(1));
            assert_eq!(metric(&score, "ACQ-02").value, Some(serde_json::json!(1.0)));
            assert_eq!(metric(&score, "ACQ-03").details["deliberate_selection"], 1);
            let mut wrong = rows.clone();
            let result = wrong
                .iter_mut()
                .find(|r| r.event.event_type == EventType::TaskOutcomeVerified)
                .unwrap();
            result.event.release.as_mut().unwrap().bundle_digest = "c".repeat(64);
            assert_eq!(
                metric(&fixture_compute(&wrong, &request()).unwrap(), "ACQ-01").numerator,
                Some(0)
            );
        }
        let mut rows = journey(AdoptionBranch::NewInstall);
        rows.retain(|r| r.event.event_type != EventType::InstallAccepted);
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-03").details["deliberate_selection"], 1);
        assert_eq!(metric(&score, "ACQ-01").numerator, Some(0));
    }
    #[test]
    fn retrospectively_backdated_start_cannot_manufacture_enrollment() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        rows[0].observed_at = rows[0].event.occurred_at + 20;
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-01").numerator,
            Some(0)
        );
        rows[0].event.enrollment_timing_evidence = Some(Evidence {
            status: Verification::Claimed,
            reference: Some(reference("timing", 1)),
        });
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-01").numerator,
            Some(0)
        );
        rows[0].event.enrollment_timing_evidence = Some(checked_evidence(8));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-01").numerator,
            Some(1)
        );
    }
    #[test]
    fn maturity_loss_unknown_cost_and_synthetic_exclusion_remain_visible() {
        let rows = journey(AdoptionBranch::ExistingInstall);
        let mut early = request();
        early.as_of = 2 * 86_400_000 - 1;
        let score = fixture_compute(&rows, &early).unwrap();
        assert_eq!(metric(&score, "ACQ-02-24H").pending, 1);
        assert_eq!(metric(&score, "ACQ-02-24H").value, None);
        let score = fixture_compute(&rows, &request()).unwrap();
        assert!(
            metric(&score, "ACQ-04").value.as_ref().unwrap()["cost_microunits_per_activation"]
                .is_null()
        );
        let mut lost = rows.clone();
        lost.last_mut().unwrap().event.coverage = Some(Coverage::Lost);
        let score = fixture_compute(&lost, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-02").lost, 1);
        assert_eq!(metric(&score, "ACQ-02").value, None);
        assert_eq!(
            metric(&score, "ACQ-02").details["conservative_observed_success_rate"],
            1.0
        );
        let mut synthetic = rows.clone();
        for r in &mut synthetic {
            r.event.audience_class = Audience::OperatorSynthetic;
        }
        let score = fixture_compute(&synthetic, &request()).unwrap();
        assert_eq!(score.excluded_synthetic_seed, synthetic.len());
        assert_eq!(metric(&score, "ACQ-01").value, None);
        assert_eq!(metric(&score, "ACQ-08").value, None);
    }
    #[test]
    fn conflicting_event_and_principal_quarantine_instead_of_counting() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let mut conflict = rows[0].clone();
        conflict.event.outcome = Outcome::Fail;
        conflict.payload_sha256 = sha256_hex(&serde_json::to_vec(&conflict.event).unwrap());
        rows.push(conflict);
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(score.conflicting_events, 1);
        assert_eq!(metric(&score, "ACQ-01").value, None);
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        rows[2].event.principal_ref = Some(reference("principal", 9));
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(score.conflicting_events, 1);
        assert_eq!(metric(&score, "ACQ-01").numerator, Some(0));
    }
    #[test]
    fn as_of_snapshots_exclude_later_arrival_and_preserve_prior_bytes() {
        let (_dir, client) = ledger();
        let original = external(1, 100, EventType::QualifiedStart);
        client.append_at(original, 100).unwrap();
        let req = ScorecardRequest {
            from: 0,
            to_exclusive: 200,
            as_of: 200,
        };
        let old = client.scorecard_at(req.clone(), 200).unwrap();
        let mut late = external(2, 110, EventType::DiscoveryObserved);
        late.outcome = Outcome::Pass;
        client.append_at(late, 300).unwrap();
        let same = client.scorecard_at(req, 300).unwrap();
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::to_value(&same).unwrap()
        );
        let newer = client
            .scorecard_at(
                ScorecardRequest {
                    from: 0,
                    to_exclusive: 200,
                    as_of: 300,
                },
                300,
            )
            .unwrap();
        assert_eq!(old.scorecard.visible_observations, 1);
        assert_eq!(newer.scorecard.visible_observations, 2);
        assert_eq!(client.snapshots().unwrap().len(), 2);
        assert!(matches!(
            client.scorecard_at(
                ScorecardRequest {
                    from: 0,
                    to_exclusive: 400,
                    as_of: 400
                },
                300
            ),
            Err(ObservationError::Input)
        ));
    }
    #[test]
    fn complete_cost_includes_failed_recovery_attempt_and_missing_cost_is_null() {
        const DAY: u64 = 86_400_000;
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        for (id, attempt, outcome, cost) in [(7, 1, Outcome::Pass, 2), (8, 2, Outcome::Fail, 3)] {
            let mut value = external(id, DAY + 20, EventType::AttemptFinished);
            value.attempt_id = reference("attempt", attempt);
            value.outcome = outcome;
            value.cost = Some(MeasuredCost {
                amount_microunits: cost,
                unit: "USD".into(),
                basis_ref: reference("cost", id),
            });
            value.active_execution_ms = Some(10);
            value.external_wait_ms = Some(5);
            value.calls = Some(2);
            value.tokens = Some(20);
            rows.push(row(value, DAY + 20));
        }
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(
            metric(&score, "ACQ-04").value.as_ref().unwrap()["cost_microunits_per_activation"],
            5.0
        );
        assert_eq!(metric(&score, "ACQ-04").details["active_execution_ms"], 20);
        rows.last_mut().unwrap().event.cost = None;
        let score = fixture_compute(&rows, &request()).unwrap();
        assert!(
            metric(&score, "ACQ-04").value.as_ref().unwrap()["cost_microunits_per_activation"]
                .is_null()
        );
    }
    #[test]
    fn retention_requires_distinct_task_and_acceptance_not_retry_ids() {
        const DAY: u64 = 86_400_000;
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let mut second = journey(AdoptionBranch::ExistingInstall);
        for (index, r) in second.iter_mut().enumerate() {
            r.event.event_id = reference("event", 100 + index as u64);
            r.event.journey_id = reference("journey", 2);
            r.event.logical_operation_id = reference("operation", 2);
            if r.event.event_type != EventType::CoverageEnded {
                r.event.occurred_at += 8 * DAY;
                r.observed_at += 8 * DAY;
            }
            r.payload_sha256 = sha256_hex(&serde_json::to_vec(&r.event).unwrap());
        }
        rows.extend(second.clone());
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-05").numerator, Some(0));
        rows.truncate(journey(AdoptionBranch::ExistingInstall).len());
        for r in &mut second {
            r.event.task_ref = Some(reference("task", 2));
            r.event.acceptance_predicate_ref = Some(reference("predicate", 2));
            r.payload_sha256 = sha256_hex(&serde_json::to_vec(&r.event).unwrap());
        }
        rows.extend(second);
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-05").numerator, Some(1));
        assert_eq!(metric(&score, "ACQ-01").numerator, Some(1));
    }
    #[test]
    fn publication_requires_both_receipt_and_exact_visibility() {
        const DAY: u64 = 86_400_000;
        let mut rows = Vec::new();
        for (id, kind) in [
            (1, EventType::PublishRequested),
            (2, EventType::PublishAccepted),
            (3, EventType::ReleaseVisible),
        ] {
            let mut value = external(id, DAY + id, kind);
            value.release = Some(release());
            value.outcome = Outcome::Pass;
            value.signed_result_evidence = Some(checked_evidence(9));
            rows.push(row(value, DAY + id));
        }
        let mut end = external(4, 3 * DAY, EventType::CoverageEnded);
        end.coverage = Some(Coverage::Complete);
        end.observation_end = Some(3 * DAY);
        rows.push(row(end, 3 * DAY));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-06").value,
            Some(serde_json::json!(1.0))
        );
        rows.retain(|r| r.event.event_type != EventType::ReleaseVisible);
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-06").numerator,
            Some(0)
        );
    }
    #[test]
    fn handoff_denominator_retains_nonstarting_recipient_and_excludes_self() {
        const DAY: u64 = 86_400_000;
        let mut rows = Vec::new();
        for (recipient, journey) in [(1, 1), (2, 2)] {
            let mut handoff = external(recipient, DAY, EventType::ShareReferenceObserved);
            handoff.outcome = Outcome::Pass;
            handoff.principal_ref = Some(reference("principal", recipient));
            handoff.journey_id = reference("journey", journey);
            handoff.source_ref = Some(reference("share", recipient));
            handoff.release = Some(release());
            handoff.referrer_principal_ref = Some(reference("principal", 9));
            handoff.referrer_audience_class = Some(Audience::ExternalEvidenced);
            handoff.referrer_binding = Some(checked_evidence(10));
            handoff.referrer_external_status_evidence = Some(checked_evidence(3));
            handoff.distinct_controller_evidence = Some(checked_evidence(11));
            rows.push(row(handoff, DAY));
            let mut end = external(10 + recipient, 16 * DAY, EventType::CoverageEnded);
            end.principal_ref = Some(reference("principal", recipient));
            end.journey_id = reference("journey", journey);
            end.coverage = Some(Coverage::Complete);
            end.observation_end = Some(16 * DAY);
            rows.push(row(end, 16 * DAY));
        }
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-07").denominator, Some(2));
        assert_eq!(metric(&score, "ACQ-07").numerator, Some(0));
        let mut consumer = journey(AdoptionBranch::ExistingInstall);
        for (index, r) in consumer.iter_mut().enumerate() {
            r.event.event_id = reference("event", 100 + index as u64);
        }
        consumer[0].event.source_channel = Some(Channel::CanonicalShare);
        consumer[0].event.source_ref = Some(reference("share", 1));
        consumer[0].event.source_evidence = Some(checked_evidence(12));
        rows.extend(consumer.clone());
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-07").numerator, Some(1));
        assert_eq!(metric(&score, "ACQ-07").value, Some(serde_json::json!(0.5)));
        let mut earlier = external(200, DAY - 1, EventType::DiscoveryObserved);
        earlier.outcome = Outcome::Pass;
        earlier.source_channel = Some(Channel::Direct);
        earlier.source_ref = Some(reference("source", 2));
        earlier.source_evidence = Some(checked_evidence(13));
        rows.push(row(earlier, DAY - 1));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-07").numerator,
            Some(0)
        );
        rows[0].event.referrer_principal_ref = rows[0].event.principal_ref.clone();
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-07").denominator, Some(1));
    }
    #[test]
    fn exact_source_adapters_reject_mismatch_and_never_upgrade_claimed_identity() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let package = peerwork_core::crypto::decode_base64url(
            vector["canonical_package_base64"].as_str().unwrap(),
        )
        .unwrap();
        let bundle_digest = vector["package_digest"].as_str().unwrap().to_owned();
        let inspected = peerwork_core::public_catalog_package::inspect_public_catalog_package(
            &package,
            &bundle_digest,
        )
        .unwrap();
        let summary: serde_json::Value =
            serde_json::from_str(&inspected.summary_canonical_json).unwrap();
        let release = Release {
            catalog_origin: "https://example.com/".into(),
            namespace: None,
            package_id: summary["metadata"]["package_id"].as_str().unwrap().into(),
            version: summary["metadata"]["version"].as_str().unwrap().into(),
            bundle_digest: bundle_digest.clone(),
        };
        let (_dir, client) = ledger();
        let mut catalog = event(1);
        catalog.event_type = EventType::ReleaseVerified;
        catalog.outcome = Outcome::Pass;
        catalog.audience_class = Audience::ExternalEvidenced;
        catalog.release = Some(release.clone());
        client
            .record_catalog_result(CatalogObservation {
                event: catalog,
                catalog_origin: release.catalog_origin.clone(),
                bundle_digest: bundle_digest.clone(),
                bundle_canonical_json: inspected.bundle_canonical_json,
            })
            .unwrap();
        assert!(!client.export().unwrap()[0].external());
        let protocol = vector["protocol_digest"].as_str().unwrap().to_owned();
        let mut selected = event(2);
        selected.event_type = EventType::AdoptionSelected;
        selected.outcome = Outcome::Pass;
        selected.release = Some(release.clone());
        selected.protocol_digest = Some(protocol.clone());
        selected.instance_ref = Some(reference("instance", 1));
        selected.adoption_branch = Some(AdoptionBranch::ExistingInstall);
        let input =
            |event: ObservationEvent, expected_protocol_digest: String| InstallObservation {
                event,
                closure_json: vector["closure"].to_string(),
                bindings_json: None,
                expected_package_id: release.package_id.clone(),
                expected_package_version: release.version.clone(),
                expected_package_digest: bundle_digest.clone(),
                expected_protocol_digest,
                selected_instance_id: "z".repeat(43),
                result_package_digest: None,
                result_protocol_digest: protocol.clone(),
                result_instance_id: "z".repeat(43),
                result_status: "ACTIVE".into(),
                result_step_action_id: None,
                result_commit_hash: None,
            };
        assert!(matches!(
            client.record_install_result(input(selected.clone(), "f".repeat(64))),
            Err(ObservationError::Input)
        ));
        assert_eq!(client.export().unwrap().len(), 1);
        client
            .record_install_result(input(selected, protocol.clone()))
            .unwrap();
        let exported = serde_json::to_string(&client.export().unwrap()).unwrap();
        assert!(
            !exported.contains("release.lock.json")
                && !exported.contains("closure_json")
                && !exported.contains(&"z".repeat(43))
        );
    }
    #[test]
    fn private_unpublished_protocol_can_activate_with_opaque_exact_proof() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        for r in &mut rows {
            if r.event.release.is_some() {
                r.event.release = None;
                r.event.protocol_ref = Some(reference("protocol", 1));
            }
        }
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-01").numerator, Some(1));
        assert_eq!(metric(&score, "ACQ-06").denominator, Some(0));
        rows.iter_mut()
            .find(|r| r.event.event_type == EventType::TaskOutcomeVerified)
            .unwrap()
            .event
            .protocol_ref = Some(reference("protocol", 2));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-01").numerator,
            Some(0)
        );
    }
    #[test]
    fn supply_requires_evidenced_publisher_and_different_controller_use() {
        const DAY: u64 = 86_400_000;
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let result = rows
            .iter_mut()
            .find(|r| r.event.event_type == EventType::TaskOutcomeVerified)
            .unwrap();
        result.event.publisher_principal_ref = Some(reference("principal", 9));
        result.event.distinct_controller_evidence = Some(checked_evidence(9));
        for (id, kind) in [
            (20, EventType::PublishAccepted),
            (21, EventType::ReleaseVisible),
        ] {
            let mut value = external(id, DAY - 1, kind);
            value.principal_ref = Some(reference("principal", 9));
            value.journey_id = reference("journey", 9);
            value.release = Some(release());
            value.outcome = Outcome::Pass;
            value.signed_result_evidence = Some(checked_evidence(id));
            rows.push(row(value, DAY - 1));
        }
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-08").numerator,
            Some(1)
        );
        rows.iter_mut()
            .find(|r| r.event.event_type == EventType::TaskOutcomeVerified)
            .unwrap()
            .event
            .publisher_principal_ref = Some(reference("principal", 1));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-08").numerator,
            Some(0)
        );
    }
    #[test]
    fn agent_workflow_and_business_are_separate_first_attempt_and_recovery() {
        const DAY: u64 = 86_400_000;
        let mut rows = Vec::new();
        for (id, class, business, workflow) in [
            (
                1,
                AttemptClass::FirstAttempt,
                Outcome::Fail,
                Outcome::Unverified,
            ),
            (2, AttemptClass::Recovery, Outcome::Pass, Outcome::Pass),
        ] {
            let mut value = external(id, DAY + id, EventType::AttemptFinished);
            value.attempt_id = reference("attempt", id);
            value.attempt_class = class;
            value.outcome = business;
            value.workflow_outcome = Some(workflow);
            value.run_kind = Some(RunKind::NaturalAgent);
            value.enrollment_timing_evidence = Some(checked_evidence(30));
            rows.push(row(value, DAY + id));
        }
        let score = fixture_compute(&rows, &request()).unwrap();
        let value = metric(&score, "ACQ-09").value.as_ref().unwrap();
        assert_eq!(value["first_attempt"]["business_fail"], 1);
        assert_eq!(value["first_attempt"]["workflow_unverified"], 1);
        assert_eq!(value["recovery"]["business_pass"], 1);
        for r in &mut rows {
            r.event.audience_class = Audience::OperatorSynthetic;
        }
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-09").value,
            None
        );
    }
    #[test]
    fn bounded_common_dispatch_and_checked_withdrawal_preserve_prior_observations() {
        let (dir, client) = ledger();
        let config = serde_json::json!({"path":dir.path().join("observations.state")}).to_string();
        for (op, input) in [
            ("export", Some("{}")),
            ("network_upload", None),
            ("append", Some("{\"raw_response\":true}")),
        ] {
            let value: serde_json::Value =
                serde_json::from_str(&acquisition_json(op, &config, input)).unwrap();
            assert_eq!(value["code"], "OBSERVATION_INPUT_INVALID");
        }
        assert!(client.export().unwrap().is_empty());
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let mut withdraw = external(200, 37 * 86_400_000, EventType::Withdrawal);
        withdraw.supersedes = Some(rows[0].event.event_id.clone());
        withdraw.evidence.status = Verification::Claimed;
        rows.push(row(withdraw.clone(), 37 * 86_400_000));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-01").numerator,
            Some(1)
        );
        withdraw.evidence = checked_evidence(200);
        rows.pop();
        rows.push(row(withdraw, 37 * 86_400_000));
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-01").numerator,
            Some(0)
        );
        assert_eq!(rows[0].event.event_type, EventType::QualifiedStart);
    }
    #[test]
    fn weekly_interval_and_derivative_use_require_explicit_checked_lineage() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-01").value, None);
        assert_eq!(
            metric(&score, "ACQ-01").details["provisional_interval"],
            true
        );
        const DAY: u64 = 86_400_000;
        for row in &mut rows {
            row.event.occurred_at += 4 * DAY;
            row.observed_at += 4 * DAY;
        }
        let week = ScorecardRequest {
            from: 4 * DAY,
            to_exclusive: 11 * DAY,
            as_of: 45 * DAY,
        };
        assert_eq!(
            metric(&fixture_compute(&rows, &week).unwrap(), "ACQ-01").value,
            Some(serde_json::json!(1))
        );
        let original = release();
        for row in &mut rows {
            if let Some(release) = &mut row.event.release {
                release.package_id = "derivative".into();
                release.bundle_digest = "c".repeat(64)
            }
        }
        let result = rows
            .iter_mut()
            .find(|r| r.event.event_type == EventType::TaskOutcomeVerified)
            .unwrap();
        result.event.publisher_principal_ref = Some(reference("principal", 9));
        result.event.distinct_controller_evidence = Some(checked_evidence(9));
        result.event.source_release = Some(original.clone());
        result.event.lineage_evidence = Some(Evidence {
            status: Verification::Claimed,
            reference: Some(reference("lineage", 1)),
        });
        for (id, kind) in [
            (20, EventType::PublishAccepted),
            (21, EventType::ReleaseVisible),
        ] {
            let mut value = external(id, 4 * DAY, kind);
            value.principal_ref = Some(reference("principal", 9));
            value.journey_id = reference("journey", 9);
            value.release = Some(original.clone());
            value.outcome = Outcome::Pass;
            value.signed_result_evidence = Some(checked_evidence(id));
            rows.push(row(value, 4 * DAY));
        }
        assert_eq!(
            metric(&fixture_compute(&rows, &week).unwrap(), "ACQ-08").numerator,
            Some(0)
        );
        rows.iter_mut()
            .find(|r| r.event.event_type == EventType::TaskOutcomeVerified)
            .unwrap()
            .event
            .lineage_evidence = Some(checked_evidence(10));
        assert_eq!(
            metric(&fixture_compute(&rows, &week).unwrap(), "ACQ-08").numerator,
            Some(1)
        );
    }

    #[test]
    fn contradictory_primary_source_and_variant_are_quarantined() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        rows[0].event.source_ref = Some(reference("source", 1));
        rows[0].event.source_channel = Some(Channel::Direct);
        rows[0].event.source_evidence = Some(checked_evidence(9));
        let mut conflict = rows[0].event.clone();
        conflict.event_id = reference("event", 200);
        conflict.event_type = EventType::DiscoveryObserved;
        conflict.source_ref = Some(reference("source", 2));
        rows.push(row(conflict, rows[0].observed_at));
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(score.conflicting_events, 1);
        assert_eq!(metric(&score, "ACQ-01").numerator, Some(0));
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        rows[0].event.variant_ref = Some(reference("variant", 1));
        rows[1].event.variant_ref = Some(reference("variant", 2));
        assert_eq!(
            fixture_compute(&rows, &request())
                .unwrap()
                .conflicting_events,
            1
        );
    }
    #[test]
    fn raw_external_flag_forgery_needs_matching_deliberate_attestation() {
        let rows = journey(AdoptionBranch::ExistingInstall);
        let score = scorecard::compute(&rows, &[], &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-01").numerator, Some(0));
        assert_eq!(score.unknown_audience_binding, rows.len());
        let attestation = attestation_for(&rows[0].event);
        let record = RecordedAttestation {
            payload_sha256: sha256_hex(&serde_json::to_vec(&attestation).unwrap()),
            attestation: attestation.clone(),
            observed_at: 0,
        };
        assert_eq!(
            metric(
                &scorecard::compute(&rows, &[record.clone()], &request()).unwrap(),
                "ACQ-01"
            )
            .numerator,
            Some(1)
        );
        for field in ["binding", "external", "observer", "version", "principal"] {
            let mut wrong = record.clone();
            match field {
                "binding" => wrong.attestation.binding_evidence_ref = reference("evidence", 99),
                "external" => {
                    wrong.attestation.external_status_evidence_ref = reference("evidence", 99)
                }
                "observer" => wrong.attestation.observer = "other-observer".into(),
                "version" => wrong.attestation.observer_version = "other-version".into(),
                _ => wrong.attestation.principal_ref = reference("principal", 99),
            }
            assert_eq!(
                metric(
                    &scorecard::compute(&rows, &[wrong], &request()).unwrap(),
                    "ACQ-01"
                )
                .numerator,
                Some(0),
                "{field}"
            );
        }
        let mut bad = serde_json::to_value(attestation).unwrap();
        bad["statement"] = serde_json::json!("arbitrary truth claim");
        assert!(serde_json::from_value::<ExternalPrincipalAttestation>(bad).is_err());
    }
    #[test]
    fn late_attestation_and_withdrawal_preserve_earlier_as_of_snapshot() {
        const DAY: u64 = 86_400_000;
        let (_dir, client) = ledger();
        let rows = journey(AdoptionBranch::ExistingInstall);
        for row in &rows {
            client
                .append_at(row.event.clone(), row.observed_at)
                .unwrap();
        }
        let old = client.scorecard_at(request(), 40 * DAY).unwrap();
        assert_eq!(metric(&old.scorecard, "ACQ-01").numerator, Some(0));
        let attestation = attestation_for(&rows[0].event);
        client.attest_at(attestation.clone(), 41 * DAY).unwrap();
        assert_eq!(
            serde_json::to_value(client.scorecard_at(request(), 41 * DAY).unwrap()).unwrap(),
            serde_json::to_value(&old).unwrap()
        );
        let mut req = request();
        req.as_of = 41 * DAY;
        assert_eq!(
            metric(
                &client
                    .scorecard_at(req.clone(), 41 * DAY)
                    .unwrap()
                    .scorecard,
                "ACQ-01"
            )
            .numerator,
            Some(1)
        );
        let mut withdrawal = external(200, 42 * DAY, EventType::Withdrawal);
        withdrawal.supersedes = Some(attestation.attestation_id.clone());
        client.append_at(withdrawal, 42 * DAY).unwrap();
        req.as_of = 42 * DAY;
        assert_eq!(
            metric(
                &client.scorecard_at(req, 42 * DAY).unwrap().scorecard,
                "ACQ-01"
            )
            .numerator,
            Some(0)
        );
        assert_eq!(client.attestations().unwrap().len(), 1);
        assert_eq!(
            client
                .snapshots()
                .unwrap()
                .first()
                .unwrap()
                .scorecard
                .snapshot_sha256,
            old.scorecard.snapshot_sha256
        );
    }
    #[test]
    fn a_different_genuine_task_can_reuse_the_same_acceptance_predicate() {
        const DAY: u64 = 86_400_000;
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let mut repeat = journey(AdoptionBranch::ExistingInstall);
        for (index, row) in repeat.iter_mut().enumerate() {
            row.event.event_id = reference("event", 100 + index as u64);
            row.event.journey_id = reference("journey", 2);
            row.event.task_ref = Some(reference("task", 2));
            row.event.occurred_at += 8 * DAY;
            row.observed_at += 8 * DAY;
        }
        rows.extend(repeat);
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-05").numerator,
            Some(1)
        );
    }
    #[test]
    fn logical_retry_journeys_and_publication_retries_collapse_without_losing_attempts() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        let mut retry = journey(AdoptionBranch::ExistingInstall);
        for (index, row) in retry.iter_mut().enumerate() {
            row.event.event_id = reference("event", 100 + index as u64);
            row.event.journey_id = reference("journey", 2);
            row.event.attempt_id = reference("attempt", 2);
        }
        rows.extend(retry);
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-03").denominator,
            Some(1)
        );
        const DAY: u64 = 86_400_000;
        let mut rows = Vec::new();
        for j in 1..=2 {
            for (id, kind) in [
                (1, EventType::PublishRequested),
                (2, EventType::PublishAccepted),
                (3, EventType::ReleaseVisible),
                (4, EventType::CoverageEnded),
            ] {
                let mut value = external(j * 10 + id, DAY + id, kind);
                value.journey_id = reference("journey", j);
                value.release = Some(release());
                value.outcome = Outcome::Pass;
                value.signed_result_evidence = Some(checked_evidence(3));
                if kind == EventType::CoverageEnded {
                    value.coverage = Some(Coverage::Complete);
                    value.occurred_at = 3 * DAY;
                    value.observation_end = Some(3 * DAY);
                }
                rows.push(row(value, 3 * DAY));
            }
        }
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-06").denominator, Some(1));
        assert_eq!(metric(&score, "ACQ-06").numerator, Some(1));
        rows.iter_mut()
            .find(|r| {
                r.event.journey_id == reference("journey", 2)
                    && r.event.event_type == EventType::ReleaseVisible
            })
            .unwrap()
            .event
            .release
            .as_mut()
            .unwrap()
            .bundle_digest = "f".repeat(64);
        assert_eq!(
            metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-06").unknown,
            1
        );
    }
    #[test]
    fn natural_run_without_pre_outcome_enrollment_stays_unknown() {
        let mut value = external(1, 86_400_000, EventType::AttemptFinished);
        value.run_kind = Some(RunKind::NaturalAgent);
        value.outcome = Outcome::Pass;
        value.workflow_outcome = Some(Outcome::Pass);
        let rows = vec![row(value, 86_400_000)];
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-09").value, None);
        assert_eq!(metric(&score, "ACQ-09").unknown, 1);
    }
    #[test]
    fn funnel_branch_breakdowns_use_the_successful_eligible_selection_window() {
        for branch in [AdoptionBranch::ExistingInstall, AdoptionBranch::NewInstall] {
            let key = if branch == AdoptionBranch::NewInstall {
                "new_install_selection"
            } else {
                "existing_install_selection"
            };
            let original = journey(branch);
            assert_eq!(
                metric(&fixture_compute(&original, &request()).unwrap(), "ACQ-03").details[key],
                1
            );
            for disposition in ["fail", "claimed", "late"] {
                let mut rows = original.clone();
                let selected = rows
                    .iter_mut()
                    .find(|r| r.event.event_type == EventType::AdoptionSelected)
                    .unwrap();
                match disposition {
                    "fail" => selected.event.outcome = Outcome::Fail,
                    "claimed" => selected.event.evidence.status = Verification::Claimed,
                    _ => {
                        selected.event.occurred_at += 8 * 86_400_000;
                        selected.observed_at += 8 * 86_400_000;
                    }
                }
                assert_eq!(
                    metric(&fixture_compute(&rows, &request()).unwrap(), "ACQ-03").details[key],
                    0,
                    "{disposition}"
                );
            }
        }
    }
    #[test]
    fn unverified_coverage_cannot_upgrade_a_mature_cohort_denominator() {
        let mut rows = journey(AdoptionBranch::ExistingInstall);
        rows.last_mut().unwrap().event.evidence.status = Verification::Claimed;
        let score = fixture_compute(&rows, &request()).unwrap();
        assert_eq!(metric(&score, "ACQ-02").denominator, Some(0));
        assert_eq!(metric(&score, "ACQ-02").unknown, 1);
    }
}
