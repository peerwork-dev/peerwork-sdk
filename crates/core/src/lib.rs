//! Shared Peerwork wire primitives. All high-level capabilities remain experimental
//! until journal replay, authority checks, and durable operation recovery are ported.

pub mod canonical;
pub mod crypto;
pub mod receipt;
pub mod strict_json;

use serde::Serialize;

pub const SDK_VERSION: &str = "0.0.1";
pub fn version() -> &'static str { SDK_VERSION }

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityManifest {
    pub version: &'static str,
    pub status: &'static str,
    pub wire_canonicalization: bool,
    pub signed_artifact_verification: bool,
    pub receipt_verification: bool,
    pub verified_workspace_reads: bool,
    pub safe_actions: bool,
    pub durable_recovery: bool,
}

pub fn capability_manifest() -> CapabilityManifest {
    CapabilityManifest {
        version: SDK_VERSION,
        status: "experimental",
        wire_canonicalization: true,
        signed_artifact_verification: true,
        receipt_verification: true,
        verified_workspace_reads: false,
        safe_actions: false,
        durable_recovery: false,
    }
}
