//! Shared Peerwork wire primitives. All high-level capabilities remain experimental
//! until journal replay, authority checks, and durable operation recovery are ported.

pub mod bootstrap_objects;
pub mod canonical;
pub mod crypto;
pub mod discovery;
pub mod e2ee;
#[allow(dead_code)]
mod full_manifest;
#[allow(dead_code)]
mod interpreter;
#[allow(dead_code)]
mod legacy_protocol_bindings;
mod migration_fragments;
#[allow(dead_code)]
mod package_closure;
#[allow(dead_code)]
mod package_namespace;
#[allow(dead_code)]
mod package_schema;
pub mod prepared_command;
pub mod prepared_secure_author;
pub mod prepared_secure_bootstrap;
pub mod prepared_secure_request;
#[allow(dead_code)]
mod protocol_composition;
#[allow(dead_code)]
mod protocol_object_source;
#[allow(dead_code)]
mod protocol_package_source;
pub mod receipt;
pub mod receipt_wire;
#[allow(dead_code)]
mod secure_chain;
pub mod secure_keyring;
pub mod secure_recipient;
#[allow(dead_code)]
mod secure_replay;
pub mod strict_json;
mod structure_bindings;
mod structure_delta;
#[allow(dead_code)]
mod structure_policy;
pub mod verified_secure_grant;
pub mod wire_json;

use serde::Serialize;

pub const SDK_VERSION: &str = "0.0.1";
pub fn version() -> &'static str {
    SDK_VERSION
}

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
