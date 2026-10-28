//! Shared Peerwork wire primitives. All high-level capabilities remain experimental
//! until journal replay, authority checks, and durable operation recovery are ported.

pub mod bootstrap_objects;
pub mod protocol_bundle;
pub mod member_scopes;
pub mod canonical;
pub mod crypto;
pub mod discovery;
pub mod e2ee;
#[allow(dead_code)]
mod full_manifest;
pub mod genesis_structure_policy;
pub mod guard_time;
#[allow(dead_code)]
mod interpreter;
#[allow(dead_code)]
mod js_locale;
#[allow(dead_code)]
mod legacy_protocol_bindings;
mod migration_fragments;
#[allow(dead_code)]
mod package_closure;
#[allow(dead_code)]
mod package_namespace;
#[allow(dead_code)]
mod package_schema;
#[allow(dead_code)]
mod prepared_package_source;
pub mod prepared_private_install;
pub mod prepared_owner_format;
pub mod prepared_owner_coordination;
pub mod prepared_public_admission;
pub mod prepared_command;
pub mod prepared_secure_action;
pub mod prepared_secure_author;
pub mod prepared_secure_bootstrap;
pub mod prepared_secure_request;
pub mod protocol_simulation;
#[allow(dead_code)]
mod protocol_composition;
#[allow(dead_code)]
mod protocol_object_source;
#[allow(dead_code)]
mod protocol_package_source;
pub mod public_output;
pub mod document_time;
pub mod public_catalog_package;
pub mod public_direct_install;
pub mod private_install_recovery;
pub mod receipt;
pub mod receipt_wire;
pub mod structure_context;
pub mod replayed_secure_journal;
#[allow(dead_code)]
mod secure_chain;
#[allow(dead_code)]
mod secure_action_delegation;
#[allow(dead_code)]
mod secure_action_allocations;
#[allow(dead_code)]
mod secure_action_inputs;
#[allow(dead_code)]
mod secure_action_relations;
pub mod secure_keyring;
pub mod secure_recipient;
pub mod source_provenance;
#[allow(dead_code)]
mod secure_recovery;
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

pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
pub fn version() -> &'static str {
    SDK_VERSION
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityManifest {
    pub backend_structure_execution: bool,
    pub backend_current_state_reads: bool,
    pub protocol_role_bundles: bool,
    pub agent_delivery: bool,
    pub backend_durable_recovery: bool,
    pub owner_self_service_archive_migration: bool,
    pub legacy_online_modes: &'static str,
    pub version: &'static str,
    pub status: &'static str,
    pub protocol_offline_simulation: bool,
    pub protocol_verified_export: bool,
    pub protocol_plan_apply: bool,
    pub guarded_invitation_finalize: bool,
    pub producer_compatibility_report: bool,
    pub workspace_url_generation: bool,
    pub anonymous_changelog_read: bool,
    pub anonymous_publication_read: bool,
    pub public_authorized_state_read: bool,
    pub private_authorized_state_read: bool,
    pub private_system_current_page_read: bool,
    pub owner_guard_time_enable: bool,
    pub owner_member_scopes: bool,
    pub private_install_auto_transport: bool,
    pub private_install_reviewed_recovery: bool,
    pub private_time_add_guard_windows: bool,
    pub wire_canonicalization: bool,
    pub signed_artifact_verification: bool,
    pub receipt_verification: bool,
    pub verified_public_workspace_reads: bool,
    pub verified_workspace_reads: bool,
    pub safe_actions: bool,
    pub durable_recovery: bool,
}

pub fn capability_manifest() -> CapabilityManifest {
    CapabilityManifest {
        backend_structure_execution: true,
        backend_current_state_reads: true,
        protocol_role_bundles: true,
        agent_delivery: true,
        backend_durable_recovery: true,
        owner_self_service_archive_migration: true,
        legacy_online_modes: "RETIRED",
        version: SDK_VERSION,
        status: "experimental",
        protocol_offline_simulation: true,
        protocol_verified_export: false,
        protocol_plan_apply: false,
        guarded_invitation_finalize: false,
        producer_compatibility_report: true,
        workspace_url_generation: true,
        anonymous_changelog_read: true,
        anonymous_publication_read: true,
        public_authorized_state_read: false,
        private_authorized_state_read: false,
        private_system_current_page_read: false,
        owner_guard_time_enable: false,
        owner_member_scopes: false,
        private_install_auto_transport: false,
        private_install_reviewed_recovery: false,
        private_time_add_guard_windows: false,
        wire_canonicalization: true,
        signed_artifact_verification: true,
        receipt_verification: true,
        verified_public_workspace_reads: false,
        verified_workspace_reads: false,
        safe_actions: false,
        durable_recovery: false,
    }
}

pub mod browser_approval;

pub mod read_view;

pub mod selected_author;

pub mod current_page;

pub mod prepared_owner_guard_time;

pub mod structure_execution;
pub mod structure_content;
pub mod structure_access;

pub mod structure_key_delivery;

pub mod structure_retained_keys;
