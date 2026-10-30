//! Native transport and durable state. No network or service mutation runs at import.

pub use peerwork_core::version;
pub use tokio_util::sync::CancellationToken as KernelCancellationToken;

pub mod interrupts;
pub mod protected_config;
pub mod acquisition;
pub mod kernel_access;
pub mod communication_state;
pub(crate) mod communication_host;
mod communication_host_owner;
pub(crate) mod communication_store;
pub mod communication_runtime;
pub mod agent_tools;
pub mod agent_frontend;
mod agent_mcp;
pub mod communication_bridge;
pub(crate) mod communication_local_channel;
pub mod participant;
mod participant_actions;
mod participant_migration;
pub mod participant_transfer;
pub mod participant_dispatch;
mod participant_presence;
mod participant_result;
mod participant_store;
mod participant_inbox;
mod participant_watch;
mod participant_outcome;
pub mod runtime_contract;
pub mod kernel_client;
pub mod public_protocol_publication;
pub mod publication_read;
pub mod kernel_identity;
pub mod kernel_intents;
pub mod public_catalog;
// Prepared secure-packet proof is not public yet; this pending-only module is
// staged internally until the complete core verifier can authorize submits.
pub mod secure_action_access;
#[allow(dead_code)]
mod secure_grant_pending;
pub mod secure_identity_directory;
#[allow(dead_code)]
mod secure_intents;
#[allow(dead_code)]
mod secure_journal_read;
#[allow(dead_code)]
mod secure_lifecycle;
#[allow(dead_code)]
mod secure_native_prepare;
pub mod secure_owner_attach;
pub mod secure_owner_create;
pub mod secure_owner_format_transition;
pub mod secure_owner_coordination;
#[allow(dead_code)]
mod secure_package_pending;
pub mod secure_private_grant_read;
pub mod secure_private_read_access;
pub mod secure_private_install;
pub mod secure_public_admission;
pub mod secure_public_decision;
pub mod secure_public_install;
pub mod secure_read_access;
pub mod secure_read_profile;
pub mod secure_recipient_enrollment;
#[allow(dead_code)]
mod secure_recipient_state;
#[allow(dead_code)]
mod secure_verified_read;
pub use secure_verified_read::SecureJournalReadBudget;
pub mod secure_state;
pub mod transport;
mod ts_migration;
#[cfg(test)]
mod test_support;
#[cfg(windows)]
mod windows_fs;

pub mod agent_context;
pub mod agent_inbox;

pub mod agent_events;

mod agent_operations;

pub mod agent_browser_approval;

pub mod agent_discovery;

pub mod workspace_urls;
pub mod changelog;

pub mod read_view;

pub mod private_read_view;

pub mod current_page;

pub mod owner_guard_time;
pub mod operation_diagnostics;

mod agent_admission;

pub mod protocol_workbench;

pub mod owner_member_scopes;
pub mod owner_checkpoint;
pub mod owner_cache_review;

pub mod owner_cache_checkpoint;

pub mod owner_cache_plan;

pub mod legacy_migration;
