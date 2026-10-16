//! Native transport and durable state. No network or service mutation runs at import.

pub use peerwork_core::version;
pub use tokio_util::sync::CancellationToken as KernelCancellationToken;

pub mod interrupts;
pub mod protected_config;
pub mod acquisition;
pub mod kernel_access;
pub mod kernel_client;
pub mod public_protocol_publication;
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
