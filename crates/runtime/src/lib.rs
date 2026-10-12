//! Native transport and durable state. No network or service mutation runs at import.

pub use peerwork_core::version;
pub use tokio_util::sync::CancellationToken as KernelCancellationToken;

pub mod interrupts;
pub mod kernel_access;
pub mod kernel_client;
pub mod kernel_identity;
pub mod kernel_intents;
// Prepared secure-packet proof is not public yet; this pending-only module is
// staged internally until the complete core verifier can authorize submits.
#[allow(dead_code)]
mod secure_intents;
#[allow(dead_code)]
mod secure_lifecycle;
#[allow(dead_code)]
mod secure_recipient_state;
pub mod secure_state;
pub mod transport;
mod ts_migration;
#[cfg(windows)]
mod windows_fs;
