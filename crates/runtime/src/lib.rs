//! Native transport and durable state. No network or service mutation runs at import.

pub use peerwork_core::version;
pub use tokio_util::sync::CancellationToken as KernelCancellationToken;

pub mod kernel_client;
pub mod kernel_access;
pub mod interrupts;
pub mod kernel_identity;
pub mod kernel_intents;
pub mod secure_state;
pub mod transport;
mod ts_migration;
#[cfg(windows)]
mod windows_fs;
