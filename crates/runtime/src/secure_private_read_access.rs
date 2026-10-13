//! Profile-scoped PRIVATE direct-grant acquisition. The profile persists
//! explicit first-contact owner pins before any grant can authorize read.

use crate::{
    secure_private_grant_read::{
        SecurePrivateDirectGrantRead, SecurePrivateDirectGrantReadConfig,
        SecurePrivateDirectGrantReadError,
    },
    secure_read_access::SecureReadAccessError,
    secure_read_profile::{SecureReadProfile, SecureReadProfileConfig},
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum SecurePrivateReadError {
    #[error(transparent)]
    Profile(#[from] SecureReadAccessError),
    #[error(transparent)]
    Grant(#[from] SecurePrivateDirectGrantReadError),
}

impl SecurePrivateReadError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Profile(error) => error.code(),
            Self::Grant(error) => error.code(),
        }
    }
}

pub struct SecurePrivateReadAccess {
    config: SecureReadProfileConfig,
}

impl SecurePrivateReadAccess {
    pub fn new(config: SecureReadProfileConfig) -> Self {
        Self { config }
    }

    pub fn activate_and_read_json(&self) -> Result<String, SecurePrivateReadError> {
        self.activate_and_read_json_with_cancel(&CancellationToken::new())
    }

    pub fn activate_and_read_json_with_cancel(
        &self,
        cancel: &CancellationToken,
    ) -> Result<String, SecurePrivateReadError> {
        let profile = SecureReadProfile::new(self.config.clone());
        match profile.read_latest_json_with_cancel(cancel) {
            Ok(value) => return Ok(value),
            Err(SecureReadAccessError::NotActive | SecureReadAccessError::VerificationFailed) => {}
            Err(error) => return Err(error.into()),
        }
        let read = profile.private_grant_read_config()?;
        SecurePrivateDirectGrantRead::new(SecurePrivateDirectGrantReadConfig {
            read,
            recipient_path: self.config.state_dir.join("recipient.state"),
            grant_state_path: self.config.state_dir.join("direct-grant.state"),
        })
        .activate_and_read_json_with_cancel(cancel)?;
        // Save the verified checkpoint floor in the shared read profile so
        // subsequent ordinary latest reads retain rollback/fork protection.
        profile.read_latest_json_with_cancel(cancel).map_err(Into::into)
    }
}
