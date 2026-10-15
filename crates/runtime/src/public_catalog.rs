//! Anonymous public protocol discovery and exact-digest package inspection.
//! Catalog rows are advisory projection data. Exact package inspection proves
//! only byte identity and package schema, not publisher trust or adoption.

use crate::transport::{HttpTransport, TransportConfig, TransportError};
use peerwork_core::{
    canonical::Path,
    public_catalog_package::{inspect_public_catalog_package, PublicCatalogPackageError},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;

// Fifty source-valid metadata rows can each contain long descriptions and
// sixteen maintainer names/origins; JSON escaped UTF-16 can expand them.
const MAX_LIST_BYTES: usize = 8 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCatalogConfig {
    #[serde(default)]
    pub transport: crate::transport::TransportOptions,
    pub origin: String,
    #[serde(default)]
    pub allow_loopback_http: bool,
    /// Optional client resource budget for one advisory search response.
    /// The default is 8 MiB; exact package bytes retain the source 1 MiB cap.
    #[serde(default)]
    pub max_listing_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicCatalogListing {
    pub catalog_origin: String,
    pub listing_canonical_json: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectedPublicPackage {
    pub catalog_origin: String,
    pub bundle_digest: String,
    pub summary_canonical_json: String,
    pub bundle_canonical_json: String,
}

#[derive(Debug, Error)]
pub enum PublicCatalogError {
    #[error("catalog input is invalid")]
    Input,
    #[error("catalog transport failed")]
    Transport,
    #[error("catalog request was cancelled")]
    Cancelled,
    #[error("catalog response exceeded the resource limit")]
    ResourceLimit,
    #[error("catalog server rejected read with HTTP {0}")]
    ServerRejected(u16),
    #[error("catalog response is invalid")]
    InvalidResponse,
    #[error("package bytes do not match the selected digest")]
    DigestMismatch,
}

impl PublicCatalogError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input => "CATALOG_INPUT_INVALID",
            Self::Transport => "CATALOG_TRANSPORT_FAILED",
            Self::Cancelled => "CANCELLED",
            Self::ResourceLimit => "CATALOG_RESOURCE_LIMIT",
            Self::ServerRejected(_) => "CATALOG_SERVER_REJECTED",
            Self::InvalidResponse => "CATALOG_INVALID_RESPONSE",
            Self::DigestMismatch => "CATALOG_DIGEST_MISMATCH",
        }
    }
}

pub struct PublicCatalog {
    config: PublicCatalogConfig,
}

impl PublicCatalog {
    pub fn new(config: PublicCatalogConfig) -> Self {
        Self { config }
    }

    /// Search is anonymous. Its metadata is only a catalog projection; callers
    /// must select a lowercase bundle digest and inspect those exact bytes.
    pub fn search(
        &self,
        query: &str,
        after: Option<&str>,
        limit: u8,
        cancel: &CancellationToken,
    ) -> Result<PublicCatalogListing, PublicCatalogError> {
        if query.encode_utf16().count() > 120
            || !(1..=50).contains(&limit)
            || after.is_some_and(|value| !value.is_empty() && !safe_cursor(value))
        {
            return Err(PublicCatalogError::Input);
        }
        let list_budget = self.config.max_listing_bytes.unwrap_or(MAX_LIST_BYTES);
        if !(1..=64 * 1024 * 1024).contains(&list_budget) {
            return Err(PublicCatalogError::Input);
        }
        let transport = self.transport()?;
        let limit_text = limit.to_string();
        let mut query_pairs = vec![("q", query), ("limit", limit_text.as_str())];
        if let Some(after) = after {
            query_pairs.push(("after", after));
        }
        let response = block_on(transport.get_public_catalog(
            "/api/protocol-catalog/v1/packages",
            &query_pairs,
            list_budget,
            cancel,
        ))?;
        if response.status != 200 {
            return Err(PublicCatalogError::ServerRejected(response.status));
        }
        let wire = parse_wire_json_bounded(&response.wire, 32, list_budget)
            .map_err(|_| PublicCatalogError::InvalidResponse)?;
        validate_listing(&wire, limit)?;
        let listing_canonical_json = canonical_wire_value(&wire, Path::SecureArtifact)
            .map_err(|_| PublicCatalogError::InvalidResponse)?;
        Ok(PublicCatalogListing {
            catalog_origin: transport.trusted_origin().to_owned(),
            listing_canonical_json,
        })
    }

    /// This GET does not need an identity. It validates canonical package
    /// bytes and the selected SHA-256 digest before returning public source.
    pub fn inspect_exact(
        &self,
        digest: &str,
        cancel: &CancellationToken,
    ) -> Result<InspectedPublicPackage, PublicCatalogError> {
        if !lower_digest(digest) {
            return Err(PublicCatalogError::Input);
        }
        let transport = self.transport()?;
        let path = format!("/api/protocol-catalog/v1/packages/by-digest/{digest}");
        let response =
            block_on(transport.get_public_catalog(&path, &[], MAX_BUNDLE_BYTES, cancel))?;
        if response.status != 200 {
            return Err(PublicCatalogError::ServerRejected(response.status));
        }
        let inspected = inspect_public_catalog_package(&response.wire, digest).map_err(
            |error| match error {
                PublicCatalogPackageError::Invalid => PublicCatalogError::InvalidResponse,
                PublicCatalogPackageError::Resource => PublicCatalogError::ResourceLimit,
                PublicCatalogPackageError::DigestMismatch => PublicCatalogError::DigestMismatch,
            },
        )?;
        Ok(InspectedPublicPackage {
            catalog_origin: transport.trusted_origin().to_owned(),
            bundle_digest: inspected.bundle_digest,
            summary_canonical_json: inspected.summary_canonical_json,
            bundle_canonical_json: inspected.bundle_canonical_json,
        })
    }

    fn transport(&self) -> Result<HttpTransport, PublicCatalogError> {
        let mut config = TransportConfig::new(&self.config.origin).with_options(self.config.transport.clone());
        config.timeout = Duration::from_secs(15);
        config.allow_loopback_http = self.config.allow_loopback_http;
        HttpTransport::new(config).map_err(map_transport)
    }
}

fn block_on<
    F: std::future::Future<Output = Result<crate::transport::ExactHttpResponse, TransportError>>,
>(
    future: F,
) -> Result<crate::transport::ExactHttpResponse, PublicCatalogError> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| PublicCatalogError::Transport)?
        .block_on(future)
        .map_err(map_transport)
}

fn map_transport(error: TransportError) -> PublicCatalogError {
    match error {
        TransportError::Cancelled => PublicCatalogError::Cancelled,
        TransportError::ResponseTooLarge => PublicCatalogError::ResourceLimit,
        TransportError::InvalidOrigin | TransportError::InvalidTrust => PublicCatalogError::Input,
        _ => PublicCatalogError::Transport,
    }
}

fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_cursor(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<u64>()
            .is_ok_and(|number| number <= 9_007_199_254_740_991)
}

fn validate_listing(value: &WireValue, limit: u8) -> Result<(), PublicCatalogError> {
    let items = match value.get("items") {
        Some(WireValue::Array(items)) if items.len() <= limit as usize => items,
        _ => return Err(PublicCatalogError::InvalidResponse),
    };
    let next_valid = match value.get("next") {
        Some(WireValue::Null) => true,
        Some(WireValue::String(units)) => {
            String::from_utf16(units).is_ok_and(|value| safe_cursor(&value))
        }
        _ => false,
    };
    if !next_valid
        || !matches!(value.get("watermark"), Some(WireValue::Number(number)) if number.is_finite() && *number >= 0.0 && number.fract() == 0.0 && *number <= 9_007_199_254_740_991.0)
    {
        return Err(PublicCatalogError::InvalidResponse);
    }
    for item in items {
        let digest = item
            .get("bundle_digest")
            .and_then(WireValue::as_string)
            .ok_or(PublicCatalogError::InvalidResponse)?;
        if !lower_digest(&digest) {
            return Err(PublicCatalogError::InvalidResponse);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        path::Path,
        process::{Command, Stdio},
    };

    #[test]
    fn pinned_public_catalog_anonymous_exact_http() {
        if std::env::var_os("PEERWORK_TEST_CATALOG_HTTP").is_none() {
            return;
        }
        let reference = std::env::var("PEERWORK_REFERENCE_ROOT").unwrap();
        let node = std::env::var("PEERWORK_NODE_BIN").unwrap();
        let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let state = tempfile::Builder::new()
            .prefix("catalog-http-")
            .tempdir_in(std::env::var("TMPDIR").unwrap())
            .unwrap();
        let mut child = Command::new(node)
            .arg(sdk.join("tests/reference-catalog-server.mjs"))
            .env("PEERWORK_REFERENCE_ROOT", reference)
            .env("PEERWORK_SDK_ROOT", &sdk)
            .env("PEERWORK_TEST_STATE", state.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert!(
            !ready.is_empty(),
            "pinned public catalog server exited before ready"
        );
        let fixture: serde_json::Value = serde_json::from_str(&ready).unwrap();
        let origin = fixture["origin"].as_str().unwrap().to_owned();
        assert_eq!(fixture["bundles"], 2);
        let catalog = PublicCatalog::new(PublicCatalogConfig {
            transport: Default::default(),
            origin,
            allow_loopback_http: true,
            max_listing_bytes: None,
        });
        let cancel = CancellationToken::new();
        let result = (|| {
            let listed = catalog.search("", None, 50, &cancel)?;
            let initial_cursor = catalog.search("", Some(""), 50, &cancel)?;
            assert_eq!(
                listed.listing_canonical_json,
                initial_cursor.listing_canonical_json
            );
            let constrained = PublicCatalog::new(PublicCatalogConfig {
            transport: Default::default(),
                origin: listed.catalog_origin.clone(),
                allow_loopback_http: true,
                max_listing_bytes: Some(1),
            });
            assert!(matches!(
                constrained.search("", None, 50, &cancel),
                Err(PublicCatalogError::ResourceLimit)
            ));
            let rows: serde_json::Value =
                serde_json::from_str(&listed.listing_canonical_json).unwrap();
            assert_eq!(rows["items"].as_array().unwrap().len(), 2);
            for filename in [
                "public-package-vectors.json",
                "public-package-v2-vectors.json",
            ] {
                let vector: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(sdk.join("conformance").join(filename)).unwrap(),
                )
                .unwrap();
                let digest = vector["package_digest"].as_str().unwrap();
                assert!(rows["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["bundle_digest"] == digest));
                let inspected = catalog.inspect_exact(digest, &cancel)?;
                let summary: serde_json::Value =
                    serde_json::from_str(&inspected.summary_canonical_json).unwrap();
                assert_eq!(summary["bundle_digest"], digest);
                assert_eq!(
                    summary["metadata"]["package_id"],
                    "peerwork-proposal-adoption"
                );
                assert!(inspected
                    .bundle_canonical_json
                    .contains("release.lock.json"));
            }
            let first: serde_json::Value = serde_json::from_slice(
                &std::fs::read(sdk.join("conformance/public-package-vectors.json")).unwrap(),
            )
            .unwrap();
            let digest = first["package_digest"].as_str().unwrap();
            assert!(matches!(
                catalog.inspect_exact(digest, &cancel),
                Err(PublicCatalogError::DigestMismatch)
            ));
            // The fourth response is a different source-valid, canonical
            // package. It isolates selected-digest binding from canonicality.
            assert!(matches!(
                catalog.inspect_exact(digest, &cancel),
                Err(PublicCatalogError::DigestMismatch)
            ));
            assert!(matches!(
                catalog.inspect_exact(&digest.to_uppercase(), &cancel),
                Err(PublicCatalogError::Input)
            ));
            Ok::<(), PublicCatalogError>(())
        })();
        child.kill().ok();
        child.wait().ok();
        result.unwrap();
    }
}
