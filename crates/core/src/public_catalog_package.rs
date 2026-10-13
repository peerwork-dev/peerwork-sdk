//! Exact public package inspection. A digest match identifies bytes, not a
//! publisher, endorsement, workspace grant, or install authorization.

use crate::{
    canonical::Path,
    package_closure::{inspect_exact_public_bundle, ClosureError},
    wire_json::canonical_wire_value,
};

#[derive(Debug, PartialEq, Eq)]
pub enum PublicCatalogPackageError {
    Invalid,
    Resource,
    DigestMismatch,
}

pub struct PublicCatalogPackageInspection {
    pub bundle_digest: String,
    pub summary_canonical_json: String,
    pub bundle_canonical_json: String,
}

pub fn inspect_public_catalog_package(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<PublicCatalogPackageInspection, PublicCatalogPackageError> {
    let (bundle, summary) =
        inspect_exact_public_bundle(bytes, expected_digest).map_err(|error| match error {
            ClosureError::Resource => PublicCatalogPackageError::Resource,
            ClosureError::Mismatch => PublicCatalogPackageError::DigestMismatch,
            _ => PublicCatalogPackageError::Invalid,
        })?;
    let summary_canonical_json = canonical_wire_value(&summary, Path::SecureArtifact)
        .map_err(|_| PublicCatalogPackageError::Invalid)?;
    let bundle_canonical_json = canonical_wire_value(&bundle, Path::SecureArtifact)
        .map_err(|_| PublicCatalogPackageError::Invalid)?;
    Ok(PublicCatalogPackageInspection {
        bundle_digest: expected_digest.to_owned(),
        summary_canonical_json,
        bundle_canonical_json,
    })
}
