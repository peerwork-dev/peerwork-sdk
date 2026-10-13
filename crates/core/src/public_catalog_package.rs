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
    let (_, summary) =
        inspect_exact_public_bundle(bytes, expected_digest).map_err(|error| match error {
            ClosureError::Resource => PublicCatalogPackageError::Resource,
            ClosureError::Mismatch => PublicCatalogPackageError::DigestMismatch,
            _ => PublicCatalogPackageError::Invalid,
        })?;
    let summary_canonical_json = canonical_wire_value(&summary, Path::SecureArtifact)
        .map_err(|_| PublicCatalogPackageError::Invalid)?;
    // The exact package bytes were checked against both the package canonical
    // form and expected digest above. Generic wire JSON uses a different object
    // key order, so reserializing would change the bytes this digest names.
    let bundle_canonical_json =
        String::from_utf8(bytes.to_vec()).map_err(|_| PublicCatalogPackageError::Invalid)?;
    Ok(PublicCatalogPackageInspection {
        bundle_digest: expected_digest.to_owned(),
        summary_canonical_json,
        bundle_canonical_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    #[test]
    fn inspected_package_preserves_exact_digest_named_bytes() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/public-package-vectors.json"
        ))
        .unwrap();
        let expected = vector["package_digest"].as_str().unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(vector["canonical_package_base64"].as_str().unwrap())
            .unwrap();
        let inspected = inspect_public_catalog_package(&bytes, expected).unwrap();
        assert_eq!(inspected.bundle_digest, expected);
        assert_eq!(inspected.bundle_canonical_json.as_bytes(), bytes);
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(inspected.bundle_canonical_json.as_bytes())
            ),
            expected
        );
        assert_eq!(
            inspect_public_catalog_package(&bytes, &"0".repeat(64)).err(),
            Some(PublicCatalogPackageError::DigestMismatch)
        );
        let mut tampered = bytes;
        tampered.push(b' ');
        assert_eq!(
            inspect_public_catalog_package(&tampered, expected).err(),
            Some(PublicCatalogPackageError::DigestMismatch)
        );
    }
}
