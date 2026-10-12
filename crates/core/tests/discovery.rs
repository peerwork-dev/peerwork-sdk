use peerwork_core::{crypto::key_id, discovery::parse_discovery_wire};
use serde_json::json;

#[test]
fn discovery_preserves_lossless_audience_and_rejects_strict_unknown_or_duplicate_fields() {
    let key = key_id(&[27; 32]);
    let wire = format!(
        r#"{{"semantics":"peerwork.kernel.v1","audience":"\ud800","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":"{key}","limits":{{"max":1}}}}"#
    );
    let parsed = parse_discovery_wire(wire.as_bytes(), wire.len()).unwrap();
    assert_eq!(parsed.audience_utf16(), [0xd800_u16]);
    assert!(parsed
        .canonical_context()
        .contains(r#""audience":"\ud800""#));
    assert_eq!(parsed.receipt_public_key(), key);
    assert_eq!(parsed.raw_wire(), wire.as_bytes());

    let duplicate = wire.replace(
        r#""audience":"\ud800""#,
        r#""audience":"first","aud\u0069ence":"last""#,
    );
    assert!(parse_discovery_wire(duplicate.as_bytes(), duplicate.len()).is_err());
    let unknown = wire.replace(
        r#""limits":{"max":1}"#,
        r#""limits":{"max":1},"surplus":true"#,
    );
    assert!(parse_discovery_wire(unknown.as_bytes(), unknown.len()).is_err());
    assert!(parse_discovery_wire(wire.as_bytes(), wire.len() - 1).is_err());
}

#[test]
fn persisted_discovery_only_allows_additive_features_and_limits() {
    let key = key_id(&[28; 32]);
    let base = json!({
        "semantics":"peerwork.kernel.v1","audience":"https://workspace.example",
        "command_type":"peerwork.kernel-command.v1+jws",
        "receipt_type":"peerwork.kernel-receipt.v1+jws",
        "receipt_public_key":key,"limits":{"old":1},
        "protocol_features":["alpha"],"manifest_language":"v1"
    });
    let parse = |value: &serde_json::Value| {
        let wire = serde_json::to_vec(value).unwrap();
        parse_discovery_wire(&wire, wire.len()).unwrap()
    };
    let before = parse(&base);
    assert!(before.supports_required_features(&["alpha".encode_utf16().collect()]));
    assert!(!before.supports_required_features(&["beta".encode_utf16().collect()]));
    let mut added = base.clone();
    added["limits"]["new"] = json!(2);
    added["protocol_features"] = json!(["alpha", "beta"]);
    assert!(parse(&added).permits_update_from(&before));
    let mut changed_key = added.clone();
    changed_key["receipt_public_key"] = json!(key_id(&[29; 32]));
    assert!(!parse(&changed_key).permits_update_from(&before));
    let mut changed_limit = added.clone();
    changed_limit["limits"]["old"] = json!(3);
    assert!(!parse(&changed_limit).permits_update_from(&before));
    let mut dropped_feature = added.clone();
    dropped_feature["protocol_features"] = json!(["beta"]);
    assert!(!parse(&dropped_feature).permits_update_from(&before));
    let mut duplicate_feature = added;
    duplicate_feature["protocol_features"] = json!(["alpha", "alpha"]);
    assert!(!parse(&duplicate_feature).permits_update_from(&before));
}
