use super::*;
use peerwork_core::replayed_secure_journal::{replay_secure_journal_exact, JournalReplayInput};
fn fixture() -> (ReplayedSecureJournal, Value) {
    let f: Value = serde_json::from_str(include_str!(
        "../../../../conformance/signed-many-action-vectors.json"
    ))
    .unwrap();
    let policies: Vec<_> = f["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::to_vec(v).unwrap())
        .collect();
    let commits: Vec<_> = f["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| serde_json::to_vec(v).unwrap())
        .collect();
    let pr: Vec<_> = policies.iter().map(Vec::as_slice).collect();
    let cr: Vec<_> = commits.iter().map(Vec::as_slice).collect();
    let cp = serde_json::to_vec(&f["checkpoint"]).unwrap();
    let keys = serde_json::to_vec(&f["keyring"]).unwrap();
    let replay = replay_secure_journal_exact(JournalReplayInput {
        policy_wires: &pr,
        commit_wires: &cr,
        checkpoint_wire: &cp,
        workspace_id: f["workspace_id"].as_str().unwrap(),
        owner_actor_id: f["owner"]["actor_id"].as_str().unwrap(),
        owner_signing_key: f["owner"]["key"].as_str().unwrap(),
        final_sequence: 2,
        final_head: f["checkpoint"]["head"].as_str(),
        final_policy_hash: f["checkpoint"]["policy_hash"].as_str().unwrap(),
        keyring_wire: Some(&keys),
    })
    .unwrap();
    (replay, f)
}
#[test]
fn authenticated_manifest_join_and_exact_record_reference() {
    let (replay, f) = fixture();
    let policy = f["policies"].as_array().unwrap().last().unwrap();
    let discovery = project(
        &replay,
        policy,
        "not-a-member",
        "not-a-key",
        0,
        false,
        &DiscoveryQuery::default(),
    )
    .unwrap();
    assert_eq!(discovery["checkpoint"]["sequence"], 2);
    assert_eq!(discovery["entry"]["status"], "not_declared");
    let instance = discovery["instances"].as_array().unwrap().first().unwrap();
    let action = instance["actions"].as_array().unwrap().first().unwrap();
    assert_eq!(action["scope_permitted"], false);
    let q: DiscoveryQuery = serde_json::from_value(
        json!({"instance_id":instance["instance_id"],"action_id":action["action_id"]}),
    )
    .unwrap();
    let selected = project(&replay, policy, "not-a-member", "not-a-key", 0, true, &q).unwrap();
    assert_eq!(selected["action"]["id"], action["action_id"]);
    assert_eq!(
        selected["refs"]["protocol_digest"],
        instance["protocol_digest"]
    );
    assert_eq!(selected["authority"]["execution"], "not_evaluated");
    assert!(selected["protocol"]["resolved_manifest"]["actions"].is_array());
    let record = replay
        .objects()
        .iter()
        .find(|o| o.get("kind").and_then(WireValue::as_string).as_deref() == Some("records"))
        .unwrap();
    let revision = number(record.get("value").unwrap(), "revision").unwrap();
    let mut q: DiscoveryQuery = serde_json::from_value(
        json!({"record_id":string(record,"id").unwrap(),"revision":revision}),
    )
    .unwrap();
    let exact = project(&replay, policy, "a", "k", 0, true, &q).unwrap();
    assert_eq!(exact["object"], value(record).unwrap());
    assert_eq!(exact["refs"]["record_revision"], revision);
    q.revision = Some(9_007_199_254_740_991);
    assert_eq!(
        project(&replay, policy, "a", "k", 0, true, &q)
            .unwrap_err()
            .code(),
        "DISCOVERY_NOT_FOUND"
    );
    let q:DiscoveryQuery=serde_json::from_value(json!({"object_ref":{"kind":string(record,"kind").unwrap(),"id":string(record,"id").unwrap(),"revision":number(record,"revision").unwrap()}})).unwrap();
    assert_eq!(
        project(&replay, policy, "a", "k", 0, true, &q).unwrap()["object"],
        value(record).unwrap()
    );
}
#[test]
fn selectors_reject_ambiguity_and_bounds_before_read() {
    for q in [
        json!({"record_id":"r"}),
        json!({"instance_id":"i","record_id":"r","revision":0}),
        json!({"instance_id":"i","limit":1}),
        json!({"action_id":"a"}),
        json!({"object_ref":{"kind":"records","id":"r","revision":9_007_199_254_740_992u64}}),
    ] {
        let q: DiscoveryQuery = serde_json::from_value(q).unwrap();
        assert_eq!(
            validate_query(&q, true).unwrap_err().code(),
            "DISCOVERY_QUERY_INVALID"
        );
    }
    let q: DiscoveryQuery = serde_json::from_value(json!({"limit":129})).unwrap();
    assert!(validate_query(&q, false).is_err());
    assert!(serde_json::from_value::<DiscoveryQuery>(json!({"unknown":true})).is_err());
}
