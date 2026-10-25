use ed25519_dalek::SigningKey;
use peerwork_core::{
    canonical::{canonical, Path},
    crypto::{actor_id, key_id, sha256_hex, sign_compact},
    discovery::parse_discovery_wire,
    prepared_command::prepare_signed_command_wire,
    receipt_wire::{
        verify_http_response_for_prepared, verify_http_response_wire, WireReceiptExpectation,
    },
    structure_execution::PROFILE,
    wire_json::parse_wire_json_bounded,
};
use serde_json::{json, Value};

fn command(signing: &SigningKey, action: &str) -> Value {
    let actor = actor_id(&signing.verifying_key().to_bytes());
    json!({"v":1,"audience":"structure-test","command_id":key_id(&[25;32]),
        "actor_id":actor,"authority":sha256_hex(actor.as_bytes()),"method":"POST",
        "path":"/api/workspace/v1/commands","workspace_id":key_id(&[26;32]),
        "instance_id":key_id(&[27;32]),"protocol_digest":"a".repeat(64),"action_id":action,
        "expected_workspace_revision":null,"expected_instance_revision":null,
        "exact_input_refs":[],"body":{"profile":PROFILE},"issued_at":1,"expires_at":600001})
}

#[test]
fn maintenance_progress_binds_original_author_source_and_keeps_blocked_verification_distinct() {
    let owner = SigningKey::from_bytes(&[21; 32]);
    let reader = SigningKey::from_bytes(&[23; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let service_kid = key_id(&service.verifying_key().to_bytes());
    let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":service_kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&wire, wire.len()).unwrap();
    let mut begin = command(&owner, "structure.maintenance.rebuild");
    begin["expected_instance_revision"] = json!(7);
    begin["body"]["expected_event_revision"] = json!(9);
    begin["body"]["ttl_ms"] = json!(60000);
    let prepare = |v: &Value, key: &SigningKey| {
        prepare_signed_command_wire(
            &parse_wire_json_bounded(&serde_json::to_vec(v).unwrap(), 40, 180_000).unwrap(),
            key,
            &discovery,
            None,
        )
        .unwrap()
    };
    let signed = prepare(&begin, &owner);
    let id = key_id(&[33; 32]);
    let job = json!({"workspace_id":begin["workspace_id"],"instance_id":begin["instance_id"],"job_id":id,"kind":"CURRENT_RECORDS","actor_id":begin["actor_id"],"membership_id":key_id(&[34;32]),"command_id":begin["command_id"],"intent_digest":signed.proof().intent_digest(),"protocol_digest":begin["protocol_digest"],"base_revision":7,"base_event_revision":9,"source_generation":"initial","target_generation":id,"deadline_at":60010,"created_at":10,"state":"BUILDING","status":"ORDERED","phase":"HEADS"});
    let initial = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":begin["workspace_id"],"instance_id":begin["instance_id"],"protocol_digest":begin["protocol_digest"],"status":"ORDERED","maintenance":job,"author_intent":signed.jws()});
    verify_http_response_for_prepared(
        &receipt(&service, &begin, signed.proof().intent_digest(), &initial),
        signed.proof(),
        &service_kid,
    )
    .unwrap();
    let mut query = command(&reader, "structure.maintenance.get");
    query["body"]["job_id"] = json!(id);
    let selected = prepare(&query, &reader);
    let mut result = initial.clone();
    result.as_object_mut().unwrap().remove("author_intent");
    result.as_object_mut().unwrap().remove("status");
    result["maintenance"]["status"] = json!("APPLIED");
    result["maintenance"]["state"] = json!("CLEANUP");
    result["maintenance"]["source"] = json!({"actor_id":begin["actor_id"],"command_id":begin["command_id"],"intent_digest":signed.proof().intent_digest(),"author_intent":signed.jws()});
    let verify = |v: &Value| {
        verify_http_response_for_prepared(
            &receipt(&service, &query, selected.proof().intent_digest(), v),
            selected.proof(),
            &service_kid,
        )
    };
    verify(&result).unwrap();
    for (field, value) in [
        ("job_id", json!(key_id(&[35; 32]))),
        ("base_revision", json!(8)),
        ("base_event_revision", json!(10)),
        ("deadline_at", json!(60011)),
        ("intent_digest", json!("b".repeat(64))),
    ] {
        let mut wrong = result.clone();
        wrong["maintenance"][field] = value;
        assert!(verify(&wrong).is_err(), "{field}");
    }
    let mut absent = result.clone();
    absent["maintenance"]["source"] = Value::Null;
    assert!(verify(&absent).is_err());
    absent["maintenance"]["status"] = json!("VERIFICATION_BLOCKED");
    absent["maintenance"]["state"] = json!("DONE");
    verify(&absent).unwrap();
    absent["maintenance"]["state"] = json!("BLOCKED");
    verify(&absent).unwrap();
    absent["maintenance"]["state"] = json!("BUILDING");
    assert!(verify(&absent).is_err());
    let mut list = command(&reader, "structure.operations.read");
    list["instance_id"] = Value::Null;
    list["protocol_digest"] = Value::Null;
    list["body"] = json!({"profile":PROFILE,"scope":"WORKSPACE","view":"HISTORY"});
    let listing = prepare(&list, &reader);
    let mut item = result["maintenance"].clone();
    let source = item.as_object_mut().unwrap().remove("source").unwrap();
    let key = format!(
        "{}:{}",
        begin["actor_id"].as_str().unwrap(),
        begin["command_id"].as_str().unwrap()
    );
    item["source_key"] = json!(key);
    item["source_verification"] = json!("VERIFIED");
    item["unsettled"] = json!(false);
    let page = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":list["workspace_id"],"operations":[item],"sources":{key.clone():source},"consistency":"LIVE_KEYSET","observer_checkpoint":0,"next_cursor":null});
    let check = |v: &Value| {
        verify_http_response_for_prepared(
            &receipt(&service, &list, listing.proof().intent_digest(), v),
            listing.proof(),
            &service_kid,
        )
    };
    check(&page).unwrap();
    let mut wrong = page.clone();
    wrong["operations"][0]["instance_id"] = json!(key_id(&[36; 32]));
    assert!(check(&wrong).is_err());
    wrong = page.clone();
    wrong["sources"]["unused"] = Value::Null;
    assert!(check(&wrong).is_err());
    let mut mine = list.clone();
    mine["body"]["scope"] = json!("MINE");
    let mine_prepared = prepare(&mine, &reader);
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &mine,
            mine_prepared.proof().intent_digest(),
            &page
        ),
        mine_prepared.proof(),
        &service_kid
    )
    .is_err());
    let mut blocked = page.clone();
    blocked["sources"][&key] = Value::Null;
    blocked["operations"][0]["source_verification"] = json!("BLOCKED");
    blocked["operations"][0]["status"] = json!("VERIFICATION_BLOCKED");
    blocked["operations"][0]["error_code"] = json!("STRUCTURE_MAINTENANCE_SOURCE_INVALID");
    blocked["operations"][0]["recovery"] = json!("INSPECT_SELECTED_OPERATION");
    check(&blocked).unwrap();
    blocked["operations"][0]["status"] = json!("APPLIED");
    assert!(check(&blocked).is_err());
}

#[test]
fn event_sources_distinguish_global_and_workspace_commands_with_the_same_actor_and_id() {
    let owner = SigningKey::from_bytes(&[21; 32]);
    let reader = SigningKey::from_bytes(&[23; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let kid = key_id(&service.verifying_key().to_bytes());
    let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":kid,"limits":{}})).unwrap();
    let discovery = parse_discovery_wire(&wire, wire.len()).unwrap();
    let prepare = |value: &Value, key: &SigningKey| {
        prepare_signed_command_wire(
            &parse_wire_json_bounded(&serde_json::to_vec(value).unwrap(), 40, 180000).unwrap(),
            key,
            &discovery,
            None,
        )
        .unwrap()
    };
    let mut global = command(&owner, "structure.workspace.create");
    global["workspace_id"] = Value::Null;
    global["instance_id"] = Value::Null;
    global["protocol_digest"] = Value::Null;
    global["body"]["name"] = json!("Created workspace");
    let global = prepare(&global, &owner);
    let mut action = command(&owner, "structure.action");
    action["body"] = json!({"profile":PROFILE,"action_id":"advance","structure":{}});
    action["expected_instance_revision"] = json!(1);
    let action = prepare(&action, &owner);
    let mut query = command(&reader, "structure.events.read");
    query["instance_id"] = Value::Null;
    query["protocol_digest"] = Value::Null;
    let selected = prepare(&query, &reader);
    let g = global.proof();
    let a = action.proof();
    assert_eq!(g.command_id(), a.command_id());
    let workspace = query["workspace_id"].as_str().unwrap();
    let global_key =
        sha256_hex(format!(r#"["{}","-","{}"]"#, g.actor_id(), g.command_id()).as_bytes());
    let action_key = sha256_hex(
        format!(
            r#"["{}","{}","{}"]"#,
            a.actor_id(),
            workspace,
            a.command_id()
        )
        .as_bytes(),
    );
    assert_ne!(global_key, action_key);
    let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":workspace,"sources":{
        global_key.clone():{"actor_id":g.actor_id(),"command_id":g.command_id(),"intent_digest":g.intent_digest(),"author_intent":global.jws()},
        action_key.clone():{"actor_id":a.actor_id(),"command_id":a.command_id(),"intent_digest":a.intent_digest(),"author_intent":action.jws()}},
        "events":[{"actor_id":g.actor_id(),"summary":{"action_id":"structure.workspace.create"},"source_key":global_key},{"actor_id":a.actor_id(),"summary":{"action_id":"structure.action"},"source_key":action_key}]});
    verify_http_response_for_prepared(
        &receipt(&service, &query, selected.proof().intent_digest(), &result),
        selected.proof(),
        &kid,
    )
    .unwrap();
}

fn receipt(signing: &SigningKey, command: &Value, intent: &str, result: &Value) -> Vec<u8> {
    let kid = key_id(&signing.verifying_key().to_bytes());
    let payload = json!({"v":1,"audience":"structure-test","actor_id":command["actor_id"],
        "workspace_id":result["workspace_id"],"command_id":command["command_id"],
        "intent_digest":intent,"result_digest":sha256_hex(canonical(result,Path::STRUCTURED).unwrap().as_bytes()),
        "protocol_digest":result["protocol_digest"],"event_sequence":null,"instance_revision":result.get("revision").unwrap_or(&Value::Null),"accepted_at":10});
    let jws = sign_compact(
        &json!({"alg":"EdDSA","typ":"peerwork.kernel-receipt.v1+jws","kid":kid}),
        &payload,
        signing,
    )
    .unwrap();
    serde_json::to_vec(&json!({"command_id":command["command_id"],"receipt":jws,"result":result}))
        .unwrap()
}

#[test]
fn structured_receipt_verifies_deep_programs_without_relaxing_legacy_receipts() {
    let identity = SigningKey::from_bytes(&[21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let service_kid = key_id(&service.verifying_key().to_bytes());
    let discovery_wire = serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test",
        "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
        "receipt_public_key":service_kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&discovery_wire, discovery_wire.len()).unwrap();
    let c = command(&identity, "structure.instance.get");
    let wire = serde_json::to_vec(&c).unwrap();
    let parsed = parse_wire_json_bounded(&wire, 40, 180_000).unwrap();
    let prepared = prepare_signed_command_wire(&parsed, &identity, &discovery, None).unwrap();
    let mut nested = json!({"leaf":"structural rule"});
    for _ in 0..17 {
        nested = json!({"nested":nested});
    }
    let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE",
        "workspace_id":c["workspace_id"],"instance_id":c["instance_id"],
        "protocol_digest":c["protocol_digest"],"revision":7,"manifest":nested});
    let response = receipt(&service, &c, prepared.proof().intent_digest(), &result);
    let verified =
        verify_http_response_for_prepared(&response, prepared.proof(), &service_kid).unwrap();
    assert_eq!(verified.instance_revision(), Some(7));
    assert_eq!(
        verified.result_canonical_json(),
        canonical(&result, Path::STRUCTURED).unwrap()
    );
    let audience: Vec<u16> = "structure-test".encode_utf16().collect();
    let actor = c["actor_id"].as_str().unwrap();
    let command_id = c["command_id"].as_str().unwrap();
    assert!(verify_http_response_wire(
        &response,
        &WireReceiptExpectation {
            audience_utf16: &audience,
            receipt_key_id: &service_kid,
            actor_id: actor,
            command_id,
            intent_digest: prepared.proof().intent_digest(),
            workspace_id: c["workspace_id"].as_str(),
            protocol_digest: c["protocol_digest"].as_str()
        }
    )
    .is_err());
    let mut wrong = result.clone();
    wrong["assurance"] = json!("INDEPENDENT_HISTORY");
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &c, prepared.proof().intent_digest(), &wrong),
        prepared.proof(),
        &service_kid
    )
    .is_err());
    let mut tampered: Value = serde_json::from_slice(&response).unwrap();
    tampered["result"]["revision"] = json!(8);
    assert!(verify_http_response_for_prepared(
        &serde_json::to_vec(&tampered).unwrap(),
        prepared.proof(),
        &service_kid
    )
    .is_err());
    assert!(
        verify_http_response_for_prepared(&response, prepared.proof(), &key_id(&[29; 32])).is_err()
    );
    let mut wrong_source = result.clone();
    wrong_source["workspace_id"] = json!(key_id(&[30; 32]));
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &c,
            prepared.proof().intent_digest(),
            &wrong_source
        ),
        prepared.proof(),
        &service_kid
    )
    .is_err());
}

#[test]
fn protocol_adoption_has_an_explicit_program_budget_while_action_inputs_keep_the_data_budget() {
    let identity = SigningKey::from_bytes(&[21; 32]);
    let kid = key_id(&identity.verifying_key().to_bytes());
    let discovery_wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test",
        "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
        "receipt_public_key":kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&discovery_wire, discovery_wire.len()).unwrap();
    let mut c = command(&identity, "structure.adopt");
    let mut nested = json!(0);
    for _ in 0..17 {
        nested = json!({"program":nested});
    }
    c["body"]["manifest"] = nested;
    let prepare = |value: &Value| {
        let bytes = serde_json::to_vec(value).unwrap();
        let parsed = parse_wire_json_bounded(&bytes, 40, 180_000).unwrap();
        prepare_signed_command_wire(&parsed, &identity, &discovery, None)
    };
    assert!(prepare(&c).is_ok());
    c["body"]["profile"] = json!("unsupported-profile");
    assert!(prepare(&c).is_err());
    c["body"]["profile"] = json!(PROFILE);
    c["action_id"] = json!("structure.action");
    assert!(prepare(&c).is_err());
}

#[test]
fn large_program_adoption_verifies_and_recovers_the_same_business_intent() {
    let identity = SigningKey::from_bytes(&[21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let service_kid = key_id(&service.verifying_key().to_bytes());
    let discovery_wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":service_kid,"limits":{}})).unwrap();
    let discovery = parse_discovery_wire(&discovery_wire, discovery_wire.len()).unwrap();
    let prepare = |value: &Value| {
        prepare_signed_command_wire(
            &parse_wire_json_bounded(&serde_json::to_vec(value).unwrap(), 40, 180_000).unwrap(),
            &identity,
            &discovery,
            None,
        )
        .unwrap()
    };
    let mut c = command(&identity, "structure.adopt");
    c["body"]["manifest"]=json!((0..100).map(|n|(format!("schema{n}"),json!({"fields":{"a":"string","b":"string","c":"string","d":"string","e":"string","f":"string","g":"string","h":"string","i":"string","j":"string","k":"string","l":"string"},"required":["a","b","c","d","e","f","g","h","i","j","k","l"]}))).collect::<serde_json::Map<_,_>>());
    let original = prepare(&c);
    assert!(original.proof().structure_business_intent().is_some());
    let mut renewed = c.clone();
    renewed["issued_at"] = json!(700001);
    renewed["expires_at"] = json!(1300001);
    let prepared = prepare(&renewed);
    assert_eq!(
        original.proof().structure_business_intent(),
        prepared.proof().structure_business_intent()
    );
    let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":c["workspace_id"],"protocol_digest":c["protocol_digest"],"status":"APPLIED","author_intent":original.jws()});
    let response = receipt(&service, &c, original.proof().intent_digest(), &result);
    verify_http_response_for_prepared(&response, original.proof(), &service_kid).unwrap();
    verify_http_response_for_prepared(&response, prepared.proof(), &service_kid).unwrap();
    renewed["body"]["manifest"]["schema0"]["fields"]["a"] = json!("integer");
    assert!(
        verify_http_response_for_prepared(&response, prepare(&renewed).proof(), &service_kid)
            .is_err()
    );
}

#[test]
fn operation_lookup_verifies_the_original_receipt_against_the_requested_intent() {
    let identity = SigningKey::from_bytes(&[21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let service_kid = key_id(&service.verifying_key().to_bytes());
    let discovery_wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test",
        "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
        "receipt_public_key":service_kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&discovery_wire, discovery_wire.len()).unwrap();
    let original = command(&identity, "structure.action");
    let intent_digest = sha256_hex(b"original intent");
    let applied = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],
        "protocol_digest":original["protocol_digest"],"revision":2,"state":{"holder":"claimed"}});
    let inner: Value =
        serde_json::from_slice(&receipt(&service, &original, &intent_digest, &applied)).unwrap();
    let mut lookup = command(&identity, "structure.operation.get");
    lookup["command_id"] = json!(key_id(&[31; 32]));
    lookup["instance_id"] = Value::Null;
    lookup["protocol_digest"] = Value::Null;
    lookup["body"] = json!({"profile":PROFILE,"command_id":original["command_id"],"intent_digest":intent_digest});
    let bytes = serde_json::to_vec(&lookup).unwrap();
    let parsed = parse_wire_json_bounded(&bytes, 40, 180_000).unwrap();
    let prepared = prepare_signed_command_wire(&parsed, &identity, &discovery, None).unwrap();
    let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],"status":"APPLIED","response":inner});
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &lookup, prepared.proof().intent_digest(), &result),
        prepared.proof(),
        &service_kid
    )
    .is_ok());
    let mut wrong = result.clone();
    wrong["response"]["command_id"] = json!(key_id(&[32; 32]));
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &lookup, prepared.proof().intent_digest(), &wrong),
        prepared.proof(),
        &service_kid
    )
    .is_err());
    wrong = result.clone();
    wrong["response"]["result"]["revision"] = json!(99);
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &lookup, prepared.proof().intent_digest(), &wrong),
        prepared.proof(),
        &service_kid
    )
    .is_err());
    wrong = result.clone();
    wrong["status"] = json!("REJECTED_NO_EFFECT");
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &lookup, prepared.proof().intent_digest(), &wrong),
        prepared.proof(),
        &service_kid
    )
    .is_err());
    let mut rejected = applied.clone();
    rejected["status"] = json!("REJECTED_NO_EFFECT");
    rejected.as_object_mut().unwrap().remove("revision");
    rejected["error"]=json!({"phase":"EXECUTION","code":"CONSTRAINT_FAILED","retryable":false,"recovery":"NEW_INTENT_REQUIRED"});
    let rejected_response: Value =
        serde_json::from_slice(&receipt(&service, &original, &intent_digest, &rejected)).unwrap();
    let lookup_rejected = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],"status":"REJECTED_NO_EFFECT","response":rejected_response});
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &lookup,
            prepared.proof().intent_digest(),
            &lookup_rejected
        ),
        prepared.proof(),
        &service_kid
    )
    .is_ok());
}

#[test]
fn renewed_authorization_recovers_original_mutation_receipts_only_for_identical_business_intent() {
    let identity = SigningKey::from_bytes(&[21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let service_kid = key_id(&service.verifying_key().to_bytes());
    let discovery_wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test",
        "command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws",
        "receipt_public_key":service_kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&discovery_wire, discovery_wire.len()).unwrap();
    let prepare = |c: &Value, signer: &SigningKey| {
        let wire = serde_json::to_vec(c).unwrap();
        let parsed = parse_wire_json_bounded(&wire, 40, 180_000).unwrap();
        prepare_signed_command_wire(&parsed, signer, &discovery, None).unwrap()
    };
    for action in [
        "structure.workspace.create",
        "structure.adopt",
        "structure.action",
    ] {
        let c = command(&identity, action);
        let original = prepare(&c, &identity);
        let mut renewed = c.clone();
        renewed["issued_at"] = json!(700_001);
        renewed["expires_at"] = json!(1_300_001);
        let prepared = prepare(&renewed, &identity);
        assert_ne!(
            original.proof().intent_digest(),
            prepared.proof().intent_digest()
        );
        assert_eq!(
            original.proof().structure_business_intent(),
            prepared.proof().structure_business_intent()
        );
        let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE",
            "workspace_id":c["workspace_id"],"protocol_digest":c["protocol_digest"],"status":"APPLIED",
            "author_intent":original.jws()});
        let response = receipt(&service, &c, original.proof().intent_digest(), &result);
        let verified =
            verify_http_response_for_prepared(&response, prepared.proof(), &service_kid).unwrap();
        assert_eq!(verified.intent_digest(), original.proof().intent_digest());
        for (field, value) in [
            ("expected_instance_revision", json!(2)),
            ("protocol_digest", json!("b".repeat(64))),
            ("authority", json!("c".repeat(64))),
            ("instance_id", json!(key_id(&[33; 32]))),
            ("command_id", json!(key_id(&[34; 32]))),
            ("body", json!({"profile":PROFILE,"changed":true})),
        ] {
            let mut changed = renewed.clone();
            changed[field] = value;
            let changed = prepare(&changed, &identity);
            assert_ne!(
                changed.proof().structure_business_intent(),
                original.proof().structure_business_intent()
            );
            assert!(
                verify_http_response_for_prepared(&response, changed.proof(), &service_kid)
                    .is_err(),
                "changed {field}"
            );
        }
        let mut rejected = result.clone();
        rejected["status"] = json!("REJECTED_NO_EFFECT");
        rejected["error"]=json!({"phase":"EXECUTION","code":"CONSTRAINT_FAILED","retryable":false,"recovery":"NEW_INTENT_REQUIRED"});
        assert!(verify_http_response_for_prepared(
            &receipt(&service, &c, original.proof().intent_digest(), &rejected),
            prepared.proof(),
            &service_kid
        )
        .is_ok());
        let mut missing = result.clone();
        missing.as_object_mut().unwrap().remove("author_intent");
        assert!(verify_http_response_for_prepared(
            &receipt(&service, &c, original.proof().intent_digest(), &missing),
            prepared.proof(),
            &service_kid
        )
        .is_err());
        let attacker = SigningKey::from_bytes(&[35; 32]);
        let other = prepare(&command(&attacker, action), &attacker);
        let mut forged = result.clone();
        forged["author_intent"] = json!(other.jws());
        assert!(verify_http_response_for_prepared(
            &receipt(&service, &c, other.proof().intent_digest(), &forged),
            prepared.proof(),
            &service_kid
        )
        .is_err());
        let mut bad_sig = original.jws().as_bytes().to_vec();
        let last = bad_sig.len() - 3;
        bad_sig[last] = if bad_sig[last] == b'A' { b'B' } else { b'A' };
        forged["author_intent"] = json!(String::from_utf8(bad_sig).unwrap());
        assert!(verify_http_response_for_prepared(
            &receipt(&service, &c, original.proof().intent_digest(), &forged),
            prepared.proof(),
            &service_kid
        )
        .is_err());
    }
    for action in [
        "structure.instance.get",
        "structure.record.get",
        "identity.register",
    ] {
        let c = command(&identity, action);
        let original = prepare(&c, &identity);
        assert!(original.proof().structure_business_intent().is_none());
        let mut renewed = c.clone();
        renewed["issued_at"] = json!(2);
        renewed["expires_at"] = json!(600_002);
        let prepared = prepare(&renewed, &identity);
        let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":c["workspace_id"],
            "protocol_digest":c["protocol_digest"],"author_intent":original.jws()});
        assert!(verify_http_response_for_prepared(
            &receipt(&service, &c, original.proof().intent_digest(), &result),
            prepared.proof(),
            &service_kid
        )
        .is_err());
    }
}

#[test]
fn selected_pages_verify_external_authors_and_ciphertext_without_replaying_business_history() {
    use ed25519_dalek::Signer;
    use peerwork_core::crypto::base64url;
    use peerwork_core::prepared_command::{
        verify_prepared_command_wire, verify_structure_author_intent, CommandPins,
    };
    let identity = SigningKey::from_bytes(&[21; 32]);
    let author = SigningKey::from_bytes(&[41; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let service_kid = key_id(&service.verifying_key().to_bytes());
    let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test","command_type":"peerwork.kernel-command.v1+jws",
        "receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":service_kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&wire, wire.len()).unwrap();
    let prepare = |c: &Value, identity: &SigningKey| {
        let wire = serde_json::to_vec(c).unwrap();
        prepare_signed_command_wire(
            &parse_wire_json_bounded(&wire, 40, 180_000).unwrap(),
            identity,
            &discovery,
            None,
        )
        .unwrap()
    };
    let mut authored = command(&author, "structure.action");
    authored["command_id"] = json!(key_id(&[42; 32]));
    let ciphertext = json!({"algorithm":"A256GCM","key_id":key_id(&[43;32]),"nonce":base64url(&[1;12]),"ciphertext":base64url(&[2;32]),"aad_digest":"b".repeat(64)});
    authored["body"] = json!({"profile":PROFILE,"action_id":"post","structure":{"status":"submitted"},"contents":[{"record_index":0,"body":ciphertext}]});
    // External peers can sign valid JSON with whitespace/member order. This
    // authenticates exact bytes without weakening local saved-packet rules.
    let kid = key_id(&author.verifying_key().to_bytes());
    let header = base64url(
        serde_json::to_vec(
            &json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid}),
        )
        .unwrap()
        .as_slice(),
    );
    let payload = base64url(serde_json::to_string_pretty(&authored).unwrap().as_bytes());
    let input = format!("{header}.{payload}");
    let jws = format!(
        "{input}.{}",
        base64url(&author.sign(input.as_bytes()).to_bytes())
    );
    let digest = sha256_hex(jws.as_bytes());
    let audience: Vec<u16> = "structure-test".encode_utf16().collect();
    assert_eq!(
        verify_structure_author_intent(&jws, &audience)
            .unwrap()
            .actor_id(),
        authored["actor_id"].as_str().unwrap()
    );
    let packet = serde_json::to_vec(&json!({"jws":jws})).unwrap();
    assert!(verify_prepared_command_wire(
        &jws,
        &packet,
        &CommandPins {
            local_key_id: &kid,
            audience_utf16: &audience
        }
    )
    .is_err());
    let mut renewed = authored.clone();
    renewed["issued_at"] = json!(700001);
    renewed["expires_at"] = json!(1300001);
    let renewed = prepare(&renewed, &author);
    let original_result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":authored["workspace_id"],"protocol_digest":authored["protocol_digest"],"status":"APPLIED","author_intent":jws});
    assert!(verify_http_response_for_prepared(&receipt(&service,&authored,&digest,&original_result),renewed.proof(),&service_kid).is_ok(),"a native authorization can recover an externally framed original intent without changing local packet validation");
    let query = command(&identity, "structure.records.read");
    let prepared = prepare(&query, &identity);
    let source_key = format!(
        "{}:{}",
        authored["actor_id"].as_str().unwrap(),
        authored["command_id"].as_str().unwrap()
    );
    let record = json!({"record_id":key_id(&[44;32]),"entity_id":key_id(&[45;32]),"revision":1,"schema":"submission","structure":{"status":"submitted"},"sealed_content":ciphertext,
        "source":{"actor_id":authored["actor_id"],"command_id":authored["command_id"],"intent_digest":digest,"record_index":0,"entity_mode":"standalone"},"source_key":source_key});
    let source = json!({"actor_id":authored["actor_id"],"command_id":authored["command_id"],"intent_digest":digest,"author_intent":jws});
    let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":query["workspace_id"],"instance_id":query["instance_id"],"protocol_digest":query["protocol_digest"],"records":[record],"sources":{(source_key.clone()):source},"next_cursor":null});
    let verify = |value: &Value| {
        verify_http_response_for_prepared(
            &receipt(&service, &query, prepared.proof().intent_digest(), value),
            prepared.proof(),
            &service_kid,
        )
    };
    assert!(verify(&result).is_ok());
    for field in ["ciphertext", "nonce", "key_id", "aad_digest"] {
        let mut changed = result.clone();
        changed["records"][0]["sealed_content"][field] = json!("tampered");
        assert!(verify(&changed).is_err(), "changed encrypted {field}");
    }
    for field in ["actor_id", "command_id", "intent_digest"] {
        let mut changed = result.clone();
        changed["sources"][&source_key][field] = json!(key_id(&[46; 32]));
        assert!(verify(&changed).is_err(), "changed source {field}");
    }
    let mut changed = result.clone();
    changed["records"][0]["source"]["record_index"] = json!(1);
    assert!(verify(&changed).is_err());
    changed = result.clone();
    changed["records"][0]["source_key"] = json!("missing");
    assert!(verify(&changed).is_err());
    changed = result.clone();
    changed["sources"][&source_key]["author_intent"] =
        json!(prepare(&command(&author, "structure.action"), &author).jws());
    assert!(verify(&changed).is_err());
    let mut get = query.clone();
    get["action_id"] = json!("structure.record.get");
    get["body"] = json!({"profile":PROFILE,"record_id":record["record_id"],"revision":1});
    let get_prepared = prepare(&get, &identity);
    let mut selected = record.clone();
    selected["profile"] = json!(PROFILE);
    selected["assurance"] = json!("BACKEND_CURRENT_STATE");
    selected["workspace_id"] = query["workspace_id"].clone();
    selected["protocol_digest"] = query["protocol_digest"].clone();
    selected["author_intent"] = json!(jws);
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &get,
            get_prepared.proof().intent_digest(),
            &selected
        ),
        get_prepared.proof(),
        &service_kid
    )
    .is_ok());
    selected["record_id"] = json!(key_id(&[47; 32]));
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &get,
            get_prepared.proof().intent_digest(),
            &selected
        ),
        get_prepared.proof(),
        &service_kid
    )
    .is_err());
    let mut events = query.clone();
    events["action_id"] = json!("structure.events.read");
    let events_prepared = prepare(&events, &identity);
    let event_key = sha256_hex(
        serde_json::to_string(&json!([
            authored["actor_id"],
            authored["workspace_id"],
            authored["command_id"]
        ]))
        .unwrap()
        .as_bytes(),
    );
    let event_page = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":events["workspace_id"],"protocol_digest":events["protocol_digest"],"events":[{"actor_id":authored["actor_id"],"instance_id":authored["instance_id"],"summary":{"action_id":"structure.action"},"source_key":event_key.clone()}],"sources":{event_key:result["sources"][&source_key]}});
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &events,
            events_prepared.proof().intent_digest(),
            &event_page
        ),
        events_prepared.proof(),
        &service_kid
    )
    .is_ok());
    let mut wrong = event_page.clone();
    wrong["events"][0]["actor_id"] = query["actor_id"].clone();
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &events,
            events_prepared.proof().intent_digest(),
            &wrong
        ),
        events_prepared.proof(),
        &service_kid
    )
    .is_err());
}

#[test]
fn operation_lookup_by_business_digest_verifies_original_actor_intent_and_receipt() {
    let identity = SigningKey::from_bytes(&[21; 32]);
    let service = SigningKey::from_bytes(&[22; 32]);
    let kid = key_id(&service.verifying_key().to_bytes());
    let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":kid,"limits":{"max":1}})).unwrap();
    let discovery = parse_discovery_wire(&wire, wire.len()).unwrap();
    let prepare = |c: &Value| {
        let wire = serde_json::to_vec(c).unwrap();
        prepare_signed_command_wire(
            &parse_wire_json_bounded(&wire, 40, 180_000).unwrap(),
            &identity,
            &discovery,
            None,
        )
        .unwrap()
    };
    let original = command(&identity, "structure.action");
    let saved = prepare(&original);
    let business = saved.proof().structure_business_intent().unwrap();
    let applied = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],"protocol_digest":original["protocol_digest"],"status":"APPLIED","revision":2,"author_intent":saved.jws()});
    let nested: Value = serde_json::from_slice(&receipt(
        &service,
        &original,
        saved.proof().intent_digest(),
        &applied,
    ))
    .unwrap();
    let mut lookup = command(&identity, "structure.operation.get");
    lookup["command_id"] = json!(key_id(&[51; 32]));
    lookup["instance_id"] = Value::Null;
    lookup["protocol_digest"] = Value::Null;
    lookup["body"] = json!({"profile":PROFILE,"command_id":original["command_id"],"business_intent_digest":business});
    let prepared = prepare(&lookup);
    let result = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],"status":"APPLIED","response":nested});
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &lookup, prepared.proof().intent_digest(), &result),
        prepared.proof(),
        &kid
    )
    .is_ok());
    let mut different = lookup.clone();
    different["body"]["business_intent_digest"] = json!("f".repeat(64));
    let different_prepared = prepare(&different);
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &different,
            different_prepared.proof().intent_digest(),
            &result
        ),
        different_prepared.proof(),
        &kid
    )
    .is_err());
    let mut missing = result.clone();
    missing["response"]["result"]
        .as_object_mut()
        .unwrap()
        .remove("author_intent");
    let inner: Value = serde_json::from_slice(&receipt(
        &service,
        &original,
        saved.proof().intent_digest(),
        &missing["response"]["result"],
    ))
    .unwrap();
    missing["response"] = inner;
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &lookup,
            prepared.proof().intent_digest(),
            &missing
        ),
        prepared.proof(),
        &kid
    )
    .is_err());
    let absence = json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],"status":"NOT_FOUND","recovery":"RESUBMIT_SAME_INTENT"});
    assert!(verify_http_response_for_prepared(
        &receipt(
            &service,
            &lookup,
            prepared.proof().intent_digest(),
            &absence
        ),
        prepared.proof(),
        &kid
    )
    .is_ok());
    let mut wrong = absence;
    wrong["recovery"] = json!("RESUBMIT_EXACT_INTENT");
    assert!(verify_http_response_for_prepared(
        &receipt(&service, &lookup, prepared.proof().intent_digest(), &wrong),
        prepared.proof(),
        &kid
    )
    .is_err());
}

fn terminal_discovery(service:&SigningKey)->peerwork_core::discovery::ParsedDiscovery{
 let wire=serde_json::to_vec(&json!({"semantics":"peerwork.kernel.v1","audience":"structure-test","command_type":"peerwork.kernel-command.v1+jws","receipt_type":"peerwork.kernel-receipt.v1+jws","receipt_public_key":key_id(&service.verifying_key().to_bytes()),"limits":{"max":1}})).unwrap();parse_discovery_wire(&wire,wire.len()).unwrap()
}
fn refusal_for(command:&Value)->Value{json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":command["workspace_id"],"instance_id":command["instance_id"],"protocol_digest":command["protocol_digest"],"status":"REJECTED_NO_EFFECT","effect_certainty":"NOT_APPLIED","error":{"phase":"AUTHORIZATION","code":"FORBIDDEN","http_status":403,"retryable":false,"recovery":"NEW_INTENT_REQUIRED"}})}
#[test]
fn signed_read_refusals_are_terminal_without_requiring_record_history_but_cannot_smuggle_data(){
 let identity=SigningKey::from_bytes(&[21;32]);let service=SigningKey::from_bytes(&[22;32]);let discovery=terminal_discovery(&service);let kid=key_id(&service.verifying_key().to_bytes());
 for action in ["structure.record.get","structure.records.read","structure.operation.get"]{
  let c=command(&identity,action);let wire=serde_json::to_vec(&c).unwrap();let prepared=prepare_signed_command_wire(&parse_wire_json_bounded(&wire,40,180000).unwrap(),&identity,&discovery,None).unwrap();let result=refusal_for(&c);
  assert!(verify_http_response_for_prepared(&receipt(&service,&c,prepared.proof().intent_digest(),&result),prepared.proof(),&kid).is_ok());
  for (field,value) in [("state",json!({"unverified":"data"})),("records",json!([])),("effect_certainty",json!("COMMITTED"))]{let mut changed=result.clone();changed[field]=value;assert!(verify_http_response_for_prepared(&receipt(&service,&c,prepared.proof().intent_digest(),&changed),prepared.proof(),&kid).is_err());}
  let mut changed=result.clone();changed["error"]["retryable"]=json!(true);assert!(verify_http_response_for_prepared(&receipt(&service,&c,prepared.proof().intent_digest(),&changed),prepared.proof(),&kid).is_err());
  changed=result;changed.as_object_mut().unwrap().remove("error");assert!(verify_http_response_for_prepared(&receipt(&service,&c,prepared.proof().intent_digest(),&changed),prepared.proof(),&kid).is_err());
 }
}
#[test]
fn restricted_commit_acknowledgment_binds_original_intent_across_authorization_renewal(){
 let identity=SigningKey::from_bytes(&[21;32]);let service=SigningKey::from_bytes(&[22;32]);let discovery=terminal_discovery(&service);let kid=key_id(&service.verifying_key().to_bytes());
 let original=command(&identity,"structure.action");let prepare=|v:&Value|prepare_signed_command_wire(&parse_wire_json_bounded(&serde_json::to_vec(v).unwrap(),40,180000).unwrap(),&identity,&discovery,None).unwrap();let signed=prepare(&original);
 let result=json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":original["workspace_id"],"instance_id":original["instance_id"],"protocol_digest":original["protocol_digest"],"status":"COMMITTED_RESULT_UNAVAILABLE","effect_certainty":"COMMITTED","error":{"phase":"RESULT_ACCESS","code":"OUTCOME_RECORDED_ACCESS_DENIED","http_status":403,"retryable":false,"recovery":"REQUEST_ACCESS_AND_READ_ORIGINAL_OUTCOME"},"author_intent":signed.jws()});
 let mut renewed=original.clone();renewed["issued_at"]=json!(700001);renewed["expires_at"]=json!(1300001);let current=prepare(&renewed);
 assert!(verify_http_response_for_prepared(&receipt(&service,&original,signed.proof().intent_digest(),&result),current.proof(),&kid).is_ok());
 let mut changed=result.clone();changed["effect_certainty"]=json!("NOT_APPLIED");assert!(verify_http_response_for_prepared(&receipt(&service,&original,signed.proof().intent_digest(),&changed),current.proof(),&kid).is_err());
 changed=result.clone();changed["produced_record_ids"]=json!([key_id(&[1;32])]);assert!(verify_http_response_for_prepared(&receipt(&service,&original,signed.proof().intent_digest(),&changed),current.proof(),&kid).is_err());
 renewed["body"]["changed"]=json!(true);let wrong=prepare(&renewed);assert!(verify_http_response_for_prepared(&receipt(&service,&original,signed.proof().intent_digest(),&result),wrong.proof(),&kid).is_err());
}

#[test]
fn selected_public_bodies_and_owner_policy_reads_bind_original_signatures(){
 use peerwork_core::crypto::base64url;
 let reader=SigningKey::from_bytes(&[21;32]);let author=SigningKey::from_bytes(&[41;32]);let owner=SigningKey::from_bytes(&[42;32]);let service=SigningKey::from_bytes(&[22;32]);let discovery=terminal_discovery(&service);let service_kid=key_id(&service.verifying_key().to_bytes());
 let prepare=|c:&Value,key:&SigningKey|prepare_signed_command_wire(&parse_wire_json_bounded(&serde_json::to_vec(c).unwrap(),40,180000).unwrap(),key,&discovery,None).unwrap();
 let public_body=json!({"format":"PUBLIC_UTF8_BASE64","chunks":[base64url(b"Signed public text")]});
 let mut authored=command(&author,"structure.action");let output=json!({"v":1,"profile":PROFILE,"audience":authored["audience"],"actor_id":authored["actor_id"],"command_id":authored["command_id"],"workspace_id":authored["workspace_id"],"instance_id":authored["instance_id"],"protocol_digest":authored["protocol_digest"],"action_id":"post","policy_revision":1,"record_index":0,"disclosure":"PUBLISH_SELECTED_RECORD","title":"A note","body":public_body});let jws=sign_compact(&json!({"alg":"EdDSA","typ":peerwork_core::public_output::TYPE,"kid":key_id(&author.verifying_key().to_bytes())}),&output,&author).unwrap();let statement=json!({"format":"AUTHOR_PUBLIC_OUTPUT_V1","chunks":jws.as_bytes().chunks(8192).map(|v|std::str::from_utf8(v).unwrap()).collect::<Vec<_>>()});
 authored["body"]=json!({"profile":PROFILE,"action_id":"post","structure":{},"publication":{"policy_revision":1,"disclosure":"PUBLISH_ACTION_AND_SELECTED_RECORDS","entries":[{"record_index":0,"statement":statement}]}});let original=prepare(&authored,&author);
 let mut get=command(&reader,"structure.record.get");let id=key_id(&[43;32]);get["body"]=json!({"profile":PROFILE,"record_id":id,"revision":1});let selected=prepare(&get,&reader);
 let result=json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":get["workspace_id"],"instance_id":get["instance_id"],"protocol_digest":get["protocol_digest"],"record_id":id,"revision":1,"entity_id":key_id(&[44;32]),"schema":"note","structure":{"status":"POSTED"},"sealed_content":null,"public_statement":statement,"source":{"actor_id":authored["actor_id"],"command_id":authored["command_id"],"intent_digest":original.proof().intent_digest(),"record_index":0},"author_intent":original.jws()});
 let verify=|r:&Value|verify_http_response_for_prepared(&receipt(&service,&get,selected.proof().intent_digest(),r),selected.proof(),&service_kid);
 assert!(verify(&result).is_ok());for changed in [Value::Null,json!({"format":"PUBLIC_UTF8_BASE64","chunks":[base64url(b"Forged public text")]})]{let mut wrong=result.clone();wrong["public_statement"]=changed;assert!(verify(&wrong).is_err());}
 let mut policy=command(&owner,"structure.publication.policy.set");policy["body"]=json!({"profile":PROFILE,"state":"ACTIVE","actions":["post"],"expected_policy_revision":0,"disclosure":"ALLOW_AUTHOR_SIGNED_ACTION_PUBLICATION"});let original=prepare(&policy,&owner);
 let get=command(&reader,"structure.publication.policy.get");let query=prepare(&get,&reader);let result=json!({"profile":PROFILE,"assurance":"BACKEND_CURRENT_STATE","workspace_id":get["workspace_id"],"instance_id":get["instance_id"],"protocol_digest":get["protocol_digest"],"policy":{"revision":1,"state":"ACTIVE","actions":["post"],"source":{"actor_id":policy["actor_id"],"command_id":policy["command_id"],"intent_digest":original.proof().intent_digest(),"author_intent":original.jws()}}});
 let verify=|r:&Value|verify_http_response_for_prepared(&receipt(&service,&get,query.proof().intent_digest(),r),query.proof(),&service_kid);assert!(verify(&result).is_ok());let mut wrong=result.clone();wrong["policy"]["actions"]=json!(["admin"]);assert!(verify(&wrong).is_err());let mut wrong=result;wrong["policy"]["revision"]=json!(2);assert!(verify(&wrong).is_err());
}
