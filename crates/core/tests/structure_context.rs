use ed25519_dalek::{SigningKey,Signer};
use peerwork_core::{crypto::{key_id,base64url},structure_context::{verify_structure_context,CONTEXT_TYPE},structure_execution::PROFILE};
use serde_json::{json,Value};

#[test]
fn context_pins_nonce_service_audience_domain_and_capability_without_a_local_clock() {
    let service=SigningKey::from_bytes(&[7;32]);let kid=key_id(&service.verifying_key().to_bytes());
    let nonce=key_id(&[8;32]);let audience:Vec<u16>="context-test".encode_utf16().collect();
    let payload=json!({"v":1,"audience":"context-test","profile":PROFILE,"nonce":nonce,"server_time_ms":123,
        "authorization_ttl_ms":600000,"idempotency":"BUSINESS_INTENT_V1","assurance":"BACKEND_CURRENT_STATE"});
    let response=|payload:&Value,typ:&str|{
        let header=base64url(serde_json::to_string(&json!({"alg":"EdDSA","typ":typ,"kid":kid})).unwrap().as_bytes());
        let payload=base64url(serde_json::to_vec(payload).unwrap().as_slice());let input=format!("{header}.{payload}");
        let signature=base64url(&service.sign(input.as_bytes()).to_bytes());
        serde_json::to_vec(&json!({"context":format!("{input}.{signature}")})).unwrap()
    };
    let wire=response(&payload,CONTEXT_TYPE);
    let proof=verify_structure_context(&wire,&nonce,&audience,&kid).unwrap();
    assert_eq!(proof.server_time_ms(),123);assert_eq!(proof.expires_at_ms(),600123);
    assert!(verify_structure_context(&wire,&key_id(&[9;32]),&audience,&kid).is_err());
    assert!(verify_structure_context(&wire,&nonce,&"other".encode_utf16().collect::<Vec<_>>(),&kid).is_err());
    assert!(verify_structure_context(&wire,&nonce,&audience,&key_id(&[10;32])).is_err());
    assert!(verify_structure_context(&response(&payload,"peerwork.kernel-receipt.v1+jws"),&nonce,&audience,&kid).is_err());
    for (field,value) in [("profile",json!("other")),("idempotency",json!("EXACT_BYTES")),("assurance",json!("INDEPENDENT_HISTORY")),
        ("authorization_ttl_ms",json!(600001)),("server_time_ms",json!(-1)),("server_time_ms",json!(1.5)),("server_time_ms",json!(9007199254140992u64)),("extra",json!(true))] {
        let mut changed=payload.clone();changed[field]=value;
        assert!(verify_structure_context(&response(&changed,CONTEXT_TYPE),&nonce,&audience,&kid).is_err(),"invalid {field}");
    }
    let mut changed:Value=serde_json::from_slice(&wire).unwrap();let mut jws=changed["context"].as_str().unwrap().as_bytes().to_vec();
    let i=jws.len()-3;jws[i]=if jws[i]==b'A'{b'B'}else{b'A'};changed["context"]=json!(String::from_utf8(jws).unwrap());
    assert!(verify_structure_context(&serde_json::to_vec(&changed).unwrap(),&nonce,&audience,&kid).is_err());
}
