//! Cross-language fixture generated with the product's TypeScript certificate,
//! signed platform context, Owner JWS and HPKE implementations. All fixture
//! private keys are documented synthetic constants, never application state.
use peerwork_core::{crypto::decode_base64url,prepared_command::verify_structure_author_intent,
    secure_recipient::SecretRecipient,structure_access::{verify_access_request,open_owner_access_keys}};
use zeroize::Zeroizing;

#[test]
fn typescript_device_request_and_owner_hpke_delivery_verify_in_native_sdk(){
 let vector:serde_json::Value=serde_json::from_str(include_str!("../../../tests/fixtures/structure-access-v1.json")).unwrap();
 let request=verify_access_request(vector["request_jws"].as_str().unwrap(),&peerwork_core::crypto::base64url(&[3;32]),&"structure-test".encode_utf16().collect::<Vec<_>>(),vector["service_key"].as_str().unwrap(),1_800_000_000_000).unwrap();
 assert_eq!(request.recipient_key_id(),vector["recipient_key_id"].as_str().unwrap());
 let author=verify_structure_author_intent(vector["owner_jws"].as_str().unwrap(),&"structure-test".encode_utf16().collect::<Vec<_>>()).unwrap();
 let recipient=SecretRecipient::from_private(Zeroizing::new([4;32])).unwrap();
 let opened=open_owner_access_keys(&author,vector["owner_id"].as_str().unwrap(),vector["actor_id"].as_str().unwrap(),&recipient,&peerwork_core::crypto::base64url(&[3;32]),"structure-test",vector["service_key"].as_str().unwrap()).unwrap();
 assert_eq!(opened.keys.len(),2);
 for key in &opened.keys { assert!(key.secret()==&[11;32]||key.secret()==&[12;32]);assert_eq!(decode_base64url(key.key_id()).unwrap().len(),32); }
 assert_eq!(opened.current_key_id,vector["key_ids"][0].as_str().unwrap());
}
