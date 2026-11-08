use peerwork_core::structure_content::{StructureContentContext as Context,StructureSealedContent as Sealed,
    StructureContentError as Error,MAX_BODY_BYTES,seal_structure_content as seal,open_structure_content as open,
    structure_content_key_id as key_id};

fn context()->Context{Context{workspace_id:"W".repeat(43),instance_id:"I".repeat(43),protocol_digest:"a".repeat(64),
    actor_id:"A".repeat(43),command_id:"C".repeat(43),action_id:"post".into(),record_index:0}}

#[test]
fn opens_exact_node_crypto_wire_without_legacy_content_wrappers(){
    // Produced by node:crypto AES-256-GCM with a fixed synthetic key/nonce and
    // sorted JSON of the service's structureContentContext command binding.
    let sealed=Sealed{algorithm:"A256GCM".into(),key_id:"P2v2sn3Q4-kLHf9ZxZvx8XhKOPcpqAkb8qnVBGmtmE4".into(),
        nonce:"BwcHBwcHBwcHBwcH".into(),ciphertext:"d5qTyTq01a5jyiBINxvyIUIMxZ5LDovz2Ss".into(),
        ciphertext_chunks:Vec::new(),aad_digest:"b6128e19c2c4e8dd62504303054aa0891f49e7b4c6172c94a28506196c3556bc".into()};
    assert_eq!(&**open(&[42;32],&sealed,&context()).unwrap(),"Hello 🚀".as_bytes());
    assert_eq!(key_id(&[42;32]),sealed.key_id);
}

#[test]
fn every_original_author_and_target_binding_is_authenticated(){
    let original=context();let sealed=seal(&[42;32],b"private body",&original).unwrap();
    for which in 0..7 {
        let mut changed=original.clone();match which{
            0=>changed.workspace_id="X".repeat(43),1=>changed.instance_id="X".repeat(43),
            2=>changed.protocol_digest="b".repeat(64),3=>changed.actor_id="X".repeat(43),
            4=>changed.command_id="X".repeat(43),5=>changed.action_id="other".into(),_=>changed.record_index=1,
        }
        assert_eq!(open(&[42;32],&sealed,&changed).unwrap_err(),Error::Invalid);
        let mut rewritten=sealed.clone();rewritten.aad_digest=peerwork_core::crypto::sha256_hex(changed.canonical_aad().unwrap().as_bytes());
        assert_eq!(open(&[42;32],&rewritten,&changed).unwrap_err(),Error::Authentication);
    }
    let mut corrupt=sealed.clone();let mut wire=peerwork_core::crypto::decode_base64url(&corrupt.ciphertext).unwrap();
    wire[0]^=1;corrupt.ciphertext=peerwork_core::crypto::base64url(&wire);
    assert_eq!(open(&[42;32],&corrupt,&original).unwrap_err(),Error::Authentication);
    assert_eq!(open(&[43;32],&sealed,&original).unwrap_err(),Error::Invalid);
    let mut wrong_key=sealed.clone();wrong_key.key_id=key_id(&[43;32]);
    assert_eq!(open(&[43;32],&wrong_key,&original).unwrap_err(),Error::Authentication);
}

#[test]
fn empty_and_maximum_bodies_roundtrip_under_the_service_wire_budget(){
    let c=context();for size in [0,6128,6129,MAX_BODY_BYTES]{
        let body=vec![0xff;size];let sealed=seal(&[42;32],&body,&c).unwrap();
        assert!(sealed.ciphertext.len()<=8192);assert!(sealed.ciphertext_chunks.iter().all(|c|c.len()<=8192));assert_eq!(&**open(&[42;32],&sealed,&c).unwrap(),body);
        assert_ne!(sealed.nonce,seal(&[42;32],&body,&c).unwrap().nonce);
    }
    assert_eq!(seal(&[42;32],&vec![0;MAX_BODY_BYTES+1],&c).unwrap_err(),Error::TooLarge);
}

#[test]
fn malformed_envelopes_and_contexts_fail_before_body_use(){
    let c=context();let good=seal(&[42;32],b"private",&c).unwrap();
    for which in 0..6{
        let mut bad=good.clone();match which{0=>bad.algorithm="other".into(),1=>bad.key_id="bad".into(),
            2=>bad.nonce.push('='),3=>bad.ciphertext.push('='),4=>bad.ciphertext="A".repeat(8193),_=>bad.aad_digest="a".repeat(64)}
        assert_eq!(open(&[42;32],&bad,&c).unwrap_err(),Error::Invalid);
    }
    let mut fields=serde_json::to_value(&good).unwrap();fields["extra"]=serde_json::json!(1);
    assert!(serde_json::from_value::<Sealed>(fields).is_err());
    let mut bad=c.clone();bad.record_index=8;assert_eq!(seal(&[42;32],b"x",&bad).unwrap_err(),Error::Invalid);
    bad=c.clone();bad.action_id="🚀".repeat(61);assert_eq!(bad.canonical_aad().unwrap_err(),Error::Invalid);
}

#[test]
fn body_selection_uses_verified_original_author_without_manual_context_reconstruction(){
    use ed25519_dalek::SigningKey;
    use peerwork_core::{crypto::{actor_id,key_id,sha256_hex,sign_compact},
        prepared_command::verify_structure_author_intent,structure_content::authored_structure_content};
    use serde_json::json;
    let signing=SigningKey::from_bytes(&[21;32]);let kid=key_id(&signing.verifying_key().to_bytes());
    let mut c=context();c.actor_id=actor_id(&signing.verifying_key().to_bytes());
    let sealed=seal(&[42;32],b"original author body",&c).unwrap();
    let mut command=json!({"v":1,"audience":"body-test","command_id":c.command_id,"actor_id":c.actor_id,
        "authority":sha256_hex(c.actor_id.as_bytes()),"method":"POST","path":"/api/workspace/v1/commands",
        "workspace_id":c.workspace_id,"instance_id":c.instance_id,"protocol_digest":c.protocol_digest,
        "action_id":"structure.action","expected_workspace_revision":null,"expected_instance_revision":1,
        "exact_input_refs":[],"body":{"profile":"backend-structure-v1","action_id":"post","structure":{},
        "contents":[{"record_index":0,"body":sealed}]},"issued_at":1,"expires_at":600001});
    let header=json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":kid});
    let verify=|command:&serde_json::Value|verify_structure_author_intent(&sign_compact(&header,command,&signing).unwrap(),&"body-test".encode_utf16().collect::<Vec<_>>()).unwrap();
    let author=verify(&command);let (derived,body)=authored_structure_content(&author,0).unwrap();
    assert_eq!(derived,c);assert_eq!(body,sealed);assert_eq!(&**open(&[42;32],&body,&derived).unwrap(),b"original author body");
    assert!(authored_structure_content(&author,1).is_err());
    command["body"]["contents"]=json!([{"record_index":0,"body":sealed},{"record_index":0,"body":sealed}]);
    assert!(authored_structure_content(&verify(&command),0).is_err());
}


#[test]
fn chunked_wire_is_canonical_and_authenticates_order_and_complete_content(){
    let c=context();let good=seal(&[42;32],&vec![91;MAX_BODY_BYTES],&c).unwrap();
    let value=serde_json::to_value(&good).unwrap();assert!(value.get("ciphertext").is_none());assert_eq!(good.ciphertext_chunks.len(),11);
    for mode in 0..7{
        let mut bad=good.clone();match mode{
            0=>bad.ciphertext="AAAA".into(),
            1=>bad.ciphertext_chunks[0].pop().map(|_|()).unwrap(),
            2=>bad.ciphertext_chunks[10].push('='),
            3=>bad.ciphertext_chunks.push("A".repeat(8192)),
            4=>{let a=bad.ciphertext_chunks[0].clone();bad.ciphertext_chunks[0]=bad.ciphertext_chunks[10].clone();bad.ciphertext_chunks[10]=a;},
            5=>{let last=bad.ciphertext_chunks[10].len()-1;bad.ciphertext_chunks[10].replace_range(last..,"_");},
            _=>{let replacement=if bad.ciphertext_chunks[0].starts_with('A'){"B"}else{"A"};bad.ciphertext_chunks[0].replace_range(0..1,replacement);},
        }
        assert!(open(&[42;32],&bad,&c).is_err());
    }
}
