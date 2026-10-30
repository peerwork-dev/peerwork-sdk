use ed25519_dalek::SigningKey;
use peerwork_core::{
    communication::*,
    crypto::{actor_id, key_id, sha256_hex, sign_compact},
    structure_content::{structure_content_key_id, StructureContentError},
    wire_json::parse_wire_json_bounded,
};
use serde_json::{json, Value};
fn context() -> MessageContentContext {
    MessageContentContext {
        workspace_id: "W".repeat(43),
        actor_id: "A".repeat(43),
        command_id: "C".repeat(43),
        conversation_id: "V".repeat(43),
        reply_to: None,
        reply_address: Some(MailboxAddress {
            mailbox_id: "S".repeat(43),
            membership_id: "T".repeat(43),
        }),
        recipients: vec![
            MailboxAddress {
                mailbox_id: "M".repeat(43),
                membership_id: "G".repeat(43),
            },
            MailboxAddress {
                mailbox_id: "N".repeat(43),
                membership_id: "H".repeat(43),
            },
        ],
    }
}
#[test]
fn native_mail_aad_binds_domain_reply_and_all_recipient_generations() {
    let original = context();
    let sealed = seal_message_content(&[42; 32], b"native message", &original).unwrap();
    assert_eq!(sealed.key_id, structure_content_key_id(&[42; 32]));
    assert_eq!(
        &**open_message_content(&[42; 32], &sealed, &original).unwrap(),
        b"native message"
    );
    for mode in 0..10 {
        let mut changed = original.clone();
        match mode {
            0 => changed.workspace_id = "Z".repeat(43),
            1 => changed.actor_id = "Z".repeat(43),
            2 => changed.command_id = "Z".repeat(43),
            3 => changed.conversation_id = "Z".repeat(43),
            4 => changed.reply_to = Some("Z".repeat(43)),
            5 => changed.reply_address = None,
            6 => changed.reply_address.as_mut().unwrap().membership_id = "Z".repeat(43),
            7 => changed.recipients.swap(0, 1),
            8 => changed.recipients[0].membership_id = "Z".repeat(43),
            _ => changed.recipients[1].mailbox_id = "Z".repeat(43),
        }
        assert_eq!(
            open_message_content(&[42; 32], &sealed, &changed).unwrap_err(),
            StructureContentError::Invalid
        );
        let mut forged = sealed.clone();
        forged.aad_digest = sha256_hex(changed.canonical_aad().unwrap().as_bytes());
        assert_eq!(
            open_message_content(&[42; 32], &forged, &changed).unwrap_err(),
            StructureContentError::Authentication
        );
    }
    let mut invalid = original;
    invalid.recipients.push(invalid.recipients[0].clone());
    assert!(invalid.canonical_aad().is_err());
}
struct Fixture {
    service: SigningKey,
    actor: String,
    stream: String,
    audience: Vec<u16>,
    pins: MailboxPins,
    item: Value,
}
impl Fixture {
    fn new() -> Self {
        let service = SigningKey::from_bytes(&[11; 32]);
        let sender = SigningKey::from_bytes(&[12; 32]);
        let actor = actor_id(&SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes());
        let audience = "native-mail-test".encode_utf16().collect::<Vec<_>>();
        let stream = "Q".repeat(43);
        let pins = MailboxPins {
            workspace_id: "W".repeat(43),
            mailbox_id: "M".repeat(43),
            membership_id: "G".repeat(43),
            receiver_id: "R".repeat(43),
            epoch: 2,
            destination_digest: "d".repeat(64),
            binding_version: 1,
            after_sequence: 4,
            after_control_sequence: Some(6),
        };
        let mut context = context();
        context.actor_id = actor_id(&sender.verifying_key().to_bytes());
        let sealed = seal_message_content(&[42; 32], b"verified sender", &context).unwrap();
        let command = json!({"v":1,"audience":"native-mail-test","actor_id":context.actor_id,"command_id":context.command_id,"authority":sha256_hex(context.actor_id.as_bytes()),"method":"POST","path":"/api/workspace/v1/commands","action_id":"structure.message.send","workspace_id":context.workspace_id,"instance_id":null,"protocol_digest":null,"expected_workspace_revision":null,"expected_instance_revision":null,"exact_input_refs":[],"issued_at":1,"expires_at":600001,"body":{"profile":"backend-structure-v1","conversation_id":context.conversation_id,"reply_to":context.reply_to,"reply_address":context.reply_address,"recipients":context.recipients,"content":{"mode":"WORKSPACE_E2EE","body":sealed}}});
        let jws=sign_compact(&json!({"alg":"EdDSA","typ":"peerwork.kernel-command.v1+jws","kid":key_id(&sender.verifying_key().to_bytes())}),&command,&sender).unwrap();
        let message = context.message_id().unwrap();
        let delivery = peerwork_core::crypto::base64url(&peerwork_core::crypto::sha256(
            peerwork_core::canonical::canonical(
                &json!([
                    "peerwork.delivery.v1",
                    pins.workspace_id,
                    pins.mailbox_id,
                    message,
                    null
                ]),
                peerwork_core::canonical::Path::SecureArtifact,
            )
            .unwrap()
            .as_bytes(),
        ));
        let item = json!({"delivery_id":delivery,"sequence":5,"kind":"MESSAGE","created_at":100,"message":{"message_id":message,"sender_actor":context.actor_id,"sender_membership":"S".repeat(43),"accepted_at":100,"command_id":context.command_id,"intent_digest":sha256_hex(jws.as_bytes()),"author_intent":jws}});
        Self {
            service,
            actor,
            stream,
            audience,
            pins,
            item,
        }
    }
    fn frame(&self, items: Value, controls: Value, changes: Value) -> Value {
        let canon = |v: &Value| {
            peerwork_core::canonical::canonical(v, peerwork_core::canonical::Path::STRUCTURED)
                .unwrap()
        };
        let mut p = json!({"kind":"peerwork.mailbox-frame.v1","audience":"native-mail-test","actor_id":self.actor,"stream_id":self.stream,"workspace_id":self.pins.workspace_id,"mailbox_id":self.pins.mailbox_id,"receiver_id":self.pins.receiver_id,"epoch":self.pins.epoch,"destination_digest":self.pins.destination_digest,"binding_version":self.pins.binding_version,"server_time":1000,"mailbox_frontier":5,"checkpoint":5,"more":false,"items_digest":sha256_hex(canon(&items).as_bytes()),"control_checkpoint":7,"controls_more":false,"controls_digest":sha256_hex(canon(&controls).as_bytes())});
        for (k, v) in changes.as_object().unwrap() {
            p[k] = v.clone();
        }
        let proof=sign_compact(&json!({"alg":"EdDSA","typ":FRAME_TYPE,"kid":key_id(&self.service.verifying_key().to_bytes())}),&p,&self.service).unwrap();
        json!({"proof":proof,"items":items,"controls":controls})
    }
    fn verify(&self, v: &Value) -> bool {
        let key = key_id(&self.service.verifying_key().to_bytes());
        verify_mailbox_frame(
            v.to_string().as_bytes(),
            &FramePins {
                audience: &self.audience,
                actor_id: &self.actor,
                stream_id: &self.stream,
                mailbox: &self.pins,
                service_key: &key,
                server_time_floor: 900,
                expires_at: 61000,
            },
        )
        .is_ok()
    }
}
#[test]
fn full_frame_checks_original_author_target_generation_and_two_cursors() {
    let f = Fixture::new();
    let good = f.frame(json!([f.item]), json!([]), json!({}));
    assert!(f.verify(&good));
    for (k, v) in [
        ("actor_id", json!("Z".repeat(43))),
        ("stream_id", json!("Z".repeat(43))),
        ("epoch", json!(1)),
        ("destination_digest", json!("b".repeat(64))),
        ("checkpoint", json!(6)),
        ("control_checkpoint", json!(5)),
        ("server_time", json!(61000)),
    ] {
        assert!(
            !f.verify(&f.frame(json!([f.item]), json!([]), json!({k:v}))),
            "{k}"
        );
    }
    for field in [
        "sender_actor",
        "command_id",
        "intent_digest",
        "sender_membership",
    ] {
        let mut item = f.item.clone();
        item["message"][field] = json!("bad");
        assert!(
            !f.verify(&f.frame(json!([item]), json!([]), json!({}))),
            "{field}"
        );
    }
    let mut wrong = f.pins.clone();
    wrong.membership_id = "Z".repeat(43);
    let key = key_id(&f.service.verifying_key().to_bytes());
    assert!(verify_mailbox_frame(
        good.to_string().as_bytes(),
        &FramePins {
            audience: &f.audience,
            actor_id: &f.actor,
            stream_id: &f.stream,
            mailbox: &wrong,
            service_key: &key,
            server_time_floor: 900,
            expires_at: 61000
        }
    )
    .is_err());
    let mut tampered = good.clone();
    tampered["items"][0]["created_at"] = json!(101);
    assert!(!f.verify(&tampered));
    // A malicious service disclosure cannot replace a peer signature with a new body.
    let mut item = f.item.clone();
    item["message"]["author_intent"] = json!("bad.signature.bytes");
    assert!(!f.verify(&f.frame(json!([item]), json!([]), json!({}))));
}
#[test]
fn control_only_progress_is_valid_and_unverified_control_source_is_not() {
    let f = Fixture::new();
    assert!(f.verify(&f.frame(
        json!([]),
        json!([]),
        json!({"checkpoint":4,"mailbox_frontier":4,"control_checkpoint":9})
    )));
    let control = json!({"sequence":7,"kind":"communication.message.withdrawn","target":{"message_id":"M".repeat(43),"delivery_id":"D".repeat(43)},"intent_digest":"a".repeat(64),"author_intent":f.item["message"]["author_intent"],"source_response":{"result":{}}});
    assert!(!f.verify(&f.frame(
        json!([]),
        json!([control]),
        json!({"checkpoint":4,"mailbox_frontier":4})
    )));
    let good = f.frame(json!([f.item]), json!([]), json!({}));
    let raw = good.to_string();
    let duplicate = format!("{{\"proof\":\"bad\",{}", &raw[1..]);
    assert!(parse_wire_json_bounded(duplicate.as_bytes(), 40, MAX_FRAME_BYTES).is_err());
    let key = key_id(&f.service.verifying_key().to_bytes());
    assert!(verify_mailbox_frame(
        &vec![b' '; MAX_FRAME_BYTES + 1],
        &FramePins {
            audience: &f.audience,
            actor_id: &f.actor,
            stream_id: &f.stream,
            mailbox: &f.pins,
            service_key: &key,
            server_time_floor: 900,
            expires_at: 61000
        }
    )
    .is_err());
}

#[test]
fn receiver_continuity_requires_device_key_and_exact_command_context() {
    let seed = [17u8; 32];
    let actor = "A".repeat(43);
    let workspace = "W".repeat(43);
    let mut body = json!({"claim_command_id":"C".repeat(43),"mailbox_id":"M".repeat(43),
        "receiver_id":receiver_id(&seed),"expected_epoch":1,"destination_digest":"d".repeat(64),"replace":false});
    body["continuity_proof"] =
        json!(receiver_claim_proof(&seed, "service-one", &actor, &workspace, &body).unwrap());
    assert!(verify_receiver_claim_proof("service-one", &actor, &workspace, &body).is_ok());
    for (field, value) in [
        ("claim_command_id", json!("N".repeat(43))),
        ("mailbox_id", json!("X".repeat(43))),
        ("receiver_id", json!(receiver_id(&[18u8; 32]))),
        ("expected_epoch", json!(2)),
        ("destination_digest", json!("e".repeat(64))),
        ("replace", json!(true)),
    ] {
        let mut changed = body.clone();
        changed[field] = value;
        assert!(
            verify_receiver_claim_proof("service-one", &actor, &workspace, &changed).is_err(),
            "{field}"
        );
    }
    assert!(verify_receiver_claim_proof("other-service", &actor, &workspace, &body).is_err());
    assert!(
        verify_receiver_claim_proof("service-one", &"B".repeat(43), &workspace, &body).is_err()
    );
    assert!(verify_receiver_claim_proof("service-one", &actor, &"X".repeat(43), &body).is_err());
    assert!(receiver_claim_proof(&[18u8; 32], "service-one", &actor, &workspace, &body).is_err());
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("claim_command_id");
    assert!(verify_receiver_claim_proof("service-one", &actor, &workspace, &missing).is_err());
}
